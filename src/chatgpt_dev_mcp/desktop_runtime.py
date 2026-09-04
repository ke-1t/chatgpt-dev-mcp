"""Managed long-lived desktop application runtime."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Mapping, Sequence, TextIO
from urllib.parse import urlsplit
from urllib.request import urlopen
import uuid

from .desktop_capture import DesktopCaptureProfile, MacOSDesktopCaptureBackend
from .director import redact_secrets
from .runtime_policy import CommandProfile, render_typed_args, validate_identifier


class DesktopRuntimeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DesktopProfile:
    identifier: str
    command: CommandProfile | None = None
    data_dir_id: str = ""
    health_url: str = ""
    auto_restart: bool = False
    bundle_id: str = ""
    max_screenshot_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        validate_identifier(self.identifier, field="desktop profile", max_length=80)
        capture_only = bool(self.bundle_id)
        launch_backed = self.command is not None or bool(self.data_dir_id)
        if capture_only and launch_backed:
            raise DesktopRuntimeError("DESKTOP_PROFILE_MODE_INVALID", "desktop profile cannot mix launch and capture-only fields")
        if capture_only:
            try:
                DesktopCaptureProfile(self.identifier, self.bundle_id, self.health_url, self.max_screenshot_bytes)
            except ValueError as exc:
                raise DesktopRuntimeError(str(getattr(exc, "code", "DESKTOP_PROFILE_INVALID")), str(exc)) from exc
        else:
            if self.command is None or not self.data_dir_id:
                raise DesktopRuntimeError("DESKTOP_PROFILE_MODE_INVALID", "launch-backed desktop profile requires command and data directory")
            validate_identifier(self.data_dir_id, field="data directory", max_length=80)
        if self.auto_restart:
            raise DesktopRuntimeError("DESKTOP_AUTO_RESTART_DENIED", "automatic restart is disabled by the base safety policy")
        if self.health_url:
            parsed = urlsplit(self.health_url)
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
                raise DesktopRuntimeError("DESKTOP_HEALTH_URL_DENIED", "health endpoint must be registered localhost HTTP")

    @property
    def capture_only(self) -> bool:
        return bool(self.bundle_id)


@dataclass
class _ManagedProcess:
    instance_id: str
    project_id: str
    worktree_id: str
    revision: str
    profile: DesktopProfile
    root: Path
    data_dir: Path
    log_path: Path
    process: subprocess.Popen[str]
    started_at: float
    executable: str
    redact_values: tuple[str, ...]
    log_handle: TextIO


class DesktopRuntimeManager:
    def __init__(
        self,
        profiles: Mapping[str, DesktopProfile],
        *,
        cache_root: Path,
        capture_backend: MacOSDesktopCaptureBackend | None = None,
    ) -> None:
        self._profiles = dict(profiles)
        self._cache_root = cache_root.resolve(strict=False)
        self._capture_backend = capture_backend or MacOSDesktopCaptureBackend()
        self._instances: dict[str, _ManagedProcess] = {}
        self._profile_instances: dict[tuple[str, str], str] = {}

    @staticmethod
    def _git_head(root: Path) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            check=False,
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "GIT_TERMINAL_PROMPT": "0"},
        )
        value = result.stdout.strip().lower()
        if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise DesktopRuntimeError("DESKTOP_REVISION_UNAVAILABLE", "repository revision could not be verified")
        return value

    @staticmethod
    def _base_env() -> dict[str, str]:
        result: dict[str, str] = {}
        for name in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"):
            value = os.environ.get(name)
            if value:
                result[name] = value
        return result

    @staticmethod
    def _redact(value: str, materials: Sequence[str]) -> str:
        result = redact_secrets(value)
        for material in sorted(materials, key=len, reverse=True):
            if material:
                result = result.replace(material, "[REDACTED]")
        return result

    @classmethod
    def _drain(cls, stream: TextIO | None, log_handle: TextIO, materials: tuple[str, ...]) -> None:
        if stream is None:
            return
        try:
            for line in stream:
                log_handle.write(cls._redact(line, materials))
                log_handle.flush()
        finally:
            stream.close()

    def start(
        self,
        root: Path,
        *,
        project_id: str,
        worktree_id: str,
        revision: str,
        profile_id: str,
        child_environment: Mapping[str, str] | None = None,
        redact_values: Sequence[str] = (),
    ) -> dict[str, object]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise DesktopRuntimeError("DESKTOP_PROFILE_UNKNOWN", "desktop profile is not registered")
        if profile.capture_only:
            raise DesktopRuntimeError("DESKTOP_CAPTURE_ONLY", "capture-only desktop profile cannot start a managed process")
        validate_identifier(project_id, field="project", max_length=80)
        validate_identifier(worktree_id.replace(":", "-"), field="worktree", max_length=128)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            raise DesktopRuntimeError("DESKTOP_REVISION_INVALID", "revision must be a full commit id")
        resolved = root.resolve(strict=True)
        current_head = self._git_head(resolved)
        if current_head != revision.lower():
            raise DesktopRuntimeError("DESKTOP_REVISION_MISMATCH", "registered runtime revision does not match the worktree")
        key = (project_id, profile_id)
        existing_id = self._profile_instances.get(key)
        if existing_id:
            existing = self._instances.get(existing_id)
            if existing and existing.process.poll() is None:
                raise DesktopRuntimeError("DESKTOP_INSTANCE_CONFLICT", "a managed instance is already running for this profile")
        assert profile.command is not None
        argv = render_typed_args(profile.command, {})
        data_dir = self._cache_root / "data" / project_id / profile.data_dir_id
        logs_dir = self._cache_root / "logs" / project_id
        data_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        instance_id = "desktop-" + uuid.uuid4().hex
        log_path = logs_dir / f"{instance_id}.log"
        log_handle = log_path.open("a", encoding="utf-8", buffering=1)
        child_env = self._base_env()
        child_env["CHATGPT_DEV_MCP_DATA_DIR"] = str(data_dir)
        if child_environment:
            child_env.update(child_environment)
        process = subprocess.Popen(
            list(argv),
            cwd=resolved,
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        materials = tuple(item for item in redact_values if isinstance(item, str) and item)
        record = _ManagedProcess(
            instance_id, project_id, worktree_id, current_head, profile, resolved, data_dir,
            log_path, process, time.time(), argv[0], materials, log_handle,
        )
        self._instances[instance_id] = record
        self._profile_instances[key] = instance_id
        threading.Thread(target=self._drain, args=(process.stdout, log_handle, materials), daemon=True).start()
        threading.Thread(target=self._drain, args=(process.stderr, log_handle, materials), daemon=True).start()
        return self.snapshot(instance_id)

    def capture_profile(self, root: Path, profile_id: str) -> dict[str, object]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise DesktopRuntimeError("DESKTOP_PROFILE_UNKNOWN", "desktop profile is not registered")
        if not profile.capture_only:
            raise DesktopRuntimeError("DESKTOP_CAPTURE_ONLY_REQUIRED", "profile-backed snapshot requires a capture-only desktop profile")
        capture_profile = DesktopCaptureProfile(
            profile.identifier,
            profile.bundle_id,
            profile.health_url,
            profile.max_screenshot_bytes,
        )
        try:
            return self._capture_backend.capture(root, capture_profile)
        except ValueError as exc:
            raise DesktopRuntimeError(str(getattr(exc, "code", "DESKTOP_CAPTURE_FAILED")), str(exc)) from exc

    def _instance(self, instance_id: str) -> _ManagedProcess:
        record = self._instances.get(instance_id)
        if record is None:
            raise DesktopRuntimeError("DESKTOP_INSTANCE_UNKNOWN", "managed desktop instance is unknown")
        return record

    @staticmethod
    def _health(record: _ManagedProcess) -> dict[str, object]:
        if not record.profile.health_url:
            return {"configured": False, "healthy": None}
        try:
            with urlopen(record.profile.health_url, timeout=1.0) as response:
                status = int(getattr(response, "status", 0) or 0)
            return {"configured": True, "healthy": 200 <= status < 400, "status": status}
        except Exception:
            return {"configured": True, "healthy": False, "status": None}

    def snapshot(self, instance_id: str) -> dict[str, object]:
        record = self._instance(instance_id)
        exit_code = record.process.poll()
        state = "running" if exit_code is None else ("stopped" if exit_code == 0 else "crashed")
        return {
            "instance_id": instance_id,
            "status": state,
            "project_id": record.project_id,
            "worktree_id": record.worktree_id,
            "revision": record.revision,
            "profile": record.profile.identifier,
            "pid": record.process.pid,
            "executable": record.executable,
            "data_dir_id": record.profile.data_dir_id,
            "health": self._health(record),
            "exit_code": exit_code,
            "started_at": record.started_at,
            "auto_restart": False,
            "external_execution": False,
        }

    def status(self, instance_id: str) -> dict[str, object]:
        return self.snapshot(instance_id)

    def logs(self, instance_id: str, *, max_bytes: int = 65536) -> dict[str, object]:
        if not 1024 <= max_bytes <= 262144:
            raise DesktopRuntimeError("DESKTOP_LOG_BOUND_INVALID", "log byte bound is invalid")
        record = self._instance(instance_id)
        record.log_handle.flush()
        try:
            data = record.log_path.read_bytes()
        except OSError as exc:
            raise DesktopRuntimeError("DESKTOP_LOG_UNAVAILABLE", "managed log could not be read") from exc
        text = data[-max_bytes:].decode("utf-8", errors="replace")
        return {
            "instance_id": instance_id,
            "status": self.snapshot(instance_id)["status"],
            "output": self._redact(text, record.redact_values),
            "truncated": len(data) > max_bytes,
            "external_execution": False,
        }

    def stop(self, instance_id: str, *, timeout_seconds: float = 5.0) -> dict[str, object]:
        record = self._instance(instance_id)
        if record.process.poll() is None:
            record.process.terminate()
            try:
                record.process.wait(timeout=max(0.1, min(timeout_seconds, 10.0)))
            except subprocess.TimeoutExpired:
                record.process.kill()
                record.process.wait(timeout=2.0)
        record.log_handle.flush()
        record.log_handle.close()
        self._profile_instances.pop((record.project_id, record.profile.identifier), None)
        result = self.snapshot(instance_id)
        result["managed_stop"] = True
        return result
