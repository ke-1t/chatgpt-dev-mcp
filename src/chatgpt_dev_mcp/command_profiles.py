from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import time
import uuid
from typing import Any, Mapping, Sequence

from .credential_slots import CredentialSlotError, CredentialSlotManager
from .process_runner import run_bounded
from .runtime_policy import CommandProfile, PolicyError, render_typed_args


class CommandProfileError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _Preflight:
    preflight_id: str
    project_id: str
    profile_id: str
    profile_hash: str
    root: str
    root_device: int
    root_inode: int
    argv: tuple[str, ...]
    grant_ids: tuple[str, ...]
    created_at: float


def _hash_argv(argv: Sequence[str]) -> str:
    return hashlib.sha256("\x00".join(argv).encode()).hexdigest()


def _bounded_text(value: object, maximum: int) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum:
        return text
    return encoded[:maximum].decode("utf-8", errors="ignore")


def _redact(value: str, redact_values: Sequence[str]) -> str:
    result = value
    for material in sorted(redact_values, key=len, reverse=True):
        if material:
            result = result.replace(material, "[REDACTED]")
    return result


class CommandProfileController:
    def __init__(self, profiles: Mapping[str, CommandProfile], *, credential_slots: CredentialSlotManager | None = None) -> None:
        self._profiles = dict(profiles)
        self._credential_slots = credential_slots
        self._preflights: dict[str, _Preflight] = {}

    def list_profiles(self) -> list[dict[str, object]]:
        return [
            {
                "profile": profile.identifier,
                "definition_hash": profile.definition_hash,
                "argument_names": [item.name for item in profile.allowed_args],
                "resources": list(profile.resources),
                "credential_slots": list(profile.credential_slots),
                "network_class": profile.network_class,
                "timeout_ms": profile.timeout_ms,
            }
            for profile in sorted(self._profiles.values(), key=lambda item: item.identifier)
        ]

    def preflight(
        self,
        root: Path,
        profile_id: str,
        arguments: Mapping[str, Any],
        *,
        project_id: str,
        credential_grants: Sequence[str] = (),
    ) -> dict[str, object]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise CommandProfileError("COMMAND_PROFILE_UNKNOWN", "command profile is not registered")
        try:
            argv = render_typed_args(profile, arguments)
        except PolicyError as exc:
            raise CommandProfileError(exc.code, str(exc)) from exc
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            raise CommandProfileError("COMMAND_ROOT_INVALID", "registered command root is not a directory")
        stat = resolved.stat()
        if credential_grants:
            if self._credential_slots is None:
                raise CommandProfileError("CREDENTIAL_GRANT_DENIED", "credential slots are unavailable")
            try:
                granted_slots = self._credential_slots.validate_grants(
                    credential_grants, project_id=project_id, command_profile=profile_id
                )
            except CredentialSlotError as exc:
                raise CommandProfileError(exc.code, str(exc)) from exc
            if any(slot not in profile.credential_slots for slot in granted_slots):
                raise CommandProfileError("CREDENTIAL_GRANT_DENIED", "profile does not allow one of the granted slots")
        preflight_id = "cmd-" + uuid.uuid4().hex
        preflight = _Preflight(
            preflight_id,
            project_id,
            profile_id,
            profile.definition_hash,
            str(resolved),
            int(stat.st_dev),
            int(stat.st_ino),
            argv,
            tuple(credential_grants),
            time.time(),
        )
        self._preflights[preflight_id] = preflight
        return {
            "preflight_id": preflight_id,
            "status": "ready",
            "profile": profile_id,
            "profile_hash": profile.definition_hash,
            "argv_hash": _hash_argv(argv),
            "resources": list(profile.resources),
            "credential_slots": list(profile.credential_slots),
            "network_class": profile.network_class,
            "timeout_ms": profile.timeout_ms,
        }

    def _safe_base_env(self) -> dict[str, str]:
        child_env: dict[str, str] = {}
        for name in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"):
            value = os.environ.get(name)
            if value:
                child_env[name] = value
        return child_env

    def run(self, root: Path, preflight_id: str) -> dict[str, object]:
        preflight = self._preflights.pop(preflight_id, None)
        if preflight is None:
            raise CommandProfileError("COMMAND_PREFLIGHT_INVALID", "preflight is unknown or already consumed")
        profile = self._profiles.get(preflight.profile_id)
        if profile is None or profile.definition_hash != preflight.profile_hash:
            raise CommandProfileError("COMMAND_PREFLIGHT_STALE", "command profile changed after preflight")
        try:
            resolved = root.resolve(strict=True)
            stat = resolved.stat()
        except OSError as exc:
            raise CommandProfileError("COMMAND_PREFLIGHT_STALE", "working directory is unavailable") from exc
        if str(resolved) != preflight.root or int(stat.st_dev) != preflight.root_device or int(stat.st_ino) != preflight.root_inode:
            raise CommandProfileError("COMMAND_PREFLIGHT_STALE", "working directory identity changed")

        child_env = self._safe_base_env()
        redact_values: tuple[str, ...] = ()
        if preflight.grant_ids:
            if self._credential_slots is None:
                raise CommandProfileError("CREDENTIAL_GRANT_DENIED", "credential slots are unavailable")
            try:
                injected, redact_values = self._credential_slots.consume_grants(
                    preflight.grant_ids,
                    project_id=preflight.project_id,
                    command_profile=preflight.profile_id,
                )
            except CredentialSlotError as exc:
                raise CommandProfileError(exc.code, str(exc)) from exc
            child_env.update(injected)

        try:
            completed = run_bounded(
                preflight.argv,
                cwd=resolved,
                env=child_env,
                timeout_seconds=profile.timeout_ms / 1000.0,
                max_output_bytes=profile.max_output_bytes,
            )
            stdout = _redact(completed.stdout, redact_values)
            stderr = _redact(completed.stderr, redact_values)
            if completed.timed_out:
                return {
                    "status": "failed",
                    "error_code": "COMMAND_TIMEOUT",
                    "exit_code": None,
                    "stdout": stdout,
                    "stderr": stderr,
                    "output_truncated": completed.output_truncated,
                    "elapsed_ms": completed.elapsed_ms,
                    "argv_hash": _hash_argv(preflight.argv),
                    "profile": preflight.profile_id,
                    "external_execution": False,
                }
            return {
                "status": "succeeded" if completed.returncode == 0 else "failed",
                "exit_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": completed.output_truncated,
                "elapsed_ms": completed.elapsed_ms,
                "argv_hash": _hash_argv(preflight.argv),
                "profile": preflight.profile_id,
                "external_execution": False,
            }
        except (OSError, ValueError) as exc:
            raise CommandProfileError("COMMAND_START_FAILED", "the command could not be started") from exc
