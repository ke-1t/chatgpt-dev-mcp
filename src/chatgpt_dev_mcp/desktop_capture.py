"""Bounded macOS capture of an already-running desktop application window."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from typing import Callable, Sequence
from urllib.parse import urlsplit
import uuid

from .director import redact_secrets
from .runtime_policy import PolicyError, validate_identifier


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$")
_MIN_SCREENSHOT_BYTES = 64 * 1024
_MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024
_JXA_SCRIPT = r'''function safe(call, fallback) {
  try { return call(); } catch (_) { return fallback; }
}
function run(argv) {
  const bundleId = argv[0];
  const se = Application("System Events");
  const processes = se.applicationProcesses();
  let target = null;
  for (let i = 0; i < processes.length; i += 1) {
    if (safe(() => processes[i].bundleIdentifier(), "") === bundleId) {
      target = processes[i];
      break;
    }
  }
  if (target === null) return JSON.stringify({running:false});
  const pid = safe(() => target.unixId(), null);
  const processName = safe(() => target.name(), "");
  const frontmost = Boolean(safe(() => target.frontmost(), false));
  const windows = safe(() => target.windows(), []);
  if (!windows || windows.length === 0) {
    return JSON.stringify({running:true, window:false, pid:pid, process_name:processName, frontmost:frontmost});
  }
  const window = windows[0];
  return JSON.stringify({
    running:true,
    window:true,
    pid:pid,
    process_name:processName,
    frontmost:frontmost,
    title:safe(() => window.name(), ""),
    position:safe(() => window.position(), []),
    size:safe(() => window.size(), []),
    focused_role:safe(() => target.attributes.byName("AXFocusedUIElement").value().role(), null),
    focused_title:safe(() => target.attributes.byName("AXFocusedUIElement").value().title(), null)
  });
}'''


class DesktopCaptureError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DesktopCaptureProfile:
    identifier: str
    bundle_id: str
    health_url: str = ""
    max_screenshot_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.identifier, field="desktop capture profile", max_length=80)
        except PolicyError as exc:
            raise DesktopCaptureError("DESKTOP_CAPTURE_PROFILE_INVALID", str(exc)) from exc
        if not self.identifier.startswith("managed-") or not isinstance(self.bundle_id, str) or not _BUNDLE_ID_RE.fullmatch(self.bundle_id) or len(self.bundle_id) > 160:
            raise DesktopCaptureError("DESKTOP_CAPTURE_PROFILE_INVALID", "desktop capture profile identity is invalid")
        if isinstance(self.max_screenshot_bytes, bool) or not isinstance(self.max_screenshot_bytes, int) or not _MIN_SCREENSHOT_BYTES <= self.max_screenshot_bytes <= _MAX_SCREENSHOT_BYTES:
            raise DesktopCaptureError("DESKTOP_CAPTURE_PROFILE_INVALID", "desktop screenshot byte bound is outside the safe range")
        if self.health_url:
            try:
                parsed = urlsplit(self.health_url)
                port = parsed.port
            except ValueError as exc:
                raise DesktopCaptureError("DESKTOP_CAPTURE_PROFILE_INVALID", "desktop health URL is invalid") from exc
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed.username
                or parsed.password
                or parsed.fragment
                or port is not None and not 1 <= port <= 65535
            ):
                raise DesktopCaptureError("DESKTOP_CAPTURE_PROFILE_INVALID", "desktop health URL must be loopback HTTP")


Runner = Callable[[tuple[str, ...], float], subprocess.CompletedProcess[str]]


def _default_runner(argv: tuple[str, ...], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    env = {key: value for key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL") if (value := os.environ.get(key))}
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        shell=False,
        env=env,
        check=False,
    )


class MacOSDesktopCaptureBackend:
    def __init__(self, *, runner: Runner | None = None, platform_name: str | None = None) -> None:
        self._runner = runner or _default_runner
        self._platform_name = platform_name or platform.system()

    @staticmethod
    def _output_directory(root: Path) -> Path:
        resolved = Path(root).resolve(strict=True)
        output = resolved / "output"
        artifacts = output / "devmcp-desktop-qa"
        for candidate in (output, artifacts):
            if candidate.exists() and candidate.is_symlink():
                raise DesktopCaptureError("DESKTOP_CAPTURE_PATH_DENIED", "desktop capture output cannot be a symlink")
        try:
            artifacts.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise DesktopCaptureError("DESKTOP_CAPTURE_PATH_DENIED", "desktop capture output directory is unavailable") from exc
        if artifacts.resolve(strict=True).parent != output.resolve(strict=True):
            raise DesktopCaptureError("DESKTOP_CAPTURE_PATH_DENIED", "desktop capture output escaped the workspace")
        return artifacts

    @staticmethod
    def _metadata(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if result.returncode != 0:
            stderr = (result.stderr or "").lower()
            if any(token in stderr for token in ("not authorized", "not permitted", "apple events", "assistive")):
                raise DesktopCaptureError("DESKTOP_ACCESSIBILITY_REQUIRED", "macOS Accessibility/Automation permission is required for desktop QA")
            raise DesktopCaptureError("DESKTOP_METADATA_UNAVAILABLE", "desktop window metadata could not be inspected")
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise DesktopCaptureError("DESKTOP_METADATA_UNAVAILABLE", "desktop window metadata was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise DesktopCaptureError("DESKTOP_METADATA_UNAVAILABLE", "desktop window metadata was not an object")
        return payload

    @staticmethod
    def _window(payload: dict[str, object]) -> tuple[int, int, int, int]:
        if payload.get("running") is not True:
            raise DesktopCaptureError("DESKTOP_APP_NOT_RUNNING", "registered desktop application is not running")
        if payload.get("window") is not True:
            raise DesktopCaptureError("DESKTOP_WINDOW_UNAVAILABLE", "registered desktop application has no capturable window")
        position = payload.get("position")
        size = payload.get("size")
        if not isinstance(position, list) or len(position) != 2 or not isinstance(size, list) or len(size) != 2:
            raise DesktopCaptureError("DESKTOP_WINDOW_INVALID", "desktop window geometry is invalid")
        try:
            x, y = int(position[0]), int(position[1])
            width, height = int(size[0]), int(size[1])
        except (TypeError, ValueError) as exc:
            raise DesktopCaptureError("DESKTOP_WINDOW_INVALID", "desktop window geometry is invalid") from exc
        if not -32768 <= x <= 32768 or not -32768 <= y <= 32768 or not 1 <= width <= 10000 or not 1 <= height <= 10000:
            raise DesktopCaptureError("DESKTOP_WINDOW_INVALID", "desktop window geometry is outside safe bounds")
        return x, y, width, height

    def capture(self, root: Path, profile: DesktopCaptureProfile) -> dict[str, object]:
        if self._platform_name != "Darwin":
            raise DesktopCaptureError("DESKTOP_CAPTURE_UNSUPPORTED", "desktop window capture is supported only on macOS")
        artifacts = self._output_directory(root)
        metadata_result = self._runner(
            ("/usr/bin/osascript", "-l", "JavaScript", "-e", _JXA_SCRIPT, "--", profile.bundle_id),
            10.0,
        )
        metadata = self._metadata(metadata_result)
        x, y, width, height = self._window(metadata)
        if metadata.get("frontmost") is not True:
            raise DesktopCaptureError(
                "DESKTOP_WINDOW_NOT_FRONTMOST",
                "desktop screenshot evidence is denied while the target window is not frontmost",
            )
        pid = metadata.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise DesktopCaptureError("DESKTOP_WINDOW_INVALID", "desktop process id is invalid")
        filename = f"{profile.identifier}-{pid}-{uuid.uuid4().hex[:12]}.png"
        target = artifacts / filename
        capture_result = self._runner(
            ("/usr/sbin/screencapture", "-x", f"-R{x},{y},{width},{height}", str(target)),
            15.0,
        )
        if capture_result.returncode != 0:
            target.unlink(missing_ok=True)
            stderr = (capture_result.stderr or "").lower()
            if any(token in stderr for token in ("not authorized", "not permitted", "could not create image", "screen recording")):
                raise DesktopCaptureError("DESKTOP_SCREEN_RECORDING_REQUIRED", "macOS Screen Recording permission is required for desktop QA")
            raise DesktopCaptureError("DESKTOP_CAPTURE_FAILED", "desktop screenshot command failed")
        try:
            image = target.read_bytes()
        except OSError as exc:
            raise DesktopCaptureError("DESKTOP_CAPTURE_FAILED", "desktop screenshot file was not created") from exc
        if not image.startswith(_PNG_SIGNATURE):
            target.unlink(missing_ok=True)
            raise DesktopCaptureError("DESKTOP_SCREENSHOT_INVALID", "desktop screenshot is not a PNG image")
        if len(image) > profile.max_screenshot_bytes:
            target.unlink(missing_ok=True)
            raise DesktopCaptureError("DESKTOP_SCREENSHOT_TOO_LARGE", "desktop screenshot exceeded the configured byte bound")
        resolved_root = Path(root).resolve(strict=True)
        relative = target.resolve(strict=True).relative_to(resolved_root)
        return {
            "status": "captured",
            "profile": profile.identifier,
            "bundle_id": profile.bundle_id,
            "pid": pid,
            "process_name": redact_secrets(str(metadata.get("process_name", "")))[:160],
            "frontmost": bool(metadata.get("frontmost", False)),
            "focused_role": redact_secrets(str(metadata.get("focused_role") or ""))[:128],
            "focused_title": redact_secrets(str(metadata.get("focused_title") or ""))[:512],
            "window": {
                "title": redact_secrets(str(metadata.get("title", "")))[:512],
                "x": x,
                "y": y,
                "width": width,
                "height": height,
            },
            "screenshot_path": relative.as_posix(),
            "sha256": hashlib.sha256(image).hexdigest(),
            "bytes": len(image),
            "external_execution": False,
        }


__all__ = [
    "DesktopCaptureError",
    "DesktopCaptureProfile",
    "MacOSDesktopCaptureBackend",
]
