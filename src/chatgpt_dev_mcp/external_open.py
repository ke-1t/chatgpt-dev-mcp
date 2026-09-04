"""Shell-free normalization and execution for opening local GUI targets."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
import subprocess
from typing import Callable, Protocol
from urllib.parse import urlsplit

OPEN_EXECUTABLE = "/usr/bin/open"
_BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_DENIED_SCHEMES = frozenset({"java" + "script", "da" + "ta", "vb" + "script", "file"})
_SENSITIVE_PARTS = frozenset({"." + "ssh", "." + "gnupg"})
_SENSITIVE_PREFIX = "." + "env"


class ExternalOpenError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ExternalOpenKind(str, Enum):
    APP_BUNDLE = "app_bundle"
    APP_PATH = "app_path"
    URL = "url"
    CUSTOM_URL = "custom_url"
    FILE = "file"
    DIRECTORY = "directory"


@dataclass(frozen=True)
class ExternalOpenPlan:
    kind: ExternalOpenKind
    target: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ExternalOpenResult:
    ok: bool
    returncode: int


class _LauncherOutcome(Protocol):
    returncode: int


Launcher = Callable[[tuple[str, ...]], _LauncherOutcome]


def _default_launcher(argv: tuple[str, ...]) -> _LauncherOutcome:
    return subprocess.run(argv, shell=False, check=False, capture_output=True, text=True, timeout=15)


def _sensitive_path(path: Path) -> bool:
    return any(part.casefold() in _SENSITIVE_PARTS or part.casefold().startswith(_SENSITIVE_PREFIX) for part in path.parts)


class ExternalOpenController:
    def __init__(self, *, launcher: Launcher | None = None) -> None:
        self._launcher = launcher or _default_launcher

    def prepare(self, kind: ExternalOpenKind | str, target: object) -> ExternalOpenPlan:
        try:
            parsed_kind = kind if isinstance(kind, ExternalOpenKind) else ExternalOpenKind(kind)
        except (TypeError, ValueError):
            raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "external-open kind is unsupported") from None
        if not isinstance(target, str) or not target or len(target) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in target):
            raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "target must be a bounded string without control characters")
        if parsed_kind is ExternalOpenKind.APP_BUNDLE:
            if _BUNDLE_RE.fullmatch(target) is None:
                raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "application bundle identifier is invalid")
            return ExternalOpenPlan(parsed_kind, target, (OPEN_EXECUTABLE, "-b", target))
        if parsed_kind in {ExternalOpenKind.APP_PATH, ExternalOpenKind.FILE, ExternalOpenKind.DIRECTORY}:
            original = Path(target).expanduser()
            if original.is_symlink():
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "symlink launch targets are denied")
            try:
                resolved = original.resolve(strict=True)
            except (FileNotFoundError, OSError):
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "launch target does not exist") from None
            if _sensitive_path(original) or _sensitive_path(resolved):
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "sensitive local launch target is denied")
            if parsed_kind is ExternalOpenKind.FILE and not resolved.is_file():
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "file target must be an existing regular file")
            if parsed_kind is ExternalOpenKind.DIRECTORY and not resolved.is_dir():
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "directory target must be an existing directory")
            if parsed_kind is ExternalOpenKind.APP_PATH and (not resolved.is_dir() or resolved.suffix.casefold() != ".app"):
                raise ExternalOpenError("EXTERNAL_OPEN_PATH_DENIED", "app target must be an existing .app bundle directory")
            normalized = str(resolved)
            return ExternalOpenPlan(parsed_kind, normalized, (OPEN_EXECUTABLE, normalized))
        try:
            parsed = urlsplit(target)
        except ValueError:
            raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "URL is malformed") from None
        scheme = parsed.scheme.casefold()
        if parsed_kind is ExternalOpenKind.URL:
            if scheme not in {"http", "https"} or not parsed.netloc:
                raise ExternalOpenError("EXTERNAL_OPEN_SCHEME_DENIED", "URL target must use http or https")
        else:
            if not scheme or _SCHEME_RE.fullmatch(parsed.scheme) is None or scheme in _DENIED_SCHEMES or scheme in {"http", "https"}:
                raise ExternalOpenError("EXTERNAL_OPEN_SCHEME_DENIED", "custom URL scheme is not allowed")
        if parsed.netloc and "@" in parsed.netloc:
            raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "URL authority must not embed userinfo")
        return ExternalOpenPlan(parsed_kind, target, (OPEN_EXECUTABLE, target))

    def execute(self, plan: ExternalOpenPlan) -> ExternalOpenResult:
        if not isinstance(plan, ExternalOpenPlan) or not plan.argv or plan.argv[0] != OPEN_EXECUTABLE:
            raise ExternalOpenError("EXTERNAL_OPEN_TARGET_INVALID", "only a prepared external-open plan may be executed")
        try:
            outcome = self._launcher(plan.argv)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ExternalOpenError("EXTERNAL_OPEN_FAILED", f"launcher failed: {exc}") from exc
        returncode = getattr(outcome, "returncode", None)
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise ExternalOpenError("EXTERNAL_OPEN_FAILED", "launcher returned an invalid result")
        return ExternalOpenResult(returncode == 0, returncode)
