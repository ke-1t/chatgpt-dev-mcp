"""Bounded read-only host inspection for storage and filesystem diagnostics.

This module intentionally exposes structured inspection actions rather than a
general command runner.  Every subprocess is shell-free, uses fixed argv
templates, returns bounded output, and is restricted to metadata/size reads.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
from typing import Mapping

from .process_runner import run_bounded


class SystemInspectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SystemInspectionPolicy:
    max_timeout_ms: int = 60_000
    max_output_bytes: int = 131_072
    max_du_depth: int = 4
    max_paths: int = 32


_METADATA_ROOTS = ("/Applications", "/Library", "/Volumes")
_DENIED_PREFIXES = ("/System", "/private", "/dev", "/proc")
_MDLS_ATTRIBUTES = (
    "kMDItemFSName",
    "kMDItemFSSize",
    "kMDItemFSCreationDate",
    "kMDItemFSContentChangeDate",
    "kMDItemContentType",
    "kMDItemIsUbiquitous",
    "kMDItemDownloadingStatus",
)


def _safe_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"}
    env = {
        key: value
        for key, value in os.environ.items()
        if key in allowed and isinstance(value, str) and "\x00" not in value and "\n" not in value and "\r" not in value
    }
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    return env


def _resolve_path(raw: object, *, allow_root: bool = False) -> Path:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise SystemInspectionError("SYSTEM_INSPECTION_PATH_INVALID", "path must be non-empty text")
    candidate = Path(os.path.abspath(os.path.expanduser(raw)))
    resolved = candidate.resolve(strict=False)
    text = str(resolved)
    if allow_root and text == "/":
        return candidate
    home = Path.home().resolve(strict=False)
    try:
        resolved.relative_to(home)
        return candidate
    except ValueError:
        pass
    if any(text == prefix or text.startswith(prefix + "/") for prefix in _DENIED_PREFIXES):
        raise SystemInspectionError("SYSTEM_INSPECTION_PATH_DENIED", "system/private paths are outside inspection policy")
    if any(text == prefix or text.startswith(prefix + "/") for prefix in _METADATA_ROOTS):
        return candidate
    raise SystemInspectionError(
        "SYSTEM_INSPECTION_PATH_DENIED",
        "path must be under the current user home, /Applications, /Library, or /Volumes",
    )


def _bounded_paths(raw: object, *, maximum: int) -> tuple[Path, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= maximum:
        raise SystemInspectionError("SYSTEM_INSPECTION_ARGUMENT_INVALID", f"paths must contain 1..{maximum} items")
    return tuple(_resolve_path(item) for item in raw)


class SystemInspectionController:
    def __init__(self, *, policy: SystemInspectionPolicy | None = None) -> None:
        self._policy = policy or SystemInspectionPolicy()

    @staticmethod
    def _executable(name: str) -> str:
        path = shutil.which(name, path=_safe_environment().get("PATH"))
        if not path:
            raise SystemInspectionError("SYSTEM_INSPECTION_TOOL_UNAVAILABLE", f"required tool {name!r} is unavailable")
        return path

    def _run(self, argv: list[str], *, timeout_ms: int) -> dict[str, object]:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= self._policy.max_timeout_ms:
            raise SystemInspectionError("SYSTEM_INSPECTION_ARGUMENT_INVALID", "timeout_ms is outside the inspection bound")
        try:
            completed = run_bounded(
                argv,
                env=_safe_environment(),
                timeout_seconds=timeout_ms / 1000.0,
                max_output_bytes=self._policy.max_output_bytes,
                merge_stderr=True,
            )
        except OSError as exc:
            raise SystemInspectionError("SYSTEM_INSPECTION_EXEC_FAILED", "inspection command could not be started") from exc
        return {
            "status": "timeout" if completed.timed_out else ("succeeded" if completed.returncode == 0 else "failed"),
            "exit_code": completed.returncode,
            "output": completed.stdout,
            "output_truncated": completed.output_truncated,
            "elapsed_ms": completed.elapsed_ms,
            "read_only": True,
        }

    def inspect(self, args: Mapping[str, object]) -> dict[str, object]:
        action = args.get("action")
        timeout_ms = args.get("timeout_ms", 30_000)
        if action == "filesystem":
            path = _resolve_path(args.get("path", "/"), allow_root=True)
            result = self._run([self._executable("df"), "-h", str(path)], timeout_ms=timeout_ms)
        elif action == "disk_usage":
            path = _resolve_path(args.get("path"))
            depth = args.get("depth", 1)
            if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= self._policy.max_du_depth:
                raise SystemInspectionError("SYSTEM_INSPECTION_ARGUMENT_INVALID", "depth is outside the inspection bound")
            argv = [self._executable("du"), "-x", "-h", "-d", str(depth), str(path)]
            result = self._run(argv, timeout_ms=timeout_ms)
        elif action == "apfs":
            result = self._run([self._executable("diskutil"), "apfs", "list"], timeout_ms=timeout_ms)
        elif action == "stat":
            paths = _bounded_paths(args.get("paths"), maximum=self._policy.max_paths)
            argv = [self._executable("stat"), "-f", "%N\t%z\t%Sm\t%HT", *map(str, paths)]
            result = self._run(argv, timeout_ms=timeout_ms)
        elif action == "metadata":
            paths = _bounded_paths(args.get("paths"), maximum=self._policy.max_paths)
            argv = [self._executable("mdls")]
            for attribute in _MDLS_ATTRIBUTES:
                argv.extend(["-name", attribute])
            argv.extend(map(str, paths))
            result = self._run(argv, timeout_ms=timeout_ms)
        elif action == "xattr_names":
            paths = _bounded_paths(args.get("paths"), maximum=self._policy.max_paths)
            result = self._run([self._executable("xattr"), *map(str, paths)], timeout_ms=timeout_ms)
        else:
            raise SystemInspectionError(
                "SYSTEM_INSPECTION_ACTION_INVALID",
                "action must be filesystem, disk_usage, apfs, stat, metadata, or xattr_names",
            )
        return {"action": action, **result, "external_execution": False}
