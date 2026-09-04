"""Safe project provisioning and allowlisted DEVELOPMENT registry mutation.

This module deliberately owns only the narrow filesystem/config operations
needed to turn an explicit user development request into a registered project.
It does not expose arbitrary paths, edit unrelated configuration, stage/commit,
add remotes, or perform network/package-manager work.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from .director import contains_secret_like_content
from .development import UNBORN_HEAD, capture_repo_identity, repo_dirty
from .discovery import AllowedRoot, PROJECT_DISCOVERY, is_within_root, load_allowed_roots
from .process_runner import run_bounded

try:  # pragma: no cover - fcntl is present on supported macOS/Linux hosts
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_COMMAND_LENGTH = 400
TASK_NAMES = ("test", "lint", "build", "dev", "format")
COMMAND_COMPOSITION_RE = re.compile(r"(?:\r|\n|;|\|\||(?<!\|)\|(?!\|)|`|\$\(|[<>])")


class DevelopmentIntentSource(str, Enum):
    EXPLICIT_USER_REQUEST = "EXPLICIT_USER_REQUEST"
    REGISTERED_PROJECT = "REGISTERED_PROJECT"


class ProjectProvisioningMode(str, Enum):
    EXISTING_PROJECT = "EXISTING_PROJECT"
    CREATE_NEW_PROJECT = "CREATE_NEW_PROJECT"


class ProvisioningError(Exception):
    def __init__(self, code: str, message: str, *, category: str = "validation", details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.details = details or {}


@dataclass(frozen=True)
class RegistryMutationResult:
    workspace_id: str
    path: Path
    created: bool
    profile: str
    commands: dict[str, str]
    policy: dict[str, Any]
    before_digest: str
    after_digest: str
    receipt: dict[str, Any]
    repo_identity: dict[str, Any]
    root_id: str
    intent_source: DevelopmentIntentSource
    provisioning_mode: ProjectProvisioningMode

    def as_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "project_id": self.workspace_id,
            "path": str(self.path),
            "created": self.created,
            "registered": True,
            "profile": self.profile,
            "commands": sorted(self.commands),
            "policy": dict(self.policy),
            "repo_identity": dict(self.repo_identity),
            "root_id": self.root_id,
            "intent_source": self.intent_source.value,
            "provisioning_mode": self.provisioning_mode.value,
            "config_digest": self.after_digest,
            "receipt": dict(self.receipt),
        }


DEFAULT_ISOLATED_POLICY: dict[str, Any] = {
    "auto_create_sessions": True,
    "auto_resume_sessions": True,
    "auto_resume_policy": "same_owner_same_task_safe_local",
    "max_parallel_sessions": 6,
    "allowed_base": "registered_project",
    "allow_workspace_wide": False,
    "integration_requires_approval": True,
    "commit_requires_approval": True,
    "push_requires_approval": True,
    "verified_auto_commit": True,
    "auto_approve_safe_local": True,
    "auto_approve_local_maintenance": True,
    "manual_approval_ttl_seconds": 1800,
    "trusted_session_grant_ttl_seconds": 7200,
    "trust_level": "standard",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_json(document: Mapping[str, Any]) -> bytes:
    try:
        encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProvisioningError("CONFIG_INVALID", "The project registry cannot be encoded safely.", category="validation") from exc
    if len(encoded) > 1024 * 1024:
        raise ProvisioningError("CONFIG_INVALID", "The project registry exceeds the safety bound.", category="validation")
    return encoded


def validate_project_id(value: object, *, name: str = "project_id") -> str:
    if not isinstance(value, str) or not PROJECT_NAME_RE.fullmatch(value) or value in {".", ".."} or value.startswith("."):
        raise ProvisioningError("PROJECT_ID_INVALID", f"{name} must be a visible single path component using letters, numbers, '_', '-', or '.'.", category="validation")
    return value


def validate_intent(value: object) -> DevelopmentIntentSource:
    if value != DevelopmentIntentSource.EXPLICIT_USER_REQUEST.value:
        code = "READ_ONLY_PROMOTION_DENIED" if value in {"READ_ONLY", "DISCOVERY_ONLY", None, ""} else "EXPLICIT_DEVELOPMENT_INTENT_REQUIRED"
        raise ProvisioningError(code, "Development promotion requires an explicit user write intent claim.", category="permission")
    return DevelopmentIntentSource.EXPLICIT_USER_REQUEST


def _root_owner_safe(root: Path) -> Path:
    try:
        if root.is_symlink() or not root.is_dir():
            raise ProvisioningError("ROOT_NOT_FOUND", "The configured discovery root is unavailable.", category="not_found")
        resolved = root.resolve(strict=True)
        info = resolved.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ProvisioningError("UNSAFE_FILESYSTEM", "The discovery root ownership or permissions are unsafe.", category="security")
    except ProvisioningError:
        raise
    except OSError as exc:
        raise ProvisioningError("UNSAFE_FILESYSTEM", "The discovery root could not be verified.", category="security", details={"reason": str(exc)}) from exc
    return resolved


def validate_target_in_root(root: AllowedRoot, path: Path, *, allow_existing: bool = True) -> Path:
    if root.mode != PROJECT_DISCOVERY:
        raise ProvisioningError("ROOT_MODE_DENIED", "Project provisioning requires a PROJECT_DISCOVERY root.", category="permission")
    root_path = _root_owner_safe(root.path)
    try:
        lexical = Path(os.path.abspath(os.fspath(path)))
        if not is_within_root(root_path, lexical) or lexical == root_path:
            raise ProvisioningError("ROOT_ESCAPE_BLOCKED", "The project path must remain below the configured discovery root.", category="security")
        if any(part.startswith(".") for part in lexical.relative_to(root_path).parts):
            raise ProvisioningError("SENSITIVE_PATH_DENIED", "Hidden project paths are not eligible for DEVELOPMENT.", category="security")
        if lexical.is_symlink():
            raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "Symlink project paths are not eligible for DEVELOPMENT.", category="security")
        if lexical.exists() and not lexical.is_dir():
            raise ProvisioningError("PROJECT_PATH_INVALID", "The project target is not an ordinary directory.", category="validation")
        if not allow_existing and lexical.exists():
            raise ProvisioningError("PROJECT_ALREADY_EXISTS", "The project directory already exists.", category="conflict")
        if lexical.exists():
            resolved = lexical.resolve(strict=True)
            if resolved != lexical or not is_within_root(root_path, resolved):
                raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "The project path resolves outside the configured root.", category="security")
            info = resolved.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise ProvisioningError("UNSAFE_FILESYSTEM", "The project directory ownership or permissions are unsafe.", category="security")
            return resolved
        return lexical
    except ProvisioningError:
        raise
    except OSError as exc:
        raise ProvisioningError("UNSAFE_FILESYSTEM", "The project path could not be verified.", category="security", details={"reason": str(exc)}) from exc


def _fixed_git_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _git_probe(path: Path, *args: str) -> str | None:
    try:
        result = run_bounded(
            ["git", "-C", str(path), *args],
            env=_fixed_git_env(),
            timeout_seconds=15,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError):
        return None
    return result.stdout.strip() if not result.timed_out and not result.output_truncated and result.returncode == 0 else None


def repo_identity_payload(path: Path) -> dict[str, Any]:
    try:
        identity = capture_repo_identity(path)
    except Exception as exc:
        raise ProvisioningError("REPOSITORY_IDENTITY_UNKNOWN", "The project repository identity could not be verified.", category="security") from exc
    branch = _git_probe(path, "symbolic-ref", "--quiet", "--short", "HEAD") or "DETACHED"
    return {
        "source_path": str(identity.source_path),
        "git_root": str(identity.git_root),
        "device": identity.device,
        "inode": identity.inode,
        "head": identity.head,
        "branch": branch,
        "git_marker": identity.git_marker,
        "unborn_head": identity.head == UNBORN_HEAD,
        "dirty": repo_dirty(path),
        "remote": bool(_git_probe(path, "remote")),
    }


def _project_markers(path: Path) -> tuple[bool, bool]:
    try:
        names = {entry.name.casefold() for entry in os.scandir(path)}
    except OSError:
        return False, False
    return bool(names & {"pyproject.toml", "pytest.ini", "setup.cfg", "requirements.txt"}), bool("package.json" in names)


def detect_commands(path: Path) -> dict[str, str]:
    """Detect only commands backed by an observed project file/script."""

    commands: dict[str, str] = {}
    python_like, node_like = _project_markers(path)
    if python_like or (path / "tests").is_dir():
        venv_python = path / ".venv" / "bin" / "python"
        commands["test"] = ".venv/bin/python -m pytest" if venv_python.is_file() and not venv_python.is_symlink() and os.access(venv_python, os.X_OK) else "python3 -m pytest"
    package = path / "package.json"
    if node_like and package.is_file() and not package.is_symlink():
        try:
            document = json.loads(package.read_text(encoding="utf-8"))
            scripts = document.get("scripts", {}) if isinstance(document, dict) else {}
            if isinstance(scripts, dict):
                for task in TASK_NAMES:
                    if isinstance(scripts.get(task), str) and scripts[task].strip():
                        commands[task] = "npm test" if task == "test" else f"npm run {task}"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    return commands


def _open_root_fd(root: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(root, flags)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            os.close(fd)
            raise ProvisioningError("UNSAFE_FILESYSTEM", "The discovery root ownership or permissions are unsafe.", category="security")
        return fd
    except ProvisioningError:
        raise
    except OSError as exc:
        raise ProvisioningError("UNSAFE_FILESYSTEM", "The discovery root could not be opened safely.", category="security", details={"reason": str(exc)}) from exc


def create_project_directory(root: AllowedRoot, directory_name: str, *, project_type: str) -> Path:
    root_path = _root_owner_safe(root.path)
    fd = _open_root_fd(root_path)
    created = False
    target = root_path / directory_name
    target_fd: int | None = None
    try:
        try:
            os.mkdir(directory_name, mode=0o700, dir_fd=fd)
            created = True
        except FileExistsError:
            if (root_path / directory_name).is_symlink():
                raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "The project target is a symlink and cannot be reused.", category="security") from None
            raise ProvisioningError("PROJECT_ALREADY_EXISTS", "The project directory already exists.", category="conflict") from None
        except OSError as exc:
            raise ProvisioningError("PROJECT_DIRECTORY_CREATE_FAILED", "The project directory could not be created atomically.", category="runtime", details={"reason": str(exc)}) from exc
        if target.is_symlink() or not target.is_dir() or target.resolve(strict=True) != target:
            raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "The created project path failed its no-follow check.", category="security")
        target_fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        target_info = os.fstat(target_fd)
        if target_info.st_uid != os.getuid() or stat.S_IMODE(target_info.st_mode) & 0o022:
            raise ProvisioningError("UNSAFE_FILESYSTEM", "The created project directory ownership or permissions are unsafe.", category="security")
        for child_name in (("src", "tests") if project_type == "PYTHON" else ("src",) if project_type == "NODE" else ()):
            try:
                os.mkdir(child_name, mode=0o700, dir_fd=target_fd)
            except FileExistsError:
                raise ProvisioningError("PROJECT_TEMPLATE_CONFLICT", "The project template path is already occupied.", category="conflict") from None
            except OSError as exc:
                raise ProvisioningError("PROJECT_TEMPLATE_CREATE_FAILED", "The project template could not be created.", category="runtime", details={"reason": str(exc)}) from exc
        os.fchmod(target_fd, 0o700)
        return target
    except ProvisioningError:
        if created:
            _rollback_empty_project(target)
        raise
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(fd)


def _rollback_empty_project(target: Path) -> None:
    """Remove only directories this provisioning operation created."""

    try:
        if target.is_symlink() or not target.is_dir():
            return
        for child in sorted(target.iterdir(), reverse=True):
            if child.is_symlink() or not child.is_dir():
                return
            child.rmdir()
        target.rmdir()
    except OSError:
        # A race or user file makes rollback unsafe; leave the partial project
        # for explicit operator review rather than deleting unknown content.
        return


def initialize_local_git(path: Path) -> dict[str, Any]:
    marker = path / ".git"
    if marker.exists() or marker.is_symlink():
        return {"git_initialized": True, "created": False, "head": _git_probe(path, "rev-parse", "--verify", "HEAD") or UNBORN_HEAD, "remote": bool(_git_probe(path, "remote"))}
    try:
        result = run_bounded(
            ["git", "-C", str(path), "init", "-q", "-b", "main"],
            env=_fixed_git_env(),
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise ProvisioningError("LOCAL_GIT_INIT_FAILED", "Local Git initialization could not be completed.", category="runtime") from exc
    if result.timed_out or result.output_truncated or result.returncode != 0 or marker.is_symlink() or not marker.is_dir():
        raise ProvisioningError("LOCAL_GIT_INIT_FAILED", "Local Git initialization could not be completed.", category="runtime")
    return {"git_initialized": True, "created": True, "head": UNBORN_HEAD, "remote": False}


def create_project_group(root: AllowedRoot, directory_name: str) -> dict[str, Any]:
    """Create one plain organizational directory below a discovery root."""

    name = validate_project_id(directory_name, name="directory_name")
    if root.mode != PROJECT_DISCOVERY:
        raise ProvisioningError("ROOT_MODE_DENIED", "Project groups require a PROJECT_DISCOVERY root.", category="permission")
    root_path = _root_owner_safe(root.path)
    target = root_path / name
    try:
        if target.is_symlink():
            raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "Symlink project-group paths are not allowed.", category="security")
        if target.exists():
            if not target.is_dir():
                raise ProvisioningError("PROJECT_PATH_INVALID", "The project-group target is not an ordinary directory.", category="validation")
            resolved = target.resolve(strict=True)
            if resolved != target or not is_within_root(root_path, resolved):
                raise ProvisioningError("SYMLINK_ESCAPE_BLOCKED", "The project-group target resolves outside the configured root.", category="security")
            info = resolved.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise ProvisioningError("UNSAFE_FILESYSTEM", "The project-group directory ownership or permissions are unsafe.", category="security")
            return {
                "status": "already_exists",
                "created": False,
                "path": str(resolved),
                "root_id": root.id,
                "receipt": {
                    "receipt_id": f"provision:{secrets.token_urlsafe(12)}",
                    "status": "idempotent",
                    "recorded_at": _utc_now(),
                },
            }
        target.mkdir(mode=0o755, parents=False, exist_ok=False)
        resolved = target.resolve(strict=True)
        return {
            "status": "created",
            "created": True,
            "path": str(resolved),
            "root_id": root.id,
            "receipt": {
                "receipt_id": f"provision:{secrets.token_urlsafe(12)}",
                "status": "created",
                "recorded_at": _utc_now(),
            },
        }
    except ProvisioningError:
        raise
    except FileExistsError:
        raise ProvisioningError("PROJECT_ALREADY_EXISTS", "The project-group target appeared during creation.", category="conflict") from None
    except OSError as exc:
        raise ProvisioningError("PROJECT_GROUP_CREATE_FAILED", "The project-group directory could not be created safely.", category="runtime", details={"reason": str(exc)}) from exc


class RegistryMutationManager:
    """Atomically add only a single DEVELOPMENT workspace entry."""

    _locks: dict[str, threading.RLock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, path: Path, *, home: Path, validate_document: Callable[[Mapping[str, Any]], None] | None = None) -> None:
        self.path = Path(path).expanduser()
        self.home = home.resolve(strict=False)
        self._validate_document = validate_document

    def _lock(self) -> threading.RLock:
        key = str(self.path.absolute())
        with self._locks_guard:
            return self._locks.setdefault(key, threading.RLock())

    def _lock_file(self):
        parent = self.path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Pin every existing component of the operator-owned config path.
            # `/tmp` (and the macOS equivalent `/var`) are intentionally
            # allowed as test/runtime staging roots, but a project-controlled
            # symlink or group/world-writable component must never redirect a
            # registry mutation.
            probe = Path(parent.anchor)
            safe_shared = {Path("/"), Path("/tmp"), Path("/var"), Path("/private/tmp"), Path("/private/var")}
            for component in parent.parts[1:]:
                probe = probe / component
                info = os.lstat(probe)
                shared_component = probe in safe_shared
                if (stat.S_ISLNK(info.st_mode) and not shared_component) or (not stat.S_ISLNK(info.st_mode) and not stat.S_ISDIR(info.st_mode)):
                    raise OSError("config parent contains a symlink or non-directory component")
                if not shared_component and (info.st_uid not in {os.getuid(), 0} or stat.S_IMODE(info.st_mode) & 0o022):
                    raise OSError("config parent ownership or permissions are unsafe")
            lock_path = parent / f".{self.path.name}.lock"
            if lock_path.is_symlink():
                raise OSError("config lock is a symlink")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            handle = os.fdopen(descriptor, "a+", encoding="utf-8")
            lock_info = os.fstat(descriptor)
            if lock_info.st_uid != os.getuid() or not stat.S_ISREG(lock_info.st_mode) or stat.S_IMODE(lock_info.st_mode) & 0o022:
                handle.close()
                raise OSError("config lock ownership or permissions are unsafe")
            os.chmod(lock_path, 0o600)
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            return handle
        except OSError as exc:
            raise ProvisioningError("CONFIG_LOCK_FAILED", "The project registry lock could not be acquired.", category="runtime", details={"reason": str(exc)}) from exc

    def _snapshot(self) -> tuple[dict[str, Any], bytes, str, bool, int]:
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return {"version": 1, "roots": [{"id": "developer", "path": "~/Developer", "mode": PROJECT_DISCOVERY}], "workspaces": {}}, b"", "", False, 0o600
        except OSError as exc:
            raise ProvisioningError("CONFIG_IDENTITY_CHANGED", "The project registry could not be inspected safely.", category="runtime", details={"reason": str(exc)}) from None
        try:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ProvisioningError("CONFIG_IDENTITY_CHANGED", "The project registry must be a regular operator-owned file.", category="security")
            raw = self.path.read_bytes()
            document = json.loads(raw.decode("utf-8"))
        except ProvisioningError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvisioningError("CONFIG_INVALID", "The project registry is not valid UTF-8 JSON.", category="validation", details={"reason": str(exc)}) from exc
        if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(document.get("workspaces", {}), dict):
            raise ProvisioningError("CONFIG_INVALID", "The project registry schema is unsupported.", category="validation")
        return document, raw, _digest(raw), True, stat.S_IMODE(info.st_mode)

    def snapshot(self) -> tuple[dict[str, Any], bytes, str, bool, int]:
        """Return a validated registry snapshot for a read-only preflight.

        The tuple deliberately includes the raw bytes and digest.  Callers
        must pass the digest back through the mutation boundary; a parsed
        document alone is not a sufficient concurrency pin.
        """

        with self._lock():
            document, raw, digest, existed, mode = self._snapshot()
            return copy.deepcopy(document), bytes(raw), digest, existed, mode

    def _atomic_write_document(
        self,
        *,
        document: Mapping[str, Any],
        previous_raw: bytes,
        previous_digest: str,
        previous_existed: bool,
        mode: int,
        changed_keys: list[str],
    ) -> tuple[str, dict[str, Any]]:
        """Write one already-validated registry candidate and read it back.

        The cooperative lock is supplemented by a final byte-for-byte
        snapshot check so an operator edit that does not use this process's
        lock cannot be silently overwritten.  Rollback is limited to the
        exact bytes written by this call.
        """

        if self._validate_document is not None:
            try:
                self._validate_document(document)
            except ProvisioningError:
                raise
            except Exception as exc:
                raise ProvisioningError(
                    "CONFIG_INVALID",
                    "The updated project registry failed schema validation.",
                    category="validation",
                    details={"reason": str(exc)},
                ) from exc

        current_document, current_raw, current_digest, current_existed, current_mode = self._snapshot()
        if (
            current_digest != previous_digest
            or current_raw != previous_raw
            or current_existed != previous_existed
            or (previous_existed and current_mode != mode)
        ):
            raise ProvisioningError(
                "CONFIG_CHANGED",
                "The project registry changed after the preflight snapshot was captured.",
                category="conflict",
                details={"current_digest": current_digest},
            )
        encoded = _safe_json(document)
        temporary: str | None = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
            os.fchmod(fd, mode or 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            temporary = None
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise ProvisioningError(
                "CONFIG_WRITE_FAILED",
                "The project registry could not be updated atomically.",
                category="runtime",
                details={"reason": str(exc)},
            ) from exc

        expected_digest = _digest(encoded)
        try:
            _read_back_document, read_back, read_back_digest, read_back_existed, _read_back_mode = self._snapshot()
            if not read_back_existed or read_back_digest != expected_digest:
                raise ValueError("read-back digest mismatch")
        except Exception as exc:
            # Never restore over a subsequent operator edit.
            try:
                current_readback = self._snapshot()
                if current_readback[3] and current_readback[2] == expected_digest:
                    if previous_existed:
                        restore_fd, restore_path = tempfile.mkstemp(prefix=f".{self.path.name}.restore-", dir=str(self.path.parent))
                        try:
                            os.fchmod(restore_fd, mode or 0o600)
                            with os.fdopen(restore_fd, "wb") as restore_stream:
                                restore_fd = -1
                                restore_stream.write(previous_raw)
                                restore_stream.flush()
                                os.fsync(restore_stream.fileno())
                            os.replace(restore_path, self.path)
                            restore_path = ""
                            directory_fd = os.open(self.path.parent, os.O_RDONLY)
                            try:
                                os.fsync(directory_fd)
                            finally:
                                os.close(directory_fd)
                        finally:
                            if restore_path:
                                try:
                                    os.unlink(restore_path)
                                except OSError:
                                    pass
                            if restore_fd >= 0:
                                os.close(restore_fd)
                    else:
                        self.path.unlink()
            except (OSError, ProvisioningError):
                pass
            raise ProvisioningError(
                "CONFIG_READBACK_FAILED",
                "The project registry update failed read-back validation.",
                category="runtime",
                details={"reason": str(exc)},
            ) from exc
        receipt = {
            "receipt_id": f"provision:{secrets.token_urlsafe(12)}",
            "status": "succeeded",
            "before_config_digest": previous_digest,
            "after_config_digest": expected_digest,
            "recorded_at": _utc_now(),
            "changed_keys": list(changed_keys),
        }
        return expected_digest, receipt

    def _validate_root(self, document: Mapping[str, Any], root_id: str, path: Path) -> AllowedRoot:
        roots, errors = load_allowed_roots(dict(document), self.home)
        if errors:
            # Existing unrelated root errors do not authorize a write; the
            # selected root must be present and valid while the caller gets the
            # errors back through the normal registry diagnostics.
            selected_error = next((item for item in errors if item.get("id") == root_id), None)
            if selected_error is not None:
                raise ProvisioningError("ROOT_INVALID", "The selected discovery root is invalid.", category="security", details=selected_error)
        selected = next((item for item in roots if item.id == root_id), None)
        if selected is None or selected.mode != PROJECT_DISCOVERY:
            raise ProvisioningError("ROOT_NOT_FOUND", "The selected PROJECT_DISCOVERY root is not configured.", category="not_found", details={"root_id": root_id})
        validate_target_in_root(selected, path)
        return selected

    @staticmethod
    def _check_overlaps(workspaces: Mapping[str, Any], workspace_id: str, path: Path) -> None:
        target = path.resolve(strict=False)
        for identifier, raw in workspaces.items():
            if identifier == workspace_id or not isinstance(raw, Mapping) or not isinstance(raw.get("path"), str):
                continue
            other = Path(os.path.expandvars(raw["path"])).expanduser().resolve(strict=False)
            if target == other or target.is_relative_to(other) or other.is_relative_to(target):
                raise ProvisioningError("WORKSPACE_PATH_CONFLICT", "The project path overlaps another registered workspace.", category="conflict", details={"workspace_id": str(identifier)})

    def add_workspace(
        self,
        *,
        workspace_id: str,
        path: Path,
        root_id: str,
        intent_source: DevelopmentIntentSource,
        provisioning_mode: ProjectProvisioningMode,
        commands: Mapping[str, str],
        repo_identity: Mapping[str, Any],
        expected_config_digest: str | None = None,
    ) -> RegistryMutationResult:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if intent_source is not DevelopmentIntentSource.EXPLICIT_USER_REQUEST:
            raise ProvisioningError("EXPLICIT_DEVELOPMENT_INTENT_REQUIRED", "Only an explicit user write request can promote a project.", category="permission")
        normalized_commands: dict[str, str] = {}
        for task, command in commands.items():
            if task not in TASK_NAMES or not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND_LENGTH or "\n" in command or "\r" in command:
                raise ProvisioningError("COMMAND_PROFILE_INVALID", "Detected project commands failed the bounded command schema.", category="validation")
            normalized_commands[task] = command.strip()
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if expected_config_digest is not None and expected_config_digest != before_digest:
                    raise ProvisioningError("CONFIG_CHANGED", "The project registry changed after the expected digest was captured.", category="conflict", details={"current_digest": before_digest})
                workspaces = document.setdefault("workspaces", {})
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                canonical = validate_target_in_root(self._validate_root(document, root_id, path), path)
                existing = workspaces.get(identifier)
                if isinstance(existing, Mapping):
                    existing_path = Path(os.path.expandvars(str(existing.get("path", "")))).expanduser().resolve(strict=False)
                    if existing_path == canonical and existing.get("profile") == "DEVELOPMENT":
                        current_commands = dict(existing.get("commands", {})) if isinstance(existing.get("commands"), Mapping) else {}
                        policy = dict(existing.get("isolated_development", {})) if isinstance(existing.get("isolated_development"), Mapping) else dict(DEFAULT_ISOLATED_POLICY)
                        return RegistryMutationResult(identifier, canonical, False, "DEVELOPMENT", current_commands, policy, before_digest, before_digest, {"receipt_id": f"provision:{secrets.token_urlsafe(12)}", "status": "idempotent", "before_config_digest": before_digest, "after_config_digest": before_digest, "recorded_at": _utc_now()}, dict(repo_identity), root_id, intent_source, provisioning_mode)
                    raise ProvisioningError("WORKSPACE_ID_CONFLICT", "workspace_id is already bound to a different registry entry.", category="conflict")
                self._check_overlaps(workspaces, identifier, canonical)
                workspaces[identifier] = {
                    "path": str(canonical),
                    "profile": "DEVELOPMENT",
                    "isolated_development": dict(DEFAULT_ISOLATED_POLICY),
                    "commands": dict(normalized_commands),
                }
                if self._validate_document is not None:
                    try:
                        self._validate_document(document)
                    except Exception as exc:
                        raise ProvisioningError("CONFIG_INVALID", "The updated project registry failed schema validation.", category="validation", details={"reason": str(exc)}) from exc
                encoded = _safe_json(document)
                temporary: str | None = None
                try:
                    fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
                    os.fchmod(fd, mode or 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, self.path)
                    temporary = None
                    directory_fd = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError as exc:
                    if temporary is not None:
                        try:
                            os.unlink(temporary)
                        except OSError:
                            pass
                    raise ProvisioningError("CONFIG_WRITE_FAILED", "The project registry could not be updated atomically.", category="runtime", details={"reason": str(exc)}) from exc
                try:
                    read_back = self.path.read_bytes()
                    read_back_document = json.loads(read_back.decode("utf-8"))
                    if _digest(read_back) != _digest(encoded) or not isinstance(read_back_document, dict):
                        raise ValueError("read-back digest mismatch")
                    if self._validate_document is not None:
                        self._validate_document(read_back_document)
                except Exception as exc:
                    # Restore only the exact file produced above; never
                    # overwrite a concurrent operator update.
                    try:
                        if self.path.exists() and _digest(self.path.read_bytes()) == _digest(encoded):
                            if existed:
                                restore_fd, restore_path = tempfile.mkstemp(prefix=f".{self.path.name}.restore-", dir=str(self.path.parent))
                                try:
                                    os.fchmod(restore_fd, mode or 0o600)
                                    with os.fdopen(restore_fd, "wb") as restore_stream:
                                        restore_fd = -1
                                        restore_stream.write(raw)
                                        restore_stream.flush()
                                        os.fsync(restore_stream.fileno())
                                    os.replace(restore_path, self.path)
                                    restore_path = ""
                                    directory_fd = os.open(self.path.parent, os.O_RDONLY)
                                    try:
                                        os.fsync(directory_fd)
                                    finally:
                                        os.close(directory_fd)
                                finally:
                                    if restore_path:
                                        try:
                                            os.unlink(restore_path)
                                        except OSError:
                                            pass
                                    if restore_fd >= 0:
                                        os.close(restore_fd)
                            else:
                                self.path.unlink()
                    except OSError:
                        pass
                    raise ProvisioningError("CONFIG_READBACK_FAILED", "The project registry update failed read-back validation.", category="runtime", details={"reason": str(exc)}) from exc
                after_digest = _digest(encoded)
                receipt = {
                    "receipt_id": f"provision:{secrets.token_urlsafe(12)}",
                    "status": "succeeded",
                    "before_config_digest": before_digest,
                    "after_config_digest": after_digest,
                    "recorded_at": _utc_now(),
                    "changed_keys": [f"workspaces.{identifier}"],
                }
                return RegistryMutationResult(identifier, canonical, True, "DEVELOPMENT", normalized_commands, dict(DEFAULT_ISOLATED_POLICY), before_digest, after_digest, receipt, dict(repo_identity), root_id, intent_source, provisioning_mode)
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    lock_handle.close()
                except OSError:
                    pass

    @staticmethod
    def _apply_policy_patch(entry: dict[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(patch, Mapping) or not patch:
            raise ProvisioningError("INVALID_POLICY_VALUE", "isolated_development must contain at least one allowlisted key.", category="validation")
        allowed = frozenset(DEFAULT_ISOLATED_POLICY)
        unknown = sorted((key for key in patch if not isinstance(key, str) or key not in allowed), key=str)
        if unknown:
            raise ProvisioningError("UNKNOWN_POLICY_KEY", "The requested registration policy contains an unsupported key.", category="permission", details={"keys": unknown})
        location = "isolated_development"
        raw_metadata = entry.get("metadata")
        if "isolated_development" not in entry and isinstance(raw_metadata, Mapping) and "isolated_development" in raw_metadata:
            location = "metadata"
            raw_policy = raw_metadata.get("isolated_development")
        else:
            raw_policy = entry.get("isolated_development")
        if not isinstance(raw_policy, Mapping):
            raw_policy = {}
        before = dict(DEFAULT_ISOLATED_POLICY)
        before.update(raw_policy)
        candidate = dict(raw_policy)
        for key, value in patch.items():
            if key in {"auto_create_sessions", "auto_resume_sessions", "allow_workspace_wide", "integration_requires_approval", "commit_requires_approval", "push_requires_approval", "verified_auto_commit", "auto_approve_safe_local", "auto_approve_local_maintenance"}:
                if not isinstance(value, bool):
                    raise ProvisioningError("INVALID_POLICY_VALUE", f"{key} must be boolean.", category="validation")
            elif key == "auto_resume_policy":
                if value != "same_owner_same_task_safe_local":
                    raise ProvisioningError("INVALID_POLICY_VALUE", "auto_resume_policy is not supported.", category="validation")
            elif key == "allowed_base":
                if value != "registered_project":
                    raise ProvisioningError("INVALID_POLICY_VALUE", "allowed_base is not supported.", category="validation")
            elif key == "max_parallel_sessions":
                if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 16:
                    raise ProvisioningError("INVALID_POLICY_VALUE", "max_parallel_sessions is outside the safe bound.", category="validation")
            elif key == "manual_approval_ttl_seconds":
                if isinstance(value, bool) or not isinstance(value, int) or not 60 <= value <= 3600:
                    raise ProvisioningError("INVALID_POLICY_VALUE", "manual_approval_ttl_seconds is outside the safe bound.", category="validation")
            elif key == "trusted_session_grant_ttl_seconds":
                if isinstance(value, bool) or not isinstance(value, int) or not 60 <= value <= 7200:
                    raise ProvisioningError("INVALID_POLICY_VALUE", "trusted_session_grant_ttl_seconds is outside the safe bound.", category="validation")
            elif key == "trust_level":
                if value not in {"standard", "trusted_development"}:
                    raise ProvisioningError("INVALID_POLICY_VALUE", "trust_level is not supported.", category="validation")
            candidate[key] = value
        if before.get("trust_level", "standard") != "trusted_development" and candidate.get("trust_level", before.get("trust_level")) == "trusted_development":
            raise ProvisioningError(
                "REGISTRATION_POLICY_DOWNGRADE_DENIED",
                "Trusted DEVELOPMENT must be enabled through the dedicated workspace-trust approval lifecycle.",
                category="permission",
                details={"key": "trust_level"},
            )
        for key in ("integration_requires_approval", "commit_requires_approval", "push_requires_approval"):
            if before.get(key) is True and candidate.get(key, before.get(key)) is False:
                raise ProvisioningError("REGISTRATION_POLICY_DOWNGRADE_DENIED", "Approval requirements cannot be downgraded by registration update.", category="permission", details={"key": key})
        effective = dict(DEFAULT_ISOLATED_POLICY)
        effective.update(candidate)
        if location == "metadata":
            metadata = dict(raw_metadata) if isinstance(raw_metadata, Mapping) else {}
            metadata["isolated_development"] = candidate
            entry["metadata"] = metadata
        else:
            entry["isolated_development"] = candidate
        return effective

    @staticmethod
    def _normalize_command_patch(patch: Mapping[str, Any]) -> dict[str, str]:
        if not isinstance(patch, Mapping) or not patch:
            raise ProvisioningError("COMMAND_PROFILE_INVALID", "commands must contain at least one allowlisted task.", category="validation")
        normalized: dict[str, str] = {}
        for task, raw_command in patch.items():
            if task not in TASK_NAMES or not isinstance(raw_command, str):
                raise ProvisioningError("COMMAND_PROFILE_INVALID", "commands contains an unsupported task or value.", category="validation")
            command = raw_command.strip()
            if not command or len(command) > MAX_COMMAND_LENGTH or COMMAND_COMPOSITION_RE.search(command) or contains_secret_like_content(command):
                raise ProvisioningError("COMMAND_PROFILE_INVALID", "commands contains unsafe or secret-like command text.", category="validation")
            normalized[task] = command
        return normalized

    def update_workspace_registration(
        self,
        *,
        workspace_id: str,
        new_workspace_id: str | None = None,
        isolated_development_patch: Mapping[str, Any] | None = None,
        commands_patch: Mapping[str, Any] | None = None,
        expected_config_digest: str | None = None,
        expected_path: Path | None = None,
    ) -> dict[str, Any]:
        """Atomically rename one entry and/or patch bounded policy/commands."""

        identifier = validate_project_id(workspace_id, name="workspace_id")
        new_identifier = validate_project_id(new_workspace_id, name="new_workspace_id") if new_workspace_id is not None else identifier
        normalized_command_patch = self._normalize_command_patch(commands_patch) if commands_patch is not None else None
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if expected_config_digest is not None and expected_config_digest != before_digest:
                    raise ProvisioningError("CONFIG_CHANGED", "The project registry changed after the preflight snapshot was captured.", category="conflict", details={"current_digest": before_digest})
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                existing = workspaces.get(identifier)
                if not isinstance(existing, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                existing_path = Path(os.path.expandvars(str(existing.get("path", "")))).expanduser().resolve(strict=False)
                if expected_path is not None and existing_path != expected_path.resolve(strict=False):
                    raise ProvisioningError("WORKSPACE_SOURCE_CHANGED", "The registered workspace path changed after preflight.", category="security")
                if new_identifier != identifier and new_identifier in workspaces:
                    raise ProvisioningError("WORKSPACE_ID_CONFLICT", "new_workspace_id is already registered.", category="conflict")
                candidate = copy.deepcopy(document)
                candidate_workspaces = candidate["workspaces"]
                candidate_entry = copy.deepcopy(candidate_workspaces[identifier])
                before_policy = dict(DEFAULT_ISOLATED_POLICY)
                raw_policy = candidate_entry.get("isolated_development")
                if not isinstance(raw_policy, Mapping) and isinstance(candidate_entry.get("metadata"), Mapping):
                    raw_policy = candidate_entry["metadata"].get("isolated_development")
                if isinstance(raw_policy, Mapping):
                    before_policy.update(raw_policy)
                after_policy = before_policy
                if isolated_development_patch is not None:
                    if candidate_entry.get("profile", "READ_ONLY") != "DEVELOPMENT":
                        raise ProvisioningError("REGISTRATION_POLICY_UPDATE_DENIED", "Only DEVELOPMENT registrations may update isolated_development.", category="permission")
                    after_policy = self._apply_policy_patch(candidate_entry, isolated_development_patch)
                commands_changed = False
                if normalized_command_patch is not None:
                    if candidate_entry.get("profile", "READ_ONLY") != "DEVELOPMENT":
                        raise ProvisioningError("REGISTRATION_COMMAND_UPDATE_DENIED", "Only DEVELOPMENT registrations may update commands.", category="permission")
                    raw_commands = candidate_entry.get("commands")
                    current_commands = dict(raw_commands) if isinstance(raw_commands, Mapping) else {}
                    updated_commands = dict(current_commands)
                    updated_commands.update(normalized_command_patch)
                    commands_changed = updated_commands != current_commands
                    candidate_entry["commands"] = updated_commands
                if new_identifier != identifier:
                    candidate_workspaces.pop(identifier)
                    candidate_workspaces[new_identifier] = candidate_entry
                else:
                    candidate_workspaces[identifier] = candidate_entry
                if new_identifier == identifier and isolated_development_patch is None and not commands_changed:
                    return {
                        "workspace_id": identifier,
                        "previous_workspace_id": identifier,
                        "path": str(existing_path),
                        "profile": str(existing.get("profile", "READ_ONLY")),
                        "changed": False,
                        "policy": before_policy,
                        "commands": sorted(existing.get("commands", {})) if isinstance(existing.get("commands"), Mapping) else [],
                        "config_digest": before_digest,
                        "receipt": {"receipt_id": f"provision:{secrets.token_urlsafe(12)}", "status": "idempotent", "before_config_digest": before_digest, "after_config_digest": before_digest, "recorded_at": _utc_now(), "changed_keys": []},
                    }
                changed_keys: list[str] = []
                if new_identifier != identifier:
                    changed_keys.append(f"workspaces.{identifier}.workspace_id")
                if isolated_development_patch is not None:
                    changed_keys.append(f"workspaces.{new_identifier}.isolated_development")
                if commands_changed:
                    changed_keys.append(f"workspaces.{new_identifier}.commands")
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=changed_keys,
                )
                return {
                    "workspace_id": new_identifier,
                    "previous_workspace_id": identifier,
                    "path": str(existing_path),
                    "profile": str(existing.get("profile", "READ_ONLY")),
                    "changed": True,
                    "policy": after_policy,
                    "commands": sorted(candidate_entry.get("commands", {})) if isinstance(candidate_entry.get("commands"), Mapping) else [],
                    "config_digest": after_digest,
                    "receipt": receipt,
                }
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    lock_handle.close()
                except OSError:
                    pass

    def remove_workspace(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str | None = None,
        expected_path: Path | None = None,
    ) -> dict[str, Any]:
        """Atomically remove only a registry entry; never touch its repo."""

        identifier = validate_project_id(workspace_id, name="workspace_id")
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if expected_config_digest is not None and expected_config_digest != before_digest:
                    raise ProvisioningError("CONFIG_CHANGED", "The project registry changed after the preflight snapshot was captured.", category="conflict", details={"current_digest": before_digest})
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                existing = workspaces.get(identifier)
                if not isinstance(existing, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                existing_path = Path(os.path.expandvars(str(existing.get("path", "")))).expanduser().resolve(strict=False)
                if expected_path is not None and existing_path != expected_path.resolve(strict=False):
                    raise ProvisioningError("WORKSPACE_SOURCE_CHANGED", "The registered workspace path changed after preflight.", category="security")
                candidate = copy.deepcopy(document)
                candidate["workspaces"].pop(identifier)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}"],
                )
                return {
                    "workspace_id": identifier,
                    "path": str(existing_path),
                    "profile": str(existing.get("profile", "READ_ONLY")),
                    "removed": True,
                    "repository_deleted": False,
                    "config_digest": after_digest,
                    "receipt": receipt,
                }
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    lock_handle.close()
                except OSError:
                    pass

    def relocate_workspace_path(
        self,
        workspace_id: str,
        *,
        expected_old_path: Path,
        new_path: Path,
        expected_config_digest: str,
    ) -> dict[str, Any]:
        """Atomically mutate only one registered workspace path."""

        identifier = validate_project_id(workspace_id, name="workspace_id")
        expected_old = Path(expected_old_path).expanduser().resolve(strict=False)
        replacement = Path(new_path).expanduser().resolve(strict=False)
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if expected_config_digest != before_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the preflight snapshot was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                existing = workspaces.get(identifier)
                if not isinstance(existing, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                existing_path = Path(os.path.expandvars(str(existing.get("path", "")))).expanduser().resolve(strict=False)
                if existing_path != expected_old:
                    raise ProvisioningError("WORKSPACE_SOURCE_CHANGED", "The registered workspace path changed after preflight.", category="security")
                if replacement == existing_path:
                    return {
                        "workspace_id": identifier,
                        "previous_path": str(existing_path),
                        "path": str(existing_path),
                        "changed": False,
                        "config_digest": before_digest,
                        "receipt": {
                            "receipt_id": f"provision:{secrets.token_urlsafe(12)}",
                            "status": "idempotent",
                            "before_config_digest": before_digest,
                            "after_config_digest": before_digest,
                            "recorded_at": _utc_now(),
                            "changed_keys": [],
                        },
                    }
                candidate = copy.deepcopy(document)
                candidate_entry = copy.deepcopy(candidate["workspaces"][identifier])
                candidate_entry["path"] = str(replacement)
                candidate["workspaces"][identifier] = candidate_entry
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.path"],
                )
                return {
                    "workspace_id": identifier,
                    "previous_path": str(existing_path),
                    "path": str(replacement),
                    "changed": True,
                    "config_digest": after_digest,
                    "receipt": receipt,
                }
            finally:
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    lock_handle.close()
                except OSError:
                    pass


__all__ = [
    "DEFAULT_ISOLATED_POLICY",
    "DevelopmentIntentSource",
    "ProjectProvisioningMode",
    "ProvisioningError",
    "RegistryMutationManager",
    "RegistryMutationResult",
    "create_project_group",
    "create_project_directory",
    "detect_commands",
    "initialize_local_git",
    "repo_identity_payload",
    "validate_intent",
    "validate_project_id",
    "validate_target_in_root",
]
