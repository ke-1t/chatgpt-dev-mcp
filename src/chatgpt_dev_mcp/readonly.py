"""Bounded READ_ONLY directory capabilities with optional durable handles."""

from __future__ import annotations

from collections import deque
import errno
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .persistence import (
    PersistenceError,
    ReadOnlyRootCapacityError,
    ReadOnlyRootConflictError,
)


ROOT_TTL_SECONDS = 15 * 60
MAX_ROOTS = 64
MAX_ROOT_ID_HISTORY = 128
MAX_PATH_LENGTH = 4096
MAX_RESULTS = 100
MAX_DEPTH = 4
MAX_VISITED_DIRECTORIES = 2000
MAX_ENTRIES_PER_DIRECTORY = 256
MAX_SEARCH_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_LINES = 2000

_SENSITIVE_NAMES = frozenset({
    ".aws", ".config", ".gnupg", ".ssh", "authorized_keys", "browser profile",
    "browser profiles", "chrome", "chromium", "credentials", "firefox", "keychain",
    "keychains", "known_hosts", "login data", "mozilla", "oauth", "safari", "secrets",
    "session", "sessions", "token", "tokens", "user data",
})
_SENSITIVE_BASENAME = re.compile(
    r"^(?:\.env(?:\..*)?|auth(?:entication)?\.json|id_(?:rsa|dsa|ecdsa|ed25519)|credentials(?:\..*)?|"
    r"secrets?(?:\..*)?|.*\.(?:pem|key|p12|pfx|kdbx))$", re.IGNORECASE,
)
_SECRET_CONTENT = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{12,})\b|"
    r"(?i:\b(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*\S+)"
)


class ReadOnlyPathError(Exception):
    def __init__(self, code: str, message: str, *, category: str = "security", details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.details = details or {}


@dataclass
class ReadOnlyRoot:
    root_id: str
    requested_path: Path
    canonical_path: Path
    device: int
    inode: int
    created_at: float
    last_accessed_at: float
    expires_at: float
    label: str | None = None
    state: str = "active"
    policy_enforced: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "root_id": self.root_id,
            "path": _display_path(self.canonical_path),
            "label": self.label,
            "created_at": _iso(self.created_at),
            "last_accessed_at": _iso(self.last_accessed_at),
            "expires_at": _iso(self.expires_at),
            "readonly": True,
            "state": self.state,
        }


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _display_path(path: Path) -> str:
    home = Path.home().resolve(strict=False)
    try:
        relative = path.relative_to(home)
    except ValueError:
        return str(path)
    return "~" if str(relative) == "." else str(Path("~") / relative)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _sensitive_name(name: str) -> bool:
    folded = name.casefold()
    return name.startswith(".") or folded in _SENSITIVE_NAMES or bool(_SENSITIVE_BASENAME.fullmatch(name))


def _expand_path(value: object) -> Path:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_PATH_LENGTH or "\x00" in value:
        raise ReadOnlyPathError("PATH_INVALID", "path must be a bounded local directory path.", category="validation")
    text = value.strip()
    home = str(Path.home().resolve(strict=False))
    if text == "$HOME":
        text = home
    elif text.startswith("$HOME/"):
        text = home + text[5:]
    elif text == "${HOME}":
        text = home
    elif text.startswith("${HOME}/"):
        text = home + text[7:]
    if "$" in text or (text.startswith("~") and text != "~" and not text.startswith("~/")):
        raise ReadOnlyPathError("PATH_INVALID", "Only the current user's home expansion is supported.", category="validation")
    return Path(os.path.expanduser(text)).absolute()


def _validate_root_policy(path: Path) -> None:
    resolved = path.resolve(strict=False)
    home = Path.home().resolve(strict=False)
    # The operator may inspect the Codex storage root itself, but child
    # traversal remains bounded by the hidden/credential filters below.
    if resolved == (home / ".codex").resolve(strict=False):
        return
    if any(_sensitive_name(part) for part in resolved.parts if part not in {"/", ""}):
        raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Credential-like, hidden, browser, and private-store roots are denied.")
    for denied in (Path("/"), Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"), Path("/etc"), Path("/private/etc")):
        if resolved == denied or (denied != Path("/") and _within(resolved, denied)):
            raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Broad or OS-managed roots are denied.")

    allowed = False
    for base in (home / "Desktop", home / "Documents", home / "Downloads", home / "Developer"):
        base = base.resolve(strict=False)
        if _within(resolved, base):
            if resolved == base:
                raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Open a specific child directory, not a broad user root.")
            allowed = True
            break

    library = (home / "Library").resolve(strict=False)
    app_support = (library / "Application Support").resolve(strict=False)
    if _within(resolved, app_support):
        if resolved == app_support:
            raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Open a specific app directory, not broad Application Support.")
        allowed = True
    elif _within(resolved, library):
        raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Only a specific Application Support app directory is permitted under Library.")

    applications = Path("/Applications")
    if _within(resolved, applications):
        relative = resolved.relative_to(applications)
        if resolved == applications or not relative.parts or not relative.parts[0].casefold().endswith(".app"):
            raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Only a specific application bundle is permitted.")
        allowed = True

    volumes = Path("/Volumes")
    if _within(resolved, volumes):
        if resolved == volumes:
            raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "Open a specific external-volume directory, not broad /Volumes.")
        allowed = True
    if not allowed:
        raise ReadOnlyPathError("PATH_SENSITIVE_DENIED", "The requested directory is outside the bounded READ_ONLY policy.")


def _relative_parts(value: object, *, file_required: bool = False) -> list[str]:
    if not isinstance(value, str) or "\x00" in value or len(value) > MAX_PATH_LENGTH:
        raise ReadOnlyPathError("PATH_ESCAPE_DENIED", "Only bounded relative paths are accepted.")
    normalized = value.replace("\\", "/").strip()
    if normalized in {"", "."}:
        if file_required:
            raise ReadOnlyPathError("FILE_NOT_REGULAR", "A file path is required.", category="validation")
        return []
    if normalized.startswith("/"):
        raise ReadOnlyPathError("PATH_ESCAPE_DENIED", "Absolute child paths are denied.")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ReadOnlyPathError("PATH_ESCAPE_DENIED", "Parent traversal is denied.")
    if any(_sensitive_name(part) for part in parts):
        raise ReadOnlyPathError("FILE_SENSITIVE_DENIED" if file_required else "PATH_SENSITIVE_DENIED", "Hidden and credential-like paths are denied.")
    return parts


def _flags(*, directory: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


class ReadOnlyPathManager:
    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        ttl_seconds: int = ROOT_TTL_SECONDS,
        persistence: Any | None = None,
    ) -> None:
        self._clock = clock or time.time
        self._ttl = max(1, min(int(ttl_seconds), ROOT_TTL_SECONDS))
        self._persistence = persistence
        self._roots: dict[str, ReadOnlyRoot] = {}
        self._closed_ids: deque[str] = deque(maxlen=MAX_ROOT_ID_HISTORY)
        self._lock = threading.RLock()

    def _now(self) -> float:
        return float(self._clock())

    def _expire(self) -> None:
        now = self._now()
        for root in self._roots.values():
            if root.state == "active" and root.expires_at <= now:
                root.state = "expired"

    def _prune_inactive(self) -> None:
        """Keep process-local root metadata bounded after expiry or replacement."""

        for root_id, root in tuple(self._roots.items()):
            if root.state in {"closed", "expired"}:
                self._roots.pop(root_id, None)
        if len(self._roots) > MAX_ROOTS:
            for root_id, root in tuple(self._roots.items()):
                if root.state == "stale":
                    self._roots.pop(root_id, None)
                    if len(self._roots) <= MAX_ROOTS:
                        break

    def _new_id(self) -> str:
        for _ in range(8):
            root_id = f"readonly:{secrets.token_urlsafe(18)}"
            if root_id not in self._roots and root_id not in self._closed_ids:
                return root_id
        raise ReadOnlyPathError("ROOT_LIMIT_REACHED", "No ephemeral READ_ONLY root capacity is available.", category="conflict")

    @staticmethod
    def _persistence_record(root: ReadOnlyRoot) -> dict[str, object]:
        return {
            "root_id": root.root_id,
            "requested_path": str(root.requested_path),
            "canonical_path": str(root.canonical_path),
            "device": root.device,
            "inode": root.inode,
            "created_at": root.created_at,
            "last_accessed_at": root.last_accessed_at,
            "expires_at": root.expires_at,
            "label": root.label or "",
            "state": root.state,
            "updated_at": root.created_at,
        }

    @staticmethod
    def _root_from_persistence(record: dict[str, object]) -> ReadOnlyRoot:
        try:
            return ReadOnlyRoot(
                str(record["root_id"]),
                Path(str(record["requested_path"])),
                Path(str(record["canonical_path"])),
                int(record["device"]),
                int(record["inode"]),
                float(record["created_at"]),
                float(record["last_accessed_at"]),
                float(record["expires_at"]),
                str(record.get("label") or "") or None,
                str(record["state"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReadOnlyPathError(
                "ROOT_PERSISTENCE_UNAVAILABLE",
                "The durable READ_ONLY root record is invalid.",
                category="runtime",
            ) from exc

    def _persist_open(self, root: ReadOnlyRoot) -> None:
        if self._persistence is None:
            return
        for _ in range(8):
            try:
                self._persistence.save_readonly_root(
                    self._persistence_record(root),
                    now=root.created_at,
                    max_active=MAX_ROOTS,
                    max_history=MAX_ROOT_ID_HISTORY,
                )
                return
            except ReadOnlyRootConflictError:
                root.root_id = self._new_id()
                continue
            except ReadOnlyRootCapacityError as exc:
                raise ReadOnlyPathError(
                    "ROOT_LIMIT_REACHED",
                    "Too many ephemeral READ_ONLY roots are open.",
                    category="conflict",
                ) from exc
            except PersistenceError as exc:
                raise ReadOnlyPathError(
                    "ROOT_PERSISTENCE_UNAVAILABLE",
                    "The durable READ_ONLY root could not be recorded safely.",
                    category="runtime",
                ) from exc
        raise ReadOnlyPathError(
            "ROOT_LIMIT_REACHED",
            "No ephemeral READ_ONLY root identity is available.",
            category="conflict",
        )

    def open(self, raw_path: object, label: object = None) -> dict[str, object]:
        with self._lock:
            self._expire()
            self._prune_inactive()
            if self._persistence is None and sum(root.state == "active" for root in self._roots.values()) >= MAX_ROOTS:
                raise ReadOnlyPathError("ROOT_LIMIT_REACHED", "Too many ephemeral READ_ONLY roots are open.", category="conflict")
            requested = _expand_path(raw_path)
            try:
                requested_stat = os.lstat(requested)
                if stat.S_ISLNK(requested_stat.st_mode):
                    raise ReadOnlyPathError("PATH_ESCAPE_DENIED", "Symlink roots are denied.")
                canonical = Path(os.path.realpath(requested))
                identity = os.stat(canonical)
            except ReadOnlyPathError:
                raise
            except FileNotFoundError:
                raise ReadOnlyPathError("PATH_NOT_FOUND", "The requested local directory was not found.", category="not_found") from None
            except PermissionError:
                raise ReadOnlyPathError("PATH_PERMISSION_DENIED", "macOS denied access to the requested directory.", category="permission") from None
            if not stat.S_ISDIR(identity.st_mode):
                raise ReadOnlyPathError("PATH_NOT_DIRECTORY", "The requested local path is not a directory.", category="validation")
            _validate_root_policy(canonical)
            if label is not None and (not isinstance(label, str) or not label.strip() or len(label) > 80 or "\n" in label or "\r" in label):
                raise ReadOnlyPathError("LABEL_INVALID", "label must be bounded single-line text.", category="validation")
            now = self._now()
            root_id = self._new_id()
            root = ReadOnlyRoot(root_id, requested, canonical, int(identity.st_dev), int(identity.st_ino), now, now, now + self._ttl, label.strip() if isinstance(label, str) else None)
            self._persist_open(root)
            if self._persistence is None:
                self._roots[root_id] = root
            return {**root.as_dict(), "status": "open", "external_execution": False}

    def _get(self, root_id: object, *, require_active: bool = True) -> ReadOnlyRoot:
        self._expire()
        if not isinstance(root_id, str) or not root_id:
            raise ReadOnlyPathError("ROOT_UNKNOWN", "root_id is required.", category="validation")
        root = self._roots.get(root_id)
        if root is None and self._persistence is not None:
            try:
                record = self._persistence.load_readonly_root(root_id)
            except PersistenceError as exc:
                raise ReadOnlyPathError(
                    "ROOT_PERSISTENCE_UNAVAILABLE",
                    "The durable READ_ONLY root could not be read safely.",
                    category="runtime",
                ) from exc
            if record is not None:
                root = self._root_from_persistence(record)
        if root is None:
            raise ReadOnlyPathError(
                "ROOT_CLOSED" if root_id in self._closed_ids else "ROOT_UNKNOWN",
                "The ephemeral READ_ONLY root is not known to this control-plane store.",
                category="not_found",
            )
        if root.state == "active" and root.expires_at <= self._now():
            root.state = "expired"
        if require_active and root.state != "active":
            code = {"expired": "ROOT_EXPIRED", "stale": "ROOT_STALE", "closed": "ROOT_CLOSED"}.get(root.state, "ROOT_UNKNOWN")
            raise ReadOnlyPathError(code, "The ephemeral READ_ONLY root is no longer active.", category="permission")
        return root

    def _mark_stale(self, root: ReadOnlyRoot) -> None:
        root.state = "stale"
        if self._persistence is None:
            return
        try:
            persisted = self._persistence.mark_readonly_root_stale(root.root_id, now=self._now())
        except PersistenceError as exc:
            raise ReadOnlyPathError(
                "ROOT_PERSISTENCE_UNAVAILABLE",
                "The durable READ_ONLY root state could not be updated safely.",
                category="runtime",
            ) from exc
        if persisted is None:
            raise ReadOnlyPathError(
                "ROOT_UNKNOWN",
                "The ephemeral READ_ONLY root is not known to this control-plane store.",
                category="not_found",
            )

    def _check_identity(
        self,
        root: ReadOnlyRoot,
        *,
        touch: bool = True,
        persist_stale: bool = True,
    ) -> None:
        try:
            canonical = Path(os.path.realpath(root.requested_path))
            current = os.stat(root.canonical_path)
            if root.policy_enforced:
                _validate_root_policy(root.canonical_path)
        except ReadOnlyPathError:
            if persist_stale:
                self._mark_stale(root)
            else:
                root.state = "stale"
            raise ReadOnlyPathError("ROOT_STALE", "The opened root is outside the current READ_ONLY policy.") from None
        except OSError:
            if persist_stale:
                self._mark_stale(root)
            else:
                root.state = "stale"
            raise ReadOnlyPathError("ROOT_STALE", "The opened root is no longer available with the same identity.") from None
        if canonical != root.canonical_path or not stat.S_ISDIR(current.st_mode) or int(current.st_dev) != root.device or int(current.st_ino) != root.inode:
            if persist_stale:
                self._mark_stale(root)
            else:
                root.state = "stale"
            raise ReadOnlyPathError("ROOT_STALE", "The opened root was moved or replaced.")
        if touch and self._persistence is None:
            root.last_accessed_at = self._now()
            root.expires_at = root.last_accessed_at + self._ttl

    def status(self, root_id: object = None) -> dict[str, object]:
        with self._lock:
            self._expire()
            if root_id is None:
                if self._persistence is None:
                    roots = [root.as_dict() for root in self._roots.values()]
                else:
                    try:
                        stored = self._persistence.load_readonly_roots()
                    except PersistenceError as exc:
                        raise ReadOnlyPathError(
                            "ROOT_PERSISTENCE_UNAVAILABLE",
                            "The durable READ_ONLY roots could not be read safely.",
                            category="runtime",
                        ) from exc
                    roots = []
                    for record in stored:
                        root = self._root_from_persistence(record)
                        if root.state == "closed":
                            continue
                        if root.state == "active" and root.expires_at <= self._now():
                            root.state = "expired"
                        roots.append(root.as_dict())
                return {"roots": roots, "count": len(roots), "external_execution": False}
            root = self._get(root_id, require_active=False)
            if root.state == "active":
                self._check_identity(root, touch=False)
            return {**root.as_dict(), "status": root.state, "external_execution": False}

    def close(self, root_id: object) -> dict[str, object]:
        with self._lock:
            root = self._get(root_id, require_active=False)
            if self._persistence is not None:
                try:
                    closed = self._persistence.close_readonly_root(root.root_id, now=self._now())
                except PersistenceError as exc:
                    raise ReadOnlyPathError(
                        "ROOT_PERSISTENCE_UNAVAILABLE",
                        "The durable READ_ONLY root could not be closed safely.",
                        category="runtime",
                    ) from exc
                if closed is None:
                    raise ReadOnlyPathError("ROOT_UNKNOWN", "The ephemeral READ_ONLY root is not known to this control-plane store.", category="not_found")
            root.state = "closed"
            self._closed_ids.append(root.root_id)
            self._roots.pop(root.root_id, None)
            return {"root_id": root.root_id, "status": "closed", "readonly": True, "external_execution": False}

    def close_all(self) -> None:
        with self._lock:
            if self._persistence is not None:
                # Durable roots belong to the control-plane TTL registry, not
                # to one child.  Closing a child must not revoke a handle that
                # a later child is entitled to read.
                self._roots.clear()
                self._closed_ids.clear()
                return
            self._closed_ids.extend(self._roots)
            self._roots.clear()

    def _open_relative(
        self,
        root: ReadOnlyRoot,
        parts: list[str],
        *,
        directory: bool,
        persist_stale: bool = True,
    ) -> int:
        self._check_identity(root, persist_stale=persist_stale)
        try:
            fd = os.open(root.canonical_path, _flags(directory=True))
        except PermissionError:
            raise ReadOnlyPathError("OS_PERMISSION_DENIED", "macOS denied access to the opened root.", category="permission") from None
        try:
            initial = os.fstat(fd)
            if int(initial.st_dev) != root.device or int(initial.st_ino) != root.inode:
                if persist_stale:
                    self._mark_stale(root)
                else:
                    root.state = "stale"
                raise ReadOnlyPathError("ROOT_STALE", "The root changed during access.")
            for index, part in enumerate(parts):
                last = index == len(parts) - 1
                child_directory = directory or not last
                try:
                    child = os.open(part, _flags(directory=child_directory), dir_fd=fd)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ReadOnlyPathError("PATH_ESCAPE_DENIED", "Symlink traversal is denied.") from None
                    if exc.errno in {errno.EACCES, errno.EPERM}:
                        raise ReadOnlyPathError("OS_PERMISSION_DENIED", "macOS denied access to the requested path.", category="permission") from None
                    if exc.errno == errno.ENOENT:
                        raise ReadOnlyPathError("FILE_NOT_FOUND" if last else "PATH_NOT_FOUND", "The requested path was not found.", category="not_found") from None
                    raise ReadOnlyPathError("PATH_UNAVAILABLE", "The requested path is unavailable.", category="runtime") from None
                os.close(fd)
                fd = child
            self._check_identity(root, touch=False, persist_stale=persist_stale)
            return fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def list_files(self, root_id: object, relative_path: object = ".", *, max_depth: int = 2, max_results: int = 100) -> dict[str, object]:
        with self._lock:
            root = self._get(root_id)
            base = _relative_parts(relative_path)
            depth_limit = max(0, min(int(max_depth), MAX_DEPTH))
            result_limit = max(1, min(int(max_results), MAX_RESULTS))
            stack: list[tuple[list[str], int]] = [(base, 0)]
            records: list[dict[str, object]] = []
            omitted: dict[str, int] = {}
            truncated = False
            visited_directories = 0
            while stack and len(records) < result_limit:
                if visited_directories >= MAX_VISITED_DIRECTORIES:
                    truncated = True
                    omitted["visited_directories"] = omitted.get("visited_directories", 0) + 1
                    break
                visited_directories += 1
                parts, depth = stack.pop()
                fd = self._open_relative(root, parts, directory=True, persist_stale=False)
                try:
                    entries = []
                    with os.scandir(fd) as iterator:
                        for entry in iterator:
                            entries.append(entry)
                            if len(entries) > MAX_ENTRIES_PER_DIRECTORY:
                                truncated = True
                                omitted["directory_entries"] = omitted.get("directory_entries", 0) + 1
                                break
                    entries.sort(key=lambda item: item.name.casefold())
                    for entry in entries[:MAX_ENTRIES_PER_DIRECTORY]:
                        if _sensitive_name(entry.name):
                            omitted["filtered"] = omitted.get("filtered", 0) + 1
                            continue
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError:
                            omitted["unavailable"] = omitted.get("unavailable", 0) + 1
                            continue
                        child_parts = [*parts, entry.name]
                        if stat.S_ISLNK(info.st_mode):
                            omitted["symlinks"] = omitted.get("symlinks", 0) + 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if depth < depth_limit:
                                stack.append((child_parts, depth + 1))
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            omitted["special"] = omitted.get("special", 0) + 1
                            continue
                        records.append({
                            "path": "/".join(child_parts), "size": int(info.st_size),
                            "modified_at": datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                        })
                        if len(records) >= result_limit:
                            truncated = True
                            break
                finally:
                    os.close(fd)
            if stack:
                truncated = True
            return {"root_id": root.root_id, "path": str(relative_path), "files": records, "truncated": truncated, "omitted": omitted, "external_execution": False}

    def search_files(self, root_id: object, relative_path: object, query: object, *, max_depth: int = 2, max_results: int = 100) -> dict[str, object]:
        with self._lock:
            if not isinstance(query, str) or not query or len(query) > 200:
                raise ReadOnlyPathError("FILE_QUERY_INVALID", "query must be a non-empty bounded literal string.", category="validation")
            listing = self.list_files(root_id, relative_path, max_depth=max_depth, max_results=MAX_RESULTS)
            limit = max(1, min(int(max_results), MAX_RESULTS))
            matches: list[dict[str, object]] = []
            scanned_bytes = 0
            truncated = bool(listing.get("truncated", False))
            for item in listing["files"]:
                path = str(item["path"])
                if scanned_bytes >= MAX_SEARCH_BYTES:
                    truncated = True
                    break
                try:
                    result = self.read_file(root_id, path, max_lines=MAX_LINES, max_bytes=MAX_RESPONSE_BYTES)
                except ReadOnlyPathError as exc:
                    if exc.code in {"FILE_BINARY_UNSUPPORTED", "FILE_SENSITIVE_DENIED", "FILE_TOO_LARGE"}:
                        continue
                    raise
                content = str(result["content"])
                scanned_bytes += len(content.encode("utf-8"))
                for line_number, line in enumerate(content.splitlines(), start=1):
                    if query in line:
                        matches.append({"path": path, "line": line_number, "excerpt": line.strip()[:240]})
                    if len(matches) >= limit:
                        truncated = True
                        break
                if len(matches) >= limit:
                    break
            return {"root_id": str(root_id), "path": str(relative_path), "query": query, "matches": matches, "truncated": truncated, "scanned_bytes": scanned_bytes, "external_execution": False}

    def read_file(self, root_id: object, relative_path: object, *, start_line: object = None, end_line: object = None, max_lines: object = None, max_bytes: object = 65536) -> dict[str, object]:
        with self._lock:
            root = self._get(root_id)
            parts = _relative_parts(relative_path, file_required=True)
            try:
                start = 1 if start_line is None else int(start_line)
                end = None if end_line is None else int(end_line)
                line_limit = MAX_LINES if max_lines is None else int(max_lines)
                byte_limit = 65536 if max_bytes is None else int(max_bytes)
            except (TypeError, ValueError):
                raise ReadOnlyPathError("READ_ARGUMENT_INVALID", "Line and byte limits must be integers.", category="validation") from None
            if start < 1 or line_limit < 1 or line_limit > MAX_LINES or byte_limit < 1 or byte_limit > MAX_RESPONSE_BYTES or (end is not None and end < start):
                raise ReadOnlyPathError("READ_ARGUMENT_INVALID", "Line or byte limits are outside the safe range.", category="validation")
            fd = self._open_relative(root, parts, directory=False, persist_stale=False)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ReadOnlyPathError("FILE_NOT_REGULAR", "The requested path is not a regular file.", category="validation")
                if int(info.st_size) > MAX_FILE_BYTES:
                    raise ReadOnlyPathError("FILE_TOO_LARGE", "The requested file exceeds the safe read bound.", category="validation")
                chunks: list[bytes] = []
                remaining = MAX_FILE_BYTES + 1
                while remaining > 0:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                if len(data) > MAX_FILE_BYTES:
                    raise ReadOnlyPathError("FILE_TOO_LARGE", "The requested file exceeds the safe read bound.", category="validation")
            finally:
                os.close(fd)
            if b"\x00" in data:
                raise ReadOnlyPathError("FILE_BINARY_UNSUPPORTED", "Binary files are not returned.", category="validation")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ReadOnlyPathError("FILE_BINARY_UNSUPPORTED", "Only UTF-8 text is returned.", category="validation") from None
            if _SECRET_CONTENT.search(text):
                raise ReadOnlyPathError("FILE_SENSITIVE_DENIED", "Secret-like file content is not returned.")
            lines = text.splitlines(keepends=True)
            effective_end = end if end is not None else start + line_limit - 1
            selected = "".join(lines[start - 1 : effective_end])
            encoded = selected.encode("utf-8")
            truncated = len(encoded) > byte_limit or effective_end < len(lines)
            if len(encoded) > byte_limit:
                selected = encoded[:byte_limit].decode("utf-8", errors="ignore")
            return {
                "root_id": root.root_id, "path": "/".join(parts), "content": selected,
                "encoding": "utf-8", "start_line": start, "end_line": min(effective_end, len(lines)),
                "bytes_returned": len(selected.encode("utf-8")), "file_size": int(info.st_size),
                "truncated": truncated, "redacted": False, "external_execution": False,
            }

    def read_configured_file(self, root_id: str, root_path: Path, relative_path: object, **kwargs: object) -> dict[str, object]:
        requested = root_path.absolute()
        try:
            canonical = Path(os.path.realpath(requested))
            identity = os.stat(canonical)
        except OSError:
            raise ReadOnlyPathError("PATH_UNAVAILABLE", "The configured READ_ONLY root is unavailable.", category="runtime") from None
        synthetic = ReadOnlyRoot(
            root_id,
            requested,
            canonical,
            int(identity.st_dev),
            int(identity.st_ino),
            0.0,
            0.0,
            float("inf"),
            policy_enforced=False,
        )
        temporary_id = f"configured:{root_id}:{secrets.token_urlsafe(8)}"
        synthetic.root_id = temporary_id
        with self._lock:
            self._roots[temporary_id] = synthetic
            try:
                result = self.read_file(temporary_id, relative_path, **kwargs)
                result["root_id"] = root_id
                return result
            finally:
                self._roots.pop(temporary_id, None)
