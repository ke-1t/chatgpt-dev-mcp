from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from .process_runner import run_bounded


PROJECT_DISCOVERY = "PROJECT_DISCOVERY"
READ_ONLY = "READ_ONLY"
ROOT_MODES = (PROJECT_DISCOVERY, READ_ONLY)
ROOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEFAULT_DISCOVERY_DEPTH = 4
MAX_DISCOVERY_DEPTH = 6
DEFAULT_DISCOVERY_RESULTS = 100
MAX_DISCOVERY_RESULTS = 100
MAX_ENTRIES_PER_DIRECTORY = 256
MAX_VISITED_DIRECTORIES = 2000
MAX_FILE_DISCOVERY_DEPTH = 4
MAX_FILE_VISITED_DIRECTORIES = 2000
MAX_ALLOWED_FILE_BYTES = 256 * 1024
MAX_FILE_LIST_OUTPUT_BYTES = 1024 * 1024
MAX_FILE_SEARCH_BYTES = 2 * 1024 * 1024
MAX_FILE_RESULTS = 100
UNBORN_HEAD = "0" * 40
SKIP_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        "target",
        ".cache",
    }
)
SENSITIVE_COMPONENT_NAMES = frozenset(
    {
        ".ssh",
        ".aws",
        ".gnupg",
        ".config",
        "keychain",
        "keychains",
        "browser profiles",
        "browser profile",
        "browser-profiles",
        "browser_profiles",
        "browserprofile",
        "browser",
        "chrome",
        "chromium",
        "firefox",
        "mozilla",
        "library",
        "application support",
        "application_support",
        "applicationsupport",
        "containers",
        "group containers",
        "group_containers",
        "groupcontainers",
        "mobile documents",
        "mobile_documents",
        "mobiledocuments",
        "cloudstorage",
        "cloud storage",
        "cloud_storage",
        "icloud",
        "icloud drive",
        "icloud_drive",
        "ubiquity",
        "credential",
        "credentials",
        "credential store",
        "credential_store",
        "credential-store",
        "credentialstore",
        "token",
        "tokens",
        "session",
        "sessions",
        "secrets",
    }
)
SENSITIVE_BASENAME_NAMES = frozenset(
    {
        "authorized_keys",
        "known_hosts",
        "cookies",
        "cookies.sqlite",
        "credentials",
        "credentials.json",
        "history",
        "history.sqlite",
        "login data",
        "login data.sqlite",
        "profile.db",
        "profile",
        "profiles",
        "session",
        "session.json",
        "session.db",
        "token",
        "token.json",
        "token.txt",
        "tokens.db",
        "auth.json",
        "oauth.json",
        "secrets.json",
        ".git-credentials",
        "git-credentials",
        "credentials.txt",
        "private.key",
        "private.pem",
    }
)


@dataclass(frozen=True)
class AllowedRoot:
    id: str
    path: Path
    mode: Literal["PROJECT_DISCOVERY", "READ_ONLY"]


class DiscoveryKind(str, Enum):
    GIT_REPOSITORY = "GIT_REPOSITORY"
    PROJECT_DIRECTORY = "PROJECT_DIRECTORY"


@dataclass(frozen=True)
class DiscoveryIdentity:
    source_path: Path
    git_root: Path
    device: int
    inode: int
    head: str
    git_marker: str


@dataclass(frozen=True)
class DiscoveryCandidate:
    candidate_id: str
    root_id: str
    path: Path
    git_root: Path
    metadata: dict[str, object]
    identity: DiscoveryIdentity | None = None


def _error(code: str, message: str, identifier: str | None = None) -> dict[str, str]:
    error = {"code": code, "message": message}
    if identifier is not None:
        error["id"] = identifier
    return error


def _expand_config_path(raw_path: str, home: Path) -> Path:
    expanded = os.path.expandvars(raw_path.strip())
    if expanded == "~":
        return home
    if expanded.startswith("~/") or expanded.startswith("~\\"):
        return home / expanded[2:]
    return Path(expanded).expanduser()


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def is_within_root(root: Path, candidate: Path) -> bool:
    root_resolved = root.resolve(strict=False)
    candidate_resolved = candidate.resolve(strict=False)
    return _is_under(candidate_resolved, root_resolved)


def _root_path_denied(path: Path, home: Path) -> bool:
    resolved = path.resolve(strict=False)
    home_resolved = home.resolve(strict=False)
    if resolved == Path("/") or resolved == home_resolved:
        return True
    system_managed = (
        Path("/System"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/var"),
        Path("/etc"),
        Path("/Applications"),
        Path("/Volumes"),
    )
    if any(resolved == managed or _is_under(resolved, managed) for managed in system_managed):
        return True
    # macOS exposes /var through the /private/var mount. Temporary test homes
    # may legitimately live below that mount, so only allow that subtree when
    # it is already contained by the caller's HOME; an explicit system root
    # remains denied.
    private_var = Path("/private/var")
    if (resolved == private_var or _is_under(resolved, private_var)) and not _is_under(resolved, home_resolved):
        return True
    library = home_resolved / "Library"
    if _is_under(resolved, library):
        return True
    return any(_is_sensitive_component(part) for part in resolved.parts)


def load_allowed_roots(document: dict[str, object], home: Path) -> tuple[list[AllowedRoot], list[dict[str, str]]]:
    """Load explicit roots or the narrow Developer-only default."""

    home = home.resolve(strict=False)
    raw_roots = document.get("roots")
    if raw_roots is None:
        raw_roots = [{"id": "developer", "path": "~/Developer", "mode": PROJECT_DISCOVERY}]
    if not isinstance(raw_roots, list):
        return [], [_error("ROOTS_INVALID", "roots must be an array.")]

    roots: list[AllowedRoot] = []
    errors: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for raw_root in raw_roots:
        if not isinstance(raw_root, dict):
            errors.append(_error("ROOT_ENTRY_INVALID", "Each root must be an object."))
            continue
        identifier = raw_root.get("id")
        if not isinstance(identifier, str) or not ROOT_ID_RE.fullmatch(identifier):
            errors.append(_error("ROOT_ID_INVALID", "Root id is invalid.", str(identifier)))
            continue
        if identifier in seen_ids:
            errors.append(_error("ROOT_ID_DUPLICATE", "Root id is duplicated.", identifier))
            continue
        seen_ids.add(identifier)
        mode = raw_root.get("mode")
        if mode not in ROOT_MODES:
            errors.append(_error("ROOT_MODE_INVALID", "Root mode must be PROJECT_DISCOVERY or READ_ONLY.", identifier))
            continue
        raw_path = raw_root.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            errors.append(_error("ROOT_PATH_INVALID", "Root path must be a non-empty string.", identifier))
            continue
        candidate = _expand_config_path(raw_path, home)
        try:
            resolved = candidate.resolve(strict=False)
        except OSError as exc:
            errors.append(_error("ROOT_PATH_INVALID", str(exc), identifier))
            continue
        if _root_path_denied(resolved, home):
            errors.append(_error("ROOT_PATH_DENIED", "Broad or sensitive roots are not allowed.", identifier))
            continue
        if not resolved.is_dir():
            errors.append(_error("ROOT_NOT_FOUND", "Root directory does not exist.", identifier))
            continue
        roots.append(AllowedRoot(identifier, resolved, mode))
    return roots, errors


def _is_sensitive_component(name: str) -> bool:
    lower = name.casefold()
    return lower in SENSITIVE_COMPONENT_NAMES or lower.startswith(".env")


def _is_sensitive_basename(name: str) -> bool:
    lower = name.casefold()
    return (
        lower in SENSITIVE_BASENAME_NAMES
        or lower.startswith(".env")
        or lower.startswith("id_")
        or lower.endswith((".pem", ".key", ".p12", ".pfx", ".kdbx"))
    )


def _is_sensitive_path(path: str | Path) -> bool:
    parts = Path(str(path).replace("\\", "/")).parts
    return any(_is_sensitive_component(part) for part in parts) or (bool(parts) and _is_sensitive_basename(parts[-1]))


def _is_binary_sample(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _has_git_marker(root: Path, path: Path) -> bool:
    return _git_marker_signature(root, path) is not None and _git_repo_root(path) == path.resolve(strict=False)


def _git_marker_signature(root: Path, path: Path) -> str | None:
    try:
        marker = path / ".git"
        marker_stat = marker.lstat()
        marker_type = marker_stat.st_mode & 0o170000
        if marker_type == 0o120000:
            return None
        if marker_type == 0o100000:
            header = marker.read_text(encoding="utf-8", errors="replace")[:4096]
            if not header.startswith("gitdir:"):
                return None
            target = header.split(":", 1)[1].strip()
            git_dir = (marker.parent / target).resolve(strict=False)
            if not is_within_root(root, git_dir):
                return None
        elif marker_type != 0o040000:
            return None
        return f"{marker_stat.st_dev}:{marker_stat.st_ino}:{marker_stat.st_mode}:{marker_stat.st_size}:{marker_stat.st_mtime_ns}"
    except OSError:
        return None


def _git_repo_root(path: Path) -> Path | None:
    resolved = path.resolve(strict=False)
    reported = _git_run(resolved, "rev-parse", "--show-toplevel")
    if not reported:
        return None
    try:
        git_root = Path(reported).resolve(strict=False)
    except OSError:
        return None
    return resolved if git_root == resolved else None


def _git_run(repo: Path, *args: str) -> str | None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        completed = run_bounded(
            ["git", "-C", str(repo), *args],
            env=env,
            timeout_seconds=3,
            max_output_bytes=1024 * 1024,
        )
    except (OSError, ValueError):
        return None
    if completed.timed_out or completed.output_truncated or completed.returncode != 0:
        return None
    # Preserve porcelain status' leading index/worktree columns; ``strip``
    # would erase the first unstaged marker when the first line starts with a
    # space.
    return completed.stdout.rstrip("\r\n")


def capture_discovery_identity(root: Path, path: Path, *, allow_unborn: bool = False) -> DiscoveryIdentity | None:
    """Capture the non-secret Git identity used for candidate TOCTOU checks."""

    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_dir() or not is_within_root(root, path):
            return None
        git_root = _git_repo_root(resolved)
        if git_root is None:
            return None
        head = _git_run(resolved, "rev-parse", "HEAD")
        if head is None:
            if not allow_unborn:
                return None
            symbolic = _git_run(resolved, "symbolic-ref", "--quiet", "HEAD")
            if symbolic is None or not symbolic.startswith("refs/heads/"):
                return None
            head = UNBORN_HEAD
        if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
            return None
        marker_signature = _git_marker_signature(root, resolved)
        if marker_signature is None:
            return None
        source_stat = resolved.stat()
        return DiscoveryIdentity(resolved, git_root, source_stat.st_dev, source_stat.st_ino, head, marker_signature)
    except OSError:
        return None


def capture_directory_identity(root: Path, path: Path) -> DiscoveryIdentity | None:
    """Capture a non-Git project directory identity for TOCTOU checks."""

    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_dir() or not is_within_root(root, resolved):
            return None
        source_stat = resolved.stat()
        return DiscoveryIdentity(
            resolved,
            resolved,
            source_stat.st_dev,
            source_stat.st_ino,
            UNBORN_HEAD,
            f"ordinary:{source_stat.st_dev}:{source_stat.st_ino}",
        )
    except OSError:
        return None


def _timestamp(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return None


def git_metadata(repo: Path, *, allow_unborn: bool = False) -> dict[str, object] | None:
    resolved = _git_repo_root(repo)
    if resolved is None:
        return None
    branch = _git_run(resolved, "branch", "--show-current") or "HEAD"
    status = _git_run(resolved, "status", "--porcelain=v1", "--untracked-files=normal") or ""
    last_commit = _git_run(resolved, "log", "-1", "--format=%cI")
    head = _git_run(resolved, "rev-parse", "HEAD")
    if head is None:
        if not allow_unborn:
            return None
        symbolic = _git_run(resolved, "symbolic-ref", "--quiet", "HEAD")
        if symbolic is None or not symbolic.startswith("refs/heads/"):
            return None
        head = UNBORN_HEAD
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        return None
    status_lines = status.splitlines()
    staged = any(len(line) >= 2 and line[0] not in {" ", "?"} for line in status_lines)
    unstaged = any(len(line) >= 2 and line[1] not in {" "} and not line.startswith("??") for line in status_lines)
    untracked = any(line.startswith("??") for line in status_lines)
    return {
        "name": resolved.name,
        "path": str(resolved),
        "git_root": str(resolved),
        "branch": branch,
        "dirty": staged or unstaged or untracked,
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
        "last_modified_at": _timestamp(resolved),
        "last_commit_at": last_commit or None,
    }


def discover_git_repositories(
    root: AllowedRoot,
    *,
    max_depth: int = DEFAULT_DISCOVERY_DEPTH,
    max_results: int = DEFAULT_DISCOVERY_RESULTS,
) -> dict[str, object]:
    """Find Git repositories below a PROJECT_DISCOVERY root with hard caps."""

    if root.mode != PROJECT_DISCOVERY:
        return {"repositories": [], "truncated": False, "visited_directories": 0, "omitted": {"root_mode": 1}}
    depth_limit = max(1, min(int(max_depth), MAX_DISCOVERY_DEPTH))
    result_limit = max(1, min(int(max_results), MAX_DISCOVERY_RESULTS))
    stack: list[tuple[Path, int]] = [(root.path, 0)]
    repositories: list[dict[str, object]] = []
    visited = 0
    truncated = False
    omitted: dict[str, int] = {}
    while stack:
        current, depth = stack.pop()
        if visited >= MAX_VISITED_DIRECTORIES:
            truncated = True
            break
        visited += 1
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name.casefold())
        except OSError:
            omitted["unreadable_directories"] = omitted.get("unreadable_directories", 0) + 1
            continue
        if len(entries) > MAX_ENTRIES_PER_DIRECTORY:
            truncated = True
            omitted["directory_entries"] = omitted.get("directory_entries", 0) + len(entries) - MAX_ENTRIES_PER_DIRECTORY
            entries = entries[:MAX_ENTRIES_PER_DIRECTORY]
        for entry in entries:
            name = entry.name
            if name.startswith(".") or name.casefold() in SKIP_DIRECTORY_NAMES or _is_sensitive_component(name):
                omitted["filtered_directories"] = omitted.get("filtered_directories", 0) + 1
                continue
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    if entry.is_symlink():
                        omitted["symlinks"] = omitted.get("symlinks", 0) + 1
                    continue
            except OSError:
                omitted["unreadable_entries"] = omitted.get("unreadable_entries", 0) + 1
                continue
            child = Path(entry.path)
            if not is_within_root(root.path, child):
                omitted["outside_root"] = omitted.get("outside_root", 0) + 1
                continue
            if _has_git_marker(root.path, child):
                metadata = git_metadata(child)
                if metadata is not None:
                    repositories.append(metadata)
                if len(repositories) >= result_limit:
                    truncated = True
                    break
            if depth < depth_limit:
                stack.append((child, depth + 1))
        if truncated and len(repositories) >= result_limit:
            break
    return {
        "repositories": repositories,
        "truncated": truncated,
        "visited_directories": visited,
        "omitted": omitted,
    }


_PROJECT_MARKER_FILES = frozenset({
    "pyproject.toml",
    "package.json",
    "cargo.toml",
    "go.mod",
    "readme.md",
})
_PROJECT_MARKER_DIRECTORIES = frozenset({"src", "tests"})


def _project_like(path: Path) -> bool:
    """Recognize a bounded project-shaped directory without listing folders wholesale."""

    try:
        with os.scandir(path) as entries:
            for index, entry in enumerate(entries):
                # A directory may contain an attacker-controlled number of
                # entries.  Inspect only the bounded prefix and fail closed if
                # the marker is outside that prefix.
                if index >= MAX_ENTRIES_PER_DIRECTORY:
                    return False
                if entry.name.casefold() in _PROJECT_MARKER_FILES:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            return True
                    except OSError:
                        return False
                if entry.name.casefold() in _PROJECT_MARKER_DIRECTORIES:
                    try:
                        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                            return True
                    except OSError:
                        return False
    except OSError:
        return False
    return False


def _bounded_directory_entries(path: Path) -> tuple[list[os.DirEntry[str]], int]:
    """Read directory metadata with bounded retained memory and exact overflow count."""

    entries: list[os.DirEntry[str]] = []
    omitted = 0
    with os.scandir(path) as iterator:
        for entry in iterator:
            if len(entries) < MAX_ENTRIES_PER_DIRECTORY:
                entries.append(entry)
            else:
                omitted += 1
    entries.sort(key=lambda entry: entry.name.casefold())
    return entries, omitted


def discover_projects(
    root: AllowedRoot,
    *,
    max_depth: int = DEFAULT_DISCOVERY_DEPTH,
    max_results: int = DEFAULT_DISCOVERY_RESULTS,
) -> dict[str, object]:
    """Find Git repositories and bounded project-shaped directories.

    Git repositories keep the legacy metadata contract.  Ordinary project
    directories are only returned when a small set of marker files/directories
    is present; arbitrary folders, hidden paths, caches, and symlinks remain
    omitted.
    """

    if root.mode != PROJECT_DISCOVERY:
        return {"repositories": [], "truncated": False, "visited_directories": 0, "omitted": {"root_mode": 1}}
    depth_limit = max(1, min(int(max_depth), MAX_DISCOVERY_DEPTH))
    result_limit = max(1, min(int(max_results), MAX_DISCOVERY_RESULTS))
    stack: list[tuple[Path, int]] = [(root.path, 0)]
    repositories: list[dict[str, object]] = []
    visited = 0
    truncated = False
    omitted: dict[str, int] = {}
    while stack:
        current, depth = stack.pop()
        if visited >= MAX_VISITED_DIRECTORIES:
            truncated = True
            break
        visited += 1
        try:
            entries, omitted_entries = _bounded_directory_entries(current)
        except OSError:
            omitted["unreadable_directories"] = omitted.get("unreadable_directories", 0) + 1
            continue
        if omitted_entries:
            truncated = True
            omitted["directory_entries"] = omitted.get("directory_entries", 0) + omitted_entries
        for entry in entries:
            name = entry.name
            if name.startswith(".") or name.casefold() in SKIP_DIRECTORY_NAMES or _is_sensitive_component(name):
                omitted["filtered_directories"] = omitted.get("filtered_directories", 0) + 1
                continue
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    if entry.is_symlink():
                        omitted["symlinks"] = omitted.get("symlinks", 0) + 1
                    continue
            except OSError:
                omitted["unreadable_entries"] = omitted.get("unreadable_entries", 0) + 1
                continue
            child = Path(entry.path)
            if not is_within_root(root.path, child):
                omitted["outside_root"] = omitted.get("outside_root", 0) + 1
                continue
            if _has_git_marker(root.path, child):
                metadata = git_metadata(child, allow_unborn=True)
                if metadata is not None:
                    metadata["kind"] = DiscoveryKind.GIT_REPOSITORY.value
                    metadata["git_initialized"] = True
                    repositories.append(metadata)
            elif _project_like(child):
                repositories.append(
                    {
                        "name": child.name,
                        "path": str(child.resolve(strict=False)),
                        "git_root": str(child.resolve(strict=False)),
                        "kind": DiscoveryKind.PROJECT_DIRECTORY.value,
                        "git_initialized": False,
                        "dirty": False,
                        "last_modified_at": _timestamp(child),
                        "last_commit_at": None,
                    }
                )
            if len(repositories) >= result_limit:
                truncated = True
                break
            if depth < depth_limit:
                stack.append((child, depth + 1))
        if truncated and len(repositories) >= result_limit:
            break
    return {
        "repositories": repositories,
        "truncated": truncated,
        "visited_directories": visited,
        "omitted": omitted,
    }


def _validate_relative_path(root: AllowedRoot, raw_path: str) -> Path:
    if not isinstance(raw_path, str) or "\x00" in raw_path:
        raise ValueError("FILE_ROOT_PATH_DENIED")
    normalized = raw_path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise ValueError("FILE_ROOT_PATH_DENIED")
    parts = [part for part in candidate.parts if part not in {"", "."}]
    if any(part.startswith(".") for part in parts) or _is_sensitive_path("/".join(parts)):
        raise ValueError("FILE_ROOT_PATH_DENIED")
    resolved = root.path.joinpath(*parts).resolve(strict=False)
    if not is_within_root(root.path, resolved):
        raise ValueError("FILE_ROOT_PATH_DENIED")
    current = root.path
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise ValueError("FILE_ROOT_PATH_DENIED")
        except OSError:
            raise ValueError("FILE_ROOT_PATH_DENIED") from None
    return resolved


def _walk_allowed_files(root: AllowedRoot, base: Path, max_depth: int, max_results: int) -> tuple[list[Path], bool, dict[str, int]]:
    if root.mode != READ_ONLY:
        raise ValueError("ROOT_MODE_DENIED")
    if not base.exists() or not base.is_dir() or base.is_symlink():
        raise ValueError("FILE_ROOT_PATH_DENIED")
    depth_limit = max(0, min(int(max_depth), MAX_FILE_DISCOVERY_DEPTH))
    result_limit = max(1, min(int(max_results), MAX_FILE_RESULTS))
    stack: list[tuple[Path, int]] = [(base, 0)]
    files: list[Path] = []
    truncated = False
    omitted: dict[str, int] = {}
    visited = 0
    while stack:
        if visited >= MAX_FILE_VISITED_DIRECTORIES:
            truncated = True
            omitted["visited_directories"] = omitted.get("visited_directories", 0) + 1
            break
        current, depth = stack.pop()
        visited += 1
        try:
            entries, omitted_entries = _bounded_directory_entries(current)
        except OSError:
            omitted["unreadable_directories"] = omitted.get("unreadable_directories", 0) + 1
            continue
        if omitted_entries:
            truncated = True
            omitted["directory_entries"] = omitted.get("directory_entries", 0) + omitted_entries
        for entry in entries:
            name = entry.name
            if name.startswith(".") or name.casefold() in SKIP_DIRECTORY_NAMES or _is_sensitive_path(name):
                omitted["filtered"] = omitted.get("filtered", 0) + 1
                continue
            try:
                if entry.is_symlink():
                    omitted["symlinks"] = omitted.get("symlinks", 0) + 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < depth_limit:
                        child = Path(entry.path)
                        if is_within_root(root.path, child):
                            stack.append((child, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    omitted["special_files"] = omitted.get("special_files", 0) + 1
                    continue
                path = Path(entry.path)
                if not is_within_root(root.path, path):
                    omitted["outside_root"] = omitted.get("outside_root", 0) + 1
                    continue
                size = path.stat().st_size
                if size > MAX_ALLOWED_FILE_BYTES:
                    omitted["oversized"] = omitted.get("oversized", 0) + 1
                    continue
                sample, _ = _read_stable_bytes(path, 4096)
                if _is_binary_sample(sample):
                    omitted["binary"] = omitted.get("binary", 0) + 1
                    continue
            except OSError:
                omitted["unreadable_files"] = omitted.get("unreadable_files", 0) + 1
                continue
            files.append(path)
            if len(files) >= result_limit:
                truncated = True
                return files, truncated, omitted
    return files, truncated, omitted


def _read_stable_bytes(path: Path, max_bytes: int) -> tuple[bytes, bool]:
    """Read a bounded regular file while rejecting replacement during the read."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("not a regular file")
        data = bytearray()
        while len(data) < max_bytes:
            chunk = os.read(descriptor, min(65536, max_bytes - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise OSError("file changed while reading")
        return bytes(data), before.st_size <= max_bytes
    finally:
        os.close(descriptor)


def _relative_file_path(root: AllowedRoot, path: Path) -> str:
    return path.resolve(strict=False).relative_to(root.path.resolve(strict=False)).as_posix()


def _file_timestamp(path: Path) -> str | None:
    return _timestamp(path)


def list_allowed_files(
    root: AllowedRoot,
    relative_path: str = ".",
    *,
    max_depth: int = 2,
    max_results: int = 100,
) -> dict[str, object]:
    base = _validate_relative_path(root, relative_path)
    files, truncated, omitted = _walk_allowed_files(root, base, max_depth, max_results)
    records: list[dict[str, object]] = []
    output_bytes = 0
    for path in files:
        record = {"path": _relative_file_path(root, path), "size": path.stat().st_size, "modified_at": _file_timestamp(path)}
        record_size = len(json.dumps(record, ensure_ascii=False))
        if output_bytes + record_size > MAX_FILE_LIST_OUTPUT_BYTES:
            truncated = True
            omitted["output_bytes"] = omitted.get("output_bytes", 0) + 1
            break
        records.append(record)
        output_bytes += record_size
    return {"root_id": root.id, "path": relative_path, "files": records, "truncated": truncated, "omitted": omitted}


_EXCERPT_SECRET_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{12,})\b")


def _safe_excerpt(text: str) -> str:
    compact = text.strip().replace("\x00", "")
    if len(compact) > 240:
        compact = compact[:237] + "..."
    return _EXCERPT_SECRET_RE.sub("[redacted-secret-like-output]", compact)


def search_allowed_files(
    root: AllowedRoot,
    relative_path: str,
    query: str,
    *,
    max_depth: int = 2,
    max_results: int = 100,
) -> dict[str, object]:
    if not isinstance(query, str) or not query or len(query) > 200:
        raise ValueError("FILE_QUERY_INVALID")
    base = _validate_relative_path(root, relative_path)
    files, truncated, omitted = _walk_allowed_files(root, base, max_depth, MAX_FILE_RESULTS)
    matches: list[dict[str, object]] = []
    scanned_bytes = 0
    result_limit = max(1, min(int(max_results), MAX_FILE_RESULTS))
    for path in files:
        try:
            remaining = MAX_FILE_SEARCH_BYTES - scanned_bytes
            if remaining <= 0:
                truncated = True
                omitted["search_bytes"] = omitted.get("search_bytes", 0) + 1
                break
            data, complete = _read_stable_bytes(path, min(MAX_ALLOWED_FILE_BYTES, remaining))
        except OSError:
            omitted["unreadable_files"] = omitted.get("unreadable_files", 0) + 1
            continue
        scanned_bytes += len(data)
        if not complete:
            truncated = True
            omitted["search_bytes"] = omitted.get("search_bytes", 0) + 1
            break
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            omitted["non_utf8"] = omitted.get("non_utf8", 0) + 1
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if query not in line:
                continue
            matches.append({"path": _relative_file_path(root, path), "line": line_number, "excerpt": _safe_excerpt(line)})
            if len(matches) >= result_limit:
                truncated = True
                break
        if len(matches) >= result_limit:
            break
    return {"root_id": root.id, "path": relative_path, "query": query, "matches": matches, "truncated": truncated, "scanned_bytes": scanned_bytes, "omitted": omitted}
