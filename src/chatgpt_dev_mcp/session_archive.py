from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable, Mapping

from .development import UNBORN_HEAD


ARCHIVE_SCHEMA_VERSION = 1
MAX_ARCHIVE_PAYLOAD_BYTES = 256 * 1024 * 1024
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()
_ARCHIVE_ID_PREFIX = f"archive-v{ARCHIVE_SCHEMA_VERSION}-"


class ArchiveError(RuntimeError):
    """Fail-closed archive eligibility, verification, or restore error."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    kind: str
    mode: int
    size: int
    content_hash: str
    symlink_target: str | None = None

    def to_hash_metadata(self) -> dict[str, object]:
        return {
            "path": validate_archive_relative_path(self.path),
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "content_hash": self.content_hash,
            "symlink_target": self.symlink_target,
        }


@dataclass(frozen=True)
class ArchiveSnapshot:
    schema_version: int
    archive_id: str
    created_at: str
    project_id: str
    logical_workspace_id: str
    workspace_id: str
    physical_worktree_id: str
    worktree_path: str
    repository_path: str
    source_revision: str
    base_revision: str
    source_path_identity: tuple[str, int, int]
    alias_session_ids: tuple[str, ...]
    tracked_paths: tuple[str, ...]
    patch_bytes: bytes
    patch_hash: str
    untracked_entries: tuple[ArchiveEntry, ...]
    payload_bytes: int
    state_hash: str


@dataclass(frozen=True)
class ArchiveVerification:
    archive_id: str
    state_hash: str
    patch_hash: str
    tracked_tree_hash: str
    verified_at: str


@dataclass(frozen=True)
class PublishedArchive:
    archive_id: str
    archive_path: str
    schema_version: int
    project_id: str
    logical_workspace_id: str
    workspace_id: str
    physical_worktree_id: str
    source_revision: str
    base_revision: str
    state_hash: str
    patch_hash: str
    manifest_hash: str
    payload_hash: str
    alias_session_ids: tuple[str, ...]
    payload_bytes: int
    created_at: str
    verified_at: str


@dataclass(frozen=True)
class RestoreResult:
    archive_id: str
    target_worktree_path: str
    state_hash: str
    restored_at: str


def canonical_json_bytes(value: object) -> bytes:
    """Serialize hash-participating JSON deterministically as UTF-8 bytes."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArchiveError("INVALID_CANONICAL_JSON", str(exc)) from exc


def validate_archive_relative_path(value: str) -> str:
    """Return one portable safe relative archive path or fail closed."""

    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ArchiveError("UNSAFE_ARCHIVE_PATH")
    if value.startswith("/"):
        raise ArchiveError("UNSAFE_ARCHIVE_PATH")
    path = PurePosixPath(value)
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError("UNSAFE_ARCHIVE_PATH")
    normalized = path.as_posix()
    if normalized != value:
        raise ArchiveError("UNSAFE_ARCHIVE_PATH")
    return normalized


def validate_archive_id(value: str) -> str:
    if not isinstance(value, str) or not value.startswith(_ARCHIVE_ID_PREFIX):
        raise ArchiveError("INVALID_ARCHIVE_ID")
    digest = value[len(_ARCHIVE_ID_PREFIX) :]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ArchiveError("INVALID_ARCHIVE_ID")
    return value


def normalized_state_hash(
    *,
    base_revision: str,
    patch_hash: str,
    entries: Iterable[ArchiveEntry],
) -> str:
    """Hash only location-independent recoverable DEVELOPMENT state."""

    ordered = sorted((entry.to_hash_metadata() for entry in entries), key=lambda item: str(item["path"]))
    payload = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "base_revision": base_revision,
        "patch_hash": patch_hash,
        "untracked_entries": ordered,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _git(
    cwd: Path,
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env) if env is not None else None,
            shell=False,
            check=False,
        )
    except (OSError, ValueError) as exc:
        raise ArchiveError("GIT_EXEC_FAILED", str(exc)) from exc
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ArchiveError("GIT_COMMAND_FAILED", detail[:1000])
    return completed


def _decode_git_paths(payload: bytes) -> tuple[str, ...]:
    if not payload:
        return ()
    result: list[str] = []
    for raw in payload.rstrip(b"\x00").split(b"\x00"):
        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ArchiveError("UNSUPPORTED_PATH_ENCODING") from exc
        result.append(validate_archive_relative_path(value))
    return tuple(result)


def _head_revision(worktree: Path) -> str:
    resolved = _git(worktree, ["rev-parse", "--verify", "HEAD"], check=False)
    if resolved.returncode == 0:
        head = resolved.stdout.decode("ascii", errors="strict").strip()
        if len(head) == 40:
            return head
    symbolic = _git(worktree, ["symbolic-ref", "--quiet", "HEAD"], check=False)
    ref = symbolic.stdout.decode("utf-8", errors="strict").strip()
    if resolved.returncode != 0 and symbolic.returncode == 0 and ref.startswith("refs/heads/"):
        return UNBORN_HEAD
    raise ArchiveError("BASE_REVISION_MISMATCH")


def _assert_base_available(repository: Path, base_revision: str) -> None:
    if base_revision != UNBORN_HEAD:
        _git(repository, ["cat-file", "-e", f"{base_revision}^{{commit}}"])


def _worktree_patch(worktree: Path, base_revision: str) -> tuple[bytes, tuple[str, ...]]:
    if base_revision == UNBORN_HEAD:
        cached = _git(worktree, ["ls-files", "--cached", "-z"]).stdout
        if cached:
            raise ArchiveError("INDEX_NOT_HEAD")
        return b"", ()
    index_check = _git(worktree, ["diff", "--cached", "--quiet", base_revision, "--"], check=False)
    if index_check.returncode == 1:
        raise ArchiveError("INDEX_NOT_HEAD")
    if index_check.returncode != 0:
        raise ArchiveError("INDEX_STATE_UNAVAILABLE")
    patch_bytes = _git(
        worktree,
        ["diff", "--binary", "--full-index", "--no-ext-diff", "--find-renames=50%", base_revision, "--"],
    ).stdout
    tracked_paths = tuple(
        sorted(
            set(
                _decode_git_paths(
                    _git(worktree, ["diff", "--name-only", "-z", "--no-ext-diff", base_revision, "--"]).stdout
                )
            )
        )
    )
    return patch_bytes, tracked_paths


def _sha256_regular_file(path: Path) -> tuple[str, int, os.stat_result]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ArchiveError("UNREADABLE_ARCHIVE_ENTRY", str(exc)) from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    after = os.lstat(path)
    before_identity = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or total != before.st_size:
        raise ArchiveError("SOURCE_CHANGED_DURING_SNAPSHOT")
    return digest.hexdigest(), total, before


def _require_safe_existing_parents(root: Path, relative_path: str) -> None:
    relative = PurePosixPath(validate_archive_relative_path(relative_path))
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ArchiveError("UNSAFE_ARCHIVE_PARENT", str(exc)) from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ArchiveError("UNSAFE_ARCHIVE_PARENT")


def _collect_untracked_entries(worktree: Path) -> tuple[ArchiveEntry, ...]:
    file_paths = _decode_git_paths(
        _git(worktree, ["ls-files", "--others", "--exclude-standard", "-z"]).stdout
    )
    directory_paths: set[str] = set()
    for value in file_paths:
        parent = PurePosixPath(value).parent
        while parent.as_posix() not in {".", ""}:
            directory_paths.add(validate_archive_relative_path(parent.as_posix()))
            parent = parent.parent

    entries: list[ArchiveEntry] = []
    for value in sorted(directory_paths):
        path = worktree / value
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise ArchiveError("UNREADABLE_ARCHIVE_ENTRY", str(exc)) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")
        entries.append(
            ArchiveEntry(value, "directory", stat.S_IMODE(info.st_mode), 0, _EMPTY_HASH)
        )

    for value in file_paths:
        path = worktree / value
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise ArchiveError("UNREADABLE_ARCHIVE_ENTRY", str(exc)) from exc
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            content_hash, size, _ = _sha256_regular_file(path)
            entries.append(ArchiveEntry(value, "file", mode, size, content_hash))
        elif stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(path)
                target_bytes = target.encode("utf-8", errors="strict")
            except (OSError, UnicodeEncodeError) as exc:
                raise ArchiveError("UNREADABLE_ARCHIVE_ENTRY", str(exc)) from exc
            entries.append(
                ArchiveEntry(
                    value,
                    "symlink",
                    mode,
                    len(target_bytes),
                    hashlib.sha256(target_bytes).hexdigest(),
                    target,
                )
            )
        else:
            raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")
    return tuple(sorted(entries, key=lambda entry: entry.path))


class SessionArchiveBuilder:
    def __init__(self, *, payload_limit_bytes: int = MAX_ARCHIVE_PAYLOAD_BYTES) -> None:
        if isinstance(payload_limit_bytes, bool) or not isinstance(payload_limit_bytes, int) or payload_limit_bytes < 1:
            raise ArchiveError("INVALID_PAYLOAD_LIMIT")
        self.payload_limit_bytes = payload_limit_bytes

    def build(
        self,
        assessment: PhysicalWorktreeAssessment,
        *,
        repository_path: str | os.PathLike[str],
    ) -> ArchiveSnapshot:
        if assessment.disposition is not ArchiveDisposition.ARCHIVE:
            raise ArchiveError("NOT_ARCHIVE_ELIGIBLE")
        worktree = Path(assessment.worktree_path).expanduser().resolve()
        repository = Path(repository_path).expanduser().resolve()
        if not worktree.is_dir() or not repository.is_dir():
            raise ArchiveError("WORKTREE_UNAVAILABLE")

        base = assessment.base_revision
        _assert_base_available(repository, base)
        head = _head_revision(worktree)
        if head != base:
            raise ArchiveError("BASE_REVISION_MISMATCH")
        patch_bytes, tracked_paths = _worktree_patch(worktree, base)
        patch_hash = hashlib.sha256(patch_bytes).hexdigest()
        entries = _collect_untracked_entries(worktree)
        payload_bytes = len(patch_bytes) + sum(
            entry.size for entry in entries if entry.kind in {"file", "symlink"}
        )
        if payload_bytes > self.payload_limit_bytes:
            raise ArchiveError("PAYLOAD_LIMIT_EXCEEDED")
        state_hash = normalized_state_hash(base_revision=base, patch_hash=patch_hash, entries=entries)
        archive_key = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "physical_worktree_id": assessment.physical_worktree_id,
            "base_revision": base,
            "patch_hash": patch_hash,
            "untracked_entries": [entry.to_hash_metadata() for entry in entries],
        }
        archive_id = _ARCHIVE_ID_PREFIX + hashlib.sha256(
            canonical_json_bytes(archive_key)
        ).hexdigest()
        repository_stat = os.stat(repository)
        return ArchiveSnapshot(
            schema_version=ARCHIVE_SCHEMA_VERSION,
            archive_id=archive_id,
            created_at=_utc_now(),
            project_id=assessment.project_id,
            logical_workspace_id=assessment.logical_workspace_id,
            workspace_id=assessment.workspace_id,
            physical_worktree_id=assessment.physical_worktree_id,
            worktree_path=str(worktree),
            repository_path=str(repository),
            source_revision=assessment.source_revision,
            base_revision=base,
            source_path_identity=(str(repository), repository_stat.st_dev, repository_stat.st_ino),
            alias_session_ids=assessment.alias_session_ids,
            tracked_paths=tracked_paths,
            patch_bytes=patch_bytes,
            patch_hash=patch_hash,
            untracked_entries=entries,
            payload_bytes=payload_bytes,
            state_hash=state_hash,
        )


def _payload_hash(*, patch_hash: str, entries: Iterable[ArchiveEntry]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "patch_hash": patch_hash,
                "untracked_entries": [
                    entry.to_hash_metadata() for entry in sorted(entries, key=lambda item: item.path)
                ],
            }
        )
    ).hexdigest()


def _private_index_tree_hash(repository: Path, *, base_revision: str, patch_bytes: bytes) -> str:
    _assert_base_available(repository, base_revision)
    with tempfile.TemporaryDirectory(prefix="devmcp-archive-index-") as scratch:
        index_path = Path(scratch) / "index"
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = str(index_path)
        if base_revision == UNBORN_HEAD:
            _git(repository, ["read-tree", "--empty"], env=env)
        else:
            _git(repository, ["read-tree", base_revision], env=env)
        if patch_bytes:
            applied = _git(
                repository,
                ["apply", "--cached", "--binary", "--whitespace=nowarn", "-"],
                input_bytes=patch_bytes,
                env=env,
                check=False,
            )
            if applied.returncode != 0:
                detail = applied.stderr.decode("utf-8", errors="replace").strip()
                raise ArchiveError("PATCH_APPLY_FAILED", detail[:1000])
        tree = _git(repository, ["write-tree"], env=env).stdout.decode("ascii", errors="strict").strip()
        if len(tree) != 40:
            raise ArchiveError("TRACKED_TREE_INVALID")
        return tree


def _entry_from_metadata(value: object) -> ArchiveEntry:
    if not isinstance(value, Mapping):
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    allowed = {"path", "kind", "mode", "size", "content_hash", "symlink_target"}
    if set(value) != allowed:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    path = value.get("path")
    kind = value.get("kind")
    mode = value.get("mode")
    size = value.get("size")
    content_hash = value.get("content_hash")
    symlink_target = value.get("symlink_target")
    if not isinstance(path, str):
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    validate_archive_relative_path(path)
    if kind not in {"file", "directory", "symlink"}:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0 or mode > 0o7777:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    if not isinstance(content_hash, str) or len(content_hash) != 64:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    if kind == "symlink":
        if not isinstance(symlink_target, str):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    elif symlink_target is not None:
        raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
    return ArchiveEntry(path, str(kind), mode, size, content_hash, symlink_target)


def _manifest_for_snapshot(snapshot: ArchiveSnapshot, verification: ArchiveVerification) -> dict[str, object]:
    if verification.archive_id != snapshot.archive_id or verification.state_hash != snapshot.state_hash:
        raise ArchiveError("VERIFICATION_BINDING_MISMATCH")
    return {
        "schema_version": snapshot.schema_version,
        "archive_id": snapshot.archive_id,
        "created_at": snapshot.created_at,
        "verified_at": verification.verified_at,
        "project_id": snapshot.project_id,
        "logical_workspace_id": snapshot.logical_workspace_id,
        "workspace_id": snapshot.workspace_id,
        "physical_worktree_id": snapshot.physical_worktree_id,
        "source_revision": snapshot.source_revision,
        "base_revision": snapshot.base_revision,
        "source_path_identity": list(snapshot.source_path_identity),
        "alias_session_ids": list(snapshot.alias_session_ids),
        "tracked_paths": list(snapshot.tracked_paths),
        "untracked_entries": [entry.to_hash_metadata() for entry in snapshot.untracked_entries],
        "state_hash": snapshot.state_hash,
        "tracked_patch_hash": snapshot.patch_hash,
        "tracked_tree_hash": verification.tracked_tree_hash,
        "overall_payload_hash": _payload_hash(
            patch_hash=snapshot.patch_hash,
            entries=snapshot.untracked_entries,
        ),
        "payload_bytes": snapshot.payload_bytes,
    }


def _read_json_object(path: Path, *, code: str) -> dict[str, object]:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ArchiveError(code)
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except ArchiveError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(code, str(exc)) from exc
    if not isinstance(value, dict):
        raise ArchiveError(code)
    return value


class SessionArchiveVerifier:
    def verify_snapshot(
        self,
        snapshot: ArchiveSnapshot,
        *,
        repository_path: str | os.PathLike[str],
    ) -> ArchiveVerification:
        repository = Path(repository_path).expanduser().resolve()
        if hashlib.sha256(snapshot.patch_bytes).hexdigest() != snapshot.patch_hash:
            raise ArchiveError("PATCH_HASH_MISMATCH")
        try:
            _assert_base_available(repository, snapshot.base_revision)
        except ArchiveError as exc:
            raise ArchiveError("BASE_COMMIT_MISSING") from exc

        source = Path(snapshot.worktree_path)
        if source.is_dir():
            if _head_revision(source) != snapshot.base_revision:
                raise ArchiveError("SOURCE_CHANGED_DURING_VERIFICATION")
            current_patch, current_tracked_paths = _worktree_patch(source, snapshot.base_revision)
            if current_patch != snapshot.patch_bytes:
                raise ArchiveError("SOURCE_CHANGED_DURING_VERIFICATION")
            if current_tracked_paths != snapshot.tracked_paths:
                raise ArchiveError("SOURCE_CHANGED_DURING_VERIFICATION")
            current_entries = _collect_untracked_entries(source)
            if current_entries != snapshot.untracked_entries:
                raise ArchiveError("SOURCE_CHANGED_DURING_VERIFICATION")

        state_hash = normalized_state_hash(
            base_revision=snapshot.base_revision,
            patch_hash=snapshot.patch_hash,
            entries=snapshot.untracked_entries,
        )
        if state_hash != snapshot.state_hash:
            raise ArchiveError("STATE_HASH_MISMATCH")
        tree_hash = _private_index_tree_hash(
            repository,
            base_revision=snapshot.base_revision,
            patch_bytes=snapshot.patch_bytes,
        )
        return ArchiveVerification(
            archive_id=snapshot.archive_id,
            state_hash=state_hash,
            patch_hash=snapshot.patch_hash,
            tracked_tree_hash=tree_hash,
            verified_at=_utc_now(),
        )

    def verify_published(
        self,
        archive_path: str | os.PathLike[str],
        *,
        repository_path: str | os.PathLike[str],
    ) -> ArchiveVerification:
        archive = Path(archive_path).expanduser().resolve()
        manifest_path = archive / "manifest.json"
        patch_path = archive / "changes.patch"
        checksums_path = archive / "checksums.json"
        manifest = _read_json_object(manifest_path, code="INVALID_ARCHIVE_MANIFEST")
        checksums = _read_json_object(checksums_path, code="INVALID_ARCHIVE_CHECKSUMS")
        try:
            patch_info = os.lstat(patch_path)
            if not stat.S_ISREG(patch_info.st_mode) or stat.S_ISLNK(patch_info.st_mode):
                raise ArchiveError("PATCH_MISSING")
            patch_bytes = patch_path.read_bytes()
        except OSError as exc:
            raise ArchiveError("PATCH_MISSING", str(exc)) from exc

        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        expected_manifest_hash = checksums.get("manifest_sha256")
        if manifest_hash != expected_manifest_hash:
            raise ArchiveError("MANIFEST_HASH_MISMATCH")
        patch_hash = hashlib.sha256(patch_bytes).hexdigest()
        expected_patch_hash = manifest.get("tracked_patch_hash")
        if patch_hash != expected_patch_hash or checksums.get("changes_patch_sha256") != patch_hash:
            raise ArchiveError("PATCH_HASH_MISMATCH")

        entries_raw = manifest.get("untracked_entries")
        if not isinstance(entries_raw, list):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        entries = tuple(_entry_from_metadata(value) for value in entries_raw)
        if tuple(sorted(entries, key=lambda entry: entry.path)) != entries:
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        file_hashes = checksums.get("untracked_files")
        if not isinstance(file_hashes, dict):
            raise ArchiveError("INVALID_ARCHIVE_CHECKSUMS")
        expected_file_paths = {entry.path for entry in entries if entry.kind == "file"}
        if set(file_hashes) != expected_file_paths:
            raise ArchiveError("INVALID_ARCHIVE_CHECKSUMS")
        for entry in entries:
            validate_archive_relative_path(entry.path)
            _require_safe_existing_parents(archive / "untracked", entry.path)
            stored = archive / "untracked" / entry.path
            if entry.kind == "file":
                digest, size, _ = _sha256_regular_file(stored)
                if digest != entry.content_hash or size != entry.size or file_hashes.get(entry.path) != digest:
                    raise ArchiveError("UNTRACKED_HASH_MISMATCH")
            elif entry.kind == "directory":
                try:
                    info = os.lstat(stored)
                except OSError as exc:
                    raise ArchiveError("UNTRACKED_ENTRY_MISSING", str(exc)) from exc
                if stat.S_ISLNK(info.st_mode):
                    raise ArchiveError("UNSAFE_STORED_SYMLINK")
                if not stat.S_ISDIR(info.st_mode):
                    raise ArchiveError("UNTRACKED_ENTRY_TYPE_MISMATCH")
            elif stored.exists() or stored.is_symlink():
                # Symlink payload is metadata-only.  A filesystem entry here
                # would create an avoidable dereference/traversal surface.
                raise ArchiveError("UNSAFE_STORED_SYMLINK")

        base_revision = manifest.get("base_revision")
        state_hash = manifest.get("state_hash")
        archive_id = manifest.get("archive_id")
        if not all(isinstance(value, str) and value for value in (base_revision, state_hash, archive_id)):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        recomputed_state = normalized_state_hash(
            base_revision=base_revision,
            patch_hash=patch_hash,
            entries=entries,
        )
        if recomputed_state != state_hash:
            raise ArchiveError("STATE_HASH_MISMATCH")
        payload_hash = _payload_hash(patch_hash=patch_hash, entries=entries)
        if manifest.get("overall_payload_hash") != payload_hash or checksums.get("overall_payload_hash") != payload_hash:
            raise ArchiveError("PAYLOAD_HASH_MISMATCH")
        try:
            tree_hash = _private_index_tree_hash(
                Path(repository_path).expanduser().resolve(),
                base_revision=base_revision,
                patch_bytes=patch_bytes,
            )
        except ArchiveError as exc:
            if exc.code == "GIT_COMMAND_FAILED":
                raise ArchiveError("BASE_COMMIT_MISSING") from exc
            raise
        if manifest.get("tracked_tree_hash") != tree_hash:
            raise ArchiveError("TRACKED_TREE_MISMATCH")
        return ArchiveVerification(
            archive_id=archive_id,
            state_hash=state_hash,
            patch_hash=patch_hash,
            tracked_tree_hash=tree_hash,
            verified_at=_utc_now(),
        )


def _default_archive_root() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "local-dev-mcp" / "session-archives"


def _safe_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise ArchiveError("ARCHIVE_PAYLOAD_WRITE_FAILED")
            written += count
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        os.close(fd)


def _copy_verified_file(source: Path, destination: Path, entry: ArchiveEntry) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ArchiveError("ARCHIVE_PAYLOAD_WRITE_FAILED", str(exc)) from exc
    digest = hashlib.sha256()
    total = 0
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode):
            raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_fd, chunk[offset:])
        try:
            os.fsync(destination_fd)
        except OSError:
            pass
        source_after = os.fstat(source_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    if (
        total != entry.size
        or digest.hexdigest() != entry.content_hash
        or (source_info.st_dev, source_info.st_ino, source_info.st_size, source_info.st_mtime_ns)
        != (source_after.st_dev, source_after.st_ino, source_after.st_size, source_after.st_mtime_ns)
    ):
        raise ArchiveError("SOURCE_CHANGED_DURING_ARCHIVE_WRITE")


class SessionArchiveStore:
    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        free_space_reserve_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if isinstance(free_space_reserve_bytes, bool) or not isinstance(free_space_reserve_bytes, int) or free_space_reserve_bytes < 0:
            raise ArchiveError("INVALID_FREE_SPACE_RESERVE")
        self.root = (Path(root) if root is not None else _default_archive_root()).expanduser().resolve()
        self.free_space_reserve_bytes = free_space_reserve_bytes

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            info = os.lstat(self.root)
        except OSError as exc:
            raise ArchiveError("ARCHIVE_ROOT_UNAVAILABLE", str(exc)) from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ArchiveError("ARCHIVE_ROOT_UNSAFE")
        os.chmod(self.root, 0o700)

    def publish(self, snapshot: ArchiveSnapshot, verification: ArchiveVerification) -> PublishedArchive:
        if (
            verification.archive_id != snapshot.archive_id
            or verification.state_hash != snapshot.state_hash
            or verification.patch_hash != snapshot.patch_hash
        ):
            raise ArchiveError("VERIFICATION_BINDING_MISMATCH")
        self._ensure_root()
        final = self.root / snapshot.archive_id
        verifier = SessionArchiveVerifier()
        if final.exists():
            existing = verifier.verify_published(final, repository_path=snapshot.repository_path)
            if existing.archive_id != snapshot.archive_id or existing.state_hash != snapshot.state_hash:
                raise ArchiveError("ARCHIVE_ID_CONTENT_CONFLICT")
            return self.load(snapshot.archive_id)

        required = snapshot.payload_bytes + self.free_space_reserve_bytes + 1024 * 1024
        try:
            free = shutil.disk_usage(self.root).free
        except OSError as exc:
            raise ArchiveError("ARCHIVE_SPACE_CHECK_FAILED", str(exc)) from exc
        if free < required:
            raise ArchiveError("INSUFFICIENT_ARCHIVE_SPACE")

        scratch = Path(tempfile.mkdtemp(prefix=f".{snapshot.archive_id}.tmp-", dir=self.root))
        os.chmod(scratch, 0o700)
        published = False
        try:
            untracked_root = scratch / "untracked"
            untracked_root.mkdir(mode=0o700)
            manifest = _manifest_for_snapshot(snapshot, verification)
            manifest_bytes = canonical_json_bytes(manifest)
            manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            _safe_write(scratch / "manifest.json", manifest_bytes)
            _safe_write(scratch / "changes.patch", snapshot.patch_bytes)

            source_root = Path(snapshot.worktree_path)
            file_hashes: dict[str, str] = {}
            for entry in snapshot.untracked_entries:
                target = untracked_root / entry.path
                if entry.kind == "directory":
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.chmod(target, 0o700)
                elif entry.kind == "file":
                    _copy_verified_file(source_root / entry.path, target, entry)
                    file_hashes[entry.path] = entry.content_hash
                elif entry.kind == "symlink":
                    # Metadata in manifest is the complete recoverable payload.
                    continue
                else:
                    raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")

            payload_hash = _payload_hash(
                patch_hash=snapshot.patch_hash,
                entries=snapshot.untracked_entries,
            )
            checksums = {
                "schema_version": snapshot.schema_version,
                "manifest_sha256": manifest_hash,
                "changes_patch_sha256": snapshot.patch_hash,
                "untracked_files": file_hashes,
                "overall_payload_hash": payload_hash,
            }
            _safe_write(scratch / "checksums.json", canonical_json_bytes(checksums))
            verifier.verify_published(scratch, repository_path=snapshot.repository_path)
            try:
                directory_fd = os.open(scratch, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
            os.replace(scratch, final)
            published = True
            try:
                root_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(root_fd)
                finally:
                    os.close(root_fd)
            except OSError:
                pass
            return self.load(snapshot.archive_id)
        finally:
            if not published and scratch.exists():
                shutil.rmtree(scratch, ignore_errors=True)

    def load(self, archive_id: str) -> PublishedArchive:
        archive_id = validate_archive_id(archive_id)
        archive = self.root / archive_id
        manifest = _read_json_object(archive / "manifest.json", code="INVALID_ARCHIVE_MANIFEST")
        checksums = _read_json_object(archive / "checksums.json", code="INVALID_ARCHIVE_CHECKSUMS")
        manifest_hash = hashlib.sha256((archive / "manifest.json").read_bytes()).hexdigest()
        if checksums.get("manifest_sha256") != manifest_hash:
            raise ArchiveError("MANIFEST_HASH_MISMATCH")
        aliases = manifest.get("alias_session_ids")
        if not isinstance(aliases, list) or not all(isinstance(value, str) for value in aliases):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        required_strings = (
            "archive_id",
            "project_id",
            "logical_workspace_id",
            "workspace_id",
            "physical_worktree_id",
            "source_revision",
            "base_revision",
            "state_hash",
            "tracked_patch_hash",
            "overall_payload_hash",
            "created_at",
            "verified_at",
        )
        if any(not isinstance(manifest.get(name), str) or not manifest.get(name) for name in required_strings):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        if manifest["archive_id"] != archive_id:
            raise ArchiveError("ARCHIVE_ID_CONTENT_CONFLICT")
        schema_version = manifest.get("schema_version")
        payload_bytes = manifest.get("payload_bytes")
        if schema_version != ARCHIVE_SCHEMA_VERSION or isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        return PublishedArchive(
            archive_id=archive_id,
            archive_path=str(archive),
            schema_version=schema_version,
            project_id=str(manifest["project_id"]),
            logical_workspace_id=str(manifest["logical_workspace_id"]),
            workspace_id=str(manifest["workspace_id"]),
            physical_worktree_id=str(manifest["physical_worktree_id"]),
            source_revision=str(manifest["source_revision"]),
            base_revision=str(manifest["base_revision"]),
            state_hash=str(manifest["state_hash"]),
            patch_hash=str(manifest["tracked_patch_hash"]),
            manifest_hash=manifest_hash,
            payload_hash=str(manifest["overall_payload_hash"]),
            alias_session_ids=tuple(aliases),
            payload_bytes=payload_bytes,
            created_at=str(manifest["created_at"]),
            verified_at=str(manifest["verified_at"]),
        )


def persist_published_archive(persistence: object, published: PublishedArchive) -> dict[str, object]:
    """Persist only bounded archive receipt metadata; never payload content."""

    receipt: dict[str, object] = {
        "archive_id": published.archive_id,
        "schema_version": published.schema_version,
        "project_id": published.project_id,
        "logical_workspace_id": published.logical_workspace_id,
        "workspace_id": published.workspace_id,
        "physical_worktree_id": published.physical_worktree_id,
        "source_revision": published.source_revision,
        "base_revision": published.base_revision,
        "state_hash": published.state_hash,
        "patch_hash": published.patch_hash,
        "manifest_hash": published.manifest_hash,
        "archive_path": published.archive_path,
        "alias_session_ids": list(published.alias_session_ids),
        "payload_bytes": published.payload_bytes,
        "created_at": published.created_at,
        "verified_at": published.verified_at,
    }
    saver = getattr(persistence, "save_session_archive_receipt", None)
    if not callable(saver):
        raise ArchiveError("ARCHIVE_PERSISTENCE_UNAVAILABLE")
    saver(receipt)
    return receipt


def _safe_restore_parent(root: Path, relative_path: str) -> Path:
    relative = PurePosixPath(validate_archive_relative_path(relative_path))
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            try:
                info = os.lstat(current)
            except OSError as exc:
                raise ArchiveError("RESTORE_PARENT_UNSAFE", str(exc)) from exc
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ArchiveError("RESTORE_PARENT_UNSAFE")
        else:
            current.mkdir(mode=0o700)
    return root / relative.as_posix()


class SessionArchiveRestorer:
    def __init__(self, *, store: SessionArchiveStore, verifier: SessionArchiveVerifier | None = None) -> None:
        self.store = store
        self.verifier = verifier or SessionArchiveVerifier()

    def restore(
        self,
        archive_id: str,
        *,
        repository_path: str | os.PathLike[str],
        target_worktree_path: str | os.PathLike[str],
    ) -> RestoreResult:
        repository = Path(repository_path).expanduser().resolve()
        target = Path(target_worktree_path).expanduser().resolve()
        published = self.store.load(archive_id)
        archive = Path(published.archive_path)
        verified = self.verifier.verify_published(archive, repository_path=repository)
        if verified.archive_id != archive_id or verified.state_hash != published.state_hash:
            raise ArchiveError("VERIFICATION_BINDING_MISMATCH")
        if not target.is_dir():
            raise ArchiveError("RESTORE_TARGET_UNAVAILABLE")
        try:
            head = _head_revision(target)
        except ArchiveError as exc:
            raise ArchiveError("RESTORE_TARGET_NOT_GIT") from exc
        if head != published.base_revision:
            raise ArchiveError("RESTORE_BASE_MISMATCH")
        status = _git(target, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]).stdout
        if status:
            raise ArchiveError("RESTORE_TARGET_NOT_CLEAN")

        manifest = _read_json_object(archive / "manifest.json", code="INVALID_ARCHIVE_MANIFEST")
        raw_entries = manifest.get("untracked_entries")
        if not isinstance(raw_entries, list):
            raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
        entries = tuple(_entry_from_metadata(value) for value in raw_entries)
        patch_bytes = (archive / "changes.patch").read_bytes()
        if patch_bytes:
            applied = _git(
                target,
                ["apply", "--binary", "--whitespace=nowarn", "-"],
                input_bytes=patch_bytes,
                check=False,
            )
            if applied.returncode != 0:
                detail = applied.stderr.decode("utf-8", errors="replace").strip()
                raise ArchiveError("RESTORE_PATCH_APPLY_FAILED", detail[:1000])

        # Directories first so later files/symlinks never need recursive copy.
        for entry in sorted(
            (item for item in entries if item.kind == "directory"),
            key=lambda item: (len(PurePosixPath(item.path).parts), item.path),
        ):
            destination = _safe_restore_parent(target, entry.path)
            if destination.exists() or destination.is_symlink():
                info = os.lstat(destination)
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise ArchiveError("RESTORE_PATH_COLLISION")
            else:
                destination.mkdir(mode=entry.mode or 0o700)
                os.chmod(destination, entry.mode or 0o700)

        for entry in entries:
            if entry.kind == "directory":
                continue
            destination = _safe_restore_parent(target, entry.path)
            if destination.exists() or destination.is_symlink():
                raise ArchiveError("RESTORE_PATH_COLLISION")
            if entry.kind == "file":
                _require_safe_existing_parents(archive / "untracked", entry.path)
                source = archive / "untracked" / entry.path
                _copy_verified_file(source, destination, entry)
                os.chmod(destination, entry.mode)
            elif entry.kind == "symlink":
                if entry.symlink_target is None:
                    raise ArchiveError("INVALID_ARCHIVE_MANIFEST")
                try:
                    os.symlink(entry.symlink_target, destination)
                except OSError as exc:
                    raise ArchiveError("RESTORE_SYMLINK_FAILED", str(exc)) from exc
            else:
                raise ArchiveError("UNSUPPORTED_ARCHIVE_ENTRY")

        restored_patch, restored_tracked_paths = _worktree_patch(target, published.base_revision)
        restored_patch_hash = hashlib.sha256(restored_patch).hexdigest()
        if restored_patch_hash != published.patch_hash:
            raise ArchiveError("RESTORED_PATCH_MISMATCH")
        if restored_tracked_paths != tuple(manifest.get("tracked_paths", ())):
            raise ArchiveError("RESTORED_PATCH_MISMATCH")
        restored_entries = _collect_untracked_entries(target)
        if restored_entries != entries:
            raise ArchiveError(
                "RESTORED_UNTRACKED_MISMATCH",
                f"expected={entries!r} actual={restored_entries!r}",
            )
        state_hash = normalized_state_hash(
            base_revision=published.base_revision,
            patch_hash=restored_patch_hash,
            entries=restored_entries,
        )
        if state_hash != published.state_hash:
            raise ArchiveError("RESTORED_STATE_MISMATCH")
        return RestoreResult(
            archive_id=archive_id,
            target_worktree_path=str(target),
            state_hash=state_hash,
            restored_at=_utc_now(),
        )


class ArchiveDisposition(str, Enum):
    """Dry-run decision for one physical retained DEVELOPMENT worktree."""

    KEEP = "KEEP"
    ARCHIVE = "ARCHIVE"
    SAFE_TO_CLOSE = "SAFE_TO_CLOSE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


@dataclass(frozen=True)
class SessionArchiveObservation:
    """Non-secret evidence used to classify one retained session alias.

    The classifier deliberately consumes observations instead of touching Git,
    SQLite, sidecars, or the filesystem itself.  Callers remain responsible for
    producing exact evidence through the existing DevMCP read-only boundaries.
    """

    session_id: str
    project_id: str
    logical_workspace_id: str
    workspace_id: str
    physical_worktree_id: str
    worktree_path: str
    source_revision: str
    base_revision: str
    status: str
    expired: bool
    stale: bool
    dirty: bool
    worktree_available: bool
    active_task: bool
    active_lease: bool
    active_session: bool
    canonical_subsumed: bool
    observation_error: str | None = None


@dataclass(frozen=True)
class PhysicalWorktreeAssessment:
    physical_worktree_id: str
    worktree_path: str
    project_id: str
    logical_workspace_id: str
    workspace_id: str
    source_revision: str
    base_revision: str
    alias_session_ids: tuple[str, ...]
    disposition: ArchiveDisposition
    reason_codes: tuple[str, ...]
    dirty: bool
    all_expired: bool
    all_stale: bool
    worktree_available: bool
    canonical_subsumed: bool
    active_task: bool
    active_lease: bool
    active_session: bool

    def to_metadata(self) -> dict[str, object]:
        """Return bounded diagnostics without worktree contents or archive data."""

        return {
            "physical_worktree_id": self.physical_worktree_id,
            "project_id": self.project_id,
            "logical_workspace_id": self.logical_workspace_id,
            "workspace_id": self.workspace_id,
            "source_revision": self.source_revision,
            "base_revision": self.base_revision,
            "alias_session_ids": list(self.alias_session_ids),
            "disposition": self.disposition.value,
            "reason_codes": list(self.reason_codes),
            "dirty": self.dirty,
            "all_expired": self.all_expired,
            "all_stale": self.all_stale,
            "worktree_available": self.worktree_available,
            "canonical_subsumed": self.canonical_subsumed,
            "active_task": self.active_task,
            "active_lease": self.active_lease,
            "active_session": self.active_session,
        }


@dataclass(frozen=True)
class SessionArchiveClassification:
    groups: tuple[PhysicalWorktreeAssessment, ...]
    counts: dict[str, int]
    physical_worktree_count: int
    alias_session_count: int

    def to_metadata(self) -> dict[str, object]:
        return {
            "physical_worktree_count": self.physical_worktree_count,
            "alias_session_count": self.alias_session_count,
            "counts": dict(self.counts),
            "groups": [group.to_metadata() for group in self.groups],
        }


def _unique(values: Iterable[str]) -> set[str]:
    return {value for value in values}


def _identity_mismatch(rows: tuple[SessionArchiveObservation, ...]) -> bool:
    identity_sets = (
        _unique(row.project_id for row in rows),
        _unique(row.logical_workspace_id for row in rows),
        _unique(row.workspace_id for row in rows),
        _unique(row.worktree_path for row in rows),
        _unique(row.source_revision for row in rows),
        _unique(row.base_revision for row in rows),
    )
    if any(len(values) != 1 for values in identity_sets):
        return True
    return any(row.source_revision != row.base_revision for row in rows)


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def observations_from_session_payloads(
    payloads: Iterable[Mapping[str, object]],
    *,
    active_task_ids: frozenset[str] = frozenset(),
    active_lease_worktree_ids: frozenset[str] = frozenset(),
    canonical_subsumed_session_ids: frozenset[str] = frozenset(),
) -> tuple[SessionArchiveObservation, ...]:
    """Normalize existing session-list payloads into classifier evidence.

    Canonical subsumption is never inferred from status or cleanliness. The
    caller must supply session IDs backed by the existing exact-subsumption
    proof. Task and lease activity are likewise explicit control-plane inputs.
    Malformed payloads remain visible as invalid observations so classification
    fails closed rather than silently omitting them.
    """

    observations: list[SessionArchiveObservation] = []
    for payload in payloads:
        identity_raw = payload.get("identity")
        identity = identity_raw if isinstance(identity_raw, Mapping) else {}
        raw_session_id = _string(payload.get("session_id"))
        session_id = raw_session_id or "invalid:missing-session-id"
        physical_worktree_id = _string(identity.get("worktree_id"))
        worktree_path = _string(identity.get("root_path")) or _string(payload.get("worktree_path"))
        workspace_id = _string(identity.get("workspace_id"))
        project_id = _string(payload.get("project_id")) or _string(identity.get("project_id"))
        logical_workspace_id = _string(payload.get("logical_workspace_id")) or _string(
            identity.get("logical_workspace_id")
        )
        source_revision = _string(payload.get("source_revision")) or _string(
            identity.get("source_revision")
        )
        base_revision = _string(payload.get("source_commit"))
        task_id = _string(payload.get("task_id")) or _string(identity.get("task_id"))

        required = {
            "session_id": raw_session_id,
            "physical_worktree_id": physical_worktree_id,
            "worktree_path": worktree_path,
            "workspace_id": workspace_id,
            "project_id": project_id,
            "logical_workspace_id": logical_workspace_id,
            "source_revision": source_revision,
            "base_revision": base_revision,
        }
        missing = sorted(name for name, value in required.items() if value is None)
        observation_error = "MISSING:" + ",".join(missing) if missing else None
        physical_identity = physical_worktree_id or f"invalid:{session_id}"

        observations.append(
            SessionArchiveObservation(
                session_id=session_id,
                project_id=project_id or "invalid",
                logical_workspace_id=logical_workspace_id or "invalid",
                workspace_id=workspace_id or "invalid",
                physical_worktree_id=physical_identity,
                worktree_path=worktree_path or "invalid",
                source_revision=source_revision or "invalid",
                base_revision=base_revision or "invalid",
                status=_string(payload.get("status")) or "invalid",
                expired=payload.get("expired") is True,
                stale=payload.get("stale") is True,
                dirty=payload.get("dirty") is True,
                worktree_available=payload.get("worktree_available") is True,
                active_task=task_id in active_task_ids if task_id is not None else False,
                active_lease=physical_identity in active_lease_worktree_ids,
                active_session=payload.get("active") is True or payload.get("status") == "active",
                canonical_subsumed=session_id in canonical_subsumed_session_ids,
                observation_error=observation_error,
            )
        )
    return tuple(observations)


_ACTIVE_TASK_STATES = frozenset({"queued", "ready", "leased", "running", "verifying", "review_ready"})


def _payload_project_id(payload: Mapping[str, object]) -> str | None:
    direct = _string(payload.get("project_id"))
    if direct is not None:
        return direct
    identity_raw = payload.get("identity")
    if isinstance(identity_raw, Mapping):
        return _string(identity_raw.get("project_id")) or _string(identity_raw.get("workspace_id"))
    return None


def _control_plane_activity(
    control_plane: Mapping[str, object],
) -> tuple[frozenset[str], frozenset[str], str | None]:
    """Extract exact current task/lease identities from Director status metadata.

    Missing or malformed current-state evidence is not interpreted as an empty
    control plane.  The caller receives an error marker so every candidate can
    fail closed instead of becoming archive-eligible on incomplete evidence.
    """

    current_raw = control_plane.get("current")
    if not isinstance(current_raw, Mapping):
        return frozenset(), frozenset(), "CONTROL_PLANE_CURRENT_MISSING"
    tasks_raw = current_raw.get("tasks")
    leases_raw = current_raw.get("leases")
    if not isinstance(tasks_raw, (list, tuple)) or not isinstance(leases_raw, (list, tuple)):
        return frozenset(), frozenset(), "CONTROL_PLANE_ACTIVITY_MISSING"

    active_task_ids: set[str] = set()
    active_lease_worktree_ids: set[str] = set()
    for task in tasks_raw:
        if not isinstance(task, Mapping):
            return frozenset(), frozenset(), "CONTROL_PLANE_TASK_INVALID"
        task_id = _string(task.get("task_id"))
        status = _string(task.get("status"))
        if task_id is None or status is None:
            return frozenset(), frozenset(), "CONTROL_PLANE_TASK_INVALID"
        if status in _ACTIVE_TASK_STATES:
            active_task_ids.add(task_id)

    for lease in leases_raw:
        if not isinstance(lease, Mapping):
            return frozenset(), frozenset(), "CONTROL_PLANE_LEASE_INVALID"
        worktree_id = _string(lease.get("working_tree_id"))
        if worktree_id is None:
            return frozenset(), frozenset(), "CONTROL_PLANE_LEASE_INVALID"
        active_lease_worktree_ids.add(worktree_id)

    return frozenset(active_task_ids), frozenset(active_lease_worktree_ids), None


def classify_session_inventory(
    payloads: Iterable[Mapping[str, object]],
    *,
    control_plane: Mapping[str, object],
    project_id: str | None = None,
    canonical_subsumed_session_ids: frozenset[str] = frozenset(),
) -> SessionArchiveClassification:
    """Classify a real retained-session inventory without mutating any state.

    ``payloads`` is compatible with ``workspace_list_development_sessions``
    session metadata. ``control_plane`` is compatible with
    ``director_status_summary`` and contributes only exact current task/lease
    evidence.  Canonical subsumption remains an explicit caller-supplied proof;
    this function never infers it from status, revision age, or cleanliness.
    """

    selected: list[Mapping[str, object]] = []
    for payload in payloads:
        if project_id is None:
            selected.append(payload)
            continue
        observed_project = _payload_project_id(payload)
        if observed_project == project_id:
            selected.append(payload)
        elif observed_project is None:
            # Unknown ownership cannot safely be discarded from a targeted
            # inventory: keep it visible and let normalization fail closed.
            selected.append(payload)

    active_task_ids, active_lease_worktree_ids, control_plane_error = _control_plane_activity(
        control_plane
    )
    observations = observations_from_session_payloads(
        selected,
        active_task_ids=active_task_ids,
        active_lease_worktree_ids=active_lease_worktree_ids,
        canonical_subsumed_session_ids=canonical_subsumed_session_ids,
    )
    if control_plane_error is not None:
        observations = tuple(
            replace(
                observation,
                observation_error=(
                    f"{observation.observation_error};{control_plane_error}"
                    if observation.observation_error
                    else control_plane_error
                ),
            )
            for observation in observations
        )
    return classify_archive_groups(observations)


def _assess_group(
    physical_worktree_id: str,
    rows: tuple[SessionArchiveObservation, ...],
    *,
    conflicting_session_ids: frozenset[str] = frozenset(),
) -> PhysicalWorktreeAssessment:
    first = rows[0]
    alias_session_ids = tuple(sorted({row.session_id for row in rows}))

    identity_mismatch = _identity_mismatch(rows)
    dirty_values = {row.dirty for row in rows}
    availability_values = {row.worktree_available for row in rows}
    if len(dirty_values) != 1 or len(availability_values) != 1:
        identity_mismatch = True

    dirty = any(row.dirty for row in rows)
    all_expired = all(row.expired for row in rows)
    all_stale = all(row.stale for row in rows)
    worktree_available = all(row.worktree_available for row in rows)
    canonical_subsumed = all(row.canonical_subsumed for row in rows)
    active_task = any(row.active_task for row in rows)
    active_lease = any(row.active_lease for row in rows)
    active_session = any(row.active_session for row in rows)

    if any(row.session_id in conflicting_session_ids for row in rows):
        disposition = ArchiveDisposition.REVIEW_REQUIRED
        reasons = ("SESSION_ID_CONFLICT",)
    elif any(row.observation_error for row in rows):
        disposition = ArchiveDisposition.REVIEW_REQUIRED
        reasons = ("INVALID_OBSERVATION",)
    elif identity_mismatch:
        disposition = ArchiveDisposition.REVIEW_REQUIRED
        reasons = ("ALIAS_IDENTITY_MISMATCH",)
    elif not worktree_available:
        disposition = ArchiveDisposition.REVIEW_REQUIRED
        reasons = ("WORKTREE_UNAVAILABLE",)
    elif active_session or active_task or active_lease or not all_expired or not all_stale:
        disposition = ArchiveDisposition.KEEP
        mutable_reasons: list[str] = []
        if active_session:
            mutable_reasons.append("ACTIVE_SESSION")
        if active_task:
            mutable_reasons.append("ACTIVE_TASK")
        if active_lease:
            mutable_reasons.append("ACTIVE_LEASE")
        if not all_expired:
            mutable_reasons.append("NOT_ALL_EXPIRED")
        if not all_stale:
            mutable_reasons.append("NOT_ALL_STALE")
        reasons = tuple(mutable_reasons)
    elif not dirty:
        disposition = ArchiveDisposition.SAFE_TO_CLOSE
        reasons = ("ALL_CLEAN",)
    elif canonical_subsumed:
        disposition = ArchiveDisposition.SAFE_TO_CLOSE
        reasons = ("CANONICAL_SUBSUMED",)
    else:
        disposition = ArchiveDisposition.ARCHIVE
        reasons = ("UNIQUE_DIRTY_DELTA",)

    return PhysicalWorktreeAssessment(
        physical_worktree_id=physical_worktree_id,
        worktree_path=first.worktree_path,
        project_id=first.project_id,
        logical_workspace_id=first.logical_workspace_id,
        workspace_id=first.workspace_id,
        source_revision=first.source_revision,
        base_revision=first.base_revision,
        alias_session_ids=alias_session_ids,
        disposition=disposition,
        reason_codes=reasons,
        dirty=dirty,
        all_expired=all_expired,
        all_stale=all_stale,
        worktree_available=worktree_available,
        canonical_subsumed=canonical_subsumed,
        active_task=active_task,
        active_lease=active_lease,
        active_session=active_session,
    )


def classify_archive_groups(
    observations: Iterable[SessionArchiveObservation],
) -> SessionArchiveClassification:
    """Group aliases by physical worktree and produce a fail-closed dry run.

    No deletion, archive creation, Git mutation, session transition, or lease
    mutation occurs here.  In particular, ``ARCHIVE`` means only that the
    physical worktree has passed the metadata-level preconditions for a later
    verified archive build; it is never prune authority by itself.
    """

    rows = tuple(observations)
    grouped: dict[str, list[SessionArchiveObservation]] = {}
    by_session_id: dict[str, set[SessionArchiveObservation]] = {}
    for observation in rows:
        by_session_id.setdefault(observation.session_id, set()).add(observation)
        grouped.setdefault(observation.physical_worktree_id, []).append(observation)
    conflicting_session_ids = frozenset(
        session_id for session_id, values in by_session_id.items() if len(values) > 1
    )

    assessments = tuple(
        sorted(
            (
                _assess_group(
                    physical_worktree_id,
                    tuple(group_rows),
                    conflicting_session_ids=conflicting_session_ids,
                )
                for physical_worktree_id, group_rows in grouped.items()
            ),
            key=lambda group: group.physical_worktree_id,
        )
    )
    counts = {disposition.value: 0 for disposition in ArchiveDisposition}
    for assessment in assessments:
        counts[assessment.disposition.value] += 1
    return SessionArchiveClassification(
        groups=assessments,
        counts=counts,
        physical_worktree_count=len(assessments),
        alias_session_count=len(rows),
    )
