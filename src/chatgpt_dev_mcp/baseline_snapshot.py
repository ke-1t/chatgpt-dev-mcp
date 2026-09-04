"""Immutable, secret-safe snapshots of a dirty canonical Git baseline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .director import contains_secret_like_content
from .development import UNBORN_HEAD
from .process_runner import run_bounded


MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILES = 4096
SNAPSHOT_ID_RE = re.compile(r"^snapshot:[A-Za-z0-9._:-]{8,160}$")
_SECRET_NAME_RE = re.compile(
    r"^(?:\.env(?:\..*)?|credentials(?:\..*)?|secrets?(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|known_hosts|.*\.(?:pem|key|p12|pfx|kdbx))$",
    re.IGNORECASE,
)
_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".aws",
        ".cache",
        ".config",
        ".ssh",
        ".tox",
        ".venv",
        "browser profiles",
        "chromedata",
        "chrome",
        "keychains",
        "mozilla",
        "node_modules",
        "dist",
        "build",
        "target",
        "coverage",
        "__pycache__",
    }
)


class BaselineSnapshotError(RuntimeError):
    """Raised when a snapshot cannot be captured or verified safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class BaselineSnapshot:
    snapshot_id: str
    workspace_id: str
    head_revision: str
    tracked_patch_hash: str
    tracked_paths: tuple[str, ...]
    untracked_manifest_hash: str
    untracked_paths: tuple[str, ...]
    created_at: str
    snapshot_hash: str
    canonical_dirty: bool
    artifact_path: Path
    included_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    excluded_reasons: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "workspace_id": self.workspace_id,
            "head_revision": self.head_revision,
            "source_revision": self.head_revision,
            "tracked_patch_hash": self.tracked_patch_hash,
            "tracked_paths": list(self.tracked_paths),
            "untracked_manifest_hash": self.untracked_manifest_hash,
            "untracked_paths": list(self.untracked_paths),
            "created_at": self.created_at,
            "snapshot_hash": self.snapshot_hash,
            "canonical_dirty": self.canonical_dirty,
            "included_paths": list(self.included_paths),
            "excluded_paths": list(self.excluded_paths),
            "excluded_reasons": dict(self.excluded_reasons),
        }


def _validate_workspace_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise BaselineSnapshotError("SNAPSHOT_WORKSPACE_INVALID", "workspace_id is invalid")
    return value


def _validate_relpath(value: str) -> str:
    if not value or value.startswith(("/", "~")) or "\\" in value or "\x00" in value:
        raise BaselineSnapshotError("SNAPSHOT_PATH_INVALID", "snapshot path is not relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BaselineSnapshotError("SNAPSHOT_PATH_INVALID", "snapshot path contains traversal")
    return "/".join(parts)


def _path_allowed(path: str) -> tuple[bool, str]:
    normalized = _validate_relpath(path)
    parts = normalized.split("/")
    if any(part.casefold() in _EXCLUDED_PARTS for part in parts):
        return False, "cache_or_build_artifact"
    if _SECRET_NAME_RE.fullmatch(parts[-1]):
        return False, "credential_like_name"
    return True, ""


def snapshot_path_allowed(path: str) -> tuple[bool, str]:
    """Expose the snapshot path policy for other secret-safe transfer formats."""

    return _path_allowed(path)


def _safe_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _git(repo: Path, *args: str, input_text: str | None = None) -> str:
    try:
        result = run_bounded(
            ["git", "-C", str(repo), *args],
            input_text=input_text,
            env=_safe_env(),
            timeout_seconds=30,
            max_output_bytes=MAX_TOTAL_BYTES,
        )
    except (OSError, ValueError) as exc:
        raise BaselineSnapshotError("SNAPSHOT_GIT_FAILED", "Git snapshot inspection failed") from exc
    if result.output_truncated:
        raise BaselineSnapshotError("SNAPSHOT_TOO_LARGE", "Git snapshot inspection output is too large")
    if result.timed_out or result.returncode != 0:
        raise BaselineSnapshotError("SNAPSHOT_GIT_FAILED", "Git snapshot inspection failed")
    return result.stdout


def _split_nul(value: str) -> list[str]:
    return [item for item in value.split("\x00") if item]


def _tracked_added_content(patch: str) -> str:
    """Return only textual lines introduced by a unified Git patch.

    Secret scanning the complete patch is both too broad and too weak: unchanged
    context lines are prefixed with a space and can look like assignments, while
    genuinely added lines are prefixed with ``+`` and therefore evade detectors
    anchored at the beginning of a content line.  Track hunk state explicitly so
    file headers are ignored but added content that itself starts with ``+`` is
    still preserved after stripping the single diff marker.
    """

    added: list[str] = []
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("\\ No newline at end of file"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return "\n".join(added)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise BaselineSnapshotError("SNAPSHOT_READ_FAILED", "Snapshot file could not be read") from exc
    return digest.hexdigest()


def _artifact_root(root: Path) -> Path:
    if not root.is_absolute():
        raise BaselineSnapshotError("SNAPSHOT_ROOT_INVALID", "snapshot artifact root must be absolute")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise BaselineSnapshotError("SNAPSHOT_ROOT_INVALID", "snapshot artifact root is not a private directory")
        os.chmod(root, 0o700)
    except OSError as exc:
        raise BaselineSnapshotError("SNAPSHOT_ROOT_INVALID", "snapshot artifact root is unavailable") from exc
    return root


def _metadata_path(artifact_root: Path, snapshot_id: str) -> Path:
    if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise BaselineSnapshotError("SNAPSHOT_ID_INVALID", "snapshot_id is invalid")
    return artifact_root / snapshot_id.removeprefix("snapshot:") / "metadata.json"


def _load_metadata(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise BaselineSnapshotError("SNAPSHOT_NOT_FOUND", "snapshot metadata is unavailable")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except BaselineSnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot metadata is invalid") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("snapshot_id"), str):
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot metadata is invalid")
    return raw


def _snapshot_from_metadata(root: Path, metadata: dict[str, Any]) -> BaselineSnapshot:
    snapshot_id = str(metadata.get("snapshot_id"))
    artifact_path = root / snapshot_id.removeprefix("snapshot:")
    raw_reasons = metadata.get("excluded_reasons", {})
    if raw_reasons is None:
        raw_reasons = {}
    if not isinstance(raw_reasons, Mapping):
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot metadata is invalid")
    return BaselineSnapshot(
        snapshot_id=snapshot_id,
        workspace_id=_validate_workspace_id(metadata.get("workspace_id")),
        head_revision=str(metadata.get("head_revision", "")),
        tracked_patch_hash=str(metadata.get("tracked_patch_hash", "")),
        tracked_paths=tuple(str(item) for item in metadata.get("tracked_paths", [])),
        untracked_manifest_hash=str(metadata.get("untracked_manifest_hash", "")),
        untracked_paths=tuple(str(item) for item in metadata.get("untracked_paths", [])),
        created_at=str(metadata.get("created_at", "")),
        snapshot_hash=str(metadata.get("snapshot_hash", "")),
        canonical_dirty=bool(metadata.get("canonical_dirty", False)),
        artifact_path=artifact_path,
        included_paths=tuple(str(item) for item in metadata.get("included_paths", [])),
        excluded_paths=tuple(str(item) for item in metadata.get("excluded_paths", [])),
        excluded_reasons=tuple(
            sorted(
                (str(path), str(reason))
                for path, reason in raw_reasons.items()
                if isinstance(path, str) and isinstance(reason, str)
            )
        ),
    )


def _verify_snapshot_artifact(snapshot: BaselineSnapshot) -> None:
    artifact = snapshot.artifact_path
    if artifact.is_symlink() or not artifact.is_dir():
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot artifact is unavailable")
    patch = artifact / "tracked.patch"
    patch_bytes = b""
    if patch.exists():
        if patch.is_symlink() or not patch.is_file():
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "tracked snapshot patch is invalid")
        try:
            patch_bytes = patch.read_bytes()
        except OSError as exc:
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "tracked snapshot patch is unreadable") from exc
    if _sha256_bytes(patch_bytes) != snapshot.tracked_patch_hash:
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "tracked snapshot patch hash does not match metadata")
    manifest: list[list[str]] = []
    for path in snapshot.untracked_paths:
        normalized = _validate_relpath(path)
        source = artifact / "untracked" / normalized
        if source.is_symlink() or not source.is_file():
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot untracked content is missing")
        try:
            size = source.stat().st_size
        except OSError as exc:
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot untracked content is unreadable") from exc
        if size > MAX_FILE_BYTES:
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot untracked content is too large")
        manifest.append([normalized, _sha256_file(source), str(size)])
    manifest_hash = _sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if manifest_hash != snapshot.untracked_manifest_hash:
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot untracked manifest does not match metadata")


def load_baseline_snapshot(snapshot_id: str, *, artifact_root: Path) -> BaselineSnapshot:
    root = _artifact_root(artifact_root)
    metadata_path = _metadata_path(root, snapshot_id)
    snapshot = _snapshot_from_metadata(root, _load_metadata(metadata_path))
    if snapshot.snapshot_id != snapshot_id:
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot identity does not match the requested id")
    _verify_snapshot_artifact(snapshot)
    return snapshot


def create_baseline_snapshot(source_repo: Path, *, workspace_id: str, artifact_root: Path) -> BaselineSnapshot:
    """Capture tracked dirty content and approved ordinary untracked files.

    The source checkout is read only. Snapshot IDs are content-addressed, so
    later canonical edits cannot change an already-created snapshot.
    """

    workspace = _validate_workspace_id(workspace_id)
    source = source_repo.resolve(strict=False)
    if source.is_symlink() or not source.is_dir():
        raise BaselineSnapshotError("SNAPSHOT_SOURCE_INVALID", "source repository is unavailable")
    try:
        head = _git(source, "rev-parse", "--verify", "HEAD").strip()
    except BaselineSnapshotError:
        # An unborn repository has no commit to diff against.  Keep the
        # baseline immutable by recording the explicit sentinel and relying on
        # the ordinary untracked-file manifest below.
        try:
            symbolic_head = _git(source, "symbolic-ref", "--quiet", "HEAD").strip()
        except BaselineSnapshotError:
            raise BaselineSnapshotError("SNAPSHOT_SOURCE_INVALID", "source HEAD is invalid") from None
        if not symbolic_head.startswith("refs/heads/"):
            raise BaselineSnapshotError("SNAPSHOT_SOURCE_INVALID", "source HEAD is invalid")
        head = UNBORN_HEAD
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        raise BaselineSnapshotError("SNAPSHOT_SOURCE_INVALID", "source HEAD is invalid")
    tracked_candidates = (
        []
        if head == UNBORN_HEAD
        else [_validate_relpath(item) for item in _split_nul(_git(source, "diff", "--name-only", "-z", "HEAD"))]
    )
    status_items = _split_nul(_git(source, "status", "--porcelain=v1", "-z", "--ignored=matching", "--untracked-files=all"))
    untracked_candidates: list[str] = []
    ignored_candidates: list[str] = []
    for item in status_items:
        if len(item) < 3:
            continue
        path = item[3:] if item[2] == " " else item[3:]
        try:
            path = _validate_relpath(path)
        except BaselineSnapshotError:
            continue
        state = item[:2]
        if state == "??":
            untracked_candidates.append(path)
        elif state == "!!":
            ignored_candidates.append(path)
    if head == UNBORN_HEAD:
        # In an unborn repository, files already added to the index are no
        # longer reported as ``??`` even though there is no committed tree to
        # reconstruct them from. Preserve those ordinary files in the same
        # content-addressed manifest used for untracked recovery content.
        staged_unborn = _split_nul(
            _git(source, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
        )
        for item in staged_unborn:
            try:
                path = _validate_relpath(item)
            except BaselineSnapshotError:
                continue
            if path not in untracked_candidates:
                untracked_candidates.append(path)

    included: list[str] = []
    excluded: list[str] = []
    excluded_reasons: dict[str, str] = {}
    tracked_paths: list[str] = []
    for path in tracked_candidates:
        allowed, reason = _path_allowed(path)
        if allowed:
            tracked_paths.append(path)
            included.append(path)
        else:
            excluded.append(path)
            excluded_reasons[path] = reason
    untracked_paths: list[str] = []
    for path in untracked_candidates:
        allowed, reason = _path_allowed(path)
        if allowed:
            candidate = source / path
            if candidate.is_symlink() or not candidate.is_file():
                excluded.append(path)
                excluded_reasons[path] = "symlink_or_non_file"
                continue
            try:
                size = candidate.stat().st_size
            except OSError:
                excluded.append(path)
                excluded_reasons[path] = "file_unreadable"
                continue
            if size > MAX_FILE_BYTES:
                excluded.append(path)
                excluded_reasons[path] = "file_too_large"
                continue
            try:
                raw = candidate.read_bytes()
                if b"\x00" in raw:
                    excluded.append(path)
                    excluded_reasons[path] = "binary_content"
                    continue
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                excluded.append(path)
                excluded_reasons[path] = "binary_or_unreadable"
                continue
            if contains_secret_like_content(text):
                excluded.append(path)
                excluded_reasons[path] = "secret_like_content"
                continue
            untracked_paths.append(path)
            included.append(path)
        else:
            excluded.append(path)
            excluded_reasons[path] = reason
    for path in ignored_candidates:
        if path in excluded:
            continue
        allowed, reason = _path_allowed(path)
        if not allowed:
            excluded.append(path)
            excluded_reasons[path] = reason or "ignored_secret_like_path"
    included = sorted(set(included))
    excluded = sorted(set(excluded) - set(included))
    excluded_reasons = {path: excluded_reasons.get(path, "policy_excluded") for path in excluded}
    if len(untracked_paths) > MAX_FILES:
        raise BaselineSnapshotError("SNAPSHOT_TOO_LARGE", "snapshot contains too many untracked files")

    deleted_tracked_paths: list[str] = []
    if tracked_paths and head != UNBORN_HEAD:
        deleted_tracked_paths = [
            path
            for path in _split_nul(_git(source, "diff", "--name-only", "-z", "--diff-filter=D", "HEAD", "--", *tracked_paths))
            if path in tracked_paths
        ]
    deleted_tracked = set(deleted_tracked_paths)
    materialized_tracked_paths = [path for path in tracked_paths if path not in deleted_tracked]
    tracked_patch_parts: list[str] = []
    if materialized_tracked_paths:
        tracked_patch_parts.append(_git(source, "diff", "--binary", "HEAD", "--", *materialized_tracked_paths))
    if deleted_tracked_paths:
        # A full binary deletion patch embeds the deleted blob and can make a
        # dirty snapshot enormous even though a same-HEAD worktree only needs
        # the deletion metadata. ``--full-index`` is sufficient for git apply
        # to verify and remove the exact tracked blob without copying it into
        # the snapshot artifact.
        tracked_patch_parts.append(_git(source, "diff", "--full-index", "HEAD", "--", *deleted_tracked_paths))
    tracked_patch = "".join(tracked_patch_parts)
    tracked_bytes = tracked_patch.encode("utf-8")
    if contains_secret_like_content(_tracked_added_content(tracked_patch)):
        raise BaselineSnapshotError(
            "SNAPSHOT_SECRET_CONTENT",
            "tracked snapshot content looks like credential material and was not captured",
        )
    total_bytes = len(tracked_bytes)
    if total_bytes > MAX_TOTAL_BYTES:
        raise BaselineSnapshotError("SNAPSHOT_TOO_LARGE", "tracked snapshot patch is too large")
    file_hashes: list[list[str]] = []
    for path in untracked_paths:
        candidate = source / path
        size = candidate.stat().st_size
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise BaselineSnapshotError("SNAPSHOT_TOO_LARGE", "snapshot is too large")
        file_hashes.append([path, _sha256_file(candidate), str(size)])
    tracked_hash = _sha256_bytes(tracked_bytes)
    manifest_hash = _sha256_bytes(json.dumps(file_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    identity = {
        "workspace_id": workspace,
        "head_revision": head,
        "tracked_patch_hash": tracked_hash,
        "tracked_paths": tracked_paths,
        "untracked_manifest_hash": manifest_hash,
        "untracked_paths": untracked_paths,
        "included_paths": included,
        "excluded_paths": excluded,
        "excluded_reasons": excluded_reasons,
        "files": file_hashes,
    }
    snapshot_hash = _sha256_bytes(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    snapshot_id = f"snapshot:{snapshot_hash[:32]}"
    root = _artifact_root(artifact_root)
    artifact = root / snapshot_id.removeprefix("snapshot:")
    metadata_path = artifact / "metadata.json"
    if metadata_path.exists():
        snapshot = _snapshot_from_metadata(root, _load_metadata(metadata_path))
        _verify_snapshot_artifact(snapshot)
        return snapshot
    try:
        artifact.mkdir(mode=0o700, parents=True, exist_ok=False)
        (artifact / "untracked").mkdir(mode=0o700)
        if tracked_patch:
            (artifact / "tracked.patch").write_bytes(tracked_bytes)
        for path in untracked_paths:
            source_path = source / path
            target = artifact / "untracked" / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source_path, target)
            os.chmod(target, 0o600)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        metadata = {
            **identity,
            "snapshot_id": snapshot_id,
            "created_at": created_at,
            "snapshot_hash": snapshot_hash,
            "canonical_dirty": bool(tracked_candidates or untracked_candidates or ignored_candidates),
            "excluded_reasons": excluded_reasons,
        }
        fd, temporary = tempfile.mkstemp(prefix="metadata-", dir=str(artifact), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, metadata_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except FileExistsError:
        snapshot = _snapshot_from_metadata(root, _load_metadata(metadata_path))
        _verify_snapshot_artifact(snapshot)
        return snapshot
    except OSError as exc:
        raise BaselineSnapshotError("SNAPSHOT_WRITE_FAILED", "snapshot artifact could not be written") from exc
    return _snapshot_from_metadata(root, metadata)


def materialize_baseline_snapshot(snapshot: BaselineSnapshot, target: Path) -> None:
    """Apply an immutable snapshot to an already-created detached worktree."""

    if not isinstance(snapshot, BaselineSnapshot):
        raise BaselineSnapshotError("SNAPSHOT_INVALID", "snapshot is invalid")
    target = target.resolve(strict=False)
    if target.is_symlink() or not target.is_dir():
        raise BaselineSnapshotError("SNAPSHOT_TARGET_INVALID", "snapshot target is unavailable")
    artifact = snapshot.artifact_path.resolve(strict=False)
    if artifact.is_symlink() or not artifact.is_dir():
        raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot artifact is unavailable")
    _verify_snapshot_artifact(snapshot)
    patch = artifact / "tracked.patch"
    if patch.exists():
        if patch.is_symlink() or not patch.is_file():
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "tracked snapshot patch is invalid")
        try:
            result = run_bounded(
                ["git", "-C", str(target), "apply", "--binary", "--whitespace=nowarn", str(patch)],
                env=_safe_env(),
                timeout_seconds=30,
                max_output_bytes=MAX_TOTAL_BYTES,
            )
        except (OSError, ValueError) as exc:
            raise BaselineSnapshotError("SNAPSHOT_APPLY_FAILED", "tracked snapshot could not be applied") from exc
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise BaselineSnapshotError("SNAPSHOT_APPLY_FAILED", "tracked snapshot could not be applied")
    for path in snapshot.untracked_paths:
        normalized = _validate_relpath(path)
        allowed, _reason = _path_allowed(normalized)
        if not allowed:
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot contains a forbidden path")
        source = artifact / "untracked" / normalized
        destination = target / normalized
        if source.is_symlink() or not source.is_file():
            raise BaselineSnapshotError("SNAPSHOT_CORRUPT", "snapshot untracked content is missing")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.is_symlink():
            raise BaselineSnapshotError("SNAPSHOT_TARGET_INVALID", "snapshot target contains a symlink")
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)


__all__ = [
    "BaselineSnapshot",
    "BaselineSnapshotError",
    "create_baseline_snapshot",
    "load_baseline_snapshot",
    "materialize_baseline_snapshot",
    "snapshot_path_allowed",
]
