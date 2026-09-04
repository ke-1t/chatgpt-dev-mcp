"""Content-addressed, secret-safe source packages for managed cloud workspaces."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .baseline_snapshot import BaselineSnapshot, snapshot_path_allowed
from .director import contains_secret_like_content


MAX_CLOUD_PACKAGE_FILES = 10000
MAX_CLOUD_PACKAGE_FILE_BYTES = 8 * 1024 * 1024
MAX_CLOUD_PACKAGE_BYTES = 64 * 1024 * 1024
_REVISION_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CloudWorkspacePackageError(ValueError):
    pass


@dataclass(frozen=True)
class CloudWorkspaceEntry:
    path: str
    mode: int
    size: int
    content_hash: str


@dataclass(frozen=True)
class CloudWorkspacePackage:
    package_id: str
    workspace_id: str
    source_revision: str
    workload_id: str
    entries: tuple[CloudWorkspaceEntry, ...]
    manifest_hash: str
    payload_bytes: int
    payload: bytes
    dirty_snapshot_id: str | None = None
    excluded_paths: tuple[str, ...] = ()
    excluded_reasons: tuple[tuple[str, str], ...] = ()


def _git_bytes(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CloudWorkspacePackageError("Git source inspection failed") from exc
    if result.returncode != 0:
        raise CloudWorkspacePackageError("source revision is unavailable")
    return result.stdout


def _safe_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise CloudWorkspacePackageError(f"{name} is invalid")
    return value


def _tar_payload(files: list[tuple[str, int, bytes]], dirty_snapshot: BaselineSnapshot | None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, mode, content in files:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
        if dirty_snapshot is not None:
            patch_path = dirty_snapshot.artifact_path / "tracked.patch"
            if patch_path.is_file() and not patch_path.is_symlink():
                content = patch_path.read_bytes()
                info = tarfile.TarInfo(".devmcp/dirty/tracked.patch")
                info.size = len(content)
                info.mode = 0o600
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(content))
            for path in dirty_snapshot.untracked_paths:
                source = dirty_snapshot.artifact_path / "untracked" / path
                content = source.read_bytes()
                info = tarfile.TarInfo(f".devmcp/dirty/untracked/{path}")
                info.size = len(content)
                info.mode = 0o600
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def build_cloud_workspace_package(
    repository_path: Path,
    *,
    source_revision: str,
    workspace_id: str,
    workload_id: str,
    dirty_snapshot: BaselineSnapshot | None = None,
) -> CloudWorkspacePackage:
    repo = Path(repository_path).resolve(strict=False)
    if repo.is_symlink() or not repo.is_dir():
        raise CloudWorkspacePackageError("repository is unavailable")
    if not isinstance(source_revision, str) or not _REVISION_RE.fullmatch(source_revision):
        raise CloudWorkspacePackageError("source revision is invalid")
    workspace = _safe_identifier(workspace_id, "workspace_id")
    workload = _safe_identifier(workload_id, "workload_id")
    resolved = _git_bytes(repo, "rev-parse", "--verify", f"{source_revision}^{{commit}}").decode("ascii", errors="strict").strip()
    if resolved.lower() != source_revision.lower():
        raise CloudWorkspacePackageError("source revision does not match")

    tree = _git_bytes(repo, "ls-tree", "-r", "-z", "--full-tree", source_revision)
    raw_entries = [item for item in tree.split(b"\0") if item]
    if len(raw_entries) > MAX_CLOUD_PACKAGE_FILES:
        raise CloudWorkspacePackageError("package contains too many files")
    files: list[tuple[str, int, bytes]] = []
    entries: list[CloudWorkspaceEntry] = []
    excluded_reasons: dict[str, str] = {}
    total_content = 0
    for raw in raw_entries:
        try:
            header, raw_path = raw.split(b"\t", 1)
            mode_text, object_type, object_id = header.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CloudWorkspacePackageError("Git tree entry is invalid") from exc
        if object_type != "blob":
            excluded_reasons[path] = f"unsupported_git_object:{object_type}"
            continue
        if mode_text == "120000":
            raise CloudWorkspacePackageError("Git symlink entries are not permitted in managed cloud packages")
        allowed, _reason = snapshot_path_allowed(path)
        if not allowed:
            excluded_reasons[path] = _reason or "policy_excluded"
            continue
        content = _git_bytes(repo, "cat-file", "blob", object_id)
        if len(content) > MAX_CLOUD_PACKAGE_FILE_BYTES:
            raise CloudWorkspacePackageError("package file exceeds size limit")
        total_content += len(content)
        if total_content > MAX_CLOUD_PACKAGE_BYTES:
            raise CloudWorkspacePackageError("package exceeds size limit")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and contains_secret_like_content(text):
            excluded_reasons[path] = "secret_like_content"
            continue
        mode = 0o755 if mode_text == "100755" else 0o644
        digest = hashlib.sha256(content).hexdigest()
        entries.append(CloudWorkspaceEntry(path, mode, len(content), digest))
        files.append((path, mode, content))

    entries.sort(key=lambda item: item.path)
    files.sort(key=lambda item: item[0])
    manifest = {
        "workspace_id": workspace,
        "source_revision": source_revision.lower(),
        "workload_id": workload,
        "entries": [entry.__dict__ for entry in entries],
        "excluded_reasons": {path: excluded_reasons[path] for path in sorted(excluded_reasons)},
        "dirty_snapshot_id": dirty_snapshot.snapshot_id if dirty_snapshot else None,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    payload = _tar_payload(files, dirty_snapshot)
    if len(payload) > MAX_CLOUD_PACKAGE_BYTES:
        raise CloudWorkspacePackageError("package payload exceeds size limit")
    identity = hashlib.sha256(manifest_bytes + hashlib.sha256(payload).digest()).hexdigest()
    return CloudWorkspacePackage(
        package_id=f"package:{identity[:32]}",
        workspace_id=workspace,
        source_revision=source_revision.lower(),
        workload_id=workload,
        entries=tuple(entries),
        manifest_hash=manifest_hash,
        payload_bytes=len(payload),
        payload=payload,
        dirty_snapshot_id=dirty_snapshot.snapshot_id if dirty_snapshot else None,
        excluded_paths=tuple(sorted(excluded_reasons)),
        excluded_reasons=tuple(sorted(excluded_reasons.items())),
    )


__all__ = [
    "CloudWorkspaceEntry",
    "CloudWorkspacePackage",
    "CloudWorkspacePackageError",
    "build_cloud_workspace_package",
]
