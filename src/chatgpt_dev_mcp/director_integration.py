"""Safe DEVELOPMENT-session diff and canonical integration primitives.

Only fixed Git subcommands are used.  The module never commits, pushes, checks
out branches, or removes a worktree.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .development import UNBORN_HEAD
from .director import normalize_relative_path, sha256_text
from .process_runner import BoundedProcessResult, run_bounded


MAX_INTEGRATION_GIT_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_INTEGRATION_GIT_TIMEOUT_SECONDS = 30.0


class IntegrationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SessionDiff:
    base_revision: str
    patch: str
    patch_hash: str
    changed_paths: tuple[str, ...]

    def as_dict(self, *, include_patch: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "base_revision": self.base_revision,
            "patch_hash": self.patch_hash,
            "changed_paths": list(self.changed_paths),
            "has_changes": bool(self.patch),
        }
        if include_patch:
            payload["patch"] = self.patch
        return payload


@dataclass(frozen=True)
class IntegrationPreflight:
    base_revision: str
    canonical_revision: str
    canonical_clean: bool
    canonical_changed: bool
    conflict_free: bool
    patch_hash: str
    changed_paths: tuple[str, ...]
    integration_ready: bool
    review_ready: bool = True
    review_reason: str = ""
    canonical_repository_clean: bool = True
    canonical_dirty_paths: tuple[str, ...] = ()
    canonical_conflicting_paths: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if not self.changed_paths:
            return "no_changes"
        if not self.canonical_clean:
            return "canonical_dirty"
        if not self.conflict_free:
            return "conflict"
        if self.canonical_changed:
            return "canonical_changed"
        if not self.review_ready:
            return "review_blocked"
        return "ready"

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "base_revision": self.base_revision,
            "canonical_revision": self.canonical_revision,
            "canonical_clean": self.canonical_clean,
            "canonical_changed": self.canonical_changed,
            "conflict_free": self.conflict_free,
            "patch_hash": self.patch_hash,
            "changed_paths": list(self.changed_paths),
            "integration_ready": self.integration_ready,
            "review_ready": self.review_ready,
            "review_reason": self.review_reason,
            "canonical_repository_clean": self.canonical_repository_clean,
            "canonical_dirty_paths": list(self.canonical_dirty_paths),
            "canonical_conflicting_paths": list(self.canonical_conflicting_paths),
        }


@dataclass(frozen=True)
class IntegrationResult:
    applied: bool
    canonical_revision: str
    patch_hash: str

    def as_dict(self) -> dict[str, object]:
        return {
            "applied": self.applied,
            "canonical_revision": self.canonical_revision,
            "patch_hash": self.patch_hash,
            "commit_created": False,
            "push_performed": False,
        }


SNAPSHOT_UNBORN_HEAD = "0" * 40


@dataclass(frozen=True)
class _SnapshotDiffEvidence:
    diff: SessionDiff
    textual_delta_paths: tuple[str, ...]


def _repo(path: Path) -> Path:
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise IntegrationError("INTEGRATION_REPO_INVALID", "repository path is not a directory")
    return resolved


def _git(
    repo: Path,
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> BoundedProcessResult:
    process = run_bounded(
        ["git", "-C", str(repo), *args],
        input_text=input_text,
        env=env,
        timeout_seconds=MAX_INTEGRATION_GIT_TIMEOUT_SECONDS,
        max_output_bytes=MAX_INTEGRATION_GIT_OUTPUT_BYTES,
    )
    if process.timed_out:
        raise IntegrationError("INTEGRATION_GIT_TIMEOUT", "fixed Git command exceeded the bounded timeout")
    if process.output_truncated:
        raise IntegrationError("INTEGRATION_OUTPUT_LIMIT", "fixed Git command exceeded the bounded output limit")
    if check and process.returncode != 0:
        raise IntegrationError("INTEGRATION_GIT_FAILED", process.stderr.strip() or "fixed Git command failed")
    return process


def _head(repo: Path) -> str:
    resolved = _git(repo, ["rev-parse", "--verify", "HEAD"], check=False)
    head = resolved.stdout.strip()
    if resolved.returncode == 0 and head:
        return head
    symbolic = _git(repo, ["symbolic-ref", "--quiet", "HEAD"], check=False)
    if symbolic.returncode == 0 and symbolic.stdout.strip().startswith("refs/heads/"):
        return UNBORN_HEAD
    raise IntegrationError("INTEGRATION_HEAD_INVALID", "repository HEAD is unavailable")


def _empty_tree(repo: Path) -> str:
    tree = _git(repo, ["hash-object", "-t", "tree", "--stdin"], input_text="").stdout.strip()
    if not tree:
        raise IntegrationError("INTEGRATION_BASE_INVALID", "Git empty-tree identity is unavailable")
    return tree


def _treeish(repo: Path, revision: str) -> str:
    return _empty_tree(repo) if revision == UNBORN_HEAD else revision


def _clean(repo: Path) -> bool:
    return not _git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout


def _dirty_paths(repo: Path) -> tuple[str, ...]:
    tracked = _git(
        repo,
        ["diff", "--name-only", "--no-renames", "-z", _treeish(repo, _head(repo)), "--"],
    ).stdout
    untracked = _git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]).stdout
    return tuple(
        sorted(
            {
                normalize_relative_path(path)
                for path in (*tracked.split("\x00"), *untracked.split("\x00"))
                if path
            }
        )
    )


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def is_code_integration_queue_entry(
    *,
    status: str,
    paths: tuple[str, ...],
    patch_hash: str = "",
    resources: tuple[str, ...] = (),
) -> bool:
    """Return whether a review-ready task belongs in the code integration queue."""

    if status != "review_ready":
        return False
    if resources and all(resource.startswith("delivery:") for resource in resources) and not patch_hash:
        return False
    return bool(paths or patch_hash)


def _conflicting_paths(
    dirty_paths: tuple[str, ...],
    changed_paths: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        path
        for path in dirty_paths
        if any(_paths_overlap(path, changed) for changed in changed_paths)
    )


def _tracked_changed_paths(worktree: Path, base_revision: str) -> tuple[str, ...]:
    raw = _git(
        worktree,
        ["diff", "--name-only", "--no-renames", "-z", _treeish(worktree, base_revision), "--"],
    ).stdout
    return tuple(normalize_relative_path(path) for path in raw.split("\x00") if path)


def _untracked_paths(worktree: Path) -> tuple[str, ...]:
    raw = _git(worktree, ["ls-files", "--others", "--exclude-standard", "-z"]).stdout
    return tuple(normalize_relative_path(path) for path in raw.split("\x00") if path)


def _untracked_patch(worktree: Path, path: str) -> str:
    process = _git(
        worktree,
        ["diff", "--no-index", "--binary", "--no-ext-diff", "--", "/dev/null", path],
        check=False,
    )
    if process.returncode not in {0, 1}:
        raise IntegrationError("INTEGRATION_DIFF_FAILED", process.stderr.strip() or "untracked diff failed")
    return process.stdout


def _parse_change_evidence(
    raw_status: str,
    raw_numstat: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    status_tokens = [token for token in raw_status.split("\x00") if token]
    if len(status_tokens) % 2:
        raise IntegrationError("INTEGRATION_DIFF_FAILED", "patch status evidence is malformed")
    statuses = {
        normalize_relative_path(status_tokens[index + 1]): status_tokens[index]
        for index in range(0, len(status_tokens), 2)
    }
    textual_delta_paths: set[str] = set()
    for record in (item for item in raw_numstat.split("\x00") if item):
        parts = record.split("\t", 2)
        if len(parts) != 3:
            raise IntegrationError("INTEGRATION_DIFF_FAILED", "patch numstat evidence is malformed")
        additions, deletions, path = parts
        normalized = normalize_relative_path(path)
        if statuses.get(normalized) != "M" or additions == "-" or deletions == "-":
            continue
        try:
            delta = int(additions) + int(deletions)
        except ValueError as exc:
            raise IntegrationError("INTEGRATION_DIFF_FAILED", "patch numstat evidence is malformed") from exc
        if delta > 0:
            textual_delta_paths.add(normalized)
    return tuple(sorted(statuses)), tuple(sorted(textual_delta_paths))


def _validate_snapshot_baseline(snapshot: BaselineSnapshot, base_revision: str) -> None:
    from .baseline_snapshot import BaselineSnapshot

    if not isinstance(snapshot, BaselineSnapshot):
        raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "source snapshot is invalid")
    if snapshot.head_revision != base_revision:
        raise IntegrationError(
            "INTEGRATION_SNAPSHOT_BASE_MISMATCH",
            "source snapshot does not match the development-session base revision",
        )
    artifact = snapshot.artifact_path
    if artifact.is_symlink() or not artifact.is_dir():
        raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "source snapshot artifact is unavailable")


def _snapshot_head(repo: Path) -> str:
    resolved = _git(repo, ["rev-parse", "--verify", "HEAD"], check=False)
    head = resolved.stdout.strip()
    if resolved.returncode == 0 and head:
        return head
    symbolic = _git(repo, ["symbolic-ref", "--quiet", "HEAD"], check=False)
    if symbolic.returncode == 0 and symbolic.stdout.strip().startswith("refs/heads/"):
        return SNAPSHOT_UNBORN_HEAD
    raise IntegrationError("INTEGRATION_HEAD_INVALID", "repository HEAD is unavailable")


def _prepare_snapshot_index(
    repo: Path,
    snapshot: BaselineSnapshot,
    base_revision: str,
    temporary: Path,
) -> tuple[dict[str, str], str]:
    _validate_snapshot_baseline(snapshot, base_revision)
    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(temporary / "index")
    if base_revision == SNAPSHOT_UNBORN_HEAD:
        _git(repo, ["read-tree", "--empty"], env=environment)
    else:
        _git(repo, ["cat-file", "-e", f"{base_revision}^{{commit}}"])
        _git(repo, ["read-tree", base_revision], env=environment)

    tracked_patch = snapshot.artifact_path / "tracked.patch"
    if tracked_patch.exists():
        if tracked_patch.is_symlink() or not tracked_patch.is_file():
            raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "tracked source snapshot patch is invalid")
        _git(
            repo,
            ["apply", "--cached", "--binary", "--whitespace=nowarn", str(tracked_patch)],
            env=environment,
        )

    for raw_path in snapshot.untracked_paths:
        path = normalize_relative_path(raw_path)
        baseline_file = snapshot.artifact_path / "untracked" / path
        if baseline_file.is_symlink() or not baseline_file.is_file():
            raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "source snapshot untracked content is unavailable")
        blob = _git(repo, ["hash-object", "-w", str(baseline_file)], env=environment).stdout.strip()
        if not blob:
            raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "source snapshot blob identity is unavailable")
        _git(
            repo,
            ["update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"],
            env=environment,
        )
    baseline_tree = _git(repo, ["write-tree"], env=environment).stdout.strip()
    if not baseline_tree:
        raise IntegrationError("INTEGRATION_SNAPSHOT_INVALID", "source snapshot tree identity is unavailable")
    return environment, baseline_tree


def _snapshot_diff_evidence(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
    snapshot: BaselineSnapshot,
    *,
    require_worktree_head: bool,
    ignore_snapshot_excluded: bool = False,
) -> _SnapshotDiffEvidence:
    source = _repo(source_repo)
    tree = _repo(worktree)
    if not isinstance(base_revision, str) or not base_revision or len(base_revision) > 128:
        raise IntegrationError("INTEGRATION_BASE_INVALID", "base revision is invalid")
    _validate_snapshot_baseline(snapshot, base_revision)
    if base_revision != SNAPSHOT_UNBORN_HEAD:
        _git(source, ["cat-file", "-e", f"{base_revision}^{{commit}}"])
        _git(tree, ["cat-file", "-e", f"{base_revision}^{{commit}}"])
    if require_worktree_head and _snapshot_head(tree) != base_revision:
        raise IntegrationError("INTEGRATION_WORKTREE_HEAD_CHANGED", "development worktree HEAD changed from its base")

    excluded_paths = set(snapshot.excluded_paths) if ignore_snapshot_excluded else set()
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-snapshot-diff-") as temporary_name:
        environment, _baseline_tree = _prepare_snapshot_index(
            tree,
            snapshot,
            base_revision,
            Path(temporary_name),
        )
        raw_tracked_paths = _git(
            tree,
            ["diff", "--name-only", "--no-renames", "-z", "--"],
            env=environment,
        ).stdout
        tracked_paths = tuple(
            normalize_relative_path(path)
            for path in raw_tracked_paths.split("\x00")
            if path and path not in excluded_paths
        )
        if tracked_paths:
            tracked = _git(
                tree,
                ["diff", "--binary", "--no-ext-diff", "--no-renames", "--", *tracked_paths],
                env=environment,
            ).stdout
            raw_status = _git(
                tree,
                ["diff", "--name-status", "--no-renames", "-z", "--", *tracked_paths],
                env=environment,
            ).stdout
            raw_numstat = _git(
                tree,
                ["diff", "--numstat", "--no-renames", "-z", "--", *tracked_paths],
                env=environment,
            ).stdout
        else:
            tracked = ""
            raw_status = ""
            raw_numstat = ""
        raw_untracked = _git(
            tree,
            ["ls-files", "--others", "--exclude-standard", "-z"],
            env=environment,
        ).stdout

    changed_tracked, textual_delta_paths = _parse_change_evidence(raw_status, raw_numstat)
    untracked = tuple(
        normalize_relative_path(path)
        for path in raw_untracked.split("\x00")
        if path and path not in excluded_paths
    )
    patch = tracked + "".join(_untracked_patch(tree, path) for path in untracked)
    changed_paths = tuple(sorted(set(changed_tracked) | set(untracked)))
    for path in changed_paths:
        if (tree / path).is_symlink() or (source / path).is_symlink():
            raise IntegrationError("INTEGRATION_SYMLINK_DENIED", "session diff contains a symlink path")
    return _SnapshotDiffEvidence(
        SessionDiff(base_revision, patch, sha256_text(patch), changed_paths),
        textual_delta_paths,
    )


def _snapshot_patch_change_evidence(
    repo: Path,
    patch: str,
    base_revision: str,
    snapshot: BaselineSnapshot,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-snapshot-patch-") as temporary_name:
        environment, baseline_tree = _prepare_snapshot_index(
            repo,
            snapshot,
            base_revision,
            Path(temporary_name),
        )
        applied = _git(
            repo,
            ["apply", "--cached", "--binary", "--whitespace=nowarn", "-"],
            input_text=patch,
            check=False,
            env=environment,
        )
        if applied.returncode != 0:
            raise IntegrationError(
                "INTEGRATION_CONFLICT",
                applied.stderr.strip() or "integration patch does not apply to its source snapshot",
            )
        raw_status = _git(
            repo,
            ["diff", "--cached", "--name-status", "--no-renames", "-z", baseline_tree, "--"],
            env=environment,
        ).stdout
        raw_numstat = _git(
            repo,
            ["diff", "--cached", "--numstat", "--no-renames", "-z", baseline_tree, "--"],
            env=environment,
        ).stdout
    return _parse_change_evidence(raw_status, raw_numstat)


def _patch_change_evidence(
    repo: Path,
    patch: str,
    anchor_revision: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve patch targets and safe textual-modification paths against HEAD.

    A temporary index gives Git responsibility for parsing binary patches,
    deletes, and renames.  Disabling rename detection when reading that index
    deliberately returns both the old and new path of a rename so either side
    can protect an existing canonical dirty change.  Only ordinary ``M``
    entries with real textual line deltas are eligible for same-file dirty-hunk
    compatibility; adds, deletes, renames, binary changes, and mode-only
    changes remain fail-closed.
    """

    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-integration-") as temporary:
        index_path = Path(temporary) / "index"
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(index_path)
        comparison_revision = _treeish(repo, anchor_revision)
        if anchor_revision == UNBORN_HEAD:
            _git(repo, ["read-tree", "--empty"], env=environment)
        else:
            _git(repo, ["read-tree", anchor_revision], env=environment)
        applied = _git(
            repo,
            ["apply", "--cached", "--whitespace=nowarn", "-"],
            input_text=patch,
            check=False,
            env=environment,
        )
        if applied.returncode != 0:
            raise IntegrationError(
                "INTEGRATION_CONFLICT",
                applied.stderr.strip() or "integration patch no longer applies to canonical HEAD",
            )
        raw_status = _git(
            repo,
            ["diff", "--cached", "--name-status", "--no-renames", "-z", comparison_revision, "--"],
            env=environment,
        ).stdout
        raw_numstat = _git(
            repo,
            ["diff", "--cached", "--numstat", "--no-renames", "-z", comparison_revision, "--"],
            env=environment,
        ).stdout

    status_tokens = [token for token in raw_status.split("\x00") if token]
    if len(status_tokens) % 2:
        raise IntegrationError("INTEGRATION_DIFF_FAILED", "patch status evidence is malformed")
    statuses = {
        normalize_relative_path(status_tokens[index + 1]): status_tokens[index]
        for index in range(0, len(status_tokens), 2)
    }
    textual_delta_paths: set[str] = set()
    for record in (item for item in raw_numstat.split("\x00") if item):
        additions, deletions, path = record.split("\t", 2)
        normalized = normalize_relative_path(path)
        if statuses.get(normalized) != "M" or additions == "-" or deletions == "-":
            continue
        if int(additions) + int(deletions) > 0:
            textual_delta_paths.add(normalized)
    return tuple(sorted(statuses)), tuple(sorted(textual_delta_paths))


def build_session_diff(source_repo: Path, worktree: Path, base_revision: str) -> SessionDiff:
    source = _repo(source_repo)
    tree = _repo(worktree)
    if not isinstance(base_revision, str) or not base_revision or len(base_revision) > 128:
        raise IntegrationError("INTEGRATION_BASE_INVALID", "base revision is invalid")
    # Prove both repositories know the requested anchor.  An unborn session
    # deliberately uses the all-zero sentinel and compares against Git's empty
    # tree without manufacturing an initial commit.  The canonical repository
    # may subsequently gain its first commit; that is handled as a normal
    # canonical revision change below.
    if base_revision != UNBORN_HEAD:
        _git(source, ["cat-file", "-e", f"{base_revision}^{{commit}}"])
        _git(tree, ["cat-file", "-e", f"{base_revision}^{{commit}}"])
    if _head(tree) != base_revision:
        raise IntegrationError("INTEGRATION_WORKTREE_HEAD_CHANGED", "development worktree HEAD changed from its base")

    tracked = _git(
        tree,
        ["diff", "--binary", "--no-ext-diff", _treeish(tree, base_revision), "--"],
    ).stdout
    untracked = _untracked_paths(tree)
    patch = tracked + "".join(_untracked_patch(tree, path) for path in untracked)
    changed_paths = tuple(sorted(set(_tracked_changed_paths(tree, base_revision)) | set(untracked)))
    for path in changed_paths:
        if (tree / path).is_symlink() or (source / path).is_symlink():
            raise IntegrationError("INTEGRATION_SYMLINK_DENIED", "session diff contains a symlink path")
    return SessionDiff(base_revision, patch, sha256_text(patch), changed_paths)


def integration_preflight(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
    *,
    review_ready: bool = True,
    review_reason: str = "",
) -> IntegrationPreflight:
    source = _repo(source_repo)
    diff = build_session_diff(source, worktree, base_revision)
    canonical_revision = _head(source)
    canonical_repository_clean = _clean(source)
    canonical_dirty_paths = _dirty_paths(source)
    overlapping_dirty_paths = _conflicting_paths(canonical_dirty_paths, diff.changed_paths)
    canonical_changed = canonical_revision != base_revision
    textual_delta_paths: tuple[str, ...] = ()
    if diff.patch:
        _patch_paths, textual_delta_paths = _patch_change_evidence(source, diff.patch, base_revision)
        check = _git(
            source,
            ["apply", "--check", "--whitespace=nowarn", "-"],
            input_text=diff.patch,
            check=False,
        )
        conflict_free = check.returncode == 0
    else:
        conflict_free = True
    # A dirty canonical path is not itself a conflict.  Isolated sessions may
    # legitimately edit disjoint hunks of the same file.  The patch-level
    # ``git apply --check`` result is the authoritative compatibility gate for
    # ordinary textual modifications.  Structural/binary changes remain
    # fail-closed when their paths are already dirty.
    structural_dirty_paths = tuple(
        path
        for path in overlapping_dirty_paths
        if not any(_paths_overlap(path, textual) for textual in textual_delta_paths)
    )
    canonical_conflicting_paths = overlapping_dirty_paths if not conflict_free else structural_dirty_paths
    canonical_clean = not canonical_conflicting_paths
    return IntegrationPreflight(
        base_revision,
        canonical_revision,
        canonical_clean,
        canonical_changed,
        conflict_free,
        diff.patch_hash,
        diff.changed_paths,
        bool(diff.patch) and canonical_clean and conflict_free and review_ready,
        review_ready,
        review_reason,
        canonical_repository_clean=canonical_repository_clean,
        canonical_dirty_paths=canonical_dirty_paths,
        canonical_conflicting_paths=canonical_conflicting_paths,
    )


def session_diff_subsumed_by_canonical(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
) -> bool:
    """Return true only when the canonical working tree contains the exact session delta."""

    source = _repo(source_repo)
    diff = build_session_diff(source, worktree, base_revision)
    if not diff.patch:
        return True
    reverse = _git(
        source,
        ["apply", "--reverse", "--check", "--whitespace=nowarn", "-"],
        input_text=diff.patch,
        check=False,
    )
    return reverse.returncode == 0


def remove_subsumed_session_worktree(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
) -> None:
    """Force-remove a dirty worktree only after exact canonical subsumption proof."""

    source = _repo(source_repo)
    tree = _repo(worktree)
    if not session_diff_subsumed_by_canonical(source, tree, base_revision):
        raise IntegrationError(
            "INTEGRATION_SESSION_NOT_SUBSUMED",
            "development worktree changes are not fully present in canonical working-tree state",
        )
    removed = _git(
        source,
        ["worktree", "remove", "--force", str(tree)],
        check=False,
    )
    if removed.returncode != 0 or tree.exists():
        raise IntegrationError(
            "INTEGRATION_WORKTREE_CLEANUP_FAILED",
            removed.stderr.strip() or "subsumed development worktree could not be removed",
        )


def apply_integration_patch(
    source_repo: Path,
    patch: str,
    *,
    expected_head: str,
    expected_patch_hash: str,
    review_ready: bool = True,
) -> IntegrationResult:
    source = _repo(source_repo)
    if not isinstance(patch, str) or not patch:
        raise IntegrationError("INTEGRATION_PATCH_EMPTY", "integration patch is empty")
    if sha256_text(patch) != expected_patch_hash:
        raise IntegrationError("INTEGRATION_PATCH_CHANGED", "integration patch no longer matches preflight")
    if not review_ready:
        raise IntegrationError("INTEGRATION_REVIEW_REQUIRED", "current independent review gate is not satisfied")
    current_head = _head(source)
    if current_head != expected_head:
        raise IntegrationError("INTEGRATION_CANONICAL_CHANGED", "canonical HEAD changed after preflight")
    patch_changed_paths, textual_delta_paths = _patch_change_evidence(source, patch, expected_head)
    canonical_conflicting_paths = _conflicting_paths(_dirty_paths(source), patch_changed_paths)
    structural_dirty_paths = tuple(
        path
        for path in canonical_conflicting_paths
        if not any(_paths_overlap(path, textual) for textual in textual_delta_paths)
    )
    if structural_dirty_paths:
        raise IntegrationError(
            "INTEGRATION_CANONICAL_DIRTY",
            "canonical repository has structural or binary dirty changes on integration paths: "
            + ", ".join(structural_dirty_paths),
        )
    check = _git(
        source,
        ["apply", "--check", "--whitespace=nowarn", "-"],
        input_text=patch,
        check=False,
    )
    if check.returncode != 0:
        if canonical_conflicting_paths:
            raise IntegrationError(
                "INTEGRATION_CANONICAL_DIRTY",
                "canonical repository has incompatible dirty changes on integration paths: "
                + ", ".join(canonical_conflicting_paths),
            )
        raise IntegrationError("INTEGRATION_CONFLICT", check.stderr.strip() or "integration patch no longer applies")
    # Re-check immediately before mutation.  This preserves the previous
    # TOCTOU fence without treating a compatible same-file dirty hunk as an
    # automatic conflict.
    recheck = _git(
        source,
        ["apply", "--check", "--whitespace=nowarn", "-"],
        input_text=patch,
        check=False,
    )
    if recheck.returncode != 0:
        canonical_conflicting_paths = _conflicting_paths(_dirty_paths(source), patch_changed_paths)
        if canonical_conflicting_paths:
            raise IntegrationError(
                "INTEGRATION_CANONICAL_DIRTY",
                "canonical repository changed incompatibly on integration paths after conflict check: "
                + ", ".join(canonical_conflicting_paths),
            )
        raise IntegrationError("INTEGRATION_CONFLICT", recheck.stderr.strip() or "integration patch no longer applies")
    canonical_conflicting_paths = _conflicting_paths(_dirty_paths(source), patch_changed_paths)
    structural_dirty_paths = tuple(
        path
        for path in canonical_conflicting_paths
        if not any(_paths_overlap(path, textual) for textual in textual_delta_paths)
    )
    if structural_dirty_paths:
        raise IntegrationError(
            "INTEGRATION_CANONICAL_DIRTY",
            "canonical repository changed structurally on integration paths after conflict check: "
            + ", ".join(structural_dirty_paths),
        )
    _git(source, ["apply", "--whitespace=nowarn", "-"], input_text=patch)
    return IntegrationResult(True, current_head, expected_patch_hash)


def build_session_diff_since_snapshot(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
    snapshot: BaselineSnapshot,
) -> SessionDiff:
    """Return only changes made after an immutable dirty source snapshot."""
    return _snapshot_diff_evidence(
        source_repo,
        worktree,
        base_revision,
        snapshot,
        require_worktree_head=True,
    ).diff


def integration_preflight_since_snapshot(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
    snapshot: BaselineSnapshot,
    *,
    review_ready: bool = True,
    review_reason: str = "",
) -> IntegrationPreflight:
    """Preflight only post-snapshot session changes against current canonical state."""
    source = _repo(source_repo)
    session_evidence = _snapshot_diff_evidence(
        source,
        worktree,
        base_revision,
        snapshot,
        require_worktree_head=True,
    )
    canonical_evidence = _snapshot_diff_evidence(
        source,
        source,
        base_revision,
        snapshot,
        require_worktree_head=False,
        ignore_snapshot_excluded=True,
    )
    diff = session_evidence.diff
    canonical_revision = _head(source)
    canonical_repository_clean = _clean(source)
    canonical_dirty_paths = _dirty_paths(source)
    overlapping_delta_paths = _conflicting_paths(canonical_evidence.diff.changed_paths, diff.changed_paths)
    opaque_baseline_overlap = _conflicting_paths(snapshot.excluded_paths, diff.changed_paths)
    if diff.patch:
        check = _git(
            source,
            ["apply", "--check", "--whitespace=nowarn", "-"],
            input_text=diff.patch,
            check=False,
        )
        conflict_free = check.returncode == 0
    else:
        conflict_free = True
    structural_overlap = tuple(
        sorted(
            set(opaque_baseline_overlap)
            | {
                path
                for path in overlapping_delta_paths
                if not any(_paths_overlap(path, textual) for textual in session_evidence.textual_delta_paths)
                or not any(_paths_overlap(path, textual) for textual in canonical_evidence.textual_delta_paths)
            }
        )
    )
    canonical_conflicting_paths = overlapping_delta_paths if not conflict_free else structural_overlap
    canonical_clean = not canonical_conflicting_paths
    return IntegrationPreflight(
        base_revision,
        canonical_revision,
        canonical_clean,
        canonical_revision != base_revision,
        conflict_free,
        diff.patch_hash,
        diff.changed_paths,
        bool(diff.patch) and canonical_clean and conflict_free and review_ready,
        review_ready,
        review_reason,
        canonical_repository_clean=canonical_repository_clean,
        canonical_dirty_paths=canonical_dirty_paths,
        canonical_conflicting_paths=canonical_conflicting_paths,
    )


def session_diff_since_snapshot_subsumed_by_canonical(
    source_repo: Path,
    worktree: Path,
    base_revision: str,
    snapshot: BaselineSnapshot,
) -> bool:
    """Return true only when canonical contains the exact post-snapshot delta."""
    source = _repo(source_repo)
    diff = build_session_diff_since_snapshot(source, worktree, base_revision, snapshot)
    if not diff.patch:
        return True
    reverse = _git(
        source,
        ["apply", "--reverse", "--check", "--whitespace=nowarn", "-"],
        input_text=diff.patch,
        check=False,
    )
    return reverse.returncode == 0


def apply_integration_patch_since_snapshot(
    source_repo: Path,
    patch: str,
    *,
    expected_head: str,
    expected_patch_hash: str,
    base_revision: str,
    snapshot: BaselineSnapshot,
    review_ready: bool = True,
) -> IntegrationResult:
    """Apply one post-snapshot delta without treating the snapshot baseline as session work."""
    source = _repo(source_repo)
    if not isinstance(patch, str) or not patch:
        raise IntegrationError("INTEGRATION_PATCH_EMPTY", "integration patch is empty")
    if sha256_text(patch) != expected_patch_hash:
        raise IntegrationError("INTEGRATION_PATCH_CHANGED", "integration patch no longer matches preflight")
    if not review_ready:
        raise IntegrationError("INTEGRATION_REVIEW_REQUIRED", "current independent review gate is not satisfied")
    current_head = _head(source)
    if current_head != expected_head:
        raise IntegrationError("INTEGRATION_CANONICAL_CHANGED", "canonical HEAD changed after preflight")

    patch_changed_paths, patch_textual_paths = _snapshot_patch_change_evidence(
        source,
        patch,
        base_revision,
        snapshot,
    )
    canonical_evidence = _snapshot_diff_evidence(
        source,
        source,
        base_revision,
        snapshot,
        require_worktree_head=False,
        ignore_snapshot_excluded=True,
    )
    canonical_overlap = _conflicting_paths(canonical_evidence.diff.changed_paths, patch_changed_paths)
    opaque_baseline_overlap = _conflicting_paths(snapshot.excluded_paths, patch_changed_paths)
    structural_overlap = tuple(
        sorted(
            set(opaque_baseline_overlap)
            | {
                path
                for path in canonical_overlap
                if not any(_paths_overlap(path, textual) for textual in patch_textual_paths)
                or not any(_paths_overlap(path, textual) for textual in canonical_evidence.textual_delta_paths)
            }
        )
    )
    if structural_overlap:
        raise IntegrationError(
            "INTEGRATION_CANONICAL_DIRTY",
            "canonical repository has structural or binary post-snapshot changes on integration paths: "
            + ", ".join(structural_overlap),
        )

    check = _git(
        source,
        ["apply", "--check", "--whitespace=nowarn", "-"],
        input_text=patch,
        check=False,
    )
    if check.returncode != 0:
        if canonical_overlap:
            raise IntegrationError(
                "INTEGRATION_CANONICAL_DIRTY",
                "canonical repository has incompatible post-snapshot changes on integration paths: "
                + ", ".join(canonical_overlap),
            )
        raise IntegrationError("INTEGRATION_CONFLICT", check.stderr.strip() or "integration patch no longer applies")

    recheck = _git(
        source,
        ["apply", "--check", "--whitespace=nowarn", "-"],
        input_text=patch,
        check=False,
    )
    if recheck.returncode != 0:
        raise IntegrationError("INTEGRATION_CONFLICT", recheck.stderr.strip() or "integration patch no longer applies")
    _git(source, ["apply", "--whitespace=nowarn", "-"], input_text=patch)
    return IntegrationResult(True, current_head, expected_patch_hash)
