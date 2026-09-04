"""Conflict-aware integration-queue classification and patch compatibility.

This module is intentionally separate from canonical patch application. It
only answers whether review-ready work belongs in the code-integration queue
and whether two isolated session diffs are provably composable in either
order. Unknown, structural, or binary overlap remains fail-closed.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .director import normalize_relative_path
from .director_integration import IntegrationError, SessionDiff
from .process_runner import BoundedProcessResult, run_bounded


_MAX_GIT_OUTPUT_BYTES = 1 * 1024 * 1024
_MAX_GIT_TIMEOUT_SECONDS = 30.0


def is_code_integration_queue_entry(
    *,
    status: str,
    paths: tuple[str, ...],
    patch_hash: str = "",
    resources: tuple[str, ...] = (),
) -> bool:
    """Return whether a review-ready task represents code awaiting integration."""

    if status != "review_ready":
        return False
    if resources and all(resource.startswith("delivery:") for resource in resources) and not patch_hash:
        return False
    return bool(paths or patch_hash)


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
        timeout_seconds=_MAX_GIT_TIMEOUT_SECONDS,
        max_output_bytes=_MAX_GIT_OUTPUT_BYTES,
    )
    if process.timed_out:
        raise IntegrationError("INTEGRATION_GIT_TIMEOUT", "fixed Git command exceeded the bounded timeout")
    if process.output_truncated:
        raise IntegrationError("INTEGRATION_OUTPUT_LIMIT", "fixed Git command exceeded the bounded output limit")
    if check and process.returncode != 0:
        raise IntegrationError("INTEGRATION_GIT_FAILED", process.stderr.strip() or "fixed Git command failed")
    return process


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _patch_change_evidence(
    repo: Path,
    patch: str,
    base_revision: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return all patch paths plus ordinary textual-modification paths."""

    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-queue-evidence-") as temporary:
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
        _git(repo, ["read-tree", base_revision], env=environment)
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
                applied.stderr.strip() or "integration patch does not apply to its base revision",
            )
        raw_status = _git(
            repo,
            ["diff", "--cached", "--name-status", "--no-renames", "-z", base_revision, "--"],
            env=environment,
        ).stdout
        raw_numstat = _git(
            repo,
            ["diff", "--cached", "--numstat", "--no-renames", "-z", base_revision, "--"],
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


def _patch_sequence_applies(repo: Path, base_revision: str, patches: tuple[str, ...]) -> bool:
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-queue-compat-") as temporary:
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
        try:
            _git(repo, ["read-tree", base_revision], env=environment)
        except IntegrationError:
            return False
        for patch in patches:
            applied = _git(
                repo,
                ["apply", "--cached", "--whitespace=nowarn", "-"],
                input_text=patch,
                check=False,
                env=environment,
            )
            if applied.returncode != 0:
                return False
    return True


def session_diffs_compatible(source_repo: Path, first: SessionDiff, second: SessionDiff) -> bool:
    """Return whether two isolated session patches are safely composable in either order."""

    overlapping_paths = tuple(
        sorted(
            left
            for left in first.changed_paths
            if any(_paths_overlap(left, right) for right in second.changed_paths)
        )
    )
    if not overlapping_paths:
        return True
    if first.base_revision != second.base_revision:
        return False

    repo = _repo(source_repo)
    try:
        _first_paths, first_textual = _patch_change_evidence(repo, first.patch, first.base_revision)
        _second_paths, second_textual = _patch_change_evidence(repo, second.patch, second.base_revision)
    except IntegrationError:
        return False
    if any(
        not any(_paths_overlap(path, textual) for textual in first_textual)
        or not any(_paths_overlap(path, textual) for textual in second_textual)
        for path in overlapping_paths
    ):
        return False
    return _patch_sequence_applies(repo, first.base_revision, (first.patch, second.patch)) and _patch_sequence_applies(
        repo,
        first.base_revision,
        (second.patch, first.patch),
    )


__all__ = ["is_code_integration_queue_entry", "session_diffs_compatible"]
