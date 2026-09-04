from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from .session_archive import (
    ArchiveDisposition,
    ArchiveError,
    PhysicalWorktreeAssessment,
    SessionArchiveBuilder,
    SessionArchiveStore,
    SessionArchiveVerifier,
    persist_published_archive,
)


@dataclass(frozen=True)
class ArchivePrunePreparation:
    assessment: PhysicalWorktreeAssessment
    archive_id: str
    archive_path: str
    physical_worktree_id: str
    alias_session_ids: tuple[str, ...]
    state_hash: str
    patch_hash: str
    payload_bytes: int
    prune_authorized: bool


def _read_back_receipt(persistence: object, archive_id: str) -> dict[str, Any]:
    getter = getattr(persistence, "get_session_archive_receipt", None)
    if not callable(getter):
        raise ArchiveError("ARCHIVE_RECEIPT_READBACK_UNAVAILABLE")
    try:
        receipt = getter(archive_id)
    except Exception as exc:  # persistence implementations normalize separately
        raise ArchiveError("ARCHIVE_RECEIPT_READBACK_FAILED", str(exc)) from exc
    if not isinstance(receipt, dict):
        raise ArchiveError("ARCHIVE_RECEIPT_READBACK_FAILED")
    return receipt


def prepare_archive_for_prune(
    assessment: PhysicalWorktreeAssessment,
    *,
    repository_path: str | os.PathLike[str],
    persistence: object,
    archive_root: str | os.PathLike[str] | None = None,
    payload_limit_bytes: int | None = None,
    free_space_reserve_bytes: int = 16 * 1024 * 1024,
) -> ArchivePrunePreparation:
    """Create durable prune authority without deleting the source worktree.

    The sequence is intentionally one-way and fail-closed:
    snapshot -> verify -> atomic publish -> verify published bytes -> SQLite
    receipt -> receipt read-back.  Only the returned ``prune_authorized=True``
    result may be used by the caller to enter an existing managed cleanup
    primitive.  This function never removes, resets, cleans, or mutates the
    original managed worktree.
    """

    if assessment.disposition is not ArchiveDisposition.ARCHIVE:
        raise ArchiveError("NOT_ARCHIVE_ELIGIBLE")

    builder = (
        SessionArchiveBuilder()
        if payload_limit_bytes is None
        else SessionArchiveBuilder(payload_limit_bytes=payload_limit_bytes)
    )
    verifier = SessionArchiveVerifier()
    store = SessionArchiveStore(
        root=Path(archive_root) if archive_root is not None else None,
        free_space_reserve_bytes=free_space_reserve_bytes,
    )

    snapshot = builder.build(assessment, repository_path=repository_path)
    verification = verifier.verify_snapshot(snapshot, repository_path=repository_path)
    published = store.publish(snapshot, verification)
    final_verification = verifier.verify_published(
        published.archive_path,
        repository_path=repository_path,
    )
    if (
        final_verification.archive_id != published.archive_id
        or final_verification.state_hash != published.state_hash
        or final_verification.patch_hash != published.patch_hash
    ):
        raise ArchiveError("ARCHIVE_FINAL_VERIFICATION_MISMATCH")

    try:
        persist_published_archive(persistence, published)
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError("ARCHIVE_RECEIPT_PERSIST_FAILED", str(exc)) from exc

    receipt = _read_back_receipt(persistence, published.archive_id)
    if (
        receipt.get("archive_id") != published.archive_id
        or receipt.get("physical_worktree_id") != assessment.physical_worktree_id
        or receipt.get("state_hash") != published.state_hash
        or receipt.get("patch_hash") != published.patch_hash
        or tuple(receipt.get("alias_session_ids", ())) != published.alias_session_ids
        or receipt.get("archive_path") != published.archive_path
        or receipt.get("pruned_at") is not None
    ):
        raise ArchiveError("ARCHIVE_RECEIPT_READBACK_MISMATCH")

    return ArchivePrunePreparation(
        assessment=assessment,
        archive_id=published.archive_id,
        archive_path=published.archive_path,
        physical_worktree_id=published.physical_worktree_id,
        alias_session_ids=published.alias_session_ids,
        state_hash=published.state_hash,
        patch_hash=published.patch_hash,
        payload_bytes=published.payload_bytes,
        prune_authorized=True,
    )


def revalidate_archive_prune_source_state(
    assessment: PhysicalWorktreeAssessment,
    *,
    preparation: ArchivePrunePreparation,
    repository_path: str | os.PathLike[str],
) -> None:
    """Re-prove that the current source worktree still matches prune authority."""

    if not preparation.prune_authorized:
        raise ArchiveError("ARCHIVE_PRUNE_NOT_AUTHORIZED")
    try:
        current = SessionArchiveBuilder().build(
            assessment,
            repository_path=repository_path,
        )
    except ArchiveError as exc:
        raise ArchiveError("ARCHIVE_SOURCE_STATE_CHANGED", exc.code) from exc

    if (
        current.archive_id != preparation.archive_id
        or current.physical_worktree_id != preparation.physical_worktree_id
        or current.state_hash != preparation.state_hash
        or current.patch_hash != preparation.patch_hash
    ):
        raise ArchiveError("ARCHIVE_SOURCE_STATE_CHANGED")


__all__ = [
    "ArchivePrunePreparation",
    "prepare_archive_for_prune",
    "revalidate_archive_prune_source_state",
]
