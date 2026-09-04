"""Fail-closed adoption of unmanaged legacy Git worktrees into formal retained evidence.

Phase 7 of the retained-evidence / generation-split remediation.

A legacy worktree may exist under a registered canonical repository's
``.git/worktrees`` directory without ever having been recorded in any
DevMCP generation (current v26 or the old ``local-dev-mcp`` generation).  It
must be possible to formally account for that bytes-only evidence without:

* accepting arbitrary external filesystem paths,
* fabricating an owner or source history,
* integrating, deleting, GC-ing, or moving the worktree.

This module contains only the pure, fail-closed decision model.  Containment
is proven against the registered canonical repository's Git common-dir, exact
filesystem identity, exact HEAD, exact tracked patch, and an untracked
manifest.  Every active-authority signal (live process, writer lease, session,
or identity collision) must be zero or the worktree stays UNMANAGED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .session_state_reconciliation import configured_legacy_roots, evidence_digest, resolve_allowlisted_root


# Capability / classification vocabulary.
LEGACY_WORKTREE_ADOPTION_CAPABILITY_ID = "development.session.adopt_legacy_worktree"
FORMALLY_ACCOUNTED_RETAINED_EVIDENCE = "FORMALLY_ACCOUNTED_RETAINED_EVIDENCE"
UNMANAGED_EVIDENCE = "UNMANAGED_EVIDENCE"
ADOPTION_BLOCKED = "ADOPTION_BLOCKED"
ADOPTION_UNKNOWN = "ADOPTION_UNKNOWN"

_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_ZERO_HEAD = "0" * 40
_ACTIVE_STATES = frozenset(
    {
        "active",
        "running",
        "attached",
        "unknown",
        "queued",
        "ready",
        "leased",
        "verifying",
        "review_ready",
        "recovery",
    }
)
_AUTHORITY_STATES = frozenset(
    {
        "active",
        "running",
        "attached",
        "queued",
        "ready",
        "leased",
        "verifying",
        "review_ready",
        "recovery",
        "suspended",
    }
)


def _valid_commit(value: object) -> bool:
    text = str(value or "")
    return bool(_COMMIT_PATTERN.fullmatch(text)) and text.lower() != _ZERO_HEAD


def _to_text(value: object) -> str:
    return str(value or "")


@dataclass(frozen=True)
class LegacyWorktreeAdoptionObservation:
    """Independent, read-only evidence collected for one candidate worktree."""

    worktree_path: str
    canonical_root: str
    workspace_id: str
    source_common_dir: str
    worktree_common_dir: str
    source_git_root: str
    head: str
    tracked_patch_hash: str
    untracked_manifest: tuple[dict[str, Any], ...]
    untracked_manifest_valid: bool
    untracked_manifest_hash: str
    filesystem_device: int
    filesystem_inode: int
    root_kind: str
    path_safe: bool
    worktree_exists: bool
    process_state: Mapping[str, Any]
    lease_state: Mapping[str, Any]
    session_state: Mapping[str, Any]
    collision_session_id: str | None
    owner_known: bool
    state_digest: str

    @property
    def evidence(self) -> dict[str, Any]:
        return {
            "worktree_path": self.worktree_path,
            "canonical_root": self.canonical_root,
            "workspace_id": self.workspace_id,
            "source_common_dir": self.source_common_dir,
            "worktree_common_dir": self.worktree_common_dir,
            "source_git_root": self.source_git_root,
            "head": self.head,
            "tracked_patch_hash": self.tracked_patch_hash,
            "untracked_manifest_hash": self.untracked_manifest_hash,
            "untracked_manifest_valid": self.untracked_manifest_valid,
            "filesystem_device": self.filesystem_device,
            "filesystem_inode": self.filesystem_inode,
            "root_kind": self.root_kind,
            "path_safe": self.path_safe,
            "worktree_exists": self.worktree_exists,
            "owner_known": self.owner_known,
            "collision_session_id": self.collision_session_id,
            "process_state": dict(self.process_state),
            "lease_state": dict(self.lease_state),
            "session_state": dict(self.session_state),
        }


@dataclass(frozen=True)
class LegacyWorktreeAdoptionPlan:
    observation: LegacyWorktreeAdoptionObservation
    classification: str
    reason_codes: tuple[str, ...]
    preservation_actions: tuple[str, ...]
    state_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": LEGACY_WORKTREE_ADOPTION_CAPABILITY_ID,
            "schema_version": 1,
            "worktree_path": self.observation.worktree_path,
            "workspace_id": self.observation.workspace_id,
            "classification": self.classification,
            "preservation_actions": list(self.preservation_actions),
            "reason_codes": list(self.reason_codes),
            "state_digest": self.state_digest,
            "evidence": self.observation.evidence,
        }


def classify_legacy_worktree_adoption(
    observation: LegacyWorktreeAdoptionObservation,
) -> LegacyWorktreeAdoptionPlan:
    """Decide whether an unmanaged legacy worktree may be formally accounted.

    Pure function: it never touches Git, the filesystem, or any control-plane
    state.  Any missing or conflicting authority signal keeps the worktree
    UNMANAGED / BLOCKED / UNKNOWN.
    """

    reasons: list[str] = []

    if not observation.path_safe:
        return _plan(observation, ADOPTION_UNKNOWN, "UNSAFE_PATH")
    if not observation.worktree_exists:
        return _plan(observation, ADOPTION_UNKNOWN, "WORKTREE_MISSING")
    # Containment must be proven against a registered canonical root; arbitrary
    # external paths are rejected by the caller before this is ever reached.
    if observation.root_kind not in {"managed", "legacy"}:
        return _plan(observation, ADOPTION_UNKNOWN, "ROOT_NOT_ALLOWED")
    if not observation.source_common_dir or observation.source_common_dir != observation.worktree_common_dir:
        return _plan(observation, ADOPTION_UNKNOWN, "GIT_COMMON_DIR_MISMATCH")
    if not observation.source_git_root or observation.source_git_root != observation.canonical_root:
        return _plan(observation, ADOPTION_UNKNOWN, "SOURCE_GIT_ROOT_MISMATCH")
    if not _valid_commit(observation.head):
        return _plan(observation, ADOPTION_UNKNOWN, "HEAD_UNKNOWN")
    if not observation.tracked_patch_hash:
        return _plan(observation, ADOPTION_UNKNOWN, "TRACKED_PATCH_HASH_UNKNOWN")
    if not observation.untracked_manifest_valid:
        return _plan(observation, ADOPTION_UNKNOWN, "UNTRACKED_MANIFEST_UNKNOWN")

    # Active authority signals: any of these means the bytes are owned by a live
    # session/process/task and must not be silently accounted.
    process_status = _to_text(observation.process_state.get("state") or "")
    if process_status in _ACTIVE_STATES:
        return _plan(observation, ADOPTION_BLOCKED, "BOUND_PROCESS")
    if process_status not in {"", "absent", "stale", "exited"}:
        return _plan(observation, ADOPTION_UNKNOWN, "PROCESS_STATE_INDETERMINATE")

    lease_status = _to_text(observation.lease_state.get("state") or "")
    if lease_status == "active":
        return _plan(observation, ADOPTION_BLOCKED, "ACTIVE_WRITER_LEASE")
    if lease_status not in {"", "released", "expired", "stale", "absent"}:
        return _plan(observation, ADOPTION_UNKNOWN, "LEASE_STATE_INDETERMINATE")

    session_status = _to_text(observation.session_state.get("status") or observation.session_state.get("state") or "")
    if session_status in _AUTHORITY_STATES:
        return _plan(observation, ADOPTION_BLOCKED, "ACTIVE_SESSION")
    if session_status not in {"", "absent", "stale", "cleanup_candidate", "abandoned", "closed"}:
        return _plan(observation, ADOPTION_UNKNOWN, "SESSION_STATE_INDETERMINATE")

    if observation.collision_session_id is not None:
        return _plan(observation, ADOPTION_BLOCKED, "EXISTING_IDENTITY_COLLISION")

    # Owner remains UNKNOWN when it cannot be proven: we never fabricate it.
    if observation.owner_known:
        reasons.append("OWNER_KNOWN")
    else:
        reasons.append("OWNER_UNKNOWN_PRESERVED")

    return _plan(
        observation,
        FORMALLY_ACCOUNTED_RETAINED_EVIDENCE,
        *reasons,
        actions=(
            "preserve_worktree",
            "preserve_sidecar_evidence",
            "record_adoption_receipt",
            "no_integration",
            "no_delete",
            "no_gc",
        ),
    )


def _plan(
    observation: LegacyWorktreeAdoptionObservation,
    classification: str,
    *reasons: str,
    actions: tuple[str, ...] = (),
) -> LegacyWorktreeAdoptionPlan:
    return LegacyWorktreeAdoptionPlan(
        observation=observation,
        classification=classification,
        reason_codes=tuple(dict.fromkeys(reasons)),
        preservation_actions=actions,
        state_digest=observation.state_digest,
    )


def adoption_receipt_id(worktree_path: str, state_digest: str) -> str:
    if len(state_digest) != 64:
        raise ValueError("adoption state digest is invalid")
    from .session_state_reconciliation import ReconciliationError

    if not re.fullmatch(r"^[A-Za-z0-9._:/\\-]{1,4096}$", worktree_path):
        raise ReconciliationError("adoption worktree path identity is invalid")
    return f"legacy-adoption:{worktree_path}:{state_digest}"


__all__ = [
    "ADOPTION_BLOCKED",
    "ADOPTION_UNKNOWN",
    "FORMALLY_ACCOUNTED_RETAINED_EVIDENCE",
    "LEGACY_WORKTREE_ADOPTION_CAPABILITY_ID",
    "LegacyWorktreeAdoptionObservation",
    "LegacyWorktreeAdoptionPlan",
    "UNMANAGED_EVIDENCE",
    "adoption_receipt_id",
    "classify_legacy_worktree_adoption",
]
