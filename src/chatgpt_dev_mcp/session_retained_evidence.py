"""Fail-closed classification for retained DEVELOPMENT evidence.

The normal stale-session reconciliation path requires an exact source identity
match.  A moved canonical checkout can make that identity unverifiable while
the Git source, revision history, and managed worktree are still independently
provable.  This module describes the narrower, non-destructive path used to
archive those bytes and terminalize their control-plane record without
pretending that the old source identity was repaired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .development import UNBORN_HEAD
from .session_identity_repair import IdentityRepairObservation
from .session_state_reconciliation import evidence_digest


RETAINED_EVIDENCE_TERMINAL = "EVIDENCE_RETAINED_TERMINAL"
RETAINED_EVIDENCE_ELIGIBLE = "RETAINED_EVIDENCE_ELIGIBLE"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

# Semantic disposition vocabulary (Phase 6).  A dirty retained session may only
# be terminalized after its *meaning* is formally decided.  Blocked dispositions
# keep unresolved dirty evidence from escaping into a terminal state; accepted
# dispositions record an explicit owner decision so the bytes are never
# silently classified.
SEMANTIC_DISPOSITION_HISTORICAL_EVIDENCE = "HISTORICAL_EVIDENCE"
SEMANTIC_DISPOSITION_SUPERSEDED_REFERENCE = "SUPERSEDED_REFERENCE_EVIDENCE"
SEMANTIC_DISPOSITION_STALE_HISTORICAL_WORK = "STALE_HISTORICAL_WORK"
SEMANTIC_DISPOSITION_ABANDONED_EXPERIMENT = "ABANDONED_EXPERIMENT"
SEMANTIC_DISPOSITION_SUPERSEDED_BY_CANONICAL = "SUPERSEDED_BY_CANONICAL"
SEMANTIC_DISPOSITION_ARCHIVE_CANDIDATE = "ARCHIVE_CANDIDATE"
SEMANTIC_DISPOSITION_REBUILD_IN_FRESH_SESSION = "REBUILD_IN_FRESH_SESSION"

SEMANTIC_DISPOSITION_ACTIVE_WORK = "ACTIVE_WORK"
SEMANTIC_DISPOSITION_OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
SEMANTIC_DISPOSITION_VALID_UNINTEGRATED_WORK = "VALID_UNINTEGRATED_WORK"
SEMANTIC_DISPOSITION_UNKNOWN = "UNKNOWN"

_ACCEPTED_SEMANTIC_DISPOSITIONS = frozenset(
    {
        SEMANTIC_DISPOSITION_HISTORICAL_EVIDENCE,
        SEMANTIC_DISPOSITION_SUPERSEDED_REFERENCE,
        SEMANTIC_DISPOSITION_STALE_HISTORICAL_WORK,
        SEMANTIC_DISPOSITION_ABANDONED_EXPERIMENT,
        SEMANTIC_DISPOSITION_SUPERSEDED_BY_CANONICAL,
        SEMANTIC_DISPOSITION_ARCHIVE_CANDIDATE,
        SEMANTIC_DISPOSITION_REBUILD_IN_FRESH_SESSION,
    }
)
_BLOCKED_SEMANTIC_DISPOSITIONS = frozenset(
    {
        SEMANTIC_DISPOSITION_ACTIVE_WORK,
        SEMANTIC_DISPOSITION_OWNER_DECISION_REQUIRED,
        SEMANTIC_DISPOSITION_VALID_UNINTEGRATED_WORK,
        SEMANTIC_DISPOSITION_UNKNOWN,
    }
)
_KNOWN_SEMANTIC_DISPOSITIONS = _ACCEPTED_SEMANTIC_DISPOSITIONS | _BLOCKED_SEMANTIC_DISPOSITIONS

_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
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
_ALLOWED_TASK_STATES = frozenset({"succeeded", "failed", "cancelled", "blocked", "stale", "absent"})
_ALLOWED_LEASE_STATES = frozenset({"released", "expired", "stale", "absent"})
_RETAINABLE_SESSION_STATES = frozenset(
    {
        "stale",
        "suspended",
        "recoverable",
        "expired_clean",
        "expired_dirty_retained",
        "stale_clean",
        "stale_dirty_retained",
        "cleanup_candidate",
    }
)


def is_accepted_semantic_disposition(value: object) -> bool:
    """Return whether an owner decision permits retained terminalization."""

    return str(value or "").strip() in _ACCEPTED_SEMANTIC_DISPOSITIONS


def is_blocked_semantic_disposition(value: object) -> bool:
    """Return whether an owner decision explicitly keeps evidence blocked."""

    return str(value or "").strip() in _BLOCKED_SEMANTIC_DISPOSITIONS


def is_active_retained_state(value: object) -> bool:
    """Return whether a lifecycle/task/process state is still live."""

    return str(value or "").strip() in _ACTIVE_STATES


def _is_unborn_head(value: object) -> bool:
    return isinstance(value, str) and value.lower() == UNBORN_HEAD


def _valid_commit(value: object) -> bool:
    text = str(value or "")
    return bool(_COMMIT_PATTERN.fullmatch(text)) and text.lower() != UNBORN_HEAD


def _valid_retained_commit(value: object, *, allow_unborn: bool) -> bool:
    return _valid_commit(value) or (allow_unborn and _is_unborn_head(value))


def _valid_retained_identity(value: Mapping[str, Any], *, allow_unborn: bool) -> bool:
    return bool(
        isinstance(value.get("source_path"), str)
        and value.get("source_path")
        and isinstance(value.get("git_root"), str)
        and value.get("git_root")
        and isinstance(value.get("device"), int)
        and not isinstance(value.get("device"), bool)
        and isinstance(value.get("inode"), int)
        and not isinstance(value.get("inode"), bool)
        and _valid_retained_commit(value.get("head"), allow_unborn=allow_unborn)
        and isinstance(value.get("git_marker"), str)
        and bool(value.get("git_marker"))
    )


def _valid_identity(value: Mapping[str, Any]) -> bool:
    return _valid_retained_identity(value, allow_unborn=False)


@dataclass(frozen=True)
class RetainedEvidencePlan:
    """Pure decision for one evidence-preserving terminal transition."""

    observation: IdentityRepairObservation
    classification: str
    reason_codes: tuple[str, ...]
    proposed_transition: str
    preservation_actions: tuple[str, ...]
    state_digest: str

    @property
    def evidence(self) -> dict[str, Any]:
        return self.observation.evidence

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": "development.session.archive",
            "schema_version": 1,
            "session_id": self.observation.session_id,
            "workspace_id": self.observation.workspace_id,
            "classification": self.classification,
            "proposed_transition": self.proposed_transition,
            "preservation_actions": list(self.preservation_actions),
            "reason_codes": list(self.reason_codes),
            "state_digest": self.state_digest,
            "evidence": self.evidence,
        }


def _plan(
    observation: IdentityRepairObservation,
    classification: str,
    *reasons: str,
    transition: str = "",
    actions: tuple[str, ...] = (),
) -> RetainedEvidencePlan:
    return RetainedEvidencePlan(
        observation=observation,
        classification=classification,
        reason_codes=tuple(dict.fromkeys(reasons)),
        proposed_transition=transition,
        preservation_actions=actions,
        state_digest=observation.state_digest,
    )


def classify_retained_evidence(observation: IdentityRepairObservation) -> RetainedEvidencePlan:
    """Classify retained evidence without changing Git, files, or lifecycle."""

    # Phase 6: an explicit, formally decided semantic disposition is required
    # before a dirty session may be terminalized.  Without it the evidence is
    # UNKNOWN and must not escape into a terminal/retained state.
    raw_disposition = str(observation.semantic_disposition or "").strip()
    if raw_disposition not in _KNOWN_SEMANTIC_DISPOSITIONS:
        if observation.lifecycle_state in _ACTIVE_STATES or observation.active_live_session:
            return _plan(observation, UNKNOWN, "SEMANTIC_DISPOSITION_UNDECIDED_ACTIVE")
        return _plan(observation, UNKNOWN, "SEMANTIC_DISPOSITION_REQUIRED")
    if raw_disposition in _BLOCKED_SEMANTIC_DISPOSITIONS:
        return _plan(observation, BLOCKED, f"SEMANTIC_DISPOSITION_BLOCKED:{raw_disposition}")

    if not observation.path_safe:
        return _plan(observation, UNKNOWN, "UNSAFE_PATH")
    if observation.active_live_session:
        return _plan(observation, BLOCKED, "ACTIVE_LIVE_SESSION")
    if observation.lifecycle_state in _ACTIVE_STATES:
        return _plan(observation, BLOCKED, "ACTIVE_SESSION_STATE")
    if observation.lifecycle_state not in _RETAINABLE_SESSION_STATES:
        return _plan(observation, UNKNOWN, "SESSION_STATE_INDETERMINATE")
    if not observation.stale and not observation.expired:
        return _plan(observation, BLOCKED, "SESSION_NOT_STALE")

    stored = observation.stored_identity
    current = observation.current_identity
    identity_heads = (
        observation.source_revision,
        observation.canonical_head,
        observation.worktree_head,
        stored.get("head"),
        current.get("head"),
    )
    unborn_flags = tuple(_is_unborn_head(value) for value in identity_heads)
    if any(unborn_flags) and not all(unborn_flags):
        return _plan(observation, UNKNOWN, "MIXED_UNBORN_IDENTITY")
    unborn_evidence = all(unborn_flags)
    if unborn_evidence:
        if (
            observation.source_revision_exists
            or observation.source_revision_ancestor_of_canonical is not None
            or observation.source_revision_ancestor_of_worktree is not None
            or observation.worktree_head_ancestor_of_canonical is not None
        ):
            return _plan(observation, UNKNOWN, "UNBORN_HISTORY_INCONSISTENT")
        if not observation.worktree_branch or observation.worktree_branch == "detached":
            return _plan(observation, UNKNOWN, "UNBORN_WORKTREE_REF_UNKNOWN")
    if not _valid_retained_identity(stored, allow_unborn=unborn_evidence) or not _valid_retained_identity(
        current, allow_unborn=unborn_evidence
    ):
        return _plan(observation, UNKNOWN, "IDENTITY_FIELDS_INVALID")
    task_status = str(observation.task_state.get("status") or observation.task_state.get("state") or "")
    if task_status in _ACTIVE_STATES:
        return _plan(observation, BLOCKED, "NONTERMINAL_TASK")
    if task_status not in _ALLOWED_TASK_STATES:
        return _plan(observation, UNKNOWN, "TASK_STATE_INDETERMINATE")
    lease_status = str(observation.lease_state.get("state") or "")
    if lease_status == "active":
        return _plan(observation, BLOCKED, "ACTIVE_WRITER_LEASE")
    if lease_status not in _ALLOWED_LEASE_STATES:
        return _plan(observation, UNKNOWN, "LEASE_STATE_INDETERMINATE")
    process_status = str(observation.process_state.get("state") or "")
    if process_status in _ACTIVE_STATES:
        return _plan(observation, BLOCKED, "BOUND_PROCESS")
    if process_status not in {"", "absent", "stale", "exited"}:
        return _plan(observation, UNKNOWN, "PROCESS_STATE_INDETERMINATE")
    if observation.evidence_conflicts:
        return _plan(observation, BLOCKED, "EVIDENCE_CONFLICT", *observation.evidence_conflicts)
    if observation.operation_in_progress:
        return _plan(observation, BLOCKED, "GIT_OPERATION_IN_PROGRESS")
    if not unborn_evidence:
        if not _valid_commit(observation.source_revision) or not observation.source_revision_exists:
            return _plan(observation, UNKNOWN, "SOURCE_REVISION_UNKNOWN")
        if not _valid_commit(observation.canonical_head):
            return _plan(observation, UNKNOWN, "CANONICAL_HEAD_UNKNOWN")
        if observation.source_revision_ancestor_of_canonical is not True:
            reason = "SOURCE_HISTORY_NOT_ANCESTOR" if observation.source_revision_ancestor_of_canonical is False else "SOURCE_HISTORY_UNKNOWN"
            return _plan(observation, UNKNOWN, reason)
    if stored.get("source_path") != observation.source_path or stored.get("git_root") != observation.source_git_root:
        return _plan(observation, UNKNOWN, "SOURCE_PATH_OR_GIT_ROOT_DRIFT")
    if stored.get("head") != observation.source_revision:
        return _plan(observation, UNKNOWN, "STORED_SOURCE_REVISION_MISMATCH")
    if current.get("source_path") != observation.source_path or current.get("git_root") != observation.source_git_root:
        return _plan(observation, UNKNOWN, "SOURCE_PATH_OR_GIT_ROOT_DRIFT")
    if current.get("head") != observation.canonical_head:
        return _plan(observation, UNKNOWN, "CURRENT_HEAD_MISMATCH")
    if not observation.worktree_exists:
        return _plan(observation, UNKNOWN, "WORKTREE_MISSING")
    if not observation.worktree_registered:
        return _plan(observation, UNKNOWN, "WORKTREE_REGISTRATION_UNKNOWN")
    if observation.worktree_prunable:
        return _plan(observation, UNKNOWN, "WORKTREE_PRUNABLE")
    if not _valid_retained_commit(observation.worktree_head, allow_unborn=unborn_evidence):
        return _plan(observation, UNKNOWN, "WORKTREE_HEAD_UNKNOWN")
    if not observation.worktree_branch:
        return _plan(observation, UNKNOWN, "WORKTREE_REF_UNKNOWN")
    if observation.worktree_source_git_root != observation.source_git_root:
        return _plan(observation, UNKNOWN, "WORKTREE_SOURCE_MISMATCH")
    if not observation.source_common_dir or observation.source_common_dir != observation.worktree_common_dir:
        return _plan(observation, UNKNOWN, "GIT_COMMON_DIR_MISMATCH")
    if not unborn_evidence:
        if observation.source_revision_ancestor_of_worktree is not True:
            reason = "SOURCE_TO_WORKTREE_HISTORY_NOT_ANCESTOR" if observation.source_revision_ancestor_of_worktree is False else "SOURCE_TO_WORKTREE_HISTORY_UNKNOWN"
            return _plan(observation, UNKNOWN, reason)
        if observation.worktree_head_ancestor_of_canonical is not True:
            reason = "WORKTREE_TO_CANONICAL_HISTORY_NOT_ANCESTOR" if observation.worktree_head_ancestor_of_canonical is False else "WORKTREE_TO_CANONICAL_HISTORY_UNKNOWN"
            return _plan(observation, UNKNOWN, reason)
    if not observation.index_clean:
        return _plan(observation, BLOCKED, "WORKTREE_INDEX_DIRTY")
    if not observation.untracked_manifest_valid:
        return _plan(observation, UNKNOWN, "UNTRACKED_MANIFEST_UNKNOWN")

    identity_changed = (
        stored.get("device") != current.get("device")
        or stored.get("inode") != current.get("inode")
    )
    identity_reason = (
        "UNBORN_RETAINED_EVIDENCE"
        if unborn_evidence
        else "SOURCE_IDENTITY_CHANGED_UNVERIFIED"
        if identity_changed
        else "SOURCE_IDENTITY_MATCHED"
    )
    return _plan(
        observation,
        RETAINED_EVIDENCE_ELIGIBLE,
        "WORKTREE_RETAINED",
        identity_reason,
        transition="cleanup_candidate",
        actions=(
            "preserve_worktree",
            "archive_worktree",
            "preserve_sidecar_evidence",
            "transition_cleanup_candidate",
        ),
    )


__all__ = [
    "BLOCKED",
    "RETAINED_EVIDENCE_ELIGIBLE",
    "RETAINED_EVIDENCE_TERMINAL",
    "RetainedEvidencePlan",
    "UNKNOWN",
    "classify_retained_evidence",
    "is_accepted_semantic_disposition",
    "is_active_retained_state",
    "is_blocked_semantic_disposition",
]
