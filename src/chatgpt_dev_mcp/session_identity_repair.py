"""Evidence-preserving repair of stale DEVELOPMENT source identity.

The normal DEVELOPMENT attach/reconciliation paths intentionally compare the
recorded device and inode of a canonical checkout.  A legitimate filesystem
move can change those values while preserving the Git repository.  This module
contains the pure, fail-closed decision model for a narrowly scoped repair:
the server may replace only the recorded source identity after independently
proving the same repository, immutable source revision, and clean retained
worktree.  It never grants a lease, changes a worktree, or deletes evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .session_state_reconciliation import evidence_digest


IDENTITY_REPAIR_CAPABILITY_ID = "development.session.repair_source_identity"
IDENTITY_REPAIR_SCHEMA_VERSION = 1
VERIFIED_STALE_CLEAN = "VERIFIED_STALE_CLEAN"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

_SESSION_ID_PATTERN = re.compile(r"^session:[A-Za-z0-9_-]{16,96}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_ZERO_HEAD = "0" * 40
_ALLOWED_TASK_STATES = frozenset({"succeeded", "failed", "cancelled", "blocked", "stale", "absent"})
_ALLOWED_LEASE_STATES = frozenset({"released", "expired", "stale", "absent"})
_ACTIVE_STATES = frozenset({"active", "running", "attached", "unknown", "queued", "ready", "leased", "verifying", "review_ready", "recovery"})
_REPAIRABLE_SESSION_STATES = frozenset({
    "stale",
    "suspended",
    "recoverable",
    "expired_clean",
    "expired_dirty_retained",
    "stale_clean",
    "stale_dirty_retained",
    "cleanup_candidate",
})


def _mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("evidence mapping is invalid")
    return {str(key): item for key, item in value.items()}


def _identity(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result = _mapping(value)
    return {
        "source_path": str(result.get("source_path") or ""),
        "git_root": str(result.get("git_root") or ""),
        "device": result.get("device"),
        "inode": result.get("inode"),
        "head": str(result.get("head") or ""),
        "git_marker": str(result.get("git_marker") or ""),
    }


def _valid_commit(value: object) -> bool:
    text = str(value or "")
    return bool(_COMMIT_PATTERN.fullmatch(text)) and text.lower() != _ZERO_HEAD


def _valid_identity_fields(value: Mapping[str, Any]) -> bool:
    return bool(
        isinstance(value.get("source_path"), str)
        and value.get("source_path")
        and isinstance(value.get("git_root"), str)
        and value.get("git_root")
        and isinstance(value.get("device"), int)
        and not isinstance(value.get("device"), bool)
        and isinstance(value.get("inode"), int)
        and not isinstance(value.get("inode"), bool)
        and _valid_commit(value.get("head"))
        and isinstance(value.get("git_marker"), str)
        and bool(value.get("git_marker"))
    )


@dataclass(frozen=True)
class IdentityRepairObservation:
    """Bounded server observation used for both preflight and execute re-read."""

    session_id: str
    workspace_id: str
    lifecycle_state: str
    stale: bool
    expired: bool
    source_path: str
    source_git_root: str
    stored_identity: Mapping[str, Any]
    current_identity: Mapping[str, Any]
    source_revision: str
    canonical_head: str
    source_revision_exists: bool
    worktree_path: str
    worktree_exists: bool
    worktree_head: str | None
    worktree_branch: str | None
    worktree_source_git_root: str
    worktree_common_dir: str
    source_common_dir: str
    worktree_registered: bool
    worktree_prunable: bool
    worktree_clean: bool
    index_clean: bool
    untracked_manifest: tuple[Mapping[str, Any], ...] = ()
    untracked_manifest_valid: bool = True
    operation_in_progress: bool = False
    path_safe: bool = True
    active_live_session: bool = False
    task_state: Mapping[str, Any] = field(default_factory=dict)
    lease_state: Mapping[str, Any] = field(default_factory=dict)
    process_state: Mapping[str, Any] = field(default_factory=dict)
    evidence_conflicts: tuple[str, ...] = ()
    source_git_dir: str = ""
    worktree_git_dir: str = ""
    source_revision_ancestor_of_canonical: bool | None = None
    source_revision_ancestor_of_worktree: bool | None = None
    worktree_head_ancestor_of_canonical: bool | None = None
    semantic_disposition: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not _SESSION_ID_PATTERN.fullmatch(self.session_id):
            raise ValueError("session_id is invalid")
        if not isinstance(self.workspace_id, str) or not self.workspace_id:
            raise ValueError("workspace_id is required")
        object.__setattr__(self, "stored_identity", _identity(self.stored_identity))
        object.__setattr__(self, "current_identity", _identity(self.current_identity))
        object.__setattr__(self, "task_state", _mapping(self.task_state))
        object.__setattr__(self, "lease_state", _mapping(self.lease_state))
        object.__setattr__(self, "process_state", _mapping(self.process_state))
        object.__setattr__(self, "evidence_conflicts", tuple(sorted({str(item) for item in self.evidence_conflicts})))
        if isinstance(self.untracked_manifest, (str, bytes)):
            raise ValueError("untracked_manifest is invalid")
        object.__setattr__(self, "untracked_manifest", tuple(_mapping(item) for item in self.untracked_manifest))

    @property
    def evidence(self) -> dict[str, Any]:
        """Return deterministic, bounded evidence without raw sidecar bytes."""

        return {
            "schema_version": IDENTITY_REPAIR_SCHEMA_VERSION,
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "lifecycle_state": self.lifecycle_state,
            "stale": bool(self.stale),
            "expired": bool(self.expired),
            "source_path": self.source_path,
            "source_git_root": self.source_git_root,
            "stored_identity": dict(self.stored_identity),
            "current_identity": dict(self.current_identity),
            "source_revision": self.source_revision,
            "canonical_head": self.canonical_head,
            "source_revision_exists": bool(self.source_revision_exists),
            "source_revision_ancestor_of_canonical": self.source_revision_ancestor_of_canonical,
            "source_revision_ancestor_of_worktree": self.source_revision_ancestor_of_worktree,
            "worktree_head_ancestor_of_canonical": self.worktree_head_ancestor_of_canonical,
            "worktree_path": self.worktree_path,
            "worktree_exists": bool(self.worktree_exists),
            "worktree_head": self.worktree_head,
            "worktree_branch": self.worktree_branch,
            "worktree_source_git_root": self.worktree_source_git_root,
            "worktree_common_dir": self.worktree_common_dir,
            "source_common_dir": self.source_common_dir,
            "source_git_dir": self.source_git_dir,
            "worktree_git_dir": self.worktree_git_dir,
            "worktree_registered": bool(self.worktree_registered),
            "worktree_prunable": bool(self.worktree_prunable),
            "worktree_clean": bool(self.worktree_clean),
            "index_clean": bool(self.index_clean),
            "untracked_manifest": [dict(item) for item in self.untracked_manifest],
            "untracked_manifest_valid": bool(self.untracked_manifest_valid),
            "operation_in_progress": bool(self.operation_in_progress),
            "path_safe": bool(self.path_safe),
            "active_live_session": bool(self.active_live_session),
            "task_state": dict(self.task_state),
            "lease_state": dict(self.lease_state),
            "process_state": dict(self.process_state),
            "evidence_conflicts": list(self.evidence_conflicts),
            "semantic_disposition": str(self.semantic_disposition or ""),
        }

    @property
    def state_digest(self) -> str:
        return evidence_digest(self.evidence)


@dataclass(frozen=True)
class IdentityRepairPlan:
    observation: IdentityRepairObservation
    classification: str
    reason_codes: tuple[str, ...]
    preserve_worktree: bool
    state_digest: str

    @property
    def evidence(self) -> dict[str, Any]:
        return self.observation.evidence

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": IDENTITY_REPAIR_CAPABILITY_ID,
            "schema_version": IDENTITY_REPAIR_SCHEMA_VERSION,
            "session_id": self.observation.session_id,
            "workspace_id": self.observation.workspace_id,
            "classification": self.classification,
            "reason_codes": list(self.reason_codes),
            "preserve_worktree": self.preserve_worktree,
            "state_digest": self.state_digest,
            "evidence": self.evidence,
        }


def _plan(
    observation: IdentityRepairObservation,
    classification: str,
    *reasons: str,
    preserve_worktree: bool = False,
) -> IdentityRepairPlan:
    return IdentityRepairPlan(
        observation=observation,
        classification=classification,
        reason_codes=tuple(dict.fromkeys(reasons)),
        preserve_worktree=preserve_worktree,
        state_digest=observation.state_digest,
    )


def classify_identity_repair(observation: IdentityRepairObservation) -> IdentityRepairPlan:
    """Classify one repair observation without changing any state."""

    stored = observation.stored_identity
    current = observation.current_identity
    if not observation.path_safe:
        return _plan(observation, UNKNOWN, "UNSAFE_PATH")
    if observation.active_live_session:
        return _plan(observation, BLOCKED, "ACTIVE_LIVE_SESSION")
    if observation.lifecycle_state in _ACTIVE_STATES:
        return _plan(observation, BLOCKED, "ACTIVE_SESSION_STATE")
    if observation.lifecycle_state not in _REPAIRABLE_SESSION_STATES:
        return _plan(observation, UNKNOWN, "SESSION_STATE_INDETERMINATE")
    if not observation.stale and not observation.expired:
        return _plan(observation, BLOCKED, "SESSION_NOT_STALE")
    if not _valid_identity_fields(stored) or not _valid_identity_fields(current):
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
        return _plan(observation, UNKNOWN, "EVIDENCE_CONFLICT", *observation.evidence_conflicts)
    if observation.operation_in_progress:
        return _plan(observation, BLOCKED, "GIT_OPERATION_IN_PROGRESS")
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
    if not _valid_commit(current.get("head")):
        return _plan(observation, UNKNOWN, "CURRENT_HEAD_UNKNOWN")
    if current.get("head") != observation.canonical_head:
        return _plan(observation, UNKNOWN, "CURRENT_HEAD_MISMATCH")
    if not observation.worktree_exists:
        return _plan(observation, UNKNOWN, "WORKTREE_MISSING")
    if not observation.worktree_registered:
        return _plan(observation, UNKNOWN, "WORKTREE_REGISTRATION_UNKNOWN")
    if observation.worktree_prunable:
        return _plan(observation, UNKNOWN, "WORKTREE_PRUNABLE")
    if not _valid_commit(observation.worktree_head):
        return _plan(observation, UNKNOWN, "WORKTREE_HEAD_UNKNOWN")
    if not observation.worktree_branch:
        return _plan(observation, UNKNOWN, "WORKTREE_REF_UNKNOWN")
    if observation.worktree_source_git_root != observation.source_git_root:
        return _plan(observation, UNKNOWN, "WORKTREE_SOURCE_MISMATCH")
    if not observation.source_common_dir or observation.source_common_dir != observation.worktree_common_dir:
        return _plan(observation, UNKNOWN, "GIT_COMMON_DIR_MISMATCH")
    if observation.source_revision_ancestor_of_worktree is not True:
        reason = (
            "SOURCE_TO_WORKTREE_HISTORY_NOT_ANCESTOR"
            if observation.source_revision_ancestor_of_worktree is False
            else "SOURCE_TO_WORKTREE_HISTORY_UNKNOWN"
        )
        return _plan(observation, UNKNOWN, reason)
    if observation.worktree_head_ancestor_of_canonical is not True:
        reason = (
            "WORKTREE_TO_CANONICAL_HISTORY_NOT_ANCESTOR"
            if observation.worktree_head_ancestor_of_canonical is False
            else "WORKTREE_TO_CANONICAL_HISTORY_UNKNOWN"
        )
        return _plan(observation, UNKNOWN, reason)
    if not observation.worktree_clean:
        return _plan(observation, BLOCKED, "WORKTREE_DIRTY")
    if not observation.index_clean:
        return _plan(observation, BLOCKED, "WORKTREE_INDEX_DIRTY")
    if not observation.untracked_manifest_valid:
        return _plan(observation, UNKNOWN, "UNTRACKED_MANIFEST_UNKNOWN")
    if observation.untracked_manifest:
        return _plan(observation, BLOCKED, "UNTRACKED_EVIDENCE_PRESENT")

    identity_changed = (
        stored.get("device") != current.get("device")
        or stored.get("inode") != current.get("inode")
    )
    reason = "SOURCE_DEVICE_OR_INODE_CHANGED" if identity_changed else "SOURCE_IDENTITY_ALREADY_MATCHED"
    return _plan(observation, VERIFIED_STALE_CLEAN, reason, preserve_worktree=True)


def identity_repair_receipt_id(session_id: str, state_digest: str) -> str:
    if not _SESSION_ID_PATTERN.fullmatch(session_id) or not re.fullmatch(r"[0-9a-f]{64}", state_digest):
        raise ValueError("identity repair receipt identity is invalid")
    return f"identity-repair:{session_id}:{state_digest}"


__all__ = [
    "BLOCKED",
    "IDENTITY_REPAIR_CAPABILITY_ID",
    "IDENTITY_REPAIR_SCHEMA_VERSION",
    "IdentityRepairObservation",
    "IdentityRepairPlan",
    "UNKNOWN",
    "VERIFIED_STALE_CLEAN",
    "classify_identity_repair",
    "identity_repair_receipt_id",
]
