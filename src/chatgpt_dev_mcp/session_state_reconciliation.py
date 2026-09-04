"""Generic, fail-closed DEVELOPMENT session lifecycle reconciliation.

This module contains the policy and evidence model used by the public capability
``development.session.reconcile_stale_state``.  It intentionally has no
workspace-move or worktree-removal authority.  Filesystem and control-plane
observations are supplied by the server; the pure classifier below makes the
same decision for a preflight and its execute-time re-read.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


RECONCILABLE_PRESERVE_WORKTREE = "RECONCILABLE_PRESERVE_WORKTREE"
RECONCILABLE_MISSING_WORKTREE = "RECONCILABLE_MISSING_WORKTREE"
ALREADY_TERMINAL = "ALREADY_TERMINAL"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

RECONCILIATION_CAPABILITY_ID = "development.session.reconcile_stale_state"
RECONCILIATION_SCHEMA_VERSION = 1
LEGACY_ROOTS_ENV = "LOCAL_DEV_MCP_LEGACY_WORKTREE_ROOTS"
MAX_SIDECAR_BYTES = 128 * 1024
MAX_EVIDENCE_JSON_BYTES = 128 * 1024
SESSION_ID_PATTERN = re.compile(r"^session:[A-Za-z0-9_-]{16,96}$")

TERMINAL_SESSION_STATES = frozenset({"integrated", "abandoned", "cleanup_candidate", "closed"})
NONTERMINAL_TASK_STATES = frozenset({"queued", "ready", "leased", "running", "verifying", "review_ready", "recovery"})
TERMINAL_TASK_STATES = frozenset({"succeeded", "failed", "cancelled", "blocked", "stale", "absent"})
ACTIVE_LEASE_STATES = frozenset({"active"})
KNOWN_LEASE_STATES = frozenset({"active", "released", "expired", "stale", "absent"})
ACTIVE_PROCESS_STATES = frozenset({"active", "running", "attached", "unknown"})
MISSING_GIT_STATES = frozenset({"missing", "absent", "prunable"})


class ReconciliationError(ValueError):
    """Raised when an observation or receipt cannot be trusted."""


def canonical_json(value: object) -> str:
    """Serialize bounded evidence deterministically before hashing."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ReconciliationError("reconciliation evidence is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_JSON_BYTES:
        raise ReconciliationError("reconciliation evidence exceeds the safety bound")
    return encoded


def evidence_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalise_mapping(value: object) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ReconciliationError("reconciliation evidence mapping is invalid")
    return {str(key): item for key, item in value.items()}


def _normalise_tuple(value: object, *, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, (tuple, list, set, frozenset)):
        raise ReconciliationError(f"{name} must be a sequence")
    values = tuple(str(item) for item in value)
    return tuple(sorted(set(values)))


@dataclass(frozen=True)
class ReconciliationSnapshot:
    """All DevMCP-controlled state needed for one deterministic decision."""

    session_id: str
    workspace_id: str
    lifecycle_state: str
    stale: bool
    expired: bool
    sidecar_state: str = ""
    sidecar_root: str = ""
    sidecar_path: str = ""
    sidecar_digest: str = ""
    sidecar_bytes: bytes | None = None
    sidecar_updated_at: str = ""
    worktree_path: str = ""
    worktree_id: str = ""
    worktree_exists: bool = False
    worktree_dirty: bool = False
    worktree_head: str | None = None
    worktree_branch: str | None = None
    worktree_device: int | None = None
    worktree_inode: int | None = None
    tracked_diff_digest: str = ""
    untracked_manifest: tuple[Mapping[str, Any], ...] = ()
    untracked_digest: str = ""
    index_clean: bool = False
    source_revision: str = ""
    source_path: str = ""
    source_device: int | None = None
    source_inode: int | None = None
    git_metadata_state: str = "missing"
    git_metadata_prunable: bool = False
    task_state: Mapping[str, Any] = field(default_factory=dict)
    lease_state: Mapping[str, Any] = field(default_factory=dict)
    process_state: Mapping[str, Any] = field(default_factory=dict)
    archive_state: Mapping[str, Any] = field(default_factory=dict)
    sqlite_state: Mapping[str, Any] = field(default_factory=dict)
    session_metadata: Mapping[str, Any] = field(default_factory=dict)
    evidence_conflicts: tuple[str, ...] = ()
    active_live_session: bool = False
    root_allowlisted: bool = False
    root_kind: str = "untrusted"
    authority_known: bool = True
    source_identity_verified: bool = False
    worktree_identity_verified: bool = False
    dirty_preservable: bool = False
    source_provenance_verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not SESSION_ID_PATTERN.fullmatch(self.session_id):
            raise ReconciliationError("session_id is invalid")
        if not isinstance(self.workspace_id, str) or not self.workspace_id:
            raise ReconciliationError("workspace_id is required")
        if not isinstance(self.lifecycle_state, str) or not self.lifecycle_state:
            raise ReconciliationError("lifecycle_state is required")
        for name in ("task_state", "lease_state", "process_state", "archive_state", "sqlite_state", "session_metadata"):
            object.__setattr__(self, name, _normalise_mapping(getattr(self, name)))
        object.__setattr__(self, "evidence_conflicts", _normalise_tuple(self.evidence_conflicts, name="evidence_conflicts"))
        manifests = self.untracked_manifest
        if manifests is None:
            manifests = ()
        if isinstance(manifests, (str, bytes)) or not isinstance(manifests, (tuple, list)):
            raise ReconciliationError("untracked_manifest must be a sequence")
        normalized_manifest = tuple(_normalise_mapping(item) for item in manifests)
        object.__setattr__(self, "untracked_manifest", normalized_manifest)
        if self.sidecar_bytes is not None:
            if not isinstance(self.sidecar_bytes, bytes):
                raise ReconciliationError("sidecar_bytes must be bytes")
            if len(self.sidecar_bytes) > MAX_SIDECAR_BYTES:
                raise ReconciliationError("sidecar_bytes exceeds the safety bound")
            if self.sidecar_digest and hashlib.sha256(self.sidecar_bytes).hexdigest() != self.sidecar_digest:
                raise ReconciliationError("sidecar_digest does not match sidecar_bytes")

    def evidence(self) -> dict[str, Any]:
        """Return digestable evidence without embedding raw sidecar bytes."""

        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "lifecycle_state": self.lifecycle_state,
            "stale": bool(self.stale),
            "expired": bool(self.expired),
            "sidecar_state": self.sidecar_state,
            "sidecar_root": self.sidecar_root,
            "sidecar_path": self.sidecar_path,
            "sidecar_digest": self.sidecar_digest,
            "sidecar_updated_at": self.sidecar_updated_at,
            "worktree_path": self.worktree_path,
            "worktree_id": self.worktree_id,
            "worktree_exists": bool(self.worktree_exists),
            "worktree_dirty": bool(self.worktree_dirty),
            "worktree_head": self.worktree_head,
            "worktree_branch": self.worktree_branch,
            "worktree_device": self.worktree_device,
            "worktree_inode": self.worktree_inode,
            "tracked_diff_digest": self.tracked_diff_digest,
            "untracked_manifest": [dict(item) for item in self.untracked_manifest],
            "untracked_digest": self.untracked_digest,
            "index_clean": bool(self.index_clean),
            "source_revision": self.source_revision,
            "source_path": self.source_path,
            "source_device": self.source_device,
            "source_inode": self.source_inode,
            "git_metadata_state": self.git_metadata_state,
            "git_metadata_prunable": bool(self.git_metadata_prunable),
            "task_state": dict(self.task_state),
            "lease_state": dict(self.lease_state),
            "process_state": dict(self.process_state),
            "archive_state": dict(self.archive_state),
            "sqlite_state": dict(self.sqlite_state),
            "session_metadata": dict(self.session_metadata),
            "evidence_conflicts": list(self.evidence_conflicts),
            "active_live_session": bool(self.active_live_session),
            "root_allowlisted": bool(self.root_allowlisted),
            "root_kind": self.root_kind,
            "authority_known": bool(self.authority_known),
            "source_identity_verified": bool(self.source_identity_verified),
            "worktree_identity_verified": bool(self.worktree_identity_verified),
            "dirty_preservable": bool(self.dirty_preservable),
            "source_provenance_verified": bool(self.source_provenance_verified),
        }

    @property
    def state_digest(self) -> str:
        return evidence_digest(self.evidence())


@dataclass(frozen=True)
class ReconciliationPlan:
    snapshot: ReconciliationSnapshot
    classification: str
    proposed_transition: str
    preservation_actions: tuple[str, ...]
    reason_codes: tuple[str, ...]
    state_digest: str

    def as_dict(self, *, include_sidecar_bytes: bool = False) -> dict[str, Any]:
        result = {
            "capability_id": RECONCILIATION_CAPABILITY_ID,
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "session_id": self.snapshot.session_id,
            "workspace_id": self.snapshot.workspace_id,
            "classification": self.classification,
            "current_lifecycle": self.snapshot.lifecycle_state,
            "proposed_transition": self.proposed_transition,
            "preservation_actions": list(self.preservation_actions),
            "reason_codes": list(self.reason_codes),
            "state_digest": self.state_digest,
            "evidence": self.snapshot.evidence(),
        }
        if include_sidecar_bytes and self.snapshot.sidecar_bytes is not None:
            result["sidecar_bytes"] = self.snapshot.sidecar_bytes
        return result


@dataclass(frozen=True)
class RootDecision:
    allowed: bool
    kind: str
    root: str
    reason: str


@dataclass(frozen=True)
class SidecarRecord:
    """Raw registered sidecar evidence before any lifecycle interpretation."""

    path: str
    session_id: str
    payload: Mapping[str, Any]
    raw_bytes: bytes
    digest: str
    updated_at: str


def read_registered_sidecars(
    sidecar_root: str | os.PathLike[str],
    *,
    session_id: str | None = None,
) -> tuple[SidecarRecord, ...]:
    """Read sidecars only from the current, DevMCP-registered sidecar root.

    Legacy worktree roots are represented by a sidecar's stored ``worktree_path``;
    this function never scans those roots or any caller-provided arbitrary tree.
    """

    root = Path(sidecar_root).expanduser()
    if session_id is not None and not SESSION_ID_PATTERN.fullmatch(session_id):
        return ()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        return ()
    candidates = [root / f"{session_id.removeprefix('session:')}.json"] if session_id else sorted(root.glob("*.json"))
    records: list[SidecarRecord] = []
    for path in candidates:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SIDECAR_BYTES:
                continue
            raw = path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            sid = payload.get("session_id") if isinstance(payload, Mapping) else None
            if not isinstance(sid, str) or not SESSION_ID_PATTERN.fullmatch(sid):
                continue
            if session_id is not None and sid != session_id:
                continue
            if not isinstance(payload, Mapping):
                continue
            records.append(
                SidecarRecord(
                    path=str(path),
                    session_id=sid,
                    payload=dict(payload),
                    raw_bytes=raw,
                    digest=hashlib.sha256(raw).hexdigest(),
                    updated_at=str(path.stat().st_mtime_ns),
                )
            )
        except (OSError, UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return tuple(records)


def configured_legacy_roots(raw: str | None = None) -> tuple[Path, ...]:
    """Parse only explicitly configured legacy roots; never discover arbitrary roots."""

    value = os.environ.get(LEGACY_ROOTS_ENV) if raw is None else raw
    if not value:
        return ()
    roots: list[Path] = []
    for item in value.split(os.pathsep):
        if not item:
            continue
        path = Path(item).expanduser()
        if not path.is_absolute():
            raise ReconciliationError("legacy worktree roots must be absolute")
        normalized = Path(os.path.abspath(str(path)))
        if normalized.is_symlink():
            raise ReconciliationError("legacy worktree root must not be a symlink")
        if normalized not in roots:
            roots.append(normalized)
    return tuple(roots)


def resolve_allowlisted_root(
    worktree_path: str | os.PathLike[str],
    *,
    managed_root: str | os.PathLike[str],
    legacy_roots: Iterable[str | os.PathLike[str]] = (),
) -> RootDecision:
    """Classify one stored path against current and explicit legacy roots."""

    candidate = Path(worktree_path).expanduser()
    if not candidate.is_absolute():
        return RootDecision(False, "untrusted", "", "WORKTREE_PATH_NOT_ABSOLUTE")
    if candidate.is_symlink():
        return RootDecision(False, "untrusted", str(candidate), "WORKTREE_PATH_SYMLINK")
    # Inspect the lexical path before resolving it.  Resolving first would
    # turn a symlinked legacy root into its real target and accidentally make
    # an untrusted location appear allowlisted.
    raw_managed = Path(managed_root).expanduser()
    if not raw_managed.is_absolute():
        return RootDecision(False, "untrusted", str(raw_managed), "MANAGED_ROOT_NOT_ABSOLUTE")
    if raw_managed.is_symlink():
        return RootDecision(False, "untrusted", str(raw_managed), "MANAGED_ROOT_SYMLINK")
    raw_legacy = tuple(Path(root).expanduser() for root in legacy_roots)
    for root in raw_legacy:
        if not root.is_absolute():
            return RootDecision(False, "untrusted", str(root), "LEGACY_ROOT_NOT_ABSOLUTE")
        if root.is_symlink():
            return RootDecision(False, "untrusted", str(root), "LEGACY_ROOT_SYMLINK")
    lexical_candidate = Path(os.path.abspath(str(candidate)))
    lexical_roots = (("managed", raw_managed), *(('legacy', root) for root in raw_legacy))
    try:
        lexical_allowlisted = any(
            os.path.commonpath((str(lexical_candidate), str(root))) == str(root)
            and lexical_candidate != root
            for _kind, root in lexical_roots
        )
    except ValueError:
        lexical_allowlisted = False
    if not lexical_allowlisted:
        return RootDecision(False, "untrusted", str(candidate), "WORKTREE_PATH_NOT_LEXICALLY_ALLOWLISTED")
    candidate = candidate.resolve(strict=False)
    roots: list[tuple[str, Path]] = [("managed", raw_managed.resolve(strict=False))]
    for root in raw_legacy:
        path = root.resolve(strict=False)
        if ("legacy", path) not in roots:
            roots.append(("legacy", path))
    for kind, root in roots:
        try:
            if os.path.commonpath((str(candidate), str(root))) == str(root) and candidate != root:
                return RootDecision(True, kind, str(root), "ROOT_ALLOWLISTED")
        except ValueError:
            continue
    return RootDecision(False, "untrusted", "", "WORKTREE_ROOT_NOT_ALLOWLISTED")


def classify_reconciliation_snapshot(snapshot: ReconciliationSnapshot) -> ReconciliationPlan:
    """Apply the fail-closed lifecycle policy to one immutable observation."""

    reasons: list[str] = []
    actions: list[str] = []
    if not snapshot.authority_known:
        return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("AUTHORITY_INDETERMINATE",), snapshot.state_digest)
    if snapshot.active_live_session:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("ACTIVE_LIVE_SESSION",), snapshot.state_digest)
    task_status = str(snapshot.task_state.get("status") or snapshot.task_state.get("state") or "")
    if task_status in NONTERMINAL_TASK_STATES:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("NONTERMINAL_TASK",), snapshot.state_digest)
    lease_state = str(snapshot.lease_state.get("state") or "")
    if lease_state in ACTIVE_LEASE_STATES:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("ACTIVE_WRITER_LEASE",), snapshot.state_digest)
    process_state = str(snapshot.process_state.get("state") or "")
    if process_state in ACTIVE_PROCESS_STATES:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("BOUND_PROCESS",), snapshot.state_digest)
    if snapshot.evidence_conflicts:
        return ReconciliationPlan(
            snapshot,
            BLOCKED,
            "",
            ("preserve_conflicting_evidence",),
            tuple(["EVIDENCE_CONFLICT", *snapshot.evidence_conflicts]),
            snapshot.state_digest,
        )
    if task_status not in TERMINAL_TASK_STATES:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("TASK_STATE_INDETERMINATE",), snapshot.state_digest)
    if lease_state not in KNOWN_LEASE_STATES:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("LEASE_STATE_INDETERMINATE",), snapshot.state_digest)
    if snapshot.lifecycle_state in TERMINAL_SESSION_STATES:
        return ReconciliationPlan(
            snapshot=snapshot,
            classification=ALREADY_TERMINAL,
            proposed_transition=snapshot.lifecycle_state,
            preservation_actions=("preserve_existing_receipts",),
            reason_codes=("LIFECYCLE_ALREADY_TERMINAL",),
            state_digest=snapshot.state_digest,
        )
    if not snapshot.stale and not snapshot.expired:
        return ReconciliationPlan(snapshot, BLOCKED, "", (), ("SESSION_NOT_STALE",), snapshot.state_digest)
    if not snapshot.source_revision or snapshot.source_revision.lower() in {"unknown", "invalid"}:
        return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("SOURCE_REVISION_UNKNOWN",), snapshot.state_digest)
    if not snapshot.root_allowlisted:
        return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("WORKTREE_ROOT_NOT_ALLOWLISTED",), snapshot.state_digest)
    if not snapshot.source_identity_verified or not snapshot.source_provenance_verified:
        return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("SOURCE_IDENTITY_UNVERIFIED",), snapshot.state_digest)

    if snapshot.worktree_exists:
        if not snapshot.worktree_identity_verified:
            return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("WORKTREE_IDENTITY_MISMATCH",), snapshot.state_digest)
        if snapshot.worktree_dirty and (not snapshot.dirty_preservable or not snapshot.index_clean):
            return ReconciliationPlan(snapshot, BLOCKED, "", (), ("DIRTY_WORKTREE_PRESERVATION_UNAVAILABLE",), snapshot.state_digest)
        reasons.append("WORKTREE_RETAINED")
        actions.append("retain_worktree")
        if snapshot.worktree_dirty:
            actions.append("archive_dirty_worktree")
        actions.append("transition_cleanup_candidate")
        return ReconciliationPlan(
            snapshot,
            RECONCILABLE_PRESERVE_WORKTREE,
            "cleanup_candidate",
            tuple(actions),
            tuple(reasons),
            snapshot.state_digest,
        )

    if snapshot.git_metadata_state not in MISSING_GIT_STATES and not snapshot.git_metadata_prunable:
        return ReconciliationPlan(snapshot, UNKNOWN, "", (), ("GIT_METADATA_NOT_MISSING_OR_PRUNABLE",), snapshot.state_digest)
    actions.extend(("preserve_sidecar_evidence", "tombstone_missing_worktree", "transition_cleanup_candidate"))
    reasons.append("MISSING_IS_NOT_SUCCESS")
    if snapshot.root_kind == "legacy":
        reasons.append("LEGACY_ROOT_NONLIVE")
    return ReconciliationPlan(
        snapshot,
        RECONCILABLE_MISSING_WORKTREE,
        "cleanup_candidate",
        tuple(actions),
        tuple(reasons),
        snapshot.state_digest,
    )


def reconciliation_receipt_id(session_id: str, state_digest: str) -> str:
    if not SESSION_ID_PATTERN.fullmatch(session_id) or len(state_digest) != 64:
        raise ReconciliationError("reconciliation receipt identity is invalid")
    return f"reconciliation:{session_id}:{state_digest}"


__all__ = [
    "ALREADY_TERMINAL",
    "BLOCKED",
    "LEGACY_ROOTS_ENV",
    "MAX_EVIDENCE_JSON_BYTES",
    "MAX_SIDECAR_BYTES",
    "RECONCILABLE_MISSING_WORKTREE",
    "RECONCILABLE_PRESERVE_WORKTREE",
    "ReconciliationError",
    "ReconciliationPlan",
    "ReconciliationSnapshot",
    "RootDecision",
    "SidecarRecord",
    "UNKNOWN",
    "canonical_json",
    "classify_reconciliation_snapshot",
    "configured_legacy_roots",
    "evidence_digest",
    "reconciliation_receipt_id",
    "resolve_allowlisted_root",
    "read_registered_sidecars",
]
