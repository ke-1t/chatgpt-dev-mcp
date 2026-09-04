"""Conservative classification for retained development sessions.

The reconciler is intentionally pure and non-destructive.  It consumes
already-bounded control-plane metadata and optional deeper comparison evidence;
it never reads, writes, deletes, resets, or cleans a worktree itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Literal, Mapping, Sequence


SessionClassification = Literal[
    "active",
    "clean",
    "unavailable",
    "already_integrated",
    "superseded",
    "conflicted",
    "recoverable_unmerged",
    "orphaned_candidate",
]
Confidence = Literal["high", "medium", "low"]

_TERMINAL_UNSUCCESSFUL_TASK_STATES = frozenset({"failed", "cancelled", "blocked", "stale"})
_INTEGRATED_SESSION_STATES = frozenset({"integrated", "cleanup_candidate", "closed"})
_ACTIVE_SESSION_STATES = frozenset({"active", "review_ready"})
_UNAVAILABLE_SESSION_STATES = frozenset({"expired_unavailable", "stale_unavailable"})
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UNBORN = "0" * 40
_MAX_RECORDS = 10_000
_MAX_PATHS = 512


class SessionReconciliationError(ValueError):
    """Raised when reconciliation metadata is malformed or ambiguous."""


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SessionReconciliationError(f"{name} must be a mapping")
    return value


def _optional_text(value: object, *, name: str, maximum: int = 256) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise SessionReconciliationError(f"{name} is invalid")
    return value


def _required_text(value: object, *, name: str, maximum: int = 256) -> str:
    parsed = _optional_text(value, name=name, maximum=maximum)
    if not parsed:
        raise SessionReconciliationError(f"{name} is required")
    return parsed


def _boolean(value: object, *, name: str, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise SessionReconciliationError(f"{name} must be boolean")
    return value


def _optional_boolean(value: object, *, name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise SessionReconciliationError(f"{name} must be boolean or null")
    return value


def _revision(value: object, *, name: str) -> str:
    text = _required_text(value, name=name, maximum=40).lower()
    if not _HEX40.fullmatch(text):
        raise SessionReconciliationError(f"{name} must be a 40-character Git revision")
    return text


def _hash64(value: object, *, name: str) -> str:
    text = _required_text(value, name=name, maximum=64).lower()
    if not _HEX64.fullmatch(text):
        raise SessionReconciliationError(f"{name} must be a 64-character lowercase hex digest")
    return text


def _safe_path(value: object) -> str:
    text = _required_text(value, name="changed path", maximum=512)
    if "\\" in text:
        raise SessionReconciliationError("changed path must use POSIX separators")
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise SessionReconciliationError("changed path must remain inside the repository")
    return path.as_posix()


@dataclass(frozen=True)
class PatchSnapshot:
    """Normalized metadata for one retained or successor patch."""

    base_revision: str
    patch_hash: str
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_revision", _revision(self.base_revision, name="base_revision"))
        object.__setattr__(self, "patch_hash", _hash64(self.patch_hash, name="patch_hash"))
        if not isinstance(self.changed_paths, tuple):
            raise SessionReconciliationError("changed_paths must be a tuple")
        if not self.changed_paths or len(self.changed_paths) > _MAX_PATHS:
            raise SessionReconciliationError("changed_paths must contain 1 to 512 paths")
        normalized = tuple(sorted({_safe_path(path) for path in self.changed_paths}))
        if len(normalized) != len(self.changed_paths):
            raise SessionReconciliationError("changed_paths must not contain duplicates")
        object.__setattr__(self, "changed_paths", normalized)

    @property
    def unborn_base(self) -> bool:
        return self.base_revision == _UNBORN

    @classmethod
    def from_diff(cls, raw: Mapping[str, object]) -> "PatchSnapshot":
        row = _mapping(raw, name="diff")
        has_changes = row.get("has_changes", True)
        if not isinstance(has_changes, bool):
            raise SessionReconciliationError("has_changes must be boolean")
        if not has_changes:
            raise SessionReconciliationError("PatchSnapshot requires a non-empty diff")
        paths = row.get("changed_paths")
        if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)):
            raise SessionReconciliationError("changed_paths must be a sequence")
        return cls(
            base_revision=_required_text(row.get("base_revision"), name="base_revision", maximum=40),
            patch_hash=_required_text(row.get("patch_hash"), name="patch_hash", maximum=64),
            changed_paths=tuple(_safe_path(path) for path in paths),
        )


@dataclass(frozen=True)
class PatchApplicationProbe:
    """Read-only forward/reverse patch-application evidence."""

    reverse_apply_clean: bool | None = None
    forward_apply_clean: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reverse_apply_clean",
            _optional_boolean(self.reverse_apply_clean, name="reverse_apply_clean"),
        )
        object.__setattr__(
            self,
            "forward_apply_clean",
            _optional_boolean(self.forward_apply_clean, name="forward_apply_clean"),
        )


@dataclass(frozen=True)
class SuccessorPatch:
    task_id: str
    patch: PatchSnapshot

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _required_text(self.task_id, name="successor task_id", maximum=160))
        if not isinstance(self.patch, PatchSnapshot):
            raise SessionReconciliationError("successor patch must be PatchSnapshot")


@dataclass(frozen=True)
class DeepSessionEvidence:
    """Optional expensive evidence supplied by a later deep reconciliation pass."""

    canonical_contains_diff: bool | None = None
    successor_contains_diff: bool | None = None
    patch_conflicts: bool | None = None
    successor_task_id: str = ""
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "canonical_contains_diff",
            _optional_boolean(self.canonical_contains_diff, name="canonical_contains_diff"),
        )
        object.__setattr__(
            self,
            "successor_contains_diff",
            _optional_boolean(self.successor_contains_diff, name="successor_contains_diff"),
        )
        object.__setattr__(
            self,
            "patch_conflicts",
            _optional_boolean(self.patch_conflicts, name="patch_conflicts"),
        )
        successor = _optional_text(self.successor_task_id, name="successor_task_id", maximum=160)
        if self.successor_contains_diff is True and not successor:
            raise SessionReconciliationError("successor_task_id is required when successor_contains_diff is true")
        object.__setattr__(self, "successor_task_id", successor)
        if not isinstance(self.reason_codes, tuple) or len(self.reason_codes) > 32:
            raise SessionReconciliationError("reason_codes must be a bounded tuple")
        object.__setattr__(
            self,
            "reason_codes",
            tuple(_required_text(code, name="reason code", maximum=96) for code in self.reason_codes),
        )


def _patches_exactly_equivalent(left: PatchSnapshot, right: PatchSnapshot) -> bool:
    return left.patch_hash == right.patch_hash and left.changed_paths == right.changed_paths


def build_deep_evidence(
    *,
    candidate: PatchSnapshot,
    canonical_probe: PatchApplicationProbe | None = None,
    successors: Sequence[SuccessorPatch] = (),
) -> DeepSessionEvidence:
    """Build conservative deep evidence from read-only comparison results."""

    if not isinstance(candidate, PatchSnapshot):
        raise SessionReconciliationError("candidate must be PatchSnapshot")
    if canonical_probe is not None and not isinstance(canonical_probe, PatchApplicationProbe):
        raise SessionReconciliationError("canonical_probe must be PatchApplicationProbe")
    if not isinstance(successors, Sequence) or isinstance(successors, (str, bytes)):
        raise SessionReconciliationError("successors must be a sequence")
    if len(successors) > _MAX_RECORDS:
        raise SessionReconciliationError("successor input exceeds bounds")

    reasons: list[str] = []
    if candidate.unborn_base:
        reasons.append("UNBORN_BASE_COMPARISON_LIMITED")

    exact_successors: list[SuccessorPatch] = []
    for successor in successors:
        if not isinstance(successor, SuccessorPatch):
            raise SessionReconciliationError("successor entries must be SuccessorPatch")
        if _patches_exactly_equivalent(candidate, successor.patch):
            exact_successors.append(successor)

    successor_contains: bool | None = None
    successor_task_id = ""
    if len(exact_successors) == 1:
        successor_contains = True
        successor_task_id = exact_successors[0].task_id
        reasons.append("SUCCESSOR_EXACT_PATCH_EQUIVALENCE")
    elif len(exact_successors) > 1:
        reasons.append("AMBIGUOUS_EXACT_SUCCESSORS")

    canonical_contains: bool | None = None
    conflicts: bool | None = None
    if canonical_probe is not None:
        reverse_clean = canonical_probe.reverse_apply_clean
        forward_clean = canonical_probe.forward_apply_clean
        if reverse_clean is True:
            canonical_contains = True
            conflicts = False
            reasons.append("CANONICAL_REVERSE_APPLY_CLEAN")
        elif reverse_clean is False and forward_clean is True:
            canonical_contains = False
            conflicts = False
            reasons.append("CANONICAL_FORWARD_APPLY_CLEAN")
        elif reverse_clean is False and forward_clean is False:
            canonical_contains = False
            conflicts = True
            reasons.append("CANONICAL_PATCH_CONFLICT")
        else:
            reasons.append("CANONICAL_APPLY_PROBE_INCOMPLETE")

    return DeepSessionEvidence(
        canonical_contains_diff=canonical_contains,
        successor_contains_diff=successor_contains,
        patch_conflicts=conflicts,
        successor_task_id=successor_task_id,
        reason_codes=tuple(reasons),
    )


@dataclass(frozen=True)
class SessionReconciliation:
    session_id: str
    task_id: str
    classification: SessionClassification
    confidence: Confidence
    reason_codes: tuple[str, ...]
    cleanup_allowed: bool = False
    needs_deep_reconciliation: bool = False
    successor_task_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "task_id": self.task_id,
            "classification": self.classification,
            "confidence": self.confidence,
            "reason_codes": list(self.reason_codes),
            "cleanup_allowed": self.cleanup_allowed,
            "needs_deep_reconciliation": self.needs_deep_reconciliation,
            "successor_task_id": self.successor_task_id,
        }


@dataclass(frozen=True)
class RetainedSessionReport:
    sessions: tuple[SessionReconciliation, ...]
    counts: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "sessions": [item.as_dict() for item in self.sessions],
            "counts": dict(self.counts),
            "cleanup_performed": False,
        }


def _result(
    *,
    session_id: str,
    task_id: str,
    classification: SessionClassification,
    confidence: Confidence,
    reasons: tuple[str, ...],
    needs_deep: bool = False,
    successor_task_id: str = "",
) -> SessionReconciliation:
    return SessionReconciliation(
        session_id=session_id,
        task_id=task_id,
        classification=classification,
        confidence=confidence,
        reason_codes=reasons,
        cleanup_allowed=False,
        needs_deep_reconciliation=needs_deep,
        successor_task_id=successor_task_id,
    )


def classify_retained_session(
    *,
    session: Mapping[str, object],
    task: Mapping[str, object] | None = None,
    deep_evidence: DeepSessionEvidence | None = None,
) -> SessionReconciliation:
    """Classify one session without authorizing cleanup.

    Evidence precedence is deliberately conservative: live/clean/unavailable
    facts first, then durable integration evidence, then deep patch evidence,
    and finally weak task-state inference.
    """

    row = _mapping(session, name="session")
    session_id = _required_text(row.get("session_id"), name="session_id", maximum=160)
    task_id = _optional_text(row.get("task_id"), name="task_id", maximum=160)
    status = _optional_text(row.get("status"), name="session status", maximum=80)
    dirty = _boolean(row.get("dirty"), name="dirty")
    active = _boolean(row.get("active"), name="active", default=False)
    worktree_available = _boolean(row.get("worktree_available"), name="worktree_available", default=True)

    task_row = _mapping(task, name="task") if task is not None else None
    task_status = ""
    integration_receipt = ""
    task_result = ""
    verification_receipt = ""
    security_audit_receipt = ""
    patch_hash = ""
    if task_row is not None:
        supplied_task_id = _required_text(task_row.get("task_id"), name="task task_id", maximum=160)
        if task_id and supplied_task_id != task_id:
            raise SessionReconciliationError("task_id does not match session task_id")
        if not task_id:
            task_id = supplied_task_id
        task_status = _optional_text(task_row.get("status"), name="task status", maximum=80)
        integration_receipt = _optional_text(
            task_row.get("integration_receipt"), name="integration_receipt", maximum=256
        )
        task_result = _optional_text(task_row.get("result"), name="task result", maximum=160)
        verification_receipt = _optional_text(
            task_row.get("verification_receipt"), name="verification_receipt", maximum=256
        )
        security_audit_receipt = _optional_text(
            task_row.get("security_audit_receipt"), name="security_audit_receipt", maximum=256
        )
        patch_hash = _optional_text(task_row.get("patch_hash"), name="patch_hash", maximum=128)

    deep = deep_evidence or DeepSessionEvidence()
    if not isinstance(deep, DeepSessionEvidence):
        raise SessionReconciliationError("deep_evidence must be DeepSessionEvidence")

    if active or status in _ACTIVE_SESSION_STATES:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="active",
            confidence="high",
            reasons=("SESSION_ACTIVE",),
        )
    if not dirty:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="clean",
            confidence="high",
            reasons=("WORKTREE_CLEAN",),
        )
    if not worktree_available or status in _UNAVAILABLE_SESSION_STATES:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="unavailable",
            confidence="high",
            reasons=("WORKTREE_UNAVAILABLE",),
            needs_deep=True,
        )

    if status in _INTEGRATED_SESSION_STATES:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="already_integrated",
            confidence="high",
            reasons=("SESSION_LIFECYCLE_INTEGRATED",),
        )
    if integration_receipt or task_result == "integrated_to_canonical":
        reasons = ("INTEGRATION_RECEIPT_PRESENT",) if integration_receipt else ("TASK_RESULT_INTEGRATED",)
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="already_integrated",
            confidence="high",
            reasons=reasons,
        )
    if deep.canonical_contains_diff is True:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="already_integrated",
            confidence="high",
            reasons=deep.reason_codes or ("CANONICAL_CONTAINS_DIFF",),
        )
    if deep.successor_contains_diff is True:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="superseded",
            confidence="high",
            reasons=deep.reason_codes or ("SUCCESSOR_CONTAINS_DIFF",),
            successor_task_id=deep.successor_task_id,
        )
    if deep.patch_conflicts is True:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="conflicted",
            confidence="high",
            reasons=deep.reason_codes or ("PATCH_CONFLICT",),
        )

    if task_row is None:
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="recoverable_unmerged",
            confidence="low",
            reasons=("TASK_METADATA_MISSING",) + deep.reason_codes,
            needs_deep=True,
        )
    if task_status in _TERMINAL_UNSUCCESSFUL_TASK_STATES:
        durable_work_evidence = bool(verification_receipt or security_audit_receipt or patch_hash)
        if durable_work_evidence:
            reasons = ["DURABLE_WORK_EVIDENCE_PRESENT", f"TASK_STATUS_{task_status.upper()}"]
            if verification_receipt:
                reasons.append("VERIFICATION_RECEIPT_PRESENT")
            if security_audit_receipt:
                reasons.append("SECURITY_AUDIT_RECEIPT_PRESENT")
            if patch_hash:
                reasons.append("PATCH_HASH_PRESENT")
            reasons.extend(deep.reason_codes)
            return _result(
                session_id=session_id,
                task_id=task_id,
                classification="recoverable_unmerged",
                confidence="medium",
                reasons=tuple(reasons),
                needs_deep=True,
            )
        reasons = ["TASK_TERMINAL_UNSUCCESSFUL", f"TASK_STATUS_{task_status.upper()}"]
        reasons.extend(deep.reason_codes)
        return _result(
            session_id=session_id,
            task_id=task_id,
            classification="orphaned_candidate",
            confidence="low",
            reasons=tuple(reasons),
            needs_deep=True,
        )

    reason = "TASK_SUCCEEDED_NOT_INTEGRATED" if task_status == "succeeded" else "TASK_NOT_TERMINAL_OR_UNCLASSIFIED"
    return _result(
        session_id=session_id,
        task_id=task_id,
        classification="recoverable_unmerged",
        confidence="medium" if task_status else "low",
        reasons=(reason,) + deep.reason_codes,
        needs_deep=True,
    )


def reconcile_retained_sessions(
    *,
    sessions: Sequence[Mapping[str, object]],
    tasks: Sequence[Mapping[str, object]] = (),
    deep_evidence_by_session: Mapping[str, DeepSessionEvidence] | None = None,
) -> RetainedSessionReport:
    """Return a deterministic, non-mutating reconciliation inventory."""

    if not isinstance(sessions, Sequence) or isinstance(sessions, (str, bytes)):
        raise SessionReconciliationError("sessions must be a sequence")
    if not isinstance(tasks, Sequence) or isinstance(tasks, (str, bytes)):
        raise SessionReconciliationError("tasks must be a sequence")
    if len(sessions) > _MAX_RECORDS or len(tasks) > _MAX_RECORDS:
        raise SessionReconciliationError("reconciliation input exceeds bounds")

    task_by_id: dict[str, Mapping[str, object]] = {}
    for raw_task in tasks:
        task = _mapping(raw_task, name="task")
        task_id = _required_text(task.get("task_id"), name="task_id", maximum=160)
        if task_id in task_by_id:
            raise SessionReconciliationError(f"duplicate task_id: {task_id}")
        task_by_id[task_id] = task

    evidence_map = deep_evidence_by_session or {}
    if not isinstance(evidence_map, Mapping):
        raise SessionReconciliationError("deep_evidence_by_session must be a mapping")

    seen_sessions: set[str] = set()
    reconciled: list[SessionReconciliation] = []
    for raw_session in sessions:
        session = _mapping(raw_session, name="session")
        session_id = _required_text(session.get("session_id"), name="session_id", maximum=160)
        if session_id in seen_sessions:
            raise SessionReconciliationError(f"duplicate session_id: {session_id}")
        seen_sessions.add(session_id)
        task_id = _optional_text(session.get("task_id"), name="task_id", maximum=160)
        deep = evidence_map.get(session_id)
        if deep is not None and not isinstance(deep, DeepSessionEvidence):
            raise SessionReconciliationError("deep evidence values must be DeepSessionEvidence")
        reconciled.append(
            classify_retained_session(
                session=session,
                task=task_by_id.get(task_id) if task_id else None,
                deep_evidence=deep,
            )
        )

    ordered = tuple(sorted(reconciled, key=lambda item: item.session_id))
    counts: dict[str, int] = {}
    for item in ordered:
        counts[item.classification] = counts.get(item.classification, 0) + 1
    return RetainedSessionReport(ordered, counts)


__all__ = [
    "DeepSessionEvidence",
    "PatchApplicationProbe",
    "PatchSnapshot",
    "RetainedSessionReport",
    "SessionReconciliation",
    "SessionReconciliationError",
    "SuccessorPatch",
    "build_deep_evidence",
    "classify_retained_session",
    "reconcile_retained_sessions",
]
