"""Deterministic continuation checkpoints and compact state deltas."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Mapping


_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def _unique(values: tuple[str, ...], *, name: str, maximum: int = 512) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > maximum or len(values) != len(set(values)):
        raise ValueError(f"{name} are invalid")
    if any(not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value for value in values):
        raise ValueError(f"{name} are invalid")
    return values


@dataclass(frozen=True, slots=True)
class ContextStateVector:
    workspace_id: str
    head: str
    changed_paths: tuple[str, ...] = ()
    active_task_ids: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    decision_revision: str = ""
    verification_receipt_ids: tuple[str, ...] = ()
    security_audit_receipt_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, str) or not self.workspace_id or len(self.workspace_id) > 160:
            raise ValueError("workspace id is invalid")
        if not isinstance(self.head, str) or not _REVISION_RE.fullmatch(self.head):
            raise ValueError("checkpoint head is invalid")
        _unique(self.changed_paths, name="changed paths")
        _unique(self.active_task_ids, name="active task ids")
        _unique(self.blocker_ids, name="blocker ids")
        _unique(self.verification_receipt_ids, name="verification receipt ids")
        _unique(self.security_audit_receipt_ids, name="security audit receipt ids")
        if not isinstance(self.decision_revision, str) or len(self.decision_revision) > 128 or "\x00" in self.decision_revision:
            raise ValueError("decision revision is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "head": self.head,
            "changed_paths": list(self.changed_paths),
            "active_task_ids": list(self.active_task_ids),
            "blocker_ids": list(self.blocker_ids),
            "decision_revision": self.decision_revision,
            "verification_receipt_ids": list(self.verification_receipt_ids),
            "security_audit_receipt_ids": list(self.security_audit_receipt_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ContextStateVector":
        if not isinstance(value, Mapping):
            raise TypeError("checkpoint state mapping is invalid")
        return cls(
            workspace_id=str(value.get("workspace_id", "")),
            head=str(value.get("head", "")),
            changed_paths=tuple(str(item) for item in value.get("changed_paths", ())),
            active_task_ids=tuple(str(item) for item in value.get("active_task_ids", ())),
            blocker_ids=tuple(str(item) for item in value.get("blocker_ids", ())),
            decision_revision=str(value.get("decision_revision", "")),
            verification_receipt_ids=tuple(str(item) for item in value.get("verification_receipt_ids", ())),
            security_audit_receipt_ids=tuple(str(item) for item in value.get("security_audit_receipt_ids", ())),
        )


@dataclass(frozen=True, slots=True)
class ContextCheckpoint:
    state: ContextStateVector
    task_id: str
    outcome: str
    next_action: str
    checkpoint_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.state, ContextStateVector):
            raise TypeError("checkpoint state is invalid")
        for name, value, maximum in (("task id", self.task_id, 128), ("outcome", self.outcome, 240), ("next action", self.next_action, 1000)):
            if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
                raise ValueError(f"{name} is invalid")
        payload = {"state": self.state.as_dict(), "task_id": self.task_id, "outcome": self.outcome, "next_action": self.next_action}
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        object.__setattr__(self, "checkpoint_id", f"checkpoint:{digest[:32]}")

    def as_dict(self) -> dict[str, object]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "workspace_id": self.state.workspace_id,
            "head": self.state.head,
            "task_id": self.task_id,
            "outcome": self.outcome,
            "next_action": self.next_action,
            "state": self.state.as_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ContextCheckpoint":
        if not isinstance(value, Mapping):
            raise TypeError("checkpoint mapping is invalid")
        raw_state = value.get("state")
        if not isinstance(raw_state, Mapping):
            raise ValueError("checkpoint state is missing")
        checkpoint = cls(
            ContextStateVector.from_dict(raw_state),
            task_id=str(value.get("task_id", "")),
            outcome=str(value.get("outcome", "")),
            next_action=str(value.get("next_action", "")),
        )
        supplied_id = value.get("checkpoint_id")
        if supplied_id is not None and str(supplied_id) != checkpoint.checkpoint_id:
            raise ValueError("checkpoint id does not match checkpoint content")
        if value.get("workspace_id") is not None and str(value.get("workspace_id")) != checkpoint.state.workspace_id:
            raise ValueError("checkpoint workspace does not match state")
        if value.get("head") is not None and str(value.get("head")) != checkpoint.state.head:
            raise ValueError("checkpoint head does not match state")
        return checkpoint


@dataclass(frozen=True, slots=True)
class ContextDelta:
    changed: bool
    head_changed: bool
    changed_paths: tuple[str, ...]
    new_task_ids: tuple[str, ...]
    completed_task_ids: tuple[str, ...]
    new_blocker_ids: tuple[str, ...]
    resolved_blocker_ids: tuple[str, ...]
    decision_revision_changed: bool
    new_verification_receipt_ids: tuple[str, ...]
    new_security_audit_receipt_ids: tuple[str, ...]


def compare_checkpoints(previous: ContextCheckpoint, current: ContextCheckpoint) -> ContextDelta:
    if not isinstance(previous, ContextCheckpoint) or not isinstance(current, ContextCheckpoint):
        raise TypeError("checkpoint comparison requires checkpoints")
    if previous.state.workspace_id != current.state.workspace_id:
        raise ValueError("cannot compare checkpoints from different workspaces")
    prev = previous.state
    now = current.state
    head_changed = prev.head != now.head
    paths_changed = prev.changed_paths != now.changed_paths
    changed_paths = tuple(now.changed_paths) if paths_changed else ()
    new_tasks = tuple(sorted(set(now.active_task_ids) - set(prev.active_task_ids)))
    completed = tuple(sorted(set(prev.active_task_ids) - set(now.active_task_ids)))
    new_blockers = tuple(sorted(set(now.blocker_ids) - set(prev.blocker_ids)))
    resolved_blockers = tuple(sorted(set(prev.blocker_ids) - set(now.blocker_ids)))
    decisions_changed = prev.decision_revision != now.decision_revision
    new_verification = tuple(sorted(set(now.verification_receipt_ids) - set(prev.verification_receipt_ids)))
    new_security = tuple(sorted(set(now.security_audit_receipt_ids) - set(prev.security_audit_receipt_ids)))
    changed = any((head_changed, paths_changed, new_tasks, completed, new_blockers, resolved_blockers, decisions_changed, new_verification, new_security, previous.outcome != current.outcome, previous.next_action != current.next_action))
    return ContextDelta(
        changed=bool(changed),
        head_changed=head_changed,
        changed_paths=changed_paths,
        new_task_ids=new_tasks,
        completed_task_ids=completed,
        new_blocker_ids=new_blockers,
        resolved_blocker_ids=resolved_blockers,
        decision_revision_changed=decisions_changed,
        new_verification_receipt_ids=new_verification,
        new_security_audit_receipt_ids=new_security,
    )


__all__ = ["ContextCheckpoint", "ContextDelta", "ContextStateVector", "compare_checkpoints"]
