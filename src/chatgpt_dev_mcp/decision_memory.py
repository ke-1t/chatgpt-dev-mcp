"""Structured, explicit and conflict-aware project decision memory."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_STATUSES = frozenset({"active", "superseded", "retired"})


def _text(value: str, *, name: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    decision_id: str
    workspace_id: str
    scope: str
    status: str
    rule: str
    rationale: str
    source_revision: str
    evidence_refs: tuple[str, ...] = ()
    superseded_by: str = ""

    def __post_init__(self) -> None:
        _text(self.decision_id, name="decision id", maximum=128)
        _text(self.workspace_id, name="workspace id", maximum=160)
        _text(self.scope, name="decision scope", maximum=160)
        if self.status not in _STATUSES:
            raise ValueError("decision status is invalid")
        _text(self.rule, name="decision rule", maximum=1000)
        _text(self.rationale, name="decision rationale", maximum=2000)
        if not isinstance(self.source_revision, str) or not _REVISION_RE.fullmatch(self.source_revision):
            raise ValueError("decision source revision is invalid")
        if not isinstance(self.evidence_refs, tuple) or len(self.evidence_refs) > 64 or len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("decision evidence references are invalid")
        for value in self.evidence_refs:
            _text(value, name="evidence reference", maximum=256)
        _text(self.superseded_by, name="superseding decision id", maximum=128, allow_empty=True)
        if self.status == "superseded" and not self.superseded_by:
            raise ValueError("superseded decision requires superseded_by")
        if self.status != "superseded" and self.superseded_by:
            raise ValueError("only superseded decisions may reference a successor")

    def as_dict(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "workspace_id": self.workspace_id,
            "scope": self.scope,
            "status": self.status,
            "rule": self.rule,
            "rationale": self.rationale,
            "source_revision": self.source_revision,
            "evidence_refs": list(self.evidence_refs),
            "superseded_by": self.superseded_by,
        }


@dataclass(frozen=True, slots=True)
class DecisionResolution:
    active: tuple[DecisionRecord, ...]
    conflicted: bool
    conflict_ids: tuple[str, ...]
    revision: str


def resolve_active_decisions(records: tuple[DecisionRecord, ...]) -> DecisionResolution:
    if not isinstance(records, tuple) or len(records) > 1024:
        raise ValueError("decision records are invalid")
    ids = tuple(record.decision_id for record in records)
    if len(ids) != len(set(ids)):
        raise ValueError("decision ids must be unique")
    by_id = {record.decision_id: record for record in records}
    workspaces = {record.workspace_id for record in records}
    if len(workspaces) > 1:
        raise ValueError("decision records must belong to one workspace")

    for record in records:
        if record.status == "superseded" and record.superseded_by not in by_id:
            raise ValueError("superseding decision does not exist")

    for record in records:
        seen: set[str] = set()
        current = record
        while current.status == "superseded":
            if current.decision_id in seen:
                raise ValueError("decision supersession cycle detected")
            seen.add(current.decision_id)
            current = by_id[current.superseded_by]

    active = tuple(sorted((record for record in records if record.status == "active"), key=lambda item: (item.scope, item.decision_id)))
    conflict_ids: set[str] = set()
    scopes: dict[str, list[DecisionRecord]] = {}
    for record in active:
        scopes.setdefault(record.scope, []).append(record)
    for scoped in scopes.values():
        if len({record.rule for record in scoped}) > 1:
            conflict_ids.update(record.decision_id for record in scoped)

    payload = [record.as_dict() for record in sorted(records, key=lambda item: item.decision_id)]
    revision = hashlib.sha256(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    return DecisionResolution(active=active, conflicted=bool(conflict_ids), conflict_ids=tuple(sorted(conflict_ids)), revision=revision)


__all__ = ["DecisionRecord", "DecisionResolution", "resolve_active_decisions"]
