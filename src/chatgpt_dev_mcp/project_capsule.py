"""Bounded deterministic project-capsule models for model-facing context."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Mapping


_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def _bounded_text(value: str, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


def _json_bytes(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class CapsuleSection:
    name: str
    priority: int
    required: bool
    items: tuple[str, ...]

    def __post_init__(self) -> None:
        _bounded_text(self.name, name="section name", maximum=80)
        if isinstance(self.priority, bool) or not isinstance(self.priority, int) or not 0 <= self.priority <= 100:
            raise ValueError("section priority is invalid")
        if not isinstance(self.required, bool):
            raise ValueError("section required flag is invalid")
        if not isinstance(self.items, tuple) or len(self.items) > 512:
            raise ValueError("section items are invalid")
        for item in self.items:
            _bounded_text(item, name="section item", maximum=4096)

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "priority": self.priority, "required": self.required, "items": list(self.items)}


@dataclass(frozen=True, slots=True)
class ContextBudget:
    max_bytes: int = 16384

    def __post_init__(self) -> None:
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int) or not 512 <= self.max_bytes <= 262144:
            raise ValueError("context budget is outside bounds")


@dataclass(frozen=True, slots=True)
class ProjectCapsule:
    workspace_id: str
    source_revision: str
    sections: tuple[CapsuleSection, ...]
    capsule_id: str = field(init=False)

    def __post_init__(self) -> None:
        _bounded_text(self.workspace_id, name="workspace id", maximum=160)
        if not isinstance(self.source_revision, str) or not _REVISION_RE.fullmatch(self.source_revision):
            raise ValueError("source revision is invalid")
        if not isinstance(self.sections, tuple) or len(self.sections) > 128:
            raise ValueError("capsule sections are invalid")
        names = tuple(section.name for section in self.sections)
        if len(names) != len(set(names)):
            raise ValueError("capsule section names must be unique")
        payload = {
            "workspace_id": self.workspace_id,
            "source_revision": self.source_revision,
            "sections": [section.as_dict() for section in self.sections],
        }
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        object.__setattr__(self, "capsule_id", f"capsule:{digest[:32]}")


@dataclass(frozen=True, slots=True)
class RenderedCapsule:
    capsule_id: str
    workspace_id: str
    source_revision: str
    sections: Mapping[str, tuple[str, ...]]
    used_bytes: int
    max_bytes: int
    omitted_count: int
    required_over_budget: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "capsule_id": self.capsule_id,
            "workspace_id": self.workspace_id,
            "source_revision": self.source_revision,
            "sections": {name: list(items) for name, items in self.sections.items()},
            "used_bytes": self.used_bytes,
            "max_bytes": self.max_bytes,
            "omitted_count": self.omitted_count,
            "required_over_budget": self.required_over_budget,
        }


def render_capsule(capsule: ProjectCapsule, budget: ContextBudget) -> RenderedCapsule:
    if not isinstance(capsule, ProjectCapsule) or not isinstance(budget, ContextBudget):
        raise TypeError("capsule and budget have invalid types")
    ordered = tuple(sorted(capsule.sections, key=lambda item: (-item.priority, item.name)))
    selected: dict[str, tuple[str, ...]] = {}
    omitted = 0

    for section in ordered:
        if not section.required:
            continue
        selected[section.name] = section.items

    required_size = _json_bytes(selected)
    required_over_budget = required_size > budget.max_bytes

    for section in ordered:
        if section.required:
            continue
        accepted: list[str] = []
        for item in section.items:
            candidate = dict(selected)
            candidate[section.name] = tuple((*accepted, item))
            if _json_bytes(candidate) <= budget.max_bytes:
                accepted.append(item)
            else:
                omitted += 1
        if accepted:
            selected[section.name] = tuple(accepted)
        omitted += len(section.items) - len(accepted) - sum(
            1 for item in section.items if item not in accepted and _json_bytes({**selected, section.name: tuple((*accepted, item))}) > budget.max_bytes
        )

    # The loop above counts each rejected item once; normalize defensively from
    # the actual selected cardinality to avoid accounting drift if logic evolves.
    omitted = sum(len(section.items) for section in ordered) - sum(len(items) for items in selected.values())
    used = _json_bytes(selected)
    return RenderedCapsule(
        capsule_id=capsule.capsule_id,
        workspace_id=capsule.workspace_id,
        source_revision=capsule.source_revision,
        sections=dict(selected),
        used_bytes=used,
        max_bytes=budget.max_bytes,
        omitted_count=omitted,
        required_over_budget=required_over_budget,
    )


__all__ = ["CapsuleSection", "ContextBudget", "ProjectCapsule", "RenderedCapsule", "render_capsule"]
