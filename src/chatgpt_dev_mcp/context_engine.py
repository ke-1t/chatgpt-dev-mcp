"""Pure composition of bounded bootstrap and task-focus context."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .context_checkpoint import ContextCheckpoint, ContextDelta, compare_checkpoints
from .decision_memory import DecisionRecord, DecisionResolution, resolve_active_decisions
from .development_context import DevelopmentContextItem, DevelopmentContextPack
from .project_capsule import CapsuleSection, ContextBudget, ProjectCapsule, RenderedCapsule, render_capsule
from .repo_map import RepoMap, RepoMapEntry


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class InstructionContext:
    status: str
    items: tuple[str, ...] = ()
    source_hash: str = ""

    def __post_init__(self) -> None:
        if self.status not in {"missing", "unavailable", "empty", "loaded", "truncated", "over_budget"}:
            raise ValueError("instruction status is invalid")
        if not isinstance(self.items, tuple) or len(self.items) > 128:
            raise ValueError("instruction items are invalid")
        encoded = 0
        for item in self.items:
            if not isinstance(item, str) or not item or len(item) > 4096 or "\x00" in item:
                raise ValueError("instruction item is invalid")
            encoded += len(item.encode("utf-8"))
        if encoded > 8192:
            raise ValueError("instruction payload is outside bounds")
        if self.source_hash and not _HASH_RE.fullmatch(self.source_hash):
            raise ValueError("instruction source hash is invalid")
        if self.status in {"loaded", "truncated"} and (not self.items or not self.source_hash):
            raise ValueError("loaded instructions require content identity")
        if self.status == "empty" and (self.items or not self.source_hash):
            raise ValueError("empty instructions require only content identity")
        if self.status in {"missing", "unavailable", "over_budget"} and self.items:
            raise ValueError("unavailable instructions cannot contain items")


def build_instruction_context(
    text: str,
    *,
    target_bytes: int = 2048,
    hard_max_bytes: int = 8192,
) -> InstructionContext:
    if not isinstance(text, str) or "\x00" in text:
        raise ValueError("instruction text is invalid")
    if isinstance(target_bytes, bool) or not isinstance(target_bytes, int) or not 256 <= target_bytes <= 8192:
        raise ValueError("instruction target budget is invalid")
    if isinstance(hard_max_bytes, bool) or not isinstance(hard_max_bytes, int) or not target_bytes <= hard_max_bytes <= 8192:
        raise ValueError("instruction hard budget is invalid")
    raw = text.encode("utf-8")
    source_hash = hashlib.sha256(raw).hexdigest()
    if len(raw) > hard_max_bytes:
        return InstructionContext("over_budget", source_hash=source_hash)
    items: list[str] = []
    used = 0
    truncated = False
    for raw_line in text.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        size = len(line.encode("utf-8"))
        if size > 4096 or used + size > target_bytes:
            truncated = True
            break
        items.append(line)
        used += size
        if len(items) >= 128:
            truncated = True
            break
    if not items:
        return InstructionContext("empty", source_hash=source_hash)
    return InstructionContext("truncated" if truncated else "loaded", tuple(items), source_hash)


@dataclass(frozen=True, slots=True)
class BootstrapInputs:
    workspace_id: str
    source_revision: str
    base_sections: tuple[CapsuleSection, ...] = ()
    decisions: tuple[DecisionRecord, ...] = ()
    repo_map: RepoMap | None = None
    checkpoint: ContextCheckpoint | None = None
    instructions: InstructionContext | None = None


@dataclass(frozen=True, slots=True)
class BootstrapContext:
    capsule: RenderedCapsule
    decision_revision: str
    decision_conflict: bool
    conflict_ids: tuple[str, ...]
    delta: ContextDelta | None
    used_bytes: int
    max_bytes: int


@dataclass(frozen=True, slots=True)
class FocusContext:
    query: str
    items: tuple[DevelopmentContextItem, ...]
    decisions: tuple[DecisionRecord, ...]
    repo_entries: tuple[RepoMapEntry, ...]
    decision_conflict: bool
    used_bytes: int
    max_bytes: int
    truncated: bool


def _item_bytes(value: object) -> int:
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class ContextEngine:
    _RESERVED_SECTIONS = frozenset({"instructions", "decisions", "repo_map", "active_work", "continuation", "delta"})

    @staticmethod
    def _decision_items(resolution: DecisionResolution) -> tuple[str, ...]:
        items = tuple(f"{record.scope}: {record.rule}" for record in resolution.active)
        if resolution.conflicted:
            return (f"CONFLICT:{','.join(resolution.conflict_ids)}", *items)
        return items

    def bootstrap(
        self,
        inputs: BootstrapInputs,
        *,
        max_bytes: int = 16384,
        previous_checkpoint: ContextCheckpoint | None = None,
    ) -> BootstrapContext:
        if not isinstance(inputs, BootstrapInputs):
            raise TypeError("bootstrap inputs are invalid")
        base_names = {section.name for section in inputs.base_sections}
        if base_names & self._RESERVED_SECTIONS:
            raise ValueError("bootstrap base section uses a reserved name")
        resolution = resolve_active_decisions(inputs.decisions)
        sections = list(inputs.base_sections)
        if inputs.instructions is not None and inputs.instructions.items:
            sections.append(CapsuleSection("instructions", 98, True, inputs.instructions.items))
        decision_items = self._decision_items(resolution)
        if decision_items:
            sections.append(CapsuleSection("decisions", 100, True, decision_items))
        if inputs.checkpoint is not None:
            if inputs.checkpoint.state.workspace_id != inputs.workspace_id:
                raise ValueError("checkpoint workspace does not match bootstrap workspace")
            sections.append(
                CapsuleSection(
                    "continuation",
                    95,
                    True,
                    (
                        f"task:{inputs.checkpoint.task_id}",
                        f"outcome:{inputs.checkpoint.outcome}",
                        f"next:{inputs.checkpoint.next_action}",
                    ),
                )
            )
            work_items = tuple(
                [*(f"active:{task_id}" for task_id in inputs.checkpoint.state.active_task_ids), *(f"blocker:{blocker}" for blocker in inputs.checkpoint.state.blocker_ids)]
            )
            if work_items:
                sections.append(CapsuleSection("active_work", 85, True, work_items))
        if inputs.repo_map is not None and inputs.repo_map.entries:
            sections.append(
                CapsuleSection(
                    "repo_map",
                    30,
                    False,
                    tuple(
                        f"{entry.path}:{entry.line} {entry.kind} {entry.name} tests={','.join(entry.tests)}"
                        for entry in inputs.repo_map.entries
                    ),
                )
            )
        delta = None
        if previous_checkpoint is not None:
            if inputs.checkpoint is None:
                raise ValueError("current checkpoint is required for delta bootstrap")
            delta = compare_checkpoints(previous_checkpoint, inputs.checkpoint)
            if delta.changed:
                delta_items = []
                if delta.head_changed:
                    delta_items.append("head_changed")
                delta_items.extend(f"completed:{task_id}" for task_id in delta.completed_task_ids)
                delta_items.extend(f"new_blocker:{blocker}" for blocker in delta.new_blocker_ids)
                if delta.decision_revision_changed:
                    delta_items.append("decision_revision_changed")
                if delta_items:
                    sections.append(CapsuleSection("delta", 88, True, tuple(delta_items)))
        capsule = ProjectCapsule(inputs.workspace_id, inputs.source_revision, tuple(sections))
        rendered = render_capsule(capsule, ContextBudget(max_bytes=max_bytes))
        return BootstrapContext(
            capsule=rendered,
            decision_revision=resolution.revision,
            decision_conflict=resolution.conflicted,
            conflict_ids=resolution.conflict_ids,
            delta=delta,
            used_bytes=rendered.used_bytes,
            max_bytes=max_bytes,
        )

    def focus(
        self,
        query: str,
        *,
        context_pack: DevelopmentContextPack,
        decisions: tuple[DecisionRecord, ...] = (),
        repo_map: RepoMap | None = None,
        max_bytes: int = 8192,
    ) -> FocusContext:
        if not isinstance(query, str) or not query.strip() or len(query) > 1000 or "\x00" in query:
            raise ValueError("focus query is invalid")
        if not isinstance(context_pack, DevelopmentContextPack):
            raise TypeError("context_pack is invalid")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 512 <= max_bytes <= 262144:
            raise ValueError("focus budget is invalid")
        resolution = resolve_active_decisions(decisions)
        used = 0
        selected_decisions: list[DecisionRecord] = []
        for record in resolution.active:
            size = _item_bytes(record)
            if used + size > max_bytes:
                break
            selected_decisions.append(record)
            used += size
        selected_items: list[DevelopmentContextItem] = []
        truncated = len(selected_decisions) < len(resolution.active)
        for item in context_pack.items:
            size = _item_bytes(item)
            if used + size > max_bytes:
                truncated = True
                continue
            selected_items.append(item)
            used += size
        selected_repo: list[RepoMapEntry] = []
        if repo_map is not None:
            for entry in repo_map.entries:
                size = _item_bytes(entry)
                if used + size > max_bytes:
                    truncated = True
                    continue
                selected_repo.append(entry)
                used += size
        return FocusContext(
            query=query.strip(),
            items=tuple(selected_items),
            decisions=tuple(selected_decisions),
            repo_entries=tuple(selected_repo),
            decision_conflict=resolution.conflicted,
            used_bytes=used,
            max_bytes=max_bytes,
            truncated=truncated or context_pack.truncated or (repo_map.truncated if repo_map is not None else False),
        )


__all__ = [
    "BootstrapContext",
    "BootstrapInputs",
    "ContextEngine",
    "FocusContext",
    "InstructionContext",
    "build_instruction_context",
]
