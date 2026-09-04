"""Deterministic parallel-work planning without creating chats or executing work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .director import (
    contains_secret_like_content,
    normalize_relative_path,
    normalize_resource_id,
    validate_workspace_id,
)


WorkMode = Literal["read_only", "writer"]


class OrchestrationValidationError(ValueError):
    """Raised when a parallel work plan is ambiguous or conflicting."""


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    workspace_id: str
    title: str
    paths: tuple[str, ...]
    mode: WorkMode = "read_only"
    depends_on: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id or len(self.task_id) > 80 or any(char.isspace() for char in self.task_id):
            raise OrchestrationValidationError("task_id is invalid")
        object.__setattr__(self, "workspace_id", validate_workspace_id(self.workspace_id))
        if (
            not isinstance(self.title, str)
            or not self.title.strip()
            or len(self.title) > 200
            or contains_secret_like_content(self.title)
        ):
            raise OrchestrationValidationError("title is invalid")
        if self.mode not in {"read_only", "writer"}:
            raise OrchestrationValidationError("mode is invalid")
        if len(self.paths) > 128:
            raise OrchestrationValidationError("paths exceed the safety bound")
        normalized_paths = tuple(normalize_relative_path(path) for path in self.paths)
        if len(set(normalized_paths)) != len(normalized_paths):
            raise OrchestrationValidationError("paths must be unique")
        object.__setattr__(self, "paths", normalized_paths)
        if len(self.depends_on) > 64:
            raise OrchestrationValidationError("depends_on exceeds the safety bound")
        if any(not isinstance(dep, str) or not dep or dep == self.task_id for dep in self.depends_on):
            raise OrchestrationValidationError("depends_on is invalid")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise OrchestrationValidationError("depends_on contains duplicates")
        if len(self.resources) > 128:
            raise OrchestrationValidationError("resources exceed the safety bound")
        normalized_resources = tuple(normalize_resource_id(resource) for resource in self.resources)
        if len(set(normalized_resources)) != len(normalized_resources):
            raise OrchestrationValidationError("resources must be unique")
        object.__setattr__(self, "resources", normalized_resources)


@dataclass(frozen=True)
class OrchestrationConflict:
    task_ids: tuple[str, ...]
    paths: tuple[str, ...]
    reason: str
    resources: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "task_ids": list(self.task_ids),
            "paths": list(self.paths),
            "resources": list(self.resources),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OrchestrationPlan:
    workspace_id: str
    tasks: tuple[AgentTask, ...]
    batches: tuple[tuple[str, ...], ...]
    conflicts: tuple[OrchestrationConflict, ...]
    suggested_leases: tuple[dict[str, object], ...]
    shared_paths: tuple[str, ...]
    shared_resources: tuple[str, ...]
    integration_owner: str | None
    max_safe_parallel_writers: int
    external_chat_creation: bool = False

    @property
    def executable(self) -> bool:
        return not self.conflicts

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "title": task.title,
                    "paths": list(task.paths),
                    "mode": task.mode,
                    "depends_on": list(task.depends_on),
                    "resources": list(task.resources),
                }
                for task in self.tasks
            ],
            "batches": [list(batch) for batch in self.batches],
            "conflicts": [conflict.as_dict() for conflict in self.conflicts],
            "suggested_leases": [dict(item) for item in self.suggested_leases],
            "shared_paths": list(self.shared_paths),
            "shared_resources": list(self.shared_resources),
            "integration_owner": self.integration_owner,
            "max_safe_parallel_writers": self.max_safe_parallel_writers,
            "executable": self.executable,
            "external_chat_creation": self.external_chat_creation,
        }


def _find_cycle(tasks: dict[str, AgentTask]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> bool:
        if task_id in visiting:
            return True
        if task_id in visited:
            return False
        visiting.add(task_id)
        for dependency in tasks[task_id].depends_on:
            if dependency in tasks and visit(dependency):
                return True
        visiting.remove(task_id)
        visited.add(task_id)
        return False

    return any(visit(task_id) for task_id in tasks)


def _paths_overlap(first: str, second: str) -> bool:
    left = first.casefold()
    right = second.casefold()
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _depends_transitively(task_id: str, dependency_id: str, tasks: dict[str, AgentTask]) -> bool:
    pending = list(tasks[task_id].depends_on)
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == dependency_id:
            return True
        if current in seen:
            continue
        seen.add(current)
        if current in tasks:
            pending.extend(tasks[current].depends_on)
    return False


def _can_run_concurrently(first: AgentTask, second: AgentTask, tasks: dict[str, AgentTask]) -> bool:
    return not _depends_transitively(first.task_id, second.task_id, tasks) and not _depends_transitively(
        second.task_id, first.task_id, tasks
    )


def _writer_scope_conflicts(first: AgentTask, second: AgentTask) -> bool:
    if first.mode != "writer" or second.mode != "writer":
        return False
    if any(_paths_overlap(left, right) for left in first.paths for right in second.paths):
        return True
    return bool(set(first.resources) & set(second.resources))


def _safe_waves(task_ids: list[str], tasks: dict[str, AgentTask]) -> tuple[tuple[str, ...], ...]:
    """Partition one dependency-ready layer into deterministic safe waves.

    Conflicts remain explicit plan findings: this helper does not invent a
    dependency or make the plan executable.  It only reports how much work
    can safely run at once if a caller later resolves/acknowledges the
    conflicting writers.
    """

    waves: list[list[str]] = []
    for task_id in sorted(task_ids):
        task = tasks[task_id]
        for wave in waves:
            if all(not _writer_scope_conflicts(task, tasks[other_id]) for other_id in wave):
                wave.append(task_id)
                break
        else:
            waves.append([task_id])
    return tuple(tuple(wave) for wave in waves)


def build_orchestration_plan(tasks: tuple[AgentTask, ...] | list[AgentTask]) -> OrchestrationPlan:
    if not isinstance(tasks, (tuple, list)) or not tasks:
        raise OrchestrationValidationError("tasks must be a non-empty list")
    if any(not isinstance(task, AgentTask) for task in tasks):
        raise OrchestrationValidationError("tasks must contain AgentTask values")
    workspace_ids = {task.workspace_id for task in tasks}
    if len(workspace_ids) != 1:
        raise OrchestrationValidationError("a plan must target one workspace")
    task_map = {task.task_id: task for task in tasks}
    if len(task_map) != len(tasks):
        raise OrchestrationValidationError("task_id values must be unique")
    missing_dependencies = {
        dependency
        for task in tasks
        for dependency in task.depends_on
        if dependency not in task_map
    }
    if missing_dependencies:
        raise OrchestrationValidationError("plan contains a missing dependency")
    if _find_cycle(task_map):
        raise OrchestrationValidationError("plan contains a dependency cycle")

    conflicts: list[OrchestrationConflict] = []
    shared_paths: set[str] = set()
    shared_resources: set[str] = set()
    for index, first in enumerate(tasks):
        for second in tasks[index + 1 :]:
            for first_path in first.paths:
                for second_path in second.paths:
                    if _paths_overlap(first_path, second_path):
                        shared_paths.update((first_path, second_path))
            shared_resources.update(set(first.resources) & set(second.resources))
    writers = [task for task in tasks if task.mode == "writer"]
    for index, first in enumerate(writers):
        for second in writers[index + 1 :]:
            if not _can_run_concurrently(first, second, task_map):
                continue
            overlap = tuple(
                sorted(
                    {
                        path
                        for path in first.paths
                        for other_path in second.paths
                        if _paths_overlap(path, other_path)
                    }
                )
            )
            if overlap:
                conflicts.append(OrchestrationConflict((first.task_id, second.task_id), overlap, "MULTIPLE_WRITERS_OVERLAP"))
                continue
            resource_overlap = tuple(sorted(set(first.resources) & set(second.resources)))
            if resource_overlap:
                conflicts.append(
                    OrchestrationConflict(
                        (first.task_id, second.task_id),
                        (),
                        "MULTIPLE_WRITERS_RESOURCE_OVERLAP",
                        resource_overlap,
                    )
                )

    batches: list[tuple[str, ...]] = []
    completed: set[str] = set()
    remaining = set(task_map)
    while remaining:
        ready = [
            task_id
            for task_id in sorted(remaining)
            if set(task_map[task_id].depends_on) <= completed
        ]
        if not ready:
            raise OrchestrationValidationError("plan could not be topologically ordered")
        batches.extend(_safe_waves(ready, task_map))
        completed.update(ready)
        remaining.difference_update(ready)
    batches = [batch for batch in batches if batch]
    suggested_leases = tuple(
        {
            "task_id": task.task_id,
            "workspace_id": task.workspace_id,
            "paths": list(task.paths),
            "resources": list(task.resources),
        }
        for task in tasks
        if task.mode == "writer"
    )
    writer_order = [task_id for batch in batches for task_id in batch if task_map[task_id].mode == "writer"]
    integration_owner = writer_order[-1] if writer_order else None
    max_safe_parallel_writers = max(
        (sum(1 for task_id in batch if task_map[task_id].mode == "writer") for batch in batches),
        default=0,
    )
    return OrchestrationPlan(
        next(iter(workspace_ids)),
        tuple(tasks),
        tuple(batches),
        tuple(conflicts),
        suggested_leases,
        tuple(sorted(shared_paths)),
        tuple(sorted(shared_resources)),
        integration_owner,
        max_safe_parallel_writers,
    )
