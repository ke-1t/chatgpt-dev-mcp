"""Pure, project-wide coordination facts for isolated development sessions.

This module deliberately does not create worktrees, run commands, or mutate a
task ledger.  It turns already-validated task and session metadata into
deterministic conflict, lifecycle, and status facts for the Director layer.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Literal

from .director import (
    contains_secret_like_content,
    normalize_relative_path,
    normalize_resource_id,
    validate_workspace_id,
)
from .integration_queue import is_code_integration_queue_entry


TaskState = Literal[
    "queued", "ready", "leased", "running", "verifying", "review_ready",
    "succeeded", "failed", "cancelled", "blocked", "stale",
]
SessionState = Literal[
    "active", "review_ready", "integrated", "expired_clean",
    "expired_dirty_retained", "stale", "cleanup_candidate",
]

_TERMINAL_TASKS = frozenset({"succeeded", "failed", "cancelled", "blocked", "stale"})
_ACTIVE_SESSION_STATES = frozenset({"active", "review_ready"})


class ParallelControlValidationError(ValueError):
    """Raised for malformed project-level coordination facts."""


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or "\x00" in value:
        raise ParallelControlValidationError(f"{name} is invalid")
    if any(character.isspace() for character in value) or contains_secret_like_content(value):
        raise ParallelControlValidationError(f"{name} is invalid")
    return value


def _revision(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or "\x00" in value:
        raise ParallelControlValidationError(f"{name} is invalid")
    return value


def _paths_overlap(left: str, right: str) -> bool:
    first = left.casefold()
    second = right.casefold()
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _normalize_task_title(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 240 or "\x00" in value:
        raise ParallelControlValidationError("task title is invalid")
    normalized = unicodedata.normalize("NFKC", value).casefold()
    collapsed = "".join(character if character.isalnum() else " " for character in normalized)
    result = " ".join(collapsed.split())
    if not result:
        raise ParallelControlValidationError("task title is invalid")
    return result


def task_intent_fingerprint(
    project_id: str,
    title: str,
    paths: tuple[str, ...] | list[str],
    resources: tuple[str, ...] | list[str],
) -> str:
    """Return a deterministic local fingerprint for one bounded task intent."""

    project = validate_workspace_id(project_id)
    normalized_paths = tuple(sorted(normalize_relative_path(path) for path in paths))
    normalized_resources = tuple(sorted(normalize_resource_id(resource) for resource in resources))
    payload = json.dumps(
        {
            "project_id": project,
            "title": _normalize_task_title(title),
            "paths": normalized_paths,
            "resources": normalized_resources,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def classify_task_intent_duplicate(
    *,
    project_id: str,
    title: str,
    paths: tuple[str, ...] | list[str],
    resources: tuple[str, ...] | list[str],
    existing_project_id: str,
    existing_title: str,
    existing_paths: tuple[str, ...] | list[str],
    existing_resources: tuple[str, ...] | list[str],
) -> Literal["exact", "near"] | None:
    """Classify only high-confidence duplicate intents; ambiguous work remains parallel-safe."""

    project = validate_workspace_id(project_id)
    existing_project = validate_workspace_id(existing_project_id)
    if project != existing_project:
        return None
    current_paths = tuple(normalize_relative_path(path) for path in paths)
    prior_paths = tuple(normalize_relative_path(path) for path in existing_paths)
    current_resources = tuple(normalize_resource_id(resource) for resource in resources)
    prior_resources = tuple(normalize_resource_id(resource) for resource in existing_resources)
    if task_intent_fingerprint(project, title, current_paths, current_resources) == task_intent_fingerprint(
        existing_project,
        existing_title,
        prior_paths,
        prior_resources,
    ):
        return "exact"
    scope_overlap = any(_paths_overlap(left, right) for left in current_paths for right in prior_paths) or bool(
        set(current_resources) & set(prior_resources)
    )
    if not scope_overlap:
        return None
    current_title = _normalize_task_title(title)
    prior_title = _normalize_task_title(existing_title)
    if current_title == prior_title:
        return "near"
    if SequenceMatcher(None, current_title, prior_title, autojunk=False).ratio() >= 0.90:
        return "near"
    return None


@dataclass(frozen=True)
class ProjectTask:
    task_id: str
    project_id: str
    logical_workspace_id: str
    owner_id: str
    development_session_id: str
    worktree_id: str
    source_revision: str
    paths: tuple[str, ...]
    resources: tuple[str, ...]
    requires: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    status: TaskState = "queued"

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _identifier(self.task_id, "task_id"))
        object.__setattr__(self, "project_id", _identifier(self.project_id, "project_id"))
        object.__setattr__(self, "logical_workspace_id", validate_workspace_id(self.logical_workspace_id))
        object.__setattr__(self, "owner_id", _identifier(self.owner_id, "owner_id"))
        object.__setattr__(self, "development_session_id", _identifier(self.development_session_id, "development_session_id"))
        object.__setattr__(self, "worktree_id", _identifier(self.worktree_id, "worktree_id"))
        object.__setattr__(self, "source_revision", _revision(self.source_revision, "source_revision"))
        if self.status not in _TASK_STATES:
            raise ParallelControlValidationError("status is invalid")
        parsed_paths = tuple(normalize_relative_path(path) for path in self.paths)
        parsed_resources = tuple(normalize_resource_id(resource) for resource in self.resources)
        parsed_requires = tuple(_identifier(item, "requirement") for item in self.requires)
        parsed_dependencies = tuple(_identifier(item, "dependency") for item in self.depends_on)
        if len(parsed_paths) != len(set(parsed_paths)) or len(parsed_resources) != len(set(parsed_resources)) or len(parsed_requires) != len(set(parsed_requires)):
            raise ParallelControlValidationError("paths and resources must be unique")
        if len(parsed_dependencies) != len(set(parsed_dependencies)) or self.task_id in parsed_dependencies:
            raise ParallelControlValidationError("dependencies are invalid")
        object.__setattr__(self, "paths", parsed_paths)
        object.__setattr__(self, "resources", parsed_resources)
        object.__setattr__(self, "requires", parsed_requires)
        object.__setattr__(self, "depends_on", parsed_dependencies)


_TASK_STATES = frozenset({
    "queued", "ready", "leased", "running", "verifying", "review_ready",
    "succeeded", "failed", "cancelled", "blocked", "stale",
})


@dataclass(frozen=True)
class ProjectConflict:
    task_ids: tuple[str, str]
    reason: Literal["PROJECT_PATH_OVERLAP", "PROJECT_RESOURCE_OVERLAP"]
    paths: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "task_ids": list(self.task_ids),
            "reason": self.reason,
            "paths": list(self.paths),
            "resources": list(self.resources),
        }


@dataclass(frozen=True)
class ProjectTaskAnalysis:
    project_id: str
    logical_workspace_id: str
    conflicts: tuple[ProjectConflict, ...]
    ready_task_ids: tuple[str, ...]
    waiting_reasons: dict[str, str]
    max_safe_parallel_writers: int

    def as_dict(self) -> dict[str, object]:
        return {
            "project_id": self.project_id,
            "logical_workspace_id": self.logical_workspace_id,
            "conflicts": [item.as_dict() for item in self.conflicts],
            "ready_task_ids": list(self.ready_task_ids),
            "waiting_reasons": dict(self.waiting_reasons),
            "max_safe_parallel_writers": self.max_safe_parallel_writers,
        }


def _has_dependency_path(task_id: str, dependency_id: str, tasks: dict[str, ProjectTask]) -> bool:
    pending = list(tasks[task_id].depends_on)
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == dependency_id:
            return True
        if current in seen:
            continue
        seen.add(current)
        current_task = tasks.get(current)
        if current_task is None:
            continue
        pending.extend(current_task.depends_on)
    return False


def _has_cycle(tasks: dict[str, ProjectTask]) -> bool:
    return any(_has_dependency_path(task_id, task_id, tasks) for task_id in tasks)


def _maximum_safe_writer_count(candidate_ids: tuple[str, ...], conflicts: tuple[ProjectConflict, ...]) -> int:
    """Return a conservative maximum independent-set size for writer tasks.

    Conflict graphs are normally tiny.  Components up to 32 tasks are solved
    exactly; larger components use a deterministic maximal independent set so
    the result can understate capacity but can never overstate writer safety.
    """

    if not candidate_ids:
        return 0
    candidates = set(candidate_ids)
    adjacency: dict[str, set[str]] = {task_id: set() for task_id in candidate_ids}
    for conflict in conflicts:
        left, right = conflict.task_ids
        if left in candidates and right in candidates:
            adjacency[left].add(right)
            adjacency[right].add(left)

    remaining = set(candidate_ids)
    components: list[set[str]] = []
    while remaining:
        seed = min(remaining)
        pending = [seed]
        component: set[str] = set()
        while pending:
            current = pending.pop()
            if current in component:
                continue
            component.add(current)
            pending.extend(adjacency[current] - component)
        remaining -= component
        components.append(component)

    def exact(component: set[str]) -> int:
        best = 0

        def search(vertices: set[str], selected: int) -> None:
            nonlocal best
            if selected + len(vertices) <= best:
                return
            if not vertices:
                best = max(best, selected)
                return
            vertex = max(vertices, key=lambda item: (len(adjacency[item] & vertices), item))
            search(vertices - {vertex} - adjacency[vertex], selected + 1)
            search(vertices - {vertex}, selected)

        search(set(component), 0)
        return best

    def conservative(component: set[str]) -> int:
        vertices = set(component)
        selected = 0
        while vertices:
            vertex = min(vertices, key=lambda item: (len(adjacency[item] & vertices), item))
            selected += 1
            vertices -= {vertex}
            vertices -= adjacency[vertex]
        return selected

    return sum(exact(component) if len(component) <= 32 else conservative(component) for component in components)


def analyze_project_tasks(tasks: tuple[ProjectTask, ...] | list[ProjectTask]) -> ProjectTaskAnalysis:
    """Analyze writer safety across every worktree of one logical project."""

    if not isinstance(tasks, (tuple, list)) or not tasks or any(not isinstance(item, ProjectTask) for item in tasks):
        raise ParallelControlValidationError("tasks must be a non-empty ProjectTask list")
    task_map = {task.task_id: task for task in tasks}
    if len(task_map) != len(tasks):
        raise ParallelControlValidationError("task ids must be unique")
    projects = {(task.project_id, task.logical_workspace_id) for task in tasks}
    if len(projects) != 1:
        raise ParallelControlValidationError("tasks must belong to one logical project")
    if any(
        dependency not in task_map
        for task in tasks
        if task.status not in _TERMINAL_TASKS
        for dependency in task.depends_on
    ):
        raise ParallelControlValidationError("dependencies must reference project tasks")
    if any(
        _has_dependency_path(task.task_id, task.task_id, task_map)
        for task in tasks
        if task.status not in _TERMINAL_TASKS
    ):
        raise ParallelControlValidationError("dependency cycle is invalid")

    conflicts: list[ProjectConflict] = []
    conflict_task_ids: set[str] = set()
    for index, first in enumerate(tasks):
        if first.status in _TERMINAL_TASKS:
            continue
        for second in tasks[index + 1 :]:
            if second.status in _TERMINAL_TASKS:
                continue
            if _has_dependency_path(first.task_id, second.task_id, task_map) or _has_dependency_path(second.task_id, first.task_id, task_map):
                continue
            overlapping_paths = (
                tuple(sorted({left for left in first.paths for right in second.paths if _paths_overlap(left, right)}))
                if first.worktree_id == second.worktree_id
                else ()
            )
            if overlapping_paths:
                conflicts.append(ProjectConflict((first.task_id, second.task_id), "PROJECT_PATH_OVERLAP", overlapping_paths))
                conflict_task_ids.update((first.task_id, second.task_id))
                continue
            overlapping_resources = tuple(sorted(set(first.resources) & set(second.resources)))
            if overlapping_resources:
                conflicts.append(ProjectConflict((first.task_id, second.task_id), "PROJECT_RESOURCE_OVERLAP", (), overlapping_resources))
                conflict_task_ids.update((first.task_id, second.task_id))

    ready: list[str] = []
    waiting: dict[str, str] = {}
    for task in sorted(tasks, key=lambda item: item.task_id):
        if task.status in _TERMINAL_TASKS:
            continue
        if task.task_id in conflict_task_ids:
            waiting[task.task_id] = "PROJECT_CONFLICT"
        elif any(task_map[dependency].status != "succeeded" for dependency in task.depends_on):
            waiting[task.task_id] = "DEPENDENCY_PENDING"
        elif task.status in {"queued", "ready"}:
            ready.append(task.task_id)

    project_id, workspace_id = next(iter(projects))
    capacity_candidates = tuple(
        sorted(
            task.task_id
            for task in tasks
            if task.status in {"queued", "ready", "leased", "running", "verifying"}
            and all(task_map[dependency].status == "succeeded" for dependency in task.depends_on)
        )
    )
    safe_writers = _maximum_safe_writer_count(capacity_candidates, tuple(conflicts))
    return ProjectTaskAnalysis(
        project_id,
        workspace_id,
        tuple(conflicts),
        tuple(ready),
        waiting,
        safe_writers,
    )


def capability_eligible_task_ids(tasks: tuple[ProjectTask, ...] | list[ProjectTask], capabilities: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Return tasks whose declared capability requirements are all satisfied."""

    if not isinstance(tasks, (tuple, list)) or any(not isinstance(item, ProjectTask) for item in tasks):
        raise ParallelControlValidationError("tasks must be ProjectTask values")
    if not isinstance(capabilities, (tuple, list)):
        raise ParallelControlValidationError("capabilities must be a list")
    parsed = tuple(_identifier(item, "capability") for item in capabilities)
    if len(parsed) != len(set(parsed)):
        raise ParallelControlValidationError("capabilities must be unique")
    available = set(parsed)
    return tuple(sorted(task.task_id for task in tasks if set(task.requires) <= available))


@dataclass(frozen=True)
class DevelopmentSessionRecord:
    project_id: str
    logical_workspace_id: str
    worktree_id: str
    development_session_id: str
    source_revision: str
    root_path_hash: str
    owner_id: str
    task_id: str
    state: SessionState
    dirty: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_id", _identifier(self.project_id, "project_id"))
        object.__setattr__(self, "logical_workspace_id", validate_workspace_id(self.logical_workspace_id))
        for name in ("worktree_id", "development_session_id", "root_path_hash", "owner_id", "task_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "source_revision", _revision(self.source_revision, "source_revision"))
        if self.state not in _SESSION_STATES or not isinstance(self.dirty, bool):
            raise ParallelControlValidationError("session state is invalid")


_SESSION_STATES = frozenset({
    "active", "review_ready", "integrated", "expired_clean",
    "expired_dirty_retained", "stale", "cleanup_candidate",
})

_ACTIVE_WRITER_TASK_STATES = frozenset({"leased", "running", "verifying"})

_SESSION_BOUND_NONTERMINAL_TASK_STATES = frozenset({
    "queued", "ready", "leased", "running", "verifying", "review_ready",
})


def orphaned_writer_task_ids(
    tasks: tuple[ProjectTask, ...] | list[ProjectTask],
    session_ids: tuple[str, ...] | list[str] | set[str] | frozenset[str],
) -> tuple[str, ...]:
    """Return active writer tasks whose bound managed session no longer exists."""

    if not isinstance(tasks, (tuple, list)) or any(not isinstance(item, ProjectTask) for item in tasks):
        raise ParallelControlValidationError("tasks must be ProjectTask values")
    if not isinstance(session_ids, (tuple, list, set, frozenset)) or any(
        not isinstance(item, str) or not item for item in session_ids
    ):
        raise ParallelControlValidationError("session_ids must contain identifiers")
    present = set(session_ids)
    return tuple(
        sorted(
            task.task_id
            for task in tasks
            if task.status in _SESSION_BOUND_NONTERMINAL_TASK_STATES
            and task.development_session_id.startswith("session:")
            and task.worktree_id.startswith("session:")
            and task.development_session_id not in present
        )
    )


@dataclass(frozen=True)
class ProjectStatusSummary:
    project_id: str
    logical_workspace_id: str
    baseline_revision: str
    canonical_revision: str
    canonical_dirty: bool
    active_session_ids: tuple[str, ...]
    active_writer_task_ids: tuple[str, ...]
    max_safe_parallel_writers: int
    tasks: ProjectTaskAnalysis
    integration_queue_task_ids: tuple[str, ...]
    cleanup_candidate_session_ids: tuple[str, ...]
    stale_or_replan_task_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "project_id": self.project_id,
            "logical_workspace_id": self.logical_workspace_id,
            "baseline_revision": self.baseline_revision,
            "canonical_revision": self.canonical_revision,
            "canonical_dirty": self.canonical_dirty,
            "active_session_ids": list(self.active_session_ids),
            "active_writer_task_ids": list(self.active_writer_task_ids),
            "max_safe_parallel_writers": self.max_safe_parallel_writers,
            "tasks": self.tasks.as_dict(),
            "integration_queue_task_ids": list(self.integration_queue_task_ids),
            "cleanup_candidate_session_ids": list(self.cleanup_candidate_session_ids),
            "stale_or_replan_task_ids": list(self.stale_or_replan_task_ids),
        }


def summarize_project_status(
    *,
    project_id: str,
    logical_workspace_id: str,
    baseline_revision: str,
    canonical_revision: str,
    canonical_dirty: bool,
    sessions: tuple[DevelopmentSessionRecord, ...] | list[DevelopmentSessionRecord],
    tasks: tuple[ProjectTask, ...] | list[ProjectTask],
) -> ProjectStatusSummary:
    """Return a non-mutating control-plane view without inventing success."""

    parsed_project = _identifier(project_id, "project_id")
    parsed_workspace = validate_workspace_id(logical_workspace_id)
    if not isinstance(canonical_dirty, bool):
        raise ParallelControlValidationError("canonical_dirty must be boolean")
    parsed_tasks = tuple(tasks)
    if any(not isinstance(task, ProjectTask) for task in parsed_tasks):
        raise ParallelControlValidationError("tasks must contain ProjectTask values")
    analysis = (
        analyze_project_tasks(parsed_tasks)
        if parsed_tasks
        else ProjectTaskAnalysis(parsed_project, parsed_workspace, (), (), {}, 0)
    )
    if (analysis.project_id, analysis.logical_workspace_id) != (parsed_project, parsed_workspace):
        raise ParallelControlValidationError("tasks do not match the requested project")
    parsed_sessions = tuple(sessions)
    if any(not isinstance(session, DevelopmentSessionRecord) for session in parsed_sessions):
        raise ParallelControlValidationError("sessions must contain DevelopmentSessionRecord values")
    if any((session.project_id, session.logical_workspace_id) != (parsed_project, parsed_workspace) for session in parsed_sessions):
        raise ParallelControlValidationError("sessions do not match the requested project")

    active_sessions = tuple(sorted(session.development_session_id for session in parsed_sessions if session.state in _ACTIVE_SESSION_STATES))
    cleanup = tuple(
        sorted(
            session.development_session_id
            for session in parsed_sessions
            if session.state in {"integrated", "cleanup_candidate"} and not session.dirty
        )
    )
    orphaned_writers = set(
        orphaned_writer_task_ids(
            parsed_tasks,
            tuple(session.development_session_id for session in parsed_sessions),
        )
    )
    active_writers = tuple(
        sorted(
            task.task_id
            for task in parsed_tasks
            if task.status in _ACTIVE_WRITER_TASK_STATES and task.task_id not in orphaned_writers
        )
    )
    queue = tuple(
        sorted(
            task.task_id
            for task in parsed_tasks
            if is_code_integration_queue_entry(
                status=task.status,
                paths=task.paths,
                resources=task.resources,
            )
        )
    )
    stale_or_replan = tuple(
        sorted(
            {task.task_id for task in parsed_tasks if task.status in {"stale", "blocked"}}
            | orphaned_writers
        )
    )
    return ProjectStatusSummary(
        parsed_project,
        parsed_workspace,
        _revision(baseline_revision, "baseline_revision"),
        _revision(canonical_revision, "canonical_revision"),
        canonical_dirty,
        active_sessions,
        active_writers,
        analysis.max_safe_parallel_writers,
        analysis,
        queue,
        cleanup,
        stale_or_replan,
    )
