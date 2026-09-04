from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Literal, Mapping, Sequence


PlanStatus = Literal["draft", "active", "superseded", "completed", "cancelled"]
PlanTaskState = Literal[
    "planned",
    "ready",
    "waiting_for_dependency",
    "waiting_for_conflict",
    "running",
    "verifying",
    "review_ready",
    "completed",
    "failed",
    "superseded",
    "cancelled",
    "unknown",
]


_PLAN_STATUSES = frozenset({"draft", "active", "superseded", "completed", "cancelled"})
_TASK_STATES = frozenset(
    {
        "planned",
        "ready",
        "waiting_for_dependency",
        "waiting_for_conflict",
        "running",
        "verifying",
        "review_ready",
        "completed",
        "failed",
        "superseded",
        "cancelled",
        "unknown",
    }
)
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_MAX_TASKS = 256
_MAX_ITEMS = 128
_MAX_TEXT = 400


class PlanManifestValidationError(ValueError):
    """Raised when a plan manifest violates the bounded control-plane contract."""


def _text(value: object, *, name: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise PlanManifestValidationError(f"{name} must be non-empty normalized text")
    if len(value) > maximum or "\x00" in value:
        raise PlanManifestValidationError(f"{name} exceeds its safety bound")
    return value


def _identifier(value: object, *, name: str) -> str:
    text = _text(value, name=name, maximum=128)
    if not _ID_RE.fullmatch(text):
        raise PlanManifestValidationError(f"{name} has an invalid format")
    return text


def _hash(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise PlanManifestValidationError(f"{name} must be a lowercase sha256 digest")
    return value


def _sequence(value: object, *, name: str, allow_empty: bool = True) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_ITEMS:
        raise PlanManifestValidationError(f"{name} must be a bounded sequence")
    if not allow_empty and not value:
        raise PlanManifestValidationError(f"{name} must not be empty")
    return tuple(value)


def _normalized_path(value: object, *, name: str) -> str:
    # Lazy import keeps this pure domain module safe to import from director.py later.
    from .director import ValidationError, normalize_relative_path

    try:
        return normalize_relative_path(value)
    except ValidationError as exc:
        raise PlanManifestValidationError(f"{name} is invalid") from exc


def _normalized_resource(value: object) -> str:
    from .director import ValidationError, normalize_resource_id

    try:
        return normalize_resource_id(value)
    except ValidationError as exc:
        raise PlanManifestValidationError("resources contain an invalid resource") from exc


def _workspace_id(value: object) -> str:
    from .director import ValidationError, validate_workspace_id

    try:
        return validate_workspace_id(value)
    except ValidationError as exc:
        raise PlanManifestValidationError("workspace_id is invalid") from exc


def _bounded_text_tuple(value: object, *, name: str, allow_empty: bool) -> tuple[str, ...]:
    items = _sequence(value, name=name, allow_empty=allow_empty)
    parsed = tuple(_text(item, name=name) for item in items)
    if len(parsed) != len(set(parsed)):
        raise PlanManifestValidationError(f"{name} must be unique")
    return parsed


def _logical_task_id(plan_id: str, plan_task_id: str) -> str:
    digest = hashlib.sha256(f"{plan_id}\0{plan_task_id}".encode("utf-8")).hexdigest()
    return f"logical:{digest[:32]}"


def plan_intent_fingerprint(
    workspace_id: str,
    title: str,
    paths: Sequence[str],
    resources: Sequence[str],
    acceptance_criteria: Sequence[str],
) -> str:
    """Return a deterministic fingerprint for bounded task intent and scope."""

    workspace = _workspace_id(workspace_id)
    normalized_title = " ".join(_text(title, name="title", maximum=240).casefold().split())
    normalized_paths = tuple(sorted({_normalized_path(path, name="path") for path in paths}))
    normalized_resources = tuple(sorted({_normalized_resource(resource) for resource in resources}))
    criteria = tuple(
        sorted({" ".join(_text(item, name="acceptance_criteria").casefold().split()) for item in acceptance_criteria})
    )
    if not criteria:
        raise PlanManifestValidationError("acceptance_criteria must not be empty")
    payload = json.dumps(
        {
            "workspace_id": workspace,
            "title": normalized_title,
            "paths": normalized_paths,
            "resources": normalized_resources,
            "acceptance_criteria": criteria,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PlanTaskSpec:
    plan_task_id: str
    logical_task_id: str
    title: str
    intent_fingerprint: str
    paths: tuple[str, ...]
    resources: tuple[str, ...]
    dependencies: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    delivery_requirements: tuple[str, ...]
    state: PlanTaskState = "planned"


@dataclass(frozen=True)
class PlanTaskAttempt:
    attempt_id: str
    logical_task_id: str
    task_id: str = ""
    owner_id: str = ""
    session_id: str = ""
    working_tree_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    outcome: str = ""
    failure_fingerprint: str = ""


@dataclass(frozen=True)
class PlanManifest:
    plan_id: str
    revision: int
    workspace_id: str
    title: str
    status: PlanStatus
    spec_path: str
    spec_hash: str
    tasks: tuple[PlanTaskSpec, ...]
    plan_path: str = ""
    plan_hash: str = ""
    supersedes_plan_ids: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""


def _parse_task(plan_id: str, workspace_id: str, value: object) -> PlanTaskSpec:
    if not isinstance(value, Mapping):
        raise PlanManifestValidationError("tasks must contain mappings")
    plan_task_id = _identifier(value.get("plan_task_id"), name="plan_task_id")
    title = _text(value.get("title"), name="task title", maximum=240)

    path_values = _sequence(value.get("paths", []), name="paths")
    paths = tuple(_normalized_path(item, name="paths") for item in path_values)
    if len(paths) != len(set(paths)):
        raise PlanManifestValidationError("paths must be unique")

    resource_values = _sequence(value.get("resources", []), name="resources")
    resources = tuple(_normalized_resource(item) for item in resource_values)
    if len(resources) != len(set(resources)):
        raise PlanManifestValidationError("resources must be unique")

    dependency_values = _sequence(value.get("dependencies", []), name="dependencies")
    dependencies = tuple(_identifier(item, name="dependency") for item in dependency_values)
    if len(dependencies) != len(set(dependencies)) or plan_task_id in dependencies:
        raise PlanManifestValidationError("dependencies must be unique and must not reference self")

    acceptance_criteria = _bounded_text_tuple(
        value.get("acceptance_criteria", []), name="acceptance_criteria", allow_empty=False
    )
    delivery_requirements = _bounded_text_tuple(
        value.get("delivery_requirements", []), name="delivery_requirements", allow_empty=False
    )

    raw_state = value.get("state", "planned")
    if raw_state not in _TASK_STATES:
        raise PlanManifestValidationError("state is invalid")

    logical_task_id = _logical_task_id(plan_id, plan_task_id)
    return PlanTaskSpec(
        plan_task_id=plan_task_id,
        logical_task_id=logical_task_id,
        title=title,
        intent_fingerprint=plan_intent_fingerprint(
            workspace_id,
            title,
            paths,
            resources,
            acceptance_criteria,
        ),
        paths=paths,
        resources=resources,
        dependencies=dependencies,
        acceptance_criteria=acceptance_criteria,
        delivery_requirements=delivery_requirements,
        state=raw_state,  # type: ignore[arg-type]
    )


def plan_manifest_from_mapping(value: Mapping[str, object]) -> PlanManifest:
    """Validate a bounded mapping and return an immutable plan manifest."""

    if not isinstance(value, Mapping):
        raise PlanManifestValidationError("manifest must be a mapping")

    plan_id = _identifier(value.get("plan_id"), name="plan_id")
    revision = value.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
        raise PlanManifestValidationError("revision must be a positive integer")
    workspace_id = _workspace_id(value.get("workspace_id"))
    title = _text(value.get("title"), name="title", maximum=240)
    status = value.get("status")
    if status not in _PLAN_STATUSES:
        raise PlanManifestValidationError("status is invalid")

    spec_path = _normalized_path(value.get("spec_path"), name="spec_path")
    spec_hash = _hash(value.get("spec_hash"), name="spec_hash")

    raw_plan_path = value.get("plan_path", "")
    raw_plan_hash = value.get("plan_hash", "")
    if bool(raw_plan_path) != bool(raw_plan_hash):
        raise PlanManifestValidationError("plan_path and plan_hash must be supplied together")
    plan_path = _normalized_path(raw_plan_path, name="plan_path") if raw_plan_path else ""
    plan_hash = _hash(raw_plan_hash, name="plan_hash") if raw_plan_hash else ""

    supersedes_values = _sequence(value.get("supersedes_plan_ids", []), name="supersedes_plan_ids")
    supersedes_plan_ids = tuple(_identifier(item, name="supersedes_plan_id") for item in supersedes_values)
    if len(supersedes_plan_ids) != len(set(supersedes_plan_ids)) or plan_id in supersedes_plan_ids:
        raise PlanManifestValidationError("supersedes_plan_ids must be unique and must not reference self")

    raw_tasks = value.get("tasks")
    if not isinstance(raw_tasks, (list, tuple)) or not raw_tasks or len(raw_tasks) > _MAX_TASKS:
        raise PlanManifestValidationError("tasks must be a non-empty bounded sequence")
    tasks = tuple(_parse_task(plan_id, workspace_id, task) for task in raw_tasks)
    task_ids = tuple(task.plan_task_id for task in tasks)
    if len(task_ids) != len(set(task_ids)):
        raise PlanManifestValidationError("duplicate plan_task_id")
    known_ids = set(task_ids)
    for task in tasks:
        unknown = [dependency for dependency in task.dependencies if dependency not in known_ids]
        if unknown:
            raise PlanManifestValidationError(f"unknown dependency: {unknown[0]}")

    created_at = value.get("created_at", "")
    updated_at = value.get("updated_at", "")
    if created_at:
        created_at = _text(created_at, name="created_at", maximum=80)
    if updated_at:
        updated_at = _text(updated_at, name="updated_at", maximum=80)

    return PlanManifest(
        plan_id=plan_id,
        revision=revision,
        workspace_id=workspace_id,
        title=title,
        status=status,  # type: ignore[arg-type]
        spec_path=spec_path,
        spec_hash=spec_hash,
        tasks=tasks,
        plan_path=plan_path,
        plan_hash=plan_hash,
        supersedes_plan_ids=supersedes_plan_ids,
        created_at=created_at,
        updated_at=updated_at,
    )


__all__ = [
    "PlanManifest",
    "PlanManifestValidationError",
    "PlanStatus",
    "PlanTaskAttempt",
    "PlanTaskSpec",
    "PlanTaskState",
    "plan_intent_fingerprint",
    "plan_manifest_from_mapping",
]
