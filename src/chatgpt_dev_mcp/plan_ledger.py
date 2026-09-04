from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sqlite3
from typing import Any, Mapping

from .director import contains_secret_like_content
from .persistence import PersistenceCorruptError, PersistenceError, SqliteDirectorStore
from .plan_manifest import (
    PlanManifest,
    PlanManifestValidationError,
    PlanTaskAttempt,
    PlanTaskSpec,
    PlanTaskState,
    plan_manifest_from_mapping,
)


_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
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
_MAX_JSON_BYTES = 128 * 1024


class PlanLedgerError(PersistenceError):
    """A durable plan mutation was invalid and must fail closed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identifier(value: object, *, name: str, allow_empty: bool = False) -> str:
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str) or "\x00" in value or len(value) > 256:
        raise PlanLedgerError(f"{name} is invalid")
    if not value:
        if allow_empty:
            return ""
        raise PlanLedgerError(f"{name} is invalid")
    if not _ID_RE.fullmatch(value):
        raise PlanLedgerError(f"{name} is invalid")
    return value


def _bounded_text(value: object, *, name: str, maximum: int = 400, allow_empty: bool = True) -> str:
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise PlanLedgerError(f"{name} is invalid")
    if not allow_empty and not value:
        raise PlanLedgerError(f"{name} is invalid")
    if contains_secret_like_content(value):
        raise PlanLedgerError(f"{name} contains non-persistable sensitive content")
    return value


def _encode_json(value: object, *, name: str) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise PlanLedgerError(f"{name} is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise PlanLedgerError(f"{name} exceeds its safety bound")
    if contains_secret_like_content(encoded):
        raise PlanLedgerError(f"{name} contains non-persistable sensitive content")
    return encoded


def _decode_json(value: object, *, name: str, expected: type) -> Any:
    if not isinstance(value, str):
        raise PersistenceCorruptError(f"stored {name} JSON is invalid")
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PersistenceCorruptError(f"stored {name} JSON is invalid") from exc
    if not isinstance(decoded, expected):
        raise PersistenceCorruptError(f"stored {name} JSON has an invalid shape")
    return decoded


def _task_values(plan_id: str, task: PlanTaskSpec) -> tuple[object, ...]:
    return (
        plan_id,
        task.plan_task_id,
        task.logical_task_id,
        task.title,
        task.intent_fingerprint,
        _encode_json(list(task.paths), name="task paths"),
        _encode_json(list(task.resources), name="task resources"),
        _encode_json(list(task.dependencies), name="task dependencies"),
        _encode_json(list(task.acceptance_criteria), name="task acceptance criteria"),
        _encode_json(list(task.delivery_requirements), name="task delivery requirements"),
        task.state,
    )


def _manifest_from_rows(header: sqlite3.Row, task_rows: list[sqlite3.Row]) -> PlanManifest:
    tasks: list[dict[str, object]] = []
    stored_by_id: dict[str, sqlite3.Row] = {}
    for row in task_rows:
        plan_task_id = str(row["plan_task_id"])
        stored_by_id[plan_task_id] = row
        paths = _decode_json(row["paths_json"], name="plan task paths", expected=list)
        resources = _decode_json(row["resources_json"], name="plan task resources", expected=list)
        dependencies = _decode_json(row["dependencies_json"], name="plan task dependencies", expected=list)
        acceptance = _decode_json(
            row["acceptance_criteria_json"], name="plan task acceptance criteria", expected=list
        )
        delivery = _decode_json(
            row["delivery_requirements_json"], name="plan task delivery requirements", expected=list
        )
        _decode_json(row["evidence_json"], name="plan task evidence", expected=dict)
        tasks.append(
            {
                "plan_task_id": plan_task_id,
                "title": row["title"],
                "paths": paths,
                "resources": resources,
                "dependencies": dependencies,
                "acceptance_criteria": acceptance,
                "delivery_requirements": delivery,
                "state": row["state"],
            }
        )

    mapping: dict[str, object] = {
        "plan_id": header["plan_id"],
        "revision": header["revision"],
        "workspace_id": header["workspace_id"],
        "title": header["title"],
        "status": header["status"],
        "spec_path": header["spec_path"],
        "spec_hash": header["spec_hash"],
        "plan_path": header["plan_path"],
        "plan_hash": header["plan_hash"],
        "supersedes_plan_ids": _decode_json(
            header["supersedes_plan_ids_json"], name="superseded plan ids", expected=list
        ),
        "created_at": header["created_at"],
        "updated_at": header["updated_at"],
        "tasks": tasks,
    }
    try:
        manifest = plan_manifest_from_mapping(mapping)
    except PlanManifestValidationError as exc:
        raise PersistenceCorruptError("stored plan manifest violates the domain contract") from exc

    for task in manifest.tasks:
        row = stored_by_id.get(task.plan_task_id)
        if row is None:
            raise PersistenceCorruptError("stored plan task identity is incomplete")
        if str(row["logical_task_id"]) != task.logical_task_id:
            raise PersistenceCorruptError("stored logical task identity is inconsistent")
        if str(row["intent_fingerprint"]) != task.intent_fingerprint:
            raise PersistenceCorruptError("stored plan task fingerprint is inconsistent")
    return manifest


class PlanLedger:
    """Stateless transactional facade over the durable Plan Control tables."""

    def __init__(self, store: SqliteDirectorStore) -> None:
        if not isinstance(store, SqliteDirectorStore):
            raise PlanLedgerError("store must be a SqliteDirectorStore")
        self.store = store

    @staticmethod
    def _load_manifest(connection: sqlite3.Connection, plan_id: str) -> PlanManifest | None:
        header = connection.execute("SELECT * FROM plan_manifests WHERE plan_id = ?", (plan_id,)).fetchone()
        if header is None:
            return None
        tasks = connection.execute(
            "SELECT * FROM plan_tasks WHERE plan_id = ? ORDER BY plan_task_id", (plan_id,)
        ).fetchall()
        if not tasks:
            raise PersistenceCorruptError("stored plan has no task rows")
        return _manifest_from_rows(header, list(tasks))

    def activate(self, manifest: PlanManifest, *, expected_revision: int | None) -> PlanManifest:
        if not isinstance(manifest, PlanManifest):
            raise PlanLedgerError("manifest must be a PlanManifest")
        if expected_revision is not None and (
            not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision <= 0
        ):
            raise PlanLedgerError("expected revision is invalid")

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT revision, workspace_id FROM plan_manifests WHERE plan_id = ?", (manifest.plan_id,)
            ).fetchone()
            if existing is None:
                if expected_revision is not None:
                    raise PlanLedgerError("expected revision does not match an unregistered plan")
            else:
                current_revision = int(existing["revision"])
                if expected_revision != current_revision:
                    raise PlanLedgerError("expected revision does not match current plan revision")
                if manifest.revision <= current_revision:
                    raise PlanLedgerError("plan revision must advance monotonically")
                if str(existing["workspace_id"]) != manifest.workspace_id:
                    raise PlanLedgerError("plan workspace cannot change across revisions")
                current_task_ids = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT plan_task_id FROM plan_tasks WHERE plan_id = ?", (manifest.plan_id,)
                    ).fetchall()
                }
                next_task_ids = {task.plan_task_id for task in manifest.tasks}
                if current_task_ids != next_task_ids:
                    raise PlanLedgerError("task set change requires the amendment control path")

            manifest_values = (
                manifest.plan_id,
                manifest.revision,
                manifest.workspace_id,
                manifest.title,
                manifest.status,
                manifest.spec_path,
                manifest.spec_hash,
                manifest.plan_path,
                manifest.plan_hash,
                _encode_json(list(manifest.supersedes_plan_ids), name="superseded plan ids"),
                manifest.created_at,
                manifest.updated_at,
            )
            connection.execute(
                """
                INSERT INTO plan_manifests(
                    plan_id, revision, workspace_id, title, status, spec_path, spec_hash,
                    plan_path, plan_hash, supersedes_plan_ids_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(plan_id) DO UPDATE SET
                    revision=excluded.revision,
                    workspace_id=excluded.workspace_id,
                    title=excluded.title,
                    status=excluded.status,
                    spec_path=excluded.spec_path,
                    spec_hash=excluded.spec_hash,
                    plan_path=excluded.plan_path,
                    plan_hash=excluded.plan_hash,
                    supersedes_plan_ids_json=excluded.supersedes_plan_ids_json,
                    created_at=excluded.created_at,
                    updated_at=excluded.updated_at
                """,
                manifest_values,
            )
            for task in manifest.tasks:
                connection.execute(
                    """
                    INSERT INTO plan_tasks(
                        plan_id, plan_task_id, logical_task_id, title, intent_fingerprint,
                        paths_json, resources_json, dependencies_json, acceptance_criteria_json,
                        delivery_requirements_json, state, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
                    ON CONFLICT(plan_id, plan_task_id) DO UPDATE SET
                        logical_task_id=excluded.logical_task_id,
                        title=excluded.title,
                        intent_fingerprint=excluded.intent_fingerprint,
                        paths_json=excluded.paths_json,
                        resources_json=excluded.resources_json,
                        dependencies_json=excluded.dependencies_json,
                        acceptance_criteria_json=excluded.acceptance_criteria_json,
                        delivery_requirements_json=excluded.delivery_requirements_json,
                        state=excluded.state
                    """,
                    _task_values(manifest.plan_id, task),
                )

        self.store.run_write(write)
        loaded = self.get(manifest.plan_id)
        if loaded is None:
            raise PersistenceCorruptError("activated plan is missing after commit")
        return loaded

    def get(self, plan_id: str) -> PlanManifest | None:
        parsed = _identifier(plan_id, name="plan_id")
        return self.store.run_read(lambda connection: self._load_manifest(connection, parsed))

    def active(self, workspace_id: str) -> tuple[PlanManifest, ...]:
        workspace = _identifier(workspace_id, name="workspace_id")

        def read(connection: sqlite3.Connection) -> tuple[PlanManifest, ...]:
            plan_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT plan_id FROM plan_manifests WHERE workspace_id = ? AND status = 'active' ORDER BY plan_id",
                    (workspace,),
                ).fetchall()
            ]
            manifests: list[PlanManifest] = []
            for plan_id in plan_ids:
                manifest = self._load_manifest(connection, plan_id)
                if manifest is None:
                    raise PersistenceCorruptError("active plan disappeared during read")
                manifests.append(manifest)
            return tuple(manifests)

        return self.store.run_read(read)

    def task(self, plan_id: str, plan_task_id: str) -> PlanTaskSpec | None:
        manifest = self.get(plan_id)
        if manifest is None:
            return None
        parsed_task = _identifier(plan_task_id, name="plan_task_id")
        return next((task for task in manifest.tasks if task.plan_task_id == parsed_task), None)

    def set_task_state(
        self,
        plan_id: str,
        plan_task_id: str,
        state: PlanTaskState,
        *,
        evidence: Mapping[str, str],
    ) -> None:
        parsed_plan = _identifier(plan_id, name="plan_id")
        parsed_task = _identifier(plan_task_id, name="plan_task_id")
        if state not in _TASK_STATES:
            raise PlanLedgerError("task state is invalid")
        if not isinstance(evidence, Mapping) or not evidence:
            raise PlanLedgerError("task state evidence must be a non-empty mapping")
        parsed_evidence: dict[str, str] = {}
        for key, value in evidence.items():
            parsed_key = _identifier(key, name="evidence key")
            parsed_evidence[parsed_key] = _bounded_text(value, name="evidence value", maximum=512, allow_empty=False)
        evidence_json = _encode_json(parsed_evidence, name="task state evidence")

        def write(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT 1 FROM plan_tasks WHERE plan_id = ? AND plan_task_id = ?",
                (parsed_plan, parsed_task),
            ).fetchone()
            if row is None:
                raise PlanLedgerError("plan task does not exist")
            connection.execute(
                "UPDATE plan_tasks SET state = ?, evidence_json = ? WHERE plan_id = ? AND plan_task_id = ?",
                (state, evidence_json, parsed_plan, parsed_task),
            )

        self.store.run_write(write)

    def append_attempt(self, attempt: PlanTaskAttempt) -> None:
        if not isinstance(attempt, PlanTaskAttempt):
            raise PlanLedgerError("attempt must be a PlanTaskAttempt")
        attempt_id = _identifier(attempt.attempt_id, name="attempt_id")
        logical_task_id = _identifier(attempt.logical_task_id, name="logical_task_id")
        values = (
            attempt_id,
            logical_task_id,
            _identifier(attempt.task_id, name="task_id", allow_empty=True),
            _identifier(attempt.owner_id, name="owner_id", allow_empty=True),
            _identifier(attempt.session_id, name="session_id", allow_empty=True),
            _identifier(attempt.working_tree_id, name="working_tree_id", allow_empty=True),
            _bounded_text(attempt.started_at, name="started_at", maximum=80),
            _bounded_text(attempt.finished_at, name="finished_at", maximum=80),
            _bounded_text(attempt.outcome, name="outcome", maximum=128),
            _bounded_text(attempt.failure_fingerprint, name="failure_fingerprint", maximum=256),
        )

        def write(connection: sqlite3.Connection) -> None:
            task_row = connection.execute(
                "SELECT plan_id, plan_task_id FROM plan_tasks WHERE logical_task_id = ?", (logical_task_id,)
            ).fetchone()
            existing = connection.execute(
                "SELECT * FROM plan_task_attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if existing is not None:
                if str(existing["logical_task_id"]) != logical_task_id:
                    raise PlanLedgerError("attempt identity is already bound to a different logical task")
                existing_values = (
                    str(existing["attempt_id"]),
                    str(existing["logical_task_id"]),
                    str(existing["task_id"]),
                    str(existing["owner_id"]),
                    str(existing["session_id"]),
                    str(existing["working_tree_id"]),
                    str(existing["started_at"]),
                    str(existing["finished_at"]),
                    str(existing["outcome"]),
                    str(existing["failure_fingerprint"]),
                )
                if existing_values != values:
                    raise PlanLedgerError("attempt identity is already bound to different attempt content")
                return
            if task_row is None:
                raise PlanLedgerError("logical task does not exist")
            connection.execute(
                """
                INSERT INTO plan_task_attempts(
                    attempt_id, logical_task_id, plan_id, plan_task_id, task_id, owner_id,
                    session_id, working_tree_id, started_at, finished_at, outcome, failure_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    logical_task_id,
                    str(task_row["plan_id"]),
                    str(task_row["plan_task_id"]),
                    *values[2:],
                ),
            )

        self.store.run_write(write)

    def attempts(self, logical_task_id: str) -> tuple[PlanTaskAttempt, ...]:
        parsed = _identifier(logical_task_id, name="logical_task_id")

        def read(connection: sqlite3.Connection) -> tuple[PlanTaskAttempt, ...]:
            rows = connection.execute(
                "SELECT * FROM plan_task_attempts WHERE logical_task_id = ? ORDER BY started_at, attempt_id",
                (parsed,),
            ).fetchall()
            attempts: list[PlanTaskAttempt] = []
            for row in rows:
                if str(row["logical_task_id"]) != parsed:
                    raise PersistenceCorruptError("stored attempt logical task identity is inconsistent")
                attempts.append(
                    PlanTaskAttempt(
                        attempt_id=str(row["attempt_id"]),
                        logical_task_id=str(row["logical_task_id"]),
                        task_id=str(row["task_id"]),
                        owner_id=str(row["owner_id"]),
                        session_id=str(row["session_id"]),
                        working_tree_id=str(row["working_tree_id"]),
                        started_at=str(row["started_at"]),
                        finished_at=str(row["finished_at"]),
                        outcome=str(row["outcome"]),
                        failure_fingerprint=str(row["failure_fingerprint"]),
                    )
                )
            return tuple(attempts)

        return self.store.run_read(read)

    def supersede(self, source_plan_id: str, replacement_plan_id: str, *, task_map: Mapping[str, str]) -> None:
        source = _identifier(source_plan_id, name="source plan_id")
        replacement = _identifier(replacement_plan_id, name="replacement plan_id")
        if source == replacement:
            raise PlanLedgerError("replacement plan must differ from source plan")
        if not isinstance(task_map, Mapping) or not task_map or len(task_map) > 128:
            raise PlanLedgerError("task_map must be a non-empty bounded mapping")
        parsed_map = {
            _identifier(key, name="source plan_task_id"): _identifier(value, name="replacement plan_task_id")
            for key, value in task_map.items()
        }
        if len(parsed_map) != len(task_map):
            raise PlanLedgerError("task_map contains duplicate source task ids")
        encoded_map = _encode_json(parsed_map, name="plan supersession task map")

        def write(connection: sqlite3.Connection) -> None:
            source_row = connection.execute(
                "SELECT 1 FROM plan_manifests WHERE plan_id = ?", (source,)
            ).fetchone()
            if source_row is None:
                raise PlanLedgerError("source plan does not exist")
            replacement_row = connection.execute(
                "SELECT 1 FROM plan_manifests WHERE plan_id = ?", (replacement,)
            ).fetchone()
            if replacement_row is None:
                raise PlanLedgerError("replacement plan does not exist")
            source_tasks = {
                str(row[0])
                for row in connection.execute(
                    "SELECT plan_task_id FROM plan_tasks WHERE plan_id = ?", (source,)
                ).fetchall()
            }
            replacement_tasks = {
                str(row[0])
                for row in connection.execute(
                    "SELECT plan_task_id FROM plan_tasks WHERE plan_id = ?", (replacement,)
                ).fetchall()
            }
            for source_task, replacement_task in parsed_map.items():
                if source_task not in source_tasks:
                    raise PlanLedgerError("source task does not exist")
                if replacement_task not in replacement_tasks:
                    raise PlanLedgerError("replacement task does not exist")

            existing = connection.execute(
                "SELECT task_map_json FROM plan_supersessions WHERE source_plan_id = ? AND replacement_plan_id = ?",
                (source, replacement),
            ).fetchone()
            if existing is not None:
                existing_map = _decode_json(existing["task_map_json"], name="plan supersession task map", expected=dict)
                if existing_map != parsed_map:
                    raise PlanLedgerError("supersession already exists with a different task map")
                return
            connection.execute(
                "INSERT INTO plan_supersessions(source_plan_id, replacement_plan_id, task_map_json, created_at) VALUES (?, ?, ?, ?)",
                (source, replacement, encoded_map, _utc_now()),
            )
            for source_task, replacement_task in parsed_map.items():
                evidence = _encode_json(
                    {
                        "replacement_plan_id": replacement,
                        "replacement_plan_task_id": replacement_task,
                    },
                    name="supersession evidence",
                )
                connection.execute(
                    "UPDATE plan_tasks SET state = 'superseded', evidence_json = ? WHERE plan_id = ? AND plan_task_id = ?",
                    (evidence, source, source_task),
                )
            if set(parsed_map) == source_tasks:
                connection.execute("UPDATE plan_manifests SET status = 'superseded' WHERE plan_id = ?", (source,))

        self.store.run_write(write)


__all__ = ["PlanLedger", "PlanLedgerError"]
