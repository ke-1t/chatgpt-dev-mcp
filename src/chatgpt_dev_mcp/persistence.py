"""Crash-safe, non-secret SQLite persistence for Director state.

The store is deliberately an internal adapter.  It records bounded state and
evidence; it never stores approval tokens, credentials, raw patches, or command
output and it never replays a side effect after a restart.
"""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .director import contains_secret_like_content


CURRENT_SCHEMA_VERSION = 14
DEFAULT_DB_FILENAME = "director.sqlite3"
DEFAULT_DATA_DIR = Path.home() / ".cache" / "local-dev-mcp"
DATA_DIR_ENV = "LOCAL_DEV_MCP_DATA_DIR"
MAX_JSON_BYTES = 128 * 1024
MAX_TEXT_BYTES = 4096
MAX_RECONCILIATION_SIDECAR_BYTES = 128 * 1024
AUTO_MAINTENANCE_WRITE_INTERVAL = 64
INCREMENTAL_VACUUM_PAGES = 64
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_STATES = frozenset(
    {
        "queued",
        "ready",
        "leased",
        "running",
        "verifying",
        "review_ready",
        "succeeded",
        "failed",
        "cancelled",
        "blocked",
        "stale",
        "recovery",
    }
)
_LEASE_STATES = frozenset({"active", "released", "expired", "stale"})
_TERMINAL_LEASE_STATES = frozenset({"released", "expired", "stale"})
_TASK_PROCESS_BINDING_STATES = frozenset({"active", "terminal", "stale"})
_TASK_PROCESS_BINDING_FIELDS = frozenset(
    {
        "process_session_id",
        "workspace_id",
        "working_tree_id",
        "development_session_id",
        "runtime_capability_epoch",
        "upstream_runtime_id",
        "created_at",
        "expires_at",
        "state",
    }
)
_GIT_AUTHORITY_STATES = frozenset(
    {
        "ready",
        "blocked",
        "selection_required",
        "executing",
        "succeeded",
        "failed",
        "unknown",
        "outcome_unknown",
        "expired",
        "invalidated",
    }
)
_GIT_OUTCOME_STATES = frozenset({"succeeded", "failed", "outcome_unknown"})
_FORBIDDEN_TEXT = ("diff --git", "*** begin patch", "approval_token", "access_token")
_READONLY_ROOT_STATES = frozenset({"active", "closed", "expired", "stale"})
_READONLY_ROOT_MAX_ACTIVE = 64
_READONLY_ROOT_MAX_HISTORY = 128
_READONLY_ROOT_SCHEMA_MISSING = "missing"
_READONLY_ROOT_SCHEMA_NATIVE = "native"
_READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET = "legacy_scoped_superset"
_READONLY_ROOT_SCOPE_NAMESPACE = "chatgpt-dev-mcp:v26-readonly-root:v1"
_OPERATOR_RECEIPT_METADATA_FIELDS = frozenset(
    {
        "record_type",
        "operator_contract",
        "action",
        "actor",
        "workspace_id",
        "target_id",
        "canonical_path",
        "canonical_revision",
        "director_generation",
        "director_database_identity",
        "schema_version",
        "expected_state_hash",
        "request_hash",
        "request_id",
        "preflight_allowed",
        "eligibility",
        "created_at",
        "source_revision",
        "candidate_id",
        "artifact_role",
        "database_identity",
        "tool_schema_hash",
        "candidate_head",
        "content_digest",
        "artifact_tree_digest",
        "artifact_patch_hash",
        "manifest_digest",
        "python_digest",
        "verification_receipt_id",
        "verification_mode",
        "verification_status",
        "verification_result_digest",
        "verification_test_count",
        "preflight_id",
        "status",
        "reason",
        "result_digest",
        "readback_digest",
        "resulting_state_hash",
    }
)
_READONLY_ROOT_BASE_COLUMNS = (
    ("root_id", "TEXT", 0, None, 1),
    ("requested_path", "TEXT", 1, None, 0),
    ("canonical_path", "TEXT", 1, None, 0),
    ("device", "INTEGER", 1, None, 0),
    ("inode", "INTEGER", 1, None, 0),
    ("created_at", "REAL", 1, None, 0),
    ("last_accessed_at", "REAL", 1, None, 0),
    ("expires_at", "REAL", 1, None, 0),
    ("state", "TEXT", 1, None, 0),
    ("updated_at", "REAL", 1, None, 0),
)
_READONLY_ROOT_NATIVE_COLUMNS = (
    _READONLY_ROOT_BASE_COLUMNS[:8]
    + (("label", "TEXT", 1, "''", 0),)
    + _READONLY_ROOT_BASE_COLUMNS[8:]
)
_READONLY_ROOT_LEGACY_SCOPED_COLUMNS = (
    _READONLY_ROOT_BASE_COLUMNS[:8]
    + (("label", "TEXT", 0, None, 0),)
    + _READONLY_ROOT_BASE_COLUMNS[8:9]
    + (
        ("scope_id", "TEXT", 1, None, 0),
        ("workspace_id", "TEXT", 1, "''", 0),
        ("session_id", "TEXT", 1, "''", 0),
        ("owner_id", "TEXT", 1, "''", 0),
    )
    + _READONLY_ROOT_BASE_COLUMNS[9:]
)

# Tables that may be carried by the bounded generation-import contract.  The
# allowlist is deliberately finite: callers can never turn the import API
# into an arbitrary SQL table/column writer.
_EVIDENCE_IMPORT_TABLES = (
    "task_ledger",
    "development_sessions",
    "writer_leases",
    "verification_receipts",
    "security_audit_receipts",
    "integration_receipts",
    "git_closeout_receipts",
    "approval_decisions",
    "session_reconciliation_receipts",
    "session_archives",
    "session_archive_restores",
    "development_loops",
    "development_loop_events",
)
_EVIDENCE_IMPORT_PRIMARY_KEYS = {
    "task_ledger": "task_id",
    "development_sessions": "session_id",
    "writer_leases": "lease_id",
    "verification_receipts": "receipt_id",
    "security_audit_receipts": "receipt_id",
    "integration_receipts": "receipt_id",
    "git_closeout_receipts": "receipt_id",
    "approval_decisions": "decision_id",
    "session_reconciliation_receipts": "reconciliation_id",
    "session_archives": "archive_id",
    "session_archive_restores": "restore_id",
    "development_loops": "loop_id",
    "development_loop_events": ("loop_id", "event_id"),
}


class PersistenceError(RuntimeError):
    """A persistence operation failed and callers must fail closed."""


class PersistenceCorruptError(PersistenceError):
    """The database cannot be trusted or its schema is unknown."""


class IdempotencyConflict(PersistenceError):
    """A request id was reused with a different immutable payload."""


class ReadOnlyRootCapacityError(PersistenceError):
    """The bounded durable READ_ONLY root registry has no active capacity."""


class ReadOnlyRootConflictError(PersistenceError):
    """A durable READ_ONLY root identity already exists."""


class ReadOnlyRootScopeConflictError(PersistenceCorruptError):
    """A target-owned scoped row contains another authority binding."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def director_db_path() -> Path:
    """Return the only runtime-selected database path.

    The path is not exposed as an MCP argument.  Tests may instantiate the
    store with a disposable explicit path, while the runtime uses this helper.
    """

    raw = os.environ.get(DATA_DIR_ENV)
    # Resolve the default from the active HOME at call time.  This preserves
    # the managed runtime contract while allowing isolated test/fixture homes
    # to remain isolated across WrapperRuntime restarts.
    directory = Path(raw).expanduser() if raw else (Path.home() / ".cache" / "local-dev-mcp")
    return directory / DEFAULT_DB_FILENAME


def _mapping(value: object, *, name: str) -> Mapping[str, Any]:
    if hasattr(value, "as_dict") and callable(value.as_dict):
        value = value.as_dict()
    if not isinstance(value, Mapping):
        raise PersistenceError(f"{name} must be a mapping")
    return value


def _text(value: object, *, name: str, maximum: int = MAX_TEXT_BYTES, allow_empty: bool = True) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise PersistenceError(f"{name} is outside its safety bound")
    if not allow_empty and not value.strip():
        raise PersistenceError(f"{name} must not be empty")
    lowered = value.lower()
    if contains_secret_like_content(value) or any(marker in lowered for marker in _FORBIDDEN_TEXT):
        raise PersistenceError(f"{name} contains non-persistable sensitive content")
    return value


def _identifier(value: object, *, name: str, maximum: int = 256) -> str:
    text = _text(value, name=name, maximum=maximum, allow_empty=False)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", text):
        raise PersistenceError(f"{name} has an invalid format")
    return text


def _process_session_identifier(value: object, *, name: str = "process_session_id") -> str:
    """Validate an upstream URL-safe process token without changing IDs."""

    text = _text(value, name=name, maximum=256, allow_empty=False)
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,256}", text):
        raise PersistenceError(f"{name} has an invalid format")
    return text


def _optional_task_id(value: object) -> str | None:
    """Normalize an optional task binding without breaking v1 rows."""

    text = _text(value, name="task_id", maximum=256)
    # v1 stored unbound task ids as empty text. Normalize that legacy sentinel
    # to SQL NULL so child receipt rows can safely reference the task ledger
    # with ON DELETE SET NULL.
    return _identifier(text, name="task_id") if text else None


def _hash(value: object, *, name: str, allow_empty: bool = True) -> str:
    text = _text(value, name=name, maximum=128, allow_empty=allow_empty)
    if text and not _HASH_RE.fullmatch(text):
        raise PersistenceError(f"{name} must be sha256 hex")
    return text


def _json(
    value: object,
    *,
    name: str,
    default: object,
    reject_forbidden_text: bool = False,
) -> str:
    candidate = default if value is None else value
    try:
        encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise PersistenceError(f"{name} is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise PersistenceError(f"{name} exceeds its safety bound")
    if contains_secret_like_content(encoded) or (
        reject_forbidden_text and any(marker in encoded.lower() for marker in _FORBIDDEN_TEXT)
    ):
        raise PersistenceError(f"{name} contains secret-like content")
    return encoded


def _decode(value: str, *, name: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PersistenceCorruptError(f"stored {name} JSON is invalid") from exc


def _paths(value: object, *, name: str) -> str:
    values = [] if value is None else value
    if not isinstance(values, (list, tuple)):
        raise PersistenceError(f"{name} must be a list")
    parsed: list[str] = []
    for item in values:
        text = _text(item, name=name, maximum=512, allow_empty=False)
        if text.startswith(('/', '~')) or "\\" in text or any(part in {"", ".", ".."} for part in text.split('/')):
            raise PersistenceError(f"{name} contains an unsafe path")
        parsed.append(text)
    if len(parsed) != len(set(parsed)):
        raise PersistenceError(f"{name} contains duplicates")
    return _json(sorted(parsed), name=name, default=[])


def _finite_number(value: object, *, name: str, default: float | None = None) -> float:
    candidate = default if value is None and default is not None else value
    try:
        number = float(candidate)
    except (TypeError, ValueError) as exc:
        raise PersistenceError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise PersistenceError(f"{name} must be a finite number")
    return number


def _readonly_root_path(value: object, *, name: str) -> str:
    text = _text(value, name=name, maximum=4096, allow_empty=False)
    if not os.path.isabs(text):
        raise PersistenceError(f"{name} must be absolute")
    return text


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _readonly_root_scope_id(path: Path) -> str:
    """Derive the versioned, non-authorizing scope for one accepted database.

    ``SqliteDirectorStore._secure_path`` is the security gate for database
    paths.  After that gate, scope identity uses an absolute, ``expanduser``
    expanded, non-strict real path so ``/tmp`` and ``/private/tmp`` aliases on
    macOS identify the same database.  It is still lexical with respect to
    case: no case folding is performed because filesystem case sensitivity is
    platform-specific.  Application-created symlink parents and final-file
    symlinks are rejected by ``_secure_path``; ``resolve(strict=False)`` only
    canonicalizes already-accepted platform aliases and existing path
    components.  The NUL-delimited namespace version prevents adoption of a
    scope generated by another runtime generation.
    """

    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise PersistenceError("database path must be absolute")
    normalized = str(candidate.resolve(strict=False))
    material = _READONLY_ROOT_SCOPE_NAMESPACE.encode("utf-8") + b"\0" + normalized.encode("utf-8")
    return "runtime:" + hashlib.sha256(material).hexdigest()[:32]


def _assert_readonly_root_scope_clean(connection: sqlite3.Connection, path: Path) -> None:
    """Reject target-scope rows that carry workspace/session/owner authority."""

    scope_id = _readonly_root_scope_id(path)
    row = connection.execute(
        "SELECT 1 FROM readonly_roots "
        "WHERE scope_id = ? AND (COALESCE(workspace_id, '') <> '' "
        "OR COALESCE(session_id, '') <> '' OR COALESCE(owner_id, '') <> '') "
        "LIMIT 1",
        (scope_id,),
    ).fetchone()
    if row is not None:
        raise ReadOnlyRootScopeConflictError("READONLY_ROOT_SCOPE_CONFLICT")


def inspect_readonly_roots_schema(
    connection: sqlite3.Connection,
    *,
    allow_missing: bool = True,
    require_indexes: bool = True,
    scope_path: Path | str | None = None,
) -> str:
    """Return the one accepted READ_ONLY root schema, or fail closed.

    v26 accepts the native 11-column table and one explicitly recognized
    15-column table from another runtime generation.  The latter is treated
    as a legacy scoped superset: rows are usable only when their scope is the
    target-owned namespace and all authority binding columns are empty.  A
    target-scoped row with any binding is an integrity conflict; a foreign
    scope is preserved and ignored.  Accepting arbitrary additive columns
    would make an unknown table migration part of the authority boundary and
    could change the meaning of root updates or deletes.
    """

    try:
        table = connection.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = 'readonly_roots'"
        ).fetchone()
        if table is None:
            if allow_missing:
                return _READONLY_ROOT_SCHEMA_MISSING
            raise PersistenceCorruptError("readonly_roots table is missing")
        if str(table[0]).lower() != "table" or not isinstance(table[1], str):
            raise PersistenceCorruptError("readonly_roots is not a regular table")

        table_sql = " ".join(table[1].upper().split())
        forbidden_markers = (
            "CHECK",
            "COLLATE",
            "CONSTRAINT",
            "FOREIGN KEY",
            "GENERATED",
            "ON CONFLICT",
            "REFERENCES",
            "STRICT",
            "UNIQUE",
            "WITHOUT ROWID",
        )
        if any(marker in table_sql for marker in forbidden_markers):
            raise PersistenceCorruptError("readonly_roots contains unsupported constraints")

        column_rows = connection.execute(
            f"PRAGMA table_info({_quote_sqlite_identifier('readonly_roots')})"
        ).fetchall()
        columns = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]).strip(),
                int(row[5]),
            )
            for row in column_rows
        )
        expected_columns = {
            _READONLY_ROOT_SCHEMA_NATIVE: _READONLY_ROOT_NATIVE_COLUMNS,
            _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET: _READONLY_ROOT_LEGACY_SCOPED_COLUMNS,
        }
        schema_name = next(
            (name for name, expected in expected_columns.items() if columns == expected),
            None,
        )
        if schema_name is None:
            raise PersistenceCorruptError("readonly_roots columns are incompatible")

        # table_info intentionally omits generated/hidden columns.  Reject
        # them explicitly so an apparently known prefix cannot hide an
        # additional value with write-time semantics.
        xinfo_rows = connection.execute(
            f"PRAGMA table_xinfo({_quote_sqlite_identifier('readonly_roots')})"
        ).fetchall()
        if len(xinfo_rows) != len(columns) or any(len(row) >= 7 and int(row[6]) != 0 for row in xinfo_rows):
            raise PersistenceCorruptError("readonly_roots contains hidden columns")

        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'readonly_roots' LIMIT 1"
        ).fetchone() is not None:
            raise PersistenceCorruptError("readonly_roots has unsupported triggers")
        if connection.execute(
            f"PRAGMA foreign_key_list({_quote_sqlite_identifier('readonly_roots')})"
        ).fetchone() is not None:
            raise PersistenceCorruptError("readonly_roots has unsupported foreign keys")

        expected_indexes = {
            _READONLY_ROOT_SCHEMA_NATIVE: {
                ("state", "expires_at"),
                ("updated_at", "root_id"),
            },
            _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET: {
                ("scope_id", "state", "expires_at"),
                ("state", "expires_at", "updated_at"),
            },
        }[schema_name]
        actual_indexes: set[tuple[str, ...]] = set()
        index_rows = connection.execute(
            f"PRAGMA index_list({_quote_sqlite_identifier('readonly_roots')})"
        ).fetchall()
        for index_row in index_rows:
            index_name = str(index_row[1])
            unique = bool(int(index_row[2]))
            origin = str(index_row[3]).lower() if len(index_row) > 3 else ""
            is_primary_key_index = origin == "pk" or index_name.startswith("sqlite_autoindex_readonly_roots_")
            if unique and not is_primary_key_index:
                raise PersistenceCorruptError("readonly_roots has an unsupported unique index")
            if is_primary_key_index:
                continue
            info_rows = connection.execute(
                f"PRAGMA index_info({_quote_sqlite_identifier(index_name)})"
            ).fetchall()
            index_columns = tuple(str(row[2]) for row in info_rows)
            if any(row[2] is None for row in info_rows):
                raise PersistenceCorruptError("readonly_roots has an expression index")
            actual_indexes.add(index_columns)
        if require_indexes and not expected_indexes.issubset(actual_indexes):
            raise PersistenceCorruptError("readonly_roots indexes are incomplete")
        if schema_name == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET and scope_path is not None:
            _assert_readonly_root_scope_clean(connection, Path(scope_path))
        return schema_name
    except PersistenceError:
        raise
    except (TypeError, ValueError, sqlite3.DatabaseError) as exc:
        raise PersistenceCorruptError("readonly_roots schema could not be inspected") from exc


def _readonly_root_record(value: object) -> dict[str, Any]:
    """Validate the private, non-authorizing durable root record."""

    record = _mapping(value, name="readonly root")
    fields = {
        "root_id",
        "requested_path",
        "canonical_path",
        "device",
        "inode",
        "created_at",
        "last_accessed_at",
        "expires_at",
        "label",
        "state",
        "updated_at",
    }
    if set(record) - fields:
        raise PersistenceError("readonly root contains unsupported fields")
    root_id = _identifier(record.get("root_id"), name="root_id", maximum=160)
    if not re.fullmatch(r"readonly:[A-Za-z0-9_-]{1,150}", root_id):
        raise PersistenceError("readonly root id has an invalid format")
    requested_path = _readonly_root_path(record.get("requested_path"), name="requested_path")
    canonical_path = _readonly_root_path(record.get("canonical_path"), name="canonical_path")
    device = record.get("device")
    inode = record.get("inode")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (device, inode)):
        raise PersistenceError("readonly root filesystem identity is invalid")
    created_at = _finite_number(record.get("created_at"), name="created_at")
    last_accessed_at = _finite_number(record.get("last_accessed_at"), name="last_accessed_at")
    expires_at = _finite_number(record.get("expires_at"), name="expires_at")
    updated_at = _finite_number(record.get("updated_at"), name="updated_at")
    if expires_at <= created_at or last_accessed_at < created_at:
        raise PersistenceError("readonly root timestamps are invalid")
    label = _text(record.get("label"), name="label", maximum=80)
    state = _text(record.get("state"), name="state", maximum=16, allow_empty=False)
    if state not in _READONLY_ROOT_STATES:
        raise PersistenceError("readonly root state is invalid")
    return {
        "root_id": root_id,
        "requested_path": requested_path,
        "canonical_path": canonical_path,
        "device": int(device),
        "inode": int(inode),
        "created_at": created_at,
        "last_accessed_at": last_accessed_at,
        "expires_at": expires_at,
        "label": label,
        "state": state,
        "updated_at": updated_at,
    }


def _task_process_binding_record(value: object) -> dict[str, Any]:
    """Validate the complete, non-secret process binding record."""

    record = _mapping(value, name="task process binding")
    if set(record) - _TASK_PROCESS_BINDING_FIELDS:
        raise PersistenceError("task process binding contains unsupported fields")
    process_session_id = _process_session_identifier(record.get("process_session_id"))
    workspace_id = _identifier(record.get("workspace_id"), name="workspace_id")
    working_tree_id = _identifier(record.get("working_tree_id"), name="working_tree_id")
    raw_development_session_id = record.get("development_session_id")
    development_session_id: str | None
    if raw_development_session_id in (None, ""):
        development_session_id = None
    else:
        development_session_id = _identifier(raw_development_session_id, name="development_session_id")
    runtime_capability_epoch = _text(
        record.get("runtime_capability_epoch"),
        name="runtime_capability_epoch",
        maximum=128,
        allow_empty=False,
    )
    upstream_runtime_id = _text(
        record.get("upstream_runtime_id"),
        name="upstream_runtime_id",
        maximum=256,
        allow_empty=False,
    )
    created_at = _finite_number(record.get("created_at"), name="created_at")
    expires_at = _finite_number(record.get("expires_at"), name="expires_at")
    if expires_at <= created_at:
        raise PersistenceError("task process binding expiry must be after creation")
    state = _text(record.get("state", "active"), name="state", maximum=32, allow_empty=False)
    if state not in _TASK_PROCESS_BINDING_STATES:
        raise PersistenceError("task process binding state is invalid")
    return {
        "process_session_id": process_session_id,
        "workspace_id": workspace_id,
        "working_tree_id": working_tree_id,
        "development_session_id": development_session_id,
        "runtime_capability_epoch": runtime_capability_epoch,
        "upstream_runtime_id": upstream_runtime_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "state": state,
    }


def _scope_hashes(value: object) -> str:
    candidate = {} if value is None else value
    if not isinstance(candidate, Mapping):
        raise PersistenceError("scope_hashes must be an object")
    parsed: dict[str, str] = {}
    for path, digest in candidate.items():
        path_text = _text(path, name="scope_hash_path", maximum=512, allow_empty=False)
        if path_text.startswith(("/", "~")) or "\\" in path_text or any(
            part in {"", ".", ".."} for part in path_text.split("/")
        ):
            raise PersistenceError("scope_hash_path contains an unsafe path")
        parsed[path_text] = _hash(digest, name="scope_hash", allow_empty=False)
    return _json(dict(sorted(parsed.items())), name="scope_hashes", default={})


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _import_value(value: object, *, name: str) -> object:
    """Validate one SQLite value crossing the generation-import boundary."""

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PersistenceError(f"{name} contains a non-finite number")
        return value
    if isinstance(value, str):
        if "\x00" in value or len(value.encode("utf-8")) > MAX_JSON_BYTES:
            raise PersistenceError(f"{name} exceeds its safety bound")
        if contains_secret_like_content(value) or any(marker in value.lower() for marker in _FORBIDDEN_TEXT):
            raise PersistenceError(f"{name} contains non-persistable sensitive content")
        return value
    if isinstance(value, bytes):
        if len(value) > MAX_JSON_BYTES:
            raise PersistenceError(f"{name} exceeds its safety bound")
        return value
    raise PersistenceError(f"{name} contains an unsupported SQLite value")


def _import_rows_hash(rows: object) -> str:
    """Build the deterministic hash used to bind imported row content."""

    if not isinstance(rows, (list, tuple)) or any(not isinstance(row, Mapping) for row in rows):
        raise PersistenceError("evidence import rows are invalid")

    def encode(value: object) -> object:
        if isinstance(value, bytes):
            return {"__bytes_hex__": value.hex()}
        if isinstance(value, Mapping):
            return {str(key): encode(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [encode(item) for item in value]
        return value

    try:
        payload = json.dumps(
            [encode(dict(row)) for row in rows],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PersistenceError("evidence import rows are not hashable") from exc
    return hashlib.sha256(payload).hexdigest()


class SqliteDirectorStore:
    """Bounded SQLite store with explicit migrations and fail-closed reads."""

    def __init__(self, path: Path | str | None = None, *, read_only: bool = False) -> None:
        selected_path = Path(path).expanduser() if path is not None else director_db_path()
        self._read_only = bool(read_only)
        self.path = self._secure_path_read_only(selected_path) if self._read_only else self._secure_path(selected_path)
        self._lock = threading.RLock()
        self._writes_since_maintenance = 0
        self._readonly_roots_schema = _READONLY_ROOT_SCHEMA_MISSING
        self._schema_version = self._bootstrap_read_only() if self._read_only else self._bootstrap()

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def readonly_roots_schema(self) -> str:
        """Return the validated durable READ_ONLY root table shape."""

        return self._readonly_roots_schema

    @staticmethod
    def _secure_path(path: Path) -> Path:
        if not path.is_absolute():
            raise PersistenceError("database path must be absolute")
        parent = path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            probe = Path(parent.anchor)
            for component in parent.parts[1:]:
                probe = probe / component
                # macOS exposes temporary directories through the stable
                # `/var` and `/tmp` compatibility symlinks.  Those platform
                # aliases are safe; an application-created link below them is
                # still rejected.
                if probe.is_symlink() and probe not in {Path("/var"), Path("/tmp")}:
                    raise PersistenceError("database directory contains a symlink")
            if parent.is_symlink() or not parent.is_dir():
                raise PersistenceError("database directory is not a private directory")
            os.chmod(parent, 0o700)
        except OSError as exc:
            raise PersistenceError("database directory is unavailable") from exc
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise PersistenceError("database path is not a regular file")
            try:
                mode = path.stat().st_mode & 0o777
            except OSError as exc:
                raise PersistenceError("database permissions cannot be inspected") from exc
            if mode & 0o077:
                raise PersistenceError("database file is not private")
        return path

    @staticmethod
    def _secure_path_read_only(path: Path) -> Path:
        """Validate an existing database without creating or chmod'ing it."""

        if not path.is_absolute():
            raise PersistenceError("database path must be absolute")
        parent = path.parent
        try:
            if parent.is_symlink() or not parent.is_dir():
                raise PersistenceError("database directory is not a private directory")
            probe = Path(parent.anchor)
            for component in parent.parts[1:]:
                probe = probe / component
                if probe.is_symlink() and probe not in {Path("/var"), Path("/tmp")}:
                    raise PersistenceError("database directory contains a symlink")
            if parent.stat().st_mode & 0o077:
                raise PersistenceError("database directory is not private")
            if path.is_symlink() or not path.is_file():
                raise PersistenceError("database path is not a regular file")
            if path.stat().st_mode & 0o077:
                raise PersistenceError("database file is not private")
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{path}{suffix}")
                if not sidecar.exists():
                    continue
                if sidecar.is_symlink() or not sidecar.is_file() or sidecar.stat().st_mode & 0o077:
                    raise PersistenceError("SQLite sidecar is not a regular private file")
        except OSError as exc:
            raise PersistenceError("database path cannot be inspected safely") from exc
        return path

    @staticmethod
    def _connect_raw(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{path}?mode=ro" if read_only else str(path),
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
                uri=read_only,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if read_only:
                connection.execute("PRAGMA query_only=ON")
            else:
                connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.close()
            raise PersistenceError("SQLite database is temporarily unavailable") from exc
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                connection.close()
            raise PersistenceCorruptError("SQLite database could not be opened safely") from exc

    def _connect(self) -> sqlite3.Connection:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if sidecar.exists() and sidecar.is_symlink():
                raise PersistenceError("SQLite sidecar is a symlink")
        connection = self._connect_raw(self.path, read_only=self._read_only)
        if not self._read_only:
            try:
                self._restrict_database_assets()
            except PersistenceError:
                connection.close()
                raise
        return connection

    def _bootstrap_read_only(self) -> int:
        """Read the existing schema contract without migration or DDL."""

        connection = self._connect()
        try:
            try:
                integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
                journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                row = connection.execute(
                    "SELECT version FROM schema_meta WHERE schema_name = 'director'"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise PersistenceCorruptError("SQLite read-only schema inspection failed") from exc
            if integrity != "ok" or journal_mode != "wal" or row is None:
                raise PersistenceCorruptError("SQLite read-only schema is unavailable")
            try:
                version = int(row[0])
            except (TypeError, ValueError) as exc:
                raise PersistenceCorruptError("SQLite read-only schema version is invalid") from exc
            if version < 1 or version > CURRENT_SCHEMA_VERSION:
                raise PersistenceCorruptError("SQLite read-only schema version is unsupported")
            self._readonly_roots_schema = inspect_readonly_roots_schema(
                connection,
                allow_missing=True,
                require_indexes=True,
                scope_path=self.path,
            )
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise PersistenceCorruptError("SQLite read-only foreign key validation failed")
            return version
        finally:
            connection.close()

    def _restrict_database_assets(self) -> None:
        """Keep the database and every SQLite sidecar private to this user."""

        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if not candidate.exists():
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise PersistenceError("SQLite database asset is not a regular private file")
            try:
                os.chmod(candidate, 0o600)
                if candidate.stat().st_mode & 0o077:
                    raise PersistenceError("SQLite database asset is not private")
            except OSError as exc:
                raise PersistenceError("SQLite database asset permissions cannot be restricted") from exc

    def _bootstrap(self) -> int:
        exists = self.path.exists()
        connection = self._connect()
        try:
            try:
                check = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            except sqlite3.DatabaseError as exc:
                raise PersistenceCorruptError("SQLite integrity check failed") from exc
            if check != "ok":
                raise PersistenceCorruptError("SQLite integrity check is not ok")
            try:
                journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                if journal_mode != "wal":
                    journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
                if journal_mode != "wal":
                    raise PersistenceError("SQLite WAL journal mode is unavailable")
            except sqlite3.OperationalError as exc:
                raise PersistenceError("SQLite WAL journal mode could not be configured") from exc
            except sqlite3.DatabaseError as exc:
                raise PersistenceCorruptError("SQLite journal mode could not be inspected safely") from exc
            if not exists:
                # This pragma is only effective before the first table exists.
                connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
                connection.execute("VACUUM")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (schema_name TEXT PRIMARY KEY, version INTEGER NOT NULL)"
            )
            row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
            version = int(row[0]) if row else 0
            if version > CURRENT_SCHEMA_VERSION:
                raise PersistenceCorruptError("SQLite schema version is newer than this runtime")
            if version < 1:
                self._migration_v1(connection)
                version = 1
                connection.execute(
                    "INSERT INTO schema_meta(schema_name, version) VALUES ('director', ?) "
                    "ON CONFLICT(schema_name) DO UPDATE SET version=excluded.version",
                    (version,),
                )
            if version < 2:
                self._migration_v2(connection)
                version = 2
                connection.execute(
                    "UPDATE schema_meta SET version = ? WHERE schema_name = 'director'",
                    (version,),
                )
            if version < 3:
                self._migration_v3(connection)
                version = 3
                connection.execute(
                    "UPDATE schema_meta SET version = ? WHERE schema_name = 'director'",
                    (version,),
                )
            if version < 4:
                self._migration_v4(connection)
                version = 4
                connection.execute(
                    "UPDATE schema_meta SET version = ? WHERE schema_name = 'director'",
                    (version,),
                )
            if version < 5:
                self._migration_v5(connection)
                version = 5
                connection.execute(
                    "UPDATE schema_meta SET version = ? WHERE schema_name = 'director'",
                    (version,),
                )
            if version < 6:
                self._migration_v6(connection)
                version = 6
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 7:
                self._migration_v7(connection)
                version = 7
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 8:
                self._migration_v8(connection)
                version = 8
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 9:
                self._migration_v9(connection)
                version = 9
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 10:
                self._migration_v10(connection)
                version = 10
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 11:
                self._migration_v11(connection)
                version = 11
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 12:
                self._migration_v12(connection)
                version = 12
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 13:
                self._migration_v13(connection)
                version = 13
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            if version < 14:
                self._migration_v14(connection)
                version = 14
                connection.execute("UPDATE schema_meta SET version = ? WHERE schema_name = 'director'", (version,))
            self._ensure_baseline_snapshot_columns(connection)
            self._ensure_development_sessions_table(connection)
            self._ensure_project_policy_receipts_table(connection)
            self._ensure_approval_decisions_table(connection)
            self._ensure_integration_intents_table(connection)
            self._ensure_integration_approval_grants_table(connection)
            self._ensure_provisioning_events_table(connection)
            self._ensure_readonly_roots_table(connection)
            self._ensure_request_lifecycle_events_table(connection)
            self._ensure_review_receipts_table(connection)
            self._ensure_session_archive_tables(connection)
            self._ensure_session_reconciliation_receipts_table(connection)
            self._ensure_evidence_generation_imports_table(connection)
            self._ensure_task_process_bindings_table(connection)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise PersistenceCorruptError("SQLite foreign key validation failed")
            connection.commit()
            self._restrict_database_assets()
            return version
        except PersistenceError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise PersistenceCorruptError("SQLite migration failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _migration_v1(connection: sqlite3.Connection) -> None:
        # Do not use executescript here: sqlite3 implicitly commits before an
        # executescript call, which would make a partially applied migration
        # survive a crash or a failed statement.  Each DDL statement remains
        # inside the caller's explicit BEGIN IMMEDIATE transaction.
        statements = (
            """
            CREATE TABLE IF NOT EXISTS task_ledger (
                task_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                title TEXT NOT NULL,
                owner_id TEXT,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL DEFAULT '',
                development_session_id TEXT NOT NULL DEFAULT '',
                allowed_paths_json TEXT NOT NULL DEFAULT '[]',
                resources_json TEXT NOT NULL DEFAULT '[]',
                lease_id TEXT NOT NULL DEFAULT '',
                base_revision TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL,
                context_pack_id TEXT NOT NULL DEFAULT '',
                verification_receipt_id TEXT NOT NULL DEFAULT '',
                security_audit_receipt_id TEXT NOT NULL DEFAULT '',
                integration_receipt_id TEXT NOT NULL DEFAULT '',
                git_commit_receipt_id TEXT NOT NULL DEFAULT '',
                git_push_receipt_id TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                result_ref TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_task_workspace_state ON task_ledger(workspace_id, state)",
            """
            CREATE TABLE IF NOT EXISTS writer_leases (
                lease_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                task_id TEXT,
                owner_id TEXT NOT NULL,
                paths_json TEXT NOT NULL DEFAULT '[]',
                resources_json TEXT NOT NULL DEFAULT '[]',
                base_revision TEXT NOT NULL DEFAULT '',
                scope_hashes_json TEXT NOT NULL DEFAULT '{}',
                workspace_state_hash TEXT NOT NULL DEFAULT '',
                workspace_wide INTEGER NOT NULL DEFAULT 0,
                acquired_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                released_at REAL,
                state TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_lease_expiry ON writer_leases(state, expires_at)",
            """
            CREATE TABLE IF NOT EXISTS verification_receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL DEFAULT '',
                base_revision TEXT NOT NULL,
                diff_hash TEXT NOT NULL DEFAULT '',
                changed_paths_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                results_json TEXT NOT NULL DEFAULT '[]',
                stale INTEGER NOT NULL DEFAULT 0,
                recorded_at TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_verification_workspace ON verification_receipts(workspace_id, recorded_at)",
            """
            CREATE TABLE IF NOT EXISTS security_audit_receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL DEFAULT '',
                base_revision TEXT NOT NULL,
                diff_hash TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                changed_paths_json TEXT NOT NULL DEFAULT '[]',
                verification_receipt_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                result_json TEXT NOT NULL DEFAULT '{}',
                stale INTEGER NOT NULL DEFAULT 0,
                audited_at TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_audit_workspace ON security_audit_receipts(workspace_id, audited_at)",
            """
            CREATE TABLE IF NOT EXISTS integration_receipts (
                receipt_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL DEFAULT '',
                working_tree_id TEXT NOT NULL DEFAULT '',
                source_revision TEXT NOT NULL DEFAULT '',
                canonical_revision TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                evidence_ids_json TEXT NOT NULL DEFAULT '[]',
                preflight_outcome TEXT NOT NULL DEFAULT '',
                integration_outcome TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                applied_at TEXT
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS git_closeout_receipts (
                receipt_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                task_id TEXT,
                workspace_id TEXT NOT NULL DEFAULT '',
                working_tree_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                approval_consumed INTEGER NOT NULL DEFAULT 0,
                expected_head TEXT NOT NULL DEFAULT '',
                actual_head TEXT NOT NULL DEFAULT '',
                expected_remote_head TEXT NOT NULL DEFAULT '',
                actual_remote_head TEXT NOT NULL DEFAULT '',
                remote TEXT NOT NULL DEFAULT '',
                branch TEXT NOT NULL DEFAULT '',
                expected_remote_url_hash TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                audit_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_git_task ON git_closeout_receipts(task_id, created_at)",
        )
        for statement in statements:
            connection.execute(statement)

    @staticmethod
    def _migration_v2(connection: sqlite3.Connection) -> None:
        """Add lease identity fields to pre-release v1 databases."""

        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(writer_leases)").fetchall()
        }
        if "workspace_state_hash" not in columns:
            connection.execute(
                "ALTER TABLE writer_leases ADD COLUMN workspace_state_hash TEXT NOT NULL DEFAULT ''"
            )
        if "workspace_wide" not in columns:
            connection.execute(
                "ALTER TABLE writer_leases ADD COLUMN workspace_wide INTEGER NOT NULL DEFAULT 0"
            )

    @staticmethod
    def _migration_v3(connection: sqlite3.Connection) -> None:
        """Link child evidence/lease rows to the task ledger safely.

        v1/v2 intentionally accepted textual task references so a receipt
        could be written before its task row.  The persisted contract now
        stores nullable references with ``ON DELETE SET NULL``: pruning a
        task never destroys its historical evidence, while a dangling task
        binding cannot be created accidentally. Existing invalid/empty
        bindings are retained as unbound (NULL) during the transactional
        rebuild.
        """

        def rebuild(table: str, create_sql: str, columns: tuple[str, ...], select_columns: tuple[str, ...]) -> None:
            temporary = f"{table}__v3"
            connection.execute(f"DROP TABLE IF EXISTS {temporary}")
            connection.execute(create_sql.replace(table, temporary, 1))
            select = ", ".join(select_columns)
            target = ", ".join(columns)
            connection.execute(f"INSERT INTO {temporary} ({target}) SELECT {select} FROM {table}")
            connection.execute(f"DROP TABLE {table}")
            connection.execute(f"ALTER TABLE {temporary} RENAME TO {table}")

        # Qualify the source table explicitly.  Without that qualification
        # SQLite resolves both sides of ``t.task_id = task_id`` to the inner
        # query, which would preserve dangling legacy references and make the
        # foreign-key rebuild fail closed instead of normalizing them to NULL.
        def task_ref(source_table: str) -> str:
            return (
                f"CASE WHEN {source_table}.task_id IS NOT NULL "
                f"AND {source_table}.task_id <> '' "
                f"AND EXISTS (SELECT 1 FROM task_ledger t WHERE t.task_id = {source_table}.task_id) "
                f"THEN {source_table}.task_id ELSE NULL END"
            )

        rebuild(
            "writer_leases",
            """
            CREATE TABLE writer_leases (
                lease_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                task_id TEXT REFERENCES task_ledger(task_id) ON DELETE SET NULL,
                owner_id TEXT NOT NULL,
                paths_json TEXT NOT NULL DEFAULT '[]',
                resources_json TEXT NOT NULL DEFAULT '[]',
                base_revision TEXT NOT NULL DEFAULT '',
                scope_hashes_json TEXT NOT NULL DEFAULT '{}',
                workspace_state_hash TEXT NOT NULL DEFAULT '',
                workspace_wide INTEGER NOT NULL DEFAULT 0,
                acquired_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                released_at REAL,
                state TEXT NOT NULL
            )
            """,
            ("lease_id", "workspace_id", "working_tree_id", "task_id", "owner_id", "paths_json", "resources_json", "base_revision", "scope_hashes_json", "workspace_state_hash", "workspace_wide", "acquired_at", "expires_at", "released_at", "state"),
            ("lease_id", "workspace_id", "working_tree_id", task_ref("writer_leases"), "owner_id", "paths_json", "resources_json", "base_revision", "scope_hashes_json", "workspace_state_hash", "workspace_wide", "acquired_at", "expires_at", "released_at", "state"),
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_lease_expiry ON writer_leases(state, expires_at)")
        rebuild(
            "verification_receipts",
            """
            CREATE TABLE verification_receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT REFERENCES task_ledger(task_id) ON DELETE SET NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL DEFAULT '',
                base_revision TEXT NOT NULL,
                diff_hash TEXT NOT NULL DEFAULT '',
                changed_paths_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                results_json TEXT NOT NULL DEFAULT '[]',
                stale INTEGER NOT NULL DEFAULT 0,
                recorded_at TEXT NOT NULL
            )
            """,
            ("receipt_id", "task_id", "workspace_id", "working_tree_id", "base_revision", "diff_hash", "changed_paths_json", "status", "results_json", "stale", "recorded_at"),
            ("receipt_id", task_ref("verification_receipts"), "workspace_id", "working_tree_id", "base_revision", "diff_hash", "changed_paths_json", "status", "results_json", "stale", "recorded_at"),
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_verification_workspace ON verification_receipts(workspace_id, recorded_at)")
        rebuild(
            "security_audit_receipts",
            """
            CREATE TABLE security_audit_receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT REFERENCES task_ledger(task_id) ON DELETE SET NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL DEFAULT '',
                base_revision TEXT NOT NULL,
                diff_hash TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                changed_paths_json TEXT NOT NULL DEFAULT '[]',
                verification_receipt_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                result_json TEXT NOT NULL DEFAULT '{}',
                stale INTEGER NOT NULL DEFAULT 0,
                audited_at TEXT NOT NULL
            )
            """,
            ("receipt_id", "task_id", "workspace_id", "working_tree_id", "base_revision", "diff_hash", "patch_hash", "changed_paths_json", "verification_receipt_id", "status", "result_json", "stale", "audited_at"),
            ("receipt_id", task_ref("security_audit_receipts"), "workspace_id", "working_tree_id", "base_revision", "diff_hash", "patch_hash", "changed_paths_json", "verification_receipt_id", "status", "result_json", "stale", "audited_at"),
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_workspace ON security_audit_receipts(workspace_id, audited_at)")
        rebuild(
            "git_closeout_receipts",
            """
            CREATE TABLE git_closeout_receipts (
                receipt_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                task_id TEXT REFERENCES task_ledger(task_id) ON DELETE SET NULL,
                workspace_id TEXT NOT NULL DEFAULT '',
                working_tree_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                approval_consumed INTEGER NOT NULL DEFAULT 0,
                expected_head TEXT NOT NULL DEFAULT '',
                actual_head TEXT NOT NULL DEFAULT '',
                expected_remote_head TEXT NOT NULL DEFAULT '',
                actual_remote_head TEXT NOT NULL DEFAULT '',
                remote TEXT NOT NULL DEFAULT '',
                branch TEXT NOT NULL DEFAULT '',
                expected_remote_url_hash TEXT NOT NULL DEFAULT '',
                patch_hash TEXT NOT NULL DEFAULT '',
                audit_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
            """,
            ("receipt_id", "operation", "task_id", "workspace_id", "working_tree_id", "status", "approval_consumed", "expected_head", "actual_head", "expected_remote_head", "actual_remote_head", "remote", "branch", "expected_remote_url_hash", "patch_hash", "audit_json", "created_at"),
            ("receipt_id", "operation", task_ref("git_closeout_receipts"), "workspace_id", "working_tree_id", "status", "approval_consumed", "expected_head", "actual_head", "expected_remote_head", "actual_remote_head", "remote", "branch", "expected_remote_url_hash", "patch_hash", "audit_json", "created_at"),
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_git_task ON git_closeout_receipts(task_id, created_at)")

    @staticmethod
    def _migration_v4(connection: sqlite3.Connection) -> None:
        """Persist task dependency edges as bounded JSON metadata."""

        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(task_ledger)").fetchall()}
        if "dependencies_json" not in columns:
            connection.execute("ALTER TABLE task_ledger ADD COLUMN dependencies_json TEXT NOT NULL DEFAULT '[]'")

    @staticmethod
    def _migration_v5(connection: sqlite3.Connection) -> None:
        """Add immutable snapshot and Director start idempotency records."""

        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_task_workspace_request ON task_ledger(workspace_id, request_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                head_revision TEXT NOT NULL,
                tracked_patch_hash TEXT NOT NULL,
                tracked_paths_json TEXT NOT NULL DEFAULT '[]',
                untracked_manifest_hash TEXT NOT NULL,
                untracked_paths_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                canonical_dirty INTEGER NOT NULL DEFAULT 0,
                included_paths_json TEXT NOT NULL DEFAULT '[]',
                excluded_paths_json TEXT NOT NULL DEFAULT '[]',
                excluded_reasons_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_snapshot_workspace_created ON baseline_snapshots(workspace_id, created_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS development_start_requests (
                workspace_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                task_id TEXT,
                session_id TEXT,
                lease_id TEXT,
                working_tree_id TEXT,
                result_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(workspace_id, request_id),
                FOREIGN KEY(task_id) REFERENCES task_ledger(task_id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_start_request_state ON development_start_requests(state, updated_at)"
        )

    @staticmethod
    def _migration_v6(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS semantic_index_metadata (
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                backend_revision TEXT NOT NULL,
                path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                symbols_json TEXT NOT NULL DEFAULT '[]',
                edges_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL,
                PRIMARY KEY(workspace_id, working_tree_id, source_revision, backend_revision, path)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_semantic_identity ON semantic_index_metadata(workspace_id, working_tree_id, source_revision, backend_revision)")

    @staticmethod
    def _migration_v7(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_cache (
                cache_key TEXT PRIMARY KEY,
                worktree_id TEXT NOT NULL,
                head_revision TEXT NOT NULL,
                relevant_diff_hash TEXT NOT NULL,
                command_fingerprint TEXT NOT NULL,
                env_fingerprint TEXT NOT NULL,
                dependency_fingerprint TEXT NOT NULL,
                relevant_paths_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                result_digest TEXT NOT NULL,
                output_summary TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_verification_cache_expiry ON verification_cache(expires_at, created_at)")

    @staticmethod
    def _migration_v8(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS development_loops (
                loop_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                worktree_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                budgets_json TEXT NOT NULL,
                started_at REAL NOT NULL,
                repeated_failure_count INTEGER NOT NULL DEFAULT 0,
                last_failure_fingerprint TEXT NOT NULL DEFAULT '',
                no_progress_count INTEGER NOT NULL DEFAULT 0,
                last_progress_token TEXT NOT NULL DEFAULT '',
                stop_reason TEXT NOT NULL DEFAULT '',
                pending_action TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS development_loop_events (
                loop_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_fingerprint TEXT NOT NULL,
                from_phase TEXT NOT NULL,
                to_phase TEXT NOT NULL,
                reason TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                sequence INTEGER NOT NULL,
                PRIMARY KEY(loop_id, event_id),
                UNIQUE(loop_id, sequence),
                FOREIGN KEY(loop_id) REFERENCES development_loops(loop_id) ON DELETE CASCADE
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_loop_identity ON development_loops(task_id, session_id, worktree_id, phase)")

    @staticmethod
    def _migration_v9(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS visual_regression_baselines (
                baseline_id TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                revision TEXT NOT NULL,
                viewport_width INTEGER NOT NULL,
                viewport_height INTEGER NOT NULL,
                theme TEXT NOT NULL,
                screenshot_digest TEXT NOT NULL,
                screenshot_ref TEXT NOT NULL,
                dom_fingerprint TEXT NOT NULL,
                accessibility_fingerprint TEXT NOT NULL,
                text_fingerprint TEXT NOT NULL,
                boxes_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_visual_baseline_identity ON visual_regression_baselines(scenario_id, revision, viewport_width, viewport_height, theme)")

    @staticmethod
    def _migration_v10(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS acceleration_receipts (
                receipt_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_hashes_json TEXT NOT NULL DEFAULT '[]',
                refs_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_acceleration_receipt_kind_created ON acceleration_receipts(kind, created_at)")

    @staticmethod
    def _migration_v11(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS context_checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                head TEXT NOT NULL,
                task_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                next_action TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_context_checkpoint_workspace_created ON context_checkpoints(workspace_id, created_at DESC, checkpoint_id DESC)"
        )

    @staticmethod
    def _migration_v12(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_performance_profiles (
                profile_id TEXT PRIMARY KEY,
                workload_class TEXT NOT NULL,
                project_fingerprint TEXT NOT NULL,
                local_environment_fingerprint TEXT NOT NULL,
                cloud_environment_fingerprint TEXT NOT NULL,
                benchmark_revision TEXT NOT NULL,
                local_success_samples INTEGER NOT NULL,
                cloud_success_samples INTEGER NOT NULL,
                local_p50_ms REAL NOT NULL,
                local_p95_ms REAL NOT NULL,
                cloud_p50_ms REAL NOT NULL,
                cloud_p95_ms REAL NOT NULL,
                cloud_stage_p50_ms REAL NOT NULL,
                cloud_return_p50_ms REAL NOT NULL,
                local_failure_rate REAL NOT NULL,
                cloud_failure_rate REAL NOT NULL,
                speed_ratio_p50 REAL NOT NULL,
                observed_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                billable_api INTEGER NOT NULL DEFAULT 0,
                sufficient INTEGER NOT NULL DEFAULT 0,
                managed_cloud_wins INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cloud_profile_lookup ON cloud_performance_profiles(workload_class, project_fingerprint, local_environment_fingerprint, cloud_environment_fingerprint, benchmark_revision, observed_at DESC)"
        )

    @staticmethod
    def _migration_v13(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS plan_manifests (
                plan_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                workspace_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                spec_path TEXT NOT NULL,
                spec_hash TEXT NOT NULL,
                plan_path TEXT NOT NULL DEFAULT '',
                plan_hash TEXT NOT NULL DEFAULT '',
                supersedes_plan_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_plan_manifests_workspace_status ON plan_manifests(workspace_id, status, plan_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS plan_tasks (
                plan_id TEXT NOT NULL REFERENCES plan_manifests(plan_id) ON DELETE CASCADE,
                plan_task_id TEXT NOT NULL,
                logical_task_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                intent_fingerprint TEXT NOT NULL,
                paths_json TEXT NOT NULL DEFAULT '[]',
                resources_json TEXT NOT NULL DEFAULT '[]',
                dependencies_json TEXT NOT NULL DEFAULT '[]',
                acceptance_criteria_json TEXT NOT NULL DEFAULT '[]',
                delivery_requirements_json TEXT NOT NULL DEFAULT '[]',
                state TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(plan_id, plan_task_id)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_plan_tasks_logical ON plan_tasks(logical_task_id)")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS plan_task_attempts (
                attempt_id TEXT PRIMARY KEY,
                logical_task_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                plan_task_id TEXT NOT NULL,
                task_id TEXT NOT NULL DEFAULT '',
                owner_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                working_tree_id TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL DEFAULT '',
                finished_at TEXT NOT NULL DEFAULT '',
                outcome TEXT NOT NULL DEFAULT '',
                failure_fingerprint TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(plan_id, plan_task_id) REFERENCES plan_tasks(plan_id, plan_task_id) ON DELETE RESTRICT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_plan_task_attempts_logical ON plan_task_attempts(logical_task_id, attempt_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS plan_supersessions (
                source_plan_id TEXT NOT NULL REFERENCES plan_manifests(plan_id) ON DELETE RESTRICT,
                replacement_plan_id TEXT NOT NULL REFERENCES plan_manifests(plan_id) ON DELETE RESTRICT,
                task_map_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(source_plan_id, replacement_plan_id)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_plan_supersessions_replacement ON plan_supersessions(replacement_plan_id, source_plan_id)"
        )

    @staticmethod
    def _migration_v14(connection: sqlite3.Connection) -> None:
        """Persist one-shot Git mutation authority without bearer material."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS git_preflight_authority (
                preflight_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                claimed_at REAL,
                finished_at REAL,
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_git_preflight_workspace_state ON git_preflight_authority(workspace_id, state, expires_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS git_approval_authority (
                token_hash TEXT PRIMARY KEY,
                confirmation_hash TEXT NOT NULL,
                preflight_id TEXT NOT NULL REFERENCES git_preflight_authority(preflight_id) ON DELETE CASCADE,
                operation TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_git_approval_preflight ON git_approval_authority(preflight_id, expires_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS git_mutation_outcomes (
                receipt_id TEXT PRIMARY KEY,
                preflight_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_git_outcome_preflight ON git_mutation_outcomes(preflight_id, created_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS git_trusted_partial_stage_states (
                state_hash TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                head TEXT NOT NULL,
                staged_diff_hash TEXT NOT NULL,
                index_state_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_git_partial_stage_identity ON git_trusted_partial_stage_states(workspace_id, working_tree_id, task_id, head)"
        )

    @staticmethod
    def _ensure_baseline_snapshot_columns(connection: sqlite3.Connection) -> None:
        """Keep schema-v5 snapshot metadata forward-compatible."""

        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "baseline_snapshots" not in tables:
            return
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(baseline_snapshots)").fetchall()}
        if "excluded_reasons_json" not in columns:
            connection.execute(
                "ALTER TABLE baseline_snapshots ADD COLUMN excluded_reasons_json TEXT NOT NULL DEFAULT '{}'"
            )

    @staticmethod
    def _ensure_development_sessions_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS development_sessions (
                session_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                logical_workspace_id TEXT NOT NULL,
                worktree_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL DEFAULT '',
                source_revision TEXT NOT NULL,
                base_commit TEXT NOT NULL,
                root_path TEXT NOT NULL,
                task_id TEXT REFERENCES task_ledger(task_id) ON DELETE SET NULL,
                owner_id TEXT,
                source_dirty INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                lifecycle_state TEXT NOT NULL,
                stale INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_project_state ON development_sessions(project_id, lifecycle_state, expires_at)"
        )

    @staticmethod
    def _ensure_project_policy_receipts_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS project_policy_receipts (
                receipt_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                before_config_digest TEXT NOT NULL,
                after_config_digest TEXT NOT NULL,
                changed_keys_json TEXT NOT NULL DEFAULT '[]',
                before_policy_json TEXT NOT NULL DEFAULT '{}',
                after_policy_json TEXT NOT NULL DEFAULT '{}',
                audit_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_workspace_recorded ON project_policy_receipts(workspace_id, recorded_at)"
        )

    @staticmethod
    def _ensure_approval_decisions_table(connection: sqlite3.Connection) -> None:
        """Create additive metadata-only evidence for authorization decisions."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_decisions (
                decision_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                reason TEXT NOT NULL,
                authorization_mode TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                outcome TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_approval_decisions_workspace_recorded ON approval_decisions(workspace_id, recorded_at)"
        )

    @staticmethod
    def _ensure_integration_approval_grants_table(connection: sqlite3.Connection) -> None:
        """Persist exact-state integration intent without bearer material."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_approval_grants (
                grant_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                canonical_revision TEXT NOT NULL,
                patch_hash TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                original_session_id TEXT NOT NULL,
                approved_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                state TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_integration_approval_grants_workspace_state_expiry "
            "ON integration_approval_grants(workspace_id, state, expires_at)"
        )

    @staticmethod
    def _ensure_integration_intents_table(connection: sqlite3.Connection) -> None:
        """Persist pre-approval integration intent without bearer material."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_intents (
                intent_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                canonical_revision TEXT NOT NULL,
                patch_hash TEXT NOT NULL,
                state_diff_hash TEXT NOT NULL,
                verification_receipt_id TEXT NOT NULL,
                security_audit_receipt_id TEXT NOT NULL,
                changed_paths_json TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_integration_intents_workspace_status_expiry "
            "ON integration_intents(workspace_id, status, expires_at)"
        )

    @staticmethod
    def _ensure_provisioning_events_table(connection: sqlite3.Connection) -> None:
        """Create the append-only non-secret provisioning audit table.

        This is additive and intentionally does not alter the Director schema
        version: older state databases can create the table transactionally on
        first open without rewriting any existing rows.
        """

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS provisioning_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                request_id TEXT NOT NULL DEFAULT '',
                owner_id TEXT NOT NULL DEFAULT '',
                project_id TEXT NOT NULL,
                target_path TEXT NOT NULL,
                intent_source TEXT NOT NULL,
                provisioning_mode TEXT NOT NULL,
                canonical_path TEXT NOT NULL,
                root_id TEXT NOT NULL,
                previous_registry_digest TEXT NOT NULL DEFAULT '',
                new_registry_digest TEXT NOT NULL DEFAULT '',
                repo_identity_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_provisioning_project_recorded ON provisioning_events(project_id, recorded_at)"
        )

    def _ensure_readonly_roots_table(self, connection: sqlite3.Connection) -> None:
        """Validate the bounded READ_ONLY root table without widening it.

        Older v26 stores use the native 11-column shape.  A schema-14
        database from another runtime generation may instead contain the
        explicitly recognized legacy scoped 15-column superset.  Both shapes
        are accepted explicitly; every other shape fails closed so an
        arbitrary additive table cannot become part of the root authority
        boundary.
        """

        schema = inspect_readonly_roots_schema(
            connection,
            allow_missing=True,
            require_indexes=False,
            scope_path=self.path,
        )
        if schema == _READONLY_ROOT_SCHEMA_MISSING:
            connection.execute(
                """
                CREATE TABLE readonly_roots (
                    root_id TEXT PRIMARY KEY,
                    requested_path TEXT NOT NULL,
                    canonical_path TEXT NOT NULL,
                    device INTEGER NOT NULL,
                    inode INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_accessed_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            schema = _READONLY_ROOT_SCHEMA_NATIVE

        if schema == _READONLY_ROOT_SCHEMA_NATIVE:
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_readonly_roots_state_expiry ON readonly_roots(state, expires_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_readonly_roots_updated ON readonly_roots(updated_at, root_id)"
            )
        elif schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_readonly_roots_scope_state "
                "ON readonly_roots(scope_id, state, expires_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_readonly_roots_expiry "
                "ON readonly_roots(state, expires_at, updated_at)"
            )
        else:
            raise PersistenceCorruptError("readonly_roots schema is unavailable")

        self._readonly_roots_schema = inspect_readonly_roots_schema(
            connection,
            allow_missing=False,
            require_indexes=True,
            scope_path=self.path,
        )

    @staticmethod
    def _ensure_request_lifecycle_events_table(connection: sqlite3.Connection) -> None:
        """Create the bounded, non-secret request lifecycle trace table."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS request_lifecycle_events (
                event_id TEXT PRIMARY KEY,
                child_instance_id TEXT NOT NULL,
                transport_generation INTEGER NOT NULL,
                request_id TEXT NOT NULL DEFAULT '',
                tool_name TEXT NOT NULL DEFAULT '',
                side_effect_class TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                event TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0,
                duration_ms REAL,
                workspace_id TEXT NOT NULL DEFAULT '',
                working_tree_id TEXT NOT NULL DEFAULT '',
                development_session_id TEXT NOT NULL DEFAULT '',
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_request_lifecycle_recorded ON request_lifecycle_events(recorded_at, event_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_request_lifecycle_request ON request_lifecycle_events(child_instance_id, request_id, recorded_at)"
        )
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(request_lifecycle_events)").fetchall()}
        additive_columns = {
            "logical_connection_id": "TEXT NOT NULL DEFAULT ''",
            "server_schema_revision": "TEXT NOT NULL DEFAULT ''",
            "server_schema_hash": "TEXT NOT NULL DEFAULT ''",
            "request_accepted": "INTEGER NOT NULL DEFAULT 0",
            "result": "TEXT NOT NULL DEFAULT ''",
            "tool_failure_code": "TEXT NOT NULL DEFAULT ''",
            "integration_intent_id": "TEXT NOT NULL DEFAULT ''",
            "integration_preflight_id": "TEXT NOT NULL DEFAULT ''",
            "integration_patch_hash": "TEXT NOT NULL DEFAULT ''",
            "canonical_revision_before": "TEXT NOT NULL DEFAULT ''",
            "mutation_started": "INTEGER NOT NULL DEFAULT 0",
            "mutation_finished": "INTEGER NOT NULL DEFAULT 0",
            "integration_receipt_id": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additive_columns.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE request_lifecycle_events ADD COLUMN {name} {declaration}")

    @staticmethod
    def _ensure_review_receipts_table(connection: sqlite3.Connection) -> None:
        """Create the bounded, independently-owned code review receipt table."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_receipts (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES task_ledger(task_id) ON DELETE CASCADE,
                implementer_owner TEXT NOT NULL,
                reviewer_owner TEXT NOT NULL,
                independent INTEGER NOT NULL DEFAULT 0,
                base_revision TEXT NOT NULL,
                diff_hash TEXT NOT NULL,
                reviewed_paths_json TEXT NOT NULL DEFAULT '[]',
                findings_json TEXT NOT NULL DEFAULT '[]',
                blocking INTEGER NOT NULL DEFAULT 0,
                reviewed_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_review_task_time ON review_receipts(task_id, reviewed_at, receipt_id)"
        )

    @staticmethod
    def _ensure_session_archive_tables(connection: sqlite3.Connection) -> None:
        """Create additive durable archive and restore-lineage tables."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS session_archives (
                archive_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                project_id TEXT NOT NULL,
                logical_workspace_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                physical_worktree_id TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                base_revision TEXT NOT NULL,
                state_hash TEXT NOT NULL,
                patch_hash TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                archive_path TEXT NOT NULL,
                alias_session_ids_json TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                pruned_at TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_archives_project_time ON session_archives(project_id, created_at, archive_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_archives_worktree ON session_archives(physical_worktree_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS session_archive_restores (
                restore_id TEXT PRIMARY KEY,
                archive_id TEXT NOT NULL REFERENCES session_archives(archive_id) ON DELETE RESTRICT,
                original_session_id TEXT NOT NULL,
                restored_session_id TEXT NOT NULL,
                restored_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_archive_restores_archive ON session_archive_restores(archive_id, restored_at, restore_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_archive_restores_session ON session_archive_restores(restored_session_id)"
        )

    @staticmethod
    def _ensure_session_reconciliation_receipts_table(connection: sqlite3.Connection) -> None:
        """Create the append-only, bounded lifecycle reconciliation evidence table."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS session_reconciliation_receipts (
                reconciliation_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                classification TEXT NOT NULL,
                proposed_transition TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                sidecar_path TEXT NOT NULL DEFAULT '',
                sidecar_root TEXT NOT NULL DEFAULT '',
                sidecar_digest TEXT NOT NULL DEFAULT '',
                sidecar_bytes BLOB NOT NULL DEFAULT X'',
                sidecar_updated_at TEXT NOT NULL DEFAULT '',
                source_revision TEXT NOT NULL DEFAULT '',
                source_path TEXT NOT NULL DEFAULT '',
                source_device INTEGER,
                source_inode INTEGER,
                worktree_path TEXT NOT NULL DEFAULT '',
                worktree_exists INTEGER NOT NULL DEFAULT 0,
                worktree_dirty INTEGER NOT NULL DEFAULT 0,
                worktree_head TEXT,
                worktree_branch TEXT,
                worktree_device INTEGER,
                worktree_inode INTEGER,
                git_metadata_json TEXT NOT NULL DEFAULT '{}',
                task_state_json TEXT NOT NULL DEFAULT '{}',
                lease_state_json TEXT NOT NULL DEFAULT '{}',
                process_state_json TEXT NOT NULL DEFAULT '{}',
                archive_state_json TEXT NOT NULL DEFAULT '{}',
                sqlite_state_json TEXT NOT NULL DEFAULT '{}',
                preservation_actions_json TEXT NOT NULL DEFAULT '[]',
                reason_codes_json TEXT NOT NULL DEFAULT '[]',
                evidence_json TEXT NOT NULL DEFAULT '{}',
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_reconciliation_session_time "
            "ON session_reconciliation_receipts(session_id, recorded_at, reconciliation_id)"
        )

    @staticmethod
    def _ensure_evidence_generation_imports_table(connection: sqlite3.Connection) -> None:
        """Create append-only provenance for bounded generation imports.

        This is additive metadata and intentionally does not advance the
        Director schema version.  The imported Director rows remain in their
        normal tables so existing lifecycle readers can restore them.
        """

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_generation_imports (
                import_id TEXT PRIMARY KEY,
                source_generation TEXT NOT NULL,
                source_database_sha256 TEXT NOT NULL,
                source_schema_version INTEGER NOT NULL,
                destination_schema_version INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                task_ids_json TEXT NOT NULL,
                record_hashes_json TEXT NOT NULL,
                source_state_json TEXT NOT NULL,
                destination_state_json TEXT NOT NULL,
                imported_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_generation_session "
            "ON evidence_generation_imports(session_id, imported_at, import_id)"
        )

    @staticmethod
    def _ensure_task_process_bindings_table(connection: sqlite3.Connection) -> None:
        """Create bounded process routing metadata without process payloads.

        This table is additive metadata for schema 14.  It intentionally has
        no command, stdin, stdout, stderr, credential, or arbitrary payload
        columns: the upstream Runtime remains the only owner of live process
        state.
        """

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_process_bindings (
                process_session_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                working_tree_id TEXT NOT NULL,
                development_session_id TEXT,
                runtime_capability_epoch TEXT NOT NULL,
                upstream_runtime_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                state TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_task_process_bindings_state_expiry "
            "ON task_process_bindings(state, expires_at)"
        )

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        if write and self._read_only:
            raise PersistenceError("SQLite store is read-only")
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield connection
                connection.commit()
            except PersistenceError:
                connection.rollback()
                raise
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise PersistenceError("SQLite transaction failed") from exc
            except Exception as exc:
                connection.rollback()
                raise PersistenceError("SQLite transaction rolled back") from exc
            finally:
                connection.close()

    def run_write(self, callback: Callable[[sqlite3.Connection], Any]) -> Any:
        if not callable(callback):
            raise PersistenceError("write callback is required")
        with self._transaction(write=True) as connection:
            result = callback(connection)
        # Retention is maintenance only: it must never turn an already
        # committed Director mutation into a misleading failure.  A later
        # store operation will still fail closed if the database is unhealthy.
        self._writes_since_maintenance += 1
        if self._writes_since_maintenance >= AUTO_MAINTENANCE_WRITE_INTERVAL:
            self._writes_since_maintenance = 0
            try:
                self.cleanup()
            except PersistenceError:
                pass
        return result

    def run_read(self, callback: Callable[[sqlite3.Connection], Any]) -> Any:
        if not callable(callback):
            raise PersistenceError("read callback is required")
        with self._transaction(write=False) as connection:
            return callback(connection)

    def integrity_check(self) -> str:
        with self._lock:
            connection = self._connect()
            try:
                value = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
                if value != "ok":
                    raise PersistenceCorruptError("SQLite integrity check is not ok")
                return value
            except PersistenceError:
                raise
            except sqlite3.DatabaseError as exc:
                raise PersistenceCorruptError("SQLite integrity check failed") from exc
            finally:
                connection.close()

    def close(self) -> None:
        return None

    @staticmethod
    def _semantic_metadata_values(value: object) -> tuple[object, ...]:
        record = _mapping(value, name="semantic metadata")
        allowed = {"workspace_id", "working_tree_id", "source_revision", "backend_revision", "path", "content_hash", "symbols", "edges", "updated_at"}
        if set(record) - allowed:
            raise PersistenceError("semantic metadata contains unsupported fields")
        path = _text(record.get("path"), name="semantic_path", maximum=512, allow_empty=False)
        if path.startswith(("/", "~")) or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise PersistenceError("semantic_path contains an unsafe path")
        symbols, edges = record.get("symbols", []), record.get("edges", [])
        if not isinstance(symbols, list) or len(symbols) > 2048 or not isinstance(edges, list) or len(edges) > 4096:
            raise PersistenceError("semantic metadata is outside its safety bound")
        symbol_keys, edge_keys = {"symbol_id", "kind", "name", "start_line", "end_line"}, {"relation", "source", "target", "line"}
        for item in symbols:
            if not isinstance(item, Mapping) or set(item) != symbol_keys:
                raise PersistenceError("semantic symbol metadata is invalid")
            _text(item.get("symbol_id"), name="semantic_symbol_id", maximum=512, allow_empty=False)
            _text(item.get("kind"), name="semantic_symbol_kind", maximum=80, allow_empty=False)
            _text(item.get("name"), name="semantic_symbol_name", maximum=256, allow_empty=False)
            start_line, end_line = item.get("start_line"), item.get("end_line")
            if isinstance(start_line, bool) or isinstance(end_line, bool) or not isinstance(start_line, int) or not isinstance(end_line, int) or not 1 <= start_line <= end_line <= 10_000_000:
                raise PersistenceError("semantic symbol line range is invalid")
        for item in edges:
            if not isinstance(item, Mapping) or set(item) != edge_keys:
                raise PersistenceError("semantic edge metadata is invalid")
            _text(item.get("relation"), name="semantic_edge_relation", maximum=80, allow_empty=False)
            _text(item.get("source"), name="semantic_edge_source", maximum=512, allow_empty=False)
            _text(item.get("target"), name="semantic_edge_target", maximum=512, allow_empty=False)
            line = item.get("line")
            if isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= 10_000_000:
                raise PersistenceError("semantic edge line is invalid")
        return (_identifier(record.get("workspace_id"), name="workspace_id"), _identifier(record.get("working_tree_id"), name="working_tree_id"), _text(record.get("source_revision"), name="source_revision", maximum=128, allow_empty=False), _identifier(record.get("backend_revision"), name="backend_revision"), path, _hash(record.get("content_hash"), name="content_hash", allow_empty=False), _json(symbols, name="semantic_symbols", default=[]), _json(edges, name="semantic_edges", default=[]), _text(record.get("updated_at"), name="updated_at", maximum=128, allow_empty=False))

    def save_semantic_metadata(self, value: object) -> None:
        values = self._semantic_metadata_values(value)
        self.run_write(lambda connection: connection.execute(
            """INSERT INTO semantic_index_metadata(workspace_id, working_tree_id, source_revision, backend_revision, path, content_hash, symbols_json, edges_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(workspace_id, working_tree_id, source_revision, backend_revision, path) DO UPDATE SET content_hash=excluded.content_hash, symbols_json=excluded.symbols_json, edges_json=excluded.edges_json, updated_at=excluded.updated_at""",
            values,
        ))

    def load_semantic_metadata(self, *, workspace_id: str, working_tree_id: str, source_revision: str, backend_revision: str) -> list[dict[str, Any]]:
        workspace, tree = _identifier(workspace_id, name="workspace_id"), _identifier(working_tree_id, name="working_tree_id")
        revision, backend = _text(source_revision, name="source_revision", maximum=128, allow_empty=False), _identifier(backend_revision, name="backend_revision")
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM semantic_index_metadata WHERE workspace_id = ? AND working_tree_id = ? AND source_revision = ? AND backend_revision = ? ORDER BY path", (workspace, tree, revision, backend)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row); item["symbols"] = _decode(item.pop("symbols_json"), name="semantic_symbols"); item["edges"] = _decode(item.pop("edges_json"), name="semantic_edges")
            if not isinstance(item["symbols"], list) or not isinstance(item["edges"], list):
                raise PersistenceCorruptError("stored semantic metadata is invalid")
            result.append(item)
        return result

    def save_verification_cache_entry(self, value: object) -> None:
        record = _mapping(value, name="verification cache entry")
        allowed = {"cache_key", "worktree_id", "head_revision", "relevant_diff_hash", "command_fingerprint", "env_fingerprint", "dependency_fingerprint", "relevant_paths", "status", "result_digest", "output_summary", "created_at", "expires_at"}
        if set(record) - allowed:
            raise PersistenceError("verification cache entry contains unsupported fields")
        status = _text(record.get("status"), name="cache_status", maximum=32, allow_empty=False)
        if status not in {"passed", "failed", "timed_out"}:
            raise PersistenceError("cache_status is invalid")
        created_at, expires_at = _finite_number(record.get("created_at"), name="created_at"), _finite_number(record.get("expires_at"), name="expires_at")
        if expires_at <= created_at:
            raise PersistenceError("verification cache expiry is invalid")
        values = (_hash(record.get("cache_key"), name="cache_key", allow_empty=False), _identifier(record.get("worktree_id"), name="worktree_id"), _text(record.get("head_revision"), name="head_revision", maximum=128, allow_empty=False), _hash(record.get("relevant_diff_hash"), name="relevant_diff_hash", allow_empty=False), _hash(record.get("command_fingerprint"), name="command_fingerprint", allow_empty=False), _hash(record.get("env_fingerprint"), name="env_fingerprint", allow_empty=False), _hash(record.get("dependency_fingerprint"), name="dependency_fingerprint", allow_empty=False), _paths(record.get("relevant_paths"), name="relevant_paths"), status, _hash(record.get("result_digest"), name="result_digest", allow_empty=False), _text(record.get("output_summary", ""), name="output_summary", maximum=2048), created_at, expires_at)
        self.run_write(lambda connection: connection.execute(
            """INSERT INTO verification_cache(cache_key, worktree_id, head_revision, relevant_diff_hash, command_fingerprint, env_fingerprint, dependency_fingerprint, relevant_paths_json, status, result_digest, output_summary, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET relevant_paths_json=excluded.relevant_paths_json, status=excluded.status, result_digest=excluded.result_digest, output_summary=excluded.output_summary, created_at=excluded.created_at, expires_at=excluded.expires_at""", values))

    def load_verification_cache_entries(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM verification_cache ORDER BY created_at, cache_key").fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row); item["relevant_paths"] = _decode(item.pop("relevant_paths_json"), name="relevant_paths")
            if not isinstance(item["relevant_paths"], list):
                raise PersistenceCorruptError("stored verification cache paths are invalid")
            result.append(item)
        return result

    def delete_verification_cache_keys(self, keys: object) -> int:
        if not isinstance(keys, (list, tuple)):
            raise PersistenceError("cache keys must be a list")
        parsed = tuple(_hash(item, name="cache_key", allow_empty=False) for item in keys)
        if not parsed:
            return 0
        def write(connection: sqlite3.Connection) -> int:
            placeholders = ",".join("?" for _ in parsed)
            return int(connection.execute(f"DELETE FROM verification_cache WHERE cache_key IN ({placeholders})", parsed).rowcount)
        return int(self.run_write(write))

    def prune_verification_cache(self, *, now: float, max_entries: int) -> int:
        timestamp = _finite_number(now, name="cache_now")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= 10000:
            raise PersistenceError("max_entries is outside its safety bound")
        def write(connection: sqlite3.Connection) -> int:
            removed = int(connection.execute("DELETE FROM verification_cache WHERE expires_at <= ?", (timestamp,)).rowcount)
            count = int(connection.execute("SELECT COUNT(*) FROM verification_cache").fetchone()[0]); overflow = max(0, count - max_entries)
            if overflow:
                removed += int(connection.execute("DELETE FROM verification_cache WHERE cache_key IN (SELECT cache_key FROM verification_cache ORDER BY created_at, cache_key LIMIT ?)", (overflow,)).rowcount)
            return removed
        return int(self.run_write(write))

    def save_baseline_snapshot(self, value: object) -> None:
        record = _mapping(value, name="baseline snapshot")
        snapshot_id = _identifier(record.get("snapshot_id"), name="snapshot_id")
        workspace_id = _identifier(record.get("workspace_id"), name="workspace_id")
        values = (
            snapshot_id,
            workspace_id,
            _text(record.get("head_revision"), name="head_revision", maximum=128, allow_empty=False),
            _hash(record.get("tracked_patch_hash"), name="tracked_patch_hash", allow_empty=False),
            _paths(record.get("tracked_paths"), name="tracked_paths"),
            _hash(record.get("untracked_manifest_hash"), name="untracked_manifest_hash", allow_empty=False),
            _paths(record.get("untracked_paths"), name="untracked_paths"),
            _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False),
            _hash(record.get("snapshot_hash"), name="snapshot_hash", allow_empty=False),
            1 if bool(record.get("canonical_dirty", False)) else 0,
            _paths(record.get("included_paths"), name="included_paths"),
            _paths(record.get("excluded_paths"), name="excluded_paths"),
            _json(record.get("excluded_reasons"), name="excluded_reasons", default={}),
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT snapshot_hash FROM baseline_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if existing is not None and str(existing[0]) != values[8]:
                raise PersistenceError("snapshot id is already bound to different content")
            connection.execute(
                "INSERT INTO baseline_snapshots(snapshot_id, workspace_id, head_revision, tracked_patch_hash, tracked_paths_json, untracked_manifest_hash, untracked_paths_json, created_at, snapshot_hash, canonical_dirty, included_paths_json, excluded_paths_json, excluded_reasons_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(snapshot_id) DO NOTHING",
                values,
            )

        self.run_write(write)

    def load_baseline_snapshots(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute("SELECT * FROM baseline_snapshots ORDER BY created_at, snapshot_id").fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute(
                    "SELECT * FROM baseline_snapshots WHERE workspace_id = ? ORDER BY created_at, snapshot_id",
                    (workspace,),
                ).fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["tracked_paths"] = _decode(item.pop("tracked_paths_json"), name="tracked_paths")
            item["untracked_paths"] = _decode(item.pop("untracked_paths_json"), name="untracked_paths")
            item["included_paths"] = _decode(item.pop("included_paths_json"), name="included_paths")
            item["excluded_paths"] = _decode(item.pop("excluded_paths_json"), name="excluded_paths")
            item["excluded_reasons"] = _decode(item.pop("excluded_reasons_json"), name="excluded_reasons")
            item["canonical_dirty"] = bool(item["canonical_dirty"])
            result.append(item)
        return result

    def get_development_start_request(self, workspace_id: str, request_id: str) -> dict[str, Any] | None:
        workspace = _identifier(workspace_id, name="workspace_id")
        request = _identifier(request_id, name="request_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM development_start_requests WHERE workspace_id = ? AND request_id = ?",
                (workspace, request),
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        item["result"] = _decode(item.pop("result_json"), name="start_request_result")
        if not isinstance(item["result"], dict):
            raise PersistenceCorruptError("stored start request result is invalid")
        return item

    def claim_development_start_request(self, workspace_id: str, request_id: str, payload_hash: str) -> dict[str, Any]:
        workspace = _identifier(workspace_id, name="workspace_id")
        request = _identifier(request_id, name="request_id")
        digest = _hash(payload_hash, name="payload_hash", allow_empty=False)
        now = _utc_now()

        def write(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT * FROM development_start_requests WHERE workspace_id = ? AND request_id = ?",
                (workspace, request),
            ).fetchone()
            if row is not None:
                if str(row["payload_hash"]) != digest:
                    raise IdempotencyConflict("IDEMPOTENCY_CONFLICT")
                item = _row_dict(row)
                item["result"] = _decode(item.pop("result_json"), name="start_request_result")
                item["created"] = False
                return item
            connection.execute(
                "INSERT INTO development_start_requests(workspace_id, request_id, payload_hash, state, created_at, updated_at) VALUES (?, ?, ?, 'in_progress', ?, ?)",
                (workspace, request, digest, now, now),
            )
            return {
                "workspace_id": workspace,
                "request_id": request,
                "payload_hash": digest,
                "state": "in_progress",
                "task_id": None,
                "session_id": None,
                "lease_id": None,
                "working_tree_id": None,
                "result": {},
                "created": True,
            }

        return self.run_write(write)

    def update_development_start_request(
        self,
        workspace_id: str,
        request_id: str,
        *,
        state: str,
        task_id: str | None = None,
        session_id: str | None = None,
        lease_id: str | None = None,
        working_tree_id: str | None = None,
        result: Mapping[str, Any] | None = None,
    ) -> None:
        if state not in {"in_progress", "succeeded", "failed"}:
            raise PersistenceError("start request state is invalid")
        workspace = _identifier(workspace_id, name="workspace_id")
        request = _identifier(request_id, name="request_id")
        encoded = _json(result or {}, name="start_request_result", default={})
        values = (
            _optional_task_id(task_id),
            _text(session_id, name="session_id", maximum=256),
            _text(lease_id, name="lease_id", maximum=256),
            _text(working_tree_id, name="working_tree_id", maximum=256),
            encoded,
            state,
            _utc_now(),
            workspace,
            request,
        )
        self.run_write(
            lambda conn: conn.execute(
                "UPDATE development_start_requests SET task_id = ?, session_id = ?, lease_id = ?, working_tree_id = ?, result_json = ?, state = ?, updated_at = ? WHERE workspace_id = ? AND request_id = ?",
                values,
            )
        )

    @staticmethod
    def _decode_session_archive_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        item = _row_dict(row) if isinstance(row, sqlite3.Row) else dict(row)
        aliases = _decode(item.pop("alias_session_ids_json"), name="session_archive_aliases")
        if not isinstance(aliases, list) or not all(isinstance(value, str) for value in aliases):
            raise PersistenceCorruptError("stored session archive aliases are invalid")
        item["alias_session_ids"] = aliases
        return item

    def save_session_archive_receipt(self, value: object) -> None:
        record = _mapping(value, name="session archive receipt")
        archive_id = _identifier(record.get("archive_id"), name="archive_id")
        schema_version = record.get("schema_version")
        payload_bytes = record.get("payload_bytes")
        if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version < 1:
            raise PersistenceError("session archive schema_version is invalid")
        if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or payload_bytes < 0:
            raise PersistenceError("session archive payload_bytes is invalid")
        alias_values = record.get("alias_session_ids")
        if not isinstance(alias_values, (list, tuple)) or not alias_values:
            raise PersistenceError("session archive alias_session_ids must be non-empty")
        aliases = sorted({_identifier(value, name="alias_session_id") for value in alias_values})
        if len(aliases) != len(alias_values):
            raise PersistenceError("session archive alias_session_ids contains duplicates")

        values = (
            archive_id,
            schema_version,
            _identifier(record.get("project_id"), name="project_id"),
            _identifier(record.get("logical_workspace_id"), name="logical_workspace_id"),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _identifier(record.get("physical_worktree_id"), name="physical_worktree_id"),
            _text(record.get("source_revision"), name="source_revision", maximum=128, allow_empty=False),
            _text(record.get("base_revision"), name="base_revision", maximum=128, allow_empty=False),
            _hash(record.get("state_hash"), name="state_hash", allow_empty=False),
            _hash(record.get("patch_hash"), name="patch_hash", allow_empty=False),
            _hash(record.get("manifest_hash"), name="manifest_hash", allow_empty=False),
            _text(record.get("archive_path"), name="archive_path", maximum=4096, allow_empty=False),
            _json(aliases, name="session_archive_aliases", default=[]),
            payload_bytes,
            _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False),
            _text(record.get("verified_at"), name="verified_at", maximum=128, allow_empty=False),
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT archive_id, schema_version, project_id, logical_workspace_id, workspace_id, physical_worktree_id, source_revision, base_revision, state_hash, patch_hash, manifest_hash, archive_path, alias_session_ids_json, payload_bytes, created_at, verified_at FROM session_archives WHERE archive_id = ?",
                (archive_id,),
            ).fetchone()
            if existing is not None:
                existing_values = tuple(existing[index] for index in range(len(values)))
                if existing_values != values:
                    raise PersistenceError("session archive id already exists with different immutable content")
                return
            connection.execute(
                "INSERT INTO session_archives(archive_id, schema_version, project_id, logical_workspace_id, workspace_id, physical_worktree_id, source_revision, base_revision, state_hash, patch_hash, manifest_hash, archive_path, alias_session_ids_json, payload_bytes, created_at, verified_at, pruned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                values,
            )

        self.run_write(write)

    def load_session_archive_receipts(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if project_id is None:
                rows = connection.execute(
                    "SELECT * FROM session_archives ORDER BY created_at, archive_id"
                ).fetchall()
            else:
                project = _identifier(project_id, name="project_id")
                rows = connection.execute(
                    "SELECT * FROM session_archives WHERE project_id = ? ORDER BY created_at, archive_id",
                    (project,),
                ).fetchall()
        return [self._decode_session_archive_row(row) for row in rows]

    def get_session_archive_receipt(self, archive_id: str) -> dict[str, Any] | None:
        archive = _identifier(archive_id, name="archive_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM session_archives WHERE archive_id = ?", (archive,)
            ).fetchone()
        return self._decode_session_archive_row(row) if row is not None else None

    def find_session_archive_by_session_id(self, session_id: str) -> dict[str, Any] | None:
        target = _identifier(session_id, name="session_id")
        matches = [
            receipt
            for receipt in self.load_session_archive_receipts()
            if target in receipt["alias_session_ids"]
        ]
        if len(matches) > 1:
            raise PersistenceCorruptError("session id is mapped to multiple durable archives")
        return matches[0] if matches else None

    def mark_session_archive_pruned(self, archive_id: str, *, pruned_at: str) -> None:
        archive = _identifier(archive_id, name="archive_id")
        timestamp = _text(pruned_at, name="pruned_at", maximum=128, allow_empty=False)

        def write(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT pruned_at FROM session_archives WHERE archive_id = ?", (archive,)
            ).fetchone()
            if row is None:
                raise PersistenceError("session archive receipt does not exist")
            existing = row[0]
            if existing is not None and existing != timestamp:
                raise PersistenceError("session archive prune timestamp already differs")
            connection.execute(
                "UPDATE session_archives SET pruned_at = ? WHERE archive_id = ?",
                (timestamp, archive),
            )

        self.run_write(write)

    def record_session_archive_restore(
        self,
        archive_id: str,
        *,
        original_session_id: str,
        restored_session_id: str,
        restored_at: str,
    ) -> None:
        archive = _identifier(archive_id, name="archive_id")
        original = _identifier(original_session_id, name="original_session_id")
        restored = _identifier(restored_session_id, name="restored_session_id")
        timestamp = _text(restored_at, name="restored_at", maximum=128, allow_empty=False)
        restore_id = _identifier(f"restore:{archive}:{restored}", name="restore_id")
        values = (restore_id, archive, original, restored, timestamp)

        def write(connection: sqlite3.Connection) -> None:
            archive_row = connection.execute(
                "SELECT alias_session_ids_json FROM session_archives WHERE archive_id = ?", (archive,)
            ).fetchone()
            if archive_row is None:
                raise PersistenceError("session archive receipt does not exist")
            aliases = _decode(archive_row[0], name="session_archive_aliases")
            if not isinstance(aliases, list) or original not in aliases:
                raise PersistenceError("restore original session is not part of the archive lineage")
            existing = connection.execute(
                "SELECT restore_id, archive_id, original_session_id, restored_session_id, restored_at FROM session_archive_restores WHERE restore_id = ?",
                (restore_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing[index] for index in range(len(values))) != values:
                    raise PersistenceError("session archive restore id already differs")
                return
            connection.execute(
                "INSERT INTO session_archive_restores(restore_id, archive_id, original_session_id, restored_session_id, restored_at) VALUES (?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_session_archive_restores(self, archive_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if archive_id is None:
                rows = connection.execute(
                    "SELECT * FROM session_archive_restores ORDER BY restored_at, restore_id"
                ).fetchall()
            else:
                archive = _identifier(archive_id, name="archive_id")
                rows = connection.execute(
                    "SELECT * FROM session_archive_restores WHERE archive_id = ? ORDER BY restored_at, restore_id",
                    (archive,),
                ).fetchall()
        return [_row_dict(row) for row in rows]

    @staticmethod
    def _decode_session_reconciliation_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        item = _row_dict(row) if isinstance(row, sqlite3.Row) else dict(row)
        for column, name in (
            ("git_metadata_json", "git_metadata"),
            ("task_state_json", "task_state"),
            ("lease_state_json", "lease_state"),
            ("process_state_json", "process_state"),
            ("archive_state_json", "archive_state"),
            ("sqlite_state_json", "sqlite_state"),
            ("preservation_actions_json", "preservation_actions"),
            ("reason_codes_json", "reason_codes"),
            ("evidence_json", "evidence"),
        ):
            decoded = _decode(item.pop(column), name=name)
            item[name] = decoded
        raw = item.get("sidecar_bytes", b"")
        if isinstance(raw, memoryview):
            raw = raw.tobytes()
        if not isinstance(raw, bytes):
            raise PersistenceCorruptError("stored reconciliation sidecar bytes are invalid")
        item["sidecar_bytes"] = raw
        item["worktree_exists"] = bool(item["worktree_exists"])
        item["worktree_dirty"] = bool(item["worktree_dirty"])
        return item

    def save_session_reconciliation_receipt(self, value: object) -> None:
        """Persist one immutable reconciliation evidence receipt.

        The receipt is intentionally independent of ``development_sessions``:
        a sidecar may outlive a row after a crash or an old runtime.  Duplicate
        writes are accepted only when every immutable field is byte-identical.
        """

        record = _mapping(value, name="session reconciliation receipt")
        reconciliation_id = _identifier(record.get("reconciliation_id"), name="reconciliation_id", maximum=256)
        schema_version = record.get("schema_version", 1)
        if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version < 1:
            raise PersistenceError("reconciliation schema_version is invalid")
        session_id = _identifier(record.get("session_id"), name="session_id", maximum=256)
        workspace_id = _identifier(record.get("workspace_id"), name="workspace_id", maximum=256)
        classification = _text(record.get("classification"), name="classification", maximum=80, allow_empty=False)
        transition = _text(record.get("proposed_transition"), name="proposed_transition", maximum=80, allow_empty=False)
        state_digest = _hash(record.get("state_digest"), name="state_digest", allow_empty=False)
        sidecar_path = _text(record.get("sidecar_path"), name="sidecar_path", maximum=4096)
        sidecar_root = _text(record.get("sidecar_root"), name="sidecar_root", maximum=4096)
        sidecar_digest = _hash(record.get("sidecar_digest"), name="sidecar_digest")
        raw_sidecar = record.get("sidecar_bytes", b"")
        if isinstance(raw_sidecar, bytearray):
            raw_sidecar = bytes(raw_sidecar)
        if not isinstance(raw_sidecar, bytes) or len(raw_sidecar) > MAX_RECONCILIATION_SIDECAR_BYTES:
            raise PersistenceError("reconciliation sidecar bytes are outside the safety bound")
        try:
            raw_text = raw_sidecar.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PersistenceError("reconciliation sidecar bytes must be UTF-8") from exc
        if contains_secret_like_content(raw_text):
            raise PersistenceError("reconciliation sidecar bytes contain secret-like content")
        if raw_sidecar and hashlib.sha256(raw_sidecar).hexdigest() != sidecar_digest:
            raise PersistenceError("reconciliation sidecar digest does not match bytes")
        values = (
            reconciliation_id,
            schema_version,
            session_id,
            workspace_id,
            classification,
            transition,
            state_digest,
            sidecar_path,
            sidecar_root,
            sidecar_digest,
            sqlite3.Binary(raw_sidecar),
            _text(record.get("sidecar_updated_at"), name="sidecar_updated_at", maximum=128),
            _text(record.get("source_revision"), name="source_revision", maximum=128),
            _text(record.get("source_path"), name="source_path", maximum=4096),
            (int(record["source_device"]) if record.get("source_device") is not None else None),
            (int(record["source_inode"]) if record.get("source_inode") is not None else None),
            _text(record.get("worktree_path"), name="worktree_path", maximum=4096),
            1 if bool(record.get("worktree_exists", False)) else 0,
            1 if bool(record.get("worktree_dirty", False)) else 0,
            _text(record.get("worktree_head"), name="worktree_head", maximum=128),
            _text(record.get("worktree_branch"), name="worktree_branch", maximum=512),
            (int(record["worktree_device"]) if record.get("worktree_device") is not None else None),
            (int(record["worktree_inode"]) if record.get("worktree_inode") is not None else None),
            _json(record.get("git_metadata"), name="git_metadata", default={}),
            _json(record.get("task_state"), name="task_state", default={}),
            _json(record.get("lease_state"), name="lease_state", default={}),
            _json(record.get("process_state"), name="process_state", default={}),
            _json(record.get("archive_state"), name="archive_state", default={}),
            _json(record.get("sqlite_state"), name="sqlite_state", default={}),
            _json(record.get("preservation_actions"), name="preservation_actions", default=[]),
            _json(record.get("reason_codes"), name="reason_codes", default=[]),
            _json(record.get("evidence"), name="evidence", default={}),
            _text(record.get("recorded_at"), name="recorded_at", maximum=128, allow_empty=False),
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT reconciliation_id, schema_version, session_id, workspace_id, classification, "
                "proposed_transition, state_digest, sidecar_path, sidecar_root, sidecar_digest, sidecar_bytes, "
                "sidecar_updated_at, source_revision, source_path, source_device, source_inode, worktree_path, "
                "worktree_exists, worktree_dirty, worktree_head, worktree_branch, worktree_device, worktree_inode, "
                "git_metadata_json, task_state_json, lease_state_json, process_state_json, archive_state_json, "
                "sqlite_state_json, preservation_actions_json, reason_codes_json, evidence_json, recorded_at "
                "FROM session_reconciliation_receipts WHERE reconciliation_id = ?",
                (reconciliation_id,),
            ).fetchone()
            if existing is not None:
                existing_values = tuple(existing[index] for index in range(len(values)))
                if existing_values != values:
                    raise PersistenceError("reconciliation receipt id already exists with different immutable content")
                return
            connection.execute(
                "INSERT INTO session_reconciliation_receipts("
                "reconciliation_id, schema_version, session_id, workspace_id, classification, proposed_transition, "
                "state_digest, sidecar_path, sidecar_root, sidecar_digest, sidecar_bytes, sidecar_updated_at, "
                "source_revision, source_path, source_device, source_inode, worktree_path, worktree_exists, "
                "worktree_dirty, worktree_head, worktree_branch, worktree_device, worktree_inode, git_metadata_json, "
                "task_state_json, lease_state_json, process_state_json, archive_state_json, sqlite_state_json, "
                "preservation_actions_json, reason_codes_json, evidence_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def get_session_reconciliation_receipt(self, reconciliation_id: str) -> dict[str, Any] | None:
        identifier = _identifier(reconciliation_id, name="reconciliation_id", maximum=256)
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM session_reconciliation_receipts WHERE reconciliation_id = ?", (identifier,)
            ).fetchone()
        return self._decode_session_reconciliation_row(row) if row is not None else None

    def find_session_reconciliation_receipt(
        self,
        session_id: str,
        *,
        state_digest: str | None = None,
    ) -> dict[str, Any] | None:
        target = _identifier(session_id, name="session_id", maximum=256)
        digest = _hash(state_digest, name="state_digest", allow_empty=False) if state_digest is not None else None
        with self._transaction(write=False) as connection:
            if digest is None:
                row = connection.execute(
                    "SELECT * FROM session_reconciliation_receipts WHERE session_id = "
                    "? ORDER BY recorded_at DESC, reconciliation_id DESC LIMIT 1",
                    (target,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM session_reconciliation_receipts WHERE session_id = ? AND state_digest = ? "
                    "ORDER BY recorded_at DESC, reconciliation_id DESC LIMIT 1",
                    (target, digest),
                ).fetchone()
        return self._decode_session_reconciliation_row(row) if row is not None else None

    def load_session_reconciliation_receipts(self, session_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if session_id is None:
                rows = connection.execute(
                    "SELECT * FROM session_reconciliation_receipts ORDER BY recorded_at, reconciliation_id"
                ).fetchall()
            else:
                target = _identifier(session_id, name="session_id", maximum=256)
                rows = connection.execute(
                    "SELECT * FROM session_reconciliation_receipts WHERE session_id = ? "
                    "ORDER BY recorded_at, reconciliation_id",
                    (target,),
                ).fetchall()
        return [self._decode_session_reconciliation_row(row) for row in rows]

    def import_evidence_generation(
        self,
        *,
        import_id: str,
        source_generation: str,
        source_database_sha256: str,
        source_schema_version: int,
        session_id: str,
        task_ids: object,
        record_hashes: object,
        source_state: object,
        destination_state: object,
        imported_at: str,
        records: Mapping[str, object],
    ) -> dict[str, Any]:
        """Atomically import a bounded, already-authorized evidence closure.

        The source database is never opened by this method.  Rows are written
        through the persistence boundary in one transaction, with immutable
        identity collision checks before any new row is committed.  This is
        intentionally not a database copier or an ATTACH/INSERT bridge.
        """

        normalized_import_id = _identifier(import_id, name="evidence_import_id", maximum=256)
        normalized_generation = _text(source_generation, name="source_generation", maximum=32, allow_empty=False)
        normalized_source_hash = _hash(source_database_sha256, name="source_database_sha256", allow_empty=False)
        if isinstance(source_schema_version, bool) or not isinstance(source_schema_version, int) or source_schema_version < 1:
            raise PersistenceError("source schema version is invalid")
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            raise PersistenceError("destination schema version is not current")
        normalized_session_id = _identifier(session_id, name="session_id")
        if not isinstance(task_ids, (list, tuple)) or any(not isinstance(item, str) for item in task_ids):
            raise PersistenceError("evidence import task_ids are invalid")
        normalized_task_ids = sorted(set(task_ids))
        if any(not item for item in normalized_task_ids):
            raise PersistenceError("evidence import task_ids are invalid")
        normalized_record_hashes = _mapping(record_hashes, name="record_hashes")
        normalized_source_state = _mapping(source_state, name="source_state")
        normalized_destination_state = _mapping(destination_state, name="destination_state")
        normalized_imported_at = _text(imported_at, name="imported_at", maximum=128, allow_empty=False)
        if not isinstance(records, Mapping):
            raise PersistenceError("evidence import records are invalid")

        for table in records:
            if table not in _EVIDENCE_IMPORT_TABLES:
                raise PersistenceError("evidence import table is not allowlisted")
            rows = records[table]
            if not isinstance(rows, (list, tuple)) or any(not isinstance(row, Mapping) for row in rows):
                raise PersistenceError("evidence import rows are invalid")

        if set(normalized_record_hashes) != set(records):
            raise PersistenceError("evidence import record hashes do not cover the supplied tables")
        for table, rows in records.items():
            expected_hash = normalized_record_hashes.get(table)
            if not isinstance(expected_hash, str) or not _HASH_RE.fullmatch(expected_hash):
                raise PersistenceError("evidence import record hash is invalid")
            if _import_rows_hash(rows) != expected_hash:
                raise PersistenceError("evidence import record hash mismatch")
        if not isinstance(normalized_source_state.get("workspace_id"), str) or not normalized_source_state["workspace_id"]:
            raise PersistenceError("evidence import source workspace identity is required")

        task_ids_json = _json(normalized_task_ids, name="evidence_task_ids", default=[])
        record_hashes_json = _json(dict(normalized_record_hashes), name="evidence_record_hashes", default={})
        source_state_json = _json(dict(normalized_source_state), name="evidence_source_state", default={})
        destination_state_json = _json(dict(normalized_destination_state), name="evidence_destination_state", default={})

        def quote_identifier(value: str) -> str:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                raise PersistenceError("evidence import identifier is invalid")
            return '"' + value + '"'

        def write(connection: sqlite3.Connection) -> dict[str, Any]:
            inserted = 0
            existing = 0
            # Parents precede child rows so SQLite foreign keys remain active.
            order = tuple(table for table in _EVIDENCE_IMPORT_TABLES if table in records)
            for table in order:
                primary_key = _EVIDENCE_IMPORT_PRIMARY_KEYS[table]
                columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({quote_identifier(table)})").fetchall()]
                identity_columns = (primary_key,) if isinstance(primary_key, str) else tuple(primary_key)
                if any(column not in columns for column in identity_columns):
                    raise PersistenceError(f"evidence import table is missing its primary key: {table}")
                quoted_table = quote_identifier(table)
                for raw in records[table]:
                    row = dict(raw)
                    if any(not isinstance(column, str) for column in row):
                        raise PersistenceError(f"evidence import row columns are invalid: {table}")
                    if set(row) - set(columns) or any(column not in row for column in identity_columns):
                        raise PersistenceError(f"evidence import row shape is invalid: {table}")
                    for column, value in row.items():
                        row[column] = _import_value(value, name=f"evidence import {table}.{column}")
                    row_workspace = row.get("workspace_id")
                    if row_workspace is not None and row_workspace != normalized_source_state["workspace_id"]:
                        raise PersistenceError("WORKSPACE_IDENTITY_MISMATCH")
                    keys = tuple(row[column] for column in identity_columns)
                    if any(not isinstance(key, (str, int)) or (isinstance(key, str) and not key) for key in keys):
                        raise PersistenceError(f"evidence import row identity is invalid: {table}")
                    where_clause = " AND ".join(f"{quote_identifier(column)} = ?" for column in identity_columns)
                    existing_row = connection.execute(
                        f"SELECT * FROM {quoted_table} WHERE {where_clause}",
                        keys,
                    ).fetchone()
                    if existing_row is not None:
                        for column, value in row.items():
                            if existing_row[column] != value:
                                raise PersistenceError("EVIDENCE_IDENTITY_CONFLICT")
                        existing += 1
                        continue
                    insert_columns = list(row)
                    placeholders = ", ".join("?" for _ in insert_columns)
                    sql = (
                        f"INSERT INTO {quoted_table} ({', '.join(quote_identifier(column) for column in insert_columns)}) "
                        f"VALUES ({placeholders})"
                    )
                    try:
                        connection.execute(sql, tuple(row[column] for column in insert_columns))
                    except sqlite3.IntegrityError as exc:
                        # A duplicate natural identity (for example the
                        # workspace/request uniqueness constraint on a task)
                        # is a content collision, not permission to rewrite
                        # the existing row.
                        raise PersistenceError("EVIDENCE_IDENTITY_CONFLICT") from exc
                    inserted += 1

            imported_task_ids = {
                str(row.get("task_id"))
                for row in records.get("task_ledger", ())
                if row.get("task_id") is not None
            }
            if imported_task_ids != set(normalized_task_ids):
                raise PersistenceError("evidence import task ids do not match task records")
            imported_sessions = {
                str(row.get("session_id"))
                for row in records.get("development_sessions", ())
                if row.get("session_id") is not None
            }
            if normalized_session_id not in imported_sessions:
                raise PersistenceError("evidence import session record is missing")

            receipt_values = (
                normalized_import_id,
                normalized_generation,
                normalized_source_hash,
                source_schema_version,
                CURRENT_SCHEMA_VERSION,
                normalized_session_id,
                task_ids_json,
                record_hashes_json,
                source_state_json,
                destination_state_json,
                normalized_imported_at,
            )
            current_receipt = connection.execute(
                "SELECT * FROM evidence_generation_imports WHERE import_id = ?",
                (normalized_import_id,),
            ).fetchone()
            if current_receipt is not None:
                expected = dict(zip(
                    ("import_id", "source_generation", "source_database_sha256", "source_schema_version", "destination_schema_version", "session_id", "task_ids_json", "record_hashes_json", "source_state_json", "destination_state_json", "imported_at"),
                    receipt_values,
                ))
                # Destination hash and timestamp are observations of the
                # first successful import, not immutable identity.  A later
                # preflight necessarily observes the database after that
                # import and must therefore remain idempotent.
                immutable_keys = (
                    "import_id",
                    "source_generation",
                    "source_database_sha256",
                    "source_schema_version",
                    "destination_schema_version",
                    "session_id",
                    "task_ids_json",
                    "record_hashes_json",
                    "source_state_json",
                )
                if any(current_receipt[key] != expected[key] for key in immutable_keys):
                    raise PersistenceError("EVIDENCE_IDENTITY_CONFLICT")
                status = "ALREADY_IMPORTED_IDENTICAL"
            else:
                connection.execute(
                    "INSERT INTO evidence_generation_imports(import_id, source_generation, source_database_sha256, source_schema_version, destination_schema_version, session_id, task_ids_json, record_hashes_json, source_state_json, destination_state_json, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    receipt_values,
                )
                status = "IMPORTED"
            return {
                "status": status,
                "import_id": normalized_import_id,
                "session_id": normalized_session_id,
                "task_ids": normalized_task_ids,
                "records_inserted": inserted,
                "records_existing": existing,
            }

        return self.run_write(write)

    def load_evidence_generation_imports(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Read generation-import provenance with strict JSON decoding."""

        with self._transaction(write=False) as connection:
            if session_id is None:
                rows = connection.execute(
                    "SELECT * FROM evidence_generation_imports ORDER BY imported_at, import_id"
                ).fetchall()
            else:
                key = _identifier(session_id, name="session_id")
                rows = connection.execute(
                    "SELECT * FROM evidence_generation_imports WHERE session_id = ? ORDER BY imported_at, import_id",
                    (key,),
                ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["task_ids"] = _decode(item.pop("task_ids_json"), name="evidence_task_ids")
            item["record_hashes"] = _decode(item.pop("record_hashes_json"), name="evidence_record_hashes")
            item["source_state"] = _decode(item.pop("source_state_json"), name="evidence_source_state")
            item["destination_state"] = _decode(item.pop("destination_state_json"), name="evidence_destination_state")
            result.append(item)
        return result

    def save_development_session(self, value: object) -> None:
        record = _mapping(value, name="development session")
        session_id = _identifier(record.get("session_id"), name="session_id")
        project_id = _identifier(record.get("project_id"), name="project_id")
        logical_workspace_id = _identifier(record.get("logical_workspace_id"), name="logical_workspace_id")
        worktree_id = _identifier(record.get("worktree_id"), name="worktree_id")
        workspace_id = _identifier(record.get("workspace_id"), name="workspace_id")
        values = (
            session_id, project_id, logical_workspace_id, worktree_id, workspace_id,
            _text(record.get("candidate_id"), name="candidate_id", maximum=256),
            _text(record.get("source_revision"), name="source_revision", maximum=128, allow_empty=False),
            _text(record.get("base_commit"), name="base_commit", maximum=128, allow_empty=False),
            _text(record.get("root_path"), name="root_path", maximum=1024, allow_empty=False),
            _optional_task_id(record.get("task_id")),
            _text(record.get("owner_id"), name="owner_id", maximum=256),
            1 if bool(record.get("source_dirty", False)) else 0,
            _finite_number(record.get("created_at"), name="created_at"),
            _finite_number(record.get("expires_at"), name="expires_at"),
            _text(record.get("lifecycle_state", "stale"), name="lifecycle_state", maximum=64, allow_empty=False),
            1 if bool(record.get("stale", False)) else 0,
            _json(record.get("metadata"), name="session_metadata", default={}),
        )
        self.run_write(
            lambda conn: conn.execute(
                "INSERT INTO development_sessions(session_id, project_id, logical_workspace_id, worktree_id, workspace_id, candidate_id, source_revision, base_commit, root_path, task_id, owner_id, source_dirty, created_at, expires_at, lifecycle_state, stale, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET project_id=excluded.project_id, logical_workspace_id=excluded.logical_workspace_id, worktree_id=excluded.worktree_id, workspace_id=excluded.workspace_id, candidate_id=excluded.candidate_id, source_revision=excluded.source_revision, base_commit=excluded.base_commit, root_path=excluded.root_path, task_id=excluded.task_id, owner_id=excluded.owner_id, source_dirty=excluded.source_dirty, created_at=excluded.created_at, expires_at=excluded.expires_at, lifecycle_state=excluded.lifecycle_state, stale=excluded.stale, metadata_json=excluded.metadata_json",
                values,
            )
        )

    def load_development_sessions(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if project_id is None:
                rows = connection.execute("SELECT * FROM development_sessions ORDER BY created_at, session_id").fetchall()
            else:
                project = _identifier(project_id, name="project_id")
                rows = connection.execute("SELECT * FROM development_sessions WHERE project_id = ? ORDER BY created_at, session_id", (project,)).fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["source_dirty"] = bool(item["source_dirty"])
            item["stale"] = bool(item["stale"])
            item["metadata"] = _decode(item.pop("metadata_json"), name="session_metadata")
            if not isinstance(item["metadata"], dict):
                raise PersistenceCorruptError("stored session metadata is invalid")
            result.append(item)
        return result

    def update_development_session_state(self, session_id: str, state: str, *, stale: bool = True) -> None:
        self.run_write(
            lambda conn: conn.execute(
                "UPDATE development_sessions SET lifecycle_state = ?, stale = ? WHERE session_id = ?",
                (_text(state, name="lifecycle_state", maximum=64, allow_empty=False), 1 if stale else 0, _identifier(session_id, name="session_id")),
            )
        )

    def save_task_process_binding(self, value: object) -> None:
        """Persist only the exact identity needed to route a task process."""

        record = _task_process_binding_record(value)
        values = (
            record["process_session_id"],
            record["workspace_id"],
            record["working_tree_id"],
            record["development_session_id"],
            record["runtime_capability_epoch"],
            record["upstream_runtime_id"],
            record["created_at"],
            record["expires_at"],
            record["state"],
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT * FROM task_process_bindings WHERE process_session_id = ?",
                (record["process_session_id"],),
            ).fetchone()
            if existing is not None:
                existing_record = _task_process_binding_record(_row_dict(existing))
                immutable_fields = (
                    "workspace_id",
                    "working_tree_id",
                    "development_session_id",
                    "runtime_capability_epoch",
                    "upstream_runtime_id",
                )
                if any(existing_record[field] != record[field] for field in immutable_fields):
                    raise PersistenceError("task process binding identity conflict")
                if existing_record["state"] in {"terminal", "stale"} and record["state"] == "active":
                    raise PersistenceError("terminal task process binding cannot be reactivated")
                connection.execute(
                    "UPDATE task_process_bindings SET created_at = ?, expires_at = ?, state = ? WHERE process_session_id = ?",
                    (record["created_at"], record["expires_at"], record["state"], record["process_session_id"]),
                )
                return
            connection.execute(
                "INSERT INTO task_process_bindings(process_session_id, workspace_id, working_tree_id, development_session_id, runtime_capability_epoch, upstream_runtime_id, created_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_task_process_binding(self, process_session_id: str) -> dict[str, Any] | None:
        key = _process_session_identifier(process_session_id)
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM task_process_bindings WHERE process_session_id = ?",
                (key,),
            ).fetchone()
        return _task_process_binding_record(_row_dict(row)) if row is not None else None

    def load_task_process_bindings(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT * FROM task_process_bindings ORDER BY created_at, process_session_id"
            ).fetchall()
        return [_task_process_binding_record(_row_dict(row)) for row in rows]

    def update_task_process_binding_state(self, process_session_id: str, state: str) -> None:
        key = _process_session_identifier(process_session_id)
        normalized_state = _text(state, name="state", maximum=32, allow_empty=False)
        if normalized_state not in _TASK_PROCESS_BINDING_STATES:
            raise PersistenceError("task process binding state is invalid")

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT state FROM task_process_bindings WHERE process_session_id = ?",
                (key,),
            ).fetchone()
            if existing is not None and existing[0] in {"terminal", "stale"} and normalized_state == "active":
                raise PersistenceError("terminal task process binding cannot be reactivated")
            connection.execute(
                "UPDATE task_process_bindings SET state = ? WHERE process_session_id = ?",
                (normalized_state, key),
            )

        self.run_write(write)

    def delete_task_process_binding(self, process_session_id: str) -> None:
        key = _process_session_identifier(process_session_id)
        self.run_write(
            lambda conn: conn.execute(
                "DELETE FROM task_process_bindings WHERE process_session_id = ?",
                (key,),
            )
        )

    def purge_task_process_bindings(self, *, now: float | None = None) -> int:
        cutoff = _finite_number(time.time() if now is None else now, name="now")
        with self._transaction(write=True) as connection:
            result = connection.execute(
                "DELETE FROM task_process_bindings WHERE state IN ('terminal', 'stale') OR expires_at <= ?",
                (cutoff,),
            ).rowcount
        return int(result)

    def save_task(self, value: object) -> None:
        record = _mapping(value, name="task")
        task_id = _identifier(record.get("task_id"), name="task_id")
        request_id = _identifier(record.get("request_id", task_id), name="request_id")
        title = _text(record.get("title", "task"), name="title", maximum=512, allow_empty=False)
        workspace = _identifier(record.get("workspace_id"), name="workspace_id")
        state = _text(record.get("state", record.get("status", "queued")), name="state", maximum=32, allow_empty=False)
        if state not in _STATES:
            raise PersistenceError("task state is invalid")
        owner = _text(record.get("owner_id"), name="owner_id", maximum=256)
        values = (
            task_id,
            request_id,
            title,
            owner,
            workspace,
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256),
            _text(record.get("development_session_id"), name="development_session_id", maximum=256),
            _paths(record.get("allowed_paths"), name="allowed_paths"),
            _json(record.get("resources"), name="resources", default=[]),
            _json(record.get("dependencies"), name="dependencies", default=[]),
            _text(record.get("lease_id"), name="lease_id", maximum=256),
            _text(record.get("base_revision"), name="base_revision", maximum=256),
            _hash(record.get("patch_hash"), name="patch_hash"),
            state,
            _text(record.get("context_pack_id"), name="context_pack_id", maximum=256),
            _text(record.get("verification_receipt_id", record.get("verification_receipt")), name="verification_receipt_id", maximum=256),
            _text(record.get("security_audit_receipt_id", record.get("security_audit_receipt")), name="security_audit_receipt_id", maximum=256),
            _text(record.get("integration_receipt_id", record.get("integration_receipt")), name="integration_receipt_id", maximum=256),
            _text(record.get("git_commit_receipt_id", record.get("git_commit_receipt")), name="git_commit_receipt_id", maximum=256),
            _text(record.get("git_push_receipt_id", record.get("git_push_receipt")), name="git_push_receipt_id", maximum=256),
            _text(record.get("result"), name="result"),
            _text(record.get("detail"), name="detail"),
            _text(record.get("result_ref"), name="result_ref", maximum=1024),
            _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False),
            _text(record.get("updated_at"), name="updated_at", maximum=128, allow_empty=False),
        )
        def write(connection: sqlite3.Connection) -> None:
            if state in {"succeeded", "failed", "cancelled", "blocked"} and values[5]:
                live_lease = connection.execute(
                    "SELECT lease_id FROM writer_leases "
                    "WHERE task_id = ? AND workspace_id = ? AND working_tree_id = ? "
                    "AND state = 'active' AND expires_at > ? LIMIT 1",
                    (task_id, workspace, values[5], time.time()),
                ).fetchone()
                if live_lease is not None:
                    raise PersistenceError("task cannot become terminal while writer lease is active")
            connection.execute(
                "INSERT INTO task_ledger(task_id, request_id, title, owner_id, workspace_id, working_tree_id, development_session_id, allowed_paths_json, resources_json, dependencies_json, lease_id, base_revision, patch_hash, state, context_pack_id, verification_receipt_id, security_audit_receipt_id, integration_receipt_id, git_commit_receipt_id, git_push_receipt_id, result, detail, result_ref, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(task_id) DO UPDATE SET request_id=excluded.request_id, title=excluded.title, owner_id=excluded.owner_id, workspace_id=excluded.workspace_id, working_tree_id=excluded.working_tree_id, development_session_id=excluded.development_session_id, allowed_paths_json=excluded.allowed_paths_json, resources_json=excluded.resources_json, dependencies_json=excluded.dependencies_json, lease_id=excluded.lease_id, base_revision=excluded.base_revision, patch_hash=excluded.patch_hash, state=excluded.state, context_pack_id=excluded.context_pack_id, verification_receipt_id=excluded.verification_receipt_id, security_audit_receipt_id=excluded.security_audit_receipt_id, integration_receipt_id=excluded.integration_receipt_id, git_commit_receipt_id=excluded.git_commit_receipt_id, git_push_receipt_id=excluded.git_push_receipt_id, result=excluded.result, detail=excluded.detail, result_ref=excluded.result_ref, updated_at=excluded.updated_at",
                values,
            )

        self.run_write(write)

    def load_tasks(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute("SELECT * FROM task_ledger ORDER BY created_at, task_id").fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute("SELECT * FROM task_ledger WHERE workspace_id = ? ORDER BY created_at, task_id", (workspace,)).fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["allowed_paths"] = _decode(item.pop("allowed_paths_json"), name="allowed_paths")
            item["resources"] = _decode(item.pop("resources_json"), name="resources")
            item["dependencies"] = _decode(item.pop("dependencies_json", "[]"), name="dependencies")
            if item["state"] not in _STATES or not isinstance(item["allowed_paths"], list) or not isinstance(item["resources"], list) or not isinstance(item["dependencies"], list):
                raise PersistenceCorruptError("stored task state is invalid")
            item["status"] = item["state"]
            result.append(item)
        return result

    def save_lease(self, value: object, *, state: str | None = None) -> None:
        record = _mapping(value, name="lease")
        lease_id = _identifier(record.get("lease_id"), name="lease_id")
        lease_state = state or str(record.get("state", "active"))
        if lease_state not in _LEASE_STATES:
            raise PersistenceError("lease state is invalid")
        values = (
            lease_id,
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _identifier(record.get("working_tree_id"), name="working_tree_id"),
            _optional_task_id(record.get("task_id")),
            _identifier(record.get("owner_id"), name="owner_id"),
            _paths(record.get("paths"), name="paths"),
            _json(record.get("resources"), name="resources", default=[]),
            _text(record.get("base_revision"), name="base_revision", maximum=256),
            _scope_hashes(record.get("scope_hashes")),
            _hash(record.get("workspace_state_hash"), name="workspace_state_hash"),
            1 if bool(record.get("workspace_wide", False)) else 0,
            _finite_number(record.get("acquired_at"), name="acquired_at", default=time.time()),
            _finite_number(record.get("expires_at"), name="expires_at", default=0.0),
            (_finite_number(record.get("released_at"), name="released_at") if record.get("released_at") is not None else None),
            lease_state,
        )
        def write(connection: sqlite3.Connection) -> None:
            if lease_state == "active":
                if values[3] is not None:
                    task = connection.execute(
                        "SELECT working_tree_id, lease_id, state FROM task_ledger WHERE task_id = ? AND workspace_id = ?",
                        (values[3], values[1]),
                    ).fetchone()
                    if task is not None and str(task[0] or "") == values[2]:
                        bound_lease_id = str(task[1] or "")
                        if (
                            str(task[2]) in {"leased", "running", "verifying", "review_ready"}
                            and bound_lease_id
                            and bound_lease_id != values[0]
                        ):
                            raise PersistenceError("active writer lease conflicts with active task binding")
                requested_paths = _decode(values[5], name="paths")
                requested_resources = set(_decode(values[6], name="resources"))
                requested_wide = bool(values[10])
                now = time.time()
                for current in connection.execute(
                    "SELECT lease_id, workspace_id, working_tree_id, paths_json, resources_json, workspace_wide FROM writer_leases "
                    "WHERE state = 'active' AND expires_at > ? AND lease_id <> ?",
                    (now, values[0]),
                ).fetchall():
                    current_resources = set(_decode(current[4], name="resources"))
                    if current_resources & requested_resources:
                        raise PersistenceError("runtime writer resource is already leased")
                    if str(current[1]) != values[1]:
                        continue
                    current_paths = _decode(current[3], name="paths")
                    if bool(current[5]) or requested_wide:
                        raise PersistenceError("project writer scope is already leased")
                    if str(current[2]) != values[2]:
                        continue
                    for left in current_paths:
                        for right in requested_paths:
                            left_text, right_text = str(left).casefold(), str(right).casefold()
                            if left_text == right_text or left_text.startswith(right_text + "/") or right_text.startswith(left_text + "/"):
                                raise PersistenceError("project writer path is already leased")
            connection.execute(
                "INSERT INTO writer_leases(lease_id, workspace_id, working_tree_id, task_id, owner_id, paths_json, resources_json, base_revision, scope_hashes_json, workspace_state_hash, workspace_wide, acquired_at, expires_at, released_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(lease_id) DO UPDATE SET workspace_id=excluded.workspace_id, working_tree_id=excluded.working_tree_id, task_id=excluded.task_id, owner_id=excluded.owner_id, paths_json=excluded.paths_json, resources_json=excluded.resources_json, base_revision=excluded.base_revision, scope_hashes_json=excluded.scope_hashes_json, workspace_state_hash=excluded.workspace_state_hash, workspace_wide=excluded.workspace_wide, acquired_at=excluded.acquired_at, expires_at=excluded.expires_at, released_at=excluded.released_at, state=excluded.state",
                values,
            )

        self.run_write(write)

    def update_lease_state(self, lease_id: str, state: str, *, released_at: float | None = None) -> None:
        if state not in _LEASE_STATES:
            raise PersistenceError("lease state is invalid")
        lease = _identifier(lease_id, name="lease_id")
        self.run_write(lambda conn: conn.execute("UPDATE writer_leases SET state = ?, released_at = COALESCE(?, released_at) WHERE lease_id = ?", (state, released_at, lease)))

    def release_expired_lease(
        self,
        lease_id: str,
        *,
        expected_workspace_id: str,
        expected_working_tree_id: str,
        expected_task_id: str,
        expected_owner_id: str,
        expected_expires_at: float,
        now: float,
    ) -> bool:
        """Release one expired lease only when its pinned identity is unchanged.

        This is the persistence-side CAS used by the native operator.  The
        operator never issues SQL; keeping the compare-and-update here makes
        the expiry check atomic with the durable state transition.
        """

        parsed_lease = _identifier(lease_id, name="lease_id")
        workspace = _identifier(expected_workspace_id, name="workspace_id")
        working_tree = _text(expected_working_tree_id, name="working_tree_id", maximum=256)
        task_id = _text(expected_task_id, name="task_id", maximum=256)
        owner = _identifier(expected_owner_id, name="owner_id")
        expiry = _finite_number(expected_expires_at, name="expected_expires_at")
        current_time = _finite_number(now, name="now")
        released_at = current_time

        def write(connection: sqlite3.Connection) -> bool:
            row = connection.execute(
                "SELECT workspace_id, working_tree_id, task_id, owner_id, expires_at, state "
                "FROM writer_leases WHERE lease_id = ?",
                (parsed_lease,),
            ).fetchone()
            if row is None:
                raise PersistenceError("lease is unavailable")
            stored_task = "" if row[2] is None else str(row[2])
            stored_expiry = _finite_number(row[4], name="stored_expires_at")
            if (
                str(row[0]) != workspace
                or str(row[1]) != working_tree
                or stored_task != task_id
                or str(row[3]) != owner
                or stored_expiry != expiry
            ):
                raise PersistenceError("lease identity changed")
            if str(row[5]) in _TERMINAL_LEASE_STATES:
                return False
            if str(row[5]) != "active":
                raise PersistenceError("lease is not active")
            if stored_expiry > current_time:
                raise PersistenceError("lease has not expired")
            connection.execute(
                "UPDATE writer_leases SET state = 'released', released_at = ? "
                "WHERE lease_id = ? AND state = 'active' AND expires_at <= ?",
                (released_at, parsed_lease, current_time),
            )
            return True

        return bool(self.run_write(write))

    def load_leases(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM writer_leases ORDER BY acquired_at, lease_id").fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["paths"] = _decode(item.pop("paths_json"), name="paths")
            item["resources"] = _decode(item.pop("resources_json"), name="resources")
            item["scope_hashes"] = _decode(item.pop("scope_hashes_json"), name="scope_hashes")
            item["workspace_wide"] = bool(item["workspace_wide"])
            if item["state"] not in _LEASE_STATES or not isinstance(item["paths"], list) or not isinstance(item["resources"], list) or not isinstance(item["scope_hashes"], dict):
                raise PersistenceCorruptError("stored lease state is invalid")
            result.append(item)
        return result

    def save_verification(self, value: object, *, task_id: str = "", working_tree_id: str = "") -> None:
        record = _mapping(value, name="verification")
        plan = record.get("plan") if isinstance(record.get("plan"), Mapping) else {}
        results = record.get("results", [])
        if isinstance(results, list):
            results = [
                {
                    "task": item.get("task"),
                    "status": item.get("status"),
                    "exit_code": item.get("exit_code"),
                }
                for item in results
                if isinstance(item, Mapping)
            ]
        workspace = record.get("workspace_id") or plan.get("workspace_id")
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _optional_task_id(record.get("task_id", task_id)),
            _identifier(workspace, name="workspace_id"),
            _text(record.get("working_tree_id", working_tree_id), name="working_tree_id", maximum=256),
            _text(record.get("base_revision"), name="base_revision", maximum=256, allow_empty=False),
            _hash(record.get("diff_hash"), name="diff_hash"),
            _paths(record.get("changed_paths", plan.get("changed_paths", [])), name="changed_paths"),
            _text(record.get("status"), name="status", maximum=32, allow_empty=False),
            _json(results, name="verification_results", default=[]),
            1 if bool(record.get("stale", False)) else 0,
            _text(record.get("recorded_at"), name="recorded_at", maximum=128, allow_empty=False),
        )
        self.run_write(lambda conn: conn.execute("INSERT INTO verification_receipts(receipt_id, task_id, workspace_id, working_tree_id, base_revision, diff_hash, changed_paths_json, status, results_json, stale, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO UPDATE SET task_id=excluded.task_id, workspace_id=excluded.workspace_id, working_tree_id=excluded.working_tree_id, base_revision=excluded.base_revision, diff_hash=excluded.diff_hash, changed_paths_json=excluded.changed_paths_json, status=excluded.status, results_json=excluded.results_json, stale=excluded.stale, recorded_at=excluded.recorded_at", values))

    def load_verifications(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM verification_receipts ORDER BY recorded_at, receipt_id").fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["changed_paths"] = _decode(item.pop("changed_paths_json"), name="changed_paths")
            item["results"] = _decode(item.pop("results_json"), name="verification_results")
            item["stale"] = bool(item["stale"])
            result.append(item)
        return result

    def invalidate_verification(self, receipt_id: str) -> None:
        receipt = _identifier(receipt_id, name="receipt_id")
        self.run_write(lambda conn: conn.execute("UPDATE verification_receipts SET status='stale', stale=1 WHERE receipt_id = ?", (receipt,)))

    def save_security_audit(self, value: object, *, task_id: str = "", working_tree_id: str = "") -> None:
        record = _mapping(value, name="security audit")
        report = record.get("report") if isinstance(record.get("report"), Mapping) else {}
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _optional_task_id(record.get("task_id", task_id)),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _text(record.get("working_tree_id", working_tree_id), name="working_tree_id", maximum=256),
            _text(record.get("base_revision"), name="base_revision", maximum=256, allow_empty=False),
            _hash(record.get("diff_hash"), name="diff_hash"),
            _hash(record.get("patch_hash"), name="patch_hash"),
            _paths(record.get("changed_paths"), name="changed_paths"),
            _text(record.get("verification_receipt_id"), name="verification_receipt_id", maximum=256),
            _text(record.get("status", report.get("status")), name="status", maximum=32, allow_empty=False),
            _json({"status": report.get("status"), "findings": report.get("findings", [])}, name="audit_result", default={}),
            1 if bool(record.get("stale", False)) else 0,
            _text(record.get("audited_at"), name="audited_at", maximum=128, allow_empty=False),
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT receipt_id, workspace_id, working_tree_id, base_revision, diff_hash, patch_hash, changed_paths_json, verification_receipt_id, status, result_json, stale FROM security_audit_receipts WHERE receipt_id = ?",
                (values[0],),
            ).fetchone()
            if existing is not None:
                existing_identity = tuple(existing[index] for index in range(11))
                incoming_identity = (
                    values[0],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    values[7],
                    values[8],
                    values[9],
                    values[10],
                    values[11],
                )
                if existing_identity != incoming_identity:
                    raise IdempotencyConflict("SECURITY_AUDIT_RECEIPT_CONFLICT")
                # Receipt identity is task-agnostic.  Keep the first task
                # reference and audited_at so a retry cannot rewrite
                # provenance or turn an evidence replay into a mutation.
                return
            connection.execute(
                "INSERT INTO security_audit_receipts(receipt_id, task_id, workspace_id, working_tree_id, base_revision, diff_hash, patch_hash, changed_paths_json, verification_receipt_id, status, result_json, stale, audited_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_security_audits(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM security_audit_receipts ORDER BY audited_at, receipt_id").fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["changed_paths"] = _decode(item.pop("changed_paths_json"), name="changed_paths")
            item["result"] = _decode(item.pop("result_json"), name="audit_result")
            item["stale"] = bool(item["stale"])
            result.append(item)
        return result

    def save_review(self, value: object) -> None:
        record = _mapping(value, name="review receipt")
        independent = record.get("independent")
        blocking = record.get("blocking")
        if not isinstance(independent, bool) or not isinstance(blocking, bool):
            raise PersistenceError("review flags must be boolean")
        base_revision = _text(record.get("base_revision"), name="base_revision", maximum=128, allow_empty=False)
        if not re.fullmatch(r"[0-9a-f]{40}", base_revision):
            raise PersistenceError("review base must be a full commit id")
        findings = record.get("findings", [])
        if not isinstance(findings, (list, tuple)) or len(findings) > 200 or any(not isinstance(item, Mapping) for item in findings):
            raise PersistenceError("review findings are invalid")
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _identifier(record.get("task_id"), name="task_id"),
            _text(record.get("implementer_owner"), name="implementer_owner", maximum=128, allow_empty=False),
            _text(record.get("reviewer_owner"), name="reviewer_owner", maximum=128, allow_empty=False),
            1 if independent else 0,
            base_revision,
            _hash(record.get("diff_hash"), name="diff_hash", allow_empty=False),
            _paths(record.get("reviewed_paths"), name="reviewed_paths"),
            _json(list(findings), name="review_findings", default=[]),
            1 if blocking else 0,
            _finite_number(record.get("reviewed_at"), name="reviewed_at"),
        )
        self.run_write(
            lambda conn: conn.execute(
                "INSERT INTO review_receipts(receipt_id, task_id, implementer_owner, reviewer_owner, independent, base_revision, diff_hash, reviewed_paths_json, findings_json, blocking, reviewed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO UPDATE SET task_id=excluded.task_id, implementer_owner=excluded.implementer_owner, reviewer_owner=excluded.reviewer_owner, independent=excluded.independent, base_revision=excluded.base_revision, diff_hash=excluded.diff_hash, reviewed_paths_json=excluded.reviewed_paths_json, findings_json=excluded.findings_json, blocking=excluded.blocking, reviewed_at=excluded.reviewed_at",
                values,
            )
        )

    def load_reviews(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if task_id is None:
                rows = connection.execute("SELECT * FROM review_receipts ORDER BY reviewed_at, receipt_id").fetchall()
            else:
                task = _identifier(task_id, name="task_id")
                rows = connection.execute(
                    "SELECT * FROM review_receipts WHERE task_id = ? ORDER BY reviewed_at, receipt_id",
                    (task,),
                ).fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["independent"] = bool(item["independent"])
            item["blocking"] = bool(item["blocking"])
            item["reviewed_paths"] = _decode(item.pop("reviewed_paths_json"), name="reviewed_paths")
            item["findings"] = _decode(item.pop("findings_json"), name="review_findings")
            if not isinstance(item["reviewed_paths"], list) or not isinstance(item["findings"], list):
                raise PersistenceCorruptError("stored review receipt JSON is invalid")
            result.append(item)
        return result

    def invalidate_security_audit(self, receipt_id: str) -> None:
        receipt = _identifier(receipt_id, name="receipt_id")
        self.run_write(lambda conn: conn.execute("UPDATE security_audit_receipts SET stale=1 WHERE receipt_id = ?", (receipt,)))

    def save_project_policy_receipt(self, value: object) -> None:
        record = _mapping(value, name="project policy receipt")
        audit = record.get("audit") if isinstance(record.get("audit"), Mapping) else {}
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _hash(record.get("before_config_digest"), name="before_config_digest", allow_empty=False),
            _hash(record.get("after_config_digest"), name="after_config_digest", allow_empty=False),
            _paths(record.get("changed_keys"), name="changed_keys"),
            _json(record.get("before_policy"), name="before_policy", default={}),
            _json(record.get("after_policy"), name="after_policy", default={}),
            _json(audit, name="policy_audit", default={}),
            _text(record.get("status"), name="status", maximum=32, allow_empty=False),
            _text(record.get("recorded_at"), name="recorded_at", maximum=128, allow_empty=False),
        )
        self.run_write(
            lambda conn: conn.execute(
                "INSERT INTO project_policy_receipts(receipt_id, workspace_id, before_config_digest, after_config_digest, changed_keys_json, before_policy_json, after_policy_json, audit_json, status, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO UPDATE SET workspace_id=excluded.workspace_id, before_config_digest=excluded.before_config_digest, after_config_digest=excluded.after_config_digest, changed_keys_json=excluded.changed_keys_json, before_policy_json=excluded.before_policy_json, after_policy_json=excluded.after_policy_json, audit_json=excluded.audit_json, status=excluded.status, recorded_at=excluded.recorded_at",
                values,
            )
        )

    def load_project_policy_receipts(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute("SELECT * FROM project_policy_receipts ORDER BY recorded_at, receipt_id").fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute(
                    "SELECT * FROM project_policy_receipts WHERE workspace_id = ? ORDER BY recorded_at, receipt_id",
                    (workspace,),
                ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["changed_keys"] = _decode(item.pop("changed_keys_json"), name="changed_keys")
            item["before_policy"] = _decode(item.pop("before_policy_json"), name="before_policy")
            item["after_policy"] = _decode(item.pop("after_policy_json"), name="after_policy")
            item["audit"] = _decode(item.pop("audit_json"), name="policy_audit")
            result.append(item)
        return result

    def save_approval_decision(self, value: object) -> None:
        record = _mapping(value, name="approval decision")
        forbidden_keys = {"approval_token", "access_token", "grant_id", "trusted_grant_token"}
        if forbidden_keys.intersection(record):
            raise PersistenceError("approval decision contains non-persistable authorization material")
        risk_class = _text(record.get("risk_class"), name="risk_class", maximum=8, allow_empty=False)
        if risk_class not in {"R0", "R1", "R2", "R3"}:
            raise PersistenceError("risk_class is invalid")
        values = (
            _identifier(record.get("decision_id"), name="decision_id"),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _identifier(record.get("working_tree_id"), name="working_tree_id"),
            _identifier(record.get("session_id"), name="session_id"),
            _identifier(record.get("task_id"), name="task_id"),
            _identifier(record.get("owner_id"), name="owner_id"),
            _text(record.get("operation"), name="operation", maximum=128, allow_empty=False),
            risk_class,
            _text(record.get("reason"), name="reason", maximum=1000, allow_empty=False),
            _text(record.get("authorization_mode"), name="authorization_mode", maximum=64, allow_empty=False),
            _hash(record.get("policy_digest"), name="policy_digest", allow_empty=False),
            _text(record.get("outcome"), name="outcome", maximum=64, allow_empty=False),
            _text(record.get("recorded_at"), name="recorded_at", maximum=128, allow_empty=False),
        )
        self.run_write(
            lambda conn: conn.execute(
                "INSERT INTO approval_decisions(decision_id, workspace_id, working_tree_id, session_id, task_id, owner_id, operation, risk_class, reason, authorization_mode, policy_digest, outcome, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(decision_id) DO UPDATE SET workspace_id=excluded.workspace_id, working_tree_id=excluded.working_tree_id, session_id=excluded.session_id, task_id=excluded.task_id, owner_id=excluded.owner_id, operation=excluded.operation, risk_class=excluded.risk_class, reason=excluded.reason, authorization_mode=excluded.authorization_mode, policy_digest=excluded.policy_digest, outcome=excluded.outcome, recorded_at=excluded.recorded_at",
                values,
            )
        )

    def load_approval_decisions(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute("SELECT * FROM approval_decisions ORDER BY recorded_at, decision_id").fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute(
                    "SELECT * FROM approval_decisions WHERE workspace_id = ? ORDER BY recorded_at, decision_id",
                    (workspace,),
                ).fetchall()
        return [_row_dict(row) for row in rows]

    def save_provisioning_event(self, value: object) -> None:
        record = _mapping(value, name="provisioning event")
        values = (
            _identifier(record.get("event_id"), name="event_id"),
            _text(record.get("event_type"), name="event_type", maximum=64, allow_empty=False),
            _text(record.get("request_id"), name="request_id", maximum=256),
            _text(record.get("owner_id"), name="owner_id", maximum=256),
            _identifier(record.get("project_id"), name="project_id"),
            _text(record.get("target_path"), name="target_path", maximum=2048),
            _text(record.get("intent_source"), name="intent_source", maximum=64, allow_empty=False),
            _text(record.get("provisioning_mode"), name="provisioning_mode", maximum=64, allow_empty=False),
            _text(record.get("canonical_path"), name="canonical_path", maximum=2048),
            _text(record.get("root_id"), name="root_id", maximum=256),
            _hash(record.get("previous_registry_digest"), name="previous_registry_digest"),
            _hash(record.get("new_registry_digest"), name="new_registry_digest"),
            _json(
                record.get("repo_identity"),
                name="repo_identity",
                default={},
                reject_forbidden_text=True,
            ),
            _json(
                record.get("result"),
                name="provisioning_result",
                default={},
                reject_forbidden_text=True,
            ),
            _text(record.get("recorded_at"), name="recorded_at", maximum=128, allow_empty=False),
        )
        def write(connection: sqlite3.Connection) -> None:
            if connection.execute("SELECT 1 FROM provisioning_events WHERE event_id = ?", (values[0],)).fetchone() is not None:
                raise PersistenceError("provisioning event ids are append-only")
            connection.execute(
                "INSERT INTO provisioning_events(event_id, event_type, request_id, owner_id, project_id, target_path, intent_source, provisioning_mode, canonical_path, root_id, previous_registry_digest, new_registry_digest, repo_identity_json, result_json, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_provisioning_events(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if project_id is None:
                rows = connection.execute("SELECT * FROM provisioning_events ORDER BY recorded_at, event_id").fetchall()
            else:
                project = _identifier(project_id, name="project_id")
                rows = connection.execute(
                    "SELECT * FROM provisioning_events WHERE project_id = ? ORDER BY recorded_at, event_id",
                    (project,),
                ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["repo_identity"] = _decode(item.pop("repo_identity_json"), name="repo_identity")
            item["result"] = _decode(item.pop("result_json"), name="provisioning_result")
            result.append(item)
        return result

    def _readonly_root_scope_clause(self) -> tuple[str, tuple[object, ...]]:
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            return (
                "scope_id = ? AND workspace_id = ? AND session_id = ? AND owner_id = ?",
                (_readonly_root_scope_id(self.path), "", "", ""),
            )
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_NATIVE:
            return "1 = 1", ()
        raise PersistenceCorruptError("readonly_roots schema is unavailable")

    def _readonly_root_select_columns(self) -> str:
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            return (
                "root_id, requested_path, canonical_path, device, inode, created_at, "
                "last_accessed_at, expires_at, label, state, scope_id, workspace_id, "
                "session_id, owner_id, updated_at"
            )
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_NATIVE:
            return (
                "root_id, requested_path, canonical_path, device, inode, created_at, "
                "last_accessed_at, expires_at, label, state, updated_at"
            )
        raise PersistenceCorruptError("readonly_roots schema is unavailable")

    def _readonly_root_row(self, row: sqlite3.Row) -> dict[str, Any] | None:
        item = _row_dict(row)
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            if (
                item.get("scope_id") != _readonly_root_scope_id(self.path)
                or any(item.get(field) != "" for field in ("workspace_id", "session_id", "owner_id"))
            ):
                return None
            item = {
                key: item[key]
                for key in (
                    "root_id",
                    "requested_path",
                    "canonical_path",
                    "device",
                    "inode",
                    "created_at",
                    "last_accessed_at",
                    "expires_at",
                    "label",
                    "state",
                    "updated_at",
                )
            }
        return _readonly_root_record(item)

    def _prune_readonly_root_rows(
        self,
        connection: sqlite3.Connection,
        *,
        now: float,
        max_history: int = _READONLY_ROOT_MAX_HISTORY,
    ) -> None:
        if not isinstance(max_history, int) or not 1 <= max_history <= 1024:
            raise PersistenceError("readonly root history bound is invalid")
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            _assert_readonly_root_scope_clean(connection, self.path)
        scope_clause, scope_values = self._readonly_root_scope_clause()
        connection.execute(
            f"UPDATE readonly_roots SET state = 'expired', updated_at = ? "
            f"WHERE ({scope_clause}) AND state = 'active' AND expires_at <= ?",
            (now, *scope_values, now),
        )
        old_rows = connection.execute(
            f"SELECT root_id FROM readonly_roots WHERE ({scope_clause}) AND state <> 'active' "
            "ORDER BY updated_at DESC, root_id DESC LIMIT -1 OFFSET ?",
            (*scope_values, max_history),
        ).fetchall()
        for row in old_rows:
            connection.execute(
                f"DELETE FROM readonly_roots WHERE root_id = ? AND ({scope_clause})",
                (row[0], *scope_values),
            )

    def save_readonly_root(
        self,
        value: object,
        *,
        now: float | None = None,
        max_active: int = _READONLY_ROOT_MAX_ACTIVE,
        max_history: int = _READONLY_ROOT_MAX_HISTORY,
    ) -> None:
        """Atomically register one bounded opaque READ_ONLY filesystem handle."""

        record = _readonly_root_record(value)
        if not isinstance(max_active, int) or not 1 <= max_active <= 1024:
            raise PersistenceError("readonly root active bound is invalid")
        current = _finite_number(
            record["updated_at"] if now is None else now,
            name="readonly_root_now",
        )
        scope_clause, scope_values = self._readonly_root_scope_clause()

        def write(connection: sqlite3.Connection) -> None:
            self._prune_readonly_root_rows(connection, now=current, max_history=max_history)
            if connection.execute(
                "SELECT 1 FROM readonly_roots WHERE root_id = ?",
                (record["root_id"],),
            ).fetchone() is not None:
                raise ReadOnlyRootConflictError("readonly root id already exists")
            active = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM readonly_roots WHERE ({scope_clause}) AND state = 'active'",
                    scope_values,
                ).fetchone()[0]
            )
            if active >= max_active:
                raise ReadOnlyRootCapacityError("readonly root capacity is exhausted")
            values = (
                record["root_id"],
                record["requested_path"],
                record["canonical_path"],
                record["device"],
                record["inode"],
                record["created_at"],
                record["last_accessed_at"],
                record["expires_at"],
                record["label"],
                record["state"],
            )
            if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
                connection.execute(
                    "INSERT INTO readonly_roots("
                    "root_id, requested_path, canonical_path, device, inode, created_at, "
                    "last_accessed_at, expires_at, label, state, scope_id, workspace_id, "
                    "session_id, owner_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (*values, _readonly_root_scope_id(self.path), "", "", "", record["updated_at"]),
                )
            elif self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_NATIVE:
                connection.execute(
                    "INSERT INTO readonly_roots("
                    "root_id, requested_path, canonical_path, device, inode, created_at, "
                    "last_accessed_at, expires_at, label, state, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (*values, record["updated_at"]),
                )
            else:
                raise PersistenceCorruptError("readonly_roots schema is unavailable")

        self.run_write(write)

    def load_readonly_root(self, root_id: object) -> dict[str, Any] | None:
        identifier = _identifier(root_id, name="root_id", maximum=160)
        scope_clause, scope_values = self._readonly_root_scope_clause()
        with self._transaction(write=False) as connection:
            if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
                _assert_readonly_root_scope_clean(connection, self.path)
            row = connection.execute(
                f"SELECT {self._readonly_root_select_columns()} FROM readonly_roots "
                f"WHERE root_id = ? AND ({scope_clause})",
                (identifier, *scope_values),
            ).fetchone()
        if row is None:
            return None
        return self._readonly_root_row(row)

    def load_readonly_roots(self) -> list[dict[str, Any]]:
        scope_clause, scope_values = self._readonly_root_scope_clause()
        with self._transaction(write=False) as connection:
            if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
                _assert_readonly_root_scope_clean(connection, self.path)
            rows = connection.execute(
                f"SELECT {self._readonly_root_select_columns()} FROM readonly_roots "
                f"WHERE ({scope_clause}) ORDER BY created_at, root_id",
                scope_values,
            ).fetchall()
        return [record for row in rows if (record := self._readonly_root_row(row)) is not None]

    def close_readonly_root(self, root_id: object, *, now: float | None = None) -> dict[str, Any] | None:
        identifier = _identifier(root_id, name="root_id", maximum=160)
        current = _finite_number(time.time() if now is None else now, name="readonly_root_now")
        scope_clause, scope_values = self._readonly_root_scope_clause()

        def write(connection: sqlite3.Connection) -> None:
            if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
                _assert_readonly_root_scope_clean(connection, self.path)
            connection.execute(
                f"UPDATE readonly_roots SET state = 'closed', updated_at = ? "
                f"WHERE root_id = ? AND ({scope_clause})",
                (current, identifier, *scope_values),
            )
            self._prune_readonly_root_rows(connection, now=current)

        self.run_write(write)
        return self.load_readonly_root(identifier)

    def mark_readonly_root_stale(self, root_id: object, *, now: float | None = None) -> dict[str, Any] | None:
        """Persist an identity/policy failure without revoking other handles."""

        identifier = _identifier(root_id, name="root_id", maximum=160)
        current = _finite_number(time.time() if now is None else now, name="readonly_root_now")
        scope_clause, scope_values = self._readonly_root_scope_clause()

        def write(connection: sqlite3.Connection) -> None:
            if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
                _assert_readonly_root_scope_clean(connection, self.path)
            connection.execute(
                f"UPDATE readonly_roots SET state = 'stale', updated_at = ? "
                f"WHERE root_id = ? AND ({scope_clause}) AND state = 'active'",
                (current, identifier, *scope_values),
            )
            self._prune_readonly_root_rows(connection, now=current)

        self.run_write(write)
        return self.load_readonly_root(identifier)

    def _cleanup_readonly_roots(
        self,
        connection: sqlite3.Connection,
        *,
        cutoff: float,
        max_rows: int,
    ) -> int:
        if self._readonly_roots_schema == _READONLY_ROOT_SCHEMA_LEGACY_SCOPED_SUPERSET:
            _assert_readonly_root_scope_clean(connection, self.path)
        scope_clause, scope_values = self._readonly_root_scope_clause()
        cursor = connection.execute(
            f"DELETE FROM readonly_roots WHERE ({scope_clause}) AND state <> 'active' AND updated_at < ?",
            (*scope_values, cutoff),
        )
        removed = cursor.rowcount
        rows = connection.execute(
            f"SELECT rowid FROM readonly_roots WHERE ({scope_clause}) AND state <> 'active' "
            "ORDER BY updated_at DESC, rowid DESC LIMIT -1 OFFSET ?",
            (*scope_values, max_rows),
        ).fetchall()
        for row in rows:
            connection.execute(
                f"DELETE FROM readonly_roots WHERE rowid = ? AND ({scope_clause})",
                (row[0], *scope_values),
            )
            removed += 1
        return removed

    def save_request_lifecycle_event(self, value: object) -> None:
        """Persist one sanitized lifecycle event; raw arguments and outputs never enter this table."""

        record = _mapping(value, name="request lifecycle event")
        raw_request_id = record.get("request_id", "")
        request_id = "" if raw_request_id is None else str(raw_request_id)
        duration = record.get("duration_ms")
        duration_ms = None if duration is None else _finite_number(duration, name="duration_ms")
        retry_count = record.get("retry_count", 0)
        if not isinstance(retry_count, int) or isinstance(retry_count, bool) or not 0 <= retry_count <= 1024:
            raise PersistenceError("retry_count is outside its safety bound")
        generation = record.get("transport_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise PersistenceError("transport_generation is invalid")
        request_accepted = int(bool(record.get("request_accepted", False)))
        mutation_started = int(bool(record.get("mutation_started", False)))
        mutation_finished = int(bool(record.get("mutation_finished", False)))
        schema_hash = _hash(record.get("server_schema_hash"), name="server_schema_hash")
        integration_patch_hash = _hash(record.get("integration_patch_hash"), name="integration_patch_hash")
        canonical_revision_before = _text(record.get("canonical_revision_before"), name="canonical_revision_before", maximum=40)
        if canonical_revision_before and not re.fullmatch(r"[0-9a-f]{40}", canonical_revision_before):
            raise PersistenceError("canonical_revision_before is invalid")
        values = (
            _identifier(record.get("event_id"), name="event_id"),
            _text(record.get("child_instance_id"), name="child_instance_id", maximum=256, allow_empty=False),
            generation,
            _text(request_id, name="request_id", maximum=256),
            _text(record.get("tool_name"), name="tool_name", maximum=128),
            _text(record.get("side_effect_class"), name="side_effect_class", maximum=64),
            _text(record.get("state"), name="state", maximum=64),
            _text(record.get("event"), name="event", maximum=96, allow_empty=False),
            _text(record.get("reason"), name="reason", maximum=256),
            retry_count,
            duration_ms,
            _text(record.get("workspace_id"), name="workspace_id", maximum=256),
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256),
            _text(record.get("development_session_id"), name="development_session_id", maximum=256),
            _text(record.get("logical_connection_id"), name="logical_connection_id", maximum=256),
            _text(record.get("server_schema_revision"), name="server_schema_revision", maximum=128),
            schema_hash,
            request_accepted,
            _text(record.get("result"), name="result", maximum=32),
            _text(record.get("tool_failure_code"), name="tool_failure_code", maximum=128),
            _text(record.get("integration_intent_id"), name="integration_intent_id", maximum=256),
            _text(record.get("integration_preflight_id"), name="integration_preflight_id", maximum=256),
            integration_patch_hash,
            canonical_revision_before,
            mutation_started,
            mutation_finished,
            _text(record.get("integration_receipt_id"), name="integration_receipt_id", maximum=256),
            _text(record.get("recorded_at", _utc_now()), name="recorded_at", maximum=128, allow_empty=False),
        )
        self.run_write(
            lambda conn: conn.execute(
                "INSERT INTO request_lifecycle_events(event_id, child_instance_id, transport_generation, request_id, tool_name, side_effect_class, state, event, reason, retry_count, duration_ms, workspace_id, working_tree_id, development_session_id, logical_connection_id, server_schema_revision, server_schema_hash, request_accepted, result, tool_failure_code, integration_intent_id, integration_preflight_id, integration_patch_hash, canonical_revision_before, mutation_started, mutation_finished, integration_receipt_id, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        )

    def load_request_lifecycle_events(
        self,
        *,
        limit: int = 100,
        child_instance_id: str | None = None,
        request_id: str | int | None = None,
    ) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise PersistenceError("request lifecycle event limit is outside its safety bound")
        clauses: list[str] = []
        parameters: list[object] = []
        if child_instance_id is not None:
            clauses.append("child_instance_id = ?")
            parameters.append(_text(child_instance_id, name="child_instance_id", maximum=256, allow_empty=False))
        if request_id is not None:
            clauses.append("request_id = ?")
            parameters.append(_text(str(request_id), name="request_id", maximum=256))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                f"SELECT * FROM request_lifecycle_events{where} ORDER BY recorded_at DESC, event_id DESC LIMIT ?",
                (*parameters, limit),
            ).fetchall()
        return [_row_dict(row) for row in rows]

    def save_integration(self, value: object) -> None:
        record = _mapping(value, name="integration")
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _text(record.get("session_id"), name="session_id", maximum=256),
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256),
            _text(record.get("source_revision"), name="source_revision", maximum=256),
            _text(record.get("canonical_revision"), name="canonical_revision", maximum=256),
            _hash(record.get("patch_hash"), name="patch_hash"),
            _json(record.get("evidence_ids"), name="evidence_ids", default=[]),
            _text(record.get("preflight_outcome"), name="preflight_outcome", maximum=64),
            _text(record.get("integration_outcome"), name="integration_outcome", maximum=64),
            _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False),
            _text(record.get("applied_at"), name="applied_at", maximum=128),
        )
        self.run_write(lambda conn: conn.execute("INSERT INTO integration_receipts(receipt_id, session_id, working_tree_id, source_revision, canonical_revision, patch_hash, evidence_ids_json, preflight_outcome, integration_outcome, created_at, applied_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO UPDATE SET session_id=excluded.session_id, working_tree_id=excluded.working_tree_id, source_revision=excluded.source_revision, canonical_revision=excluded.canonical_revision, patch_hash=excluded.patch_hash, evidence_ids_json=excluded.evidence_ids_json, preflight_outcome=excluded.preflight_outcome, integration_outcome=excluded.integration_outcome, created_at=excluded.created_at, applied_at=excluded.applied_at", values))

    def load_integrations(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM integration_receipts ORDER BY created_at, receipt_id").fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["evidence_ids"] = _decode(item.pop("evidence_ids_json"), name="evidence_ids")
            result.append(item)
        return result

    def save_integration_intent(self, value: object) -> None:
        record = _mapping(value, name="integration intent")
        allowed = {
            "intent_id",
            "session_id",
            "workspace_id",
            "working_tree_id",
            "source_revision",
            "canonical_revision",
            "patch_hash",
            "state_diff_hash",
            "verification_receipt_id",
            "security_audit_receipt_id",
            "changed_paths",
            "created_at",
            "expires_at",
            "status",
        }
        if set(record) - allowed:
            raise PersistenceError("integration intent contains unsupported fields")
        source_revision = _text(record.get("source_revision"), name="source_revision", maximum=40, allow_empty=False)
        canonical_revision = _text(record.get("canonical_revision"), name="canonical_revision", maximum=40, allow_empty=False)
        if not re.fullmatch(r"[0-9a-f]{40}", source_revision) or not re.fullmatch(r"[0-9a-f]{40}", canonical_revision):
            raise PersistenceError("integration intent revision is invalid")
        created_at = _finite_number(record.get("created_at"), name="created_at")
        expires_at = _finite_number(record.get("expires_at"), name="expires_at")
        if expires_at <= created_at:
            raise PersistenceError("integration intent expiry is invalid")
        status = _text(record.get("status"), name="status", maximum=32, allow_empty=False)
        if status not in {"awaiting_confirmation", "confirmed", "integrated", "revoked", "stale"}:
            raise PersistenceError("integration intent status is invalid")
        values = (
            _identifier(record.get("intent_id"), name="intent_id"),
            _identifier(record.get("session_id"), name="session_id"),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _identifier(record.get("working_tree_id"), name="working_tree_id"),
            source_revision,
            canonical_revision,
            _hash(record.get("patch_hash"), name="patch_hash", allow_empty=False),
            _hash(record.get("state_diff_hash"), name="state_diff_hash", allow_empty=False),
            _identifier(record.get("verification_receipt_id"), name="verification_receipt_id"),
            _identifier(record.get("security_audit_receipt_id"), name="security_audit_receipt_id"),
            _paths(record.get("changed_paths"), name="changed_paths"),
            created_at,
            expires_at,
            status,
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT * FROM integration_intents WHERE intent_id = ?",
                (values[0],),
            ).fetchone()
            if existing is not None:
                immutable_existing = (
                    str(existing["intent_id"]),
                    str(existing["session_id"]),
                    str(existing["workspace_id"]),
                    str(existing["working_tree_id"]),
                    str(existing["source_revision"]),
                    str(existing["canonical_revision"]),
                    str(existing["patch_hash"]),
                    str(existing["state_diff_hash"]),
                    str(existing["verification_receipt_id"]),
                    str(existing["security_audit_receipt_id"]),
                    str(existing["changed_paths_json"]),
                )
                if immutable_existing != values[:11]:
                    raise PersistenceError("integration intent id is already bound to different content")
                connection.execute(
                    "UPDATE integration_intents SET expires_at = ?, status = ? WHERE intent_id = ?",
                    (values[12], values[13], values[0]),
                )
                return
            connection.execute(
                "INSERT INTO integration_intents(intent_id, session_id, workspace_id, working_tree_id, source_revision, canonical_revision, patch_hash, state_diff_hash, verification_receipt_id, security_audit_receipt_id, changed_paths_json, created_at, expires_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_integration_intents(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute(
                    "SELECT * FROM integration_intents ORDER BY created_at, intent_id"
                ).fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute(
                    "SELECT * FROM integration_intents WHERE workspace_id = ? ORDER BY created_at, intent_id",
                    (workspace,),
                ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["changed_paths"] = _decode(item.pop("changed_paths_json"), name="changed_paths")
            if not isinstance(item["changed_paths"], list):
                raise PersistenceCorruptError("stored integration intent paths are invalid")
            result.append(item)
        return result

    def update_integration_intent_status(self, intent_id: str, status: str) -> None:
        normalized_id = _identifier(intent_id, name="intent_id")
        normalized_status = _text(status, name="status", maximum=32, allow_empty=False)
        if normalized_status not in {"awaiting_confirmation", "confirmed", "integrated", "revoked", "stale"}:
            raise PersistenceError("integration intent status is invalid")
        self.run_write(
            lambda conn: conn.execute(
                "UPDATE integration_intents SET status = ? WHERE intent_id = ?",
                (normalized_status, normalized_id),
            )
        )

    def save_integration_approval_grant(self, value: object) -> None:
        record = _mapping(value, name="integration approval grant")
        allowed = {
            "grant_id",
            "workspace_id",
            "working_tree_id",
            "source_revision",
            "canonical_revision",
            "patch_hash",
            "policy_digest",
            "original_session_id",
            "approved_at",
            "expires_at",
            "state",
        }
        if set(record) - allowed:
            raise PersistenceError("integration approval grant contains unsupported fields")
        source_revision = _text(record.get("source_revision"), name="source_revision", maximum=40, allow_empty=False)
        canonical_revision = _text(record.get("canonical_revision"), name="canonical_revision", maximum=40, allow_empty=False)
        if not re.fullmatch(r"[0-9a-f]{40}", source_revision) or not re.fullmatch(r"[0-9a-f]{40}", canonical_revision):
            raise PersistenceError("integration approval grant revision is invalid")
        approved_at = _finite_number(record.get("approved_at"), name="approved_at")
        expires_at = _finite_number(record.get("expires_at"), name="expires_at")
        if expires_at <= approved_at:
            raise PersistenceError("integration approval grant expiry is invalid")
        state = _text(record.get("state"), name="state", maximum=32, allow_empty=False)
        if state not in {"active", "integrated", "revoked"}:
            raise PersistenceError("integration approval grant state is invalid")
        values = (
            _identifier(record.get("grant_id"), name="grant_id"),
            _identifier(record.get("workspace_id"), name="workspace_id"),
            _identifier(record.get("working_tree_id"), name="working_tree_id"),
            source_revision,
            canonical_revision,
            _hash(record.get("patch_hash"), name="patch_hash", allow_empty=False),
            _hash(record.get("policy_digest"), name="policy_digest", allow_empty=False),
            _identifier(record.get("original_session_id"), name="original_session_id"),
            approved_at,
            expires_at,
            state,
        )
        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT * FROM integration_approval_grants WHERE grant_id = ?",
                (values[0],),
            ).fetchone()
            if existing is not None:
                immutable_existing = (
                    str(existing["grant_id"]),
                    str(existing["workspace_id"]),
                    str(existing["working_tree_id"]),
                    str(existing["source_revision"]),
                    str(existing["canonical_revision"]),
                    str(existing["patch_hash"]),
                    str(existing["policy_digest"]),
                    str(existing["original_session_id"]),
                    float(existing["approved_at"]),
                )
                if immutable_existing != values[:9]:
                    raise PersistenceError("integration approval grant id is already bound to different content")
                connection.execute(
                    "UPDATE integration_approval_grants SET expires_at = ?, state = ? WHERE grant_id = ?",
                    (values[9], values[10], values[0]),
                )
                return
            connection.execute(
                "INSERT INTO integration_approval_grants(grant_id, workspace_id, working_tree_id, source_revision, canonical_revision, patch_hash, policy_digest, original_session_id, approved_at, expires_at, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def load_integration_approval_grants(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            if workspace_id is None:
                rows = connection.execute(
                    "SELECT * FROM integration_approval_grants ORDER BY approved_at, grant_id"
                ).fetchall()
            else:
                workspace = _identifier(workspace_id, name="workspace_id")
                rows = connection.execute(
                    "SELECT * FROM integration_approval_grants WHERE workspace_id = ? ORDER BY approved_at, grant_id",
                    (workspace,),
                ).fetchall()
        return [_row_dict(row) for row in rows]

    def update_integration_approval_grant_state(self, grant_id: str, state: str) -> None:
        normalized_id = _identifier(grant_id, name="grant_id")
        normalized_state = _text(state, name="state", maximum=32, allow_empty=False)
        if normalized_state not in {"active", "integrated", "revoked"}:
            raise PersistenceError("integration approval grant state is invalid")
        self.run_write(
            lambda conn: conn.execute(
                "UPDATE integration_approval_grants SET state = ? WHERE grant_id = ?",
                (normalized_state, normalized_id),
            )
        )

    def save_git_preflight_authority(self, value: object) -> None:
        """Persist one immutable Git preflight and optional hashed approval atomically."""

        record = _mapping(value, name="git preflight authority")
        operation = _text(record.get("operation"), name="git_operation", maximum=32, allow_empty=False)
        if operation not in {"stage", "stage_paths", "stage_hunks", "verified_commit", "commit", "push"}:
            raise PersistenceError("git preflight operation is invalid")
        state = _text(record.get("state"), name="git_authority_state", maximum=32, allow_empty=False)
        if state not in _GIT_AUTHORITY_STATES:
            raise PersistenceError("git preflight authority state is invalid")
        preflight_id = _identifier(record.get("preflight_id"), name="preflight_id")
        workspace_id = _text(record.get("workspace_id"), name="workspace_id", maximum=256, allow_empty=False)
        working_tree_id = _text(record.get("working_tree_id"), name="working_tree_id", maximum=256, allow_empty=False)
        task_id = _text(record.get("task_id"), name="task_id", maximum=256, allow_empty=False)
        payload_json = _json(record.get("payload"), name="git_preflight_payload", default={})
        created_at = _finite_number(record.get("created_at"), name="created_at")
        expires_at = _finite_number(record.get("expires_at"), name="expires_at")
        if expires_at < created_at:
            raise PersistenceError("git preflight expiry precedes creation")
        schema_version = int(record.get("schema_version", CURRENT_SCHEMA_VERSION))
        if schema_version != CURRENT_SCHEMA_VERSION:
            raise PersistenceError("git preflight schema version is invalid")
        approval_token_hash = _hash(record.get("approval_token_hash"), name="approval_token_hash")
        approval_confirmation_hash = _hash(
            record.get("approval_confirmation_hash"),
            name="approval_confirmation_hash",
        )
        if bool(approval_token_hash) != bool(approval_confirmation_hash):
            raise PersistenceError("git approval hashes must be supplied together")
        approval_expires_at = _finite_number(
            record.get("approval_expires_at", expires_at),
            name="approval_expires_at",
        )

        with self._transaction(write=True) as connection:
            connection.execute(
                """
                INSERT INTO git_preflight_authority(
                    preflight_id, operation, workspace_id, working_tree_id, task_id,
                    state, payload_json, created_at, expires_at, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(preflight_id) DO NOTHING
                """,
                (
                    preflight_id,
                    operation,
                    workspace_id,
                    working_tree_id,
                    task_id,
                    state,
                    payload_json,
                    created_at,
                    expires_at,
                    schema_version,
                ),
            )
            stored = connection.execute(
                "SELECT operation, workspace_id, working_tree_id, task_id, state, payload_json, created_at, expires_at, schema_version FROM git_preflight_authority WHERE preflight_id = ?",
                (preflight_id,),
            ).fetchone()
            expected = (
                operation,
                workspace_id,
                working_tree_id,
                task_id,
                state,
                payload_json,
                created_at,
                expires_at,
                schema_version,
            )
            if stored is None or tuple(stored) != expected:
                raise PersistenceError("git preflight id was reused with different authority")
            if approval_token_hash:
                connection.execute(
                    """
                    INSERT INTO git_approval_authority(
                        token_hash, confirmation_hash, preflight_id, operation,
                        workspace_id, expires_at, schema_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(token_hash) DO NOTHING
                    """,
                    (
                        approval_token_hash,
                        approval_confirmation_hash,
                        preflight_id,
                        operation,
                        workspace_id,
                        approval_expires_at,
                        schema_version,
                    ),
                )
                approval = connection.execute(
                    "SELECT confirmation_hash, preflight_id, operation, workspace_id, expires_at, schema_version FROM git_approval_authority WHERE token_hash = ?",
                    (approval_token_hash,),
                ).fetchone()
                approval_expected = (
                    approval_confirmation_hash,
                    preflight_id,
                    operation,
                    workspace_id,
                    approval_expires_at,
                    schema_version,
                )
                if approval is None or tuple(approval) != approval_expected:
                    raise PersistenceError("git approval hash was reused with different authority")

    def load_git_preflight_authority(self, preflight_id: str) -> dict[str, Any] | None:
        normalized_id = _identifier(preflight_id, name="preflight_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM git_preflight_authority WHERE preflight_id = ?",
                (normalized_id,),
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        item["payload"] = _decode(item.pop("payload_json"), name="git preflight payload")
        return item

    def claim_git_preflight_authority(
        self,
        *,
        preflight_id: str,
        operation: str,
        workspace_id: str,
        now: float,
        approval_token_hash: str = "",
        confirmation_hash: str = "",
    ) -> dict[str, Any]:
        """Atomically consume READY authority before any Git side effect."""

        normalized_id = _identifier(preflight_id, name="preflight_id")
        normalized_operation = _text(operation, name="git_operation", maximum=32, allow_empty=False)
        normalized_workspace = _text(workspace_id, name="workspace_id", maximum=256, allow_empty=False)
        claimed_at = _finite_number(now, name="claimed_at")
        token_hash = _hash(approval_token_hash, name="approval_token_hash")
        confirm_hash = _hash(confirmation_hash, name="approval_confirmation_hash")
        if bool(token_hash) != bool(confirm_hash):
            return {"status": "approval_required"}

        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM git_preflight_authority WHERE preflight_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                return {"status": "not_found"}
            if int(row["schema_version"]) != CURRENT_SCHEMA_VERSION:
                return {"status": "schema_mismatch"}
            if row["operation"] != normalized_operation or row["workspace_id"] != normalized_workspace:
                return {"status": "binding_mismatch"}
            state = str(row["state"])
            if state != "ready":
                if state in {"executing", "succeeded", "failed", "unknown", "outcome_unknown", "invalidated"}:
                    return {"status": "already_consumed", "state": state}
                if state == "expired":
                    return {"status": "expired"}
                return {"status": "not_ready", "state": state}
            if claimed_at >= float(row["expires_at"]):
                connection.execute(
                    "UPDATE git_preflight_authority SET state = 'expired', finished_at = ? WHERE preflight_id = ? AND state = 'ready'",
                    (claimed_at, normalized_id),
                )
                return {"status": "expired"}

            approval = connection.execute(
                "SELECT * FROM git_approval_authority WHERE preflight_id = ?",
                (normalized_id,),
            ).fetchone()
            if approval is not None:
                if not token_hash:
                    return {"status": "approval_required"}
                if str(approval["token_hash"]) != token_hash:
                    return {"status": "approval_not_found"}
                if str(approval["confirmation_hash"]) != confirm_hash:
                    return {"status": "approval_confirmation_mismatch"}
                if approval["operation"] != normalized_operation or approval["workspace_id"] != normalized_workspace:
                    return {"status": "approval_mismatch"}
                if approval["consumed_at"] is not None:
                    return {"status": "approval_consumed"}
                if claimed_at >= float(approval["expires_at"]):
                    return {"status": "approval_expired"}
            elif token_hash:
                return {"status": "approval_not_found"}

            updated = connection.execute(
                "UPDATE git_preflight_authority SET state = 'executing', claimed_at = ? WHERE preflight_id = ? AND state = 'ready'",
                (claimed_at, normalized_id),
            )
            if updated.rowcount != 1:
                return {"status": "already_consumed"}
            if approval is not None:
                consumed = connection.execute(
                    "UPDATE git_approval_authority SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL",
                    (claimed_at, token_hash),
                )
                if consumed.rowcount != 1:
                    raise PersistenceError("git approval claim lost atomicity")
            return {
                "status": "claimed",
                "payload": _decode(str(row["payload_json"]), name="git preflight payload"),
            }

    def finish_git_preflight_authority(self, preflight_id: str, state: str, *, now: float) -> bool:
        normalized_id = _identifier(preflight_id, name="preflight_id")
        normalized_state = _text(state, name="git_authority_state", maximum=32, allow_empty=False)
        if normalized_state not in {"succeeded", "failed", "unknown", "outcome_unknown", "invalidated"}:
            raise PersistenceError("git terminal authority state is invalid")
        finished_at = _finite_number(now, name="finished_at")
        with self._transaction(write=True) as connection:
            result = connection.execute(
                "UPDATE git_preflight_authority SET state = ?, finished_at = ? WHERE preflight_id = ? AND state IN ('ready', 'executing')",
                (normalized_state, finished_at, normalized_id),
            )
            return result.rowcount == 1

    def save_git_mutation_outcome(self, value: object) -> None:
        record = _mapping(value, name="git mutation outcome")
        status = _text(record.get("status"), name="git_outcome_status", maximum=32, allow_empty=False)
        if status not in _GIT_OUTCOME_STATES:
            raise PersistenceError("git mutation outcome status is invalid")
        operation = _text(record.get("operation"), name="git_operation", maximum=32, allow_empty=False)
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            _identifier(record.get("preflight_id"), name="preflight_id"),
            operation,
            _text(record.get("workspace_id"), name="workspace_id", maximum=256, allow_empty=False),
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256, allow_empty=False),
            _text(record.get("task_id"), name="task_id", maximum=256, allow_empty=False),
            status,
            _json(record.get("payload"), name="git_mutation_payload", default={}),
            _finite_number(record.get("created_at"), name="created_at"),
            CURRENT_SCHEMA_VERSION,
        )
        self.run_write(
            lambda connection: connection.execute(
                """
                INSERT INTO git_mutation_outcomes(
                    receipt_id, preflight_id, operation, workspace_id,
                    working_tree_id, task_id, status, payload_json, created_at, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(receipt_id) DO NOTHING
                """,
                values,
            )
        )

    def load_git_mutation_outcome_for_preflight(self, preflight_id: str) -> dict[str, Any] | None:
        normalized_id = _identifier(preflight_id, name="preflight_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM git_mutation_outcomes WHERE preflight_id = ? ORDER BY created_at DESC, receipt_id DESC LIMIT 1",
                (normalized_id,),
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        item["payload"] = _decode(item.pop("payload_json"), name="git mutation payload")
        return item

    def save_git_trusted_partial_stage_state(self, value: object) -> None:
        record = _mapping(value, name="git trusted partial stage state")
        values = (
            _hash(record.get("state_hash"), name="state_hash", allow_empty=False),
            _text(record.get("repository_id"), name="repository_id", maximum=256, allow_empty=False),
            _text(record.get("workspace_id"), name="workspace_id", maximum=256, allow_empty=False),
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256, allow_empty=False),
            _text(record.get("task_id"), name="task_id", maximum=256, allow_empty=False),
            _text(record.get("head"), name="head", maximum=64, allow_empty=False),
            _hash(record.get("staged_diff_hash"), name="staged_diff_hash", allow_empty=False),
            _hash(record.get("index_state_hash"), name="index_state_hash", allow_empty=False),
            _finite_number(record.get("created_at"), name="created_at"),
            CURRENT_SCHEMA_VERSION,
        )
        self.run_write(
            lambda connection: connection.execute(
                """
                INSERT INTO git_trusted_partial_stage_states(
                    state_hash, repository_id, workspace_id, working_tree_id,
                    task_id, head, staged_diff_hash, index_state_hash, created_at, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(state_hash) DO NOTHING
                """,
                values,
            )
        )

    def has_git_trusted_partial_stage_state(self, state_hash: str) -> bool:
        normalized_hash = _hash(state_hash, name="state_hash", allow_empty=False)
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT 1 FROM git_trusted_partial_stage_states WHERE state_hash = ?",
                (normalized_hash,),
            ).fetchone()
        return row is not None

    def save_git_closeout(self, value: object) -> None:
        record = _mapping(value, name="git closeout")
        operation = _text(record.get("operation"), name="operation", maximum=32, allow_empty=False)
        if operation not in {
            "commit_preflight",
            "commit",
            "verified_commit_preflight",
            "verified_commit",
            "push_preflight",
            "push",
        }:
            raise PersistenceError("git closeout operation is invalid")
        values = (
            _identifier(record.get("receipt_id"), name="receipt_id"),
            operation,
            _optional_task_id(record.get("task_id")),
            _text(record.get("workspace_id"), name="workspace_id", maximum=256),
            _text(record.get("working_tree_id"), name="working_tree_id", maximum=256),
            _text(record.get("status"), name="status", maximum=64, allow_empty=False),
            1 if bool(record.get("approval_consumed", False)) else 0,
            _text(record.get("expected_head"), name="expected_head", maximum=256),
            _text(record.get("actual_head"), name="actual_head", maximum=256),
            _text(record.get("expected_remote_head"), name="expected_remote_head", maximum=256),
            _text(record.get("actual_remote_head"), name="actual_remote_head", maximum=256),
            _text(record.get("remote"), name="remote", maximum=256),
            _text(record.get("branch"), name="branch", maximum=256),
            _hash(record.get("expected_remote_url_hash"), name="expected_remote_url_hash"),
            _hash(record.get("patch_hash"), name="patch_hash"),
            _json(record.get("audit", record.get("audit_json")), name="audit", default={}),
            _text(record.get("created_at", _utc_now()), name="created_at", maximum=128, allow_empty=False),
        )
        self.run_write(lambda conn: conn.execute("INSERT INTO git_closeout_receipts(receipt_id, operation, task_id, workspace_id, working_tree_id, status, approval_consumed, expected_head, actual_head, expected_remote_head, actual_remote_head, remote, branch, expected_remote_url_hash, patch_hash, audit_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO UPDATE SET operation=excluded.operation, task_id=excluded.task_id, workspace_id=excluded.workspace_id, working_tree_id=excluded.working_tree_id, status=excluded.status, approval_consumed=excluded.approval_consumed, expected_head=excluded.expected_head, actual_head=excluded.actual_head, expected_remote_head=excluded.expected_remote_head, actual_remote_head=excluded.actual_remote_head, remote=excluded.remote, branch=excluded.branch, expected_remote_url_hash=excluded.expected_remote_url_hash, patch_hash=excluded.patch_hash, audit_json=excluded.audit_json, created_at=excluded.created_at", values))

    def load_git_closeouts(self) -> list[dict[str, Any]]:
        with self._transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM git_closeout_receipts ORDER BY created_at, receipt_id").fetchall()
        result = []
        for row in rows:
            item = _row_dict(row)
            item["approval_consumed"] = bool(item["approval_consumed"])
            item["audit"] = _decode(item.pop("audit_json"), name="git audit")
            result.append(item)
        return result

    def reconcile_terminal_git_outcomes(self) -> list[dict[str, str]]:
        """Downgrade false-success task rows using their bound durable Git receipt.

        Reconciliation is deliberately one-way: only a persisted ``succeeded``
        task whose exact bound Git receipt says ``failed`` or
        ``outcome_unknown`` is corrected.  No task is ever promoted and the
        immutable Git closeout record remains intact.
        """

        corrections: list[dict[str, str]] = []
        with self._transaction(write=True) as connection:
            rows = connection.execute(
                """
                SELECT
                    task.task_id,
                    task.detail,
                    task.git_commit_receipt_id,
                    task.git_push_receipt_id,
                    commit_receipt.status AS commit_status,
                    push_receipt.status AS push_status
                FROM task_ledger AS task
                LEFT JOIN git_closeout_receipts AS commit_receipt
                  ON commit_receipt.receipt_id = task.git_commit_receipt_id
                LEFT JOIN git_closeout_receipts AS push_receipt
                  ON push_receipt.receipt_id = task.git_push_receipt_id
                WHERE task.state = 'succeeded'
                  AND (
                    commit_receipt.status IN ('failed', 'outcome_unknown')
                    OR push_receipt.status IN ('failed', 'outcome_unknown')
                  )
                ORDER BY task.created_at, task.task_id
                """
            ).fetchall()
            for row in rows:
                item = _row_dict(row)
                operation = "push" if item.get("push_status") in {"failed", "outcome_unknown"} else "commit"
                receipt_status = str(item[f"{operation}_status"])
                receipt_field = f"git_{operation}_receipt_id"
                receipt_id = str(item.get(receipt_field, ""))
                state_after = "failed" if receipt_status == "failed" else "blocked"
                marker = f"RECONCILED_GIT_RECEIPT_OUTCOME:{operation}:{receipt_id}:{receipt_status}"
                prior_detail = str(item.get("detail", ""))
                detail = (marker if not prior_detail else f"{prior_detail} | {marker}")[:1000]
                connection.execute(
                    f"UPDATE task_ledger SET state = ?, {receipt_field} = '', result = '', result_ref = '', detail = ?, updated_at = ? WHERE task_id = ? AND state = 'succeeded'",
                    (state_after, detail, _utc_now(), item["task_id"]),
                )
                corrections.append(
                    {
                        "task_id": str(item["task_id"]),
                        "operation": operation,
                        "receipt_id": receipt_id,
                        "receipt_status": receipt_status,
                        "state_before": "succeeded",
                        "state_after": state_after,
                    }
                )
        return corrections

    @staticmethod
    def _fact_for(facts: Mapping[object, Mapping[str, Any]], record: Mapping[str, Any]) -> Mapping[str, Any] | None:
        workspace = record.get("workspace_id")
        tree = record.get("working_tree_id")
        for identity in (record.get("lease_id"), record.get("task_id"), record.get("receipt_id")):
            if identity:
                fact = facts.get((workspace, tree, identity))
                if fact is not None:
                    return fact
        fact = facts.get((workspace, tree))
        if fact is not None:
            return fact
        # Records created before working_tree_id was introduced must not be
        # silently reattached to an unrelated tree.  Only records without a
        # stored tree may use the logical-workspace fallback.
        if not tree:
            return facts.get(workspace)
        return None

    def reconcile(
        self,
        *,
        now: float | None = None,
        workspace_facts: Mapping[object, Mapping[str, Any]] | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, list[str]]:
        """Reconcile durable state, optionally scoped to one workspace.

        A workspace-local identity failure must not stale or expire records
        belonging to unrelated registered workspaces simply because their
        facts were not part of this reconciliation pass.
        """

        current_time = float(time.time() if now is None else now)
        facts = workspace_facts or {}
        scope = _identifier(workspace_id, name="workspace_id") if workspace_id is not None else None
        observed_trees = {
            (key[0], key[1])
            for key in facts
            if isinstance(key, tuple) and len(key) >= 2 and key[0] and key[1]
        }

        def tree_is_in_scope(record: Mapping[str, Any]) -> bool:
            """Return whether a scoped pass actually observed this worktree."""

            if scope is None:
                return True
            tree = record.get("working_tree_id")
            if not tree:
                # Legacy records without a tree retain the existing logical
                # workspace fallback and fail-closed reconciliation behavior.
                return True
            return (record.get("workspace_id"), tree) in observed_trees

        expired_leases: list[str] = []
        stale_leases: list[str] = []
        recovered_leases: list[str] = []
        stale_tasks: list[str] = []
        recovered_tasks: list[str] = []
        stale_verifications: list[str] = []
        stale_audits: list[str] = []
        leases = self.load_leases()
        for lease in leases:
            if scope is not None and lease["workspace_id"] != scope:
                continue
            if lease["state"] != "active":
                continue
            if float(lease["expires_at"]) <= current_time:
                self.update_lease_state(lease["lease_id"], "expired")
                expired_leases.append(lease["lease_id"])
                continue
            if not tree_is_in_scope(lease):
                continue
            fact = self._fact_for(facts, lease)
            valid = bool(fact) and fact.get("head") == lease["base_revision"]
            if valid and lease.get("working_tree_id"):
                valid = fact.get("working_tree_id") == lease["working_tree_id"]
            if valid and lease.get("workspace_wide"):
                valid = fact.get("workspace_state_hash") == lease.get("workspace_state_hash")
            elif valid and fact.get("path_hashes") is not None:
                valid = dict(fact["path_hashes"]) == _decode(lease["scope_hashes_json"], name="scope_hashes") if isinstance(lease.get("scope_hashes_json"), str) else dict(fact["path_hashes"]) == dict(lease.get("scope_hashes", {}))
            if valid:
                recovered_leases.append(lease["lease_id"])
            else:
                self.update_lease_state(lease["lease_id"], "stale")
                stale_leases.append(lease["lease_id"])
        for task in self.load_tasks():
            if scope is not None and task["workspace_id"] != scope:
                continue
            if task["state"] not in {"leased", "running", "verifying", "review_ready"}:
                continue
            if not tree_is_in_scope(task):
                continue
            fact = self._fact_for(facts, task)
            valid = bool(fact) and fact.get("head") == task["base_revision"]
            if valid and task.get("working_tree_id"):
                valid = fact.get("working_tree_id") == task["working_tree_id"]
            if valid and task.get("development_session_id"):
                valid = fact.get("development_session_id") == task["development_session_id"]
            if valid and task.get("patch_hash"):
                valid = fact.get("patch_hash") == task["patch_hash"]
            if valid:
                self.save_task({**task, "state": "ready", "updated_at": _utc_now()})
                recovered_tasks.append(task["task_id"])
            else:
                self.save_task({**task, "state": "stale", "updated_at": _utc_now()})
                stale_tasks.append(task["task_id"])
        for receipt in self.load_verifications():
            if scope is not None and receipt["workspace_id"] != scope:
                continue
            if not tree_is_in_scope(receipt):
                continue
            fact = self._fact_for(facts, receipt)
            if not receipt["stale"] and (
                not fact
                or fact.get("head") != receipt["base_revision"]
                or (fact.get("working_tree_id") is not None and fact.get("working_tree_id") != receipt["working_tree_id"])
                or (fact.get("diff_hash") is not None and fact.get("diff_hash") != receipt["diff_hash"])
            ):
                self.run_write(lambda conn, receipt_id=receipt["receipt_id"]: conn.execute("UPDATE verification_receipts SET status='stale', stale=1 WHERE receipt_id = ?", (receipt_id,)))
                stale_verifications.append(receipt["receipt_id"])
        for receipt in self.load_security_audits():
            if scope is not None and receipt["workspace_id"] != scope:
                continue
            if not tree_is_in_scope(receipt):
                continue
            # A task-bound audit may share a working tree with a task fact.
            # Prefer the receipt identity so a task's intentionally omitted
            # raw patch hash cannot mask the audit's reproducible diff fact.
            fact = facts.get((receipt.get("workspace_id"), receipt.get("working_tree_id"), receipt.get("receipt_id")))
            if fact is None:
                fact = self._fact_for(facts, receipt)
            patch_valid = not receipt["patch_hash"]
            if receipt["patch_hash"]:
                patch_valid = bool(fact) and fact.get("patch_hash") == receipt["patch_hash"]
                # A security audit created from a verification receipt uses
                # the current diff digest as its patch field when no raw
                # patch text was supplied.  That digest is reproducible from
                # the working tree after restart, whereas an independent
                # patch digest must remain fail-closed without the raw patch.
                if (
                    not patch_valid
                    and fact
                    and fact.get("patch_hash") is None
                    and receipt.get("verification_receipt_id")
                    and receipt["patch_hash"] == receipt["diff_hash"]
                ):
                    patch_valid = fact.get("diff_hash") == receipt["patch_hash"]
            if not receipt["stale"] and (
                not fact
                or fact.get("head") != receipt["base_revision"]
                or (fact.get("working_tree_id") is not None and fact.get("working_tree_id") != receipt["working_tree_id"])
                or (fact.get("diff_hash") is not None and fact.get("diff_hash") != receipt["diff_hash"])
                or not patch_valid
            ):
                self.run_write(lambda conn, receipt_id=receipt["receipt_id"]: conn.execute("UPDATE security_audit_receipts SET stale=1 WHERE receipt_id = ?", (receipt_id,)))
                stale_audits.append(receipt["receipt_id"])
        return {
            "expired_leases": expired_leases,
            "stale_leases": stale_leases,
            "recovered_leases": recovered_leases,
            "stale_tasks": stale_tasks,
            "recovered_tasks": recovered_tasks,
            "stale_verifications": stale_verifications,
            "stale_audits": stale_audits,
        }

    def save_development_loop(self, state: object, *, pending_action: str = "") -> None:
        from .development_loop import DevelopmentLoopState
        if not isinstance(state, DevelopmentLoopState):
            raise PersistenceError("development loop state is invalid")
        values = (
            _identifier(state.loop_id, name="loop_id"), _identifier(state.owner_id, name="owner_id"),
            _identifier(state.task_id, name="task_id"), _identifier(state.session_id, name="session_id"),
            _identifier(state.worktree_id, name="worktree_id"), _text(state.phase, name="loop_phase", maximum=32, allow_empty=False),
            _json(state.budgets.__dict__, name="loop_budgets", default={}), float(state.started_at), int(state.repeated_failure_count),
            _text(state.last_failure_fingerprint, name="last_failure_fingerprint", maximum=256), int(state.no_progress_count),
            _text(state.last_progress_token, name="last_progress_token", maximum=256), _text(state.stop_reason, name="loop_stop_reason", maximum=128),
            _text(pending_action, name="pending_action", maximum=128), _utc_now(),
        )
        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute("SELECT owner_id, task_id, session_id, worktree_id, started_at FROM development_loops WHERE loop_id = ?", (values[0],)).fetchone()
            if existing is not None and tuple(existing) != (values[1], values[2], values[3], values[4], values[7]):
                raise PersistenceError("loop id is already bound to different identity")
            stored = connection.execute("SELECT event_id, event_fingerprint, from_phase, to_phase, reason, occurred_at, sequence FROM development_loop_events WHERE loop_id = ? ORDER BY sequence", (values[0],)).fetchall()
            if len(stored) > len(state.history):
                raise PersistenceError("development loop history cannot move backwards")
            for index, row in enumerate(stored):
                entry = state.history[index]
                if tuple(row) != (entry.event_id, entry.event_fingerprint, entry.from_phase, entry.to_phase, entry.reason, float(entry.at), index):
                    raise PersistenceError("development loop event history conflicts with persisted evidence")
            connection.execute("""INSERT INTO development_loops(loop_id, owner_id, task_id, session_id, worktree_id, phase, budgets_json, started_at, repeated_failure_count, last_failure_fingerprint, no_progress_count, last_progress_token, stop_reason, pending_action, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(loop_id) DO UPDATE SET phase=excluded.phase, budgets_json=excluded.budgets_json, repeated_failure_count=excluded.repeated_failure_count, last_failure_fingerprint=excluded.last_failure_fingerprint, no_progress_count=excluded.no_progress_count, last_progress_token=excluded.last_progress_token, stop_reason=excluded.stop_reason, pending_action=excluded.pending_action, updated_at=excluded.updated_at""", values)
            for index, entry in enumerate(state.history[len(stored):], start=len(stored)):
                connection.execute("INSERT INTO development_loop_events(loop_id, event_id, event_fingerprint, from_phase, to_phase, reason, occurred_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (values[0], _identifier(entry.event_id, name="loop_event_id"), _hash(entry.event_fingerprint, name="loop_event_fingerprint", allow_empty=False), entry.from_phase, entry.to_phase, entry.reason, float(entry.at), index))
        self.run_write(write)

    def load_development_loop(self, loop_id: str) -> dict[str, Any] | None:
        from .development_loop import DevelopmentLoopState, LoopBudgets, LoopHistoryEntry
        parsed = _identifier(loop_id, name="loop_id")
        with self._transaction(write=False) as connection:
            row = connection.execute("SELECT * FROM development_loops WHERE loop_id = ?", (parsed,)).fetchone()
            if row is None:
                return None
            events = connection.execute("SELECT * FROM development_loop_events WHERE loop_id = ? ORDER BY sequence", (parsed,)).fetchall()
        item = _row_dict(row); budgets = _decode(item["budgets_json"], name="loop_budgets")
        if not isinstance(budgets, dict):
            raise PersistenceCorruptError("stored loop budgets are invalid")
        state = DevelopmentLoopState(loop_id=str(item["loop_id"]), owner_id=str(item["owner_id"]), task_id=str(item["task_id"]), session_id=str(item["session_id"]), worktree_id=str(item["worktree_id"]), budgets=LoopBudgets(**budgets), started_at=float(item["started_at"]), phase=str(item["phase"]), history=tuple(LoopHistoryEntry(str(event["event_id"]), str(event["event_fingerprint"]), str(event["from_phase"]), str(event["to_phase"]), str(event["reason"]), float(event["occurred_at"])) for event in events), repeated_failure_count=int(item["repeated_failure_count"]), last_failure_fingerprint=str(item["last_failure_fingerprint"]), no_progress_count=int(item["no_progress_count"]), last_progress_token=str(item["last_progress_token"]), stop_reason=str(item["stop_reason"]))
        return {"state": state, "pending_action": str(item["pending_action"]), "updated_at": str(item["updated_at"])}

    def save_visual_regression_baseline(self, baseline: object) -> None:
        from .visual_regression import VisualRegressionBaseline
        if not isinstance(baseline, VisualRegressionBaseline):
            raise PersistenceError("visual regression baseline is invalid")
        identity, evidence = baseline.identity, baseline.evidence
        values = (
            _identifier(baseline.baseline_id, name="baseline_id"), _identifier(identity.scenario_id, name="scenario_id"),
            _text(identity.revision.lower(), name="revision", maximum=64, allow_empty=False), int(identity.viewport[0]), int(identity.viewport[1]),
            _identifier(identity.theme, name="theme"), _hash(evidence.screenshot_digest, name="screenshot_digest", allow_empty=False),
            _text(evidence.screenshot_ref, name="screenshot_ref", maximum=512, allow_empty=False), _hash(evidence.dom_fingerprint, name="dom_fingerprint", allow_empty=False),
            _hash(evidence.accessibility_fingerprint, name="accessibility_fingerprint", allow_empty=False), _hash(evidence.text_fingerprint, name="text_fingerprint", allow_empty=False),
            _hash(evidence.boxes_fingerprint, name="boxes_fingerprint", allow_empty=False), _text(baseline.created_at, name="created_at", maximum=128, allow_empty=False),
        )
        if not values[7].startswith("artifact:"):
            raise PersistenceError("screenshot_ref must be an artifact reference")
        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute("SELECT * FROM visual_regression_baselines WHERE baseline_id = ?", (values[0],)).fetchone()
            if existing is not None:
                stored = (str(existing["baseline_id"]), str(existing["scenario_id"]), str(existing["revision"]), int(existing["viewport_width"]), int(existing["viewport_height"]), str(existing["theme"]), str(existing["screenshot_digest"]), str(existing["screenshot_ref"]), str(existing["dom_fingerprint"]), str(existing["accessibility_fingerprint"]), str(existing["text_fingerprint"]), str(existing["boxes_fingerprint"]), str(existing["created_at"]))
                if stored != values:
                    raise PersistenceError("visual baseline id is already bound to different evidence")
                return
            connection.execute("INSERT INTO visual_regression_baselines(baseline_id, scenario_id, revision, viewport_width, viewport_height, theme, screenshot_digest, screenshot_ref, dom_fingerprint, accessibility_fingerprint, text_fingerprint, boxes_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values)
        self.run_write(write)

    def load_visual_regression_baseline(self, baseline_id: str):
        from .visual_regression import VisualBaselineIdentity, VisualEvidence, VisualRegressionBaseline
        with self._transaction(write=False) as connection:
            row = connection.execute("SELECT * FROM visual_regression_baselines WHERE baseline_id = ?", (_identifier(baseline_id, name="baseline_id"),)).fetchone()
        if row is None:
            return None
        identity = VisualBaselineIdentity(str(row["scenario_id"]), str(row["revision"]), (int(row["viewport_width"]), int(row["viewport_height"])), str(row["theme"]))
        evidence = VisualEvidence(str(row["screenshot_digest"]), str(row["screenshot_ref"]), str(row["dom_fingerprint"]), str(row["accessibility_fingerprint"]), str(row["text_fingerprint"]), str(row["boxes_fingerprint"]))
        return VisualRegressionBaseline(str(row["baseline_id"]), identity, evidence, str(row["created_at"]))

    def save_acceleration_receipt(self, value: object) -> None:
        record = _mapping(value, name="acceleration receipt")
        allowed = {"receipt_id", "kind", "subject_id", "reason", "evidence_hashes", "refs", "metadata", "created_at", "external_execution"}
        if set(record) - allowed:
            raise PersistenceError("acceleration receipt contains non-persistable fields")
        kind = _text(record.get("kind"), name="acceleration_kind", maximum=64, allow_empty=False)
        if kind not in {"semantic", "context", "performance", "verification_selection", "verification_cache", "loop", "qa", "review_link", "capability", "delivery", "readiness"}:
            raise PersistenceError("acceleration receipt kind is invalid")
        raw_hashes, raw_refs, metadata = record.get("evidence_hashes", []), record.get("refs", []), record.get("metadata", {})
        if not isinstance(raw_hashes, (list, tuple)) or not isinstance(raw_refs, (list, tuple)) or len(raw_hashes) > 128 or len(raw_refs) > 128 or not isinstance(metadata, Mapping):
            raise PersistenceError("acceleration receipt evidence is invalid")
        denied = {"source", "source_text", "content", "payload", "secret", "token", "password", "credential"}
        if any(str(key).casefold() in denied for key in metadata):
            raise PersistenceError("acceleration metadata contains a denied field")
        hashes = [_hash(item, name="acceleration_evidence_hash", allow_empty=False) for item in raw_hashes]
        refs = [_text(item, name="acceleration_ref", maximum=512, allow_empty=False) for item in raw_refs]
        values = (_identifier(record.get("receipt_id"), name="receipt_id"), kind, _identifier(record.get("subject_id"), name="subject_id"), _text(record.get("reason"), name="acceleration_reason", maximum=400, allow_empty=False), _json(sorted(hashes), name="acceleration_evidence_hashes", default=[]), _json(sorted(refs), name="acceleration_refs", default=[]), _json(dict(metadata), name="acceleration_metadata", default={}), _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False))
        self.run_write(lambda connection: connection.execute("INSERT INTO acceleration_receipts(receipt_id, kind, subject_id, reason, evidence_hashes_json, refs_json, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO NOTHING", values))

    def load_acceleration_receipts(self, *, kind: str | None = None, limit: int = 256) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 4096:
            raise PersistenceError("acceleration receipt limit is invalid")
        with self._transaction(write=False) as connection:
            if kind is None:
                rows = connection.execute("SELECT * FROM acceleration_receipts ORDER BY created_at DESC, receipt_id LIMIT ?", (limit,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM acceleration_receipts WHERE kind = ? ORDER BY created_at DESC, receipt_id LIMIT ?", (_text(kind, name="acceleration_kind", maximum=64, allow_empty=False), limit)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["evidence_hashes"] = _decode(item.pop("evidence_hashes_json"), name="acceleration_evidence_hashes")
            item["refs"] = _decode(item.pop("refs_json"), name="acceleration_refs")
            item["metadata"] = _decode(item.pop("metadata_json"), name="acceleration_metadata")
            item["external_execution"] = False
            result.append(item)
        return result

    def get_acceleration_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        """Read one bounded acceleration receipt without changing its state."""

        identifier = _identifier(receipt_id, name="receipt_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM acceleration_receipts WHERE receipt_id = ?",
                (identifier,),
            ).fetchone()
        return self._decode_acceleration_receipt_row(row) if row is not None else None

    @staticmethod
    def _operator_receipt_metadata_safe(value: object) -> bool:
        """Reject raw operator inputs and secrets at the persistence boundary."""

        denied_keys = {
            "args",
            "arguments",
            "raw_args",
            "raw_arguments",
            "patch",
            "patch_content",
            "command_output",
            "approval_token",
            "token",
            "credential",
            "credentials",
            "secret",
            "password",
        }
        if isinstance(value, Mapping):
            return all(
                str(key).casefold() not in denied_keys
                and SqliteDirectorStore._operator_receipt_metadata_safe(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return all(SqliteDirectorStore._operator_receipt_metadata_safe(item) for item in value)
        return True

    @staticmethod
    def _operator_receipt_values(record: object) -> tuple[tuple[object, ...], dict[str, Any]]:
        value = _mapping(record, name="operator receipt")
        allowed = {
            "receipt_id",
            "kind",
            "subject_id",
            "reason",
            "evidence_hashes",
            "refs",
            "metadata",
            "created_at",
            "external_execution",
        }
        if set(value) - allowed:
            raise PersistenceError("operator receipt contains non-persistable fields")
        if value.get("kind") != "operator":
            raise PersistenceError("operator receipt kind is invalid")
        metadata = value.get("metadata")
        if not isinstance(metadata, Mapping) or not SqliteDirectorStore._operator_receipt_metadata_safe(metadata):
            raise PersistenceError("operator receipt metadata contains raw input or sensitive fields")
        if set(str(key) for key in metadata) - _OPERATOR_RECEIPT_METADATA_FIELDS:
            raise PersistenceError("operator receipt metadata contains an unsupported field")
        if any(
            not isinstance(item, (str, bool, int, float))
            or (isinstance(item, float) and not math.isfinite(item))
            for item in metadata.values()
        ):
            raise PersistenceError("operator receipt metadata values must be scalar")
        record_type = metadata.get("record_type")
        if record_type not in {"preflight", "claim", "outcome"}:
            raise PersistenceError("operator receipt record type is invalid")
        raw_hashes = value.get("evidence_hashes", [])
        raw_refs = value.get("refs", [])
        if (
            not isinstance(raw_hashes, (list, tuple))
            or not isinstance(raw_refs, (list, tuple))
            or len(raw_hashes) > 32
            or len(raw_refs) > 32
        ):
            raise PersistenceError("operator receipt evidence is invalid")
        hashes = [_hash(item, name="operator_evidence_hash", allow_empty=False) for item in raw_hashes]
        refs = [_text(item, name="operator_ref", maximum=512, allow_empty=False) for item in raw_refs]
        normalized_metadata = dict(metadata)
        metadata_json = _json(
            normalized_metadata,
            name="operator_metadata",
            default={},
            reject_forbidden_text=True,
        )
        values = (
            _identifier(value.get("receipt_id"), name="receipt_id"),
            "operator",
            _identifier(value.get("subject_id"), name="subject_id"),
            _text(value.get("reason"), name="operator_reason", maximum=400, allow_empty=False),
            _json(sorted(hashes), name="operator_evidence_hashes", default=[]),
            _json(sorted(refs), name="operator_refs", default=[]),
            metadata_json,
            _text(value.get("created_at"), name="created_at", maximum=128, allow_empty=False),
        )
        return values, {
            "receipt_id": values[0],
            "kind": values[1],
            "subject_id": values[2],
            "reason": values[3],
            "evidence_hashes": sorted(hashes),
            "refs": sorted(refs),
            "metadata": normalized_metadata,
            "created_at": values[7],
            "external_execution": False,
        }

    @staticmethod
    def _decode_acceleration_receipt_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        item = _row_dict(row)
        item["evidence_hashes"] = _decode(item.pop("evidence_hashes_json"), name="acceleration_evidence_hashes")
        item["refs"] = _decode(item.pop("refs_json"), name="acceleration_refs")
        item["metadata"] = _decode(item.pop("metadata_json"), name="acceleration_metadata")
        item["external_execution"] = False
        return item

    def save_operator_receipt(self, value: object) -> None:
        """Persist one immutable external-operator receipt in schema 14 storage.

        The operator deliberately reuses ``acceleration_receipts`` instead of
        creating a second state database.  The record type and metadata
        allowlist keep audit evidence bounded and prevent raw CLI input from
        crossing this boundary.
        """

        values, _normalized = self._operator_receipt_values(value)

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT receipt_id, kind, subject_id, reason, evidence_hashes_json, refs_json, metadata_json, created_at "
                "FROM acceleration_receipts WHERE receipt_id = ?",
                (values[0],),
            ).fetchone()
            if existing is not None:
                existing_values = tuple(existing[index] for index in range(len(values)))
                if existing_values != values:
                    raise IdempotencyConflict("OPERATOR_RECEIPT_CONFLICT")
                return
            connection.execute(
                "INSERT INTO acceleration_receipts(receipt_id, kind, subject_id, reason, evidence_hashes_json, refs_json, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

        self.run_write(write)

    def get_operator_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        identifier = _identifier(receipt_id, name="receipt_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM acceleration_receipts WHERE receipt_id = ? AND kind = 'operator'",
                (identifier,),
            ).fetchone()
        return self._decode_acceleration_receipt_row(row) if row is not None else None

    @staticmethod
    def _operator_marker_id(kind: str, receipt_id: str) -> str:
        return f"operator:{kind}:{receipt_id}"

    def get_operator_outcome(self, preflight_id: str) -> dict[str, Any] | None:
        return self.get_operator_receipt(self._operator_marker_id("outcome", _identifier(preflight_id, name="receipt_id")))

    def claim_operator_receipt(
        self,
        receipt_id: str,
        *,
        actor: str,
        claimed_at: float | None = None,
    ) -> dict[str, Any]:
        """Atomically claim a preflight exactly once across operator processes."""

        preflight_id = _identifier(receipt_id, name="receipt_id")
        actor_id = _identifier(actor, name="actor")
        timestamp = _utc_now() if claimed_at is None else datetime.fromtimestamp(
            _finite_number(claimed_at, name="claimed_at"), tz=timezone.utc
        ).isoformat().replace("+00:00", "Z")
        claim_id = self._operator_marker_id("claim", preflight_id)
        outcome_id = self._operator_marker_id("outcome", preflight_id)

        def write(connection: sqlite3.Connection) -> dict[str, Any]:
            preflight = connection.execute(
                "SELECT * FROM acceleration_receipts WHERE receipt_id = ? AND kind = 'operator'",
                (preflight_id,),
            ).fetchone()
            if preflight is None:
                raise PersistenceError("operator preflight receipt is unavailable")
            preflight_item = self._decode_acceleration_receipt_row(preflight)
            if preflight_item.get("metadata", {}).get("record_type") != "preflight":
                raise PersistenceError("operator receipt is not a preflight")
            outcome = connection.execute(
                "SELECT * FROM acceleration_receipts WHERE receipt_id = ? AND kind = 'operator'",
                (outcome_id,),
            ).fetchone()
            if outcome is not None:
                return {
                    "status": "completed",
                    "receipt_id": preflight_id,
                    "outcome": self._decode_acceleration_receipt_row(outcome),
                }
            claimed = connection.execute(
                "SELECT * FROM acceleration_receipts WHERE receipt_id = ? AND kind = 'operator'",
                (claim_id,),
            ).fetchone()
            if claimed is not None:
                return {"status": "already_claimed", "receipt_id": preflight_id}
            claim_record = {
                "receipt_id": claim_id,
                "kind": "operator",
                "subject_id": str(preflight_item["subject_id"]),
                "reason": "external operator preflight claim",
                "evidence_hashes": list(preflight_item.get("evidence_hashes", [])),
                "refs": [],
                "metadata": {
                    "record_type": "claim",
                    "preflight_id": preflight_id,
                    "actor": actor_id,
                },
                "created_at": timestamp,
            }
            claim_values, _normalized = self._operator_receipt_values(claim_record)
            connection.execute(
                "INSERT INTO acceleration_receipts(receipt_id, kind, subject_id, reason, evidence_hashes_json, refs_json, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                claim_values,
            )
            return {"status": "claimed", "receipt_id": preflight_id, "claim_id": claim_id}

        return self.run_write(write)

    def save_context_checkpoint(self, value: object) -> None:
        record = _mapping(value, name="context checkpoint")
        checkpoint_id = _identifier(record.get("checkpoint_id"), name="checkpoint_id")
        workspace_id = _identifier(record.get("workspace_id"), name="workspace_id")
        head = _text(record.get("head"), name="checkpoint_head", maximum=64, allow_empty=False).lower()
        if not re.fullmatch(r"[0-9a-f]{40}", head):
            raise PersistenceError("checkpoint head is invalid")
        task_id = _identifier(record.get("task_id"), name="task_id")
        outcome = _text(record.get("outcome"), name="checkpoint_outcome", maximum=240, allow_empty=False)
        next_action = _text(record.get("next_action"), name="checkpoint_next_action", maximum=1000, allow_empty=False)
        state = record.get("state")
        if not isinstance(state, Mapping):
            raise PersistenceError("checkpoint state must be an object")
        if state.get("workspace_id") != workspace_id or state.get("head") != head:
            raise PersistenceError("checkpoint state identity does not match checkpoint")
        state_json = _json(dict(state), name="context_checkpoint_state", default={})
        created_at = _text(record.get("created_at"), name="created_at", maximum=128, allow_empty=False)
        values = (checkpoint_id, workspace_id, head, task_id, outcome, next_action, state_json, created_at)

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute("SELECT * FROM context_checkpoints WHERE checkpoint_id = ?", (checkpoint_id,)).fetchone()
            if existing is not None:
                stored = (
                    str(existing["checkpoint_id"]), str(existing["workspace_id"]), str(existing["head"]),
                    str(existing["task_id"]), str(existing["outcome"]), str(existing["next_action"]),
                    str(existing["state_json"]),
                )
                if stored != values[:-1]:
                    raise PersistenceError("checkpoint id is already bound to different content")
                return
            connection.execute(
                "INSERT INTO context_checkpoints(checkpoint_id, workspace_id, head, task_id, outcome, next_action, state_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
            stale = connection.execute(
                "SELECT checkpoint_id FROM context_checkpoints WHERE workspace_id = ? ORDER BY created_at DESC, checkpoint_id DESC LIMIT -1 OFFSET 64",
                (workspace_id,),
            ).fetchall()
            if stale:
                connection.executemany("DELETE FROM context_checkpoints WHERE checkpoint_id = ?", [(row[0],) for row in stale])

        self.run_write(write)

    def load_latest_context_checkpoint(self, workspace_id: str) -> dict[str, Any] | None:
        parsed_workspace = _identifier(workspace_id, name="workspace_id")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM context_checkpoints WHERE workspace_id = ? ORDER BY created_at DESC, checkpoint_id DESC LIMIT 1",
                (parsed_workspace,),
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        state = _decode(item.pop("state_json"), name="context_checkpoint_state")
        if not isinstance(state, dict):
            raise PersistenceCorruptError("stored context checkpoint state is invalid")
        item["state"] = state
        return item

    def save_cloud_performance_profile(self, value: object) -> None:
        """Persist bounded aggregate timing evidence only; never raw benchmark output."""

        record = _mapping(value, name="cloud performance profile")
        profile_id = _identifier(record.get("profile_id"), name="profile_id", maximum=128)
        if not profile_id.startswith("profile:"):
            raise PersistenceError("profile_id is invalid")
        workload = _identifier(record.get("workload_class"), name="workload_class", maximum=128)
        project = _identifier(record.get("project_fingerprint"), name="project_fingerprint", maximum=256)
        local_env = _identifier(record.get("local_environment_fingerprint"), name="local_environment_fingerprint", maximum=256)
        cloud_env = _identifier(record.get("cloud_environment_fingerprint"), name="cloud_environment_fingerprint", maximum=256)
        benchmark = _identifier(record.get("benchmark_revision"), name="benchmark_revision", maximum=256)

        def count(name: str) -> int:
            raw = record.get(name)
            if not isinstance(raw, int) or isinstance(raw, bool) or not 0 <= raw <= 1_000_000:
                raise PersistenceError(f"{name} is invalid")
            return raw

        def finite(name: str, *, rate: bool = False) -> float:
            raw = record.get(name)
            if not isinstance(raw, (int, float)) or isinstance(raw, bool):
                raise PersistenceError(f"{name} is invalid")
            parsed = float(raw)
            if not math.isfinite(parsed) or parsed < 0 or (rate and parsed > 1.0):
                raise PersistenceError(f"{name} is invalid")
            return parsed

        def flag(name: str) -> bool:
            raw = record.get(name)
            if not isinstance(raw, bool):
                raise PersistenceError(f"{name} must be boolean")
            return raw

        billable = flag("billable_api")
        if billable:
            raise PersistenceError("managed cloud performance profile cannot contain billable API evidence")
        observed_at = finite("observed_at")
        expires_at = finite("expires_at")
        if expires_at <= observed_at:
            raise PersistenceError("cloud performance profile expiry is invalid")
        values = (
            profile_id,
            workload,
            project,
            local_env,
            cloud_env,
            benchmark,
            count("local_success_samples"),
            count("cloud_success_samples"),
            finite("local_p50_ms"),
            finite("local_p95_ms"),
            finite("cloud_p50_ms"),
            finite("cloud_p95_ms"),
            finite("cloud_stage_p50_ms"),
            finite("cloud_return_p50_ms"),
            finite("local_failure_rate", rate=True),
            finite("cloud_failure_rate", rate=True),
            finite("speed_ratio_p50"),
            observed_at,
            expires_at,
            0,
            int(flag("sufficient")),
            int(flag("managed_cloud_wins")),
        )

        def write(connection: sqlite3.Connection) -> None:
            existing = connection.execute(
                "SELECT * FROM cloud_performance_profiles WHERE profile_id = ?",
                (profile_id,),
            ).fetchone()
            if existing is not None:
                stored = tuple(existing[index] for index in range(len(values)))
                if stored != values:
                    raise PersistenceError("profile_id is already bound to different performance evidence")
                return
            connection.execute(
                "INSERT INTO cloud_performance_profiles(profile_id, workload_class, project_fingerprint, local_environment_fingerprint, cloud_environment_fingerprint, benchmark_revision, local_success_samples, cloud_success_samples, local_p50_ms, local_p95_ms, cloud_p50_ms, cloud_p95_ms, cloud_stage_p50_ms, cloud_return_p50_ms, local_failure_rate, cloud_failure_rate, speed_ratio_p50, observed_at, expires_at, billable_api, sufficient, managed_cloud_wins) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
            stale = connection.execute(
                "SELECT profile_id FROM cloud_performance_profiles WHERE workload_class = ? AND project_fingerprint = ? ORDER BY observed_at DESC, profile_id DESC LIMIT -1 OFFSET 64",
                (workload, project),
            ).fetchall()
            if stale:
                connection.executemany(
                    "DELETE FROM cloud_performance_profiles WHERE profile_id = ?",
                    [(row[0],) for row in stale],
                )

        self.run_write(write)

    def load_cloud_performance_profile(
        self,
        *,
        workload_class: str,
        project_fingerprint: str,
        local_environment_fingerprint: str,
        cloud_environment_fingerprint: str,
        benchmark_revision: str,
    ) -> dict[str, Any] | None:
        values = (
            _identifier(workload_class, name="workload_class", maximum=128),
            _identifier(project_fingerprint, name="project_fingerprint", maximum=256),
            _identifier(local_environment_fingerprint, name="local_environment_fingerprint", maximum=256),
            _identifier(cloud_environment_fingerprint, name="cloud_environment_fingerprint", maximum=256),
            _identifier(benchmark_revision, name="benchmark_revision", maximum=256),
        )
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM cloud_performance_profiles WHERE workload_class = ? AND project_fingerprint = ? AND local_environment_fingerprint = ? AND cloud_environment_fingerprint = ? AND benchmark_revision = ? ORDER BY observed_at DESC, profile_id DESC LIMIT 1",
                values,
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        for key in ("billable_api", "sufficient", "managed_cloud_wins"):
            item[key] = bool(item[key])
        return item

    def cleanup(self, *, retention_seconds: float = 30 * 24 * 60 * 60, max_rows_per_table: int = 512) -> dict[str, int]:
        if retention_seconds < 0 or not 1 <= max_rows_per_table <= 10000:
            raise PersistenceError("retention bounds are invalid")
        process_bindings_removed = self.purge_task_process_bindings(now=time.time())
        cutoff = datetime.fromtimestamp(time.time() - retention_seconds, timezone.utc).isoformat().replace("+00:00", "Z")
        tables = (
            ("task_ledger", "created_at", "state IN ('succeeded','failed','cancelled','blocked','stale')", cutoff),
            ("writer_leases", "acquired_at", "state IN ('released','expired','stale')", time.time() - retention_seconds),
            ("verification_receipts", "recorded_at", "stale = 1 OR status = 'stale'", cutoff),
            ("security_audit_receipts", "audited_at", "stale = 1", cutoff),
            ("review_receipts", "reviewed_at", "1=1", time.time() - retention_seconds),
            ("integration_receipts", "created_at", "integration_outcome != 'active'", cutoff),
            ("git_closeout_receipts", "created_at", "1=1", cutoff),
            ("provisioning_events", "recorded_at", "1=1", cutoff),
            ("request_lifecycle_events", "recorded_at", "1=1", cutoff),
            ("development_start_requests", "updated_at", "state IN ('succeeded','failed')", cutoff),
            ("cloud_performance_profiles", "expires_at", "1=1", time.time()),
        )
        removed: dict[str, int] = {"task_process_bindings": process_bindings_removed}
        with self._transaction(write=True) as connection:
            removed["readonly_roots"] = self._cleanup_readonly_roots(
                connection,
                cutoff=time.time() - retention_seconds,
                max_rows=max_rows_per_table,
            )
            for table, timestamp_column, predicate, table_cutoff in tables:
                cursor = connection.execute(f"DELETE FROM {table} WHERE ({predicate}) AND {timestamp_column} < ?", (table_cutoff,))
                count = cursor.rowcount
                rows = connection.execute(f"SELECT rowid FROM {table} WHERE ({predicate}) ORDER BY {timestamp_column} DESC, rowid DESC LIMIT -1 OFFSET ?", (max_rows_per_table,)).fetchall()
                for row in rows:
                    connection.execute(f"DELETE FROM {table} WHERE rowid = ?", (row[0],))
                removed[table] = count + len(rows)
        # Checkpoint after the write transaction has released its lock.  A
        # checkpoint inside BEGIN IMMEDIATE can report SQLITE_BUSY even though
        # the cleanup itself was atomic and successful.
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
                # A small fixed reclaim budget avoids a long-lived WAL/state
                # store accumulating free pages without turning maintenance
                # into an unbounded I/O operation.
                connection.execute(f"PRAGMA incremental_vacuum({INCREMENTAL_VACUUM_PAGES})")
                self._restrict_database_assets()
            except sqlite3.DatabaseError as exc:
                raise PersistenceError("SQLite WAL checkpoint failed") from exc
            finally:
                connection.close()
        return removed


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "DEFAULT_DATA_DIR",
    "IdempotencyConflict",
    "PersistenceCorruptError",
    "PersistenceError",
    "ReadOnlyRootCapacityError",
    "ReadOnlyRootConflictError",
    "ReadOnlyRootScopeConflictError",
    "SqliteDirectorStore",
    "director_db_path",
    "inspect_readonly_roots_schema",
]
