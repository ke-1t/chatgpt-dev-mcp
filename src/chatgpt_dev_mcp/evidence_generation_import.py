"""Bounded, evidence-preserving import between Director generations.

Only the requested session and its durable dependency closure are read from
the source database.  The destination is mutated through
``SqliteDirectorStore.import_evidence_generation`` in one transaction; this
module never copies a database, edits a sidecar, or attaches SQLite files.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Mapping

from .persistence import CURRENT_SCHEMA_VERSION, PersistenceError, SqliteDirectorStore


MAX_DEPENDENCY_RECORDS = 128
SUPPORTED_SOURCE_SCHEMAS = frozenset({13, 14})


class EvidenceGenerationImportError(RuntimeError):
    """A generation import cannot be trusted or completed atomically."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass(frozen=True)
class EvidenceGenerationBundle:
    source_generation: str
    source_database: Path
    source_database_sha256: str
    source_schema_version: int
    destination_schema_version: int
    session_id: str
    task_ids: tuple[str, ...]
    records: Mapping[str, tuple[Mapping[str, Any], ...]]
    record_hashes: Mapping[str, str]
    source_state: Mapping[str, Any]
    source_data_version: int
    source_device: int
    source_inode: int
    source_sidecar_sha256: str = ""


@dataclass(frozen=True)
class EvidenceImportPlan:
    bundle: EvidenceGenerationBundle
    destination_database: Path
    destination_database_sha256: str
    import_id: str
    destination_state: Mapping[str, Any]
    destination_data_version: int
    destination_device: int
    destination_inode: int


_RECEIPT_FIELDS = (
    ("verification_receipt_id", "verification_receipts"),
    ("security_audit_receipt_id", "security_audit_receipts"),
    ("integration_receipt_id", "integration_receipts"),
    ("git_commit_receipt_id", "git_closeout_receipts"),
)
_PRIMARY_KEYS = {
    "task_ledger": "task_id",
    "development_sessions": "session_id",
    "writer_leases": "lease_id",
    "verification_receipts": "receipt_id",
    "security_audit_receipts": "receipt_id",
    "integration_receipts": "receipt_id",
    "git_closeout_receipts": "receipt_id",
}
_TABLE_ORDER = (
    "task_ledger",
    "development_sessions",
    "writer_leases",
    "verification_receipts",
    "security_audit_receipts",
    "integration_receipts",
    "git_closeout_receipts",
)
_SIDECAR_FIELDS = (
    "session_id",
    "workspace_id",
    "task_id",
    "owner_id",
    "source_revision",
    "base_commit",
    "worktree_id",
    "worktree_path",
    "lifecycle_state",
    "stale",
    "source_dirty",
)
_SIDECAR_STRING_LIMITS = {
    "session_id": 160,
    "workspace_id": 160,
    "task_id": 256,
    "owner_id": 160,
    "source_revision": 128,
    "base_commit": 128,
    "worktree_id": 256,
    "worktree_path": 1024,
    "lifecycle_state": 64,
}


def _absolute_lexical(path: Path, *, field: str) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise EvidenceGenerationImportError("PATH_NOT_ABSOLUTE", f"{field} must be absolute")
    lexical = Path(os.path.abspath(str(expanded)))
    current = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        current /= component
        try:
            if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
                raise EvidenceGenerationImportError("PATH_SYMLINK", f"{field} contains a symlink")
        except OSError as exc:
            raise EvidenceGenerationImportError("PATH_UNREADABLE", f"{field} cannot be inspected") from exc
    return lexical


def _database_error_code(role: str, suffix: str) -> str:
    prefixes = {
        "source": "SOURCE_DATABASE",
        "destination": "DESTINATION_DATABASE",
    }
    try:
        return f"{prefixes[role]}_{suffix}"
    except KeyError as exc:
        raise ValueError(f"unsupported database role: {role}") from exc


def _regular_database(path: Path, *, field: str, role: str) -> Path:
    lexical = _absolute_lexical(path, field=field)
    try:
        info = os.lstat(lexical)
    except OSError as exc:
        raise EvidenceGenerationImportError(_database_error_code(role, "UNAVAILABLE"), f"{field} is unavailable") from exc
    if not os.path.isfile(lexical) or lexical.is_symlink() or info.st_uid != os.getuid():
        raise EvidenceGenerationImportError(_database_error_code(role, "UNSAFE"), f"{field} is not a private regular file")
    if info.st_mode & 0o077:
        raise EvidenceGenerationImportError(_database_error_code(role, "UNSAFE"), f"{field} is not private")
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{lexical}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            try:
                side_info = os.lstat(sidecar)
            except OSError as exc:
                raise EvidenceGenerationImportError(_database_error_code(role, "UNSAFE"), "database sidecar cannot be inspected") from exc
            if sidecar.is_symlink() or not os.path.isfile(sidecar) or side_info.st_uid != os.getuid() or side_info.st_mode & 0o077:
                raise EvidenceGenerationImportError(_database_error_code(role, "UNSAFE"), "database sidecar is unsafe")
    return lexical


def _database_asset_hash(path: Path, *, role: str) -> str:
    """Hash the main SQLite database; WAL commits are pinned by data_version."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceGenerationImportError(_database_error_code(role, "UNAVAILABLE"), "database hash cannot be read") from exc
    return digest.hexdigest()


def _database_identity(path: Path, *, field: str) -> tuple[int, int]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise EvidenceGenerationImportError("DATABASE_IDENTITY_UNAVAILABLE", f"{field} identity cannot be read") from exc
    if path.is_symlink() or not path.is_file():
        raise EvidenceGenerationImportError("DATABASE_IDENTITY_UNSAFE", f"{field} is not a regular file")
    return int(info.st_dev), int(info.st_ino)


def _read_only_data_version(path: Path, *, role: str) -> int:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            value = connection.execute("PRAGMA data_version").fetchone()
            if value is None:
                raise EvidenceGenerationImportError(_database_error_code(role, "INVALID"), "database data version is unavailable")
            return int(value[0])
        finally:
            connection.close()
    except EvidenceGenerationImportError:
        raise
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        raise EvidenceGenerationImportError(_database_error_code(role, "INVALID"), "database data version is unavailable") from exc


def _read_sidecar(path: Path, *, session_id: str, workspace_id: str) -> tuple[dict[str, Any], str] | None:
    """Read only bounded, non-secret sidecar provenance; never copy its bytes."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EvidenceGenerationImportError("SOURCE_SIDECAR_UNAVAILABLE", "source sidecar cannot be inspected") from exc
    if path.is_symlink() or not path.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise EvidenceGenerationImportError("SOURCE_SIDECAR_UNSAFE", "source sidecar is not a private regular file")
    try:
        raw = path.read_bytes()
        if len(raw) > 128 * 1024:
            raise EvidenceGenerationImportError("SOURCE_SIDECAR_TOO_LARGE", "source sidecar exceeds the safety bound")
        payload = json.loads(raw.decode("utf-8"))
    except EvidenceGenerationImportError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceGenerationImportError("SOURCE_SIDECAR_INVALID", "source sidecar is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise EvidenceGenerationImportError("SOURCE_SIDECAR_INVALID", "source sidecar must be an object")
    if str(payload.get("session_id") or "") != session_id or str(payload.get("workspace_id") or "") != workspace_id:
        raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_MISMATCH", "source sidecar identity does not match the session")
    bounded: dict[str, Any] = {}
    for field, maximum in _SIDECAR_STRING_LIMITS.items():
        if field not in payload:
            continue
        value = payload[field]
        if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
            raise EvidenceGenerationImportError("SOURCE_SIDECAR_INVALID", f"source sidecar field is invalid: {field}")
        bounded[field] = value
    for field in ("stale", "source_dirty"):
        if field in payload and not isinstance(payload[field], bool):
            raise EvidenceGenerationImportError("SOURCE_SIDECAR_INVALID", f"source sidecar field is invalid: {field}")
    bounded["lifecycle_state"] = str(payload.get("lifecycle_state") or "")
    bounded["stale"] = payload.get("stale", False)
    bounded["source_dirty"] = payload.get("source_dirty", False)
    return bounded, hashlib.sha256(raw).hexdigest()


def _json_hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _query_row(connection: sqlite3.Connection, table: str, key: str, value: str) -> dict[str, Any] | None:
    if table not in _PRIMARY_KEYS or _PRIMARY_KEYS[table] != key:
        raise EvidenceGenerationImportError("IMPORT_TABLE_INVALID", "source table is not allowlisted")
    row = connection.execute(f'SELECT * FROM "{table}" WHERE "{key}" = ?', (value,)).fetchone()
    return dict(row) if row is not None else None


class EvidenceGenerationImporter:
    """Plan and execute a bounded source-generation import."""

    def __init__(
        self,
        destination_store: SqliteDirectorStore,
        *,
        allowed_source_roots: tuple[Path, ...] = (),
        source_sidecar_root: Path | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(destination_store, SqliteDirectorStore):
            raise TypeError("destination_store must be a SqliteDirectorStore")
        self.destination_store = destination_store
        self.destination_database = _absolute_lexical(destination_store.path, field="destination database")
        _regular_database(self.destination_database, field="destination database", role="destination")
        self.allowed_source_roots = tuple(_absolute_lexical(Path(root), field="source root") for root in allowed_source_roots)
        self.source_sidecar_root = (
            _absolute_lexical(Path(source_sidecar_root), field="source sidecar root")
            if source_sidecar_root is not None
            else None
        )
        if self.source_sidecar_root is not None:
            self._assert_allowed_source(self.source_sidecar_root)
        self._clock = clock or time.time

    def _assert_allowed_source(self, source: Path) -> None:
        if not self.allowed_source_roots:
            raise EvidenceGenerationImportError("SOURCE_ROOT_UNCONFIGURED", "source generation roots are not configured")
        for root in self.allowed_source_roots:
            try:
                source.relative_to(root)
            except ValueError:
                continue
            return
        raise EvidenceGenerationImportError("SOURCE_ROOT_NOT_ALLOWED", "source database is outside the configured generation roots")

    def _read_bundle(self, source_database: Path, *, session_id: str, workspace_id: str, source_generation: str) -> EvidenceGenerationBundle:
        source = _regular_database(source_database, field="source database", role="source")
        self._assert_allowed_source(source)
        if source == self.destination_database:
            raise EvidenceGenerationImportError("SOURCE_DESTINATION_SAME", "source and destination databases must be different")
        source_device, source_inode = _database_identity(source, field="source database")
        source_hash_before: str | None = None
        source_data_version: int | None = None
        sidecar_state: dict[str, Any] = {"present": False}
        sidecar_hash = ""
        try:
            connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            source_hash_before = _database_asset_hash(source, role="source")
            source_data_version_row = connection.execute("PRAGMA data_version").fetchone()
            if source_data_version_row is None:
                raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "source data version is unavailable")
            source_data_version = int(source_data_version_row[0])
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            if integrity != "ok":
                raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "source database integrity check failed")
            schema_row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
            if schema_row is None or int(schema_row[0]) not in SUPPORTED_SOURCE_SCHEMAS:
                raise EvidenceGenerationImportError("SOURCE_SCHEMA_UNKNOWN", "source schema is not recognized")
            source_schema = int(schema_row[0])
            session = _query_row(connection, "development_sessions", "session_id", session_id)
            if session is None:
                raise EvidenceGenerationImportError("SESSION_NOT_FOUND", "requested source session does not exist")
            if str(session.get("workspace_id", "")) != workspace_id:
                raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_MISMATCH", "source session belongs to another workspace")
            task_ids: list[str] = []
            records: dict[str, list[Mapping[str, Any]]] = {table: [] for table in _TABLE_ORDER}
            records["development_sessions"].append(session)
            task_id = str(session.get("task_id") or "")
            pending = [task_id] if task_id else []
            seen_tasks: set[str] = set()
            while pending:
                current_task_id = pending.pop(0)
                if current_task_id in seen_tasks:
                    continue
                if len(seen_tasks) >= MAX_DEPENDENCY_RECORDS:
                    raise EvidenceGenerationImportError("DEPENDENCY_CLOSURE_TOO_LARGE", "evidence dependency closure exceeds the safety bound")
                seen_tasks.add(current_task_id)
                task = _query_row(connection, "task_ledger", "task_id", current_task_id)
                if task is None:
                    raise EvidenceGenerationImportError("MISSING_DEPENDENCY", f"task dependency is missing: {current_task_id}")
                if str(task.get("workspace_id", "")) != workspace_id:
                    raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_MISMATCH", "task dependency belongs to another workspace")
                records["task_ledger"].append(task)
                task_ids.append(current_task_id)
                lease_id = str(task.get("lease_id") or "")
                if lease_id:
                    lease = _query_row(connection, "writer_leases", "lease_id", lease_id)
                    if lease is None:
                        raise EvidenceGenerationImportError("MISSING_DEPENDENCY", f"writer lease dependency is missing: {lease_id}")
                    if str(lease.get("workspace_id", "")) != workspace_id:
                        raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_MISMATCH", "writer lease belongs to another workspace")
                    if not any(str(item.get("lease_id")) == lease_id for item in records["writer_leases"]):
                        records["writer_leases"].append(lease)
                dependencies_raw = task.get("dependencies_json", "[]")
                try:
                    dependencies = json.loads(str(dependencies_raw))
                except json.JSONDecodeError as exc:
                    raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "task dependency JSON is invalid") from exc
                if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
                    raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "task dependency JSON is invalid")
                pending.extend(item for item in dependencies if item not in seen_tasks)
                for field, table in _RECEIPT_FIELDS:
                    receipt_id = str(task.get(field) or "")
                    if not receipt_id:
                        continue
                    receipt = _query_row(connection, table, "receipt_id", receipt_id)
                    if receipt is None:
                        raise EvidenceGenerationImportError("MISSING_DEPENDENCY", f"receipt dependency is missing: {receipt_id}")
                    if str(receipt.get("workspace_id", "")) != workspace_id:
                        raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_MISMATCH", "receipt belongs to another workspace")
                    if not any(str(item.get("receipt_id")) == receipt_id for item in records[table]):
                        records[table].append(receipt)
            data_version_after = int(connection.execute("PRAGMA data_version").fetchone()[0])
            if data_version_after != source_data_version:
                raise EvidenceGenerationImportError("SOURCE_DATABASE_CHANGED", "source database changed during preflight")
            connection.close()
        except EvidenceGenerationImportError:
            raise
        except (OSError, sqlite3.DatabaseError, ValueError) as exc:
            raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "source database could not be read safely") from exc
        finally:
            try:
                connection.close()
            except (NameError, AttributeError):
                pass
        if source_hash_before is None or source_data_version is None or _database_asset_hash(source, role="source") != source_hash_before:
            raise EvidenceGenerationImportError("SOURCE_DATABASE_CHANGED", "source database changed during preflight")
        current_device, current_inode = _database_identity(source, field="source database")
        if (current_device, current_inode) != (source_device, source_inode):
            raise EvidenceGenerationImportError("SOURCE_DATABASE_CHANGED", "source database identity changed during preflight")
        if self.source_sidecar_root is not None:
            sidecar_path = self.source_sidecar_root / f"{session_id.removeprefix('session:')}.json"
            sidecar_path = _absolute_lexical(sidecar_path, field="source sidecar")
            try:
                sidecar_path.relative_to(self.source_sidecar_root)
            except ValueError as exc:
                raise EvidenceGenerationImportError("SOURCE_SIDECAR_INVALID", "source sidecar is outside its authority root") from exc
            sidecar = _read_sidecar(sidecar_path, session_id=session_id, workspace_id=workspace_id)
            if sidecar is not None:
                sidecar_payload, sidecar_hash = sidecar
                sidecar_state = {"present": True, "sha256": sidecar_hash, "fields": sidecar_payload}
        frozen_records = {
            table: tuple(records[table])
            for table in _TABLE_ORDER
            if records[table]
        }
        record_hashes = {
            table: _json_hash(rows)
            for table, rows in frozen_records.items()
        }
        session_state = {
            "workspace_id": workspace_id,
            "lifecycle_state": str(session.get("lifecycle_state", "")),
            "stale": bool(session.get("stale", False)),
            "task_ids": tuple(task_ids),
            "database": {
                "device": source_device,
                "inode": source_inode,
                "sha256": source_hash_before,
                "schema_version": source_schema,
                "data_version": source_data_version,
            },
            "sidecar": sidecar_state,
        }
        return EvidenceGenerationBundle(
            source_generation=source_generation,
            source_database=source,
            source_database_sha256=source_hash_before,
            source_schema_version=source_schema,
            destination_schema_version=CURRENT_SCHEMA_VERSION,
            session_id=session_id,
            task_ids=tuple(task_ids),
            records=frozen_records,
            record_hashes=record_hashes,
            source_state=session_state,
            source_data_version=source_data_version,
            source_device=source_device,
            source_inode=source_inode,
            source_sidecar_sha256=sidecar_hash,
        )

    def preflight(
        self,
        source_database: Path | str,
        *,
        session_id: str,
        workspace_id: str,
        source_generation: str = "v25",
    ) -> EvidenceImportPlan:
        if (
            not isinstance(source_generation, str)
            or "\x00" in source_generation
            or not source_generation
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", source_generation)
        ):
            raise EvidenceGenerationImportError("SOURCE_GENERATION_INVALID", "source generation is required")
        if (
            not isinstance(session_id, str)
            or not session_id
            or "\x00" in session_id
            or "/" in session_id
            or "\\" in session_id
        ):
            raise EvidenceGenerationImportError("SESSION_ID_INVALID", "session id is invalid")
        if not isinstance(workspace_id, str) or not workspace_id or "\x00" in workspace_id:
            raise EvidenceGenerationImportError("WORKSPACE_IDENTITY_INVALID", "workspace id is required")
        if not isinstance(source_database, (str, Path)) or "\x00" in str(source_database):
            raise EvidenceGenerationImportError("SOURCE_DATABASE_INVALID", "source database path is invalid")
        if self.destination_store.schema_version != CURRENT_SCHEMA_VERSION:
            raise EvidenceGenerationImportError("DESTINATION_SCHEMA_INVALID", "destination schema is not schema 14")
        try:
            self.destination_store.integrity_check()
        except PersistenceError as exc:
            raise EvidenceGenerationImportError("DESTINATION_DATABASE_INVALID", "destination database integrity failed") from exc
        destination_hash = _database_asset_hash(self.destination_database, role="destination")
        destination_data_version = _read_only_data_version(self.destination_database, role="destination")
        destination_device, destination_inode = _database_identity(self.destination_database, field="destination database")
        bundle = self._read_bundle(Path(source_database), session_id=session_id, workspace_id=workspace_id, source_generation=source_generation)
        import_id = "evidence-import:" + hashlib.sha256(
            f"{bundle.source_database_sha256}:{bundle.session_id}:{self.destination_database}".encode()
        ).hexdigest()[:32]
        destination_state = {
            "schema_version": self.destination_store.schema_version,
            "integrity": "ok",
            "database_sha256": destination_hash,
            "database_device": destination_device,
            "database_inode": destination_inode,
            "data_version": destination_data_version,
        }
        return EvidenceImportPlan(
            bundle=bundle,
            destination_database=self.destination_database,
            destination_database_sha256=destination_hash,
            import_id=import_id,
            destination_state=destination_state,
            destination_data_version=destination_data_version,
            destination_device=destination_device,
            destination_inode=destination_inode,
        )

    def execute(self, plan: EvidenceImportPlan) -> dict[str, Any]:
        source = _regular_database(plan.bundle.source_database, field="source database", role="source")
        self._assert_allowed_source(source)
        if source == self.destination_database:
            raise EvidenceGenerationImportError("SOURCE_DESTINATION_SAME", "source and destination databases must be different")
        source_device, source_inode = _database_identity(source, field="source database")
        if (source_device, source_inode) != (plan.bundle.source_device, plan.bundle.source_inode):
            raise EvidenceGenerationImportError("SOURCE_DATABASE_CHANGED", "source database identity changed after preflight")
        destination_device, destination_inode = _database_identity(self.destination_database, field="destination database")
        if (destination_device, destination_inode) != (plan.destination_device, plan.destination_inode):
            raise EvidenceGenerationImportError("DESTINATION_DATABASE_CHANGED", "destination database identity changed after preflight")
        if self.source_sidecar_root is not None:
            sidecar_path = _absolute_lexical(
                self.source_sidecar_root / f"{plan.bundle.session_id.removeprefix('session:')}.json",
                field="source sidecar",
            )
            current_sidecar = _read_sidecar(
                sidecar_path,
                session_id=plan.bundle.session_id,
                workspace_id=str(plan.bundle.source_state.get("workspace_id") or "")
                if plan.bundle.source_state.get("workspace_id")
                else "",
            )
            expected_sidecar_hash = plan.bundle.source_sidecar_sha256
            current_sidecar_hash = current_sidecar[1] if current_sidecar is not None else ""
            if current_sidecar_hash != expected_sidecar_hash:
                raise EvidenceGenerationImportError("SOURCE_SIDECAR_CHANGED", "source sidecar changed after preflight")
        if (
            _database_asset_hash(source, role="source") != plan.bundle.source_database_sha256
            or _read_only_data_version(source, role="source") != plan.bundle.source_data_version
        ):
            raise EvidenceGenerationImportError("SOURCE_DATABASE_CHANGED", "source database changed after preflight")
        if (
            _database_asset_hash(self.destination_database, role="destination") != plan.destination_database_sha256
            or _read_only_data_version(self.destination_database, role="destination") != plan.destination_data_version
        ):
            raise EvidenceGenerationImportError("DESTINATION_DATABASE_CHANGED", "destination database changed after preflight")
        destination_state = {
            "schema_version": self.destination_store.schema_version,
            "integrity": "ok",
            "database_sha256": plan.destination_database_sha256,
            "database_device": plan.destination_device,
            "database_inode": plan.destination_inode,
            "data_version": plan.destination_data_version,
        }
        try:
            result = self.destination_store.import_evidence_generation(
                import_id=plan.import_id,
                source_generation=plan.bundle.source_generation,
                source_database_sha256=plan.bundle.source_database_sha256,
                source_schema_version=plan.bundle.source_schema_version,
                session_id=plan.bundle.session_id,
                task_ids=list(plan.bundle.task_ids),
                record_hashes=dict(plan.bundle.record_hashes),
                source_state=dict(plan.bundle.source_state),
                destination_state=destination_state,
                imported_at=str(self._clock()),
                records=plan.bundle.records,
            )
        except PersistenceError as exc:
            code = str(exc) if str(exc) in {"EVIDENCE_IDENTITY_CONFLICT"} else "IMPORT_FAILED"
            raise EvidenceGenerationImportError(code, str(exc) or "evidence generation import failed") from exc
        return {
            **result,
            "source_generation": plan.bundle.source_generation,
            "source_database_sha256": plan.bundle.source_database_sha256,
            "destination_schema_version": plan.bundle.destination_schema_version,
            "source_preserved": True,
        }


__all__ = [
    "EvidenceGenerationBundle",
    "EvidenceGenerationImportError",
    "EvidenceGenerationImporter",
    "EvidenceImportPlan",
    "MAX_DEPENDENCY_RECORDS",
    "SUPPORTED_SOURCE_SCHEMAS",
]
