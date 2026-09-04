"""Fail-closed activation of an approved v26 runtime candidate.

The controller deliberately contains no process or launchd policy.  A caller
provides the official activation/rollback functions, while this module owns
the immutable candidate pin and all pre/post safety checks.  This keeps the
same contract usable by a canary harness and by the production maintenance
capability without allowing caller-selected shell commands.
"""

from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
from typing import Any, Callable, Mapping
from urllib.parse import quote

from .connector_resilience import persistence_db_identity
from .persistence import PersistenceError, inspect_readonly_roots_schema


V26_SCHEMA_VERSION = 14
EXPECTED_V26_TOOL_COUNT = 76
V26_BOOTSTRAP_CONTRACT_VERSION = "v26-bootstrap-v1"
V26_PYTHON_LOCATOR = "workspace://chatgpt-dev-mcp/.venv/bin/python"
ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION = "activation-db-semantic-v1"
ACTIVATION_DATABASE_EXCLUDED_TABLES = ("request_lifecycle_events",)
ACTIVATION_MAX_PIN_DIAGNOSTIC_COMPONENTS = 64


class RuntimeActivationError(RuntimeError):
    """A candidate cannot be safely activated or read back."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass(frozen=True)
class CandidateRuntime:
    source_root: Path
    expected_head: str
    expected_schema_version: int
    entrypoint: Path
    python_executable: Path
    state_dir: Path
    database_path: Path
    expected_base_revision: str | None = None
    expected_patch_hash: str = ""
    expected_tool_count: int = EXPECTED_V26_TOOL_COUNT
    expected_tool_schema_hash: str = ""


@dataclass(frozen=True)
class RuntimeReadback:
    source_root: Path
    head: str
    schema_version: int
    doctor_status: str
    tool_count: int
    tool_schema_hash: str = ""
    pid: int | None = None
    persistence_status: str = ""
    cross_call_receipt_continuity: str = ""
    readonly_root_continuity: str = ""
    tunnel_status: str = ""
    state_isolation: str = ""
    port_isolation: str = ""
    # Deployment identity is optional for embedders that only need the core
    # controller contract.  The production host fills these fields from the
    # live wrapper/manifest so activation can pin the actual state boundary.
    state_database_identity: str = ""
    database_path: Path | None = None
    port: int | None = None
    tunnel_identity: str = ""
    runtime_path: Path | None = None
    manifest_path: Path | None = None
    python_executable: Path | None = None
    base_revision: str = ""
    patch_hash: str = ""
    # ``None`` is deliberately treated as unknown.  A schema-compatible
    # rollback source must also be a known clean checkout; a dirty/unknown
    # source is not a last-known-good rollback authority.
    source_clean: bool | None = None


@dataclass(frozen=True)
class _ActivationDatabaseFingerprint:
    semantic_digest: str
    database_identity: str
    semantic_component_digests: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ActivationPlan:
    candidate: CandidateRuntime
    current: RuntimeReadback
    canary_receipt: Mapping[str, Any]
    candidate_fingerprint: str
    activation_database_semantic_digest: str = ""
    database_identity: str = ""
    semantic_component_digests: tuple[tuple[str, str], ...] = ()
    semantic_digest_version: str = ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION
    excluded_audit_tables: tuple[str, ...] = ACTIVATION_DATABASE_EXCLUDED_TABLES
    status: str = "READY"


def _validate_database_assets(path: Path) -> None:
    """Validate SQLite sidecars without using their bytes as activation state."""

    for suffix in ("", "-wal", "-shm"):
        asset = Path(f"{path}{suffix}")
        try:
            if asset.is_symlink():
                raise RuntimeActivationError(
                    "CANDIDATE_DATABASE_UNSAFE",
                    "candidate database asset is not a regular file",
                )
            if not asset.exists():
                if suffix == "":
                    raise RuntimeActivationError(
                        "CANDIDATE_DATABASE_UNAVAILABLE",
                        "candidate database is unavailable",
                    )
                continue
            if not asset.is_file():
                raise RuntimeActivationError(
                    "CANDIDATE_DATABASE_UNSAFE",
                    "candidate database asset is not a regular file",
                )
        except RuntimeActivationError:
            raise
        except OSError as exc:
            raise RuntimeActivationError(
                "CANDIDATE_DATABASE_UNREADABLE",
                "candidate database asset cannot be inspected",
            ) from exc


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'

def _canonical_sqlite_value(value: object) -> dict[str, Any]:
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "integer", "value": int(value)}
    if isinstance(value, int):
        return {"type": "integer", "value": value}
    if isinstance(value, float):
        return {"type": "real", "value": value.hex()}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {
            "type": "blob",
            "length": len(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        }
    raise RuntimeActivationError(
        "CANDIDATE_DATABASE_INVALID",
        "candidate database contains an unsupported SQLite value type",
    )


def _readonly_sqlite_uri(path: Path) -> str:
    return f"file:{quote(str(path), safe='/')}?mode=ro"


def _json_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_activation_database_semantics(
    path: Path,
    *,
    expected_schema_version: int,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Return a deterministic logical-state digest for activation CAS.

    SQLite page layout, WAL bytes, and the rebuildable SHM index are deliberately
    outside this digest.  Every application table remains included except the
    request lifecycle audit stream, whose rows are expected to change while a
    capability request is being admitted and executed.
    """

    _validate_database_assets(path)
    try:
        connection = sqlite3.connect(_readonly_sqlite_uri(path), uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            # Keep schema and row reads on one SQLite snapshot while writers
            # continue their normal WAL-backed lifecycle work.
            connection.execute("BEGIN")
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            if integrity != "ok":
                raise RuntimeActivationError(
                    "CANDIDATE_DATABASE_INVALID",
                    "candidate database integrity check failed",
                )
            schema_row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
            if schema_row is None or int(schema_row[0]) != expected_schema_version:
                raise RuntimeActivationError(
                    "SCHEMA_INCOMPATIBLE",
                    "candidate database schema is incompatible",
                )
            try:
                inspect_readonly_roots_schema(connection, scope_path=path)
            except PersistenceError as exc:
                raise RuntimeActivationError(
                    "SCHEMA_INCOMPATIBLE",
                    "candidate readonly_roots schema is incompatible",
                ) from exc

            schema_rows = connection.execute(
                "SELECT type, name, tbl_name, sql "
                "FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' "
                "AND type IN ('table', 'index', 'trigger', 'view') "
                "ORDER BY type, name, tbl_name, sql"
            ).fetchall()
            schema_objects = [
                {
                    "type": str(row[0]),
                    "name": str(row[1]),
                    "table_name": str(row[2]),
                    "sql": row[3] if row[3] is None or isinstance(row[3], str) else str(row[3]),
                }
                for row in schema_rows
            ]

            tables: list[dict[str, Any]] = []
            for table_name in sorted(
                str(row[1])
                for row in schema_rows
                if row[0] == "table" and not str(row[1]).startswith("sqlite_")
            ):
                quoted_table = _quote_sqlite_identifier(table_name)
                column_rows = connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
                columns = [
                    {
                        "cid": int(row[0]),
                        "name": str(row[1]),
                        "type": str(row[2]),
                        "notnull": int(row[3]),
                        "default": row[4] if row[4] is None or isinstance(row[4], str) else str(row[4]),
                        "primary_key": int(row[5]),
                    }
                    for row in column_rows
                ]
                rows = (
                    [
                        [_canonical_sqlite_value(value) for value in row]
                        for row in connection.execute(f"SELECT * FROM {quoted_table}").fetchall()
                    ]
                    if table_name not in ACTIVATION_DATABASE_EXCLUDED_TABLES
                    else []
                )
                rows.sort(
                    key=lambda row: json.dumps(
                        row,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                )
                tables.append({"name": table_name, "columns": columns, "rows": rows})

            semantic_component_digests: dict[str, str] = {
                "schema": _json_digest(
                    {
                        "semantic_digest_version": ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION,
                        "schema_version": int(expected_schema_version),
                        "excluded_audit_tables": list(ACTIVATION_DATABASE_EXCLUDED_TABLES),
                        "schema_objects": schema_objects,
                    }
                )
            }
            for table in tables:
                table_name = str(table["name"])
                semantic_component_digests[f"table:{table_name}:schema"] = _json_digest(
                    {"name": table_name, "columns": table["columns"]}
                )
                semantic_component_digests[f"table:{table_name}:rows"] = _json_digest(
                    {"name": table_name, "rows": table["rows"]}
                )

            payload = {
                "semantic_digest_version": ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION,
                "schema_version": int(expected_schema_version),
                "excluded_audit_tables": list(ACTIVATION_DATABASE_EXCLUDED_TABLES),
                "schema_objects": schema_objects,
                "tables": tables,
            }
            return _json_digest(payload), tuple(sorted(semantic_component_digests.items()))
        finally:
            connection.close()
    except RuntimeActivationError:
        raise
    except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
        raise RuntimeActivationError(
            "CANDIDATE_DATABASE_INVALID",
            "candidate database cannot be inspected as logical SQLite state",
        ) from exc


def _activation_database_fingerprint(
    path: Path,
    *,
    expected_schema_version: int,
) -> _ActivationDatabaseFingerprint:
    """Read semantic state and physical identity with a replacement check."""

    _validate_database_assets(path)
    try:
        identity_before = persistence_db_identity(path, schema_version=expected_schema_version)
    except (OSError, ValueError) as exc:
        raise RuntimeActivationError(
            "CANDIDATE_DATABASE_UNREADABLE",
            "candidate database identity could not be read",
        ) from exc
    semantic_digest, semantic_component_digests = _read_activation_database_semantics(
        path,
        expected_schema_version=expected_schema_version,
    )
    _validate_database_assets(path)
    try:
        identity_after = persistence_db_identity(path, schema_version=expected_schema_version)
    except (OSError, ValueError) as exc:
        raise RuntimeActivationError(
            "CANDIDATE_DATABASE_UNREADABLE",
            "candidate database identity could not be re-read",
        ) from exc
    if identity_before != identity_after:
        raise RuntimeActivationError(
            "CANDIDATE_DATABASE_DRIFT",
            "candidate database identity changed during activation inspection",
        )
    return _ActivationDatabaseFingerprint(
        semantic_digest=semantic_digest,
        database_identity=identity_after,
        semantic_component_digests=semantic_component_digests,
    )


def _activation_database_semantic_digest(
    path: Path,
    *,
    expected_schema_version: int = V26_SCHEMA_VERSION,
) -> str:
    return _activation_database_fingerprint(
        Path(path),
        expected_schema_version=expected_schema_version,
    ).semantic_digest


def _activation_pin_change_details(
    plan: ActivationPlan,
    *,
    observed_semantic_digest: str,
    observed_database_identity: str,
    observed_component_digests: tuple[tuple[str, str], ...],
    observed_candidate_fingerprint: str,
) -> dict[str, Any]:
    expected_components = dict(plan.semantic_component_digests)
    observed_components = dict(observed_component_digests)
    changed_semantic_components = sorted(
        component
        for component in expected_components.keys() | observed_components.keys()
        if expected_components.get(component) != observed_components.get(component)
    )
    changed_pin_components: list[str] = []
    if plan.activation_database_semantic_digest != observed_semantic_digest:
        changed_pin_components.append("activation_database_semantic_digest")
    if plan.database_identity != observed_database_identity:
        changed_pin_components.append("database_identity")
    if not changed_pin_components:
        changed_pin_components.append("candidate_fingerprint")
    return {
        "changed_pin_components": changed_pin_components,
        "changed_semantic_component_count": len(changed_semantic_components),
        "changed_semantic_components": changed_semantic_components[:ACTIVATION_MAX_PIN_DIAGNOSTIC_COMPONENTS],
        "candidate_fingerprint_expected": plan.candidate_fingerprint,
        "candidate_fingerprint_observed": observed_candidate_fingerprint,
        "activation_database_semantic_digest_expected": plan.activation_database_semantic_digest,
        "activation_database_semantic_digest_observed": observed_semantic_digest,
        "database_identity_expected": plan.database_identity,
        "database_identity_observed": observed_database_identity,
        "semantic_digest_version": plan.semantic_digest_version,
        "excluded_audit_tables": list(plan.excluded_audit_tables),
    }


def _sha256_database_assets(path: Path) -> str:
    """Hash physical SQLite assets for diagnostics, never for activation CAS."""

    _validate_database_assets(path)
    digest = hashlib.sha256()
    for suffix in ("", "-wal"):
        asset = Path(f"{path}{suffix}")
        try:
            if not asset.exists():
                digest.update(f"{suffix}:missing\0".encode("utf-8"))
                continue
            if asset.is_symlink() or not asset.is_file():
                raise RuntimeActivationError("CANDIDATE_DATABASE_UNSAFE", "candidate database asset is not a regular file")
            digest.update(f"{suffix}:present\0".encode("utf-8"))
            with asset.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except RuntimeActivationError:
            raise
        except OSError as exc:
            raise RuntimeActivationError("CANDIDATE_DATABASE_UNREADABLE", "candidate database cannot be read") from exc
    return digest.hexdigest()


def _regular_private_file(
    path: Path,
    *,
    field: str,
    unavailable_code: str,
    unsafe_code: str,
    require_executable: bool = False,
    allow_final_symlink: bool = False,
    require_current_user_owner: bool = True,
) -> None:
    """Require a user-owned regular file without following a final symlink."""

    try:
        os.lstat(path)
    except OSError as exc:
        raise RuntimeActivationError(unavailable_code, f"{field} is unavailable") from exc
    if path.is_symlink() and not allow_final_symlink:
        raise RuntimeActivationError(unsafe_code, f"{field} is not a regular file")
    inspected = path.resolve(strict=True) if path.is_symlink() else path
    try:
        inspected_info = os.stat(inspected)
    except OSError as exc:
        raise RuntimeActivationError(unavailable_code, f"{field} target is unavailable") from exc
    if not inspected.is_file():
        raise RuntimeActivationError(unsafe_code, f"{field} is not a regular file")
    if require_current_user_owner and inspected_info.st_uid != os.getuid():
        raise RuntimeActivationError(unsafe_code, f"{field} is not owned by the current user")
    if inspected_info.st_mode & 0o022:
        raise RuntimeActivationError(unsafe_code, f"{field} is writable by another user")
    if require_executable and not os.access(inspected, os.X_OK):
        raise RuntimeActivationError(unavailable_code, f"{field} is not executable")


def _safe_absolute(path: Path, *, field: str, allow_final_symlink: bool = False) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise RuntimeActivationError("PATH_NOT_ABSOLUTE", f"{field} must be absolute")
    lexical = Path(os.path.abspath(str(expanded)))
    current = Path(lexical.anchor)
    components = lexical.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            is_final = index == len(components) - 1
            if current.is_symlink() and not (allow_final_symlink and is_final) and current not in {Path("/var"), Path("/tmp")}:
                raise RuntimeActivationError("PATH_SYMLINK", f"{field} contains a symlink")
        except OSError as exc:
            raise RuntimeActivationError("PATH_UNREADABLE", f"{field} cannot be inspected") from exc
    return lexical


def _default_git_head_reader(root: Path) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeActivationError("CANDIDATE_GIT_UNAVAILABLE", "candidate Git HEAD could not be read") from exc
    head = completed.stdout.strip()
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head.lower()):
        raise RuntimeActivationError("CANDIDATE_GIT_INVALID", "candidate Git HEAD is invalid")
    return head


def _default_git_clean_reader(root: Path) -> bool:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), "status", "--porcelain=v1"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeActivationError("CANDIDATE_GIT_UNAVAILABLE", "candidate Git status could not be read") from exc
    return not bool(completed.stdout.strip())


def _default_git_descendant_reader(root: Path, base: str, head: str) -> bool:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), "merge-base", "--is-ancestor", base, head),
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeActivationError("CANDIDATE_ANCESTRY_UNKNOWN", "candidate ancestry could not be verified") from exc
    return completed.returncode == 0


def _default_git_diff_hash_reader(root: Path) -> str:
    try:
        completed = subprocess.run(
            # A clean candidate has no working-tree diff.  The candidate
            # patch pin therefore hashes the exact HEAD commit patch, not an
            # always-empty post-checkout diff.
            ("git", "-C", str(root), "show", "--format=", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD", "--"),
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeActivationError("CANDIDATE_GIT_UNAVAILABLE", "candidate patch identity could not be read") from exc
    return hashlib.sha256(completed.stdout).hexdigest()


def validate_v26_bootstrap_contract(
    source_root: Path,
    *,
    expected_head: str | None = None,
    git_head_reader: Callable[[Path], str] | None = None,
    git_clean_reader: Callable[[Path], bool] | None = None,
) -> Mapping[str, Any]:
    """Validate the static source contract required for a v26 cold start."""

    source = _safe_absolute(Path(source_root), field="v26 bootstrap source")
    if not source.is_dir() or source.is_symlink():
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source root is unavailable",
        )
    required_files = {
        "local_maintenance": source / "src" / "chatgpt_dev_mcp" / "local_maintenance.py",
        "production_runtime": source / "src" / "chatgpt_dev_mcp" / "production_runtime.py",
        "http_entrypoint": source / "src" / "chatgpt_dev_mcp" / "http_entrypoint.py",
        "runtime_activation": source / "src" / "chatgpt_dev_mcp" / "runtime_activation.py",
    }
    trees: dict[str, ast.AST] = {}
    texts: dict[str, str] = {}
    for name, path in required_files.items():
        try:
            _regular_private_file(
                path,
                field=f"v26 bootstrap {name} source",
                unavailable_code="RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
                unsafe_code="RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            )
            text = path.read_text(encoding="utf-8")
            trees[name] = ast.parse(text, filename=str(path))
            texts[name] = text
        except RuntimeActivationError as exc:
            raise RuntimeActivationError(
                "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
                f"v26 rollback source is missing the bootstrap contract: {name}",
            ) from exc
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise RuntimeActivationError(
                "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
                f"v26 rollback source cannot be statically validated: {name}",
            ) from exc

    def has_definition(tree: ast.AST, name: str, node_types: object) -> bool:
        return any(isinstance(node, node_types) and getattr(node, "name", None) == name for node in ast.walk(tree))

    def string_constant(tree: ast.AST, name: str) -> str | None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
        return None

    if not has_definition(trees["local_maintenance"], "_bootstrap_v26_runtime", (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source has no cold-start bootstrap entrypoint",
        )
    if not has_definition(trees["production_runtime"], "ProductionRuntimeHost", ast.ClassDef) or not has_definition(
        trees["production_runtime"], "build_production_runtime", (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source has no production maintenance host",
        )
    if not has_definition(trees["runtime_activation"], "validate_v26_bootstrap_contract", (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source has no versioned bootstrap contract validator",
        )
    if (
        string_constant(trees["runtime_activation"], "V26_BOOTSTRAP_CONTRACT_VERSION") != V26_BOOTSTRAP_CONTRACT_VERSION
        or string_constant(trees["runtime_activation"], "V26_PYTHON_LOCATOR") != V26_PYTHON_LOCATOR
    ):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source has an unknown bootstrap contract version",
        )
    required_binding_markers = (
        "runtime_activation_controller",
        "runtime_activation_current_reader",
        "host.controller",
        "host.read_current",
        "host.bind_runtime",
    )
    if any(marker not in texts["production_runtime"] for marker in required_binding_markers):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 production factory does not expose the existing maintenance bindings",
        )
    has_factory_import = any(
        (isinstance(node, ast.Name) and node.id == "build_production_runtime")
        or (isinstance(node, ast.alias) and node.name == "build_production_runtime")
        for node in ast.walk(trees["http_entrypoint"])
    )
    has_factory_call = any(
        isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "build_production_runtime")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "build_production_runtime")
        )
        for node in ast.walk(trees["http_entrypoint"])
    )
    if not has_factory_import or not has_factory_call:
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 HTTP entrypoint is not bound to the production runtime factory",
        )
    if (
        "bootstrap-v26-runtime" not in texts["local_maintenance"]
        or "validate_v26_bootstrap_contract" not in texts["local_maintenance"]
        or "_resolve_v26_python_locator" not in texts["production_runtime"]
        or "V26_PYTHON_LOCATOR" not in texts["production_runtime"]
        or "V26_BOOTSTRAP_CONTRACT_VERSION" not in texts["runtime_activation"]
    ):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
            "v26 rollback source does not expose the fixed bootstrap command",
        )

    head_reader = git_head_reader or _default_git_head_reader
    clean_reader = git_clean_reader or _default_git_clean_reader
    try:
        head = head_reader(source)
        clean = clean_reader(source)
    except RuntimeActivationError:
        raise
    except Exception as exc:  # noqa: BLE001 - source identity must fail closed
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_UNKNOWN",
            "v26 rollback source Git identity could not be verified",
        ) from exc
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_UNKNOWN",
            "v26 rollback source Git HEAD is invalid",
        )
    if expected_head is not None and head != expected_head:
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_MISMATCH",
            "v26 rollback source Git HEAD differs from the pinned identity",
        )
    if clean is not True:
        raise RuntimeActivationError(
            "RUNTIME_ROLLBACK_SOURCE_DIRTY",
            "v26 rollback source is dirty or its clean state is unknown",
        )
    return {
        "status": "PASS",
        "contract_version": V26_BOOTSTRAP_CONTRACT_VERSION,
        "head": head,
        "source_root": str(source),
    }


def _default_schema_reader(database_path: Path) -> int:
    try:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            if integrity != "ok":
                raise RuntimeActivationError("CANDIDATE_DATABASE_INVALID", "candidate database integrity check failed")
            row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
            if row is None:
                raise RuntimeActivationError("SCHEMA_UNKNOWN", "candidate database schema is unknown")
            return int(row[0])
        finally:
            connection.close()
    except RuntimeActivationError:
        raise
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        raise RuntimeActivationError("CANDIDATE_DATABASE_INVALID", "candidate database cannot be opened read-only") from exc


def _mapping(value: object, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeActivationError("ACTIVATION_EVIDENCE_INVALID", f"{name} must be an object")
    return value


class RuntimeActivationController:
    """Validate and activate one exact v26 candidate identity."""

    def __init__(
        self,
        *,
        git_head_reader: Callable[[Path], str] | None = None,
        git_clean_reader: Callable[[Path], bool] | None = None,
        git_descendant_reader: Callable[[Path, str, str], bool] | None = None,
        git_diff_hash_reader: Callable[[Path], str] | None = None,
        schema_reader: Callable[[Path], int] | None = None,
        catalog_reader: Callable[[CandidateRuntime], Mapping[str, Any]] | None = None,
        doctor_reader: Callable[[CandidateRuntime], Mapping[str, Any]] | None = None,
        mutation_reader: Callable[[], bool] | None = None,
        bootstrap_contract_reader: Callable[[Path], Mapping[str, Any]] | None = None,
        executor: Callable[[ActivationPlan], Mapping[str, Any]] | None = None,
        rollback_executor: Callable[[ActivationPlan], Any] | None = None,
        post_readback: Callable[[CandidateRuntime], Mapping[str, Any]] | None = None,
    ) -> None:
        self._git_head_reader = git_head_reader or _default_git_head_reader
        self._git_clean_reader = git_clean_reader or _default_git_clean_reader
        self._git_descendant_reader = git_descendant_reader or _default_git_descendant_reader
        self._git_diff_hash_reader = git_diff_hash_reader or _default_git_diff_hash_reader
        self._schema_reader = schema_reader or _default_schema_reader
        self._catalog_reader = catalog_reader or (lambda _candidate: {})
        self._doctor_reader = doctor_reader or (lambda _candidate: {})
        self._mutation_reader = mutation_reader or (lambda: False)
        self._bootstrap_contract_reader = bootstrap_contract_reader
        self._executor = executor
        self._rollback_executor = rollback_executor
        self._post_readback = post_readback

    @staticmethod
    def _candidate_fingerprint(
        candidate: CandidateRuntime,
        *,
        database_semantic_digest: str,
        database_identity: str,
    ) -> str:
        payload = {
            "source_root": str(candidate.source_root),
            "expected_head": candidate.expected_head,
            "expected_schema_version": candidate.expected_schema_version,
            "entrypoint": str(candidate.entrypoint),
            "python_executable": str(candidate.python_executable),
            "state_dir": str(candidate.state_dir),
            "database_path": str(candidate.database_path),
            "database_identity": database_identity,
            "activation_database_semantic_digest": database_semantic_digest,
            "semantic_digest_version": ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION,
            "excluded_audit_tables": list(ACTIVATION_DATABASE_EXCLUDED_TABLES),
            "expected_base_revision": candidate.expected_base_revision,
            "expected_patch_hash": candidate.expected_patch_hash,
            "expected_tool_count": candidate.expected_tool_count,
            "expected_tool_schema_hash": candidate.expected_tool_schema_hash,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _validate_candidate(
        self,
        candidate: CandidateRuntime,
        *,
        execute: bool = False,
    ) -> tuple[str, str, str, tuple[tuple[str, str], ...], Mapping[str, Any], Mapping[str, Any]]:
        del execute
        source = _safe_absolute(Path(candidate.source_root), field="candidate source")
        entrypoint = _safe_absolute(Path(candidate.entrypoint), field="candidate entrypoint")
        python = _safe_absolute(Path(candidate.python_executable), field="candidate Python", allow_final_symlink=True)
        state = _safe_absolute(Path(candidate.state_dir), field="candidate state")
        database = _safe_absolute(Path(candidate.database_path), field="candidate database")
        if not source.is_dir() or source.is_symlink():
            raise RuntimeActivationError("CANDIDATE_SOURCE_UNAVAILABLE", "candidate source root is unavailable")
        if not entrypoint.is_file() or entrypoint.is_symlink():
            raise RuntimeActivationError("CANDIDATE_ENTRYPOINT_UNAVAILABLE", "candidate runtime entrypoint is unavailable")
        _regular_private_file(
            entrypoint,
            field="candidate entrypoint",
            unavailable_code="CANDIDATE_ENTRYPOINT_UNAVAILABLE",
            unsafe_code="CANDIDATE_ENTRYPOINT_UNSAFE",
        )
        _regular_private_file(
            python,
            field="candidate Python executable",
            unavailable_code="CANDIDATE_PYTHON_UNAVAILABLE",
            unsafe_code="CANDIDATE_PYTHON_UNSAFE",
            require_executable=True,
            allow_final_symlink=True,
            require_current_user_owner=False,
        )
        if not state.is_dir() or state.is_symlink():
            raise RuntimeActivationError("CANDIDATE_STATE_UNAVAILABLE", "candidate state directory is unavailable")
        if not database.is_file() or database.is_symlink():
            raise RuntimeActivationError("CANDIDATE_DATABASE_UNAVAILABLE", "candidate database is unavailable")
        _regular_private_file(
            database,
            field="candidate database",
            unavailable_code="CANDIDATE_DATABASE_UNAVAILABLE",
            unsafe_code="CANDIDATE_DATABASE_UNSAFE",
        )
        if state == _safe_absolute(Path("/"), field="candidate state"):
            raise RuntimeActivationError("CANDIDATE_STATE_INVALID", "candidate state directory is unsafe")
        try:
            entrypoint.relative_to(source)
        except ValueError as exc:
            raise RuntimeActivationError(
                "CANDIDATE_ENTRYPOINT_SCOPE",
                "candidate entrypoint must be inside the candidate source root",
            ) from exc
        try:
            database.relative_to(state)
        except ValueError as exc:
            raise RuntimeActivationError(
                "CANDIDATE_DATABASE_SCOPE",
                "candidate database must be inside the isolated candidate state directory",
            ) from exc
        if candidate.expected_schema_version != V26_SCHEMA_VERSION:
            raise RuntimeActivationError("SCHEMA_INCOMPATIBLE", "candidate is not a schema-14 runtime")
        if not re.fullmatch(r"[0-9a-f]{40}", candidate.expected_head):
            raise RuntimeActivationError("CANDIDATE_HEAD_INVALID", "candidate expected HEAD is invalid")
        if candidate.expected_base_revision and not re.fullmatch(r"[0-9a-f]{40}", candidate.expected_base_revision):
            raise RuntimeActivationError("CANDIDATE_BASE_INVALID", "candidate expected base revision is invalid")
        head = self._git_head_reader(source)
        if head != candidate.expected_head:
            raise RuntimeActivationError("CANDIDATE_HEAD_MISMATCH", "candidate HEAD differs from the pinned identity")
        if not self._git_clean_reader(source):
            raise RuntimeActivationError("CANDIDATE_WORKTREE_DIRTY", "candidate worktree is not clean")
        if candidate.expected_patch_hash:
            if not re.fullmatch(r"[0-9a-f]{64}", candidate.expected_patch_hash):
                raise RuntimeActivationError("CANDIDATE_PATCH_INVALID", "candidate expected patch hash is invalid")
            if self._git_diff_hash_reader(source) != candidate.expected_patch_hash:
                raise RuntimeActivationError("CANDIDATE_PATCH_MISMATCH", "candidate patch identity differs from the pin")
        if candidate.expected_base_revision:
            if not self._git_descendant_reader(source, candidate.expected_base_revision, head):
                raise RuntimeActivationError("CANDIDATE_ANCESTRY_MISMATCH", "candidate is not descended from the approved base")
        if self._bootstrap_contract_reader is not None:
            try:
                contract = _mapping(self._bootstrap_contract_reader(source), name="v26 bootstrap contract")
            except RuntimeActivationError:
                raise
            except Exception as exc:  # noqa: BLE001 - bootstrap capability must fail closed
                raise RuntimeActivationError(
                    "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
                    "candidate v26 bootstrap contract could not be verified",
                ) from exc
            if str(contract.get("status", "")).upper() != "PASS" or str(contract.get("head", "")) != head:
                raise RuntimeActivationError(
                    "RUNTIME_ROLLBACK_BOOTSTRAP_INCOMPATIBLE",
                    "candidate v26 bootstrap contract is not PASS for the pinned HEAD",
                )
        try:
            schema = self._schema_reader(database)
        except RuntimeActivationError:
            raise
        except Exception as exc:  # noqa: BLE001 - reader failures must fail closed
            raise RuntimeActivationError("CANDIDATE_DATABASE_INVALID", "candidate database schema could not be read") from exc
        if schema != candidate.expected_schema_version:
            raise RuntimeActivationError("SCHEMA_INCOMPATIBLE", "candidate database schema is incompatible")
        try:
            catalog = _mapping(self._catalog_reader(candidate), name="candidate tool catalog")
        except RuntimeActivationError:
            raise
        except Exception as exc:  # noqa: BLE001 - reader failures must fail closed
            raise RuntimeActivationError("TOOL_CATALOG_INVALID", "candidate tool catalog could not be read") from exc
        catalog_status = catalog.get("status")
        if not isinstance(catalog_status, str) or catalog_status.upper() not in {"HEALTHY", "VALID", "PASS"}:
            raise RuntimeActivationError("TOOL_CATALOG_INVALID", "candidate tool catalog is not healthy")
        try:
            tool_count = int(catalog.get("tool_count", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeActivationError("TOOL_CATALOG_INVALID", "candidate tool count is invalid") from exc
        if tool_count != candidate.expected_tool_count:
            raise RuntimeActivationError("TOOL_CATALOG_INVALID", "candidate tool count is not the v26 contract")
        if candidate.expected_tool_schema_hash and str(catalog.get("tool_schema_hash", "")) != candidate.expected_tool_schema_hash:
            raise RuntimeActivationError("TOOL_CATALOG_INVALID", "candidate tool schema hash differs from the pin")
        try:
            doctor = _mapping(self._doctor_reader(candidate), name="candidate doctor")
        except RuntimeActivationError:
            raise
        except Exception as exc:  # noqa: BLE001 - reader failures must fail closed
            raise RuntimeActivationError("DOCTOR_UNHEALTHY", "candidate doctor could not be read") from exc
        if str(doctor.get("status", "")).upper() not in {"HEALTHY", "PASS", "OK"}:
            raise RuntimeActivationError("DOCTOR_UNHEALTHY", "candidate doctor is not healthy")
        try:
            mutation_in_progress = self._mutation_reader()
        except Exception as exc:  # noqa: BLE001 - inability to prove quiescence is unsafe
            raise RuntimeActivationError("MUTATION_STATE_UNKNOWN", "runtime mutation state could not be read") from exc
        if mutation_in_progress:
            raise RuntimeActivationError("MUTATION_IN_PROGRESS", "another runtime mutation is in progress")
        try:
            database_fingerprint = _activation_database_fingerprint(
                database,
                expected_schema_version=candidate.expected_schema_version,
            )
        except RuntimeActivationError:
            raise
        except Exception as exc:  # noqa: BLE001 - database state must fail closed
            raise RuntimeActivationError(
                "CANDIDATE_DATABASE_INVALID",
                "candidate database logical state could not be read",
            ) from exc
        return (
            head,
            database_fingerprint.semantic_digest,
            database_fingerprint.database_identity,
            database_fingerprint.semantic_component_digests,
            catalog,
            doctor,
        )

    def _validate_current(self, current: RuntimeReadback, *, expected_schema_version: int) -> None:
        if not isinstance(current, RuntimeReadback):
            raise RuntimeActivationError("CURRENT_RUNTIME_READBACK_INVALID", "current runtime read-back is invalid")
        if not current.source_root.is_absolute():
            raise RuntimeActivationError("CURRENT_RUNTIME_READBACK_INVALID", "current runtime source root is not absolute")
        if not re.fullmatch(r"[0-9a-f]{40}", current.head):
            raise RuntimeActivationError("CURRENT_RUNTIME_READBACK_INVALID", "current runtime HEAD is invalid")
        if isinstance(current.schema_version, bool) or not isinstance(current.schema_version, int) or current.schema_version < 1:
            raise RuntimeActivationError("CURRENT_RUNTIME_READBACK_INVALID", "current runtime schema is invalid")
        if current.schema_version < expected_schema_version:
            raise RuntimeActivationError(
                "NO_SAFE_RUNTIME_ROLLBACK",
                "the current runtime cannot safely reopen the candidate database",
                details={"current_schema_version": current.schema_version, "candidate_schema_version": expected_schema_version},
            )
        if current.source_clean is not True:
            raise RuntimeActivationError(
                "NO_SAFE_RUNTIME_ROLLBACK",
                "the current runtime source is dirty or its clean state is unknown",
            )
        try:
            current_tool_count = int(current.tool_count)
        except (TypeError, ValueError) as exc:
            raise RuntimeActivationError("CURRENT_RUNTIME_READBACK_INVALID", "current runtime tool count is invalid") from exc
        if current_tool_count != EXPECTED_V26_TOOL_COUNT:
            raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "the current runtime is not a known-good v26-compatible catalog")
        if str(current.doctor_status).upper() not in {"HEALTHY", "PASS", "OK"}:
            raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "the current runtime is not healthy enough for rollback")
        for field, allowed in {
            "persistence_status": {"HEALTHY", "PASS", "OK"},
            "cross_call_receipt_continuity": {"PASS", "HEALTHY", "OK"},
            "readonly_root_continuity": {"PASS", "HEALTHY", "OK"},
            "tunnel_status": {"HEALTHY", "PASS", "OK"},
        }.items():
            if str(getattr(current, field, "")).upper() not in allowed:
                raise RuntimeActivationError(
                    "NO_SAFE_RUNTIME_ROLLBACK",
                    f"the current runtime {field} is not healthy enough for rollback",
                )
        if self._bootstrap_contract_reader is not None:
            try:
                contract = _mapping(self._bootstrap_contract_reader(current.source_root), name="current v26 bootstrap contract")
            except RuntimeActivationError:
                raise
            except Exception as exc:  # noqa: BLE001 - rollback capability must fail closed
                raise RuntimeActivationError(
                    "NO_SAFE_RUNTIME_ROLLBACK",
                    "current runtime bootstrap contract could not be verified",
                ) from exc
            if str(contract.get("status", "")).upper() != "PASS" or str(contract.get("head", "")) != current.head:
                raise RuntimeActivationError(
                    "NO_SAFE_RUNTIME_ROLLBACK",
                    "current runtime is not a bootstrap-capable v26 rollback authority",
                )

    @staticmethod
    def _validate_receipt(candidate: CandidateRuntime, receipt: Mapping[str, Any]) -> None:
        if not isinstance(receipt, Mapping):
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary receipt is not an object")
        if receipt.get("status") != "PASS":
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary receipt is not PASS")
        if receipt.get("candidate_head") != candidate.expected_head:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary HEAD does not match")
        try:
            schema_version = int(receipt.get("schema_version", 0))
            tool_count = int(receipt.get("tool_count", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary numeric fields are invalid") from exc
        if schema_version != candidate.expected_schema_version:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary schema does not match")
        if tool_count != candidate.expected_tool_count:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary tool count does not match")
        if candidate.expected_patch_hash and receipt.get("patch_hash") != candidate.expected_patch_hash:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary patch identity does not match")
        if candidate.expected_tool_schema_hash and receipt.get("tool_schema_hash") != candidate.expected_tool_schema_hash:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary tool schema hash does not match")
        if str(receipt.get("doctor_status", "")).upper() not in {"HEALTHY", "PASS", "OK"}:
            raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", "candidate canary doctor is not healthy")
        required_statuses = {
            "persistence_status": {"HEALTHY", "PASS", "OK"},
            "cross_call_receipt_continuity": {"PASS", "HEALTHY", "OK"},
            "readonly_root_continuity": {"PASS", "HEALTHY", "OK"},
            "integration_preflight": {"PASS", "READ_ONLY_PASS", "HEALTHY", "OK"},
            "tunnel_status": {"HEALTHY", "PASS", "OK"},
            "state_isolation": {"PASS", "HEALTHY", "OK"},
            "port_isolation": {"PASS", "HEALTHY", "OK"},
        }
        for field, allowed in required_statuses.items():
            if str(receipt.get(field, "")).upper() not in allowed:
                raise RuntimeActivationError("CANARY_RECEIPT_MISMATCH", f"candidate canary {field} is not proven")

    def preflight(
        self,
        candidate: CandidateRuntime,
        *,
        current: RuntimeReadback,
        canary_receipt: Mapping[str, Any],
    ) -> ActivationPlan:
        if candidate.expected_schema_version != V26_SCHEMA_VERSION:
            raise RuntimeActivationError("SCHEMA_INCOMPATIBLE", "candidate is not a schema-14 runtime")
        self._validate_current(current, expected_schema_version=candidate.expected_schema_version)
        self._validate_receipt(candidate, canary_receipt)
        _head, database_semantic_digest, database_identity, semantic_component_digests, _catalog, _doctor = self._validate_candidate(candidate)
        if current.database_path is not None:
            if not current.database_path.is_absolute():
                raise RuntimeActivationError(
                    "CURRENT_RUNTIME_READBACK_INVALID",
                    "current runtime database path is not absolute",
                )
            if current.database_path.resolve(strict=False) != candidate.database_path.resolve(strict=False):
                raise RuntimeActivationError(
                    "CANDIDATE_DATABASE_IDENTITY_MISMATCH",
                    "candidate database path differs from the current runtime database",
                )
        if current.state_database_identity and current.state_database_identity != database_identity:
            raise RuntimeActivationError(
                "CANDIDATE_DATABASE_IDENTITY_MISMATCH",
                "candidate database identity differs from the current runtime database",
            )
        fingerprint = self._candidate_fingerprint(
            candidate,
            database_semantic_digest=database_semantic_digest,
            database_identity=database_identity,
        )
        return ActivationPlan(
            candidate=candidate,
            current=current,
            canary_receipt=dict(canary_receipt),
            candidate_fingerprint=fingerprint,
            activation_database_semantic_digest=database_semantic_digest,
            database_identity=database_identity,
            semantic_component_digests=semantic_component_digests,
        )

    def execute(self, plan: ActivationPlan) -> Mapping[str, Any]:
        if self._executor is None:
            raise RuntimeActivationError("ACTIVATION_EXECUTOR_UNAVAILABLE", "official activation executor is not configured")
        try:
            (
                _head,
                database_semantic_digest,
                database_identity,
                semantic_component_digests,
                _catalog,
                _doctor,
            ) = self._validate_candidate(plan.candidate, execute=True)
        except RuntimeActivationError as exc:
            if exc.code == "CANDIDATE_HEAD_MISMATCH":
                raise RuntimeActivationError("CANDIDATE_HEAD_DRIFT", "candidate HEAD changed after preflight") from exc
            raise
        observed_candidate_fingerprint = self._candidate_fingerprint(
            plan.candidate,
            database_semantic_digest=database_semantic_digest,
            database_identity=database_identity,
        )
        if observed_candidate_fingerprint != plan.candidate_fingerprint:
            raise RuntimeActivationError(
                "CANDIDATE_PIN_CHANGED",
                "candidate identity changed after preflight",
                details=_activation_pin_change_details(
                    plan,
                    observed_semantic_digest=database_semantic_digest,
                    observed_database_identity=database_identity,
                    observed_component_digests=semantic_component_digests,
                    observed_candidate_fingerprint=observed_candidate_fingerprint,
                ),
            )
        try:
            started = _mapping(self._executor(plan), name="activation result")
            readback = _mapping(self._post_readback(plan.candidate) if self._post_readback else {}, name="activation readback")
            if str(readback.get("head", "")) != plan.candidate.expected_head:
                raise RuntimeActivationError("POST_ACTIVATION_HEAD_MISMATCH", "activated runtime HEAD differs from candidate")
            if int(readback.get("schema_version", 0)) != plan.candidate.expected_schema_version:
                raise RuntimeActivationError("POST_ACTIVATION_SCHEMA_MISMATCH", "activated runtime schema differs from candidate")
            if str(readback.get("doctor_status", "")).upper() not in {"HEALTHY", "PASS", "OK"}:
                raise RuntimeActivationError("POST_ACTIVATION_UNHEALTHY", "activated runtime doctor is not healthy")
            try:
                readback_tool_count = int(readback.get("tool_count", 0))
            except (TypeError, ValueError) as exc:
                raise RuntimeActivationError("POST_ACTIVATION_CATALOG_MISMATCH", "activated runtime tool count is invalid") from exc
            if readback_tool_count != plan.candidate.expected_tool_count:
                raise RuntimeActivationError("POST_ACTIVATION_CATALOG_MISMATCH", "activated runtime tool catalog is incomplete")
            if plan.candidate.expected_tool_schema_hash and str(readback.get("tool_schema_hash", "")) != plan.candidate.expected_tool_schema_hash:
                raise RuntimeActivationError("POST_ACTIVATION_CATALOG_MISMATCH", "activated runtime tool schema differs from the candidate")
            for field, allowed in {
                "persistence_status": {"HEALTHY", "PASS", "OK"},
                "cross_call_receipt_continuity": {"PASS", "HEALTHY", "OK"},
                "readonly_root_continuity": {"PASS", "HEALTHY", "OK"},
                "tunnel_status": {"HEALTHY", "PASS", "OK"},
                "state_isolation": {"PASS", "HEALTHY", "OK"},
                "port_isolation": {"PASS", "HEALTHY", "OK"},
            }.items():
                if str(readback.get(field, "")).upper() not in allowed:
                    raise RuntimeActivationError("POST_ACTIVATION_HEALTH_MISMATCH", f"activated runtime {field} is not healthy")
            return {
                "status": "ACTIVATED",
                "started": dict(started),
                "readback": dict(readback),
                "candidate_fingerprint": plan.candidate_fingerprint,
                "activation_database_semantic_digest": plan.activation_database_semantic_digest,
                "semantic_digest_version": plan.semantic_digest_version,
                "excluded_audit_tables": list(plan.excluded_audit_tables),
                "database_identity": plan.database_identity,
            }
        except RuntimeActivationError as exc:
            if self._rollback_executor is None:
                raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "activation failed and no compatible rollback executor exists") from exc
            if plan.current.schema_version < plan.candidate.expected_schema_version:
                raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "activation failed and the old runtime is schema-incompatible") from exc
            try:
                self._rollback_executor(plan)
            except Exception as rollback_exc:  # noqa: BLE001 - outcome is deliberately unknown
                raise RuntimeActivationError("OUTCOME_UNKNOWN", "activation failed and rollback outcome is unknown") from rollback_exc
            return {"status": "ROLLED_BACK", "reason": exc.code, "rollback_schema_version": plan.current.schema_version}
        except Exception as exc:  # noqa: BLE001 - an executor failure must still attempt the safe rollback
            if self._rollback_executor is None:
                raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "activation failed and no compatible rollback executor exists") from exc
            if plan.current.schema_version < plan.candidate.expected_schema_version:
                raise RuntimeActivationError("NO_SAFE_RUNTIME_ROLLBACK", "activation failed and the old runtime is schema-incompatible") from exc
            try:
                self._rollback_executor(plan)
            except Exception as rollback_exc:  # noqa: BLE001 - outcome is deliberately unknown
                raise RuntimeActivationError("OUTCOME_UNKNOWN", "activation failed and rollback outcome is unknown") from rollback_exc
            return {"status": "ROLLED_BACK", "reason": "ACTIVATION_FAILED", "rollback_schema_version": plan.current.schema_version}


__all__ = [
    "ACTIVATION_DATABASE_EXCLUDED_TABLES",
    "ACTIVATION_DATABASE_SEMANTIC_DIGEST_VERSION",
    "ACTIVATION_MAX_PIN_DIAGNOSTIC_COMPONENTS",
    "ActivationPlan",
    "CandidateRuntime",
    "EXPECTED_V26_TOOL_COUNT",
    "V26_BOOTSTRAP_CONTRACT_VERSION",
    "V26_PYTHON_LOCATOR",
    "RuntimeActivationController",
    "RuntimeActivationError",
    "RuntimeReadback",
    "V26_SCHEMA_VERSION",
    "validate_v26_bootstrap_contract",
]