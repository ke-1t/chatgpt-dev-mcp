"""Prepare immutable v26 candidate and recovery artifacts.

This module is deliberately narrower than activation.  It accepts only the
server-owned canonical workspace and, when applicable, existing integration
receipts, builds a clean detached artifact from either an exact tracked patch
or an exact committed HEAD, and records bounded
readiness evidence.  It never changes the canonical checkout, production
deployment, production database, LaunchAgent, or activation state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import tempfile
from typing import Any, Callable, Mapping, Sequence

from .connector_resilience import persistence_db_identity
from .persistence import PersistenceError, inspect_readonly_roots_schema
from .process_runner import run_bounded


V26_SCHEMA_VERSION = 14
EXPECTED_V26_TOOL_COUNT = 76
MANIFEST_NAME = ".v26-candidate-manifest.json"
ENTRYPOINT_LOCATOR = "src/chatgpt_dev_mcp/http_entrypoint.py"
MAX_PATCH_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_PATHS = 64
MAX_PATH_BYTES = 512
MAX_INTEGRATION_RECEIPTS = 8
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SOURCE_MODES = frozenset({"integrated_patch", "committed_head"})
_EMPTY_PATCH_HASH = hashlib.sha256(b"").hexdigest()
_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_RETAINED_CHECKOUT_MARKERS = frozenset(
    {"development", "reconciliation", "frozen", "reference", "disposable"}
)


class CandidatePreparationError(RuntimeError):
    """A source, artifact, receipt, or role boundary failed closed."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


@dataclass(frozen=True)
class PythonRuntimeIdentity:
    locator: Path
    resolved: Path
    digest: str
    version: str


@dataclass(frozen=True)
class CandidatePreparationRequest:
    workspace_id: str
    source_mode: str
    expected_base_revision: str
    expected_patch_hash: str
    permitted_paths: tuple[str, ...]
    integration_receipt_groups: tuple[tuple[str, tuple[str, ...]], ...]
    expected_bootstrap_contract: str
    expected_schema_version: int
    expected_tool_count: int
    expected_tool_schema_hash: str
    artifact_role: str

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "CandidatePreparationRequest":
        if not isinstance(params, Mapping):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_ARGUMENT_INVALID",
                "candidate preparation parameters must be an object",
            )

        def text(name: str, maximum: int = 256) -> str:
            value = params.get(name)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
                raise CandidatePreparationError(
                    "CANDIDATE_PREPARATION_ARGUMENT_INVALID",
                    f"{name} is invalid",
                )
            return value

        workspace_id = text("workspace_id")
        if not _WORKSPACE_ID.fullmatch(workspace_id):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_ARGUMENT_INVALID",
                "workspace_id has an invalid format",
            )
        source_mode = params.get("source_mode", "integrated_patch")
        if not isinstance(source_mode, str) or source_mode not in _SOURCE_MODES:
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_MODE_INVALID",
                "source_mode must be integrated_patch or committed_head",
            )
        base = text("expected_base_revision", 40).lower()
        patch_hash = text("expected_patch_hash", 64).lower()
        if not _HEX40.fullmatch(base):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_BASE_INVALID",
                "expected_base_revision must be a full Git revision",
            )
        if not _HEX64.fullmatch(patch_hash):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_PATCH_INVALID",
                "expected_patch_hash must be a SHA-256 digest",
            )
        raw_paths = params.get("permitted_paths")
        if source_mode == "committed_head":
            if not isinstance(raw_paths, (list, tuple)) or raw_paths:
                raise CandidatePreparationError(
                    "CANDIDATE_COMMITTED_HEAD_CONTRACT_INVALID",
                    "committed_head requires an empty permitted_paths list",
                )
            paths = ()
        else:
            if not isinstance(raw_paths, (list, tuple)) or not raw_paths or len(raw_paths) > MAX_PATHS:
                raise CandidatePreparationError(
                    "CANDIDATE_PREPARATION_PATHS_INVALID",
                    "permitted_paths must contain a bounded non-empty list",
                )
            paths = tuple(sorted({_normalize_relative_path(item) for item in raw_paths}))
            if len(paths) != len(raw_paths):
                raise CandidatePreparationError(
                    "CANDIDATE_PREPARATION_PATHS_INVALID",
                    "permitted_paths must be unique",
                )
        raw_receipts = params.get("integration_receipts")
        if source_mode == "committed_head":
            if "integration_receipt_id" in params or not isinstance(raw_receipts, (list, tuple)) or raw_receipts:
                raise CandidatePreparationError(
                    "CANDIDATE_COMMITTED_HEAD_CONTRACT_INVALID",
                    "committed_head requires an empty integration_receipts list",
                )
            receipt_groups = ()
        elif raw_receipts is None:
            receipt_id = text("integration_receipt_id", 256)
            receipt_groups = ((receipt_id, paths),)
        else:
            if (
                not isinstance(raw_receipts, (list, tuple))
                or not raw_receipts
                or len(raw_receipts) > MAX_INTEGRATION_RECEIPTS
            ):
                raise CandidatePreparationError(
                    "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                    "integration_receipts must contain a bounded non-empty list",
                )
            parsed_groups: list[tuple[str, tuple[str, ...]]] = []
            seen_receipts: set[str] = set()
            seen_paths: set[str] = set()
            for item in raw_receipts:
                if not isinstance(item, Mapping):
                    raise CandidatePreparationError(
                        "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                        "each integration receipt entry must be an object",
                    )
                receipt_id_value = item.get("receipt_id")
                if (
                    not isinstance(receipt_id_value, str)
                    or not receipt_id_value
                    or len(receipt_id_value.encode("utf-8")) > 256
                    or receipt_id_value in seen_receipts
                ):
                    raise CandidatePreparationError(
                        "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                        "integration receipt ids must be unique bounded strings",
                    )
                receipt_paths = item.get("permitted_paths")
                if (
                    not isinstance(receipt_paths, (list, tuple))
                    or not receipt_paths
                    or len(receipt_paths) > MAX_PATHS
                ):
                    raise CandidatePreparationError(
                        "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                        "each integration receipt must bind a bounded path list",
                    )
                normalized_paths = tuple(sorted({_normalize_relative_path(value) for value in receipt_paths}))
                if len(normalized_paths) != len(receipt_paths) or seen_paths.intersection(normalized_paths):
                    raise CandidatePreparationError(
                        "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                        "integration receipt path groups must be unique and disjoint",
                    )
                seen_receipts.add(receipt_id_value)
                seen_paths.update(normalized_paths)
                parsed_groups.append((receipt_id_value, normalized_paths))
            if set(paths) != seen_paths:
                raise CandidatePreparationError(
                    "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                    "integration receipt path groups must cover permitted_paths exactly",
                )
            receipt_groups = tuple(parsed_groups)
        if source_mode == "committed_head" and patch_hash != _EMPTY_PATCH_HASH:
            raise CandidatePreparationError(
                "CANDIDATE_COMMITTED_HEAD_CONTRACT_INVALID",
                "committed_head requires the SHA-256 hash of an empty patch",
                details={"expected_empty_patch_hash": _EMPTY_PATCH_HASH},
            )
        contract = text("expected_bootstrap_contract", 128)
        schema = params.get("expected_schema_version")
        tool_count = params.get("expected_tool_count")
        if isinstance(schema, bool) or not isinstance(schema, int) or schema != V26_SCHEMA_VERSION:
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_SCHEMA_INVALID",
                "only the v26 schema-14 candidate contract is supported",
            )
        if isinstance(tool_count, bool) or not isinstance(tool_count, int) or tool_count != EXPECTED_V26_TOOL_COUNT:
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_CATALOG_INVALID",
                "only the verified 76-tool v26 catalog is supported",
            )
        tool_hash = text("expected_tool_schema_hash", 64).lower()
        if not _HEX64.fullmatch(tool_hash):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_CATALOG_INVALID",
                "expected_tool_schema_hash must be a SHA-256 digest",
            )
        role = text("artifact_role", 32)
        if role not in {"candidate", "recovery_baseline"}:
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_ROLE_INVALID",
                "artifact_role must be candidate or recovery_baseline",
            )
        return cls(
            workspace_id=workspace_id,
            source_mode=source_mode,
            expected_base_revision=base,
            expected_patch_hash=patch_hash,
            permitted_paths=paths,
            integration_receipt_groups=receipt_groups,
            expected_bootstrap_contract=contract,
            expected_schema_version=schema,
            expected_tool_count=tool_count,
            expected_tool_schema_hash=tool_hash,
            artifact_role=role,
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "source_mode": self.source_mode,
            "base_revision": self.expected_base_revision,
            "source_patch_hash": self.expected_patch_hash,
            "permitted_paths": list(self.permitted_paths),
            "integration_receipts": [
                {"receipt_id": receipt_id, "permitted_paths": list(paths)}
                for receipt_id, paths in self.integration_receipt_groups
            ],
            "bootstrap_contract": self.expected_bootstrap_contract,
            "schema_version": self.expected_schema_version,
            "tool_count": self.expected_tool_count,
            "tool_schema_hash": self.expected_tool_schema_hash,
            "artifact_role": self.artifact_role,
        }

    @property
    def integration_receipt_id(self) -> str:
        """Return the first receipt for compatibility with older evidence readers."""

        return self.integration_receipt_groups[0][0]

    def to_params(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "source_mode": self.source_mode,
            "expected_base_revision": self.expected_base_revision,
            "expected_patch_hash": self.expected_patch_hash,
            "permitted_paths": list(self.permitted_paths),
            "integration_receipts": [
                {"receipt_id": receipt_id, "permitted_paths": list(paths)}
                for receipt_id, paths in self.integration_receipt_groups
            ],
            "expected_bootstrap_contract": self.expected_bootstrap_contract,
            "expected_schema_version": self.expected_schema_version,
            "expected_tool_count": self.expected_tool_count,
            "expected_tool_schema_hash": self.expected_tool_schema_hash,
            "artifact_role": self.artifact_role,
        }


@dataclass(frozen=True)
class CandidatePreparationPlan:
    request: CandidatePreparationRequest
    canonical_root: Path
    artifact_root: Path
    state_root: Path
    database_source: Path
    integration_record: Mapping[str, Any]
    source_patch: str
    changed_paths: tuple[str, ...]
    source_identity_digest: str
    candidate_id: str
    python_identity: PythonRuntimeIdentity
    database_schema: int
    database_identity: str
    state_digest: str
    prepared_at: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _python_locator(workspace_id: str) -> str:
    return f"workspace://{workspace_id}/.venv/bin/python"


def _receipt_groups_payload(request: CandidatePreparationRequest) -> list[dict[str, Any]]:
    return [
        {"receipt_id": receipt_id, "permitted_paths": list(paths)}
        for receipt_id, paths in request.integration_receipt_groups
    ]


def _normalize_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATHS_INVALID",
            "permitted path is outside its safety bound",
        )
    if "\x00" in value or "\\" in value or value.startswith(("/", "~")):
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATHS_INVALID",
            "permitted paths must be repository-relative",
        )
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATHS_INVALID",
            "permitted paths must not contain traversal or ambiguous components",
        )
    return value


def _safe_env(**overrides: str) -> dict[str, str]:
    environment = {
        "PATH": _SYSTEM_PATH,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(Path.home()),
    }
    environment.update(overrides)
    return environment


def _git(
    repository: Path,
    *args: str,
    input_text: str | None = None,
    check: bool = True,
    environment: Mapping[str, str] | None = None,
) -> str:
    result = run_bounded(
        ("git", "-C", str(repository), *args),
        input_text=input_text,
        env=dict(environment or _safe_env()),
        timeout_seconds=45,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if result.timed_out or result.output_truncated:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_GIT_UNAVAILABLE",
            "bounded Git operation did not complete safely",
        )
    if check and result.returncode != 0:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_GIT_FAILED",
            result.stderr.strip() or "bounded Git operation failed",
        )
    return result.stdout


def _git_checked_hash(repository: Path, *args: str) -> str:
    value = _git(repository, *args).strip()
    if not _HEX40.fullmatch(value):
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_GIT_INVALID",
            "Git returned an invalid object identity",
        )
    return value


def _assert_repo_root(root: Path) -> Path:
    candidate = Path(root).expanduser()
    if not candidate.is_absolute():
        raise CandidatePreparationError(
            "CANDIDATE_SOURCE_NOT_CANONICAL",
            "candidate source must be an absolute server-resolved workspace",
        )
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise OSError("source root is not an ordinary directory")
        resolved = candidate.resolve(strict=True)
        git_marker = resolved / ".git"
        if git_marker.is_symlink() or not git_marker.is_dir():
            raise OSError("source root is not the primary Git checkout")
        common = Path(_git(resolved, "rev-parse", "--git-common-dir").strip())
        if not common.is_absolute():
            common = resolved / common
        if common.resolve(strict=True) != git_marker.resolve(strict=True):
            raise OSError("source root is a linked worktree")
        if any(part.casefold() in _RETAINED_CHECKOUT_MARKERS for part in resolved.parts):
            raise OSError("source root is a retained or development checkout")
    except CandidatePreparationError:
        raise
    except (OSError, ValueError) as exc:
        raise CandidatePreparationError(
            "CANDIDATE_SOURCE_NOT_CANONICAL",
            "registered source is not the canonical primary checkout",
        ) from exc
    return resolved


def _assert_bounded_directory(root: Path, *, label: str) -> Path:
    candidate = Path(root).expanduser()
    if not candidate.is_absolute():
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_SCOPE",
            f"{label} must be an absolute bounded directory",
        )
    try:
        if candidate.exists() and candidate.is_symlink():
            raise OSError("bounded directory is a symlink")
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise OSError("bounded directory ownership or permissions are unsafe")
    except OSError as exc:
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_SCOPE",
            f"{label} is unavailable or unsafe",
        ) from exc
    return resolved


def _assert_repo_relative_file(root: Path, relative: str, *, allow_missing: bool = True) -> None:
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing and index == len(parts) - 1:
                return
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_PATH_INVALID",
                f"source path is unavailable: {relative}",
            ) from None
        except OSError as exc:
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_PATH_INVALID",
                f"source path cannot be inspected: {relative}",
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_SYMLINK_DENIED",
                f"source path is a symlink: {relative}",
            )
        if index == len(parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_PATH_INVALID",
                f"source path is not a regular file: {relative}",
            )

def _nul_paths(output: str) -> tuple[str, ...]:
    return tuple(item for item in output.split("\x00") if item)


def _source_patch_for_paths(
    root: Path,
    base_revision: str,
    paths: Sequence[str],
) -> tuple[str, tuple[str, ...]]:
    for path in paths:
        _assert_repo_relative_file(root, path)
    tracked_changed = set(
        _nul_paths(
            _git(
                root,
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                base_revision,
                "--",
                *paths,
            )
        )
    )
    untracked_all = set(
        _nul_paths(_git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    )
    untracked_changed = untracked_all.intersection(paths)
    changed = tracked_changed | untracked_changed
    missing = sorted(set(paths) - changed)
    if missing:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATH_SET_MISMATCH",
            "permitted_paths does not match the current integrated source patch",
            details={"missing_changed_paths": missing},
        )
    tracked_patch = _git(
        root,
        "diff",
        "--binary",
        "--no-ext-diff",
        base_revision,
        "--",
        *paths,
    )
    untracked_patch: list[str] = []
    for path in sorted(untracked_changed):
        result = run_bounded(
            ("git", "-C", str(root), "diff", "--no-index", "--binary", "--no-ext-diff", "--", "/dev/null", path),
            env=_safe_env(),
            timeout_seconds=45,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if result.timed_out or result.output_truncated or result.returncode not in {0, 1}:
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_GIT_FAILED",
                "untracked source patch could not be read safely",
            )
        untracked_patch.append(result.stdout)
    patch = tracked_patch + "".join(untracked_patch)
    if len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATCH_TOO_LARGE",
            "integrated source patch exceeds the bounded artifact limit",
        )
    return patch, tuple(sorted(changed))


def _read_source_patch(
    root: Path,
    request: CandidatePreparationRequest,
) -> tuple[str, tuple[str, ...], dict[str, str]]:
    staged = _nul_paths(_git(root, "diff", "--cached", "--name-only", "-z"))
    if staged:
        raise CandidatePreparationError(
            "CANDIDATE_STAGED_CHANGES_PRESENT",
            "candidate preparation refuses staged source changes",
            details={"paths": list(staged)},
        )
    if request.source_mode == "committed_head":
        tracked = _nul_paths(_git(root, "diff", "--name-only", "-z"))
        if tracked:
            raise CandidatePreparationError(
                "CANDIDATE_COMMITTED_HEAD_DIRTY",
                "committed_head requires a clean tracked source",
                details={"paths": list(tracked)},
            )
        if request.expected_patch_hash != _EMPTY_PATCH_HASH:
            raise CandidatePreparationError(
                "CANDIDATE_COMMITTED_HEAD_CONTRACT_INVALID",
                "committed_head requires the SHA-256 hash of an empty patch",
                details={"expected_empty_patch_hash": _EMPTY_PATCH_HASH},
            )
        return "", (), {}
    patch, changed = _source_patch_for_paths(
        root,
        request.expected_base_revision,
        request.permitted_paths,
    )
    group_patches: dict[str, str] = {}
    for receipt_id, paths in request.integration_receipt_groups:
        group_patch, group_changed = _source_patch_for_paths(
            root,
            request.expected_base_revision,
            paths,
        )
        if group_changed != paths:
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_PATH_SET_MISMATCH",
                "an integration receipt path group does not match the current source patch",
            )
        group_patches[receipt_id] = group_patch
    if _sha256_bytes(patch.encode("utf-8")) != request.expected_patch_hash:
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_PATCH_MISMATCH",
            "current canonical patch does not match the requested source identity",
            details={"observed_patch_hash": _sha256_bytes(patch.encode("utf-8"))},
        )
    return patch, changed, group_patches


def _integration_record(
    request: CandidatePreparationRequest,
    records: Sequence[Mapping[str, Any]],
    *,
    canonical_head: str,
    group_patches: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    selected: list[dict[str, Any]] = []
    for receipt_id, _paths in request.integration_receipt_groups:
        matches = [
            record
            for record in records
            if isinstance(record, Mapping) and record.get("receipt_id") == receipt_id
        ]
        if len(matches) != 1:
            raise CandidatePreparationError(
                "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                "the exact integration receipt is not uniquely available",
            )
        record = matches[0]
        if record.get("integration_outcome") not in {"applied", "already_subsumed"}:
            raise CandidatePreparationError(
                "CANDIDATE_INTEGRATION_RECEIPT_INVALID",
                "integration receipt is not an applied integration",
            )
        if (
            record.get("source_revision") != request.expected_base_revision
            or record.get("canonical_revision") != canonical_head
        ):
            raise CandidatePreparationError(
                "CANDIDATE_INTEGRATION_RECEIPT_MISMATCH",
                "integration receipt identity does not match current canonical source",
            )
        if group_patches is not None:
            expected_hash = _sha256_bytes(group_patches[receipt_id].encode("utf-8"))
            if record.get("patch_hash") != expected_hash:
                raise CandidatePreparationError(
                    "CANDIDATE_INTEGRATION_RECEIPT_MISMATCH",
                    "integration receipt patch identity does not match its bound source paths",
                )
        elif len(request.integration_receipt_groups) == 1 and record.get("patch_hash") != request.expected_patch_hash:
            raise CandidatePreparationError(
                "CANDIDATE_INTEGRATION_RECEIPT_MISMATCH",
                "integration receipt identity does not match current canonical source",
            )
        selected.append(dict(record))
    return {"receipts": selected}


def _inspect_database(path: Path, *, expected_schema: int) -> tuple[int, str]:
    database = Path(path).expanduser()
    try:
        info = database.lstat()
        if database.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise OSError("database is not a safe regular file")
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
            inspect_readonly_roots_schema(connection, scope_path=database)
        finally:
            connection.close()
        if integrity != "ok" or row is None or int(row[0]) != expected_schema:
            raise ValueError("database schema or integrity is incompatible")
        return expected_schema, persistence_db_identity(database, schema_version=expected_schema)
    except CandidatePreparationError:
        raise
    except (OSError, sqlite3.DatabaseError, PersistenceError, ValueError) as exc:
        raise CandidatePreparationError(
            "CANDIDATE_DATABASE_INCOMPATIBLE",
            "the current v26 database is not a readable schema-14 source",
        ) from exc

def _copy_database(source: Path, destination: Path, *, expected_schema: int) -> str:
    try:
        if destination.exists() or destination.is_symlink():
            raise OSError("candidate database destination already exists")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        destination_connection = sqlite3.connect(str(destination))
        try:
            source_connection.execute("PRAGMA query_only=ON")
            source_connection.backup(destination_connection)
            destination_connection.commit()
        finally:
            destination_connection.close()
            source_connection.close()
        _inspect_database(destination, expected_schema=expected_schema)
        return persistence_db_identity(destination, schema_version=expected_schema)
    except CandidatePreparationError:
        raise
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        raise CandidatePreparationError(
            "CANDIDATE_DATABASE_SNAPSHOT_FAILED",
            "candidate database snapshot could not be created without changing production state",
        ) from exc


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CandidatePreparationError(
            "CANDIDATE_PYTHON_IDENTITY_UNKNOWN",
            "Python executable identity could not be read",
        ) from exc
    return digest.hexdigest()


def _default_python_resolver(root: Path) -> PythonRuntimeIdentity:
    locator = root / ".venv" / "bin" / "python"
    try:
        info = locator.lstat()
        if not locator.is_file() or info.st_mode & 0o022 or not os.access(locator, os.X_OK):
            raise OSError("workspace Python is not a safe executable")
        resolved = locator.resolve(strict=True)
        resolved_info = resolved.stat()
        if not resolved.is_file() or resolved_info.st_mode & 0o022 or not os.access(resolved, os.X_OK):
            raise OSError("workspace Python target is not a safe executable")
        result = run_bounded(
            (
                str(locator),
                "-B",
                "-c",
                "import json,sys; print(json.dumps({'executable':sys.executable,'version':sys.version.split()[0]}))",
            ),
            cwd=root,
            env=_safe_env(
                PYTHONNOUSERSITE="1",
                PYTHONDONTWRITEBYTECODE="1",
                PYTHONPATH="",
                PYTHONHOME="",
                VIRTUAL_ENV="",
            ),
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
        )
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise OSError("workspace Python identity probe failed")
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
        observed = Path(str(payload["executable"])).resolve(strict=True)
        if observed != resolved:
            raise OSError("Python identity probe selected a different executable")
        version = str(payload["version"])
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
            raise OSError("Python version identity is invalid")
        return PythonRuntimeIdentity(locator, resolved, _file_digest(resolved), version)
    except CandidatePreparationError:
        raise
    except (IndexError, KeyError, OSError, TypeError, ValueError) as exc:
        raise CandidatePreparationError(
            "CANDIDATE_PYTHON_IDENTITY_UNKNOWN",
            "canonical workspace Python could not be resolved through its project environment",
        ) from exc


def _tracked_source_clean_reader(root: Path) -> bool:
    """Check committed source cleanliness while intentionally ignoring untracked files."""

    staged = _nul_paths(_git(root, "diff", "--cached", "--name-only", "-z"))
    unstaged = _nul_paths(_git(root, "diff", "--name-only", "-z"))
    return not staged and not unstaged


def _default_bootstrap_validator(
    root: Path,
    expected_head: str,
    allow_dirty: bool,
) -> Mapping[str, Any]:
    try:
        from .runtime_activation import validate_v26_bootstrap_contract

        return validate_v26_bootstrap_contract(
            root,
            expected_head=expected_head,
            git_head_reader=(lambda _root: expected_head) if allow_dirty else None,
            git_clean_reader=(lambda _root: True) if allow_dirty else _tracked_source_clean_reader,
        )
    except CandidatePreparationError:
        raise
    except Exception as exc:  # noqa: BLE001 - contract verification must fail closed
        raise CandidatePreparationError(
            "CANDIDATE_BOOTSTRAP_CONTRACT_UNSUPPORTED",
            "the existing v26 bootstrap contract is unavailable or invalid",
        ) from exc


def _default_runtime_probe(
    root: Path,
    python: Path,
    *,
    expected_tool_count: int,
    expected_tool_schema_hash: str,
) -> Mapping[str, Any]:
    with tempfile.TemporaryDirectory(prefix="devmcp-v26-candidate-probe-") as temporary:
        probe_root = Path(temporary)
        config = probe_root / "config.json"
        state = probe_root / "state"
        state.mkdir(mode=0o700)
        config.write_text('{"version": 1, "workspaces": {}}\n', encoding="utf-8")
        script = (
            "import json; "
            "from chatgpt_dev_mcp.server import WrapperRuntime; "
            "from chatgpt_dev_mcp.v26_surface import V26RuntimeAdapter, V26_SURFACE_REVISION; "
            "from chatgpt_dev_mcp.observability import tool_schema_metadata; "
            "runtime=WrapperRuntime(preserve_persistent_state=True); "
            "tools=V26RuntimeAdapter(runtime).list_tools()['tools']; "
            "metadata=tool_schema_metadata(tools, revision=V26_SURFACE_REVISION); "
            "print(json.dumps({'status':'PASS' if len(tools)==76 else 'FAIL','tool_count':len(tools),'tool_schema_hash':metadata['hash']}))"
        )
        result = run_bounded(
            (str(python), "-B", "-c", script),
            cwd=root,
            env=_safe_env(
                PYTHONPATH=str(root / "src"),
                LOCAL_DEV_MCP_CONFIG=str(config),
                LOCAL_DEV_MCP_DATA_DIR=str(state),
                CODING_TOOLS_MCP_TELEMETRY="off",
                PYTHONNOUSERSITE="1",
                PYTHONDONTWRITEBYTECODE="1",
            ),
            timeout_seconds=60,
            max_output_bytes=MAX_OUTPUT_BYTES,
            merge_stderr=False,
        )
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise CandidatePreparationError(
                "CANDIDATE_RUNTIME_PROBE_FAILED",
                "candidate runtime probe failed",
            )
        try:
            payload = json.loads((result.stdout or "").strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise CandidatePreparationError(
                "CANDIDATE_RUNTIME_PROBE_FAILED",
                "candidate runtime probe returned invalid evidence",
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or str(payload.get("status", "")).upper() != "PASS"
            or int(payload.get("tool_count", 0)) != expected_tool_count
            or payload.get("tool_schema_hash") != expected_tool_schema_hash
        ):
            raise CandidatePreparationError(
                "CANDIDATE_RUNTIME_PROBE_FAILED",
                "candidate runtime catalog does not match the v26 expectation",
            )
        return dict(payload)


def _content_digest(root: Path) -> str:
    digest = hashlib.sha256()
    try:
        entries: list[tuple[str, Path]] = []
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(directories)
            files[:] = sorted(files)
            retained_directories: list[str] = []
            for name in directories:
                directory = current_path / name
                info = directory.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise OSError(f"unsafe artifact directory: {name}")
                if name != ".git":
                    retained_directories.append(name)
            directories[:] = retained_directories
            for name in files:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                if relative == MANIFEST_NAME:
                    continue
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise OSError(f"unsafe artifact entry: {relative}")
                entries.append((relative, path))
        for relative, path in sorted(entries):
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    except CandidatePreparationError:
        raise
    except OSError as exc:
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_INVALID",
            "candidate content digest could not be computed safely",
        ) from exc
    return digest.hexdigest()


def _read_manifest(root: Path) -> dict[str, Any]:
    manifest = root / MANIFEST_NAME
    try:
        info = manifest.lstat()
        if manifest.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise OSError("manifest is unsafe")
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_INVALID",
            "candidate manifest is unavailable or invalid",
        ) from exc
    if not isinstance(value, dict):
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_INVALID",
            "candidate manifest is not an object",
        )
    return value


def _set_read_only(root: Path) -> None:
    try:
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in files:
                path = Path(current) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise OSError("artifact contains a symlink")
                path.chmod(stat.S_IMODE(info.st_mode) & ~0o222)
            for name in directories:
                path = Path(current) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise OSError("artifact contains a symlink")
                path.chmod(stat.S_IMODE(info.st_mode) & ~0o222)
        root.chmod(stat.S_IMODE(root.stat().st_mode) & ~0o222)
    except OSError as exc:
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_IMMUTABILITY_FAILED",
            "candidate artifact could not be made immutable",
        ) from exc


def _persist_receipt(store: Any, record: Mapping[str, Any]) -> None:
    try:
        existing = next(
            (
                item
                for item in store.load_acceleration_receipts(kind="readiness", limit=4096)
                if item.get("receipt_id") == record.get("receipt_id")
            ),
            None,
        )
        if existing is not None:
            if (
                existing.get("metadata") != record.get("metadata")
                or existing.get("evidence_hashes") != sorted(record.get("evidence_hashes", []))
                or existing.get("refs") != sorted(record.get("refs", []))
            ):
                raise CandidatePreparationError(
                    "CANDIDATE_RECEIPT_ID_CONFLICT",
                    "candidate preparation receipt id is already bound to different evidence",
                )
            return
        store.save_acceleration_receipt(record)
    except CandidatePreparationError:
        raise
    except Exception as exc:  # noqa: BLE001 - persistence is an authority boundary
        raise CandidatePreparationError(
            "CANDIDATE_RECEIPT_PERSISTENCE_UNAVAILABLE",
            "candidate preparation receipt could not be persisted",
        ) from exc


class CandidatePreparationController:
    """Build one exact candidate or recovery baseline from managed source."""
    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        python_resolver: Callable[[Path], PythonRuntimeIdentity] | None = None,
        bootstrap_validator: Callable[[Path, str, bool], Mapping[str, Any]] | None = None,
        runtime_probe: Callable[[Path, Path, int, str], Mapping[str, Any]] | None = None,
        database_inspector: Callable[[Path, int], tuple[int, str]] | None = None,
        database_snapshotter: Callable[[Path, Path, int], str] | None = None,
    ) -> None:
        self._clock = clock or (lambda: __import__("time").time())
        self._python_resolver = python_resolver or _default_python_resolver
        self._bootstrap_validator = bootstrap_validator or _default_bootstrap_validator
        self._runtime_probe = runtime_probe or (
            lambda root, python, count, tool_hash: _default_runtime_probe(
                root,
                python,
                expected_tool_count=count,
                expected_tool_schema_hash=tool_hash,
            )
        )
        self._database_inspector = database_inspector or (
            lambda path, schema: _inspect_database(path, expected_schema=schema)
        )
        self._database_snapshotter = database_snapshotter or (
            lambda source, destination, schema: _copy_database(
                source,
                destination,
                expected_schema=schema,
            )
        )

    def preflight(
        self,
        params: Mapping[str, Any],
        *,
        canonical_root: Path,
        artifact_root: Path,
        state_root: Path,
        database_source: Path,
        integration_receipts: Sequence[Mapping[str, Any]],
    ) -> tuple[dict[str, Any], CandidatePreparationPlan]:
        request = CandidatePreparationRequest.from_params(params)
        canonical = _assert_repo_root(canonical_root)
        artifact_parent = Path(artifact_root).expanduser()
        state_parent = Path(state_root).expanduser()
        if not artifact_parent.is_absolute() or not state_parent.is_absolute():
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_SCOPE",
                "candidate artifact and state roots must be absolute server-owned roots",
            )
        for required in (
            "src/chatgpt_dev_mcp/local_maintenance.py",
            "src/chatgpt_dev_mcp/production_runtime.py",
            "src/chatgpt_dev_mcp/runtime_activation.py",
            ENTRYPOINT_LOCATOR,
        ):
            _assert_repo_relative_file(canonical, required, allow_missing=False)
        head = _git_checked_hash(canonical, "rev-parse", "--verify", "HEAD")
        if head != request.expected_base_revision:
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_HEAD_MISMATCH",
                "canonical source HEAD differs from the requested base revision",
            )
        if request.source_mode == "committed_head":
            record: Mapping[str, Any] = {"receipts": []}
        else:
            record = _integration_record(request, integration_receipts, canonical_head=head)
        patch, changed_paths, group_patches = _read_source_patch(canonical, request)
        if request.source_mode != "committed_head":
            record = _integration_record(
                request,
                integration_receipts,
                canonical_head=head,
                group_patches=group_patches,
            )
        try:
            python_identity = self._python_resolver(canonical)
            if not isinstance(python_identity, PythonRuntimeIdentity):
                raise TypeError("Python resolver returned an invalid identity")
        except CandidatePreparationError:
            raise
        except Exception as exc:  # noqa: BLE001 - identity must fail closed
            raise CandidatePreparationError(
                "CANDIDATE_PYTHON_IDENTITY_UNKNOWN",
                "canonical workspace Python identity is unavailable",
            ) from exc
        database_schema, database_identity = self._database_inspector(
            Path(database_source).expanduser(),
            request.expected_schema_version,
        )
        try:
            contract = self._bootstrap_validator(canonical, head, request.source_mode == "integrated_patch")
        except CandidatePreparationError:
            raise
        except Exception as exc:  # noqa: BLE001 - contract must fail closed
            raise CandidatePreparationError(
                "CANDIDATE_BOOTSTRAP_CONTRACT_UNSUPPORTED",
                "the integrated source does not satisfy the existing bootstrap contract",
            ) from exc
        if (
            not isinstance(contract, Mapping)
            or str(contract.get("status", "")).upper() != "PASS"
            or contract.get("head") != head
            or contract.get("contract_version") != request.expected_bootstrap_contract
        ):
            raise CandidatePreparationError(
                "CANDIDATE_BOOTSTRAP_CONTRACT_MISMATCH",
                "integrated source bootstrap contract does not match the requested version",
            )
        source_identity = request.identity_payload()
        source_identity.update(
            {
                "source_head": head,
                "python_digest": python_identity.digest,
                "python_version": python_identity.version,
                "database_schema": database_schema,
                "database_identity": database_identity,
            }
        )
        source_identity_digest = _json_digest(source_identity)
        candidate_id = f"{request.artifact_role}:{source_identity_digest[:32]}"
        prepared_at = datetime.fromtimestamp(float(self._clock()), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        state_digest = _json_digest(
            {
                "source_identity_digest": source_identity_digest,
                "canonical_root": str(canonical),
                "artifact_root": str(artifact_parent),
                "state_root": str(state_parent),
                "database_source": str(Path(database_source).expanduser()),
            }
        )
        plan = CandidatePreparationPlan(
            request=request,
            canonical_root=canonical,
            artifact_root=artifact_parent,
            state_root=state_parent,
            database_source=Path(database_source).expanduser(),
            integration_record=record,
            source_patch=patch,
            changed_paths=changed_paths,
            source_identity_digest=source_identity_digest,
            candidate_id=candidate_id,
            python_identity=python_identity,
            database_schema=database_schema,
            database_identity=database_identity,
            state_digest=state_digest,
            prepared_at=prepared_at,
        )
        preview = {
            "operation": "runtime.candidate.prepare",
            "candidate_id": candidate_id,
            "artifact_role": request.artifact_role,
            "artifact_locator": f"v26://{request.artifact_role}/{candidate_id}",
            "source_mode": request.source_mode,
            "source_head": head,
            "base_revision": request.expected_base_revision,
            "source_patch_hash": request.expected_patch_hash,
            "permitted_paths": list(request.permitted_paths),
            "bootstrap_contract": request.expected_bootstrap_contract,
            "schema_version": request.expected_schema_version,
            "tool_count": request.expected_tool_count,
            "tool_schema_hash": request.expected_tool_schema_hash,
            "database_schema": database_schema,
            "python_locator": _python_locator(request.workspace_id),
            "python_digest": python_identity.digest,
            "activation_eligible": request.artifact_role == "candidate",
            "state_digest": state_digest,
            "external_execution": False,
        }
        return preview, plan

    def execute(
        self,
        plan: CandidatePreparationPlan,
        *,
        integration_receipts: Sequence[Mapping[str, Any]],
        database_source: Path,
        persistence: Any,
    ) -> Mapping[str, Any]:
        if not isinstance(plan, CandidatePreparationPlan):
            raise CandidatePreparationError(
                "CANDIDATE_PREPARATION_STATE_INVALID",
                "candidate preparation plan is unavailable",
            )
        preview, current = self.preflight(
            plan.request.to_params(),
            canonical_root=plan.canonical_root,
            artifact_root=plan.artifact_root,
            state_root=plan.state_root,
            database_source=Path(database_source).expanduser(),
            integration_receipts=integration_receipts,
        )
        if (
            current.source_identity_digest != plan.source_identity_digest
            or current.state_digest != plan.state_digest
            or current.canonical_root != plan.canonical_root
            or current.database_source != Path(database_source).expanduser()
        ):
            raise CandidatePreparationError(
                "CANDIDATE_SOURCE_DRIFT",
                "canonical source or server-owned artifact roots changed after preflight",
            )
        artifact_parent = _assert_bounded_directory(plan.artifact_root, label="candidate artifact root")
        state_parent = _assert_bounded_directory(plan.state_root, label="candidate state root")
        stem = plan.candidate_id.replace(":", "-", 1)
        final_root = artifact_parent / stem
        final_state = state_parent / stem
        final_database = final_state / "director.sqlite3"
        if final_root.exists() or final_root.is_symlink():
            result = self._read_existing_artifact(
                final_root,
                plan,
                final_state=final_state,
                final_database=final_database,
                persistence=persistence,
            )
            return result
        if final_state.exists() or final_state.is_symlink():
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_ID_CONFLICT",
                "candidate state identity already exists without its artifact",
            )
        try:
            with tempfile.TemporaryDirectory(prefix=f".{stem}-", dir=str(artifact_parent)) as temporary:
                staging_parent = Path(temporary)
                staging_root = staging_parent / "artifact"
                _git(
                    staging_parent,
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--no-checkout",
                    str(plan.canonical_root),
                    str(staging_root),
                )
                _git(staging_root, "checkout", "--detach", plan.request.expected_base_revision)
                if plan.source_patch:
                    patch_file = staging_parent / "integrated.patch"
                    patch_file.write_text(plan.source_patch, encoding="utf-8")
                    _git(
                        staging_root,
                        "apply",
                        "--binary",
                        "--whitespace=nowarn",
                        str(patch_file),
                    )
                for required in (
                    "src/chatgpt_dev_mcp/local_maintenance.py",
                    "src/chatgpt_dev_mcp/production_runtime.py",
                    "src/chatgpt_dev_mcp/runtime_activation.py",
                    ENTRYPOINT_LOCATOR,
                ):
                    _assert_repo_relative_file(staging_root, required, allow_missing=False)
                _git(staging_root, "remote", "remove", "origin", check=False)
                content_digest = _content_digest(staging_root)
                manifest = {
                    "format_version": 1,
                    "artifact_role": plan.request.artifact_role,
                    "candidate_id": plan.candidate_id,
                    "workspace_id": plan.request.workspace_id,
                    "source_mode": plan.request.source_mode,
                    "source_head": plan.request.expected_base_revision,
                    "base_revision": plan.request.expected_base_revision,
                    "source_patch_hash": plan.request.expected_patch_hash,
                    "permitted_paths": list(plan.request.permitted_paths),
                    "integration_receipts": _receipt_groups_payload(plan.request),
                    "bootstrap_contract": plan.request.expected_bootstrap_contract,
                    "schema_version": plan.request.expected_schema_version,
                    "tool_count": plan.request.expected_tool_count,
                    "tool_schema_hash": plan.request.expected_tool_schema_hash,
                    "content_digest": content_digest,
                    "entrypoint_locator": ENTRYPOINT_LOCATOR,
                    "python_locator": _python_locator(plan.request.workspace_id),
                    "python_digest": plan.python_identity.digest,
                    "python_version": plan.python_identity.version,
                    "database_schema": plan.database_schema,
                    "activation_eligible": plan.request.artifact_role == "candidate",
                    "recovery_baseline": plan.request.artifact_role == "recovery_baseline",
                    "prepared_at": plan.prepared_at,
                }
                manifest_bytes = (
                    json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
                ).encode("utf-8")
                (staging_root / MANIFEST_NAME).write_bytes(manifest_bytes)
                _git(staging_root, "add", "--all", "--")
                tree = _git_checked_hash(staging_root, "write-tree")
                artifact_head = _git(
                    staging_root,
                    "commit-tree",
                    tree,
                    "-p",
                    plan.request.expected_base_revision,
                    input_text="v26 immutable candidate artifact\n",
                    environment=_safe_env(
                        GIT_AUTHOR_NAME="DevMCP artifact builder",
                        GIT_AUTHOR_EMAIL="devmcp@localhost",
                        GIT_COMMITTER_NAME="DevMCP artifact builder",
                        GIT_COMMITTER_EMAIL="devmcp@localhost",
                        GIT_AUTHOR_DATE="1970-01-01T00:00:00Z",
                        GIT_COMMITTER_DATE="1970-01-01T00:00:00Z",
                    ),
                ).strip()
                if not _HEX40.fullmatch(artifact_head):
                    raise CandidatePreparationError(
                        "CANDIDATE_ARTIFACT_INVALID",
                        "synthetic candidate artifact identity is invalid",
                    )
                # The index and worktree already contain the exact tree that
                # was committed above.  Move the detached HEAD directly so
                # the staging repository becomes clean without invoking a
                # destructive reset operation.
                _git(staging_root, "update-ref", "HEAD", artifact_head)
                if _git(staging_root, "status", "--porcelain=v1", "--untracked-files=all").strip():
                    raise CandidatePreparationError(
                        "CANDIDATE_ARTIFACT_DIRTY",
                        "candidate artifact is not clean after materialization",
                    )
                if _git(staging_root, "remote").strip():
                    raise CandidatePreparationError(
                        "CANDIDATE_ARTIFACT_SOURCE_LINKED",
                        "candidate artifact retained a source remote",
                    )
                common = Path(_git(staging_root, "rev-parse", "--git-common-dir").strip())
                if not common.is_absolute():
                    common = staging_root / common
                if common.resolve(strict=True) != (staging_root / ".git").resolve(strict=True):
                    raise CandidatePreparationError(
                        "CANDIDATE_ARTIFACT_WORKTREE_LINKED",
                        "candidate artifact is linked to another Git worktree",
                    )
                contract = self._bootstrap_validator(staging_root, artifact_head, False)
                if (
                    not isinstance(contract, Mapping)
                    or str(contract.get("status", "")).upper() != "PASS"
                    or contract.get("head") != artifact_head
                    or contract.get("contract_version") != plan.request.expected_bootstrap_contract
                ):
                    raise CandidatePreparationError(
                        "CANDIDATE_BOOTSTRAP_CONTRACT_MISMATCH",
                        "candidate artifact bootstrap contract is not valid for its immutable HEAD",
                    )
                probe = self._runtime_probe(
                    staging_root,
                    plan.python_identity.locator,
                    plan.request.expected_tool_count,
                    plan.request.expected_tool_schema_hash,
                )
                if (
                    not isinstance(probe, Mapping)
                    or str(probe.get("status", "")).upper() != "PASS"
                    or int(probe.get("tool_count", 0)) != plan.request.expected_tool_count
                    or probe.get("tool_schema_hash") != plan.request.expected_tool_schema_hash
                ):
                    raise CandidatePreparationError(
                        "CANDIDATE_RUNTIME_PROBE_FAILED",
                        "candidate runtime catalog does not match the v26 expectation",
                    )
                artifact_patch_hash = _sha256_bytes(
                    _git(
                        staging_root,
                        "show",
                        "--format=",
                        "--binary",
                        "--full-index",
                        "--no-ext-diff",
                        "--no-textconv",
                        "HEAD",
                        "--",
                    ).encode("utf-8")
                )
                tree_digest = _sha256_bytes(
                    _git(staging_root, "rev-parse", "HEAD^{tree}").strip().encode("ascii")
                )
                state_stage = Path(tempfile.mkdtemp(prefix=f".{stem}-", dir=str(state_parent)))
                try:
                    database_identity = self._database_snapshotter(
                        plan.database_source,
                        state_stage / "director.sqlite3",
                        plan.database_schema,
                    )
                    _git(staging_root, "fsck", "--no-progress", "--connectivity-only")
                    os.replace(staging_root, final_root)
                    os.replace(state_stage, final_state)
                except Exception:
                    shutil.rmtree(state_stage, ignore_errors=True)
                    raise
                _set_read_only(final_root)
                database_identity = persistence_db_identity(
                    final_state / "director.sqlite3",
                    schema_version=plan.database_schema,
                )
        except CandidatePreparationError:
            raise
        except (OSError, ValueError, sqlite3.DatabaseError) as exc:
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_PREPARATION_FAILED",
                "candidate artifact preparation failed before activation eligibility",
            ) from exc
        manifest_digest = _sha256_bytes((final_root / MANIFEST_NAME).read_bytes())
        metadata = {
            "artifact_role": plan.request.artifact_role,
            "candidate_id": plan.candidate_id,
            "workspace_id": plan.request.workspace_id,
            "source_mode": plan.request.source_mode,
            "source_head": plan.request.expected_base_revision,
            "base_revision": plan.request.expected_base_revision,
            "source_patch_hash": plan.request.expected_patch_hash,
            "permitted_paths": list(plan.request.permitted_paths),
            "integration_receipts": _receipt_groups_payload(plan.request),
            "bootstrap_contract": plan.request.expected_bootstrap_contract,
            "schema_version": plan.request.expected_schema_version,
            "tool_count": plan.request.expected_tool_count,
            "tool_schema_hash": plan.request.expected_tool_schema_hash,
            "content_digest": _content_digest(final_root),
            "artifact_head": _git_checked_hash(final_root, "rev-parse", "--verify", "HEAD"),
            "artifact_tree_digest": tree_digest,
            "artifact_patch_hash": artifact_patch_hash,
            "manifest_digest": manifest_digest,
            "entrypoint_locator": ENTRYPOINT_LOCATOR,
            "python_locator": _python_locator(plan.request.workspace_id),
            "python_digest": plan.python_identity.digest,
            "python_version": plan.python_identity.version,
            "database_schema": plan.database_schema,
            "database_identity": database_identity,
            "activation_eligible": plan.request.artifact_role == "candidate",
            "prepared_at": plan.prepared_at,
        }
        receipt_id = f"candidate-preparation:{_json_digest(metadata)[:32]}"
        receipt_digest = _json_digest(
            {
                "receipt_id": receipt_id,
                "kind": "candidate_preparation",
                "metadata": metadata,
                "evidence_hashes": sorted(
                    {
                        metadata["content_digest"],
                        metadata["artifact_tree_digest"],
                        metadata["artifact_patch_hash"],
                        metadata["manifest_digest"],
                        metadata["database_identity"],
                    }
                ),
            }
        )
        metadata["receipt_digest"] = receipt_digest
        receipt = {
            "receipt_id": receipt_id,
            "kind": "readiness",
            "subject_id": plan.candidate_id,
            "reason": "v26 immutable candidate artifact preparation",
            "evidence_hashes": sorted(
                {
                    metadata["content_digest"],
                    metadata["artifact_tree_digest"],
                    metadata["artifact_patch_hash"],
                    metadata["manifest_digest"],
                    metadata["database_identity"],
                }
            ),
            "refs": [
                f"artifact://v26/{plan.candidate_id}",
                *[
                    f"integration://{receipt_id}"
                    for receipt_id, _paths in plan.request.integration_receipt_groups
                ],
            ],
            "metadata": metadata,
            "created_at": plan.prepared_at,
            "external_execution": False,
        }
        _persist_receipt(persistence, receipt)
        return {
            "status": "READY",
            "candidate_id": plan.candidate_id,
            "artifact_role": plan.request.artifact_role,
            "artifact_root": str(final_root),
            "artifact_locator": f"v26://{plan.request.artifact_role}/{plan.candidate_id}",
            "source_mode": plan.request.source_mode,
            "source_head": plan.request.expected_base_revision,
            "base_revision": plan.request.expected_base_revision,
            "source_patch_hash": plan.request.expected_patch_hash,
            "artifact_head": metadata["artifact_head"],
            "artifact_patch_hash": metadata["artifact_patch_hash"],
            "content_digest": metadata["content_digest"],
            "artifact_tree_digest": metadata["artifact_tree_digest"],
            "entrypoint": str(final_root / ENTRYPOINT_LOCATOR),
            "entrypoint_locator": ENTRYPOINT_LOCATOR,
            "python_executable": str(plan.python_identity.locator),
            "python_locator": _python_locator(plan.request.workspace_id),
            "python_digest": plan.python_identity.digest,
            "python_version": plan.python_identity.version,
            "state_dir": str(final_state),
            "database_path": str(final_database),
            "database_schema": plan.database_schema,
            "database_identity": metadata["database_identity"],
            "schema_version": plan.request.expected_schema_version,
            "tool_count": plan.request.expected_tool_count,
            "tool_schema_hash": plan.request.expected_tool_schema_hash,
            "bootstrap_contract": plan.request.expected_bootstrap_contract,
            "preparation_receipt_id": receipt_id,
            "preparation_receipt_digest": receipt_digest,
            "activation_eligible": plan.request.artifact_role == "candidate",
            "production_mutated": False,
            "commit_created": False,
            "push_performed": False,
            "external_execution": False,
        }

    def _read_existing_artifact(
        self,
        root: Path,
        plan: CandidatePreparationPlan,
        *,
        final_state: Path,
        final_database: Path,
        persistence: Any,
    ) -> Mapping[str, Any]:
        manifest = _read_manifest(root)
        expected = plan.request
        if (
            manifest.get("candidate_id") != plan.candidate_id
            or manifest.get("artifact_role") != expected.artifact_role
            or manifest.get("source_mode") != expected.source_mode
            or manifest.get("source_head") != expected.expected_base_revision
            or manifest.get("source_patch_hash") != expected.expected_patch_hash
            or manifest.get("permitted_paths") != list(expected.permitted_paths)
            or manifest.get("integration_receipts") != _receipt_groups_payload(expected)
            or manifest.get("bootstrap_contract") != expected.expected_bootstrap_contract
            or manifest.get("tool_schema_hash") != expected.expected_tool_schema_hash
            or manifest.get("activation_eligible") != (expected.artifact_role == "candidate")
        ):
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_ID_CONFLICT",
                "existing candidate identity is bound to different source evidence",
            )
        artifact_head = _git_checked_hash(root, "rev-parse", "--verify", "HEAD")
        if _git(root, "status", "--porcelain=v1", "--untracked-files=all").strip():
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_DIRTY",
                "existing candidate artifact was modified after preparation",
            )
        if _content_digest(root) != manifest.get("content_digest"):
            raise CandidatePreparationError(
                "CANDIDATE_ARTIFACT_MUTATED",
                "candidate artifact bytes differ from its preparation manifest",
            )
        if not final_database.is_file() or final_database.is_symlink():
            raise CandidatePreparationError(
                "CANDIDATE_DATABASE_UNAVAILABLE",
                "existing candidate state is missing its database snapshot",
            )
        metadata = {
            "artifact_role": expected.artifact_role,
            "candidate_id": plan.candidate_id,
            "workspace_id": expected.workspace_id,
            "source_mode": expected.source_mode,
            "source_head": expected.expected_base_revision,
            "base_revision": expected.expected_base_revision,
            "source_patch_hash": expected.expected_patch_hash,
            "permitted_paths": list(expected.permitted_paths),
            "integration_receipts": _receipt_groups_payload(expected),
            "bootstrap_contract": expected.expected_bootstrap_contract,
            "schema_version": expected.expected_schema_version,
            "tool_count": expected.expected_tool_count,
            "tool_schema_hash": expected.expected_tool_schema_hash,
            "content_digest": manifest["content_digest"],
            "artifact_head": artifact_head,
            "artifact_patch_hash": _sha256_bytes(
                _git(
                    root,
                    "show",
                    "--format=",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    "HEAD",
                    "--",
                ).encode("utf-8")
            ),
            "artifact_tree_digest": _sha256_bytes(
                _git(root, "rev-parse", "HEAD^{tree}").strip().encode("ascii")
            ),
            "manifest_digest": _sha256_bytes((root / MANIFEST_NAME).read_bytes()),
            "entrypoint_locator": ENTRYPOINT_LOCATOR,
            "python_locator": _python_locator(expected.workspace_id),
            "python_digest": manifest["python_digest"],
            "python_version": manifest["python_version"],
            "database_schema": expected.expected_schema_version,
            "database_identity": persistence_db_identity(
                final_database,
                schema_version=expected.expected_schema_version,
            ),
            "activation_eligible": expected.artifact_role == "candidate",
            "prepared_at": manifest.get("prepared_at", ""),
        }
        receipt_id = f"candidate-preparation:{_json_digest(metadata)[:32]}"
        receipt_digest = _json_digest(
            {
                "receipt_id": receipt_id,
                "kind": "candidate_preparation",
                "metadata": metadata,
                "evidence_hashes": sorted(
                    {
                        metadata["content_digest"],
                        metadata["artifact_tree_digest"],
                        metadata["artifact_patch_hash"],
                        metadata["manifest_digest"],
                        metadata["database_identity"],
                    }
                ),
            }
        )
        metadata["receipt_digest"] = receipt_digest
        _persist_receipt(
            persistence,
            {
                "receipt_id": receipt_id,
                "kind": "readiness",
                "subject_id": plan.candidate_id,
                "reason": "v26 immutable candidate artifact preparation",
                "evidence_hashes": sorted(
                    {
                        metadata["content_digest"],
                        metadata["artifact_tree_digest"],
                        metadata["artifact_patch_hash"],
                        metadata["manifest_digest"],
                        metadata["database_identity"],
                    }
                ),
                "refs": [
                    f"artifact://v26/{plan.candidate_id}",
                    *[
                        f"integration://{receipt_id}"
                        for receipt_id, _paths in expected.integration_receipt_groups
                    ],
                ],
                "metadata": metadata,
                "created_at": metadata["prepared_at"],
                "external_execution": False,
            },
        )
        return {
            "status": "READY",
            "candidate_id": plan.candidate_id,
            "artifact_role": expected.artifact_role,
            "artifact_root": str(root),
            "artifact_locator": f"v26://{expected.artifact_role}/{plan.candidate_id}",
            "source_mode": expected.source_mode,
            "source_head": expected.expected_base_revision,
            "base_revision": expected.expected_base_revision,
            "source_patch_hash": expected.expected_patch_hash,
            "artifact_head": metadata["artifact_head"],
            "artifact_patch_hash": metadata["artifact_patch_hash"],
            "content_digest": metadata["content_digest"],
            "artifact_tree_digest": _sha256_bytes(
                _git(root, "rev-parse", "HEAD^{tree}").strip().encode("ascii")
            ),
            "entrypoint": str(root / ENTRYPOINT_LOCATOR),
            "entrypoint_locator": ENTRYPOINT_LOCATOR,
            "python_executable": str(plan.python_identity.locator),
            "python_locator": _python_locator(expected.workspace_id),
            "python_digest": plan.python_identity.digest,
            "python_version": plan.python_identity.version,
            "state_dir": str(final_state),
            "database_path": str(final_database),
            "database_schema": expected.expected_schema_version,
            "database_identity": metadata["database_identity"],
            "schema_version": expected.expected_schema_version,
            "tool_count": expected.expected_tool_count,
            "tool_schema_hash": expected.expected_tool_schema_hash,
            "bootstrap_contract": expected.expected_bootstrap_contract,
            "preparation_receipt_id": receipt_id,
            "preparation_receipt_digest": receipt_digest,
            "activation_eligible": expected.artifact_role == "candidate",
            "production_mutated": False,
            "commit_created": False,
            "push_performed": False,
            "external_execution": False,
        }


def validate_preparation_receipt_for_activation(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    """Allow only a candidate-role receipt to enter a later activation gate."""

    if not isinstance(receipt, Mapping):
        raise CandidatePreparationError(
            "CANDIDATE_PREPARATION_RECEIPT_INVALID",
            "candidate preparation receipt is not an object",
        )
    metadata = receipt.get("metadata")
    if not isinstance(metadata, Mapping) or metadata.get("artifact_role") != "candidate":
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_ROLE_INVALID",
            "recovery baselines cannot be used as activation candidates",
        )
    if metadata.get("activation_eligible") is not True:
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_ROLE_INVALID",
            "candidate receipt is not activation eligible",
        )
    return dict(metadata)


def validate_prepared_candidate_for_activation(
    candidate_root: Path,
    *,
    expected_schema_version: int,
    expected_tool_schema_hash: str,
) -> Mapping[str, Any] | None:
    """Reject prepared recovery artifacts at the existing activation gate.

    Legacy candidates without a preparation manifest remain under the
    pre-existing activation contract.  Artifacts produced by this module must
    carry the explicit candidate role and must still match their immutable
    byte digest before the normal canary and activation checks run.
    """

    root = Path(candidate_root).expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_INVALID",
            "prepared candidate root is unavailable",
        )
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.exists():
        return None
    manifest = _read_manifest(root)
    if (
        manifest.get("artifact_role") != "candidate"
        or manifest.get("activation_eligible") is not True
        or manifest.get("schema_version") != expected_schema_version
        or manifest.get("tool_schema_hash") != expected_tool_schema_hash
    ):
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_ROLE_INVALID",
            "only a prepared candidate artifact may enter runtime activation",
        )
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_DIRTY",
            "prepared candidate artifact is not clean",
        )
    if _content_digest(root) != manifest.get("content_digest"):
        raise CandidatePreparationError(
            "CANDIDATE_ARTIFACT_MUTATED",
            "prepared candidate artifact bytes differ from its manifest",
        )
    return manifest


__all__ = [
    "CandidatePreparationController",
    "CandidatePreparationError",
    "CandidatePreparationPlan",
    "CandidatePreparationRequest",
    "ENTRYPOINT_LOCATOR",
    "EXPECTED_V26_TOOL_COUNT",
    "MANIFEST_NAME",
    "PythonRuntimeIdentity",
    "V26_SCHEMA_VERSION",
    "validate_prepared_candidate_for_activation",
    "validate_preparation_receipt_for_activation",
]