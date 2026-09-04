"""Bounded control-plane primitives for multi-chat development flows.

The policy primitives remain side-effect-free: they never read or write the
filesystem, run a command, create a worktree, or report provider/account usage
as a fact.  ``WrapperRuntime`` supplies the narrow filesystem and registered
task adapters around these contracts.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable, Iterable, Literal, Mapping


DEFAULT_CONTEXT_MAX_BYTES = 64 * 1024
DEFAULT_CONTEXT_MAX_ITEMS = 32
DEFAULT_CONTEXT_MAX_ITEM_BYTES = 16 * 1024
DEFAULT_PATCH_MAX_BYTES = 128 * 1024
DEFAULT_PATCH_MAX_FILES = 32
DEFAULT_LEDGER_MAX_RECORDS = 256
DEFAULT_LEASE_TTL_SECONDS = 15 * 60

_MAX_CONTEXT_BYTES = 256 * 1024
_MAX_CONTEXT_ITEMS = 128
_MAX_CONTEXT_ITEM_BYTES = 64 * 1024
_MAX_PATCH_BYTES = 512 * 1024
_MAX_PATCH_FILES = 128
_MAX_IDENTIFIER_LENGTH = 128
_MAX_TITLE_LENGTH = 240
_MAX_DETAIL_LENGTH = 1000
_MAX_RESULT_REF_LENGTH = 512

_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")
_SENSITIVE_DIR_NAMES = frozenset(
    {
        ".aws",
        ".config",
        ".git",
        ".ssh",
        "browser profiles",
        "chromedata",
        "chrome",
        "keychains",
        "mozilla",
    }
)
_SENSITIVE_BASENAME_RE = re.compile(
    r"^(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|known_hosts|"
    r"credentials(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|key|p12|pfx|kdbx))$",
    re.IGNORECASE,
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?im)(^\s*[\"']?(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)[\"']?\s*[:=]\s*)"
    r"([\"']?)([^\s,}\]]+)(\2)",
)
_BEARER_SECRET_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")
_TOKEN_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{12,})\b"
)
_APPLY_PATCH_HEADER_RE = re.compile(
    r"^\*\*\*\s+(Add|Update|Delete) File:\s*(.+?)\s*$"
)
_APPLY_PATCH_MOVE_RE = re.compile(r"^\*\*\*\s+Move to:\s*(.+?)\s*$")
_UNIFIED_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+(.+?)\s*$")

PatchStatus = Literal["allow", "review_required", "deny"]
PatchRisk = Literal["low", "medium", "high"]
TaskStatus = Literal[
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
]

__all__ = [
    "CapabilitySnapshot",
    "ContextItem",
    "ContextPack",
    "ContextSource",
    "DirectorError",
    "LedgerConflict",
    "LeaseConflict",
    "PatchDecision",
    "TaskLedger",
    "TaskReceipt",
    "UsageLedger",
    "ValidationError",
    "WriterLease",
    "WriterLeaseManager",
    "build_context_pack",
    "contains_secret_like_content",
    "evaluate_patch",
    "normalize_relative_path",
    "normalize_resource_id",
    "redact_secrets",
    "sha256_text",
    "validate_workspace_id",
]


class DirectorError(ValueError):
    """Base class for deterministic policy-layer failures."""


class ValidationError(DirectorError):
    """Raised when a proposal is malformed or outside the policy boundary."""


class LeaseConflict(DirectorError):
    """Raised when another writer owns the workspace lease."""


class LedgerConflict(DirectorError):
    """Raised when a task transition or idempotency check conflicts."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_text(value: object, *, name: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be text")
    if not allow_empty and not value.strip():
        raise ValidationError(f"{name} must not be empty")
    if len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{name} is outside its safety bound")
    return value


def validate_workspace_id(value: object) -> str:
    text = _bounded_text(value, name="workspace_id", maximum=64)
    if not _WORKSPACE_ID_RE.fullmatch(text):
        raise ValidationError("workspace_id has an invalid format")
    return text


def _validate_identifier(value: object, *, name: str) -> str:
    text = _bounded_text(value, name=name, maximum=_MAX_IDENTIFIER_LENGTH)
    if not _IDENTIFIER_RE.fullmatch(text):
        raise ValidationError(f"{name} has an invalid format")
    return text


def normalize_resource_id(value: object) -> str:
    text = _bounded_text(value, name="resource", maximum=240)
    if not _RESOURCE_RE.fullmatch(text) or contains_secret_like_content(text):
        raise ValidationError("resource has an invalid format")
    return text


def sha256_text(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("hash input must be text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sensitive_path(path: str) -> bool:
    parts = [part.lower() for part in path.split("/")]
    return any(part in _SENSITIVE_DIR_NAMES for part in parts) or bool(
        _SENSITIVE_BASENAME_RE.fullmatch(parts[-1])
    )


def normalize_relative_path(value: object) -> str:
    """Validate a workspace-relative, non-sensitive POSIX path."""

    raw = _bounded_text(value, name="path", maximum=240)
    if raw != raw.strip() or raw.startswith(("/", "~")) or "\\" in raw:
        raise ValidationError("path must be a normalized relative POSIX path")
    pieces = raw.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise ValidationError("path must not contain traversal or empty segments")
    normalized = str(PurePosixPath(*pieces))
    if normalized != raw or _is_sensitive_path(normalized):
        raise ValidationError("path is sensitive or not normalized")
    return normalized


def contains_secret_like_content(value: str) -> bool:
    return bool(
        _PRIVATE_KEY_RE.search(value)
        or _ASSIGNMENT_SECRET_RE.search(value)
        or _BEARER_SECRET_RE.search(value)
        or _TOKEN_SECRET_RE.search(value)
    )


def _patch_contains_secret_like_content(value: str) -> bool:
    if contains_secret_like_content(value):
        return True
    content_lines: list[str] = []
    for line in value.splitlines():
        if line.startswith(("+++", "---")):
            continue
        content_lines.append(line[1:] if line.startswith(("+", "-", " ")) else line)
    return contains_secret_like_content("\n".join(content_lines))


def redact_secrets(value: str) -> str:
    """Redact common credential shapes without attempting to parse arbitrary data."""

    redacted = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", value)
    redacted = _ASSIGNMENT_SECRET_RE.sub(r"\1\2[REDACTED]\4", redacted)
    redacted = _BEARER_SECRET_RE.sub("Bearer [REDACTED]", redacted)
    return _TOKEN_SECRET_RE.sub("[REDACTED_TOKEN]", redacted)


def _truncate_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


@dataclass(frozen=True)
class ContextSource:
    """A caller-provided source slice; no filesystem access happens here."""

    path: str
    content: str
    start_line: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        if not isinstance(self.content, str) or "\x00" in self.content:
            raise ValidationError("context content must be text without NUL bytes")
        if len(self.content.encode("utf-8")) > _MAX_CONTEXT_ITEM_BYTES * 16:
            raise ValidationError("context content exceeds the input safety bound")
        if not isinstance(self.start_line, int) or isinstance(self.start_line, bool) or self.start_line < 1:
            raise ValidationError("start_line must be a positive integer")


@dataclass(frozen=True)
class ContextItem:
    path: str
    content: str
    start_line: int
    end_line: int
    truncated: bool
    content_hash: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "content": self.content,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "truncated": self.truncated,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True)
class ContextPack:
    workspace_id: str
    items: tuple[ContextItem, ...]
    total_bytes: int
    truncated: bool
    omitted_paths: tuple[str, ...]
    base_revision: str
    context_pack_id: str
    generated_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 2,
            "workspace_id": self.workspace_id,
            "base_revision": self.base_revision,
            "context_pack_id": self.context_pack_id,
            "generated_at": self.generated_at,
            "items": [item.as_dict() for item in self.items],
            "total_bytes": self.total_bytes,
            "truncated": self.truncated,
            "omitted_paths": list(self.omitted_paths),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_context_pack(
    workspace_id: object,
    sources: Iterable[ContextSource],
    *,
    max_bytes: int = DEFAULT_CONTEXT_MAX_BYTES,
    max_items: int = DEFAULT_CONTEXT_MAX_ITEMS,
    max_item_bytes: int = DEFAULT_CONTEXT_MAX_ITEM_BYTES,
    base_revision: str = "unknown",
    generated_at: str | None = None,
) -> ContextPack:
    """Build a bounded, redacted context pack from already-read source slices."""

    workspace = validate_workspace_id(workspace_id)
    revision = _bounded_text(base_revision, name="base_revision", maximum=128)
    created_at = generated_at or _utc_now()
    if not 1 <= max_bytes <= _MAX_CONTEXT_BYTES:
        raise ValidationError("max_bytes is outside its safety bound")
    if not 1 <= max_items <= _MAX_CONTEXT_ITEMS:
        raise ValidationError("max_items is outside its safety bound")
    if not 1 <= max_item_bytes <= _MAX_CONTEXT_ITEM_BYTES:
        raise ValidationError("max_item_bytes is outside its safety bound")

    parsed = list(sources)
    if any(not isinstance(source, ContextSource) for source in parsed):
        raise ValidationError("sources must contain ContextSource values")
    paths = [source.path for source in parsed]
    if len(paths) != len(set(paths)):
        raise ValidationError("context paths must be unique")

    items: list[ContextItem] = []
    omitted: list[str] = []
    total_bytes = 0
    was_truncated = False
    for index, source in enumerate(parsed):
        redacted = redact_secrets(source.content)
        bounded, item_truncated = _truncate_utf8(redacted, max_item_bytes)
        remaining = max_bytes - total_bytes
        if index >= max_items or remaining <= 0:
            omitted.append(source.path)
            was_truncated = True
            continue
        bounded, pack_truncated = _truncate_utf8(bounded, remaining)
        item_truncated = item_truncated or pack_truncated
        if not bounded and source.content:
            omitted.append(source.path)
            was_truncated = True
            continue
        line_count = bounded.count("\n") + (1 if bounded else 0)
        items.append(
            ContextItem(
                path=source.path,
                content=bounded,
                start_line=source.start_line,
                end_line=source.start_line + max(line_count - 1, 0),
                truncated=item_truncated,
                content_hash=sha256_text(source.content),
            )
        )
        total_bytes += len(bounded.encode("utf-8"))
        was_truncated = was_truncated or item_truncated

    fingerprint = sha256_text(
        json.dumps(
            {
                "workspace_id": workspace,
                "base_revision": revision,
                "files": [
                    [source.path, sha256_text(source.content), source.start_line]
                    for source in parsed
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return ContextPack(
        workspace_id=workspace,
        items=tuple(items),
        total_bytes=total_bytes,
        truncated=was_truncated,
        omitted_paths=tuple(omitted),
        base_revision=revision,
        context_pack_id=f"context:{fingerprint[:32]}",
        generated_at=created_at,
    )


@dataclass(frozen=True)
class PatchDecision:
    status: PatchStatus
    risk: PatchRisk
    reason: str
    paths: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.status != "deny"

    @property
    def requires_review(self) -> bool:
        return self.status == "review_required"

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "allowed": self.allowed,
            "requires_review": self.requires_review,
            "risk": self.risk,
            "reason": self.reason,
            "paths": list(self.paths),
            "operations": list(self.operations),
        }


def _patch_path_from_unified(raw: str, prefix: str) -> str | None:
    path = raw.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    if path.startswith(prefix + "/"):
        path = path[len(prefix) + 1 :]
    return normalize_relative_path(path)


def _deny_patch(reason: str) -> PatchDecision:
    return PatchDecision(status="deny", risk="high", reason=reason)


def evaluate_patch(
    patch: object,
    *,
    max_bytes: int = DEFAULT_PATCH_MAX_BYTES,
    max_files: int = DEFAULT_PATCH_MAX_FILES,
    allowed_prefixes: Iterable[str] = (),
) -> PatchDecision:
    """Preflight a patch without applying it or exposing patch contents."""

    if not isinstance(patch, str) or not patch.strip() or "\x00" in patch:
        return _deny_patch("PATCH_INVALID_INPUT")
    encoded_size = len(patch.encode("utf-8"))
    if not 1 <= max_bytes <= _MAX_PATCH_BYTES or encoded_size > max_bytes:
        return _deny_patch("PATCH_SIZE_LIMIT")
    if not 1 <= max_files <= _MAX_PATCH_FILES:
        return _deny_patch("PATCH_FILE_LIMIT")
    if _patch_contains_secret_like_content(patch):
        return _deny_patch("PATCH_SECRET_LIKE_CONTENT")

    try:
        prefixes = tuple(normalize_relative_path(value) for value in allowed_prefixes)
    except ValidationError:
        return _deny_patch("PATCH_PREFIX_INVALID")

    lines = patch.splitlines()
    has_begin = any(line.strip() == "*** Begin Patch" for line in lines)
    has_end = any(line.strip() == "*** End Patch" for line in lines)
    if has_begin != has_end:
        return _deny_patch("PATCH_BOUNDARY_INVALID")

    apply_entries: list[tuple[str, str]] = []
    for line in lines:
        match = _APPLY_PATCH_HEADER_RE.match(line)
        if match:
            operation, raw_path = match.groups()
            try:
                path = normalize_relative_path(raw_path)
            except ValidationError:
                return _deny_patch("PATCH_PATH_INVALID")
            apply_entries.append((operation.lower(), path))
            continue
        move_match = _APPLY_PATCH_MOVE_RE.match(line)
        if move_match:
            try:
                path = normalize_relative_path(move_match.group(1))
            except ValidationError:
                return _deny_patch("PATCH_PATH_INVALID")
            apply_entries.append(("move", path))

    entries = apply_entries
    if not entries:
        unified_entries: list[tuple[str, str]] = []
        pending_old: str | None = None
        pending_old_seen = False
        for line in lines:
            match = _UNIFIED_HEADER_RE.match(line)
            if not match:
                continue
            marker, raw_path = match.groups()
            try:
                path = _patch_path_from_unified(raw_path, "a" if marker == "---" else "b")
            except ValidationError:
                return _deny_patch("PATCH_PATH_INVALID")
            if marker == "---":
                if pending_old_seen:
                    return _deny_patch("PATCH_HEADER_INVALID")
                pending_old = path
                pending_old_seen = True
                continue
            if not pending_old_seen:
                return _deny_patch("PATCH_HEADER_INVALID")
            new_path = path
            if pending_old is None and new_path is None:
                return _deny_patch("PATCH_HEADER_INVALID")
            if pending_old is None:
                operation = "add"
                logical_paths = (new_path,)
            elif new_path is None:
                operation = "delete"
                logical_paths = (pending_old,)
            elif pending_old != new_path:
                operation = "move"
                logical_paths = (pending_old, new_path)
            else:
                operation = "update"
                logical_paths = (pending_old,)
            for logical_path in logical_paths:
                if logical_path is not None:
                    unified_entries.append((operation, logical_path))
            pending_old = None
            pending_old_seen = False
        if pending_old_seen:
            return _deny_patch("PATCH_HEADER_INVALID")
        entries = unified_entries

    if not entries:
        return _deny_patch("PATCH_NO_FILES")
    if len(entries) > max_files:
        return _deny_patch("PATCH_FILE_LIMIT")

    paths = tuple(path for _, path in entries)
    if len(paths) != len(set(paths)):
        return _deny_patch("PATCH_DUPLICATE_PATH")
    if prefixes and any(
        not any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)
        for path in paths
    ):
        return _deny_patch("PATCH_PATH_OUTSIDE_ALLOWED_PREFIX")

    operations = tuple(operation for operation, _ in entries)
    if any(operation in {"delete", "move"} for operation in operations):
        return PatchDecision(
            status="review_required",
            risk="high",
            reason="PATCH_DESTRUCTIVE_REVIEW",
            paths=paths,
            operations=operations,
        )
    risk: PatchRisk = "medium" if "update" in operations else "low"
    return PatchDecision(status="allow", risk=risk, reason="PATCH_PREFLIGHT_OK", paths=paths, operations=operations)


@dataclass(frozen=True)
class WriterLease:
    workspace_id: str
    working_tree_id: str
    owner_id: str
    task_id: str
    paths: tuple[str, ...]
    resources: tuple[str, ...]
    lease_id: str
    expires_at: float
    base_revision: str
    scope_hashes: tuple[tuple[str, str], ...] = ()
    workspace_state_hash: str = ""
    workspace_wide: bool = False
    acquired_at: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "owner_id": self.owner_id,
            "task_id": self.task_id,
            "paths": list(self.paths),
            "resources": list(self.resources),
            "lease_id": self.lease_id,
            "expires_at": self.expires_at,
            "base_revision": self.base_revision,
            "scope_hashes": dict(self.scope_hashes),
            "workspace_state_hash": self.workspace_state_hash,
            "workspace_wide": self.workspace_wide,
            "acquired_at": self.acquired_at,
        }


class WriterLeaseManager:
    """In-memory path/resource scoped writer guard."""

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
        on_change: Callable[[WriterLease, str], None] | None = None,
    ) -> None:
        if not 1 <= ttl_seconds <= 24 * 60 * 60:
            raise ValidationError("ttl_seconds is outside its safety bound")
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._on_change = on_change
        self._lock = threading.Lock()
        self._leases: dict[str, WriterLease] = {}

    def _notify(self, lease: WriterLease, state: str) -> None:
        if self._on_change is not None:
            self._on_change(lease, state)

    @staticmethod
    def _paths_overlap(first: str, second: str) -> bool:
        left = first.casefold()
        right = second.casefold()
        return left == right or left.startswith(right + "/") or right.startswith(left + "/")

    def _prune(self, now: float) -> None:
        expired = [lease_id for lease_id, lease in self._leases.items() if lease.expires_at <= now]
        for lease_id in expired:
            lease = self._leases.get(lease_id)
            if lease is not None:
                self._notify(lease, "expired")
                self._leases.pop(lease_id, None)

    def _active_values(self, now: float) -> tuple[WriterLease, ...]:
        self._prune(now)
        return tuple(self._leases.values())

    def acquire(
        self,
        workspace_id: object,
        owner_id: object,
        *,
        working_tree_id: object | None = None,
        task_id: object | None = None,
        paths: Iterable[object] | None = None,
        resources: Iterable[object] = (),
        base_revision: object = "unknown",
        scope_hashes: Mapping[str, str] | None = None,
        workspace_state_hash: object = "",
        workspace_wide: bool = False,
    ) -> WriterLease:
        workspace = validate_workspace_id(workspace_id)
        owner = _validate_identifier(owner_id, name="owner_id")
        tree = _validate_identifier(
            working_tree_id if working_tree_id is not None else f"workspace:{workspace}",
            name="working_tree_id",
        )
        task = _validate_identifier(task_id if task_id is not None else f"legacy:{owner}", name="task_id")
        # ``None`` is retained as a compatibility spelling for the old
        # direct Python API. Public Director contracts must pass an explicit
        # ``workspace_wide=true`` when they want that scope; an empty list is
        # never silently widened.
        if paths is None:
            workspace_wide = True
        elif not isinstance(workspace_wide, bool):
            raise ValidationError("workspace_wide must be boolean")
        parsed_paths = tuple(normalize_relative_path(path) for path in (paths or ()))
        if len(parsed_paths) != len(set(parsed_paths)):
            raise ValidationError("lease paths must be unique")
        parsed_resources = tuple(normalize_resource_id(resource) for resource in resources)
        if len(parsed_resources) != len(set(parsed_resources)):
            raise ValidationError("lease resources must be unique")
        if not workspace_wide and not parsed_paths and not parsed_resources:
            raise ValidationError("INVALID_LEASE_SCOPE")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128)
        state_hash = _bounded_text(workspace_state_hash, name="workspace_state_hash", maximum=128, allow_empty=True)
        parsed_hashes: list[tuple[str, str]] = []
        for path, digest in (scope_hashes or {}).items():
            normalized = normalize_relative_path(path)
            if not workspace_wide and not any(
                normalized == allowed or normalized.startswith(allowed + "/")
                for allowed in parsed_paths
            ):
                raise ValidationError("scope hash path is outside lease paths")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValidationError("scope hash must be sha256 hex")
            parsed_hashes.append((normalized, digest))
        parsed_hashes.sort()
        now = self._clock()
        with self._lock:
            active = self._active_values(now)
            for current in active:
                if set(current.resources) & set(parsed_resources):
                    raise LeaseConflict("runtime resource already has an active writer")
                if current.workspace_id != workspace:
                    continue
                if current.workspace_wide or workspace_wide:
                    raise LeaseConflict("working tree already has a workspace-wide writer")
                if current.working_tree_id == tree and any(
                    self._paths_overlap(first, second)
                    for first in current.paths
                    for second in parsed_paths
                ):
                    raise LeaseConflict("writer lease paths overlap")
            lease = WriterLease(
                workspace,
                tree,
                owner,
                task,
                parsed_paths,
                parsed_resources,
                uuid.uuid4().hex,
                now + self._ttl_seconds,
                revision,
                tuple(parsed_hashes),
                state_hash,
                workspace_wide,
                now,
            )
            self._notify(lease, "active")
            self._leases[lease.lease_id] = lease
            return lease

    def refresh(self, lease: WriterLease) -> WriterLease:
        if not isinstance(lease, WriterLease):
            raise ValidationError("lease must be a WriterLease")
        now = self._clock()
        with self._lock:
            self._prune(now)
            current = self._leases.get(lease.lease_id)
            if current is None or current.owner_id != lease.owner_id:
                raise LeaseConflict("lease is not current")
            refreshed = replace(current, expires_at=now + self._ttl_seconds)
            self._notify(refreshed, "active")
            self._leases[lease.lease_id] = refreshed
            return refreshed

    def update_snapshot(
        self,
        lease: WriterLease,
        *,
        base_revision: object,
        scope_hashes: Mapping[str, str],
        workspace_state_hash: object = "",
    ) -> WriterLease:
        if not isinstance(lease, WriterLease):
            raise ValidationError("lease must be a WriterLease")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128)
        state_hash = _bounded_text(workspace_state_hash, name="workspace_state_hash", maximum=128, allow_empty=True)
        parsed: list[tuple[str, str]] = []
        for path, digest in scope_hashes.items():
            normalized = normalize_relative_path(path)
            if not lease.workspace_wide and not any(
                normalized == allowed or normalized.startswith(allowed + "/")
                for allowed in lease.paths
            ):
                raise ValidationError("snapshot path is outside lease scope")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValidationError("scope hash must be sha256 hex")
            parsed.append((normalized, digest))
        parsed.sort()
        with self._lock:
            self._prune(self._clock())
            current = self._leases.get(lease.lease_id)
            if current is None or current.owner_id != lease.owner_id:
                raise LeaseConflict("lease is not current")
            updated = replace(
                current,
                base_revision=revision,
                scope_hashes=tuple(parsed),
                workspace_state_hash=state_hash,
            )
            self._notify(updated, "active")
            self._leases[lease.lease_id] = updated
            return updated

    def release(self, lease: WriterLease) -> None:
        if not isinstance(lease, WriterLease):
            raise ValidationError("lease must be a WriterLease")
        with self._lock:
            current = self._leases.get(lease.lease_id)
            if current is None or current.owner_id != lease.owner_id:
                raise LeaseConflict("lease is not current")
            self._notify(current, "released")
            self._leases.pop(lease.lease_id, None)

    def suspend(self, lease: WriterLease) -> None:
        """Drop one live lease while retaining restart-recovery evidence."""

        if not isinstance(lease, WriterLease):
            raise ValidationError("lease must be a WriterLease")
        with self._lock:
            current = self._leases.get(lease.lease_id)
            if current is None or current.owner_id != lease.owner_id:
                raise LeaseConflict("lease is not current")
            self._notify(current, "stale")
            self._leases.pop(lease.lease_id, None)

    def restore(self, leases: Iterable[WriterLease], *, now: float | None = None) -> tuple[WriterLease, ...]:
        """Restore only validated, unexpired leases after a persistence reconcile."""

        current_time = self._clock() if now is None else float(now)
        restored: list[WriterLease] = []
        with self._lock:
            self._prune(current_time)
            for lease in leases:
                if not isinstance(lease, WriterLease) or lease.expires_at <= current_time:
                    continue
                conflict = False
                for active in self._leases.values():
                    if active.workspace_id != lease.workspace_id:
                        continue
                    if active.workspace_wide or lease.workspace_wide or any(
                        self._paths_overlap(left, right)
                        for left in active.paths
                        for right in lease.paths
                    ) or set(active.resources) & set(lease.resources):
                        conflict = True
                        break
                if conflict:
                    continue
                self._leases[lease.lease_id] = lease
                restored.append(lease)
        return tuple(restored)

    def get(self, lease_id: object) -> WriterLease | None:
        lease_key = _validate_identifier(lease_id, name="lease_id")
        with self._lock:
            self._prune(self._clock())
            return self._leases.get(lease_key)

    def active(
        self,
        workspace_id: object,
        *,
        working_tree_id: object | None = None,
    ) -> tuple[WriterLease, ...]:
        workspace = validate_workspace_id(workspace_id)
        tree = _validate_identifier(working_tree_id, name="working_tree_id") if working_tree_id is not None else None
        with self._lock:
            active = self._active_values(self._clock())
            return tuple(
                sorted(
                    (
                        lease
                        for lease in active
                        if lease.workspace_id == workspace and (tree is None or lease.working_tree_id == tree)
                    ),
                    key=lambda lease: lease.lease_id,
                )
            )

    def observed_active(
        self,
        workspace_id: object,
        *,
        working_tree_id: object | None = None,
    ) -> tuple[WriterLease, ...]:
        """Observe unexpired leases without changing lease state.

        ``active`` is an authority-management method: pruning an expired lease
        emits a durable state transition through ``on_change``.  Read-only
        status and preflight paths must not trigger that transition merely by
        inspecting the current state, so they use this non-mutating view.
        """

        workspace = validate_workspace_id(workspace_id)
        tree = _validate_identifier(working_tree_id, name="working_tree_id") if working_tree_id is not None else None
        now = self._clock()
        with self._lock:
            return tuple(
                sorted(
                    (
                        lease
                        for lease in self._leases.values()
                        if lease.expires_at > now
                        and lease.workspace_id == workspace
                        and (tree is None or lease.working_tree_id == tree)
                    ),
                    key=lambda lease: lease.lease_id,
                )
            )

    def active_all(self) -> tuple[WriterLease, ...]:
        """Return every unexpired lease for controlled runtime shutdown."""

        with self._lock:
            return tuple(sorted(self._active_values(self._clock()), key=lambda lease: lease.lease_id))

    def covers(
        self,
        lease: WriterLease,
        paths: Iterable[object],
        *,
        resources: Iterable[object] = (),
    ) -> bool:
        if not isinstance(lease, WriterLease):
            raise ValidationError("lease must be a WriterLease")
        parsed_paths = tuple(normalize_relative_path(path) for path in paths)
        parsed_resources = tuple(normalize_resource_id(resource) for resource in resources)
        if not lease.workspace_wide and any(
            not any(path == allowed or path.startswith(allowed + "/") for allowed in lease.paths)
            for path in parsed_paths
        ):
            return False
        return set(parsed_resources) <= set(lease.resources)

    def current(self, workspace_id: object) -> WriterLease | None:
        active = self.active(workspace_id)
        return active[0] if active else None


@dataclass(frozen=True)
class TaskReceipt:
    task_id: str
    request_id: str
    workspace_id: str
    title: str
    status: TaskStatus
    owner_id: str | None
    created_at: str
    updated_at: str
    detail: str = ""
    result_ref: str = ""
    working_tree_id: str = ""
    development_session_id: str = ""
    allowed_paths: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    lease_id: str = ""
    base_revision: str = ""
    patch_hash: str = ""
    verification_receipt: str = ""
    security_audit_receipt: str = ""
    context_pack_id: str = ""
    integration_receipt: str = ""
    git_commit_receipt: str = ""
    git_push_receipt: str = ""
    dependencies: tuple[str, ...] = ()
    result: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "title": self.title,
            "status": self.status,
            "owner_id": self.owner_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "detail": self.detail,
            "result_ref": self.result_ref,
            "working_tree_id": self.working_tree_id,
            "development_session_id": self.development_session_id,
            "allowed_paths": list(self.allowed_paths),
            "resources": list(self.resources),
            "lease_id": self.lease_id,
            "base_revision": self.base_revision,
            "patch_hash": self.patch_hash,
            "verification_receipt": self.verification_receipt,
            "security_audit_receipt": self.security_audit_receipt,
            "context_pack_id": self.context_pack_id,
            "integration_receipt": self.integration_receipt,
            "git_commit_receipt": self.git_commit_receipt,
            "git_push_receipt": self.git_push_receipt,
            "dependencies": list(self.dependencies),
            "result": self.result,
        }


class TaskLedger:
    """Bounded, idempotent local task state; it does not execute tasks."""

    def __init__(
        self,
        *,
        max_records: int = DEFAULT_LEDGER_MAX_RECORDS,
        clock: Callable[[], str] = _utc_now,
        on_change: Callable[[TaskReceipt], None] | None = None,
    ) -> None:
        if not 1 <= max_records <= 4096:
            raise ValidationError("max_records is outside its safety bound")
        self._max_records = max_records
        self._clock = clock
        self._on_change = on_change
        self._lock = threading.Lock()
        self._records: dict[str, TaskReceipt] = {}

    def _notify(self, receipt: TaskReceipt) -> None:
        if self._on_change is not None:
            self._on_change(receipt)

    @staticmethod
    def _title(value: object) -> str:
        title = _bounded_text(value, name="title", maximum=_MAX_TITLE_LENGTH)
        if contains_secret_like_content(title):
            raise ValidationError("title looks like credential material")
        return title

    @staticmethod
    def _detail(value: object) -> str:
        detail = _bounded_text(value, name="detail", maximum=_MAX_DETAIL_LENGTH, allow_empty=True)
        if contains_secret_like_content(detail):
            raise ValidationError("detail looks like credential material")
        return detail

    @staticmethod
    def _result_ref(value: object) -> str:
        result_ref = _bounded_text(value, name="result_ref", maximum=_MAX_RESULT_REF_LENGTH, allow_empty=True)
        if contains_secret_like_content(result_ref) or "\n" in result_ref or "\r" in result_ref:
            raise ValidationError("result_ref is invalid")
        return result_ref

    def _trim_for_insert(self) -> None:
        while len(self._records) >= self._max_records:
            terminal = [
                record
                for record in self._records.values()
                if record.status in {"succeeded", "failed", "cancelled", "blocked", "stale"}
            ]
            if not terminal:
                raise LedgerConflict("task ledger is full of active tasks")
            oldest = min(terminal, key=lambda record: record.created_at)
            self._records.pop(oldest.task_id, None)

    @staticmethod
    def _optional_identifier(value: object, *, name: str) -> str:
        if value is None or value == "":
            return ""
        return _validate_identifier(value, name=name)

    @staticmethod
    def _optional_hash(value: object, *, name: str) -> str:
        if value is None or value == "":
            return ""
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValidationError(f"{name} must be sha256 hex")
        return value

    def enqueue(
        self,
        request_id: object,
        workspace_id: object,
        title: object,
        *,
        working_tree_id: object = "",
        development_session_id: object = "",
        allowed_paths: Iterable[object] = (),
        resources: Iterable[object] = (),
        depends_on: Iterable[object] = (),
        base_revision: object = "",
        context_pack_id: object = "",
    ) -> TaskReceipt:
        request = _validate_identifier(request_id, name="request_id")
        workspace = validate_workspace_id(workspace_id)
        task_title = self._title(title)
        tree = self._optional_identifier(working_tree_id, name="working_tree_id")
        session_id = self._optional_identifier(development_session_id, name="development_session_id")
        parsed_paths = tuple(normalize_relative_path(path) for path in allowed_paths)
        if len(parsed_paths) != len(set(parsed_paths)):
            raise ValidationError("allowed_paths must be unique")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128, allow_empty=True)
        context_id = self._optional_identifier(context_pack_id, name="context_pack_id")
        parsed_resources = tuple(normalize_resource_id(resource) for resource in resources)
        if len(parsed_resources) != len(set(parsed_resources)):
            raise ValidationError("resources must be unique")
        parsed_dependencies = tuple(_validate_identifier(item, name="dependency") for item in depends_on)
        if len(parsed_dependencies) != len(set(parsed_dependencies)) or request in parsed_dependencies:
            raise ValidationError("dependencies must be unique and cannot reference the request id")
        if len(parsed_dependencies) > 64:
            raise ValidationError("dependencies exceed the safety bound")
        with self._lock:
            for record in self._records.values():
                if record.request_id != request or record.workspace_id != workspace:
                    continue
                if record.title != task_title:
                    raise LedgerConflict("request_id is already used for a different task")
                return record
            self._trim_for_insert()
            now = self._clock()
            receipt = TaskReceipt(
                task_id=f"task-{uuid.uuid4().hex}",
                request_id=request,
                workspace_id=workspace,
                title=task_title,
                status="queued",
                owner_id=None,
                created_at=now,
                updated_at=now,
                working_tree_id=tree,
                development_session_id=session_id,
                allowed_paths=parsed_paths,
                resources=parsed_resources,
                dependencies=parsed_dependencies,
                base_revision=revision,
                context_pack_id=context_id,
            )
            self._notify(receipt)
            self._records[receipt.task_id] = receipt
            return receipt

    def _transition_locked(
        self,
        current: TaskReceipt,
        status: TaskStatus,
        *,
        owner_id: str | None = None,
        lease_id: str | None = None,
        patch_hash: str | None = None,
        verification_receipt: str | None = None,
        security_audit_receipt: str | None = None,
        integration_receipt: str | None = None,
        git_commit_receipt: str | None = None,
        git_push_receipt: str | None = None,
        detail: str | None = None,
        result_ref: str | None = None,
        result: str | None = None,
    ) -> TaskReceipt:
        transitions: dict[TaskStatus, set[TaskStatus]] = {
            "queued": {"ready", "running", "cancelled", "blocked", "stale"},
            "ready": {"leased", "running", "cancelled", "blocked", "stale"},
            "leased": {"running", "cancelled", "blocked", "stale"},
            "running": {"verifying", "review_ready", "succeeded", "failed", "cancelled", "blocked", "stale"},
            "verifying": {"review_ready", "failed", "blocked", "stale"},
            "review_ready": {"succeeded", "failed", "cancelled", "blocked", "stale"},
            "succeeded": set(),
            "failed": set(),
            "cancelled": set(),
            "blocked": set(),
            "stale": set(),
        }
        if owner_id is not None and current.owner_id is not None and owner_id != current.owner_id:
            raise LedgerConflict("task is owned by a different writer")
        if lease_id is not None and current.lease_id and lease_id != current.lease_id:
            raise LedgerConflict("task is bound to a different writer lease")
        if current.status != status and status not in transitions[current.status]:
            raise LedgerConflict(f"invalid task transition: {current.status}->{status}")
        return replace(
            current,
            status=status,
            owner_id=owner_id if owner_id is not None else current.owner_id,
            lease_id=lease_id if lease_id is not None else current.lease_id,
            patch_hash=patch_hash if patch_hash is not None else current.patch_hash,
            verification_receipt=(
                verification_receipt if verification_receipt is not None else current.verification_receipt
            ),
            security_audit_receipt=(
                security_audit_receipt if security_audit_receipt is not None else current.security_audit_receipt
            ),
            integration_receipt=(
                integration_receipt if integration_receipt is not None else current.integration_receipt
            ),
            git_commit_receipt=(
                git_commit_receipt if git_commit_receipt is not None else current.git_commit_receipt
            ),
            git_push_receipt=(
                git_push_receipt if git_push_receipt is not None else current.git_push_receipt
            ),
            detail=detail if detail is not None else current.detail,
            result_ref=result_ref if result_ref is not None else current.result_ref,
            result=result if result is not None else current.result,
            updated_at=self._clock(),
        )

    def bind_execution(
        self,
        task_id: object,
        *,
        working_tree_id: object,
        development_session_id: object,
        base_revision: object = "",
        allowed_paths: Iterable[object] | None = None,
        resources: Iterable[object] | None = None,
    ) -> TaskReceipt:
        """Attach immutable session/worktree identity to a task receipt."""

        task_key = _validate_identifier(task_id, name="task_id")
        tree = _validate_identifier(working_tree_id, name="working_tree_id")
        session = _validate_identifier(development_session_id, name="development_session_id")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128, allow_empty=True)
        parsed_paths = None if allowed_paths is None else tuple(normalize_relative_path(path) for path in allowed_paths)
        parsed_resources = None if resources is None else tuple(normalize_resource_id(resource) for resource in resources)
        with self._lock:
            current = self._records.get(task_key)
            if current is None:
                raise LedgerConflict("task is unknown")
            bound = replace(
                current,
                working_tree_id=tree,
                development_session_id=session,
                base_revision=revision or current.base_revision,
                allowed_paths=current.allowed_paths if parsed_paths is None else parsed_paths,
                resources=current.resources if parsed_resources is None else parsed_resources,
                updated_at=self._clock(),
            )
            self._notify(bound)
            self._records[task_key] = bound
            return bound

    def transition(
        self,
        task_id: object,
        status: TaskStatus,
        *,
        owner_id: object | None = None,
        lease_id: object = "",
        patch_hash: object = "",
        verification_receipt: object = "",
        security_audit_receipt: object = "",
        git_commit_receipt: object = "",
        git_push_receipt: object = "",
        detail: object = "",
        result_ref: object = "",
        result: object = "",
        integration_receipt: object = "",
    ) -> TaskReceipt:
        task = _validate_identifier(task_id, name="task_id")
        if status not in {
            "queued", "ready", "leased", "running", "verifying", "review_ready",
            "succeeded", "failed", "cancelled", "blocked", "stale",
        }:
            raise ValidationError("status is invalid")
        owner = _validate_identifier(owner_id, name="owner_id") if owner_id is not None else None
        lease = self._optional_identifier(lease_id, name="lease_id")
        patch = self._optional_hash(patch_hash, name="patch_hash")
        verification = self._optional_identifier(verification_receipt, name="verification_receipt")
        audit = self._optional_identifier(security_audit_receipt, name="security_audit_receipt")
        git_commit = self._optional_identifier(git_commit_receipt, name="git_commit_receipt")
        git_push = self._optional_identifier(git_push_receipt, name="git_push_receipt")
        integration = self._optional_identifier(integration_receipt, name="integration_receipt")
        parsed_detail = self._detail(detail)
        parsed_result_ref = self._result_ref(result_ref)
        parsed_result = self._detail(result)
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            updated = self._transition_locked(
                current,
                status,
                owner_id=owner,
                lease_id=lease or None,
                patch_hash=patch or None,
                verification_receipt=verification or None,
                security_audit_receipt=audit or None,
                git_commit_receipt=git_commit or None,
                git_push_receipt=git_push or None,
                integration_receipt=integration or None,
                detail=parsed_detail or None,
                result_ref=parsed_result_ref or None,
                result=parsed_result or None,
            )
            self._notify(updated)
            self._records[task] = updated
            return updated

    def start(self, task_id: object, owner_id: object) -> TaskReceipt:
        task = _validate_identifier(task_id, name="task_id")
        owner = _validate_identifier(owner_id, name="owner_id")
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            if current.status == "running" and current.owner_id == owner:
                return current
            if current.status not in {"queued", "ready", "leased"}:
                raise LedgerConflict("task is not startable")
            updated = self._transition_locked(current, "running", owner_id=owner)
            self._notify(updated)
            self._records[task] = updated
            return updated

    def rollback_claim(self, task_id: object, *, detail: object = "") -> TaskReceipt:
        """Return an allocator-bound task to ready after a local claim failure."""

        task = _validate_identifier(task_id, name="task_id")
        parsed_detail = self._detail(detail)
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            if current.status not in {"leased", "running"}:
                raise LedgerConflict("task claim is not rollbackable")
            updated = replace(
                current,
                status="ready",
                owner_id=None,
                lease_id="",
                working_tree_id="",
                development_session_id="",
                detail=parsed_detail or current.detail,
                updated_at=self._clock(),
            )
            self._notify(updated)
            self._records[task] = updated
            return updated

    def resume(
        self,
        task_id: object,
        *,
        owner_id: object,
        base_revision: object = "",
        detail: object = "",
    ) -> TaskReceipt:
        """Return one stale task to ready without carrying stale write evidence."""

        task = _validate_identifier(task_id, name="task_id")
        owner = _validate_identifier(owner_id, name="owner_id")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128, allow_empty=True)
        parsed_detail = self._detail(detail)
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            if current.status != "stale":
                raise LedgerConflict("task is not resumable")
            if current.owner_id != owner:
                raise LedgerConflict("task is owned by a different writer")
            if revision and current.base_revision and revision != current.base_revision:
                raise LedgerConflict("task base revision changed")
            updated = replace(
                current,
                status="ready",
                owner_id=None,
                lease_id="",
                base_revision=revision or current.base_revision,
                patch_hash="",
                verification_receipt="",
                security_audit_receipt="",
                integration_receipt="",
                git_commit_receipt="",
                git_push_receipt="",
                detail=parsed_detail,
                result_ref="",
                result="",
                updated_at=self._clock(),
            )
            self._notify(updated)
            self._records[task] = updated
            return updated

    def reactivate(
        self,
        task_id: object,
        *,
        owner_id: object,
        lease_id: object,
        base_revision: object = "",
        detail: object = "",
    ) -> TaskReceipt:
        """Atomically rebind a stale task to the same owner and a fresh lease."""

        task = _validate_identifier(task_id, name="task_id")
        owner = _validate_identifier(owner_id, name="owner_id")
        lease = _validate_identifier(lease_id, name="lease_id")
        revision = _bounded_text(base_revision, name="base_revision", maximum=128, allow_empty=True)
        parsed_detail = self._detail(detail)
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            if current.status != "stale":
                raise LedgerConflict("task is not resumable")
            if current.owner_id != owner:
                raise LedgerConflict("task is owned by a different writer")
            if revision and current.base_revision and revision != current.base_revision:
                raise LedgerConflict("task base revision changed")
            updated = replace(
                current,
                status="running",
                owner_id=owner,
                lease_id=lease,
                base_revision=revision or current.base_revision,
                patch_hash="",
                verification_receipt="",
                security_audit_receipt="",
                integration_receipt="",
                git_commit_receipt="",
                git_push_receipt="",
                detail=parsed_detail,
                result_ref="",
                result="",
                updated_at=self._clock(),
            )
            self._notify(updated)
            self._records[task] = updated
            return updated

    def finish(
        self,
        task_id: object,
        status: Literal["succeeded", "failed", "cancelled"],
        *,
        owner_id: object,
        detail: object = "",
        result_ref: object = "",
    ) -> TaskReceipt:
        task = _validate_identifier(task_id, name="task_id")
        owner = _validate_identifier(owner_id, name="owner_id")
        if status not in {"succeeded", "failed", "cancelled"}:
            raise ValidationError("status is not terminal")
        parsed_detail = self._detail(detail)
        parsed_result_ref = self._result_ref(result_ref)
        with self._lock:
            current = self._records.get(task)
            if current is None:
                raise LedgerConflict("task does not exist")
            if current.status not in {"running", "verifying", "review_ready"} or current.owner_id != owner:
                raise LedgerConflict("task is not owned by this writer")
            updated = self._transition_locked(
                current,
                status,
                detail=parsed_detail,
                result_ref=parsed_result_ref,
            )
            self._notify(updated)
            self._records[task] = updated
            return updated

    def restore(self, records: Iterable[TaskReceipt], *, replace_existing: bool = False) -> None:
        """Load already-validated records without replaying task transitions."""

        parsed = tuple(records)
        if any(not isinstance(record, TaskReceipt) for record in parsed):
            raise ValidationError("records must contain TaskReceipt values")
        normalized = tuple(
            replace(record, status="review_ready")
            if (
                # Persistence hydration conservatively downgrades a pushed
                # canonical review-ready task to ``stale`` before TaskLedger
                # sees it. A successful push receipt is already durable evidence,
                # so restore only this exact synthetic stale shape and leave
                # explicit/session stale tasks terminal.
                record.status == "stale"
                and record.detail == "push receipt recorded"
                and record.working_tree_id
                and not record.working_tree_id.startswith("session:")
                and not record.development_session_id
                and record.git_commit_receipt.startswith(("git-commit:", "git-verified-commit:"))
                and record.git_push_receipt.startswith("git-push:")
            )
            else record
            for record in parsed
        )
        with self._lock:
            if replace_existing:
                self._records.clear()
            for record in normalized:
                self._records[record.task_id] = record
            if len(self._records) > self._max_records:
                ordered = sorted(self._records.values(), key=lambda item: (item.created_at, item.task_id))
                self._records = {item.task_id: item for item in ordered[-self._max_records:]}

    def get(self, task_id: object) -> TaskReceipt | None:
        task = _validate_identifier(task_id, name="task_id")
        with self._lock:
            return self._records.get(task)

    def list(self, *, workspace_id: object | None = None) -> tuple[TaskReceipt, ...]:
        workspace = validate_workspace_id(workspace_id) if workspace_id is not None else None
        with self._lock:
            records = [
                record
                for record in self._records.values()
                if workspace is None or record.workspace_id == workspace
            ]
            return tuple(sorted(records, key=lambda record: (record.created_at, record.task_id)))


@dataclass(frozen=True)
class CapabilitySnapshot:
    profile: str
    external_execution: bool
    account_usage: Literal["unknown"]
    capabilities: tuple[str, ...]
    local_counters: Mapping[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "external_execution": self.external_execution,
            "account_usage": self.account_usage,
            "capabilities": list(self.capabilities),
            "local_counters": dict(self.local_counters),
        }


class UsageLedger:
    """Tracks local observations only; provider quota remains explicitly unknown."""

    def __init__(
        self,
        *,
        profile: str = "DEVELOPMENT",
        capabilities: Iterable[str] = (),
        external_execution: bool = False,
    ) -> None:
        if profile not in {"READ_ONLY", "READ_WRITE", "DEVELOPMENT"}:
            raise ValidationError("profile is invalid")
        if not isinstance(external_execution, bool):
            raise ValidationError("external_execution must be boolean")
        parsed_capabilities = tuple(sorted({_validate_identifier(value, name="capability") for value in capabilities}))
        self._profile = profile
        self._capabilities = parsed_capabilities
        self._external_execution = bool(external_execution)
        self._counters: Counter[str] = Counter()
        self._lock = threading.Lock()

    def record(self, capability: object, amount: int = 1) -> None:
        name = _validate_identifier(capability, name="capability")
        if not isinstance(amount, int) or isinstance(amount, bool) or not 1 <= amount <= 1000:
            raise ValidationError("amount is outside its safety bound")
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> CapabilitySnapshot:
        with self._lock:
            counters = dict(sorted(self._counters.items()))
        return CapabilitySnapshot(
            profile=self._profile,
            external_execution=self._external_execution,
            account_usage="unknown",
            capabilities=self._capabilities,
            local_counters=counters,
        )
