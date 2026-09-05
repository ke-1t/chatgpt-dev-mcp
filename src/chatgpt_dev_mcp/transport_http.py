"""Wrapper-owned Streamable HTTP transport with per-session runtimes.

The production connector currently uses the STDIO entrypoint.  This module is
an intentionally disposable alternative for local/Tunnel experiments: every
MCP session gets a fresh :class:`WrapperRuntime`, so handshake, workspace,
candidate, approval, and development state never crosses an HTTP session.

The upstream HTTP transport is not used here because it would expose the
upstream runtime's registry rather than this wrapper's policy-filtered surface.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import OrderedDict, deque
from typing import Any, Callable
from urllib.parse import urlsplit

from coding_tools_mcp.errors import JsonRpcError
from coding_tools_mcp.protocol import (
    dispatch_rpc,
    jsonrpc_error,
    rpc_params,
    response_id,
    validate_initialize_params,
    validate_initialize_request,
    validate_rpc_envelope,
)

from .server import WrapperRuntime, load_registry
from .chatgpt_connector_compat import request_id_scope
from .connection_doctor import diagnose_connection
from .connection_observability import ConnectionObservabilityStore
from .observability import HEALTH_SCHEMA_REVISION, TOOL_SCHEMA_REVISION, registry_health, schema_consistency, tool_schema_metadata
from .request_lifecycle import RequestConflict, RequestRegistry, RequestRecord, SideEffectClass
from .v26_surface import V26_SURFACE_REVISION, V26RuntimeAdapter

MCP_ENDPOINT = "/mcp"
CANARY_MCP_ENDPOINT = "/mcp/v25-canary"
V26_CANARY_MCP_ENDPOINT = "/mcp/v26-canary"
MCP_ENDPOINTS = frozenset({MCP_ENDPOINT, CANARY_MCP_ENDPOINT, V26_CANARY_MCP_ENDPOINT})
HEALTH_ENDPOINT = "/healthz"
READY_ENDPOINT = "/readyz"
DEFAULT_MAX_HTTP_SESSIONS = 128
DEFAULT_HTTP_SESSION_TTL_SECONDS = 10 * 60
DEFAULT_MAX_RETIRED_SESSION_IDS = 4096
DEFAULT_MAX_SESSION_CREATIONS = 32
DEFAULT_SESSION_CREATION_WINDOW_SECONDS = 60.0
DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_HTTP_INFLIGHT = 64
MAX_RETIRED_SESSION_IDS = 16384
MAX_HTTP_BODY_BYTES = 1 * 1024 * 1024
MAX_SESSION_ID_BYTES = 256
SESSION_ID_PREFIX = "mcp_"
_SESSION_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def _default_http_runtime_factory() -> WrapperRuntime:
    """Create the wrapper runtime with the HTTP telemetry contract."""

    return WrapperRuntime(transport="http")


def _normalized_initialize_params(request: dict[str, Any]) -> str:
    validate_rpc_envelope(request)
    validate_initialize_request(request)
    params = dict(rpc_params(request))
    params["protocolVersion"] = validate_initialize_params(params)
    return json.dumps(params, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _tool_side_effect_class(request: dict[str, Any]) -> SideEffectClass:
    if request.get("method") != "tools/call":
        return SideEffectClass.READ_ONLY
    params = request.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str):
        return SideEffectClass.READ_ONLY
    arguments = params.get("arguments") if isinstance(params, dict) else None
    if not isinstance(arguments, dict):
        arguments = {}
    if name == "readonly_path":
        if arguments.get("action", "open") in {"open", "status", "close"}:
            return SideEffectClass.LOCAL_REVERSIBLE
        return SideEffectClass.READ_ONLY
    if name == "browser_inspect":
        if arguments.get("kind") == "screenshot":
            return SideEffectClass.LOCAL_REVERSIBLE
        return SideEffectClass.READ_ONLY
    if name == "browser_action":
        if arguments.get("action") in {"viewport", "wait"}:
            return SideEffectClass.LOCAL_REVERSIBLE
        return SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
    if name == "browser_test_session":
        if arguments.get("action") == "profiles":
            return SideEffectClass.READ_ONLY
        return SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
    if name == "desktop_runtime":
        if arguments.get("action") in {"profiles", "status", "logs"}:
            return SideEffectClass.READ_ONLY
        return SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
    if name == "director_review":
        if arguments.get("action") in {"list", "readiness"}:
            return SideEffectClass.READ_ONLY
        return SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
    if name in {
        "workspace_list_development_sessions",
        "semantic_code_query",
        "development_context",
        "workspace_register_preflight",
        "workspace_unregister_preflight",
        "workspace_registration_update_preflight",
        "git_stage_preflight",
        "git_stage_paths_preflight",
        "git_stage_hunks_preflight",
        "git_commit_preflight",
        "git_verified_commit_preflight",
        "git_push_preflight",
        "workspace_integration_preflight",
        "workspace_request_development",
    }:
        return SideEffectClass.LOCAL_REVERSIBLE
    if name in {
        "apply_patch",
        "run_task",
        "run_tests",
        "run_lint",
        "run_build",
        "run_dev",
        "run_format",
        "task_poll",
        "task_stop",
        "arbitrary_command_run",
        "git_commit",
        "git_push",
        "git_workflow_apply",
        "github_workflow_apply",
        "dependency_apply",
        "browser_action",
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_keyboard",
        "browser_session_start",
        "browser_session_close",
        "desktop_runtime_start",
        "desktop_runtime_snapshot",
        "desktop_runtime_stop",
        "director_task_ledger",
        "director_writer_lease",
        "director_baseline_snapshot",
        "git_stage",
        "git_stage_hunks",
        "patch_revert",
        "director_development_start",
        "director_next_action",
        "capability_execute",
        "director_plan_work",
        "director_claim_task",
        "verification_run",
        "verification_record",
        "browser_qa_run",
        "local_maintenance",
        "command_profile_run",
        "workspace_create_development_session",
        "workspace_attach_development_session",
        "workspace_resume_development_session",
        "workspace_close_development_session",
        "workspace_integrate_development_session",
    } or name.endswith(("_apply", "_commit", "_push")):
        return SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
    if name in {"browser_viewport", "browser_wait"}:
        return SideEffectClass.LOCAL_REVERSIBLE
    return SideEffectClass.READ_ONLY


class HTTPTransportError(Exception):
    """A bounded transport error that can be rendered as JSON-RPC."""

    def __init__(
        self,
        status: int,
        code: int,
        message: str,
        *,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.reason = reason
        self.details = dict(details or {})

    def response(self, request_id: str | int | None = None) -> dict[str, Any]:
        return jsonrpc_error(request_id, self.code, self.message, {"reason": self.reason, **self.details})


@dataclass
class HTTPSessionRecord:
    session_id: str
    runtime: WrapperRuntime
    created_at: float
    last_seen: float
    lock: threading.RLock
    request_registry: RequestRegistry
    initialize_result: dict[str, Any] | None = None
    initialize_params: str | None = None
    active_requests: int = 0


class WrapperHTTPSessionManager:
    """Own bounded, non-reusable HTTP sessions and their wrapper runtimes."""

    def __init__(
        self,
        runtime_factory: Callable[[], WrapperRuntime] = _default_http_runtime_factory,
        *,
        max_sessions: int = DEFAULT_MAX_HTTP_SESSIONS,
        session_ttl_seconds: float = DEFAULT_HTTP_SESSION_TTL_SECONDS,
        max_retired_session_ids: int = DEFAULT_MAX_RETIRED_SESSION_IDS,
        max_session_creations: int = DEFAULT_MAX_SESSION_CREATIONS,
        session_creation_window_seconds: float = DEFAULT_SESSION_CREATION_WINDOW_SECONDS,
        session_id_namespace: str = "",
        clock: Callable[[], float] = time.monotonic,
        observability_store: ConnectionObservabilityStore | None = None,
        transport_generation: str = "http",
        schema_metadata: dict[str, Any] | None = None,
    ) -> None:
        if not isinstance(max_sessions, int) or isinstance(max_sessions, bool) or not 1 <= max_sessions <= 1024:
            raise ValueError("max_sessions must be between 1 and 1024")
        if session_ttl_seconds <= 0 or session_ttl_seconds > 24 * 60 * 60:
            raise ValueError("session_ttl_seconds must be between 0 and 86400")
        if (
            not isinstance(max_retired_session_ids, int)
            or isinstance(max_retired_session_ids, bool)
            or not 1 <= max_retired_session_ids <= MAX_RETIRED_SESSION_IDS
        ):
            raise ValueError(f"max_retired_session_ids must be between 1 and {MAX_RETIRED_SESSION_IDS}")
        if (
            not isinstance(max_session_creations, int)
            or isinstance(max_session_creations, bool)
            or not 1 <= max_session_creations <= 4096
        ):
            raise ValueError("max_session_creations must be between 1 and 4096")
        if session_creation_window_seconds <= 0 or session_creation_window_seconds > 24 * 60 * 60:
            raise ValueError("session_creation_window_seconds must be between 0 and 86400")
        if (
            not isinstance(session_id_namespace, str)
            or len(session_id_namespace) > 32
            or any(character not in _SESSION_ID_CHARS for character in session_id_namespace)
        ):
            raise ValueError("session_id_namespace must contain only MCP session id characters and be at most 32 characters")
        self.runtime_factory = runtime_factory
        self.max_sessions = max_sessions
        self.ttl_seconds = float(session_ttl_seconds)
        self.max_retired_session_ids = max_retired_session_ids
        self.max_session_creations = max_session_creations
        self.session_creation_window_seconds = float(session_creation_window_seconds)
        self._session_id_namespace = session_id_namespace
        self._observability_store = observability_store
        self._transport_generation = transport_generation
        self._schema_metadata = dict(schema_metadata or {})
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, HTTPSessionRecord] = {}
        self._retired: OrderedDict[str, str] = OrderedDict()
        self._session_nonce = secrets.token_urlsafe(18)
        self._next_session_sequence = 0
        self._session_creation_times: deque[float] = deque()
        self._closed = False

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def schema_metadata(self) -> dict[str, Any]:
        return dict(self._schema_metadata)

    def _new_session_id(self) -> str:
        self._next_session_sequence += 1
        candidate = f"{SESSION_ID_PREFIX}{self._session_id_namespace}{self._session_nonce}_{self._next_session_sequence}"
        if len(candidate.encode("ascii")) > MAX_SESSION_ID_BYTES:
            raise HTTPTransportError(503, -32000, "Unable to allocate a session identifier", reason="session_id_unavailable")
        return candidate

    def _remember_retired(self, session_id: str, reason: str) -> None:
        """Remember a bounded amount of lifecycle history while fail-closing old IDs."""

        self._retired[session_id] = reason
        self._retired.move_to_end(session_id)
        while len(self._retired) > self.max_retired_session_ids:
            self._retired.popitem(last=False)

    def _close_record(self, record: HTTPSessionRecord) -> None:
        with record.lock:
            try:
                record.runtime.close()
            except Exception:
                # Session cleanup is best effort; the session is still retired and
                # cannot be reused even if an upstream task refuses to close.
                pass

    def prune(self, *, now: float | None = None) -> int:
        current = self._clock() if now is None else now
        expired: list[HTTPSessionRecord] = []
        with self._lock:
            for session_id, record in list(self._sessions.items()):
                if record.active_requests == 0 and current - record.last_seen >= self.ttl_seconds:
                    self._sessions.pop(session_id, None)
                    self._remember_retired(session_id, "expired_session")
                    if self._observability_store is not None:
                        self._observability_store.record_disconnect(session_id, reason="expired_session")
                    expired.append(record)
        for record in expired:
            self._close_record(record)
        return len(expired)

    def _oldest_idle_session_locked(self) -> HTTPSessionRecord | None:
        idle = (record for record in self._sessions.values() if record.active_requests == 0)
        return min(idle, key=lambda record: (record.last_seen, record.created_at, record.session_id), default=None)

    def create(self) -> HTTPSessionRecord:
        self.prune()
        now = self._clock()
        evicted: HTTPSessionRecord | None = None
        with self._lock:
            if self._closed:
                raise HTTPTransportError(503, -32000, "The HTTP transport is closed", reason="transport_closed")
            cutoff = now - self.session_creation_window_seconds
            while self._session_creation_times and self._session_creation_times[0] <= cutoff:
                self._session_creation_times.popleft()
            if len(self._session_creation_times) >= self.max_session_creations:
                raise HTTPTransportError(429, -32000, "The session creation rate is bounded", reason="session_creation_limit")
            if len(self._sessions) >= self.max_sessions:
                evicted = self._oldest_idle_session_locked()
                if evicted is None:
                    raise HTTPTransportError(429, -32000, "The maximum number of MCP sessions is active", reason="session_limit")
            session_id = self._new_session_id()
            runtime = self.runtime_factory()
            # Request lifecycle records are emitted by the wrapped runtime,
            # while v26 requests may be delegated through an adapter. Bind the
            # logical HTTP connection to the underlying runtime so every
            # child-emitted event carries the same connection identity.
            runtime_owner = getattr(runtime, "_runtime", runtime)
            logical_connection_id = f"http-session:{session_id}"
            setattr(runtime_owner, "logical_connection_id", logical_connection_id)
            setattr(runtime_owner, "protocol_runtime_identity", logical_connection_id)
            bind_doctor = getattr(runtime, "bind_connection_doctor", None)
            if callable(bind_doctor) and self._observability_store is not None:
                def _doctor(
                    client_schema=None,
                    *,
                    _runtime=runtime,
                    _session_id=session_id,
                    _store=self._observability_store,
                ):
                    local_result = _runtime.call_tool("director_health", {})
                    local_health = (
                        local_result.get("structuredContent", {})
                        if isinstance(local_result, dict)
                        else {}
                    )
                    observation = _store.snapshot(_session_id) or {}
                    return diagnose_connection(local_health, observation, client_schema)

                bind_doctor(_doctor)
            registry = getattr(runtime, "request_registry", None)
            if not isinstance(registry, RequestRegistry):
                registry = RequestRegistry()
                setattr(runtime, "request_registry", registry)
            if evicted is not None:
                self._sessions.pop(evicted.session_id, None)
                self._remember_retired(evicted.session_id, "capacity_evicted_session")
                if self._observability_store is not None:
                    self._observability_store.record_disconnect(evicted.session_id, reason="capacity_evicted_session")
            record = HTTPSessionRecord(session_id, runtime, now, now, threading.RLock(), registry, active_requests=1)
            self._sessions[session_id] = record
            self._session_creation_times.append(now)
            if self._observability_store is not None:
                self._observability_store.create_session(
                    session_id,
                    transport_generation=self._transport_generation,
                    registry_revision=str(self._schema_metadata.get("revision") or ""),
                    schema_hash=str(self._schema_metadata.get("hash") or ""),
                    tool_count=self._schema_metadata.get("count") if isinstance(self._schema_metadata.get("count"), int) else None,
                )
        if evicted is not None:
            self._close_record(evicted)
        return record

    def claim(self, session_id: str) -> HTTPSessionRecord:
        self._validate_id(session_id)
        self.prune()
        with self._lock:
            if self._closed:
                raise HTTPTransportError(503, -32000, "The HTTP transport is closed", reason="transport_closed")
            record = self._sessions.get(session_id)
            if record is not None:
                record.active_requests += 1
                record.last_seen = self._clock()
                return record
            reason = self._retired.get(session_id, "unknown_session")
        raise HTTPTransportError(404, -32001, "Unknown MCP session", reason=reason)

    def release(self, record: HTTPSessionRecord) -> None:
        with self._lock:
            if record.active_requests <= 0:
                raise RuntimeError("MCP session request claim underflow")
            record.active_requests -= 1
            if self._sessions.get(record.session_id) is record:
                record.last_seen = self._clock()

    def get(self, session_id: str) -> HTTPSessionRecord:
        self._validate_id(session_id)
        self.prune()
        with self._lock:
            if self._closed:
                raise HTTPTransportError(503, -32000, "The HTTP transport is closed", reason="transport_closed")
            record = self._sessions.get(session_id)
            if record is not None:
                record.last_seen = self._clock()
                return record
            reason = self._retired.get(session_id, "unknown_session")
        raise HTTPTransportError(404, -32001, "Unknown MCP session", reason=reason)

    def delete(self, session_id: str, *, reason: str = "deleted_session") -> bool:
        self._validate_id(session_id)
        with self._lock:
            record = self._sessions.pop(session_id, None)
            if record is None:
                if session_id in self._retired:
                    return False
                self._remember_retired(session_id, reason)
                return False
            self._remember_retired(session_id, reason)
            if self._observability_store is not None:
                self._observability_store.record_disconnect(session_id, reason=reason)
        self._close_record(record)
        return True

    def retired_reason(self, session_id: str) -> str:
        self._validate_id(session_id)
        with self._lock:
            return self._retired.get(session_id, "unknown_session")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            records = list(self._sessions.values())
            for record in records:
                self._remember_retired(record.session_id, "transport_closed")
                if self._observability_store is not None:
                    self._observability_store.record_disconnect(record.session_id, reason="transport_closed")
            self._sessions.clear()
        for record in records:
            self._close_record(record)

    @staticmethod
    def _validate_id(session_id: str) -> None:
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id.encode("utf-8")) > MAX_SESSION_ID_BYTES
            or any(char not in _SESSION_ID_CHARS for char in session_id)
        ):
            raise HTTPTransportError(400, -32600, "Invalid MCP session identifier", reason="invalid_session_id")


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _build_schema_diagnostics(
    runtime_factory: Callable[[], WrapperRuntime],
    *,
    revision: str | None = None,
) -> dict[str, Any]:
    """Capture wrapper-owned schema facts without probing the production tunnel."""

    runtime: WrapperRuntime | None = None
    try:
        runtime = runtime_factory()
        definitions_payload = runtime.list_tools()
        listed_payload = runtime.list_tools()
        definitions = definitions_payload.get("tools", []) if isinstance(definitions_payload, dict) else []
        listed = listed_payload.get("tools", []) if isinstance(listed_payload, dict) else []
        if not isinstance(definitions, list) or not isinstance(listed, list):
            raise TypeError("wrapper tool registry did not return lists")
        active_revision = revision
        if active_revision is None:
            revision_getter = getattr(runtime, "_active_tool_schema_revision", None)
            active_revision = revision_getter() if callable(revision_getter) else TOOL_SCHEMA_REVISION
        if not isinstance(active_revision, str) or not active_revision:
            raise ValueError("wrapper tool schema revision is unavailable")
        metadata = tool_schema_metadata(definitions, revision=active_revision)
        consistency = schema_consistency(definitions, listed, revision=active_revision)
        _config_path, entries, roots, errors = load_registry()
        registry = registry_health(
            config_present=_config_path.is_file(),
            root_descriptors=[{"id": root.id, "mode": root.mode, "path": str(root.path)} for root in roots],
            workspace_descriptors=[
                {"id": entry.identifier, "profile": entry.profile, "path": str(entry.path), "commands": sorted(entry.commands)}
                for entry in entries.values()
            ],
            error_codes=[str(error.get("code", "CONFIG_INVALID")) for error in errors if isinstance(error, dict)],
        )
        registry_status = registry.get("status")
        status = (
            "consistent"
            if consistency["status"] == "consistent" and metadata["revision"] == active_revision
            else "inconsistent"
        )
        return {
            "status": status,
            "tool_schema": metadata,
            "schema_consistency": consistency,
            "registry_status": registry_status,
        }
    except Exception:  # noqa: BLE001 - health must fail closed without leaking internals
        return {
            "status": "unavailable",
            "tool_schema": {"revision": None, "count": 0, "hash": None},
            "schema_consistency": {"status": "unavailable"},
            "registry_status": "unavailable",
        }
    finally:
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass


def _current_registry_status() -> tuple[str, dict[str, Any]]:
    """Read the local registry for each health check and fail closed on errors."""

    try:
        config_path, entries, roots, errors = load_registry()
        registry = registry_health(
            config_present=config_path.is_file(),
            root_descriptors=[{"id": root.id, "mode": root.mode, "path": str(root.path)} for root in roots],
            workspace_descriptors=[
                {"id": entry.identifier, "profile": entry.profile, "path": str(entry.path), "commands": sorted(entry.commands)}
                for entry in entries.values()
            ],
            error_codes=[str(error.get("code", "CONFIG_INVALID")) for error in errors if isinstance(error, dict)],
        )
        return str(registry.get("status", "unavailable")), registry
    except Exception:  # noqa: BLE001 - health must fail closed without leaking internals
        return "unavailable", {"status": "unavailable"}


class WrapperMCPHTTPServer(ThreadingHTTPServer):
    """Threaded loopback HTTP server that owns wrapper session runtimes."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        runtime_factory: Callable[[], WrapperRuntime] = _default_http_runtime_factory,
        max_sessions: int = DEFAULT_MAX_HTTP_SESSIONS,
        session_ttl_seconds: float = DEFAULT_HTTP_SESSION_TTL_SECONDS,
        max_retired_session_ids: int = DEFAULT_MAX_RETIRED_SESSION_IDS,
        max_session_creations: int = DEFAULT_MAX_SESSION_CREATIONS,
        session_creation_window_seconds: float = DEFAULT_SESSION_CREATION_WINDOW_SECONDS,
        request_timeout_seconds: float = DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS,
        max_inflight: int = DEFAULT_MAX_HTTP_INFLIGHT,
        handler_class: type[BaseHTTPRequestHandler] | None = None,
    ) -> None:
        host = str(server_address[0])
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("HTTP transport must bind to a loopback IP address") from exc
        if not address.is_loopback:
            raise ValueError("HTTP transport must bind to a loopback IP address")
        if request_timeout_seconds <= 0 or request_timeout_seconds > 300:
            raise ValueError("request_timeout_seconds must be between 0 and 300")
        if not isinstance(max_inflight, int) or isinstance(max_inflight, bool) or not 1 <= max_inflight <= 1024:
            raise ValueError("max_inflight must be between 1 and 1024")
        self.runtime_factory = runtime_factory
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.max_inflight = max_inflight
        self._inflight = threading.BoundedSemaphore(max_inflight)
        self.schema_diagnostics = _build_schema_diagnostics(runtime_factory)
        schema_metadata = dict(self.schema_diagnostics.get("tool_schema") or {})
        v26_runtime_factory = lambda: V26RuntimeAdapter(runtime_factory())
        self.v26_schema_diagnostics = _build_schema_diagnostics(
            v26_runtime_factory,
            revision=V26_SURFACE_REVISION,
        )
        v26_schema_metadata = dict(self.v26_schema_diagnostics.get("tool_schema") or {})
        self.connection_observability = ConnectionObservabilityStore(
            server_instance_id=f"http-{secrets.token_urlsafe(12)}",
        )
        self.sessions = WrapperHTTPSessionManager(
            runtime_factory,
            max_sessions=max_sessions,
            session_ttl_seconds=session_ttl_seconds,
            max_retired_session_ids=max_retired_session_ids,
            max_session_creations=max_session_creations,
            session_creation_window_seconds=session_creation_window_seconds,
            observability_store=self.connection_observability,
            transport_generation="http-v25-stable",
            schema_metadata=schema_metadata,
        )
        self.canary_sessions = WrapperHTTPSessionManager(
            runtime_factory,
            max_sessions=max_sessions,
            session_ttl_seconds=session_ttl_seconds,
            max_retired_session_ids=max_retired_session_ids,
            max_session_creations=max_session_creations,
            session_creation_window_seconds=session_creation_window_seconds,
            session_id_namespace="v25c_",
            observability_store=self.connection_observability,
            transport_generation="http-v25-canary",
            schema_metadata=schema_metadata,
        )
        self.v26_canary_sessions = WrapperHTTPSessionManager(
            v26_runtime_factory,
            max_sessions=max_sessions,
            session_ttl_seconds=session_ttl_seconds,
            max_retired_session_ids=max_retired_session_ids,
            max_session_creations=max_session_creations,
            session_creation_window_seconds=session_creation_window_seconds,
            session_id_namespace="v26c_",
            observability_store=self.connection_observability,
            transport_generation="http-v26-canary",
            schema_metadata=v26_schema_metadata,
        )
        self._endpoint_sessions = {
            MCP_ENDPOINT: self.sessions,
            CANARY_MCP_ENDPOINT: self.canary_sessions,
            V26_CANARY_MCP_ENDPOINT: self.v26_canary_sessions,
        }
        super().__init__(server_address, handler_class or WrapperMCPHandler)

    def session_manager_for(self, path: str) -> WrapperHTTPSessionManager:
        manager = self._endpoint_sessions.get(path)
        if manager is None:
            raise HTTPTransportError(404, -32001, "Unknown MCP endpoint", reason="unknown_mcp_endpoint")
        return manager

    def health_payload(self, *, ready: bool) -> tuple[int, dict[str, Any]]:
        diagnostics = self.schema_diagnostics
        schema = diagnostics["tool_schema"]
        managers = tuple(self._endpoint_sessions.values())
        manager_ready = all(not manager.closed for manager in managers)
        registry_status, registry = _current_registry_status()
        schema_ready = diagnostics["status"] == "consistent" and registry_status == "valid"
        if ready:
            status = "ready" if manager_ready and schema_ready else "not_ready"
            http_status = 200 if status == "ready" else 503
        else:
            status = "healthy" if manager_ready and schema_ready else "unhealthy"
            http_status = 200
        payload = {
            "status": status,
            "transport": "http",
            "active_sessions": sum(manager.active_count for manager in managers),
            "health_schema_revision": HEALTH_SCHEMA_REVISION,
            "schema_revision": schema.get("revision"),
            "schema_count": schema.get("count"),
            "schema_hash": schema.get("hash"),
            "schema_consistency": diagnostics.get("schema_consistency", {}).get("status"),
            "registry_status": registry_status,
            "runtime_status": "alive" if manager_ready else "closed",
        }
        if not manager_ready:
            payload["reason"] = "session_manager_closed"
        elif not schema_ready:
            payload["reason"] = "registry_invalid" if registry_status != "valid" else "schema_unavailable"
        return http_status, payload

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address

    def process_request(self, request, client_address):
        if not self._inflight.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 60\r\n"
                    b"Connection: close\r\n\r\n"
                    b'{"error":{"code":-32000,"data":{"reason":"inflight_limit"}}}'
                )
            finally:
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._inflight.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._inflight.release()

    def server_close(self) -> None:
        for manager in self._endpoint_sessions.values():
            manager.close()
        super().server_close()


class WrapperMCPHandler(BaseHTTPRequestHandler):
    """Minimal Streamable HTTP framing around the shared MCP dispatcher."""

    server: WrapperMCPHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "chatgpt-dev-mcp-http/0.1"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        # Do not emit request paths, headers, or tool arguments to stderr.
        return None

    def _path(self) -> str:
        return urlsplit(self.path).path

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any] | None,
        *,
        session_id: str | None = None,
    ) -> None:
        body = _json_bytes(payload) if payload is not None else b""
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, MCP-Protocol-Version")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")
        if session_id is not None:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_error(self, error: HTTPTransportError, request_id: str | int | None = None) -> None:
        self._send_json(error.status, error.response(request_id))

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        if self._path() not in MCP_ENDPOINTS:
            self._send_json(404, None)
            return
        self.send_response(204)
        self.send_header("Allow", "OPTIONS, GET, POST, DELETE")
        self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, MCP-Protocol-Version")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self._path() == HEALTH_ENDPOINT:
            status, payload = self.server.health_payload(ready=False)
            self._send_json(status, payload)
            return
        if self._path() == READY_ENDPOINT:
            status, payload = self.server.health_payload(ready=True)
            self._send_json(status, payload)
            return
        if self._path() in MCP_ENDPOINTS:
            self._send_json(405, {"error": f"SSE GET stream is not supported; use POST {self._path()}."})
            return
        self._send_json(404, None)

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._path()
        if path not in MCP_ENDPOINTS:
            self._send_json(404, None)
            return
        manager = self.server.session_manager_for(path)
        session_id = self.headers.get("Mcp-Session-Id")
        if not session_id:
            self._send_error(HTTPTransportError(400, -32600, "Mcp-Session-Id is required", reason="session_id_required"))
            return
        try:
            deleted = manager.delete(session_id)
        except HTTPTransportError as exc:
            self._send_error(exc)
            return
        if not deleted:
            reason = manager.retired_reason(session_id)
            self._send_error(HTTPTransportError(404, -32001, "Unknown MCP session", reason=reason))
            return
        self._send_json(204, None)

    def _read_request(self) -> dict[str, Any]:
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise HTTPTransportError(415, -32600, "Content-Type must be application/json", reason="content_type")
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            raise HTTPTransportError(411, -32600, "Content-Length is required", reason="content_length_required")
        if length > MAX_HTTP_BODY_BYTES:
            raise HTTPTransportError(413, -32600, "Request body exceeds the bounded HTTP limit", reason="body_too_large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise HTTPTransportError(400, -32700, "Incomplete JSON request body", reason="incomplete_body")
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPTransportError(400, -32700, "Parse error", reason="invalid_json") from None
        if not isinstance(request, dict):
            raise HTTPTransportError(400, -32600, "Batch requests are not supported", reason="batch_not_supported")
        return request

    def _validate_protocol_header(self, runtime: WrapperRuntime) -> None:
        header = self.headers.get("MCP-Protocol-Version")
        if header is not None and header != runtime.protocol_version:
            raise HTTPTransportError(400, -32602, "MCP-Protocol-Version does not match the initialized session", reason="protocol_version_mismatch")

    @staticmethod
    def _begin_protocol_request(record: HTTPSessionRecord, request: dict[str, Any]) -> RequestRecord | None:
        if request.get("method") == "tools/call":
            # WrapperRuntime.call_tool owns tool-side effect classification and
            # process-session attachment.
            return None
        request_id = response_id(request)
        if request_id is None:
            return None
        try:
            item = record.request_registry.accept(request_id, str(request.get("method", "")))
            record.request_registry.start(request_id, generation=item.key.transport_generation)
            return item
        except RequestConflict:
            # Protocol duplicate-id errors are rendered by dispatch_rpc; the
            # diagnostic registry must not turn them into a session-wide fault.
            return None

    @staticmethod
    def _finish_protocol_request(record: HTTPSessionRecord, tracked: RequestRecord | None, response: dict[str, Any] | None) -> None:
        if tracked is None:
            return
        try:
            if isinstance(response, dict) and "error" in response:
                record.request_registry.fail(
                    tracked.key.request_id,
                    generation=tracked.key.transport_generation,
                    reason="protocol_error",
                )
            else:
                record.request_registry.complete(
                    tracked.key.request_id,
                    generation=tracked.key.transport_generation,
                )
        except (KeyError, RuntimeError, TypeError, ValueError):
            return

    @staticmethod
    def _upstream_transport_error(
        record: HTTPSessionRecord,
        request: dict[str, Any],
        exc: Exception,
        *,
        tracked: RequestRecord | None = None,
    ) -> HTTPTransportError:
        request_id = response_id(request)
        if tracked is None and request_id is not None:
            try:
                tracked = record.request_registry.get(request_id)
            except (KeyError, ValueError):
                tracked = None
        side_effect_started = bool(tracked.side_effect_started) if tracked is not None else False
        side_effect_class = tracked.side_effect_class if tracked is not None else _tool_side_effect_class(request)
        outcome = "outcome_unknown" if side_effect_started else "not_started"
        retryable = side_effect_class is SideEffectClass.READ_ONLY and not side_effect_started and request.get("method") != "tools/call"
        details = {
            "error_code": "UPSTREAM_TRANSPORT_UNAVAILABLE",
            "retryable": retryable,
            "request_state": tracked.state.value if tracked is not None else "DISCONNECTED",
            "side_effect_started": side_effect_started,
            "outcome": outcome,
            "recovery_action": "safe_retry_once" if retryable else ("read_back_required" if side_effect_started else "reconnect_required"),
        }
        return HTTPTransportError(
            502,
            -32050,
            "Upstream MCP runtime is unavailable",
            reason="upstream_transport_unavailable",
            details=details,
        )

    def _dispatch_with_recovery(
        self,
        record: HTTPSessionRecord,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        tracked = self._begin_protocol_request(record, request)
        retry_count = 0
        while True:
            try:
                request_id = response_id(request)
                with request_id_scope(request_id):
                    response = dispatch_rpc(record.runtime, request)
            except (ConnectionError, BrokenPipeError, EOFError, TimeoutError, OSError) as exc:
                if (
                    retry_count == 0
                    and request.get("method") in {"ping", "tools/list", "server/discover"}
                    and tracked is not None
                ):
                    retry_count += 1
                    record.request_registry.mark_retry(
                        tracked.key.request_id,
                        generation=tracked.key.transport_generation,
                    )
                    continue
                if tracked is not None:
                    try:
                        record.request_registry.fail(
                            tracked.key.request_id,
                            generation=tracked.key.transport_generation,
                            reason="upstream_transport_unavailable",
                        )
                    except (KeyError, RuntimeError, TypeError, ValueError):
                        pass
                raise self._upstream_transport_error(record, request, exc, tracked=tracked) from None
            self._finish_protocol_request(record, tracked, response)
            return response

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._path()
        if path not in MCP_ENDPOINTS:
            self._send_json(404, None)
            return
        manager = self.server.session_manager_for(path)
        try:
            request = self._read_request()
        except HTTPTransportError as exc:
            self._send_error(exc)
            return

        method = request.get("method")
        request_id = response_id(request) if isinstance(request, dict) else None
        if method == "initialize":
            if self.headers.get("Mcp-Session-Id") is not None:
                self._send_error(HTTPTransportError(400, -32600, "initialize must not include Mcp-Session-Id", reason="session_header_on_initialize"), request_id)
                return
            try:
                record = manager.create()
            except HTTPTransportError as exc:
                self._send_error(exc, request_id)
                return
            tracked_initialize: RequestRecord | None = None
            try:
                if request_id is not None:
                    try:
                        tracked_initialize = record.request_registry.accept(request_id, "initialize")
                        record.request_registry.start(
                            request_id,
                            generation=tracked_initialize.key.transport_generation,
                        )
                    except RequestConflict:
                        tracked_initialize = None
                response = dispatch_rpc(record.runtime, request)
                if response is None or not record.runtime.initialized or (isinstance(response, dict) and "error" in response):
                    self._finish_protocol_request(record, tracked_initialize, response)
                    manager.release(record)
                    manager.delete(record.session_id, reason="initialization_failed")
                    if response is None:
                        response = jsonrpc_error(request_id, -32600, "initialize must be a JSON-RPC request with a non-null id")
                    self._send_json(400, response)
                    return
                self._finish_protocol_request(record, tracked_initialize, response)
                self.server.connection_observability.record_initialize(record.session_id)
            except Exception as exc:  # noqa: BLE001 - transport must remain alive
                try:
                    if tracked_initialize is not None:
                        record.request_registry.fail(
                            tracked_initialize.key.request_id,
                            generation=tracked_initialize.key.transport_generation,
                            reason="initialization_failed",
                        )
                except (KeyError, RuntimeError, TypeError, ValueError):
                    pass
                manager.release(record)
                manager.delete(record.session_id, reason="initialization_failed")
                self._send_error(HTTPTransportError(500, -32603, str(exc), reason="initialization_failed"), request_id)
                return
            try:
                self._send_json(200, response, session_id=record.session_id)
            finally:
                try:
                    drain = getattr(record.runtime, "run_deferred_actions", None)
                    if callable(drain):
                        drain()
                finally:
                    manager.release(record)
            return

        session_id = self.headers.get("Mcp-Session-Id")
        if session_id is None:
            self._send_error(HTTPTransportError(400, -32600, "Mcp-Session-Id is required", reason="session_id_required"), request_id)
            return
        record: HTTPSessionRecord | None = None
        try:
            record = manager.claim(session_id)
            with record.lock:
                self._validate_protocol_header(record.runtime)
                validate_rpc_envelope(request)
                response = self._dispatch_with_recovery(record, request)
                if method == "tools/list":
                    schema = manager.schema_metadata
                    self.server.connection_observability.record_tools_list(
                        session_id,
                        registry_revision=str(schema.get("revision") or ""),
                        schema_hash=str(schema.get("hash") or ""),
                        tool_count=schema.get("count") if isinstance(schema.get("count"), int) else None,
                    )
                elif method == "tools/call":
                    self.server.connection_observability.record_tool_call(session_id)
        except HTTPTransportError as exc:
            if record is not None:
                manager.release(record)
            self._send_error(exc, request_id)
            return
        except JsonRpcError as exc:
            response = jsonrpc_error(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001 - transport must remain alive
            response = jsonrpc_error(request_id, -32603, str(exc))

        try:
            if response is None:
                self._send_json(202, None, session_id=session_id)
            else:
                self._send_json(200 if "error" not in response else 400, response, session_id=session_id)
        finally:
            assert record is not None
            try:
                drain = getattr(record.runtime, "run_deferred_actions", None)
                if callable(drain):
                    drain()
            finally:
                manager.release(record)


def serve_http(
    runtime_factory: Callable[[], WrapperRuntime] = _default_http_runtime_factory,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    max_sessions: int = DEFAULT_MAX_HTTP_SESSIONS,
    session_ttl_seconds: float = DEFAULT_HTTP_SESSION_TTL_SECONDS,
    max_retired_session_ids: int = DEFAULT_MAX_RETIRED_SESSION_IDS,
    max_session_creations: int = DEFAULT_MAX_SESSION_CREATIONS,
    session_creation_window_seconds: float = DEFAULT_SESSION_CREATION_WINDOW_SECONDS,
    request_timeout_seconds: float = DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS,
    max_inflight: int = DEFAULT_MAX_HTTP_INFLIGHT,
) -> int:
    """Run the disposable wrapper transport until interrupted."""

    server = WrapperMCPHTTPServer(
        (host, port),
        runtime_factory=runtime_factory,
        max_sessions=max_sessions,
        session_ttl_seconds=session_ttl_seconds,
        max_retired_session_ids=max_retired_session_ids,
        max_session_creations=max_session_creations,
        session_creation_window_seconds=session_creation_window_seconds,
        request_timeout_seconds=request_timeout_seconds,
        max_inflight=max_inflight,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


__all__ = [
    "CANARY_MCP_ENDPOINT",
    "DEFAULT_HTTP_SESSION_TTL_SECONDS",
    "DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS",
    "DEFAULT_MAX_HTTP_INFLIGHT",
    "DEFAULT_MAX_HTTP_SESSIONS",
    "DEFAULT_MAX_RETIRED_SESSION_IDS",
    "DEFAULT_MAX_SESSION_CREATIONS",
    "DEFAULT_SESSION_CREATION_WINDOW_SECONDS",
    "HEALTH_ENDPOINT",
    "MCP_ENDPOINT",
    "MCP_ENDPOINTS",
    "MAX_HTTP_BODY_BYTES",
    "READY_ENDPOINT",
    "V26_CANARY_MCP_ENDPOINT",
    "WrapperHTTPSessionManager",
    "WrapperMCPHandler",
    "WrapperMCPHTTPServer",
    "serve_http",
]
