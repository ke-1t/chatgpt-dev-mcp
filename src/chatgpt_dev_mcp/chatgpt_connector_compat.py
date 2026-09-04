"""Connection-scoped compatibility for a long-lived Secure MCP STDIO broker.

The Tunnel may keep one physical MCP child alive while the Connector opens
several logical MCP connections.  The physical child therefore owns one
process-scoped wrapper runtime, while every logical connection gets a fresh
protocol state and request registry.  Only the Connector's bounded
pre-operation duplicate initialize is replayed within one connection.

This boundary is deliberate: command preflights, read-only roots, managed
development runtimes, process-session routing, Director state, leases, and
receipts must survive a Connector reconnect.  Handshake state must not.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TextIO

from coding_tools_mcp.errors import JsonRpcError
from coding_tools_mcp.protocol import (
    dispatch_rpc,
    invalid_request_response,
    jsonrpc_error,
    response_id,
    rpc_params,
    validate_initialize_params,
    validate_initialize_request,
    validate_rpc_envelope,
)
from coding_tools_mcp.transport_stdio import StdioRuntime

from .observability import tool_schema_metadata
from .request_lifecycle import RequestConflict, RequestRegistry, SideEffectClass

_PRE_OPERATION_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "notifications/cancelled",
        "ping",
        "server/discover",
    }
)


class ProtocolState(str, Enum):
    """Lifecycle of one logical MCP protocol connection."""

    NEW = "NEW"
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


def _normalized_initialize_params(request: dict[str, Any]) -> str:
    """Return a stable, JSON-safe representation of valid init parameters."""

    validate_rpc_envelope(request)
    validate_initialize_request(request)
    params = dict(rpc_params(request))
    params["protocolVersion"] = validate_initialize_params(params)
    return json.dumps(params, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _validation_error_response(request: dict[str, Any], error: JsonRpcError) -> dict[str, Any]:
    return jsonrpc_error(response_id(request), error.code, error.message, error.data)


def _silence_broken_stdout(sink: TextIO) -> None:
    """Prevent the interpreter's final stdout flush from reviving a dead pipe."""

    if sink is not sys.stdout:
        return
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except OSError:
        return
    try:
        sink.close()
    except (OSError, ValueError):
        pass


@dataclass
class InitializeReplayState:
    """State for one logical protocol connection.

    This object is never reused after a logical connection is retired.  The
    broker creates a new protocol state/request registry while retaining the
    physical child's ``WrapperRuntime``.  The replay cache here is therefore
    deliberately limited to the one pre-operation duplicate allowed by the
    connector compatibility contract.
    """

    cached_result: dict[str, Any] | None = None
    normalized_params: str | None = None
    replay_count: int = 0
    operation_started: bool = False
    state: ProtocolState = ProtocolState.NEW
    transport_generation: int = 1
    protocol_session_generation: int = 0
    connection_marker: str | None = None
    last_request_id: str | int | None = None
    last_request_method: str | None = None
    request_registry: RequestRegistry = field(default_factory=RequestRegistry)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def publish(self, runtime: StdioRuntime) -> None:
        """Expose non-secret lifecycle diagnostics to the wrapper health path."""

        setattr(runtime, "protocol_state", self.state.value)
        setattr(runtime, "transport_generation", self.transport_generation)
        setattr(runtime, "protocol_session_generation", self.protocol_session_generation)
        # WrapperRuntime consumes the same registry for tools/call requests;
        # protocol requests are tracked here so both transports share one
        # child/generation identity without double-registering a tool call.
        sink = getattr(runtime, "_persist_request_lifecycle_event", None)
        if callable(sink):
            self.request_registry.set_event_sink(sink)
        setattr(runtime, "request_registry", self.request_registry)
        snapshot = self.request_registry.snapshot()
        setattr(runtime, "child_instance_id", snapshot["child_instance_id"])
        setattr(runtime, "last_reconciliation_at", snapshot["last_reconciliation_at"])

    @staticmethod
    def _connection_marker(request: dict[str, Any]) -> str | None:
        params = request.get("params")
        if not isinstance(params, dict):
            return None
        metadata = params.get("_meta")
        if not isinstance(metadata, dict):
            return None
        containers: list[dict[str, Any]] = [metadata]
        for key in ("chatgpt-dev-mcp", "chatgpt_dev_mcp", "mcp", "connection"):
            nested = metadata.get(key)
            if isinstance(nested, dict):
                containers.append(nested)
        for container in containers:
            for key in (
                "connection_id",
                "connectionId",
                "session_id",
                "sessionId",
                "mcp_session_id",
                "mcpSessionId",
            ):
                value = container.get(key)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    text = str(value).strip()
                    if text:
                        return text[:256]
        return None

    def _record_request_locked(self, request: dict[str, Any]) -> None:
        # Notifications have no request id and must not hide the last
        # request that can identify a transport boundary.
        if request.get("id") is None:
            return
        self.last_request_id = request.get("id")
        method = request.get("method")
        self.last_request_method = method if isinstance(method, str) else None

    def boundary_for(self, request: dict[str, Any]) -> str | None:
        """Validate a request marker against this connection only.

        A marker change is interpreted by :class:`ConnectionRuntimeManager`,
        which owns runtime replacement.  This state object never resets or
        mutates protocol generation in place.
        """

        method = request.get("method")
        marker = self._connection_marker(request)
        with self._lock:
            if self.connection_marker is not None and marker is not None and marker != self.connection_marker:
                if method == "initialize":
                    return "connection_marker_changed"
                return "stale"
        return None

    def stale_response(self, request: dict[str, Any]) -> dict[str, Any]:
        return jsonrpc_error(
            response_id(request),
            -32001,
            "Stale protocol connection",
            {
                "reason": "stale_transport_generation",
                "transport_generation": self.transport_generation,
            },
        )

    def initialization_in_progress_response(self, request: dict[str, Any]) -> dict[str, Any]:
        return jsonrpc_error(
            response_id(request),
            -32600,
            "Server initialization is already in progress",
            {"reason": "initialization_in_progress"},
        )

    def close(self, runtime: StdioRuntime, *, final: bool = False) -> None:
        with self._lock:
            self.state = ProtocolState.CLOSING
            self.publish(runtime)
        try:
            logical_close = getattr(runtime, "close_for_logical_connection", None)
            if not final and callable(logical_close):
                logical_close()
            else:
                runtime.close()
        finally:
            with self._lock:
                self.state = ProtocolState.CLOSED
                self.publish(runtime)

    public_tool_schema_fingerprint: str | None = None
    client_initialized: bool = False
    _pending_notifications: list[dict[str, Any]] = field(default_factory=list)

    def current_public_tool_schema_fingerprint(self, runtime: StdioRuntime) -> str:
        definitions = runtime.list_tools().get("tools", [])
        return str(tool_schema_metadata(definitions)["hash"])

    def mark_client_initialized(self, runtime: StdioRuntime) -> None:
        with self._lock:
            self.client_initialized = True
        self.observe_public_tool_schema(runtime, notify=False)

    def observe_public_tool_schema(
        self,
        runtime: StdioRuntime,
        *,
        notify: bool = True,
    ) -> bool:
        fingerprint = self.current_public_tool_schema_fingerprint(runtime)
        with self._lock:
            previous = self.public_tool_schema_fingerprint
            self.public_tool_schema_fingerprint = fingerprint
            changed = previous is not None and previous != fingerprint
            if changed and notify and self.client_initialized:
                self._pending_notifications.append(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/tools/list_changed",
                        "params": {},
                    }
                )
            return changed

    def pop_pending_notifications(self) -> list[dict[str, Any]]:
        with self._lock:
            notifications = self._pending_notifications
            self._pending_notifications = []
            return notifications

    def replacement_block_reason(
        self,
        runtime: StdioRuntime | None = None,
        *,
        include_runtime_processes: bool = True,
    ) -> str | None:
        """Return a fail-closed reason if this protocol state cannot retire.

        A logical-connection rotation reuses the same process runtime, so an
        owned background process is not itself a replacement blocker.  The
        runtime-level check remains available for callers that really destroy
        a runtime.
        """

        active = self.request_registry.active_records()
        for record in active:
            if record.side_effect_class is not SideEffectClass.READ_ONLY or record.side_effect_started:
                return "outcome_unknown"
        if active:
            # Even a read-only callback must finish against the same registry
            # that accepted it.  Replacing that registry in flight would make
            # completion accounting land in the next logical connection.
            return "request_in_progress"
        if include_runtime_processes:
            process_check = getattr(runtime, "connection_replacement_block_reason", None)
            if callable(process_check):
                reason = process_check()
                if reason:
                    return str(reason)
        return None

    def retire_protocol(self, runtime: StdioRuntime) -> None:
        """Retire only this connection's protocol state.

        The physical runtime is intentionally left open.  Publishing CLOSED
        before the replacement state is installed keeps diagnostics monotonic;
        the replacement immediately publishes its own fresh registry.
        """

        with self._lock:
            self.state = ProtocolState.CLOSING
            self.publish(runtime)
            self.state = ProtocolState.CLOSED
            self.publish(runtime)

    def record_first_initialize(self, request: dict[str, Any], response: dict[str, Any]) -> None:
        result = response.get("result")
        if not isinstance(result, dict):
            return
        try:
            normalized = _normalized_initialize_params(request)
        except JsonRpcError:
            return
        self.normalized_params = normalized
        self.cached_result = copy.deepcopy(result)

    def replay(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            normalized = _normalized_initialize_params(request)
        except JsonRpcError as error:
            return _validation_error_response(request, error)

        if self.cached_result is None or self.normalized_params is None:
            return jsonrpc_error(
                response_id(request),
                -32600,
                "Server is already initialized",
                {"reason": "initialization_cache_unavailable"},
            )
        if self.operation_started:
            return jsonrpc_error(
                response_id(request),
                -32600,
                "Server is already initialized",
                {"reason": "operation_already_started"},
            )
        if normalized != self.normalized_params:
            return jsonrpc_error(
                response_id(request),
                -32602,
                "Incompatible duplicate initialize",
                {"reason": "incompatible_initialize"},
            )
        # An exact-compatible duplicate before any normal operation is a pure
        # replay of the cached handshake result: it does not call initialize
        # again and does not grow per-request state.  A fixed numeric replay
        # ceiling therefore turns harmless Connector discovery bursts into a
        # transport failure.  The actual safety boundary is lifecycle-based:
        # incompatible params are rejected above, and once a normal operation
        # starts the next initialize rotates to a fresh logical protocol state.
        self.replay_count += 1
        return {"jsonrpc": "2.0", "id": response_id(request), "result": copy.deepcopy(self.cached_result)}


def dispatch_rpc_compat(
    runtime: StdioRuntime,
    request: dict[str, Any],
    state: InitializeReplayState,
) -> dict[str, Any] | None:
    """Dispatch one request with connection-scoped initialization handling."""

    method = request.get("method")
    state.publish(runtime)
    boundary = state.boundary_for(request)
    if boundary == "stale":
        return state.stale_response(request)

    marker = state._connection_marker(request)
    tracked_request_id: str | int | None = None
    tracked_request_generation: int | None = None
    # WrapperRuntime.call_tool owns tool-side effect classification and
    # process-session attachment. Generic runtimes used by the broker tests do
    # not, so the compatibility boundary tracks tools/call as ambiguous and
    # keeps runtime replacement fail-closed while it is in flight.
    owns_tool_lifecycle = callable(getattr(runtime, "_begin_request_lifecycle", None))
    candidate_id = request.get("id")
    if (
        isinstance(candidate_id, (str, int))
        and not isinstance(candidate_id, bool)
        and method != "initialize"
        and (method != "tools/call" or not owns_tool_lifecycle)
    ):
        side_effect_class = (
            SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
            if method == "tools/call"
            else SideEffectClass.READ_ONLY
        )
        try:
            tracked = state.request_registry.accept(
                candidate_id,
                str(method or ""),
                side_effect_class=side_effect_class,
            )
            state.request_registry.start(candidate_id, generation=tracked.key.transport_generation)
            tracked_request_id = candidate_id
            tracked_request_generation = tracked.key.transport_generation
        except RequestConflict:
            # JSON-RPC duplicate-id semantics are handled by the protocol
            # dispatcher. Do not let a diagnostic registry collision poison
            # the protocol session.
            tracked_request_id = None
    with state._lock:
        if state.connection_marker is None and marker is not None:
            state.connection_marker = marker
        if marker is not None and state.connection_marker is not None and marker != state.connection_marker:
            return state.stale_response(request)
        if method == "initialize":
            if state.state is ProtocolState.INITIALIZING:
                return state.initialization_in_progress_response(request)
            if runtime.initialized:
                response = state.replay(request)
                state._record_request_locked(request)
                return response
            state.state = ProtocolState.INITIALIZING
            if state.protocol_session_generation == 0:
                state.protocol_session_generation = 1
            state.publish(runtime)
        elif state.state is ProtocolState.INITIALIZING:
            return jsonrpc_error(
                response_id(request),
                -32002,
                "Server initialization is in progress",
                {"reason": "initialization_in_progress"},
            )
        elif runtime.initialized and method not in _PRE_OPERATION_METHODS:
            state.operation_started = True

    try:
        response = dispatch_rpc(runtime, request)
    except Exception:
        if tracked_request_id is not None:
            try:
                if method == "tools/call":
                    state.request_registry.disconnect(
                        tracked_request_id,
                        generation=tracked_request_generation,
                        reason="dispatch_exception",
                    )
                else:
                    state.request_registry.fail(
                        tracked_request_id,
                        generation=tracked_request_generation,
                        reason="dispatch_exception",
                    )
            except (KeyError, RuntimeError):
                pass
        with state._lock:
            if method == "initialize":
                state.state = ProtocolState.NEW
                state.publish(runtime)
        raise

    with state._lock:
        state._record_request_locked(request)
        if method == "initialize":
            if runtime.initialized and isinstance(response, dict) and "result" in response:
                state.state = ProtocolState.READY
                if state.connection_marker is None:
                    state.connection_marker = marker
                if state.cached_result is None:
                    state.record_first_initialize(request, response)
            else:
                state.state = ProtocolState.NEW
            state.publish(runtime)
    if method == "initialize" and runtime.initialized and isinstance(response, dict) and "result" in response:
        state.observe_public_tool_schema(runtime, notify=False)
    elif method == "notifications/initialized" and runtime.initialized:
        state.mark_client_initialized(runtime)
    elif runtime.initialized and state.client_initialized:
        state.observe_public_tool_schema(runtime)
    if tracked_request_id is not None:
        try:
            if isinstance(response, dict) and "error" in response:
                state.request_registry.fail(
                    tracked_request_id,
                    generation=tracked_request_generation,
                    reason="protocol_error",
                )
            else:
                state.request_registry.complete(
                    tracked_request_id,
                    generation=tracked_request_generation,
                )
        except (KeyError, RuntimeError):
            # A reconnect may retire the request between dispatch and response;
            # the generation guard intentionally rejects that delayed callback.
            pass
    return response


@dataclass
class LogicalStdioSession:
    """A runtime and protocol state owned by one logical MCP connection."""

    runtime: StdioRuntime
    state: InitializeReplayState
    logical_connection_id: str

    def pop_pending_notifications(self) -> list[dict[str, Any]]:
        return self.state.pop_pending_notifications()


@dataclass
class LogicalConnectionObservation:
    """Bounded metadata-only evidence for one logical STDIO connection."""

    logical_connection_id: str
    child_instance_id: str
    opened_at: float
    request_count: int = 0
    last_request_at: float | None = None
    last_completed_at: float | None = None
    last_request_method: str = ""
    closed_at: float | None = None
    close_reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "logical_connection_id": self.logical_connection_id,
            "child_instance_id": self.child_instance_id,
            "opened_at": self.opened_at,
            "request_count": self.request_count,
            "last_request_at": self.last_request_at,
            "last_completed_at": self.last_completed_at,
            "last_request_method": self.last_request_method,
            "closed_at": self.closed_at,
            "close_reason": self.close_reason,
        }


class ConnectionRuntimeManager:
    """Own fresh protocol sessions behind one long-lived process runtime.

    The wrapper runtime belongs to the physical child.  Logical connections
    replace only ``InitializeReplayState`` and its request registry; they do
    not replace command approvals, read-only roots, development runtimes, or
    other cross-call handoff state.
    """

    def __init__(
        self,
        runtime_factory: Callable[[], StdioRuntime],
        *,
        initial_runtime: StdioRuntime | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(runtime_factory):
            raise TypeError("runtime_factory must be callable")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._runtime_factory = runtime_factory
        self._initial_runtime = initial_runtime
        self._clock = clock
        self._current: LogicalStdioSession | None = None
        self._retired_markers: set[str] = set()
        self._connection_sequence = 0
        self._connection_history: list[LogicalConnectionObservation] = []
        self._lock = threading.RLock()

    @property
    def current_session(self) -> LogicalStdioSession | None:
        with self._lock:
            return self._current

    @staticmethod
    def _marker(request: dict[str, Any]) -> str | None:
        return InitializeReplayState._connection_marker(request)

    def _publish_connection_history_locked(self, runtime: StdioRuntime) -> None:
        setattr(runtime, "logical_connection_history", [item.as_dict() for item in self._connection_history])

    def _observation_locked(self, logical_connection_id: str) -> LogicalConnectionObservation | None:
        for observation in reversed(self._connection_history):
            if observation.logical_connection_id == logical_connection_id:
                return observation
        return None

    def _record_request_locked(self, session: LogicalStdioSession, request: dict[str, Any]) -> None:
        observation = self._observation_locked(session.logical_connection_id)
        if observation is None:
            return
        observation.request_count += 1
        observation.last_request_at = float(self._clock())
        method = request.get("method")
        observation.last_request_method = str(method)[:80] if isinstance(method, str) else ""
        self._publish_connection_history_locked(session.runtime)

    def _record_completed_locked(self, session: LogicalStdioSession) -> None:
        observation = self._observation_locked(session.logical_connection_id)
        if observation is None:
            return
        observation.last_completed_at = float(self._clock())
        self._publish_connection_history_locked(session.runtime)

    def _record_closed_locked(self, session: LogicalStdioSession, *, reason: str) -> None:
        observation = self._observation_locked(session.logical_connection_id)
        if observation is None:
            return
        if observation.closed_at is None:
            observation.closed_at = float(self._clock())
        observation.close_reason = str(reason or "unknown")[:160]
        self._publish_connection_history_locked(session.runtime)

    def _new_session_locked(
        self,
        marker: str | None,
        *,
        runtime: StdioRuntime | None = None,
    ) -> LogicalStdioSession:
        if runtime is None:
            if self._initial_runtime is not None:
                runtime = self._initial_runtime
                self._initial_runtime = None
            else:
                runtime = self._runtime_factory()
        self._connection_sequence += 1
        # Request ownership is protocol-session local, so the registry itself
        # remains fresh on reconnect. The child identity, however, identifies
        # the physical WrapperRuntime/process and must survive a logical
        # Connector reconnect.
        existing_child_id = getattr(runtime, "child_instance_id", None)
        child_instance_id = existing_child_id if isinstance(existing_child_id, str) and existing_child_id else None
        state = InitializeReplayState(
            connection_marker=marker,
            request_registry=RequestRegistry(child_instance_id=child_instance_id),
        )
        logical_connection_id = f"stdio-connection:{self._connection_sequence}"
        setattr(runtime, "logical_connection_id", logical_connection_id)
        setattr(runtime, "protocol_runtime_identity", logical_connection_id)
        setattr(runtime, "protocol_state", state.state.value)
        state.publish(runtime)
        self._current = LogicalStdioSession(runtime, state, logical_connection_id)
        self._connection_history.append(
            LogicalConnectionObservation(
                logical_connection_id=logical_connection_id,
                child_instance_id=str(getattr(runtime, "child_instance_id", ""))[:160],
                opened_at=float(self._clock()),
            )
        )
        del self._connection_history[:-64]
        self._publish_connection_history_locked(runtime)
        return self._current

    @staticmethod
    def _replacement_error(request: dict[str, Any], reason: str, state: InitializeReplayState) -> dict[str, Any]:
        if reason == "outcome_unknown":
            return jsonrpc_error(
                response_id(request),
                -32050,
                "Logical connection replacement is blocked by an active request",
                {
                    "reason": "outcome_unknown",
                    "outcome": "outcome_unknown",
                    "recovery_action": "read_back_required",
                    "transport_generation": state.transport_generation,
                },
            )
        if reason == "request_in_progress":
            return jsonrpc_error(
                response_id(request),
                -32050,
                "Logical connection replacement is blocked by an active read-only request",
                {
                    "reason": "request_in_progress",
                    "recovery_action": "retry_after_completion",
                    "transport_generation": state.transport_generation,
                },
            )
        return jsonrpc_error(
            response_id(request),
            -32050,
            "A fresh protocol runtime could not be created",
            {"reason": reason, "recovery_action": "reconnect_required"},
        )

    def _rotate_locked(
        self,
        request: dict[str, Any],
        marker: str | None,
        *,
        reason: str,
    ) -> LogicalStdioSession | dict[str, Any]:
        current = self._current
        if current is None:
            return self._new_session_locked(marker)
        # A logical rotation keeps the physical runtime and any owned process
        # sessions alive.  Only an actually in-flight request can make
        # swapping the protocol registry unsafe.
        block_reason = current.state.replacement_block_reason(
            current.runtime,
            include_runtime_processes=False,
        )
        if block_reason is not None:
            return self._replacement_error(request, block_reason, current.state)

        old_marker = current.state.connection_marker
        if old_marker is not None and old_marker != marker:
            self._retired_markers.add(old_marker)
            if len(self._retired_markers) > 32:
                self._retired_markers = set(sorted(self._retired_markers)[-32:])
        if marker is not None:
            self._retired_markers.discard(marker)

        # Retire only protocol-local state.  Cross-call handoff state belongs
        # to the physical child and must survive this boundary.
        runtime = current.runtime
        self._record_closed_locked(current, reason=reason)
        try:
            current.state.retire_protocol(runtime)
            reset = getattr(runtime, "reset_protocol_session", None)
            if callable(reset):
                reset()
            else:
                setattr(runtime, "initialized", False)
        except Exception:  # noqa: BLE001 - a failed reset cannot justify reuse
            self._current = None
            return self._replacement_error(request, "protocol_reset_failed", current.state)
        self._current = None
        try:
            return self._new_session_locked(marker, runtime=runtime)
        except Exception:  # noqa: BLE001 - fail closed at the boundary
            return self._replacement_error(request, "protocol_state_factory_failed", current.state)

    def _prepare_locked(self, request: dict[str, Any]) -> LogicalStdioSession | dict[str, Any]:
        marker = self._marker(request)
        method = request.get("method")
        current = self._current or self._new_session_locked(marker)
        current_marker = current.state.connection_marker

        if marker is not None and marker in self._retired_markers:
            return current.state.stale_response(request)
        if current_marker is not None and marker is not None and marker != current_marker:
            if method not in {"initialize", "server/discover"}:
                return current.state.stale_response(request)
            return self._rotate_locked(request, marker, reason="connection_marker_changed")

        # ``server/discover`` is the Connector's explicit discovery boundary.
        # When it arrives after an initialized connection, begin a new logical
        # protocol session even if the optional connection marker is absent.
        # This prevents duplicate-initialize replay counters from leaking into
        # the next Connector handshake.
        if method == "server/discover" and current.state.state is ProtocolState.READY:
            return self._rotate_locked(request, marker, reason="server_discover")

        # Without a trustworthy marker, an initialize after a normal operation
        # is the only production fallback available on a raw STDIO stream.
        # It always retires the old protocol state; request ids and handshake
        # params are deliberately ignored.
        if method == "initialize" and current.state.state is ProtocolState.READY and current.state.operation_started:
            return self._rotate_locked(request, marker, reason="post_operation_initialize")
        return current

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch one request, replacing runtimes only at safe boundaries."""

        with self._lock:
            selected = self._prepare_locked(request)
        if isinstance(selected, dict):
            return selected
        with self._lock:
            self._record_request_locked(selected, request)
        try:
            return dispatch_rpc_compat(selected.runtime, request, selected.state)
        finally:
            with self._lock:
                self._record_completed_locked(selected)

    def close(self, *, reason: str = "manager_shutdown") -> None:
        with self._lock:
            current = self._current
            self._current = None
            if current is not None:
                self._record_closed_locked(current, reason=reason)
                try:
                    current.state.close(current.runtime, final=True)
                except Exception:  # noqa: BLE001 - shutdown must not reopen state
                    return

    def pop_pending_notifications(self) -> list[dict[str, Any]]:
        with self._lock:
            current = self._current
        if current is None:
            return []
        return current.pop_pending_notifications()

    def run_after_response(self) -> None:
        """Run bounded actions only after the current response was flushed.

        A local Tunnel restart cannot be executed synchronously from the MCP
        child: ``launchctl kickstart -k`` is allowed to terminate that very
        child before its JSON-RPC response reaches the connector.  Runtime
        actions therefore queue a detached supervisor and this hook drains
        the queue only after the response bytes are on the STDIO sink.
        """

        with self._lock:
            current = self._current
        if current is None:
            return
        drain = getattr(current.runtime, "run_deferred_actions", None)
        if callable(drain):
            drain()


def serve_stdio_compat(
    runtime: StdioRuntime | None = None,
    *,
    runtime_factory: Callable[[], StdioRuntime] | None = None,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """Serve STDIO through a connection-isolated runtime broker.

    ``runtime=`` remains accepted for existing embedders.  ``runtime_factory``
    is used only to construct the physical child's runtime; logical connection
    rotation reuses that instance and replaces protocol state only.
    """

    if runtime is not None and runtime_factory is not None:
        raise ValueError("pass runtime or runtime_factory, not both")
    if runtime is None and runtime_factory is None:
        raise ValueError("runtime_factory is required when runtime is omitted")
    initial_runtime = runtime
    if runtime_factory is None:
        assert runtime is not None
        logical_factory = getattr(runtime, "new_logical_runtime", None)
        if callable(logical_factory):
            runtime_factory = logical_factory
        else:
            runtime_type = type(runtime)

            def runtime_factory() -> StdioRuntime:
                return runtime_type()

    source = input_stream or sys.stdin
    sink = output_stream or sys.stdout
    manager = ConnectionRuntimeManager(runtime_factory, initial_runtime=initial_runtime)
    try:
        for line in source:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                response = jsonrpc_error(None, -32700, "Parse error")
            else:
                try:
                    response = (
                        manager.dispatch(request)
                        if isinstance(request, dict)
                        else invalid_request_response()
                    )
                except Exception as exc:  # noqa: BLE001 - keep the stdio server alive
                    response = jsonrpc_error(None, -32603, str(exc))
            if response is not None:
                try:
                    sink.write(json.dumps(response, separators=(",", ":")) + "\n")
                    sink.flush()
                except (BrokenPipeError, OSError, ValueError):
                    # The connector may have closed a stale transport while a
                    # response was being written.  Drain any explicitly
                    # queued recovery action, silence the interpreter's final
                    # stdout flush, then retire this child without emitting
                    # another traceback into the Tunnel's pipe.
                    _silence_broken_stdout(sink)
                    manager.run_after_response()
                    break
                manager.run_after_response()
            for notification in manager.pop_pending_notifications():
                try:
                    sink.write(json.dumps(notification, separators=(",", ":")) + "\n")
                    sink.flush()
                except (BrokenPipeError, OSError, ValueError):
                    _silence_broken_stdout(sink)
                    break
    finally:
        manager.close()
    return 0
