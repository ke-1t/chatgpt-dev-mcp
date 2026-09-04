"""Bounded, generation-aware MCP request lifecycle state.

The wrapper deliberately keeps this registry in memory.  Director's SQLite
store remains the source of truth for sessions, leases, receipts, and task
state; this module only answers whether a transport request is still active
and whether it is safe to recover the transport boundary.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Mapping


class RequestState(str, Enum):
    NEW = "NEW"
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    COMPLETING = "COMPLETING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    DISCONNECTED = "DISCONNECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECOVERING = "RECOVERING"


class SideEffectClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOCAL_REVERSIBLE = "LOCAL_REVERSIBLE"
    LOCAL_WRITE = "LOCAL_WRITE"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    OUTCOME_AMBIGUOUS_CAPABLE = "OUTCOME_AMBIGUOUS_CAPABLE"


TERMINAL_STATES = frozenset(
    {
        RequestState.COMPLETED,
        RequestState.FAILED,
        RequestState.CANCELLED,
        RequestState.TIMED_OUT,
        RequestState.DISCONNECTED,
        RequestState.OUTCOME_UNKNOWN,
    }
)


class RequestLifecycleError(RuntimeError):
    """Base error for an invalid lifecycle transition."""


class RequestConflict(RequestLifecycleError):
    """A request id or operation slot is already owned by a live request."""

    def __init__(self, reason: str, record: "RequestRecord") -> None:
        super().__init__(reason)
        self.reason = reason
        self.record = record


@dataclass(frozen=True)
class RequestKey:
    child_instance_id: str
    transport_generation: int
    request_id: str | int


@dataclass
class RequestRecord:
    key: RequestKey
    tool_name: str
    side_effect_class: SideEffectClass
    started_at: float
    last_heartbeat: float
    state: RequestState = RequestState.NEW
    workspace_id: str | None = None
    working_tree_id: str | None = None
    development_session_id: str | None = None
    process_session_id: str | None = None
    operation_key: str | None = None
    side_effect_started: bool = False
    terminal_reason: str | None = None
    retry_count: int = 0
    terminal_at: float | None = None
    duration_ms: float | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def as_dict(self) -> dict[str, Any]:
        """Return bounded, non-secret diagnostics for health surfaces."""

        return {
            "request_id": self.key.request_id,
            "tool_name": self.tool_name,
            "transport_generation": self.key.transport_generation,
            "state": self.state.value,
            "side_effect_class": self.side_effect_class.value,
            "side_effect_started": self.side_effect_started,
            "process_session_id": self.process_session_id,
            "operation_key": self.operation_key,
            "terminal_reason": self.terminal_reason,
            "retry_count": self.retry_count,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "development_session_id": self.development_session_id,
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class RecoveryActivityEvidence:
    """Live request evidence used by fail-closed retained-session recovery."""

    integration_in_progress: bool
    external_execution_in_progress: bool


def recovery_activity_evidence(
    records: tuple[RequestRecord, ...],
    *,
    development_session_id: str,
    external_capability: Callable[[str], bool],
) -> RecoveryActivityEvidence:
    """Classify live activity relevant to one retained DEVELOPMENT session."""

    if not isinstance(development_session_id, str) or not development_session_id:
        raise ValueError("development_session_id must be non-empty text")
    if not callable(external_capability):
        raise TypeError("external_capability must be callable")

    integration_in_progress = False
    external_execution_in_progress = False
    for record in records:
        if not isinstance(record, RequestRecord) or record.terminal:
            continue
        if (
            record.tool_name == "workspace_integrate_development_session"
            and record.development_session_id == development_session_id
        ):
            integration_in_progress = True
        if record.tool_name == "git_push":
            external_execution_in_progress = True
            continue
        if record.tool_name != "capability_execute":
            continue
        capability_id = record.metadata.get("capability_id")
        if not isinstance(capability_id, str) or not capability_id:
            external_execution_in_progress = True
            continue
        try:
            if bool(external_capability(capability_id)):
                external_execution_in_progress = True
        except Exception:  # noqa: BLE001 - unknown capability state must fail closed
            external_execution_in_progress = True

    return RecoveryActivityEvidence(
        integration_in_progress=integration_in_progress,
        external_execution_in_progress=external_execution_in_progress,
    )


def _valid_request_id(request_id: object) -> bool:
    return isinstance(request_id, (str, int)) and not isinstance(request_id, bool)


def safe_retry_decision(
    side_effect_class: SideEffectClass,
    *,
    side_effect_started: bool,
    attempts: int,
) -> bool:
    """Whether one transport-only retry is safe.

    This intentionally does not inspect the error text. Callers must already
    have classified the failure as a pre-side-effect transport failure.
    """

    return (
        side_effect_class is SideEffectClass.READ_ONLY
        and not side_effect_started
        and isinstance(attempts, int)
        and not isinstance(attempts, bool)
        and attempts == 0
    )


class RequestRegistry:
    """Thread-safe bounded request registry for one child instance.

    The registry never performs a tool call and never mutates Director state.
    A process probe is supplied by the caller so this class cannot accidentally
    kill or replay an operation while reconciling stale metadata.
    """

    def __init__(
        self,
        *,
        child_instance_id: str | None = None,
        transport_generation: int = 1,
        clock: Callable[[], float] = time.monotonic,
        heartbeat_timeout_seconds: float = 60.0,
        terminal_ttl_seconds: float = 300.0,
        max_entries: int = 512,
        max_events: int = 128,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not isinstance(transport_generation, int) or isinstance(transport_generation, bool) or transport_generation < 1:
            raise ValueError("transport_generation must be a positive integer")
        if heartbeat_timeout_seconds <= 0 or terminal_ttl_seconds <= 0:
            raise ValueError("lifecycle TTLs must be positive")
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or not 1 <= max_entries <= 8192:
            raise ValueError("max_entries must be between 1 and 8192")
        if not isinstance(max_events, int) or isinstance(max_events, bool) or not 1 <= max_events <= 1024:
            raise ValueError("max_events must be between 1 and 1024")
        self.child_instance_id = child_instance_id or secrets.token_urlsafe(12)
        if not isinstance(self.child_instance_id, str) or not self.child_instance_id:
            raise ValueError("child_instance_id must be a non-empty string")
        self._clock = clock
        self.heartbeat_timeout_seconds = float(heartbeat_timeout_seconds)
        self.terminal_ttl_seconds = float(terminal_ttl_seconds)
        self.max_entries = max_entries
        self._generation = transport_generation
        self._records: "OrderedDict[RequestKey, RequestRecord]" = OrderedDict()
        self._events: Deque[dict[str, Any]] = deque(maxlen=max_events)
        self._event_sink = event_sink
        self._event_sink_error: str | None = None
        self._lock = threading.RLock()
        self._reconciled_count = 0
        self._stale_request_count = 0
        self._outcome_unknown_count = 0
        self._last_reconciliation_at: float | None = None
        self._last_recovery_reason: str | None = None

    @property
    def transport_generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def key(self, request_id: str | int, *, generation: int | None = None) -> RequestKey:
        if not _valid_request_id(request_id):
            raise ValueError("request_id must be a non-boolean string or integer")
        with self._lock:
            selected_generation = self._generation if generation is None else generation
        if not isinstance(selected_generation, int) or isinstance(selected_generation, bool) or selected_generation < 1:
            raise ValueError("generation must be a positive integer")
        return RequestKey(self.child_instance_id, selected_generation, request_id)

    def _now(self) -> float:
        return float(self._clock())

    @staticmethod
    def _active(record: RequestRecord) -> bool:
        return not record.terminal

    def _emit_locked(self, event: str, record: RequestRecord | None = None, **fields: Any) -> None:
        payload: dict[str, Any] = {
            "event_id": f"request-event:{secrets.token_urlsafe(18)}",
            "child_instance_id": self.child_instance_id,
            "event": event,
            "transport_generation": record.key.transport_generation if record is not None else self._generation,
        }
        if record is not None:
            payload.update(
                {
                    "request_id": record.key.request_id,
                    "tool_name": record.tool_name,
                    "state": record.state.value,
                    "side_effect_class": record.side_effect_class.value,
                    "side_effect_started": record.side_effect_started,
                    "retry_count": record.retry_count,
                    "workspace_id": record.workspace_id,
                    "working_tree_id": record.working_tree_id,
                    "development_session_id": record.development_session_id,
                    "duration_ms": record.duration_ms,
                }
            )
            for key in (
                "logical_connection_id",
                "server_schema_revision",
                "server_schema_hash",
                "request_accepted",
                "result",
                "tool_failure_code",
                "integration_intent_id",
                "integration_preflight_id",
                "integration_patch_hash",
                "canonical_revision_before",
                "integration_receipt_id",
            ):
                if key in record.metadata:
                    payload[key] = record.metadata[key]
        for key, value in fields.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                payload[key] = value
        self._events.append(payload)
        if self._event_sink is not None:
            try:
                self._event_sink(dict(payload))
            except Exception as exc:  # noqa: BLE001 - diagnostics must not break request ownership
                self._event_sink_error = type(exc).__name__

    def annotate(
        self,
        request_id: str | int,
        *,
        generation: int | None = None,
        **fields: Any,
    ) -> RequestRecord:
        """Attach bounded non-secret correlation metadata to one live request."""

        allowed = {
            "logical_connection_id",
            "server_schema_revision",
            "server_schema_hash",
            "request_accepted",
            "result",
            "tool_failure_code",
            "integration_intent_id",
            "integration_preflight_id",
            "integration_patch_hash",
            "canonical_revision_before",
            "integration_receipt_id",
        }
        with self._lock:
            record = self._get_locked(request_id, generation=generation)
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key in {
                    "logical_connection_id",
                    "server_schema_revision",
                    "server_schema_hash",
                    "request_accepted",
                } and key in record.metadata:
                    # These fields describe the generation that accepted the
                    # request.  Completion/recovery code may add operational
                    # metadata, but it must never rewrite the accepted
                    # server identity after a reconnect.
                    continue
                text = str(value)
                if len(text.encode("utf-8")) <= 512:
                    record.metadata[key] = text
            return record

    def emit(
        self,
        request_id: str | int,
        event: str,
        *,
        generation: int | None = None,
        **fields: Any,
    ) -> RequestRecord:
        """Emit one bounded diagnostic event without changing request state."""

        with self._lock:
            record = self._get_locked(request_id, generation=generation)
            self._emit_locked(event, record, **fields)
            return record

    def _transition_locked(
        self,
        record: RequestRecord,
        state: RequestState,
        *,
        reason: str | None = None,
    ) -> RequestRecord:
        if record.terminal:
            # Terminal transitions are idempotent. A delayed completion from a
            # prior callback is deliberately ignored instead of reopening it.
            if state in TERMINAL_STATES:
                return record
            raise RequestLifecycleError(f"terminal request cannot transition to {state.value}")
        allowed: Mapping[RequestState, frozenset[RequestState]] = {
            RequestState.NEW: frozenset({RequestState.ACCEPTED}),
            RequestState.ACCEPTED: frozenset(
                {
                    RequestState.RUNNING,
                    RequestState.COMPLETED,
                    RequestState.FAILED,
                    RequestState.CANCELLED,
                    RequestState.TIMED_OUT,
                    RequestState.DISCONNECTED,
                    RequestState.OUTCOME_UNKNOWN,
                    RequestState.RECOVERING,
                }
            ),
            RequestState.RUNNING: frozenset(
                {
                    RequestState.COMPLETING,
                    RequestState.COMPLETED,
                    RequestState.FAILED,
                    RequestState.CANCELLED,
                    RequestState.TIMED_OUT,
                    RequestState.DISCONNECTED,
                    RequestState.OUTCOME_UNKNOWN,
                    RequestState.RECOVERING,
                }
            ),
            RequestState.COMPLETING: frozenset(
                {
                    RequestState.COMPLETED,
                    RequestState.FAILED,
                    RequestState.CANCELLED,
                    RequestState.TIMED_OUT,
                    RequestState.DISCONNECTED,
                    RequestState.OUTCOME_UNKNOWN,
                }
            ),
            RequestState.RECOVERING: frozenset(
                {
                    RequestState.RUNNING,
                    RequestState.COMPLETED,
                    RequestState.FAILED,
                    RequestState.CANCELLED,
                    RequestState.TIMED_OUT,
                    RequestState.DISCONNECTED,
                    RequestState.OUTCOME_UNKNOWN,
                }
            ),
        }
        if state not in allowed.get(record.state, frozenset()):
            raise RequestLifecycleError(f"invalid transition {record.state.value} -> {state.value}")
        record.state = state
        now = self._now()
        record.last_heartbeat = now
        if state in TERMINAL_STATES:
            record.terminal_at = now
            record.duration_ms = max(0.0, (now - record.started_at) * 1000.0)
            record.terminal_reason = reason or record.terminal_reason
            if state is RequestState.OUTCOME_UNKNOWN:
                self._outcome_unknown_count += 1
            self._emit_locked("REQUEST_TERMINAL", record, reason=record.terminal_reason)
        return record

    def _is_stale_locked(self, record: RequestRecord, now: float) -> bool:
        return now - record.last_heartbeat >= self.heartbeat_timeout_seconds

    def _prune_locked(self, now: float) -> int:
        removed = 0
        for key, record in list(self._records.items()):
            if record.terminal and now - record.last_heartbeat >= self.terminal_ttl_seconds:
                self._records.pop(key, None)
                self._reconciled_count += 1
                removed += 1
                self._emit_locked("REQUEST_REAPED_STALE", record, reason="terminal_ttl")
        while len(self._records) > self.max_entries:
            # Never evict a live request. Prefer the oldest terminal record;
            # if all records are live, retain them and let the caller observe
            # a bounded conflict rather than silently losing ownership.
            candidate = next((key for key, item in self._records.items() if item.terminal), None)
            if candidate is None:
                break
            record = self._records.pop(candidate)
            self._reconciled_count += 1
            removed += 1
            self._emit_locked("REQUEST_REAPED_STALE", record, reason="capacity")
        return removed

    def _reap_stale_read_locked(self, record: RequestRecord, now: float) -> bool:
        if not self._is_stale_locked(record, now):
            return False
        # Read-only requests have no process or write receipt to preserve. A
        # disconnected heartbeat can therefore be terminalized safely.
        if (
            record.side_effect_class is SideEffectClass.READ_ONLY
            and not record.side_effect_started
            and record.process_session_id is None
        ):
            self._transition_locked(record, RequestState.DISCONNECTED, reason="stale_read_only_request")
            self._reconciled_count += 1
            self._stale_request_count += 1
            self._last_recovery_reason = "stale_read_only_request"
            self._emit_locked("REQUEST_REAPED_STALE", record, reason="stale_read_only_request")
            return True
        return False

    def accept(
        self,
        request_id: str | int,
        tool_name: str,
        *,
        side_effect_class: SideEffectClass = SideEffectClass.READ_ONLY,
        operation_key: str | None = None,
        workspace_id: str | None = None,
        working_tree_id: str | None = None,
        development_session_id: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> RequestRecord:
        if not isinstance(side_effect_class, SideEffectClass):
            side_effect_class = SideEffectClass(str(side_effect_class))
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("tool_name must be a non-empty string")
        now = self._now()
        with self._lock:
            self._prune_locked(now)
            key = self.key(request_id)
            existing = self._records.get(key)
            if existing is not None:
                if self._reap_stale_read_locked(existing, now):
                    existing = None
                elif existing.terminal and (
                    existing.state is RequestState.COMPLETED
                    or (
                        existing.side_effect_class is SideEffectClass.READ_ONLY
                        and side_effect_class is SideEffectClass.READ_ONLY
                        and not existing.side_effect_started
                    )
                ):
                    # JSON-RPC ids are correlation identifiers, not operation
                    # idempotency keys. Once a response completed, the id no
                    # longer owns a request slot and may be reused even for a
                    # subsequent write. Non-completed write outcomes remain
                    # fail-closed so an ambiguous side effect is never replayed
                    # merely because the client recycled its transport id.
                    self._emit_locked(
                        "REQUEST_REUSED_TERMINAL_ID",
                        existing,
                        reason="completed_or_safe_read_only_id_reuse",
                    )
                    existing = None
                elif existing.terminal and existing.tool_name != tool_name:
                    # JSON-RPC clients may reuse an id after a completed
                    # response for a different method. Keep the terminal
                    # record for delayed-response diagnostics, but do not
                    # let a completed initialize block the next tools/call
                    # that happens to use the same id. Ambiguous same-method
                    # write outcomes remain fail-closed above until their
                    # terminal record is pruned or explicitly reconciled.
                    existing = None
                else:
                    raise RequestConflict("request_id_reuse" if existing.terminal else "request_already_active", existing)
            if operation_key:
                for active in tuple(self._records.values()):
                    if active.key.transport_generation != self._generation or active.operation_key != operation_key or active.terminal:
                        continue
                    if self._reap_stale_read_locked(active, now):
                        continue
                    raise RequestConflict("operation_already_started", active)
            record = RequestRecord(
                key=key,
                tool_name=tool_name,
                side_effect_class=side_effect_class,
                started_at=now,
                last_heartbeat=now,
                state=RequestState.NEW,
                operation_key=operation_key,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                development_session_id=development_session_id,
                metadata={str(k): str(v) for k, v in (metadata or {}).items() if isinstance(k, str)},
            )
            self._records[key] = record
            self._transition_locked(record, RequestState.ACCEPTED)
            self._emit_locked("REQUEST_ACCEPTED", record)
            self._prune_locked(now)
            return record

    def _get_locked(self, request_id: str | int, generation: int | None = None) -> RequestRecord:
        key = self.key(request_id, generation=generation)
        record = self._records.get(key)
        if record is None:
            raise KeyError(request_id)
        return record

    def get(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        with self._lock:
            return self._get_locked(request_id, generation)

    def start(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        with self._lock:
            record = self._get_locked(request_id, generation)
            record.last_heartbeat = self._now()
            return self._transition_locked(record, RequestState.RUNNING)

    def heartbeat(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        with self._lock:
            record = self._get_locked(request_id, generation)
            if record.terminal:
                return record
            record.last_heartbeat = self._now()
            return record

    def mark_completing(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        with self._lock:
            record = self._get_locked(request_id, generation)
            if record.terminal:
                return record
            return self._transition_locked(record, RequestState.COMPLETING)

    def mark_side_effect_started(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        with self._lock:
            record = self._get_locked(request_id, generation)
            record.side_effect_started = True
            record.last_heartbeat = self._now()
            self._emit_locked("REQUEST_SIDE_EFFECT_STARTED", record)
            return record

    def mark_retry(self, request_id: str | int, *, generation: int | None = None, reason: str = "transport_recovery") -> RequestRecord:
        """Record a bounded transport retry without replaying a tool operation."""

        with self._lock:
            record = self._get_locked(request_id, generation)
            if record.terminal:
                return record
            record.retry_count += 1
            record.last_heartbeat = self._now()
            self._emit_locked("REQUEST_RETRY_SCHEDULED", record, reason=reason)
            return record

    def set_event_sink(self, event_sink: Callable[[dict[str, Any]], None] | None) -> None:
        with self._lock:
            self._event_sink = event_sink

    @property
    def event_sink_error(self) -> str | None:
        with self._lock:
            return self._event_sink_error

    def attach_process(
        self,
        request_id: str | int,
        process_session_id: str,
        *,
        generation: int | None = None,
    ) -> RequestRecord:
        if not isinstance(process_session_id, str) or not process_session_id:
            raise ValueError("process_session_id must be a non-empty string")
        with self._lock:
            record = self._get_locked(request_id, generation)
            record.process_session_id = process_session_id
            record.last_heartbeat = self._now()
            return record

    def _terminal(
        self,
        request_id: str | int,
        state: RequestState,
        *,
        generation: int | None = None,
        reason: str | None = None,
    ) -> RequestRecord:
        if state not in TERMINAL_STATES:
            raise ValueError("state must be terminal")
        with self._lock:
            record = self._get_locked(request_id, generation)
            return self._transition_locked(record, state, reason=reason)

    def complete(self, request_id: str | int, *, generation: int | None = None) -> RequestRecord:
        return self._terminal(request_id, RequestState.COMPLETED, generation=generation, reason="completed")

    def fail(self, request_id: str | int, *, generation: int | None = None, reason: str = "failed") -> RequestRecord:
        return self._terminal(request_id, RequestState.FAILED, generation=generation, reason=reason)

    def cancel(self, request_id: str | int, *, generation: int | None = None, reason: str = "cancelled") -> RequestRecord:
        return self._terminal(request_id, RequestState.CANCELLED, generation=generation, reason=reason)

    def timeout(self, request_id: str | int, *, generation: int | None = None, reason: str = "timeout") -> RequestRecord:
        return self._terminal(request_id, RequestState.TIMED_OUT, generation=generation, reason=reason)

    def disconnect(self, request_id: str | int, *, generation: int | None = None, reason: str = "disconnected") -> RequestRecord:
        with self._lock:
            record = self._get_locked(request_id, generation)
            state = RequestState.OUTCOME_UNKNOWN if record.side_effect_started else RequestState.DISCONNECTED
            return self._transition_locked(record, state, reason=reason)

    def complete_key(self, key: RequestKey) -> RequestRecord | None:
        with self._lock:
            if key.child_instance_id != self.child_instance_id or key.transport_generation != self._generation:
                self._last_recovery_reason = "stale_transport_generation"
                self._emit_locked("STALE_RESPONSE_REJECTED", None, request_id=key.request_id)
                return None
            record = self._records.get(key)
            if record is None:
                return None
            return self._transition_locked(record, RequestState.COMPLETED, reason="completed")

    def retire_generation(self, *, reason: str = "transport_reconnect") -> int:
        with self._lock:
            retired = 0
            for record in tuple(self._records.values()):
                if record.key.transport_generation != self._generation or record.terminal:
                    continue
                state = RequestState.OUTCOME_UNKNOWN if record.side_effect_started else RequestState.DISCONNECTED
                self._transition_locked(record, state, reason=reason)
                retired += 1
            self._generation += 1
            self._last_recovery_reason = reason
            self._emit_locked("TRANSPORT_GENERATION_REPLACED", None, reason=reason)
            self._prune_locked(self._now())
            return retired

    def reconcile(self, process_probe: Callable[[str], bool] | None = None) -> dict[str, int]:
        now = self._now()
        with self._lock:
            self._last_reconciliation_at = now
            reaped = self._prune_locked(now)
            active = 0
            for record in tuple(self._records.values()):
                if record.terminal or not self._is_stale_locked(record, now):
                    if not record.terminal:
                        active += 1
                    continue
                if record.process_session_id and process_probe is not None:
                    try:
                        alive = bool(process_probe(record.process_session_id))
                    except Exception:  # noqa: BLE001 - unknown process state is fail-closed
                        alive = True
                    if alive:
                        active += 1
                        continue
                    state = RequestState.OUTCOME_UNKNOWN if record.side_effect_started else RequestState.TIMED_OUT
                    self._transition_locked(record, state, reason="process_exited")
                    self._reconciled_count += 1
                    reaped += 1
                    self._stale_request_count += 1
                    self._emit_locked("PROCESS_BINDING_RECONCILED", record, reason="process_exited")
                    continue
                if self._reap_stale_read_locked(record, now):
                    reaped += 1
                    continue
                if record.side_effect_started:
                    self._transition_locked(record, RequestState.OUTCOME_UNKNOWN, reason="stale_side_effect")
                    self._reconciled_count += 1
                    reaped += 1
                    self._stale_request_count += 1
                else:
                    active += 1
            self._prune_locked(now)
            return {"reconciled": reaped, "active": active, "terminal": sum(item.terminal for item in self._records.values())}

    def reconcile_processes(self, process_probe: Callable[[str], bool]) -> dict[str, int]:
        return self.reconcile(process_probe)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            active = [record for record in self._records.values() if not record.terminal]
            terminal = [record for record in self._records.values() if record.terminal]
            return {
                "child_instance_id": self.child_instance_id,
                "transport_generation": self._generation,
                "active_request_count": len(active),
                "terminal_request_count": len(terminal),
                "stale_request_count": self._stale_request_count,
                "active_process_sessions": len({record.process_session_id for record in active if record.process_session_id}),
                "reconciled_request_count": self._reconciled_count,
                "last_reconciliation_at": self._last_reconciliation_at,
                "last_recovery_reason": self._last_recovery_reason,
                "restart_required": False,
                "outcome_unknown_count": self._outcome_unknown_count,
                "event_sink_error": self._event_sink_error,
                "events": list(self._events),
            }

    def active_records(self) -> tuple[RequestRecord, ...]:
        """Return the live records owned by this connection.

        Connection lifecycle code uses this narrow read-only view to decide
        whether a logical protocol runtime may be retired.  It must prove
        that every live request is read-only before replacing a runtime;
        ambiguous writes remain owned by this generation until their outcome
        is reconciled.
        """

        with self._lock:
            return tuple(record for record in self._records.values() if not record.terminal)


__all__ = [
    "RecoveryActivityEvidence",
    "RequestConflict",
    "RequestKey",
    "RequestLifecycleError",
    "RequestRecord",
    "RequestRegistry",
    "RequestState",
    "SideEffectClass",
    "TERMINAL_STATES",
    "recovery_activity_evidence",
    "safe_retry_decision",
]
