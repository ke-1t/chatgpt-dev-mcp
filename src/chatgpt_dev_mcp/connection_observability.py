"""Bounded metadata-only observability for Streamable HTTP connections."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _session_hash(session_id: str) -> str:
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be non-empty")
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


@dataclass
class ConnectionObservation:
    connection_epoch: int
    server_instance_id: str
    transport_generation: str
    hashed_client_session_id: str
    created_at: str
    registry_revision: str = ""
    schema_hash: str = ""
    tool_count: int | None = None
    reconnect_count: int = 0
    last_initialize_at: str | None = None
    last_list_tools_at: str | None = None
    schema_advertised_at: str | None = None
    last_tool_call_at: str | None = None
    last_disconnect_at: str | None = None
    disconnect_reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "connection_epoch": self.connection_epoch,
            "server_instance_id": self.server_instance_id,
            "transport_generation": self.transport_generation,
            "hashed_client_session_id": self.hashed_client_session_id,
            "created_at": self.created_at,
            "registry_revision": self.registry_revision,
            "schema_hash": self.schema_hash,
            "tool_count": self.tool_count,
            "reconnect_count": self.reconnect_count,
            "last_initialize_at": self.last_initialize_at,
            "last_list_tools_at": self.last_list_tools_at,
            "schema_advertised_at": self.schema_advertised_at,
            "last_tool_call_at": self.last_tool_call_at,
            "last_disconnect_at": self.last_disconnect_at,
            "disconnect_reason": self.disconnect_reason,
        }


class ConnectionObservabilityStore:
    """Keep bounded connection metadata without retaining raw session ids."""

    def __init__(
        self,
        *,
        server_instance_id: str,
        max_records: int = 4096,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(server_instance_id, str) or not server_instance_id or len(server_instance_id) > 160:
            raise ValueError("server_instance_id must be a bounded non-empty string")
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= 16384:
            raise ValueError("max_records must be between 1 and 16384")
        self.server_instance_id = server_instance_id
        self.max_records = max_records
        self._clock = clock
        self._lock = threading.RLock()
        self._records: OrderedDict[str, ConnectionObservation] = OrderedDict()
        self._next_epoch = 0

    def create_session(
        self,
        session_id: str,
        *,
        transport_generation: str,
        registry_revision: str = "",
        schema_hash: str = "",
        tool_count: int | None = None,
    ) -> dict[str, object]:
        if not isinstance(transport_generation, str) or not transport_generation or len(transport_generation) > 80:
            raise ValueError("transport_generation must be a bounded non-empty string")
        session_hash = _session_hash(session_id)
        with self._lock:
            self._next_epoch += 1
            observation = ConnectionObservation(
                connection_epoch=self._next_epoch,
                server_instance_id=self.server_instance_id,
                transport_generation=transport_generation,
                hashed_client_session_id=session_hash,
                created_at=_timestamp(self._clock()),
                registry_revision=str(registry_revision or "")[:160],
                schema_hash=str(schema_hash or "")[:128],
                tool_count=tool_count if isinstance(tool_count, int) and not isinstance(tool_count, bool) and tool_count >= 0 else None,
            )
            self._records[session_hash] = observation
            self._records.move_to_end(session_hash)
            while len(self._records) > self.max_records:
                self._records.popitem(last=False)
            return observation.as_dict()

    def _record(self, session_id: str) -> ConnectionObservation | None:
        key = _session_hash(session_id)
        record = self._records.get(key)
        if record is not None:
            self._records.move_to_end(key)
        return record

    def record_initialize(self, session_id: str) -> None:
        with self._lock:
            record = self._record(session_id)
            if record is not None:
                record.last_initialize_at = _timestamp(self._clock())

    def record_tools_list(
        self,
        session_id: str,
        *,
        registry_revision: str = "",
        schema_hash: str = "",
        tool_count: int | None = None,
    ) -> None:
        with self._lock:
            record = self._record(session_id)
            if record is None:
                return
            now = _timestamp(self._clock())
            record.last_list_tools_at = now
            record.schema_advertised_at = now
            if registry_revision:
                record.registry_revision = str(registry_revision)[:160]
            if schema_hash:
                record.schema_hash = str(schema_hash)[:128]
            if isinstance(tool_count, int) and not isinstance(tool_count, bool) and tool_count >= 0:
                record.tool_count = tool_count

    def record_tool_call(self, session_id: str) -> None:
        with self._lock:
            record = self._record(session_id)
            if record is not None:
                record.last_tool_call_at = _timestamp(self._clock())

    def record_disconnect(self, session_id: str, *, reason: str) -> None:
        with self._lock:
            record = self._record(session_id)
            if record is not None:
                record.last_disconnect_at = _timestamp(self._clock())
                record.disconnect_reason = str(reason or "unknown")[:160]

    def snapshot(self, session_id: str | None = None) -> dict[str, object] | list[dict[str, object]] | None:
        with self._lock:
            if session_id is not None:
                record = self._record(session_id)
                return record.as_dict() if record is not None else None
            return [record.as_dict() for record in self._records.values()]


__all__ = ["ConnectionObservation", "ConnectionObservabilityStore"]
