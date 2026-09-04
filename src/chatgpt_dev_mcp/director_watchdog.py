"""Read-only connection, schema, and registry watchdog decisions."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Literal, Mapping


WatchdogStatus = Literal["healthy", "degraded", "blocked", "unknown", "stale"]
TransportStatus = Literal["connected", "disconnected", "unknown"]
RegistryStatus = Literal["valid", "degraded", "invalid", "unknown"]
_REVISION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,80}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class WatchdogValidationError(ValueError):
    """Raised when an observation cannot be trusted as a watchdog input."""


@dataclass(frozen=True)
class SchemaObservation:
    revision: str
    count: int
    hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.revision, str) or not _REVISION_RE.fullmatch(self.revision):
            raise WatchdogValidationError("schema revision is invalid")
        if not isinstance(self.count, int) or isinstance(self.count, bool) or not 0 <= self.count <= 4096:
            raise WatchdogValidationError("schema count is invalid")
        if not isinstance(self.hash, str) or not _HASH_RE.fullmatch(self.hash):
            raise WatchdogValidationError("schema hash is invalid")

    @classmethod
    def from_mapping(cls, raw: object) -> "SchemaObservation":
        if not isinstance(raw, Mapping):
            raise WatchdogValidationError("schema observation must be an object")
        return cls(raw.get("revision"), raw.get("count"), raw.get("hash"))

    def as_dict(self) -> dict[str, object]:
        return {"revision": self.revision, "count": self.count, "hash": self.hash}


@dataclass(frozen=True)
class WatchdogSnapshot:
    observed_at: float
    transport: TransportStatus
    server_ready: bool | None
    local_schema: SchemaObservation | None
    client_schema: SchemaObservation | None
    registry_status: RegistryStatus
    registry_error_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.observed_at, (int, float)) or isinstance(self.observed_at, bool):
            raise WatchdogValidationError("observed_at is invalid")
        if self.transport not in {"connected", "disconnected", "unknown"}:
            raise WatchdogValidationError("transport status is invalid")
        if self.server_ready not in {True, False, None}:
            raise WatchdogValidationError("server_ready is invalid")
        if self.registry_status not in {"valid", "degraded", "invalid", "unknown"}:
            raise WatchdogValidationError("registry status is invalid")
        if any(not isinstance(code, str) or not code or len(code) > 80 for code in self.registry_error_codes):
            raise WatchdogValidationError("registry error codes are invalid")


@dataclass(frozen=True)
class WatchdogResult:
    status: WatchdogStatus
    reasons: tuple[str, ...]
    recommended_action: str
    age_seconds: float
    schema_consistent: bool | None
    registry_status: RegistryStatus

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasons": list(self.reasons),
            "recommended_action": self.recommended_action,
            "age_seconds": self.age_seconds,
            "schema_consistent": self.schema_consistent,
            "registry_status": self.registry_status,
        }


def evaluate_watchdog(
    snapshot: WatchdogSnapshot,
    *,
    now: float | None = None,
    max_age_seconds: float = 300,
) -> WatchdogResult:
    """Classify a point-in-time observation without reconnecting or mutating state."""

    if not isinstance(snapshot, WatchdogSnapshot):
        raise WatchdogValidationError("snapshot must be a WatchdogSnapshot")
    if not 1 <= max_age_seconds <= 24 * 60 * 60:
        raise WatchdogValidationError("max_age_seconds is outside its safety bound")
    current = time.time() if now is None else now
    if not isinstance(current, (int, float)) or isinstance(current, bool):
        raise WatchdogValidationError("now is invalid")
    age = max(0.0, float(current) - float(snapshot.observed_at))
    if age > max_age_seconds:
        return WatchdogResult(
            status="stale",
            reasons=("OBSERVATION_STALE",),
            recommended_action="wait_for_fresh_observation",
            age_seconds=round(age, 3),
            schema_consistent=None,
            registry_status=snapshot.registry_status,
        )

    reasons: list[str] = []
    if snapshot.transport == "disconnected":
        reasons.append("TRANSPORT_DISCONNECTED")
    elif snapshot.transport == "unknown":
        reasons.append("TRANSPORT_UNKNOWN")
    if snapshot.server_ready is False:
        reasons.append("SERVER_NOT_READY")
    elif snapshot.server_ready is None:
        reasons.append("SERVER_READINESS_UNKNOWN")

    if snapshot.local_schema is None or snapshot.client_schema is None:
        schema_consistent: bool | None = None
        reasons.append("CLIENT_SCHEMA_UNAVAILABLE")
    else:
        schema_consistent = snapshot.local_schema == snapshot.client_schema
        if not schema_consistent:
            reasons.append("SCHEMA_MISMATCH")

    if snapshot.registry_status == "invalid":
        reasons.append("REGISTRY_INVALID")
    elif snapshot.registry_status == "degraded":
        reasons.append("REGISTRY_DEGRADED")
    elif snapshot.registry_status == "unknown":
        reasons.append("REGISTRY_UNKNOWN")

    blocking = {
        "TRANSPORT_DISCONNECTED",
        "SERVER_NOT_READY",
        "SCHEMA_MISMATCH",
        "REGISTRY_INVALID",
    }
    degraded = {"REGISTRY_DEGRADED"}
    if any(reason in blocking for reason in reasons):
        status: WatchdogStatus = "blocked"
    elif any(reason in degraded for reason in reasons):
        status = "degraded"
    elif reasons:
        status = "unknown"
    else:
        status = "healthy"

    if status == "healthy":
        action = "none"
    elif any(reason in {"SCHEMA_MISMATCH", "CLIENT_SCHEMA_UNAVAILABLE", "TRANSPORT_DISCONNECTED"} for reason in reasons):
        action = "reconnect_and_rescan"
    elif any(reason.startswith("REGISTRY_") for reason in reasons):
        action = "inspect_registry"
    else:
        action = "collect_fresh_health"
    return WatchdogResult(status, tuple(reasons), action, round(age, 3), schema_consistent, snapshot.registry_status)
