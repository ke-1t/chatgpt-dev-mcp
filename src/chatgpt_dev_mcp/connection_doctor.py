"""Evidence-based, metadata-only connection failure classification."""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping


class ConnectionFailureClass(str, Enum):
    HEALTHY = "HEALTHY"
    CLIENT_TOOL_SCHEMA_STALE = "CLIENT_TOOL_SCHEMA_STALE"
    CHATGPT_DYNAMIC_TOOL_ATTACHMENT = "CHATGPT_DYNAMIC_TOOL_ATTACHMENT"
    MCP_CHILD_RESTART = "MCP_CHILD_RESTART"
    TRANSPORT_SESSION_FAILURE = "TRANSPORT_SESSION_FAILURE"
    TUNNEL_UNAVAILABLE = "TUNNEL_UNAVAILABLE"
    DIRECTOR_UNHEALTHY = "DIRECTOR_UNHEALTHY"
    REGISTRY_SCHEMA_MISMATCH = "REGISTRY_SCHEMA_MISMATCH"


_BAD_LOCAL_STATUS = frozenset(
    {"down", "error", "failed", "invalid", "not_ready", "unavailable", "unhealthy"}
)
_TRANSPORT_FAILURE_REASONS = frozenset(
    {
        "deleted_session",
        "expired_session",
        "initialization_failed",
        "transport_closed",
        "transport_failure",
        "upstream_transport_unavailable",
    }
)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _status(value: object) -> str:
    return str(_mapping(value).get("status", "")).strip().casefold()


def _server_schema(local: Mapping[str, Any], observation: Mapping[str, Any]) -> dict[str, object]:
    consistency = _mapping(local.get("schema_consistency"))
    schema = _mapping(consistency.get("local_tool_schema"))
    revision = schema.get("revision", observation.get("registry_revision", ""))
    count = schema.get("count", observation.get("tool_count", 0))
    schema_hash = schema.get("hash", observation.get("schema_hash", ""))
    return {
        "revision": revision if isinstance(revision, str) else "",
        "count": count if isinstance(count, int) and not isinstance(count, bool) else 0,
        "hash": schema_hash if isinstance(schema_hash, str) else "",
    }


def _client_schema_stale(server_schema: Mapping[str, object], client_schema: Mapping[str, Any]) -> bool:
    for key in ("revision", "count", "hash"):
        client_value = client_schema.get(key)
        if client_value is not None and client_value != server_schema.get(key):
            return True
    return False


def _identity_changed(runtime: Mapping[str, Any], observation: Mapping[str, Any]) -> bool:
    for key in ("child_instance_id", "server_instance_id"):
        current = runtime.get(key)
        observed = observation.get(key)
        if (
            isinstance(current, str)
            and current
            and isinstance(observed, str)
            and observed
            and current != observed
        ):
            return True
    return False


def _classify(
    local: Mapping[str, Any],
    observation: Mapping[str, Any],
    client_schema: Mapping[str, Any],
    server_schema: Mapping[str, object],
) -> ConnectionFailureClass:
    director_status = _status(local.get("director_persistence"))
    if director_status in _BAD_LOCAL_STATUS:
        return ConnectionFailureClass.DIRECTOR_UNHEALTHY

    registry_status = _status(local.get("registry"))
    schema_status = _status(local.get("schema_consistency"))
    if (
        registry_status in _BAD_LOCAL_STATUS
        or (registry_status and registry_status not in {"healthy", "valid"})
        or (schema_status and schema_status != "consistent")
    ):
        return ConnectionFailureClass.REGISTRY_SCHEMA_MISMATCH

    tunnel_status = _status(local.get("tunnel"))
    if tunnel_status in _BAD_LOCAL_STATUS:
        return ConnectionFailureClass.TUNNEL_UNAVAILABLE

    runtime = _mapping(local.get("runtime"))
    runtime_status = str(runtime.get("status", "")).strip().casefold()
    if (
        runtime.get("restart_required") is True
        or runtime_status in _BAD_LOCAL_STATUS
        or _identity_changed(runtime, observation)
    ):
        return ConnectionFailureClass.MCP_CHILD_RESTART

    transport_status = _status(local.get("transport"))
    disconnect_reason = observation.get("disconnect_reason")
    if transport_status in _BAD_LOCAL_STATUS or (
        observation.get("last_disconnect_at") is not None
        and isinstance(disconnect_reason, str)
        and disconnect_reason in _TRANSPORT_FAILURE_REASONS
    ):
        return ConnectionFailureClass.TRANSPORT_SESSION_FAILURE

    if client_schema:
        available = client_schema.get("available")
        client_status = str(client_schema.get("status", "")).strip().casefold()
        if available is False or client_status in {"detached", "missing", "unavailable"}:
            return ConnectionFailureClass.CHATGPT_DYNAMIC_TOOL_ATTACHMENT
        if _client_schema_stale(server_schema, client_schema):
            return ConnectionFailureClass.CLIENT_TOOL_SCHEMA_STALE

    return ConnectionFailureClass.HEALTHY


def _recommendations(failure: ConnectionFailureClass) -> list[str]:
    return {
        ConnectionFailureClass.HEALTHY: ["no_action_required"],
        ConnectionFailureClass.CLIENT_TOOL_SCHEMA_STALE: [
            "refresh_or_rescan_chatgpt_tools",
            "compare_client_and_server_schema",
            "open_fresh_chat_or_reattach",
        ],
        ConnectionFailureClass.CHATGPT_DYNAMIC_TOOL_ATTACHMENT: [
            "refresh_or_rescan_chatgpt_tools",
            "open_fresh_chat_or_reattach",
            "use_fresh_app_identity_if_still_detached",
        ],
        ConnectionFailureClass.MCP_CHILD_RESTART: [
            "reattach_after_mcp_child_restart",
            "reinitialize_mcp_session",
        ],
        ConnectionFailureClass.TRANSPORT_SESSION_FAILURE: [
            "create_fresh_transport_session",
            "reinitialize_mcp_session",
        ],
        ConnectionFailureClass.TUNNEL_UNAVAILABLE: [
            "recover_local_tunnel",
            "verify_tunnel_health_and_ready",
        ],
        ConnectionFailureClass.DIRECTOR_UNHEALTHY: [
            "recover_director_persistence",
            "verify_director_health",
        ],
        ConnectionFailureClass.REGISTRY_SCHEMA_MISMATCH: [
            "repair_registry_or_schema_mismatch",
            "revalidate_server_tool_schema",
        ],
    }[failure]


def diagnose_connection(
    local_health: Mapping[str, Any],
    observation: Mapping[str, Any],
    client_schema: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the strongest supported failure class using metadata only."""

    outer = _mapping(local_health)
    local = _mapping(outer.get("health")) or outer
    observed = _mapping(observation)
    client = _mapping(client_schema)
    server_schema = _server_schema(local, observed)
    failure = _classify(local, observed, client, server_schema)
    runtime = _mapping(local.get("runtime"))

    return {
        "failure_class": failure.value,
        "recommended_actions": _recommendations(failure),
        "registry_schema": server_schema,
        "freshness": {
            "checked_at": local.get("checked_at") if isinstance(local.get("checked_at"), str) else None,
            "last_initialize_at": observed.get("last_initialize_at")
            if isinstance(observed.get("last_initialize_at"), str)
            else None,
            "last_list_tools_at": observed.get("last_list_tools_at")
            if isinstance(observed.get("last_list_tools_at"), str)
            else None,
            "last_tool_call_at": observed.get("last_tool_call_at")
            if isinstance(observed.get("last_tool_call_at"), str)
            else None,
            "last_disconnect_at": observed.get("last_disconnect_at")
            if isinstance(observed.get("last_disconnect_at"), str)
            else None,
        },
        "evidence": {
            "runtime_status": runtime.get("status") if isinstance(runtime.get("status"), str) else "unknown",
            "runtime_restart_required": runtime.get("restart_required") is True,
            "tunnel_status": _status(local.get("tunnel")) or "unknown",
            "director_status": _status(local.get("director_persistence")) or "unknown",
            "registry_status": _status(local.get("registry")) or "unknown",
            "schema_status": _status(local.get("schema_consistency")) or "unknown",
            "transport_status": _status(local.get("transport")) or "unknown",
            "disconnect_reason": disconnect_reason
            if isinstance((disconnect_reason := observed.get("disconnect_reason")), str)
            else None,
            "client_schema_provided": bool(client),
            "client_available": client.get("available") if isinstance(client.get("available"), bool) else None,
        },
    }


__all__ = ["ConnectionFailureClass", "diagnose_connection"]
