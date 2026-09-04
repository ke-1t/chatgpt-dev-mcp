"""Authority-preserving compatibility bindings for v24 tools hidden by v25."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .capability_gateway_mcp import (
    CapabilityExecutionContext,
    CapabilityHandler,
    StableCapabilityGateway,
    StableCapabilityGatewayError,
)
from .capability_registry import CapabilitySpec


_DIRECT_HUMAN_APPROVAL_TOOLS = frozenset({"workspace_project_create"})


@dataclass(frozen=True)
class LegacyToolBinding:
    spec: CapabilitySpec
    handler: CapabilityHandler
    delegated_authority: bool


class DelegatedStableCapabilityGateway(StableCapabilityGateway):
    """Stable gateway extension where selected handlers delegate final authority.

    Delegation never grants permission itself. It only suppresses a redundant
    outer confirmation when the registered handler calls an existing typed
    tool whose approval/lease/policy checks remain authoritative.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._delegated_handler_ids: set[str] = set()

    def register_delegated_handler(self, handler: CapabilityHandler, *, replace: bool = False) -> None:
        self.register_handler(handler, replace=replace)
        self._delegated_handler_ids.add(handler.handler_id)

    def _approval_required(self, spec: CapabilitySpec) -> bool:
        if spec.approval_policy != "delegated":
            return super()._approval_required(spec)
        if spec.risk_class not in {"R1", "R2", "R3"}:
            raise StableCapabilityGatewayError(
                "CAPABILITY_RISK_POLICY_INVALID",
                "Delegated authority is reserved for non-R0 compatibility operations.",
            )
        if spec.handler not in self._delegated_handler_ids:
            raise StableCapabilityGatewayError(
                "CAPABILITY_DELEGATED_AUTHORITY_INVALID",
                "Capability handler is not registered as authority-preserving.",
            )
        return False


def build_legacy_tool_binding(
    tool_definition: Mapping[str, Any],
    *,
    category: str,
    shard: str,
    risk_class: str,
    workspace_binding: str,
    invoke: Callable[[str, dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
    deprecated: bool = False,
    replacement: str | None = None,
) -> LegacyToolBinding:
    name = tool_definition.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("legacy tool definition requires a name")
    schema = tool_definition.get("inputSchema", {"type": "object"})
    if not isinstance(schema, Mapping):
        raise ValueError("legacy tool inputSchema must be an object")
    annotations = tool_definition.get("annotations", {})
    read_only = bool(annotations.get("readOnlyHint")) if isinstance(annotations, Mapping) else False
    if read_only and risk_class != "R0":
        raise ValueError("read-only legacy compatibility tools must use R0")
    if read_only:
        approval_policy = "none"
    elif name in _DIRECT_HUMAN_APPROVAL_TOOLS:
        approval_policy = "human"
    else:
        approval_policy = "delegated"
    handler_id = f"legacy.tool.{name}"
    handler_version = "v24"
    spec = CapabilitySpec(
        capability_id=name,
        version="24.0.0",
        description=str(tool_definition.get("description") or tool_definition.get("title") or name),
        input_schema=dict(schema),
        output_schema={"type": "object"},
        risk_class=risk_class,
        approval_policy=approval_policy,
        workspace_binding=workspace_binding,
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120_000,
        idempotency="idempotent" if bool(annotations.get("idempotentHint")) else "handler_defined",
        audit_category=name,
        deprecated=deprecated,
        replacement=replacement,
        handler=handler_id,
        handler_version=handler_version,
        category=category,
        shard=shard,
        exposure="registry",
    )

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del state
        result = invoke(name, dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Delegated legacy handler returned a non-object result.",
            )
        return dict(result)

    handler = CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        execute=execute,
    )
    return LegacyToolBinding(
        spec=spec,
        handler=handler,
        delegated_authority=not read_only and approval_policy == "delegated",
    )


__all__ = [
    "DelegatedStableCapabilityGateway",
    "LegacyToolBinding",
    "build_legacy_tool_binding",
]

