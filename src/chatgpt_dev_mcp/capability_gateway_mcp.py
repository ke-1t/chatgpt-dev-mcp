"""Stable internal capability dispatch with exact fail-closed preflight receipts.

The public MCP gateway exposes capability ids and params only. Handler ids,
risk metadata, approval policy, and trusted handler state remain server-owned.
This module never accepts shell commands, dynamic imports, or caller-selected
handler names.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
import threading
import time
from typing import Any, Callable, Mapping

from .capability_registry import (
    CapabilityRegistry,
    CapabilitySpec,
    CapabilityValidationError,
    CompositeCapabilityRegistry,
)


class StableCapabilityGatewayError(ValueError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass(frozen=True)
class CapabilityExecutionContext:
    workspace_id: str
    working_tree_id: str
    session_id: str
    owner_id: str
    task_id: str
    policy_revision: str
    policy_digest: str
    writer_lease_id: str = ""
    credential_grants: tuple[str, ...] = ()
    network_allowed: bool = False
    trusted_session_grant_id: str = ""
    workspace_trust_level: str = "standard"


@dataclass(frozen=True)
class CapabilityHandler:
    handler_id: str
    handler_version: str
    execute: Callable[[dict[str, Any], CapabilityExecutionContext, Any], Any]
    preflight: Callable[[dict[str, Any], CapabilityExecutionContext], tuple[Any, Any]] | None = None


@dataclass(frozen=True)
class _PreflightReceipt:
    preflight_id: str
    capability_id: str
    capability_version: str
    normalized_args_hash: str
    workspace_id: str
    working_tree_id: str
    session_id: str
    owner_id: str
    task_id: str
    policy_revision: str
    policy_digest: str
    handler_id: str
    handler_version: str
    writer_lease_id: str
    credential_grants: tuple[str, ...]
    network_allowed: bool
    trusted_session_grant_id: str
    workspace_trust_level: str
    risk_class: str
    approval_policy: str
    approval_required: bool
    approval_confirmation: str
    handler_state: Any
    handler_preview: Any
    created_at: float
    expires_at: float


class CapabilityPreflightStore:
    """Process-local receipt state shared by stable gateway runtime instances."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.preflights: dict[str, _PreflightReceipt] = {}
        # Values are absolute expiry timestamps for replay protection.
        self.consumed: dict[str, float] = {}


class StableCapabilityGateway:
    """Dispatch only exact registry capabilities through pre-registered handlers."""

    def __init__(
        self,
        registry: CapabilityRegistry | CompositeCapabilityRegistry,
        *,
        clock: Callable[[], float] | None = None,
        ttl_seconds: int = 900,
        max_preflights: int = 512,
        preflight_store: CapabilityPreflightStore | None = None,
    ) -> None:
        if not isinstance(registry, (CapabilityRegistry, CompositeCapabilityRegistry)):
            raise TypeError("registry must be a CapabilityRegistry or CompositeCapabilityRegistry")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 1800:
            raise ValueError("ttl_seconds is outside safe bounds")
        if isinstance(max_preflights, bool) or not isinstance(max_preflights, int) or not 16 <= max_preflights <= 4096:
            raise ValueError("max_preflights is outside safe bounds")
        self.registry = registry
        self._clock = clock or time.time
        self._ttl_seconds = ttl_seconds
        self._max_preflights = max_preflights
        self._handlers: dict[str, CapabilityHandler] = {}
        if preflight_store is not None and not isinstance(preflight_store, CapabilityPreflightStore):
            raise TypeError("preflight_store must be a CapabilityPreflightStore")
        self._preflight_store = preflight_store or CapabilityPreflightStore()

    def register_handler(self, handler: CapabilityHandler, *, replace: bool = False) -> None:
        if not isinstance(handler, CapabilityHandler):
            raise TypeError("handler must be a CapabilityHandler")
        if not handler.handler_id or not handler.handler_version or not callable(handler.execute):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_INVALID", "Capability handler is invalid.")
        if handler.preflight is not None and not callable(handler.preflight):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_INVALID", "Capability preflight handler is invalid.")
        if handler.handler_id in self._handlers and not replace:
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_DUPLICATE", "Capability handler is already registered.")
        self._handlers[handler.handler_id] = handler

    def catalog(
        self,
        *,
        prefix: str | None = None,
        limit: int = 50,
        include_deprecated: bool = True,
        category: str | None = None,
        shard: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        return self.registry.catalog(
            prefix=prefix,
            limit=limit,
            include_deprecated=include_deprecated,
            category=category,
            shard=shard,
            query=query,
        )

    def overview(self, *, include_deprecated: bool = False) -> dict[str, Any]:
        return self.registry.overview(include_deprecated=include_deprecated)

    def describe(self, capability_id: str) -> dict[str, Any]:
        return self.registry.describe(capability_id)

    def preflight(
        self,
        capability_id: str,
        params: Mapping[str, Any],
        context: CapabilityExecutionContext,
    ) -> dict[str, Any]:
        spec = self.registry.get(capability_id)
        normalized = self.registry.validate_params(capability_id, params)
        self._validate_context(spec, context)
        handler = self._handler_for(spec)
        self._prune()

        handler_preview: Any = None
        handler_state: Any = None
        if handler.preflight is not None:
            handler_preflight = handler.preflight(dict(normalized), context)
            if not isinstance(handler_preflight, tuple) or len(handler_preflight) != 2:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                    "Capability handler preflight must return (public_preview, server_state).",
                )
            handler_preview, handler_state = handler_preflight

        approval_required = self._approval_required_for_context(spec, context)
        created_at = float(self._clock())
        preflight_id = "capability-preflight:" + secrets.token_urlsafe(24)
        confirmation = (
            f"EXECUTE_CAPABILITY:{capability_id}:{secrets.token_urlsafe(12)}"
            if approval_required
            else ""
        )
        receipt = _PreflightReceipt(
            preflight_id=preflight_id,
            capability_id=spec.capability_id,
            capability_version=spec.version,
            normalized_args_hash=_json_hash(normalized),
            workspace_id=context.workspace_id,
            working_tree_id=context.working_tree_id,
            session_id=context.session_id,
            owner_id=context.owner_id,
            task_id=context.task_id,
            policy_revision=context.policy_revision,
            policy_digest=context.policy_digest,
            handler_id=spec.handler,
            handler_version=handler.handler_version,
            writer_lease_id=context.writer_lease_id,
            credential_grants=_normalized_grants(context.credential_grants),
            network_allowed=bool(context.network_allowed),
            trusted_session_grant_id=context.trusted_session_grant_id,
            workspace_trust_level=context.workspace_trust_level,
            risk_class=spec.risk_class,
            approval_policy=spec.approval_policy,
            approval_required=approval_required,
            approval_confirmation=confirmation,
            handler_state=handler_state,
            handler_preview=handler_preview,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        with self._preflight_store.lock:
            self._preflight_store.preflights[preflight_id] = receipt
            self._prune_locked(created_at)

        payload: dict[str, Any] = {
            "preflight_id": receipt.preflight_id,
            "capability_id": receipt.capability_id,
            "capability_version": receipt.capability_version,
            "normalized_args_hash": receipt.normalized_args_hash,
            "workspace_id": receipt.workspace_id,
            "working_tree_id": receipt.working_tree_id,
            "session_id": receipt.session_id,
            "owner_id": receipt.owner_id,
            "task_id": receipt.task_id,
            "policy_revision": receipt.policy_revision,
            "policy_digest": receipt.policy_digest,
            "writer_lease_id": receipt.writer_lease_id,
            "credential_grants": list(receipt.credential_grants),
            "network_allowed": receipt.network_allowed,
            "workspace_trust_level": receipt.workspace_trust_level,
            "risk_class": receipt.risk_class,
            "approval_policy": receipt.approval_policy,
            "approval_required": receipt.approval_required,
            "created_at": receipt.created_at,
            "expires_at": receipt.expires_at,
            "handler_preflight": receipt.handler_preview,
        }
        if approval_required:
            confirmation = receipt.approval_confirmation
            payload["approval"] = {
                "preflight_id": receipt.preflight_id,
                "confirmation": confirmation,
                "copy_block": f"```text\n{confirmation}\n```",
                "presentation_hint": "copyable_code_block",
                "expires_at": receipt.expires_at,
            }
        return payload

    def execute(
        self,
        preflight_id: str,
        capability_id: str,
        params: Mapping[str, Any],
        context: CapabilityExecutionContext,
        *,
        confirmation: str = "",
    ) -> dict[str, Any]:
        store = self._preflight_store
        with store.lock:
            if preflight_id in store.consumed:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_PREFLIGHT_REPLAY",
                    "Capability preflight replay is denied.",
                )
            receipt = store.preflights.get(preflight_id)
            if receipt is None:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_PREFLIGHT_NOT_FOUND",
                    "Capability preflight is unknown or no longer usable.",
                )
            now = float(self._clock())
            if now >= receipt.expires_at:
                store.preflights.pop(preflight_id, None)
                raise StableCapabilityGatewayError(
                    "CAPABILITY_PREFLIGHT_EXPIRED",
                    "Capability preflight expired; create a new preflight.",
                )
            if capability_id != receipt.capability_id:
                raise StableCapabilityGatewayError("CAPABILITY_CHANGED", "Capability id changed after preflight.")

            spec = self.registry.get(capability_id)
            normalized = self.registry.validate_params(capability_id, params)
            if spec.version != receipt.capability_version:
                raise StableCapabilityGatewayError("CAPABILITY_VERSION_CHANGED", "Capability version changed after preflight.")
            if _json_hash(normalized) != receipt.normalized_args_hash:
                raise StableCapabilityGatewayError("CAPABILITY_ARGS_CHANGED", "Capability params changed after preflight.")

            self._validate_context(spec, context)
            self._validate_pinned_context(receipt, context)
            handler = self._handler_for(spec)
            if handler.handler_version != receipt.handler_version or spec.handler_version != receipt.handler_version:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_VERSION_CHANGED",
                    "Capability handler version changed after preflight.",
                )
            if handler.handler_id != receipt.handler_id:
                raise StableCapabilityGatewayError("CAPABILITY_HANDLER_CHANGED", "Capability handler changed after preflight.")
            if self._approval_required_for_context(spec, context) != receipt.approval_required or spec.approval_policy != receipt.approval_policy:
                raise StableCapabilityGatewayError("CAPABILITY_POLICY_CHANGED", "Capability approval policy changed after preflight.")
            if receipt.approval_required and confirmation != receipt.approval_confirmation:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_APPROVAL_REQUIRED",
                    "Return the exact confirmation issued by capability_preflight.",
                )

            # Consume atomically before invoking a potentially mutating handler.
            # This prevents two runtime instances from racing the same receipt.
            store.preflights.pop(preflight_id, None)
            store.consumed[preflight_id] = now + max(float(self._ttl_seconds) * 2.0, 600.0)
            self._prune_locked(now)
        result = handler.execute(dict(normalized), context, receipt.handler_state)
        try:
            validated_result = self.registry.validate_result(capability_id, result)
        except CapabilityValidationError as exc:
            raise StableCapabilityGatewayError(
                "CAPABILITY_RESULT_INVALID",
                "Capability handler result does not match the registered output schema.",
            ) from exc
        return {
            "preflight_id": preflight_id,
            "capability_id": spec.capability_id,
            "capability_version": spec.version,
            "risk_class": spec.risk_class,
            "audit_category": spec.audit_category,
            "preflight_consumed": True,
            "result": validated_result,
        }

    def _handler_for(self, spec: CapabilitySpec) -> CapabilityHandler:
        handler = self._handlers.get(spec.handler)
        if handler is None:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_UNAVAILABLE",
                "Registered capability handler is unavailable.",
            )
        if handler.handler_version != spec.handler_version:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_VERSION_CHANGED",
                "Registered capability handler version does not match the registry.",
            )
        return handler

    @staticmethod
    def _approval_required(spec: CapabilitySpec) -> bool:
        if spec.risk_class not in {"R0", "R1", "R2", "R3"}:
            raise StableCapabilityGatewayError("CAPABILITY_RISK_INVALID", "Capability risk class is invalid.")
        policy = spec.approval_policy
        if policy in {"none", "automatic"}:
            if spec.risk_class in {"R2", "R3"}:
                raise StableCapabilityGatewayError(
                    "CAPABILITY_RISK_POLICY_INVALID",
                    "R2/R3 capabilities cannot bypass an approval or trusted-grant policy.",
                )
            return False
        if policy in {"human", "explicit", "trusted_session_grant"}:
            if policy == "trusted_session_grant":
                if spec.risk_class != "R2":
                    raise StableCapabilityGatewayError(
                        "CAPABILITY_RISK_POLICY_INVALID",
                        "trusted_session_grant is reserved for R2 capabilities.",
                    )
                return False
            return True
        raise StableCapabilityGatewayError("CAPABILITY_APPROVAL_POLICY_INVALID", "Capability approval policy is invalid.")

    def _approval_required_for_context(self, spec: CapabilitySpec, context: CapabilityExecutionContext) -> bool:
        if spec.approval_policy != "workspace_trust":
            return self._approval_required(spec)
        if spec.risk_class not in {"R1", "R2"}:
            raise StableCapabilityGatewayError("CAPABILITY_RISK_POLICY_INVALID", "workspace_trust is limited to bounded R1/R2 local-development capabilities.")
        if context.workspace_trust_level not in {"standard", "trusted_development"}:
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_TRUST_INVALID", "Workspace trust context is invalid.")
        return context.workspace_trust_level != "trusted_development"

    @staticmethod
    def _validate_context(spec: CapabilitySpec, context: CapabilityExecutionContext) -> None:
        if not isinstance(context, CapabilityExecutionContext):
            raise StableCapabilityGatewayError("CAPABILITY_CONTEXT_INVALID", "Capability execution context is invalid.")
        if spec.workspace_binding not in {"none", "required"}:
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_POLICY_INVALID", "Capability workspace policy is invalid.")
        if spec.workspace_binding == "required" and (not context.workspace_id or not context.working_tree_id):
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_REQUIRED", "Capability requires an exact workspace binding.")
        if spec.session_required and not context.session_id:
            raise StableCapabilityGatewayError("CAPABILITY_SESSION_REQUIRED", "Capability requires an active session binding.")
        if not context.policy_revision or not _is_sha256(context.policy_digest):
            raise StableCapabilityGatewayError("CAPABILITY_POLICY_CONTEXT_INVALID", "Capability policy context is invalid.")
        if spec.writer_lease_required and not context.writer_lease_id:
            raise StableCapabilityGatewayError("CAPABILITY_WRITER_LEASE_REQUIRED", "Capability requires a current writer lease.")
        grants = set(_normalized_grants(context.credential_grants))
        missing_credentials = sorted(set(spec.credential_requirements) - grants)
        if missing_credentials:
            raise StableCapabilityGatewayError(
                "CAPABILITY_CREDENTIAL_REQUIRED",
                "Capability credential requirements are not satisfied.",
            )
        if spec.network_required and not context.network_allowed:
            raise StableCapabilityGatewayError("CAPABILITY_NETWORK_REQUIRED", "Capability requires an approved network context.")
        if context.trusted_session_grant_id and not isinstance(context.trusted_session_grant_id, str):
            raise StableCapabilityGatewayError("CAPABILITY_TRUSTED_GRANT_INVALID", "Trusted session grant context is invalid.")
        if context.workspace_trust_level not in {"standard", "trusted_development"}:
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_TRUST_INVALID", "Workspace trust context is invalid.")
        if spec.approval_policy == "trusted_session_grant" and not context.trusted_session_grant_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_TRUSTED_GRANT_REQUIRED",
                "Capability requires an active trusted-session grant.",
            )

    @staticmethod
    def _validate_pinned_context(receipt: _PreflightReceipt, context: CapabilityExecutionContext) -> None:
        if context.workspace_id != receipt.workspace_id:
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_CHANGED", "Workspace changed after preflight.")
        if context.working_tree_id != receipt.working_tree_id:
            raise StableCapabilityGatewayError("CAPABILITY_WORKING_TREE_CHANGED", "Working tree changed after preflight.")
        if context.session_id != receipt.session_id:
            raise StableCapabilityGatewayError("CAPABILITY_SESSION_CHANGED", "Session changed after preflight.")
        if context.owner_id != receipt.owner_id or context.task_id != receipt.task_id:
            raise StableCapabilityGatewayError("CAPABILITY_TASK_BINDING_CHANGED", "Owner/task binding changed after preflight.")
        if context.policy_revision != receipt.policy_revision or context.policy_digest != receipt.policy_digest:
            raise StableCapabilityGatewayError("CAPABILITY_POLICY_CHANGED", "Policy changed after preflight.")
        if context.writer_lease_id != receipt.writer_lease_id:
            raise StableCapabilityGatewayError("CAPABILITY_WRITER_LEASE_CHANGED", "Writer lease changed after preflight.")
        if _normalized_grants(context.credential_grants) != receipt.credential_grants:
            raise StableCapabilityGatewayError("CAPABILITY_CREDENTIAL_GRANTS_CHANGED", "Credential grants changed after preflight.")
        if bool(context.network_allowed) != receipt.network_allowed:
            raise StableCapabilityGatewayError("CAPABILITY_NETWORK_CONTEXT_CHANGED", "Network authorization changed after preflight.")
        if context.trusted_session_grant_id != receipt.trusted_session_grant_id:
            raise StableCapabilityGatewayError("CAPABILITY_TRUSTED_GRANT_CHANGED", "Trusted-session grant changed after preflight.")
        if context.workspace_trust_level != receipt.workspace_trust_level:
            raise StableCapabilityGatewayError("CAPABILITY_WORKSPACE_TRUST_CHANGED", "Workspace trust changed after preflight.")

    def _prune(self) -> None:
        now = float(self._clock())
        with self._preflight_store.lock:
            self._prune_locked(now)

    def _prune_locked(self, now: float) -> None:
        preflights = self._preflight_store.preflights
        consumed = self._preflight_store.consumed
        for preflight_id, receipt in list(preflights.items()):
            if now >= receipt.expires_at:
                preflights.pop(preflight_id, None)
        for preflight_id, replay_expires_at in list(consumed.items()):
            if now >= replay_expires_at:
                consumed.pop(preflight_id, None)
        if len(preflights) > self._max_preflights:
            oldest = sorted(preflights.values(), key=lambda item: item.created_at)
            for receipt in oldest[: len(preflights) - self._max_preflights]:
                preflights.pop(receipt.preflight_id, None)


def _json_hash(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StableCapabilityGatewayError(
            "CAPABILITY_PARAMS_NOT_JSON",
            "Capability params must be deterministic JSON values.",
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _normalized_grants(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or any(not isinstance(item, str) or not item for item in values):
        raise StableCapabilityGatewayError("CAPABILITY_CREDENTIAL_CONTEXT_INVALID", "Credential grants are invalid.")
    return tuple(sorted(set(values)))


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "CapabilityExecutionContext",
    "CapabilityHandler",
    "CapabilityPreflightStore",
    "StableCapabilityGateway",
    "StableCapabilityGatewayError",
]
