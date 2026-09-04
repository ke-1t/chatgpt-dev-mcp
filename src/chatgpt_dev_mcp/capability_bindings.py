"""Typed bindings from stable capability ids to existing bounded handlers."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .capability_gateway_mcp import (
    CapabilityExecutionContext,
    CapabilityHandler,
    StableCapabilityGatewayError,
)
from .capability_registry import CapabilitySpec


def build_github_repository_bindings(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
    typed_preflight: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
    typed_apply: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[
    tuple[CapabilitySpec, CapabilityHandler],
    tuple[CapabilitySpec, CapabilityHandler],
    tuple[CapabilitySpec, CapabilityHandler],
]:
    """Bind repository posture reads and one approval-preserving mutation."""

    if not all(callable(item) for item in (typed_read, typed_preflight, typed_apply)):
        raise TypeError("GitHub repository handlers must be callable")

    read_schema = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["summary", "forks", "secret_scanning_alerts", "branch_protection", "actions"],
            },
            "branch": {"type": "string", "minLength": 1, "maxLength": 240},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        "required": ["action"],
        "additionalProperties": False,
    }
    preflight_schema = {
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["set_visibility"]},
            "visibility": {"type": "string", "enum": ["private", "public", "internal"]},
        },
        "required": ["operation", "visibility"],
        "additionalProperties": False,
    }
    apply_schema = {
        "type": "object",
        "properties": {
            "preflight_id": {"type": "string", "minLength": 1, "maxLength": 160},
            "approval_id": {"type": "string", "minLength": 1, "maxLength": 160},
            "confirmation": {"type": "string", "minLength": 1, "maxLength": 400},
        },
        "required": ["preflight_id", "approval_id", "confirmation"],
        "additionalProperties": False,
    }

    def spec(capability_id: str, schema: Mapping[str, Any], *, risk_class: str, approval_policy: str) -> CapabilitySpec:
        descriptions = {
            "github_repository_read": "Read bounded GitHub repository posture derived only from the registered workspace remote.",
            "github_repository_preflight": "Prepare one bounded repository visibility change and return the controller-owned one-shot approval challenge.",
            "github_repository_apply": "Consume the exact controller-owned repository visibility approval with TOCTOU checks and authoritative read-back.",
        }
        return CapabilitySpec(
            capability_id=capability_id,
            version="1.0.0",
            description=descriptions[capability_id],
            category="github_repository",
            shard="platform_integrations",
            exposure="registry",
            input_schema=dict(schema),
            output_schema={"type": "object", "additionalProperties": True},
            risk_class=risk_class,
            approval_policy=approval_policy,
            workspace_binding="required",
            session_required=False,
            writer_lease_required=False,
            network_required=True,
            credential_requirements=(),
            timeout_ms=120000,
            idempotency="idempotent" if capability_id == "github_repository_read" else "handler_defined",
            audit_category=capability_id,
            deprecated=False,
            replacement=None,
            handler=capability_id,
            handler_version="1",
        )

    callbacks = {
        "github_repository_read": typed_read,
        "github_repository_preflight": typed_preflight,
        "github_repository_apply": typed_apply,
    }
    specs = {
        "github_repository_read": spec("github_repository_read", read_schema, risk_class="R0", approval_policy="none"),
        "github_repository_preflight": spec("github_repository_preflight", preflight_schema, risk_class="R0", approval_policy="none"),
        "github_repository_apply": spec("github_repository_apply", apply_schema, risk_class="R3", approval_policy="delegated"),
    }

    def binding(capability_id: str) -> tuple[CapabilitySpec, CapabilityHandler]:
        def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
            del context
            preview: dict[str, Any] = {"operation": capability_id, "external_execution": True}
            if capability_id == "github_repository_read":
                preview["action"] = str(params["action"])
                if "branch" in params:
                    preview["branch"] = str(params["branch"])
                if "limit" in params:
                    preview["limit"] = int(params["limit"])
            elif capability_id == "github_repository_preflight":
                preview["operation"] = str(params["operation"])
                preview["visibility"] = str(params["visibility"])
            else:
                preview["preflight_id"] = str(params["preflight_id"])
            return preview, dict(params)

        def execute(
            params: dict[str, Any],
            context: CapabilityExecutionContext,
            state: Any,
        ) -> Mapping[str, Any]:
            del state
            result = callbacks[capability_id](dict(params), context)
            if not isinstance(result, Mapping):
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_RESULT_INVALID",
                    "GitHub repository capability returned an invalid result.",
                )
            return dict(result)

        handler = CapabilityHandler(
            handler_id=capability_id,
            handler_version="1",
            preflight=preflight,
            execute=execute,
        )
        return specs[capability_id], handler

    return (
        binding("github_repository_read"),
        binding("github_repository_preflight"),
        binding("github_repository_apply"),
    )


def build_analysis_pack_binding(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_read):
        raise TypeError("typed_read must be callable")
    capability_id = "development.analysis_pack"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="Prepare bounded non-secret workspace evidence for assistant-side analysis without external execution.",
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "changed_paths": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 240},
                    "maxItems": 128,
                },
                "include_diff": {"type": "boolean"},
                "include_failures": {"type": "boolean"},
                "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 65536},
            },
            "required": ["task_id", "changed_paths"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5000,
        idempotency="idempotent",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        del context
        preview = {
            "operation": capability_id,
            "task_id": str(params["task_id"]),
            "changed_path_count": len(params["changed_paths"]),
            "include_diff": params.get("include_diff", True) is True,
            "include_failures": params.get("include_failures", True) is True,
            "max_bytes": int(params.get("max_bytes", 65536)),
            "external_execution": False,
        }
        return preview, dict(params)

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del state
        result = typed_read(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Analysis-pack preparation returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_list_binding(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind bounded DEVELOPMENT session inventory reads without widening v25 tools."""

    if not callable(typed_read):
        raise TypeError("typed_read must be callable")
    capability_id = "development.session_list"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="List bounded DEVELOPMENT session metadata with cursor pagination and optional lifecycle filters.",
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "active_only": {"type": "boolean"},
                "statuses": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
                    "maxItems": 32,
                    "uniqueItems": True,
                },
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 160},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "cursor": {"type": "string", "minLength": 1, "maxLength": 1024},
            },
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="idempotent",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        del context
        return (
            {
                "operation": capability_id,
                "workspace_id": params.get("workspace_id"),
                "active_only": params.get("active_only", False) is True,
                "status_count": len(params.get("statuses", ())),
                "limit": int(params.get("limit", 20)),
                "has_cursor": bool(params.get("cursor")),
                "external_execution": False,
            },
            dict(params),
        )

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del state
        result = typed_read(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Development session listing returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_abandon_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind explicit durable-session abandonment behind human approval."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.abandon"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Explicitly abandon one retained DEVELOPMENT session. The server must create and verify a durable "
            "recovery archive before the managed worktree can be pruned."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R2",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if (
            not isinstance(prepared, tuple)
            or len(prepared) != 2
            or not isinstance(prepared[0], Mapping)
        ):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Development session abandonment preparation returned an invalid result.",
            )
        return dict(prepared[0]), prepared[1]

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Development session abandonment returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_archive_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind non-destructive archive and terminalization for retained evidence."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.archive"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Create and verify a durable recovery archive for one retained DEVELOPMENT session, then "
            "record an evidence-retained terminal state without removing its managed worktree."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Development session archive preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Development session archive preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Development session archive returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_set_evidence_disposition_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind non-destructive semantic-disposition terminalization for retained evidence."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.set_evidence_disposition"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Record a non-destructive semantic disposition decision for one retained DEVELOPMENT session "
            "after an execute-time re-read proves the worktree, lifecycle, task, lease, and process states "
            "are unchanged; the worktree and evidence bytes are never removed or integrated."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
                "disposition": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["session_id", "disposition"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R1",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Evidence disposition preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Evidence disposition preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Evidence disposition returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_legacy_worktree_adoption_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind non-destructive formal accounting of an unmanaged legacy worktree."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.adopt_legacy_worktree"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Formally account for an unmanaged legacy Git worktree under a registered canonical repository "
            "without fabricating ownership, history, or integrating its bytes. The worktree is never moved, "
            "deleted, GC-ed, or marked active."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "worktree_path": {"type": "string", "minLength": 1, "maxLength": 4096},
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 256},
            },
            "required": ["worktree_path", "workspace_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Legacy worktree adoption preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Legacy worktree adoption preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Legacy worktree adoption returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_reconcile_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind generic stale-session reconciliation behind an exact state pin."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.reconcile_stale_state"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Reconcile one stale DEVELOPMENT session across DevMCP-controlled state while preserving dirty "
            "worktrees and requiring an exact execute-time evidence re-read."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R1",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Session reconciliation preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Session reconciliation preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Session reconciliation returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_development_session_identity_repair_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind evidence-preserving source identity repair behind an exact pin."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.session.repair_source_identity"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Repair one stale DEVELOPMENT session's recorded source identity after proving the same Git repository, "
            "immutable revision, and clean retained worktree; no worktree or evidence is removed."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R1",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Source identity repair preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Source identity repair preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Source identity repair returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_runtime_candidate_activation_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Expose candidate activation behind a CAS-pinned, approval-gated plan."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "runtime.candidate.activate"
    path_schema = {"type": "string", "minLength": 1, "maxLength": 1024}
    input_schema = {
        "type": "object",
        "properties": {
            "candidate_root": path_schema,
            "expected_head": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "expected_schema_version": {"type": "integer", "minimum": 1, "maximum": 1000},
            "entrypoint": path_schema,
            "python_executable": path_schema,
            "state_dir": path_schema,
            "database_path": path_schema,
            "expected_base_revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "expected_patch_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "expected_tool_schema_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "canary_receipt": {"type": "object", "additionalProperties": True},
        },
        "required": [
            "candidate_root",
            "expected_head",
            "expected_schema_version",
            "entrypoint",
            "python_executable",
            "state_dir",
            "database_path",
            "expected_base_revision",
            "expected_patch_hash",
            "expected_tool_schema_hash",
            "canary_receipt",
        ],
        "additionalProperties": False,
    }
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Preflight and activate one Git-pinned runtime candidate with schema, catalog, doctor, and rollback safety checks."
        ),
        category="runtime",
        shard="development",
        exposure="registry",
        input_schema=input_schema,
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=180000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Runtime candidate activation preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Runtime candidate activation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Runtime candidate activation returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_runtime_candidate_preparation_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Expose bounded candidate materialization without granting activation authority."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "runtime.candidate.prepare"
    input_schema = {
        "type": "object",
        "properties": {
            "workspace_id": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$",
            },
            "source_mode": {
                "type": "string",
                "enum": ["integrated_patch", "committed_head"],
            },
            "expected_base_revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "expected_patch_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "permitted_paths": {
                "type": "array",
                "minItems": 0,
                "maxItems": 64,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "pattern": r"^(?!/)(?!~)(?!.*\\)(?!.*(?:^|/)\.\.?/).+$",
                },
            },
            "integration_receipts": {
                "type": "array",
                "minItems": 0,
                "maxItems": 8,
                "uniqueItems": True,
                "items": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                        },
                        "permitted_paths": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 64,
                            "uniqueItems": True,
                            "items": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 512,
                                "pattern": r"^(?!/)(?!~)(?!.*\\)(?!.*(?:^|/)\.\.?/).+$",
                            },
                        },
                    },
                    "required": ["receipt_id", "permitted_paths"],
                    "additionalProperties": False,
                },
            },
            "expected_bootstrap_contract": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "expected_schema_version": {"type": "integer", "const": 14},
            "expected_tool_count": {"type": "integer", "const": 76},
            "expected_tool_schema_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "artifact_role": {
                "type": "string",
                "enum": ["candidate", "recovery_baseline"],
            },
        },
        "required": [
            "workspace_id",
            "expected_base_revision",
            "expected_patch_hash",
            "permitted_paths",
            "integration_receipts",
            "expected_bootstrap_contract",
            "expected_schema_version",
            "expected_tool_count",
            "expected_tool_schema_hash",
            "artifact_role",
        ],
        "additionalProperties": False,
    }
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Materialize one exact verified v26 source patch into an immutable candidate or recovery-baseline artifact; "
            "this operation never activates or changes production."
        ),
        category="runtime",
        shard="development",
        exposure="registry",
        input_schema=input_schema,
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R1",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=180000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Runtime candidate preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Runtime candidate preparation did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Runtime candidate preparation returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_evidence_generation_import_binding(
    typed_preflight: Callable[
        [dict[str, Any], CapabilityExecutionContext],
        tuple[Mapping[str, Any], Any],
    ],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Expose bounded cross-generation evidence import as an approved mutation."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.evidence.import_generation"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=(
            "Import one dependency-closed retained session from a recognized state generation without replacing or deleting source evidence."
        ),
        category="development",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "source_database": {"type": "string", "minLength": 1, "maxLength": 1024},
                "source_generation": {"type": "string", "minLength": 1, "maxLength": 64},
                "session_id": {"type": "string", "minLength": 1, "maxLength": 160},
            },
            "required": ["source_database", "source_generation", "session_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R2",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Evidence generation import preparation returned an invalid result.",
            )
        preview, state = prepared
        preview = {"operation": capability_id, **dict(preview)}
        if not isinstance(preview.get("state_digest"), str) or len(preview["state_digest"]) != 64:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Evidence generation import did not return an immutable state digest.",
            )
        return dict(preview), state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Evidence generation import returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_hybrid_route_binding(
    typed_route: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_route):
        raise TypeError("typed_route must be callable")
    capability_id = "development.execution.route"
    spec = CapabilitySpec(
        capability_id=capability_id, version="1.0.0",
        description="Choose local execution or ChatGPT built-in assistant handoff without performing the workload.",
        category="development", shard="development", exposure="registry",
        input_schema={
            "type":"object",
            "properties":{
                "mode":{"type":"string","enum":["local","cloud","auto"]},
                "workload":{"type":"string","enum":["generic","latency_sensitive","compute_heavy","bulk_analysis","privileged_local"]},
                "chatgpt_builtin_available":{"type":"boolean"},
                "requires_local_secrets":{"type":"boolean"},
                "requires_authenticated_browser":{"type":"boolean"},
                "requires_macos":{"type":"boolean"},
            },
            "required":["mode","workload"], "additionalProperties":False,
        },
        output_schema={"type":"object","additionalProperties":True},
        risk_class="R0", approval_policy="automatic", workspace_binding="required",
        session_required=False, writer_lease_required=False, network_required=False,
        credential_requirements=(), timeout_ms=5000, idempotency="idempotent",
        audit_category=capability_id, deprecated=False, replacement=None,
        handler=capability_id, handler_version="1",
    )
    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        result = typed_route(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_PREFLIGHT_INVALID", "Hybrid route returned an invalid result.")
        return dict(result), dict(result)
    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params, context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_STATE_INVALID", "Hybrid route state is invalid.")
        return dict(state)
    return spec, CapabilityHandler(handler_id=capability_id, handler_version="1", preflight=preflight, execute=execute)


def build_development_fast_step_binding(
    typed_preflight: Callable[[dict[str, Any], CapabilityExecutionContext], tuple[Mapping[str, Any], Any]],
    typed_execute: Callable[[Any, CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    capability_id = "development.fast_step"
    path_array = {"type":"array","items":{"type":"string","minLength":1,"maxLength":512},"maxItems":64}
    spec = CapabilitySpec(
        capability_id=capability_id, version="1.0.0",
        description="Run bounded context, optional lease-protected patch, diff, selective verification, and audit in one local step.",
        category="development", shard="development", exposure="registry",
        input_schema={
            "type":"object",
            "properties":{
                "query":{"type":"string","minLength":1,"maxLength":1000},
                "target_paths":path_array, "diff_paths":path_array, "changed_paths":path_array,
                "patch":{"type":"string","maxLength":524288},
                "verify":{"type":"boolean"}, "audit":{"type":"boolean"},
            },
            "required":["query"], "additionalProperties":False,
        },
        output_schema={"type":"object","additionalProperties":True},
        risk_class="R1", approval_policy="automatic", workspace_binding="required",
        session_required=True, writer_lease_required=True, network_required=False,
        credential_requirements=(), timeout_ms=120000, idempotency="handler_defined",
        audit_category=capability_id, deprecated=False, replacement=None,
        handler=capability_id, handler_version="1",
    )
    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_PREFLIGHT_INVALID", "Fast-step preparation returned an invalid result.")
        return dict(prepared[0]), prepared[1]
    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params
        result = typed_execute(state, context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError("CAPABILITY_HANDLER_RESULT_INVALID", "Fast-step execution returned an invalid result.")
        return dict(result)
    return spec, CapabilityHandler(handler_id=capability_id, handler_version="1", preflight=preflight, execute=execute)


def _build_context_read_binding(
    *,
    capability_id: str,
    description: str,
    input_schema: dict[str, Any],
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_read):
        raise TypeError("typed_read must be callable")
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description=description,
        category="context",
        shard="development",
        exposure="registry",
        input_schema=input_schema,
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version=handler_version,
    )

    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        del context
        preview = {
            "operation": capability_id,
            "max_bytes": int(params.get("max_bytes", 16384 if capability_id == "context.bootstrap" else 8192)),
            "external_execution": False,
        }
        if capability_id == "context.focus":
            preview["task_id"] = str(params.get("task_id", ""))
        return preview, dict(params)

    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del state
        result = typed_read(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                f"{capability_id} returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_context_bootstrap_binding(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    return _build_context_read_binding(
        capability_id="context.bootstrap",
        description="Return a bounded revision-aware project bootstrap without replaying full session history.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 1000},
                "max_bytes": {"type": "integer", "minimum": 512, "maximum": 262144, "default": 16384},
            },
            "additionalProperties": False,
        },
        typed_read=typed_read,
    )


def build_context_focus_binding(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    return _build_context_read_binding(
        capability_id="context.focus",
        description="Return bounded task-focused semantic definitions, callers, tests, diffs, and repository map context.",
        input_schema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "query": {"type": "string", "minLength": 1, "maxLength": 1000},
                "target_paths": {"type": "array", "maxItems": 64, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                "diff_paths": {"type": "array", "maxItems": 64, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                "max_bytes": {"type": "integer", "minimum": 512, "maximum": 262144, "default": 8192},
            },
            "required": ["task_id", "query"],
            "additionalProperties": False,
        },
        typed_read=typed_read,
    )


def build_performance_summary_binding(
    typed_read: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_read):
        raise TypeError("typed_read must be callable")
    capability_id = "performance.summary"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="Return a bounded local performance summary for the selected workspace without exporting telemetry.",
        category="observability",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 4096, "default": 256},
                "top": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version=handler_version,
    )

    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        del context
        return {
            "operation": capability_id,
            "limit": int(params.get("limit", 256)),
            "top": int(params.get("top", 20)),
            "external_execution": False,
        }, dict(params)

    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del state
        result = typed_read(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "performance.summary returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_context_checkpoint_binding(
    typed_write: Callable[[dict[str, Any], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_write):
        raise TypeError("typed_write must be callable")
    capability_id = "context.checkpoint"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="Persist one bounded non-secret continuation checkpoint for the selected workspace revision.",
        category="context",
        shard="development",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "outcome": {"type": "string", "minLength": 1, "maxLength": 240},
                "next_action": {"type": "string", "minLength": 1, "maxLength": 1000},
            },
            "required": ["task_id", "outcome", "next_action"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R1",
        approval_policy="automatic",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=120000,
        idempotency="idempotent",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version=handler_version,
    )

    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        del context
        return {
            "operation": capability_id,
            "task_id": str(params.get("task_id", "")),
            "external_execution": False,
        }, dict(params)

    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del state
        result = typed_write(dict(params), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "context.checkpoint returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_workspace_trust_binding(*, capability_id: str, target_level: str, risk_class: str, approval_policy: str, typed_prepare: Callable[[str, str, str], tuple[Mapping[str, Any], Any]], typed_execute: Callable[[Any], Mapping[str, Any]]) -> tuple[CapabilitySpec, CapabilityHandler]:
    if target_level not in {"standard", "trusted_development"}: raise ValueError("unsupported trust target")
    spec = CapabilitySpec(
        capability_id=capability_id, version="1.0.0",
        description="Enable persistent Trusted DEVELOPMENT for one registered workspace." if target_level == "trusted_development" else "Revoke Trusted DEVELOPMENT and return the workspace to standard approval mode.",
        category="governance", shard="governance_security", exposure="registry",
        input_schema={"type":"object","properties":{"expected_config_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["expected_config_digest"],"additionalProperties":False},
        output_schema={"type":"object","additionalProperties":True}, risk_class=risk_class, approval_policy=approval_policy,
        workspace_binding="required", session_required=False, writer_lease_required=False, network_required=False,
        credential_requirements=(), timeout_ms=5000, idempotency="idempotent", audit_category=capability_id,
        deprecated=False, replacement=None, handler=capability_id, handler_version="1",
    )
    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_prepare(context.workspace_id, str(params["expected_config_digest"]), target_level)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_PREFLIGHT_INVALID", "Workspace-trust preparation returned an invalid result.")
        return dict(prepared[0]), prepared[1]
    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params, context
        result = typed_execute(state)
        if not isinstance(result, Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_RESULT_INVALID", "Workspace-trust execution returned an invalid result.")
        return dict(result)
    return spec, CapabilityHandler(handler_id=capability_id, handler_version="1", preflight=preflight, execute=execute)


def build_trusted_delivery_binding(*, capability_id: str, description: str, input_schema: Mapping[str, Any], typed_preflight: Callable[[dict[str, Any], CapabilityExecutionContext], tuple[Mapping[str, Any], Any]], typed_execute: Callable[[Any], Mapping[str, Any]]) -> tuple[CapabilitySpec, CapabilityHandler]:
    spec = CapabilitySpec(
        capability_id=capability_id, version="1.0.0", description=description, category="delivery", shard="delivery", exposure="registry",
        input_schema=dict(input_schema), output_schema={"type":"object","additionalProperties":True}, risk_class="R2", approval_policy="workspace_trust",
        workspace_binding="required", session_required=False, writer_lease_required=False, network_required=False, credential_requirements=(),
        timeout_ms=120000, idempotency="handler_defined", audit_category=capability_id, deprecated=False, replacement=None, handler=capability_id, handler_version="1",
    )
    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        prepared = typed_preflight(dict(params), context)
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_PREFLIGHT_INVALID", "Trusted delivery preflight returned an invalid result.")
        return dict(prepared[0]), prepared[1]
    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params, context
        result = typed_execute(state)
        if not isinstance(result, Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_RESULT_INVALID", "Trusted delivery execution returned an invalid result.")
        return dict(result)
    return spec, CapabilityHandler(handler_id=capability_id, handler_version="1", preflight=preflight, execute=execute)


def build_external_open_binding(typed_prepare: Callable[[dict[str, Any]], tuple[Mapping[str, Any], Any]], typed_execute: Callable[[Any], Mapping[str, Any]]) -> tuple[CapabilitySpec, CapabilityHandler]:
    spec = CapabilitySpec(
        capability_id="external_open", version="1.0.0", description="Open one validated application, URL, file, or directory without shell authority.",
        category="development", shard="development", exposure="registry",
        input_schema={"type":"object","properties":{"kind":{"type":"string","enum":["app_bundle","app_path","url","custom_url","file","directory"]},"target":{"type":"string","minLength":1,"maxLength":4096}},"required":["kind","target"],"additionalProperties":False},
        output_schema={"type":"object","additionalProperties":True}, risk_class="R2", approval_policy="workspace_trust", workspace_binding="required",
        session_required=False, writer_lease_required=False, network_required=False, credential_requirements=(), timeout_ms=20000,
        idempotency="handler_defined", audit_category="external_open", deprecated=False, replacement=None, handler="external_open", handler_version="1",
    )
    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        del context
        prepared = typed_prepare(dict(params))
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_PREFLIGHT_INVALID", "External-open preparation returned an invalid result.")
        return dict(prepared[0]), prepared[1]
    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params, context
        result = typed_execute(state)
        if not isinstance(result, Mapping): raise StableCapabilityGatewayError("CAPABILITY_HANDLER_RESULT_INVALID", "External-open execution returned an invalid result.")
        return dict(result)
    return spec, CapabilityHandler(handler_id="external_open", handler_version="1", preflight=preflight, execute=execute)


def build_macos_app_replace_binding(
    typed_prepare: Callable[[dict[str, Any]], tuple[Mapping[str, Any], Any]],
    typed_execute: Callable[[Any], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind one replace-only signed macOS app installation capability."""

    if not callable(typed_prepare) or not callable(typed_execute):
        raise TypeError("typed_prepare and typed_execute must be callable")
    capability_id = "platform.macos_app.replace"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="Replace one existing signed macOS app from a bounded HTTPS DMG, ZIP, TAR.GZ, or redirected supported artifact while preserving signer identity and user data.",
        category="platform_runtime",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "source_url": {"type": "string", "minLength": 1, "maxLength": 4096},
                "app_name": {"type": "string", "minLength": 1, "maxLength": 200},
                "bundle_id": {"type": "string", "minLength": 1, "maxLength": 255},
            },
            "required": ["source_url", "app_name", "bundle_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=True,
        credential_requirements=(),
        timeout_ms=120_000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(params: dict[str, Any], context: CapabilityExecutionContext) -> tuple[Mapping[str, Any], Any]:
        del context
        prepared = typed_prepare(dict(params))
        if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[0], Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "macOS app replacement preparation returned an invalid result.",
            )
        return dict(prepared[0]), prepared[1]

    def execute(params: dict[str, Any], context: CapabilityExecutionContext, state: Any) -> Mapping[str, Any]:
        del params, context
        result = typed_execute(state)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "macOS app replacement execution returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


def build_external_capability_invoke_binding(
    typed_execute: Callable[[str, Mapping[str, object], CapabilityExecutionContext], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind optional external providers behind workspace trust and network policy."""

    if not callable(typed_execute):
        raise TypeError("typed_execute must be callable")
    handler_id = "external.capability.invoke"
    spec = CapabilitySpec(
        capability_id=handler_id,
        version="1.0.0",
        description="Invoke one bounded non-secret capability through an optional configured external provider.",
        category="platform_runtime",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "capability": {"type": "string", "minLength": 1, "maxLength": 128},
                "request": {"type": "object", "additionalProperties": True},
            },
            "required": ["capability", "request"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R2",
        approval_policy="workspace_trust",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=True,
        credential_requirements=(),
        timeout_ms=120_000,
        idempotency="handler_defined",
        audit_category=handler_id,
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version="1",
    )

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del state
        capability = params.get("capability")
        request = params.get("request")
        if not isinstance(capability, str) or not isinstance(request, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_ARGS_INVALID",
                "External capability invocation arguments are invalid.",
            )
        result = typed_execute(capability, dict(request), context)
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "External capability invocation returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=handler_id,
        handler_version="1",
        execute=execute,
    )


def build_platform_profile_register_binding(
    typed_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind ``platform.profile.register`` to the existing typed profile pair.

    The outer gateway owns capability/risk metadata and the inner typed tools
    remain the source of truth for their own validation and one-shot receipt.
    The inner confirmation is retained only as server-side handler state.
    """

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")

    handler_id = "platform.profile.register"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id="platform.profile.register",
        version="1.0.0",
        description="Register one bounded browser or capture-only desktop QA profile.",
        category="desktop_profiles",
        shard="qa",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "kind": {"type": "string", "enum": ["browser", "desktop"]},
                "profile_id": {"type": "string", "minLength": 1, "maxLength": 80},
                "allowed_origins": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "minItems": 1,
                    "maxItems": 16,
                },
                "viewport_width": {"type": "integer", "minimum": 320, "maximum": 3840},
                "viewport_height": {"type": "integer", "minimum": 240, "maximum": 2160},
                "bundle_id": {"type": "string", "minLength": 1, "maxLength": 160},
                "health_url": {"type": "string", "maxLength": 2048},
                "max_screenshot_bytes": {"type": "integer", "minimum": 65536, "maximum": 16777216},
            },
            "required": ["workspace_id", "kind", "profile_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5_000,
        idempotency="idempotent",
        audit_category="platform.profile.register",
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version=handler_version,
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        requested_workspace = params.get("workspace_id")
        if requested_workspace != context.workspace_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_WORKSPACE_CHANGED",
                "Capability workspace does not match the pinned execution context.",
            )
        raw = typed_preflight(dict(params))
        if not isinstance(raw, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed platform-profile preflight returned an invalid result.",
            )
        preflight_id = raw.get("preflight_id")
        approval = raw.get("approval")
        confirmation = approval.get("confirmation") if isinstance(approval, Mapping) else None
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed platform-profile preflight did not return a usable one-shot confirmation.",
            )
        preview = {
            key: value
            for key, value in raw.items()
            if key not in {"approval", "confirmation", "preflight_id"}
        }
        state = {
            "typed_preflight_id": preflight_id,
            "typed_confirmation": confirmation,
        }
        return preview, state

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params, context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed platform-profile handler state is unavailable.",
            )
        preflight_id = state.get("typed_preflight_id")
        confirmation = state.get("typed_confirmation")
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed platform-profile handler state is invalid.",
            )
        return typed_execute({"preflight_id": preflight_id, "confirmation": confirmation})

    handler = CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )
    return spec, handler


def build_credential_slot_register_binding(
    typed_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind secret-free credential reference registration behind human approval."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    handler_id = "platform.credential.register"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=handler_id,
        version="1.0.0",
        description="Register one bounded credential slot reference without accepting credential material.",
        category="desktop_profiles",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "slot_id": {"type": "string", "minLength": 1, "maxLength": 80},
                "source_kind": {"type": "string", "enum": ["env", "keychain"]},
                "source_name": {"type": "string", "minLength": 1, "maxLength": 128},
                "allowed_profiles": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 80},
                    "minItems": 1,
                    "maxItems": 16,
                },
            },
            "required": ["workspace_id", "slot_id", "source_kind", "source_name", "allowed_profiles"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5_000,
        idempotency="idempotent",
        audit_category=handler_id,
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version=handler_version,
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if params.get("workspace_id") != context.workspace_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_WORKSPACE_CHANGED",
                "Capability workspace does not match the pinned execution context.",
            )
        raw = typed_preflight(dict(params))
        if not isinstance(raw, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed credential-slot preflight returned an invalid result.",
            )
        preflight_id = raw.get("preflight_id")
        approval = raw.get("approval")
        confirmation = approval.get("confirmation") if isinstance(approval, Mapping) else None
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed credential-slot preflight did not return a usable one-shot confirmation.",
            )
        preview = {
            key: value
            for key, value in raw.items()
            if key not in {"approval", "confirmation", "preflight_id"}
        }
        return preview, {"typed_preflight_id": preflight_id, "typed_confirmation": confirmation}

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params, context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed credential-slot handler state is unavailable.",
            )
        preflight_id = state.get("typed_preflight_id")
        confirmation = state.get("typed_confirmation")
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed credential-slot handler state is invalid.",
            )
        return typed_execute({"preflight_id": preflight_id, "confirmation": confirmation})

    return spec, CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_command_profile_register_binding(
    typed_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind bounded command-profile registration behind one human approval."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    handler_id = "platform.command_profile.register"
    handler_version = "1"
    arg_spec_schema = {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["path", "selector", "choice", "integer", "boolean"]},
            "flag": {"type": "string", "maxLength": 80},
            "choices": {"type": "array", "items": {"type": "string", "maxLength": 80}, "maxItems": 32},
            "max_length": {"type": "integer", "minimum": 1, "maximum": 1000},
            "required": {"type": "boolean"},
        },
        "required": ["type"],
        "additionalProperties": False,
    }
    spec = CapabilitySpec(
        capability_id=handler_id,
        version="1.0.0",
        description="Register one bounded fixed-argv command profile without exposing a generic config editor.",
        category="desktop_profiles",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "profile_id": {"type": "string", "minLength": 1, "maxLength": 80},
                "argv": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "items": {"type": "string", "minLength": 1, "maxLength": 240},
                },
                "allowed_args": {"type": "object", "maxProperties": 32, "additionalProperties": arg_spec_schema},
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 120000, "default": 30000},
                "max_output_bytes": {"type": "integer", "minimum": 1024, "maximum": 1048576, "default": 65536},
                "resources": {
                    "type": "array",
                    "maxItems": 32,
                    "items": {"type": "string", "minLength": 1, "maxLength": 160},
                },
                "credential_slots": {
                    "type": "array",
                    "maxItems": 16,
                    "items": {"type": "string", "minLength": 1, "maxLength": 80},
                },
                "network_class": {
                    "type": "string",
                    "enum": ["none", "github", "dependency", "browser", "api-test"],
                    "default": "none",
                },
                "lifecycle": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["ephemeral"]},
                        "purpose": {"type": "string", "minLength": 1, "maxLength": 160},
                        "owner": {"type": "string", "minLength": 1, "maxLength": 160},
                        "created_at": {"type": "string", "minLength": 1, "maxLength": 64},
                        "expires_at": {"type": "string", "minLength": 1, "maxLength": 64},
                    },
                    "required": ["kind", "purpose", "owner", "created_at"],
                    "additionalProperties": False,
                },
            },
            "required": ["workspace_id", "profile_id", "argv", "allowed_args"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5_000,
        idempotency="idempotent",
        audit_category=handler_id,
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version=handler_version,
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if params.get("workspace_id") != context.workspace_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_WORKSPACE_CHANGED",
                "Capability workspace does not match the pinned execution context.",
            )
        raw = typed_preflight(dict(params))
        if not isinstance(raw, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile preflight returned an invalid result.",
            )
        preflight_id = raw.get("preflight_id")
        approval = raw.get("approval")
        confirmation = approval.get("confirmation") if isinstance(approval, Mapping) else None
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile preflight did not return a usable one-shot confirmation.",
            )
        preview = {
            key: value
            for key, value in raw.items()
            if key not in {"approval", "confirmation", "preflight_id"}
        }
        return preview, {"typed_preflight_id": preflight_id, "typed_confirmation": confirmation}

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile handler state is unavailable.",
            )
        preflight_id = state.get("typed_preflight_id")
        confirmation = state.get("typed_confirmation")
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile handler state is invalid.",
            )
        try:
            return typed_execute({"preflight_id": preflight_id, "confirmation": confirmation})
        except Exception as exc:
            if getattr(exc, "code", "") != "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND":
                raise
        refreshed = typed_preflight(dict(params))
        if not isinstance(refreshed, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile preflight returned an invalid result during recovery.",
            )
        refreshed_preflight_id = refreshed.get("preflight_id")
        refreshed_approval = refreshed.get("approval")
        refreshed_confirmation = refreshed_approval.get("confirmation") if isinstance(refreshed_approval, Mapping) else None
        if (
            not isinstance(refreshed_preflight_id, str)
            or not refreshed_preflight_id
            or not isinstance(refreshed_confirmation, str)
            or not refreshed_confirmation
        ):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile recovery preflight did not return a usable one-shot confirmation.",
            )
        return typed_execute(
            {"preflight_id": refreshed_preflight_id, "confirmation": refreshed_confirmation}
        )

    return spec, CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_command_profile_unregister_binding(
    typed_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind exact command-profile removal behind one human approval."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    handler_id = "platform.command_profile.unregister"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=handler_id,
        version="1.0.0",
        description="Unregister one exact managed command profile without exposing a generic config editor.",
        category="desktop_profiles",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "profile_id": {"type": "string", "minLength": 1, "maxLength": 80},
            },
            "required": ["workspace_id", "profile_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5_000,
        idempotency="handler_defined",
        audit_category=handler_id,
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version=handler_version,
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if params.get("workspace_id") != context.workspace_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_WORKSPACE_CHANGED",
                "Capability workspace does not match the pinned execution context.",
            )
        raw = typed_preflight(dict(params))
        if not isinstance(raw, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile unregister preflight returned an invalid result.",
            )
        preflight_id = raw.get("preflight_id")
        approval = raw.get("approval")
        confirmation = approval.get("confirmation") if isinstance(approval, Mapping) else None
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile unregister preflight did not return a usable one-shot confirmation.",
            )
        preview = {
            key: value
            for key, value in raw.items()
            if key not in {"approval", "confirmation", "preflight_id"}
        }
        return preview, {"typed_preflight_id": preflight_id, "typed_confirmation": confirmation}

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params, context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile unregister handler state is unavailable.",
            )
        preflight_id = state.get("typed_preflight_id")
        confirmation = state.get("typed_confirmation")
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile unregister handler state is invalid.",
            )
        return typed_execute({"preflight_id": preflight_id, "confirmation": confirmation})

    return spec, CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_command_profile_cleanup_binding(
    typed_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    """Bind pinned ephemeral command-profile cleanup behind one human approval."""

    if not callable(typed_preflight) or not callable(typed_execute):
        raise TypeError("typed_preflight and typed_execute must be callable")
    handler_id = "platform.command_profile.cleanup_ephemeral"
    handler_version = "1"
    spec = CapabilitySpec(
        capability_id=handler_id,
        version="1.0.0",
        description="Clean up an exact preflight-pinned set of explicitly ephemeral command profiles.",
        category="desktop_profiles",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "mode": {
                    "type": "string",
                    "enum": ["expired", "all_ephemeral"],
                    "default": "expired",
                },
            },
            "required": ["workspace_id"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R3",
        approval_policy="human",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=5_000,
        idempotency="handler_defined",
        audit_category=handler_id,
        deprecated=False,
        replacement=None,
        handler=handler_id,
        handler_version=handler_version,
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[dict[str, Any], Mapping[str, Any]]:
        if params.get("workspace_id") != context.workspace_id:
            raise StableCapabilityGatewayError(
                "CAPABILITY_WORKSPACE_CHANGED",
                "Capability workspace does not match the pinned execution context.",
            )
        raw = typed_preflight(dict(params))
        if not isinstance(raw, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile cleanup preflight returned an invalid result.",
            )
        preview = {
            key: value
            for key, value in raw.items()
            if key not in {"approval", "confirmation", "preflight_id"}
        }
        if raw.get("status") == "noop":
            return preview, {"noop": True, "noop_result": dict(raw)}
        preflight_id = raw.get("preflight_id")
        approval = raw.get("approval")
        confirmation = approval.get("confirmation") if isinstance(approval, Mapping) else None
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_PREFLIGHT_INVALID",
                "Typed command-profile cleanup preflight did not return a usable one-shot confirmation.",
            )
        return preview, {
            "typed_preflight_id": preflight_id,
            "typed_confirmation": confirmation,
            "noop": False,
        }

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del params, context
        if not isinstance(state, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile cleanup handler state is unavailable.",
            )
        if state.get("noop") is True:
            result = state.get("noop_result")
            if not isinstance(result, Mapping):
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_STATE_INVALID",
                    "Typed command-profile cleanup no-op state is invalid.",
                )
            return dict(result)
        preflight_id = state.get("typed_preflight_id")
        confirmation = state.get("typed_confirmation")
        if not isinstance(preflight_id, str) or not preflight_id or not isinstance(confirmation, str) or not confirmation:
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_STATE_INVALID",
                "Typed command-profile cleanup handler state is invalid.",
            )
        return typed_execute({"preflight_id": preflight_id, "confirmation": confirmation})

    return spec, CapabilityHandler(
        handler_id=handler_id,
        handler_version=handler_version,
        preflight=preflight,
        execute=execute,
    )


def build_workspace_organization_bindings(
    typed_group_create: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_relocate_preflight: Callable[[dict[str, Any]], Mapping[str, Any]],
    typed_relocate_execute: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> tuple[
    tuple[CapabilitySpec, CapabilityHandler],
    tuple[CapabilitySpec, CapabilityHandler],
    tuple[CapabilitySpec, CapabilityHandler],
]:
    """Expose bounded project grouping and workspace relocation via the registry."""

    if not all(callable(item) for item in (typed_group_create, typed_relocate_preflight, typed_relocate_execute)):
        raise TypeError("workspace organization handlers must be callable")

    schemas: dict[str, dict[str, Any]] = {
        "project_group_create": {
            "type": "object",
            "properties": {
                "root_id": {"type": "string", "minLength": 1, "maxLength": 64, "default": "developer"},
                "directory_name": {"type": "string", "minLength": 1, "maxLength": 128},
                "request_id": {"type": "string", "maxLength": 128},
                "owner_id": {"type": "string", "maxLength": 128},
            },
            "required": ["directory_name"],
            "additionalProperties": False,
        },
        "workspace_relocate_preflight": {
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "destination_root_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "destination_parent": {"type": "string", "minLength": 1, "maxLength": 512},
                "destination_name": {"type": "string", "minLength": 1, "maxLength": 128},
                "request_id": {"type": "string", "maxLength": 128},
                "owner_id": {"type": "string", "maxLength": 128},
            },
            "required": ["workspace_id", "destination_root_id", "destination_parent"],
            "additionalProperties": False,
        },
        "workspace_relocate": {
            "type": "object",
            "properties": {
                "preflight_id": {"type": "string", "minLength": 1, "maxLength": 160},
                "confirmation": {"type": "string", "minLength": 1, "maxLength": 400},
                "request_id": {"type": "string", "maxLength": 128},
                "owner_id": {"type": "string", "maxLength": 128},
            },
            "required": ["preflight_id", "confirmation"],
            "additionalProperties": False,
        },
    }
    metadata = {
        "project_group_create": (
            "Create one plain organizational directory below a configured PROJECT_DISCOVERY root without Git or workspace registration.",
            "R2",
            "human",
        ),
        "workspace_relocate_preflight": (
            "Read-only validation and identity pinning for one registered workspace relocation.",
            "R0",
            "none",
        ),
        "workspace_relocate": (
            "Consume one exact relocation preflight confirmation and atomically move the workspace plus its registry path with rollback protection.",
            "R3",
            "delegated",
        ),
    }
    callbacks = {
        "project_group_create": typed_group_create,
        "workspace_relocate_preflight": typed_relocate_preflight,
        "workspace_relocate": typed_relocate_execute,
    }

    def build(capability_id: str) -> tuple[CapabilitySpec, CapabilityHandler]:
        description, risk_class, approval_policy = metadata[capability_id]
        spec = CapabilitySpec(
            capability_id=capability_id,
            version="1.0.0",
            description=description,
            category="workspace_organization",
            shard="development",
            exposure="registry",
            input_schema=schemas[capability_id],
            output_schema={"type": "object", "additionalProperties": True},
            risk_class=risk_class,
            approval_policy=approval_policy,
            workspace_binding="none",
            session_required=False,
            writer_lease_required=False,
            network_required=False,
            credential_requirements=(),
            timeout_ms=120_000,
            idempotency="handler_defined",
            audit_category=capability_id,
            deprecated=False,
            replacement=None,
            handler=capability_id,
            handler_version="1",
        )

        def preflight(
            params: dict[str, Any],
            context: CapabilityExecutionContext,
        ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
            del context
            preview: dict[str, Any] = {"operation": capability_id, "external_execution": False}
            if capability_id == "project_group_create":
                preview.update(root_id=str(params.get("root_id", "developer")), directory_name=str(params["directory_name"]))
            elif capability_id == "workspace_relocate_preflight":
                preview.update(
                    workspace_id=str(params["workspace_id"]),
                    destination_root_id=str(params["destination_root_id"]),
                    destination_parent=str(params["destination_parent"]),
                )
                if "destination_name" in params:
                    preview["destination_name"] = str(params["destination_name"])
            else:
                preview["preflight_id"] = str(params["preflight_id"])
            return preview, dict(params)

        def execute(
            params: dict[str, Any],
            context: CapabilityExecutionContext,
            state: Any,
        ) -> Mapping[str, Any]:
            del params, context
            if not isinstance(state, Mapping):
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_STATE_INVALID",
                    "Workspace organization handler state is unavailable.",
                )
            result = callbacks[capability_id](dict(state))
            if not isinstance(result, Mapping):
                raise StableCapabilityGatewayError(
                    "CAPABILITY_HANDLER_RESULT_INVALID",
                    "Workspace organization capability returned an invalid result.",
                )
            return dict(result)

        return spec, CapabilityHandler(
            handler_id=capability_id,
            handler_version="1",
            preflight=preflight,
            execute=execute,
        )

    return (
        build("project_group_create"),
        build("workspace_relocate_preflight"),
        build("workspace_relocate"),
    )


__all__ = [
    "build_command_profile_cleanup_binding",
    "build_command_profile_register_binding",
    "build_command_profile_unregister_binding",
    "build_credential_slot_register_binding",
    "build_context_bootstrap_binding",
    "build_context_checkpoint_binding",
    "build_context_focus_binding",
    "build_performance_summary_binding",
    "build_development_session_list_binding",
    "build_development_session_archive_binding",
    "build_development_session_reconcile_binding",
    "build_development_session_identity_repair_binding",
    "build_runtime_candidate_activation_binding",
    "build_runtime_candidate_preparation_binding",
    "build_evidence_generation_import_binding",
    "build_development_fast_step_binding",
    "build_external_capability_invoke_binding",
    "build_external_open_binding",
    "build_github_repository_bindings",
    "build_macos_app_replace_binding",
    "build_hybrid_route_binding",
    "build_platform_profile_register_binding",
    "build_trusted_delivery_binding",
    "build_workspace_trust_binding",
    "build_workspace_organization_bindings",
]
