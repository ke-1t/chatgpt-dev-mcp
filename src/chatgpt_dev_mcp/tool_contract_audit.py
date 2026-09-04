"""Machine-readable public tool contract audit for v26 migration work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


_PRIVILEGED = frozenset(
    {
        "workspace_create_development_session",
        "workspace_integrate_development_session",
        "git_commit",
        "git_push",
        "capability_execute",
    }
)
_CONDITIONAL_APPROVAL = frozenset({"capability_preflight", "capability_execute"})
_HUMAN_APPROVAL = frozenset(
    {
        "workspace_create_development_session",
        "workspace_integrate_development_session",
        "git_commit",
        "git_push",
    }
)

# A READ_ONLY request may append bounded, non-secret evidence that is useful
# for later observability or an explicitly paired mutation.  Keep these
# exceptions explicit so a durable write cannot disappear behind the generic
# ``none`` classification.  The v26 projection discloses the same boundary in
# the public description; frozen v25 definitions remain untouched.
_READ_ONLY_DURABLE_EVIDENCE = {
    "security_audit": "append_only_audit_evidence",
    "workspace_integration_preflight": "append_only_integration_preflight_evidence",
    "workspace_list_development_sessions": "append_only_observability_evidence",
    "semantic_code_query": "append_only_semantic_evidence",
    "development_context": "append_only_context_evidence",
    "workspace_register_preflight": "append_only_provisioning_preflight_evidence",
    "workspace_unregister_preflight": "append_only_provisioning_preflight_evidence",
    "workspace_registration_update_preflight": "append_only_provisioning_preflight_evidence",
    "git_stage_preflight": "durable_git_preflight_authority",
    "git_stage_paths_preflight": "durable_git_preflight_authority",
    "git_stage_hunks_preflight": "durable_git_preflight_authority",
    "git_commit_preflight": "durable_git_preflight_authority_and_closeout",
    "git_verified_commit_preflight": "durable_git_preflight_authority_and_closeout",
    "git_push_preflight": "durable_git_preflight_authority_and_closeout",
    "browser_inspect": "managed_browser_observation_or_screenshot_artifact",
}


@dataclass(frozen=True)
class ToolContractAuditRecord:
    name: str
    title: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    annotations: Mapping[str, bool]
    toolset: str
    permission: str
    side_effects: str
    approval: str
    filesystem: str
    network: str
    destructive: bool
    external_execution: bool


def _toolset(name: str) -> str:
    if name.startswith("workspace_") or name in {
        "readonly_path",
        "list_allowed_files",
        "read_allowed_file",
        "search_allowed_files",
    }:
        return "WORKSPACE"
    if name in {
        "read_file",
        "list_files",
        "search_text",
        "view_image",
        "apply_patch",
        "development_context",
    }:
        return "CODE"
    if name.startswith("git_"):
        return "GIT"
    if name.startswith("verification_") or name.startswith("run_") or name.startswith("task_"):
        return "VERIFY"
    if name.startswith("browser_"):
        return "BROWSER"
    if name.startswith("desktop_"):
        return "RUNTIME"
    if name.startswith("director_") or name in {
        "server_info",
        "check_exec_environment",
        "doctor_connection",
    }:
        return "DIAGNOSTICS"
    if name.startswith("capability_"):
        return "PRIVILEGED"
    return "CORE"


def _filesystem_scope(name: str) -> str:
    if name in {"readonly_path", "list_allowed_files", "read_allowed_file", "search_allowed_files"}:
        return "configured_readonly_root"
    if name.startswith("git_"):
        return "git_repository"
    if name in {
        "server_info",
        "director_health",
        "check_exec_environment",
        "capability_catalog",
        "capability_describe",
        "doctor_connection",
    }:
        return "none"
    return "workspace"


def audit_tool_contracts(definitions: Sequence[Mapping[str, Any]]) -> list[ToolContractAuditRecord]:
    records: list[ToolContractAuditRecord] = []
    for definition in definitions:
        name = str(definition.get("name", ""))
        annotations_raw = definition.get("annotations")
        annotations_map = annotations_raw if isinstance(annotations_raw, Mapping) else {}
        annotations = {
            key: bool(annotations_map.get(key, False))
            for key in (
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            )
        }
        read_only = annotations["readOnlyHint"]
        permission = (
            "READ_ONLY"
            if read_only
            else ("PRIVILEGED" if name in _PRIVILEGED else "SCOPED_WRITE")
        )
        approval = (
            "human"
            if name in _HUMAN_APPROVAL
            else ("conditional" if name in _CONDITIONAL_APPROVAL else "none")
        )
        open_world = annotations["openWorldHint"]
        network = "required" if name == "git_push" else ("possible" if open_world else "none")
        if name in _READ_ONLY_DURABLE_EVIDENCE:
            # These are bounded evidence/control records, not workspace,
            # session, lease, or external-authority mutations.  Their
            # existence is nevertheless part of the contract and must remain
            # visible to the machine-readable audit.
            side_effects = _READ_ONLY_DURABLE_EVIDENCE[name]
        elif name == "readonly_path" and not read_only:
            # v26 open/close updates only the bounded, TTL-checked handle
            # registry. It never becomes workspace or control-plane authority.
            side_effects = "bounded_readonly_handle_registry"
        elif read_only:
            side_effects = "none"
        elif name.startswith("git_"):
            side_effects = "git_mutation"
        elif name.startswith(("run_", "task_", "browser_", "desktop_")):
            side_effects = "managed_process_or_runtime"
        elif name.startswith("capability_"):
            side_effects = "capability_dependent"
        else:
            side_effects = "workspace_or_control_plane_write"
        records.append(
            ToolContractAuditRecord(
                name=name,
                title=str(definition.get("title", "")),
                description=str(definition.get("description", "")),
                input_schema=(
                    definition.get("inputSchema")
                    if isinstance(definition.get("inputSchema"), Mapping)
                    else {}
                ),
                output_schema=(
                    definition.get("outputSchema")
                    if isinstance(definition.get("outputSchema"), Mapping)
                    else {}
                ),
                annotations=annotations,
                toolset=_toolset(name),
                permission=permission,
                side_effects=side_effects,
                approval=approval,
                filesystem=_filesystem_scope(name),
                network=network,
                destructive=annotations["destructiveHint"],
                external_execution=open_world,
            )
        )
    return records


def lint_tool_contracts(definitions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    names: set[str] = set()
    for record in audit_tool_contracts(definitions):
        if not record.name:
            errors.append("tool name is empty")
            continue
        if record.name in names:
            errors.append(f"duplicate tool name: {record.name}")
        names.add(record.name)
        if not record.title:
            errors.append(f"{record.name}: title is empty")
        if not record.description:
            errors.append(f"{record.name}: description is empty")
        if record.input_schema.get("type") != "object":
            errors.append(f"{record.name}: input schema must be object")
        if "additionalProperties" not in record.input_schema:
            errors.append(f"{record.name}: input schema must declare additionalProperties")
        if set(record.annotations) != {
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        }:
            errors.append(f"{record.name}: incomplete annotations")
        properties = record.input_schema.get("properties")
        if properties is not None and not isinstance(properties, Mapping):
            errors.append(f"{record.name}: properties must be object")

    for broad in ("run_task", "desktop_runtime", "browser_test_session", "browser_action"):
        if broad in names:
            errors.append(f"{broad}: broad discriminator tool is not allowed on v26")
    return {
        "status": "valid" if not errors else "invalid",
        "count": len(names),
        "errors": errors,
    }


__all__ = ["ToolContractAuditRecord", "audit_tool_contracts", "lint_tool_contracts"]
