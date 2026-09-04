"""Exact v24 long-tail inventory routed through the stable Capability Registry."""

from __future__ import annotations

from collections.abc import Mapping


REGISTRY_CATEGORY_TOOL_GROUPS: Mapping[str, tuple[str, ...]] = {
    "platform_runtime": (
        "get_default_cwd",
        "set_default_cwd",
        "request_permissions",
        "system_inspect",
        "external_capability_status",
        "local_maintenance",
    ),
    "workspace": (
        "workspace_register_preflight",
        "workspace_register",
        "workspace_unregister_preflight",
        "workspace_unregister",
        "workspace_registration_update_preflight",
        "workspace_registration_update",
        "workspace_platform_profile_register_preflight",
        "workspace_platform_profile_register",
        "workspace_project_policy_get",
        "workspace_project_policy_update",
        "workspace_promote_development",
        "workspace_project_create",
    ),
    "development": (
        "workspace_request_development_session_attach",
        "workspace_attach_development_session",
        "workspace_create_worktree",
        "context_pack",
        "semantic_code_query",
        "workspace_profile",
        "director_baseline_snapshot",
    ),
    "files_changes": (
        "list_dir",
        "host_file_preflight",
        "host_file_apply",
        "patch_preflight",
        "patch_revert_preflight",
        "patch_revert",
    ),
    "git_delivery": (
        "git_blame",
        "git_stage_preflight",
        "git_stage",
        "git_stage_paths_preflight",
        "git_stage_paths",
        "git_stage_hunks_preflight",
        "git_stage_hunks",
        "git_verified_commit_preflight",
        "git_verified_commit",
        "git_workflow_preflight",
        "git_workflow_apply",
        "github_workflow_read",
        "github_workflow_preflight",
        "github_workflow_apply",
    ),
    "verification_tasks": (
        "arbitrary_command_preflight",
        "arbitrary_command_run",
        "orchestration_plan",
    ),
    "desktop_profiles": (
        "command_profile_list",
        "command_profile_preflight",
        "command_profile_run",
        "dependency_change_preflight",
        "dependency_apply",
        "dependency_audit",
        "credential_slot_list",
        "credential_slot_preflight",
    ),
    "governance": (
        "director_audit_log",
        "director_usage",
        "director_task_ledger",
        "director_writer_lease",
        "security_audit",
        "director_review",
        "director_plan_work",
        "director_claim_task",
        "director_dispatch_status",
    ),
}

REGISTRY_SHARD_BY_CATEGORY: Mapping[str, str] = {
    "platform_runtime": "platform_integrations",
    "workspace": "development",
    "development": "development",
    "files_changes": "files_changes",
    "git_delivery": "delivery",
    "verification_tasks": "verification",
    "desktop_profiles": "platform_integrations",
    "governance": "governance_security",
}

REGISTRY_CATEGORY_BY_TOOL: Mapping[str, str] = {
    name: category
    for category, names in REGISTRY_CATEGORY_TOOL_GROUPS.items()
    for name in names
}

REGISTRY_TOOL_NAMES = tuple(
    name
    for names in REGISTRY_CATEGORY_TOOL_GROUPS.values()
    for name in names
)

REGISTRY_REPLACEMENTS: Mapping[str, str] = {
    "workspace_platform_profile_register_preflight": "platform.profile.register",
    "workspace_platform_profile_register": "platform.profile.register",
}


def registry_category(tool_name: str) -> str:
    try:
        return REGISTRY_CATEGORY_BY_TOOL[tool_name]
    except KeyError as exc:
        raise ValueError(f"tool is not in stable registry inventory: {tool_name}") from exc


def registry_shard(tool_name: str) -> str:
    return REGISTRY_SHARD_BY_CATEGORY[registry_category(tool_name)]


__all__ = [
    "REGISTRY_CATEGORY_BY_TOOL",
    "REGISTRY_CATEGORY_TOOL_GROUPS",
    "REGISTRY_REPLACEMENTS",
    "REGISTRY_SHARD_BY_CATEGORY",
    "REGISTRY_TOOL_NAMES",
    "registry_category",
    "registry_shard",
]

