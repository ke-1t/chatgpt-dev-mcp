from __future__ import annotations

import json
import re
import ast
from io import StringIO
from pathlib import Path


def main() -> None:
    from chatgpt_dev_mcp.chatgpt_connector_compat import serve_stdio_compat
    from chatgpt_dev_mcp.server import WrapperRuntime
    from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES, STABLE_SURFACE_REVISION

    runtime = WrapperRuntime()
    try:
        initialized = runtime.initialize()
        tools = runtime.list_tools().get("tools", [])
        names = [item.get("name") for item in tools if isinstance(item, dict)]
        info = runtime.call_tool("server_info", {})["structuredContent"]
    finally:
        runtime.close()

    dangerous = {
        "exec_command",
        "write_stdin",
        "kill_session",
        "git_merge",
        "git_rebase",
        "git_reset",
        "git_checkout",
        "git_branch_delete",
        "force_cleanup",
    }
    required = {
        "workspace_register_preflight",
        "workspace_register",
        "workspace_unregister_preflight",
        "workspace_unregister",
        "workspace_registration_update_preflight",
        "workspace_registration_update",
        "workspace_platform_profile_register_preflight",
        "workspace_platform_profile_register",
        "workspace_discover",
        "workspace_promote_development",
        "workspace_project_create",
        "workspace_request_development",
        "workspace_create_development_session",
        "workspace_request_development_session_attach",
        "workspace_attach_development_session",
        "workspace_list_development_sessions",
        "workspace_session_status",
        "workspace_close_development_session",
        "workspace_project_policy_get",
        "workspace_project_policy_update",
        "readonly_path",
        "list_allowed_files",
        "read_allowed_file",
        "search_allowed_files",
        "director_health",
        "director_usage",
        "context_pack",
        "patch_preflight",
        "workspace_profile",
        "verification_plan",
        "verification_record",
        "director_task_ledger",
        "director_writer_lease",
        "security_audit",
        "orchestration_plan",
        "workspace_session_diff",
        "workspace_integration_preflight",
        "workspace_integrate_development_session",
        "git_commit_preflight",
        "git_commit",
        "git_push_preflight",
        "git_push",
        "git_workflow_preflight",
        "git_workflow_apply",
        "github_workflow_read",
        "github_workflow_preflight",
        "github_workflow_apply",
        "command_profile_list",
        "command_profile_preflight",
        "command_profile_run",
        "dependency_change_preflight",
        "dependency_apply",
        "dependency_audit",
        "browser_test_session",
        "browser_inspect",
        "browser_action",
        "desktop_runtime",
        "director_review",
        "patch_revert_preflight",
        "patch_revert",
        "credential_slot_list",
        "credential_slot_preflight",
        "director_plan_work",
        "director_claim_task",
        "director_dispatch_status",
    }
    public_names = set(names)
    assert len(names) == 52 and public_names == set(STABLE_PUBLIC_TOOL_NAMES), names
    registry_required = required - public_names
    registry_runtime = WrapperRuntime()
    try:
        for capability_id in sorted(registry_required):
            described = registry_runtime.call_tool(
                "capability_describe",
                {"capability_id": capability_id},
            )
            assert not described.get("isError"), (capability_id, described)
            assert described["structuredContent"]["exposure"] == "registry", capability_id
    finally:
        registry_runtime.close()
    assert not dangerous & set(names), sorted(dangerous & set(names))
    by_name = {item["name"]: item for item in tools if isinstance(item, dict) and isinstance(item.get("name"), str)}
    for preflight_name in ("git_commit_preflight", "git_push_preflight"):
        annotations = by_name[preflight_name]["annotations"]
        assert annotations["readOnlyHint"] is True and annotations["destructiveHint"] is False and annotations["idempotentHint"] is False
    commit_annotations = by_name["git_commit"]["annotations"]
    push_annotations = by_name["git_push"]["annotations"]
    assert commit_annotations["readOnlyHint"] is False and commit_annotations["destructiveHint"] is True
    assert push_annotations["readOnlyHint"] is False and push_annotations["destructiveHint"] is True and push_annotations["openWorldHint"] is True
    git_source = Path(__file__).resolve().parents[1] / "src" / "chatgpt_dev_mcp" / "git_write.py"
    literal_values = {
        node.value
        for node in ast.walk(ast.parse(git_source.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not literal_values & {"--force", "--force-with-lease", "--amend", "--no-verify", "--delete", "--mirror", "--tags"}
    assert "--porcelain" in literal_values and "commit" in literal_values and "--message" in literal_values
    assert initialized["capabilities"]["tools"]["listChanged"] is True
    assert info["tool_schema"]["count"] == 52
    assert info["tool_schema"]["revision"] == STABLE_SURFACE_REVISION
    assert re.fullmatch(r"[0-9a-f]{64}", info["tool_schema"]["hash"])
    assert info["health"]["schema_revision"] == "health-v1"
    assert info["health"]["schema_consistency"]["status"] == "consistent"

    requests = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        ]
    ) + "\n"
    output = StringIO()
    serve_stdio_compat(__import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime(), input_stream=StringIO(requests), output_stream=output)
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    listed = next(response for response in responses if response.get("id") == 2)["result"]["tools"]
    assert len(listed) == 52
    assert all(response.get("method") != "notifications/tools/list_changed" for response in responses)

    print(
        json.dumps(
            {
                "status": "PASS",
                "tool_count": len(names),
                "schema": info["tool_schema"],
                "health": {
                    "schema_revision": info["health"]["schema_revision"],
                    "status": info["health"]["status"],
                    "schema_consistency": info["health"]["schema_consistency"]["status"],
                    "tunnel": info["health"]["tunnel"]["status"],
                },
                "list_changed": initialized["capabilities"]["tools"]["listChanged"],
                "notification_shim": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
