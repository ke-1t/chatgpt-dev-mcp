from __future__ import annotations

import json
import os
import tempfile
from io import StringIO
from pathlib import Path


def main() -> None:
    from chatgpt_dev_mcp.chatgpt_connector_compat import serve_stdio_compat
    from chatgpt_dev_mcp.observability import compare_client_observation
    from chatgpt_dev_mcp.server import WrapperRuntime
    from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES, STABLE_SURFACE_REVISION

    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-schema-health-") as temp:
        root = Path(temp)
        home = root / "home"
        (home / "Developer").mkdir(parents=True)
        config = home / ".config" / "local-dev-mcp" / "config.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {},
                }
            ),
            encoding="utf-8",
        )
        previous = {key: os.environ.get(key) for key in ("HOME", "LOCAL_DEV_MCP_CONFIG", "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL")}
        os.environ["HOME"] = str(home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
        os.environ["LOCAL_DEV_MCP_TUNNEL_HEALTH_URL"] = "disabled"
        try:
            requests = "\n".join(
                [
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}),
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "server_info", "arguments": {}}}),
                ]
            ) + "\n"
            output = StringIO()
            serve_stdio_compat(WrapperRuntime(), input_stream=StringIO(requests), output_stream=output)
            responses = [json.loads(line) for line in output.getvalue().splitlines()]
            by_id = {response.get("id"): response for response in responses}
            tools = by_id[2]["result"]["tools"]
            info = by_id[3]["result"]["structuredContent"]
            names = {item["name"] for item in tools}
            assert len(tools) == 52 and names == set(STABLE_PUBLIC_TOOL_NAMES), names
            assert "exec_command" not in names and {"git_commit_preflight", "git_commit", "git_push_preflight", "git_push"} <= names, names
            assert {
                "workspace_session_diff",
                "workspace_integration_preflight",
                "workspace_integrate_development_session",
                "capability_catalog",
                "capability_describe",
                "capability_preflight",
                "capability_execute",
            } <= names, names
            assert info["tool_schema"]["revision"] == STABLE_SURFACE_REVISION, info
            assert info["tool_schema"]["count"] == 52, info
            assert info["health"]["schema_revision"] == "health-v1", info
            assert info["health"]["schema_consistency"]["status"] == "consistent", info
            assert info["health"]["tunnel"]["status"] == "unknown", info
            local_schema = info["tool_schema"]
            stale_schema = dict(local_schema)
            stale_schema["count"] = 23
            assert compare_client_observation(local_schema, stale_schema) == "mismatched"
            assert all(response.get("method") != "notifications/tools/list_changed" for response in responses)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    print("smoke_schema_health: PASS")


if __name__ == "__main__":
    main()
