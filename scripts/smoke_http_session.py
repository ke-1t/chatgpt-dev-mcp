#!/usr/bin/env python3
"""Disposable loopback Streamable HTTP session smoke.

This script creates only a temporary HOME and Git repository.  It never reads
or modifies the production Tunnel profile, local registry, or any real project.
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from chatgpt_dev_mcp.transport_http import WrapperMCPHTTPServer


def request(
    port: int,
    payload: dict[str, object] | None = None,
    *,
    session_id: str | None = None,
    method: str = "POST",
    path: str = "/mcp",
) -> tuple[int, dict[str, str], dict[str, object] | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Accept": "application/json, text/event-stream"}
    body = b""
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    headers_out = dict(response.headers)
    connection.close()
    return response.status, headers_out, json.loads(raw.decode("utf-8")) if raw else None


def initialize(port: int, request_id: str) -> str:
    status, headers, response = request(
        port,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "clientInfo": {"name": "smoke", "version": "1"}},
        },
    )
    assert status == 200 and response is not None, response
    session_id = headers.get("Mcp-Session-Id")
    assert session_id and session_id.startswith("mcp_"), headers
    return session_id


def call(port: int, session_id: str, request_id: str, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    status, _headers, response = request(
        port,
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}},
        session_id=session_id,
    )
    assert status == 200 and response is not None, response
    return response


def main() -> int:
    previous_home = os.environ.get("HOME")
    previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
    previous_health = os.environ.get("LOCAL_DEV_MCP_TUNNEL_HEALTH_URL")
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-http-smoke-") as temp:
        home = Path(temp) / "home"
        repo = home / "Developer" / "smoke-repo"
        repo.mkdir(parents=True)
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "smoke@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "HTTP Smoke"], check=True)
        (repo / "README.md").write_text("disposable smoke\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "smoke"], check=True)
        config = home / "config.json"
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
        os.environ["HOME"] = str(home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
        os.environ["LOCAL_DEV_MCP_TUNNEL_HEALTH_URL"] = "disabled"
        server = WrapperMCPHTTPServer(("127.0.0.1", 0), max_sessions=4)
        thread = threading.Thread(target=server.serve_forever, name="http-smoke", daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            session_a = initialize(port, "a")
            session_b = initialize(port, "b")
            assert session_a != session_b
            status, _headers, health = request(port, method="GET", path="/healthz")
            assert status == 200 and health is not None
            assert health["status"] == "healthy" and health["transport"] == "http"
            assert health["active_sessions"] == 2
            assert health["schema_revision"] == "tool-registry-v25-stable"
            assert health["schema_count"] == 52
            status, _headers, ready = request(port, method="GET", path="/readyz")
            assert status == 200 and ready is not None and ready["status"] == "ready"
            tool_counts: list[int] = []
            candidates: list[str] = []
            for session_id, prefix in ((session_a, "a"), (session_b, "b")):
                status, _headers, listed = request(port, {"jsonrpc": "2.0", "id": f"{prefix}-list", "method": "tools/list", "params": {}}, session_id=session_id)
                assert status == 200 and listed is not None
                names = {item["name"] for item in listed["result"]["tools"]}
                assert len(names) == 52 and "exec_command" not in names and {"git_commit_preflight", "git_commit", "git_push_preflight", "git_push", "capability_catalog", "capability_execute"} <= names
                tool_counts.append(len(names))
                discovered = call(port, session_id, f"{prefix}-discover", "workspace_discover", {"root_id": "developer"})
                repositories = discovered["result"]["structuredContent"]["repositories"]
                candidates.append(repositories[0]["candidate_id"])
            assert tool_counts == [52, 52] and candidates[0] != candidates[1]
            info = call(port, session_a, "a-info", "server_info")
            metadata = info["result"]["structuredContent"]
            assert metadata["tool_schema"]["revision"] == "tool-registry-v25-stable"
            assert metadata["tool_schema"]["count"] == 52
            assert metadata["health"]["schema_revision"] == "health-v1"
            cross = call(port, session_b, "b-cross", "workspace_open", {"id": candidates[0]})
            assert cross["result"]["isError"]
            status, _headers, _ = request(port, method="DELETE", session_id=session_a)
            assert status == 204
            status, _headers, rejected = request(port, {"jsonrpc": "2.0", "id": "closed", "method": "ping", "params": {}}, session_id=session_a)
            assert status == 404 and rejected is not None and rejected["error"]["data"]["reason"] == "deleted_session"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive(), "HTTP server thread did not stop"
    if previous_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = previous_home
    if previous_config is None:
        os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
    else:
        os.environ["LOCAL_DEV_MCP_CONFIG"] = previous_config
    if previous_health is None:
        os.environ.pop("LOCAL_DEV_MCP_TUNNEL_HEALTH_URL", None)
    else:
        os.environ["LOCAL_DEV_MCP_TUNNEL_HEALTH_URL"] = previous_health
    print("smoke_http_session: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
