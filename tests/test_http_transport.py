from __future__ import annotations

import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


RUN_LIVE_TESTS = os.environ.get("DEVMCP_RUN_LIVE_TESTS") == "1"


def _request(
    port: int,
    payload: dict[str, object] | None = None,
    *,
    session_id: str | None = None,
    method: str = "POST",
    path: str = "/mcp",
) -> tuple[int, dict[str, str], dict[str, object] | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Accept": "application/json, text/event-stream"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    else:
        body = b""
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    parsed = json.loads(raw.decode("utf-8")) if raw else None
    return response.status, dict(response.headers), parsed


def _initialize(port: int, request_id: str, *, path: str = "/mcp") -> tuple[str, dict[str, object]]:
    status, headers, response = _request(
        port,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "http-test", "version": "1"},
            },
        },
        path=path,
    )
    assert status == 200, response
    assert response is not None
    session_id = headers.get("Mcp-Session-Id")
    assert session_id
    return session_id, response


def _call(port: int, session_id: str, request_id: str, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    status, _headers, response = _request(
        port,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
        session_id=session_id,
    )
    assert status == 200, response
    assert response is not None
    return response


class HttpTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        from chatgpt_dev_mcp.transport_http import WrapperMCPHTTPServer

        self.temp = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-http-")
        self.home = Path(self.temp.name) / "home"
        developer = self.home / "Developer"
        developer.mkdir(parents=True)
        self.repo = developer / "repo-a"
        self.repo.mkdir()
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "HTTP Test"], check=True)
        (self.repo / "README.md").write_text("http fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "fixture"], check=True)
        self.config = self.home / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {"repo-a": {"path": str(self.repo), "profile": "READ_ONLY"}},
                }
            ),
            encoding="utf-8",
        )
        self.previous_home = os.environ.get("HOME")
        self.previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        os.environ["HOME"] = str(self.home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)
        self.server = WrapperMCPHTTPServer(("127.0.0.1", 0), max_sessions=8, session_ttl_seconds=3600)
        self.thread = threading.Thread(target=self.server.serve_forever, name="http-mcp-test", daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def test_non_loopback_bind_is_rejected(self) -> None:
        from chatgpt_dev_mcp.transport_http import WrapperMCPHTTPServer

        with self.assertRaises(ValueError):
            WrapperMCPHTTPServer(("0.0.0.0", 0))

    def test_health_and_ready_endpoints_report_http_schema(self) -> None:
        status, _headers, health = _request(self.port, method="GET", path="/healthz")
        self.assertEqual(status, 200)
        assert health is not None
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["transport"], "http")
        self.assertEqual(health["active_sessions"], 0)
        self.assertEqual(health["schema_revision"], "tool-registry-v25-stable")
        self.assertEqual(health["schema_count"], 52)
        self.assertRegex(health["schema_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(health["schema_consistency"], "consistent")
        self.assertEqual(health["registry_status"], "valid")
        self.assertEqual(health["runtime_status"], "alive")

        status, _headers, ready = _request(self.port, method="GET", path="/readyz")
        self.assertEqual(status, 200)
        assert ready is not None
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(ready["transport"], "http")

    def test_ready_endpoint_rechecks_local_registry_after_startup(self) -> None:
        self.config.write_text("{\"version\":", encoding="utf-8")
        status, _headers, response = _request(self.port, method="GET", path="/readyz")
        self.assertEqual(status, 503)
        assert response is not None
        self.assertEqual(response["status"], "not_ready")
        self.assertEqual(response["reason"], "registry_invalid")

    def test_ready_endpoint_fails_closed_when_session_manager_is_closed(self) -> None:
        self.server.sessions.close()
        status, _headers, health = _request(self.port, method="GET", path="/healthz")
        self.assertEqual(status, 200)
        assert health is not None
        self.assertEqual(health["status"], "unhealthy")
        self.assertEqual(health["reason"], "session_manager_closed")

        status, _headers, response = _request(self.port, method="GET", path="/readyz")
        self.assertEqual(status, 503)
        assert response is not None
        self.assertEqual(response["status"], "not_ready")
        self.assertEqual(response["reason"], "session_manager_closed")

    def test_ready_endpoint_fails_closed_for_invalid_registry(self) -> None:
        from chatgpt_dev_mcp.transport_http import WrapperMCPHTTPServer

        self.config.write_text("{\"version\":", encoding="utf-8")
        server = WrapperMCPHTTPServer(("127.0.0.1", 0), max_sessions=2)
        thread = threading.Thread(target=server.serve_forever, name="http-invalid-registry", daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            status, _headers, response = _request(port, method="GET", path="/readyz")
            self.assertEqual(status, 503)
            assert response is not None
            self.assertEqual(response["status"], "not_ready")
            self.assertEqual(response["reason"], "registry_invalid")
            self.assertEqual(response["registry_status"], "invalid")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.previous_home
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        self.temp.cleanup()

    def test_two_sessions_have_independent_runtime_and_policy_surface(self) -> None:
        session_a, init_a = _initialize(self.port, "a-init")
        session_b, init_b = _initialize(self.port, "b-init")
        self.assertNotEqual(session_a, session_b)
        self.assertTrue(init_a["result"]["capabilities"]["tools"]["listChanged"])
        self.assertTrue(init_b["result"]["capabilities"]["tools"]["listChanged"])
        self.assertEqual(self.server.sessions.get(session_a).runtime.telemetry._base_properties["transport"], "http")
        self.assertEqual(self.server.sessions.get(session_b).runtime.telemetry._base_properties["transport"], "http")

        for session_id, request_id in ((session_a, "a-list"), (session_b, "b-list")):
            status, _headers, response = _request(
                self.port,
                {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}},
                session_id=session_id,
            )
            self.assertEqual(status, 200)
            assert response is not None
            names = {item["name"] for item in response["result"]["tools"]}
            self.assertEqual(len(names), 52)
            self.assertTrue(
                {
                    "exec_command",
                    "commit",
                    "push",
                    "merge",
                    "reset",
                    "checkout",
                }.isdisjoint(names)
            )

        opened = _call(self.port, session_a, "a-open", "workspace_open", {"id": "repo-a"})
        self.assertFalse(opened["result"]["isError"])
        status, _headers, response = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "b-status", "method": "tools/call", "params": {"name": "workspace_status", "arguments": {}}},
            session_id=session_b,
        )
        self.assertEqual(status, 200)
        assert response is not None
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(response["result"]["structuredContent"]["error"]["code"], "WORKSPACE_NOT_SELECTED")

        discovered = _call(self.port, session_a, "a-discover", "workspace_discover", {"root_id": "developer"})
        candidate_id = discovered["result"]["structuredContent"]["repositories"][0]["candidate_id"]
        self.assertIsInstance(candidate_id, str)
        candidate_attempt = _call(self.port, session_b, "b-candidate", "workspace_open", {"id": candidate_id})
        self.assertTrue(candidate_attempt["result"]["isError"])
        self.assertEqual(candidate_attempt["result"]["structuredContent"]["error"]["code"], "DISCOVERY_CANDIDATE_NOT_FOUND")

    def test_hidden_registry_mutations_are_not_callable_over_http(self) -> None:
        session_id, _ = _initialize(self.port, "hidden-init")
        target = self.home / "Developer" / "direct-http-project"
        before = self.config.read_bytes()
        project_params = {
            "project_id": "direct-http-project",
            "directory_name": "direct-http-project",
            "root_id": "developer",
            "initialize_git": True,
            "project_type": "EMPTY",
        }
        for name, arguments in (
            ("workspace_project_create", project_params),
            (
                "workspace_project_policy_update",
                {
                    "workspace_id": "fixture",
                    "expected_config_digest": "0" * 64,
                    "isolated_development": {"auto_resume_sessions": True},
                },
            ),
        ):
            response = _call(self.port, session_id, f"hidden-{name}", name, arguments)
            self.assertTrue(response["result"]["isError"], response)
            self.assertEqual(response["result"]["structuredContent"]["error"]["code"], "POLICY_HIDDEN")
        self.assertFalse(target.exists())
        self.assertEqual(self.config.read_bytes(), before)

    def test_connection_observability_tracks_http_lifecycle_without_raw_session_ids(self) -> None:
        session_id, _ = _initialize(self.port, "obs-init")
        created = self.server.connection_observability.snapshot(session_id)
        assert created is not None
        self.assertEqual(created["connection_epoch"], 1)
        self.assertIsNotNone(created["last_initialize_at"])
        self.assertIsNone(created["last_list_tools_at"])
        self.assertIsNone(created["last_tool_call_at"])
        self.assertNotIn(session_id, repr(created))

        status, _headers, listed = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "obs-list", "method": "tools/list", "params": {}},
            session_id=session_id,
        )
        self.assertEqual(status, 200)
        assert listed is not None
        after_list = self.server.connection_observability.snapshot(session_id)
        assert after_list is not None
        self.assertIsNotNone(after_list["last_list_tools_at"])
        self.assertIsNotNone(after_list["schema_advertised_at"])
        self.assertEqual(after_list["registry_revision"], self.server.schema_diagnostics["tool_schema"]["revision"])
        self.assertEqual(after_list["schema_hash"], self.server.schema_diagnostics["tool_schema"]["hash"])
        self.assertEqual(after_list["tool_count"], self.server.schema_diagnostics["tool_schema"]["count"])

        response = _call(self.port, session_id, "obs-call", "workspace_status")
        self.assertIn("result", response)
        after_call = self.server.connection_observability.snapshot(session_id)
        assert after_call is not None
        self.assertIsNotNone(after_call["last_tool_call_at"])

        status, _headers, deleted = _request(self.port, method="DELETE", session_id=session_id)
        self.assertEqual(status, 204)
        self.assertIsNone(deleted)
        after_delete = self.server.connection_observability.snapshot(session_id)
        assert after_delete is not None
        self.assertIsNotNone(after_delete["last_disconnect_at"])
        self.assertEqual(after_delete["disconnect_reason"], "deleted_session")

    def test_v26_hidden_registry_mutations_are_not_callable_over_http(self) -> None:
        session_id, _ = _initialize(self.port, "v26-hidden-init", path="/mcp/v26-canary")
        target = self.home / "Developer" / "direct-v26-project"
        before = self.config.read_bytes()
        project_params = {
            "project_id": "direct-v26-project",
            "directory_name": "direct-v26-project",
            "root_id": "developer",
            "initialize_git": True,
            "project_type": "EMPTY",
        }
        for name, arguments in (
            ("workspace_project_create", project_params),
            (
                "workspace_project_policy_update",
                {
                    "workspace_id": "fixture",
                    "expected_config_digest": "0" * 64,
                    "isolated_development": {"auto_resume_sessions": True},
                },
            ),
        ):
            response = _request(
                self.port,
                {
                    "jsonrpc": "2.0",
                    "id": f"v26-hidden-{name}",
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                session_id=session_id,
                path="/mcp/v26-canary",
            )[2]
            assert response is not None
            self.assertTrue(response["result"]["isError"], response)
            self.assertEqual(response["result"]["structuredContent"]["error"]["code"], "POLICY_HIDDEN")
        self.assertFalse(target.exists())
        self.assertEqual(self.config.read_bytes(), before)

    def test_v25_canary_endpoint_matches_schema_and_is_session_isolated(self) -> None:
        canonical_session, _canonical_init = _initialize(self.port, "canonical-init", path="/mcp")
        canary_session, _canary_init = _initialize(self.port, "canary-init", path="/mcp/v25-canary")
        self.assertNotEqual(canonical_session, canary_session)

        tool_sets: list[set[str]] = []
        for path, session_id, request_id in (
            ("/mcp", canonical_session, "canonical-list"),
            ("/mcp/v25-canary", canary_session, "canary-list"),
        ):
            status, _headers, response = _request(
                self.port,
                {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}},
                session_id=session_id,
                path=path,
            )
            self.assertEqual(status, 200)
            assert response is not None
            names = {item["name"] for item in response["result"]["tools"]}
            self.assertEqual(len(names), 52)
            tool_sets.append(names)
        self.assertEqual(tool_sets[0], tool_sets[1])

        status, _headers, wrong_endpoint = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "cross-canary", "method": "ping", "params": {}},
            session_id=canonical_session,
            path="/mcp/v25-canary",
        )
        self.assertEqual(status, 404)
        assert wrong_endpoint is not None
        self.assertEqual(wrong_endpoint["error"]["data"]["reason"], "unknown_session")

        status, _headers, wrong_endpoint = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "cross-canonical", "method": "ping", "params": {}},
            session_id=canary_session,
            path="/mcp",
        )
        self.assertEqual(status, 404)
        assert wrong_endpoint is not None
        self.assertEqual(wrong_endpoint["error"]["data"]["reason"], "unknown_session")

        status, _headers, lookalike = _request(
            self.port,
            {
                "jsonrpc": "2.0",
                "id": "lookalike-init",
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "clientInfo": {"name": "http-test", "version": "1"}},
            },
            path="/mcp/v25-canary/",
        )
        self.assertEqual(status, 404)
        self.assertIsNone(lookalike)

    @unittest.skipUnless(
        RUN_LIVE_TESTS,
        "set DEVMCP_RUN_LIVE_TESTS=1 to exercise the host-managed v26 canary",
    )
    def test_v26_canary_endpoint_advertises_distinct_narrow_surface(self) -> None:
        v26_session, _v26_init = _initialize(self.port, "v26-init", path="/mcp/v26-canary")
        self.assertIn("v26c_", v26_session)

        status, _headers, response = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "v26-list", "method": "tools/list", "params": {}},
            session_id=v26_session,
            path="/mcp/v26-canary",
        )
        self.assertEqual(status, 200)
        assert response is not None
        names = {item["name"] for item in response["result"]["tools"]}
        self.assertEqual(len(names), 76)
        self.assertNotIn("run_task", names)
        self.assertNotIn("desktop_runtime", names)
        self.assertNotIn("browser_test_session", names)
        self.assertNotIn("browser_action", names)
        self.assertIn("run_tests", names)
        self.assertIn("desktop_runtime_status", names)
        self.assertIn("browser_session_start", names)
        self.assertIn("browser_navigate", names)
        self.assertIn("browser_click", names)
        self.assertIn("security_audit", names)
        self.assertNotIn("git_verified_commit", names)
        self.assertIn("doctor_connection", names)

        status, _headers, security_audit = _request(
            self.port,
            {
                "jsonrpc": "2.0",
                "id": "v26-security-audit",
                "method": "tools/call",
                "params": {"name": "security_audit", "arguments": {"workspace_id": "repo-a"}},
            },
            session_id=v26_session,
            path="/mcp/v26-canary",
        )
        self.assertEqual(status, 200)
        assert security_audit is not None
        self.assertFalse(security_audit["result"].get("isError", False), security_audit)

        status, _headers, audit_log = _request(
            self.port,
            {
                "jsonrpc": "2.0",
                "id": "v26-audit-log",
                "method": "tools/call",
                "params": {"name": "director_audit_log", "arguments": {"limit": 1}},
            },
            session_id=v26_session,
            path="/mcp/v26-canary",
        )
        self.assertEqual(status, 200)
        assert audit_log is not None
        self.assertTrue(audit_log["result"].get("isError", False), audit_log)
        self.assertEqual(audit_log["result"]["structuredContent"]["error"]["code"], "POLICY_HIDDEN")

        observation = self.server.connection_observability.snapshot(v26_session)
        assert observation is not None
        self.assertEqual(observation["transport_generation"], "http-v26-canary")
        self.assertEqual(observation["registry_revision"], "tool-registry-v26-canary")
        self.assertEqual(observation["tool_count"], 76)
        self.assertEqual(self.server.v26_schema_diagnostics["status"], "consistent")
        self.assertEqual(
            self.server.v26_schema_diagnostics["schema_consistency"]["local_tool_schema"]["revision"],
            "tool-registry-v26-canary",
        )
        self.assertEqual(
            self.server.v26_schema_diagnostics["schema_consistency"]["listed_tool_schema"]["revision"],
            "tool-registry-v26-canary",
        )

        status, _headers, doctor = _request(
            self.port,
            {
                "jsonrpc": "2.0",
                "id": "v26-doctor",
                "method": "tools/call",
                "params": {"name": "doctor_connection", "arguments": {}},
            },
            session_id=v26_session,
            path="/mcp/v26-canary",
        )
        self.assertEqual(status, 200)
        assert doctor is not None
        self.assertEqual(doctor["result"]["structuredContent"]["failure_class"], "HEALTHY")

    def test_v26_request_lifecycle_events_pin_schema_and_http_connection_identity(self) -> None:
        from chatgpt_dev_mcp.v26_surface import V26_SURFACE_REVISION

        v26_session, _ = _initialize(self.port, "v26-audit-init", path="/mcp/v26-canary")
        request_id = f"v26-http-audit-{v26_session}"
        status, _headers, response = _request(
            self.port,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": "workspace_list", "arguments": {}},
            },
            session_id=v26_session,
            path="/mcp/v26-canary",
        )
        self.assertEqual(status, 200)
        assert response is not None
        self.assertFalse(response["result"].get("isError", False), response)

        record = self.server.v26_canary_sessions.get(v26_session)
        runtime = getattr(record.runtime, "_runtime", record.runtime)
        events = runtime._persistence.load_request_lifecycle_events(request_id=request_id, limit=20)
        self.assertTrue(events)
        schema = self.server.v26_schema_diagnostics["tool_schema"]
        self.assertTrue(all(event["server_schema_revision"] == V26_SURFACE_REVISION for event in events))
        self.assertTrue(all(event["server_schema_hash"] == schema["hash"] for event in events))
        self.assertTrue(all(event["transport_generation"] == 1 for event in events))
        self.assertTrue(all(event["child_instance_id"] == runtime.child_instance_id for event in events))
        self.assertTrue(all(event["logical_connection_id"] == f"http-session:{v26_session}" for event in events))

    def test_unknown_expired_deleted_and_duplicate_initialize_fail_closed(self) -> None:
        session_id, _ = _initialize(self.port, "init")
        status, _headers, duplicate = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "duplicate", "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
            session_id=session_id,
        )
        self.assertEqual(status, 400)
        assert duplicate is not None
        self.assertEqual(duplicate["error"]["code"], -32600)

        status, _headers, unknown = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "unknown", "method": "ping", "params": {}},
            session_id="mcp-unknown-session",
        )
        self.assertEqual(status, 404)
        assert unknown is not None
        self.assertEqual(unknown["error"]["data"]["reason"], "unknown_session")

        status, _headers, deleted = _request(self.port, method="DELETE", session_id=session_id)
        self.assertEqual(status, 204)
        self.assertIsNone(deleted)
        status, _headers, after_delete = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "after-delete", "method": "ping", "params": {}},
            session_id=session_id,
        )
        self.assertEqual(status, 404)
        assert after_delete is not None
        self.assertEqual(after_delete["error"]["data"]["reason"], "deleted_session")

    def test_session_expiry_is_rejected(self) -> None:
        self.server.sessions.ttl_seconds = 0
        session_id, _ = _initialize(self.port, "expire")
        time.sleep(0.01)
        status, _headers, response = _request(
            self.port,
            {"jsonrpc": "2.0", "id": "expired", "method": "ping", "params": {}},
            session_id=session_id,
        )
        self.assertEqual(status, 404)
        assert response is not None
        self.assertEqual(response["error"]["data"]["reason"], "expired_session")
        self.assertEqual(self.server.sessions.active_count, 0)

    def test_retired_session_history_is_bounded_and_evicted_ids_fail_closed(self) -> None:
        from chatgpt_dev_mcp.transport_http import HTTPTransportError, WrapperHTTPSessionManager

        class FakeRuntime:
            def close(self) -> None:
                return None

        manager = WrapperHTTPSessionManager(
            runtime_factory=FakeRuntime,
            max_sessions=4,
            session_ttl_seconds=60,
            max_retired_session_ids=2,
        )
        records = [manager.create() for _ in range(3)]
        for record in records:
            self.assertTrue(manager.delete(record.session_id))

        self.assertEqual(manager.active_count, 0)
        self.assertLessEqual(len(manager._retired), 2)
        with self.assertRaises(HTTPTransportError) as raised:
            manager.get(records[0].session_id)
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.reason, "unknown_session")
        self.assertEqual(manager.retired_reason(records[0].session_id), "unknown_session")

    def test_default_http_session_ttl_is_ten_minutes(self) -> None:
        from chatgpt_dev_mcp.transport_http import DEFAULT_HTTP_SESSION_TTL_SECONDS

        self.assertEqual(DEFAULT_HTTP_SESSION_TTL_SECONDS, 10 * 60)

    def test_session_count_limit_fails_closed_when_all_sessions_are_busy(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.transport_http as transport_http

        session_id, _ = _initialize(self.port, "limit-a")
        runtime = self.server.sessions.get(session_id).runtime
        self.server.sessions.max_sessions = 1
        original_dispatch = transport_http.dispatch_rpc
        entered = threading.Event()
        release = threading.Event()
        result: list[tuple[int, dict[str, str], dict[str, object] | None]] = []

        def dispatch_with_busy_session(candidate_runtime, request):
            if candidate_runtime is runtime and request.get("method") == "ping":
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("test release timeout")
            return original_dispatch(candidate_runtime, request)

        with patch.object(transport_http, "dispatch_rpc", side_effect=dispatch_with_busy_session):
            busy = threading.Thread(
                target=lambda: result.append(
                    _request(
                        self.port,
                        {"jsonrpc": "2.0", "id": "limit-busy", "method": "ping", "params": {}},
                        session_id=session_id,
                    )
                ),
                daemon=True,
            )
            busy.start()
            self.assertTrue(entered.wait(1))
            status, _headers, response = _request(
                self.port,
                {
                    "jsonrpc": "2.0",
                    "id": "limit-b",
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25"},
                },
            )
            release.set()
            busy.join(timeout=3)

        self.assertFalse(busy.is_alive())
        self.assertEqual(result[0][0], 200)
        self.assertEqual(status, 429)
        assert response is not None
        self.assertEqual(response["error"]["data"]["reason"], "session_limit")
        self.assertEqual(self.server.sessions.active_count, 1)

    def test_session_count_limit_evicts_oldest_idle_session_but_keeps_busy_session(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.transport_http as transport_http

        self.server.sessions.max_sessions = 2
        session_a, _ = _initialize(self.port, "capacity-a")
        runtime_a = self.server.sessions.get(session_a).runtime
        original_dispatch = transport_http.dispatch_rpc
        entered = threading.Event()
        release = threading.Event()
        result: list[tuple[int, dict[str, str], dict[str, object] | None]] = []

        def dispatch_with_busy_session(runtime, request):
            if runtime is runtime_a and request.get("method") == "ping":
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("test release timeout")
            return original_dispatch(runtime, request)

        with patch.object(transport_http, "dispatch_rpc", side_effect=dispatch_with_busy_session):
            busy = threading.Thread(
                target=lambda: result.append(
                    _request(
                        self.port,
                        {"jsonrpc": "2.0", "id": "capacity-busy", "method": "ping", "params": {}},
                        session_id=session_a,
                    )
                ),
                daemon=True,
            )
            busy.start()
            self.assertTrue(entered.wait(1))
            session_b, _ = _initialize(self.port, "capacity-b")
            session_c, _ = _initialize(self.port, "capacity-c")
            release.set()
            busy.join(timeout=3)

        self.assertFalse(busy.is_alive())
        self.assertEqual(result[0][0], 200)
        self.assertEqual(self.server.sessions.active_count, 2)
        self.assertEqual(self.server.sessions.retired_reason(session_b), "capacity_evicted_session")
        self.assertEqual(self.server.sessions.retired_reason(session_a), "unknown_session")
        self.assertIs(self.server.sessions.get(session_a).runtime, runtime_a)
        self.assertNotEqual(session_c, session_b)

    def test_session_creation_rate_limit_fails_closed(self) -> None:
        from chatgpt_dev_mcp.transport_http import HTTPTransportError, WrapperHTTPSessionManager

        class FakeRuntime:
            def close(self) -> None:
                return None

        manager = WrapperHTTPSessionManager(
            runtime_factory=FakeRuntime,
            max_sessions=2,
            session_ttl_seconds=60,
            max_session_creations=1,
            session_creation_window_seconds=60,
        )
        first = manager.create()
        self.assertTrue(manager.delete(first.session_id))
        with self.assertRaises(HTTPTransportError) as raised:
            manager.create()
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(raised.exception.reason, "session_creation_limit")

    def test_http_limits_require_bounded_timeout_and_inflight_capacity(self) -> None:
        from chatgpt_dev_mcp.transport_http import WrapperMCPHTTPServer

        with self.assertRaises(ValueError):
            WrapperMCPHTTPServer(("127.0.0.1", 0), request_timeout_seconds=0)
        with self.assertRaises(ValueError):
            WrapperMCPHTTPServer(("127.0.0.1", 0), max_inflight=0)
        self.assertGreater(self.server.request_timeout_seconds, 0)
        self.assertGreaterEqual(self.server.max_inflight, 1)

    def test_max_inflight_requests_fail_closed(self) -> None:
        for _ in range(self.server.max_inflight):
            self.server._inflight.acquire()
        try:
            status, _headers, response = _request(self.port, method="GET", path="/healthz")
        finally:
            for _ in range(self.server.max_inflight):
                self.server._inflight.release()
        self.assertEqual(status, 503)
        assert response is not None
        self.assertEqual(response["error"]["data"]["reason"], "inflight_limit")

    def test_requests_within_one_session_are_serialized(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.transport_http as transport_http

        session_id, _ = _initialize(self.port, "mutex-init")
        original_dispatch = transport_http.dispatch_rpc
        entered = threading.Event()
        release = threading.Event()
        state_lock = threading.Lock()
        active = 0
        max_active = 0

        def dispatch_with_observation(runtime, request):
            nonlocal active, max_active
            if request.get("method") != "ping":
                return original_dispatch(runtime, request)
            with state_lock:
                active += 1
                max_active = max(max_active, active)
            entered.set()
            try:
                if not release.wait(2):
                    raise RuntimeError("test release timeout")
                return original_dispatch(runtime, request)
            finally:
                with state_lock:
                    active -= 1

        results: list[tuple[int, dict[str, str], dict[str, object] | None]] = []
        with patch.object(transport_http, "dispatch_rpc", side_effect=dispatch_with_observation):
            first = threading.Thread(target=lambda: results.append(_request(self.port, {"jsonrpc": "2.0", "id": "mutex-a", "method": "ping", "params": {}}, session_id=session_id)), daemon=True)
            second = threading.Thread(target=lambda: results.append(_request(self.port, {"jsonrpc": "2.0", "id": "mutex-b", "method": "ping", "params": {}}, session_id=session_id)), daemon=True)
            first.start()
            self.assertTrue(entered.wait(1))
            second.start()
            time.sleep(0.1)
            self.assertTrue(second.is_alive())
            release.set()
            first.join(timeout=3)
            second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(max_active, 1)
        self.assertEqual({item[0] for item in results}, {200})

    def test_read_only_requests_retry_once_after_upstream_transport_failure(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.transport_http as transport_http

        session_id, _ = _initialize(self.port, "recovery-init")
        original_dispatch = transport_http.dispatch_rpc
        calls = 0

        def flaky_dispatch(runtime, request):
            nonlocal calls
            if request.get("method") == "ping" and calls == 0:
                calls += 1
                raise ConnectionError("fixture upstream disconnect")
            calls += 1
            return original_dispatch(runtime, request)

        with patch.object(transport_http, "dispatch_rpc", side_effect=flaky_dispatch):
            status, _headers, response = _request(
                self.port,
                {"jsonrpc": "2.0", "id": "recovery-ping", "method": "ping", "params": {}},
                session_id=session_id,
            )

        self.assertEqual(status, 200)
        self.assertIsNotNone(response)
        self.assertEqual(calls, 2)

    def test_schema_health_and_surface_match_for_concurrent_sessions(self) -> None:
        def initialize_and_list(index: int) -> tuple[str, int, str, str]:
            session_id, _ = _initialize(self.port, f"parallel-{index}")
            status, _headers, response = _request(
                self.port,
                {"jsonrpc": "2.0", "id": f"list-{index}", "method": "tools/list", "params": {}},
                session_id=session_id,
            )
            assert status == 200 and response is not None
            tools = response["result"]["tools"]
            info = _call(self.port, session_id, f"info-{index}", "server_info")
            structured = info["result"]["structuredContent"]
            return session_id, len(tools), structured["tool_schema"]["hash"], structured["health"]["schema_revision"]

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(initialize_and_list, (1, 2)))
        self.assertNotEqual(results[0][0], results[1][0])
        self.assertEqual({item[1] for item in results}, {52})
        self.assertEqual(len({item[2] for item in results}), 1)
        self.assertRegex(results[0][2], r"^[0-9a-f]{64}$")
        self.assertEqual({item[3] for item in results}, {"health-v1"})

    def test_approval_and_development_session_ids_do_not_cross_sessions(self) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "repo-a": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "true"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        session_a, _ = _initialize(self.port, "approval-a")
        session_b, _ = _initialize(self.port, "approval-b")
        discovered = _call(self.port, session_a, "approval-discover", "workspace_discover", {"root_id": "developer"})
        candidate_id = discovered["result"]["structuredContent"]["repositories"][0]["candidate_id"]
        opened = _call(self.port, session_a, "approval-open", "workspace_open", {"id": candidate_id})
        self.assertFalse(opened["result"]["isError"])
        approval = _call(
            self.port,
            session_a,
            "approval-request",
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "repo-a"},
        )
        approval_token = approval["result"]["structuredContent"]["approval_token"]
        self.assertIsInstance(approval_token, str)

        cross_session = _call(
            self.port,
            session_b,
            "approval-cross",
            "workspace_create_development_session",
            {"approval_token": approval_token, "confirmation": approval["result"]["structuredContent"]["confirmation"]},
        )
        self.assertTrue(cross_session["result"]["isError"])
        self.assertEqual(cross_session["result"]["structuredContent"]["error"]["code"], "DEVELOPMENT_APPROVAL_NOT_FOUND")

        status = _call(
            self.port,
            session_b,
            "session-cross",
            "workspace_session_status",
            {"session_id": "session:AAAAAAAAAAAAAAAAAAAA"},
        )
        self.assertTrue(status["result"]["isError"])
        self.assertEqual(status["result"]["structuredContent"]["error"]["code"], "DEVELOPMENT_SESSION_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
