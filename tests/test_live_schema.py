from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LIVE_EXECUTABLE = REPOSITORY_ROOT / ".venv" / "bin" / "chatgpt-dev-mcp"
RUN_LIVE_TESTS = os.environ.get("DEVMCP_RUN_LIVE_TESTS") == "1"
ROUTING_FIELDS = {"workspace_id", "working_tree_id", "session_id", "workspace_ref"}
GLOBAL_TOOLS = {
    "check_exec_environment",
    "server_info",
    "director_health",
    "workspace_list",
    "workspace_list_development_sessions",
}


@unittest.skipUnless(
    RUN_LIVE_TESTS and LIVE_EXECUTABLE.is_file(),
    "set DEVMCP_RUN_LIVE_TESTS=1 and install the live MCP executable",
)
class LiveSchemaTests(unittest.TestCase):
    """Exercise the installed entry point, rather than only WrapperRuntime."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-live-schema-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.workspace_a = self.home / "Developer" / "workspace-a"
        self.workspace_b = self.home / "Developer" / "workspace-b"
        for workspace, marker in ((self.workspace_a, "a"), (self.workspace_b, "b")):
            workspace.mkdir(parents=True)
            (workspace / "marker.txt").write_text(f"workspace-{marker}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(workspace), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Live Schema Test"], check=True)
            subprocess.run(["git", "-C", str(workspace), "add", "marker.txt"], check=True)
            subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "initial"], check=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "workspace-a": {"path": str(self.workspace_a), "profile": "READ_ONLY"},
                        "workspace-b": {"path": str(self.workspace_b), "profile": "READ_ONLY"},
                    },
                }
            ),
            encoding="utf-8",
        )
        self.process: subprocess.Popen[str] | None = None

    def tearDown(self) -> None:
        self._stop_process()
        self.tempdir.cleanup()

    def _start_process(self) -> subprocess.Popen[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "director-state"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CODING_TOOLS_MCP_TELEMETRY": "off",
            }
        )
        self.process = subprocess.Popen(
            [str(LIVE_EXECUTABLE)],
            cwd=str(REPOSITORY_ROOT),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return self.process

    def _response(self, request: dict[str, object]) -> dict[str, object]:
        assert self.process is not None
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=8):
                raise AssertionError(f"timed out waiting for {request.get('method')}; pid={self.process.poll()}")
        finally:
            selector.close()
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError(f"live MCP exited while handling {request.get('method')}; rc={self.process.poll()}")
        return json.loads(line)

    def _notification(self, method: str, params: dict[str, object] | None = None) -> None:
        assert self.process is not None
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(
                {"jsonrpc": "2.0", "method": method, "params": params or {}},
                separators=(",", ":"),
            )
            + "\n"
        )
        self.process.stdin.flush()

    def _stop_process(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stderr is not None:
            process.stderr.read()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    @staticmethod
    def _tool_call(name: str, arguments: dict[str, object] | None = None, request_id: int = 1) -> dict[str, object]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }

    def test_live_tools_list_matches_registry_and_global_routing_contract(self) -> None:
        from chatgpt_dev_mcp.observability import tool_schema_metadata
        from chatgpt_dev_mcp.server import WrapperRuntime

        with patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "director-state"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
            },
        ):
            runtime = WrapperRuntime()
            try:
                expected_definitions = runtime.list_tools()["tools"]
                expected_metadata = tool_schema_metadata(expected_definitions)
            finally:
                runtime.close()

            self._start_process()
            initialized = self._response(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "live-schema-regression", "version": "1"},
                    },
                }
            )
            self.assertEqual(initialized["result"]["serverInfo"]["version"], "0.41")
            self._notification("notifications/initialized")

            listed = self._response({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            live_definitions = listed["result"]["tools"]
            self.assertEqual(live_definitions, expected_definitions)
            self.assertEqual(tool_schema_metadata(live_definitions), expected_metadata)
            self.assertEqual(expected_metadata["count"], 52)
            self.assertEqual(expected_metadata["revision"], "tool-registry-v25-stable")
            self.assertRegex(expected_metadata["hash"], r"^[0-9a-f]{64}$")

            usage = self._response(
                self._tool_call(
                    "capability_describe",
                    {"capability_id": "director_usage"},
                    request_id=29,
                )
            )
            self.assertFalse(usage["result"].get("isError", False), usage)
            self.assertEqual(usage["result"]["structuredContent"]["exposure"], "registry")

            by_name = {item["name"]: item for item in live_definitions}
            for name in ("apply_patch", "run_task", "read_file", "search_text", "git_status", "git_diff"):
                self.assertTrue(ROUTING_FIELDS <= set(by_name[name]["inputSchema"]["properties"]), name)
            self.assertEqual(set(by_name["apply_patch"]["inputSchema"]["required"]), {"patch", "lease_id"})
            self.assertEqual(set(by_name["run_task"]["inputSchema"]["required"]), {"task"})
            self.assertEqual(
                set(by_name["director_development_start"]["inputSchema"]["required"]),
                {"workspace_id", "request_id", "title", "owner_id"},
            )
            for name in GLOBAL_TOOLS:
                required = set(by_name[name]["inputSchema"].get("required", []))
                self.assertFalse(required & ROUTING_FIELDS, name)

            info = self._response(self._tool_call("server_info", request_id=3))
            info_structured = info["result"]["structuredContent"]
            self.assertFalse(info["result"].get("isError", False), info)
            self.assertEqual(info_structured["tool_schema"], expected_metadata)
            self.assertEqual(info_structured["health"]["schema_consistency"]["checks"], {
                "count_match": True,
                "hash_match": True,
                "revision_match": True,
            })
            self.assertEqual(info_structured["reattach_handshake"]["status"], "available")
            self.assertRegex(info_structured["reattach_handshake"]["persistence_db_identity"], r"^[0-9a-f]{64}$")
            self.assertRegex(info_structured["reattach_handshake"]["director_generation"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                info_structured["health"]["director_persistence"]["db_identity"],
                info_structured["reattach_handshake"]["persistence_db_identity"],
            )

            unsupported = self._response(self._tool_call("director_health", request_id=28))
            unsupported_structured = unsupported["result"]["structuredContent"]
            self.assertEqual(unsupported_structured["client_schema_evidence"]["status"], "unsupported")
            self.assertEqual(
                unsupported_structured["client_schema_evidence"]["reason"],
                "CLIENT_INJECTED_SCHEMA_NOT_REPORTED_BY_MCP_TRANSPORT",
            )
            self.assertTrue(unsupported_structured["client_schema_evidence"]["safe_for_server_side_recovery"])
            for request_id in range(30, 40):
                repeated_info = self._response(self._tool_call("server_info", request_id=request_id))
                self.assertFalse(repeated_info["result"].get("isError", False), repeated_info)
            for request_id, name in enumerate(sorted(GLOBAL_TOOLS), start=40):
                response = self._response(self._tool_call(name, request_id=request_id))
                self.assertFalse(response["result"].get("isError", False), (name, response))
                if name == "check_exec_environment":
                    self.assertIsNone(response["result"]["structuredContent"]["workspace"])

            stale = self._response(
                self._tool_call(
                    "director_health",
                    {
                        "client_schema": {
                            "revision": "tool-registry-v7",
                            "count": 53,
                            "hash": "a" * 64,
                            "tools": ["workspace_list"],
                        }
                    },
                    request_id=4,
                )
            )
            stale_structured = stale["result"]["structuredContent"]
            self.assertEqual(stale_structured["schema_error_code"], "CLIENT_TOOL_SCHEMA_STALE")
            self.assertTrue(stale_structured["rescan_required"])
            self.assertEqual(stale_structured["client_schema_evidence"]["status"], "stale")
            self.assertEqual(stale_structured["watchdog"]["recommended_action"], "reconnect_and_rescan")

            self.assertFalse(self._response(self._tool_call("workspace_open", {"id": "workspace-a"}, 5))["result"].get("isError", False))
            self.assertFalse(self._response(self._tool_call("workspace_open", {"id": "workspace-b"}, 6))["result"].get("isError", False))
            for request_id, name in enumerate(sorted(GLOBAL_TOOLS), start=7):
                response = self._response(self._tool_call(name, request_id=request_id))
                self.assertFalse(response["result"].get("isError", False), (name, response))

    def test_live_reconnect_with_reused_request_id_is_connection_safe(self) -> None:
        """Exercise the long-lived child sequence used by the Secure Tunnel."""

        self._start_process()
        params = {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "live-reconnect", "version": "1"},
        }
        logical_ids: list[str] = []
        for _ in range(11):
            initialized = self._response({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params})
            self.assertNotIn("error", initialized)
            self._notification("notifications/initialized")
            for name in ("server_info", "director_health", "workspace_list"):
                response = self._response(self._tool_call(name, request_id=0))
                self.assertFalse(response["result"].get("isError", False), (name, response))
                if name == "server_info":
                    logical_ids.append(response["result"]["structuredContent"]["health"]["runtime"]["logical_connection_id"])

        initialized = self._response({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params})
        self.assertNotIn("error", initialized)
        self._notification("notifications/initialized")
        final_info = self._response(self._tool_call("server_info", request_id=0))
        runtime = final_info["result"]["structuredContent"]["health"]["runtime"]
        logical_ids.append(runtime["logical_connection_id"])
        self.assertEqual(len(logical_ids), 12)
        self.assertEqual(len(set(logical_ids)), 12)
        self.assertEqual(runtime["transport_generation"], 1)
        self.assertEqual(runtime["protocol_session_generation"], 1)

    def test_live_three_clients_do_not_share_protocol_state(self) -> None:
        """Three disposable child connections initialize independently."""

        clients = [self._spawn_process() for _ in range(3)]
        try:
            def initialize_and_probe(item: tuple[int, subprocess.Popen[str]]) -> None:
                index, process = item
                response = self._response_for_process(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {"name": f"client-{index}", "version": "1"},
                        },
                    },
                )
                self.assertNotIn("error", response)
                info = self._response_for_process(process, self._tool_call("server_info", request_id=2))
                self.assertFalse(info["result"].get("isError", False), info)
                if index == 0:
                    probe = self._tool_call("workspace_list", request_id=3)
                elif index == 1:
                    probe = self._tool_call("director_health", request_id=3)
                else:
                    return
                probe_response = self._response_for_process(process, probe)
                self.assertFalse(probe_response["result"].get("isError", False), probe_response)

            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(initialize_and_probe, enumerate(clients)))
        finally:
            for process in clients:
                self._stop_process_instance(process)

    def test_live_child_restart_starts_a_clean_protocol_generation(self) -> None:
        """A restarted executable does not inherit the previous handshake."""

        self._start_process()
        params = {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "child-restart", "version": "1"},
        }
        first = self._response({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})
        self.assertNotIn("error", first)
        self._notification("notifications/initialized")
        first_info = self._response(self._tool_call("server_info", request_id=2))
        first_runtime = first_info["result"]["structuredContent"]["health"]["runtime"]
        self._stop_process()

        self._start_process()
        second = self._response({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})
        self.assertNotIn("error", second)
        self._notification("notifications/initialized")
        second_info = self._response(self._tool_call("server_info", request_id=2))
        second_runtime = second_info["result"]["structuredContent"]["health"]["runtime"]
        self.assertEqual(first_runtime["transport_generation"], 1)
        self.assertEqual(first_runtime["protocol_session_generation"], 1)
        self.assertEqual(second_runtime["transport_generation"], 1)
        self.assertEqual(second_runtime["protocol_session_generation"], 1)
        self.assertNotEqual(first_runtime["pid"], second_runtime["pid"])

    def _spawn_process(self) -> subprocess.Popen[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "director-state"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CODING_TOOLS_MCP_TELEMETRY": "off",
            }
        )
        return subprocess.Popen(
            [str(LIVE_EXECUTABLE)],
            cwd=str(REPOSITORY_ROOT),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    @staticmethod
    def _response_for_process(process: subprocess.Popen[str], request: dict[str, object]) -> dict[str, object]:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        process.stdin.flush()
        line = process.stdout.readline()
        if not line:
            raise AssertionError(f"live MCP exited while handling {request.get('method')}; rc={process.poll()}")
        return json.loads(line)

    @staticmethod
    def _stop_process_instance(process: subprocess.Popen[str]) -> None:
        try:
            if process.stdin is not None:
                process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


if __name__ == "__main__":
    unittest.main()
