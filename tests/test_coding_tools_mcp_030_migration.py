from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from coding_tools_mcp.errors import JsonRpcError
from coding_tools_mcp.protocol import dispatch_rpc
from coding_tools_mcp.server import Runtime
from coding_tools_mcp.telemetry import SessionTelemetry


class CodingToolsMcp030MigrationTests(unittest.TestCase):
    def _runtime(self) -> tuple[tempfile.TemporaryDirectory[str], Runtime, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="coding-tools-mcp-030-")
        workspace = Path(temporary.name) / "workspace"
        (workspace / "nested").mkdir(parents=True)
        runtime = Runtime(workspace)
        return temporary, runtime, workspace

    def test_runtime_uses_command_contract_and_real_telemetry(self) -> None:
        temporary, runtime, _workspace = self._runtime()
        try:
            self.assertIsInstance(runtime.telemetry, SessionTelemetry)
            names = set(runtime.exposed_tool_names())
            self.assertIn("kill_command", names)
            self.assertIn("write_stdin", names)
            self.assertIn("read_output", names)
            self.assertNotIn("kill_session", names)
            self.assertNotIn("get_default_cwd", names)
            self.assertNotIn("set_default_cwd", names)

            initialized = dispatch_rpc(
                runtime,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25"},
                },
            )
            self.assertIsNotNone(initialized)
            assert initialized is not None
            self.assertNotIn("error", initialized)
            self.assertGreaterEqual(runtime.telemetry._legacy_requests, 1)
            with self.assertRaises(JsonRpcError):
                runtime.call_tool("get_default_cwd", {})
        finally:
            runtime.close()
            temporary.cleanup()

    def test_command_id_output_refs_workspace_relative_workdir_and_continuation(self) -> None:
        temporary, runtime, workspace = self._runtime()
        try:
            started = runtime.call_tool(
                "exec_command",
                {
                    "cmd": "printf 'alpha-beta-gamma'",
                    "workdir": "nested",
                    "yield_time_ms": 30000,
                    "max_output_bytes": 6,
                },
            )
            self.assertFalse(started["isError"], started)
            payload = started["structuredContent"]
            command_id = payload["command_id"]
            self.assertIsInstance(command_id, str)
            self.assertEqual(payload["output_ref"], f"command:{command_id}:stdout")
            self.assertEqual(payload["output_refs"]["stderr"], f"command:{command_id}:stderr")

            output = runtime.call_tool(
                "read_output",
                {
                    "output_ref": payload["output_ref"],
                    "offset": 0,
                    "limit": 5,
                },
            )
            self.assertFalse(output["isError"], output)
            self.assertEqual(output["structuredContent"]["content"], "alpha")

            location = runtime.call_tool(
                "exec_command",
                {"cmd": "pwd", "workdir": "nested", "yield_time_ms": 30000},
            )
            self.assertFalse(location["isError"], location)
            self.assertTrue(location["structuredContent"]["stdout"].strip().endswith(str(workspace / "nested")))
        finally:
            runtime.close()
            temporary.cleanup()

    def test_cancel_notification_does_not_terminate_command_but_kill_command_does(self) -> None:
        temporary, runtime, _workspace = self._runtime()
        try:
            started = runtime.call_tool(
                "exec_command",
                {"cmd": "sleep 30", "yield_time_ms": 0},
            )
            self.assertFalse(started["isError"], started)
            command_id = started["structuredContent"]["command_id"]
            self.assertIn(command_id, runtime.commands)

            cancelled = dispatch_rpc(
                runtime,
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": "request-to-cancel"},
                },
            )
            self.assertIsNone(cancelled)
            self.assertIn(command_id, runtime.commands)

            stopped = runtime.call_tool(
                "kill_command",
                {"command_id": command_id, "signal": "TERM", "wait_ms": 2000},
            )
            self.assertFalse(stopped["isError"], stopped)
            self.assertIn(stopped["structuredContent"]["status"], {"terminated", "killed", "exited"})
            self.assertNotIn(command_id, runtime.commands)
        finally:
            runtime.close()
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
