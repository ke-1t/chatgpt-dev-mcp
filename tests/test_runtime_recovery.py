from __future__ import annotations

import json
import os
import subprocess
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from typing import Callable
from unittest.mock import patch


class RuntimeRecoveryTests(unittest.TestCase):
    def _isolated_environment(self, root: Path) -> dict[str, str]:
        home = root / "home"
        config = home / ".config" / "local-dev-mcp" / "config.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"version": 1, "workspaces": {}}), encoding="utf-8")
        return {
            "HOME": str(home),
            "LOCAL_DEV_MCP_CONFIG": str(config),
            "LOCAL_DEV_MCP_DATA_DIR": str(root / "director-state"),
            "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
        }

    def test_startup_gc_exception_does_not_block_mcp_transport(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="runtime-recovery-gc-") as temp:
            root = Path(temp)
            with patch.dict(os.environ, self._isolated_environment(root), clear=False):
                with patch.object(
                    WrapperRuntime,
                    "_gc_expired_clean_sessions",
                    side_effect=ValueError("retained worktree path is malformed"),
                ):
                    runtime = WrapperRuntime()
                try:
                    self.assertEqual(runtime.last_recovery_reason, "startup_reconciliation_failed:ValueError")
                    result = runtime.call_tool("server_info", {})
                    self.assertFalse(result["isError"], result)
                    self.assertEqual(result["structuredContent"]["tool_schema"]["revision"], "tool-registry-v25-stable")
                    self.assertEqual(result["structuredContent"]["tool_schema"]["count"], 52)
                    self.assertEqual(
                        result["structuredContent"]["tool_schema"]["hash"],
                        "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
                    )
                finally:
                    runtime.close()

    def test_restart_reconciles_stale_task_and_lease_rows_without_blocking_same_session_resume(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="runtime-recovery-stale-rows-") as temp:
            root = Path(temp)
            home = root / "home"
            repo = home / "Developer" / "project-x"
            repo.mkdir(parents=True)
            (repo / "README.md").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
            config = home / ".config" / "local-dev-mcp" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "project-x": {
                                "path": str(repo),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "printf test-ok"},
                                "metadata": {
                                    "isolated_development": {
                                        "auto_create_sessions": True,
                                        "auto_resume_sessions": True,
                                        "auto_resume_policy": "same_owner_same_task_safe_local",
                                        "max_parallel_sessions": 6,
                                        "allowed_base": "registered_project",
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "director-state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(root / "worktrees"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
            }
            with patch.dict(os.environ, environment, clear=False):
                first = WrapperRuntime()
                started_result = first.call_tool(
                    "director_development_start",
                    {
                        "workspace_id": "project-x",
                        "request_id": "restart-stale-row-reconciliation",
                        "title": "restart stale row reconciliation",
                        "owner_id": "owner-restart-stale-row",
                        "paths": ["README.md"],
                        "resources": [],
                    },
                )
                self.assertFalse(started_result["isError"], started_result)
                started = started_result["structuredContent"]
                session_id = started["session_id"]
                task_id = started["task"]["task_id"]
                lease_id = started["lease_id"]
                patched = first.call_tool(
                    "apply_patch",
                    {
                        "session_id": session_id,
                        "lease_id": lease_id,
                        "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-baseline\n+restart-retained\n*** End Patch",
                    },
                )
                self.assertFalse(patched["isError"], patched)
                first.close()

                second = WrapperRuntime()
                try:
                    self.assertIsNotNone(second._persistence)
                    lease_row = next(row for row in second._persistence.load_leases() if row["lease_id"] == lease_id)
                    task_row = next(row for row in second._persistence.load_tasks() if row["task_id"] == task_id)
                    self.assertEqual(lease_row["state"], "stale")
                    self.assertEqual(task_row["state"], "stale")

                    resumed = second.call_tool(
                        "workspace_resume_development_session",
                        {
                            "session_id": session_id,
                            "owner_id": "owner-restart-stale-row",
                            "task_id": task_id,
                        },
                    )
                    self.assertFalse(resumed["isError"], resumed)
                    payload = resumed["structuredContent"]
                    self.assertEqual(payload["session_id"], session_id)
                    self.assertNotEqual(payload["lease_id"], lease_id)
                    self.assertEqual(
                        (Path(payload["worktree_path"]).expanduser() / "README.md").read_text(encoding="utf-8"),
                        "restart-retained\n",
                    )
                finally:
                    second.close()

    def test_deferred_restart_runs_only_after_stdio_response_flush(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import serve_stdio_compat
        from coding_tools_mcp.telemetry import SessionTelemetry

        events: list[tuple[str, str]] = []

        class Runtime:
            protocol_version = "2025-11-25"
            initialized = False

            def __init__(self) -> None:
                self._deferred: list[Callable[[], object]] = []
                self.telemetry = SessionTelemetry(permission_mode="safe", transport="stdio")

            def initialize(self, client_info=None, protocol_version=None):
                self.initialized = True
                return {
                    "protocolVersion": protocol_version or self.protocol_version,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "deferred", "version": "test"},
                }

            def server_identity(self):
                return {"name": "deferred", "version": "test"}

            def list_tools(self):
                return {"tools": [{"name": "restart"}]}

            def defer_after_response(self, action):
                self._deferred.append(action)

            def run_deferred_actions(self):
                actions, self._deferred = self._deferred, []
                for action in actions:
                    action()

            def call_tool(self, name, arguments, *, request_id=None, context=None):
                self.defer_after_response(lambda: events.append(("action", output.getvalue())))
                return {"structuredContent": {"status": "recovering"}}

            def close(self):
                self.telemetry.finish()

        runtime = Runtime()
        output = StringIO()
        requests = "".join(
            json.dumps(item) + "\n"
            for item in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "restart", "arguments": {}},
                },
            )
        )

        serve_stdio_compat(runtime, input_stream=StringIO(requests), output_stream=output)

        self.assertEqual(len(events), 1)
        self.assertIn('"id":2', events[0][1])
        self.assertIn('"status":"recovering"', events[0][1])

    def test_broken_stdio_pipe_does_not_escape_as_final_flush_traceback(self) -> None:
        import chatgpt_dev_mcp.chatgpt_connector_compat as connector_compat
        from chatgpt_dev_mcp.chatgpt_connector_compat import serve_stdio_compat

        class Runtime:
            protocol_version = "2025-11-25"
            initialized = False

            def __init__(self) -> None:
                self.closed = False

            def initialize(self, client_info=None):
                return {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "broken-pipe", "version": "test"},
                }

            def close(self):
                self.closed = True

        class BrokenSink:
            def write(self, _value):
                raise BrokenPipeError("connector closed")

            def flush(self):
                raise BrokenPipeError("connector closed")

            def close(self):
                return None

        runtime = Runtime()
        request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "clientInfo": {"name": "test", "version": "1"}},
            }
        ) + "\n"
        original_stdout = connector_compat.sys.stdout
        try:
            connector_compat.sys.stdout = BrokenSink()  # type: ignore[assignment]
            serve_stdio_compat(runtime, input_stream=StringIO(request))
        finally:
            replacement_stdout = connector_compat.sys.stdout
            if replacement_stdout is not original_stdout and hasattr(replacement_stdout, "close"):
                replacement_stdout.close()
            connector_compat.sys.stdout = original_stdout
        self.assertTrue(runtime.closed)


if __name__ == "__main__":
    unittest.main()
