from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult


class LocalMaintenanceMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="local-maintenance-mcp-")
        root = Path(self.tempdir.name)
        self.home = root / "home"
        self.repo = self.home / "Developer" / "project-x"
        self.repo.mkdir(parents=True)
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "project-x": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "printf test-ok"},
                            "isolated_development": {
                                "auto_create_sessions": True,
                                "auto_resume_sessions": True,
                                "auto_resume_policy": "same_owner_same_task_safe_local",
                                "max_parallel_sessions": 6,
                                "allowed_base": "registered_project",
                                "integration_requires_approval": True,
                                "commit_requires_approval": True,
                                "push_requires_approval": True,
                                "verified_auto_commit": True,
                                "auto_approve_safe_local": True,
                                "auto_approve_local_maintenance": True,
                                "manual_approval_ttl_seconds": 1800,
                                "trusted_session_grant_ttl_seconds": 7200,
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.env = patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.home / ".director-state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.home / ".cache" / "local-dev-mcp" / "worktrees"),
            },
        )
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self.tempdir.cleanup()

    def test_r2_restart_requires_no_human_approval_and_persists_decision(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        session_id = None
        calls: list[tuple[str, ...]] = []
        try:
            start = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "maintenance-task",
                    "title": "Bounded maintenance test",
                    "owner_id": "maintenance-owner",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(start["isError"], start)
            start_payload = start["structuredContent"]
            session_id = start_payload["session_id"]
            task_id = start_payload["task"]["task_id"]
            runtime._local_maintenance._runner = lambda argv: calls.append(argv) or MaintenanceRunResult(0, True, "ok")

            result = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": session_id,
                    "task_id": task_id,
                    "owner_id": "maintenance-owner",
                },
            )
            self.assertFalse(result["isError"], result)
            payload = result["structuredContent"]
            self.assertEqual(payload["status"], "recovering")
            self.assertEqual(payload["risk_class"], "R2")
            self.assertNotIn("approval_token", payload)
            self.assertNotIn("confirmation", payload)
            self.assertEqual(len(calls), 0)
            runtime.run_deferred_actions()
            self.assertEqual(len(calls), 1)
            decisions = runtime._persistence.load_approval_decisions("project-x")
            self.assertEqual(decisions[-1]["operation"], "restart_dev_mcp_tunnel")
            self.assertEqual(decisions[-1]["outcome"], "recovering")
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_r2_restart_handler_accepts_gateway_binding_fields(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        session_id = None
        calls: list[tuple[str, ...]] = []
        try:
            start = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "maintenance-binding-task",
                    "title": "Bounded maintenance binding test",
                    "owner_id": "maintenance-owner",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(start["isError"], start)
            start_payload = start["structuredContent"]
            session_id = start_payload["session_id"]
            task_id = start_payload["task"]["task_id"]
            runtime._local_maintenance._runner = lambda argv: calls.append(argv) or MaintenanceRunResult(0, True, "ok")

            payload = runtime._local_maintenance_tool(
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": session_id,
                    "task_id": task_id,
                    "owner_id": "maintenance-owner",
                    "working_tree_id": session_id,
                }
            )

            self.assertEqual(payload["status"], "recovering")
            runtime.run_deferred_actions()
            self.assertEqual(len(calls), 1)
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_r2_shortcut_creation_requires_no_human_approval_and_persists_decision(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        session_id = None
        calls: list[str] = []
        try:
            start = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "shortcut-maintenance-task",
                    "title": "Bounded shortcut maintenance test",
                    "owner_id": "maintenance-owner",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(start["isError"], start)
            start_payload = start["structuredContent"]
            session_id = start_payload["session_id"]
            task_id = start_payload["task"]["task_id"]
            runtime._local_maintenance._shortcut_writer = lambda: calls.append("write") or MaintenanceRunResult(
                0,
                True,
                "~/Desktop/Restart ChatGPT Dev MCP.command",
            )

            result = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "create_mcp_restart_shortcut",
                    "workspace_id": "project-x",
                    "session_id": session_id,
                    "task_id": task_id,
                    "owner_id": "maintenance-owner",
                },
            )
            self.assertFalse(result["isError"], result)
            payload = result["structuredContent"]
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["risk_class"], "R2")
            self.assertNotIn("approval_token", payload)
            self.assertNotIn("confirmation", payload)
            self.assertEqual(calls, ["write"])
            decisions = runtime._persistence.load_approval_decisions("project-x")
            self.assertEqual(decisions[-1]["operation"], "create_mcp_restart_shortcut")
            self.assertEqual(decisions[-1]["outcome"], "succeeded")
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()


    def test_r2_toolchain_install_is_publicly_exposed_and_uses_fixed_installer(self) -> None:
        from chatgpt_dev_mcp.server import CUSTOM_TOOLS, WrapperRuntime

        tool = next(item for item in CUSTOM_TOOLS if item["name"] == "local_maintenance")
        action_schema = tool["inputSchema"]["properties"]["action"]
        self.assertIn("install_dev_toolchain", action_schema["enum"])

        runtime = WrapperRuntime()
        session_id = None
        calls: list[str] = []
        try:
            start = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "toolchain-maintenance-task",
                    "title": "Fixed developer toolchain maintenance test",
                    "owner_id": "maintenance-owner",
                    "paths": ["README.md"],
                    "resources": ["maintenance:install_dev_toolchain"],
                },
            )
            self.assertFalse(start["isError"], start)
            start_payload = start["structuredContent"]
            session_id = start_payload["session_id"]
            task_id = start_payload["task"]["task_id"]
            runtime._local_maintenance._toolchain_installer = lambda: calls.append("install") or MaintenanceRunResult(
                0,
                True,
                "installed",
            )
            result = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "install_dev_toolchain",
                    "workspace_id": "project-x",
                    "session_id": session_id,
                    "task_id": task_id,
                    "owner_id": "maintenance-owner",
                },
            )
            self.assertFalse(result["isError"], result)
            payload = result["structuredContent"]
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["risk_class"], "R2")
            self.assertEqual(calls, ["install"])
            decisions = runtime._persistence.load_approval_decisions("project-x")
            self.assertEqual(decisions[-1]["operation"], "install_dev_toolchain")
            self.assertEqual(decisions[-1]["outcome"], "succeeded")
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()


if __name__ == "__main__":
    unittest.main()
