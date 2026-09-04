from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SessionSlotReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-slot-reconcile-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.repo = self.home / "Developer" / "project-x"
        self.repo.mkdir(parents=True)
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)

        self.config_path = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config_path.parent.mkdir(parents=True)
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "project-x": {
                            "path": "~/Developer/project-x",
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "printf test-ok"},
                            "metadata": {
                                "isolated_development": {
                                    "auto_create_sessions": True,
                                    "auto_resume_sessions": True,
                                    "auto_resume_policy": "same_owner_same_task_safe_local",
                                    "max_parallel_sessions": 1,
                                    "allowed_base": "registered_project",
                                }
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.previous = {
            "HOME": os.environ.get("HOME"),
            "LOCAL_DEV_MCP_CONFIG": os.environ.get("LOCAL_DEV_MCP_CONFIG"),
            "LOCAL_DEV_MCP_WORKTREE_ROOT": os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT"),
        }
        os.environ["HOME"] = str(self.home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config_path)
        os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = str(self.home / ".cache" / "local-dev-mcp" / "worktrees")

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_terminal_task_without_live_lease_does_not_leak_parallel_slot(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            first_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "slot-leak-first",
                    "title": "slot leak first",
                    "owner_id": "owner-slot-leak-first",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(first_result["isError"], first_result)
            first = first_result["structuredContent"]
            first_session_id = first["session_id"]
            first_task_id = first["task"]["task_id"]
            first_lease_id = first["lease_id"]
            first_worktree = Path(first["worktree_path"]).expanduser()

            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": first_session_id,
                    "lease_id": first_lease_id,
                    "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+slot-leak-retained\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            released = runtime.call_tool(
                "director_writer_lease",
                {"action": "release", "lease_id": first_lease_id},
            )
            self.assertFalse(released["isError"], released)
            stale = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": first_task_id,
                    "status": "stale",
                    "owner_id": "owner-slot-leak-first",
                    "detail": "simulated task invalidation",
                },
            )
            self.assertFalse(stale["isError"], stale)

            second_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "slot-leak-second",
                    "title": "slot leak second",
                    "owner_id": "owner-slot-leak-second",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(second_result["isError"], second_result)
            second = second_result["structuredContent"]
            self.assertNotEqual(second.get("blocked_reason"), "MAX_PARALLEL_SESSIONS")
            self.assertEqual(second["status"], "active")

            retained = runtime.call_tool(
                "workspace_session_status",
                {"session_id": first_session_id},
            )["structuredContent"]
            self.assertFalse(retained["active"])
            self.assertTrue(retained["stale"])
            self.assertEqual(retained["durable_state"], "suspended")
            self.assertTrue(retained["dirty"])
            self.assertTrue(first_worktree.is_dir())
            self.assertEqual(
                (first_worktree / "README.md").read_text(encoding="utf-8"),
                "slot-leak-retained\n",
            )
        finally:
            runtime.close()

    def test_terminal_task_with_live_lease_still_counts_toward_parallel_limit(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            first_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "slot-live-lease-first",
                    "title": "slot live lease first",
                    "owner_id": "owner-slot-live-lease-first",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(first_result["isError"], first_result)
            first = first_result["structuredContent"]

            stale = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": first["task"]["task_id"],
                    "status": "stale",
                    "owner_id": "owner-slot-live-lease-first",
                    "detail": "simulated task invalidation with live lease",
                },
            )
            self.assertFalse(stale["isError"], stale)

            second_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "slot-live-lease-second",
                    "title": "slot live lease second",
                    "owner_id": "owner-slot-live-lease-second",
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(second_result["isError"], second_result)
            second = second_result["structuredContent"]
            self.assertEqual(second["blocked_reason"], "MAX_PARALLEL_SESSIONS")

            retained = runtime.call_tool(
                "workspace_session_status",
                {"session_id": first["session_id"]},
            )["structuredContent"]
            self.assertTrue(retained["active"])
            self.assertFalse(retained["stale"])
            self.assertEqual(retained["durable_state"], "active")
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
