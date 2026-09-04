from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch


class WorkspaceBindingTests(unittest.TestCase):
    def _runtime(self, root: Path):
        from chatgpt_dev_mcp.server import WrapperRuntime

        workspace_a = root / "workspace-a"
        workspace_b = root / "workspace-b"
        workspace_a.mkdir()
        workspace_b.mkdir()
        (workspace_a / "marker.txt").write_text("workspace-a\n", encoding="utf-8")
        (workspace_b / "marker.txt").write_text("workspace-b\n", encoding="utf-8")
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "workspace-a": {"path": str(workspace_a), "profile": "READ_ONLY"},
                        "workspace-b": {"path": str(workspace_b), "profile": "READ_ONLY"},
                    },
                }
            ),
            encoding="utf-8",
        )
        env = patch.dict(
            os.environ,
            {
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "state"),
            },
        )
        env.start()
        self.addCleanup(env.stop)
        runtime = WrapperRuntime()
        self.addCleanup(runtime.close)
        return runtime

    def test_explicit_workspace_binding_routes_to_original_workspace_after_switch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            runtime = self._runtime(Path(raw))
            runtime.call_tool("workspace_open", {"id": "workspace-a"})
            status_a = runtime.call_tool("workspace_status", {})["structuredContent"]
            tree_a = status_a["identity"]["worktree_id"]

            runtime.call_tool("workspace_open", {"id": "workspace-b"})
            status_b = runtime.call_tool("workspace_status", {})["structuredContent"]
            tree_b = status_b["identity"]["worktree_id"]
            self.assertNotEqual(tree_a, tree_b)

            result = runtime.call_tool(
                "read_file",
                {
                    "path": "marker.txt",
                    "workspace_id": "workspace-a",
                    "working_tree_id": tree_a,
                },
            )["structuredContent"]

            self.assertTrue(result["ok"])
            self.assertIn("workspace-a", result["content"])
            self.assertNotIn("workspace-b", result["content"])

    def test_unbound_workspace_tool_fails_closed_after_multiple_workspaces_opened(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            runtime = self._runtime(Path(raw))
            runtime.call_tool("workspace_open", {"id": "workspace-a"})
            runtime.call_tool("workspace_open", {"id": "workspace-b"})

            result = runtime.call_tool("read_file", {"path": "marker.txt"})["structuredContent"]

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "WORKSPACE_BINDING_REQUIRED")

    def test_server_info_remains_global_after_multiple_workspaces_opened(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            runtime = self._runtime(Path(raw))
            runtime.call_tool("workspace_open", {"id": "workspace-a"})
            runtime.call_tool("workspace_open", {"id": "workspace-b"})

            result = runtime.call_tool("server_info", {})

            self.assertFalse(result["isError"], result)
            info = result["structuredContent"]
            self.assertEqual(info["tool_count"], info["tool_schema"]["count"])
            self.assertNotIn("workspace_id", info.get("wrapper", {}))
            self.assertNotIn("profile", info.get("wrapper", {}))

    def test_process_receipt_routes_poll_to_original_workspace_after_switch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            root = Path(raw)
            workspace_a = root / "workspace-a"
            workspace_b = root / "workspace-b"
            workspace_a.mkdir()
            workspace_b.mkdir()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "workspace-a": {
                                "path": str(workspace_a),
                                "profile": "DEVELOPMENT",
                                "commands": {"dev": "sleep 2"},
                            },
                            "workspace-b": {
                                "path": str(workspace_b),
                                "profile": "DEVELOPMENT",
                                "commands": {"dev": "sleep 2"},
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "LOCAL_DEV_MCP_CONFIG": str(config),
                    "LOCAL_DEV_MCP_DATA_DIR": str(root / "state"),
                },
            ):
                from chatgpt_dev_mcp.server import WrapperRuntime

                runtime = WrapperRuntime()
                try:
                    runtime.call_tool("workspace_open", {"id": "workspace-a"})
                    tree_a = runtime.call_tool("workspace_status", {})["structuredContent"]["identity"]["worktree_id"]
                    started = runtime.call_tool(
                        "run_task",
                        {
                            "task": "dev",
                            "workspace_id": "workspace-a",
                            "working_tree_id": tree_a,
                            "yield_time_ms": 0,
                        },
                    )
                    self.assertFalse(started["isError"], started)
                    process_id = started["structuredContent"].get("session_id")
                    self.assertIsInstance(process_id, str)

                    runtime.call_tool("workspace_open", {"id": "workspace-b"})
                    tree_b = runtime.call_tool("workspace_status", {})["structuredContent"]["identity"]["worktree_id"]
                    mismatched = runtime.call_tool(
                        "task_poll",
                        {
                            "process_session_id": process_id,
                            "working_tree_id": tree_b,
                            "yield_time_ms": 0,
                        },
                    )
                    self.assertTrue(mismatched["isError"], mismatched)
                    self.assertEqual(
                        mismatched["structuredContent"]["error"]["code"],
                        "SESSION_BINDING_MISMATCH",
                    )
                    alias_mismatch = runtime.call_tool(
                        "task_poll",
                        {
                            "process_session_id": process_id,
                            "session_id": "process:wrong-alias",
                            "yield_time_ms": 0,
                        },
                    )
                    self.assertTrue(alias_mismatch["isError"], alias_mismatch)
                    self.assertEqual(
                        alias_mismatch["structuredContent"]["error"]["code"],
                        "SESSION_BINDING_MISMATCH",
                    )
                    polled = runtime.call_tool(
                        "task_poll",
                        {"process_session_id": process_id, "yield_time_ms": 0},
                    )

                    self.assertFalse(polled["isError"], polled)
                finally:
                    runtime.close()

    def test_completed_run_task_remains_pollable_for_terminal_readback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            root = Path(raw)
            workspace = root / "workspace-a"
            workspace.mkdir()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "workspace-a": {
                                "path": str(workspace),
                                "profile": "DEVELOPMENT",
                                "commands": {"dev": "sleep 0.05"},
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "LOCAL_DEV_MCP_CONFIG": str(config),
                    "LOCAL_DEV_MCP_DATA_DIR": str(root / "state"),
                },
            ):
                from chatgpt_dev_mcp.server import WrapperRuntime

                runtime = WrapperRuntime()
                try:
                    runtime.call_tool("workspace_open", {"id": "workspace-a"})
                    tree_id = runtime.call_tool("workspace_status", {})["structuredContent"]["identity"]["worktree_id"]
                    started = runtime.call_tool(
                        "run_task",
                        {
                            "task": "dev",
                            "workspace_id": "workspace-a",
                            "working_tree_id": tree_id,
                            "yield_time_ms": 0,
                        },
                    )
                    self.assertFalse(started["isError"], started)
                    process_id = started["structuredContent"].get("session_id")
                    self.assertIsInstance(process_id, str)

                    time.sleep(0.15)
                    polled = runtime.call_tool(
                        "task_poll",
                        {
                            "process_session_id": process_id,
                            "workspace_id": "workspace-a",
                            "working_tree_id": tree_id,
                            "yield_time_ms": 0,
                        },
                    )

                    self.assertFalse(polled["isError"], polled)
                    self.assertNotEqual(
                        polled["structuredContent"].get("error", {}).get("code"),
                        "SESSION_NOT_APPROVED",
                    )
                finally:
                    runtime.close()

    def test_wrong_worktree_binding_fails_closed_instead_of_using_selected_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            runtime = self._runtime(Path(raw))
            runtime.call_tool("workspace_open", {"id": "workspace-a"})
            status = runtime.call_tool("workspace_status", {})["structuredContent"]

            result = runtime.call_tool(
                "read_file",
                {
                    "path": "marker.txt",
                    "workspace_id": "workspace-a",
                    "working_tree_id": "worktree:wrong",
                },
            )["structuredContent"]

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "WORKSPACE_BINDING_MISMATCH")
            self.assertNotEqual(status["identity"]["worktree_id"], "worktree:wrong")

    def test_explicit_registered_canonical_binding_rehydrates_after_runtime_binding_loss(self) -> None:
        with tempfile.TemporaryDirectory(prefix="workspace-binding-") as raw:
            runtime = self._runtime(Path(raw))
            runtime.call_tool("workspace_open", {"id": "workspace-a"})
            status = runtime.call_tool("workspace_status", {})["structuredContent"]
            tree_id = status["identity"]["worktree_id"]

            runtime._workspace_bindings.clear()
            runtime.current = None
            if runtime.upstream is not None:
                runtime.upstream.close()
            runtime.upstream = None

            result = runtime.call_tool(
                "read_file",
                {
                    "path": "marker.txt",
                    "workspace_id": "workspace-a",
                    "working_tree_id": tree_id,
                },
            )["structuredContent"]

            self.assertTrue(result["ok"], result)
            self.assertIn("workspace-a", result["content"])
            self.assertIsNone(runtime.current)
            self.assertIn(("workspace-a", tree_id), runtime._workspace_bindings)

    def test_canonical_worktree_id_does_not_depend_on_process_stat_inode(self) -> None:
        from chatgpt_dev_mcp.server import WorkspaceEntry, WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="worktree-id-") as raw:
            root = Path(raw)
            runtime = object.__new__(WrapperRuntime)
            runtime.development_sessions = {}
            entry = WorkspaceEntry("fixture", root, "READ_ONLY", {})

            with patch.object(
                Path,
                "stat",
                side_effect=[
                    SimpleNamespace(st_dev=10, st_ino=100),
                    SimpleNamespace(st_dev=10, st_ino=999),
                ],
            ):
                first = WrapperRuntime._director_working_tree_id(runtime, entry)
                second = WrapperRuntime._director_working_tree_id(runtime, entry)

            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
