from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class ProcessSessionReconciliationTests(unittest.TestCase):
    @staticmethod
    def _isolated_environment(root: Path) -> dict[str, str]:
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

    def test_reconcile_drops_receipt_when_owner_development_session_is_gone(self) -> None:
        from chatgpt_dev_mcp.server import TaskProcessBinding, WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="process-receipt-reconcile-") as temp:
            root = Path(temp)
            with patch.dict(os.environ, self._isolated_environment(root), clear=False):
                runtime = WrapperRuntime()
                try:
                    process_session_id = "process:orphaned-after-close"
                    owner_session_id = "session:already-closed"
                    runtime.approved_sessions.add(process_session_id)
                    runtime._task_process_sessions[process_session_id] = TaskProcessBinding(
                        "chatgpt-dev-mcp", owner_session_id, owner_session_id
                    )
                    self.assertNotIn(owner_session_id, runtime.development_sessions)
                    self.assertFalse(runtime._process_session_alive(process_session_id))
                    self.assertEqual(runtime._reconcile_task_process_bindings(), 1)
                    self.assertNotIn(process_session_id, runtime.approved_sessions)
                    self.assertNotIn(process_session_id, runtime._task_process_sessions)
                finally:
                    runtime.close()

    def test_reconcile_drops_receipt_when_owner_development_session_is_stale(self) -> None:
        from chatgpt_dev_mcp.server import TaskProcessBinding, WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="process-receipt-stale-") as temp:
            root = Path(temp)
            with patch.dict(os.environ, self._isolated_environment(root), clear=False):
                runtime = WrapperRuntime()
                try:
                    process_session_id = "process:stale-owner"
                    owner_session_id = "session:stale-owner"
                    runtime.approved_sessions.add(process_session_id)
                    runtime._task_process_sessions[process_session_id] = TaskProcessBinding(
                        "chatgpt-dev-mcp", owner_session_id, owner_session_id
                    )
                    runtime.development_sessions[owner_session_id] = SimpleNamespace(
                        stale=True, lifecycle_state="stale"
                    )
                    self.assertFalse(runtime._process_session_alive(process_session_id))
                    self.assertEqual(runtime._reconcile_task_process_bindings(), 1)
                    self.assertNotIn(process_session_id, runtime.approved_sessions)
                    self.assertNotIn(process_session_id, runtime._task_process_sessions)
                finally:
                    runtime.development_sessions.pop(owner_session_id, None)
                    runtime.close()

    def test_reconcile_keeps_receipt_when_active_owner_runtime_is_temporarily_detached(self) -> None:
        from chatgpt_dev_mcp.server import TaskProcessBinding, WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="process-receipt-detached-") as temp:
            root = Path(temp)
            with patch.dict(os.environ, self._isolated_environment(root), clear=False):
                runtime = WrapperRuntime()
                try:
                    process_session_id = "process:active-owner-detached"
                    owner_session_id = "session:active-owner"
                    runtime.approved_sessions.add(process_session_id)
                    runtime._task_process_sessions[process_session_id] = TaskProcessBinding(
                        "chatgpt-dev-mcp", owner_session_id, owner_session_id
                    )
                    runtime.development_sessions[owner_session_id] = SimpleNamespace(
                        stale=False, lifecycle_state="active"
                    )
                    self.assertTrue(runtime._process_session_alive(process_session_id))
                    self.assertEqual(runtime._reconcile_task_process_bindings(), 0)
                    self.assertIn(process_session_id, runtime.approved_sessions)
                    self.assertIn(process_session_id, runtime._task_process_sessions)
                finally:
                    runtime.development_sessions.pop(owner_session_id, None)
                    runtime.close()

    def test_director_health_does_not_purge_durable_process_bindings(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="process-receipt-health-") as temp:
            root = Path(temp)
            with patch.dict(os.environ, self._isolated_environment(root), clear=False):
                runtime = WrapperRuntime()
                try:
                    self.assertIsNotNone(runtime._persistence)
                    binding = {
                        "process_session_id": "process:health-observation",
                        "workspace_id": "chatgpt-dev-mcp",
                        "working_tree_id": "worktree:health-observation",
                        "development_session_id": None,
                        "runtime_capability_epoch": "epoch:health-observation",
                        "upstream_runtime_id": "runtime:health-observation",
                        "created_at": 1.0,
                        "expires_at": 2.0,
                        "state": "active",
                    }
                    runtime._persistence.save_task_process_binding(binding)

                    before = runtime._persistence.load_task_process_binding(binding["process_session_id"])
                    result = runtime.call_tool("director_health", {})
                    after = runtime._persistence.load_task_process_binding(binding["process_session_id"])

                    self.assertFalse(result["isError"], result)
                    self.assertEqual(after, before)
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
