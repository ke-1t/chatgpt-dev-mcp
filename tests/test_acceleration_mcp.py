from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class AccelerationMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-acceleration-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(
            "def greet(name: str) -> str:\n    return f'hello {name}'\n",
            encoding="utf-8",
        )
        tests = self.repo / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text(
            "from app import greet\n\ndef test_greet():\n    assert greet('world') == 'hello world'\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "fixture-root", "path": str(self.root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)

    def tearDown(self) -> None:
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        self.tempdir.cleanup()

    def _runtime(self):
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        selected = runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(selected.get("isError"), selected)
        return runtime

    def test_acceleration_tools_are_registered(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            names = {item["name"] for item in runtime.list_tools()["tools"]}
            self.assertEqual(len(names), 52)
            self.assertTrue({"development_context", "verification_run", "director_next_action", "browser_qa_run"} <= names)
            for capability_id in ("semantic_code_query", "external_capability_status"):
                self.assertNotIn(capability_id, names)
                described = runtime.call_tool(
                    "capability_describe",
                    {"capability_id": capability_id},
                )["structuredContent"]
                self.assertEqual(described["exposure"], "registry")
        finally:
            runtime.close()

    def test_semantic_query_runs_through_wrapper_runtime(self) -> None:
        runtime = self._runtime()
        try:
            result = runtime.call_tool(
                "semantic_code_query",
                {"workspace_id": "fixture", "query": "greet", "relations": ["definition", "tests"]},
            )
            self.assertFalse(result.get("isError"), result)
            payload = result["structuredContent"]
            self.assertEqual(payload["workspace_id"], "fixture")
            self.assertTrue(any(item["symbol_id"].endswith(":greet") for item in payload["matches"]))
        finally:
            runtime.close()

    def test_development_context_runs_through_wrapper_runtime(self) -> None:
        runtime = self._runtime()
        try:
            result = runtime.call_tool(
                "development_context",
                {
                    "workspace_id": "fixture",
                    "task_id": "task-context",
                    "query": "greet",
                    "target_paths": ["app.py"],
                    "diff_paths": ["app.py"],
                    "max_bytes": 8192,
                },
            )
            self.assertFalse(result.get("isError"), result)
            payload = result["structuredContent"]
            self.assertEqual(payload["task_id"], "task-context")
            self.assertEqual(payload["workspace_id"], "fixture")
            self.assertGreater(payload["used_bytes"], 0)
        finally:
            runtime.close()

    def test_full_verification_uses_registered_task_command(self) -> None:
        runtime = self._runtime()
        try:
            queued = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "workspace_id": "fixture",
                    "request_id": "verify-fixture",
                    "title": "Verify fixture",
                    "allowed_paths": ["app.py"],
                },
            )
            self.assertFalse(queued.get("isError"), queued)
            task_id = queued["structuredContent"]["receipt"]["task_id"]
            result = runtime.call_tool(
                "verification_run",
                {"workspace_id": "fixture", "task_id": task_id, "mode": "full", "changed_paths": ["app.py"]},
            )
            self.assertFalse(result.get("isError"), result)
            payload = result["structuredContent"]
            self.assertEqual(payload["requested_mode"], "full")
            self.assertEqual(payload["mode"], "full")
            self.assertIn(payload["status"], {"passed", "failed", "incomplete", "not_run"})
        finally:
            runtime.close()

    def test_external_capability_status_is_side_effect_free(self) -> None:
        runtime = self._runtime()
        try:
            before = runtime._persistence.load_acceleration_receipts(kind="capability", limit=20)
            result = runtime.call_tool("external_capability_status", {})
            self.assertFalse(result.get("isError"), result)
            payload = result["structuredContent"]
            self.assertFalse(payload["process_started"])
            self.assertFalse(payload["network_used"])
            self.assertFalse(payload["external_execution"])
            self.assertNotIn("receipt_id", payload)
            after = runtime._persistence.load_acceleration_receipts(kind="capability", limit=20)
            self.assertEqual(after, before)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
