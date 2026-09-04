from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class DirectorPersistenceRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-runtime-persistence-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
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
        self.previous_data = os.environ.get("LOCAL_DEV_MCP_DATA_DIR")
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)
        os.environ["LOCAL_DEV_MCP_DATA_DIR"] = str(self.root / "runtime-state")

    def tearDown(self) -> None:
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        if self.previous_data is None:
            os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
        else:
            os.environ["LOCAL_DEV_MCP_DATA_DIR"] = self.previous_data
        self.tempdir.cleanup()

    def _open(self):
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        opened = runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)
        return runtime

    def test_task_lifecycle_survives_child_restart_without_restoring_running(self) -> None:
        first = self._open()
        queued = first.call_tool(
            "director_task_ledger",
            {"action": "enqueue", "workspace_id": "fixture", "request_id": "request-1", "title": "persisted task"},
        )["structuredContent"]["receipt"]
        task_id = queued["task_id"]
        first.call_tool("director_task_ledger", {"action": "start", "task_id": task_id, "owner_id": "owner-1"})
        first.close()

        second = self._open()
        try:
            records = second.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})["structuredContent"]["records"]
            restored = next(record for record in records if record["task_id"] == task_id)
            self.assertNotEqual(restored["status"], "running")
            self.assertIn(restored["status"], {"ready", "stale", "blocked"})
        finally:
            second.close()

    def test_valid_unexpired_lease_is_reconciled_after_restart(self) -> None:
        first = self._open()
        try:
            task = first.call_tool(
                "director_task_ledger",
                {"action": "enqueue", "workspace_id": "fixture", "request_id": "request-lease", "title": "lease task"},
            )["structuredContent"]["receipt"]
            acquired = first.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "workspace_id": "fixture",
                    "owner_id": "owner-1",
                    "task_id": task["task_id"],
                    "paths": ["README.md"],
                    "resources": [],
                },
            )["structuredContent"]["lease"]
            lease_id = acquired["lease_id"]
        finally:
            first.close()

        second = self._open()
        try:
            status = second.call_tool(
                "director_writer_lease",
                {"action": "status", "workspace_id": "fixture", "lease_id": lease_id},
            )
            self.assertFalse(status["isError"], status)
            self.assertEqual(status["structuredContent"]["lease"]["lease_id"], lease_id)
        finally:
            second.close()

    def test_verification_and_security_receipts_survive_restart(self) -> None:
        first = self._open()
        try:
            task = first.call_tool(
                "director_task_ledger",
                {"action": "enqueue", "workspace_id": "fixture", "request_id": "request-evidence", "title": "evidence"},
            )["structuredContent"]["receipt"]
            verification = first.call_tool(
                "verification_record",
                {
                    "changed_paths": ["README.md"],
                    "task_id": task["task_id"],
                    "results": [],
                },
            )
            self.assertFalse(verification["isError"], verification)
            audit = first.call_tool(
                "security_audit",
                {"task_id": task["task_id"], "verification_receipt_id": verification["structuredContent"]["receipt"]["receipt_id"]},
            )
            self.assertFalse(audit["isError"], audit)
        finally:
            first.close()

        second = self._open()
        try:
            self.assertIn(verification["structuredContent"]["receipt"]["receipt_id"], second._director_receipt_history)
            self.assertIn(audit["structuredContent"]["receipt"]["receipt_id"], second._director_audit_receipt_history)
        finally:
            second.close()

    def test_corrupt_state_blocks_director_mutation(self) -> None:
        first = self._open()
        first.close()
        db = self.root / "runtime-state" / "director.sqlite3"
        db.write_bytes(b"corrupt")
        second = self._open()
        try:
            result = second.call_tool(
                "director_task_ledger",
                {"action": "enqueue", "workspace_id": "fixture", "request_id": "blocked", "title": "blocked"},
            )
            self.assertTrue(result["isError"])
        finally:
            second.close()

    def test_missing_head_quarantines_only_that_workspace(self) -> None:
        invalid = self.root / "invalid-workspace"
        invalid.mkdir()
        (invalid / "README.md").write_text("not a git repository\n", encoding="utf-8")
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                        },
                        "invalid": {
                            "path": str(invalid),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "invalid"})
            self.assertFalse(opened["isError"], opened)
            self.assertEqual(
                opened["structuredContent"]["director"]["error"]["code"],
                "INVALID_WORKSPACE_HEAD",
            )
            self.assertIsNone(runtime._persistence_error)

            health = runtime.call_tool("director_health", {})["structuredContent"]["health"]
            self.assertEqual(health["director_persistence"]["status"], "healthy")
            self.assertEqual(
                [item["workspace_id"] for item in health["director_persistence"]["invalid_workspaces"]],
                ["invalid"],
            )

            opened_good = runtime.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened_good["isError"], opened_good)
            queued = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "workspace_id": "fixture",
                    "request_id": "valid-after-invalid-head",
                    "title": "valid workspace remains writable",
                },
            )
            self.assertFalse(queued["isError"], queued)

            invalid_summary = runtime.call_tool("director_status_summary", {"workspace_id": "invalid"})
            self.assertTrue(invalid_summary["isError"], invalid_summary)
            self.assertEqual(
                invalid_summary["structuredContent"]["error"]["code"],
                "INVALID_WORKSPACE_HEAD",
            )
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
