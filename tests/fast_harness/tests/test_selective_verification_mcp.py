from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SelectiveVerificationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-fast-verification-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        tests = self.repo / "tests"
        tests.mkdir()
        (tests / "test_selected.py").write_text(
            "import unittest\n\n"
            "class Selected(unittest.TestCase):\n"
            "    def test_selected(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        (tests / "test_unrelated.py").write_text(
            "import unittest\n\n"
            "class Unrelated(unittest.TestCase):\n"
            "    def test_unrelated(self):\n"
            "        self.fail('unrelated test must not run during FAST verification')\n",
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
                            "commands": {
                                "test": "python3 -m unittest discover -s tests -p 'test_*.py' -q"
                            },
                            "metadata": {
                                "isolated_development": {
                                    "auto_create_sessions": True,
                                    "auto_resume_sessions": True,
                                    "auto_resume_policy": "same_owner_same_task_safe_local",
                                    "max_parallel_sessions": 2,
                                    "allowed_base": "registered_project",
                                    "allow_workspace_wide": False,
                                    "integration_requires_approval": True,
                                    "commit_requires_approval": True,
                                    "push_requires_approval": True,
                                }
                            },
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

    def test_fast_verification_executes_only_selected_test_paths(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened.get("isError"), opened)
            queued = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "workspace_id": "fixture",
                    "request_id": "verify-selected-only",
                    "title": "Verify selected test only",
                    "allowed_paths": ["tests/test_selected.py"],
                },
            )
            self.assertFalse(queued.get("isError"), queued)
            task_id = queued["structuredContent"]["receipt"]["task_id"]

            result = runtime.call_tool(
                "verification_run",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "mode": "fast",
                    "changed_paths": ["tests/test_selected.py"],
                },
            )
            self.assertFalse(result.get("isError"), result)
            payload = result["structuredContent"]
            self.assertEqual(payload["requested_mode"], "fast")
            self.assertEqual(payload["mode"], "fast")
            self.assertEqual(payload["selection"]["tests"], ["tests/test_selected.py"])
            self.assertEqual(payload["status"], "passed", payload)
        finally:
            runtime.close()

    def test_orphaned_writer_task_is_detected_only_when_bound_session_is_missing(self) -> None:
        from chatgpt_dev_mcp.director_parallel import ProjectTask, orphaned_writer_task_ids

        orphan = ProjectTask(
            "task-orphan",
            "fixture",
            "fixture",
            "owner",
            "session:closed-session",
            "session:closed-session",
            "a" * 40,
            ("src/app.py",),
            (),
            status="verifying",
        )
        live = ProjectTask(
            "task-live",
            "fixture",
            "fixture",
            "owner",
            "session:live-session",
            "session:live-session",
            "a" * 40,
            ("src/other.py",),
            (),
            status="running",
        )
        queued = ProjectTask(
            "task-queued",
            "fixture",
            "fixture",
            "owner",
            "session:task-queued",
            "canonical",
            "a" * 40,
            ("src/queued.py",),
            (),
            status="queued",
        )
        self.assertEqual(
            orphaned_writer_task_ids(
                (orphan, live, queued),
                ("session:live-session",),
            ),
            ("task-orphan",),
        )

    def test_clean_director_session_close_stales_active_task_before_removal(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        runtime = WrapperRuntime()
        try:
            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "fixture",
                    "request_id": "close-stales-task",
                    "title": "Close stale task regression",
                    "owner_id": "test-owner",
                    "paths": ["tests/test_selected.py"],
                    "source_revision": head,
                },
            )
            self.assertFalse(started.get("isError"), started)
            payload = started["structuredContent"]
            task_id = payload["task_id"]
            closed = runtime.call_tool(
                "workspace_close_development_session",
                {"session_id": payload["session_id"]},
            )
            self.assertFalse(closed.get("isError"), closed)
            task = runtime._director_ledger.get(task_id)
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "stale")
            self.assertEqual(task.detail, "DEVELOPMENT_SESSION_CLOSED_CLEAN")
        finally:
            runtime.close()

    def test_development_start_reconciles_missing_session_writer_before_overlap_check(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        runtime = WrapperRuntime()
        try:
            orphan = runtime._director_ledger.enqueue(
                "historical-orphan",
                "fixture",
                "Historical orphan",
                allowed_paths=("tests/test_selected.py",),
                base_revision=head,
            )
            runtime._director_ledger.bind_execution(
                orphan.task_id,
                working_tree_id="session:missing-session",
                development_session_id="session:missing-session",
                base_revision=head,
                allowed_paths=("tests/test_selected.py",),
            )
            runtime._director_ledger.transition(orphan.task_id, "ready")
            runtime._director_ledger.transition(
                orphan.task_id,
                "running",
                owner_id="historical-owner",
            )

            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "fixture",
                    "request_id": "replacement-after-orphan",
                    "title": "Replacement after orphan",
                    "owner_id": "replacement-owner",
                    "paths": ["tests/test_selected.py"],
                    "source_revision": head,
                },
            )
            self.assertFalse(started.get("isError"), started)
            payload = started["structuredContent"]
            self.assertEqual(payload["status"], "active", payload)
            reconciled = runtime._director_ledger.get(orphan.task_id)
            self.assertIsNotNone(reconciled)
            self.assertEqual(reconciled.status, "stale")
            self.assertEqual(reconciled.detail, "ORPHANED_DEVELOPMENT_SESSION")
            runtime.call_tool(
                "workspace_close_development_session",
                {"session_id": payload["session_id"]},
            )
        finally:
            runtime.close()

    def test_reaudit_refreshes_review_ready_task_to_latest_security_receipt(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened.get("isError"), opened)
            task = runtime._director_ledger.enqueue(
                "reaudit-refresh",
                "fixture",
                "Reaudit refresh regression",
                allowed_paths=("tests/test_selected.py",),
                base_revision=head,
            )
            runtime._director_ledger.transition(task.task_id, "ready")
            runtime._director_ledger.start(task.task_id, "audit-owner")
            runtime._director_ledger.transition(
                task.task_id,
                "verifying",
                owner_id="audit-owner",
            )
            verified = runtime.call_tool(
                "verification_record",
                {
                    "workspace_id": "fixture",
                    "task_id": task.task_id,
                    "changed_paths": ["tests/test_selected.py"],
                    "results": [
                        {
                            "task": "test",
                            "exit_code": 0,
                            "output": "selected verification passed",
                            "duration_ms": 1,
                            "timed_out": False,
                        }
                    ],
                },
            )
            self.assertFalse(verified.get("isError"), verified)
            verification_id = verified["structuredContent"]["receipt"]["receipt_id"]

            first = runtime.call_tool(
                "security_audit",
                {
                    "workspace_id": "fixture",
                    "task_id": task.task_id,
                    "verification_receipt_id": verification_id,
                    "patch": (
                        "diff --git a/tests/test_selected.py b/tests/test_selected.py\n"
                        "--- a/tests/test_selected.py\n"
                        "+++ b/tests/test_selected.py\n"
                        "@@ -1 +1 @@\n"
                        "-before\n"
                        "+after\n"
                    ),
                },
            )
            self.assertFalse(first.get("isError"), first)
            first_id = first["structuredContent"]["receipt"]["receipt_id"]
            after_first = runtime._director_ledger.get(task.task_id)
            self.assertIsNotNone(after_first)
            self.assertEqual(after_first.status, "verifying")
            self.assertEqual(after_first.security_audit_receipt, "")
            transitioned = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task.task_id,
                    "status": "review_ready",
                    "owner_id": "audit-owner",
                    "verification_receipt": verification_id,
                    "security_audit_receipt": first_id,
                },
            )
            self.assertFalse(transitioned.get("isError"), transitioned)
            after_transition = runtime._director_ledger.get(task.task_id)
            self.assertIsNotNone(after_transition)
            self.assertEqual(after_transition.status, "review_ready")
            self.assertEqual(after_transition.security_audit_receipt, first_id)

            second = runtime.call_tool(
                "security_audit",
                {
                    "workspace_id": "fixture",
                    "task_id": task.task_id,
                    "verification_receipt_id": verification_id,
                },
            )
            self.assertFalse(second.get("isError"), second)
            second_id = second["structuredContent"]["receipt"]["receipt_id"]
            self.assertNotEqual(first_id, second_id)
            after_second = runtime._director_ledger.get(task.task_id)
            self.assertIsNotNone(after_second)
            self.assertEqual(after_second.status, "review_ready")
            self.assertEqual(after_second.security_audit_receipt, first_id)
            transitioned_again = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task.task_id,
                    "status": "review_ready",
                    "owner_id": "audit-owner",
                    "verification_receipt": verification_id,
                    "security_audit_receipt": second_id,
                },
            )
            self.assertFalse(transitioned_again.get("isError"), transitioned_again)
            refreshed = runtime._director_ledger.get(task.task_id)
            self.assertIsNotNone(refreshed)
            self.assertEqual(refreshed.security_audit_receipt, second_id)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
