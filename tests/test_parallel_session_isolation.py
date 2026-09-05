from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ParallelSessionIsolationTests(unittest.TestCase):
    def test_restart_fence_classifier_uses_upstream_tool_annotations(self) -> None:
        runtime = self._runtime()
        try:
            self.assertFalse(runtime._restart_tool_is_mutating("read_file"))
            self.assertFalse(runtime._restart_tool_is_mutating("security_audit"))
            self.assertFalse(runtime._restart_tool_is_mutating("workspace_integration_preflight"))
            self.assertTrue(runtime._restart_tool_is_mutating("browser_inspect", {"kind": "screenshot"}))
            self.assertFalse(runtime._restart_tool_is_mutating("set_default_cwd"))
        finally:
            runtime.close()

    def test_integrated_session_does_not_count_toward_parallel_limit(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSession, DevelopmentSessionStatus, RepoIdentity
        from chatgpt_dev_mcp.server import _session_counts_toward_parallel_limit

        identity = RepoIdentity(Path("/tmp/source"), Path("/tmp/source"), 1, 1, "a" * 40, ".git")
        session = DevelopmentSession(
            "session:abcdefghijklmnop",
            "registered:fixture",
            "fixture",
            identity,
            Path("/tmp/worktree"),
            "a" * 40,
            False,
            100.0,
            1000.0,
            {},
            lifecycle_state=DevelopmentSessionStatus.INTEGRATED.value,
        )
        self.assertFalse(_session_counts_toward_parallel_limit(session, 200.0))

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="parallel-session-isolation-")
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
        self._env = patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.home / ".director-state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.home / ".cache" / "local-dev-mcp" / "worktrees"),
            },
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self.tempdir.cleanup()

    def _runtime(self):
        from chatgpt_dev_mcp.server import WrapperRuntime

        return WrapperRuntime()

    def _start(self, runtime, request_id: str, title_or_path: str, path: str | None = None):
        # Preserve the original path-only helper while accepting the optional
        # request title used by the approval-bound v0.41 coverage.
        title = title_or_path if path is not None else request_id
        path = title_or_path if path is None else path
        result = runtime.call_tool(
            "director_development_start",
            {
                "workspace_id": "project-x",
                "request_id": request_id,
                "title": title,
                "owner_id": f"owner-{request_id}",
                "paths": [path],
                "resources": [],
            },
        )
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]

    def test_resource_only_scope_can_start_without_path_hashes(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-resource-only",
                    "title": "resource only scope",
                    "owner_id": "owner-resource-only",
                    "paths": [],
                    "resources": ["runtime:test-service"],
                },
            )
            self.assertFalse(result["isError"], result)
            payload = result["structuredContent"]
            session_id = payload["session_id"]
            self.assertEqual(payload["lease"]["paths"], [])
            self.assertEqual(payload["lease"]["resources"], ["runtime:test-service"])
            self.assertEqual(payload["lease"]["scope_hashes"], {})
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_cross_owner_duplicate_task_is_blocked_before_second_worktree_creation(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            first = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-duplicate-a",
                    "title": "Fix restart checkpoint recovery",
                    "owner_id": "owner-chat-a",
                    "paths": ["src/server.py"],
                    "resources": [],
                },
            )
            self.assertFalse(first["isError"], first)
            first_payload = first["structuredContent"]
            session_id = first_payload["session_id"]

            duplicate = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-duplicate-b",
                    "title": "Fix restart checkpoint recoveries",
                    "owner_id": "owner-chat-b",
                    "paths": ["src/server.py"],
                    "resources": [],
                },
            )
            self.assertFalse(duplicate["isError"], duplicate)
            payload = duplicate["structuredContent"]
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["blocked_reason"], "DUPLICATE_TASK_ACTIVE")
            self.assertEqual(payload["duplicate_match"], "near")
            self.assertEqual(payload["existing_task_id"], first_payload["task_id"])
            self.assertEqual(payload["existing_session_id"], first_payload["session_id"])
            self.assertIsNone(payload["session"])

            sessions = runtime.call_tool("workspace_list_development_sessions", {})["structuredContent"]["sessions"]
            active = [item for item in sessions if item["active"]]
            self.assertEqual([item["session_id"] for item in active], [first_payload["session_id"]])
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_explicit_session_routes_read_and_patch_after_selected_switch(self) -> None:
        runtime = self._runtime()
        sessions = []
        try:
            first = self._start(runtime, "request-a", "a.txt")
            second = self._start(runtime, "request-b", "b.txt")
            sessions.extend((first["session_id"], second["session_id"]))

            runtime.call_tool("workspace_open", {"id": first["session_id"]})
            runtime.call_tool("workspace_open", {"id": second["session_id"]})

            lease_bound_read = runtime.call_tool(
                "read_file",
                {"lease_id": first["lease"]["lease_id"], "path": "README.md"},
            )
            self.assertFalse(lease_bound_read["isError"], lease_bound_read)
            self.assertEqual(lease_bound_read["structuredContent"]["content"], "baseline\n")

            mismatched_read = runtime.call_tool(
                "read_file",
                {
                    "session_id": first["session_id"],
                    "lease_id": second["lease"]["lease_id"],
                    "path": "README.md",
                },
            )
            self.assertTrue(mismatched_read["isError"], mismatched_read)
            self.assertIn(
                mismatched_read["structuredContent"]["error"]["code"],
                {"WORKSPACE_BINDING_MISMATCH", "WRITER_LEASE_SCOPE_MISMATCH"},
            )

            patched_a = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": first["session_id"],
                    "lease_id": first["lease"]["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: a.txt\n+from-a\n*** End Patch",
                },
            )
            self.assertFalse(patched_a["isError"], patched_a)
            patched_b = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": second["session_id"],
                    "lease_id": second["lease"]["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: b.txt\n+from-b\n*** End Patch",
                },
            )
            self.assertFalse(patched_b["isError"], patched_b)

            read_a = runtime.call_tool("read_file", {"session_id": first["session_id"], "path": "a.txt"})
            read_b = runtime.call_tool("read_file", {"session_id": second["session_id"], "path": "b.txt"})
            self.assertEqual(read_a["structuredContent"]["content"], "from-a\n")
            self.assertEqual(read_b["structuredContent"]["content"], "from-b\n")
            self.assertFalse((self.repo / "a.txt").exists())
            self.assertFalse((self.repo / "b.txt").exists())

            status_a = runtime.call_tool("workspace_session_status", {"session_id": first["session_id"]})
            status_b = runtime.call_tool("workspace_session_status", {"session_id": second["session_id"]})
            self.assertTrue(status_a["structuredContent"]["active"], status_a)
            self.assertTrue(status_b["structuredContent"]["active"], status_b)
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_integration_preflight_keeps_verification_and_audit_bound_to_session(self) -> None:
        runtime = self._runtime()
        sessions = []
        try:
            first = self._start(runtime, "request-evidence-a", "a.txt")
            second = self._start(runtime, "request-evidence-b", "b.txt")
            sessions.extend((first["session_id"], second["session_id"]))

            evidence: dict[str, tuple[str, str]] = {}
            for started, filename, content in (
                (first, "a.txt", "from-a"),
                (second, "b.txt", "from-b"),
            ):
                session_id = started["session_id"]
                patched = runtime.call_tool(
                    "apply_patch",
                    {
                        "session_id": session_id,
                        "lease_id": started["lease"]["lease_id"],
                        "patch": f"*** Begin Patch\n*** Add File: {filename}\n+{content}\n*** End Patch",
                    },
                )
                self.assertFalse(patched["isError"], patched)
                verification = runtime.call_tool(
                    "verification_record",
                    {
                        "session_id": session_id,
                        "changed_paths": [filename],
                        "results": [{"task": "test", "exit_code": 0, "output": "ok"}],
                    },
                )["structuredContent"]
                audit = runtime.call_tool(
                    "security_audit",
                    {
                        "session_id": session_id,
                        "verification_receipt_id": verification["receipt"]["receipt_id"],
                    },
                )["structuredContent"]
                evidence[session_id] = (
                    verification["receipt"]["receipt_id"],
                    audit["receipt"]["receipt_id"],
                )

            # Reproduce a retained-session reconnect after A already had
            # valid evidence. Reactivation clears the task-level evidence
            # binding and returns the task to running while B remains the
            # workspace-global latest receipt.
            first_task_id = first["task"]["task_id"]
            first_owner_id = first["task"]["owner_id"]
            runtime._director_ledger.transition(
                first_task_id,
                "stale",
                owner_id=first_owner_id,
                detail="test retained reconnect after evidence",
            )
            resumed = runtime._director_ledger.reactivate(
                first_task_id,
                owner_id=first_owner_id,
                lease_id=first["lease"]["lease_id"],
                base_revision=first["source_revision"],
                detail="SAFE_LOCAL_SESSION_RESUMED",
            )
            self.assertEqual(resumed.status, "running")
            self.assertEqual(resumed.verification_receipt, "")
            self.assertEqual(resumed.security_audit_receipt, "")

            first_preflight = runtime.call_tool(
                "workspace_integration_preflight",
                {"session_id": first["session_id"]},
            )["structuredContent"]
            self.assertEqual(first_preflight["verification_receipt_id"], evidence[first["session_id"]][0])
            self.assertEqual(first_preflight["security_audit_receipt_id"], evidence[first["session_id"]][1])
            self.assertNotIn("VERIFICATION_RECEIPT_STALE", first_preflight["blockers"])
            self.assertNotIn("SECURITY_AUDIT_DIFF_MISMATCH", first_preflight["blockers"])
            self.assertNotIn("SECURITY_AUDIT_PATCH_MISMATCH", first_preflight["blockers"])
            self.assertNotIn("SECURITY_AUDIT_VERIFICATION_MISMATCH", first_preflight["blockers"])
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_integration_preflight_reports_already_subsumed_without_approval(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-already-subsumed", "subsumed.txt")
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: subsumed.txt\n+already present\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)

            (self.repo / "subsumed.txt").write_text("already present\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(self.repo), "add", "subsumed.txt"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "subsumed elsewhere"], check=True)

            preflight = runtime.call_tool(
                "workspace_integration_preflight",
                {"session_id": session_id},
            )
            self.assertFalse(preflight["isError"], preflight)
            payload = preflight["structuredContent"]
            self.assertEqual(payload["status"], "already_subsumed")
            self.assertTrue(payload["already_subsumed"])
            self.assertFalse(payload["integration_ready"])
            self.assertFalse(payload["human_confirmation_required"])
            self.assertNotIn("approval_token", payload)
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_security_audit_does_not_transition_task_or_release_session_writer_lease(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-review-release", "review-release.txt")
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: review-release.txt\n+ready\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            verification = runtime.call_tool(
                "verification_record",
                {
                    "session_id": session_id,
                    "changed_paths": ["review-release.txt"],
                    "results": [{"task": "test", "exit_code": 0, "output": "ok"}],
                },
            )["structuredContent"]
            audit_args = {
                "session_id": session_id,
                "verification_receipt_id": verification["receipt"]["receipt_id"],
            }
            audit = runtime.call_tool(
                "security_audit",
                audit_args,
                request_id="security-audit-retry",
            )
            self.assertFalse(audit["isError"], audit)
            first_audit_id = audit["structuredContent"]["receipt"]["receipt_id"]
            first_audit_at = audit["structuredContent"]["receipt"]["audited_at"]
            retried_audit = runtime.call_tool(
                "security_audit",
                audit_args,
                request_id="security-audit-retry-2",
            )
            self.assertFalse(retried_audit["isError"], retried_audit)
            second_audit_id = retried_audit["structuredContent"]["receipt"]["receipt_id"]
            self.assertEqual(first_audit_id, second_audit_id)
            self.assertEqual(retried_audit["structuredContent"]["receipt"]["audited_at"], first_audit_at)
            self.assertEqual(runtime._director_audit_receipt_history[first_audit_id].audited_at, first_audit_at)
            persisted_audits = runtime._persistence.load_security_audits()
            matching_audits = [item for item in persisted_audits if item["receipt_id"] == first_audit_id]
            self.assertEqual(len(matching_audits), 1)
            lifecycle_events = runtime._persistence.load_request_lifecycle_events(
                request_id="security-audit-retry",
                limit=30,
            )
            self.assertFalse(any(event["event"] == "REQUEST_SIDE_EFFECT_STARTED" for event in lifecycle_events))
            task = runtime._director_ledger.get(started["task"]["task_id"])
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "verifying")
            self.assertEqual(
                runtime._director_writer_manager.active("project-x", working_tree_id=session_id),
                (runtime._director_writer_manager.get(started["lease_id"]),),
            )
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_security_audit_receipt_conflict_maps_publicly_without_poisoning_persistence_health(self) -> None:
        from chatgpt_dev_mcp.persistence import IdempotencyConflict, PersistenceError

        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-security-audit-conflict", "security-audit-conflict.txt")
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: security-audit-conflict.txt\n+evidence\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            verification = runtime.call_tool(
                "verification_record",
                {
                    "session_id": session_id,
                    "changed_paths": ["security-audit-conflict.txt"],
                    "results": [{"task": "test", "exit_code": 0, "output": "ok"}],
                },
            )["structuredContent"]
            audit_args = {
                "session_id": session_id,
                "verification_receipt_id": verification["receipt"]["receipt_id"],
            }
            initial = runtime.call_tool(
                "security_audit",
                audit_args,
                request_id="security-audit-conflict-initial",
            )
            self.assertFalse(initial["isError"], initial)
            before_rows = runtime._persistence.load_security_audits()

            with patch.object(
                runtime._persistence,
                "save_security_audit",
                side_effect=IdempotencyConflict("SECURITY_AUDIT_RECEIPT_CONFLICT"),
            ):
                conflict = runtime.call_tool(
                    "security_audit",
                    audit_args,
                    request_id="security-audit-conflict-replay",
                )

            self.assertTrue(conflict["isError"], conflict)
            conflict_error = conflict["structuredContent"]["error"]
            self.assertEqual(conflict_error["code"], "SECURITY_AUDIT_RECEIPT_CONFLICT")
            self.assertEqual(conflict_error["category"], "conflict")
            self.assertIsNone(runtime._persistence_error)
            self.assertEqual(runtime._persistence.load_security_audits(), before_rows)

            runtime._persistence_error = None
            with patch.object(
                runtime._persistence,
                "save_security_audit",
                side_effect=PersistenceError("fixture write failure"),
            ):
                failed = runtime.call_tool(
                    "security_audit",
                    audit_args,
                    request_id="security-audit-write-failure",
                )

            self.assertTrue(failed["isError"], failed)
            self.assertEqual(
                failed["structuredContent"]["error"]["code"],
                "DIRECTOR_PERSISTENCE_WRITE_FAILED",
            )
            self.assertEqual(runtime._persistence_error, "fixture write failure")
            self.assertEqual(runtime._persistence.load_security_audits(), before_rows)
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_lease_free_review_ready_session_does_not_block_shared_restart(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-review-restart", "review-restart.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            owner_id = started["task"]["owner_id"]
            runtime._director_ledger.transition(task_id, "verifying", owner_id=owner_id)
            runtime._director_ledger.transition(task_id, "review_ready", owner_id=owner_id)
            runtime._release_session_leases(runtime.development_sessions[session_id])

            blockers = runtime._local_maintenance_restart_blockers(
                caller_session_id="session:caller",
                caller_task_id="task-caller",
                caller_worktree_id="worktree:caller",
            )

            self.assertNotIn(session_id, blockers["blocking_session_ids"])
            self.assertNotIn(task_id, blockers["blocking_task_ids"])
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_lease_free_review_ready_canonical_task_does_not_block_shared_restart(self) -> None:
        runtime = self._runtime()
        try:
            task = runtime._director_ledger.enqueue(
                "restart-review-ready-canonical",
                "project-x",
                "Review-ready canonical task",
                working_tree_id="worktree:canonical-review",
                allowed_paths=("README.md",),
            )
            runtime._director_ledger.transition(task.task_id, "running", owner_id="owner-review-ready")
            runtime._director_ledger.transition(task.task_id, "verifying", owner_id="owner-review-ready")
            runtime._director_ledger.transition(task.task_id, "review_ready", owner_id="owner-review-ready")

            blockers = runtime._local_maintenance_restart_blockers(
                caller_session_id="session:caller",
                caller_task_id="task-caller",
                caller_worktree_id="worktree:caller",
            )

            self.assertNotIn(task.task_id, blockers["blocking_task_ids"])
        finally:
            runtime.close()

    def test_fresh_verification_rebinds_a_resumed_running_dirty_task(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-resumed-evidence", "a.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            owner_id = started["task"]["owner_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease"]["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: a.txt\n+from-a\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            verifying = runtime._director_ledger.get(task_id)
            self.assertIsNotNone(verifying)
            self.assertEqual(verifying.status, "verifying")

            runtime._director_ledger.transition(task_id, "stale", owner_id=owner_id, detail="test retained reconnect")
            resumed = runtime._director_ledger.reactivate(
                task_id,
                owner_id=owner_id,
                lease_id=started["lease"]["lease_id"],
                base_revision=started["source_revision"],
                detail="SAFE_LOCAL_SESSION_RESUMED",
            )
            self.assertEqual(resumed.status, "running")
            self.assertEqual(resumed.verification_receipt, "")

            verification = runtime.call_tool(
                "verification_record",
                {
                    "session_id": session_id,
                    "task_id": task_id,
                    "changed_paths": ["a.txt"],
                    "results": [{"task": "test", "exit_code": 0, "output": "ok"}],
                },
            )["structuredContent"]
            rebound = runtime._director_ledger.get(task_id)
            self.assertIsNotNone(rebound)
            self.assertEqual(rebound.status, "verifying")
            self.assertEqual(rebound.verification_receipt, verification["receipt"]["receipt_id"])
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_explicit_session_routes_all_read_tools_and_tasks_after_selected_switch(self) -> None:
        runtime = self._runtime()
        sessions = []
        try:
            first = self._start(runtime, "request-read-a", "a.txt")
            second = self._start(runtime, "request-read-b", "b.txt")
            sessions.extend((first["session_id"], second["session_id"]))
            for started, filename, content in ((first, "a.txt", "from-a"), (second, "b.txt", "from-b")):
                patched = runtime.call_tool(
                    "apply_patch",
                    {
                        "session_id": started["session_id"],
                        "lease_id": started["lease"]["lease_id"],
                        "patch": f"*** Begin Patch\n*** Add File: {filename}\n+{content}\n*** End Patch",
                    },
                )
                self.assertFalse(patched["isError"], patched)

            # Deliberately select B immediately before every explicit A call.
            runtime.call_tool("workspace_open", {"id": second["session_id"]})
            session_a = first["session_id"]
            calls = (
                ("read_file", {"session_id": session_a, "path": "a.txt"}),
                ("list_dir", {"session_id": session_a, "path": "."}),
                ("list_files", {"session_id": session_a, "path": ".", "patterns": ["a.txt"]}),
                ("search_text", {"session_id": session_a, "query": "from-a", "path": "."}),
                ("git_status", {"session_id": session_a, "path": "."}),
                ("git_diff", {"session_id": session_a, "path": "."}),
                ("git_log", {"session_id": session_a, "path": ".", "max_count": 1}),
                ("git_show", {"session_id": session_a, "rev": "HEAD", "include_diff": False}),
                ("git_blame", {"session_id": session_a, "path": "README.md", "max_lines": 1}),
                ("run_task", {"session_id": session_a, "task": "test", "timeout_ms": 5000}),
            )
            for name, arguments in calls:
                result = runtime.call_tool(name, arguments)
                self.assertFalse(result["isError"], (name, result))
            content_result = runtime.call_tool("read_file", {"session_id": session_a, "path": "a.txt"})
            self.assertEqual(content_result["structuredContent"]["content"], "from-a\n")
            task_result = runtime.call_tool("run_task", {"session_id": session_a, "task": "test", "timeout_ms": 5000})
            self.assertEqual(task_result["structuredContent"]["working_tree_id"], first["working_tree_id"])
            self.assertEqual(task_result["structuredContent"]["development_session_id"], session_a)
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_empty_scope_is_rejected_before_worktree_creation(self) -> None:
        runtime = self._runtime()
        try:
            result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-empty",
                    "title": "empty scope",
                    "owner_id": "owner-empty",
                    "paths": [],
                    "resources": [],
                },
            )
            self.assertTrue(result["isError"], result)
            self.assertEqual(result["structuredContent"]["error"]["code"], "INVALID_LEASE_SCOPE")
            self.assertEqual(list((self.home / ".cache" / "local-dev-mcp" / "worktrees").glob("*")), [])
        finally:
            runtime.close()

    def test_workspace_wide_scope_requires_policy_and_reason_and_can_patch_when_explicit(self) -> None:
        config_document = json.loads(self.config.read_text(encoding="utf-8"))
        config_document["workspaces"]["project-x"]["metadata"]["isolated_development"]["allow_workspace_wide"] = True
        self.config.write_text(json.dumps(config_document), encoding="utf-8")
        runtime = self._runtime()
        session_id = None
        try:
            missing_reason = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-wide-no-reason",
                    "title": "wide scope without reason",
                    "owner_id": "owner-wide-no-reason",
                    "paths": [],
                    "resources": [],
                    "workspace_wide": True,
                },
            )
            self.assertTrue(missing_reason["isError"], missing_reason)
            self.assertEqual(missing_reason["structuredContent"]["error"]["code"], "WORKSPACE_WIDE_REASON_REQUIRED")

            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-wide",
                    "title": "explicit wide scope",
                    "owner_id": "owner-wide",
                    "paths": [],
                    "resources": [],
                    "workspace_wide": True,
                    "scope_reason": "bounded foundation migration",
                },
            )
            self.assertFalse(started["isError"], started)
            payload = started["structuredContent"]
            session_id = payload["session_id"]
            self.assertTrue(payload["lease"]["workspace_wide"])
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": payload["lease"]["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: wide-scope.txt\n+wide\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_same_request_id_payload_mismatch_is_an_idempotency_conflict(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            first = self._start(runtime, "request-idempotent", "a.txt")
            session_id = first["session_id"]
            result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-idempotent",
                    "title": "different title",
                    "owner_id": "owner-other",
                    "paths": ["a.txt"],
                    "resources": [],
                },
            )
            self.assertTrue(result["isError"], result)
            self.assertEqual(result["structuredContent"]["error"]["code"], "IDEMPOTENCY_CONFLICT")
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_same_request_id_replay_across_runtime_returns_same_task_session_and_lease(self) -> None:
        first_runtime = self._runtime()
        second_runtime = None
        first_session = None
        try:
            first = self._start(first_runtime, "request-replay", "replay.txt")
            first_session = first["session_id"]
            first_runtime.close()

            second_runtime = self._runtime()
            replay = self._start(second_runtime, "request-replay", "replay.txt")

            self.assertEqual(replay["status"], "active")
            self.assertTrue(replay["reused_existing_request"])
            self.assertEqual(replay["task"]["task_id"], first["task"]["task_id"])
            self.assertEqual(replay["session_id"], first["session_id"])
            self.assertEqual(replay["working_tree_id"], first["working_tree_id"])
            self.assertNotEqual(replay["lease_id"], first["lease"]["lease_id"])
            self.assertEqual(replay["lease"]["lease_id"], replay["lease_id"])
            self.assertFalse(replay.get("reattach_required", False))
        finally:
            if second_runtime is not None:
                second_runtime.close()
            if first_session is not None:
                # The first runtime is intentionally closed before the replay;
                # the retained worktree is resumed under the same identity.
                pass

    def test_explicit_project_start_does_not_inherit_selected_other_project_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        repo_y = self.home / "Developer" / "project-y"
        repo_y.mkdir(parents=True)
        (repo_y / "README.md").write_text("project-y baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_y), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo_y), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo_y), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo_y), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo_y), "commit", "-qm", "initial"], check=True)
        config_document = json.loads(self.config.read_text(encoding="utf-8"))
        config_document["workspaces"]["project-y"] = {
            "path": str(repo_y),
            "profile": "DEVELOPMENT",
            "commands": {"test": "printf project-y-ok"},
            "metadata": {
                "isolated_development": {
                    "auto_create_sessions": True,
                    "max_parallel_sessions": 2,
                    "allowed_base": "registered_project",
                }
            },
        }
        self.config.write_text(json.dumps(config_document), encoding="utf-8")

        runtime = self._runtime()
        session_x = None
        session_y = None
        try:
            started_x = self._start(runtime, "request-project-x", "x.txt")
            session_x = started_x["session_id"]
            selected = runtime.call_tool("workspace_open", {"id": session_x})
            self.assertFalse(selected["isError"], selected)

            started_y_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-y",
                    "request_id": "request-project-y",
                    "title": "project y task",
                    "owner_id": "owner-project-y",
                    "paths": ["y.txt"],
                    "resources": [],
                },
            )
            self.assertFalse(started_y_result["isError"], started_y_result)
            started_y = started_y_result["structuredContent"]
            session_y = started_y["session_id"]
            self.assertNotEqual(session_y, session_x)
            self.assertEqual(started_y["task"]["workspace_id"], "project-y")
            self.assertEqual(started_y["task"]["development_session_id"], session_y)
            self.assertTrue(runtime.call_tool("workspace_session_status", {"session_id": session_x})["structuredContent"]["active"])

            read_y = runtime.call_tool("read_file", {"session_id": session_y, "path": "README.md"})
            self.assertFalse(read_y["isError"], read_y)
            self.assertEqual(read_y["structuredContent"]["content"], "project-y baseline\n")
        finally:
            for session_id in (session_y, session_x):
                if session_id is None:
                    continue
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_explicit_dirty_snapshot_is_used_by_multiple_sessions(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "foundation.js").write_text("dirty foundation\n", encoding="utf-8")
        (self.repo / "foundation-new.js").write_text("new foundation\n", encoding="utf-8")
        runtime = WrapperRuntime()
        sessions = []
        try:
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            first = self._start_with_snapshot(runtime, "request-snapshot-a", "a.txt", snapshot["snapshot_id"])
            second = self._start_with_snapshot(runtime, "request-snapshot-b", "b.txt", snapshot["snapshot_id"])
            third = self._start_with_snapshot(runtime, "request-snapshot-c", "c.txt", snapshot["snapshot_id"])
            sessions.extend((first["session_id"], second["session_id"], third["session_id"]))
            for started in (first, second, third):
                worktree = Path(started["worktree_path"]).expanduser()
                self.assertEqual((worktree / "foundation.js").read_text(encoding="utf-8"), "dirty foundation\n")
                self.assertEqual((worktree / "foundation-new.js").read_text(encoding="utf-8"), "new foundation\n")
                self.assertEqual(started["source_snapshot_id"], snapshot["snapshot_id"])
                self.assertEqual(started["source_snapshot_hash"], snapshot["snapshot_hash"])
            self.assertEqual((self.repo / "foundation.js").read_text(encoding="utf-8"), "dirty foundation\n")
            self.assertFalse((self.repo / "a.txt").exists())
            self.assertFalse((self.repo / "b.txt").exists())
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_workspace_session_diff_uses_only_post_snapshot_delta(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            (self.repo / "foundation.js").write_text("dirty foundation\n", encoding="utf-8")
            (self.repo / "foundation-new.js").write_text("new foundation\n", encoding="utf-8")
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            started = self._start_with_snapshot(
                runtime,
                "request-snapshot-relative-diff",
                "delta.txt",
                snapshot["snapshot_id"],
            )
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: delta.txt\n+session delta\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)

            session_diff = runtime.call_tool(
                "workspace_session_diff",
                {"session_id": session_id, "include_patch": True},
            )
            self.assertFalse(session_diff["isError"], session_diff)
            diff = session_diff["structuredContent"]["diff"]
            self.assertEqual(diff["changed_paths"], ["delta.txt"])
            self.assertIn("delta.txt", diff["patch"])
            self.assertNotIn("foundation.js", diff["patch"])
            self.assertNotIn("foundation-new.js", diff["patch"])
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_snapshot_verification_run_fingerprint_uses_only_post_snapshot_delta(self) -> None:
        from chatgpt_dev_mcp.verification_cache import verification_input_fingerprint

        runtime = self._runtime()
        session_id = None
        try:
            (self.repo / "README.md").write_text("dirty snapshot baseline\n", encoding="utf-8")
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            started = self._start_with_snapshot(
                runtime,
                "request-snapshot-verification-fingerprint",
                "README.md",
                snapshot["snapshot_id"],
            )
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: README.md\n"
                        "@@\n"
                        "-dirty snapshot baseline\n"
                        "+session verification delta\n"
                        "*** End Patch"
                    ),
                },
            )
            self.assertFalse(patched["isError"], patched)
            session_diff = runtime.call_tool(
                "workspace_session_diff",
                {"session_id": session_id, "include_patch": True},
            )["structuredContent"]["diff"]
            verified = runtime.call_tool(
                "verification_run",
                {
                    "session_id": session_id,
                    "task_id": started["task"]["task_id"],
                    "mode": "fast",
                    "changed_paths": ["README.md"],
                },
            )
            self.assertFalse(verified["isError"], verified)
            expected = verification_input_fingerprint(
                Path(started["worktree_path"]).expanduser(),
                changed_paths=("README.md",),
                diff_text=session_diff["patch"],
                diff_known=True,
            )
            self.assertEqual(verified["structuredContent"]["relevant_diff_hash"], expected)
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_snapshot_verification_record_and_audit_bind_post_snapshot_patch_hash(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            (self.repo / "foundation.js").write_text("dirty snapshot baseline\n", encoding="utf-8")
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            started = self._start_with_snapshot(
                runtime,
                "request-snapshot-verification-receipt",
                "delta.txt",
                snapshot["snapshot_id"],
            )
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: delta.txt\n+session verification receipt\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            session_diff = runtime.call_tool(
                "workspace_session_diff",
                {"session_id": session_id, "include_patch": False},
            )["structuredContent"]["diff"]
            verification = runtime.call_tool(
                "verification_record",
                {
                    "session_id": session_id,
                    "changed_paths": ["delta.txt"],
                    "results": [{"task": "test", "exit_code": 0, "output": "snapshot verification passed"}],
                },
            )
            self.assertFalse(verification["isError"], verification)
            receipt = verification["structuredContent"]["receipt"]
            self.assertEqual(receipt["diff_hash"], session_diff["patch_hash"])

            audit = runtime.call_tool(
                "security_audit",
                {
                    "session_id": session_id,
                    "verification_receipt_id": receipt["receipt_id"],
                },
            )
            self.assertFalse(audit["isError"], audit)
            audit_receipt = audit["structuredContent"]["receipt"]
            self.assertEqual(audit_receipt["diff_hash"], session_diff["patch_hash"])
            self.assertEqual(audit_receipt["patch_hash"], session_diff["patch_hash"])
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_safe_local_resume_accepts_snapshot_relative_compatible_dirty_baseline(self) -> None:
        runtime = self._runtime()
        reconnected = None
        session_id = None
        try:
            (self.repo / "README.md").write_text("dirty snapshot baseline\n", encoding="utf-8")
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            request_id = "request-snapshot-safe-resume"
            started = self._start_with_snapshot(runtime, request_id, "README.md", snapshot["snapshot_id"])
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: README.md\n"
                        "@@\n"
                        "-dirty snapshot baseline\n"
                        "+retained snapshot delta\n"
                        "*** End Patch"
                    ),
                },
            )
            self.assertFalse(patched["isError"], patched)
            runtime.close()

            reconnected = self._runtime()
            resumed = reconnected.call_tool(
                "workspace_resume_development_session",
                {
                    "session_id": session_id,
                    "owner_id": f"owner-{request_id}",
                    "task_id": task_id,
                },
            )
            self.assertFalse(resumed["isError"], resumed)
            payload = resumed["structuredContent"]
            self.assertTrue(payload["resumed"])
            self.assertEqual(payload["recovery_decision"], {"safe_to_resume": True, "reasons": []})
            self.assertEqual(
                (Path(payload["worktree_path"]).expanduser() / "README.md").read_text(encoding="utf-8"),
                "retained snapshot delta\n",
            )
            self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), "dirty snapshot baseline\n")
        finally:
            if reconnected is not None:
                reconnected.close()
            else:
                runtime.close()

    def test_snapshot_session_integration_preflight_and_apply_use_only_post_snapshot_delta(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            (self.repo / "foundation.js").write_text("dirty foundation\n", encoding="utf-8")
            (self.repo / "foundation-new.js").write_text("new foundation\n", encoding="utf-8")
            snapshot_result = runtime.call_tool("director_baseline_snapshot", {"workspace_id": "project-x"})
            self.assertFalse(snapshot_result["isError"], snapshot_result)
            snapshot = snapshot_result["structuredContent"]
            started = self._start_with_snapshot(
                runtime,
                "request-snapshot-relative-integration",
                "delta.txt",
                snapshot["snapshot_id"],
            )
            session_id = started["session_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: delta.txt\n+session delta\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            verification = runtime.call_tool(
                "verification_record",
                {
                    "session_id": session_id,
                    "changed_paths": ["delta.txt"],
                    "results": [{"task": "test", "exit_code": 0, "output": "snapshot delta verified"}],
                },
            )
            self.assertFalse(verification["isError"], verification)
            audit = runtime.call_tool("security_audit", {"session_id": session_id})
            self.assertFalse(audit["isError"], audit)

            session_diff = runtime.call_tool(
                "workspace_session_diff",
                {"session_id": session_id, "include_patch": False},
            )["structuredContent"]["diff"]
            self.assertEqual(session_diff["changed_paths"], ["delta.txt"])
            self.assertEqual(audit["structuredContent"]["receipt"]["patch_hash"], session_diff["patch_hash"])

            preflight = runtime.call_tool("workspace_integration_preflight", {"session_id": session_id})
            self.assertFalse(preflight["isError"], preflight)
            payload = preflight["structuredContent"]
            self.assertTrue(payload["integration_ready"], payload)
            self.assertEqual(payload["changed_paths"], ["delta.txt"])
            integrated = runtime.call_tool(
                "workspace_integrate_development_session",
                {
                    "session_id": session_id,
                    "approval_token": payload["approval_token"],
                    "confirmation": payload["confirmation"],
                },
            )
            self.assertFalse(integrated["isError"], integrated)
            self.assertTrue(integrated["structuredContent"]["result"]["applied"], integrated)
            self.assertEqual((self.repo / "delta.txt").read_text(encoding="utf-8"), "session delta\n")
            self.assertEqual((self.repo / "foundation.js").read_text(encoding="utf-8"), "dirty foundation\n")
            self.assertEqual((self.repo / "foundation-new.js").read_text(encoding="utf-8"), "new foundation\n")

            repeated = runtime.call_tool(
                "workspace_integrate_development_session",
                {
                    "session_id": session_id,
                    "approval_token": payload["approval_token"],
                    "confirmation": payload["confirmation"],
                },
            )
            self.assertFalse(repeated["isError"], repeated)
            self.assertEqual(repeated["structuredContent"]["status"], "already_integrated")
            self.assertFalse(repeated["structuredContent"]["mutation_performed"])
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_approval_bound_arbitrary_command_is_public_and_exactly_session_scoped(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-command", "command.txt")
            session_id = started["session_id"]
            preflight = runtime.call_tool(
                "arbitrary_command_preflight",
                {
                    "session_id": session_id,
                    "argv": ["printf", "public-ok"],
                    "workdir": ".",
                    "timeout_ms": 5000,
                },
            )
            self.assertFalse(preflight["isError"], preflight)
            approval = preflight["structuredContent"]
            self.assertTrue(approval["one_shot"])

            result = runtime.call_tool(
                "arbitrary_command_run",
                {
                    "session_id": session_id,
                    "approval_token": approval["approval_token"],
                    "confirmation": approval["confirmation"],
                },
            )
            self.assertFalse(result["isError"], result)
            self.assertIn("public-ok", result["structuredContent"]["output"])
            self.assertEqual(result["structuredContent"]["workspace_id"], "project-x")
            self.assertEqual(result["structuredContent"]["working_tree_id"], session_id)
            self.assertEqual(result["structuredContent"]["task_id"], started["task"]["task_id"])
        finally:
            if session_id is not None:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_safe_local_session_resume_preserves_identity_dirty_work_and_reacquires_lease(self) -> None:
        runtime = self._runtime()
        reconnected = None
        session_id = None
        try:
            started = self._start(runtime, "request-resume", "resume.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            old_lease_id = started["lease_id"]
            worktree_id = started["working_tree_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": old_lease_id,
                    "patch": "*** Begin Patch\n*** Add File: resume.txt\n+retained\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            runtime.close()

            reconnected = self._runtime()
            wrong_owner = reconnected.call_tool(
                "workspace_resume_development_session",
                {"session_id": session_id, "owner_id": "different-owner", "task_id": task_id},
            )
            self.assertTrue(wrong_owner["isError"], wrong_owner)
            self.assertEqual(wrong_owner["structuredContent"]["error"]["code"], "AUTO_RESUME_NOT_ALLOWED")

            resumed = reconnected.call_tool(
                "workspace_resume_development_session",
                {"session_id": session_id, "owner_id": "owner-request-resume", "task_id": task_id},
            )
            self.assertFalse(resumed["isError"], resumed)
            payload = resumed["structuredContent"]
            self.assertEqual(payload["session_id"], session_id)
            self.assertEqual(payload["working_tree_id"], worktree_id)
            self.assertEqual(payload["task"]["task_id"], task_id)
            self.assertEqual(payload["status"], "active")
            self.assertTrue(payload["resumed"])
            self.assertEqual(payload["recovery_decision"], {"safe_to_resume": True, "reasons": []})
            self.assertNotEqual(payload["lease_id"], old_lease_id)
            self.assertEqual((Path(payload["worktree_path"]).expanduser() / "resume.txt").read_text(encoding="utf-8"), "retained\n")
            self.assertFalse((self.repo / "resume.txt").exists())
            second_patch = reconnected.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": payload["lease_id"],
                    "patch": "*** Begin Patch\n*** Update File: resume.txt\n@@\n-retained\n+retained-again\n*** End Patch",
                },
            )
            self.assertFalse(second_patch["isError"], second_patch)
        finally:
            if reconnected is not None:
                reconnected.close()
            elif runtime is not None:
                runtime.close()

    def test_safe_local_session_resume_rejects_canonical_path_conflict(self) -> None:
        runtime = self._runtime()
        reconnected = None
        session_id = None
        try:
            started = self._start(runtime, "request-resume-conflict", "resume-conflict.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: resume-conflict.txt\n+retained\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            runtime.close()

            (self.repo / "resume-conflict.txt").write_text("canonical\n", encoding="utf-8")
            reconnected = self._runtime()
            resumed = reconnected.call_tool(
                "workspace_resume_development_session",
                {
                    "session_id": session_id,
                    "owner_id": "owner-request-resume-conflict",
                    "task_id": task_id,
                },
            )
            self.assertTrue(resumed["isError"], resumed)
            error = resumed["structuredContent"]["error"]
            self.assertEqual(error["code"], "AUTO_RESUME_NOT_ALLOWED")
            self.assertEqual(error["details"]["reason"], "RECOVERY_DECISION_BLOCKED")
            self.assertIn("CANONICAL_HEAD_CHANGED", error["details"]["reasons"])
        finally:
            if reconnected is not None:
                reconnected.close()
            elif runtime is not None:
                runtime.close()

    def test_crash_restart_marks_session_bindings_stale_and_rebinds_runtime(self) -> None:
        """A child crash must not leave a durable lease blocking safe resume."""

        runtime = self._runtime()
        reconnected = None
        session_id = None
        try:
            started = self._start(runtime, "request-crash-recovery", "crash-recovery.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            old_lease_id = started["lease_id"]

            # Deliberately do not call WrapperRuntime.close(): this models the
            # child disappearing while its SQLite lease is still active.
            reconnected = self._runtime()
            old_lease = next(
                item for item in reconnected._persistence.load_leases() if item["lease_id"] == old_lease_id
            )
            old_task = next(
                item for item in reconnected._persistence.load_tasks() if item["task_id"] == task_id
            )
            self.assertEqual(old_lease["state"], "stale")
            self.assertEqual(old_task["state"], "stale")

            resumed = reconnected.call_tool(
                "workspace_resume_development_session",
                {
                    "session_id": session_id,
                    "owner_id": "owner-request-crash-recovery",
                    "task_id": task_id,
                },
            )
            self.assertFalse(resumed["isError"], resumed)
            payload = resumed["structuredContent"]
            self.assertEqual(payload["session_id"], session_id)
            self.assertNotEqual(payload["lease_id"], old_lease_id)
            self.assertEqual(reconnected.current.identifier, session_id)
            self.assertIs(reconnected.upstream, reconnected._development_runtimes[session_id])

            diff = reconnected.call_tool("workspace_session_diff", {"session_id": session_id})
            self.assertFalse(diff["isError"], diff)
        finally:
            if reconnected is not None:
                reconnected.close()
            # Close only the child runtime object from the crashed wrapper;
            # closing the wrapper itself would overwrite the resumed session's
            # durable active state with a stale marker.
            for child_runtime in tuple(runtime._development_runtimes.values()):
                try:
                    child_runtime.close()
                except Exception:
                    pass

    def test_old_wrapper_close_does_not_clobber_newer_resumed_session_state(self) -> None:
        runtime = self._runtime()
        reconnected = None
        old_closed = False
        try:
            started = self._start(runtime, "request-generation-fence", "generation-fence.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]

            reconnected = self._runtime()
            resumed = reconnected.call_tool(
                "workspace_resume_development_session",
                {
                    "session_id": session_id,
                    "owner_id": "owner-request-generation-fence",
                    "task_id": task_id,
                },
            )
            self.assertFalse(resumed["isError"], resumed)

            runtime.close()
            old_closed = True

            persisted = next(
                item
                for item in reconnected._persistence.load_development_sessions()
                if item["session_id"] == session_id
            )
            self.assertFalse(persisted["stale"])
            self.assertEqual(persisted["lifecycle_state"], "active")
        finally:
            if reconnected is not None:
                reconnected.close()
            if not old_closed:
                for child_runtime in tuple(runtime._development_runtimes.values()):
                    try:
                        child_runtime.close()
                    except Exception:
                        pass

    def test_preserve_active_restore_stales_session_without_exact_task_and_lease(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = self._runtime()
        preserved = None
        try:
            started = self._start(runtime, "request-orphan-active", "orphan-active.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            lease = runtime._director_writer_manager.get(started["lease_id"])
            self.assertIsNotNone(lease)
            runtime._director_writer_manager.release(lease)
            runtime._director_ledger.transition(
                task_id,
                "stale",
                owner_id="owner-request-orphan-active",
            )

            preserved = WrapperRuntime(preserve_persistent_state=True)
            restored = preserved.development_sessions[session_id]
            self.assertTrue(restored.stale)
            self.assertEqual(restored.lifecycle_state, "stale")
        finally:
            if preserved is not None:
                preserved.close()
            for child_runtime in tuple(runtime._development_runtimes.values()):
                try:
                    child_runtime.close()
                except Exception:
                    pass

    def test_authorized_write_and_verification_refresh_exact_writer_lease(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        now = [100.0]
        runtime = WrapperRuntime(clock=lambda: now[0])
        try:
            started = self._start(runtime, "request-lease-heartbeat", "lease-heartbeat.txt")
            lease_id = started["lease_id"]
            session_id = started["session_id"]
            initial = runtime._director_writer_manager.get(lease_id)
            self.assertIsNotNone(initial)
            initial_expires_at = initial.expires_at

            now[0] += 100.0
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": lease_id,
                    "patch": "*** Begin Patch\n*** Add File: lease-heartbeat.txt\n+heartbeat\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)

            after_write = runtime._director_writer_manager.get(lease_id)
            self.assertIsNotNone(after_write)
            self.assertGreater(after_write.expires_at, initial_expires_at)

            now[0] += 100.0
            verified = runtime.call_tool(
                "verification_run",
                {
                    "session_id": session_id,
                    "task_id": started["task"]["task_id"],
                    "mode": "fast",
                    "changed_paths": ["lease-heartbeat.txt"],
                },
            )
            self.assertFalse(verified["isError"], verified)

            after_verification = runtime._director_writer_manager.get(lease_id)
            self.assertIsNotNone(after_verification)
            self.assertGreater(after_verification.expires_at, after_write.expires_at)
        finally:
            runtime.close()

    def test_failed_multi_file_patch_does_not_leave_partial_mutation(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-atomic-patch-failure",
                    "title": "atomic patch failure",
                    "owner_id": "owner-request-atomic-patch-failure",
                    "paths": ["atomic-first.txt", "atomic-missing.txt"],
                    "resources": [],
                },
            )
            self.assertFalse(started_result["isError"], started_result)
            started = started_result["structuredContent"]
            session_id = started["session_id"]
            worktree = Path(started["worktree_path"]).expanduser()

            result = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": session_id,
                    "lease_id": started["lease_id"],
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Add File: atomic-first.txt\n"
                        "+first\n"
                        "*** Update File: atomic-missing.txt\n"
                        "@@\n"
                        "-missing\n"
                        "+changed\n"
                        "*** End Patch"
                    ),
                },
            )

            self.assertTrue(result["isError"], result)
            self.assertFalse((worktree / "atomic-first.txt").exists())
            self.assertFalse((worktree / "atomic-missing.txt").exists())
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_same_request_id_auto_resumes_retained_session_without_new_identity(self) -> None:
        runtime = self._runtime()
        reconnected = None
        try:
            started = self._start(runtime, "request-idempotent-resume", "resume-idempotent.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            worktree_id = started["working_tree_id"]
            runtime.close()

            reconnected = self._runtime()
            replay = self._start(reconnected, "request-idempotent-resume", "resume-idempotent.txt")
            self.assertEqual(replay["status"], "active")
            self.assertTrue(replay["reused_existing_request"])
            self.assertTrue(replay["resumed"])
            self.assertEqual(replay["session_id"], session_id)
            self.assertEqual(replay["working_tree_id"], worktree_id)
            self.assertEqual(replay["task"]["task_id"], task_id)
            self.assertFalse(replay.get("reattach_required", False))
        finally:
            if reconnected is not None:
                reconnected.close()
            elif runtime is not None:
                runtime.close()

    def test_resuming_one_session_does_not_stale_or_close_other_parallel_sessions(self) -> None:
        runtime = self._runtime()
        try:
            first = self._start(runtime, "request-resume-a", "a-resume.txt")
            second = self._start(runtime, "request-resume-b", "b-resume.txt")
            third = self._start(runtime, "request-resume-c", "c-resume.txt")
            first_session_id = first["session_id"]
            first_task_id = first["task"]["task_id"]

            first_lease = runtime._director_writer_manager.get(first["lease_id"])
            self.assertIsNotNone(first_lease)
            runtime._director_writer_manager.release(first_lease)
            runtime._director_ledger.transition(first_task_id, "stale", owner_id="owner-request-resume-a")
            first_session = runtime.development_sessions[first_session_id]
            first_session.stale = True
            first_session.lifecycle_state = "stale"
            old_runtime = runtime._development_runtimes.pop(first_session_id)
            old_runtime.close()

            resumed = runtime.call_tool(
                "workspace_resume_development_session",
                {"session_id": first_session_id, "owner_id": "owner-request-resume-a", "task_id": first_task_id},
            )
            self.assertFalse(resumed["isError"], resumed)
            self.assertEqual(resumed["structuredContent"]["session_id"], first_session_id)
            for other in (second, third):
                status = runtime.call_tool("workspace_session_status", {"session_id": other["session_id"]})
                self.assertFalse(status["isError"], status)
                self.assertTrue(status["structuredContent"]["active"], status)
                self.assertIn(other["session_id"], runtime._development_runtimes)
        finally:
            runtime.close()

    def test_reattach_request_for_retained_session_ignores_unrelated_parallel_active_session(self) -> None:
        runtime = self._runtime()
        try:
            retained = self._start(runtime, "request-reattach-retained", "reattach-retained.txt")
            active = self._start(runtime, "request-reattach-active", "reattach-active.txt")

            retained_session_id = retained["session_id"]
            retained_task_id = retained["task"]["task_id"]
            retained_lease = runtime._director_writer_manager.get(retained["lease_id"])
            self.assertIsNotNone(retained_lease)
            runtime._director_writer_manager.release(retained_lease)
            runtime._director_ledger.transition(
                retained_task_id,
                "stale",
                owner_id="owner-request-reattach-retained",
            )
            retained_session = runtime.development_sessions[retained_session_id]
            retained_session.stale = True
            retained_session.lifecycle_state = "suspended"
            retained_runtime = runtime._development_runtimes.pop(retained_session_id)
            retained_runtime.close()

            selected = runtime.call_tool("workspace_open", {"id": active["session_id"]})
            self.assertFalse(selected["isError"], selected)
            self.assertEqual(runtime.active_development_session_id, active["session_id"])

            requested = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": retained_session_id},
            )

            self.assertFalse(requested["isError"], requested)
            payload = requested["structuredContent"]
            self.assertEqual(payload["session_id"], retained_session_id)
            self.assertTrue(payload["approval_token"].startswith("approval:"))
            self.assertEqual(payload["status"], "stale_clean")

            attached = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": retained_session_id,
                    "approval_token": payload["approval_token"],
                    "confirmation": payload["confirmation"],
                },
            )
            self.assertFalse(attached["isError"], attached)
            attached_payload = attached["structuredContent"]
            self.assertEqual(attached_payload["session_id"], retained_session_id)
            self.assertTrue(attached_payload["resumed"])
            self.assertIn(retained_session_id, runtime._development_runtimes)

            active_status = runtime.call_tool(
                "workspace_session_status",
                {"session_id": active["session_id"]},
            )
            self.assertFalse(active_status["isError"], active_status)
            self.assertTrue(active_status["structuredContent"]["active"])
        finally:
            runtime.close()

    def test_status_summary_reports_stale_task_session_without_mutating_durable_state(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(
                runtime,
                "request-status-reconcile-stale-task",
                "status-reconcile-stale-task.txt",
            )
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            lease = runtime._director_writer_manager.get(started["lease_id"])
            self.assertIsNotNone(lease)
            runtime._director_writer_manager.release(lease)
            runtime._director_ledger.transition(
                task_id,
                "stale",
                owner_id="owner-request-status-reconcile-stale-task",
            )

            before = runtime.call_tool(
                "workspace_session_status",
                {"session_id": session_id},
            )
            self.assertFalse(before["isError"], before)
            self.assertTrue(before["structuredContent"]["active"])
            before_task = runtime._persistence.load_tasks(workspace_id="project-x")
            before_session = [
                item
                for item in runtime._persistence.load_development_sessions()
                if item.get("session_id") == session_id
            ]

            summary = runtime.call_tool(
                "director_status_summary",
                {"workspace_id": "project-x"},
            )

            self.assertFalse(summary["isError"], summary)
            payload = summary["structuredContent"]
            self.assertNotIn(session_id, payload["summary"]["active_session_ids"])
            self.assertEqual(payload["current"]["session_count"], 0)
            after = runtime.call_tool(
                "workspace_session_status",
                {"session_id": session_id},
            )
            self.assertFalse(after["isError"], after)
            self.assertTrue(after["structuredContent"]["active"])
            self.assertEqual(runtime._persistence.load_tasks(workspace_id="project-x"), before_task)
            self.assertEqual(
                [
                    item
                    for item in runtime._persistence.load_development_sessions()
                    if item.get("session_id") == session_id
                ],
                before_session,
            )
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_evidence_observers_do_not_reconcile_an_expired_active_session(self) -> None:
        from chatgpt_dev_mcp.development import session_sidecar_root

        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-observer-expired-session", "observer-expired-session.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            owner_id = started["task"]["owner_id"]
            lease = runtime._director_writer_manager.get(started["lease_id"])
            self.assertIsNotNone(lease)
            runtime._director_writer_manager.release(lease)
            runtime._director_ledger.transition(task_id, "stale", owner_id=owner_id)

            session = runtime.development_sessions[session_id]
            session.expires_at = runtime._now()
            sidecar_path = session_sidecar_root() / f"{session_id.removeprefix('session:')}.json"
            before = {
                "tasks": runtime._persistence.load_tasks(workspace_id="project-x"),
                "sessions": [
                    item
                    for item in runtime._persistence.load_development_sessions()
                    if item.get("session_id") == session_id
                ],
                "leases": runtime._persistence.load_leases(),
                "sidecar": sidecar_path.read_bytes(),
                "active_session_id": runtime.active_development_session_id,
                "session_stale": session.stale,
                "session_lifecycle": session.lifecycle_state,
            }

            calls = (
                ("semantic_code_query", {"session_id": session_id, "query": "README", "relations": [], "refresh_paths": []}),
                (
                    "development_context",
                    {
                        "session_id": session_id,
                        "task_id": task_id,
                        "query": "README",
                        "target_paths": [],
                        "diff_paths": [],
                        "max_bytes": 1024,
                    },
                ),
                ("workspace_list_development_sessions", {"workspace_id": "project-x"}),
                ("director_status_summary", {"workspace_id": "project-x"}),
            )
            for name, arguments in calls:
                result = runtime.call_tool(name, arguments)
                self.assertIn("structuredContent", result, result)

            after = {
                "tasks": runtime._persistence.load_tasks(workspace_id="project-x"),
                "sessions": [
                    item
                    for item in runtime._persistence.load_development_sessions()
                    if item.get("session_id") == session_id
                ],
                "leases": runtime._persistence.load_leases(),
                "sidecar": sidecar_path.read_bytes(),
                "active_session_id": runtime.active_development_session_id,
                "session_stale": session.stale,
                "session_lifecycle": session.lifecycle_state,
            }
            self.assertEqual(after, before)
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_safe_local_resume_accepts_exact_active_verifying_task_and_lease(self) -> None:
        runtime = self._runtime()
        session_id = None
        try:
            started = self._start(runtime, "request-resume-verifying", "resume-verifying.txt")
            session_id = started["session_id"]
            task_id = started["task"]["task_id"]
            lease_id = started["lease_id"]
            owner_id = "owner-request-resume-verifying"

            runtime._director_ledger.transition(
                task_id,
                "verifying",
                owner_id=owner_id,
            )

            resumed = runtime.call_tool(
                "workspace_resume_development_session",
                {"session_id": session_id, "owner_id": owner_id, "task_id": task_id},
            )

            self.assertFalse(resumed["isError"], resumed)
            payload = resumed["structuredContent"]
            self.assertEqual(payload["session_id"], session_id)
            self.assertEqual(payload["lease_id"], lease_id)
            self.assertEqual(payload["task"]["status"], "verifying")
            self.assertFalse(payload["resumed"])
        finally:
            if session_id is not None:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_shared_restart_checkpoints_snapshot_baseline_with_only_leased_delta(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        restart_calls: list[tuple[str, ...]] = []
        try:
            owner = self._start(runtime, "request-restart-snapshot-owner", "restart-snapshot-owner.txt")
            sessions.append(owner["session_id"])
            (self.repo / "baseline-only.txt").write_text("snapshot baseline\n", encoding="utf-8")
            snapshot = create_baseline_snapshot(
                self.repo,
                workspace_id="project-x",
                artifact_root=runtime._snapshot_artifact_root(),
            )
            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-restart-snapshot-worker",
                    "title": "snapshot worker",
                    "owner_id": "owner-request-restart-snapshot-worker",
                    "paths": ["restart-snapshot-worker.txt"],
                    "resources": [],
                    "source_snapshot_id": snapshot.snapshot_id,
                },
            )
            self.assertFalse(started["isError"], started)
            worker = started["structuredContent"]
            sessions.append(worker["session_id"])
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-snapshot-worker.txt\n+task delta\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: restart_calls.append(argv) or MaintenanceRunResult(0, True, "queued")
            )

            restarted = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-snapshot-owner",
                },
            )

            self.assertFalse(restarted["isError"], restarted)
            self.assertEqual(len(restart_calls), 1)
            persisted = {
                item["session_id"]: item
                for item in runtime._require_persistence().load_development_sessions()
            }
            checkpoint = persisted[worker["session_id"]]["metadata"]["restart_checkpoint"]
            self.assertEqual(checkpoint["changed_paths"], ["restart-snapshot-worker.txt"])
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_shared_restart_rejects_snapshot_baseline_path_changed_outside_lease(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        try:
            owner = self._start(runtime, "request-restart-snapshot-guard-owner", "restart-snapshot-guard-owner.txt")
            sessions.append(owner["session_id"])
            (self.repo / "baseline-guard.txt").write_text("snapshot baseline\n", encoding="utf-8")
            snapshot = create_baseline_snapshot(
                self.repo,
                workspace_id="project-x",
                artifact_root=runtime._snapshot_artifact_root(),
            )
            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-restart-snapshot-guard-worker",
                    "title": "snapshot guard worker",
                    "owner_id": "owner-request-restart-snapshot-guard-worker",
                    "paths": ["restart-snapshot-guard-worker.txt"],
                    "resources": [],
                    "source_snapshot_id": snapshot.snapshot_id,
                },
            )
            self.assertFalse(started["isError"], started)
            worker = started["structuredContent"]
            sessions.append(worker["session_id"])
            worker_session = runtime.development_sessions[worker["session_id"]]
            (worker_session.worktree_path / "baseline-guard.txt").write_text(
                "changed outside lease\n",
                encoding="utf-8",
            )
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )

            restarted = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-snapshot-guard-owner",
                },
            )

            self.assertTrue(restarted["isError"], restarted)
            self.assertEqual(
                restarted["structuredContent"]["error"]["code"],
                "LOCAL_MAINTENANCE_RESTART_CHECKPOINT_FAILED",
            )
            self.assertEqual(
                restarted["structuredContent"]["error"]["details"]["session_id"],
                worker["session_id"],
            )
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_shared_restart_checkpoints_other_dirty_development_session(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        restart_calls: list[tuple[str, ...]] = []
        try:
            first = self._start(runtime, "request-restart-owner", "restart-owner.txt")
            second = self._start(runtime, "request-restart-blocker", "restart-blocker.txt")
            sessions.extend((first["session_id"], second["session_id"]))
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": second["session_id"],
                    "lease_id": second["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-blocker.txt\n+dirty but checkpointable\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: restart_calls.append(argv) or MaintenanceRunResult(0, True, "queued")
            )

            result = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": first["session_id"],
                    "task_id": first["task"]["task_id"],
                    "owner_id": "owner-request-restart-owner",
                },
            )

            self.assertFalse(result["isError"], result)
            self.assertEqual(len(restart_calls), 1)
            persisted = {
                item["session_id"]: item
                for item in runtime._require_persistence().load_development_sessions()
            }
            checkpoint = persisted[second["session_id"]]["metadata"]["restart_checkpoint"]
            self.assertEqual(checkpoint["session_id"], second["session_id"])
            self.assertEqual(checkpoint["task_id"], second["task"]["task_id"])
            self.assertEqual(checkpoint["lease_id"], second["lease_id"])
            self.assertEqual(checkpoint["source_child_instance_id"], runtime.child_instance_id)
            self.assertEqual(
                checkpoint["scope_hashes"],
                runtime._director_scope_snapshot(
                    runtime.development_sessions[second["session_id"]].worktree_path,
                    tuple(second["lease"]["paths"]),
                    workspace_wide=False,
                ),
            )
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_restart_fence_rejects_mutation_after_restart_is_scheduled(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        try:
            first = self._start(runtime, "request-restart-fence-owner", "restart-fence-owner.txt")
            second = self._start(runtime, "request-restart-fence-worker", "restart-fence-worker.txt")
            sessions.extend((first["session_id"], second["session_id"]))
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )

            restarted = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": first["session_id"],
                    "task_id": first["task"]["task_id"],
                    "owner_id": "owner-request-restart-fence-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            mutation = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": second["session_id"],
                    "lease_id": second["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-fence-worker.txt\n+must not run\n*** End Patch",
                },
            )

            self.assertTrue(mutation["isError"], mutation)
            self.assertEqual(
                mutation["structuredContent"]["error"]["code"],
                "RUNTIME_RESTART_FENCED",
            )
            status = runtime.call_tool(
                "workspace_session_status",
                {"session_id": second["session_id"]},
            )
            self.assertFalse(status["isError"], status)
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_restart_checkpoint_recovers_unchanged_dirty_session_on_new_child(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-restart-recovery-owner", "restart-recovery-owner.txt")
            worker = self._start(first_runtime, "request-restart-recovery-worker", "restart-recovery-worker.txt")
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-recovery-worker.txt\n+preserve me\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )
            old_child_id = first_runtime.child_instance_id

            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-recovery-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            first_runtime.close()
            first_runtime = None
            second_runtime = self._runtime()
            self.assertNotEqual(second_runtime.child_instance_id, old_child_id)

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertTrue(status["structuredContent"]["active"], status)
            self.assertFalse(status["structuredContent"]["stale"], status)
            task = second_runtime._director_ledger.get(worker["task"]["task_id"])
            self.assertIsNotNone(task)
            self.assertIn(task.status, {"leased", "running", "verifying", "review_ready"})
            leases = second_runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=worker["session_id"],
            )
            self.assertEqual([lease.lease_id for lease in leases], [worker["lease_id"]])
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_restart_checkpoint_recovers_caller_session_on_new_child(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(
                first_runtime,
                "request-restart-caller-recovery-owner",
                "restart-caller-recovery-owner.txt",
            )
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": owner["session_id"],
                    "lease_id": owner["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-caller-recovery-owner.txt\n+preserve caller\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )

            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-caller-recovery-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            first_runtime.close()
            first_runtime = None
            second_runtime = self._runtime()

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": owner["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertTrue(status["structuredContent"]["active"], status)
            self.assertFalse(status["structuredContent"]["stale"], status)
            task = second_runtime._director_ledger.get(owner["task"]["task_id"])
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "running")
            leases = second_runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=owner["session_id"],
            )
            self.assertEqual([lease.lease_id for lease in leases], [owner["lease_id"]])
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_restart_checkpoint_recovers_snapshot_baseline_session_on_new_child(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(
                first_runtime,
                "request-restart-snapshot-recovery-owner",
                "restart-snapshot-recovery-owner.txt",
            )
            (self.repo / "snapshot-baseline.txt").write_text("snapshot baseline\n", encoding="utf-8")
            snapshot = create_baseline_snapshot(
                self.repo,
                workspace_id="project-x",
                artifact_root=first_runtime._snapshot_artifact_root(),
            )
            started = first_runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-restart-snapshot-recovery-worker",
                    "title": "snapshot recovery worker",
                    "owner_id": "owner-request-restart-snapshot-recovery-worker",
                    "paths": ["restart-snapshot-recovery-worker.txt"],
                    "resources": [],
                    "source_snapshot_id": snapshot.snapshot_id,
                },
            )
            self.assertFalse(started["isError"], started)
            worker = started["structuredContent"]
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-snapshot-recovery-worker.txt\n+preserve me\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )

            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-snapshot-recovery-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            first_runtime.close()
            first_runtime = None
            second_runtime = self._runtime()

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertTrue(status["structuredContent"]["active"], status)
            self.assertFalse(status["structuredContent"]["stale"], status)
            task = second_runtime._director_ledger.get(worker["task"]["task_id"])
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "running")
            leases = second_runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=worker["session_id"],
            )
            self.assertEqual([lease.lease_id for lease in leases], [worker["lease_id"]])
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_restart_checkpoint_scope_change_fails_closed_to_stale_retained(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-restart-mismatch-owner", "restart-mismatch-owner.txt")
            worker = self._start(first_runtime, "request-restart-mismatch-worker", "restart-mismatch-worker.txt")
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-mismatch-worker.txt\n+checkpointed\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )
            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-mismatch-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            worker_session = first_runtime.development_sessions[worker["session_id"]]
            (worker_session.worktree_path / "restart-mismatch-worker.txt").write_text(
                "changed after checkpoint\n",
                encoding="utf-8",
            )
            first_runtime.close()
            first_runtime = None
            second_runtime = self._runtime()

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertFalse(status["structuredContent"]["active"], status)
            self.assertTrue(status["structuredContent"]["stale"], status)
            self.assertEqual(status["structuredContent"]["status"], "stale_dirty_retained")
            leases = second_runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=worker["session_id"],
            )
            self.assertEqual(leases, ())
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_restart_checkpoint_out_of_scope_change_fails_closed_to_stale_retained(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-restart-outside-owner", "restart-outside-owner.txt")
            worker = self._start(first_runtime, "request-restart-outside-worker", "restart-outside-worker.txt")
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-outside-worker.txt\n+checkpointed\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )
            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-outside-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)

            worker_session = first_runtime.development_sessions[worker["session_id"]]
            (worker_session.worktree_path / "outside-restart-scope.txt").write_text(
                "external out-of-scope change\n",
                encoding="utf-8",
            )
            first_runtime.close()
            first_runtime = None
            second_runtime = self._runtime()

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertFalse(status["structuredContent"]["active"], status)
            self.assertTrue(status["structuredContent"]["stale"], status)
            self.assertEqual(status["structuredContent"]["status"], "stale_dirty_retained")
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_restart_checkpoint_runtime_rebuild_failure_keeps_task_and_lease_stale(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-restart-runtime-failure-owner", "restart-runtime-failure-owner.txt")
            worker = self._start(first_runtime, "request-restart-runtime-failure-worker", "restart-runtime-failure-worker.txt")
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-runtime-failure-worker.txt\n+checkpointed\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )
            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-runtime-failure-owner",
                },
            )
            self.assertFalse(restarted["isError"], restarted)
            first_runtime.close()
            first_runtime = None

            with patch("chatgpt_dev_mcp.server.Runtime", side_effect=RuntimeError("runtime rebuild failed")):
                second_runtime = self._runtime()

            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertTrue(status["structuredContent"]["stale"], status)
            task = second_runtime._director_ledger.get(worker["task"]["task_id"])
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "stale")
            self.assertEqual(
                second_runtime._director_writer_manager.active(
                    "project-x",
                    working_tree_id=worker["session_id"],
                ),
                (),
            )
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_shared_restart_suspends_orphaned_active_dirty_session_without_losing_diff(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-orphan-restart-owner", "orphan-restart-owner.txt")
            worker = self._start(first_runtime, "request-orphan-restart-worker", "orphan-restart-worker.txt")
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: orphan-restart-worker.txt\n+preserve me\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            lease = first_runtime._director_writer_manager.get(worker["lease_id"])
            self.assertIsNotNone(lease)
            first_runtime._director_writer_manager.release(lease)
            first_runtime._director_ledger.transition(
                worker["task"]["task_id"],
                "stale",
                owner_id="owner-request-orphan-restart-worker",
            )
            before = first_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(before["isError"], before)
            self.assertTrue(before["structuredContent"]["active"], before)
            self.assertTrue(before["structuredContent"]["dirty"], before)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )

            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-orphan-restart-owner",
                },
            )

            self.assertFalse(restarted["isError"], restarted)
            suspended = first_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(suspended["isError"], suspended)
            self.assertFalse(suspended["structuredContent"]["active"], suspended)
            self.assertTrue(suspended["structuredContent"]["stale"], suspended)
            self.assertTrue(suspended["structuredContent"]["dirty"], suspended)
            first_runtime.close()
            first_runtime = None

            second_runtime = self._runtime()
            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertFalse(status["structuredContent"]["active"], status)
            self.assertTrue(status["structuredContent"]["stale"], status)
            self.assertTrue(status["structuredContent"]["dirty"], status)
            self.assertEqual(
                (Path(status["structuredContent"]["worktree_path"]).expanduser() / "orphan-restart-worker.txt").read_text(encoding="utf-8"),
                "preserve me\n",
            )
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_shared_restart_recovers_path_scoped_resource_session(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        first_runtime = self._runtime()
        second_runtime = None
        try:
            owner = self._start(first_runtime, "request-resource-restart-owner-safe", "resource-restart-owner-safe.txt")
            resource_result = first_runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-resource-restart-worker-safe",
                    "title": "resource restart worker safe",
                    "owner_id": "owner-resource-restart-worker-safe",
                    "paths": ["resource-restart-worker-safe.txt"],
                    "resources": ["logical:resource-lock"],
                },
            )
            self.assertFalse(resource_result["isError"], resource_result)
            worker = resource_result["structuredContent"]
            patched = first_runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: resource-restart-worker-safe.txt\n+checkpointed resource work\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            first_runtime._local_maintenance._restart_scheduler = (
                lambda argv: MaintenanceRunResult(0, True, "queued")
            )
            old_child_id = first_runtime.child_instance_id

            restarted = first_runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-resource-restart-owner-safe",
                },
            )
            self.assertFalse(restarted["isError"], restarted)
            first_runtime.close()
            first_runtime = None

            second_runtime = self._runtime()
            self.assertNotEqual(second_runtime.child_instance_id, old_child_id)
            status = second_runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(status["isError"], status)
            self.assertTrue(status["structuredContent"]["active"], status)
            leases = second_runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=worker["session_id"],
            )
            self.assertEqual(len(leases), 1)
            self.assertEqual(leases[0].resources, ("logical:resource-lock",))
        finally:
            if first_runtime is not None:
                first_runtime.close()
            if second_runtime is not None:
                second_runtime.close()

    def test_shared_restart_still_blocks_unfenceable_resource_session(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        restart_calls: list[tuple[str, ...]] = []
        try:
            owner = self._start(runtime, "request-resource-restart-owner", "resource-restart-owner.txt")
            resource_result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-resource-restart-blocker",
                    "title": "resource restart blocker",
                    "owner_id": "owner-resource-restart-blocker",
                    "paths": [],
                    "resources": ["runtime:unfenceable-service"],
                },
            )
            self.assertFalse(resource_result["isError"], resource_result)
            resource_session = resource_result["structuredContent"]
            sessions.extend((owner["session_id"], resource_session["session_id"]))
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: restart_calls.append(argv) or MaintenanceRunResult(0, True, "queued")
            )

            restarted = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-resource-restart-owner",
                },
            )

            self.assertTrue(restarted["isError"], restarted)
            error = restarted["structuredContent"]["error"]
            self.assertEqual(error["code"], "LOCAL_MAINTENANCE_ACTIVE_WORK_BLOCKED")
            self.assertIn(resource_session["session_id"], error["details"]["blocking_session_ids"])
            self.assertEqual(restart_calls, [])
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_shared_restart_suspends_active_session_after_writer_lease_disappears(self) -> None:
        from chatgpt_dev_mcp.local_maintenance import MaintenanceRunResult

        runtime = self._runtime()
        sessions: list[str] = []
        restart_calls: list[tuple[str, ...]] = []
        try:
            owner = self._start(runtime, "request-restart-missing-lease-owner", "restart-missing-lease-owner.txt")
            worker = self._start(runtime, "request-restart-missing-lease-worker", "restart-missing-lease-worker.txt")
            sessions.extend((owner["session_id"], worker["session_id"]))
            patched = runtime.call_tool(
                "apply_patch",
                {
                    "session_id": worker["session_id"],
                    "lease_id": worker["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: restart-missing-lease-worker.txt\n+retained work\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            worker_leases = runtime._director_writer_manager.active(
                "project-x",
                working_tree_id=worker["session_id"],
            )
            self.assertEqual(len(worker_leases), 1)
            runtime._director_writer_manager.release(worker_leases[0])
            self.assertEqual(
                runtime._director_writer_manager.active(
                    "project-x",
                    working_tree_id=worker["session_id"],
                ),
                (),
            )
            runtime._local_maintenance._restart_scheduler = (
                lambda argv: restart_calls.append(argv) or MaintenanceRunResult(0, True, "queued")
            )

            restarted = runtime.call_tool(
                "local_maintenance",
                {
                    "action": "restart_dev_mcp_tunnel",
                    "workspace_id": "project-x",
                    "session_id": owner["session_id"],
                    "task_id": owner["task"]["task_id"],
                    "owner_id": "owner-request-restart-missing-lease-owner",
                },
            )

            self.assertFalse(restarted["isError"], restarted)
            self.assertEqual(len(restart_calls), 1)
            worker_status = runtime.call_tool(
                "workspace_session_status",
                {"session_id": worker["session_id"]},
            )
            self.assertFalse(worker_status["isError"], worker_status)
            self.assertFalse(worker_status["structuredContent"]["active"])
            self.assertTrue(worker_status["structuredContent"]["dirty"])
            self.assertEqual(worker_status["structuredContent"]["durable_state"], "suspended")
            worker_task = runtime._director_ledger.get(worker["task"]["task_id"])
            self.assertIsNotNone(worker_task)
            self.assertEqual(worker_task.status, "stale")
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_shared_restart_uses_current_task_state_over_superseded_persisted_state(self) -> None:
        runtime = self._runtime()
        try:
            current = runtime._director_ledger.enqueue(
                "restart-current-state",
                "project-x",
                "Current task state wins",
                working_tree_id="worktree:current-state",
                allowed_paths=("README.md",),
            )
            runtime._director_ledger.transition(current.task_id, "stale", detail="reconciled stale")
            stale_current = runtime._director_ledger.get(current.task_id)
            self.assertIsNotNone(stale_current)
            self.assertEqual(stale_current.status, "stale")

            superseded_persisted = stale_current.as_dict()
            superseded_persisted["state"] = "running"
            superseded_persisted["status"] = "running"
            runtime._require_persistence().save_task(superseded_persisted)

            persistence_only = dict(superseded_persisted)
            persistence_only.update(
                {
                    "task_id": "task-persistence-only-active",
                    "request_id": "persistence-only-active",
                    "title": "Persistence-only active task",
                    "detail": "",
                }
            )
            runtime._require_persistence().save_task(persistence_only)

            blockers = runtime._local_maintenance_restart_blockers(
                caller_session_id="session:caller",
                caller_task_id="task-caller",
                caller_worktree_id="worktree:caller",
            )

            self.assertNotIn(current.task_id, blockers["blocking_task_ids"])
            self.assertIn("task-persistence-only-active", blockers["blocking_task_ids"])
        finally:
            runtime.close()

    def _start_with_snapshot(self, runtime, request_id: str, path: str, snapshot_id: str):
        result = runtime.call_tool(
            "director_development_start",
            {
                "workspace_id": "project-x",
                "request_id": request_id,
                "title": request_id,
                "owner_id": f"owner-{request_id}",
                "paths": [path],
                "resources": [],
                "source_snapshot_id": snapshot_id,
            },
        )
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]


if __name__ == "__main__":
    unittest.main()
