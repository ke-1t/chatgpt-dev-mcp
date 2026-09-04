from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class ParallelDevelopmentE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-parallel-e2e-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
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
                                    "max_parallel_sessions": 6,
                                    "allowed_base": "registered_project",
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
        self.previous = {
            "HOME": os.environ.get("HOME"),
            "LOCAL_DEV_MCP_CONFIG": os.environ.get("LOCAL_DEV_MCP_CONFIG"),
            "LOCAL_DEV_MCP_DATA_DIR": os.environ.get("LOCAL_DEV_MCP_DATA_DIR"),
            "LOCAL_DEV_MCP_WORKTREE_ROOT": os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT"),
        }
        os.environ["HOME"] = str(self.home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)
        os.environ["LOCAL_DEV_MCP_DATA_DIR"] = str(self.home / ".director-state")
        os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = str(self.home / ".cache" / "local-dev-mcp" / "worktrees")

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def _start(self, runtime, request_id: str, title: str, paths: list[str]):
        result = runtime.call_tool(
            "director_development_start",
            {
                "workspace_id": "project-x",
                "request_id": request_id,
                "title": title,
                "owner_id": f"chat-{request_id}",
                "paths": paths,
                "resources": [],
            },
        )
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]

    def test_same_base_sessions_allow_dirty_canonical_without_copying_content(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        sessions = []
        try:
            first = self._start(runtime, "request-a", "API work", ["src/api.py"])
            sessions.append(first["session_id"])
            self.assertEqual(first["task"]["status"], "running")
            self.assertFalse(first["lease"]["workspace_wide"])
            duplicate = self._start(runtime, "request-a", "API work", ["src/api.py"])
            self.assertEqual(duplicate["status"], "active")
            self.assertTrue(duplicate["reused_existing_request"])
            self.assertEqual(duplicate["session_id"], first["session_id"])
            (self.repo / "canonical-only.txt").write_text("must stay canonical\n", encoding="utf-8")
            second = self._start(runtime, "request-b", "UI work", ["src/ui.py"])
            third = self._start(runtime, "request-c", "Test work", ["tests/test_api.py"])
            sessions.extend((second["session_id"], third["session_id"]))
            self.assertEqual({first["source_revision"], second["source_revision"], third["source_revision"]}, {first["source_revision"]})
            self.assertTrue(second["canonical"]["dirty"])
            self.assertFalse(second["canonical"]["dirty_content_copied"])
            self.assertFalse((Path(second["worktree_path"]) / "canonical-only.txt").exists())
            summary = runtime.call_tool("director_status_summary", {"workspace_id": "project-x"})["structuredContent"]
            self.assertEqual(len(summary["sessions"]), 3)
            self.assertEqual(len(summary["summary"]["active_session_ids"]), 3)
        finally:
            for session_id in sessions:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_director_status_summary_observes_each_session_once(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.server as server_module
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        sessions = []
        try:
            for index in range(3):
                started = self._start(
                    runtime,
                    f"observation-{index}",
                    f"observation task {index}",
                    [f"observation/{index}.txt"],
                )
                sessions.append(started["session_id"])

            probed_paths: list[str] = []

            def record_dirty_probe(path: Path) -> bool:
                probed_paths.append(str(Path(path).resolve(strict=False)))
                return False

            with patch.object(server_module, "repo_dirty", side_effect=record_dirty_probe) as dirty_probe:
                summary = runtime.call_tool(
                    "director_status_summary",
                    {"workspace_id": "project-x"},
                )["structuredContent"]

            self.assertEqual(len(summary["sessions"]), 3)
            self.assertEqual(dirty_probe.call_count, 4, probed_paths)
        finally:
            for session_id in sessions:
                runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
            runtime.close()

    def test_empty_scope_is_rejected_without_explicit_workspace_wide(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            result = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-wide",
                    "title": "Broad project work",
                    "owner_id": "chat-request-wide",
                    "paths": [],
                    "resources": [],
                },
            )
            self.assertTrue(result["isError"], result)
            self.assertEqual(result["structuredContent"]["error"]["code"], "INVALID_LEASE_SCOPE")
        finally:
            runtime.close()

    def test_six_parallel_sessions_fit_policy_cap_and_seventh_is_queued(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        sessions = []
        try:
            for index in range(6):
                started = self._start(
                    runtime,
                    f"request-{index}",
                    f"parallel task {index}",
                    [f"areas/{index}.txt"],
                )
                sessions.append(started["session_id"])
                self.assertEqual(started["status"], "active")
                self.assertEqual(started["task"]["status"], "running")
            summary = runtime.call_tool("director_status_summary", {"workspace_id": "project-x"})["structuredContent"]
            self.assertEqual(len(summary["summary"]["active_session_ids"]), 6)
            seventh = self._start(runtime, "request-6", "queued task", ["areas/6.txt"])
            self.assertEqual(seventh["status"], "blocked")
            self.assertEqual(seventh["blocked_reason"], "MAX_PARALLEL_SESSIONS")
            self.assertIsNone(seventh["session"])
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_three_client_sessions_remain_isolated_after_selected_switch_and_close(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        clients = [WrapperRuntime() for _ in range(3)]
        started: list[dict[str, object]] = []
        closed: set[str] = set()
        overlap_session_id: str | None = None
        try:
            for index, client in enumerate(clients):
                started.append(self._start(client, f"client-request-{index}", f"client task {index}", [f"client-{index}.txt"]))

            overlap = clients[0].call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "client-conflict",
                    "title": "independent overlap work",
                    "owner_id": "client-conflict-owner",
                    "paths": ["client-0.txt"],
                    "resources": [],
                },
            )
            self.assertFalse(overlap["isError"], overlap)
            overlap_payload = overlap["structuredContent"]
            self.assertEqual(overlap_payload["status"], "active")
            self.assertNotEqual(overlap_payload["working_tree_id"], started[0]["working_tree_id"])
            overlap_session_id = str(overlap_payload["session_id"])

            for index, (client, session) in enumerate(zip(clients, started)):
                # Switch the selected convenience view away from the session;
                # every implementation call remains explicitly session/lease bound.
                selected = client.call_tool("workspace_open", {"id": "project-x"})
                self.assertFalse(selected["isError"], selected)
                session_id = str(session["session_id"])
                lease_id = str(session["lease"]["lease_id"])
                read = client.call_tool("read_file", {"session_id": session_id, "path": "README.md"})
                self.assertFalse(read["isError"], read)
                patch = client.call_tool(
                    "apply_patch",
                    {
                        "session_id": session_id,
                        "lease_id": lease_id,
                        "patch": f"*** Begin Patch\n*** Add File: client-{index}.txt\n+from-client-{index}\n*** End Patch",
                    },
                )
                self.assertFalse(patch["isError"], patch)
                task = client.call_tool(
                    "run_task",
                    {"session_id": session_id, "task": "test", "timeout_ms": 5000},
                )
                self.assertFalse(task["isError"], task)
                self.assertEqual(task["structuredContent"]["working_tree_id"], session["working_tree_id"])

            self.assertFalse((self.repo / "client-0.txt").exists())
            self.assertFalse((self.repo / "client-1.txt").exists())
            self.assertFalse((self.repo / "client-2.txt").exists())

            first_session_id = str(started[0]["session_id"])
            closed_result = clients[0].call_tool("workspace_close_development_session", {"session_id": first_session_id})
            self.assertTrue(closed_result["isError"], closed_result)
            self.assertEqual(closed_result["structuredContent"]["error"]["code"], "DIRTY_WORKTREE_REQUIRES_REVIEW")
            self.assertNotIn(first_session_id, clients[0]._development_runtimes)
            closed.add(first_session_id)

            for index, (client, session) in enumerate(zip(clients[1:], started[1:]), start=1):
                session_id = str(session["session_id"])
                read = client.call_tool("read_file", {"session_id": session_id, "path": f"client-{index}.txt"})
                self.assertFalse(read["isError"], read)
                self.assertTrue(client.call_tool("workspace_session_status", {"session_id": session_id})["structuredContent"]["active"])
        finally:
            if overlap_session_id is not None:
                try:
                    clients[0].call_tool("workspace_close_development_session", {"session_id": overlap_session_id})
                except Exception:
                    pass
            for client, session in zip(clients, started):
                session_id = str(session["session_id"])
                if session_id in closed:
                    continue
                try:
                    client.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            for client in clients:
                client.close()

    def test_same_path_distinct_worktrees_become_stale_after_normal_restart(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        sessions = []
        try:
            first = self._start(runtime, "request-a", "API work", ["src/api.py"])
            sessions.append(first["session_id"])
            second = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-overlap",
                    "title": "Independent API documentation work",
                    "owner_id": "chat-overlap",
                    "paths": ["src/api.py"],
                    "resources": [],
                },
            )
            self.assertFalse(second["isError"], second)
            second_payload = second["structuredContent"]
            self.assertEqual(second_payload["status"], "active")
            self.assertNotEqual(second_payload["working_tree_id"], first["working_tree_id"])
            sessions.append(second_payload["session_id"])
            runtime.close()

            restarted = WrapperRuntime()
            try:
                summary = restarted.call_tool("director_status_summary", {"workspace_id": "project-x"})["structuredContent"]
                self.assertEqual(summary["summary"]["active_session_ids"], [])
                self.assertTrue(
                    any(
                        item["status"] == "stale_clean"
                        for item in summary["history"]["recent_sessions"]
                    )
                )
                self.assertEqual(summary["integration_queue"], [])
            finally:
                restarted.close()
        finally:
            # The restart intentionally retains managed worktrees. Close any
            # session records that the first runtime still knows about before
            # the disposable repository is removed.
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            try:
                runtime.close()
            except Exception:
                pass

    def test_cross_chat_same_path_leases_are_isolated_by_worktree(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        first_runtime = WrapperRuntime()
        second_runtime = WrapperRuntime()
        first_session = None
        second_session = None
        try:
            first = self._start(first_runtime, "request-a", "API work", ["src/api.py"])
            first_session = first["session_id"]
            second = second_runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "project-x",
                    "request_id": "request-b",
                    "title": "Independent API documentation work",
                    "owner_id": "chat-b",
                    "paths": ["src/api.py"],
                    "resources": [],
                },
            )
            self.assertFalse(second["isError"], second)
            second_payload = second["structuredContent"]
            self.assertEqual(second_payload["status"], "active")
            self.assertNotEqual(second_payload["working_tree_id"], first["working_tree_id"])
            second_session = second_payload["session_id"]
        finally:
            if first_session is not None:
                first_runtime.call_tool("workspace_close_development_session", {"session_id": first_session})
            if second_session is not None:
                second_runtime.call_tool("workspace_close_development_session", {"session_id": second_session})
            first_runtime.close()
            second_runtime.close()

    def test_runtime_close_suspends_session_lease_without_deleting_retained_worktree(self) -> None:
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        started = self._start(runtime, "request-close", "close task", ["close.txt"])
        worktree = Path(started["worktree_path"]).expanduser()
        lease_id = started["lease"]["lease_id"]
        runtime.close()

        store = SqliteDirectorStore(self.home / ".director-state" / "director.sqlite3")
        try:
            lease = next(item for item in store.load_leases() if item["lease_id"] == lease_id)
            self.assertEqual(lease["state"], "stale")
            self.assertTrue(worktree.is_dir())
        finally:
            store.close()

    def test_canonical_lease_only_read_bootstraps_exact_binding_after_restart(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        first = WrapperRuntime()
        lease_id = None
        try:
            opened = first.call_tool("workspace_open", {"id": "project-x"})
            self.assertFalse(opened["isError"], opened)
            task = first.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "workspace_id": "project-x",
                    "request_id": "canonical-lease-request",
                    "title": "canonical lease read",
                    "allowed_paths": ["README.md"],
                },
            )
            self.assertFalse(task["isError"], task)
            lease = first.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "workspace_id": "project-x",
                    "owner_id": "canonical-owner",
                    "task_id": task["structuredContent"]["receipt"]["task_id"],
                    "paths": ["README.md"],
                    "resources": [],
                },
            )
            self.assertFalse(lease["isError"], lease)
            lease_id = lease["structuredContent"]["lease"]["lease_id"]
        finally:
            first.close()

        second = WrapperRuntime()
        try:
            self.assertIsNone(second.current)
            read = second.call_tool("read_file", {"lease_id": lease_id, "path": "README.md"})
            self.assertFalse(read["isError"], read)
            self.assertEqual(read["structuredContent"]["content"], "baseline\n")
            patched = second.call_tool(
                "apply_patch",
                {
                    "lease_id": lease_id,
                    "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-baseline\n+lease-bootstrap\n*** End Patch",
                },
            )
            self.assertFalse(patched["isError"], patched)
            read_after_patch = second.call_tool("read_file", {"lease_id": lease_id, "path": "README.md"})
            self.assertFalse(read_after_patch["isError"], read_after_patch)
            self.assertEqual(read_after_patch["structuredContent"]["content"], "lease-bootstrap\n")
            self.assertIsNone(second.current)
            self.assertEqual(len(second._workspace_bindings), 1)
        finally:
            second.close()

    def test_safe_resume_rehydrates_secondary_session_lease_by_exact_id(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        config = json.loads(self.config.read_text(encoding="utf-8"))
        policy = config["workspaces"]["project-x"]["metadata"]["isolated_development"]
        policy.update(
            {
                "auto_resume_sessions": True,
                "auto_resume_policy": "same_owner_same_task_safe_local",
                "allow_workspace_wide": False,
                "verified_auto_commit": True,
                "auto_approve_safe_local": True,
                "auto_approve_local_maintenance": True,
                "manual_approval_ttl_seconds": 1800,
                "trusted_session_grant_ttl_seconds": 7200,
            }
        )
        self.config.write_text(json.dumps(config), encoding="utf-8")
        (self.repo / "secondary.txt").write_text("secondary\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "secondary.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "add secondary fixture"], check=True)

        first = WrapperRuntime()
        started = self._start(first, "primary-resume-fixture", "Primary resume fixture", ["README.md"])
        first.call_tool("workspace_open", {"id": started["session_id"]})
        secondary = first.call_tool(
            "director_writer_lease",
            {
                "action": "acquire",
                "workspace_id": "project-x",
                "working_tree_id": started["working_tree_id"],
                "session_id": started["session_id"],
                "owner_id": "secondary-owner",
                "task_id": "secondary-task",
                "paths": ["secondary.txt"],
                "resources": [],
            },
        )
        self.assertFalse(secondary["isError"], secondary)
        secondary_lease_id = secondary["structuredContent"]["lease"]["lease_id"]
        first.close()

        second = WrapperRuntime()
        try:
            resumed = second.call_tool(
                "workspace_resume_development_session",
                {
                    "session_id": started["session_id"],
                    "owner_id": "chat-primary-resume-fixture",
                    "task_id": started["task_id"],
                },
            )
            self.assertFalse(resumed["isError"], resumed)
            patch = second.call_tool(
                "apply_patch",
                {
                    "workspace_id": "project-x",
                    "working_tree_id": started["working_tree_id"],
                    "session_id": started["session_id"],
                    "lease_id": secondary_lease_id,
                    "patch": "*** Begin Patch\n*** Update File: secondary.txt\n@@\n-secondary\n+rehydrated\n*** End Patch",
                },
            )
            self.assertFalse(patch["isError"], patch)
            worktree = Path(started["worktree_path"]).expanduser()
            self.assertEqual((worktree / "secondary.txt").read_text(encoding="utf-8"), "rehydrated\n")
            self.assertEqual((self.repo / "secondary.txt").read_text(encoding="utf-8"), "secondary\n")
            ledger = second.call_tool(
                "director_task_ledger",
                {"action": "list", "workspace_id": "project-x"},
            )["structuredContent"]
            secondary_task = next(
                item
                for item in ledger["records"]
                if item["lease_id"] == secondary_lease_id
            )
            self.assertEqual(secondary_task["lease_id"], secondary_lease_id)
            self.assertIn(secondary_task["status"], {"running", "verifying"})
        finally:
            second.close()

    def test_dirty_session_close_is_allowed_only_when_exact_delta_is_already_canonical(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        started = self._start(runtime, "subsumed-close", "Subsumed close", ["README.md"])
        worktree = Path(started["worktree_path"]).expanduser()
        try:
            applied = runtime.call_tool(
                "apply_patch",
                {
                    "workspace_id": "project-x",
                    "working_tree_id": started["working_tree_id"],
                    "session_id": started["session_id"],
                    "lease_id": started["lease_id"],
                    "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-baseline\n+already-integrated\n*** End Patch",
                },
            )
            self.assertFalse(applied["isError"], applied)
            (self.repo / "README.md").write_text("already-integrated\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "integrate equivalent session delta"], check=True)

            closed = runtime.call_tool(
                "workspace_close_development_session",
                {"session_id": started["session_id"]},
            )
            self.assertFalse(closed["isError"], closed)
            self.assertTrue(closed["structuredContent"]["superseded_by_canonical"])
            self.assertFalse(worktree.exists())
        finally:
            runtime.close()

    def test_disjoint_review_ready_tasks_can_integrate_out_of_order_with_approval(self) -> None:
        """Independent review-ready work need not wait behind an unrelated queue item."""

        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        sessions = []

        def prepare(started: dict[str, object], filename: str, content: str) -> None:
            session_id = str(started["session_id"])
            sessions.append(session_id)
            selected = runtime.call_tool("workspace_open", {"id": session_id})
            self.assertFalse(selected["isError"], selected)
            patch = f"*** Begin Patch\n*** Add File: {filename}\n+{content}\n*** End Patch"
            applied = runtime.call_tool(
                "apply_patch",
                {"patch": patch, "lease_id": started["lease"]["lease_id"]},
            )
            self.assertFalse(applied["isError"], applied)
            task_id = started["task"]["task_id"]
            verification = runtime.call_tool(
                "verification_record",
                {
                    "task_id": task_id,
                    "changed_paths": [filename],
                    "results": [{"task": "test", "exit_code": 0, "output": "ok"}],
                },
            )
            self.assertFalse(verification["isError"], verification)
            audit = runtime.call_tool(
                "security_audit",
                {
                    "task_id": task_id,
                    "verification_receipt_id": verification["structuredContent"]["receipt"]["receipt_id"],
                },
            )
            self.assertFalse(audit["isError"], audit)
            transitioned = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task_id,
                    "status": "review_ready",
                    "owner_id": started["task"]["owner_id"],
                    "verification_receipt": verification["structuredContent"]["receipt"]["receipt_id"],
                    "security_audit_receipt": audit["structuredContent"]["receipt"]["receipt_id"],
                },
            )
            self.assertFalse(transitioned["isError"], transitioned)
            summary = runtime.call_tool("director_status_summary", {"workspace_id": "project-x"})["structuredContent"]
            task = next(item for item in summary["tasks"] if item["task_id"] == task_id)
            self.assertEqual(task["status"], "review_ready", summary)

        try:
            first = self._start(runtime, "request-a", "API work", ["a.txt"])
            second = self._start(runtime, "request-b", "UI work", ["b.txt"])
            prepare(first, "a.txt", "from-a")
            prepare(second, "b.txt", "from-b")

            # The second task is disjoint from the first, so its explicit
            # approval may be consumed without waiting for FIFO queue order.
            runtime.call_tool("workspace_open", {"id": second["session_id"]})
            second_preflight = runtime.call_tool(
                "workspace_integration_preflight", {"session_id": second["session_id"]}
            )["structuredContent"]
            self.assertTrue(second_preflight["integration_ready"], second_preflight)
            out_of_order = runtime.call_tool(
                "workspace_integrate_development_session",
                {
                    "session_id": second["session_id"],
                    "approval_token": second_preflight["approval_token"],
                    "confirmation": second_preflight["confirmation"],
                },
            )
            self.assertFalse(out_of_order["isError"], out_of_order)
            self.assertFalse((self.repo / "a.txt").exists())
            self.assertEqual((self.repo / "b.txt").read_text(encoding="utf-8"), "from-b\n")
            subprocess.run(["git", "-C", str(self.repo), "add", "b.txt"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "integrate-b"], check=True)

            # The earlier task still requires its own fresh explicit approval,
            # and can integrate after the unrelated canonical change.
            runtime.call_tool("workspace_open", {"id": first["session_id"]})
            first_preflight = runtime.call_tool(
                "workspace_integration_preflight", {"session_id": first["session_id"]}
            )["structuredContent"]
            self.assertTrue(first_preflight["integration_ready"], first_preflight)
            integrated = runtime.call_tool(
                "workspace_integrate_development_session",
                {
                    "session_id": first["session_id"],
                    "approval_token": first_preflight["approval_token"],
                    "confirmation": first_preflight["confirmation"],
                },
            )
            self.assertFalse(integrated["isError"], integrated)
            after_first = runtime.call_tool("director_status_summary", {"workspace_id": "project-x"})["structuredContent"]
            first_session = next(
                item
                for item in after_first["history"]["recent_sessions"]
                if item["session_id"] == first["session_id"]
            )
            self.assertEqual(first_session["status"], "integrated")
            self.assertEqual((self.repo / "a.txt").read_text(encoding="utf-8"), "from-a\n")
            self.assertEqual((self.repo / "b.txt").read_text(encoding="utf-8"), "from-b\n")
        finally:
            for session_id in sessions:
                try:
                    runtime.call_tool("workspace_close_development_session", {"session_id": session_id})
                except Exception:
                    pass
            runtime.close()

    def test_status_summary_separates_current_state_from_bounded_retained_history(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        active = self._start(runtime, "summary-active", "Active work", ["src/active.py"])
        retained = self._start(runtime, "summary-retained", "Retained work", ["src/retained.py"])
        try:
            dirty = runtime.call_tool(
                "apply_patch",
                {
                    "workspace_id": "project-x",
                    "working_tree_id": retained["working_tree_id"],
                    "session_id": retained["session_id"],
                    "lease_id": retained["lease_id"],
                    "patch": "*** Begin Patch\n*** Add File: src/retained.py\n+retained\n*** End Patch",
                },
            )["structuredContent"]
            self.assertTrue(dirty["ok"], dirty)
            blocked = runtime.call_tool(
                "workspace_close_development_session",
                {"session_id": retained["session_id"]},
            )["structuredContent"]
            self.assertEqual(blocked["error"]["code"], "DIRTY_WORKTREE_REQUIRES_REVIEW")

            summary = runtime.call_tool(
                "director_status_summary",
                {"workspace_id": "project-x"},
            )["structuredContent"]
            self.assertEqual([item["session_id"] for item in summary["sessions"]], [active["session_id"]])
            self.assertEqual(summary["current"]["session_count"], 1)
            self.assertEqual(summary["current"]["task_count"], 1)
            self.assertGreaterEqual(summary["history"]["session_count"], 1)
            self.assertGreaterEqual(summary["history"]["task_count"], 1)
            self.assertLessEqual(len(summary["history"]["recent_sessions"]), summary["history"]["limit"])
            self.assertLessEqual(len(summary["history"]["recent_tasks"]), summary["history"]["limit"])
            self.assertIn(
                retained["session_id"],
                {item["session_id"] for item in summary["history"]["recent_sessions"]},
            )
        finally:
            runtime.call_tool("workspace_close_development_session", {"session_id": active["session_id"]})
            runtime.close()

    def test_trusted_delivery_integrates_only_after_existing_evidence_is_ready(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["project-x"]["metadata"]["isolated_development"]["trust_level"] = "trusted_development"
        self.config.write_text(json.dumps(document), encoding="utf-8")
        runtime = WrapperRuntime(); started = self._start(runtime, "trusted-integration", "Trusted integration", ["trusted.txt"])
        try:
            runtime.call_tool("workspace_open", {"id":started["session_id"]})
            params = {"session_id":started["session_id"]}
            routing = {"workspace_id":"project-x","working_tree_id":started["working_tree_id"],"session_id":started["session_id"]}
            not_ready = runtime.call_tool("capability_preflight", {"capability_id":"delivery.integrate","params":params,**routing})
            self.assertTrue(not_ready["isError"], not_ready)
            self.assertEqual(not_ready["structuredContent"]["error"]["code"], "TRUSTED_DELIVERY_NOT_READY")
            applied = runtime.call_tool("apply_patch", {"patch":"*** Begin Patch\n*** Add File: trusted.txt\n+trusted\n*** End Patch","lease_id":started["lease"]["lease_id"]})
            self.assertFalse(applied["isError"], applied)
            task_id = started["task"]["task_id"]
            verification = runtime.call_tool("verification_record", {"task_id":task_id,"changed_paths":["trusted.txt"],"results":[{"task":"test","exit_code":0,"output":"ok"}]})
            self.assertFalse(verification["isError"], verification)
            audit = runtime.call_tool("security_audit", {"task_id":task_id,"verification_receipt_id":verification["structuredContent"]["receipt"]["receipt_id"]})
            self.assertFalse(audit["isError"], audit)
            transitioned = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task_id,
                    "status": "review_ready",
                    "owner_id": started["task"]["owner_id"],
                    "verification_receipt": verification["structuredContent"]["receipt"]["receipt_id"],
                    "security_audit_receipt": audit["structuredContent"]["receipt"]["receipt_id"],
                },
            )
            self.assertFalse(transitioned["isError"], transitioned)
            ready = runtime.call_tool("capability_preflight", {"capability_id":"delivery.integrate","params":params,**routing})
            self.assertFalse(ready["isError"], ready); preflight = ready["structuredContent"]
            self.assertFalse(preflight["approval_required"]); self.assertNotIn("approval_token", repr(preflight))
            # The stable capability preflight is durable across logical MCP
            # children, while the legacy inner integration approval store is
            # process-local.  Losing that inner store must not invalidate the
            # already-authorized outer delivery capability.
            runtime._integration_approvals.clear()
            integrated = runtime.call_tool("capability_execute", {"preflight_id":preflight["preflight_id"],"capability_id":"delivery.integrate","params":params,**routing})
            self.assertFalse(integrated["isError"], integrated)
            self.assertEqual((self.repo / "trusted.txt").read_text(encoding="utf-8"), "trusted\n")
        finally:
            try: runtime.call_tool("workspace_close_development_session", {"session_id":started["session_id"]})
            except Exception: pass
            runtime.close()

    def test_trusted_delivery_push_reuses_exact_normal_push_preflight(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["project-x"]["metadata"]["isolated_development"]["trust_level"] = "trusted_development"
        self.config.write_text(json.dumps(document), encoding="utf-8")
        subprocess.run(["git","-C",str(self.repo),"checkout","-qb","feature/trusted-push"], check=True)
        (self.repo / "README.md").write_text("trusted-push\n", encoding="utf-8")
        subprocess.run(["git","-C",str(self.repo),"add","README.md"], check=True)
        subprocess.run(["git","-C",str(self.repo),"commit","-qm","trusted push fixture"], check=True)
        bare = self.root / "trusted-remote.git"; subprocess.run(["git","init","--bare","-q",str(bare)], check=True)
        subprocess.run(["git","-C",str(self.repo),"remote","add","origin",str(bare)], check=True)
        runtime = WrapperRuntime()
        try:
            self.assertFalse(runtime.call_tool("workspace_open", {"id":"project-x"})["isError"])
            queued = runtime.call_tool("director_task_ledger", {"action":"enqueue","request_id":"trusted-push-e2e","workspace_id":"project-x","title":"Trusted push fixture","allowed_paths":["README.md"]})["structuredContent"]
            task_id = queued["receipt"]["task_id"]
            runtime.call_tool("director_task_ledger", {"action":"start","task_id":task_id,"owner_id":"trusted-push-owner"})
            runtime.call_tool("director_task_ledger", {"action":"transition","task_id":task_id,"status":"verifying","owner_id":"trusted-push-owner"})
            plan = runtime.call_tool("verification_plan", {"changed_paths":["README.md"]})["structuredContent"]["plan"]
            self.assertEqual(plan["reason"], "NO_EXECUTION_REQUIRED")
            verification = runtime.call_tool("verification_record", {"task_id":task_id,"changed_paths":["README.md"],"results":[]})["structuredContent"]
            audit = runtime.call_tool("security_audit", {"task_id":task_id,"verification_receipt_id":verification["receipt"]["receipt_id"]})
            self.assertFalse(audit["isError"], audit)
            runtime.call_tool("director_task_ledger", {"action":"transition","task_id":task_id,"status":"review_ready","owner_id":"trusted-push-owner","verification_receipt":verification["receipt"]["receipt_id"],"security_audit_receipt":audit["structuredContent"]["receipt"]["receipt_id"]})
            expected_head = subprocess.run(["git","-C",str(self.repo),"rev-parse","HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            params = {"task_id":task_id,"remote":"origin","branch":"feature/trusted-push","expected_head":expected_head}
            prepared = runtime.call_tool("capability_preflight", {"capability_id":"delivery.push","params":params,"workspace_id":"project-x"})
            self.assertFalse(prepared["isError"], prepared); preflight = prepared["structuredContent"]
            self.assertFalse(preflight["approval_required"]); self.assertNotIn("approval", repr(preflight.get("handler_preflight")))
            pushed = runtime.call_tool("capability_execute", {"preflight_id":preflight["preflight_id"],"capability_id":"delivery.push","params":params,"workspace_id":"project-x"})
            self.assertFalse(pushed["isError"], pushed)
            remote_head = subprocess.run(["git","--git-dir",str(bare),"rev-parse","refs/heads/feature/trusted-push"], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(remote_head, expected_head)
        finally:
            runtime.close()

    def test_development_start_reconciles_active_writer_lease_with_no_managed_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            head = subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            orphan_task = runtime._director_ledger.enqueue(
                "orphan-lease-fixture",
                "project-x",
                "Orphan lease fixture",
                allowed_paths=("src/reconciled.py",),
                base_revision=head,
            )
            runtime._director_ledger.bind_execution(
                orphan_task.task_id,
                working_tree_id="session:missing-session",
                development_session_id="session:missing-session",
                base_revision=head,
                allowed_paths=("src/reconciled.py",),
            )
            runtime._director_ledger.transition(orphan_task.task_id, "ready")
            orphan = runtime._director_writer_manager.acquire(
                "project-x",
                "orphan-owner",
                working_tree_id="session:missing-session",
                task_id=orphan_task.task_id,
                paths=("src/reconciled.py",),
                base_revision=head,
                scope_hashes={},
                workspace_wide=False,
            )
            runtime._director_ledger.transition(
                orphan_task.task_id,
                "running",
                owner_id="orphan-owner",
                lease_id=orphan.lease_id,
            )
            self.assertIsNotNone(runtime._director_writer_manager.get(orphan.lease_id))

            started = self._start(
                runtime,
                "replacement-after-orphan-lease",
                "Replacement after orphan lease",
                ["src/reconciled.py"],
            )
            self.assertIsNone(runtime._director_writer_manager.get(orphan.lease_id))
            runtime.call_tool("workspace_close_development_session", {"session_id": started["session_id"]})
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
