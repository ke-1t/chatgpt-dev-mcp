from __future__ import annotations

import unittest


class ContextPackTests(unittest.TestCase):
    def test_context_pack_redacts_secrets_and_bounds_sources(self) -> None:
        from chatgpt_dev_mcp.director import ContextSource, build_context_pack

        pack = build_context_pack(
            "sample-project",
            [
                ContextSource(
                    "src/app.py",
                    '"token": "super-secret-value"\nprint(\'ok\')',
                    start_line=10,
                ),
                ContextSource("tests/test_app.py", "x" * 100),
            ],
            max_bytes=40,
            max_item_bytes=64,
        )

        self.assertEqual(pack.workspace_id, "sample-project")
        self.assertEqual([item.path for item in pack.items], ["src/app.py", "tests/test_app.py"])
        self.assertNotIn("super-secret-value", pack.to_json())
        self.assertIn("[REDACTED]", pack.items[0].content)
        self.assertTrue(pack.truncated)
        self.assertLessEqual(pack.total_bytes, 40)

    def test_context_pack_pins_revision_file_hashes_and_stable_identity(self) -> None:
        from chatgpt_dev_mcp.director import ContextSource, build_context_pack, sha256_text

        sources = [ContextSource("src/app.py", "print('ok')\n")]
        first = build_context_pack(
            "sample-project",
            sources,
            base_revision="abc123",
            generated_at="2026-08-12T00:00:00Z",
        )
        second = build_context_pack(
            "sample-project",
            sources,
            base_revision="abc123",
            generated_at="2026-08-12T00:01:00Z",
        )

        self.assertEqual(first.context_pack_id, second.context_pack_id)
        self.assertEqual(first.base_revision, "abc123")
        self.assertEqual(first.generated_at, "2026-08-12T00:00:00Z")
        self.assertEqual(first.items[0].content_hash, sha256_text("print('ok')\n"))
        self.assertEqual(first.as_dict()["schema_version"], 2)

    def test_context_pack_rejects_sensitive_or_duplicate_paths(self) -> None:
        from chatgpt_dev_mcp.director import ContextSource, ValidationError, build_context_pack

        with self.assertRaises(ValidationError):
            ContextSource(".env", "secret")
        with self.assertRaises(ValidationError):
            build_context_pack(
                "sample-project",
                [ContextSource("src/a.py", "a"), ContextSource("src/a.py", "b")],
            )


class PatchGateTests(unittest.TestCase):
    def test_patch_gate_allows_normal_update_and_requires_review_for_delete(self) -> None:
        from chatgpt_dev_mcp.director import evaluate_patch

        allowed = evaluate_patch(
            "*** Begin Patch\n*** Update File: src/app.py\n@@\n-print('old')\n+print('new')\n*** End Patch\n",
            allowed_prefixes=("src",),
        )
        self.assertEqual(allowed.status, "allow")
        self.assertEqual(allowed.paths, ("src/app.py",))

        review = evaluate_patch("*** Begin Patch\n*** Delete File: src/old.py\n*** End Patch\n")
        self.assertEqual(review.status, "review_required")
        self.assertTrue(review.requires_review)

    def test_patch_gate_denies_traversal_sensitive_content_and_unknown_files(self) -> None:
        from chatgpt_dev_mcp.director import evaluate_patch

        self.assertEqual(
            evaluate_patch("*** Begin Patch\n*** Update File: ../outside.py\n*** End Patch\n").reason,
            "PATCH_PATH_INVALID",
        )
        self.assertEqual(
            evaluate_patch("*** Begin Patch\n*** Update File: .env\n*** End Patch\n").reason,
            "PATCH_PATH_INVALID",
        )
        self.assertEqual(evaluate_patch("not a patch").reason, "PATCH_NO_FILES")
        self.assertEqual(
            evaluate_patch("*** Begin Patch\n*** Update File: src/a.py\n+token=real-secret\n*** End Patch\n").reason,
            "PATCH_SECRET_LIKE_CONTENT",
        )

    def test_patch_gate_supports_unified_headers_without_exposing_content(self) -> None:
        from chatgpt_dev_mcp.director import evaluate_patch

        decision = evaluate_patch("--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n")
        self.assertEqual(decision.status, "allow")
        self.assertEqual(decision.paths, ("src/app.py",))

    def test_patch_gate_classifies_unified_add_delete_and_prefix_escape(self) -> None:
        from chatgpt_dev_mcp.director import evaluate_patch

        added = evaluate_patch("--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+new\n")
        self.assertEqual(added.status, "allow")
        self.assertEqual(added.operations, ("add",))
        deleted = evaluate_patch("--- a/src/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n")
        self.assertEqual(deleted.status, "review_required")
        self.assertEqual(deleted.operations, ("delete",))
        outside = evaluate_patch(
            "*** Begin Patch\n*** Update File: tests/test_app.py\n*** End Patch\n",
            allowed_prefixes=("src",),
        )
        self.assertEqual(outside.reason, "PATCH_PATH_OUTSIDE_ALLOWED_PREFIX")


class WriterLeaseTests(unittest.TestCase):
    def test_path_scoped_writers_can_run_concurrently_and_expire(self) -> None:
        from chatgpt_dev_mcp.director import LeaseConflict, WriterLeaseManager

        now = [100.0]
        manager = WriterLeaseManager(ttl_seconds=10, clock=lambda: now[0])
        first = manager.acquire(
            "sample-project",
            "chat-a",
            working_tree_id="worktree:main",
            task_id="task-a",
            paths=("src/a.py",),
            base_revision="abc123",
            scope_hashes={"src/a.py": "a" * 64},
        )
        second = manager.acquire(
            "sample-project",
            "chat-b",
            working_tree_id="worktree:main",
            task_id="task-b",
            paths=("src/b.py",),
            base_revision="abc123",
            scope_hashes={"src/b.py": "b" * 64},
        )
        self.assertNotEqual(first.lease_id, second.lease_id)
        self.assertEqual(len(manager.active("sample-project", working_tree_id="worktree:main")), 2)
        self.assertTrue(manager.covers(first, ("src/a.py",)))
        self.assertFalse(manager.covers(first, ("src/b.py",)))

        now[0] = 111.0
        self.assertEqual(manager.active("sample-project", working_tree_id="worktree:main"), ())

    def test_observed_active_does_not_prune_or_emit_expiry(self) -> None:
        from chatgpt_dev_mcp.director import WriterLeaseManager

        now = [100.0]
        events: list[str] = []
        manager = WriterLeaseManager(
            ttl_seconds=10,
            clock=lambda: now[0],
            on_change=lambda _lease, state: events.append(state),
        )
        lease = manager.acquire(
            "sample-project",
            "chat-a",
            working_tree_id="worktree:main",
            task_id="task-a",
            paths=("src/a.py",),
            base_revision="abc123",
            scope_hashes={"src/a.py": "a" * 64},
        )
        events.clear()
        now[0] = 111.0

        self.assertEqual(manager.observed_active("sample-project"), ())
        self.assertEqual(events, [])
        self.assertIn(lease.lease_id, manager._leases)
        self.assertEqual(events, [])

    def test_parent_child_path_and_runtime_resource_conflicts(self) -> None:
        from chatgpt_dev_mcp.director import LeaseConflict, WriterLeaseManager

        manager = WriterLeaseManager()
        first = manager.acquire(
            "sample-project",
            "chat-a",
            working_tree_id="worktree:main",
            task_id="task-a",
            paths=("src/api",),
            resources=("port:8765",),
            base_revision="abc123",
        )
        with self.assertRaises(LeaseConflict):
            manager.acquire(
                "sample-project",
                "chat-b",
                working_tree_id="worktree:main",
                task_id="task-b",
                paths=("src/api/client.py",),
                base_revision="abc123",
            )
        with self.assertRaises(LeaseConflict):
            manager.acquire(
                "sample-project",
                "chat-c",
                working_tree_id="worktree:main",
                task_id="task-c",
                paths=("tests/test_api.py",),
                resources=("port:8765",),
                base_revision="abc123",
            )

        other_tree = manager.acquire(
            "sample-project",
            "chat-d",
            working_tree_id="worktree:other",
            task_id="task-d",
            paths=("src/api/client.py",),
            base_revision="abc123",
        )
        self.assertNotEqual(first.lease_id, other_tree.lease_id)
        other_workspace = manager.acquire(
            "sample-project-alias",
            "chat-alias",
            working_tree_id="worktree:main",
            task_id="task-alias",
            paths=("src/api/client.py",),
            base_revision="abc123",
        )
        self.assertNotEqual(first.lease_id, other_workspace.lease_id)
        with self.assertRaises(LeaseConflict):
            manager.acquire(
                "sample-project",
                "chat-e",
                working_tree_id="worktree:other",
                task_id="task-e",
                paths=("tests/test_other.py",),
                resources=("port:8765",),
                base_revision="abc123",
            )

    def test_legacy_workspace_scope_remains_compatible(self) -> None:
        from chatgpt_dev_mcp.director import LeaseConflict, WriterLeaseManager

        manager = WriterLeaseManager()
        first = manager.acquire("sample-project", "chat-a")
        self.assertTrue(first.workspace_wide)
        self.assertTrue(manager.covers(first, ("any/path.py",)))
        with self.assertRaises(LeaseConflict):
            manager.acquire("sample-project", "chat-b")
        manager.release(first)
        self.assertIsNone(manager.current("sample-project"))


class TaskLedgerTests(unittest.TestCase):
    def test_restore_recovers_pushed_canonical_task_from_synthetic_stale(self) -> None:
        from chatgpt_dev_mcp.director import TaskLedger, TaskReceipt

        restored = TaskReceipt(
            task_id="task-pushed",
            request_id="req-pushed",
            workspace_id="portfolio-mcp",
            title="Publish verified delivery",
            status="stale",
            owner_id="chat-a",
            created_at="2026-08-22T00:00:00Z",
            updated_at="2026-08-22T00:01:00Z",
            detail="push receipt recorded",
            working_tree_id="worktree:canonical",
            git_commit_receipt="git-commit:abc",
            git_push_receipt="git-push:def",
            result="committed_to_canonical",
        )
        ledger = TaskLedger()

        ledger.restore((restored,))

        task = ledger.get("task-pushed")
        self.assertIsNotNone(task)
        self.assertEqual(task.status, "review_ready")
        self.assertEqual(task.git_commit_receipt, "git-commit:abc")
        self.assertEqual(task.git_push_receipt, "git-push:def")

    def test_restore_does_not_recover_explicit_or_session_stale_task(self) -> None:
        from chatgpt_dev_mcp.director import TaskLedger, TaskReceipt

        explicit = TaskReceipt(
            task_id="task-explicit-stale",
            request_id="req-explicit-stale",
            workspace_id="portfolio-mcp",
            title="Explicit stale",
            status="stale",
            owner_id="chat-a",
            created_at="2026-08-22T00:00:00Z",
            updated_at="2026-08-22T00:01:00Z",
            detail="writer lease expired",
            working_tree_id="worktree:canonical",
            git_commit_receipt="git-commit:abc",
            git_push_receipt="git-push:def",
        )
        session_bound = TaskReceipt(
            task_id="task-session-stale",
            request_id="req-session-stale",
            workspace_id="portfolio-mcp",
            title="Session stale",
            status="stale",
            owner_id="chat-a",
            created_at="2026-08-22T00:00:00Z",
            updated_at="2026-08-22T00:01:00Z",
            detail="push receipt recorded",
            working_tree_id="session:abc",
            development_session_id="session:abc",
            git_commit_receipt="git-commit:abc",
            git_push_receipt="git-push:def",
        )
        ledger = TaskLedger()

        ledger.restore((explicit, session_bound))

        self.assertEqual(ledger.get("task-explicit-stale").status, "stale")
        self.assertEqual(ledger.get("task-session-stale").status, "stale")

    def test_task_lifecycle_is_idempotent_and_bounded(self) -> None:
        from chatgpt_dev_mcp.director import LedgerConflict, TaskLedger

        ticks = iter(
            [
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:01Z",
                "2026-01-01T00:00:02Z",
                "2026-01-01T00:00:03Z",
                "2026-01-01T00:00:04Z",
            ]
        )
        ledger = TaskLedger(max_records=1, clock=lambda: next(ticks))
        queued = ledger.enqueue("req-1", "sample-project", "Run tests")
        self.assertEqual(ledger.enqueue("req-1", "sample-project", "Run tests"), queued)
        running = ledger.start(queued.task_id, "chat-a")
        self.assertEqual(running.status, "running")
        finished = ledger.finish(
            queued.task_id,
            "succeeded",
            owner_id="chat-a",
            detail="24 tests passed",
            result_ref="receipt:1",
        )
        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(ledger.list(), (finished,))
        with self.assertRaises(LedgerConflict):
            ledger.enqueue("req-1", "sample-project", "Different task")

        second = ledger.enqueue("req-2", "sample-project", "Run lint")
        ledger.start(second.task_id, "chat-a")
        with self.assertRaises(LedgerConflict):
            ledger.finish(second.task_id, "succeeded", owner_id="chat-b")

    def test_active_tasks_cannot_be_evicted_and_terminal_detail_cannot_leak(self) -> None:
        from chatgpt_dev_mcp.director import LedgerConflict, TaskLedger, ValidationError

        ledger = TaskLedger(max_records=1)
        first = ledger.enqueue("req-1", "sample-project", "Run tests")
        ledger.start(first.task_id, "chat-a")
        with self.assertRaises(LedgerConflict):
            ledger.enqueue("req-2", "sample-project", "Run lint")
        with self.assertRaises(ValidationError):
            ledger.finish(first.task_id, "failed", owner_id="chat-a", detail="token=secret")
        with self.assertRaises(ValidationError):
            ledger.enqueue("req-3", "sample-project", "token=secret")

    def test_task_ledger_records_parallel_write_evidence(self) -> None:
        from chatgpt_dev_mcp.director import LedgerConflict, TaskLedger

        ledger = TaskLedger()
        queued = ledger.enqueue(
            "req-parallel",
            "sample-project",
            "Implement view",
            working_tree_id="worktree:main",
            allowed_paths=("src/view.py",),
            base_revision="abc123",
            context_pack_id="context:abc",
        )
        ready = ledger.transition(queued.task_id, "ready")
        leased = ledger.transition(
            ready.task_id,
            "leased",
            owner_id="chat-a",
            lease_id="lease:abc",
        )
        with self.assertRaises(LedgerConflict):
            ledger.start(leased.task_id, "chat-b")
        running = ledger.start(leased.task_id, "chat-a")
        verifying = ledger.transition(
            running.task_id,
            "verifying",
            owner_id="chat-a",
            patch_hash="a" * 64,
        )
        review = ledger.transition(
            verifying.task_id,
            "review_ready",
            owner_id="chat-a",
            verification_receipt="verify:abc",
            security_audit_receipt="audit:abc",
        )
        finished = ledger.finish(review.task_id, "succeeded", owner_id="chat-a", result_ref="diff:abc")

        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(finished.working_tree_id, "worktree:main")
        self.assertEqual(finished.allowed_paths, ("src/view.py",))
        self.assertEqual(finished.lease_id, "lease:abc")
        self.assertEqual(finished.patch_hash, "a" * 64)
        self.assertEqual(finished.verification_receipt, "verify:abc")
        self.assertEqual(finished.security_audit_receipt, "audit:abc")

    def test_stale_task_resume_is_explicit_bounded_and_clears_old_write_evidence(self) -> None:
        from chatgpt_dev_mcp.director import LedgerConflict, TaskLedger

        ledger = TaskLedger()
        queued = ledger.enqueue(
            "req-resume",
            "sample-project",
            "Resume interrupted work",
            working_tree_id="worktree:main",
            allowed_paths=("src/view.py",),
            base_revision="abc123",
        )
        ready = ledger.transition(queued.task_id, "ready")
        leased = ledger.transition(ready.task_id, "leased", owner_id="chat-a", lease_id="lease-old")
        running = ledger.start(leased.task_id, "chat-a")
        verifying = ledger.transition(
            running.task_id,
            "verifying",
            owner_id="chat-a",
            patch_hash="a" * 64,
            verification_receipt="verify:old",
            security_audit_receipt="audit:old",
        )
        stale = ledger.transition(verifying.task_id, "stale", owner_id="chat-a", detail="writer lease expired")

        resumed = ledger.resume(
            stale.task_id,
            owner_id="chat-a",
            base_revision="abc123",
            detail="explicit resume after lease expiry",
        )

        self.assertEqual(resumed.status, "ready")
        self.assertIsNone(resumed.owner_id)
        self.assertEqual(resumed.lease_id, "")
        self.assertEqual(resumed.patch_hash, "")
        self.assertEqual(resumed.verification_receipt, "")
        self.assertEqual(resumed.security_audit_receipt, "")
        self.assertEqual(resumed.integration_receipt, "")
        self.assertEqual(resumed.git_commit_receipt, "")
        self.assertEqual(resumed.git_push_receipt, "")
        self.assertEqual(resumed.base_revision, "abc123")
        self.assertEqual(resumed.allowed_paths, ("src/view.py",))
        self.assertEqual(resumed.detail, "explicit resume after lease expiry")

        with self.assertRaises(LedgerConflict):
            ledger.resume(resumed.task_id, owner_id="chat-a", base_revision="abc123")

    def test_resume_rejects_wrong_owner_and_non_stale_terminal_tasks(self) -> None:
        from chatgpt_dev_mcp.director import LedgerConflict, TaskLedger

        ledger = TaskLedger()
        queued = ledger.enqueue("req-owner", "sample-project", "Resume owner check")
        running = ledger.start(queued.task_id, "chat-a")
        stale = ledger.transition(running.task_id, "stale", owner_id="chat-a")
        with self.assertRaises(LedgerConflict):
            ledger.resume(stale.task_id, owner_id="chat-b", base_revision="abc123")

        cancelled = ledger.enqueue("req-cancelled", "sample-project", "Cancelled work")
        cancelled = ledger.transition(cancelled.task_id, "cancelled")
        with self.assertRaises(LedgerConflict):
            ledger.resume(cancelled.task_id, owner_id="chat-a", base_revision="abc123")


class UsageLedgerTests(unittest.TestCase):
    def test_usage_snapshot_distinguishes_local_counts_from_account_usage(self) -> None:
        from chatgpt_dev_mcp.director import UsageLedger

        ledger = UsageLedger(capabilities=("context_pack", "patch_gate"), external_execution=False)
        ledger.record("context_pack", 2)
        ledger.record("task")
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.account_usage, "unknown")
        self.assertFalse(snapshot.external_execution)
        self.assertEqual(snapshot.local_counters, {"context_pack": 2, "task": 1})
        self.assertEqual(snapshot.capabilities, ("context_pack", "patch_gate"))


if __name__ == "__main__":
    unittest.main()
