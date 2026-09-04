from __future__ import annotations

import unittest


class ParallelControlTests(unittest.TestCase):
    def _task(self, task_id: str, session_id: str, worktree_id: str, paths: tuple[str, ...], **overrides: object):
        from chatgpt_dev_mcp.director_parallel import ProjectTask

        payload = {
            "task_id": task_id,
            "project_id": "project-x",
            "logical_workspace_id": "project-x",
            "owner_id": f"chat-{task_id}",
            "development_session_id": session_id,
            "worktree_id": worktree_id,
            "source_revision": "a" * 40,
            "paths": paths,
            "resources": (),
        }
        payload.update(overrides)
        return ProjectTask(**payload)

    def test_disjoint_paths_in_distinct_sessions_are_parallel_safe(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("api", "session-a", "worktree-a", ("src/api.py",)),
                self._task("ui", "session-b", "worktree-b", ("src/ui.py",)),
            ]
        )

        self.assertEqual(result.conflicts, ())
        self.assertEqual(result.ready_task_ids, ("api", "ui"))
        self.assertEqual(result.max_safe_parallel_writers, 2)

    def test_overlapping_paths_across_distinct_worktrees_are_parallel_safe(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("api-a", "session-a", "worktree-a", ("src/api.py",)),
                self._task("api-b", "session-b", "worktree-b", ("src/api.py",)),
            ]
        )

        self.assertEqual(result.conflicts, ())
        self.assertEqual(result.ready_task_ids, ("api-a", "api-b"))
        self.assertEqual(result.max_safe_parallel_writers, 2)

    def test_overlapping_paths_inside_same_worktree_still_conflict(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("api-a", "session-a", "worktree-a", ("src/api.py",)),
                self._task("api-b", "session-b", "worktree-a", ("src/api.py",)),
            ]
        )

        self.assertEqual(result.conflicts[0].reason, "PROJECT_PATH_OVERLAP")
        self.assertEqual(result.conflicts[0].task_ids, ("api-a", "api-b"))
        self.assertEqual(result.max_safe_parallel_writers, 1)

    def test_conflicting_pair_does_not_hide_independent_parallel_capacity(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("shared-a", "session-a", "worktree-a", ("src/shared.py",)),
                self._task("shared-b", "session-b", "worktree-b", ("src/shared.py",)),
                self._task("independent", "session-c", "worktree-c", ("src/independent.py",)),
            ]
        )

        self.assertEqual(result.max_safe_parallel_writers, 3)

    def test_dependency_turns_overlap_into_waiting_not_conflict(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("api-a", "session-a", "worktree-a", ("src/api.py",)),
                self._task(
                    "api-b",
                    "session-b",
                    "worktree-b",
                    ("src/api.py",),
                    depends_on=("api-a",),
                ),
            ]
        )

        self.assertEqual(result.conflicts, ())
        self.assertEqual(result.ready_task_ids, ("api-a",))
        self.assertEqual(result.waiting_reasons, {"api-b": "DEPENDENCY_PENDING"})

    def test_terminal_task_may_reference_pruned_dependency_without_blocking_project_analysis(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task(
                    "old-cancelled",
                    "session-old",
                    "worktree-old",
                    ("src/old.py",),
                    status="cancelled",
                    depends_on=("already-pruned",),
                ),
                self._task("new-work", "session-new", "worktree-new", ("src/new.py",)),
            ]
        )

        self.assertEqual(result.ready_task_ids, ("new-work",))
        self.assertEqual(result.waiting_reasons, {})

    def test_live_task_still_rejects_dependency_missing_from_project_analysis(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        with self.assertRaisesRegex(ValueError, "dependencies must reference project tasks"):
            analyze_project_tasks(
                [
                    self._task(
                        "new-work",
                        "session-new",
                        "worktree-new",
                        ("src/new.py",),
                        depends_on=("missing-live-dependency",),
                    )
                ]
            )

    def test_resource_conflict_is_project_wide(self) -> None:
        from chatgpt_dev_mcp.director_parallel import analyze_project_tasks

        result = analyze_project_tasks(
            [
                self._task("a", "session-a", "worktree-a", ("src/a.py",), resources=("port:3000",)),
                self._task("b", "session-b", "worktree-b", ("src/b.py",), resources=("port:3000",)),
            ]
        )

        self.assertEqual(result.conflicts[0].reason, "PROJECT_RESOURCE_OVERLAP")
        self.assertEqual(result.conflicts[0].resources, ("port:3000",))

    def test_task_intent_fingerprint_is_stable_for_equivalent_input(self) -> None:
        from chatgpt_dev_mcp.director_parallel import task_intent_fingerprint

        first = task_intent_fingerprint(
            "project-x",
            "Fix  Restart-Safe   Recovery",
            ("src/b.py", "src/a.py"),
            ("runtime:z", "runtime:a"),
        )
        second = task_intent_fingerprint(
            "project-x",
            "fix restart safe recovery",
            ("src/a.py", "src/b.py"),
            ("runtime:a", "runtime:z"),
        )

        self.assertEqual(first, second)

    def test_task_intent_duplicate_classifier_requires_scope_and_strong_intent_match(self) -> None:
        from chatgpt_dev_mcp.director_parallel import classify_task_intent_duplicate

        exact = classify_task_intent_duplicate(
            project_id="project-x",
            title="Fix restart-safe recovery",
            paths=("src/server.py",),
            resources=(),
            existing_project_id="project-x",
            existing_title="fix restart safe recovery",
            existing_paths=("src/server.py",),
            existing_resources=(),
        )
        near = classify_task_intent_duplicate(
            project_id="project-x",
            title="Fix restart checkpoint recovery",
            paths=("src/server.py",),
            resources=(),
            existing_project_id="project-x",
            existing_title="Fix restart checkpoint recoveries",
            existing_paths=("src/server.py",),
            existing_resources=(),
        )
        different_purpose = classify_task_intent_duplicate(
            project_id="project-x",
            title="Document restart endpoint behavior",
            paths=("src/server.py",),
            resources=(),
            existing_project_id="project-x",
            existing_title="Fix restart checkpoint recovery",
            existing_paths=("src/server.py",),
            existing_resources=(),
        )
        disjoint_scope = classify_task_intent_duplicate(
            project_id="project-x",
            title="Fix restart checkpoint recovery",
            paths=("src/other.py",),
            resources=(),
            existing_project_id="project-x",
            existing_title="Fix restart checkpoint recovery",
            existing_paths=("src/server.py",),
            existing_resources=(),
        )

        self.assertEqual(exact, "exact")
        self.assertEqual(near, "near")
        self.assertIsNone(different_purpose)
        self.assertIsNone(disjoint_scope)

    def test_status_summary_marks_only_integrated_clean_sessions_for_cleanup(self) -> None:
        from chatgpt_dev_mcp.director_parallel import DevelopmentSessionRecord, summarize_project_status

        summary = summarize_project_status(
            project_id="project-x",
            logical_workspace_id="project-x",
            baseline_revision="a" * 40,
            canonical_revision="b" * 40,
            canonical_dirty=True,
            sessions=(
                DevelopmentSessionRecord("project-x", "project-x", "worktree-a", "session-a", "a" * 40, "root:a", "chat-a", "task-a", "integrated", dirty=False),
                DevelopmentSessionRecord("project-x", "project-x", "worktree-b", "session-b", "a" * 40, "root:b", "chat-b", "task-b", "expired_dirty_retained", dirty=True),
            ),
            tasks=(self._task("task-a", "session-a", "worktree-a", ("src/a.py",), status="review_ready"),),
        )

        self.assertEqual(summary.cleanup_candidate_session_ids, ("session-a",))
        self.assertEqual(summary.integration_queue_task_ids, ("task-a",))
        self.assertEqual(summary.stale_or_replan_task_ids, ())
        self.assertTrue(summary.canonical_dirty)

    def test_status_summary_accepts_project_with_no_tasks(self) -> None:
        from chatgpt_dev_mcp.director_parallel import summarize_project_status

        summary = summarize_project_status(
            project_id="project-x",
            logical_workspace_id="project-x",
            baseline_revision="a" * 40,
            canonical_revision="a" * 40,
            canonical_dirty=False,
            sessions=(),
            tasks=(),
        )

        self.assertEqual(summary.active_session_ids, ())
        self.assertEqual(summary.active_writer_task_ids, ())
        self.assertEqual(summary.integration_queue_task_ids, ())
        self.assertEqual(summary.cleanup_candidate_session_ids, ())
        self.assertEqual(summary.stale_or_replan_task_ids, ())
        self.assertEqual(summary.tasks.conflicts, ())
        self.assertEqual(summary.tasks.ready_task_ids, ())
        self.assertEqual(summary.tasks.waiting_reasons, {})
        self.assertEqual(summary.tasks.max_safe_parallel_writers, 0)

    def test_status_summary_excludes_delivery_only_review_ready_task_from_integration_queue(self) -> None:
        from chatgpt_dev_mcp.director_parallel import summarize_project_status

        summary = summarize_project_status(
            project_id="project-x",
            logical_workspace_id="project-x",
            baseline_revision="a" * 40,
            canonical_revision="a" * 40,
            canonical_dirty=False,
            sessions=(),
            tasks=(
                self._task(
                    "publish",
                    "session-publish",
                    "worktree-publish",
                    (),
                    resources=("delivery:github-main-publish",),
                    status="review_ready",
                ),
                self._task("code", "session-code", "worktree-code", ("src/code.py",), status="review_ready"),
            ),
        )
        self.assertEqual(summary.integration_queue_task_ids, ("code",))

    def test_orphaned_session_bound_queued_and_ready_tasks_are_reconciled(self) -> None:
        from chatgpt_dev_mcp.director_parallel import orphaned_writer_task_ids

        queued = self._task(
            "queued",
            "session:missing-queued",
            "session:missing-queued",
            ("src/shared.py",),
            status="queued",
        )
        ready = self._task(
            "ready",
            "session:missing-ready",
            "session:missing-ready",
            ("src/shared.py",),
            status="ready",
        )
        live = self._task(
            "live",
            "session:present",
            "session:present",
            ("src/other.py",),
            status="running",
        )
        canonical_queued = self._task(
            "canonical-queued",
            "session:synthetic",
            "canonical",
            ("src/canonical.py",),
            status="queued",
        )

        self.assertEqual(
            orphaned_writer_task_ids(
                (queued, ready, live, canonical_queued),
                {"session:present"},
            ),
            ("queued", "ready"),
        )


if __name__ == "__main__":
    unittest.main()
