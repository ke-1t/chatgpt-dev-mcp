from __future__ import annotations

import unittest


class DevelopmentFastPathTestCase(unittest.TestCase):
    def test_runs_stages_in_order_with_authorized_mutation(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import DevelopmentStepRequest, LocalDevelopmentFastPath

        order: list[str] = []
        result = LocalDevelopmentFastPath().run(
            DevelopmentStepRequest(task_id="task-1", query="change", changed_paths=("src/a.py",)),
            status_reader=lambda: order.append("status") or {"clean": True},
            context_builder=lambda: order.append("context") or {"items": 1},
            authorized_mutation=lambda: order.append("mutation") or {"applied": True},
            diff_reader=lambda: order.append("diff") or {"patch": "x"},
            verification_runner=lambda: order.append("verify") or {"status": "passed", "cache_status": "miss"},
            security_auditor=lambda: order.append("audit") or {"status": "pass"},
        )
        self.assertEqual(order, ["status", "context", "mutation", "diff", "verify", "audit"])
        self.assertEqual(result.verification["status"], "passed")

    def test_read_only_flow_does_not_require_mutation(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import DevelopmentStepRequest, LocalDevelopmentFastPath

        order: list[str] = []
        result = LocalDevelopmentFastPath().run(
            DevelopmentStepRequest(task_id="task-1", query="inspect", changed_paths=("src/a.py",)),
            status_reader=lambda: order.append("status") or {},
            context_builder=lambda: order.append("context") or {},
            diff_reader=lambda: order.append("diff") or {},
            verification_runner=lambda: order.append("verify") or {"status": "passed"},
            security_auditor=lambda: order.append("audit") or {"status": "pass"},
        )
        self.assertEqual(order, ["status", "context", "diff", "verify", "audit"])
        self.assertIsNone(result.mutation)

    def test_skips_verification_when_no_changed_paths(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import DevelopmentStepRequest, LocalDevelopmentFastPath

        order: list[str] = []
        result = LocalDevelopmentFastPath().run(
            DevelopmentStepRequest(task_id="task-1", query="inspect", changed_paths=()),
            status_reader=lambda: order.append("status") or {},
            context_builder=lambda: order.append("context") or {},
            diff_reader=lambda: order.append("diff") or {},
            verification_runner=lambda: order.append("verify") or {"status": "passed"},
            security_auditor=lambda: order.append("audit") or {"status": "pass"},
        )
        self.assertEqual(order, ["status", "context", "diff", "audit"])
        self.assertIsNone(result.verification)

    def test_fail_stops_after_stage_error(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import DevelopmentStepRequest, LocalDevelopmentFastPath

        order: list[str] = []
        def fail_mutation() -> object:
            order.append("mutation")
            raise RuntimeError("boom")

        with self.assertRaisesRegex(RuntimeError, "boom"):
            LocalDevelopmentFastPath().run(
                DevelopmentStepRequest(task_id="task-1", query="change", changed_paths=("src/a.py",)),
                status_reader=lambda: order.append("status") or {},
                context_builder=lambda: order.append("context") or {},
                authorized_mutation=fail_mutation,
                diff_reader=lambda: order.append("diff") or {},
                verification_runner=lambda: order.append("verify") or {},
                security_auditor=lambda: order.append("audit") or {},
            )
        self.assertEqual(order, ["status", "context", "mutation"])

    def test_records_stage_metrics_cache_and_session_reuse(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import DevelopmentStepRequest, LocalDevelopmentFastPath
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        values = iter([0.000, 0.001, 0.001, 0.003, 0.003, 0.004, 0.004, 0.006, 0.006, 0.007])
        result = LocalDevelopmentFastPath(metrics=PerformanceMetrics(), clock=lambda: next(values)).run(
            DevelopmentStepRequest(task_id="task-1", query="inspect", changed_paths=("src/a.py",), session_reused=True),
            status_reader=lambda: {}, context_builder=lambda: {}, diff_reader=lambda: {},
            verification_runner=lambda: {"status": "passed", "cache_status": "hit"},
            security_auditor=lambda: {"status": "pass"},
        )
        self.assertEqual(result.metrics["reuse_count"], 1)
        self.assertEqual(result.metrics["cache_hits"], 1)
        self.assertEqual(result.metrics["stages"]["status"]["total_ms"], 1.0)
        self.assertEqual(result.metrics["stages"]["context"]["total_ms"], 2.0)

    def test_session_reuse_requires_exact_safe_local_identity(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import ReusableSessionEvidence, can_reuse_session

        evidence = ReusableSessionEvidence(session_id="session:abc", owner_id="owner", task_id="task", source_revision="a" * 40, status="active", stale=False, worktree_available=True, dirty=True)
        self.assertTrue(can_reuse_session(evidence, owner_id="owner", task_id="task", source_revision="a" * 40))
        variants = ({"owner_id": "other"}, {"task_id": "other"}, {"source_revision": "b" * 40}, {"status": "stale_clean"}, {"stale": True}, {"worktree_available": False})
        for changes in variants:
            candidate = ReusableSessionEvidence(**{**evidence.__dict__, **changes})
            with self.subTest(changes=changes):
                self.assertFalse(can_reuse_session(candidate, owner_id="owner", task_id="task", source_revision="a" * 40))

    def test_fast_path_has_no_delivery_authority(self) -> None:
        from chatgpt_dev_mcp.development_fast_path import LocalDevelopmentFastPath

        fast_path = LocalDevelopmentFastPath()
        for name in ("commit", "push", "integrate", "external_write", "credential_grant"):
            self.assertFalse(hasattr(fast_path, name), name)


if __name__ == "__main__":
    unittest.main()
