from __future__ import annotations

import unittest


class HybridExecutionTests(unittest.TestCase):
    def test_no_builtin_declaration_uses_local(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionMode, RouteRequest, WorkloadKind
        from chatgpt_dev_mcp.hybrid_execution import HybridExecutionCoordinator

        calls: list[str] = []
        result = HybridExecutionCoordinator(local_execute=lambda payload: calls.append("local") or payload).execute(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.COMPUTE_HEAVY), {"value": 1}
        )
        self.assertEqual(calls, ["local"])
        self.assertEqual(result["backend"], "local_native")
        self.assertFalse(result["fallback"])
        self.assertEqual(result["reason"], "auto_performance_profile_missing")
        self.assertEqual(result["execution_kind"], "local_execute")
        self.assertFalse(result["billable_api"])

    def test_builtin_route_is_assistant_handoff_and_executes_nothing(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionMode, PerformanceRouteEvidence, RouteRequest, WorkloadKind
        from chatgpt_dev_mcp.hybrid_execution import HybridExecutionCoordinator

        calls: list[str] = []
        coordinator = HybridExecutionCoordinator(
            local_execute=lambda payload: calls.append("local") or payload,
            chatgpt_builtin_available=True,
        )
        result = coordinator.execute(
            RouteRequest(
                mode=ExecutionMode.AUTO,
                workload=WorkloadKind.BULK_ANALYSIS,
                performance=PerformanceRouteEvidence(
                    profile_id="profile:measured",
                    current=True,
                    sufficient=True,
                    managed_cloud_wins=True,
                    reason="thresholds_passed",
                ),
            ),
            {"value": 2},
        )

        self.assertEqual(calls, [])
        self.assertEqual(result["backend"], "chatgpt_builtin")
        self.assertEqual(result["execution_kind"], "assistant_handoff")
        self.assertTrue(result["requires_assistant_action"])
        self.assertFalse(result["human_confirmation_required"])
        self.assertFalse(result["billable_api"])
        self.assertEqual(result["handoff"]["kind"], "python_analysis")
        self.assertEqual(result["handoff"]["parallelism_hint"], 3)
        self.assertEqual(result["handoff"]["max_parallelism"], 5)
        self.assertIsNone(result["result"])

    def test_builtin_availability_without_measured_win_stays_local(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionMode, RouteRequest, WorkloadKind
        from chatgpt_dev_mcp.hybrid_execution import HybridExecutionCoordinator

        result = HybridExecutionCoordinator(
            local_execute=lambda payload: payload,
            chatgpt_builtin_available=True,
        ).execute(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.COMPUTE_HEAVY),
            {"value": 3},
        )

        self.assertEqual(result["backend"], "local_native")
        self.assertEqual(result["reason"], "auto_performance_profile_missing")
        self.assertEqual(result["execution_kind"], "local_execute")
        self.assertFalse(result["billable_api"])

    def test_cloud_mode_is_builtin_handoff_when_declared_available(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionMode, RouteRequest, WorkloadKind
        from chatgpt_dev_mcp.hybrid_execution import HybridExecutionCoordinator

        result = HybridExecutionCoordinator(
            local_execute=lambda payload: payload,
            chatgpt_builtin_available=True,
        ).route(RouteRequest(mode=ExecutionMode.CLOUD, workload=WorkloadKind.COMPUTE_HEAVY))

        self.assertEqual(result["backend"], "chatgpt_builtin")
        self.assertEqual(result["reason"], "explicit_chatgpt_builtin_mode")
        self.assertEqual(result["execution_kind"], "assistant_handoff")

    def test_hard_local_work_never_handoffs(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionMode, RouteRequest, WorkloadKind
        from chatgpt_dev_mcp.hybrid_execution import HybridExecutionCoordinator

        result = HybridExecutionCoordinator(
            local_execute=lambda payload: payload,
            chatgpt_builtin_available=True,
        ).execute(
            RouteRequest(
                mode=ExecutionMode.AUTO,
                workload=WorkloadKind.COMPUTE_HEAVY,
                requires_local_secrets=True,
            ),
            {"value": 4},
        )
        self.assertEqual(result["backend"], "local_native")
        self.assertEqual(result["execution_kind"], "local_execute")


if __name__ == "__main__":
    unittest.main()
