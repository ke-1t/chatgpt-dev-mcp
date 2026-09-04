from __future__ import annotations

import unittest


class ExecutionRouterTestCase(unittest.TestCase):
    def test_canonical_backend_names_are_local_and_builtin_only(self) -> None:
        from chatgpt_dev_mcp.execution_router import ExecutionBackend, ExecutionMode

        self.assertEqual({mode.value for mode in ExecutionMode}, {"local", "cloud", "auto"})
        self.assertEqual(ExecutionBackend.CHATGPT_BUILTIN.value, "chatgpt_builtin")
        self.assertIs(ExecutionBackend.CHATGPT_MANAGED_CLOUD, ExecutionBackend.CHATGPT_BUILTIN)
        self.assertEqual({backend.value for backend in ExecutionBackend}, {"local_native", "chatgpt_builtin"})

    def test_builtin_availability_maps_legacy_managed_cloud_storage(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability

        availability = BackendAvailability(managed_cloud=True)
        self.assertTrue(availability.chatgpt_builtin)
        self.assertEqual(availability.chatgpt_builtin_reason, "")

    def test_local_mode_always_uses_local_backend(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(RouteRequest(mode=ExecutionMode.LOCAL, workload=WorkloadKind.COMPUTE_HEAVY), BackendAvailability(local=True, managed_cloud=True))
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertFalse(decision.fallback)
        self.assertTrue(decision.available)
        self.assertEqual(decision.reason, "explicit_local_mode")

    def test_cloud_mode_is_legacy_alias_for_chatgpt_builtin(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(RouteRequest(mode=ExecutionMode.CLOUD, workload=WorkloadKind.BULK_ANALYSIS), BackendAvailability(local=True, managed_cloud=True))
        self.assertIs(decision.backend, ExecutionBackend.CHATGPT_BUILTIN)
        self.assertFalse(decision.fallback)
        self.assertEqual(decision.reason, "explicit_chatgpt_builtin_mode")

    def test_cloud_mode_falls_back_to_local_when_builtin_unavailable(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(
            RouteRequest(mode=ExecutionMode.CLOUD, workload=WorkloadKind.COMPUTE_HEAVY),
            BackendAvailability(local=True, managed_cloud=False, managed_cloud_reason="not_declared"),
        )
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertTrue(decision.fallback)
        self.assertEqual(decision.reason, "chatgpt_builtin_unavailable:not_declared")

    def test_auto_requires_performance_evidence_before_builtin_handoff(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.COMPUTE_HEAVY),
            BackendAvailability(local=True, managed_cloud=True),
        )
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertEqual(decision.reason, "auto_performance_profile_missing")

    def test_auto_uses_builtin_only_for_current_sufficient_measured_win(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, PerformanceRouteEvidence, RouteRequest, WorkloadKind, choose_backend

        evidence = PerformanceRouteEvidence(
            profile_id="profile:measured",
            current=True,
            sufficient=True,
            managed_cloud_wins=True,
            reason="thresholds_passed",
        )
        decision = choose_backend(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.COMPUTE_HEAVY, performance=evidence),
            BackendAvailability(local=True, managed_cloud=True),
        )
        self.assertIs(decision.backend, ExecutionBackend.CHATGPT_BUILTIN)
        self.assertEqual(decision.reason, "auto_chatgpt_builtin_measured_win")

    def test_auto_rejects_stale_insufficient_or_losing_performance_evidence(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, PerformanceRouteEvidence, RouteRequest, WorkloadKind, choose_backend

        cases = (
            (PerformanceRouteEvidence("profile:stale", False, True, True, "expired"), "auto_performance_profile_stale"),
            (PerformanceRouteEvidence("profile:small", True, False, True, "too_few_samples"), "auto_performance_profile_insufficient"),
            (PerformanceRouteEvidence("profile:slow", True, True, False, "threshold_not_met"), "auto_chatgpt_builtin_threshold_not_met"),
        )
        for evidence, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                decision = choose_backend(
                    RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.COMPUTE_HEAVY, performance=evidence),
                    BackendAvailability(local=True, managed_cloud=True),
                )
                self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
                self.assertEqual(decision.reason, expected_reason)

    def test_auto_measured_win_stays_local_when_builtin_is_unavailable(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, PerformanceRouteEvidence, RouteRequest, WorkloadKind, choose_backend

        evidence = PerformanceRouteEvidence("profile:measured", True, True, True, "thresholds_passed")
        decision = choose_backend(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.BULK_ANALYSIS, performance=evidence),
            BackendAvailability(local=True, managed_cloud=False, managed_cloud_reason="not_declared"),
        )
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertEqual(decision.reason, "auto_chatgpt_builtin_unavailable:not_declared")

    def test_auto_keeps_non_offload_workloads_local_even_when_builtin_available(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        for workload in (WorkloadKind.GENERIC, WorkloadKind.LATENCY_SENSITIVE):
            with self.subTest(workload=workload):
                decision = choose_backend(
                    RouteRequest(mode=ExecutionMode.AUTO, workload=workload),
                    BackendAvailability(local=True, managed_cloud=True),
                )
                self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
                self.assertEqual(decision.reason, "auto_workload_not_offload_candidate")

    def test_auto_keeps_generic_work_local(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.GENERIC), BackendAvailability(local=True, managed_cloud=True))
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertEqual(decision.reason, "auto_workload_not_offload_candidate")

    def test_hard_local_requirement_overrides_cloud_mode(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        for constraint in ("requires_local_secrets", "requires_authenticated_browser", "requires_macos"):
            with self.subTest(constraint=constraint):
                decision = choose_backend(
                    RouteRequest(mode=ExecutionMode.CLOUD, workload=WorkloadKind.COMPUTE_HEAVY, **{constraint: True}),
                    BackendAvailability(local=True, managed_cloud=True),
                )
                self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
                self.assertTrue(decision.fallback)
                self.assertEqual(decision.reason, f"hard_local_requirement:{constraint}")

    def test_unavailable_local_is_reported_instead_of_incompatible_cloud(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, WorkloadKind, choose_backend

        decision = choose_backend(
            RouteRequest(mode=ExecutionMode.AUTO, workload=WorkloadKind.GENERIC, requires_local_secrets=True),
            BackendAvailability(local=False, managed_cloud=True, local_reason="mac_offline"),
        )
        self.assertIs(decision.backend, ExecutionBackend.LOCAL_NATIVE)
        self.assertFalse(decision.available)
        self.assertFalse(decision.fallback)
        self.assertEqual(decision.reason, "local_unavailable:mac_offline")

    def test_unknown_cloud_defaults_to_unavailable(self) -> None:
        from chatgpt_dev_mcp.execution_router import BackendAvailability

        availability = BackendAvailability(local=True)
        self.assertFalse(availability.managed_cloud)
        self.assertFalse(availability.chatgpt_builtin)


if __name__ == "__main__":
    unittest.main()
