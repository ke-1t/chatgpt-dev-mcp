from __future__ import annotations

import unittest


class CloudPerformanceTests(unittest.TestCase):
    def _sample(self, backend: str, total_ms: float, *, success: bool = True, billable_api: bool = False):
        from chatgpt_dev_mcp.cloud_performance import BackendPerformanceSample

        return BackendPerformanceSample(
            backend=backend,
            workload_class="test_shard",
            project_fingerprint="project:v1",
            environment_fingerprint=f"env:{backend}",
            benchmark_revision="bench:v1",
            total_ms=total_ms,
            stage_ms=0.0,
            return_ms=0.0,
            input_bytes=100,
            output_bytes=10,
            success=success,
            failure_fingerprint="" if success else "failed",
            warm=False,
            billable_api=billable_api,
        )

    def test_profile_selects_cloud_only_when_thresholds_pass(self) -> None:
        from chatgpt_dev_mcp.cloud_performance import ManagedCloudSelectionPolicy, derive_performance_profile

        samples = tuple(self._sample("local_native", value) for value in (100, 100, 100, 100, 100)) + tuple(
            self._sample("chatgpt_managed_cloud", value) for value in (70, 75, 80, 80, 80)
        )
        profile = derive_performance_profile(samples, policy=ManagedCloudSelectionPolicy())
        self.assertTrue(profile.sufficient)
        self.assertTrue(profile.managed_cloud_wins)
        self.assertLess(profile.cloud_p50_ms, profile.local_p50_ms)

    def test_profile_accepts_canonical_chatgpt_builtin_backend(self) -> None:
        from dataclasses import replace

        from chatgpt_dev_mcp.cloud_performance import CHATGPT_BUILTIN_BACKEND, ManagedCloudSelectionPolicy, derive_performance_profile

        local = tuple(replace(self._sample("local_native", 100), workload_class="bulk_analysis") for _ in range(5))
        builtin = tuple(
            replace(
                self._sample("chatgpt_managed_cloud", 70),
                backend=CHATGPT_BUILTIN_BACKEND,
                workload_class="bulk_analysis",
                environment_fingerprint="chatgpt-builtin:runtime-v1",
            )
            for _ in range(5)
        )
        profile = derive_performance_profile(local + builtin, policy=ManagedCloudSelectionPolicy())

        self.assertTrue(profile.sufficient)
        self.assertTrue(profile.managed_cloud_wins)
        self.assertFalse(profile.billable_api)

    def test_chatgpt_builtin_sample_rejects_billable_api(self) -> None:
        from dataclasses import replace

        from chatgpt_dev_mcp.cloud_performance import CHATGPT_BUILTIN_BACKEND, CloudPerformanceError, ManagedCloudSelectionPolicy, derive_performance_profile

        local = tuple(self._sample("local_native", 100) for _ in range(5))
        builtin = tuple(
            replace(
                self._sample("chatgpt_managed_cloud", 70),
                backend=CHATGPT_BUILTIN_BACKEND,
                billable_api=True,
                environment_fingerprint="chatgpt-builtin:runtime-v1",
            )
            for _ in range(5)
        )
        with self.assertRaises(CloudPerformanceError):
            derive_performance_profile(local + builtin, policy=ManagedCloudSelectionPolicy())

    def test_profile_rejects_insufficient_or_billable_cloud_samples(self) -> None:
        from chatgpt_dev_mcp.cloud_performance import CloudPerformanceError, ManagedCloudSelectionPolicy, derive_performance_profile

        small = tuple(self._sample("local_native", 100) for _ in range(4)) + tuple(self._sample("chatgpt_managed_cloud", 70) for _ in range(4))
        self.assertFalse(derive_performance_profile(small, policy=ManagedCloudSelectionPolicy()).sufficient)
        billable = tuple(self._sample("local_native", 100) for _ in range(5)) + tuple(self._sample("chatgpt_managed_cloud", 70, billable_api=True) for _ in range(5))
        with self.assertRaises(CloudPerformanceError):
            derive_performance_profile(billable, policy=ManagedCloudSelectionPolicy())

    def test_profile_requires_matching_warm_project_and_environment_classes(self) -> None:
        from dataclasses import replace

        from chatgpt_dev_mcp.cloud_performance import CloudPerformanceError, ManagedCloudSelectionPolicy, derive_performance_profile

        base = tuple(self._sample("local_native", 100) for _ in range(5)) + tuple(self._sample("chatgpt_managed_cloud", 70) for _ in range(5))
        with self.assertRaisesRegex(CloudPerformanceError, "comparable"):
            derive_performance_profile(base[:-1] + (replace(base[-1], warm=True),), policy=ManagedCloudSelectionPolicy())
        with self.assertRaisesRegex(CloudPerformanceError, "comparable"):
            derive_performance_profile(base[:-1] + (replace(base[-1], project_fingerprint="project:v2"),), policy=ManagedCloudSelectionPolicy())
        with self.assertRaisesRegex(CloudPerformanceError, "environment"):
            derive_performance_profile(base[:-1] + (replace(base[-1], environment_fingerprint="cloud:v2"),), policy=ManagedCloudSelectionPolicy())

    def test_p95_and_failure_rate_can_veto_a_fast_p50(self) -> None:
        from dataclasses import replace

        from chatgpt_dev_mcp.cloud_performance import ManagedCloudSelectionPolicy, derive_performance_profile

        local = tuple(self._sample("local_native", value) for value in (100, 100, 100, 100, 100))
        p95_bad = tuple(self._sample("chatgpt_managed_cloud", value) for value in (60, 60, 60, 60, 150))
        self.assertFalse(derive_performance_profile(local + p95_bad, policy=ManagedCloudSelectionPolicy()).managed_cloud_wins)

        cloud = [self._sample("chatgpt_managed_cloud", 60) for _ in range(6)]
        cloud[-1] = replace(cloud[-1], success=False, failure_fingerprint="boom")
        profile = derive_performance_profile(local + tuple(cloud), policy=ManagedCloudSelectionPolicy(max_failure_rate_regression=0.05))
        self.assertFalse(profile.managed_cloud_wins)


if __name__ == "__main__":
    unittest.main()
