from __future__ import annotations

import math
import unittest


class PerformanceMetricsTestCase(unittest.TestCase):
    def test_aggregates_stage_duration(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        metrics.record("resolve", 2.5)
        metrics.record("resolve", 3.5)
        stage = metrics.snapshot()["stages"]["resolve"]
        self.assertEqual(stage["count"], 2)
        self.assertEqual(stage["total_ms"], 6.0)
        self.assertEqual(stage["max_ms"], 3.5)

    def test_counts_cache_hits_misses_and_reuse(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import CacheOutcome, PerformanceMetrics

        metrics = PerformanceMetrics()
        metrics.record("verify", 1.0, cache=CacheOutcome.HIT)
        metrics.record("verify", 2.0, cache=CacheOutcome.MISS)
        metrics.record("session", 0.5, reused=True)
        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["cache_hits"], 1)
        self.assertEqual(snapshot["cache_misses"], 1)
        self.assertEqual(snapshot["reuse_count"], 1)
        self.assertEqual(snapshot["record_count"], 3)

    def test_rejects_invalid_durations(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        for value in (-1.0, math.inf, -math.inf, math.nan):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    metrics.record("resolve", value)

    def test_rejects_invalid_stage_names(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        for stage in ("", "../resolve", "a" * 81):
            with self.subTest(stage=stage):
                with self.assertRaises(ValueError):
                    metrics.record(stage, 1.0)

    def test_bounds_number_of_distinct_stages(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics(max_stages=2)
        metrics.record("one", 1.0)
        metrics.record("two", 1.0)
        with self.assertRaises(ValueError):
            metrics.record("three", 1.0)
        self.assertEqual(set(metrics.snapshot()["stages"]), {"one", "two"})

    def test_snapshot_is_detached_from_internal_state(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        metrics.record("resolve", 1.0)
        snapshot = metrics.snapshot()
        snapshot["stages"]["resolve"]["count"] = 99
        self.assertEqual(metrics.snapshot()["stages"]["resolve"]["count"], 1)

    def test_summary_computes_percentiles_cache_ratio_and_output_bytes(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import CacheOutcome, PerformanceMetrics

        metrics = PerformanceMetrics(max_samples_per_stage=4)
        for value in (10.0, 20.0, 30.0, 40.0):
            metrics.record("context.bootstrap", value, cache=CacheOutcome.HIT, output_bytes=100)

        stage = metrics.summary()["stages"]["context.bootstrap"]

        self.assertEqual(stage["sample_count"], 4)
        self.assertEqual(stage["p50_ms"], 25.0)
        self.assertEqual(stage["p95_ms"], 40.0)
        self.assertEqual(stage["cache_hit_ratio"], 1.0)
        self.assertEqual(stage["average_output_bytes"], 100.0)
        self.assertEqual(stage["max_output_bytes"], 100)

    def test_sample_retention_is_bounded_but_lifetime_failures_are_preserved(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics(max_samples_per_stage=2)
        metrics.record("verify", 1.0, success=False, failure_fingerprint="timeout")
        metrics.record("verify", 2.0)
        metrics.record("verify", 3.0)

        stage = metrics.summary()["stages"]["verify"]

        self.assertEqual(metrics.snapshot()["record_count"], 3)
        self.assertEqual(stage["sample_count"], 2)
        self.assertEqual(stage["p50_ms"], 2.5)
        self.assertEqual(stage["p95_ms"], 3.0)
        self.assertEqual(stage["failure_count"], 1)
        self.assertEqual(stage["failure_fingerprints"], {"timeout": 1})
        self.assertEqual(stage["average_ms"], 2.0)
        self.assertAlmostEqual(stage["failure_rate"], 1 / 3)

    def test_neutral_samples_preserve_latency_without_diluting_failure_rate(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        metrics.record("verification.run", 10.0, neutral=True)
        metrics.record("verification.run", 20.0, success=False, failure_fingerprint="verification_failed")

        stage = metrics.summary()["stages"]["verification.run"]

        self.assertEqual(stage["count"], 2)
        self.assertEqual(stage["neutral_count"], 1)
        self.assertEqual(stage["completed_count"], 1)
        self.assertEqual(stage["failure_count"], 1)
        self.assertEqual(stage["failure_rate"], 1.0)
        self.assertEqual(stage["average_ms"], 15.0)

    def test_neutral_sample_rejects_failure_state(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        with self.assertRaises(ValueError):
            metrics.record("verification.run", 1.0, success=False, neutral=True, failure_fingerprint="verification_failed")

    def test_summary_orders_slow_operations_and_bounds_requested_limit(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        metrics.record("fast", 1.0)
        metrics.record("slow", 9.0)

        summary = metrics.summary(limit=1)

        self.assertEqual(summary["slow_operations"], ["slow"])
        with self.assertRaises(ValueError):
            metrics.summary(limit=0)
        with self.assertRaises(ValueError):
            metrics.summary(limit=101)

    def test_empty_summary_has_no_fabricated_percentiles(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        summary = PerformanceMetrics().summary()

        self.assertEqual(summary["stages"], {})
        self.assertEqual(summary["slow_operations"], [])

    def test_failure_fingerprint_rejects_raw_error_text(self) -> None:
        from chatgpt_dev_mcp.performance_metrics import PerformanceMetrics

        metrics = PerformanceMetrics()
        with self.assertRaises(ValueError):
            metrics.record("verify", 1.0, success=False, failure_fingerprint="raw error with spaces")
        with self.assertRaises(ValueError):
            metrics.record("verify", 1.0, success=True, failure_fingerprint="timeout")


if __name__ == "__main__":
    unittest.main()
