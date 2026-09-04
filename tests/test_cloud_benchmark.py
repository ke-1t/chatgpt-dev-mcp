from __future__ import annotations

import unittest


class CloudBenchmarkTests(unittest.TestCase):
    def test_assistant_analysis_kernel_is_deterministic_and_bounded(self) -> None:
        from chatgpt_dev_mcp.cloud_benchmark import run_assistant_analysis_kernel

        payload = (
            "diff --git a/src/app.py b/src/app.py\n"
            "@@ -1,2 +1,3 @@\n"
            "-old = 1\n"
            "+new = 2\n"
            "+print(new)\n"
        )
        first = run_assistant_analysis_kernel(payload, rounds=32)
        second = run_assistant_analysis_kernel(payload.encode("utf-8"), rounds=32)

        self.assertEqual(first, second)
        self.assertEqual(first["byte_count"], len(payload.encode("utf-8")))
        self.assertEqual(first["file_count"], 1)
        self.assertEqual(first["hunk_count"], 1)
        self.assertEqual(first["addition_count"], 2)
        self.assertEqual(first["deletion_count"], 1)
        self.assertEqual(len(first["checksum"]), 64)

    def test_bulk_analysis_is_a_routing_comparable_workload(self) -> None:
        from chatgpt_dev_mcp.cloud_benchmark import WORKLOAD_IDS, route_workload_for_benchmark

        self.assertIn("bulk_analysis", WORKLOAD_IDS)
        self.assertEqual(route_workload_for_benchmark("bulk_analysis"), "bulk_analysis")
        self.assertEqual(route_workload_for_benchmark("static_analysis"), "bulk_analysis")
        self.assertEqual(route_workload_for_benchmark("parallel_shard_bundle"), "compute_heavy")

    def test_assistant_analysis_diagnostic_uses_fixed_size_comparable_fixture(self) -> None:
        import json

        from chatgpt_dev_mcp.cloud_benchmark import run_assistant_analysis_diagnostic

        result = run_assistant_analysis_diagnostic(repeats=6, rounds=256, payload_bytes=8177)
        self.assertEqual(result["payload_bytes"], 8177)
        self.assertEqual(len(result["execute_ms"]), 6)
        self.assertEqual(result["checksum"], result["checksum_repeat"])
        self.assertFalse(result["routing_evidence_eligible"])
        print("DEVMCP_ASSISTANT_ANALYSIS_DIAGNOSTIC=" + json.dumps(result, sort_keys=True, separators=(",", ":")))

    def test_parallel_assistant_analysis_diagnostic_reports_wall_clock_speedup(self) -> None:
        import json

        from chatgpt_dev_mcp.cloud_benchmark import run_parallel_assistant_analysis_diagnostic

        result = run_parallel_assistant_analysis_diagnostic(
            repeats=5,
            shards=4,
            rounds=1024,
            payload_bytes=8177,
        )
        self.assertEqual(len(result["sequential_ms"]), 5)
        self.assertEqual(len(result["parallel_ms"]), 5)
        self.assertEqual(result["checksum"], result["checksum_repeat"])
        self.assertGreater(result["parallel_speedup_p50"], 0.0)
        self.assertFalse(result["routing_evidence_eligible"])
        print("DEVMCP_PARALLEL_ASSISTANT_ANALYSIS_DIAGNOSTIC=" + json.dumps(result, sort_keys=True, separators=(",", ":")))

    def test_runner_accounts_for_every_stage_in_total_latency(self) -> None:
        from chatgpt_dev_mcp.cloud_benchmark import BenchmarkStageResult, run_benchmark_sample

        stages = iter(
            [
                BenchmarkStageResult("package", 2, 100),
                BenchmarkStageResult("stage", 3, 0),
                BenchmarkStageResult("prepare", 5, 0),
                BenchmarkStageResult("execute", 7, 0),
                BenchmarkStageResult("result", 11, 20),
                BenchmarkStageResult("return", 13, 0),
                BenchmarkStageResult("verify", 17, 0),
            ]
        )
        sample = run_benchmark_sample(
            backend="chatgpt_managed_cloud",
            workload_id="test_shard",
            project_fingerprint="project:v1",
            environment_fingerprint="cloud:v1",
            benchmark_revision="bench:v1",
            stage_runner=lambda name: next(stages),
            warm=False,
            billable_api=False,
        )
        self.assertEqual(sample.total_ms, 58)
        self.assertEqual(sample.input_bytes, 100)
        self.assertEqual(sample.output_bytes, 20)

    def test_runner_keys_profile_by_public_route_workload(self) -> None:
        from chatgpt_dev_mcp.cloud_benchmark import BenchmarkStageResult, run_benchmark_sample

        sample = run_benchmark_sample(
            backend="chatgpt_builtin",
            workload_id="static_analysis",
            project_fingerprint="project:v1",
            environment_fingerprint="chatgpt:v1",
            benchmark_revision="assistant-analysis-v1",
            stage_runner=lambda name: BenchmarkStageResult(name, 1.0, 0),
            warm=False,
            billable_api=False,
        )

        self.assertEqual(sample.workload_class, "bulk_analysis")

    def test_raw_runtime_diagnostic_runs_identical_deterministic_kernels(self) -> None:
        import json

        from chatgpt_dev_mcp.cloud_benchmark import run_raw_runtime_diagnostic

        result = run_raw_runtime_diagnostic(repeats=6, cpu_rounds=120_000, data_size=180_000)
        self.assertEqual(len(result["cpu_single_ms"]), 6)
        self.assertEqual(len(result["python_data_ms"]), 6)
        self.assertEqual(result["cpu_checksum"], result["cpu_checksum_repeat"])
        self.assertEqual(result["data_checksum"], result["data_checksum_repeat"])
        print("DEVMCP_RAW_RUNTIME_DIAGNOSTIC=" + json.dumps(result, sort_keys=True, separators=(",", ":")))

    def test_runner_normalizes_stage_failure_and_preserves_warm_class(self) -> None:
        from chatgpt_dev_mcp.cloud_benchmark import BenchmarkStageResult, run_benchmark_sample

        def failing_stage(name: str) -> BenchmarkStageResult:
            if name == "execute":
                raise RuntimeError("synthetic failure text must not be persisted")
            return BenchmarkStageResult(name, 1.0, 10 if name in {"package", "result"} else 0)

        failed = run_benchmark_sample(
            backend="chatgpt_managed_cloud",
            workload_id="test_shard",
            project_fingerprint="project:v1",
            environment_fingerprint="cloud:v1",
            benchmark_revision="bench:v1",
            stage_runner=failing_stage,
            warm=True,
            billable_api=False,
        )
        self.assertFalse(failed.success)
        self.assertEqual(failed.failure_fingerprint, "execute:RuntimeError")
        self.assertTrue(failed.warm)
        self.assertEqual(failed.total_ms, 3.0)
        self.assertEqual(failed.input_bytes, 10)
        self.assertEqual(failed.output_bytes, 0)


if __name__ == "__main__":
    unittest.main()
