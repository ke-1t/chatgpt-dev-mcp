"""Deterministic stage accounting for LOCAL vs managed-cloud benchmark samples."""

from __future__ import annotations

import math
import os
import platform
import statistics
import sys
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from .cloud_performance import BackendPerformanceSample


BENCHMARK_STAGE_ORDER = ("package", "stage", "prepare", "execute", "result", "return", "verify")
WORKLOAD_IDS = (
    "cpu_single",
    "cpu_parallel",
    "python_data",
    "git_analysis",
    "devmcp_test_shard",
    "static_analysis",
    "parallel_shard_bundle",
    "test_shard",
    "bulk_analysis",
)

MAX_ASSISTANT_ANALYSIS_BYTES = 64 * 1024


class CloudBenchmarkError(ValueError):
    pass


@dataclass(frozen=True)
class BenchmarkStageResult:
    name: str
    duration_ms: float
    byte_count: int = 0


def route_workload_for_benchmark(workload_id: str) -> str:
    """Map a concrete benchmark workload onto the public routing workload class."""

    mapping = {
        "bulk_analysis": "bulk_analysis",
        "static_analysis": "bulk_analysis",
        "git_analysis": "bulk_analysis",
        "parallel_shard_bundle": "compute_heavy",
        "cpu_parallel": "compute_heavy",
        "cpu_single": "compute_heavy",
        "python_data": "compute_heavy",
        "devmcp_test_shard": "compute_heavy",
        "test_shard": "compute_heavy",
    }
    try:
        return mapping[workload_id]
    except KeyError as exc:
        raise CloudBenchmarkError("workload_id is invalid") from exc


def run_assistant_analysis_kernel(payload: str | bytes, *, rounds: int = 32) -> dict[str, object]:
    """Run one deterministic bounded diff-analysis kernel on either runtime.

    The same payload and algorithm can execute on LOCAL_NATIVE or the ChatGPT
    built-in Python runtime.  The kernel intentionally has no filesystem,
    network, credential, or provider dependency.
    """

    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise CloudBenchmarkError("assistant analysis payload must be text or bytes")
    if not raw or len(raw) > MAX_ASSISTANT_ANALYSIS_BYTES:
        raise CloudBenchmarkError("assistant analysis payload size is invalid")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 10_000:
        raise CloudBenchmarkError("assistant analysis rounds is invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CloudBenchmarkError("assistant analysis payload must be UTF-8") from exc

    lines = text.splitlines()
    file_count = sum(1 for line in lines if line.startswith("diff --git "))
    hunk_count = sum(1 for line in lines if line.startswith("@@"))
    addition_count = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    deletion_count = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    state = hashlib.sha256(raw).digest()
    for index in range(rounds):
        state = hashlib.sha256(state + raw + index.to_bytes(4, "big")).digest()
    return {
        "byte_count": len(raw),
        "line_count": len(lines),
        "file_count": file_count,
        "hunk_count": hunk_count,
        "addition_count": addition_count,
        "deletion_count": deletion_count,
        "rounds": rounds,
        "checksum": state.hex(),
    }


def _assistant_analysis_fixture(payload_bytes: int) -> bytes:
    if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or not 256 <= payload_bytes <= MAX_ASSISTANT_ANALYSIS_BYTES:
        raise CloudBenchmarkError("assistant analysis fixture size is invalid")
    block = (
        "diff --git a/src/example.py b/src/example.py\n"
        "@@ -1,3 +1,4 @@\n"
        "-old_value = 1\n"
        "+new_value = 2\n"
        "+result = new_value * 3\n"
        " context = result\n"
    ).encode("utf-8")
    repeats = (payload_bytes // len(block)) + 1
    return (block * repeats)[:payload_bytes]


def run_assistant_analysis_diagnostic(
    *,
    repeats: int = 6,
    rounds: int = 256,
    payload_bytes: int = 8177,
) -> dict[str, object]:
    """Measure the identical bounded assistant-analysis execution stage only."""

    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= 20:
        raise CloudBenchmarkError("repeats is invalid")
    payload = _assistant_analysis_fixture(payload_bytes)
    execute_ms: list[float] = []
    checksum = ""
    for _ in range(repeats):
        started = time.perf_counter()
        result = run_assistant_analysis_kernel(payload, rounds=rounds)
        execute_ms.append((time.perf_counter() - started) * 1000.0)
        checksum = str(result["checksum"])
    repeat_checksum = str(run_assistant_analysis_kernel(payload, rounds=rounds)["checksum"])
    return {
        "repeats": repeats,
        "rounds": rounds,
        "payload_bytes": len(payload),
        "execute_ms": execute_ms,
        "execute_summary": _summarize_ms(execute_ms),
        "checksum": checksum,
        "checksum_repeat": repeat_checksum,
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "routing_evidence_eligible": False,
    }


def run_parallel_assistant_analysis_diagnostic(
    *,
    repeats: int = 5,
    shards: int = 4,
    rounds: int = 1024,
    payload_bytes: int = 8177,
) -> dict[str, object]:
    """Compare sequential and same-runtime parallel execution for independent shards.

    This remains diagnostic-only: it measures execution-stage wall clock on one
    runtime and excludes assistant handoff/return overhead, so it cannot by
    itself authorize AUTO routing.
    """

    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= 20:
        raise CloudBenchmarkError("repeats is invalid")
    if not isinstance(shards, int) or isinstance(shards, bool) or not 1 <= shards <= 5:
        raise CloudBenchmarkError("shards is invalid")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 10_000:
        raise CloudBenchmarkError("assistant analysis rounds is invalid")

    payload = _assistant_analysis_fixture(payload_bytes)

    def one_shard() -> str:
        return str(run_assistant_analysis_kernel(payload, rounds=rounds)["checksum"])

    def aggregate(values: list[str]) -> str:
        return hashlib.sha256("".join(values).encode("ascii")).hexdigest()

    sequential_ms: list[float] = []
    parallel_ms: list[float] = []
    checksum = ""
    for _ in range(repeats):
        started = time.perf_counter()
        sequential_checksums = [one_shard() for _ in range(shards)]
        sequential_ms.append((time.perf_counter() - started) * 1000.0)

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=shards) as executor:
            parallel_checksums = list(executor.map(lambda _index: one_shard(), range(shards)))
        parallel_ms.append((time.perf_counter() - started) * 1000.0)

        sequential_checksum = aggregate(sequential_checksums)
        parallel_checksum = aggregate(parallel_checksums)
        if sequential_checksum != parallel_checksum:
            raise CloudBenchmarkError("parallel shard checksum mismatch")
        checksum = sequential_checksum

    repeat_checksum = aggregate([one_shard() for _ in range(shards)])
    sequential_summary = _summarize_ms(sequential_ms)
    parallel_summary = _summarize_ms(parallel_ms)
    parallel_p50 = parallel_summary["p50_ms"]
    return {
        "repeats": repeats,
        "shards": shards,
        "rounds": rounds,
        "payload_bytes": len(payload),
        "sequential_ms": sequential_ms,
        "parallel_ms": parallel_ms,
        "sequential_summary": sequential_summary,
        "parallel_summary": parallel_summary,
        "parallel_speedup_p50": (
            sequential_summary["p50_ms"] / parallel_p50 if parallel_p50 > 0 else math.inf
        ),
        "checksum": checksum,
        "checksum_repeat": repeat_checksum,
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "routing_evidence_eligible": False,
    }


def _cpu_single_kernel(rounds: int) -> int:
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 10_000_000:
        raise CloudBenchmarkError("cpu_rounds is invalid")
    value = 0x12345678
    mask = (1 << 64) - 1
    for index in range(rounds):
        value ^= (value << 13) & mask
        value ^= value >> 7
        value ^= (value << 17) & mask
        value = (value + index * 0x9E3779B1) & mask
    return value


def _python_data_kernel(size: int) -> int:
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 10_000_000:
        raise CloudBenchmarkError("data_size is invalid")
    total = 0
    rolling = 2166136261
    for index in range(size):
        value = ((index * 2654435761) ^ (index >> 3)) & 0xFFFFFFFF
        rolling ^= value
        rolling = (rolling * 16777619) & 0xFFFFFFFF
        total = (total + (rolling ^ (value >> 5))) & 0xFFFFFFFFFFFFFFFF
    return total


def _summarize_ms(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    p95_index = max(0, min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1))
    return {
        "p50_ms": float(statistics.median(ordered)),
        "p95_ms": float(ordered[p95_index]),
        "min_ms": float(ordered[0]),
        "max_ms": float(ordered[-1]),
    }


def run_raw_runtime_diagnostic(
    *,
    repeats: int = 5,
    cpu_rounds: int = 120_000,
    data_size: int = 180_000,
) -> dict[str, object]:
    """Measure two deterministic Python kernels for runtime diagnostics only.

    These timings deliberately exclude package transfer and verification, so
    they must never be used as AUTO-routing evidence.
    """

    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= 20:
        raise CloudBenchmarkError("repeats is invalid")
    cpu_ms: list[float] = []
    data_ms: list[float] = []
    cpu_checksum = 0
    data_checksum = 0
    for _ in range(repeats):
        started = time.perf_counter()
        cpu_checksum = _cpu_single_kernel(cpu_rounds)
        cpu_ms.append((time.perf_counter() - started) * 1000.0)
        started = time.perf_counter()
        data_checksum = _python_data_kernel(data_size)
        data_ms.append((time.perf_counter() - started) * 1000.0)
    return {
        "repeats": repeats,
        "cpu_rounds": cpu_rounds,
        "data_size": data_size,
        "cpu_single_ms": cpu_ms,
        "python_data_ms": data_ms,
        "cpu_summary": _summarize_ms(cpu_ms),
        "data_summary": _summarize_ms(data_ms),
        "cpu_checksum": cpu_checksum,
        "cpu_checksum_repeat": _cpu_single_kernel(cpu_rounds),
        "data_checksum": data_checksum,
        "data_checksum_repeat": _python_data_kernel(data_size),
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "routing_evidence_eligible": False,
    }


def run_benchmark_sample(
    *,
    backend: str,
    workload_id: str,
    project_fingerprint: str,
    environment_fingerprint: str,
    benchmark_revision: str,
    stage_runner: Callable[[str], BenchmarkStageResult],
    warm: bool,
    billable_api: bool,
) -> BackendPerformanceSample:
    if workload_id not in WORKLOAD_IDS:
        raise CloudBenchmarkError("workload_id is invalid")
    results: list[BenchmarkStageResult] = []
    failure_fingerprint = ""
    for expected in BENCHMARK_STAGE_ORDER:
        try:
            result = stage_runner(expected)
        except Exception as exc:  # noqa: BLE001 - benchmark failures are normalized evidence
            failure_fingerprint = f"{expected}:{type(exc).__name__}"
            break
        if not isinstance(result, BenchmarkStageResult) or result.name != expected:
            raise CloudBenchmarkError("benchmark stage order mismatch")
        if not math.isfinite(result.duration_ms) or result.duration_ms < 0 or result.byte_count < 0:
            raise CloudBenchmarkError("benchmark stage result is invalid")
        results.append(result)
    durations = {result.name: float(result.duration_ms) for result in results}
    total = sum(durations.values())
    input_bytes = next((result.byte_count for result in results if result.name == "package"), 0)
    output_bytes = next((result.byte_count for result in results if result.name == "result"), 0)
    return BackendPerformanceSample(
        backend=backend,
        workload_class=route_workload_for_benchmark(workload_id),
        project_fingerprint=project_fingerprint,
        environment_fingerprint=environment_fingerprint,
        benchmark_revision=benchmark_revision,
        total_ms=total,
        stage_ms=durations.get("stage", 0.0) + durations.get("prepare", 0.0),
        return_ms=durations.get("return", 0.0) + durations.get("verify", 0.0),
        input_bytes=input_bytes,
        output_bytes=output_bytes,
        success=not failure_fingerprint,
        failure_fingerprint=failure_fingerprint,
        warm=bool(warm),
        billable_api=bool(billable_api),
    )


__all__ = [
    "BENCHMARK_STAGE_ORDER",
    "BenchmarkStageResult",
    "CloudBenchmarkError",
    "MAX_ASSISTANT_ANALYSIS_BYTES",
    "WORKLOAD_IDS",
    "route_workload_for_benchmark",
    "run_assistant_analysis_diagnostic",
    "run_assistant_analysis_kernel",
    "run_parallel_assistant_analysis_diagnostic",
    "run_benchmark_sample",
    "run_raw_runtime_diagnostic",
]
