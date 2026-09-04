"""Bounded performance samples and routing profiles for managed cloud execution."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass


LOCAL_BACKEND = "local_native"
MANAGED_BACKEND = "chatgpt_managed_cloud"
CHATGPT_BUILTIN_BACKEND = "chatgpt_builtin"
_CHATGPT_BACKENDS = {MANAGED_BACKEND, CHATGPT_BUILTIN_BACKEND}


class CloudPerformanceError(ValueError):
    pass


@dataclass(frozen=True)
class BackendPerformanceSample:
    backend: str
    workload_class: str
    project_fingerprint: str
    environment_fingerprint: str
    benchmark_revision: str
    total_ms: float
    stage_ms: float
    return_ms: float
    input_bytes: int
    output_bytes: int
    success: bool
    failure_fingerprint: str
    warm: bool
    billable_api: bool


@dataclass(frozen=True)
class ManagedCloudSelectionPolicy:
    min_success_samples: int = 5
    min_p50_improvement: float = 0.15
    max_p95_regression: float = 0.10
    max_failure_rate_regression: float = 0.05
    profile_ttl_seconds: float = 24 * 60 * 60


@dataclass(frozen=True)
class CloudPerformanceProfile:
    profile_id: str
    workload_class: str
    project_fingerprint: str
    local_environment_fingerprint: str
    cloud_environment_fingerprint: str
    benchmark_revision: str
    local_success_samples: int
    cloud_success_samples: int
    local_p50_ms: float
    local_p95_ms: float
    cloud_p50_ms: float
    cloud_p95_ms: float
    cloud_stage_p50_ms: float
    cloud_return_p50_ms: float
    local_failure_rate: float
    cloud_failure_rate: float
    speed_ratio_p50: float
    observed_at: float
    expires_at: float
    billable_api: bool
    sufficient: bool
    managed_cloud_wins: bool


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return math.inf
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return float(ordered[index])


def _validate_sample(sample: BackendPerformanceSample) -> None:
    if sample.backend not in {LOCAL_BACKEND, *_CHATGPT_BACKENDS}:
        raise CloudPerformanceError("backend is invalid")
    for value in (sample.total_ms, sample.stage_ms, sample.return_ms):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
            raise CloudPerformanceError("latency sample is invalid")
    if sample.input_bytes < 0 or sample.output_bytes < 0:
        raise CloudPerformanceError("byte count is invalid")
    if sample.backend in _CHATGPT_BACKENDS and sample.billable_api:
        raise CloudPerformanceError("ChatGPT built-in samples cannot consume billable API")


def derive_performance_profile(
    samples: tuple[BackendPerformanceSample, ...],
    *,
    policy: ManagedCloudSelectionPolicy,
    observed_at: float | None = None,
) -> CloudPerformanceProfile:
    if not samples:
        raise CloudPerformanceError("samples are required")
    for sample in samples:
        _validate_sample(sample)
    first = samples[0]
    for sample in samples:
        if (
            sample.workload_class != first.workload_class
            or sample.project_fingerprint != first.project_fingerprint
            or sample.benchmark_revision != first.benchmark_revision
            or sample.warm != first.warm
        ):
            raise CloudPerformanceError("samples are not comparable")
    local = [sample for sample in samples if sample.backend == LOCAL_BACKEND]
    cloud = [sample for sample in samples if sample.backend in _CHATGPT_BACKENDS]
    if not local or not cloud:
        raise CloudPerformanceError("both local and managed-cloud samples are required")
    local_envs = {sample.environment_fingerprint for sample in local}
    cloud_envs = {sample.environment_fingerprint for sample in cloud}
    if len(local_envs) != 1 or len(cloud_envs) != 1:
        raise CloudPerformanceError("environment fingerprint changed within sample set")
    local_ok = [sample for sample in local if sample.success]
    cloud_ok = [sample for sample in cloud if sample.success]
    local_p50 = _percentile([sample.total_ms for sample in local_ok], 0.50)
    local_p95 = _percentile([sample.total_ms for sample in local_ok], 0.95)
    cloud_p50 = _percentile([sample.total_ms for sample in cloud_ok], 0.50)
    cloud_p95 = _percentile([sample.total_ms for sample in cloud_ok], 0.95)
    local_failure = 1.0 - (len(local_ok) / len(local))
    cloud_failure = 1.0 - (len(cloud_ok) / len(cloud))
    sufficient = len(local_ok) >= policy.min_success_samples and len(cloud_ok) >= policy.min_success_samples
    p50_pass = sufficient and cloud_p50 <= local_p50 * (1.0 - policy.min_p50_improvement)
    p95_pass = sufficient and cloud_p95 <= local_p95 * (1.0 + policy.max_p95_regression)
    failure_pass = cloud_failure <= local_failure + policy.max_failure_rate_regression
    wins = bool(sufficient and p50_pass and p95_pass and failure_pass)
    now = time.time() if observed_at is None else float(observed_at)
    identity = f"{first.workload_class}|{first.project_fingerprint}|{next(iter(local_envs))}|{next(iter(cloud_envs))}|{first.benchmark_revision}|{first.warm}"
    import hashlib

    profile_id = f"profile:{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
    return CloudPerformanceProfile(
        profile_id=profile_id,
        workload_class=first.workload_class,
        project_fingerprint=first.project_fingerprint,
        local_environment_fingerprint=next(iter(local_envs)),
        cloud_environment_fingerprint=next(iter(cloud_envs)),
        benchmark_revision=first.benchmark_revision,
        local_success_samples=len(local_ok),
        cloud_success_samples=len(cloud_ok),
        local_p50_ms=local_p50,
        local_p95_ms=local_p95,
        cloud_p50_ms=cloud_p50,
        cloud_p95_ms=cloud_p95,
        cloud_stage_p50_ms=_percentile([sample.stage_ms for sample in cloud_ok], 0.50),
        cloud_return_p50_ms=_percentile([sample.return_ms for sample in cloud_ok], 0.50),
        local_failure_rate=local_failure,
        cloud_failure_rate=cloud_failure,
        speed_ratio_p50=(local_p50 / cloud_p50) if cloud_p50 not in {0.0, math.inf} else math.inf,
        observed_at=now,
        expires_at=now + policy.profile_ttl_seconds,
        billable_api=False,
        sufficient=sufficient,
        managed_cloud_wins=wins,
    )


__all__ = [
    "BackendPerformanceSample",
    "CHATGPT_BUILTIN_BACKEND",
    "CloudPerformanceError",
    "CloudPerformanceProfile",
    "ManagedCloudSelectionPolicy",
    "derive_performance_profile",
]
