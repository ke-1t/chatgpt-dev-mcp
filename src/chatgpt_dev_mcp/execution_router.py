"""Pure backend selection for local and ChatGPT built-in execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionMode(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"
    AUTO = "auto"


class ExecutionBackend(str, Enum):
    LOCAL_NATIVE = "local_native"
    CHATGPT_BUILTIN = "chatgpt_builtin"
    # Compatibility aliases for callers that still import the previous names.
    CHATGPT_MANAGED_CLOUD = "chatgpt_builtin"


class WorkloadKind(str, Enum):
    GENERIC = "generic"
    LATENCY_SENSITIVE = "latency_sensitive"
    COMPUTE_HEAVY = "compute_heavy"
    BULK_ANALYSIS = "bulk_analysis"
    PRIVILEGED_LOCAL = "privileged_local"


@dataclass(frozen=True)
class BackendAvailability:
    local: bool = True
    managed_cloud: bool = False
    local_reason: str = ""
    managed_cloud_reason: str = ""

    @property
    def chatgpt_builtin(self) -> bool:
        return self.managed_cloud

    @property
    def chatgpt_builtin_reason(self) -> str:
        return self.managed_cloud_reason


@dataclass(frozen=True)
class PerformanceRouteEvidence:
    profile_id: str
    current: bool
    sufficient: bool
    managed_cloud_wins: bool
    reason: str = ""


@dataclass(frozen=True)
class RouteRequest:
    mode: ExecutionMode
    workload: WorkloadKind = WorkloadKind.GENERIC
    requires_local_secrets: bool = False
    requires_authenticated_browser: bool = False
    requires_macos: bool = False
    performance: PerformanceRouteEvidence | None = None


@dataclass(frozen=True)
class RouteDecision:
    backend: ExecutionBackend
    reason: str
    available: bool = True
    fallback: bool = False


def _local_unavailable(availability: BackendAvailability) -> RouteDecision:
    suffix = availability.local_reason or "unavailable"
    return RouteDecision(
        backend=ExecutionBackend.LOCAL_NATIVE,
        available=False,
        fallback=False,
        reason=f"local_unavailable:{suffix}",
    )


def _hard_local_requirement(request: RouteRequest) -> str | None:
    if request.requires_local_secrets:
        return "requires_local_secrets"
    if request.requires_authenticated_browser:
        return "requires_authenticated_browser"
    if request.requires_macos:
        return "requires_macos"
    if request.workload is WorkloadKind.PRIVILEGED_LOCAL:
        return "privileged_local_workload"
    return None


def choose_backend(request: RouteRequest, availability: BackendAvailability) -> RouteDecision:
    """Choose a compatible backend without probing or mutating any backend."""

    hard_local = _hard_local_requirement(request)
    if hard_local is not None:
        if not availability.local:
            return _local_unavailable(availability)
        return RouteDecision(
            backend=ExecutionBackend.LOCAL_NATIVE,
            reason=f"hard_local_requirement:{hard_local}",
            fallback=request.mode is ExecutionMode.CLOUD,
        )

    if request.mode is ExecutionMode.LOCAL:
        if not availability.local:
            return _local_unavailable(availability)
        return RouteDecision(ExecutionBackend.LOCAL_NATIVE, "explicit_local_mode")

    if request.mode is ExecutionMode.CLOUD:
        if availability.chatgpt_builtin:
            return RouteDecision(ExecutionBackend.CHATGPT_BUILTIN, "explicit_chatgpt_builtin_mode")
        if availability.local:
            reason = availability.chatgpt_builtin_reason or "unavailable"
            return RouteDecision(
                ExecutionBackend.LOCAL_NATIVE,
                f"chatgpt_builtin_unavailable:{reason}",
                fallback=True,
            )
        return _local_unavailable(availability)

    if request.workload in {WorkloadKind.COMPUTE_HEAVY, WorkloadKind.BULK_ANALYSIS}:
        evidence = request.performance
        if evidence is None:
            auto_reason = "auto_performance_profile_missing"
        elif not evidence.current:
            auto_reason = "auto_performance_profile_stale"
        elif not evidence.sufficient:
            auto_reason = "auto_performance_profile_insufficient"
        elif not evidence.managed_cloud_wins:
            auto_reason = "auto_chatgpt_builtin_threshold_not_met"
        elif availability.chatgpt_builtin:
            return RouteDecision(
                ExecutionBackend.CHATGPT_BUILTIN,
                "auto_chatgpt_builtin_measured_win",
            )
        else:
            auto_reason = f"auto_chatgpt_builtin_unavailable:{availability.chatgpt_builtin_reason or 'unavailable'}"
    else:
        auto_reason = "auto_workload_not_offload_candidate"

    if availability.local:
        return RouteDecision(ExecutionBackend.LOCAL_NATIVE, auto_reason)

    return _local_unavailable(availability)


__all__ = [
    "BackendAvailability",
    "ExecutionBackend",
    "ExecutionMode",
    "PerformanceRouteEvidence",
    "RouteDecision",
    "RouteRequest",
    "WorkloadKind",
    "choose_backend",
]
