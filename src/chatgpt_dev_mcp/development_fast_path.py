"""Composite local development steps without expanding execution authority."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .performance_metrics import CacheOutcome, PerformanceMetrics


@dataclass(frozen=True)
class ReusableSessionEvidence:
    session_id: str
    owner_id: str
    task_id: str
    source_revision: str
    status: str
    stale: bool
    worktree_available: bool
    dirty: bool = False


def can_reuse_session(
    evidence: ReusableSessionEvidence,
    *,
    owner_id: str,
    task_id: str,
    source_revision: str,
) -> bool:
    """Return whether an existing session matches the safe-local resume boundary."""

    return (
        isinstance(evidence, ReusableSessionEvidence)
        and evidence.owner_id == owner_id
        and evidence.task_id == task_id
        and evidence.source_revision == source_revision
        and evidence.status == "active"
        and not evidence.stale
        and evidence.worktree_available
    )


@dataclass(frozen=True)
class DevelopmentStepRequest:
    task_id: str
    query: str
    changed_paths: tuple[str, ...] = ()
    verify: bool = True
    audit: bool = True
    session_reused: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id:
            raise ValueError("task_id is required")
        if not isinstance(self.query, str):
            raise ValueError("query must be a string")
        if not isinstance(self.changed_paths, tuple) or any(
            not isinstance(path, str) or not path for path in self.changed_paths
        ):
            raise ValueError("changed_paths must be a tuple of non-empty strings")
        if not isinstance(self.verify, bool) or not isinstance(self.audit, bool) or not isinstance(self.session_reused, bool):
            raise ValueError("step flags must be boolean")


@dataclass(frozen=True)
class DevelopmentStepResult:
    status: object
    context: object
    mutation: object | None
    diff: object
    verification: object | None
    audit: object | None
    metrics: dict[str, object]


class LocalDevelopmentFastPath:
    """Run authorized local primitives in one fail-stop orchestration call."""

    def __init__(
        self,
        *,
        metrics: PerformanceMetrics | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._metrics = metrics or PerformanceMetrics()
        self._clock = clock

    def _stage(
        self,
        name: str,
        operation: Callable[[], object],
        *,
        reused: bool = False,
    ) -> object:
        started = float(self._clock())
        try:
            return operation()
        finally:
            elapsed_ms = max(0.0, (float(self._clock()) - started) * 1000.0)
            self._metrics.record(name, elapsed_ms, reused=reused)

    @staticmethod
    def _cache_outcome(result: object) -> CacheOutcome:
        if not isinstance(result, Mapping):
            return CacheOutcome.NONE
        status = result.get("cache_status")
        if status == CacheOutcome.HIT.value:
            return CacheOutcome.HIT
        if status == CacheOutcome.MISS.value:
            return CacheOutcome.MISS
        return CacheOutcome.NONE

    def _verification_stage(self, operation: Callable[[], object]) -> object:
        started = float(self._clock())
        try:
            result = operation()
        except Exception:
            elapsed_ms = max(0.0, (float(self._clock()) - started) * 1000.0)
            self._metrics.record("verify", elapsed_ms)
            raise
        elapsed_ms = max(0.0, (float(self._clock()) - started) * 1000.0)
        self._metrics.record("verify", elapsed_ms, cache=self._cache_outcome(result))
        return result

    def run(
        self,
        request: DevelopmentStepRequest,
        *,
        status_reader: Callable[[], object],
        context_builder: Callable[[], object],
        diff_reader: Callable[[], object],
        authorized_mutation: Callable[[], object] | None = None,
        verification_runner: Callable[[], object] | None = None,
        security_auditor: Callable[[], object] | None = None,
    ) -> DevelopmentStepResult:
        if not isinstance(request, DevelopmentStepRequest):
            raise TypeError("request must be DevelopmentStepRequest")
        for name, operation in (
            ("status_reader", status_reader),
            ("context_builder", context_builder),
            ("diff_reader", diff_reader),
        ):
            if not callable(operation):
                raise TypeError(f"{name} must be callable")

        status = self._stage("status", status_reader, reused=request.session_reused)
        context = self._stage("context", context_builder)
        mutation = None
        if authorized_mutation is not None:
            if not callable(authorized_mutation):
                raise TypeError("authorized_mutation must be callable")
            mutation = self._stage("mutation", authorized_mutation)
        diff = self._stage("diff", diff_reader)

        verification = None
        if request.verify and request.changed_paths:
            if not callable(verification_runner):
                raise ValueError("verification_runner is required when verification is requested")
            verification = self._verification_stage(verification_runner)

        audit = None
        if request.audit:
            if not callable(security_auditor):
                raise ValueError("security_auditor is required when audit is requested")
            audit = self._stage("audit", security_auditor)

        return DevelopmentStepResult(
            status=status,
            context=context,
            mutation=mutation,
            diff=diff,
            verification=verification,
            audit=audit,
            metrics=self._metrics.snapshot(),
        )


__all__ = [
    "DevelopmentStepRequest",
    "DevelopmentStepResult",
    "LocalDevelopmentFastPath",
    "ReusableSessionEvidence",
    "can_reuse_session",
]
