"""Pure bounded state machine for autonomous local development loops."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, replace
from typing import Literal

LoopPhase = Literal["IMPLEMENT", "FAST_VERIFY", "REMEDIATE", "QA", "REVIEW", "FULL_VERIFY", "READY", "BLOCKED", "FAILED"]
TERMINAL_PHASES = frozenset({"READY", "BLOCKED", "FAILED"})


@dataclass(frozen=True)
class LoopBudgets:
    max_iterations: int = 32
    max_wall_seconds: int = 3600
    max_changed_files: int = 64
    max_diff_bytes: int = 2 * 1024 * 1024
    max_repeated_failure: int = 3
    max_no_progress: int = 3

    def __post_init__(self) -> None:
        for name, value, maximum in (("max_iterations", self.max_iterations, 1000), ("max_wall_seconds", self.max_wall_seconds, 24 * 60 * 60), ("max_changed_files", self.max_changed_files, 10000), ("max_diff_bytes", self.max_diff_bytes, 64 * 1024 * 1024), ("max_repeated_failure", self.max_repeated_failure, 100), ("max_no_progress", self.max_no_progress, 100)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} is outside bounds")


@dataclass(frozen=True)
class LoopEvent:
    event_id: str
    kind: str
    at: float
    failure_fingerprint: str = ""
    progress_token: str = ""
    changed_files: int = 0
    diff_bytes: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id or len(self.event_id) > 128:
            raise ValueError("event_id is invalid")
        if not isinstance(self.kind, str) or not self.kind or len(self.kind) > 80:
            raise ValueError("event kind is invalid")
        if not isinstance(self.at, (int, float)) or isinstance(self.at, bool) or not math.isfinite(float(self.at)):
            raise ValueError("event time is invalid")
        if not isinstance(self.failure_fingerprint, str) or len(self.failure_fingerprint) > 256:
            raise ValueError("failure_fingerprint is invalid")
        if not isinstance(self.progress_token, str) or len(self.progress_token) > 256:
            raise ValueError("progress_token is invalid")
        for name, value, maximum in (("changed_files", self.changed_files, 100000), ("diff_bytes", self.diff_bytes, 256 * 1024 * 1024)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"{name} is invalid")

    @property
    def fingerprint(self) -> str:
        payload = json.dumps({"event_id": self.event_id, "kind": self.kind, "at": float(self.at), "failure_fingerprint": self.failure_fingerprint, "progress_token": self.progress_token, "changed_files": self.changed_files, "diff_bytes": self.diff_bytes}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LoopHistoryEntry:
    event_id: str
    event_fingerprint: str
    from_phase: LoopPhase
    to_phase: LoopPhase
    reason: str
    at: float


@dataclass(frozen=True)
class DevelopmentLoopState:
    loop_id: str
    owner_id: str
    task_id: str
    session_id: str
    worktree_id: str
    budgets: LoopBudgets
    started_at: float
    phase: LoopPhase = "IMPLEMENT"
    history: tuple[LoopHistoryEntry, ...] = ()
    repeated_failure_count: int = 0
    last_failure_fingerprint: str = ""
    no_progress_count: int = 0
    last_progress_token: str = ""
    stop_reason: str = ""

    @classmethod
    def create(cls, *, loop_id: str, owner_id: str, task_id: str, session_id: str, worktree_id: str, budgets: LoopBudgets | None = None, started_at: float) -> "DevelopmentLoopState":
        for name, value in (("loop_id", loop_id), ("owner_id", owner_id), ("task_id", task_id), ("session_id", session_id), ("worktree_id", worktree_id)):
            if not isinstance(value, str) or not value or len(value) > 160:
                raise ValueError(f"{name} is invalid")
        if not isinstance(started_at, (int, float)) or isinstance(started_at, bool) or not math.isfinite(float(started_at)):
            raise ValueError("started_at is invalid")
        return cls(loop_id=loop_id, owner_id=owner_id, task_id=task_id, session_id=session_id, worktree_id=worktree_id, budgets=budgets or LoopBudgets(), started_at=float(started_at))


_TRANSITIONS: dict[tuple[LoopPhase, str], LoopPhase] = {
    ("IMPLEMENT", "implementation_complete"): "FAST_VERIFY", ("IMPLEMENT", "implementation_failed"): "REMEDIATE",
    ("FAST_VERIFY", "verification_passed"): "QA", ("FAST_VERIFY", "verification_failed"): "REMEDIATE",
    ("REMEDIATE", "remediation_complete"): "FAST_VERIFY", ("REMEDIATE", "remediation_failed"): "FAILED",
    ("QA", "qa_passed"): "REVIEW", ("QA", "qa_failed"): "REMEDIATE",
    ("REVIEW", "review_passed"): "FULL_VERIFY", ("REVIEW", "review_blocking"): "REMEDIATE", ("REVIEW", "review_failed"): "REMEDIATE",
    ("FULL_VERIFY", "verification_passed"): "READY", ("FULL_VERIFY", "verification_failed"): "REMEDIATE",
    ("READY", "delivery_failed"): "REMEDIATE",
}


def _append(state: DevelopmentLoopState, event: LoopEvent, *, to_phase: LoopPhase, reason: str, repeated_failure_count: int, last_failure_fingerprint: str, no_progress_count: int, last_progress_token: str, stop_reason: str = "") -> DevelopmentLoopState:
    entry = LoopHistoryEntry(event.event_id, event.fingerprint, state.phase, to_phase, reason, float(event.at))
    return replace(state, phase=to_phase, history=(*state.history, entry), repeated_failure_count=repeated_failure_count, last_failure_fingerprint=last_failure_fingerprint, no_progress_count=no_progress_count, last_progress_token=last_progress_token, stop_reason=stop_reason)


def advance(state: DevelopmentLoopState, event: LoopEvent) -> DevelopmentLoopState:
    if not isinstance(state, DevelopmentLoopState) or not isinstance(event, LoopEvent):
        raise TypeError("state/event type is invalid")
    for entry in state.history:
        if entry.event_id == event.event_id:
            if entry.event_fingerprint == event.fingerprint:
                return state
            raise ValueError("event_id is already bound to different content")
    if state.phase in TERMINAL_PHASES and not (state.phase == "READY" and event.kind == "delivery_failed"):
        raise ValueError("loop is already terminal")
    if float(event.at) < state.started_at:
        raise ValueError("event predates loop start")
    base = dict(repeated_failure_count=state.repeated_failure_count, last_failure_fingerprint=state.last_failure_fingerprint, no_progress_count=state.no_progress_count, last_progress_token=state.last_progress_token)
    if len(state.history) + 1 > state.budgets.max_iterations:
        return _append(state, event, to_phase="FAILED", reason="ITERATION_BUDGET", stop_reason="ITERATION_BUDGET", **base)
    if float(event.at) - state.started_at > state.budgets.max_wall_seconds:
        return _append(state, event, to_phase="BLOCKED", reason="WALL_TIME_BUDGET", stop_reason="WALL_TIME_BUDGET", **base)
    if event.changed_files > state.budgets.max_changed_files:
        return _append(state, event, to_phase="BLOCKED", reason="CHANGED_FILE_BUDGET", stop_reason="CHANGED_FILE_BUDGET", **base)
    if event.diff_bytes > state.budgets.max_diff_bytes:
        return _append(state, event, to_phase="BLOCKED", reason="DIFF_BYTE_BUDGET", stop_reason="DIFF_BYTE_BUDGET", **base)
    last_progress, no_progress = state.last_progress_token, state.no_progress_count
    if event.progress_token:
        if event.progress_token == last_progress:
            no_progress += 1
        else:
            no_progress, last_progress = 0, event.progress_token
    repeated_failure, last_failure = state.repeated_failure_count, state.last_failure_fingerprint
    if event.failure_fingerprint:
        if event.failure_fingerprint == last_failure:
            repeated_failure += 1
        else:
            repeated_failure, last_failure = 1, event.failure_fingerprint
    values = dict(repeated_failure_count=repeated_failure, last_failure_fingerprint=last_failure, no_progress_count=no_progress, last_progress_token=last_progress)
    if repeated_failure >= state.budgets.max_repeated_failure:
        return _append(state, event, to_phase="FAILED", reason="REPEATED_FAILURE_LIMIT", stop_reason="REPEATED_FAILURE_LIMIT", **values)
    if no_progress >= state.budgets.max_no_progress:
        return _append(state, event, to_phase="FAILED", reason="NO_PROGRESS_LIMIT", stop_reason="NO_PROGRESS_LIMIT", **values)
    if event.kind == "blocked":
        next_phase, stop_reason = "BLOCKED", "EXPLICIT_BLOCK"
    elif event.kind == "fatal":
        next_phase, stop_reason = "FAILED", "FATAL_EVENT"
    else:
        try:
            next_phase = _TRANSITIONS[(state.phase, event.kind)]
        except KeyError as exc:
            raise ValueError(f"event {event.kind!r} is invalid for phase {state.phase}") from exc
        stop_reason = "" if next_phase not in {"BLOCKED", "FAILED"} else event.kind.upper()
    return _append(state, event, to_phase=next_phase, reason=event.kind, stop_reason=stop_reason, **values)


def apply_delivery_failure(state: DevelopmentLoopState, evidence_ref: str, *, at: float) -> DevelopmentLoopState:
    if not isinstance(state, DevelopmentLoopState) or state.phase not in {"READY", "REMEDIATE"}:
        raise ValueError("delivery failure can only reopen READY work")
    if not isinstance(evidence_ref, str) or not evidence_ref or len(evidence_ref) > 256 or "\x00" in evidence_ref:
        raise ValueError("delivery evidence reference is invalid")
    digest = hashlib.sha256(evidence_ref.encode("utf-8")).hexdigest()
    event = LoopEvent(event_id=f"delivery:{digest[:32]}", kind="delivery_failed", at=at, failure_fingerprint=digest, progress_token=evidence_ref)
    if state.phase == "REMEDIATE":
        for entry in state.history:
            if entry.event_id == event.event_id and entry.event_fingerprint == event.fingerprint:
                return state
        raise ValueError("delivery failure cannot replace existing remediation evidence")
    return advance(state, event)


__all__ = ["DevelopmentLoopState", "LoopBudgets", "LoopEvent", "LoopHistoryEntry", "LoopPhase", "apply_delivery_failure", "advance"]
