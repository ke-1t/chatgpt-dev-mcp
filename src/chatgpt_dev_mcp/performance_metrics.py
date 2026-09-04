"""Bounded in-memory performance evidence for development execution."""

from __future__ import annotations

import math
import re
import threading
from collections import deque
from enum import Enum


_STAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_FAILURE_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")


class CacheOutcome(str, Enum):
    NONE = "none"
    HIT = "hit"
    MISS = "miss"


class PerformanceMetrics:
    """Aggregate bounded timing/caching data without retaining raw payloads."""

    def __init__(self, *, max_stages: int = 64, max_samples_per_stage: int = 256) -> None:
        if isinstance(max_stages, bool) or not isinstance(max_stages, int) or not 1 <= max_stages <= 256:
            raise ValueError("max_stages is outside bounds")
        if (
            isinstance(max_samples_per_stage, bool)
            or not isinstance(max_samples_per_stage, int)
            or not 1 <= max_samples_per_stage <= 4096
        ):
            raise ValueError("max_samples_per_stage is outside bounds")
        self._max_stages = max_stages
        self._max_samples_per_stage = max_samples_per_stage
        self._stages: dict[str, dict[str, object]] = {}
        self._samples: dict[str, deque[float]] = {}
        self._record_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._reuse_count = 0
        self._lock = threading.RLock()

    @staticmethod
    def _stage(value: str) -> str:
        if not isinstance(value, str) or not _STAGE_RE.fullmatch(value):
            raise ValueError("stage is invalid")
        return value

    @staticmethod
    def _duration(value: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("elapsed_ms must be numeric")
        parsed = float(value)
        if not math.isfinite(parsed) or parsed < 0:
            raise ValueError("elapsed_ms must be finite and non-negative")
        return parsed

    def record(
        self,
        stage: str,
        elapsed_ms: float,
        *,
        cache: CacheOutcome = CacheOutcome.NONE,
        reused: bool = False,
        success: bool = True,
        neutral: bool = False,
        failure_fingerprint: str = "",
        output_bytes: int = 0,
    ) -> None:
        parsed_stage = self._stage(stage)
        parsed_elapsed = self._duration(elapsed_ms)
        if not isinstance(cache, CacheOutcome):
            raise ValueError("cache must be a CacheOutcome")
        if not isinstance(reused, bool):
            raise ValueError("reused must be boolean")
        if not isinstance(success, bool):
            raise ValueError("success must be boolean")
        if not isinstance(neutral, bool):
            raise ValueError("neutral must be boolean")
        if neutral and not success:
            raise ValueError("neutral samples cannot be failures")
        if not isinstance(failure_fingerprint, str) or len(failure_fingerprint) > 160 or "\x00" in failure_fingerprint:
            raise ValueError("failure_fingerprint is invalid")
        if failure_fingerprint and not _FAILURE_FINGERPRINT_RE.fullmatch(failure_fingerprint):
            raise ValueError("failure_fingerprint is invalid")
        if success and failure_fingerprint:
            raise ValueError("successful samples cannot include failure_fingerprint")
        if isinstance(output_bytes, bool) or not isinstance(output_bytes, int) or not 0 <= output_bytes <= 1_073_741_824:
            raise ValueError("output_bytes is outside bounds")

        with self._lock:
            current = self._stages.get(parsed_stage)
            if current is None:
                if len(self._stages) >= self._max_stages:
                    raise ValueError("stage capacity exceeded")
                current = {
                    "count": 0,
                    "total_ms": 0.0,
                    "max_ms": 0.0,
                    "cache_hits": 0,
                    "cache_misses": 0,
                    "neutral_count": 0,
                    "failure_count": 0,
                    "failure_fingerprints": {},
                    "total_output_bytes": 0,
                    "max_output_bytes": 0,
                }
                self._stages[parsed_stage] = current
                self._samples[parsed_stage] = deque(maxlen=self._max_samples_per_stage)

            current["count"] = int(current["count"]) + 1
            current["total_ms"] = float(current["total_ms"]) + parsed_elapsed
            current["max_ms"] = max(float(current["max_ms"]), parsed_elapsed)
            current["total_output_bytes"] = int(current["total_output_bytes"]) + output_bytes
            current["max_output_bytes"] = max(int(current["max_output_bytes"]), output_bytes)
            self._samples[parsed_stage].append(parsed_elapsed)
            self._record_count += 1
            if cache is CacheOutcome.HIT:
                self._cache_hits += 1
                current["cache_hits"] = int(current["cache_hits"]) + 1
            elif cache is CacheOutcome.MISS:
                self._cache_misses += 1
                current["cache_misses"] = int(current["cache_misses"]) + 1
            if reused:
                self._reuse_count += 1
            if neutral:
                current["neutral_count"] = int(current["neutral_count"]) + 1
            elif not success:
                current["failure_count"] = int(current["failure_count"]) + 1
                fingerprint = failure_fingerprint or "failure"
                fingerprints = current["failure_fingerprints"]
                if not isinstance(fingerprints, dict):
                    raise RuntimeError("performance fingerprint state is invalid")
                fingerprints[fingerprint] = int(fingerprints.get(fingerprint, 0)) + 1

    @staticmethod
    def _median(samples: list[float]) -> float:
        midpoint = len(samples) // 2
        if len(samples) % 2:
            return samples[midpoint]
        return (samples[midpoint - 1] + samples[midpoint]) / 2.0

    @staticmethod
    def _p95(samples: list[float]) -> float:
        index = max(0, min(len(samples) - 1, math.ceil(len(samples) * 0.95) - 1))
        return samples[index]

    @staticmethod
    def _copy_stage(values: dict[str, object]) -> dict[str, object]:
        copied = dict(values)
        fingerprints = copied.get("failure_fingerprints")
        copied["failure_fingerprints"] = dict(fingerprints) if isinstance(fingerprints, dict) else {}
        return copied

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "record_count": self._record_count,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "reuse_count": self._reuse_count,
                "max_stages": self._max_stages,
                "max_samples_per_stage": self._max_samples_per_stage,
                "stages": {name: self._copy_stage(values) for name, values in self._stages.items()},
            }

    def summary(self, *, limit: int = 20) -> dict[str, object]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("summary limit is outside bounds")
        with self._lock:
            stages: dict[str, dict[str, object]] = {}
            for name in sorted(self._stages):
                values = self._stages[name]
                samples = sorted(self._samples[name])
                count = int(values["count"])
                neutral_count = int(values.get("neutral_count", 0))
                completed_count = max(0, count - neutral_count)
                hits = int(values["cache_hits"])
                misses = int(values["cache_misses"])
                cache_total = hits + misses
                stages[name] = {
                    **self._copy_stage(values),
                    "sample_count": len(samples),
                    "completed_count": completed_count,
                    "p50_ms": self._median(samples),
                    "p95_ms": self._p95(samples),
                    "average_ms": (float(values["total_ms"]) / count) if count else 0.0,
                    "failure_rate": (int(values["failure_count"]) / completed_count) if completed_count else 0.0,
                    "cache_hit_ratio": (hits / cache_total) if cache_total else None,
                    "average_output_bytes": (int(values["total_output_bytes"]) / count) if count else 0.0,
                }
            slow = sorted(
                stages,
                key=lambda name: (float(stages[name]["p95_ms"]), float(stages[name]["max_ms"]), name),
                reverse=True,
            )[:limit]
            return {
                "record_count": self._record_count,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "reuse_count": self._reuse_count,
                "stages": stages,
                "slow_operations": slow,
            }


__all__ = ["CacheOutcome", "PerformanceMetrics"]
