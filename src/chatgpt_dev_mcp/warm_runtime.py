"""Disposable bounded warm runtime cache for acceleration services."""

from __future__ import annotations

import math
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

_KIND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")


class WarmRuntimeError(ValueError):
    pass


@dataclass
class _WarmEntry:
    kind: str
    identity: str
    value: object
    paths: tuple[str, ...]
    created_at: float
    last_used_at: float


def _identity(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 512:
        raise WarmRuntimeError("identity is invalid")
    return value


def _paths(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > 128:
        raise WarmRuntimeError("paths are invalid")
    parsed: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 512 or value.startswith(("/", "~")) or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/")):
            raise WarmRuntimeError("path is invalid")
        parsed.append(value)
    if len(parsed) != len(set(parsed)):
        raise WarmRuntimeError("paths must be unique")
    return tuple(sorted(parsed))


def _path_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


class WarmRuntimeManager:
    def __init__(self, *, max_entries: int = 16, ttl_seconds: float = 300.0, clock: Callable[[], float] | None = None) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= 256:
            raise WarmRuntimeError("max_entries is outside bounds")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(float(ttl_seconds)) or not 0.1 <= float(ttl_seconds) <= 24 * 60 * 60:
            raise WarmRuntimeError("ttl_seconds is outside bounds")
        if clock is not None and not callable(clock):
            raise WarmRuntimeError("clock is invalid")
        self._max_entries = max_entries
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock or time.monotonic
        self._entries: OrderedDict[tuple[str, str], _WarmEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = self._misses = self._evictions = self._close_errors = 0

    @staticmethod
    def _kind(value: str) -> str:
        if not isinstance(value, str) or not _KIND_RE.fullmatch(value):
            raise WarmRuntimeError("kind is invalid")
        return value

    def _close_entry(self, entry: _WarmEntry) -> int:
        close = getattr(entry.value, "close", None)
        if not callable(close):
            return 0
        try:
            close()
        except Exception:
            self._close_errors += 1
            return 1
        return 0

    def _prune_expired(self, now: float) -> int:
        expired = [key for key, entry in self._entries.items() if now - entry.last_used_at >= self._ttl_seconds]
        for key in expired:
            self._close_entry(self._entries.pop(key))
            self._evictions += 1
        return len(expired)

    def get_or_create(self, kind: str, identity: str, factory: Callable[[], object], *, paths: tuple[str, ...] = ()) -> object:
        parsed_kind, parsed_identity, parsed_paths = self._kind(kind), _identity(identity), _paths(paths)
        if not callable(factory):
            raise WarmRuntimeError("factory is invalid")
        key = (parsed_kind, parsed_identity)
        with self._lock:
            now = float(self._clock())
            if not math.isfinite(now):
                raise WarmRuntimeError("clock returned invalid time")
            self._prune_expired(now)
            existing = self._entries.get(key)
            if existing is not None:
                existing.last_used_at = now
                if parsed_paths:
                    existing.paths = tuple(sorted(set((*existing.paths, *parsed_paths))))
                self._entries.move_to_end(key)
                self._hits += 1
                return existing.value
            self._misses += 1
            value = factory()
            self._entries[key] = _WarmEntry(parsed_kind, parsed_identity, value, parsed_paths, now, now)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                _old_key, old_entry = self._entries.popitem(last=False)
                self._close_entry(old_entry)
                self._evictions += 1
            return value

    def invalidate(self, *, identity: str | None = None, path: str | None = None) -> int:
        if identity is None and path is None:
            raise WarmRuntimeError("identity or path is required")
        parsed_identity = _identity(identity) if identity is not None else None
        parsed_path = _paths((path,))[0] if path is not None else None
        with self._lock:
            keys = [key for key, entry in self._entries.items() if (parsed_identity is not None and entry.identity == parsed_identity) or (parsed_path is not None and any(_path_overlap(parsed_path, item) for item in entry.paths))]
            for key in keys:
                self._close_entry(self._entries.pop(key))
            return len(keys)

    def close_all(self) -> dict[str, int]:
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
            errors_before = self._close_errors
            for entry in entries:
                self._close_entry(entry)
            return {"closed": len(entries), "close_errors": self._close_errors - errors_before}

    def status(self) -> dict[str, object]:
        with self._lock:
            self._prune_expired(float(self._clock()))
            return {"entry_count": len(self._entries), "max_entries": self._max_entries, "ttl_seconds": self._ttl_seconds, "hits": self._hits, "misses": self._misses, "evictions": self._evictions, "close_errors": self._close_errors, "external_execution": False}


__all__ = ["WarmRuntimeError", "WarmRuntimeManager"]
