"""Content-addressed verification cache with fail-closed identity matching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .director import redact_secrets

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")


def _safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise ValueError("verification cache path is invalid")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("verification cache path is invalid")
    return path.as_posix()


def _overlap(left: str, right: str) -> bool:
    a, b = left.rstrip("/"), right.rstrip("/")
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def verification_input_fingerprint(
    root: Path,
    *,
    changed_paths: tuple[str, ...],
    diff_text: str,
    diff_known: bool,
) -> str:
    """Hash actual verification inputs, including untracked file bytes."""

    if not isinstance(root, Path):
        raise TypeError("root must be a Path")
    if not isinstance(diff_text, str) or not isinstance(diff_known, bool):
        raise TypeError("verification diff evidence is invalid")

    manifest: list[tuple[str, str, str]] = []
    for relative in sorted({_safe_path(path) for path in changed_paths}):
        candidate = root / relative
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            manifest.append((relative, "missing", ""))
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(candidate)
            manifest.append((relative, "symlink", hashlib.sha256(target.encode("utf-8")).hexdigest()))
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"verification cache path is not a regular file: {relative}")

        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest.append((relative, "file", digest.hexdigest()))

    diff_payload = diff_text if diff_known else "diff-unavailable"
    diff_digest = hashlib.sha256(diff_payload.encode("utf-8")).hexdigest()
    payload = json.dumps((manifest, diff_known, diff_digest), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationCacheKey:
    worktree_id: str
    head: str
    relevant_diff_hash: str
    command_fingerprint: str
    env_fingerprint: str
    dependency_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.worktree_id, str) or not self.worktree_id or len(self.worktree_id) > 160:
            raise ValueError("worktree_id is invalid")
        if not _HEAD_RE.fullmatch(self.head):
            raise ValueError("head is invalid")
        for value in (self.relevant_diff_hash, self.command_fingerprint, self.env_fingerprint, self.dependency_fingerprint):
            if not _HASH_RE.fullmatch(value):
                raise ValueError("cache fingerprint is invalid")

    @property
    def digest(self) -> str:
        payload = json.dumps((self.worktree_id, self.head, self.relevant_diff_hash, self.command_fingerprint, self.env_fingerprint, self.dependency_fingerprint), separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationCacheEntry:
    key: VerificationCacheKey
    relevant_paths: tuple[str, ...]
    status: str
    result_digest: str
    output_summary: str
    created_at: float
    expires_at: float

    def as_persistence_dict(self) -> dict[str, object]:
        return {"cache_key": self.key.digest, "worktree_id": self.key.worktree_id, "head_revision": self.key.head, "relevant_diff_hash": self.key.relevant_diff_hash, "command_fingerprint": self.key.command_fingerprint, "env_fingerprint": self.key.env_fingerprint, "dependency_fingerprint": self.key.dependency_fingerprint, "relevant_paths": list(self.relevant_paths), "status": self.status, "result_digest": self.result_digest, "output_summary": self.output_summary, "created_at": self.created_at, "expires_at": self.expires_at}


@dataclass(frozen=True)
class CacheLookup:
    hit: bool
    entry: VerificationCacheEntry | None
    reason: str


class VerificationCache:
    def __init__(self, *, store: object | None = None, clock: Callable[[], float] = time.time, ttl_seconds: int = 15 * 60, max_entries: int = 512) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 24 * 60 * 60:
            raise ValueError("ttl_seconds is outside bounds")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= 10000:
            raise ValueError("max_entries is outside bounds")
        self._store, self._clock, self._ttl, self._max_entries = store, clock, ttl_seconds, max_entries
        self._entries: dict[str, VerificationCacheEntry] = {}
        self._restore()

    @staticmethod
    def _from_record(record: dict[str, object]) -> VerificationCacheEntry:
        key = VerificationCacheKey(worktree_id=str(record["worktree_id"]), head=str(record["head_revision"]), relevant_diff_hash=str(record["relevant_diff_hash"]), command_fingerprint=str(record["command_fingerprint"]), env_fingerprint=str(record["env_fingerprint"]), dependency_fingerprint=str(record["dependency_fingerprint"]))
        if str(record.get("cache_key", "")) != key.digest:
            raise ValueError("persisted cache key is invalid")
        paths = tuple(_safe_path(path) for path in record.get("relevant_paths", []) if isinstance(path, str))
        status, result_digest = str(record.get("status", "")), str(record.get("result_digest", ""))
        if status not in {"passed", "failed", "timed_out"} or not _HASH_RE.fullmatch(result_digest):
            raise ValueError("persisted cache result is invalid")
        return VerificationCacheEntry(key, paths, status, result_digest, str(record.get("output_summary", "")), float(record["created_at"]), float(record["expires_at"]))

    def _restore(self) -> None:
        if self._store is None or not hasattr(self._store, "load_verification_cache_entries"):
            return
        now = float(self._clock())
        try:
            records = self._store.load_verification_cache_entries()
        except Exception:
            return
        for record in records:
            try:
                entry = self._from_record(record)
            except (KeyError, TypeError, ValueError):
                continue
            if entry.expires_at > now:
                self._entries[entry.key.digest] = entry
        self._trim(persist=False)

    def _trim(self, *, persist: bool = True) -> None:
        now = float(self._clock())
        stale = [digest for digest, entry in self._entries.items() if entry.expires_at <= now]
        for digest in stale:
            self._entries.pop(digest, None)
        overflow = max(0, len(self._entries) - self._max_entries)
        if overflow:
            oldest = sorted(self._entries.items(), key=lambda pair: (pair[1].created_at, pair[0]))[:overflow]
            stale.extend(digest for digest, _ in oldest)
            for digest, _ in oldest:
                self._entries.pop(digest, None)
        if persist and self._store is not None:
            if stale and hasattr(self._store, "delete_verification_cache_keys"):
                self._store.delete_verification_cache_keys(tuple(dict.fromkeys(stale)))
            if hasattr(self._store, "prune_verification_cache"):
                self._store.prune_verification_cache(now=now, max_entries=self._max_entries)

    def put(self, key: VerificationCacheKey, *, relevant_paths: tuple[str, ...], status: str, result_digest: str, output_summary: str = "") -> VerificationCacheEntry:
        if not isinstance(key, VerificationCacheKey):
            raise TypeError("key must be VerificationCacheKey")
        paths = tuple(_safe_path(path) for path in relevant_paths)
        if not paths or len(paths) != len(set(paths)) or len(paths) > 256:
            raise ValueError("relevant_paths are invalid")
        if status not in {"passed", "failed", "timed_out"} or not _HASH_RE.fullmatch(result_digest):
            raise ValueError("cache result is invalid")
        if not isinstance(output_summary, str) or len(output_summary.encode("utf-8")) > 2048:
            raise ValueError("output_summary is outside bounds")
        created = float(self._clock())
        entry = VerificationCacheEntry(key, paths, status, result_digest, redact_secrets(output_summary), created, created + self._ttl)
        self._entries[key.digest] = entry
        if self._store is not None and hasattr(self._store, "save_verification_cache_entry"):
            self._store.save_verification_cache_entry(entry.as_persistence_dict())
        self._trim()
        return entry

    def get(self, key: VerificationCacheKey) -> CacheLookup:
        if not isinstance(key, VerificationCacheKey):
            raise TypeError("key must be VerificationCacheKey")
        self._trim()
        entry = self._entries.get(key.digest)
        return CacheLookup(entry is not None, entry, "exact_fingerprint" if entry is not None else "fingerprint_miss")

    def invalidate(self, changed_paths: tuple[str, ...]) -> int:
        changed = tuple(_safe_path(path) for path in changed_paths)
        if len(changed) != len(set(changed)):
            raise ValueError("changed_paths contain duplicates")
        remove = [digest for digest, entry in self._entries.items() if any(_overlap(relevant, changed_path) for relevant in entry.relevant_paths for changed_path in changed)]
        for digest in remove:
            self._entries.pop(digest, None)
        if remove and self._store is not None and hasattr(self._store, "delete_verification_cache_keys"):
            self._store.delete_verification_cache_keys(tuple(remove))
        return len(remove)


__all__ = [
    "CacheLookup",
    "VerificationCache",
    "VerificationCacheEntry",
    "VerificationCacheKey",
    "verification_input_fingerprint",
]
