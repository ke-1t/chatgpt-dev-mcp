"""Bounded task-aware context assembled from trusted semantic and reader inputs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .director import redact_secrets
from .semantic_index import SemanticIndex, SemanticMatch, SemanticQuery


CONFIG_NAMES = frozenset({"pyproject.toml", "package.json", "package-lock.json", "tsconfig.json", "Cargo.toml", "go.mod"})
QUERY_STOP_WORDS = frozenset({"and", "for", "from", "implementation", "into", "the", "this", "with"})


@dataclass(frozen=True)
class DevelopmentContextItem:
    kind: str
    path: str
    line: int
    score: int
    reason: str
    source_hash: str
    content: str

    def as_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "path": self.path, "line": self.line, "score": self.score, "reason": self.reason, "source_hash": self.source_hash, "content": self.content}


@dataclass(frozen=True)
class DevelopmentContextPack:
    task_id: str
    query: str
    items: tuple[DevelopmentContextItem, ...]
    used_bytes: int
    max_bytes: int
    truncated: bool

    def as_dict(self) -> dict[str, object]:
        return {"task_id": self.task_id, "query": self.query, "items": [item.as_dict() for item in self.items], "used_bytes": self.used_bytes, "max_bytes": self.max_bytes, "truncated": self.truncated, "external_execution": False}


def _safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1000 or "\\" in value:
        raise ValueError("context path is invalid")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} or part.startswith(".") for part in path.parts):
        raise ValueError("context path is invalid")
    return path.as_posix()


def _snippet(text: str, line: int, *, radius: int = 4, max_chars: int = 6000) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    center = min(max(1, line), len(lines))
    start = max(0, center - radius - 1)
    end = min(len(lines), center + radius)
    return "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))[:max_chars]


class DevelopmentContextBuilder:
    def __init__(self, index: SemanticIndex, *, safe_reader: Callable[[str], str], diff_reader: Callable[[str], str]) -> None:
        if not isinstance(index, SemanticIndex):
            raise TypeError("index must be SemanticIndex")
        if not callable(safe_reader) or not callable(diff_reader):
            raise TypeError("context readers must be callable")
        self._index = index
        self._safe_reader = safe_reader
        self._diff_reader = diff_reader

    @staticmethod
    def _kind(match: SemanticMatch) -> str:
        if match.relation == "definition":
            return "definition"
        if match.relation == "test" or Path(match.path).name.startswith("test_") or match.path.startswith("tests/"):
            return "test"
        return "caller"

    def _semantic_items(self, query: str, target_paths: tuple[str, ...]) -> list[DevelopmentContextItem]:
        items: list[DevelopmentContextItem] = []
        seen: set[tuple[str, str, int, str]] = set()

        def append_match(match: SemanticMatch, *, bonus: int = 0, reason_prefix: str = "semantic") -> None:
            kind = self._kind(match)
            key = (kind, match.path, match.line, match.symbol_id)
            if key in seen:
                return
            seen.add(key)
            try:
                source = self._safe_reader(match.path)
            except Exception:
                return
            if not isinstance(source, str):
                return
            content = redact_secrets(_snippet(source, match.line))
            if content:
                items.append(
                    DevelopmentContextItem(
                        kind=kind,
                        path=match.path,
                        line=match.line,
                        score=match.score + bonus,
                        reason=f"{reason_prefix}:{match.reason}",
                        source_hash=match.source_hash,
                        content=content,
                    )
                )

        # Explicit target paths are a caller instruction, not a weak ranking hint.
        # Pull their definitions first and retain caller-supplied target ordering.
        target_count = len(target_paths)
        for target_index, path in enumerate(target_paths):
            direct_matches = self._index.query(
                SemanticQuery(text="", path=path, relations=("definition",), limit=100)
            )
            target_bonus = 2_000 + (target_count - target_index) * 10
            for match in direct_matches:
                if match.path == path:
                    append_match(match, bonus=target_bonus, reason_prefix="target")

        # SemanticIndex intentionally uses bounded substring matching. Natural
        # language task descriptions therefore need to be decomposed into useful
        # search terms rather than treated as one exact substring.
        terms: list[str] = []
        for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", query):
            for token in raw.casefold().split("_"):
                if len(token) < 3 or token in QUERY_STOP_WORDS or token in terms:
                    continue
                terms.append(token)
        for term in terms[:12]:
            for match in self._index.query(
                SemanticQuery(text=term, relations=("definition", "references", "tests"), limit=100)
            ):
                bonus = 500 if match.path in target_paths else 0
                append_match(match, bonus=bonus, reason_prefix=f"query:{term}")

        # Preserve compatibility for concise symbol-like queries that are more
        # specific than their individual tokens.
        if len(query.split()) <= 2:
            for match in self._index.query(
                SemanticQuery(text=query, relations=("definition", "references", "tests"), limit=100)
            ):
                bonus = 500 if match.path in target_paths else 0
                append_match(match, bonus=bonus)
        return items

    def _diff_items(self, diff_paths: tuple[str, ...]) -> list[DevelopmentContextItem]:
        items = []
        for path in diff_paths:
            try:
                diff = self._diff_reader(path)
            except Exception:
                continue
            if isinstance(diff, str) and diff:
                items.append(DevelopmentContextItem(kind="diff", path=path, line=1, score=86, reason="changed_path_diff", source_hash=hashlib.sha256(diff.encode("utf-8")).hexdigest(), content=redact_secrets(diff[:8000])))
        return items

    def _config_items(self, target_paths: tuple[str, ...]) -> list[DevelopmentContextItem]:
        items = []
        for path in target_paths:
            if Path(path).name not in CONFIG_NAMES:
                continue
            try:
                source = self._safe_reader(path)
            except Exception:
                continue
            if isinstance(source, str):
                items.append(DevelopmentContextItem(kind="config", path=path, line=1, score=58, reason="target_configuration", source_hash=hashlib.sha256(source.encode("utf-8")).hexdigest(), content=redact_secrets(source[:8000])))
        return items

    @staticmethod
    def _item_bytes(item: DevelopmentContextItem) -> int:
        return len(json.dumps(item.as_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8"))

    def build(self, *, task_id: str, query: str, target_paths: tuple[str, ...], diff_paths: tuple[str, ...], max_bytes: int = 65536) -> DevelopmentContextPack:
        if not isinstance(task_id, str) or not task_id or len(task_id) > 128:
            raise ValueError("task_id is invalid")
        if not isinstance(query, str) or not query.strip() or len(query) > 1000 or "\x00" in query:
            raise ValueError("query is invalid")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 512 <= max_bytes <= 262144:
            raise ValueError("max_bytes is outside bounds")
        targets = tuple(_safe_path(path) for path in target_paths)
        diffs = tuple(_safe_path(path) for path in diff_paths)
        candidates = self._semantic_items(query, targets) + self._diff_items(diffs) + self._config_items(targets)
        kind_order = {"definition": 0, "caller": 1, "test": 2, "diff": 3, "config": 4}
        candidates.sort(key=lambda item: (-item.score, kind_order[item.kind], item.path, item.line, item.reason))
        selected: list[DevelopmentContextItem] = []
        used = 0
        truncated = False
        for item in candidates:
            size = self._item_bytes(item)
            if used + size > max_bytes:
                truncated = True
                continue
            selected.append(item)
            used += size
        return DevelopmentContextPack(task_id, query.strip(), tuple(selected), used, max_bytes, truncated)


__all__ = ["DevelopmentContextBuilder", "DevelopmentContextItem", "DevelopmentContextPack"]
