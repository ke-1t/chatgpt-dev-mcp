"""Small deterministic repository map ranked from the existing semantic index."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

from .semantic_index import SemanticIndexSnapshot


def _tokens(value: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", value) if token}


@dataclass(frozen=True, slots=True)
class RepoMapEntry:
    symbol_id: str
    path: str
    kind: str
    name: str
    line: int
    score: int
    relations: tuple[str, ...]
    tests: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "symbol_id": self.symbol_id,
            "path": self.path,
            "kind": self.kind,
            "name": self.name,
            "line": self.line,
            "score": self.score,
            "relations": list(self.relations),
            "tests": list(self.tests),
        }


@dataclass(frozen=True, slots=True)
class RepoMap:
    entries: tuple[RepoMapEntry, ...]
    used_bytes: int
    max_bytes: int
    truncated: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "entries": [entry.as_dict() for entry in self.entries],
            "used_bytes": self.used_bytes,
            "max_bytes": self.max_bytes,
            "truncated": self.truncated,
        }


def build_repo_map(
    snapshot: SemanticIndexSnapshot,
    *,
    query: str,
    target_paths: tuple[str, ...] = (),
    changed_paths: tuple[str, ...] = (),
    max_items: int = 64,
    max_bytes: int = 8192,
) -> RepoMap:
    if not isinstance(snapshot, SemanticIndexSnapshot):
        raise TypeError("snapshot must be SemanticIndexSnapshot")
    if not isinstance(query, str) or len(query) > 500 or "\x00" in query:
        raise ValueError("repo-map query is invalid")
    if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= 256:
        raise ValueError("repo-map max_items is invalid")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 512 <= max_bytes <= 262144:
        raise ValueError("repo-map max_bytes is invalid")
    if len(target_paths) != len(set(target_paths)) or len(changed_paths) != len(set(changed_paths)):
        raise ValueError("repo-map paths must be unique")

    query_tokens = _tokens(query)
    candidates: list[RepoMapEntry] = []
    for symbol in snapshot.symbols:
        score = 10
        symbol_tokens = _tokens(f"{symbol.name} {symbol.symbol_id} {symbol.path}")
        score += 500 * len(query_tokens & symbol_tokens)
        if symbol.path in target_paths:
            score += 10_000
        if symbol.path in changed_paths:
            score += 5_000
        relations = {"definition"}
        tests: set[str] = set()
        for edge in snapshot.edges:
            if edge.target != symbol.symbol_id:
                continue
            relations.add(edge.relation)
            if edge.relation == "reference":
                score += 3
            elif edge.relation == "test":
                score += 8
                tests.add(edge.path)
        candidates.append(
            RepoMapEntry(
                symbol_id=symbol.symbol_id,
                path=symbol.path,
                kind=symbol.kind,
                name=symbol.name,
                line=symbol.start_line,
                score=score,
                relations=tuple(sorted(relations, key=lambda item: (item != "definition", item))),
                tests=tuple(sorted(tests)),
            )
        )

    candidates.sort(key=lambda item: (-item.score, item.path, item.line, item.symbol_id))
    selected: list[RepoMapEntry] = []
    for entry in candidates:
        if len(selected) >= max_items:
            break
        candidate = [item.as_dict() for item in (*selected, entry)]
        if len(json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")) > max_bytes:
            continue
        selected.append(entry)
    used = len(json.dumps([item.as_dict() for item in selected], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return RepoMap(entries=tuple(selected), used_bytes=used, max_bytes=max_bytes, truncated=len(selected) < len(candidates))


__all__ = ["RepoMap", "RepoMapEntry", "build_repo_map"]
