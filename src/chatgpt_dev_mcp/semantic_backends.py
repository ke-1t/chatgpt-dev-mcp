"""Fail-soft semantic provider adapters with a trusted built-in fallback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .semantic_index import SemanticIndex, SemanticMatch, SemanticQuery


class SemanticProvider(Protocol):
    name: str
    def status(self) -> dict[str, object]: ...
    def query(self, query: SemanticQuery) -> tuple["ProviderResult", ...]: ...
    def refresh(self, changed_paths: tuple[str, ...]) -> dict[str, object]: ...


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    match: SemanticMatch

    @property
    def symbol_id(self) -> str:
        return self.match.symbol_id

    @property
    def relation(self) -> str:
        return self.match.relation

    @property
    def path(self) -> str:
        return self.match.path

    @property
    def confidence(self) -> float:
        return self.match.confidence

    def as_dict(self) -> dict[str, object]:
        return {"provider": self.provider, **self.match.as_dict()}


class BuiltinProvider:
    name = "builtin"

    def __init__(self, index: SemanticIndex) -> None:
        if not isinstance(index, SemanticIndex):
            raise TypeError("index must be SemanticIndex")
        self._index = index

    def status(self) -> dict[str, object]:
        return {"provider": self.name, "status": "available", "reason": "builtin_local_index", "external_execution": False}

    def query(self, query: SemanticQuery) -> tuple[ProviderResult, ...]:
        return tuple(ProviderResult(self.name, match) for match in self._index.query(query))

    def refresh(self, changed_paths: tuple[str, ...]) -> dict[str, object]:
        self._index.refresh(changed_paths)
        return self.status()


class _ConfiguredOptionalProvider:
    provider_name = "optional"

    def __init__(self, *, configured: bool = False, reason: str = "not_configured") -> None:
        self._configured = bool(configured)
        self._reason = reason

    @property
    def name(self) -> str:
        return self.provider_name

    def status(self) -> dict[str, object]:
        return {"provider": self.name, "status": "available" if self._configured else "unavailable", "reason": "configured_adapter" if self._configured else self._reason, "process_spawned": False, "external_execution": False}

    def query(self, query: SemanticQuery) -> tuple[ProviderResult, ...]:
        del query
        return ()

    def refresh(self, changed_paths: tuple[str, ...]) -> dict[str, object]:
        del changed_paths
        return self.status()


class TreeSitterProvider(_ConfiguredOptionalProvider):
    provider_name = "tree_sitter"


class LspProvider(_ConfiguredOptionalProvider):
    provider_name = "lsp"


class SerenaProvider(_ConfiguredOptionalProvider):
    provider_name = "serena"


class ProviderRegistry:
    def __init__(self, builtin: BuiltinProvider, *, optional: tuple[SemanticProvider, ...] = ()) -> None:
        if not isinstance(builtin, BuiltinProvider):
            raise TypeError("builtin provider is required")
        self._builtin = builtin
        self._optional = tuple(optional)

    def status(self) -> list[dict[str, object]]:
        statuses = [self._builtin.status()]
        for provider in self._optional:
            try:
                status = provider.status()
            except Exception:
                status = {"provider": getattr(provider, "name", "optional"), "status": "unavailable", "reason": "status_error"}
            statuses.append(dict(status))
        return statuses

    @staticmethod
    def _key(result: ProviderResult) -> tuple[str, str, str, int]:
        match = result.match
        return match.relation, match.symbol_id, match.path, match.line

    def query(self, query: SemanticQuery) -> tuple[ProviderResult, ...]:
        candidates = list(self._builtin.query(query))
        for provider in self._optional:
            try:
                if provider.status().get("status") != "available":
                    continue
                results = provider.query(query)
            except Exception:
                continue
            candidates.extend(result for result in results if isinstance(result, ProviderResult))
        selected: dict[tuple[str, str, str, int], ProviderResult] = {}
        for result in candidates:
            key = self._key(result)
            current = selected.get(key)
            if current is None or (result.match.score, result.match.confidence, result.provider == "builtin") > (current.match.score, current.match.confidence, current.provider == "builtin"):
                selected[key] = result
        ordered = sorted(selected.values(), key=lambda item: (-item.match.score, -item.match.confidence, item.provider != "builtin", item.match.path, item.match.line))
        return tuple(ordered[: query.limit])

    def refresh(self, changed_paths: tuple[str, ...]) -> list[dict[str, object]]:
        statuses = [self._builtin.refresh(changed_paths)]
        for provider in self._optional:
            try:
                statuses.append(provider.refresh(changed_paths))
            except Exception:
                statuses.append({"provider": getattr(provider, "name", "optional"), "status": "unavailable", "reason": "refresh_error"})
        return statuses


__all__ = ["BuiltinProvider", "LspProvider", "ProviderRegistry", "ProviderResult", "SemanticProvider", "SerenaProvider", "TreeSitterProvider"]
