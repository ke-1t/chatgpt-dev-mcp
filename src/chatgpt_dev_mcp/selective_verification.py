"""Fail-closed selection of the smallest defensible affected test set."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .change_impact import classify_change_impact
from .semantic_index import SemanticIndexSnapshot

PROJECT_RULE_PATHS = frozenset({"pyproject.toml", "package.json", "package-lock.json", "Cargo.toml", "go.mod", "go.sum"})


def _path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("changed path is invalid")
    parsed = Path(value)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError("changed path is invalid")
    return parsed.as_posix()


def _is_test(path: str) -> bool:
    name = Path(path).name
    return path.startswith("tests/") or name.startswith("test_") or name.endswith("_test.py")


@dataclass(frozen=True)
class VerificationSelection:
    tests: tuple[str, ...]
    reasons: Mapping[str, tuple[str, ...]]
    fallback_full: bool
    global_reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"tests": list(self.tests), "reasons": {path: list(reasons) for path, reasons in self.reasons.items()}, "fallback_full": self.fallback_full, "global_reasons": list(self.global_reasons), "external_execution": False}


class VerificationSelector:
    def select(self, changed_paths: tuple[str, ...], semantic_snapshot: SemanticIndexSnapshot, project_profile: object) -> VerificationSelection:
        if not isinstance(semantic_snapshot, SemanticIndexSnapshot):
            raise TypeError("semantic_snapshot must be SemanticIndexSnapshot")
        changed = tuple(_path(path) for path in changed_paths)
        if not changed or len(changed) != len(set(changed)):
            raise ValueError("changed_paths must be non-empty and unique")
        commands = getattr(project_profile, "commands", ())
        verification_tasks = getattr(project_profile, "verification_tasks", ())
        test_configured = "test" in commands and "test" in verification_tasks
        impact = classify_change_impact(changed)
        if not impact.execution_required and test_configured:
            return VerificationSelection(
                tests=(),
                reasons={},
                fallback_full=False,
                global_reasons=("documentation_only",),
            )
        selected: dict[str, set[str]] = {}
        global_reasons: set[str] = set()
        for path in changed:
            if _is_test(path):
                selected.setdefault(path, set()).update({"direct_path", "test_owner"})
            if Path(path).name in PROJECT_RULE_PATHS:
                global_reasons.add("project_rule")
        changed_symbols = {symbol.symbol_id for symbol in semantic_snapshot.symbols if symbol.path in changed}
        affected_symbols = set(changed_symbols)
        if changed_symbols:
            while True:
                expanded = {edge.source for edge in semantic_snapshot.edges if edge.relation == "reference" and edge.target in affected_symbols and ":" in edge.source}
                before = len(affected_symbols)
                affected_symbols.update(expanded)
                if len(affected_symbols) == before:
                    break
            for edge in semantic_snapshot.edges:
                if edge.relation == "test" and edge.target in affected_symbols and _is_test(edge.path):
                    selected.setdefault(edge.path, set()).add("symbol_dependency")
        non_test_changes = tuple(path for path in changed if not _is_test(path) and Path(path).name not in PROJECT_RULE_PATHS)
        graph_unknown = bool(non_test_changes) and not changed_symbols
        dependency_known = any(
            "symbol_dependency" in reasons or "test_owner" in reasons
            for reasons in selected.values()
        )
        dependency_unknown = bool(non_test_changes) and not dependency_known
        fallback_full = bool(global_reasons) or not test_configured or graph_unknown or dependency_unknown
        if fallback_full:
            global_reasons.add("fallback_full")
        normalized_reasons = {path: tuple(sorted(reasons, key=lambda item: (item != "direct_path", item != "test_owner", item))) for path, reasons in sorted(selected.items())}
        return VerificationSelection(tests=tuple(sorted(selected)), reasons=normalized_reasons, fallback_full=fallback_full, global_reasons=tuple(sorted(global_reasons)))


__all__ = ["VerificationSelection", "VerificationSelector"]
