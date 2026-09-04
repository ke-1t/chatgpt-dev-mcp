"""Deterministic fail-closed classification of changed repository paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .director import normalize_relative_path


_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt"})
_DOC_ROOT_FILES = frozenset({"README.md", "CHANGELOG.md", "CONTRIBUTING.md"})


@dataclass(frozen=True, slots=True)
class ChangeImpact:
    paths: tuple[str, ...]
    execution_required: bool
    reason: str


def classify_change_impact(paths: Iterable[str]) -> ChangeImpact:
    parsed = tuple(normalize_relative_path(path) for path in paths)
    if not parsed or len(parsed) != len(set(parsed)):
        raise ValueError("changed paths must be non-empty and unique")

    documentation_only = all(
        path in _DOC_ROOT_FILES
        or (path.startswith("docs/") and Path(path).suffix.lower() in _DOC_SUFFIXES)
        for path in parsed
    )
    return ChangeImpact(
        paths=parsed,
        execution_required=not documentation_only,
        reason="documentation_only" if documentation_only else "execution_relevant_or_unknown",
    )


__all__ = ["ChangeImpact", "classify_change_impact"]
