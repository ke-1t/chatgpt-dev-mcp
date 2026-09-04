"""Bounded non-secret evidence packs for assistant-side analysis."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .director import ValidationError, contains_secret_like_content, normalize_relative_path

MAX_SOURCE_BYTES = 1024 * 1024
MIN_OUTPUT_BYTES = 1024
MAX_OUTPUT_BYTES = 65536
MAX_CHANGED_PATHS = 128
MAX_FAILURES = 128


class AnalysisPackError(ValueError):
    pass


def _json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise AnalysisPackError("analysis-pack content must be JSON serializable") from exc


def _validate_identifier(value: object, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum or "\x00" in value:
        raise AnalysisPackError(f"{name} is invalid")
    return value


def _paths(values: object) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or len(values) > MAX_CHANGED_PATHS:
        raise AnalysisPackError("changed_paths must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        try:
            path = normalize_relative_path(value)
        except ValidationError as exc:
            raise AnalysisPackError("changed path is invalid or sensitive") from exc
        if path not in seen:
            result.append(path)
            seen.add(path)
    return result


def _mapping(value: object, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AnalysisPackError(f"{name} must be an object")
    return dict(value)


def _failures(value: object) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > MAX_FAILURES:
        raise AnalysisPackError("failures must be a bounded list")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise AnalysisPackError("failure entries must be objects")
        result.append(dict(item))
    return result


def _truncate_utf8(value: str, maximum: int) -> str:
    if maximum <= 0:
        return ""
    return value.encode("utf-8")[:maximum].decode("utf-8", errors="ignore")


def _payload_size(pack: Mapping[str, object]) -> int:
    measured = {key: value for key, value in pack.items() if key != "used_bytes"}
    return len(_json(measured).encode("utf-8"))


def _fit(pack: dict[str, Any], maximum: int) -> None:
    while _payload_size(pack) > maximum:
        changed = False
        diffs = pack["diffs"]
        for path in reversed(list(diffs)):
            text = diffs[path]
            if not text:
                continue
            current = _payload_size(pack)
            excess = max(1, current - maximum)
            encoded = text.encode("utf-8")
            target = max(0, len(encoded) - excess - 64)
            diffs[path] = _truncate_utf8(text, target)
            changed = True
            break
        if changed:
            pack["truncated"] = True
            continue
        if pack["failures"]:
            pack["failures"].pop()
            pack["truncated"] = True
            continue
        if pack["metadata"]:
            pack["metadata"] = {}
            pack["truncated"] = True
            continue
        raise AnalysisPackError("max_bytes is too small for the analysis-pack envelope")
    pack["used_bytes"] = _payload_size(pack)


def build_analysis_pack(
    *,
    workspace_id: str,
    task_id: str,
    changed_paths: Sequence[str],
    diffs: Mapping[str, str] | None = None,
    failures: Sequence[Mapping[str, object]] | None = None,
    metadata: Mapping[str, object] | None = None,
    include_diff: bool = True,
    include_failures: bool = True,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> dict[str, object]:
    """Build a deterministic, bounded pack from already-authorized local evidence."""

    workspace = _validate_identifier(workspace_id, name="workspace_id", maximum=160)
    task = _validate_identifier(task_id, name="task_id", maximum=128)
    paths = _paths(changed_paths)
    if not isinstance(include_diff, bool) or not isinstance(include_failures, bool):
        raise AnalysisPackError("include flags must be boolean")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not MIN_OUTPUT_BYTES <= max_bytes <= MAX_OUTPUT_BYTES:
        raise AnalysisPackError("max_bytes is outside the allowed bound")

    raw_diffs = _mapping(diffs, name="diffs")
    normalized_diffs: dict[str, str] = {}
    allowed_paths = set(paths)
    for raw_path, value in raw_diffs.items():
        try:
            path = normalize_relative_path(raw_path)
        except ValidationError as exc:
            raise AnalysisPackError("diff path is invalid or sensitive") from exc
        if path not in allowed_paths:
            raise AnalysisPackError("diff path is not present in changed_paths")
        if not isinstance(value, str):
            raise AnalysisPackError("diff content must be text")
        normalized_diffs[path] = value

    normalized_failures = _failures(failures)
    normalized_metadata = _mapping(metadata, name="metadata")
    source_content = {
        "diffs": normalized_diffs,
        "failures": normalized_failures,
        "metadata": normalized_metadata,
    }
    serialized_source = _json(source_content)
    if len(serialized_source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise AnalysisPackError("analysis-pack source content exceeds the safety bound")
    if contains_secret_like_content(serialized_source):
        raise AnalysisPackError("analysis-pack source content contains secret-like material")

    identity = {
        "workspace_id": workspace,
        "task_id": task,
        "changed_files": paths,
        "diffs": normalized_diffs if include_diff else {},
        "failures": normalized_failures if include_failures else [],
        "metadata": normalized_metadata,
    }
    digest = hashlib.sha256(_json(identity).encode("utf-8")).hexdigest()[:32]
    pack: dict[str, Any] = {
        "analysis_pack_id": f"analysis-pack:{digest}",
        "workspace_id": workspace,
        "task_id": task,
        "changed_files": paths,
        "diffs": dict(normalized_diffs) if include_diff else {},
        "failures": list(normalized_failures) if include_failures else [],
        "metadata": dict(normalized_metadata),
        "truncated": False,
        "redactions": 0,
        "used_bytes": 0,
        "external_execution": False,
    }
    _fit(pack, max_bytes)
    return pack


__all__ = ["AnalysisPackError", "build_analysis_pack"]
