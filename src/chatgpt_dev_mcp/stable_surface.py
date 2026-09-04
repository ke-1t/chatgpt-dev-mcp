from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from typing import Any


STABLE_SURFACE_REVISION = "tool-registry-v25-stable"
V25_STABLE_SCHEMA_HASH = "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c"
PROFILE_LEGACY = "legacy"
PROFILE_STABLE_GATEWAY = "stable_gateway"

STABLE_DEDICATED_TOOL_NAMES = (
    "server_info",
    "director_health",
    "check_exec_environment",
    "workspace_list",
    "workspace_discover",
    "workspace_open",
    "workspace_status",
    "workspace_request_development",
    "workspace_create_development_session",
    "workspace_resume_development_session",
    "workspace_list_development_sessions",
    "workspace_session_status",
    "workspace_close_development_session",
    "workspace_session_diff",
    "development_context",
    "director_development_start",
    "workspace_integration_preflight",
    "workspace_integrate_development_session",
    "read_file",
    "list_files",
    "search_text",
    "readonly_path",
    "list_allowed_files",
    "read_allowed_file",
    "search_allowed_files",
    "view_image",
    "apply_patch",
    "git_status",
    "git_diff",
    "git_log",
    "git_show",
    "git_commit_preflight",
    "git_commit",
    "git_push_preflight",
    "git_push",
    "run_task",
    "task_poll",
    "task_stop",
    "verification_run",
    "verification_plan",
    "verification_record",
    "director_next_action",
    "browser_test_session",
    "browser_inspect",
    "browser_action",
    "browser_qa_run",
    "desktop_runtime",
    "director_status_summary",
)

GATEWAY_TOOL_NAMES = (
    "capability_catalog",
    "capability_describe",
    "capability_preflight",
    "capability_execute",
)

STABLE_PUBLIC_TOOL_NAMES = STABLE_DEDICATED_TOOL_NAMES + GATEWAY_TOOL_NAMES


def _schema_hash(definitions: Sequence[Mapping[str, Any]]) -> str:
    canonical = sorted((dict(item) for item in definitions), key=lambda item: str(item.get("name", "")))
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_frozen_v25_schema(definitions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    actual_count = len(definitions)
    actual_hash = _schema_hash(definitions)
    revision_match = STABLE_SURFACE_REVISION == "tool-registry-v25-stable"
    count_match = actual_count == 52
    hash_match = actual_hash == V25_STABLE_SCHEMA_HASH
    mismatches = [
        field
        for field, matched in (
            ("revision", revision_match),
            ("count", count_match),
            ("hash", hash_match),
        )
        if not matched
    ]
    return {
        "status": "valid" if revision_match and count_match and hash_match else "invalid",
        "revision": STABLE_SURFACE_REVISION,
        "count": actual_count,
        "hash": actual_hash,
        "revision_match": revision_match,
        "count_match": count_match,
        "hash_match": hash_match,
        "mismatches": mismatches,
        "expected_revision": "tool-registry-v25-stable",
        "expected_count": 52,
        "expected_hash": V25_STABLE_SCHEMA_HASH,
    }

CATEGORY_TOOL_GROUPS: Mapping[str, tuple[str, ...]] = {
    "platform_runtime": STABLE_DEDICATED_TOOL_NAMES[0:3],
    "workspace": STABLE_DEDICATED_TOOL_NAMES[3:7],
    "development": STABLE_DEDICATED_TOOL_NAMES[7:18],
    "files_changes": STABLE_DEDICATED_TOOL_NAMES[18:27],
    "git_delivery": STABLE_DEDICATED_TOOL_NAMES[27:35],
    "verification_tasks": STABLE_DEDICATED_TOOL_NAMES[35:42],
    "browser_qa": STABLE_DEDICATED_TOOL_NAMES[42:46],
    "desktop_profiles": STABLE_DEDICATED_TOOL_NAMES[46:47],
    "governance": STABLE_DEDICATED_TOOL_NAMES[47:48],
    "capability_gateway": GATEWAY_TOOL_NAMES,
}


def resolve_public_surface_profile(value: str | None) -> str:
    normalized = (PROFILE_STABLE_GATEWAY if value is None else value).strip().lower()
    if normalized == "":
        return PROFILE_STABLE_GATEWAY
    if normalized == PROFILE_LEGACY:
        return PROFILE_LEGACY
    if normalized == PROFILE_STABLE_GATEWAY:
        return PROFILE_STABLE_GATEWAY
    raise ValueError(f"unsupported public surface profile: {value!r}")


def surface_mode_from_environment() -> str:
    return resolve_public_surface_profile(os.environ.get("CHATGPT_DEV_MCP_SURFACE"))


def validate_surface_manifest(
    definitions: Sequence[Mapping[str, Any]],
    mode: str,
) -> dict[str, Any]:
    resolved = resolve_public_surface_profile(mode)
    if resolved == PROFILE_LEGACY:
        public_names = [str(item.get("name", "")) for item in definitions]
        counts = Counter(public_names)
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        return {
            "status": "valid" if not duplicates else "invalid",
            "mode": resolved,
            "count": len(public_names),
            "missing_names": [],
            "unexpected_names": [],
            "duplicate_names": duplicates,
            "category_mismatches": {},
        }

    result = validate_gateway_surface(definitions)
    category_for = {
        name: category
        for category, names in CATEGORY_TOOL_GROUPS.items()
        for name in names
    }
    mismatches: dict[str, str] = {}
    for item in definitions:
        name = item.get("name")
        if not isinstance(name, str) or name not in category_for:
            continue
        declared = item.get("category")
        if declared is not None and declared != category_for[name]:
            mismatches[name] = str(declared)
    result.update(
        {
            "mode": resolved,
            "count": result["public_count"],
            "unexpected_names": list(result["extra_names"]),
            "category_mismatches": mismatches,
        }
    )
    if mismatches:
        result["status"] = "invalid"
    return result


def validate_gateway_surface(definitions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate the exact stable-gateway public manifest."""
    public_names = [str(item.get("name", "")) for item in definitions]
    counts = Counter(public_names)
    expected = set(STABLE_PUBLIC_TOOL_NAMES)
    missing = sorted(name for name in expected if counts[name] == 0)
    duplicates = sorted(name for name, count in counts.items() if name in expected and count > 1)
    extra = sorted(name for name in counts if name not in expected)
    valid = not missing and not duplicates and not extra and len(public_names) == len(STABLE_PUBLIC_TOOL_NAMES)
    return {
        "status": "valid" if valid else "invalid",
        "revision": STABLE_SURFACE_REVISION,
        "public_count": len(public_names),
        "gateway_count": sum(counts[name] for name in GATEWAY_TOOL_NAMES),
        "public_names": public_names,
        "missing_names": missing,
        "duplicate_names": duplicates,
        "extra_names": extra,
    }


def select_stable_surface(definitions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Select exactly the stable manifest in deterministic manifest order."""

    buckets: dict[str, list[Mapping[str, Any]]] = {}
    for item in definitions:
        name = str(item.get("name", ""))
        if name in STABLE_PUBLIC_TOOL_NAMES:
            buckets.setdefault(name, []).append(item)
    missing = [name for name in STABLE_PUBLIC_TOOL_NAMES if len(buckets.get(name, ())) == 0]
    duplicates = [name for name in STABLE_PUBLIC_TOOL_NAMES if len(buckets.get(name, ())) > 1]
    if missing or duplicates:
        raise ValueError(f"invalid stable surface inventory: missing={missing!r}, duplicates={duplicates!r}")
    return [dict(buckets[name][0]) for name in STABLE_PUBLIC_TOOL_NAMES]


__all__ = [
    "CATEGORY_TOOL_GROUPS",
    "GATEWAY_TOOL_NAMES",
    "PROFILE_LEGACY",
    "PROFILE_STABLE_GATEWAY",
    "STABLE_DEDICATED_TOOL_NAMES",
    "STABLE_PUBLIC_TOOL_NAMES",
    "STABLE_SURFACE_REVISION",
    "V25_STABLE_SCHEMA_HASH",
    "resolve_public_surface_profile",
    "select_stable_surface",
    "surface_mode_from_environment",
    "validate_frozen_v25_schema",
    "validate_gateway_surface",
    "validate_surface_manifest",
]
