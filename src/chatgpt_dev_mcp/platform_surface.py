from __future__ import annotations

from typing import Any

from coding_tools_mcp.server import tool_output_schema


def _obj(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        value["required"] = list(required)
    return value


def _text(maximum: int = 240, minimum: int = 1) -> dict[str, Any]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def _definition(name: str, schema: dict[str, Any], *, mutate: bool = False, open_world: bool = False) -> dict[str, Any]:
    title = name.replace("_", " ").title()
    return {
        "name": name,
        "title": title,
        "description": f"Bounded v0.41 platform contract for {name}.",
        "inputSchema": schema,
        "outputSchema": tool_output_schema(),
        "annotations": {
            "title": title,
            "readOnlyHint": not mutate,
            "destructiveHint": mutate,
            "idempotentHint": False,
            "openWorldHint": open_world,
        },
    }


ID = _text(128)
SHORT_ID = _text(80)
BRANCH = _text(240)
APPROVAL = _text(128)
CONFIRMATION = _text(400)
HASH40 = {"type": "string", "pattern": "^[0-9a-fA-F]{40}$"}
HASH64 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}


GIT_PARAMS = _obj(
    {
        "branch": BRANCH,
        "source_branch": BRANCH,
        "target_branch": BRANCH,
        "policy": {"type": "string", "enum": ["ff_only", "no_ff"]},
        "base_branch": BRANCH,
    }
)
GITHUB_PARAMS = _obj(
    {
        "number": {"type": "integer", "minimum": 1, "maximum": 2_000_000_000},
        "title": _text(300),
        "body": _text(20_000, 0),
        "head_branch": BRANCH,
        "base_branch": BRANCH,
    }
)
BROWSER_PARAMS = _obj(
    {
        "url": _text(2048),
        "selector": _text(500),
        "value": _text(4096, 0),
        "key": _text(40),
        "width": {"type": "integer", "minimum": 320, "maximum": 3840},
        "height": {"type": "integer", "minimum": 240, "maximum": 2160},
        "milliseconds": {"type": "integer", "minimum": 0, "maximum": 30_000},
    }
)
REVIEW_FINDING = _obj(
    {
        "category": {
            "type": "string",
            "enum": ["correctness", "regression_risk", "security", "concurrency", "api_schema_compatibility", "test_coverage", "maintainability"],
        },
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "message": _text(2000),
        "blocking": {"type": "boolean"},
        "path": _text(240, 0),
    },
    ("category", "severity", "message"),
)
DISPATCH_TASK = _obj(
    {
        "id": SHORT_ID,
        "title": _text(240),
        "kind": {"type": "string", "enum": ["implementation", "verification", "review", "security", "integration", "cleanup"]},
        "depends_on": {"type": "array", "maxItems": 64, "items": SHORT_ID},
        "paths": {"type": "array", "maxItems": 128, "items": _text(240)},
        "resources": {"type": "array", "maxItems": 128, "items": _text(240)},
    },
    ("id", "title"),
)


def build_platform_tools() -> list[dict[str, Any]]:
    specs: list[tuple[str, dict[str, Any], bool, bool]] = [
        (
            "git_workflow_preflight",
            _obj({"operation": {"type": "string", "enum": ["branch_create", "merge", "rebase", "merge_abort", "rebase_abort"]}, "params": GIT_PARAMS}, ("operation", "params")),
            False,
            False,
        ),
        ("git_workflow_apply", _obj({"preflight_id": ID, "approval_id": APPROVAL, "confirmation": CONFIRMATION}, ("preflight_id", "approval_id", "confirmation")), True, False),
        (
            "github_workflow_read",
            _obj({"action": {"type": "string", "enum": ["pr_status", "checks", "reviews", "merge_readiness"]}, "number": {"type": "integer", "minimum": 1, "maximum": 2_000_000_000}, "credential_grant_id": ID}, ("action", "number")),
            False,
            True,
        ),
        ("github_workflow_preflight", _obj({"operation": {"type": "string", "enum": ["pr_create", "pr_merge"]}, "params": GITHUB_PARAMS, "credential_grant_id": ID}, ("operation", "params")), False, True),
        ("github_workflow_apply", _obj({"preflight_id": ID, "approval_id": APPROVAL, "confirmation": CONFIRMATION}, ("preflight_id", "approval_id", "confirmation")), True, True),
        ("command_profile_list", _obj({}), False, False),
        ("command_profile_preflight", _obj({"profile_id": SHORT_ID, "arguments": {"type": "object", "maxProperties": 32}, "credential_grant_ids": {"type": "array", "maxItems": 16, "items": ID}}, ("profile_id", "arguments")), False, False),
        ("command_profile_run", _obj({"preflight_id": ID}, ("preflight_id",)), True, True),
        ("dependency_change_preflight", _obj({"action": {"type": "string", "enum": ["add", "remove"]}, "package": _text(160), "version": _text(80, 0)}, ("action", "package")), False, False),
        ("dependency_apply", _obj({"preflight_id": ID}, ("preflight_id",)), True, True),
        ("dependency_audit", _obj({}), False, False),
        ("browser_test_session", _obj({"action": {"type": "string", "enum": ["profiles", "start", "close"]}, "profile_id": SHORT_ID, "browser_session_id": ID}, ("action",)), True, True),
        ("browser_inspect", _obj({"browser_session_id": ID, "kind": {"type": "string", "enum": ["snapshot", "visible_text", "accessibility", "console", "network", "screenshot", "visual_diff"]}, "baseline_id": ID, "threshold": {"type": "number", "minimum": 0, "maximum": 1}}, ("browser_session_id", "kind")), False, True),
        ("browser_action", _obj({"browser_session_id": ID, "action": {"type": "string", "enum": ["navigate", "click", "type", "keyboard", "viewport", "wait"]}, "params": BROWSER_PARAMS}, ("browser_session_id", "action", "params")), True, True),
        ("desktop_runtime", _obj({"action": {"type": "string", "enum": ["profiles", "start", "status", "logs", "snapshot", "stop"]}, "profile_id": SHORT_ID, "instance_id": ID, "revision": HASH40, "credential_grant_ids": {"type": "array", "maxItems": 16, "items": ID}, "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 262_144}}, ("action",)), True, True),
        ("director_review", _obj({"action": {"type": "string", "enum": ["record", "list", "readiness", "remediate"]}, "task_id": ID, "reviewer_id": ID, "base_revision": HASH40, "diff_hash": HASH64, "reviewed_paths": {"type": "array", "maxItems": 512, "items": _text(240)}, "findings": {"type": "array", "maxItems": 200, "items": REVIEW_FINDING}, "require_independent": {"type": "boolean"}, "receipt_id": ID, "request_id": ID, "title": _text(240)}, ("action",)), False, False),
        ("patch_revert_preflight", _obj({"patch_id": ID}, ("patch_id",)), False, False),
        ("patch_revert", _obj({"preflight_id": ID, "approval_id": APPROVAL, "confirmation": CONFIRMATION}, ("preflight_id", "approval_id", "confirmation")), True, False),
        ("credential_slot_list", _obj({}), False, False),
        ("credential_slot_preflight", _obj({"slot_id": SHORT_ID, "profile_id": SHORT_ID}, ("slot_id", "profile_id")), False, False),
        ("director_plan_work", _obj({"request_id": SHORT_ID, "base_revision": HASH40, "max_concurrency": {"type": "integer", "minimum": 1, "maximum": 6}, "tasks": {"type": "array", "minItems": 1, "maxItems": 64, "items": DISPATCH_TASK}}, ("request_id", "base_revision", "tasks")), False, False),
        ("director_claim_task", _obj({"plan_id": ID, "owner_id": ID}, ("plan_id", "owner_id")), True, False),
        ("director_dispatch_status", _obj({"plan_id": ID}, ("plan_id",)), False, False),
    ]
    definitions = [_definition(name, schema, mutate=mutate, open_world=open_world) for name, schema, mutate, open_world in specs]
    for definition in definitions:
        name = definition["name"]
        if name == "director_review":
            # ``record`` appends a review receipt and ``remediate`` enqueues a
            # Task Ledger item; the combined action surface must not present
            # those mutations as a READ_ONLY inspection tool.
            definition["description"] = (
                "Inspect review state, append a bounded review receipt, or create a remediation task. "
                "The record and remediate actions are local control-plane mutations; list and readiness only observe."
            )
            definition["annotations"]["readOnlyHint"] = False
            definition["annotations"]["destructiveHint"] = False
        elif name == "director_plan_work":
            definition["description"] = (
                "Create a bounded local Director dispatch plan and its Task Ledger entries. "
                "This is a control-plane mutation and does not create chats or execute tasks."
            )
            definition["annotations"]["readOnlyHint"] = False
            definition["annotations"]["destructiveHint"] = False
    return definitions
