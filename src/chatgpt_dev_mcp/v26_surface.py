"""Versioned v26 HTTP public tool surface.

The v25 Stable surface remains immutable.  v26 narrows broad discriminator
tools into semantically explicit public tools while reusing the proven v25
runtime handlers internally.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from coding_tools_mcp.tool_results import make_tool_result

from .connector_resilience import classify_client_schema_evidence
from .director_audit import audit_watchdog
from .director_watchdog import SchemaObservation, WatchdogSnapshot, evaluate_watchdog
from .observability import tool_schema_metadata
from .stable_surface import STABLE_PUBLIC_TOOL_NAMES
from .tool_contract_policy import (
    INTEGRATION_EXECUTE_CONTRACT,
    INTEGRATION_PREFLIGHT_CONTRACT,
    ToolContract,
)


V26_SURFACE_REVISION = "tool-registry-v26-canary"

_SAFETY_CONTRACTS: Mapping[str, ToolContract] = {
    INTEGRATION_PREFLIGHT_CONTRACT.name: INTEGRATION_PREFLIGHT_CONTRACT,
    INTEGRATION_EXECUTE_CONTRACT.name: INTEGRATION_EXECUTE_CONTRACT,
}

_WORKSPACE_BINDING_FIELDS = ("workspace_id", "working_tree_id", "workspace_ref", "session_id")

_RUN_TASK_SPLITS: tuple[tuple[str, str, str, str], ...] = (
    ("run_tests", "test", "Run registered tests", "Run only the registered test command in the selected DEVELOPMENT workspace."),
    ("run_lint", "lint", "Run registered lint", "Run only the registered lint command in the selected DEVELOPMENT workspace."),
    ("run_build", "build", "Run registered build", "Run only the registered build command in the selected DEVELOPMENT workspace."),
    ("run_dev", "dev", "Run registered dev process", "Run only the registered dev command in the selected DEVELOPMENT workspace."),
    ("run_format", "format", "Run registered formatter", "Run only the registered format command in the selected DEVELOPMENT workspace."),
)

_BROWSER_SESSION_SPLITS: tuple[tuple[str, str, str, str, tuple[str, ...], bool], ...] = (
    ("browser_profile_list", "profiles", "List browser profiles", "List configured browser test profiles without starting or closing a browser session.", (), True),
    ("browser_session_start", "start", "Start browser test session", "Start one configured browser test session for the selected workspace.", ("profile_id",), False),
    ("browser_session_close", "close", "Close browser test session", "Close one exact managed browser test session.", ("browser_session_id",), False),
)

_BROWSER_ACTION_SPLITS: tuple[
    tuple[str, str, str, str, tuple[str, ...], bool, bool], ...
] = (
    ("browser_navigate", "navigate", "Navigate browser", "Navigate one managed browser session to an allowed URL.", ("url",), True, True),
    ("browser_click", "click", "Click browser element", "Click one selector in an existing managed browser session.", ("selector",), True, True),
    ("browser_type", "type", "Type browser text", "Type bounded text into one selector in an existing managed browser session.", ("selector", "value"), True, True),
    ("browser_keyboard", "keyboard", "Send browser key", "Send one bounded keyboard key to an existing managed browser session.", ("key",), True, True),
    ("browser_viewport", "viewport", "Set browser viewport", "Set viewport dimensions for one managed browser session without navigating or interacting with page content.", ("width", "height"), False, False),
    ("browser_wait", "wait", "Wait in browser session", "Wait for a bounded duration in one managed browser session without navigating or interacting with page content.", ("milliseconds",), False, False),
)

_DESKTOP_RUNTIME_SPLITS: tuple[tuple[str, str, str, str, tuple[str, ...], bool], ...] = (
    ("desktop_profile_list", "profiles", "List desktop profiles", "List configured desktop runtime profiles without starting or stopping a process.", (), True),
    ("desktop_runtime_start", "start", "Start desktop runtime", "Start one configured managed desktop runtime in the selected workspace.", ("profile_id", "revision", "credential_grant_ids"), False),
    ("desktop_runtime_status", "status", "Read desktop runtime status", "Read status for one exact managed desktop runtime instance.", ("instance_id",), True),
    ("desktop_runtime_logs", "logs", "Read desktop runtime logs", "Read bounded logs for one exact managed desktop runtime instance.", ("instance_id", "max_bytes"), True),
    ("desktop_runtime_snapshot", "snapshot", "Capture desktop runtime snapshot", "Capture a snapshot from one managed runtime instance or configured capture-only desktop profile.", ("instance_id", "profile_id"), False),
    ("desktop_runtime_stop", "stop", "Stop desktop runtime", "Stop one exact managed desktop runtime instance.", ("instance_id",), False),
)

_PROMOTED_DIRECT_TOOL_NAMES = (
    "security_audit",
    "director_task_ledger",
    "director_writer_lease",
    "git_stage_preflight",
    "git_stage",
    "git_stage_hunks_preflight",
    "git_stage_hunks",
)

_SPLIT_REQUIRED_FIELDS: Mapping[str, tuple[str, ...]] = {
    "browser_session_start": ("profile_id",),
    "browser_session_close": ("browser_session_id",),
    "desktop_runtime_start": ("profile_id",),
    "desktop_runtime_status": ("instance_id",),
    "desktop_runtime_logs": ("instance_id",),
    "desktop_runtime_stop": ("instance_id",),
}


def _expanded_names() -> tuple[str, ...]:
    names: list[str] = []
    for name in STABLE_PUBLIC_TOOL_NAMES:
        if name == "run_task":
            names.extend(item[0] for item in _RUN_TASK_SPLITS)
            continue
        if name == "browser_test_session":
            names.extend(item[0] for item in _BROWSER_SESSION_SPLITS)
            continue
        if name == "browser_action":
            names.extend(item[0] for item in _BROWSER_ACTION_SPLITS)
            continue
        if name == "desktop_runtime":
            names.extend(item[0] for item in _DESKTOP_RUNTIME_SPLITS)
            continue
        names.append(name)
        if name == "director_health":
            names.append("doctor_connection")
        if name == "director_status_summary":
            names.extend(_PROMOTED_DIRECT_TOOL_NAMES)
    return tuple(names)


V26_PUBLIC_TOOL_NAMES = _expanded_names()


def _annotations(
    *,
    title: str,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }


def _schema_for(template: Mapping[str, Any], *, keep: Sequence[str]) -> dict[str, Any]:
    schema = copy.deepcopy(dict(template.get("inputSchema") or {}))
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        properties = {}
        schema["properties"] = properties
    allowed = set(keep) | set(_WORKSPACE_BINDING_FIELDS)
    for key in list(properties):
        if key not in allowed:
            properties.pop(key, None)
    required = schema.get("required")
    if isinstance(required, list):
        schema["required"] = [key for key in required if key in properties]
    schema["additionalProperties"] = False
    return schema


def _tool_from_template(
    template: Mapping[str, Any],
    *,
    name: str,
    title: str,
    description: str,
    keep: Sequence[str],
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
) -> dict[str, Any]:
    tool = {
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": _schema_for(template, keep=keep),
        "outputSchema": copy.deepcopy(template.get("outputSchema") or {"type": "object"}),
        "annotations": _annotations(
            title=title,
            read_only=read_only,
            destructive=destructive,
            idempotent=idempotent,
            open_world=open_world,
        ),
    }
    required = _SPLIT_REQUIRED_FIELDS.get(name)
    if required:
        tool["inputSchema"]["required"] = list(required)
    return tool


def _project_safety_contract(
    template: Mapping[str, Any],
    contract: ToolContract,
) -> dict[str, Any]:
    tool = copy.deepcopy(dict(template))
    tool["title"] = str(contract.annotations.get("title") or tool.get("title") or contract.name)
    tool["description"] = contract.description
    tool["annotations"] = dict(contract.annotations)

    input_schema = copy.deepcopy(dict(tool.get("inputSchema") or {}))
    properties = input_schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError(f"{contract.name} input schema properties are missing")
    for name, guidance in contract.parameters.items():
        parameter = properties.get(name)
        if not isinstance(parameter, dict):
            raise ValueError(f"{contract.name} input schema is missing {name!r}")
        parameter["description"] = guidance
    tool["inputSchema"] = input_schema
    if contract.name == "workspace_integration_preflight":
        tool["x-devmcp-side-effects"] = "append_only_integration_preflight_evidence"
    return tool


def _project_readonly_path(template: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the durable handle lifecycle explicitly on the v26 surface."""

    tool = copy.deepcopy(dict(template))
    tool["title"] = "Manage bounded READ_ONLY path handle"
    tool["description"] = (
        "Open, inspect, or close one bounded local directory through a durable, TTL-bound READ_ONLY handle. "
        "The handle may be used across MCP child processes, but it never grants workspace, command, Git, session, "
        "writer, network, or arbitrary host capability authority. Path confinement and symlink checks remain active."
    )
    annotations = dict(tool.get("annotations") or {})
    annotations.update(
        {
            "title": tool["title"],
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        }
    )
    tool["annotations"] = annotations
    return tool


def _project_security_audit(template: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the read-only workflow boundary on the v26 surface.

    The v25 template is frozen, so this clarification belongs only to the
    versioned canary projection.
    """

    tool = copy.deepcopy(dict(template))
    tool["description"] = (
        "Perform a bounded fail-closed, READ_ONLY evaluation of profile, watchdog, patch, and verification findings. "
        "It appends an audit receipt but does not change task, session, or lease state; use director_task_ledger for an explicit workflow transition."
    )
    annotations = dict(tool.get("annotations") or {})
    annotations["readOnlyHint"] = True
    annotations["destructiveHint"] = False
    annotations["idempotentHint"] = True
    annotations["openWorldHint"] = False
    tool["annotations"] = annotations
    tool["x-devmcp-side-effects"] = "append_only_audit_evidence"
    return tool


def _project_browser_inspect(template: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the screenshot artifact write in the v26 combined tool."""

    tool = copy.deepcopy(dict(template))
    tool["description"] = (
        "Inspect one exact managed browser session. Snapshot, text, accessibility, console, network, and visual-diff "
        "observations do not persist page content; kind=screenshot writes one bounded managed artifact/baseline for "
        "later visual comparison. The artifact stays inside the managed browser cache and grants no workspace, "
        "filesystem, network, or control-plane authority."
    )
    annotations = dict(tool.get("annotations") or {})
    annotations.update(
        {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        }
    )
    tool["annotations"] = annotations
    tool["x-devmcp-side-effects"] = "managed_browser_observation_or_screenshot_artifact"
    return tool


_V26_DURABLE_EVIDENCE_DESCRIPTIONS: Mapping[str, str] = {
    "workspace_list_development_sessions": (
        "List bounded managed DEVELOPMENT sessions and live status observations. It does not mutate workspace, "
        "session, task, or lease authority; it appends only bounded non-secret observability evidence."
    ),
    "semantic_code_query": (
        "Query the bounded local semantic index. It does not mutate workspace or control-plane authority; it may "
        "append only bounded semantic evidence metadata without source content or secrets."
    ),
    "development_context": (
        "Build bounded task-aware context from the selected workspace/session. It does not mutate workspace or "
        "control-plane authority; it may append only bounded context evidence metadata without raw file content or secrets."
    ),
    "git_stage_preflight": (
        "Read-only Git staging preflight using a private temporary index. It never mutates the real index or repository, "
        "but records bounded durable Git preflight authority for the exact paired staging operation."
    ),
    "git_stage_paths_preflight": (
        "Read-only selective Git staging preflight using a private temporary index. It never mutates the real index or "
        "repository, but records bounded durable Git preflight authority for the exact paired staging operation."
    ),
    "git_stage_hunks_preflight": (
        "Read-only Git hunk preflight using a private temporary index. It never mutates the real index or repository, "
        "but records bounded durable Git preflight authority for the exact paired hunk-staging operation."
    ),
    "git_commit_preflight": (
        "Read-only staged Git commit preflight. It never mutates the repository, but records bounded durable Git "
        "preflight authority and closeout evidence for the exact paired commit operation."
    ),
    "git_verified_commit_preflight": (
        "Read-only verified Git commit preflight. It never mutates the repository, but records bounded durable Git "
        "preflight authority and closeout evidence for the exact paired commit operation."
    ),
    "git_push_preflight": (
        "Read-only Git push preflight. It never mutates the repository or remote, but records bounded durable Git "
        "preflight authority and closeout evidence for the exact paired push operation."
    ),
}


def _project_durable_evidence_tool(template: Mapping[str, Any], name: str) -> dict[str, Any]:
    tool = copy.deepcopy(dict(template))
    description = _V26_DURABLE_EVIDENCE_DESCRIPTIONS.get(name)
    if description is not None:
        tool["description"] = description
    side_effects = {
        "workspace_list_development_sessions": "append_only_observability_evidence",
        "semantic_code_query": "append_only_semantic_evidence",
        "development_context": "append_only_context_evidence",
        "git_stage_preflight": "durable_git_preflight_authority",
        "git_stage_paths_preflight": "durable_git_preflight_authority",
        "git_stage_hunks_preflight": "durable_git_preflight_authority",
        "git_commit_preflight": "durable_git_preflight_authority_and_closeout",
        "git_verified_commit_preflight": "durable_git_preflight_authority_and_closeout",
        "git_push_preflight": "durable_git_preflight_authority_and_closeout",
    }.get(name)
    if side_effects is not None:
        tool["x-devmcp-side-effects"] = side_effects
    return tool


def _browser_action_tool(
    template: Mapping[str, Any],
    *,
    name: str,
    action: str,
    title: str,
    description: str,
    params_keep: Sequence[str],
    destructive: bool,
    open_world: bool,
) -> dict[str, Any]:
    tool = _tool_from_template(
        template,
        name=name,
        title=title,
        description=description,
        keep=("browser_session_id", "params"),
        read_only=False,
        destructive=destructive,
        open_world=open_world,
    )
    input_schema = tool["inputSchema"]
    properties = input_schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("browser_action schema properties are missing")
    params_schema = properties.get("params")
    if not isinstance(params_schema, dict):
        raise ValueError("browser_action params schema is missing")
    params_schema = copy.deepcopy(params_schema)
    params_properties = params_schema.get("properties")
    if not isinstance(params_properties, dict):
        raise ValueError("browser_action params properties are missing")
    allowed = set(params_keep)
    missing = [key for key in params_keep if key not in params_properties]
    if missing:
        raise ValueError(f"browser_action params missing fields: {missing!r}")
    for key in list(params_properties):
        if key not in allowed:
            params_properties.pop(key, None)
    params_schema["required"] = list(params_keep)
    params_schema["additionalProperties"] = False
    properties["params"] = params_schema
    input_schema["required"] = ["browser_session_id", "params"]
    tool["x-devmcp-fixed-dispatch"] = {"tool": "browser_action", "action": action}
    return tool


def _doctor_tool(output_schema: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": "doctor_connection",
        "title": "Diagnose current HTTP connection",
        "description": "Classify the current v26 HTTP connection using bounded local health, connection metadata, and optional client schema evidence. It does not restart processes or mutate state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_schema": {
                    "type": "object",
                    "properties": {
                        "revision": {"type": "string", "minLength": 1, "maxLength": 80},
                        "count": {"type": "integer", "minimum": 0, "maximum": 4096},
                        "hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "available": {"type": "boolean"},
                        "status": {"type": "string", "maxLength": 40},
                    },
                    "additionalProperties": False,
                }
            },
            "additionalProperties": False,
        },
        "outputSchema": copy.deepcopy(dict(output_schema)),
        "annotations": _annotations(
            title="Diagnose current HTTP connection",
            read_only=True,
            idempotent=True,
        ),
    }


def build_v26_surface(
    definitions: Sequence[Mapping[str, Any]],
    authoritative_definitions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project frozen v25 plus current typed contracts into the v26 canary manifest."""

    buckets: dict[str, Mapping[str, Any]] = {}
    for item in definitions:
        name = item.get("name")
        if isinstance(name, str) and name in STABLE_PUBLIC_TOOL_NAMES:
            if name in buckets:
                raise ValueError(f"duplicate v25 tool definition: {name}")
            buckets[name] = item
    missing = [name for name in STABLE_PUBLIC_TOOL_NAMES if name not in buckets]
    if missing:
        raise ValueError(f"missing v25 tool definitions: {missing!r}")

    authoritative: dict[str, Mapping[str, Any]] = {}
    for item in authoritative_definitions:
        name = item.get("name")
        if isinstance(name, str) and name in _PROMOTED_DIRECT_TOOL_NAMES:
            if name in authoritative:
                raise ValueError(f"duplicate authoritative tool definition: {name}")
            authoritative[name] = item
    missing_promoted = [name for name in _PROMOTED_DIRECT_TOOL_NAMES if name not in authoritative]
    if missing_promoted:
        raise ValueError(f"missing authoritative tool definitions: {missing_promoted!r}")

    rendered: list[dict[str, Any]] = []
    for name in STABLE_PUBLIC_TOOL_NAMES:
        template = buckets[name]
        if name == "readonly_path":
            rendered.append(_project_readonly_path(template))
            continue
        if name == "browser_inspect":
            rendered.append(_project_browser_inspect(template))
            continue
        if name == "capability_catalog":
            tool = copy.deepcopy(dict(template))
            tool["description"] = (
                "Discover registered long-tail capabilities in two stages. Without prefix/category/shard/query filters, "
                "return only compact shard/category counts; with a filter, return bounded matching capability metadata. "
                "Deprecated capabilities are hidden unless explicitly requested."
            )
            schema = tool.get("inputSchema")
            if isinstance(schema, dict):
                properties = schema.get("properties")
                if isinstance(properties, dict):
                    include_deprecated = properties.get("include_deprecated")
                    if isinstance(include_deprecated, dict):
                        include_deprecated["default"] = False
            rendered.append(tool)
            continue
        if name == "director_health":
            rendered.append(copy.deepcopy(dict(template)))
            rendered.append(_doctor_tool(template.get("outputSchema") or {"type": "object"}))
            continue
        if name == "run_task":
            for public_name, task, title, description in _RUN_TASK_SPLITS:
                tool = _tool_from_template(
                    template,
                    name=public_name,
                    title=title,
                    description=description,
                    keep=("workdir", "timeout_ms", "yield_time_ms", "max_output_bytes"),
                    read_only=False,
                    destructive=True,
                    open_world=True,
                )
                tool["x-devmcp-fixed-dispatch"] = {"tool": "run_task", "task": task}
                rendered.append(tool)
            continue
        if name == "browser_test_session":
            for public_name, action, title, description, keep, read_only in _BROWSER_SESSION_SPLITS:
                tool = _tool_from_template(
                    template,
                    name=public_name,
                    title=title,
                    description=description,
                    keep=keep,
                    read_only=read_only,
                    destructive=not read_only,
                    open_world=not read_only,
                )
                tool["x-devmcp-fixed-dispatch"] = {"tool": "browser_test_session", "action": action}
                rendered.append(tool)
            continue
        if name == "browser_action":
            for public_name, action, title, description, params_keep, destructive, open_world in _BROWSER_ACTION_SPLITS:
                rendered.append(
                    _browser_action_tool(
                        template,
                        name=public_name,
                        action=action,
                        title=title,
                        description=description,
                        params_keep=params_keep,
                        destructive=destructive,
                        open_world=open_world,
                    )
                )
            continue
        if name == "desktop_runtime":
            for public_name, action, title, description, keep, read_only in _DESKTOP_RUNTIME_SPLITS:
                tool = _tool_from_template(
                    template,
                    name=public_name,
                    title=title,
                    description=description,
                    keep=keep,
                    read_only=read_only,
                    destructive=not read_only,
                    open_world=not read_only,
                )
                tool["x-devmcp-fixed-dispatch"] = {"tool": "desktop_runtime", "action": action}
                rendered.append(tool)
            continue
        contract = _SAFETY_CONTRACTS.get(name)
        if contract is not None:
            rendered.append(_project_safety_contract(template, contract))
        elif name in _V26_DURABLE_EVIDENCE_DESCRIPTIONS:
            rendered.append(_project_durable_evidence_tool(template, name))
        else:
            rendered.append(copy.deepcopy(dict(template)))
        if name == "director_status_summary":
            for promoted in _PROMOTED_DIRECT_TOOL_NAMES:
                if promoted == "security_audit":
                    rendered.append(_project_security_audit(authoritative[promoted]))
                elif promoted in _V26_DURABLE_EVIDENCE_DESCRIPTIONS:
                    rendered.append(_project_durable_evidence_tool(authoritative[promoted], promoted))
                else:
                    rendered.append(copy.deepcopy(dict(authoritative[promoted])))

    names = tuple(str(item.get("name", "")) for item in rendered)
    if names != V26_PUBLIC_TOOL_NAMES:
        raise ValueError("v26 public surface order mismatch")
    return rendered


_ALIAS_DISPATCH: dict[str, tuple[str, str, str]] = {
    **{name: ("run_task", "task", task) for name, task, _title, _description in _RUN_TASK_SPLITS},
    **{
        name: ("browser_test_session", "action", action)
        for name, action, _title, _description, _keep, _read_only in _BROWSER_SESSION_SPLITS
    },
    **{
        name: ("browser_action", "action", action)
        for name, action, _title, _description, _params_keep, _destructive, _open_world in _BROWSER_ACTION_SPLITS
    },
    **{
        name: ("desktop_runtime", "action", action)
        for name, action, _title, _description, _keep, _read_only in _DESKTOP_RUNTIME_SPLITS
    },
}


class V26RuntimeAdapter:
    """Expose v26 contracts while delegating execution to proven v25 handlers."""

    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self._connection_doctor: Callable[[Mapping[str, Any] | None], Mapping[str, Any]] | None = None
        enable_readonly = getattr(runtime, "enable_v26_readonly_continuity", None)
        if callable(enable_readonly):
            enable_readonly()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runtime, name)

    def bind_connection_doctor(
        self,
        callback: Callable[[Mapping[str, Any] | None], Mapping[str, Any]],
    ) -> None:
        if not callable(callback):
            raise TypeError("connection doctor callback must be callable")
        self._connection_doctor = callback

    def _v26_definitions(self) -> list[dict[str, Any]]:
        payload = self._runtime.list_tools()
        definitions = payload.get("tools", []) if isinstance(payload, Mapping) else []
        if not isinstance(definitions, list):
            raise TypeError("runtime tool registry must be a list")
        legacy_loader = getattr(self._runtime, "_legacy_tool_definitions", None)
        if not callable(legacy_loader):
            raise TypeError("runtime authoritative tool definitions are unavailable")
        authoritative_definitions = legacy_loader()
        if not isinstance(authoritative_definitions, list):
            raise TypeError("runtime authoritative tool registry must be a list")
        return build_v26_surface(definitions, authoritative_definitions)

    def _pin_v26_schema_identity(self) -> list[dict[str, Any]]:
        definitions = self._v26_definitions()
        pin = getattr(self._runtime, "pin_request_schema_identity", None)
        if callable(pin):
            pin(definitions, revision=V26_SURFACE_REVISION)
        return definitions

    def list_tools(self) -> dict[str, Any]:
        return {"tools": self._pin_v26_schema_identity()}

    def _v26_schema_metadata(self) -> dict[str, Any]:
        definitions = self.list_tools()["tools"]
        return tool_schema_metadata(definitions, revision=V26_SURFACE_REVISION)

    @staticmethod
    def _project_health_schema(health: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
        projected = copy.deepcopy(dict(health))
        consistency = dict(projected.get("schema_consistency") or {})
        consistency.update(
            {
                "status": "consistent",
                "local_tool_schema": dict(schema),
                "listed_tool_schema": dict(schema),
                "checks": {"count_match": True, "hash_match": True, "revision_match": True},
            }
        )
        projected["schema_consistency"] = consistency
        return projected

    def _project_director_health(self, args: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        if bool(result.get("isError")):
            return dict(result)
        raw_payload = result.get("structuredContent")
        if not isinstance(raw_payload, Mapping):
            return dict(result)

        payload = copy.deepcopy(dict(raw_payload))
        schema = self._v26_schema_metadata()
        raw_health = payload.get("health")
        health = self._project_health_schema(raw_health if isinstance(raw_health, Mapping) else {}, schema)
        payload["health"] = health

        client_raw = args.get("client_schema") if isinstance(args.get("client_schema"), Mapping) else None
        local_observation = SchemaObservation.from_mapping(schema)
        client_observation = SchemaObservation.from_mapping(client_raw) if client_raw is not None else None
        runtime = health.get("runtime") if isinstance(health.get("runtime"), Mapping) else {}
        registry = health.get("registry") if isinstance(health.get("registry"), Mapping) else {}
        registry_status = str(registry.get("status", "unknown"))
        if registry_status not in {"valid", "degraded", "invalid", "unknown"}:
            registry_status = "unknown"
        observed_at = time.time()
        watchdog = evaluate_watchdog(
            WatchdogSnapshot(
                observed_at=observed_at,
                transport="connected",
                server_ready=runtime.get("status") == "alive",
                local_schema=local_observation,
                client_schema=client_observation,
                registry_status=registry_status,
                registry_error_codes=tuple(
                    str(code)
                    for code in registry.get("config_error_codes", [])
                    if isinstance(code, str)
                ),
            ),
            now=observed_at,
        )
        audit = audit_watchdog(watchdog)

        definitions = self.list_tools()["tools"]
        server_tools = sorted(
            item["name"] for item in definitions if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        )
        client_tools: list[str] = []
        if client_raw is not None and isinstance(client_raw.get("tools"), list):
            client_tools = sorted({str(name) for name in client_raw["tools"] if isinstance(name, str)})
        client_schema_evidence = classify_client_schema_evidence(
            local_schema=schema,
            client_schema=dict(client_raw) if client_raw is not None else None,
            transport_reports_client_schema=False,
        )
        metadata_mismatch = client_schema_evidence.status in {"stale", "mismatch", "unavailable"}
        missing_on_client = sorted(set(server_tools) - set(client_tools)) if client_tools else []
        extra_on_client = sorted(set(client_tools) - set(server_tools)) if client_tools else []
        rescan_required = bool(metadata_mismatch or missing_on_client or extra_on_client)
        schema_compatibility = {
            "server_schema": dict(schema),
            "client_schema": dict(client_raw) if client_raw is not None else None,
            "missing_on_client": missing_on_client,
            "extra_on_client": extra_on_client,
            "rescan_required": rescan_required,
            "error_code": "CLIENT_TOOL_SCHEMA_STALE" if rescan_required else None,
        }
        payload.update(
            {
                "watchdog": watchdog.as_dict(),
                "audit": audit.as_dict(),
                "schema_compatibility": schema_compatibility,
                "client_schema_evidence": client_schema_evidence.as_dict(),
                "server_schema": dict(schema),
                "client_schema": dict(client_raw) if client_raw is not None else None,
                "missing_on_client": missing_on_client,
                "extra_on_client": extra_on_client,
                "rescan_required": rescan_required,
                "schema_error_code": "CLIENT_TOOL_SCHEMA_STALE" if rescan_required else None,
            }
        )
        return make_tool_result("director_health", payload, is_error=False)

    def _project_server_info(self, result: Mapping[str, Any]) -> dict[str, Any]:
        if bool(result.get("isError")):
            return dict(result)
        raw_payload = result.get("structuredContent")
        if not isinstance(raw_payload, Mapping):
            return dict(result)
        payload = copy.deepcopy(dict(raw_payload))
        definitions = self.list_tools()["tools"]
        schema = self._v26_schema_metadata()
        payload["tools"] = [item["name"] for item in definitions]
        payload["tool_count"] = len(definitions)
        payload["tool_schema"] = dict(schema)
        raw_health = payload.get("health")
        if isinstance(raw_health, Mapping):
            payload["health"] = self._project_health_schema(raw_health, schema)
        reattach = payload.get("reattach_handshake")
        if isinstance(reattach, Mapping):
            projected_reattach = dict(reattach)
            projected_reattach.update(
                {
                    "registry_version": V26_SURFACE_REVISION,
                    "registry_hash": schema["hash"],
                    "schema_revision": V26_SURFACE_REVISION,
                    "schema_digest": schema["hash"],
                }
            )
            payload["reattach_handshake"] = projected_reattach
        return make_tool_result("server_info", payload, is_error=False)

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        *,
        request_id: str | int | None = None,
    ) -> dict[str, Any]:
        args = dict(arguments or {})
        self._pin_v26_schema_identity()
        if name == "server_info":
            return self._project_server_info(self._runtime.call_tool(name, args, request_id=request_id))
        if name == "director_health":
            return self._project_director_health(
                args,
                self._runtime.call_tool(name, args, request_id=request_id),
            )
        if name == "capability_catalog":
            include_deprecated = args.get("include_deprecated", False)
            if not isinstance(include_deprecated, bool):
                return self._runtime.call_tool(name, args, request_id=request_id)
            args["include_deprecated"] = include_deprecated
            has_filter = any(
                isinstance(args.get(field), str) and bool(str(args[field]).strip())
                for field in ("prefix", "category", "shard", "query")
            )
            if has_filter:
                return self._runtime.call_tool(name, args, request_id=request_id)
            gateway = getattr(self._runtime, "_stable_capability_gateway", None)
            overview = getattr(gateway, "overview", None)
            if not callable(overview):
                payload = {
                    "error": "CAPABILITY_OVERVIEW_UNAVAILABLE",
                    "message": "The runtime does not expose bounded capability overview metadata.",
                    "ok": False,
                }
                return make_tool_result(name, payload, is_error=True)
            payload = dict(overview(include_deprecated=include_deprecated))
            payload.setdefault("ok", True)
            return make_tool_result(name, payload, is_error=False)

        if name == "doctor_connection":
            if self._connection_doctor is None:
                payload = {
                    "failure_class": "TRANSPORT_SESSION_FAILURE",
                    "recommended_actions": ["create_fresh_transport_session"],
                    "reason": "connection_observation_unavailable",
                    "ok": False,
                }
                return make_tool_result(name, payload, is_error=True)
            client_schema = args.get("client_schema")
            payload = dict(
                self._connection_doctor(
                    client_schema if isinstance(client_schema, Mapping) else None
                )
            )
            payload.setdefault("ok", True)
            return make_tool_result(name, payload, is_error=False)

        dispatch = _ALIAS_DISPATCH.get(name)
        if dispatch is not None:
            target, discriminator, value = dispatch
            args.pop(discriminator, None)
            args[discriminator] = value
            return self._runtime.call_tool(target, args, request_id=request_id)
        return self._runtime.call_tool(name, args, request_id=request_id)

    def close(self) -> None:
        self._runtime.close()


__all__ = [
    "V26_PUBLIC_TOOL_NAMES",
    "V26_SURFACE_REVISION",
    "V26RuntimeAdapter",
    "build_v26_surface",
]
