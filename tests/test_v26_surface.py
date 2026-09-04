from __future__ import annotations

import unittest

from chatgpt_dev_mcp.observability import tool_schema_metadata
from chatgpt_dev_mcp.server import WrapperRuntime
from chatgpt_dev_mcp.tool_contract_policy import (
    INTEGRATION_EXECUTE_CONTRACT,
    INTEGRATION_PREFLIGHT_CONTRACT,
)
from chatgpt_dev_mcp.stable_surface import (
    STABLE_SURFACE_REVISION,
    V25_STABLE_SCHEMA_HASH,
    validate_frozen_v25_schema,
)
from chatgpt_dev_mcp.v26_surface import (
    V26_PUBLIC_TOOL_NAMES,
    V26_SURFACE_REVISION,
    V26RuntimeAdapter,
    build_v26_surface,
)


class _RecordingRuntime:
    protocol_version = "2025-11-25"
    initialized = True

    def __init__(
        self,
        definitions: list[dict[str, object]],
        legacy_definitions: list[dict[str, object]] | None = None,
    ) -> None:
        self.definitions = definitions
        self.legacy_definitions = legacy_definitions or definitions
        self.calls: list[tuple[str, dict[str, object], object]] = []

    def list_tools(self) -> dict[str, object]:
        return {"tools": self.definitions}

    def _legacy_tool_definitions(self) -> list[dict[str, object]]:
        return self.legacy_definitions

    def call_tool(self, name: str, arguments: dict[str, object] | None, *, request_id=None):
        args = dict(arguments or {})
        self.calls.append((name, args, request_id))
        return {"structuredContent": {"name": name, "arguments": args}, "isError": False}

    def close(self) -> None:
        return None


class V26SurfaceTests(unittest.TestCase):
    def _v25_definitions(self) -> list[dict[str, object]]:
        runtime = WrapperRuntime()
        try:
            return runtime.list_tools()["tools"]
        finally:
            runtime.close()

    def _legacy_definitions(self) -> list[dict[str, object]]:
        runtime = WrapperRuntime()
        try:
            return runtime._legacy_tool_definitions()
        finally:
            runtime.close()

    def test_v25_schema_remains_frozen_while_v26_gets_distinct_revision(self) -> None:
        v25 = self._v25_definitions()
        frozen = validate_frozen_v25_schema(v25)
        self.assertEqual(frozen["status"], "valid")
        self.assertEqual(frozen["revision"], STABLE_SURFACE_REVISION)
        self.assertEqual(frozen["hash"], V25_STABLE_SCHEMA_HASH)
        self.assertEqual(V26_SURFACE_REVISION, "tool-registry-v26-canary")
        self.assertNotEqual(V26_SURFACE_REVISION, STABLE_SURFACE_REVISION)

    def test_v26_splits_materially_broad_tools_instead_of_targeting_v25_count(self) -> None:
        definitions = build_v26_surface(self._v25_definitions(), self._legacy_definitions())
        names = [item["name"] for item in definitions]

        self.assertEqual(tuple(names), V26_PUBLIC_TOOL_NAMES)
        self.assertEqual(len(names), 76)
        self.assertEqual(len(set(names)), 76)
        for broad_name in ("run_task", "desktop_runtime", "browser_test_session", "browser_action"):
            self.assertNotIn(broad_name, names)

        for dedicated_name in (
            "run_tests",
            "run_lint",
            "run_build",
            "run_dev",
            "run_format",
            "browser_profile_list",
            "browser_session_start",
            "browser_session_close",
            "browser_navigate",
            "browser_click",
            "browser_type",
            "browser_keyboard",
            "browser_viewport",
            "browser_wait",
            "desktop_profile_list",
            "desktop_runtime_start",
            "desktop_runtime_status",
            "desktop_runtime_logs",
            "desktop_runtime_snapshot",
            "desktop_runtime_stop",
            "doctor_connection",
            "security_audit",
            "director_task_ledger",
            "director_writer_lease",
            "git_stage_preflight",
            "git_stage",
            "git_stage_hunks_preflight",
            "git_stage_hunks",
        ):
            self.assertIn(dedicated_name, names)

        for gateway_only_name in (
            "director_baseline_snapshot",
            "director_audit_log",
            "patch_preflight",
            "git_verified_commit_preflight",
            "git_verified_commit",
        ):
            self.assertNotIn(gateway_only_name, names)

    def test_v26_dedicated_schemas_remove_generic_action_discriminators(self) -> None:
        definitions = {
            item["name"]: item
            for item in build_v26_surface(self._v25_definitions(), self._legacy_definitions())
        }

        for name in ("run_tests", "run_lint", "run_build", "run_dev", "run_format"):
            schema = definitions[name]["inputSchema"]
            self.assertNotIn("task", schema["properties"])
            self.assertNotIn("task", schema.get("required", []))

        for name in (
            "browser_profile_list",
            "browser_session_start",
            "browser_session_close",
            "desktop_profile_list",
            "desktop_runtime_start",
            "desktop_runtime_status",
            "desktop_runtime_logs",
            "desktop_runtime_snapshot",
            "desktop_runtime_stop",
        ):
            schema = definitions[name]["inputSchema"]
            self.assertNotIn("action", schema["properties"])
            self.assertNotIn("action", schema.get("required", []))

        self.assertTrue(definitions["desktop_runtime_status"]["annotations"]["readOnlyHint"])
        self.assertTrue(definitions["desktop_runtime_logs"]["annotations"]["readOnlyHint"])
        self.assertFalse(definitions["desktop_runtime_start"]["annotations"]["readOnlyHint"])
        self.assertFalse(definitions["browser_session_start"]["annotations"]["readOnlyHint"])

        self.assertIn("profile_id", definitions["browser_session_start"]["inputSchema"]["required"])
        self.assertIn("browser_session_id", definitions["browser_session_close"]["inputSchema"]["required"])
        self.assertIn("profile_id", definitions["desktop_runtime_start"]["inputSchema"]["required"])
        self.assertIn("instance_id", definitions["desktop_runtime_status"]["inputSchema"]["required"])
        self.assertIn("instance_id", definitions["desktop_runtime_logs"]["inputSchema"]["required"])
        self.assertIn("instance_id", definitions["desktop_runtime_stop"]["inputSchema"]["required"])

        browser_expected = {
            "browser_navigate": {"url"},
            "browser_click": {"selector"},
            "browser_type": {"selector", "value"},
            "browser_keyboard": {"key"},
            "browser_viewport": {"width", "height"},
            "browser_wait": {"milliseconds"},
        }
        for name, expected_params in browser_expected.items():
            schema = definitions[name]["inputSchema"]
            self.assertNotIn("action", schema["properties"])
            params = schema["properties"]["params"]
            self.assertEqual(set(params["properties"]), expected_params)
            self.assertEqual(set(params["required"]), expected_params)

        self.assertTrue(definitions["browser_navigate"]["annotations"]["openWorldHint"])
        self.assertFalse(definitions["browser_wait"]["annotations"]["openWorldHint"])
        self.assertFalse(definitions["browser_viewport"]["annotations"]["destructiveHint"])

    def test_promoted_direct_tools_preserve_existing_authoritative_contracts(self) -> None:
        legacy = {item["name"]: item for item in self._legacy_definitions()}
        definitions = {
            item["name"]: item
            for item in build_v26_surface(self._v25_definitions(), list(legacy.values()))
        }
        promoted = (
            "security_audit",
            "director_task_ledger",
            "director_writer_lease",
            "git_stage_preflight",
            "git_stage",
            "git_stage_hunks_preflight",
            "git_stage_hunks",
        )
        for name in promoted:
            self.assertEqual(definitions[name]["inputSchema"], legacy[name]["inputSchema"])
            self.assertEqual(definitions[name]["outputSchema"], legacy[name]["outputSchema"])
            self.assertEqual(definitions[name]["annotations"], legacy[name]["annotations"])

    def test_v26_capability_catalog_uses_two_stage_discovery_without_changing_v25(self) -> None:
        runtime = WrapperRuntime()
        try:
            v25_definition = {
                item["name"]: item for item in runtime.list_tools()["tools"]
            }["capability_catalog"]
            self.assertTrue(v25_definition["inputSchema"]["properties"]["include_deprecated"]["default"])

            v25_result = runtime.call_tool("capability_catalog", {})["structuredContent"]
            self.assertIn("capabilities", v25_result)
            self.assertNotIn("mode", v25_result)
            self.assertEqual(
                v25_result["registry"]["count"],
                sum(shard["count"] for shard in v25_result["registry"]["shards"]),
            )
            self.assertEqual(len(runtime.list_tools()["tools"]), 52)

            adapter = V26RuntimeAdapter(runtime)
            self.assertEqual(len(adapter.list_tools()["tools"]), 76)
            v26_definition = {
                item["name"]: item for item in adapter.list_tools()["tools"]
            }["capability_catalog"]
            self.assertFalse(v26_definition["inputSchema"]["properties"]["include_deprecated"]["default"])

            overview = adapter.call_tool("capability_catalog", {})["structuredContent"]
            self.assertEqual(overview["mode"], "overview")
            self.assertFalse(overview["include_deprecated"])
            self.assertEqual(overview["capabilities"], [])
            self.assertGreater(len(overview["shards"]), 0)

            filtered = adapter.call_tool("capability_catalog", {"shard": "delivery"})["structuredContent"]
            self.assertIn("capabilities", filtered)
            self.assertNotEqual(filtered["capabilities"], [])
            self.assertTrue(all(item["shard"] == "delivery" for item in filtered["capabilities"]))
            self.assertTrue(all(not item["deprecated"] for item in filtered["capabilities"]))

            organization = adapter.call_tool(
                "capability_catalog",
                {"category": "workspace_organization"},
            )["structuredContent"]
            organization_ids = {item["capability_id"] for item in organization["capabilities"]}
            self.assertEqual(
                organization_ids,
                {"project_group_create", "workspace_relocate_preflight", "workspace_relocate"},
            )
            described = adapter.call_tool(
                "capability_describe",
                {"capability_id": "workspace_relocate"},
            )["structuredContent"]
            self.assertEqual(described["approval_policy"], "delegated")
            self.assertEqual(described["exposure"], "registry")
        finally:
            runtime.close()

    def test_v26_projects_shared_integration_safety_contract_without_mutating_v25(self) -> None:
        v25 = self._v25_definitions()
        frozen_before = validate_frozen_v25_schema(v25)
        definitions = {
            item["name"]: item
            for item in build_v26_surface(v25, self._legacy_definitions())
        }

        preflight = definitions["workspace_integration_preflight"]
        execute = definitions["workspace_integrate_development_session"]

        self.assertEqual(preflight["description"], INTEGRATION_PREFLIGHT_CONTRACT.description)
        self.assertEqual(execute["description"], INTEGRATION_EXECUTE_CONTRACT.description)
        self.assertEqual(execute["annotations"], dict(INTEGRATION_EXECUTE_CONTRACT.annotations))
        for name, guidance in INTEGRATION_EXECUTE_CONTRACT.parameters.items():
            self.assertEqual(execute["inputSchema"]["properties"][name]["description"], guidance)
        for name, guidance in INTEGRATION_PREFLIGHT_CONTRACT.parameters.items():
            self.assertEqual(preflight["inputSchema"]["properties"][name]["description"], guidance)

        frozen_after = validate_frozen_v25_schema(v25)
        self.assertEqual(frozen_before, frozen_after)
        self.assertEqual(frozen_after["hash"], V25_STABLE_SCHEMA_HASH)

    def test_runtime_adapter_pins_underlying_task_and_action(self) -> None:
        base = _RecordingRuntime(self._v25_definitions(), self._legacy_definitions())
        adapter = V26RuntimeAdapter(base)

        adapter.call_tool("run_tests", {"workdir": "."}, request_id="r1")
        adapter.call_tool("browser_session_start", {"profile_id": "chromium"}, request_id="r2")
        adapter.call_tool("desktop_runtime_logs", {"instance_id": "desktop-1"}, request_id="r3")
        adapter.call_tool(
            "browser_click",
            {"browser_session_id": "browser-1", "params": {"selector": "#buy"}},
            request_id="r4",
        )
        adapter.call_tool("security_audit", {"workspace_id": "workspace-a"}, request_id="r5")

        self.assertEqual(base.calls[0], ("run_task", {"workdir": ".", "task": "test"}, "r1"))
        self.assertEqual(base.calls[1], ("browser_test_session", {"profile_id": "chromium", "action": "start"}, "r2"))
        self.assertEqual(base.calls[2], ("desktop_runtime", {"instance_id": "desktop-1", "action": "logs"}, "r3"))
        self.assertEqual(
            base.calls[3],
            (
                "browser_action",
                {"browser_session_id": "browser-1", "params": {"selector": "#buy"}, "action": "click"},
                "r4",
            ),
        )
        self.assertEqual(base.calls[4], ("security_audit", {"workspace_id": "workspace-a"}, "r5"))

    def test_v26_request_audit_is_pinned_to_the_adapter_generation(self) -> None:
        runtime = WrapperRuntime()
        runtime.logical_connection_id = "logical:v26-test"
        try:
            adapter = V26RuntimeAdapter(runtime)
            schema = tool_schema_metadata(adapter.list_tools()["tools"], revision=V26_SURFACE_REVISION)
            request_id = f"v26-audit-request-{runtime.child_instance_id}"
            result = adapter.call_tool("workspace_list", {}, request_id=request_id)
            self.assertFalse(result["isError"], result)
            events = runtime._persistence.load_request_lifecycle_events(request_id=request_id, limit=20)
            self.assertTrue(events)
            self.assertTrue(all(event["server_schema_revision"] == V26_SURFACE_REVISION for event in events))
            self.assertTrue(all(event["server_schema_hash"] == schema["hash"] for event in events))
            self.assertTrue(all(event["transport_generation"] == 1 for event in events))
            self.assertTrue(all(event["child_instance_id"] == runtime.child_instance_id for event in events))
            self.assertTrue(all(event["logical_connection_id"] == "logical:v26-test" for event in events))
        finally:
            runtime.close()

    def test_doctor_connection_is_direct_read_only_v26_tool(self) -> None:
        base = _RecordingRuntime(self._v25_definitions(), self._legacy_definitions())
        adapter = V26RuntimeAdapter(base)
        adapter.bind_connection_doctor(lambda client_schema=None: {"failure_class": "HEALTHY", "client_schema": client_schema or {}})

        result = adapter.call_tool("doctor_connection", {"client_schema": {"revision": V26_SURFACE_REVISION}})
        self.assertEqual(result["structuredContent"]["failure_class"], "HEALTHY")
        self.assertEqual(base.calls, [])

        definition = {item["name"]: item for item in adapter.list_tools()["tools"]}["doctor_connection"]
        self.assertTrue(definition["annotations"]["readOnlyHint"])
        self.assertFalse(definition["annotations"]["destructiveHint"])
        self.assertFalse(definition["annotations"]["openWorldHint"])

    def test_v26_director_health_uses_v26_schema_for_watchdog_and_nested_evidence(self) -> None:
        runtime = WrapperRuntime()
        try:
            adapter = V26RuntimeAdapter(runtime)
            schema = tool_schema_metadata(adapter.list_tools()["tools"], revision=V26_SURFACE_REVISION)
            result = adapter.call_tool("director_health", {"client_schema": schema})
            self.assertFalse(result["isError"], result)
            health = result["structuredContent"]

            self.assertNotEqual(health["watchdog"]["status"], "blocked")
            self.assertTrue(health["watchdog"]["schema_consistent"])
            self.assertNotIn("SCHEMA_MISMATCH", health["watchdog"]["reasons"])
            self.assertNotEqual(health["audit"]["status"], "blocked")
            self.assertFalse(health["schema_compatibility"]["rescan_required"])
            self.assertEqual(health["server_schema"], schema)
            self.assertEqual(health["health"]["schema_consistency"]["local_tool_schema"], schema)
            self.assertEqual(health["health"]["schema_consistency"]["listed_tool_schema"], schema)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
