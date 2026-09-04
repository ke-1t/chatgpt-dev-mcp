from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry
from chatgpt_dev_mcp.chatgpt_connector_compat import InitializeReplayState
from chatgpt_dev_mcp.observability import tool_schema_metadata
from chatgpt_dev_mcp.stable_surface import (
    STABLE_SURFACE_REVISION,
    V25_STABLE_SCHEMA_HASH,
    validate_frozen_v25_schema,
)


class _ToolListRuntime:
    def __init__(self, tools: list[dict[str, object]]) -> None:
        self.tools = tools

    def list_tools(self) -> dict[str, object]:
        return {"tools": self.tools}


class StableGatewaySchemaStabilityTests(unittest.TestCase):
    def _runtime(self, root: Path):
        from chatgpt_dev_mcp.server import WrapperRuntime

        env = {
            "HOME": str(root / "home"),
            "LOCAL_DEV_MCP_CONFIG": str(root / "config.json"),
            "LOCAL_DEV_MCP_DATA_DIR": str(root / "data"),
            "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
            "CHATGPT_DEV_MCP_SURFACE": "stable_gateway",
        }
        return patch.dict(os.environ, env), WrapperRuntime

    @staticmethod
    def _public_schema_snapshot(runtime) -> dict[str, object]:
        tools = runtime.list_tools()["tools"]
        metadata = tool_schema_metadata(tools, revision=STABLE_SURFACE_REVISION)
        return {
            "names": tuple(item["name"] for item in tools),
            "schemas": tools,
            "count": metadata["count"],
            "hash": metadata["hash"],
            "revision": metadata["revision"],
        }

    @staticmethod
    def _registry_with_dummy(runtime) -> CompositeCapabilityRegistry:
        current = runtime._stable_capability_registry
        shards: list[CapabilityRegistry] = []
        for shard_id in current.shard_ids:
            source = current._registries[shard_id]
            clone = CapabilityRegistry(list(source._specs.values()), shard_id=shard_id)
            if shard_id == "qa":
                template = source.get("platform.profile.register")
                clone.register(
                    replace(
                        template,
                        capability_id="qa.schema_stability_dummy",
                        description="Schema-stability acceptance-test capability.",
                        handler="schema_stability_dummy",
                        handler_version="1",
                    )
                )
            shards.append(clone)
        return CompositeCapabilityRegistry(shards).freeze()

    def test_registry_addition_changes_internal_catalog_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    before_public = self._public_schema_snapshot(runtime)
                    before_registry = runtime._stable_capability_registry.metadata()
                    before_catalog = runtime.call_tool("capability_catalog", {"limit": 100})["structuredContent"]

                    replacement_registry = self._registry_with_dummy(runtime)
                    runtime._stable_capability_registry = replacement_registry
                    runtime._stable_capability_gateway.registry = replacement_registry

                    after_public = self._public_schema_snapshot(runtime)
                    after_registry = replacement_registry.metadata()
                    after_catalog = runtime.call_tool("capability_catalog", {"limit": 100})["structuredContent"]

                    self.assertEqual(before_public["names"], after_public["names"])
                    self.assertEqual(before_public["count"], 52)
                    self.assertEqual(after_public["count"], 52)
                    self.assertEqual(before_public["revision"], STABLE_SURFACE_REVISION)
                    self.assertEqual(after_public["revision"], STABLE_SURFACE_REVISION)
                    self.assertEqual(before_public["hash"], after_public["hash"])
                    self.assertEqual(before_public["schemas"], after_public["schemas"])
                    self.assertEqual(after_catalog["count"], before_catalog["count"] + 1)
                    self.assertEqual(after_registry["count"], before_registry["count"] + 1)
                    self.assertNotEqual(after_registry["hash"], before_registry["hash"])
                finally:
                    runtime.close()

    def test_v25_public_schema_is_pinned_to_exact_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    tools = runtime.list_tools()["tools"]
                    result = validate_frozen_v25_schema(tools)

                    self.assertEqual(
                        V25_STABLE_SCHEMA_HASH,
                        "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
                    )
                    self.assertEqual(result["status"], "valid")
                    self.assertTrue(result["revision_match"])
                    self.assertTrue(result["count_match"])
                    self.assertTrue(result["hash_match"])
                finally:
                    runtime.close()

    def test_v25_freeze_guard_identifies_description_and_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    tools = runtime.list_tools()["tools"]
                    changed = [dict(item) for item in tools]
                    changed[0] = dict(changed[0])
                    changed[0]["description"] = f"{changed[0]['description']} drift"

                    description_drift = validate_frozen_v25_schema(changed)
                    missing_tool = validate_frozen_v25_schema(tools[:-1])

                    self.assertEqual(description_drift["status"], "invalid")
                    self.assertEqual(description_drift["mismatches"], ["hash"])
                    self.assertFalse(description_drift["hash_match"])
                    self.assertEqual(missing_tool["status"], "invalid")
                    self.assertEqual(missing_tool["mismatches"], ["count", "hash"])
                    self.assertFalse(missing_tool["count_match"])
                    self.assertFalse(missing_tool["hash_match"])
                finally:
                    runtime.close()

    def test_list_changed_is_not_queued_when_public_schema_is_unchanged(self) -> None:
        runtime = _ToolListRuntime([{"name": "server_info", "inputSchema": {"type": "object"}}])
        state = InitializeReplayState()
        state.observe_public_tool_schema(runtime, notify=False)
        state.mark_client_initialized(runtime)
        state.observe_public_tool_schema(runtime)
        self.assertEqual(state.pop_pending_notifications(), [])

    def test_list_changed_is_queued_once_when_public_schema_changes(self) -> None:
        runtime = _ToolListRuntime([{"name": "server_info", "inputSchema": {"type": "object"}}])
        state = InitializeReplayState()
        state.observe_public_tool_schema(runtime, notify=False)
        state.mark_client_initialized(runtime)
        runtime.tools.append({"name": "new_public_tool", "inputSchema": {"type": "object"}})
        self.assertTrue(state.observe_public_tool_schema(runtime))
        self.assertEqual(
            state.pop_pending_notifications(),
            [{"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}}],
        )
        self.assertEqual(state.pop_pending_notifications(), [])

    def test_list_changed_is_not_queued_before_client_initialized(self) -> None:
        runtime = _ToolListRuntime([{"name": "server_info", "inputSchema": {"type": "object"}}])
        state = InitializeReplayState()
        state.observe_public_tool_schema(runtime, notify=False)
        runtime.tools.append({"name": "new_public_tool", "inputSchema": {"type": "object"}})
        self.assertTrue(state.observe_public_tool_schema(runtime))
        self.assertEqual(state.pop_pending_notifications(), [])


if __name__ == "__main__":
    unittest.main()
