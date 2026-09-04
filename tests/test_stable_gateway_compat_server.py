from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class StableGatewayCompatibilityServerTests(unittest.TestCase):
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

    def _fixture(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "fixture": {
                            "path": str(repo),
                            "profile": "DEVELOPMENT",
                            "commands": {},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return config

    def test_stable_catalog_contains_hidden_v24_tools_typed_alias_and_p2_registry_capabilities(self) -> None:
        from chatgpt_dev_mcp.stable_registry_inventory import REGISTRY_TOOL_NAMES

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    public_names = {item["name"] for item in runtime.list_tools()["tools"]}
                    self.assertEqual(len(public_names), 52)
                    self.assertFalse(set(REGISTRY_TOOL_NAMES) & public_names)

                    result = runtime.call_tool("capability_catalog", {"limit": 100})
                    self.assertFalse(result["isError"], result)
                    catalog = result["structuredContent"]
                    capability_names = {item["capability_id"] for item in catalog["capabilities"]}
                    self.assertEqual(catalog["returned"], len(capability_names))
                    self.assertEqual(catalog["returned"], min(100, catalog["count"]))
                    self.assertGreaterEqual(catalog["count"], catalog["returned"])
                    for capability_id in REGISTRY_TOOL_NAMES:
                        if capability_id in capability_names:
                            continue
                        described = runtime.call_tool("capability_describe", {"capability_id": capability_id})
                        self.assertFalse(described["isError"], described)
                        self.assertEqual(described["structuredContent"]["capability_id"], capability_id)
                    self.assertIn("platform.profile.register", capability_names)
                    self.assertIn("platform.credential.register", capability_names)
                    self.assertIn("external.capability.invoke", capability_names)
                    self.assertIn("platform.macos_app.replace", capability_names)
                    self.assertIn("context.bootstrap", capability_names)
                    self.assertIn("context.focus", capability_names)
                    self.assertIn("context.checkpoint", capability_names)
                    self.assertIn("performance.summary", capability_names)
                    self.assertNotIn("development.cloud_compute", capability_names)
                    self.assertNotIn("development.openai_api_compute", capability_names)
                    self.assertNotIn("development.openai_probe", capability_names)
                    self.assertIn("development.analysis_pack", capability_names)
                    self.assertIn("development.session.abandon", capability_names)
                    self.assertTrue(
                        {
                            "external_open",
                            "workspace.trust.enable",
                            "workspace.trust.revoke",
                            "delivery.integrate",
                            "delivery.push",
                        }.issubset(capability_names)
                    )
                finally:
                    runtime.close()

    def test_hidden_readonly_tool_executes_via_gateway_and_preserves_workspace_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    params = {"workspace_id": "fixture"}
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "capability_id": "workspace_project_policy_get",
                            "params": params,
                        },
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertFalse(preflight["approval_required"])

                    executed = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "workspace_project_policy_get",
                            "params": params,
                        },
                    )
                    self.assertFalse(executed["isError"], executed)
                    self.assertEqual(executed["structuredContent"]["result"]["workspace_id"], "fixture")
                finally:
                    runtime.close()

    def test_delegated_mutation_still_requires_underlying_typed_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    params = {"preflight_id": "missing-preflight", "confirmation": "not-approved"}
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "capability_id": "workspace_unregister",
                            "params": params,
                        },
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertFalse(preflight["approval_required"])

                    executed = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "workspace_unregister",
                            "params": params,
                        },
                    )
                    self.assertTrue(executed["isError"], executed)
                    self.assertNotEqual(executed["structuredContent"]["error"]["code"], "CAPABILITY_APPROVAL_REQUIRED")
                    self.assertIn("PREFLIGHT", executed["structuredContent"]["error"]["code"])
                finally:
                    runtime.close()

    def test_workspace_project_create_r3_requires_one_outer_human_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            environment, runtime_type = self._runtime(root)
            with environment:
                runtime = runtime_type()
                try:
                    described = runtime.call_tool(
                        "capability_describe",
                        {"capability_id": "workspace_project_create"},
                    )["structuredContent"]
                    self.assertEqual(described["risk_class"], "R3")
                    self.assertEqual(described["approval_policy"], "human")

                    params = {
                        "project_id": "new-project",
                        "directory_name": "new-project",
                        "root_id": "developer",
                        "initialize_git": True,
                        "project_type": "EMPTY",
                        "auto_start_development": False,
                    }
                    target = root / "new-project"
                    preflight_outer = runtime.call_tool(
                        "capability_preflight",
                        {"capability_id": "workspace_project_create", "params": params},
                    )
                    self.assertFalse(preflight_outer["isError"], preflight_outer)
                    preflight = preflight_outer["structuredContent"]
                    self.assertTrue(preflight["approval_required"])
                    self.assertFalse(target.exists())

                    denied = runtime.call_tool(
                        "capability_execute",
                        {
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "workspace_project_create",
                            "params": params,
                        },
                    )
                    self.assertTrue(denied["isError"], denied)
                    self.assertEqual(denied["structuredContent"]["error"]["code"], "CAPABILITY_APPROVAL_REQUIRED")
                    self.assertFalse(target.exists())
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
