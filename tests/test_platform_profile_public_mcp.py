from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class PlatformProfilePublicMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-platform-profile-public-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(self.root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        self.previous_surface = os.environ.get("CHATGPT_DEV_MCP_SURFACE")
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)
        os.environ["CHATGPT_DEV_MCP_SURFACE"] = "stable_gateway"

    def tearDown(self) -> None:
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        if self.previous_surface is None:
            os.environ.pop("CHATGPT_DEV_MCP_SURFACE", None)
        else:
            os.environ["CHATGPT_DEV_MCP_SURFACE"] = self.previous_surface
        self.tempdir.cleanup()

    def test_platform_profile_registration_is_preflight_gated_and_one_shot(self) -> None:
        from coding_tools_mcp.protocol import RequestContext
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            names = {item["name"] for item in runtime.list_tools()["tools"]}
            self.assertNotIn("workspace_platform_profile_register_preflight", names)
            self.assertNotIn("workspace_platform_profile_register", names)
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "platform.profile.register"},
            )["structuredContent"]
            self.assertEqual(described["exposure"], "registry")

            before = self.config.read_text(encoding="utf-8")
            direct = runtime.call_tool(
                "workspace_platform_profile_register_preflight",
                {
                    "workspace_id": "fixture",
                    "kind": "browser",
                    "profile_id": "managed-fixture-browser",
                    "allowed_origins": ["http://127.0.0.1:8765"],
                    "viewport_width": 1280,
                    "viewport_height": 720,
                },
                context=RequestContext(era="legacy", protocol_version="2025-11-25"),
            )
            self.assertTrue(direct["isError"], direct)
            self.assertEqual(direct["structuredContent"]["error"]["code"], "POLICY_HIDDEN")
            browser_params = {
                "workspace_id": "fixture",
                "kind": "browser",
                "profile_id": "managed-fixture-browser",
                "allowed_origins": ["http://127.0.0.1:8765"],
                "viewport_width": 1280,
                "viewport_height": 720,
            }
            browser_preflight_result = runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "platform.profile.register",
                    "params": browser_params,
                },
            )
            self.assertFalse(browser_preflight_result["isError"], browser_preflight_result)
            browser_preflight = browser_preflight_result["structuredContent"]
            self.assertEqual(self.config.read_text(encoding="utf-8"), before)
            self.assertTrue(browser_preflight["approval_required"])
            self.assertFalse(browser_preflight.get("external_execution", False))

            browser_applied_result = runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": browser_preflight["preflight_id"],
                    "capability_id": "platform.profile.register",
                    "params": browser_params,
                    "confirmation": browser_preflight["approval"]["confirmation"],
                },
            )
            self.assertFalse(browser_applied_result["isError"], browser_applied_result)
            browser_applied = browser_applied_result["structuredContent"]["result"]
            self.assertEqual(browser_applied["status"], "registered")
            self.assertFalse(browser_applied.get("external_execution", False))

            replay = runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": browser_preflight["preflight_id"],
                    "capability_id": "platform.profile.register",
                    "params": browser_params,
                    "confirmation": browser_preflight["approval"]["confirmation"],
                },
            )
            self.assertTrue(replay["isError"])

            desktop_params = {
                "workspace_id": "fixture",
                "kind": "desktop",
                "profile_id": "managed-fixture-desktop",
                "bundle_id": "com.example.fixture",
                "health_url": "http://127.0.0.1:8765/health",
            }
            desktop_preflight_result = runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "platform.profile.register",
                    "params": desktop_params,
                },
            )
            self.assertFalse(desktop_preflight_result["isError"], desktop_preflight_result)
            desktop_preflight = desktop_preflight_result["structuredContent"]
            desktop_applied_result = runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": desktop_preflight["preflight_id"],
                    "capability_id": "platform.profile.register",
                    "params": desktop_params,
                    "confirmation": desktop_preflight["approval"]["confirmation"],
                },
            )
            self.assertFalse(desktop_applied_result["isError"], desktop_applied_result)
            desktop_applied = desktop_applied_result["structuredContent"]["result"]
            self.assertEqual(desktop_applied["status"], "registered")
            self.assertFalse(desktop_applied.get("external_execution", False))

            document = json.loads(self.config.read_text(encoding="utf-8"))
            platform = document["workspaces"]["fixture"]["platform"]
            self.assertEqual(platform["browser_profiles"]["managed-fixture-browser"]["allowed_origins"], ["http://127.0.0.1:8765"])
            self.assertEqual(platform["desktop_profiles"]["managed-fixture-desktop"]["bundle_id"], "com.example.fixture")
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
