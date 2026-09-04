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
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)

    def tearDown(self) -> None:
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        self.tempdir.cleanup()

    def test_platform_profile_registration_is_preflight_gated_and_one_shot(self) -> None:
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
            browser_preflight = runtime.call_tool(
                "workspace_platform_profile_register_preflight",
                {
                    "workspace_id": "fixture",
                    "kind": "browser",
                    "profile_id": "managed-fixture-browser",
                    "allowed_origins": ["http://127.0.0.1:8765"],
                    "viewport_width": 1280,
                    "viewport_height": 720,
                },
            )["structuredContent"]
            self.assertEqual(self.config.read_text(encoding="utf-8"), before)
            self.assertTrue(browser_preflight["approval_required"])
            self.assertFalse(browser_preflight["external_execution"])

            browser_applied = runtime.call_tool(
                "workspace_platform_profile_register",
                {"preflight_id": browser_preflight["preflight_id"], "confirmation": browser_preflight["approval"]["confirmation"]},
            )["structuredContent"]
            self.assertEqual(browser_applied["status"], "registered")
            self.assertFalse(browser_applied["external_execution"])

            replay = runtime.call_tool(
                "workspace_platform_profile_register",
                {"preflight_id": browser_preflight["preflight_id"], "confirmation": browser_preflight["approval"]["confirmation"]},
            )
            self.assertTrue(replay["isError"])

            desktop_preflight = runtime.call_tool(
                "workspace_platform_profile_register_preflight",
                {
                    "workspace_id": "fixture",
                    "kind": "desktop",
                    "profile_id": "managed-fixture-desktop",
                    "bundle_id": "com.example.fixture",
                    "health_url": "http://127.0.0.1:8765/health",
                },
            )["structuredContent"]
            desktop_applied = runtime.call_tool(
                "workspace_platform_profile_register",
                {"preflight_id": desktop_preflight["preflight_id"], "confirmation": desktop_preflight["approval"]["confirmation"]},
            )["structuredContent"]
            self.assertEqual(desktop_applied["status"], "registered")
            self.assertFalse(desktop_applied["external_execution"])

            document = json.loads(self.config.read_text(encoding="utf-8"))
            platform = document["workspaces"]["fixture"]["platform"]
            self.assertEqual(platform["browser_profiles"]["managed-fixture-browser"]["allowed_origins"], ["http://127.0.0.1:8765"])
            self.assertEqual(platform["desktop_profiles"]["managed-fixture-desktop"]["bundle_id"], "com.example.fixture")
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
