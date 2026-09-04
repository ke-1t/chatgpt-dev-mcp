from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from unittest.mock import patch


class StableSurfaceTests(unittest.TestCase):
    def test_stable_gateway_is_the_default_surface_profile(self) -> None:
        from chatgpt_dev_mcp.stable_surface import (
            PROFILE_LEGACY,
            PROFILE_STABLE_GATEWAY,
            resolve_public_surface_profile,
            surface_mode_from_environment,
        )

        self.assertEqual(resolve_public_surface_profile(None), PROFILE_STABLE_GATEWAY)
        self.assertEqual(resolve_public_surface_profile(""), PROFILE_STABLE_GATEWAY)
        self.assertEqual(resolve_public_surface_profile("  "), PROFILE_STABLE_GATEWAY)
        self.assertEqual(resolve_public_surface_profile(PROFILE_LEGACY), PROFILE_LEGACY)

        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(surface_mode_from_environment(), PROFILE_STABLE_GATEWAY)
        with patch.dict("os.environ", {"CHATGPT_DEV_MCP_SURFACE": ""}, clear=True):
            self.assertEqual(surface_mode_from_environment(), PROFILE_STABLE_GATEWAY)
        with patch.dict("os.environ", {"CHATGPT_DEV_MCP_SURFACE": PROFILE_LEGACY}, clear=True):
            self.assertEqual(surface_mode_from_environment(), PROFILE_LEGACY)

    def test_stable_manifest_is_exactly_fifty_two_tools(self) -> None:
        from chatgpt_dev_mcp.stable_surface import (
            CATEGORY_TOOL_GROUPS,
            GATEWAY_TOOL_NAMES,
            STABLE_DEDICATED_TOOL_NAMES,
            STABLE_PUBLIC_TOOL_NAMES,
        )

        self.assertEqual(len(STABLE_DEDICATED_TOOL_NAMES), 48)
        self.assertEqual(
            GATEWAY_TOOL_NAMES,
            (
                "capability_catalog",
                "capability_describe",
                "capability_preflight",
                "capability_execute",
            ),
        )
        self.assertEqual(STABLE_PUBLIC_TOOL_NAMES, STABLE_DEDICATED_TOOL_NAMES + GATEWAY_TOOL_NAMES)
        self.assertEqual(len(STABLE_PUBLIC_TOOL_NAMES), 52)
        self.assertEqual(len(set(STABLE_PUBLIC_TOOL_NAMES)), 52)
        self.assertEqual(sum(len(names) for names in CATEGORY_TOOL_GROUPS.values()), 52)
        self.assertEqual(
            {name: len(tools) for name, tools in CATEGORY_TOOL_GROUPS.items()},
            {
                "platform_runtime": 3,
                "workspace": 4,
                "development": 11,
                "files_changes": 9,
                "git_delivery": 8,
                "verification_tasks": 7,
                "browser_qa": 4,
                "desktop_profiles": 1,
                "governance": 1,
                "capability_gateway": 4,
            },
        )
        promoted = {
            "workspace_resume_development_session",
            "workspace_session_diff",
            "development_context",
            "director_development_start",
            "workspace_integration_preflight",
            "workspace_integrate_development_session",
            "view_image",
            "git_push_preflight",
            "git_push",
            "task_poll",
            "task_stop",
            "director_next_action",
            "browser_action",
        }
        self.assertTrue(promoted.issubset(set(STABLE_DEDICATED_TOOL_NAMES)))

    def test_select_stable_surface_uses_manifest_order_and_drops_legacy_long_tail(self) -> None:
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES, select_stable_surface

        definitions = [{"name": "legacy_long_tail"}]
        definitions += [{"name": name, "marker": name} for name in reversed(STABLE_PUBLIC_TOOL_NAMES)]
        selected = select_stable_surface(definitions)

        self.assertEqual([item["name"] for item in selected], list(STABLE_PUBLIC_TOOL_NAMES))
        self.assertNotIn("legacy_long_tail", {item["name"] for item in selected})

    def test_validator_rejects_missing_duplicate_and_extra_stable_tools(self) -> None:
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES, validate_gateway_surface

        missing = [{"name": name} for name in STABLE_PUBLIC_TOOL_NAMES if name != "capability_execute"]
        missing_result = validate_gateway_surface(missing)
        self.assertEqual(missing_result["status"], "invalid")
        self.assertEqual(missing_result["missing_names"], ["capability_execute"])

        duplicate = [{"name": name} for name in STABLE_PUBLIC_TOOL_NAMES] + [{"name": "server_info"}]
        duplicate_result = validate_gateway_surface(duplicate)
        self.assertEqual(duplicate_result["status"], "invalid")
        self.assertEqual(duplicate_result["duplicate_names"], ["server_info"])

        extra = [{"name": name} for name in STABLE_PUBLIC_TOOL_NAMES] + [{"name": "legacy_long_tail"}]
        extra_result = validate_gateway_surface(extra)
        self.assertEqual(extra_result["status"], "invalid")
        self.assertEqual(extra_result["extra_names"], ["legacy_long_tail"])


if __name__ == "__main__":
    unittest.main()
