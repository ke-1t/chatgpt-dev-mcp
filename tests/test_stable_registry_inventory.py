from __future__ import annotations

import unittest


class StableRegistryInventoryTests(unittest.TestCase):
    def test_exact_current_hidden_inventory_is_sixty_three_unique_tools(self) -> None:
        from chatgpt_dev_mcp.stable_registry_inventory import (
            REGISTRY_CATEGORY_BY_TOOL,
            REGISTRY_CATEGORY_TOOL_GROUPS,
            REGISTRY_SHARD_BY_CATEGORY,
            REGISTRY_TOOL_NAMES,
        )
        from chatgpt_dev_mcp.stable_surface import STABLE_DEDICATED_TOOL_NAMES

        self.assertEqual(len(REGISTRY_TOOL_NAMES), 63)
        self.assertEqual(len(set(REGISTRY_TOOL_NAMES)), 63)
        self.assertFalse(set(REGISTRY_TOOL_NAMES) & set(STABLE_DEDICATED_TOOL_NAMES))
        self.assertEqual(set(REGISTRY_CATEGORY_BY_TOOL), set(REGISTRY_TOOL_NAMES))
        self.assertEqual(
            {category: len(names) for category, names in REGISTRY_CATEGORY_TOOL_GROUPS.items()},
            {
                "platform_runtime": 4,
                "workspace": 12,
                "development": 7,
                "files_changes": 6,
                "git_delivery": 14,
                "verification_tasks": 3,
                "desktop_profiles": 8,
                "governance": 9,
            },
        )
        self.assertTrue(
            {"git_stage_preflight", "git_stage"}
            <= set(REGISTRY_CATEGORY_TOOL_GROUPS["git_delivery"])
        )
        self.assertTrue(
            {"git_stage_paths_preflight", "git_stage_paths"}
            <= set(REGISTRY_CATEGORY_TOOL_GROUPS["git_delivery"])
        )
        self.assertTrue(
            {"git_stage_hunks_preflight", "git_stage_hunks"}
            <= set(REGISTRY_CATEGORY_TOOL_GROUPS["git_delivery"])
        )
        self.assertEqual(
            set(REGISTRY_SHARD_BY_CATEGORY.values()),
            {"development", "files_changes", "delivery", "verification", "governance_security", "platform_integrations"},
        )

    def test_profile_registration_compatibility_pair_points_to_typed_replacement(self) -> None:
        from chatgpt_dev_mcp.stable_registry_inventory import REGISTRY_REPLACEMENTS

        self.assertEqual(
            REGISTRY_REPLACEMENTS,
            {
                "workspace_platform_profile_register_preflight": "platform.profile.register",
                "workspace_platform_profile_register": "platform.profile.register",
            },
        )

    def test_ephemeral_cleanup_does_not_expand_stable_direct_surface(self) -> None:
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES

        self.assertEqual(len(STABLE_PUBLIC_TOOL_NAMES), 52)
        self.assertEqual(len(set(STABLE_PUBLIC_TOOL_NAMES)), 52)
        self.assertNotIn("platform.command_profile.cleanup_ephemeral", STABLE_PUBLIC_TOOL_NAMES)


if __name__ == "__main__":
    unittest.main()
