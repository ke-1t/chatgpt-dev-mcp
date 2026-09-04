from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest


PLANNED_PLATFORM_TOOLS = {
    "git_workflow_preflight",
    "git_workflow_apply",
    "github_workflow_read",
    "github_workflow_preflight",
    "github_workflow_apply",
    "command_profile_list",
    "command_profile_preflight",
    "command_profile_run",
    "platform.command_profile.register",
    "platform.command_profile.unregister",
    "platform.command_profile.cleanup_ephemeral",
    "dependency_change_preflight",
    "dependency_apply",
    "dependency_audit",
    "browser_test_session",
    "browser_inspect",
    "browser_action",
    "desktop_runtime",
    "director_review",
    "patch_revert_preflight",
    "patch_revert",
    "credential_slot_list",
    "credential_slot_preflight",
    "director_plan_work",
    "director_claim_task",
    "director_dispatch_status",
}


class PlatformMcpSurfaceTests(unittest.TestCase):
    def test_planned_platform_contracts_are_public_and_bounded(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            definitions = {item["name"]: item for item in runtime.list_tools()["tools"]}
            direct_tools = {
                "browser_test_session",
                "browser_inspect",
                "browser_action",
                "desktop_runtime",
            }
            registry_tools = PLANNED_PLATFORM_TOOLS - direct_tools
            self.assertTrue(direct_tools <= set(definitions))
            self.assertTrue(registry_tools.isdisjoint(definitions))

            forbidden_public_inputs = {
                "executable",
                "command",
                "cmd",
                "shell",
                "shell_command",
                "environment",
                "env",
                "repository",
                "owner",
                "api_origin",
                "credential_value",
                "token",
                "absolute_path",
            }
            for name in direct_tools:
                schema = definitions[name]["inputSchema"]
                properties = set(schema.get("properties", {}))
                self.assertFalse(forbidden_public_inputs & properties, (name, properties))
                self.assertFalse(schema.get("additionalProperties", True), name)
            for capability_id in registry_tools:
                described = runtime.call_tool(
                    "capability_describe",
                    {"capability_id": capability_id},
                )["structuredContent"]
                self.assertEqual(described["exposure"], "registry")
                schema = described["input_schema"]
                properties = set(schema.get("properties", {}))
                self.assertFalse(forbidden_public_inputs & properties, (capability_id, properties))
                self.assertFalse(schema.get("additionalProperties", True), capability_id)
        finally:
            runtime.close()

    def test_command_profile_list_uses_registered_platform_metadata(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-platform-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "fixture": {
                                "path": str(root),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "python3 -m unittest"},
                                "metadata": {
                                    "platform": {
                                        "command_profiles": {
                                            "python-version": {
                                                "argv": ["python3", "--version"],
                                                "allowed_args": {},
                                                "network_class": "none"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            runtime = WrapperRuntime()
            try:
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                self.assertTrue(opened.get("ok", True), opened)
                result = runtime.call_tool(
                    "command_profile_list",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    },
                )
                self.assertFalse(result.get("isError", False), result)
                profiles = result["structuredContent"]["profiles"]
                self.assertEqual([item["profile"] for item in profiles], ["python-version"])
                self.assertNotIn("python3", str(profiles))

                preflight = runtime.call_tool(
                    "command_profile_preflight",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "profile_id": "python-version",
                        "arguments": {},
                    },
                )
                self.assertFalse(preflight.get("isError", False), preflight)
                executed = runtime.call_tool(
                    "command_profile_run",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "preflight_id": preflight["structuredContent"]["preflight_id"],
                    },
                )
                self.assertFalse(executed.get("isError", False), executed)
                self.assertEqual(executed["structuredContent"]["exit_code"], 0)

                slots = runtime.call_tool(
                    "credential_slot_list",
                    {"workspace_id": "fixture", "working_tree_id": opened["identity"]["worktree_id"]},
                )
                self.assertFalse(slots.get("isError", False), slots)
                self.assertEqual(slots["structuredContent"]["slots"], [])

                browsers = runtime.call_tool(
                    "browser_test_session",
                    {"workspace_id": "fixture", "working_tree_id": opened["identity"]["worktree_id"], "action": "profiles"},
                )
                self.assertFalse(browsers.get("isError", False), browsers)
                self.assertEqual(browsers["structuredContent"]["profiles"], [])

                desktop = runtime.call_tool(
                    "desktop_runtime",
                    {"workspace_id": "fixture", "working_tree_id": opened["identity"]["worktree_id"], "action": "profiles"},
                )
                self.assertFalse(desktop.get("isError", False), desktop)
                self.assertEqual(desktop["structuredContent"]["profiles"], [])

                github = runtime.call_tool(
                    "github_workflow_read",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "action": "pr_status",
                        "number": 1,
                    },
                )
                self.assertTrue(github.get("isError", False), github)
                self.assertEqual(github["structuredContent"]["error"]["code"], "PLATFORM_FEATURE_UNAVAILABLE")
            finally:
                runtime.close()
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_command_profile_registration_capability_is_registry_only_and_human_approved(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "platform.command_profile.register"},
            )["structuredContent"]
            self.assertEqual(described["exposure"], "registry")
            self.assertEqual(described["risk_class"], "R3")
            self.assertEqual(described["approval_policy"], "human")
            self.assertFalse(described["network_required"])
            self.assertEqual(
                described["input_schema"]["properties"]["network_class"]["enum"],
                ["none", "github", "dependency", "browser", "api-test"],
            )
            lifecycle = described["input_schema"]["properties"]["lifecycle"]
            self.assertEqual(lifecycle["properties"]["kind"]["enum"], ["ephemeral"])
            self.assertFalse(lifecycle["additionalProperties"])
        finally:
            runtime.close()

    def test_command_profile_unregistration_capability_is_registry_only_and_human_approved(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "platform.command_profile.unregister"},
            )["structuredContent"]
            self.assertEqual(described["exposure"], "registry")
            self.assertEqual(described["risk_class"], "R3")
            self.assertEqual(described["approval_policy"], "human")
            self.assertFalse(described["network_required"])
            self.assertEqual(
                set(described["input_schema"]["properties"]),
                {"workspace_id", "profile_id"},
            )
        finally:
            runtime.close()

    def test_command_profile_cleanup_capability_is_registry_only_and_bounded(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "platform.command_profile.cleanup_ephemeral"},
            )["structuredContent"]
            self.assertEqual(described["exposure"], "registry")
            self.assertEqual(described["risk_class"], "R3")
            self.assertEqual(described["approval_policy"], "human")
            self.assertFalse(described["network_required"])
            schema = described["input_schema"]
            self.assertEqual(set(schema["properties"]), {"workspace_id", "mode"})
            self.assertEqual(schema["properties"]["mode"]["enum"], ["expired", "all_ephemeral"])
            self.assertFalse(schema["additionalProperties"])
        finally:
            runtime.close()

    def test_command_profile_registration_capability_registers_and_refreshes_runtime(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-command-profile-register-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "fixture": {
                                "path": str(root),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "python3 -m unittest"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            runtime = WrapperRuntime()
            try:
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                params = {
                    "workspace_id": "fixture",
                    "profile_id": "managed-live-eval",
                    "argv": ["python3", "tools/run_ai_editorial_eval.py"],
                    "allowed_args": {},
                    "timeout_ms": 120000,
                    "max_output_bytes": 131072,
                    "resources": [],
                    "credential_slots": [],
                    "network_class": "api-test",
                }
                preflight_result = runtime.call_tool(
                    "capability_preflight",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "capability_id": "platform.command_profile.register",
                        "params": params,
                    },
                )
                self.assertFalse(preflight_result["isError"], preflight_result)
                preflight = preflight_result["structuredContent"]
                self.assertTrue(preflight["approval_required"])

                applied = runtime.call_tool(
                    "capability_execute",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "preflight_id": preflight["preflight_id"],
                        "capability_id": "platform.command_profile.register",
                        "params": params,
                        "confirmation": preflight["approval"]["confirmation"],
                    },
                )
                self.assertFalse(applied["isError"], applied)
                profiles = runtime.call_tool(
                    "command_profile_list",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    },
                )["structuredContent"]["profiles"]
                self.assertEqual([item["profile"] for item in profiles], ["managed-live-eval"])
                self.assertEqual(profiles[0]["network_class"], "api-test")
            finally:
                runtime.close()
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_command_profile_unregistration_capability_removes_profile_and_refreshes_runtime(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-command-profile-unregister-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "fixture": {
                                "path": str(root),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "python3 -m unittest"},
                                "platform": {
                                    "command_profiles": {
                                        "managed-live-eval": {
                                            "argv": ["python3", "--version"],
                                            "allowed_args": {},
                                            "network_class": "none",
                                        }
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            runtime = WrapperRuntime()
            try:
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                params = {"workspace_id": "fixture", "profile_id": "managed-live-eval"}
                preflight_result = runtime.call_tool(
                    "capability_preflight",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "capability_id": "platform.command_profile.unregister",
                        "params": params,
                    },
                )
                self.assertFalse(preflight_result["isError"], preflight_result)
                preflight = preflight_result["structuredContent"]
                self.assertTrue(preflight["approval_required"])

                applied = runtime.call_tool(
                    "capability_execute",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "preflight_id": preflight["preflight_id"],
                        "capability_id": "platform.command_profile.unregister",
                        "params": params,
                        "confirmation": preflight["approval"]["confirmation"],
                    },
                )
                self.assertFalse(applied["isError"], applied)
                self.assertEqual(applied["structuredContent"]["result"]["status"], "unregistered")
                profiles = runtime.call_tool(
                    "command_profile_list",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    },
                )["structuredContent"]["profiles"]
                self.assertEqual(profiles, [])
            finally:
                runtime.close()
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_command_profile_cleanup_capability_removes_only_expired_ephemeral_and_refreshes_runtime(self) -> None:
        from datetime import datetime, timedelta, timezone

        from chatgpt_dev_mcp.server import WrapperRuntime

        now = datetime.now(timezone.utc)
        expired_created = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        expired_expires = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_created = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_expires = (now + timedelta(hours=22)).strftime("%Y-%m-%dT%H:%M:%SZ")

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-command-profile-cleanup-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "fixture": {
                                "path": str(root),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "python3 -m unittest"},
                                "platform": {
                                    "command_profiles": {
                                        "managed-expired": {
                                            "argv": ["python3", "--version"],
                                            "lifecycle": {
                                                "kind": "ephemeral",
                                                "purpose": "expired",
                                                "owner": "fixture",
                                                "created_at": expired_created,
                                                "expires_at": expired_expires,
                                            },
                                        },
                                        "managed-future": {
                                            "argv": ["python3", "--version"],
                                            "lifecycle": {
                                                "kind": "ephemeral",
                                                "purpose": "future",
                                                "owner": "fixture",
                                                "created_at": future_created,
                                                "expires_at": future_expires,
                                            },
                                        },
                                        "managed-once-name-only": {"argv": ["python3", "--version"]},
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            runtime = WrapperRuntime()
            try:
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                params = {"workspace_id": "fixture", "mode": "expired"}
                preflight_result = runtime.call_tool(
                    "capability_preflight",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "capability_id": "platform.command_profile.cleanup_ephemeral",
                        "params": params,
                    },
                )
                self.assertFalse(preflight_result["isError"], preflight_result)
                preflight = preflight_result["structuredContent"]
                self.assertTrue(preflight["approval_required"])
                inner = preflight["handler_preflight"]
                self.assertEqual([item["profile_id"] for item in inner["candidates"]], ["managed-expired"])

                applied = runtime.call_tool(
                    "capability_execute",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                        "preflight_id": preflight["preflight_id"],
                        "capability_id": "platform.command_profile.cleanup_ephemeral",
                        "params": params,
                        "confirmation": preflight["approval"]["confirmation"],
                    },
                )
                self.assertFalse(applied["isError"], applied)
                self.assertEqual(applied["structuredContent"]["result"]["removed_profile_ids"], ["managed-expired"])
                profiles = runtime.call_tool(
                    "command_profile_list",
                    {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    },
                )["structuredContent"]["profiles"]
                self.assertEqual([item["profile"] for item in profiles], ["managed-future", "managed-once-name-only"])
            finally:
                runtime.close()
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous


if __name__ == "__main__":
    unittest.main()
