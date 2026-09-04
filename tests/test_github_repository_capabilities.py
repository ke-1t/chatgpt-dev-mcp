from __future__ import annotations

import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class GitHubRepositoryCapabilityTests(unittest.TestCase):
    def test_registry_bindings_expose_r0_r0_r3_delegated_network_contract(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_github_repository_bindings
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[tuple[str, dict[str, object]]] = []

        def read(params, context):
            calls.append(("read", dict(params)))
            return {"availability": "available", "workspace_id": context.workspace_id}

        def preflight(params, context):
            calls.append(("preflight", dict(params)))
            return {
                "status": "ready",
                "preflight_id": "github-repository-preflight:fixture",
                "approval": {
                    "approval_id": "github-repository-approval:fixture",
                    "confirmation": "fixture-confirmation",
                },
            }

        def apply(params, context):
            calls.append(("apply", dict(params)))
            return {"status": "succeeded", "workspace_id": context.workspace_id}

        bindings = build_github_repository_bindings(read, preflight, apply)
        self.assertEqual(len(bindings), 3)
        specs = {spec.capability_id: spec for spec, _handler in bindings}
        handlers = {handler.handler_id: handler for _spec, handler in bindings}

        self.assertEqual(
            (specs["github_repository_read"].risk_class, specs["github_repository_read"].approval_policy),
            ("R0", "none"),
        )
        self.assertEqual(
            (specs["github_repository_preflight"].risk_class, specs["github_repository_preflight"].approval_policy),
            ("R0", "none"),
        )
        self.assertEqual(
            (specs["github_repository_apply"].risk_class, specs["github_repository_apply"].approval_policy),
            ("R3", "delegated"),
        )
        for spec in specs.values():
            self.assertEqual(spec.exposure, "registry")
            self.assertEqual(spec.workspace_binding, "required")
            self.assertTrue(spec.network_required)
            self.assertEqual(spec.credential_requirements, ())

        self.assertEqual(
            specs["github_repository_read"].input_schema["properties"]["action"]["enum"],
            ["summary", "forks", "secret_scanning_alerts", "branch_protection", "actions"],
        )
        self.assertEqual(
            specs["github_repository_preflight"].input_schema["properties"]["visibility"]["enum"],
            ["private", "public", "internal"],
        )
        self.assertEqual(
            set(specs["github_repository_apply"].input_schema["required"]),
            {"preflight_id", "approval_id", "confirmation"},
        )

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
            workspace_trust_level="standard",
        )
        read_params = {"action": "summary"}
        preview, state = handlers["github_repository_read"].preflight(read_params, context)
        self.assertEqual(preview["action"], "summary")
        self.assertEqual(handlers["github_repository_read"].execute(read_params, context, state)["availability"], "available")

        mutation_params = {"operation": "set_visibility", "visibility": "private"}
        preview, state = handlers["github_repository_preflight"].preflight(mutation_params, context)
        self.assertEqual(preview["visibility"], "private")
        self.assertEqual(handlers["github_repository_preflight"].execute(mutation_params, context, state)["status"], "ready")

        apply_params = {
            "preflight_id": "github-repository-preflight:fixture",
            "approval_id": "github-repository-approval:fixture",
            "confirmation": "fixture-confirmation",
        }
        preview, state = handlers["github_repository_apply"].preflight(apply_params, context)
        self.assertEqual(preview["preflight_id"], apply_params["preflight_id"])
        self.assertEqual(handlers["github_repository_apply"].execute(apply_params, context, state)["status"], "succeeded")
        self.assertEqual([kind for kind, _params in calls], ["read", "preflight", "apply"])

    def test_server_catalog_adds_repository_capabilities_without_expanding_direct_surface(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {
                "HOME": str(root / "home"),
                "LOCAL_DEV_MCP_CONFIG": str(root / "config.json"),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "data"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CHATGPT_DEV_MCP_SURFACE": "stable_gateway",
            }
            with patch.dict(os.environ, env):
                runtime = WrapperRuntime()
                try:
                    self.assertEqual(len(runtime.list_tools()["tools"]), 52)
                    catalog_result = runtime.call_tool("capability_catalog", {"query": "github_repository"})
                    self.assertFalse(catalog_result["isError"], catalog_result)
                    capabilities = {
                        item["capability_id"]: item
                        for item in catalog_result["structuredContent"]["capabilities"]
                    }
                    self.assertEqual(
                        set(capabilities),
                        {"github_repository_read", "github_repository_preflight", "github_repository_apply"},
                    )
                    self.assertEqual(capabilities["github_repository_read"]["risk_class"], "R0")
                    self.assertEqual(capabilities["github_repository_preflight"]["risk_class"], "R0")
                    self.assertEqual(capabilities["github_repository_apply"]["risk_class"], "R3")
                    self.assertEqual(capabilities["github_repository_apply"]["approval_policy"], "delegated")
                finally:
                    runtime.close()

    def test_gateway_executes_read_preflight_and_delegated_apply_with_fake_github_transport(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        class FakeTransport:
            def __init__(self) -> None:
                self.visibility = "public"
                self.patch_count = 0

            def request(self, method: str, path: str, *, body=None):
                if method == "GET" and path == "/repos/acme/demo":
                    return 200, {
                        "full_name": "acme/demo",
                        "visibility": self.visibility,
                        "private": self.visibility != "public",
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                        "forks_count": 0,
                        "security_and_analysis": {},
                    }
                if method == "PATCH" and path == "/repos/acme/demo":
                    self.patch_count += 1
                    self.visibility = str(body["visibility"])
                    return 200, {
                        "full_name": "acme/demo",
                        "visibility": self.visibility,
                        "private": self.visibility != "public",
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                        "forks_count": 0,
                        "security_and_analysis": {},
                    }
                raise AssertionError((method, path, body))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/acme/demo.git"],
                check=True,
            )
            (root / "config.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                        "workspaces": {
                            "fixture": {
                                "path": str(repo),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "printf ok"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            env = {
                "HOME": str(root / "home"),
                "LOCAL_DEV_MCP_CONFIG": str(root / "config.json"),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "data"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CHATGPT_DEV_MCP_SURFACE": "stable_gateway",
            }
            with patch.dict(os.environ, env):
                runtime = WrapperRuntime()
                try:
                    fake = FakeTransport()
                    runtime._github_repository._transport = fake
                    opened = runtime.call_tool("workspace_open", {"id": "fixture"})
                    self.assertFalse(opened["isError"], opened)
                    tree = opened["structuredContent"]["identity"]["worktree_id"]

                    read_params = {"action": "summary"}
                    read_preflight = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_read",
                            "params": read_params,
                        },
                    )
                    self.assertFalse(read_preflight["isError"], read_preflight)
                    read_exec = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_read",
                            "preflight_id": read_preflight["structuredContent"]["preflight_id"],
                            "params": read_params,
                        },
                    )
                    self.assertFalse(read_exec["isError"], read_exec)
                    self.assertEqual(read_exec["structuredContent"]["result"]["data"]["visibility"], "public")

                    mutation_params = {"operation": "set_visibility", "visibility": "private"}
                    mutation_outer = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_preflight",
                            "params": mutation_params,
                        },
                    )
                    self.assertFalse(mutation_outer["isError"], mutation_outer)
                    mutation_exec = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_preflight",
                            "preflight_id": mutation_outer["structuredContent"]["preflight_id"],
                            "params": mutation_params,
                        },
                    )
                    self.assertFalse(mutation_exec["isError"], mutation_exec)
                    repository_preflight = mutation_exec["structuredContent"]["result"]
                    apply_params = {
                        "preflight_id": repository_preflight["preflight_id"],
                        "approval_id": repository_preflight["approval"]["approval_id"],
                        "confirmation": repository_preflight["approval"]["confirmation"],
                    }
                    apply_outer = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_apply",
                            "params": apply_params,
                        },
                    )
                    self.assertFalse(apply_outer["isError"], apply_outer)
                    self.assertFalse(apply_outer["structuredContent"]["approval_required"])
                    apply_exec = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": tree,
                            "capability_id": "github_repository_apply",
                            "preflight_id": apply_outer["structuredContent"]["preflight_id"],
                            "params": apply_params,
                        },
                    )
                    self.assertFalse(apply_exec["isError"], apply_exec)
                    self.assertEqual(apply_exec["structuredContent"]["result"]["status"], "succeeded")
                    self.assertEqual(fake.patch_count, 1)
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
