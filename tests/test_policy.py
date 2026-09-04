from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path


class PolicyTests(unittest.TestCase):
    def test_director_data_dir_inside_registered_project_falls_back_to_managed_cache(self) -> None:
        from chatgpt_dev_mcp.server import _director_db_path_for_runtime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-db-containment-") as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            repo.mkdir()
            config = root / "config.json"
            config.write_text(
                json.dumps({"version": 1, "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT"}}}),
                encoding="utf-8",
            )
            previous_home = os.environ.get("HOME")
            previous_data = os.environ.get("LOCAL_DEV_MCP_DATA_DIR")
            os.environ["HOME"] = str(home)
            os.environ["LOCAL_DEV_MCP_DATA_DIR"] = str(repo / ".director-state")
            try:
                selected = _director_db_path_for_runtime(config)
                self.assertEqual(selected, home / ".cache" / "local-dev-mcp" / "director.sqlite3")
            finally:
                if previous_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = previous_home
                if previous_data is None:
                    os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
                else:
                    os.environ["LOCAL_DEV_MCP_DATA_DIR"] = previous_data

    def test_custom_registry_inside_git_repo_never_gets_sibling_database(self) -> None:
        from chatgpt_dev_mcp.server import _director_db_path_for_runtime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-config-repo-") as temp:
            root = Path(temp)
            home = root / "home"
            repo = root / "repo"
            repo.mkdir()
            (repo / ".git").mkdir()
            config = repo / "config.json"
            config.write_text(json.dumps({"version": 1, "workspaces": {}}), encoding="utf-8")
            previous_home = os.environ.get("HOME")
            previous_data = os.environ.get("LOCAL_DEV_MCP_DATA_DIR")
            os.environ["HOME"] = str(home)
            os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
            try:
                selected = _director_db_path_for_runtime(config)
                self.assertEqual(selected, home / ".cache" / "local-dev-mcp" / "director.sqlite3")
            finally:
                if previous_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = previous_home
                if previous_data is None:
                    os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
                else:
                    os.environ["LOCAL_DEV_MCP_DATA_DIR"] = previous_data

    def test_sensitive_names_are_denied_but_normal_source_is_allowed(self) -> None:
        from chatgpt_dev_mcp.server import _is_sensitive_path

        self.assertTrue(_is_sensitive_path(".env"))
        self.assertTrue(_is_sensitive_path(".ssh/id_ed25519"))
        self.assertTrue(_is_sensitive_path(".config/tool.json"))
        self.assertTrue(_is_sensitive_path(".git/config"))
        self.assertTrue(
            _is_sensitive_path(str(Path(tempfile.gettempdir()) / "example" / ".aws" / "credentials"))
        )
        self.assertFalse(_is_sensitive_path("src/server.py"))
        self.assertFalse(_is_sensitive_path("tests/test_api.py"))

    def test_registry_is_id_only_and_profile_is_explicit(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-test-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("fixture\n", encoding="utf-8")
            config = Path(temp) / "config.json"
            config.write_text(json.dumps({"version": 1, "workspaces": {"fixture": {"path": str(root), "profile": "READ_ONLY"}}}), encoding="utf-8")
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            try:
                runtime = WrapperRuntime()
                listing = runtime.call_tool("workspace_list", {})
                self.assertFalse(listing["isError"])
                self.assertEqual(listing["structuredContent"]["workspaces"][0]["id"], "fixture")
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})
                self.assertFalse(opened["isError"])
                self.assertEqual(opened["structuredContent"]["profile"], "READ_ONLY")
                missing = runtime.call_tool("workspace_open", {"id": "not-registered"})
                self.assertTrue(missing["isError"])
                self.assertEqual(missing["structuredContent"]["error"]["code"], "WORKSPACE_NOT_FOUND")
                runtime.close()
            finally:
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_optional_project_metadata_is_validated_and_exposed(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime, load_registry

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-metadata-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("fixture\n", encoding="utf-8")
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roots": [
                            {
                                "id": "developer",
                                "path": str(Path(__file__).resolve().parents[1]),
                                "mode": "PROJECT_DISCOVERY",
                            }
                        ],
                        "workspaces": {
                            "fixture": {
                                "path": str(root),
                                "profile": "READ_ONLY",
                                "commands": {"test": "pytest"},
                                "metadata": {
                                    "language": "Python",
                                    "framework": "stdlib",
                                    "architecture_ref": "docs/ARCHITECTURE.md",
                                    "canonical_paths": ["src", "tests"],
                                    "task_descriptions": {"test": "Run the test suite"},
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            try:
                _, entries, _, errors = load_registry()
                self.assertEqual(errors, [])
                self.assertEqual(entries["fixture"].metadata["language"], "Python")
                runtime = WrapperRuntime()
                listing = runtime.call_tool("workspace_list", {})["structuredContent"]
                descriptor = listing["workspaces"][0]
                self.assertEqual(descriptor["metadata"]["canonical_paths"], ["src", "tests"])
                self.assertNotIn("pytest", str(descriptor))
                opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                self.assertEqual(opened["metadata"]["task_descriptions"]["test"], "Run the test suite")
                runtime.close()
            finally:
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_project_metadata_rejects_unknown_keys_and_unsafe_paths(self) -> None:
        from chatgpt_dev_mcp.server import load_registry

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-invalid-metadata-") as temp:
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
                                "profile": "READ_ONLY",
                                "metadata": {
                                    "unknown": "reject",
                                    "canonical_paths": ["../outside"],
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            try:
                _, entries, _, errors = load_registry()
                self.assertEqual(entries, {})
                self.assertTrue(any(error["code"] == "METADATA_INVALID" for error in errors))
            finally:
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous

    def test_stdio_handshake_exposes_guarded_tools(self) -> None:
        from io import StringIO

        from coding_tools_mcp.transport_stdio import serve_stdio

        from chatgpt_dev_mcp.server import WrapperRuntime

        request_lines = "\n".join(
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "workspace_list", "arguments": {}}}),
            ]
        ) + "\n"
        output = StringIO()
        serve_stdio(WrapperRuntime(), input_stream=StringIO(request_lines), output_stream=output)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "chatgpt-dev-mcp")
        self.assertTrue(responses[0]["result"]["capabilities"]["tools"]["listChanged"])
        tool_names = {item["name"] for item in responses[1]["result"]["tools"]}
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES

        self.assertEqual(len(tool_names), 52)
        self.assertEqual(tool_names, set(STABLE_PUBLIC_TOOL_NAMES))
        self.assertIn("workspace_open", tool_names)
        self.assertIn("run_task", tool_names)
        self.assertNotIn("exec_command", tool_names)
        self.assertEqual(responses[2]["result"]["structuredContent"]["ok"], True)

    def test_tool_schema_metadata_changes_with_visible_definition(self) -> None:
        from chatgpt_dev_mcp.server import _tool_schema_metadata

        definitions = [{"name": "alpha", "inputSchema": {"type": "object"}}]
        baseline = _tool_schema_metadata(definitions)
        reordered = _tool_schema_metadata(list(reversed(definitions)))
        changed = _tool_schema_metadata(definitions + [{"name": "beta", "inputSchema": {"type": "object"}}])

        self.assertEqual(baseline["revision"], "tool-registry-v25-stable")
        self.assertEqual(baseline, reordered)
        self.assertEqual(changed["revision"], baseline["revision"])
        self.assertEqual(changed["count"], baseline["count"] + 1)
        self.assertNotEqual(changed["hash"], baseline["hash"])

    def test_release_contract_pins_dependency_and_schema_surface(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project_root = Path(__file__).resolve().parents[1]
        pyproject = (project_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"coding-tools-mcp==0.2.3"', pyproject)
        uv_lock = (project_root / "uv.lock").read_text(encoding="utf-8")
        self.assertIn('specifier = "==0.2.3"', uv_lock)
        runtime = WrapperRuntime()
        try:
            metadata = runtime.call_tool("server_info", {})["structuredContent"]["tool_schema"]
            self.assertEqual(metadata["revision"], "tool-registry-v25-stable")
            self.assertEqual(metadata["count"], 52)
            self.assertRegex(metadata["hash"], r"^[0-9a-f]{64}$")
        finally:
            runtime.close()

    def test_server_info_succeeds_without_selected_workspace(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            result = runtime.call_tool("server_info", {})
            self.assertFalse(result["isError"])
            info = result["structuredContent"]
            self.assertEqual(info["tool_count"], 52)
            self.assertEqual(info["tool_schema"]["count"], 52)
            self.assertEqual(info["tool_schema"]["revision"], "tool-registry-v25-stable")
            self.assertRegex(info["tool_schema"]["hash"], r"^[0-9a-f]{64}$")
            self.assertNotIn("workspace_id", info.get("wrapper", {}))
            self.assertNotIn("profile", info.get("wrapper", {}))
            health = info["health"]
            self.assertEqual(health["schema_revision"], "health-v1")
            self.assertIn(health["status"], {"healthy", "degraded"})
            self.assertEqual(health["schema_consistency"]["status"], "consistent")
            self.assertEqual(health["schema_consistency"]["local_tool_schema"]["count"], 52)
            self.assertEqual(health["schema_consistency"]["client_observation"], "not_available")
            self.assertEqual(health["runtime"]["status"], "alive")
            self.assertEqual(health["runtime"]["workspace_selected"], False)
        finally:
            runtime.close()

    def test_server_info_schema_and_health_are_stable_across_reads(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            first = runtime.call_tool("server_info", {})["structuredContent"]
            second = runtime.call_tool("server_info", {})["structuredContent"]
            self.assertEqual(first["tool_schema"], second["tool_schema"])
            self.assertEqual(first["health"]["schema_consistency"], second["health"]["schema_consistency"])
            self.assertEqual(first["health"]["registry"]["config_digest"], second["health"]["registry"]["config_digest"])
            self.assertEqual(first["health"]["runtime"]["pid"], second["health"]["runtime"]["pid"])
            self.assertEqual(first["health"]["runtime"]["started_at"], second["health"]["runtime"]["started_at"])
        finally:
            runtime.close()

    def test_server_info_reports_misconfigured_tunnel_as_degraded(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        previous = os.environ.get("LOCAL_DEV_MCP_TUNNEL_HEALTH_URL")
        os.environ["LOCAL_DEV_MCP_TUNNEL_HEALTH_URL"] = "https://example.com/healthz"
        try:
            runtime = WrapperRuntime()
            try:
                info = runtime.call_tool("server_info", {})["structuredContent"]
                self.assertEqual(info["health"]["tunnel"]["status"], "misconfigured")
                self.assertEqual(info["health"]["status"], "degraded")
            finally:
                runtime.close()
        finally:
            if previous is None:
                os.environ.pop("LOCAL_DEV_MCP_TUNNEL_HEALTH_URL", None)
            else:
                os.environ["LOCAL_DEV_MCP_TUNNEL_HEALTH_URL"] = previous

    def test_server_info_matches_wrapper_tool_surface(self) -> None:
        from chatgpt_dev_mcp.server import HIDDEN_UPSTREAM_TOOLS, WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-test-") as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps({"version": 1, "workspaces": {"fixture": {"path": str(root), "profile": "READ_ONLY"}}}),
                encoding="utf-8",
            )
            previous = os.environ.get("LOCAL_DEV_MCP_CONFIG")
            os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
            try:
                runtime = WrapperRuntime()
                runtime.call_tool("workspace_open", {"id": "fixture"})
                info = runtime.call_tool("server_info", {})["structuredContent"]
                exposed_names = [item["name"] for item in runtime.list_tools().get("tools", [])]
                self.assertEqual(info["tools"], exposed_names)
                self.assertEqual(info["tool_count"], len(exposed_names))
                metadata = info["tool_schema"]
                self.assertEqual(metadata["count"], len(exposed_names))
                self.assertEqual(metadata["revision"], "tool-registry-v25-stable")
                self.assertRegex(metadata["hash"], r"^[0-9a-f]{64}$")
                self.assertEqual(info["wrapper"]["workspace_id"], "fixture")
                self.assertEqual(info["wrapper"]["profile"], "READ_ONLY")
                self.assertEqual(info["health"]["schema_revision"], "health-v1")
                self.assertTrue(info["health"]["runtime"]["workspace_selected"])
                second_info = runtime.call_tool("server_info", {})["structuredContent"]
                self.assertEqual(second_info["tool_schema"], metadata)
                self.assertTrue((HIDDEN_UPSTREAM_TOOLS - {"apply_patch"}).isdisjoint(info["tools"]))
                runtime.close()
            finally:
                if previous is None:
                    os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
                else:
                    os.environ["LOCAL_DEV_MCP_CONFIG"] = previous


if __name__ == "__main__":
    unittest.main()
