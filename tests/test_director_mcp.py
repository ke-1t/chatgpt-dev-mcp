from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class DirectorMcpIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-director-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text('token=secret-value\nhello\n', encoding="utf-8")
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
                    "roots": [
                        {
                            "id": "developer",
                            "path": str(Path(__file__).resolve().parents[1]),
                            "mode": "PROJECT_DISCOVERY",
                        }
                    ],
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

    def _runtime(self):
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        self.assertFalse(runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])
        return runtime

    def test_director_tools_are_registered_and_health_is_honest_without_client_schema(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            names = {item["name"] for item in runtime.list_tools()["tools"]}
            self.assertEqual(len(names), 52)
            self.assertTrue(
                {
                    "director_health",
                    "verification_plan",
                    "verification_record",
                    "workspace_session_diff",
                    "workspace_integration_preflight",
                    "workspace_integrate_development_session",
                } <= names
            )
            for capability_id in (
                "director_usage",
                "context_pack",
                "patch_preflight",
                "workspace_profile",
                "director_task_ledger",
                "director_writer_lease",
                "security_audit",
                "orchestration_plan",
            ):
                self.assertNotIn(capability_id, names)
                described = runtime.call_tool(
                    "capability_describe",
                    {"capability_id": capability_id},
                )["structuredContent"]
                self.assertEqual(described["exposure"], "registry")
            health = runtime.call_tool("director_health", {})["structuredContent"]
            self.assertEqual(health["watchdog"]["status"], "unknown")
            self.assertEqual(health["capabilities"]["account_usage"], "unknown")
            self.assertEqual(health["client_schema_evidence"]["status"], "unsupported")
            self.assertFalse(health["client_schema_evidence"]["server_observed"])
            self.assertFalse(health["client_schema_evidence"]["caller_provided"])
            self.assertFalse(health["external_execution"])

            stale = runtime.call_tool(
                "director_health",
                {
                    "client_schema": {
                        "revision": "tool-registry-v7",
                        "count": 51,
                        "hash": "a" * 64,
                        "tools": ["workspace_list"],
                    }
                },
            )["structuredContent"]
            self.assertTrue(stale["schema_compatibility"]["rescan_required"])
            self.assertEqual(stale["schema_compatibility"]["server_schema"]["revision"], "tool-registry-v25-stable")
            self.assertEqual(stale["schema_compatibility"]["error_code"], "CLIENT_TOOL_SCHEMA_STALE")
            self.assertIn("apply_patch", stale["schema_compatibility"]["missing_on_client"])
            self.assertEqual(stale["client_schema_evidence"]["status"], "stale")
            self.assertFalse(stale["client_schema_evidence"]["server_observed"])
            self.assertTrue(stale["client_schema_evidence"]["caller_provided"])
            self.assertTrue(stale["rescan_required"])
            self.assertEqual(stale["schema_error_code"], "CLIENT_TOOL_SCHEMA_STALE")
            self.assertIn("apply_patch", stale["missing_on_client"])
        finally:
            runtime.close()

    def test_context_verification_ledger_lease_and_audit_flow(self) -> None:
        runtime = self._runtime()
        try:
            context = runtime.call_tool("context_pack", {"paths": ["README.md"]})["structuredContent"]
            self.assertNotIn("secret-value", json.dumps(context))
            self.assertEqual(context["schema_version"], 2)
            self.assertTrue(context["context_pack_id"].startswith("context:"))

            lease = runtime.call_tool(
                "director_writer_lease",
                {"action": "acquire", "owner_id": "chat-a", "task_id": "write-readme", "paths": ["README.md"]},
            )["structuredContent"]["lease"]
            self.assertEqual(
                runtime.call_tool(
                    "patch_preflight",
                    {"patch": "*** Begin Patch\n*** Update File: README.md\n*** End Patch\n", "lease_id": lease["lease_id"]},
                )["structuredContent"]["decision"]["status"],
                "allow",
            )

            plan = runtime.call_tool("verification_plan", {"changed_paths": ["README.md"]})["structuredContent"]
            self.assertEqual(plan["plan"]["tasks"], [])
            self.assertEqual(plan["plan"]["reason"], "NO_EXECUTION_REQUIRED")
            recorded = runtime.call_tool(
                "verification_record",
                {"changed_paths": ["README.md"], "results": []},
            )["structuredContent"]
            self.assertEqual(recorded["receipt"]["status"], "passed")

            queued = runtime.call_tool(
                "director_task_ledger",
                {"action": "enqueue", "request_id": "request-1", "title": "Verify"},
            )["structuredContent"]["receipt"]
            runtime.call_tool("director_task_ledger", {"action": "start", "task_id": queued["task_id"], "owner_id": "chat-a"})
            finished = runtime.call_tool(
                "director_task_ledger",
                {"action": "finish", "task_id": queued["task_id"], "owner_id": "chat-a", "status": "succeeded"},
            )["structuredContent"]["receipt"]
            self.assertEqual(finished["status"], "succeeded")

            self.assertEqual(lease["owner_id"], "chat-a")
            self.assertEqual(lease["paths"], ["README.md"])
            self.assertFalse(runtime.call_tool("security_audit", {})["isError"])
        finally:
            runtime.close()

    def test_director_task_ledger_registry_schema_accepts_resources(self) -> None:
        runtime = self._runtime()
        try:
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "director_task_ledger"},
            )["structuredContent"]
            self.assertIn("resources", described["input_schema"]["properties"])

            preflight = runtime.call_tool(
                "capability_preflight",
                {
                    "capability_id": "director_task_ledger",
                    "params": {
                        "action": "enqueue",
                        "request_id": "delivery-task-schema",
                        "title": "Publish canonical main",
                        "resources": ["delivery:github-main-publish"],
                    },
                },
            )
            self.assertFalse(preflight["isError"], preflight)
        finally:
            runtime.close()

    def test_apply_patch_requires_lease_and_rejects_stale_file_base(self) -> None:
        runtime = self._runtime()
        try:
            patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-hello\n+hello world\n*** End Patch\n"
            missing = runtime.call_tool("apply_patch", {"patch": patch})["structuredContent"]
            self.assertEqual(missing["error"]["code"], "WRITER_LEASE_REQUIRED")

            lease = runtime.call_tool(
                "director_writer_lease",
                {"action": "acquire", "owner_id": "chat-a", "task_id": "task-a", "paths": ["README.md"]},
            )["structuredContent"]["lease"]
            outside = runtime.call_tool(
                "patch_preflight",
                {
                    "patch": "*** Begin Patch\n*** Update File: other.txt\n*** End Patch\n",
                    "lease_id": lease["lease_id"],
                },
            )["structuredContent"]
            self.assertEqual(outside["error"]["code"], "WRITER_LEASE_REQUIRED")
            (self.repo / "README.md").write_text("changed elsewhere\n", encoding="utf-8")
            stale = runtime.call_tool(
                "apply_patch",
                {"patch": patch, "lease_id": lease["lease_id"]},
            )["structuredContent"]
            self.assertEqual(stale["error"]["code"], "STALE_WRITE_BASE")
        finally:
            runtime.close()

    def test_apply_patch_accepts_unified_diff_and_registers_managed_revert(self) -> None:
        runtime = self._runtime()
        try:
            for filename in ("alpha.txt", "beta.txt", "gamma.txt"):
                (self.repo / filename).write_text("before\n", encoding="utf-8")
            lease = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-unified",
                    "task_id": "task-unified",
                    "paths": ["README.md", "alpha.txt", "beta.txt", "gamma.txt"],
                },
            )["structuredContent"]["lease"]
            patch = "\n".join(
                (
                    "--- a/README.md",
                    "+++ b/README.md",
                    "@@ -2 +2 @@",
                    "-hello",
                    "+hello unified",
                    "--- a/alpha.txt",
                    "+++ b/alpha.txt",
                    "@@ -1 +1 @@",
                    "-before",
                    "+alpha unified",
                    "--- a/beta.txt",
                    "+++ b/beta.txt",
                    "@@ -1 +1 @@",
                    "-before",
                    "+beta unified",
                    "--- a/gamma.txt",
                    "+++ b/gamma.txt",
                    "@@ -1 +1 @@",
                    "-before",
                    "+gamma unified",
                )
            ) + "\n"
            preflight = runtime.call_tool(
                "patch_preflight",
                {"patch": patch, "lease_id": lease["lease_id"]},
            )["structuredContent"]
            self.assertEqual(
                preflight["decision"]["paths"],
                ["README.md", "alpha.txt", "beta.txt", "gamma.txt"],
            )
            applied = runtime.call_tool(
                "apply_patch",
                {"patch": patch, "lease_id": lease["lease_id"]},
            )
            self.assertFalse(applied["isError"], applied)
            managed_revert = applied["structuredContent"]["managed_revert"]
            self.assertEqual(managed_revert["status"], "registered")
            self.assertIn("hello unified", (self.repo / "README.md").read_text(encoding="utf-8"))
            for filename in ("alpha.txt", "beta.txt", "gamma.txt"):
                self.assertIn("unified", (self.repo / filename).read_text(encoding="utf-8"))
        finally:
            runtime.close()

    def test_writer_lease_allows_disjoint_paths_and_blocks_overlap(self) -> None:
        runtime = self._runtime()
        try:
            missing_paths = runtime.call_tool(
                "director_writer_lease",
                {"action": "acquire", "owner_id": "chat-z", "task_id": "task-z"},
            )["structuredContent"]
            self.assertEqual(missing_paths["error"]["code"], "DIRECTOR_LEASE_PATHS_REQUIRED")

            resource_only = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-resource",
                    "task_id": "task-resource",
                    "paths": [],
                    "resources": ["sqlite:test-db"],
                },
            )["structuredContent"]["lease"]
            self.assertEqual(resource_only["paths"], [])
            self.assertEqual(resource_only["resources"], ["sqlite:test-db"])

            (self.repo / "a.txt").write_text("a\n", encoding="utf-8")
            (self.repo / "b.txt").write_text("b\n", encoding="utf-8")
            first = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-a",
                    "task_id": "task-a",
                    "paths": ["a.txt"],
                    "resources": ["port:8765"],
                },
            )["structuredContent"]["lease"]
            second = runtime.call_tool(
                "director_writer_lease",
                {"action": "acquire", "owner_id": "chat-b", "task_id": "task-b", "paths": ["b.txt"]},
            )["structuredContent"]["lease"]
            self.assertNotEqual(first["lease_id"], second["lease_id"])
            status = runtime.call_tool("director_writer_lease", {"action": "status"})["structuredContent"]
            self.assertEqual(len(status["leases"]), 3)

            overlap = runtime.call_tool(
                "director_writer_lease",
                {"action": "acquire", "owner_id": "chat-c", "task_id": "task-c", "paths": ["a.txt"]},
            )["structuredContent"]
            self.assertFalse(overlap["ok"])

            resource = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-d",
                    "task_id": "task-d",
                    "paths": ["README.md"],
                    "resources": ["port:8765"],
                },
            )["structuredContent"]
            self.assertFalse(resource["ok"])
        finally:
            runtime.close()

    def test_stale_task_can_resume_and_bind_a_new_writer_lease(self) -> None:
        runtime = self._runtime()
        try:
            old_lease = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-a",
                    "task_id": "resume-task",
                    "paths": ["README.md"],
                },
            )["structuredContent"]["lease"]
            task_id = old_lease["task_id"]

            active_resume = runtime.call_tool(
                "director_task_ledger",
                {"action": "resume", "task_id": task_id, "owner_id": "chat-a"},
            )["structuredContent"]
            self.assertEqual(active_resume["error"]["code"], "DIRECTOR_TASK_LEASE_ACTIVE")

            runtime.call_tool(
                "director_writer_lease",
                {"action": "release", "lease_id": old_lease["lease_id"]},
            )
            stale = runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task_id,
                    "owner_id": "chat-a",
                    "status": "stale",
                    "detail": "lease expired",
                },
            )["structuredContent"]["receipt"]
            self.assertEqual(stale["status"], "stale")

            resumed = runtime.call_tool(
                "director_task_ledger",
                {"action": "resume", "task_id": task_id, "owner_id": "chat-a"},
            )["structuredContent"]["receipt"]
            self.assertEqual(resumed["status"], "ready")
            self.assertEqual(resumed["lease_id"], "")
            self.assertIsNone(resumed["owner_id"])

            new_lease = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-b",
                    "task_id": task_id,
                    "paths": ["README.md"],
                },
            )["structuredContent"]["lease"]
            self.assertNotEqual(new_lease["lease_id"], old_lease["lease_id"])
            rebound = runtime.call_tool(
                "director_task_ledger",
                {"action": "list", "workspace_id": "fixture"},
            )["structuredContent"]["records"]
            resumed_task = next(item for item in rebound if item["task_id"] == task_id)
            self.assertEqual(resumed_task["status"], "leased")
            self.assertEqual(resumed_task["lease_id"], new_lease["lease_id"])
            self.assertEqual(resumed_task["owner_id"], "chat-b")
        finally:
            runtime.close()

    def test_running_task_cannot_acquire_a_replacement_writer_lease_without_resume(self) -> None:
        runtime = self._runtime()
        try:
            first = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-a",
                    "task_id": "replace-running-task",
                    "paths": ["README.md"],
                },
            )["structuredContent"]["lease"]
            task_id = first["task_id"]
            runtime.call_tool(
                "director_task_ledger",
                {"action": "start", "task_id": task_id, "owner_id": "chat-a"},
            )
            runtime.call_tool(
                "director_writer_lease",
                {"action": "release", "lease_id": first["lease_id"]},
            )

            replacement = runtime.call_tool(
                "director_writer_lease",
                {
                    "action": "acquire",
                    "owner_id": "chat-a",
                    "task_id": task_id,
                    "paths": ["README.md"],
                },
            )["structuredContent"]

            self.assertFalse(replacement["ok"])
            self.assertEqual(replacement["error"]["code"], "DIRECTOR_PERSISTENCE_WRITE_FAILED")
            status = runtime.call_tool("director_writer_lease", {"action": "status"})["structuredContent"]
            self.assertEqual(status["leases"], [])
        finally:
            runtime.close()

    def test_trusted_development_registry_surface_and_lifecycle(self) -> None:
        runtime = self._runtime()
        try:
            names = {item["name"] for item in runtime.list_tools()["tools"]}
            self.assertEqual(len(names), 52)
            for capability_id in ("external_open", "workspace.trust.enable", "workspace.trust.revoke", "delivery.integrate", "delivery.push"):
                self.assertNotIn(capability_id, names)
                self.assertEqual(runtime.call_tool("capability_describe", {"capability_id":capability_id})["structuredContent"]["exposure"], "registry")
            policy = runtime.call_tool("workspace_project_policy_get", {"workspace_id":"fixture"})["structuredContent"]
            self.assertEqual(policy["policy"]["trust_level"], "standard")
            opening_params = {"kind":"url","target":"https://example.com"}
            opening = runtime.call_tool("capability_preflight", {"capability_id":"external_open","params":opening_params,"workspace_id":"fixture"})["structuredContent"]
            self.assertTrue(opening["approval_required"])
            enabling_params = {"expected_config_digest":policy["config_digest"]}
            enabling = runtime.call_tool("capability_preflight", {"capability_id":"workspace.trust.enable","params":enabling_params,"workspace_id":"fixture"})["structuredContent"]
            self.assertTrue(enabling["approval_required"])
            enabled = runtime.call_tool("capability_execute", {"preflight_id":enabling["preflight_id"],"capability_id":"workspace.trust.enable","params":enabling_params,"workspace_id":"fixture","confirmation":enabling["approval"]["confirmation"]})
            self.assertFalse(enabled["isError"], enabled)
            trusted = runtime.call_tool("workspace_project_policy_get", {"workspace_id":"fixture"})["structuredContent"]
            self.assertEqual(trusted["policy"]["trust_level"], "trusted_development")
            stale_open = runtime.call_tool("capability_execute", {"preflight_id":opening["preflight_id"],"capability_id":"external_open","params":opening_params,"workspace_id":"fixture","confirmation":opening["approval"]["confirmation"]})
            self.assertTrue(stale_open["isError"])
            fresh_open = runtime.call_tool("capability_preflight", {"capability_id":"external_open","params":opening_params,"workspace_id":"fixture"})["structuredContent"]
            self.assertFalse(fresh_open["approval_required"])
            revoking_params = {"expected_config_digest":trusted["config_digest"]}
            revoking = runtime.call_tool("capability_preflight", {"capability_id":"workspace.trust.revoke","params":revoking_params,"workspace_id":"fixture"})["structuredContent"]
            self.assertFalse(revoking["approval_required"])
            revoked = runtime.call_tool("capability_execute", {"preflight_id":revoking["preflight_id"],"capability_id":"workspace.trust.revoke","params":revoking_params,"workspace_id":"fixture"})
            self.assertFalse(revoked["isError"], revoked)
            self.assertEqual(runtime.call_tool("workspace_project_policy_get", {"workspace_id":"fixture"})["structuredContent"]["policy"]["trust_level"], "standard")
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
