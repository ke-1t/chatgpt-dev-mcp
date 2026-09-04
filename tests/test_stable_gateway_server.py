from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class StableGatewayServerTests(unittest.TestCase):
    def _runtime(self, root: Path, surface: str):
        from chatgpt_dev_mcp.server import WrapperRuntime

        env = {
            "HOME": str(root / "home"),
            "LOCAL_DEV_MCP_CONFIG": str(root / "config.json"),
            "LOCAL_DEV_MCP_DATA_DIR": str(root / "data"),
            "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
            "CHATGPT_DEV_MCP_SURFACE": surface,
        }
        return patch.dict(os.environ, env), WrapperRuntime

    def test_stable_gateway_mode_lists_exactly_fifty_two_tools_and_v25_schema(self) -> None:
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES, STABLE_SURFACE_REVISION

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    definitions = runtime.list_tools()["tools"]
                    names = tuple(item["name"] for item in definitions)
                    self.assertEqual(names, STABLE_PUBLIC_TOOL_NAMES)
                    info = runtime._server_info_without_workspace()
                    self.assertEqual(info["tool_count"], 52)
                    self.assertEqual(info["tool_schema"]["revision"], STABLE_SURFACE_REVISION)
                    self.assertEqual(info["health"]["schema_consistency"]["status"], "consistent")
                    self.assertEqual(info["health"]["schema_consistency"]["local_tool_schema"]["revision"], STABLE_SURFACE_REVISION)
                finally:
                    runtime.close()

    def test_capability_preflight_survives_wrapper_runtime_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                first = runtime_type()
                second = runtime_type()
                try:
                    params = {"action": "filesystem", "path": "/"}
                    preflight_result = first.call_tool(
                        "capability_preflight",
                        {"capability_id": "system_inspect", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]

                    executed = second.call_tool(
                        "capability_execute",
                        {
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "system_inspect",
                            "params": params,
                        },
                    )

                    self.assertFalse(executed["isError"], executed)
                    result = executed["structuredContent"]["result"]
                    self.assertEqual(result["status"], "succeeded")
                    self.assertTrue(result["read_only"])

                    replay = first.call_tool(
                        "capability_execute",
                        {
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "system_inspect",
                            "params": params,
                        },
                    )
                    self.assertTrue(replay["isError"], replay)
                    self.assertEqual(
                        replay["structuredContent"]["error"]["code"],
                        "CAPABILITY_PREFLIGHT_REPLAY",
                    )
                finally:
                    second.close()
                    first.close()

    def test_runtime_activation_survives_stable_gateway_lifecycle_audit(self) -> None:
        from chatgpt_dev_mcp.runtime_activation import RuntimeActivationController, RuntimeReadback

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
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
            environment, runtime_type = self._runtime(root, "stable_gateway")
            executor_calls: list[str] = []
            provisioning_events_at_executor: list[int] = []
            current = RuntimeReadback(
                source_root=Path("/current"),
                head="c" * 40,
                schema_version=14,
                doctor_status="HEALTHY",
                tool_count=76,
                tool_schema_hash="f" * 64,
                persistence_status="HEALTHY",
                cross_call_receipt_continuity="PASS",
                readonly_root_continuity="PASS",
                tunnel_status="HEALTHY",
                source_clean=True,
            )
            controller = RuntimeActivationController(
                git_head_reader=lambda _root: "a" * 40,
                git_clean_reader=lambda _root: True,
                git_descendant_reader=lambda _root, _base, _head: True,
                git_diff_hash_reader=lambda _root: "e" * 64,
                schema_reader=lambda _path: 14,
                catalog_reader=lambda _candidate: {
                    "status": "HEALTHY",
                    "tool_count": 76,
                    "tool_schema_hash": "f" * 64,
                },
                doctor_reader=lambda _candidate: {"status": "HEALTHY"},
                mutation_reader=lambda: False,
                executor=lambda _plan: (
                    provisioning_events_at_executor.append(
                        len(runtime._persistence.load_provisioning_events("fixture"))  # noqa: SLF001
                    )
                    or executor_calls.append("executor")
                    or {"status": "started"}
                ),
                post_readback=lambda _candidate: {
                    "head": "a" * 40,
                    "schema_version": 14,
                    "doctor_status": "HEALTHY",
                    "tool_count": 76,
                    "tool_schema_hash": "f" * 64,
                    "persistence_status": "HEALTHY",
                    "cross_call_receipt_continuity": "PASS",
                    "readonly_root_continuity": "PASS",
                    "tunnel_status": "HEALTHY",
                    "state_isolation": "PASS",
                    "port_isolation": "PASS",
                },
            )
            with environment:
                runtime = runtime_type(
                    runtime_activation_controller=controller,
                    runtime_activation_current_reader=lambda: current,
                )
                try:
                    candidate_root = root / "candidate"
                    candidate_root.mkdir()
                    entrypoint = candidate_root / "server.py"
                    entrypoint.write_text("print('candidate')\n", encoding="utf-8")
                    python = root / "python"
                    python.write_text("#!/bin/sh\n", encoding="utf-8")
                    python.chmod(0o700)
                    params = {
                        "candidate_root": str(candidate_root),
                        "expected_head": "a" * 40,
                        "expected_schema_version": 14,
                        "entrypoint": str(entrypoint),
                        "python_executable": str(python),
                        "state_dir": str(runtime._persistence.path.parent),  # noqa: SLF001
                        "database_path": str(runtime._persistence.path),  # noqa: SLF001
                        "expected_base_revision": "b" * 40,
                        "expected_patch_hash": "e" * 64,
                        "expected_tool_schema_hash": "f" * 64,
                        "canary_receipt": {
                            "status": "PASS",
                            "candidate_head": "a" * 40,
                            "schema_version": 14,
                            "tool_count": 76,
                            "tool_schema_hash": "f" * 64,
                            "patch_hash": "e" * 64,
                            "doctor_status": "HEALTHY",
                            "persistence_status": "HEALTHY",
                            "cross_call_receipt_continuity": "PASS",
                            "readonly_root_continuity": "PASS",
                            "integration_preflight": "PASS",
                            "tunnel_status": "HEALTHY",
                            "state_isolation": "PASS",
                            "port_isolation": "PASS",
                        },
                    }
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "capability_id": "runtime.candidate.activate",
                            "params": params,
                        },
                        request_id="activation-preflight",
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    handler_preflight = preflight["handler_preflight"]
                    self.assertEqual(handler_preflight["semantic_digest_version"], "activation-db-semantic-v1")
                    self.assertEqual(handler_preflight["excluded_audit_tables"], ["request_lifecycle_events"])

                    execute_result = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "runtime.candidate.activate",
                            "params": params,
                            "confirmation": preflight["approval"]["confirmation"],
                        },
                        request_id="activation-execute",
                    )

                    self.assertFalse(execute_result["isError"], execute_result)
                    self.assertEqual(execute_result["structuredContent"]["result"]["status"], "ACTIVATED")
                    self.assertEqual(executor_calls, ["executor"])
                    self.assertEqual(provisioning_events_at_executor, [0])
                    self.assertEqual(
                        [
                            event["event_type"]
                            for event in runtime._persistence.load_provisioning_events("fixture")  # noqa: SLF001
                        ],
                        [
                            "RUNTIME_CANDIDATE_ACTIVATE_REQUESTED",
                            "RUNTIME_CANDIDATE_ACTIVATE_SUCCEEDED",
                        ],
                    )
                finally:
                    runtime.close()

    def test_director_health_composes_bounded_runtime_observability_without_new_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    runtime._performance_metrics.record("context.bootstrap", 12.0)
                    health = runtime.call_tool("director_health", {})

                    self.assertFalse(health["isError"], health)
                    observability = health["structuredContent"]["observability"]
                    self.assertEqual(len(runtime.list_tools()["tools"]), 52)
                    self.assertIn("providers", observability)
                    self.assertIn("performance", observability)
                    self.assertIn("retained_sessions", observability)
                    self.assertIn("persistence", observability)
                    self.assertIn("tunnel", observability)
                    self.assertEqual(observability["retained_sessions"]["total"], 0)
                    self.assertEqual(observability["retained_sessions"]["scope"], "global")
                    self.assertEqual(observability["retained_sessions"]["active_by_project"], {})
                    self.assertGreaterEqual(observability["performance"]["sample_count"], 1)
                    self.assertFalse(observability["providers"]["process_started"])
                    self.assertFalse(observability["providers"]["network_used"])
                finally:
                    runtime.close()

    def test_verification_performance_outcome_treats_continuations_as_neutral(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self.assertEqual(WrapperRuntime._verification_performance_outcome("passed"), (True, False, ""))
        self.assertEqual(WrapperRuntime._verification_performance_outcome("incomplete"), (True, True, ""))
        self.assertEqual(WrapperRuntime._verification_performance_outcome("not_run"), (True, True, ""))
        self.assertEqual(
            WrapperRuntime._verification_performance_outcome("failed"),
            (False, False, "verification_failed"),
        )

    def test_performance_observability_marks_legacy_ambiguous_verification_outcomes_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    runtime._acceleration_observer.record(
                        "performance",
                        subject_id="verification.run",
                        reason="runtime_metric",
                        metadata={
                            "workspace_id": "fixture",
                            "duration_ms": 10.0,
                            "output_bytes": 0,
                            "cache_status": "none",
                            "reused": False,
                            "success": False,
                            "failure_fingerprint": "verification_not_passed",
                        },
                    )
                    runtime._acceleration_observer.record(
                        "performance",
                        subject_id="verification.run",
                        reason="runtime_metric",
                        metadata={
                            "workspace_id": "fixture",
                            "duration_ms": 20.0,
                            "output_bytes": 0,
                            "cache_status": "none",
                            "reused": False,
                            "success": False,
                            "failure_fingerprint": "verification_failed",
                        },
                    )

                    stage = runtime._performance_observability_summary()["stages"]["verification.run"]

                    self.assertEqual(stage["count"], 2)
                    self.assertEqual(stage["neutral_count"], 1)
                    self.assertEqual(stage["completed_count"], 1)
                    self.assertEqual(stage["failure_count"], 1)
                    self.assertEqual(stage["failure_rate"], 1.0)
                    self.assertEqual(stage["failure_fingerprints"], {"verification_failed": 1})
                finally:
                    runtime.close()

    def test_surface_profile_is_pinned_at_runtime_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    before = [item["name"] for item in runtime.list_tools()["tools"]]
                    os.environ["CHATGPT_DEV_MCP_SURFACE"] = "legacy"
                    after = [item["name"] for item in runtime.list_tools()["tools"]]
                    self.assertEqual(before, after)
                    self.assertEqual(len(after), 52)
                finally:
                    runtime.close()

    def test_legacy_mode_does_not_advertise_gateway_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "legacy")
            with environment:
                runtime = runtime_type()
                try:
                    names = {item["name"] for item in runtime.list_tools()["tools"]}
                    self.assertNotIn("capability_catalog", names)
                    self.assertNotIn("capability_execute", names)
                    self.assertGreater(len(names), 52)
                finally:
                    runtime.close()

    def test_catalog_and_describe_are_callable_without_workspace_and_hide_handler_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    catalog_result = runtime.call_tool("capability_catalog", {"shard": "qa"})
                    self.assertFalse(catalog_result["isError"], catalog_result)
                    catalog = catalog_result["structuredContent"]
                    self.assertEqual(len(catalog["registry"]["shards"]), 7)
                    self.assertIn("platform.profile.register", [item["capability_id"] for item in catalog["capabilities"]])

                    describe_result = runtime.call_tool("capability_describe", {"capability_id": "platform.profile.register"})
                    self.assertFalse(describe_result["isError"], describe_result)
                    described = describe_result["structuredContent"]
                    self.assertEqual(described["shard"], "qa")
                    self.assertNotIn("handler", described)
                    self.assertNotIn("handler_version", described)
                finally:
                    runtime.close()

    def test_development_catalog_exposes_hybrid_capabilities_without_changing_tool_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    self.assertEqual(len(runtime.list_tools()["tools"]), 52)
                    catalog_result = runtime.call_tool("capability_catalog", {"shard": "development"})
                    self.assertFalse(catalog_result["isError"], catalog_result)
                    capability_ids = {
                        item["capability_id"]
                        for item in catalog_result["structuredContent"]["capabilities"]
                    }
                    self.assertIn("development.execution.route", capability_ids)
                    self.assertIn("development.fast_step", capability_ids)
                    self.assertIn("development.analysis_pack", capability_ids)
                    self.assertIn("development.session.abandon", capability_ids)
                    self.assertIn("development.session_list", capability_ids)
                    self.assertIn("development.session.reconcile_stale_state", capability_ids)
                    self.assertIn("development.session.repair_source_identity", capability_ids)
                    self.assertNotIn("development.cloud_compute", capability_ids)
                    self.assertNotIn("development.openai_api_compute", capability_ids)
                    self.assertNotIn("development.openai_probe", capability_ids)
                    self.assertIn("context.bootstrap", capability_ids)
                    self.assertIn("context.focus", capability_ids)
                    self.assertIn("context.checkpoint", capability_ids)
                    self.assertIn("performance.summary", capability_ids)
                    for removed_capability in (
                        "development.cloud_compute",
                        "development.openai_api_compute",
                        "development.openai_probe",
                    ):
                        description = runtime.call_tool(
                            "capability_describe",
                            {"capability_id": removed_capability},
                        )
                        self.assertTrue(description["isError"], description)
                    abandon_description = runtime.call_tool(
                        "capability_describe",
                        {"capability_id": "development.session.abandon"},
                    )
                    self.assertFalse(abandon_description["isError"], abandon_description)
                    self.assertEqual(abandon_description["structuredContent"]["risk_class"], "R2")
                    self.assertEqual(abandon_description["structuredContent"]["approval_policy"], "human")
                    reconcile_description = runtime.call_tool(
                        "capability_describe",
                        {"capability_id": "development.session.reconcile_stale_state"},
                    )
                    self.assertFalse(reconcile_description["isError"], reconcile_description)
                    self.assertEqual(reconcile_description["structuredContent"]["risk_class"], "R1")
                    repair_description = runtime.call_tool(
                        "capability_describe",
                        {"capability_id": "development.session.repair_source_identity"},
                    )
                    self.assertFalse(repair_description["isError"], repair_description)
                    self.assertEqual(repair_description["structuredContent"]["risk_class"], "R1")
                    self.assertEqual(repair_description["structuredContent"]["approval_policy"], "automatic")
                finally:
                    runtime.close()

    def test_workspace_organization_capabilities_are_registry_only_and_describable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    direct_names = {item["name"] for item in runtime.list_tools()["tools"]}
                    self.assertEqual(len(direct_names), 52)
                    self.assertNotIn("project_group_create", direct_names)
                    self.assertNotIn("workspace_relocate_preflight", direct_names)
                    self.assertNotIn("workspace_relocate", direct_names)

                    catalog = runtime.call_tool(
                        "capability_catalog",
                        {"category": "workspace_organization", "limit": 100},
                    )
                    self.assertFalse(catalog["isError"], catalog)
                    ids = {
                        item["capability_id"]
                        for item in catalog["structuredContent"]["capabilities"]
                    }
                    self.assertEqual(
                        ids,
                        {"project_group_create", "workspace_relocate_preflight", "workspace_relocate"},
                    )

                    expected = {
                        "project_group_create": ("R2", "human"),
                        "workspace_relocate_preflight": ("R0", "none"),
                        "workspace_relocate": ("R3", "delegated"),
                    }
                    for capability_id, (risk_class, approval_policy) in expected.items():
                        described = runtime.call_tool(
                            "capability_describe",
                            {"capability_id": capability_id},
                        )
                        self.assertFalse(described["isError"], described)
                        payload = described["structuredContent"]
                        self.assertEqual(payload["risk_class"], risk_class)
                        self.assertEqual(payload["approval_policy"], approval_policy)
                        self.assertEqual(payload["category"], "workspace_organization")
                        self.assertEqual(payload["exposure"], "registry")
                finally:
                    runtime.close()

    def test_macos_app_replace_is_human_approved_long_tail_and_hides_source_url(self) -> None:
        from chatgpt_dev_mcp.macos_app_install import MacOSAppInstallPlan, MacOSAppInstallResult

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            config = root / "config.json"
            config.write_text(
                json.dumps({
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                }),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    self.assertEqual(len(runtime.list_tools()["tools"]), 52)
                    catalog_result = runtime.call_tool("capability_catalog", {"shard": "platform_integrations", "limit": 100})
                    self.assertFalse(catalog_result["isError"], catalog_result)
                    capability_names = {item["capability_id"] for item in catalog_result["structuredContent"]["capabilities"]}
                    self.assertIn("platform.macos_app.replace", capability_names)

                    secret_url = "https://downloads.example.com/Demo.dmg?token=must-not-leak"
                    plan = MacOSAppInstallPlan(
                        source_url=secret_url,
                        artifact_kind="dmg",
                        app_name="Demo.app",
                        bundle_id="com.example.demo",
                        destination=Path("/Applications/Demo.app"),
                        installed_version="1.0",
                        expected_team_id="TEAM12345",
                    )
                    runtime._macos_app_install = SimpleNamespace(
                        prepare=lambda **kwargs: plan,
                        execute=lambda prepared: MacOSAppInstallResult(
                            ok=True,
                            bundle_id=prepared.bundle_id,
                            previous_version=prepared.installed_version,
                            installed_version="2.0",
                            destination=str(prepared.destination),
                            team_id=prepared.expected_team_id,
                        ),
                    )
                    params = {"source_url": secret_url, "app_name": "Demo.app", "bundle_id": "com.example.demo"}
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "platform.macos_app.replace", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertEqual(preflight["risk_class"], "R3")
                    self.assertEqual(preflight["approval_policy"], "human")
                    self.assertTrue(preflight["approval_required"])
                    self.assertTrue(preflight["network_allowed"])
                    self.assertNotIn(secret_url, json.dumps(preflight["handler_preflight"], sort_keys=True))
                    self.assertEqual(preflight["handler_preflight"]["bundle_id"], "com.example.demo")
                    execute_result = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "platform.macos_app.replace",
                            "params": params,
                            "confirmation": preflight["approval"]["confirmation"],
                        },
                    )
                    self.assertFalse(execute_result["isError"], execute_result)
                    result = execute_result["structuredContent"]["result"]
                    self.assertTrue(result["ok"])
                    self.assertEqual(result["installed_version"], "2.0")
                    self.assertFalse(result["user_data_removed"])
                    self.assertFalse(result["privilege_escalation_used"])
                finally:
                    runtime.close()

    def test_external_capability_invoke_records_reuse_without_payload_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    runtime._capability_gateway = SimpleNamespace(
                        close=lambda: None,
                        invoke=lambda capability, request: {
                            "status": "succeeded",
                            "reason": "provider_result",
                            "capability": capability,
                            "provider_id": "fixture-provider",
                            "restarted": False,
                            "provider_reused": True,
                            "output": "payload-that-must-not-be-metric-metadata",
                            "output_truncated": False,
                            "external_execution": False,
                        }
                    )
                    context = SimpleNamespace(workspace_id="fixture-workspace")

                    result = runtime._external_capability_invoke(
                        "docs.resolve",
                        {"query": "secret-free-request-body"},
                        context,
                    )

                    self.assertTrue(result["provider_reused"])
                    summary = runtime._performance_metrics.summary()
                    self.assertEqual(summary["reuse_count"], 1)
                    self.assertIn("external.capability.invoke", summary["stages"])
                    receipts = runtime._persistence.load_acceleration_receipts(kind="performance", limit=10)
                    matching = [item for item in receipts if item.get("subject_id") == "external.capability.invoke"]
                    self.assertEqual(len(matching), 1)
                    metadata = matching[0]["metadata"]
                    self.assertEqual(metadata["workspace_id"], "fixture-workspace")
                    self.assertTrue(metadata["reused"])
                    self.assertNotIn("query", metadata)
                    self.assertNotIn("output", metadata)
                finally:
                    runtime.close()

    def test_context_capabilities_execute_through_stable_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            (repo / "AGENTS.md").write_text("# Project rules\n- Never push without approval\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "commit", "-qm", "init"],
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
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    opened = runtime.call_tool("workspace_open", {"id": "fixture"})
                    self.assertFalse(opened["isError"], opened)
                    working_tree_id = opened["structuredContent"]["identity"]["worktree_id"]
                    bootstrap = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(bootstrap["isError"], bootstrap)
                    bootstrap_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "preflight_id": bootstrap["structuredContent"]["preflight_id"], "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(bootstrap_exec["isError"], bootstrap_exec)
                    self.assertEqual(bootstrap_exec["structuredContent"]["result"]["workspace_id"], "fixture")
                    self.assertFalse(bootstrap_exec["structuredContent"]["result"]["external_execution"])

                    bootstrap_result = bootstrap_exec["structuredContent"]["result"]
                    self.assertEqual(bootstrap_result["instructions_status"], "loaded")
                    self.assertTrue(
                        any(
                            "Never push without approval" in item
                            for item in bootstrap_result["capsule"]["sections"]["instructions"]
                        )
                    )

                    performance = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "performance.summary", "params": {"limit": 256, "top": 20}},
                    )
                    self.assertFalse(performance["isError"], performance)
                    performance_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "performance.summary", "preflight_id": performance["structuredContent"]["preflight_id"], "params": {"limit": 256, "top": 20}},
                    )
                    self.assertFalse(performance_exec["isError"], performance_exec)
                    performance_result = performance_exec["structuredContent"]["result"]
                    self.assertEqual(performance_result["workspace_id"], "fixture")
                    self.assertGreaterEqual(performance_result["sample_count"], 1)
                    self.assertIn("context.bootstrap", performance_result["stages"])

                    session_list_params = {"limit": 5}
                    session_list = runtime.call_tool(
                        "capability_preflight",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": working_tree_id,
                            "capability_id": "development.session_list",
                            "params": session_list_params,
                        },
                    )
                    self.assertFalse(session_list["isError"], session_list)
                    session_list_exec = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": working_tree_id,
                            "capability_id": "development.session_list",
                            "preflight_id": session_list["structuredContent"]["preflight_id"],
                            "params": session_list_params,
                        },
                    )
                    self.assertFalse(session_list_exec["isError"], session_list_exec)
                    session_list_result = session_list_exec["structuredContent"]["result"]
                    self.assertEqual(session_list_result["workspace_id"], "fixture")
                    self.assertEqual(session_list_result["returned"], 0)
                    self.assertEqual(session_list_result["counts"]["filtered_total"], 0)
                    self.assertFalse(session_list_result["external_execution"])

                    checkpoint_params = {
                        "task_id": "task-fixture",
                        "outcome": "verified",
                        "next_action": "commit the focused fixture change",
                    }
                    checkpoint = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.checkpoint", "params": checkpoint_params},
                    )
                    self.assertFalse(checkpoint["isError"], checkpoint)
                    checkpoint_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.checkpoint", "preflight_id": checkpoint["structuredContent"]["preflight_id"], "params": checkpoint_params},
                    )
                    self.assertFalse(checkpoint_exec["isError"], checkpoint_exec)
                    checkpoint_id = checkpoint_exec["structuredContent"]["result"]["checkpoint_id"]
                    self.assertTrue(checkpoint_id.startswith("checkpoint:"))

                    resumed = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(resumed["isError"], resumed)
                    resumed_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "preflight_id": resumed["structuredContent"]["preflight_id"], "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(resumed_exec["isError"], resumed_exec)
                    continuation = resumed_exec["structuredContent"]["result"]["capsule"]["sections"]["continuation"]
                    self.assertIn("next:commit the focused fixture change", continuation)

                    (repo / "README.md").write_text("fixture changed\n", encoding="utf-8")
                    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
                    subprocess.run(
                        ["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "commit", "-qm", "advance"],
                        check=True,
                    )
                    delta_preflight = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(delta_preflight["isError"], delta_preflight)
                    delta_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.bootstrap", "preflight_id": delta_preflight["structuredContent"]["preflight_id"], "params": {"max_bytes": 4096}},
                    )
                    self.assertFalse(delta_exec["isError"], delta_exec)
                    delta_result = delta_exec["structuredContent"]["result"]
                    self.assertIn("next:commit the focused fixture change", delta_result["capsule"]["sections"]["continuation"])
                    self.assertTrue(delta_result["delta"]["head_changed"])

                    focus = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.focus", "params": {"task_id": "task-fixture", "query": "README fixture", "target_paths": ["README.md"], "max_bytes": 4096}},
                    )
                    self.assertFalse(focus["isError"], focus)
                    focus_exec = runtime.call_tool(
                        "capability_execute",
                        {"workspace_id": "fixture", "working_tree_id": working_tree_id, "capability_id": "context.focus", "preflight_id": focus["structuredContent"]["preflight_id"], "params": {"task_id": "task-fixture", "query": "README fixture", "target_paths": ["README.md"], "max_bytes": 4096}},
                    )
                    self.assertFalse(focus_exec["isError"], focus_exec)
                    self.assertEqual(focus_exec["structuredContent"]["result"]["query"], "README fixture")
                    self.assertFalse(focus_exec["structuredContent"]["result"]["external_execution"])
                finally:
                    runtime.close()

    def test_runtime_registers_available_stdio_provider_into_internal_gateway(self) -> None:
        class FixtureProvider:
            def status(self):
                return {"status": "available", "tools": []}

            def invoke(self, capability, request):
                return {"ok": True}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider = FixtureProvider()
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment, patch(
                "chatgpt_dev_mcp.server.CapabilityAdapterCatalog.build_provider",
                side_effect=lambda provider_id: provider if provider_id == "context7" else None,
            ):
                runtime = runtime_type()
                try:
                    statuses = {
                        item["provider_id"]: item
                        for item in runtime._capability_gateway.status()["providers"]
                    }
                    self.assertEqual(statuses["context7"]["status"], "available")
                finally:
                    runtime.close()

    def test_hybrid_route_capability_auto_falls_back_to_local_without_cloud_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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
                        "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                    }
                ),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    params = {
                        "mode": "auto",
                        "workload": "compute_heavy",
                        "chatgpt_builtin_available": True,
                    }
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "development.execution.route", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertFalse(preflight["approval_required"])
                    self.assertEqual(preflight["handler_preflight"]["backend"], "local_native")
                    self.assertFalse(preflight["handler_preflight"]["fallback"])
                    self.assertEqual(preflight["handler_preflight"]["reason"], "auto_performance_profile_missing")
                    self.assertEqual(preflight["handler_preflight"]["execution_kind"], "local_execute")
                    self.assertFalse(preflight["handler_preflight"]["billable_api"])
                    self.assertTrue(preflight["handler_preflight"]["chatgpt_builtin_available"])
                    self.assertTrue(preflight["handler_preflight"]["managed_cloud_available"])
                    self.assertNotIn("api_cloud_available", preflight["handler_preflight"])
                    self.assertNotIn("openai_api_available", preflight["handler_preflight"])
                    self.assertIsNone(preflight["handler_preflight"]["performance_profile_id"])

                    execute_result = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "development.execution.route",
                            "params": params,
                        },
                    )
                    self.assertFalse(execute_result["isError"], execute_result)
                    result = execute_result["structuredContent"]["result"]
                    self.assertEqual(result["backend"], "local_native")
                    self.assertFalse(result["fallback"])
                finally:
                    runtime.close()

    def test_hybrid_route_explicit_cloud_is_non_billable_builtin_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            config = root / "config.json"
            config.write_text(
                json.dumps({
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                }),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    params = {"mode": "cloud", "workload": "compute_heavy", "chatgpt_builtin_available": True}
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "development.execution.route", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    route = preflight_result["structuredContent"]["handler_preflight"]
                    self.assertEqual(route["backend"], "chatgpt_builtin")
                    self.assertEqual(route["reason"], "explicit_chatgpt_builtin_mode")
                    self.assertEqual(route["execution_kind"], "assistant_handoff")
                    self.assertTrue(route["requires_assistant_action"])
                    self.assertFalse(route["human_confirmation_required"])
                    self.assertFalse(route["billable_api"])
                finally:
                    runtime.close()

    def test_hybrid_route_rejects_removed_api_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            config = root / "config.json"
            config.write_text(
                json.dumps({
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                }),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    params = {"mode": "api", "workload": "bulk_analysis"}
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "development.execution.route", "params": params},
                    )
                    self.assertTrue(preflight_result["isError"], preflight_result)
                finally:
                    runtime.close()

    def test_hybrid_route_uses_current_persisted_managed_cloud_profile_when_adapter_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                        "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                    }
                ),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            managed = SimpleNamespace(
                status=lambda: {"available": True, "reason": "ready", "environment_fingerprint": "cloud:test-v1"},
            )
            with environment:
                runtime = runtime_type(managed_cloud_adapter=managed)
                try:
                    project_fingerprint = runtime._hybrid_project_fingerprint("fixture")
                    local_fingerprint = runtime._hybrid_local_environment_fingerprint()
                    now = runtime._now()
                    runtime._persistence.save_cloud_performance_profile(
                        {
                            "profile_id": "profile:" + "c" * 32,
                            "workload_class": "compute_heavy",
                            "project_fingerprint": project_fingerprint,
                            "local_environment_fingerprint": local_fingerprint,
                            "cloud_environment_fingerprint": "cloud:test-v1",
                            "benchmark_revision": "managed-cloud-benchmark-v1",
                            "local_success_samples": 5,
                            "cloud_success_samples": 5,
                            "local_p50_ms": 100.0,
                            "local_p95_ms": 120.0,
                            "cloud_p50_ms": 70.0,
                            "cloud_p95_ms": 100.0,
                            "cloud_stage_p50_ms": 5.0,
                            "cloud_return_p50_ms": 4.0,
                            "local_failure_rate": 0.0,
                            "cloud_failure_rate": 0.0,
                            "speed_ratio_p50": 100.0 / 70.0,
                            "observed_at": now,
                            "expires_at": now + 3600.0,
                            "billable_api": False,
                            "sufficient": True,
                            "managed_cloud_wins": True,
                        }
                    )
                    params = {
                        "mode": "auto",
                        "workload": "compute_heavy",
                        "chatgpt_builtin_available": True,
                    }
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "development.execution.route", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    route = preflight_result["structuredContent"]["handler_preflight"]
                    self.assertEqual(route["backend"], "chatgpt_builtin")
                    self.assertEqual(route["reason"], "auto_chatgpt_builtin_measured_win")
                    self.assertEqual(route["execution_kind"], "assistant_handoff")
                    self.assertTrue(route["requires_assistant_action"])
                    self.assertFalse(route["human_confirmation_required"])
                    self.assertFalse(route["billable_api"])
                    self.assertTrue(route["chatgpt_builtin_available"])
                    self.assertEqual(route["performance_profile_id"], "profile:" + "c" * 32)
                    self.assertEqual(route["local_success_samples"], 5)
                    self.assertEqual(route["cloud_success_samples"], 5)
                    self.assertEqual(route["local_p50_ms"], 100.0)
                    self.assertEqual(route["cloud_p50_ms"], 70.0)
                finally:
                    runtime.close()

    def test_analysis_pack_executes_read_only_over_bound_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("before\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            (repo / "README.md").write_text("after\n", encoding="utf-8")
            config = root / "config.json"
            config.write_text(
                json.dumps({
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {"fixture": {"path": str(repo), "profile": "DEVELOPMENT", "commands": {}}},
                }),
                encoding="utf-8",
            )
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    params = {
                        "task_id": "task-analysis",
                        "changed_paths": ["README.md"],
                        "include_diff": True,
                        "include_failures": True,
                        "max_bytes": 4096,
                    }
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "development.analysis_pack", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertFalse(preflight["approval_required"])
                    execute_result = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "development.analysis_pack",
                            "params": params,
                        },
                    )
                    self.assertFalse(execute_result["isError"], execute_result)
                    result = execute_result["structuredContent"]["result"]
                    self.assertEqual(result["workspace_id"], "fixture")
                    self.assertEqual(result["task_id"], "task-analysis")
                    self.assertEqual(result["changed_files"], ["README.md"])
                    self.assertIn("README.md", result["diffs"])
                    self.assertIn("+after", result["diffs"]["README.md"])
                    self.assertFalse(result["external_execution"])
                    self.assertLessEqual(result["used_bytes"], 4096)
                finally:
                    runtime.close()

    def test_fast_step_server_composes_existing_safe_operations_in_one_call(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    session_id = "session:test-fast-step"
                    task_id = "task-fast-step"
                    owner_id = "owner-fast-step"
                    runtime.development_sessions[session_id] = SimpleNamespace(
                        session_id=session_id,
                        owner_id=owner_id,
                        task_id=task_id,
                        source_revision="a" * 40,
                        base_commit="a" * 40,
                        stale=False,
                        lifecycle_state="active",
                        worktree_path=root,
                        is_expired=lambda now: False,
                    )
                    context = CapabilityExecutionContext(
                        workspace_id="fixture",
                        working_tree_id=session_id,
                        session_id=session_id,
                        owner_id=owner_id,
                        task_id=task_id,
                        policy_revision="project-policy-v1",
                        policy_digest="a" * 64,
                        writer_lease_id="lease-fast-step",
                        workspace_trust_level="trusted_development",
                    )
                    order: list[str] = []
                    with (
                        patch("chatgpt_dev_mcp.server.repo_dirty", return_value=True),
                        patch.object(runtime, "_workspace_status", side_effect=lambda args: order.append("status") or {"ok": True}),
                        patch.object(runtime, "_development_context", side_effect=lambda args: order.append("context") or {"items": []}),
                        patch.object(runtime, "_invoke_legacy_capability", side_effect=lambda name, params, ctx: order.append(name) or {"patch": ""}),
                        patch.object(runtime, "_verification_run", side_effect=lambda args: order.append("verify") or {"status": "passed", "cache_status": "hit", "results": [{"task": "test", "exit_code": 0, "output": "ok", "duration_ms": 1, "timed_out": False}]}),
                        patch.object(runtime, "_director_verification_record", side_effect=lambda args: order.append("formalize") or {"receipt": {"receipt_id": "verify:test"}}),
                        patch.object(runtime, "_director_security_audit", side_effect=lambda args: order.append(f"audit:{args.get('verification_receipt_id')}") or {"report": {"status": "pass"}}),
                    ):
                        result = runtime._development_fast_step_execute(
                            {"query": "inspect", "changed_paths": ["src/a.py"], "verify": True, "audit": True},
                            context,
                        )
                    self.assertEqual(order, ["status", "context", "git_diff", "verify", "formalize", "audit:verify:test"])
                    self.assertEqual(result["backend"], "local_native")
                    self.assertEqual(result["verification"]["formal"]["receipt"]["receipt_id"], "verify:test")
                    self.assertEqual(result["metrics"]["cache_hits"], 1)
                    self.assertEqual(result["metrics"]["reuse_count"], 1)
                finally:
                    runtime.development_sessions.pop("session:test-fast-step", None)
                    runtime.close()

    def test_fast_step_clean_audit_does_not_reuse_stale_verification_receipt(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    session_id = "session:test-clean-fast-step"
                    task_id = "task-clean-fast-step"
                    owner_id = "owner-clean-fast-step"
                    runtime.development_sessions[session_id] = SimpleNamespace(
                        session_id=session_id,
                        owner_id=owner_id,
                        task_id=task_id,
                        source_revision="a" * 40,
                        base_commit="a" * 40,
                        stale=False,
                        lifecycle_state="active",
                        worktree_path=root,
                        is_expired=lambda now: False,
                    )
                    context = CapabilityExecutionContext(
                        workspace_id="fixture",
                        working_tree_id=session_id,
                        session_id=session_id,
                        owner_id=owner_id,
                        task_id=task_id,
                        policy_revision="project-policy-v1",
                        policy_digest="a" * 64,
                        writer_lease_id="lease-clean-fast-step",
                    )
                    audit_args: list[dict[str, object]] = []
                    with (
                        patch("chatgpt_dev_mcp.server.repo_dirty", return_value=False),
                        patch.object(runtime, "_workspace_status", return_value={"ok": True}),
                        patch.object(runtime, "_development_context", return_value={"items": []}),
                        patch.object(runtime, "_invoke_legacy_capability", return_value={"diff": ""}),
                        patch.object(
                            runtime,
                            "_director_security_audit",
                            side_effect=lambda args: audit_args.append(dict(args)) or {"report": {"status": "pass"}},
                        ),
                    ):
                        result = runtime._development_fast_step_execute(
                            {"query": "inspect", "changed_paths": [], "verify": True, "audit": True},
                            context,
                        )
                    self.assertIsNone(result["verification"])
                    self.assertEqual(len(audit_args), 1)
                    self.assertTrue(audit_args[0].get("_skip_verification_if_clean"))
                    self.assertNotIn("verification_receipt_id", audit_args[0])
                finally:
                    runtime.development_sessions.pop("session:test-clean-fast-step", None)
                    runtime.close()

    def test_legacy_command_profile_bridge_delegates_only_fixed_fast_step_in_trusted_context(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    context = CapabilityExecutionContext(
                        workspace_id="fixture",
                        working_tree_id="session:fixture",
                        session_id="session:fixture",
                        owner_id="owner",
                        task_id="task",
                        policy_revision="project-policy-v1",
                        policy_digest="a" * 64,
                        writer_lease_id="lease-fixture",
                        workspace_trust_level="trusted_development",
                    )
                    preflight_calls: list[tuple[str, dict[str, object]]] = []
                    execute_calls: list[tuple[str, dict[str, object]]] = []

                    def fake_preflight(capability_id, params, received_context):
                        self.assertIs(received_context, context)
                        preflight_calls.append((capability_id, dict(params)))
                        return {
                            "preflight_id": "capability-preflight:fixture",
                            "capability_id": capability_id,
                            "approval_required": False,
                            "handler_preflight": {"backend": "local_native"},
                            "expires_at": 9999999999.0,
                        }

                    def fake_execute(preflight_id, capability_id, params, received_context, *, confirmation=""):
                        self.assertEqual(preflight_id, "capability-preflight:fixture")
                        self.assertIs(received_context, context)
                        self.assertEqual(confirmation, "")
                        execute_calls.append((capability_id, dict(params)))
                        return {"result": {"backend": "local_native", "status": "passed"}}

                    with (
                        patch.object(
                            runtime,
                            "_compat_fast_step_context_args",
                            side_effect=lambda args: {**args, "lease_id": "lease-fixture"},
                        ),
                        patch.object(runtime, "_stable_capability_context", return_value=context),
                        patch.object(runtime._stable_capability_gateway, "preflight", side_effect=fake_preflight),
                        patch.object(runtime._stable_capability_gateway, "execute", side_effect=fake_execute),
                    ):
                        prepared = runtime.call_tool(
                            "command_profile_preflight",
                            {
                                "workspace_id": "fixture",
                                "session_id": "session:fixture",
                                "working_tree_id": "session:fixture",
                                "profile_id": "compat.development.fast_step",
                                "arguments": {"query": "inspect current diff", "verify": True, "audit": True},
                            },
                        )
                        self.assertFalse(prepared["isError"], prepared)
                        payload = prepared["structuredContent"]
                        self.assertTrue(payload["compatibility_bridge"])
                        self.assertEqual(payload["capability_id"], "development.fast_step")
                        self.assertFalse(payload["approval_required"])
                        self.assertTrue(payload["preflight_id"].startswith("compat-fast-step:"))

                        executed = runtime.call_tool(
                            "command_profile_run",
                            {
                                "workspace_id": "fixture",
                                "session_id": "session:fixture",
                                "working_tree_id": "session:fixture",
                                "preflight_id": payload["preflight_id"],
                            },
                        )
                        self.assertFalse(executed["isError"], executed)
                        result = executed["structuredContent"]
                        self.assertTrue(result["compatibility_bridge"])
                        self.assertEqual(result["capability_id"], "development.fast_step")
                        self.assertEqual(result["result"]["backend"], "local_native")

                    self.assertEqual(preflight_calls, [("development.fast_step", {"query": "inspect current diff", "verify": True, "audit": True})])
                    self.assertEqual(execute_calls, preflight_calls)
                finally:
                    runtime.close()

    def test_legacy_fast_step_bridge_allows_standard_trust_for_r1_automatic_policy(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    context = CapabilityExecutionContext(
                        workspace_id="fixture",
                        working_tree_id="session:fixture",
                        session_id="session:fixture",
                        owner_id="owner",
                        task_id="task",
                        policy_revision="project-policy-v1",
                        policy_digest="a" * 64,
                        writer_lease_id="lease-fixture",
                        workspace_trust_level="standard",
                    )
                    with (
                        patch.object(
                            runtime,
                            "_compat_fast_step_context_args",
                            side_effect=lambda args: {**args, "lease_id": "lease-fixture"},
                        ),
                        patch.object(runtime, "_stable_capability_context", return_value=context),
                        patch.object(
                            runtime._stable_capability_gateway,
                            "preflight",
                            return_value={
                                "preflight_id": "capability-preflight:standard-fixture",
                                "capability_id": "development.fast_step",
                                "approval_required": False,
                                "handler_preflight": {"backend": "local_native"},
                                "expires_at": 9999999999.0,
                            },
                        ),
                    ):
                        prepared = runtime.call_tool(
                            "command_profile_preflight",
                            {
                                "workspace_id": "fixture",
                                "session_id": "session:fixture",
                                "working_tree_id": "session:fixture",
                                "profile_id": "compat.development.fast_step",
                                "arguments": {"query": "inspect"},
                            },
                        )
                    self.assertFalse(prepared["isError"], prepared)
                    payload = prepared["structuredContent"]
                    self.assertTrue(payload["compatibility_bridge"])
                    self.assertFalse(payload["approval_required"])
                finally:
                    runtime.close()

    def test_legacy_fast_step_bridge_infers_only_one_exact_session_lease(self) -> None:
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    exact = SimpleNamespace(
                        lease_id="lease-exact",
                        workspace_id="fixture",
                        working_tree_id="session:fixture",
                        task_id="task-fixture",
                        owner_id="owner-fixture",
                    )
                    with patch.object(runtime._director_writer_manager, "observed_active", return_value=[exact]):
                        bound = runtime._compat_fast_step_context_args(
                            {
                                "workspace_id": "fixture",
                                "working_tree_id": "session:fixture",
                                "session_id": "session:fixture",
                            }
                        )
                    self.assertEqual(bound["lease_id"], "lease-exact")

                    with patch.object(runtime._director_writer_manager, "observed_active", return_value=[]):
                        with self.assertRaisesRegex(Exception, "current writer lease"):
                            runtime._compat_fast_step_context_args(
                                {
                                    "workspace_id": "fixture",
                                    "working_tree_id": "session:fixture",
                                    "session_id": "session:fixture",
                                }
                            )

                    with patch.object(runtime._director_writer_manager, "observed_active", return_value=[exact, exact]):
                        with self.assertRaisesRegex(Exception, "exactly one"):
                            runtime._compat_fast_step_context_args(
                                {
                                    "workspace_id": "fixture",
                                    "working_tree_id": "session:fixture",
                                    "session_id": "session:fixture",
                                }
                            )
                finally:
                    runtime.close()

    def test_platform_profile_capability_preserves_typed_approval_and_single_use_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    params = {
                        "workspace_id": "fixture",
                        "kind": "desktop",
                        "profile_id": "managed-desktop-main",
                        "bundle_id": "com.example.App",
                    }
                    before = config.read_text(encoding="utf-8")
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "platform.profile.register", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]
                    self.assertTrue(preflight["approval_required"])
                    self.assertNotIn("handler_version", preflight)
                    self.assertEqual(config.read_text(encoding="utf-8"), before)

                    denied = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "platform.profile.register",
                            "params": params,
                        },
                    )
                    self.assertTrue(denied["isError"], denied)
                    self.assertEqual(denied["structuredContent"]["error"]["code"], "CAPABILITY_APPROVAL_REQUIRED")

                    applied = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "platform.profile.register",
                            "params": params,
                            "confirmation": preflight["approval"]["confirmation"],
                        },
                    )
                    self.assertFalse(applied["isError"], applied)
                    self.assertTrue(applied["structuredContent"]["preflight_consumed"])
                    document = json.loads(config.read_text(encoding="utf-8"))
                    self.assertEqual(
                        document["workspaces"]["fixture"]["platform"]["desktop_profiles"]["managed-desktop-main"]["bundle_id"],
                        "com.example.App",
                    )

                    replay = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "platform.profile.register",
                            "params": params,
                            "confirmation": preflight["approval"]["confirmation"],
                        },
                    )
                    self.assertTrue(replay["isError"], replay)
                    self.assertEqual(replay["structuredContent"]["error"]["code"], "CAPABILITY_PREFLIGHT_REPLAY")
                finally:
                    runtime.close()

    def test_platform_profile_registration_refreshes_live_desktop_runtime_without_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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
            environment, runtime_type = self._runtime(root, "stable_gateway")
            with environment:
                runtime = runtime_type()
                try:
                    opened = runtime.call_tool("workspace_open", {"id": "fixture"})
                    self.assertFalse(opened["isError"], opened)

                    before = runtime.call_tool("desktop_runtime", {"workspace_id": "fixture", "action": "profiles"})
                    self.assertFalse(before["isError"], before)
                    self.assertEqual(before["structuredContent"]["profiles"], [])

                    params = {
                        "workspace_id": "fixture",
                        "kind": "desktop",
                        "profile_id": "managed-desktop-main",
                        "bundle_id": "com.example.App",
                    }
                    preflight_result = runtime.call_tool(
                        "capability_preflight",
                        {"workspace_id": "fixture", "capability_id": "platform.profile.register", "params": params},
                    )
                    self.assertFalse(preflight_result["isError"], preflight_result)
                    preflight = preflight_result["structuredContent"]

                    applied = runtime.call_tool(
                        "capability_execute",
                        {
                            "workspace_id": "fixture",
                            "preflight_id": preflight["preflight_id"],
                            "capability_id": "platform.profile.register",
                            "params": params,
                            "confirmation": preflight["approval"]["confirmation"],
                        },
                    )
                    self.assertFalse(applied["isError"], applied)

                    after = runtime.call_tool("desktop_runtime", {"workspace_id": "fixture", "action": "profiles"})
                    self.assertFalse(after["isError"], after)
                    self.assertEqual(
                        [item["profile"] for item in after["structuredContent"]["profiles"]],
                        ["managed-desktop-main"],
                    )
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
