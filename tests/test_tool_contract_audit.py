from __future__ import annotations

import unittest

from chatgpt_dev_mcp.server import WrapperRuntime
from chatgpt_dev_mcp.request_lifecycle import SideEffectClass
from chatgpt_dev_mcp.stable_surface import V25_STABLE_SCHEMA_HASH, validate_frozen_v25_schema
from chatgpt_dev_mcp.tool_contract_audit import audit_tool_contracts, lint_tool_contracts
from chatgpt_dev_mcp.transport_http import _tool_side_effect_class
from chatgpt_dev_mcp.v26_surface import build_v26_surface


class ToolContractAuditTests(unittest.TestCase):
    def _v25_definitions(self) -> list[dict[str, object]]:
        runtime = WrapperRuntime()
        try:
            return runtime.list_tools()["tools"]
        finally:
            runtime.close()

    def _legacy_definitions(self) -> list[dict[str, object]]:
        runtime = WrapperRuntime()
        try:
            return runtime._legacy_tool_definitions()
        finally:
            runtime.close()

    def test_all_v25_public_tools_receive_complete_machine_readable_audit_records(self) -> None:
        records = audit_tool_contracts(self._v25_definitions())
        self.assertEqual(len(records), 52)
        self.assertEqual(len({record.name for record in records}), 52)
        for record in records:
            self.assertTrue(record.name)
            self.assertTrue(record.description)
            self.assertIn(record.permission, {"READ_ONLY", "SCOPED_WRITE", "PRIVILEGED"})
            self.assertTrue(record.side_effects)
            self.assertIn(record.approval, {"none", "conditional", "human"})
            self.assertTrue(record.filesystem)
            self.assertIn(record.network, {"none", "possible", "required"})
            self.assertIsInstance(record.destructive, bool)
            self.assertIsInstance(record.external_execution, bool)
            self.assertEqual(set(record.annotations), {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"})

    def test_v26_surface_lints_cleanly_and_has_no_generic_discriminator_tools(self) -> None:
        v25 = self._v25_definitions()
        self.assertEqual(validate_frozen_v25_schema(v25)["hash"], V25_STABLE_SCHEMA_HASH)
        v26 = build_v26_surface(v25, self._legacy_definitions())
        result = lint_tool_contracts(
            v26
        )
        self.assertEqual(result["status"], "valid", result)
        self.assertEqual(result["errors"], [])

    def test_security_audit_declares_append_only_receipt_without_workflow_mutation(self) -> None:
        v25 = self._v25_definitions()
        legacy = self._legacy_definitions()
        v26 = build_v26_surface(v25, legacy)
        stable = next(item for item in legacy if item["name"] == "security_audit")
        canary = next(item for item in v26 if item["name"] == "security_audit")
        self.assertIn("READ_ONLY evaluation", stable["description"])
        self.assertIn("does not change task, session, or lease state", canary["description"])
        record = next(item for item in audit_tool_contracts(v26) if item.name == "security_audit")
        self.assertTrue(record.annotations["readOnlyHint"])
        self.assertEqual(record.side_effects, "append_only_audit_evidence")
        readonly_record = next(item for item in audit_tool_contracts(v26) if item.name == "readonly_path")
        self.assertFalse(readonly_record.annotations["readOnlyHint"])
        self.assertEqual(readonly_record.side_effects, "bounded_readonly_handle_registry")

    def test_read_only_durable_evidence_is_explicitly_classified(self) -> None:
        v25 = build_v26_surface(self._v25_definitions(), self._legacy_definitions())
        by_name = {item["name"]: item for item in v25}
        # A few pre-v25 compatibility tools are intentionally not promoted to
        # the 76-tool v26 surface.  Audit their legacy definitions separately
        # without changing the public v26 count.
        for item in self._legacy_definitions():
            if item["name"] not in by_name:
                by_name[item["name"]] = item
        definitions = list(by_name.values())
        records = {record.name: record for record in audit_tool_contracts(definitions)}
        expected = {
            "workspace_integration_preflight": "append_only_integration_preflight_evidence",
            "workspace_list_development_sessions": "append_only_observability_evidence",
            "semantic_code_query": "append_only_semantic_evidence",
            "development_context": "append_only_context_evidence",
            "workspace_register_preflight": "append_only_provisioning_preflight_evidence",
            "workspace_unregister_preflight": "append_only_provisioning_preflight_evidence",
            "workspace_registration_update_preflight": "append_only_provisioning_preflight_evidence",
            "git_stage_preflight": "durable_git_preflight_authority",
            "git_stage_hunks_preflight": "durable_git_preflight_authority",
            "git_commit_preflight": "durable_git_preflight_authority_and_closeout",
            "git_verified_commit_preflight": "durable_git_preflight_authority_and_closeout",
            "git_push_preflight": "durable_git_preflight_authority_and_closeout",
            "browser_inspect": "managed_browser_observation_or_screenshot_artifact",
        }
        for name, side_effects in expected.items():
            self.assertEqual(records[name].side_effects, side_effects, name)

    def test_v26_browser_inspect_discloses_bounded_screenshot_artifact_write(self) -> None:
        v25 = {item["name"]: item for item in self._v25_definitions()}
        v26 = {
            item["name"]: item
            for item in build_v26_surface(list(v25.values()), self._legacy_definitions())
        }
        self.assertTrue(v25["browser_inspect"]["annotations"]["readOnlyHint"])
        browser = v26["browser_inspect"]
        self.assertFalse(browser["annotations"]["readOnlyHint"])
        self.assertIn("screenshot", browser["description"].lower())
        self.assertIn("artifact", browser["description"].lower())
        self.assertIn("managed", browser["description"].lower())

    def test_provisioning_audit_discloses_lifecycle_stream_contract(self) -> None:
        audit_tool = next(item for item in self._legacy_definitions() if item["name"] == "director_audit_log")
        description = audit_tool["description"].lower()
        for marker in ("registration/provisioning", "baseline", "relocation", "runtime", "evidence import", "append-only"):
            self.assertIn(marker, description)
        self.assertIn("raw arguments", description)
        self.assertIn("approval tokens", description)

    def test_request_classification_matches_argument_sensitive_and_durable_paths(self) -> None:
        runtime = WrapperRuntime()
        try:
            self.assertIs(
                runtime._request_side_effect_class("browser_inspect", {"kind": "snapshot"}),
                SideEffectClass.READ_ONLY,
            )
            self.assertIs(
                runtime._request_side_effect_class("browser_inspect", {"kind": "screenshot"}),
                SideEffectClass.LOCAL_REVERSIBLE,
            )
            self.assertIs(
                runtime._request_side_effect_class("director_dispatch_status", {"plan_id": "plan-1"}),
                SideEffectClass.READ_ONLY,
            )
            for name in (
                "workspace_integration_preflight",
                "workspace_register_preflight",
                "git_stage_preflight",
                "git_commit_preflight",
                "director_review",
                "director_plan_work",
                "director_baseline_snapshot",
            ):
                expected = (
                    SideEffectClass.LOCAL_REVERSIBLE
                    if name in {"workspace_integration_preflight", "workspace_register_preflight", "git_stage_preflight", "git_commit_preflight"}
                    else SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
                )
                self.assertIs(runtime._request_side_effect_class(name, {}), expected, name)
        finally:
            runtime.close()

        def http_request(name: str, arguments: dict[str, object]) -> dict[str, object]:
            return {
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }

        self.assertIs(
            _tool_side_effect_class(http_request("browser_inspect", {"kind": "snapshot"})),
            SideEffectClass.READ_ONLY,
        )
        self.assertIs(
            _tool_side_effect_class(http_request("browser_inspect", {"kind": "screenshot"})),
            SideEffectClass.LOCAL_REVERSIBLE,
        )
        self.assertIs(
            _tool_side_effect_class(http_request("director_dispatch_status", {"plan_id": "plan-1"})),
            SideEffectClass.READ_ONLY,
        )
        for name in (
            "workspace_integration_preflight",
            "git_stage_preflight",
            "git_commit_preflight",
            "director_review",
            "director_plan_work",
            "director_baseline_snapshot",
        ):
            expected = (
                SideEffectClass.LOCAL_REVERSIBLE
                if name in {"workspace_integration_preflight", "git_stage_preflight", "git_commit_preflight"}
                else SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE
            )
            self.assertIs(_tool_side_effect_class(http_request(name, {})), expected, name)

    def test_side_effect_classification_has_runtime_http_and_v26_contract_parity(self) -> None:
        runtime = WrapperRuntime()
        try:
            runtime.enable_v26_readonly_continuity()
            v26 = build_v26_surface(self._v25_definitions(), runtime._legacy_tool_definitions())
            by_name = {item["name"]: item for item in v26}
            audit_definitions = list(v26)
            audit_names = set(by_name)
            audit_definitions.extend(
                item for item in runtime._legacy_tool_definitions() if item["name"] not in audit_names
            )
            records = {record.name: record for record in audit_tool_contracts(audit_definitions)}

            cases = (
                ("server_info", {}, SideEffectClass.READ_ONLY, False, "none"),
                ("director_health", {}, SideEffectClass.READ_ONLY, False, "none"),
                ("director_status_summary", {"workspace_id": "project-x"}, SideEffectClass.READ_ONLY, False, "none"),
                ("workspace_profile", {"workspace_id": "project-x"}, SideEffectClass.READ_ONLY, False, "none"),
                ("workspace_list_development_sessions", {}, SideEffectClass.LOCAL_REVERSIBLE, False, "append_only_observability_evidence"),
                ("semantic_code_query", {"workspace_id": "project-x"}, SideEffectClass.LOCAL_REVERSIBLE, False, "append_only_semantic_evidence"),
                ("development_context", {"workspace_id": "project-x"}, SideEffectClass.LOCAL_REVERSIBLE, False, "append_only_context_evidence"),
                ("workspace_integration_preflight", {}, SideEffectClass.LOCAL_REVERSIBLE, False, "append_only_integration_preflight_evidence"),
                ("workspace_register_preflight", {}, SideEffectClass.LOCAL_REVERSIBLE, False, "append_only_provisioning_preflight_evidence"),
                ("git_stage_preflight", {}, SideEffectClass.LOCAL_REVERSIBLE, False, "durable_git_preflight_authority"),
                ("security_audit", {}, SideEffectClass.READ_ONLY, False, "append_only_audit_evidence"),
                ("workspace_request_development", {}, SideEffectClass.LOCAL_REVERSIBLE, False, "none"),
                ("director_development_start", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "workspace_or_control_plane_write"),
                ("director_next_action", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "workspace_or_control_plane_write"),
                ("capability_execute", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "capability_dependent"),
                ("git_stage_hunks", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "git_mutation"),
                ("apply_patch", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "workspace_or_control_plane_write"),
                ("workspace_integrate_development_session", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "workspace_or_control_plane_write"),
                ("git_commit", {}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True, "git_mutation"),
            )

            def http_request(name: str, arguments: dict[str, object]) -> dict[str, object]:
                return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}

            v26_x_effects = {
                "workspace_list_development_sessions": "append_only_observability_evidence",
                "development_context": "append_only_context_evidence",
                "workspace_integration_preflight": "append_only_integration_preflight_evidence",
                "git_stage_preflight": "durable_git_preflight_authority",
                "security_audit": "append_only_audit_evidence",
            }
            for name, arguments, expected, sync_required, expected_effects in cases:
                self.assertIs(runtime._request_side_effect_class(name, arguments), expected, name)
                self.assertIs(_tool_side_effect_class(http_request(name, arguments)), expected, name)
                self.assertEqual(runtime._requires_active_session_synchronization(name, arguments), sync_required, name)
                self.assertEqual(records[name].side_effects, expected_effects, name)
                if name in by_name:
                    if name in v26_x_effects:
                        self.assertEqual(by_name[name]["x-devmcp-side-effects"], v26_x_effects[name], name)
                    else:
                        self.assertNotIn("x-devmcp-side-effects", by_name[name], name)
                    self.assertEqual(
                        by_name[name]["annotations"]["readOnlyHint"],
                        expected is not SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
                        name,
                    )
                if name in {"security_audit", "workspace_integration_preflight"}:
                    self.assertTrue(by_name[name]["annotations"]["readOnlyHint"], name)
                    self.assertTrue(by_name[name]["annotations"]["idempotentHint"], name)

            # v26 split tools are accepted by the HTTP surface under their
            # public name and delegated to one of the proven runtime handlers.
            # Compare the transport classification with that actual delegated
            # call, not with the alias name (which is intentionally not a
            # direct WrapperRuntime handler).
            delegated = (
                ("run_tests", "run_task", {"task": "test"}),
                ("run_lint", "run_task", {"task": "lint"}),
                ("run_build", "run_task", {"task": "build"}),
                ("run_dev", "run_task", {"task": "dev"}),
                ("run_format", "run_task", {"task": "format"}),
                ("browser_profile_list", "browser_test_session", {"action": "profiles"}),
                ("browser_session_start", "browser_test_session", {"action": "start"}),
                ("browser_session_close", "browser_test_session", {"action": "close"}),
                ("browser_navigate", "browser_action", {"action": "navigate"}),
                ("browser_click", "browser_action", {"action": "click"}),
                ("browser_type", "browser_action", {"action": "type"}),
                ("browser_keyboard", "browser_action", {"action": "keyboard"}),
                ("browser_viewport", "browser_action", {"action": "viewport"}),
                ("browser_wait", "browser_action", {"action": "wait"}),
                ("desktop_profile_list", "desktop_runtime", {"action": "profiles"}),
                ("desktop_runtime_start", "desktop_runtime", {"action": "start"}),
                ("desktop_runtime_status", "desktop_runtime", {"action": "status"}),
                ("desktop_runtime_logs", "desktop_runtime", {"action": "logs"}),
                ("desktop_runtime_snapshot", "desktop_runtime", {"action": "snapshot"}),
                ("desktop_runtime_stop", "desktop_runtime", {"action": "stop"}),
            )
            for public_name, runtime_name, runtime_arguments in delegated:
                self.assertIs(
                    _tool_side_effect_class(http_request(public_name, {})),
                    runtime._request_side_effect_class(runtime_name, runtime_arguments),
                    public_name,
                )
        finally:
            runtime.close()

    def test_argument_sensitive_observers_do_not_require_active_session_sync(self) -> None:
        runtime = WrapperRuntime()
        try:
            runtime.enable_v26_readonly_continuity()
            cases = (
                ("readonly_path", {"action": "open"}, SideEffectClass.LOCAL_REVERSIBLE, False),
                ("browser_inspect", {"kind": "snapshot"}, SideEffectClass.READ_ONLY, False),
                ("browser_inspect", {"kind": "screenshot"}, SideEffectClass.LOCAL_REVERSIBLE, False),
                ("browser_action", {"action": "viewport"}, SideEffectClass.LOCAL_REVERSIBLE, False),
                ("browser_action", {"action": "click"}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True),
                ("browser_test_session", {"action": "profiles"}, SideEffectClass.READ_ONLY, False),
                ("browser_test_session", {"action": "start"}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True),
                ("desktop_runtime", {"action": "status"}, SideEffectClass.READ_ONLY, False),
                ("desktop_runtime", {"action": "start"}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True),
                ("director_review", {"action": "list"}, SideEffectClass.READ_ONLY, False),
                ("director_review", {"action": "approve"}, SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE, True),
            )
            for name, arguments, expected_class, sync_required in cases:
                self.assertIs(runtime._request_side_effect_class(name, arguments), expected_class, name)
                self.assertEqual(runtime._requires_active_session_synchronization(name, arguments), sync_required, name)
        finally:
            runtime.close()

    def test_evidence_only_request_does_not_mark_side_effect_started(self) -> None:
        runtime = WrapperRuntime()
        request_id = f"evidence-only-lifecycle-{runtime.child_instance_id}"
        try:
            result = runtime.call_tool("semantic_code_query", {}, request_id=request_id)
            self.assertTrue(result["isError"], result)
            events = runtime._persistence.load_request_lifecycle_events(request_id=request_id, limit=30)
            self.assertTrue(events)
            self.assertFalse(any(event["event"] == "REQUEST_SIDE_EFFECT_STARTED" for event in events))
            terminal = next(event for event in events if event["event"] == "REQUEST_TERMINAL")
            self.assertEqual(terminal["side_effect_class"], SideEffectClass.LOCAL_REVERSIBLE.value)
            self.assertFalse(runtime.request_registry.get(request_id).side_effect_started)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
