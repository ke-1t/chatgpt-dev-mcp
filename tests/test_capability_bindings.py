from __future__ import annotations

import unittest


class CapabilityBindingTests(unittest.TestCase):
    def test_development_session_identity_repair_binding_pins_preflight_state(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_identity_repair_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[str] = []

        def prepare(params, context):
            calls.append("prepare")
            return (
                {
                    "session_id": params["session_id"],
                    "classification": "VERIFIED_STALE_CLEAN",
                    "preserve_worktree": True,
                    "state_digest": "c" * 64,
                },
                {"session_id": params["session_id"], "state_digest": "c" * 64},
            )

        def execute(state, context):
            calls.append("execute")
            return {"session_id": state["session_id"], "identity_repaired": True, "worktree_retained": True}

        spec, handler = build_development_session_identity_repair_binding(prepare, execute)
        self.assertEqual(spec.capability_id, "development.session.repair_source_identity")
        self.assertEqual(spec.risk_class, "R1")
        self.assertEqual(spec.approval_policy, "automatic")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.network_required)
        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="d" * 64,
        )
        params = {"session_id": "session:fixture-repair-0001"}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["operation"], "development.session.repair_source_identity")
        self.assertTrue(preview["preserve_worktree"])
        self.assertEqual(handler.execute(params, context, state)["identity_repaired"], True)
        self.assertEqual(calls, ["prepare", "execute"])

    def test_development_session_reconcile_binding_pins_preflight_state(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_reconcile_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[tuple[str, object]] = []

        def prepare(params, context):
            calls.append(("prepare", dict(params)))
            return (
                {
                    "session_id": params["session_id"],
                    "classification": "RECONCILABLE_PRESERVE_WORKTREE",
                    "state_digest": "a" * 64,
                },
                {"session_id": params["session_id"], "state_digest": "a" * 64},
            )

        def execute(state, context):
            calls.append(("execute", dict(state)))
            return {
                "session_id": state["session_id"],
                "classification": "RECONCILABLE_PRESERVE_WORKTREE",
                "transition": "cleanup_candidate",
                "receipt_id": "reconciliation:fixture",
            }

        spec, handler = build_development_session_reconcile_binding(prepare, execute)
        self.assertEqual(spec.capability_id, "development.session.reconcile_stale_state")
        self.assertEqual(spec.risk_class, "R1")
        self.assertEqual(spec.approval_policy, "automatic")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertEqual(spec.input_schema["required"], ["session_id"])

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="b" * 64,
        )
        preview, state = handler.preflight({"session_id": "session:fixture-reconcile-0001"}, context)
        self.assertEqual(preview["operation"], "development.session.reconcile_stale_state")
        self.assertEqual(preview["state_digest"], "a" * 64)
        result = handler.execute({"session_id": "session:fixture-reconcile-0001"}, context, state)
        self.assertEqual(result["transition"], "cleanup_candidate")
        self.assertEqual([kind for kind, _ in calls], ["prepare", "execute"])

    def test_development_session_list_binding_is_read_only_and_paginated(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_list_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[dict[str, object]] = []

        def read_sessions(params, context):
            calls.append(dict(params))
            return {
                "sessions": [],
                "returned": 0,
                "next_cursor": None,
                "counts": {"inventory_total": 0, "filtered_total": 0, "active": 0, "statuses": {}},
            }

        spec, handler = build_development_session_list_binding(read_sessions)
        self.assertEqual(spec.capability_id, "development.session_list")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "none")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertEqual(
            set(spec.input_schema["properties"]),
            {"active_only", "statuses", "workspace_id", "limit", "cursor"},
        )
        self.assertEqual(spec.input_schema["properties"]["limit"]["maximum"], 100)
        self.assertEqual(spec.input_schema["properties"]["statuses"]["maxItems"], 32)

        context = CapabilityExecutionContext(
            workspace_id="chatgpt-dev-mcp",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"workspace_id": "chatgpt-dev-mcp", "limit": 20}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["operation"], "development.session_list")
        self.assertEqual(calls, [])
        self.assertEqual(handler.execute(params, context, state)["returned"], 0)
        self.assertEqual(calls, [params])

    def test_development_session_abandon_binding_requires_explicit_human_approval(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_abandon_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[tuple[str, dict[str, object]]] = []

        def prepare(params, context):
            calls.append(("prepare", dict(params)))
            return ({"session_id": params["session_id"], "will_archive_before_prune": True}, dict(params))

        def execute(state, context):
            calls.append(("execute", dict(state)))
            return {"session_id": state["session_id"], "status": "abandoned"}

        spec, handler = build_development_session_abandon_binding(prepare, execute)
        self.assertEqual(spec.capability_id, "development.session.abandon")
        self.assertEqual(spec.risk_class, "R2")
        self.assertEqual(spec.approval_policy, "human")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"session_id": "session:durable-fixture-0001"}
        preview, state = handler.preflight(params, context)
        self.assertTrue(preview["will_archive_before_prune"])
        self.assertEqual(handler.execute(params, context, state)["status"], "abandoned")
        self.assertEqual([kind for kind, _ in calls], ["prepare", "execute"])

    def test_development_session_archive_binding_is_non_destructive_r0(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_archive_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[tuple[str, dict[str, object]]] = []

        def prepare(params, context):
            calls.append(("prepare", dict(params)))
            return (
                {"session_id": params["session_id"], "will_prune": False, "state_digest": "e" * 64},
                dict(params),
            )

        def execute(state, context):
            calls.append(("execute", dict(state)))
            return {
                "session_id": state["session_id"],
                "snapshot_verified": True,
                "worktree_retained": True,
            }

        spec, handler = build_development_session_archive_binding(prepare, execute)
        self.assertEqual(spec.capability_id, "development.session.archive")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "none")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertFalse(spec.deprecated)

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"session_id": "session:durable-fixture-0001"}
        preview, state = handler.preflight(params, context)
        self.assertFalse(preview["will_prune"])
        self.assertEqual(preview["operation"], "development.session.archive")
        self.assertEqual(preview["state_digest"], "e" * 64)
        result = handler.execute(params, context, state)
        self.assertTrue(result["snapshot_verified"])
        self.assertTrue(result["worktree_retained"])
        self.assertEqual([kind for kind, _ in calls], ["prepare", "execute"])

    def test_performance_summary_binding_is_read_only_registry_capability(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_performance_summary_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[dict[str, object]] = []

        def read_summary(params, context):
            calls.append(dict(params))
            return {"sample_count": 3, "workspace_id": context.workspace_id, "external_execution": False}

        spec, handler = build_performance_summary_binding(read_summary)
        self.assertEqual(spec.capability_id, "performance.summary")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "none")
        self.assertEqual(spec.exposure, "registry")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertEqual(spec.input_schema["properties"]["limit"]["maximum"], 4096)
        self.assertEqual(spec.input_schema["properties"]["top"]["maximum"], 100)

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"limit": 256, "top": 10}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["operation"], "performance.summary")
        self.assertEqual(calls, [])
        self.assertEqual(handler.execute(params, context, state)["sample_count"], 3)
        self.assertEqual(calls, [params])

    def test_context_bindings_are_read_only_registry_capabilities(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_context_bootstrap_binding, build_context_checkpoint_binding, build_context_focus_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[tuple[str, dict[str, object]]] = []

        def bootstrap_read(params, context):
            calls.append(("bootstrap", dict(params)))
            return {"ok": True, "workspace_id": context.workspace_id, "used_bytes": 512}

        def focus_read(params, context):
            calls.append(("focus", dict(params)))
            return {"ok": True, "workspace_id": context.workspace_id, "used_bytes": 1024}

        def checkpoint_write(params, context):
            calls.append(("checkpoint", dict(params)))
            return {"ok": True, "workspace_id": context.workspace_id, "checkpoint_id": "checkpoint:1"}

        bootstrap_spec, bootstrap_handler = build_context_bootstrap_binding(bootstrap_read)
        focus_spec, focus_handler = build_context_focus_binding(focus_read)
        checkpoint_spec, checkpoint_handler = build_context_checkpoint_binding(checkpoint_write)

        for spec in (bootstrap_spec, focus_spec):
            self.assertEqual(spec.risk_class, "R0")
            self.assertEqual(spec.approval_policy, "none")
            self.assertEqual(spec.workspace_binding, "required")
            self.assertFalse(spec.session_required)
            self.assertFalse(spec.writer_lease_required)
            self.assertFalse(spec.network_required)
            self.assertEqual(spec.exposure, "registry")
        self.assertEqual(bootstrap_spec.capability_id, "context.bootstrap")
        self.assertEqual(focus_spec.capability_id, "context.focus")
        self.assertEqual(checkpoint_spec.capability_id, "context.checkpoint")
        self.assertEqual(checkpoint_spec.risk_class, "R1")
        self.assertEqual(checkpoint_spec.approval_policy, "automatic")
        self.assertFalse(checkpoint_spec.writer_lease_required)
        self.assertFalse(checkpoint_spec.network_required)
        self.assertEqual(bootstrap_spec.input_schema["properties"]["max_bytes"]["maximum"], 262144)
        self.assertEqual(focus_spec.input_schema["properties"]["target_paths"]["maxItems"], 64)

        context = CapabilityExecutionContext(
            workspace_id="workspace-a",
            working_tree_id="worktree:a",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        bootstrap_params = {"query": "current project", "max_bytes": 4096}
        focus_params = {"task_id": "task-focus", "query": "verification selector", "target_paths": ["src/app.py"], "max_bytes": 8192}
        checkpoint_params = {"task_id": "task-focus", "outcome": "verified", "next_action": "commit"}

        bootstrap_preview, bootstrap_state = bootstrap_handler.preflight(bootstrap_params, context)
        focus_preview, focus_state = focus_handler.preflight(focus_params, context)
        checkpoint_preview, checkpoint_state = checkpoint_handler.preflight(checkpoint_params, context)
        self.assertEqual(calls, [])
        self.assertEqual(bootstrap_preview["operation"], "context.bootstrap")
        self.assertEqual(focus_preview["operation"], "context.focus")
        self.assertEqual(checkpoint_preview["operation"], "context.checkpoint")

        self.assertEqual(bootstrap_handler.execute(bootstrap_params, context, bootstrap_state)["used_bytes"], 512)
        self.assertEqual(focus_handler.execute(focus_params, context, focus_state)["used_bytes"], 1024)
        self.assertEqual(checkpoint_handler.execute(checkpoint_params, context, checkpoint_state)["checkpoint_id"], "checkpoint:1")
        self.assertEqual([kind for kind, _params in calls], ["bootstrap", "focus", "checkpoint"])

    def test_hybrid_route_binding_is_read_only_automatic(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_hybrid_route_binding

        spec, handler = build_hybrid_route_binding(
            lambda params, context: {"backend": "local_native", "reason": "test", "available": True, "fallback": False}
        )
        self.assertEqual(spec.capability_id, "development.execution.route")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "automatic")
        self.assertFalse(spec.writer_lease_required)
        self.assertEqual(spec.input_schema["properties"]["mode"]["enum"], ["local", "cloud", "auto"])
        self.assertEqual(spec.input_schema["properties"]["chatgpt_builtin_available"], {"type": "boolean"})
        self.assertNotIn("performance", spec.input_schema["properties"])
        self.assertEqual(handler.handler_id, spec.capability_id)

    def test_fast_step_binding_requires_writer_lease_and_uses_r1_automatic_policy(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_fast_step_binding

        spec, handler = build_development_fast_step_binding(
            lambda params, context: ({"task_id": context.task_id}, dict(params)),
            lambda state, context: {"ok": True, "task_id": context.task_id, "state": state},
        )
        self.assertEqual(spec.capability_id, "development.fast_step")
        self.assertEqual(spec.risk_class, "R1")
        self.assertEqual(spec.approval_policy, "automatic")
        self.assertTrue(spec.session_required)
        self.assertTrue(spec.writer_lease_required)
        self.assertEqual(handler.handler_id, spec.capability_id)

    def test_openai_api_bindings_are_not_exposed(self) -> None:
        import chatgpt_dev_mcp.capability_bindings as bindings

        self.assertFalse(hasattr(bindings, "build_cloud_compute_binding"))
        self.assertFalse(hasattr(bindings, "build_openai_api_compute_binding"))
        self.assertFalse(hasattr(bindings, "build_openai_probe_binding"))

    def test_analysis_pack_binding_is_read_only_automatic_and_bounded(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_analysis_pack_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls: list[dict[str, object]] = []

        def read_pack(params, context):
            calls.append(dict(params))
            return {
                "analysis_pack_id": "analysis-pack:fixture",
                "workspace_id": context.workspace_id,
                "task_id": params["task_id"],
                "external_execution": False,
            }

        spec, handler = build_analysis_pack_binding(read_pack)
        self.assertEqual(spec.capability_id, "development.analysis_pack")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "automatic")
        self.assertFalse(spec.network_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertEqual(spec.credential_requirements, ())
        self.assertEqual(spec.input_schema["properties"]["max_bytes"]["maximum"], 65536)

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="session:fixture",
            owner_id="owner",
            task_id="task",
            policy_revision="project-policy-v1",
            policy_digest="a" * 64,
        )
        params = {
            "task_id": "task",
            "changed_paths": ["src/example.py"],
            "include_diff": True,
            "include_failures": True,
            "max_bytes": 4096,
        }
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["operation"], "development.analysis_pack")
        self.assertEqual(preview["max_bytes"], 4096)
        self.assertEqual(calls, [])
        result = handler.execute(params, context, state)
        self.assertEqual(result["analysis_pack_id"], "analysis-pack:fixture")
        self.assertEqual(calls, [params])

    def test_external_open_binding_is_registry_only_workspace_trust(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_external_open_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext
        calls = []
        def prepare(params): calls.append(("prepare", dict(params))); return (dict(params), (params["kind"], params["target"]))
        def execute(state): calls.append(("execute", state)); return {"ok":True,"returncode":0}
        spec, handler = build_external_open_binding(prepare, execute)
        self.assertEqual((spec.capability_id, spec.exposure, spec.risk_class, spec.approval_policy), ("external_open","registry","R2","workspace_trust"))
        context = CapabilityExecutionContext(workspace_id="workspace-a", working_tree_id="session:tree-a", session_id="", owner_id="owner", task_id="task", policy_revision="policy-v1", policy_digest="a"*64, workspace_trust_level="trusted_development")
        params = {"kind":"url","target":"https://example.com"}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview, params)
        self.assertEqual(handler.execute(params, context, state), {"ok":True,"returncode":0})
        self.assertEqual(calls, [("prepare", params), ("execute", ("url","https://example.com"))])

    def test_macos_app_replace_binding_requires_human_approval_and_network(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_macos_app_replace_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []
        def prepare(params): calls.append(("prepare", dict(params))); return ({"bundle_id": params["bundle_id"]}, "prepared")
        def execute(state): calls.append(("execute", state)); return {"ok": True}

        spec, handler = build_macos_app_replace_binding(prepare, execute)
        self.assertEqual(spec.capability_id, "platform.macos_app.replace")
        self.assertEqual(spec.exposure, "registry")
        self.assertEqual(spec.risk_class, "R3")
        self.assertEqual(spec.approval_policy, "human")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertTrue(spec.network_required)
        self.assertIn("TAR.GZ", spec.description)
        self.assertEqual(spec.credential_requirements, ())
        self.assertEqual(spec.input_schema["required"], ["source_url", "app_name", "bundle_id"])

        context = CapabilityExecutionContext(
            workspace_id="workspace-a",
            working_tree_id="worktree:a",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
            network_allowed=True,
        )
        params = {
            "source_url": "https://downloads.example.com/Demo.dmg?token=secret",
            "app_name": "Demo.app",
            "bundle_id": "com.example.demo",
        }
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview, {"bundle_id": "com.example.demo"})
        self.assertEqual(handler.execute(params, context, state), {"ok": True})
        self.assertEqual(calls, [("prepare", params), ("execute", "prepared")])

    def test_platform_profile_binding_reuses_typed_preflight_and_execute(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_platform_profile_register_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []

        def typed_preflight(args):
            calls.append(("preflight", dict(args)))
            return {
                "preflight_id": "platform-profile-preflight:typed",
                "workspace_id": args["workspace_id"],
                "kind": args["kind"],
                "profile_id": args["profile_id"],
                "status": "new",
                "spec_hash": "c" * 64,
                "approval_required": True,
                "approval": {
                    "preflight_id": "platform-profile-preflight:typed",
                    "confirmation": "REGISTER_PLATFORM_PROFILE:typed-secret",
                    "expires_at": 2000.0,
                },
                "expires_at": 2000.0,
            }

        def typed_execute(args):
            calls.append(("execute", dict(args)))
            return {"changed": True, "workspace_id": "workspace-a", "profile_id": "desktop-main"}

        spec, handler = build_platform_profile_register_binding(typed_preflight, typed_execute)
        context = CapabilityExecutionContext(
            workspace_id="workspace-a",
            working_tree_id="session:tree-a",
            session_id="",
            owner_id="owner-a",
            task_id="task-a",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {
            "workspace_id": "workspace-a",
            "kind": "desktop",
            "profile_id": "desktop-main",
            "bundle_id": "com.example.App",
        }

        preview, state = handler.preflight(params, context)
        self.assertEqual(spec.capability_id, "platform.profile.register")
        self.assertEqual(spec.category, "desktop_profiles")
        self.assertEqual(spec.shard, "qa")
        self.assertEqual(spec.exposure, "registry")
        self.assertEqual(spec.risk_class, "R3")
        self.assertEqual(spec.approval_policy, "human")
        self.assertEqual(spec.handler, handler.handler_id)
        self.assertEqual(spec.handler_version, handler.handler_version)
        self.assertEqual(calls[0], ("preflight", params))
        self.assertEqual(preview["status"], "new")
        self.assertNotIn("approval", preview)
        self.assertNotIn("confirmation", repr(preview))
        self.assertEqual(
            state,
            {
                "typed_preflight_id": "platform-profile-preflight:typed",
                "typed_confirmation": "REGISTER_PLATFORM_PROFILE:typed-secret",
            },
        )

        result = handler.execute(params, context, state)
        self.assertEqual(result["changed"], True)
        self.assertEqual(
            calls[1],
            (
                "execute",
                {
                    "preflight_id": "platform-profile-preflight:typed",
                    "confirmation": "REGISTER_PLATFORM_PROFILE:typed-secret",
                },
            ),
        )

    def test_platform_profile_binding_rejects_context_workspace_mismatch_before_typed_preflight(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_platform_profile_register_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []
        spec, handler = build_platform_profile_register_binding(
            lambda args: calls.append(dict(args)),
            lambda args: {"unexpected": True},
        )
        self.assertEqual(spec.workspace_binding, "required")
        context = CapabilityExecutionContext(
            workspace_id="workspace-b",
            working_tree_id="session:tree-b",
            session_id="",
            owner_id="owner-a",
            task_id="task-a",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        with self.assertRaises(Exception) as raised:
            handler.preflight(
                {"workspace_id": "workspace-a", "kind": "desktop", "profile_id": "desktop-main", "bundle_id": "com.example.App"},
                context,
            )
        self.assertEqual(raised.exception.code, "CAPABILITY_WORKSPACE_CHANGED")
        self.assertEqual(calls, [])

    def test_command_profile_cleanup_binding_is_registry_only_human_approved_and_pins_typed_preflight(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_command_profile_cleanup_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []

        def typed_preflight(args):
            calls.append(("preflight", dict(args)))
            return {
                "preflight_id": "command-profile-cleanup-preflight:typed",
                "workspace_id": args["workspace_id"],
                "mode": args.get("mode", "expired"),
                "status": "ready",
                "candidate_set_hash": "c" * 64,
                "candidates": [{"profile_id": "managed-expired", "profile_hash": "d" * 64}],
                "approval_required": True,
                "approval": {
                    "preflight_id": "command-profile-cleanup-preflight:typed",
                    "confirmation": "CLEANUP_EPHEMERAL_COMMAND_PROFILES:typed-secret",
                    "expires_at": 2000.0,
                },
                "expires_at": 2000.0,
            }

        def typed_execute(args):
            calls.append(("execute", dict(args)))
            return {"status": "cleaned", "removed_profile_ids": ["managed-expired"]}

        spec, handler = build_command_profile_cleanup_binding(typed_preflight, typed_execute)
        self.assertEqual(spec.capability_id, "platform.command_profile.cleanup_ephemeral")
        self.assertEqual(spec.category, "desktop_profiles")
        self.assertEqual(spec.shard, "platform_integrations")
        self.assertEqual(spec.exposure, "registry")
        self.assertEqual(spec.risk_class, "R3")
        self.assertEqual(spec.approval_policy, "human")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertEqual(set(spec.input_schema["properties"]), {"workspace_id", "mode"})
        self.assertEqual(spec.input_schema["properties"]["mode"]["enum"], ["expired", "all_ephemeral"])
        self.assertFalse(spec.input_schema["additionalProperties"])

        context = CapabilityExecutionContext(
            workspace_id="workspace-a",
            working_tree_id="session:tree-a",
            session_id="",
            owner_id="owner-a",
            task_id="task-a",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"workspace_id": "workspace-a", "mode": "expired"}
        preview, state = handler.preflight(params, context)
        self.assertEqual(calls, [("preflight", params)])
        self.assertEqual(preview["status"], "ready")
        self.assertNotIn("approval", preview)
        self.assertNotIn("preflight_id", preview)
        self.assertNotIn("typed-secret", repr(preview))
        self.assertEqual(
            state,
            {
                "typed_preflight_id": "command-profile-cleanup-preflight:typed",
                "typed_confirmation": "CLEANUP_EPHEMERAL_COMMAND_PROFILES:typed-secret",
                "noop": False,
            },
        )

        result = handler.execute(params, context, state)
        self.assertEqual(result["removed_profile_ids"], ["managed-expired"])
        self.assertEqual(
            calls[1],
            (
                "execute",
                {
                    "preflight_id": "command-profile-cleanup-preflight:typed",
                    "confirmation": "CLEANUP_EPHEMERAL_COMMAND_PROFILES:typed-secret",
                },
            ),
        )

    def test_command_profile_cleanup_binding_rejects_workspace_mismatch_and_short_circuits_noop(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_command_profile_cleanup_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []

        def typed_preflight(args):
            calls.append(("preflight", dict(args)))
            return {
                "workspace_id": args["workspace_id"],
                "mode": args.get("mode", "expired"),
                "status": "noop",
                "approval_required": False,
                "candidates": [],
            }

        def typed_execute(args):
            calls.append(("execute", dict(args)))
            return {"unexpected": True}

        _spec, handler = build_command_profile_cleanup_binding(typed_preflight, typed_execute)
        mismatch_context = CapabilityExecutionContext(
            workspace_id="workspace-b",
            working_tree_id="session:tree-b",
            session_id="",
            owner_id="owner-a",
            task_id="task-a",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        with self.assertRaises(Exception) as raised:
            handler.preflight({"workspace_id": "workspace-a", "mode": "expired"}, mismatch_context)
        self.assertEqual(raised.exception.code, "CAPABILITY_WORKSPACE_CHANGED")
        self.assertEqual(calls, [])

        context = CapabilityExecutionContext(
            workspace_id="workspace-a",
            working_tree_id="session:tree-a",
            session_id="",
            owner_id="owner-a",
            task_id="task-a",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {"workspace_id": "workspace-a", "mode": "expired"}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["status"], "noop")
        self.assertFalse(preview["approval_required"])
        self.assertEqual(handler.execute(params, context, state)["status"], "noop")
        self.assertEqual(calls, [("preflight", params)])

    def test_command_profile_register_binding_recreates_lost_typed_preflight(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_command_profile_register_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        class LostTypedPreflight(RuntimeError):
            code = "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND"

        calls: list[tuple[str, dict[str, object]]] = []
        generation = 0

        def typed_preflight(args):
            nonlocal generation
            generation += 1
            calls.append(("preflight", dict(args)))
            return {
                "preflight_id": f"command-profile-preflight:{generation}",
                "workspace_id": args["workspace_id"],
                "profile_id": args["profile_id"],
                "status": "new",
                "approval": {"confirmation": f"REGISTER_COMMAND_PROFILE:inner-{generation}"},
            }

        def typed_execute(args):
            calls.append(("execute", dict(args)))
            if args["preflight_id"] == "command-profile-preflight:1":
                raise LostTypedPreflight("typed preflight was lost after runtime restart")
            return {"status": "registered", "preflight_id": args["preflight_id"]}

        _spec, handler = build_command_profile_register_binding(typed_preflight, typed_execute)
        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )
        params = {
            "workspace_id": "fixture",
            "profile_id": "managed-maintenance",
            "argv": ["python3", "scripts/devmcp_maintenance.py"],
            "allowed_args": {"action": {"type": "choice", "choices": ["shortcut", "restart"], "required": True}},
        }

        _preview, state = handler.preflight(params, context)
        result = handler.execute(params, context, state)

        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["preflight_id"], "command-profile-preflight:2")
        self.assertEqual(
            [kind for kind, _ in calls],
            ["preflight", "execute", "preflight", "execute"],
        )
        self.assertEqual(calls[-1][1]["confirmation"], "REGISTER_COMMAND_PROFILE:inner-2")




    def test_development_session_set_evidence_disposition_binding_is_non_destructive_r1(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_development_session_set_evidence_disposition_binding
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        calls = []

        def prepare(params, context):
            calls.append(('prepare', dict(params)))
            return (
                {
                    'session_id': params['session_id'],
                    'requested_disposition': params['disposition'],
                    'worktree_retained': True,
                    'state_digest': 'e' * 64,
                },
                {'session_id': params['session_id'], 'requested_disposition': params['disposition']},
            )

        def execute(state, context):
            calls.append(('execute', dict(state)))
            return {
                'session_id': state['session_id'],
                'previous_disposition': '',
                'new_disposition': state['requested_disposition'],
                'sidecar_updated': True,
                'worktree_retained': True,
            }

        spec, handler = build_development_session_set_evidence_disposition_binding(prepare, execute)
        self.assertEqual(spec.capability_id, 'development.session.set_evidence_disposition')
        self.assertEqual(spec.risk_class, 'R1')
        self.assertEqual(spec.approval_policy, 'automatic')
        self.assertEqual(spec.workspace_binding, 'required')
        self.assertFalse(spec.session_required)
        self.assertFalse(spec.writer_lease_required)
        self.assertFalse(spec.network_required)
        self.assertFalse(spec.deprecated)

        context = CapabilityExecutionContext(
            workspace_id='fixture',
            working_tree_id='worktree:fixture',
            session_id='',
            owner_id='owner',
            task_id='task',
            policy_revision='policy-v1',
            policy_digest='a' * 64,
        )
        params = {'session_id': 'session:durable-fixture-0002', 'disposition': 'ABANDONED_EXPERIMENT'}
        preview, state = handler.preflight(params, context)
        self.assertTrue(preview['worktree_retained'])
        self.assertEqual(preview['operation'], 'development.session.set_evidence_disposition')
        self.assertEqual(preview['state_digest'], 'e' * 64)
        result = handler.execute(params, context, state)
        self.assertTrue(result['sidecar_updated'])
        self.assertTrue(result['worktree_retained'])
        self.assertEqual([kind for kind, _ in calls], ['prepare', 'execute'])


if __name__ == '__main__':
    unittest.main()
