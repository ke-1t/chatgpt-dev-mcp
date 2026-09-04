from __future__ import annotations

import unittest


POLICY_A = "a" * 64
POLICY_B = "b" * 64


class ExternalCapabilityBindingTests(unittest.TestCase):
    def test_external_invoke_binding_requires_workspace_trust_and_network(self) -> None:
        from chatgpt_dev_mcp.capability_bindings import build_external_capability_invoke_binding

        spec, _handler = build_external_capability_invoke_binding(lambda capability, request: {
            "status": "unavailable",
            "capability": capability,
            "request_seen": bool(request),
        })

        self.assertEqual(spec.capability_id, "external.capability.invoke")
        self.assertEqual(spec.risk_class, "R2")
        self.assertEqual(spec.approval_policy, "workspace_trust")
        self.assertTrue(spec.network_required)
        self.assertEqual(spec.workspace_binding, "required")


def _spec(capability_id: str = "test.echo", **overrides):
    from chatgpt_dev_mcp.capability_registry import CapabilitySpec

    values = {
        "capability_id": capability_id,
        "version": "1.0.0",
        "description": "Echo a bounded value",
        "category": "development",
        "shard": "development",
        "exposure": "registry",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string", "minLength": 1, "maxLength": 80}},
            "required": ["value"],
            "additionalProperties": False,
        },
        "output_schema": {"type": "object"},
        "risk_class": "R0",
        "approval_policy": "none",
        "workspace_binding": "required",
        "session_required": False,
        "writer_lease_required": False,
        "network_required": False,
        "credential_requirements": (),
        "timeout_ms": 5_000,
        "idempotency": "idempotent",
        "audit_category": "test",
        "deprecated": False,
        "replacement": None,
        "handler": "test.echo",
        "handler_version": "1",
    }
    values.update(overrides)
    return CapabilitySpec(**values)


def _context(**overrides):
    from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

    values = {
        "workspace_id": "workspace-a",
        "working_tree_id": "session:tree-a",
        "session_id": "session:a",
        "owner_id": "owner-a",
        "task_id": "task-a",
        "policy_revision": "policy-v1",
        "policy_digest": POLICY_A,
        "writer_lease_id": "",
        "credential_grants": (),
        "network_allowed": False,
        "workspace_trust_level": "standard",
    }
    values.update(overrides)
    return CapabilityExecutionContext(**values)


def _gateway(spec=None, *, clock=None, handler_version="1", preflight=None, execute=None, preflight_store=None):
    from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityHandler, StableCapabilityGateway
    from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry([spec or _spec()])
    gateway = StableCapabilityGateway(
        registry,
        clock=clock,
        ttl_seconds=120,
        preflight_store=preflight_store,
    )
    gateway.register_handler(
        CapabilityHandler(
            handler_id=(spec or _spec()).handler,
            handler_version=handler_version,
            preflight=preflight,
            execute=execute or (lambda params, context, state: {"echo": params["value"], "state": state}),
        )
    )
    return registry, gateway


class CapabilityGatewayTests(unittest.TestCase):
    def test_shared_preflight_store_supports_cross_gateway_execute_and_replay(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityPreflightStore

        store = CapabilityPreflightStore()
        _registry, first = _gateway(preflight_store=store)
        _registry, second = _gateway(preflight_store=store)
        context = _context()

        preflight = first.preflight("test.echo", {"value": "hello"}, context)
        result = second.execute(
            preflight["preflight_id"],
            "test.echo",
            {"value": "hello"},
            context,
        )

        self.assertEqual(result["result"]["echo"], "hello")
        with self.assertRaisesRegex(Exception, "replay") as raised:
            first.execute(
                preflight["preflight_id"],
                "test.echo",
                {"value": "hello"},
                context,
            )
        self.assertEqual(raised.exception.code, "CAPABILITY_PREFLIGHT_REPLAY")

    def test_default_preflight_ttl_is_fifteen_minutes(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityHandler, StableCapabilityGateway
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        registry = CapabilityRegistry([_spec()])
        gateway = StableCapabilityGateway(registry, clock=lambda: 1000.0)
        gateway.register_handler(
            CapabilityHandler(
                handler_id="test.echo",
                handler_version="1",
                execute=lambda params, context, state: {"echo": params["value"]},
            )
        )

        preflight = gateway.preflight("test.echo", {"value": "hello"}, _context())

        self.assertEqual(preflight["expires_at"] - preflight["created_at"], 900.0)

    def test_workspace_trust_policy_standard_trusted_and_pinned(self) -> None:
        spec = _spec(risk_class="R2", approval_policy="workspace_trust")
        _registry, gateway = _gateway(spec)
        standard = _context(workspace_trust_level="standard")
        self.assertTrue(gateway.preflight("test.echo", {"value":"open"}, standard)["approval_required"])
        trusted = _context(workspace_trust_level="trusted_development")
        preflight = gateway.preflight("test.echo", {"value":"open"}, trusted)
        self.assertFalse(preflight["approval_required"])
        self.assertEqual(preflight["workspace_trust_level"], "trusted_development")
        with self.assertRaises(Exception) as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value":"open"}, standard)
        self.assertEqual(raised.exception.code, "CAPABILITY_WORKSPACE_TRUST_CHANGED")
        with self.assertRaises(Exception) as invalid:
            gateway.preflight("test.echo", {"value":"open"}, _context(workspace_trust_level="unbounded"))
        self.assertEqual(invalid.exception.code, "CAPABILITY_WORKSPACE_TRUST_INVALID")

    def test_gateway_accepts_composite_registry_and_filters_catalog(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityHandler, StableCapabilityGateway
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry

        spec = _spec("test.echo")
        shard = CapabilityRegistry([spec], shard_id="development")
        composite = CompositeCapabilityRegistry([shard]).freeze()
        gateway = StableCapabilityGateway(composite, ttl_seconds=120)
        gateway.register_handler(
            CapabilityHandler(
                handler_id="test.echo",
                handler_version="1",
                execute=lambda params, context, state: {"echo": params["value"]},
            )
        )

        catalog = gateway.catalog(category="development", shard="development", query="echo")
        self.assertEqual([item["capability_id"] for item in catalog["capabilities"]], ["test.echo"])
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)
        result = gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(result["result"], {"echo": "hello"})

    def test_gateway_keeps_legacy_catalog_and_exposes_internal_overview(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import StableCapabilityGateway
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry

        development = CapabilityRegistry(
            [
                _spec("test.active"),
                _spec("test.legacy", deprecated=True, replacement="test.active"),
            ],
            shard_id="development",
        )
        gateway = StableCapabilityGateway(CompositeCapabilityRegistry([development]).freeze(), ttl_seconds=120)

        legacy = gateway.catalog()
        self.assertEqual(
            [item["capability_id"] for item in legacy["capabilities"]],
            ["test.active", "test.legacy"],
        )
        self.assertNotIn("mode", legacy)

        overview = gateway.overview()
        self.assertEqual(overview["mode"], "overview")
        self.assertFalse(overview["include_deprecated"])
        self.assertEqual(overview["count"], 1)
        self.assertEqual(overview["capabilities"], [])

        explicit = gateway.catalog(prefix="test.", include_deprecated=False)
        self.assertEqual(
            [item["capability_id"] for item in explicit["capabilities"]],
            ["test.active"],
        )

    def test_readonly_preflight_and_execute_are_exact_and_single_use(self) -> None:
        _registry, gateway = _gateway()
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)

        self.assertFalse(preflight["approval_required"])
        self.assertEqual(preflight["capability_id"], "test.echo")
        self.assertEqual(preflight["capability_version"], "1.0.0")
        self.assertEqual(preflight["risk_class"], "R0")
        self.assertEqual(preflight["policy_digest"], POLICY_A)
        self.assertEqual(len(preflight["normalized_args_hash"]), 64)
        self.assertNotIn("handler_version", preflight)

        result = gateway.execute(
            preflight["preflight_id"],
            "test.echo",
            {"value": "hello"},
            context,
        )
        self.assertEqual(result["result"]["echo"], "hello")
        self.assertTrue(result["preflight_consumed"])
        self.assertNotIn("handler_version", result)

        with self.assertRaisesRegex(Exception, "replay") as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(raised.exception.code, "CAPABILITY_PREFLIGHT_REPLAY")

    def test_approval_required_path_requires_exact_confirmation(self) -> None:
        spec = _spec(risk_class="R3", approval_policy="human")
        _registry, gateway = _gateway(spec)
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "approved"}, context)

        self.assertTrue(preflight["approval_required"])
        approval = preflight["approval"]
        confirmation = approval["confirmation"]
        self.assertEqual(approval["copy_block"], f"```text\n{confirmation}\n```")
        self.assertEqual(approval["presentation_hint"], "copyable_code_block")
        self.assertNotIn("```", confirmation)
        with self.assertRaises(Exception) as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "approved"}, context)
        self.assertEqual(raised.exception.code, "CAPABILITY_APPROVAL_REQUIRED")

        result = gateway.execute(
            preflight["preflight_id"],
            "test.echo",
            {"value": "approved"},
            context,
            confirmation=confirmation,
        )
        self.assertEqual(result["result"]["echo"], "approved")

    def test_trusted_session_grant_policy_never_degrades_to_human_confirmation(self) -> None:
        spec = _spec(risk_class="R2", approval_policy="trusted_session_grant")
        _registry, gateway = _gateway(spec)

        with self.assertRaises(Exception) as raised:
            gateway.preflight("test.echo", {"value": "maintenance"}, _context())

        self.assertEqual(raised.exception.code, "CAPABILITY_TRUSTED_GRANT_REQUIRED")

    def test_modified_args_are_rejected(self) -> None:
        _registry, gateway = _gateway()
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "original"}, context)
        with self.assertRaises(Exception) as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "changed"}, context)
        self.assertEqual(raised.exception.code, "CAPABILITY_ARGS_CHANGED")

    def test_expired_preflight_is_rejected(self) -> None:
        now = [1000.0]
        _registry, gateway = _gateway(clock=lambda: now[0])
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)
        now[0] = 1120.0
        with self.assertRaises(Exception) as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(raised.exception.code, "CAPABILITY_PREFLIGHT_EXPIRED")

    def test_cross_workspace_and_cross_session_are_rejected(self) -> None:
        spec = _spec(session_required=True)
        _registry, gateway = _gateway(spec)
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)

        with self.assertRaises(Exception) as workspace_error:
            gateway.execute(
                preflight["preflight_id"],
                "test.echo",
                {"value": "hello"},
                _context(workspace_id="workspace-b"),
            )
        self.assertEqual(workspace_error.exception.code, "CAPABILITY_WORKSPACE_CHANGED")

        with self.assertRaises(Exception) as session_error:
            gateway.execute(
                preflight["preflight_id"],
                "test.echo",
                {"value": "hello"},
                _context(session_id="session:b"),
            )
        self.assertEqual(session_error.exception.code, "CAPABILITY_SESSION_CHANGED")

    def test_policy_and_handler_version_drift_are_rejected(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityHandler

        _registry, gateway = _gateway()
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)
        with self.assertRaises(Exception) as policy_error:
            gateway.execute(
                preflight["preflight_id"],
                "test.echo",
                {"value": "hello"},
                _context(policy_revision="policy-v2", policy_digest=POLICY_B),
            )
        self.assertEqual(policy_error.exception.code, "CAPABILITY_POLICY_CHANGED")

        gateway.register_handler(
            CapabilityHandler(
                handler_id="test.echo",
                handler_version="2",
                execute=lambda params, context, state: {"echo": params["value"]},
            ),
            replace=True,
        )
        with self.assertRaises(Exception) as handler_error:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(handler_error.exception.code, "CAPABILITY_HANDLER_VERSION_CHANGED")

    def test_writer_lease_credential_and_network_requirements_fail_closed(self) -> None:
        spec = _spec(
            writer_lease_required=True,
            network_required=True,
            credential_requirements=("oauth:example",),
        )
        _registry, gateway = _gateway(spec)

        with self.assertRaises(Exception) as lease_error:
            gateway.preflight(
                "test.echo",
                {"value": "hello"},
                _context(network_allowed=True, credential_grants=("oauth:example",)),
            )
        self.assertEqual(lease_error.exception.code, "CAPABILITY_WRITER_LEASE_REQUIRED")

        with self.assertRaises(Exception) as credential_error:
            gateway.preflight(
                "test.echo",
                {"value": "hello"},
                _context(writer_lease_id="lease:1", network_allowed=True),
            )
        self.assertEqual(credential_error.exception.code, "CAPABILITY_CREDENTIAL_REQUIRED")

        with self.assertRaises(Exception) as network_error:
            gateway.preflight(
                "test.echo",
                {"value": "hello"},
                _context(writer_lease_id="lease:1", credential_grants=("oauth:example",)),
            )
        self.assertEqual(network_error.exception.code, "CAPABILITY_NETWORK_REQUIRED")

        valid_context = _context(
            writer_lease_id="lease:1",
            credential_grants=("oauth:example",),
            network_allowed=True,
        )
        preflight = gateway.preflight("test.echo", {"value": "hello"}, valid_context)
        with self.assertRaises(Exception) as changed_lease:
            gateway.execute(
                preflight["preflight_id"],
                "test.echo",
                {"value": "hello"},
                _context(
                    writer_lease_id="lease:2",
                    credential_grants=("oauth:example",),
                    network_allowed=True,
                ),
            )
        self.assertEqual(changed_lease.exception.code, "CAPABILITY_WRITER_LEASE_CHANGED")

    def test_handler_preflight_state_is_server_side_and_not_caller_controlled(self) -> None:
        seen = []

        def handler_preflight(params, context):
            return {"validated": True}, {"secret_state": "server-only"}

        def handler_execute(params, context, state):
            seen.append(state)
            return {"ok": True}

        _registry, gateway = _gateway(preflight=handler_preflight, execute=handler_execute)
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)
        self.assertEqual(preflight["handler_preflight"], {"validated": True})
        self.assertNotIn("secret_state", repr(preflight))

        gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(seen, [{"secret_state": "server-only"}])

    def test_handler_output_must_match_declared_schema_and_receipt_remains_consumed(self) -> None:
        spec = _spec(
            output_schema={
                "type": "object",
                "properties": {"ok": {"type": "boolean"}},
                "required": ["ok"],
                "additionalProperties": False,
            }
        )
        _registry, gateway = _gateway(spec, execute=lambda params, context, state: {"ok": "yes"})
        context = _context()
        preflight = gateway.preflight("test.echo", {"value": "hello"}, context)

        with self.assertRaises(Exception) as raised:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(raised.exception.code, "CAPABILITY_RESULT_INVALID")

        with self.assertRaises(Exception) as replay:
            gateway.execute(preflight["preflight_id"], "test.echo", {"value": "hello"}, context)
        self.assertEqual(replay.exception.code, "CAPABILITY_PREFLIGHT_REPLAY")

    def test_arbitrary_handler_and_risk_override_cannot_escape_registry(self) -> None:
        _registry, gateway = _gateway()
        context = _context()
        with self.assertRaises(Exception) as unknown:
            gateway.preflight("shell.exec", {"value": "rm -rf /"}, context)
        self.assertEqual(unknown.exception.code, "UNKNOWN_CAPABILITY")

        with self.assertRaises(Exception) as override:
            gateway.preflight(
                "test.echo",
                {"value": "hello", "handler": "shell.exec", "risk_class": "R0"},
                context,
            )
        self.assertEqual(override.exception.code, "INVALID_CAPABILITY_PARAMS")

    def test_registered_capability_without_exact_handler_fails_closed(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import StableCapabilityGateway
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        registry = CapabilityRegistry([_spec(handler="shell.exec", handler_version="9")])
        gateway = StableCapabilityGateway(registry, ttl_seconds=120)
        with self.assertRaises(Exception) as raised:
            gateway.preflight("test.echo", {"value": "hello"}, _context())
        self.assertEqual(raised.exception.code, "CAPABILITY_HANDLER_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
