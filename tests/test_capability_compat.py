from __future__ import annotations

import unittest


def _context():
    from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

    return CapabilityExecutionContext(
        workspace_id="fixture",
        working_tree_id="worktree:fixture",
        session_id="",
        owner_id="owner",
        task_id="task",
        policy_revision="policy-v1",
        policy_digest="a" * 64,
    )


class CapabilityCompatTests(unittest.TestCase):
    def test_readonly_binding_preserves_schema_and_needs_no_outer_approval(self) -> None:
        from chatgpt_dev_mcp.capability_compat import DelegatedStableCapabilityGateway, build_legacy_tool_binding
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        definition = {
            "name": "legacy.read",
            "description": "read",
            "inputSchema": {
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "idempotentHint": True},
        }
        binding = build_legacy_tool_binding(
            definition,
            category="development",
            shard="development",
            risk_class="R0",
            workspace_binding="required",
            invoke=lambda name, params, context: {"name": name, "value": params["value"]},
        )
        registry = CapabilityRegistry([binding.spec])
        gateway = DelegatedStableCapabilityGateway(registry, ttl_seconds=120)
        gateway.register_handler(binding.handler)
        preflight = gateway.preflight("legacy.read", {"value": "ok"}, _context())
        self.assertFalse(preflight["approval_required"])
        result = gateway.execute(preflight["preflight_id"], "legacy.read", {"value": "ok"}, _context())
        self.assertEqual(result["result"], {"name": "legacy.read", "value": "ok"})
        self.assertEqual(binding.spec.input_schema, definition["inputSchema"])
        self.assertNotIn("handler", registry.describe("legacy.read"))

    def test_delegated_binding_requires_explicit_authority_preserving_registration(self) -> None:
        from chatgpt_dev_mcp.capability_compat import DelegatedStableCapabilityGateway, build_legacy_tool_binding
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        definition = {
            "name": "legacy.write",
            "inputSchema": {"type": "object", "additionalProperties": False},
            "annotations": {"readOnlyHint": False},
        }
        binding = build_legacy_tool_binding(
            definition,
            category="delivery",
            shard="delivery",
            risk_class="R3",
            workspace_binding="required",
            invoke=lambda name, params, context: {"ok": True},
        )
        self.assertTrue(binding.delegated_authority)
        self.assertEqual(binding.spec.approval_policy, "delegated")
        registry = CapabilityRegistry([binding.spec])

        ordinary = DelegatedStableCapabilityGateway(registry, ttl_seconds=120)
        ordinary.register_handler(binding.handler)
        with self.assertRaises(Exception) as raised:
            ordinary.preflight("legacy.write", {}, _context())
        self.assertEqual(raised.exception.code, "CAPABILITY_DELEGATED_AUTHORITY_INVALID")

        delegated = DelegatedStableCapabilityGateway(registry, ttl_seconds=120)
        delegated.register_delegated_handler(binding.handler)
        preflight = delegated.preflight("legacy.write", {}, _context())
        self.assertFalse(preflight["approval_required"])
        self.assertNotIn("approval", preflight)
        result = delegated.execute(preflight["preflight_id"], "legacy.write", {}, _context())
        self.assertTrue(result["result"]["ok"])


if __name__ == "__main__":
    unittest.main()

