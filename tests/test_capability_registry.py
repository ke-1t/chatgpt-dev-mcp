from __future__ import annotations

import unittest


def _spec(capability_id: str, **overrides):
    from chatgpt_dev_mcp.capability_registry import CapabilitySpec

    values = {
        "capability_id": capability_id,
        "version": "1.0.0",
        "description": f"Capability {capability_id}",
        "category": "development",
        "shard": "development",
        "exposure": "registry",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string", "minLength": 1}},
            "required": ["name"],
            "additionalProperties": False,
        },
        "output_schema": {"type": "object"},
        "risk_class": "R0",
        "approval_policy": "none",
        "workspace_binding": "none",
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


class CapabilityRegistryTests(unittest.TestCase):
    def test_unknown_capability_is_rejected(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityRegistryError

        registry = CapabilityRegistry()
        with self.assertRaises(CapabilityRegistryError) as raised:
            registry.describe("missing.capability")
        self.assertEqual(raised.exception.code, "UNKNOWN_CAPABILITY")

    def test_invalid_params_are_rejected_strictly(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityValidationError

        registry = CapabilityRegistry([_spec("test.echo")])

        for params in ({}, {"name": ""}, {"name": 3}, {"name": "ok", "extra": True}):
            with self.subTest(params=params):
                with self.assertRaises(CapabilityValidationError) as raised:
                    registry.validate_params("test.echo", params)
                self.assertEqual(raised.exception.code, "INVALID_CAPABILITY_PARAMS")

        self.assertEqual(registry.validate_params("test.echo", {"name": "ok"}), {"name": "ok"})

    def test_duplicate_capability_id_is_rejected(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityRegistryError

        registry = CapabilityRegistry([_spec("test.echo")])
        with self.assertRaises(CapabilityRegistryError) as raised:
            registry.register(_spec("test.echo"))
        self.assertEqual(raised.exception.code, "DUPLICATE_CAPABILITY")

    def test_deprecated_capability_returns_replacement(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        registry = CapabilityRegistry(
            [
                _spec(
                    "legacy.echo",
                    deprecated=True,
                    replacement="test.echo",
                )
            ]
        )
        described = registry.describe("legacy.echo")
        self.assertTrue(described["deprecated"])
        self.assertEqual(described["replacement"], "test.echo")

    def test_catalog_is_bounded_sorted_and_does_not_expose_handler_callable(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityRegistryError

        registry = CapabilityRegistry([_spec(f"test.{index:03d}") for index in range(8)])
        result = registry.catalog(prefix="test.", limit=3)

        self.assertEqual(result["count"], 8)
        self.assertEqual(result["returned"], 3)
        self.assertEqual([item["capability_id"] for item in result["capabilities"]], ["test.000", "test.001", "test.002"])
        self.assertNotIn("handler_callable", result["capabilities"][0])
        self.assertNotIn("handler", result["capabilities"][0])
        self.assertNotIn("handler_version", result["capabilities"][0])

        described = registry.describe("test.000")
        self.assertEqual(described["category"], "development")
        self.assertEqual(described["shard"], "development")
        self.assertEqual(described["exposure"], "registry")
        self.assertNotIn("handler", described)
        self.assertNotIn("handler_version", described)

        with self.assertRaises(CapabilityRegistryError) as raised:
            registry.catalog(limit=101)
        self.assertEqual(raised.exception.code, "CATALOG_LIMIT_OUT_OF_RANGE")

    def test_catalog_preserves_legacy_deprecated_default(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        registry = CapabilityRegistry(
            [
                _spec("test.active"),
                _spec("test.legacy", deprecated=True, replacement="test.active"),
            ]
        )

        default = registry.catalog(prefix="test.")
        self.assertEqual(
            [item["capability_id"] for item in default["capabilities"]],
            ["test.active", "test.legacy"],
        )
        self.assertNotIn("mode", default)
        self.assertNotIn("include_deprecated", default)

        filtered = registry.catalog(prefix="test.", include_deprecated=False)
        self.assertEqual([item["capability_id"] for item in filtered["capabilities"]], ["test.active"])

    def test_internal_metadata_hash_changes_when_registry_changes(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        registry = CapabilityRegistry([_spec("test.echo")])
        before = registry.metadata()
        registry.register(_spec("test.second"))
        after = registry.metadata()

        self.assertEqual(before["revision"], "capability-registry-v1")
        self.assertEqual(before["count"], 1)
        self.assertEqual(after["count"], 2)
        self.assertNotEqual(before["hash"], after["hash"])
        self.assertEqual(len(after["hash"]), 64)

    def test_internal_metadata_hash_pins_hidden_handler_routing(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry

        before = CapabilityRegistry([_spec("test.echo", handler="test.echo.v1", handler_version="1")]).metadata()
        after = CapabilityRegistry([_spec("test.echo", handler="test.echo.v2", handler_version="2")]).metadata()

        self.assertNotEqual(before["hash"], after["hash"])

    def test_registry_can_be_frozen_after_assembly(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityRegistryError

        registry = CapabilityRegistry([_spec("test.echo")])
        self.assertFalse(registry.is_frozen)
        self.assertIs(registry.freeze(), registry)
        self.assertTrue(registry.is_frozen)

        with self.assertRaises(CapabilityRegistryError) as raised:
            registry.register(_spec("test.second"))
        self.assertEqual(raised.exception.code, "CAPABILITY_REGISTRY_FROZEN")

    def test_handler_output_is_validated_against_declared_schema(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityValidationError

        registry = CapabilityRegistry(
            [
                _spec(
                    "test.echo",
                    output_schema={
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                        "additionalProperties": False,
                    },
                )
            ]
        )

        self.assertEqual(registry.validate_result("test.echo", {"ok": True}), {"ok": True})
        with self.assertRaises(CapabilityValidationError) as raised:
            registry.validate_result("test.echo", {"ok": "yes"})
        self.assertEqual(raised.exception.code, "INVALID_CAPABILITY_RESULT")

    def test_shard_registry_rejects_mismatched_capability_shard(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CapabilityRegistryError

        registry = CapabilityRegistry(shard_id="development")
        registry.register(_spec("test.dev"))
        with self.assertRaises(CapabilityRegistryError) as raised:
            registry.register(_spec("test.delivery", shard="delivery"))
        self.assertEqual(raised.exception.code, "CAPABILITY_SHARD_MISMATCH")

    def test_composite_registry_routes_across_default_shards_and_freezes_children(self) -> None:
        from chatgpt_dev_mcp.capability_registry import (
            DEFAULT_CAPABILITY_SHARDS,
            CapabilityRegistry,
            CompositeCapabilityRegistry,
        )

        registries = [CapabilityRegistry(shard_id=shard) for shard in DEFAULT_CAPABILITY_SHARDS]
        development = next(registry for registry in registries if registry.shard_id == "development")
        delivery = next(registry for registry in registries if registry.shard_id == "delivery")
        development.register(_spec("code.references"))
        delivery.register(_spec("git.release", category="git_delivery", shard="delivery"))
        composite = CompositeCapabilityRegistry(registries).freeze()

        self.assertEqual(tuple(composite.shard_ids), DEFAULT_CAPABILITY_SHARDS)
        self.assertTrue(composite.is_frozen)
        self.assertTrue(all(registry.is_frozen for registry in registries))
        self.assertEqual(composite.get("code.references").shard, "development")
        self.assertEqual(composite.describe("git.release")["category"], "git_delivery")
        self.assertEqual(composite.validate_params("code.references", {"name": "symbol"}), {"name": "symbol"})

    def test_composite_registry_rejects_duplicate_capability_across_shards(self) -> None:
        from chatgpt_dev_mcp.capability_registry import (
            CapabilityRegistry,
            CapabilityRegistryError,
            CompositeCapabilityRegistry,
        )

        development = CapabilityRegistry([_spec("shared.echo")], shard_id="development")
        delivery = CapabilityRegistry([_spec("shared.echo", shard="delivery")], shard_id="delivery")
        with self.assertRaises(CapabilityRegistryError) as raised:
            CompositeCapabilityRegistry([development, delivery])
        self.assertEqual(raised.exception.code, "DUPLICATE_CAPABILITY")

    def test_composite_catalog_filters_by_category_shard_and_query(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry

        development = CapabilityRegistry(
            [
                _spec("code.references", description="Find references to one symbol"),
                _spec("code.callers", description="Find callers of one symbol", category="code_intelligence"),
            ],
            shard_id="development",
        )
        media = CapabilityRegistry(
            [_spec("media.inspect", description="Inspect media artifact", category="media", shard="media")],
            shard_id="media",
        )
        composite = CompositeCapabilityRegistry([development, media]).freeze()

        by_category = composite.catalog(category="code_intelligence")
        self.assertEqual([item["capability_id"] for item in by_category["capabilities"]], ["code.callers"])
        by_shard = composite.catalog(shard="media")
        self.assertEqual([item["capability_id"] for item in by_shard["capabilities"]], ["media.inspect"])
        by_query = composite.catalog(query="references")
        self.assertEqual([item["capability_id"] for item in by_query["capabilities"]], ["code.references"])
        self.assertIn("media", composite.shard_ids)

    def test_composite_overview_returns_compact_shard_summary(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry

        development = CapabilityRegistry(
            [
                _spec("context.bootstrap", category="context"),
                _spec("development.fast_step"),
                _spec(
                    "development.legacy",
                    deprecated=True,
                    replacement="development.fast_step",
                ),
            ],
            shard_id="development",
        )
        delivery = CapabilityRegistry(
            [
                _spec("git.stage", category="git_delivery", shard="delivery"),
                _spec("git.push", category="git_delivery", shard="delivery"),
            ],
            shard_id="delivery",
        )
        composite = CompositeCapabilityRegistry([development, delivery]).freeze()

        legacy_catalog = composite.catalog()
        self.assertEqual(legacy_catalog["count"], 5)
        self.assertEqual(len(legacy_catalog["capabilities"]), 5)
        self.assertNotIn("mode", legacy_catalog)

        overview = composite.overview()

        self.assertEqual(overview["mode"], "overview")
        self.assertFalse(overview["include_deprecated"])
        self.assertEqual(overview["count"], 4)
        self.assertEqual(overview["returned"], 2)
        self.assertEqual(overview["capabilities"], [])
        self.assertEqual(
            overview["shards"],
            [
                {
                    "shard_id": "development",
                    "count": 2,
                    "categories": [
                        {"category": "context", "count": 1},
                        {"category": "development", "count": 1},
                    ],
                },
                {
                    "shard_id": "delivery",
                    "count": 2,
                    "categories": [{"category": "git_delivery", "count": 2}],
                },
            ],
        )
        self.assertEqual(overview["discovery"]["filters"], ["shard", "category", "query", "prefix"])
        self.assertEqual(overview["discovery"]["describe_tool"], "capability_describe")

        with_deprecated = composite.overview(include_deprecated=True)
        self.assertTrue(with_deprecated["include_deprecated"])
        self.assertEqual(with_deprecated["count"], 5)
        self.assertEqual(with_deprecated["shards"][0]["count"], 3)

    def test_composite_metadata_hash_pins_shard_contents(self) -> None:
        from chatgpt_dev_mcp.capability_registry import CapabilityRegistry, CompositeCapabilityRegistry

        before = CompositeCapabilityRegistry(
            [CapabilityRegistry([_spec("test.echo")], shard_id="development")]
        ).metadata()
        after = CompositeCapabilityRegistry(
            [CapabilityRegistry([_spec("test.echo"), _spec("test.second")], shard_id="development")]
        ).metadata()

        self.assertEqual(before["count"], 1)
        self.assertEqual(after["count"], 2)
        self.assertNotEqual(before["hash"], after["hash"])
        self.assertEqual(before["shards"][0]["shard_id"], "development")


if __name__ == "__main__":
    unittest.main()
