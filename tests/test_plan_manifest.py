from __future__ import annotations

import unittest

from chatgpt_dev_mcp.plan_manifest import (
    PlanManifestValidationError,
    plan_intent_fingerprint,
    plan_manifest_from_mapping,
)


def _manifest(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "plan_id": "devmcp-plan-control-plane",
        "revision": 1,
        "workspace_id": "chatgpt-dev-mcp",
        "title": "Plan Control Plane",
        "status": "active",
        "spec_path": "docs/superpowers/specs/example.md",
        "spec_hash": "a" * 64,
        "plan_path": "docs/superpowers/plans/example.md",
        "plan_hash": "b" * 64,
        "supersedes_plan_ids": [],
        "tasks": [
            {
                "plan_task_id": "plan-control.manifest",
                "title": "Add manifest model",
                "paths": ["src/chatgpt_dev_mcp/plan_manifest.py"],
                "resources": ["architecture:plan-control-task1"],
                "dependencies": [],
                "acceptance_criteria": ["model validates"],
                "delivery_requirements": ["focused tests pass"],
            }
        ],
    }
    value.update(overrides)
    return value


class PlanManifestTests(unittest.TestCase):
    def test_parses_manifest_and_derives_stable_logical_task_identity(self) -> None:
        manifest = plan_manifest_from_mapping(_manifest())

        self.assertEqual(manifest.plan_id, "devmcp-plan-control-plane")
        self.assertEqual(manifest.revision, 1)
        self.assertEqual(manifest.tasks[0].plan_task_id, "plan-control.manifest")
        self.assertEqual(
            manifest.tasks[0].logical_task_id,
            plan_manifest_from_mapping(_manifest(title="Renamed plan title")).tasks[0].logical_task_id,
        )

    def test_logical_task_identity_changes_when_stable_task_id_changes(self) -> None:
        original = plan_manifest_from_mapping(_manifest()).tasks[0].logical_task_id
        changed = _manifest()
        changed["tasks"] = [
            {
                "plan_task_id": "plan-control.persistence",
                "title": "Add manifest model",
                "paths": ["src/chatgpt_dev_mcp/plan_manifest.py"],
                "resources": ["architecture:plan-control-task1"],
                "dependencies": [],
                "acceptance_criteria": ["model validates"],
                "delivery_requirements": ["focused tests pass"],
            }
        ]

        replacement = plan_manifest_from_mapping(changed).tasks[0].logical_task_id

        self.assertNotEqual(original, replacement)

    def test_intent_fingerprint_is_order_independent_for_scope_sets(self) -> None:
        first = plan_intent_fingerprint(
            "chatgpt-dev-mcp",
            "Add plan model",
            ["tests/test_plan_manifest.py", "src/chatgpt_dev_mcp/plan_manifest.py"],
            ["architecture:plan-control-task1", "resource:secondary"],
            ["model validates", "focused tests pass"],
        )
        second = plan_intent_fingerprint(
            "chatgpt-dev-mcp",
            "Add plan model",
            ["src/chatgpt_dev_mcp/plan_manifest.py", "tests/test_plan_manifest.py"],
            ["resource:secondary", "architecture:plan-control-task1"],
            ["focused tests pass", "model validates"],
        )

        self.assertEqual(first, second)

    def test_rejects_duplicate_plan_task_ids(self) -> None:
        value = _manifest()
        task = dict(value["tasks"][0])  # type: ignore[index]
        value["tasks"] = [task, dict(task)]

        with self.assertRaisesRegex(PlanManifestValidationError, "duplicate plan_task_id"):
            plan_manifest_from_mapping(value)

    def test_rejects_unknown_task_dependency(self) -> None:
        value = _manifest()
        task = dict(value["tasks"][0])  # type: ignore[index]
        task["dependencies"] = ["plan-control.missing"]
        value["tasks"] = [task]

        with self.assertRaisesRegex(PlanManifestValidationError, "unknown dependency"):
            plan_manifest_from_mapping(value)

    def test_rejects_invalid_hashes(self) -> None:
        with self.assertRaisesRegex(PlanManifestValidationError, "spec_hash"):
            plan_manifest_from_mapping(_manifest(spec_hash="not-a-hash"))

        with self.assertRaisesRegex(PlanManifestValidationError, "plan_hash"):
            plan_manifest_from_mapping(_manifest(plan_hash="also-not-a-hash"))

    def test_rejects_absolute_or_traversing_paths(self) -> None:
        for invalid in ("/tmp/file.py", "../escape.py", "src/../escape.py"):
            value = _manifest()
            task = dict(value["tasks"][0])  # type: ignore[index]
            task["paths"] = [invalid]
            value["tasks"] = [task]

            with self.subTest(invalid=invalid):
                with self.assertRaises(PlanManifestValidationError):
                    plan_manifest_from_mapping(value)

    def test_rejects_duplicate_resources(self) -> None:
        value = _manifest()
        task = dict(value["tasks"][0])  # type: ignore[index]
        task["resources"] = ["resource:one", "resource:one"]
        value["tasks"] = [task]

        with self.assertRaisesRegex(PlanManifestValidationError, "resources"):
            plan_manifest_from_mapping(value)

    def test_rejects_empty_acceptance_criteria(self) -> None:
        value = _manifest()
        task = dict(value["tasks"][0])  # type: ignore[index]
        task["acceptance_criteria"] = []
        value["tasks"] = [task]

        with self.assertRaisesRegex(PlanManifestValidationError, "acceptance_criteria"):
            plan_manifest_from_mapping(value)

    def test_rejects_unknown_manifest_or_task_status(self) -> None:
        with self.assertRaisesRegex(PlanManifestValidationError, "status"):
            plan_manifest_from_mapping(_manifest(status="paused"))

        value = _manifest()
        task = dict(value["tasks"][0])  # type: ignore[index]
        task["state"] = "paused"
        value["tasks"] = [task]
        with self.assertRaisesRegex(PlanManifestValidationError, "state"):
            plan_manifest_from_mapping(value)


if __name__ == "__main__":
    unittest.main()
