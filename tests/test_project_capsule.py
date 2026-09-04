from __future__ import annotations

import unittest

from chatgpt_dev_mcp.project_capsule import CapsuleSection, ContextBudget, ProjectCapsule, render_capsule


class ProjectCapsuleTests(unittest.TestCase):
    def test_safety_sections_survive_small_budget(self) -> None:
        capsule = ProjectCapsule(
            workspace_id="demo",
            source_revision="a" * 40,
            sections=(
                CapsuleSection("invariants", 100, True, ("no broker writes",)),
                CapsuleSection("repo_map", 20, False, tuple(f"symbol-{i}" for i in range(100))),
            ),
        )

        rendered = render_capsule(capsule, ContextBudget(max_bytes=1024))

        self.assertIn("invariants", rendered.sections)
        self.assertGreater(rendered.omitted_count, 0)
        self.assertFalse(rendered.required_over_budget)

    def test_capsule_id_is_deterministic(self) -> None:
        section = CapsuleSection("state", 80, True, ("clean",))
        first = ProjectCapsule("demo", "a" * 40, (section,))
        second = ProjectCapsule("demo", "a" * 40, (section,))

        self.assertEqual(first.capsule_id, second.capsule_id)

    def test_duplicate_sections_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ProjectCapsule(
                "demo",
                "a" * 40,
                (CapsuleSection("state", 80, True, ("one",)), CapsuleSection("state", 70, False, ("two",))),
            )


if __name__ == "__main__":
    unittest.main()
