from __future__ import annotations

import unittest

from chatgpt_dev_mcp.change_impact import classify_change_impact


class ChangeImpactTests(unittest.TestCase):
    def test_markdown_under_docs_is_execution_free(self) -> None:
        impact = classify_change_impact(("docs/superpowers/specs/example.md",))

        self.assertFalse(impact.execution_required)
        self.assertEqual(impact.reason, "documentation_only")

    def test_root_readme_is_execution_free(self) -> None:
        impact = classify_change_impact(("README.md",))

        self.assertFalse(impact.execution_required)

    def test_project_rule_and_unknown_files_fail_closed(self) -> None:
        self.assertTrue(classify_change_impact(("pyproject.toml",)).execution_required)
        self.assertTrue(classify_change_impact(("notes/generated.bin",)).execution_required)

    def test_mixed_docs_and_source_requires_execution(self) -> None:
        impact = classify_change_impact(("docs/guide.md", "src/chatgpt_dev_mcp/server.py"))

        self.assertTrue(impact.execution_required)


if __name__ == "__main__":
    unittest.main()
