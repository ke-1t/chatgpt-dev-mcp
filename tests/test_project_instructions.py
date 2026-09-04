from __future__ import annotations

import unittest


class ProjectInstructionsTests(unittest.TestCase):
    def test_normalizes_markdown_lines_and_stays_within_budget(self) -> None:
        from chatgpt_dev_mcp.project_instructions import parse_project_instructions

        result = parse_project_instructions(
            "# Project rules\n- Never push without approval\n1. Run focused tests\n\nPlain invariant\n",
            max_bytes=64,
        )

        self.assertEqual(result.status, "loaded")
        self.assertEqual(
            result.items,
            ("Project rules", "Never push without approval", "Run focused tests"),
        )
        self.assertLessEqual(result.used_bytes, 64)
        self.assertEqual(len(result.source_hash), 64)

    def test_missing_result_is_non_fatal_and_empty(self) -> None:
        from chatgpt_dev_mcp.project_instructions import ProjectInstructionResult

        result = ProjectInstructionResult.missing()

        self.assertEqual(result.status, "missing")
        self.assertEqual(result.items, ())
        self.assertEqual(result.source_hash, "")
        self.assertEqual(result.used_bytes, 0)

    def test_rejects_nul_and_hard_limit_overflow(self) -> None:
        from chatgpt_dev_mcp.project_instructions import parse_project_instructions

        with self.assertRaises(ValueError):
            parse_project_instructions("unsafe\x00instruction")
        with self.assertRaises(ValueError):
            parse_project_instructions("x" * 8193, hard_max_bytes=8192)

    def test_empty_content_is_reported_as_empty(self) -> None:
        from chatgpt_dev_mcp.project_instructions import parse_project_instructions

        result = parse_project_instructions("\n  \n")

        self.assertEqual(result.status, "empty")
        self.assertEqual(result.items, ())


if __name__ == "__main__":
    unittest.main()
