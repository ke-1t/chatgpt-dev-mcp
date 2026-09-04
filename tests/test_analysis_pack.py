from __future__ import annotations

import unittest


class AnalysisPackTests(unittest.TestCase):
    def test_builds_deterministic_bounded_structured_pack(self) -> None:
        from chatgpt_dev_mcp.analysis_pack import build_analysis_pack

        kwargs = {
            "workspace_id": "fixture",
            "task_id": "task-1",
            "changed_paths": ["src/a.py", "tests/test_a.py"],
            "diffs": {"src/a.py": "+safe change\n"},
            "failures": [{"test": "tests/test_a.py", "message": "expected 1, got 2"}],
            "metadata": {"head": "a" * 40},
            "max_bytes": 4096,
        }
        first = build_analysis_pack(**kwargs)
        second = build_analysis_pack(**kwargs)

        self.assertEqual(first["analysis_pack_id"], second["analysis_pack_id"])
        self.assertTrue(first["analysis_pack_id"].startswith("analysis-pack:"))
        self.assertEqual(first["workspace_id"], "fixture")
        self.assertEqual(first["task_id"], "task-1")
        self.assertEqual(first["changed_files"], ["src/a.py", "tests/test_a.py"])
        self.assertEqual(first["diffs"], {"src/a.py": "+safe change\n"})
        self.assertEqual(len(first["failures"]), 1)
        self.assertFalse(first["truncated"])
        self.assertEqual(first["redactions"], 0)
        self.assertFalse(first["external_execution"])
        self.assertLessEqual(first["used_bytes"], 4096)

    def test_rejects_absolute_traversal_and_unknown_diff_paths(self) -> None:
        from chatgpt_dev_mcp.analysis_pack import AnalysisPackError, build_analysis_pack

        for path in ("/tmp/a.py", "../a.py"):
            with self.subTest(path=path), self.assertRaises(AnalysisPackError):
                build_analysis_pack(
                    workspace_id="fixture",
                    task_id="task-1",
                    changed_paths=[path],
                )

        with self.assertRaises(AnalysisPackError):
            build_analysis_pack(
                workspace_id="fixture",
                task_id="task-1",
                changed_paths=["src/a.py"],
                diffs={"src/b.py": "+change\n"},
            )

    def test_rejects_sensitive_path_built_at_runtime(self) -> None:
        from chatgpt_dev_mcp.analysis_pack import AnalysisPackError, build_analysis_pack

        sensitive_path = "." + "env"
        with self.assertRaises(AnalysisPackError):
            build_analysis_pack(
                workspace_id="fixture",
                task_id="task-1",
                changed_paths=[sensitive_path],
            )

    def test_secret_detector_causes_fail_closed_rejection(self) -> None:
        import chatgpt_dev_mcp.analysis_pack as analysis_pack

        original = analysis_pack.contains_secret_like_content
        analysis_pack.contains_secret_like_content = lambda value: True
        try:
            with self.assertRaises(analysis_pack.AnalysisPackError):
                analysis_pack.build_analysis_pack(
                    workspace_id="fixture",
                    task_id="task-1",
                    changed_paths=["src/a.py"],
                    diffs={"src/a.py": "+ordinary content\n"},
                )
        finally:
            analysis_pack.contains_secret_like_content = original

    def test_truncates_diff_content_to_max_bytes_without_partial_utf8(self) -> None:
        from chatgpt_dev_mcp.analysis_pack import build_analysis_pack

        result = build_analysis_pack(
            workspace_id="fixture",
            task_id="task-1",
            changed_paths=["src/a.py"],
            diffs={"src/a.py": "+" + ("日本語" * 2000)},
            max_bytes=1024,
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["used_bytes"], 1024)
        self.assertIsInstance(result["diffs"]["src/a.py"], str)

    def test_include_flags_omit_diff_and_failure_content(self) -> None:
        from chatgpt_dev_mcp.analysis_pack import build_analysis_pack

        result = build_analysis_pack(
            workspace_id="fixture",
            task_id="task-1",
            changed_paths=["src/a.py"],
            diffs={"src/a.py": "+safe\n"},
            failures=[{"message": "safe failure"}],
            include_diff=False,
            include_failures=False,
        )
        self.assertEqual(result["diffs"], {})
        self.assertEqual(result["failures"], [])


if __name__ == "__main__":
    unittest.main()
