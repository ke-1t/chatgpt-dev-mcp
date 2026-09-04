from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path: sys.path.insert(0, str(SRC))


class VerificationSelectorTests(unittest.TestCase):
    def _snapshot(self):
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name); (root / "pkg").mkdir(); (root / "tests").mkdir()
        (root / "pkg" / "service.py").write_text("def run(value):\n    return value + 1\n", encoding="utf-8")
        (root / "tests" / "test_service.py").write_text("from pkg.service import run\n\ndef test_run():\n    assert run(1) == 2\n", encoding="utf-8")
        return temporary, SemanticIndex(root, identity="session:test").build()

    @staticmethod
    def _profile(): return SimpleNamespace(workspace_id="workspace", profile="DEVELOPMENT", commands={"test": "registered"}, verification_tasks=("test",))

    def test_direct_test_change_selects_the_test_without_full_fallback(self) -> None:
        from chatgpt_dev_mcp.selective_verification import VerificationSelector
        temporary, snapshot = self._snapshot(); self.addCleanup(temporary.cleanup)
        selection = VerificationSelector().select(("tests/test_service.py",), snapshot, self._profile())
        self.assertEqual(selection.tests, ("tests/test_service.py",)); self.assertFalse(selection.fallback_full); self.assertIn("direct_path", selection.reasons["tests/test_service.py"]); self.assertIn("test_owner", selection.reasons["tests/test_service.py"])

    def test_source_change_selects_semantically_dependent_test(self) -> None:
        from chatgpt_dev_mcp.selective_verification import VerificationSelector
        temporary, snapshot = self._snapshot(); self.addCleanup(temporary.cleanup)
        selection = VerificationSelector().select(("pkg/service.py",), snapshot, self._profile())
        self.assertEqual(selection.tests, ("tests/test_service.py",)); self.assertFalse(selection.fallback_full); self.assertIn("symbol_dependency", selection.reasons["tests/test_service.py"])

    def test_src_layout_source_change_selects_runtime_import_test(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        from chatgpt_dev_mcp.selective_verification import VerificationSelector
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); root = Path(temporary.name)
        (root / "src" / "pkg").mkdir(parents=True); (root / "tests").mkdir()
        (root / "src" / "pkg" / "service.py").write_text("def run(value):\n    return value + 1\n", encoding="utf-8")
        (root / "tests" / "test_service.py").write_text("from pkg.service import run\n\ndef test_run():\n    assert run(1) == 2\n", encoding="utf-8")
        snapshot = SemanticIndex(root, identity="session:src-layout").build()
        selection = VerificationSelector().select(("src/pkg/service.py",), snapshot, self._profile())
        self.assertEqual(selection.tests, ("tests/test_service.py",))
        self.assertFalse(selection.fallback_full)
        self.assertIn("symbol_dependency", selection.reasons["tests/test_service.py"])

    def test_known_source_change_with_direct_changed_test_does_not_fallback_full_when_dependency_edge_is_unavailable(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndexSnapshot, SymbolRecord
        from chatgpt_dev_mcp.selective_verification import VerificationSelector

        snapshot = SemanticIndexSnapshot(
            identity="session:test",
            symbols=(
                SymbolRecord(
                    symbol_id="pkg/service.py:run",
                    path="pkg/service.py",
                    kind="function",
                    name="run",
                    start_line=1,
                    end_line=2,
                    content_hash="a" * 64,
                ),
            ),
            edges=(),
        )
        selection = VerificationSelector().select(
            ("pkg/service.py", "tests/test_service_integration.py"),
            snapshot,
            self._profile(),
        )
        self.assertEqual(selection.tests, ("tests/test_service_integration.py",))
        self.assertFalse(selection.fallback_full)
        self.assertIn("test_owner", selection.reasons["tests/test_service_integration.py"])
        self.assertNotIn("fallback_full", selection.global_reasons)

    def test_unknown_graph_and_project_rule_fail_closed_to_full(self) -> None:
        from chatgpt_dev_mcp.selective_verification import VerificationSelector
        from chatgpt_dev_mcp.semantic_index import SemanticIndexSnapshot
        empty = SemanticIndexSnapshot(identity="session:test", symbols=(), edges=())
        unknown = VerificationSelector().select(("pkg/unknown.py",), empty, self._profile()); project_rule = VerificationSelector().select(("pyproject.toml",), empty, self._profile())
        self.assertTrue(unknown.fallback_full); self.assertIn("fallback_full", unknown.global_reasons); self.assertTrue(project_rule.fallback_full); self.assertIn("project_rule", project_rule.global_reasons)

    def test_docs_only_change_does_not_fallback_full(self) -> None:
        from chatgpt_dev_mcp.selective_verification import VerificationSelector
        from chatgpt_dev_mcp.semantic_index import SemanticIndexSnapshot

        empty = SemanticIndexSnapshot(identity="session:test", symbols=(), edges=())
        selection = VerificationSelector().select(("docs/guide.md",), empty, self._profile())

        self.assertFalse(selection.fallback_full)
        self.assertEqual(selection.tests, ())
        self.assertIn("documentation_only", selection.global_reasons)


if __name__ == "__main__": unittest.main()
