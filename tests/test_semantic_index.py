from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class SemanticIndexTests(unittest.TestCase):
    def test_src_layout_module_identity_matches_runtime_imports_and_test_edges(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "src" / "pkg").mkdir(parents=True); (root / "tests").mkdir()
            (root / "src" / "pkg" / "service.py").write_text("def run(value):\n    return value + 1\n", encoding="utf-8")
            (root / "tests" / "test_service.py").write_text("from pkg.service import run\n\ndef test_run():\n    assert run(1) == 2\n", encoding="utf-8")
            snapshot = SemanticIndex(root, identity="worktree:src-layout@abc").build()
            symbol = snapshot.symbol("pkg.service:run")
            self.assertEqual(symbol.path, "src/pkg/service.py")
            self.assertIn("tests.test_service", snapshot.tests_for("pkg.service:run"))

    def test_real_src_package_keeps_src_in_module_identity(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "src" / "pkg").mkdir(parents=True)
            (root / "src" / "__init__.py").write_text("", encoding="utf-8")
            (root / "src" / "pkg" / "service.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            snapshot = SemanticIndex(root, identity="worktree:src-package@abc").build()
            self.assertEqual(snapshot.symbol("src.pkg.service:run").path, "src/pkg/service.py")

    def test_python_index_extracts_definition_reference_import_and_test_edges(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "pkg").mkdir(); (root / "tests").mkdir()
            (root / "pkg" / "service.py").write_text("from math import sqrt\n\ndef run(value):\n    return sqrt(value)\n", encoding="utf-8")
            (root / "pkg" / "client.py").write_text("from pkg.service import run\n\ndef execute():\n    return run(9)\n", encoding="utf-8")
            (root / "tests" / "test_service.py").write_text("from pkg.service import run\n\ndef test_run():\n    assert run(4) == 2\n", encoding="utf-8")
            snapshot = SemanticIndex(root, identity="worktree:test@abc").build()
            symbol = snapshot.symbol("pkg.service:run")
            self.assertEqual(symbol.kind, "function")
            self.assertEqual(symbol.path, "pkg/service.py")
            self.assertTrue(any(edge.source == "pkg.client:execute" for edge in snapshot.references_to("pkg.service:run")))
            self.assertIn("pkg.client", snapshot.importers_of("pkg.service"))
            self.assertIn("tests.test_service", snapshot.tests_for("pkg.service:run"))

    def test_refresh_reparses_only_changed_file_and_preserves_unchanged_edges(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "pkg").mkdir()
            (root / "pkg" / "service.py").write_text("def run(value):\n    return value + 1\n", encoding="utf-8")
            (root / "pkg" / "client.py").write_text("from pkg.service import run\n\ndef execute():\n    return run(9)\n", encoding="utf-8")
            class CountingSemanticIndex(SemanticIndex):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs); self.parsed_paths = []
                def _parse(self, path):
                    self.parsed_paths.append(path.relative_to(self.root).as_posix()); return super()._parse(path)
            index = CountingSemanticIndex(root, identity="worktree:test@abc")
            first = index.build(); original_hash = first.symbol("pkg.service:run").content_hash; index.parsed_paths.clear()
            (root / "pkg" / "service.py").write_text("def run(value):\n    return value + 2\n", encoding="utf-8")
            refreshed = index.refresh(("pkg/service.py",))
            self.assertEqual(index.parsed_paths, ["pkg/service.py"])
            self.assertNotEqual(refreshed.symbol("pkg.service:run").content_hash, original_hash)
            self.assertTrue(any(edge.source == "pkg.client:execute" for edge in refreshed.references_to("pkg.service:run")))

    def test_query_prefers_exact_symbol_and_same_file_reference_with_provenance(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex, SemanticQuery
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "pkg").mkdir()
            (root / "pkg" / "service.py").write_text("def run(value):\n    return value + 1\n\ndef local():\n    return run(1)\n", encoding="utf-8")
            (root / "pkg" / "client.py").write_text("from pkg.service import run\n\ndef run_client():\n    return run(2)\n", encoding="utf-8")
            index = SemanticIndex(root, identity="worktree:test@abc"); index.build()
            results = index.query(SemanticQuery(text="run", symbol="pkg.service:run", path="pkg/service.py", relations=("definition", "references"), limit=5))
            self.assertGreaterEqual(len(results), 2)
            self.assertEqual(results[0].relation, "definition"); self.assertEqual(results[0].symbol_id, "pkg.service:run"); self.assertEqual(results[0].path, "pkg/service.py")
            self.assertGreater(results[0].confidence, results[-1].confidence)
            self.assertEqual([item.path for item in results if item.relation == "reference"][0], "pkg/service.py")
            self.assertTrue(all(item.reason and item.source_hash for item in results))

    def test_build_skips_symlinked_and_oversized_python_sources(self) -> None:
        from chatgpt_dev_mcp.semantic_index import MAX_SOURCE_BYTES, SemanticIndex
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp); outside = Path(outside_tmp) / "outside.py"; outside.write_text("def escaped():\n    return 1\n", encoding="utf-8")
            try: (root / "linked.py").symlink_to(outside)
            except OSError: self.skipTest("symlinks are unavailable on this platform")
            (root / "huge.py").write_bytes(b"#" * (MAX_SOURCE_BYTES + 1)); (root / "safe.py").write_text("def safe():\n    return 1\n", encoding="utf-8")
            snapshot = SemanticIndex(root, identity="worktree:test@abc").build(); symbol_ids = {item.symbol_id for item in snapshot.symbols}
            self.assertIn("safe:safe", symbol_ids); self.assertNotIn("linked:escaped", symbol_ids); self.assertFalse(any(item.path == "huge.py" for item in snapshot.symbols))

    def test_persistent_metadata_restores_without_ast_parse_and_rejects_stale_content(self) -> None:
        from chatgpt_dev_mcp.semantic_index import SemanticIndex, SemanticQuery
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "service.py").write_text("def run(value):\n    return value + 1\n\ndef local():\n    return run(1)\n", encoding="utf-8")
            original = SemanticIndex(root, identity="worktree:test@abc"); original.build()
            records = original.metadata_records(workspace_id="workspace", working_tree_id="session:semantic-test", source_revision="a" * 40, updated_at="2026-08-14T00:00:00Z")
            class NoParseSemanticIndex(SemanticIndex):
                def _parse(self, path): raise AssertionError("restoring valid metadata must not parse AST")
            restored = NoParseSemanticIndex(root, identity="worktree:test@abc"); self.assertTrue(restored.restore_metadata(records))
            results = restored.query(SemanticQuery(symbol="service:run", relations=("definition", "references")))
            self.assertEqual(results[0].symbol_id, "service:run"); self.assertTrue(any(item.relation == "reference" for item in results))
            (root / "service.py").write_text("def run(value):\n    return value + 2\n", encoding="utf-8")
            self.assertFalse(SemanticIndex(root, identity="worktree:test@abc").restore_metadata(records))


if __name__ == "__main__": unittest.main()
