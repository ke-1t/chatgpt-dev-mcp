from __future__ import annotations

import unittest

from chatgpt_dev_mcp.repo_map import build_repo_map
from chatgpt_dev_mcp.semantic_index import SemanticEdge, SemanticIndexSnapshot, SymbolRecord


class RepoMapTests(unittest.TestCase):
    def _snapshot(self) -> SemanticIndexSnapshot:
        symbols = (
            SymbolRecord("src/verify.py:select", "src/verify.py", "function", "select_verification", 10, 20, "a" * 64),
            SymbolRecord("src/other.py:work", "src/other.py", "function", "unrelated_work", 5, 9, "b" * 64),
        )
        edges = (
            SemanticEdge("reference", "src/caller.py:run", "src/verify.py:select", "src/caller.py", 7),
            SemanticEdge("test", "tests/test_verify.py:test_select", "src/verify.py:select", "tests/test_verify.py", 12),
        )
        return SemanticIndexSnapshot("demo", symbols, edges)

    def test_query_and_changed_path_rank_relevant_symbol_first(self) -> None:
        repo_map = build_repo_map(self._snapshot(), query="verification select", changed_paths=("src/verify.py",), max_items=10, max_bytes=4096)

        self.assertEqual(repo_map.entries[0].symbol_id, "src/verify.py:select")
        self.assertIn("tests/test_verify.py", repo_map.entries[0].tests)

    def test_output_is_bounded_and_deterministic(self) -> None:
        first = build_repo_map(self._snapshot(), query="verify", max_items=1, max_bytes=4096)
        second = build_repo_map(self._snapshot(), query="verify", max_items=1, max_bytes=4096)

        self.assertEqual(first.entries, second.entries)
        self.assertEqual(len(first.entries), 1)
        self.assertLessEqual(first.used_bytes, first.max_bytes)

    def test_explicit_target_path_outranks_unrelated_graph_hub(self) -> None:
        symbols = (
            SymbolRecord("src/context_gateway.py:bootstrap", "src/context_gateway.py", "function", "context_bootstrap", 10, 20, "a" * 64),
            SymbolRecord("src/persistence.py:load", "src/persistence.py", "function", "load_everything", 5, 9, "b" * 64),
        )
        edges = tuple(
            SemanticEdge("reference", f"src/caller_{index}.py:run", "src/persistence.py:load", f"src/caller_{index}.py", index + 1)
            for index in range(40)
        )
        snapshot = SemanticIndexSnapshot("demo", symbols, edges)

        repo_map = build_repo_map(
            snapshot,
            query="Context Gateway bootstrap focus implementation",
            target_paths=("src/context_gateway.py",),
            max_items=2,
            max_bytes=4096,
        )

        self.assertEqual(repo_map.entries[0].path, "src/context_gateway.py")
        self.assertEqual(repo_map.entries[0].symbol_id, "src/context_gateway.py:bootstrap")


if __name__ == "__main__":
    unittest.main()
