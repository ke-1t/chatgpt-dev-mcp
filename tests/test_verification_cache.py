from __future__ import annotations

from dataclasses import replace
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class VerificationCacheTests(unittest.TestCase):
    @staticmethod
    def _key():
        from chatgpt_dev_mcp.verification_cache import VerificationCacheKey
        return VerificationCacheKey(worktree_id="session:test", head="a" * 40, relevant_diff_hash="b" * 64, command_fingerprint="c" * 64, env_fingerprint="d" * 64, dependency_fingerprint="e" * 64)

    def test_identical_fingerprint_hits_and_each_identity_change_misses(self) -> None:
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        key = self._key(); cache = VerificationCache(clock=lambda: 100.0)
        cache.put(key, relevant_paths=("src/service.py",), status="passed", result_digest="f" * 64, output_summary="1 passed")
        self.assertTrue(cache.get(key).hit)
        for variant in (replace(key, worktree_id="session:other"), replace(key, head="1" * 40), replace(key, relevant_diff_hash="2" * 64), replace(key, command_fingerprint="3" * 64), replace(key, env_fingerprint="4" * 64), replace(key, dependency_fingerprint="5" * 64)):
            self.assertFalse(cache.get(variant).hit)

    def test_disjoint_parallel_write_does_not_invalidate_unrelated_entry(self) -> None:
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        key = self._key(); cache = VerificationCache(clock=lambda: 100.0)
        cache.put(key, relevant_paths=("src/service.py", "tests/test_service.py"), status="passed", result_digest="f" * 64, output_summary="1 passed")
        self.assertEqual(cache.invalidate(("docs/readme.md",)), 0); self.assertTrue(cache.get(key).hit)
        self.assertEqual(cache.invalidate(("src",)), 1); self.assertFalse(cache.get(key).hit)

    def test_persistent_failure_round_trip_is_never_promoted_to_pass(self) -> None:
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteDirectorStore(Path(tmp) / "director.sqlite3"); key = self._key()
            VerificationCache(store=store, clock=lambda: 100.0, ttl_seconds=60, max_entries=10).put(key, relevant_paths=("src/service.py",), status="failed", result_digest="0" * 64, output_summary="assertion failed")
            hit = VerificationCache(store=store, clock=lambda: 101.0, ttl_seconds=60, max_entries=10).get(key)
            self.assertTrue(hit.hit); self.assertEqual(hit.entry.status, "failed"); self.assertNotEqual(hit.entry.status, "passed")

    def test_input_fingerprint_changes_when_untracked_file_content_changes(self) -> None:
        from chatgpt_dev_mcp.verification_cache import verification_input_fingerprint

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "tests" / "test_new.py"
            path.parent.mkdir(parents=True)
            path.write_text("value = 1\n", encoding="utf-8")
            first = verification_input_fingerprint(root, changed_paths=("tests/test_new.py",), diff_text="", diff_known=True)
            path.write_text("value = 2\n", encoding="utf-8")
            second = verification_input_fingerprint(root, changed_paths=("tests/test_new.py",), diff_text="", diff_known=True)
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
