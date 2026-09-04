from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _profile():
    from chatgpt_dev_mcp.director_profile import ProjectProfile
    return ProjectProfile.from_mapping({"workspace_id": "workspace", "profile": "DEVELOPMENT", "language": "Python", "framework": "stdlib", "canonical_paths": ["src", "tests"], "commands": {"test": "python3 -m unittest"}, "verification_tasks": ["test"]})


def _snapshot():
    from chatgpt_dev_mcp.semantic_index import SemanticIndexSnapshot
    return SemanticIndexSnapshot(identity="workspace:tree:head", symbols=(), edges=())


class DocumentationOnlyVerificationTests(unittest.TestCase):
    def test_full_verification_has_dedicated_bounded_timeout(self) -> None:
        from chatgpt_dev_mcp.server import (
            FULL_VERIFICATION_COMMAND_TIMEOUT_MS,
            FULL_VERIFICATION_SHARD_POLL_BUDGET_SECONDS,
            VERIFICATION_SHARD_POLL_BUDGET_SECONDS,
        )

        self.assertEqual(FULL_VERIFICATION_COMMAND_TIMEOUT_MS, 600_000)
        self.assertGreater(FULL_VERIFICATION_SHARD_POLL_BUDGET_SECONDS, VERIFICATION_SHARD_POLL_BUDGET_SECONDS)
        self.assertLess(FULL_VERIFICATION_SHARD_POLL_BUDGET_SECONDS, 120)

    def test_docs_only_plan_is_eligible_without_test_task(self) -> None:
        from chatgpt_dev_mcp.director_verification import make_verification_plan

        plan = make_verification_plan(_profile(), ("docs/guide.md",))

        self.assertTrue(plan.eligible)
        self.assertEqual(plan.tasks, ())
        self.assertEqual(plan.reason, "NO_EXECUTION_REQUIRED")

    def test_docs_only_empty_result_receipt_is_passed_and_fresh(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, make_verification_plan

        pipeline = VerificationPipeline(_profile())
        plan = make_verification_plan(_profile(), ("docs/guide.md",))
        receipt = pipeline.record(
            plan,
            (),
            base_revision="a" * 40,
            diff_hash="b" * 64,
            working_tree_id="session:test",
        )

        self.assertEqual(receipt.status, "passed")
        self.assertEqual(receipt.results, ())
        self.assertEqual(receipt.base_revision, "a" * 40)
        self.assertEqual(receipt.diff_hash, "b" * 64)

    def test_ordinary_empty_result_receipt_is_not_run(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, make_verification_plan

        pipeline = VerificationPipeline(_profile())
        plan = make_verification_plan(_profile(), ("src/app.py",))
        receipt = pipeline.record(
            plan,
            (),
            base_revision="a" * 40,
            diff_hash="b" * 64,
            working_tree_id="session:test",
        )

        self.assertEqual(receipt.status, "not_run")


class VerificationReceiptIdentityTests(unittest.TestCase):
    def test_same_evidence_on_different_worktrees_has_distinct_receipt_ids(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, VerificationResult, make_verification_plan

        pipeline = VerificationPipeline(_profile())
        plan = make_verification_plan(_profile(), ("src/app.py",))
        results = (VerificationResult("test", "passed", 0, 1, "ok", False),)
        common = {
            "base_revision": "a" * 40,
            "diff_hash": "b" * 64,
            "recorded_at": "2026-08-17T00:00:00Z",
        }

        session_receipt = pipeline.record(plan, results, working_tree_id="session:test", **common)
        canonical_receipt = pipeline.record(plan, results, working_tree_id="worktree:canonical", **common)

        self.assertNotEqual(session_receipt.receipt_id, canonical_receipt.receipt_id)
        self.assertEqual(session_receipt.working_tree_id, "session:test")
        self.assertEqual(canonical_receipt.working_tree_id, "worktree:canonical")


class FullVerificationContinuationTests(unittest.TestCase):
    def test_large_full_suite_advances_in_bounded_cached_continuations(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        calls: list[tuple[str, tuple[str, ...]]] = []
        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": "ok", "duration_ms": 1}

        shards = tuple((f"tests/test_{index}.py",) for index in range(5))
        engine = VerificationEngine(_profile(), cache=VerificationCache(), runner=runner, full_test_shards=shards)
        kwargs = {"mode": "full", "task_id": "task-1", "changed_paths": ("src/app.py",), "semantic_snapshot": _snapshot(), "worktree_id": "session:test", "head": "a" * 40, "relevant_diff_hash": "b" * 64, "env_fingerprint": "c" * 64, "dependency_fingerprint": "d" * 64}

        first = engine.run(**kwargs)
        self.assertEqual(first.status, "incomplete")
        self.assertTrue(first.continuation_required)
        self.assertEqual(first.pending_work_units, 3)
        self.assertEqual(len(calls), 2)

        second = engine.run(**kwargs)
        self.assertEqual(second.status, "incomplete")
        self.assertTrue(second.continuation_required)
        self.assertEqual(second.pending_work_units, 1)
        self.assertEqual(len(calls), 4)

        final = engine.run(**kwargs)
        self.assertEqual(final.status, "passed")
        self.assertFalse(final.continuation_required)
        self.assertEqual(final.pending_work_units, 0)
        self.assertEqual(len(calls), 5)
        self.assertEqual(tuple(item.selected_tests for item in final.results), shards)


if __name__ == "__main__":
    unittest.main()
