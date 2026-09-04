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
    return ProjectProfile.from_mapping({"workspace_id": "workspace", "profile": "DEVELOPMENT", "language": "Python", "framework": "stdlib", "canonical_paths": ["src", "tests"], "commands": {"test": "python3 -m unittest", "lint": "python3 -m compileall src", "build": "python3 -m compileall tests"}, "verification_tasks": ["test", "lint", "build"]})


def _snapshot():
    from chatgpt_dev_mcp.semantic_index import SemanticEdge, SemanticIndexSnapshot, SymbolRecord
    return SemanticIndexSnapshot(identity="workspace:tree:head", symbols=(SymbolRecord(symbol_id="src.app:run", path="src/app.py", kind="function", name="run", start_line=1, end_line=2, content_hash="1" * 64),), edges=(SemanticEdge(relation="test", source="tests.test_app:test_run", target="src.app:run", path="tests/test_app.py", line=5),))


class VerificationEngineTests(unittest.TestCase):
    def test_server_shard_poll_budget_stays_below_transport_timeout(self) -> None:
        from chatgpt_dev_mcp.server import VERIFICATION_SHARD_POLL_BUDGET_SECONDS

        self.assertGreater(VERIFICATION_SHARD_POLL_BUDGET_SECONDS, 0)
        self.assertLess(VERIFICATION_SHARD_POLL_BUDGET_SECONDS, 120)

    def _run_kwargs(self) -> dict[str, object]:
        return {"task_id": "task-1", "semantic_snapshot": _snapshot(), "worktree_id": "session:test", "head": "a" * 40, "relevant_diff_hash": "b" * 64, "env_fingerprint": "c" * 64, "dependency_fingerprint": "d" * 64}

    def test_fast_mode_runs_selected_tests_and_reports_cache_miss(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        calls = []
        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests)); return {"exit_code": 0, "output": "ok", "duration_ms": 12}
        receipt = VerificationEngine(_profile(), cache=VerificationCache(), runner=runner).run(mode="fast", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual(calls, [("test", ("tests/test_app.py",))]); self.assertEqual(receipt.status, "passed"); self.assertFalse(receipt.selection.fallback_full); self.assertEqual(receipt.results[0].cache_status, "miss")

    def test_fast_docs_only_verification_runs_zero_commands(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        calls: list[tuple[str, tuple[str, ...]]] = []

        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": "unexpected", "duration_ms": 1}

        receipt = VerificationEngine(_profile(), cache=VerificationCache(), runner=runner).run(
            mode="fast",
            changed_paths=("docs/guide.md",),
            **self._run_kwargs(),
        )

        self.assertEqual(calls, [])
        self.assertEqual(receipt.status, "passed")
        self.assertEqual(receipt.results, ())
        self.assertIn("documentation_only", receipt.selection.global_reasons)

    def test_fast_unknown_impact_does_not_silently_run_full_suite(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        calls: list[tuple[str, tuple[str, ...]]] = []

        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": "unexpected full run", "duration_ms": 1}

        receipt = VerificationEngine(_profile(), cache=VerificationCache(), runner=runner).run(
            mode="fast",
            changed_paths=("src/unknown.py",),
            **self._run_kwargs(),
        )

        self.assertTrue(receipt.selection.fallback_full)
        self.assertEqual(calls, [])
        self.assertEqual(receipt.status, "incomplete")

    def test_cached_failure_is_reused_as_failure_not_promoted_to_pass(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        cache = VerificationCache(); calls = 0
        def failing_runner(task: str, selected_tests: tuple[str, ...]):
            nonlocal calls; calls += 1; return {"exit_code": 7, "output": "failed", "duration_ms": 3}
        first = VerificationEngine(_profile(), cache=cache, runner=failing_runner).run(mode="fast", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual(first.status, "failed"); self.assertEqual(calls, 1)
        def must_not_run(task: str, selected_tests: tuple[str, ...]):
            raise AssertionError("cache hit must not execute runner")
        second = VerificationEngine(_profile(), cache=cache, runner=must_not_run).run(mode="fast", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual(second.status, "failed"); self.assertEqual(second.results[0].cache_status, "hit"); self.assertEqual(second.results[0].status, "failed")

    def test_full_mode_ignores_selective_reduction_and_runs_authoritative_suite(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        calls = []
        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests)); return {"exit_code": 0, "output": task, "duration_ms": 1}
        receipt = VerificationEngine(_profile(), cache=VerificationCache(), runner=runner).run(mode="full", changed_paths=("tests/test_app.py",), **self._run_kwargs())
        self.assertEqual(calls, [("test", ()), ("lint", ()), ("build", ())]); self.assertEqual(receipt.mode, "full"); self.assertEqual(receipt.status, "passed"); self.assertEqual(tuple(result.task for result in receipt.results), ("test", "lint", "build"))

    def test_full_mode_uses_bounded_test_shards_when_supplied(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache
        calls = []
        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests)); return {"exit_code": 0, "output": task, "duration_ms": 1}
        engine = VerificationEngine(
            _profile(),
            cache=VerificationCache(),
            runner=runner,
            full_test_shards=(("tests/test_a.py", "tests/test_b.py"), ("tests/test_c.py",)),
        )
        receipt = engine.run(mode="full", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual(
            calls,
            [
                ("test", ("tests/test_a.py", "tests/test_b.py")),
                ("test", ("tests/test_c.py",)),
                ("lint", ()),
                ("build", ()),
            ],
        )
        self.assertEqual(receipt.status, "passed")

    def test_full_mode_reuses_exact_identity_cache_for_small_suite_and_aux_tasks(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        calls: list[tuple[str, tuple[str, ...]]] = []

        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": task, "duration_ms": 1}

        cache = VerificationCache()
        shards = (("tests/test_a.py",), ("tests/test_b.py",))
        engine = VerificationEngine(_profile(), cache=cache, runner=runner, full_test_shards=shards)
        kwargs = {"mode": "full", "changed_paths": ("src/app.py",), **self._run_kwargs()}

        first = engine.run(**kwargs)
        first_call_count = len(calls)
        second = engine.run(**kwargs)

        self.assertEqual(first.status, "passed")
        self.assertEqual(second.status, "passed")
        self.assertEqual(len(calls), first_call_count)
        self.assertTrue(second.results)
        self.assertTrue(all(result.cache_status == "hit" for result in second.results))

    def test_full_mode_advances_supplied_test_shards_across_continuations(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        calls: list[tuple[str, tuple[str, ...]]] = []

        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": task, "duration_ms": 1}

        shards = tuple((f"tests/test_{index}.py",) for index in range(6))
        engine = VerificationEngine(
            _profile(),
            cache=VerificationCache(),
            runner=runner,
            full_test_shards=shards,
        )

        first = engine.run(mode="full", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual({selected for task, selected in calls if task == "test"}, set(shards[:2]))
        self.assertEqual(first.pending_work_units, 4)
        self.assertTrue(first.continuation_required)
        self.assertEqual(first.status, "incomplete")

        second = engine.run(mode="full", changed_paths=("src/app.py",), **self._run_kwargs())
        self.assertEqual({selected for task, selected in calls if task == "test"}, set(shards[:4]))
        self.assertEqual(second.pending_work_units, 2)
        self.assertTrue(second.continuation_required)
        self.assertEqual(second.status, "incomplete")

        receipt = engine.run(mode="full", changed_paths=("src/app.py",), **self._run_kwargs())

        self.assertEqual({selected for task, selected in calls if task == "test"}, set(shards))
        self.assertIn(("lint", ()), calls)
        self.assertIn(("build", ()), calls)
        self.assertEqual(receipt.pending_work_units, 0)
        self.assertFalse(receipt.continuation_required)
        self.assertEqual(receipt.status, "passed")

    def test_full_continuation_refreshes_cached_shards_until_run_completes(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationEngine
        from chatgpt_dev_mcp.verification_cache import VerificationCache

        now = [0.0]
        calls: list[tuple[str, tuple[str, ...]]] = []

        def runner(task: str, selected_tests: tuple[str, ...]):
            calls.append((task, selected_tests))
            return {"exit_code": 0, "output": task, "duration_ms": 1}

        shards = tuple((f"tests/test_{index}.py",) for index in range(5))
        cache = VerificationCache(clock=lambda: now[0], ttl_seconds=5)
        engine = VerificationEngine(_profile(), cache=cache, runner=runner, full_test_shards=shards)
        kwargs = {"mode": "full", "changed_paths": ("src/app.py",), **self._run_kwargs()}

        first = engine.run(**kwargs)
        self.assertEqual(first.pending_work_units, 3)

        now[0] = 4.0
        second = engine.run(**kwargs)
        self.assertEqual(second.pending_work_units, 1)

        now[0] = 8.0
        final = engine.run(**kwargs)

        test_calls = [selected for task, selected in calls if task == "test"]
        self.assertEqual(test_calls, list(shards))
        self.assertEqual(final.pending_work_units, 0)
        self.assertFalse(final.continuation_required)
        self.assertEqual(final.status, "passed")


if __name__ == "__main__":
    unittest.main()
