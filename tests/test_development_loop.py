from __future__ import annotations

import time
import unittest


class DevelopmentLoopTests(unittest.TestCase):
    def _state(self):
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState, LoopBudgets
        now = time.time()
        return DevelopmentLoopState.create(loop_id="loop-1", owner_id="owner", task_id="task-1", session_id="session-1", worktree_id="tree-1", budgets=LoopBudgets(max_iterations=20, max_repeated_failure=2, max_no_progress=2), started_at=now), now

    def test_happy_path_reaches_ready(self) -> None:
        from chatgpt_dev_mcp.development_loop import LoopEvent, advance
        state, now = self._state()
        for index, kind in enumerate(("implementation_complete", "verification_passed", "qa_passed", "review_passed", "verification_passed"), start=1):
            state = advance(state, LoopEvent(f"event-{index}", kind, now + index, progress_token=f"p-{index}"))
        self.assertEqual(state.phase, "READY")

    def test_repeated_failure_stops_fail_closed_and_duplicate_event_is_idempotent(self) -> None:
        from chatgpt_dev_mcp.development_loop import LoopEvent, advance
        state, now = self._state(); state = advance(state, LoopEvent("implemented", "implementation_complete", now + 1))
        first = LoopEvent("failed-1", "verification_failed", now + 2, failure_fingerprint="same")
        state = advance(state, first); self.assertIs(advance(state, first), state)
        state = advance(state, LoopEvent("remediated", "remediation_complete", now + 3)); state = advance(state, LoopEvent("failed-2", "verification_failed", now + 4, failure_fingerprint="same"))
        self.assertEqual(state.phase, "FAILED"); self.assertEqual(state.stop_reason, "REPEATED_FAILURE_LIMIT")

    def test_diff_budget_stops_before_unsafe_progress(self) -> None:
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState, LoopBudgets, LoopEvent, advance
        now = time.time(); state = DevelopmentLoopState.create(loop_id="loop-budget", owner_id="owner", task_id="task", session_id="session", worktree_id="tree", budgets=LoopBudgets(max_diff_bytes=10), started_at=now)
        state = advance(state, LoopEvent("oversize", "implementation_complete", now + 1, diff_bytes=11))
        self.assertEqual(state.phase, "BLOCKED"); self.assertEqual(state.stop_reason, "DIFF_BYTE_BUDGET")


if __name__ == "__main__": unittest.main()
