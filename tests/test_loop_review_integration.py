from __future__ import annotations

import unittest


class LoopReviewIntegrationTests(unittest.TestCase):
    def test_blocking_review_moves_loop_to_remediate_without_writer_authority(self) -> None:
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState, LoopEvent, advance
        from chatgpt_dev_mcp.director import TaskLedger
        from chatgpt_dev_mcp.director_review import ReviewController
        ledger = TaskLedger(max_records=64)
        task = ledger.enqueue("req", "repo", "Implement", allowed_paths=["src/app.py"], base_revision="a" * 40)
        state = DevelopmentLoopState.create(loop_id="loop", owner_id="owner", task_id=task.task_id, session_id="session", worktree_id="tree", started_at=100.0)
        state = advance(state, LoopEvent("implemented", "implementation_complete", 101.0))
        state = advance(state, LoopEvent("fast", "verification_passed", 102.0))
        state = advance(state, LoopEvent("qa", "qa_passed", 103.0))
        review = ReviewController()
        receipt = review.record(task, reviewer_owner="reviewer", base_revision="a" * 40, diff_hash="b" * 64, reviewed_paths=["src/app.py"], findings=[{"category": "correctness", "severity": "high", "message": "blocking", "blocking": True, "path": "src/app.py"}])
        result = review.apply_to_loop(ledger, receipt.receipt_id, state, at=104.0)
        self.assertEqual(result["state"].phase, "REMEDIATE")
        self.assertIsNotNone(result["remediation_task"])
        self.assertFalse(result["writer_authority_granted"])


if __name__ == "__main__": unittest.main()
