from __future__ import annotations

import unittest


class LoopDeliveryIntegrationTests(unittest.TestCase):
    def test_delivery_failure_reopens_ready_loop_idempotently(self) -> None:
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState, LoopEvent, advance, apply_delivery_failure
        state = DevelopmentLoopState.create(loop_id="loop", owner_id="owner", task_id="task", session_id="session", worktree_id="tree", started_at=100.0)
        for index, kind in enumerate(("implementation_complete", "verification_passed", "qa_passed", "review_passed", "verification_passed"), start=1):
            state = advance(state, LoopEvent(f"e-{index}", kind, 100.0 + index, progress_token=f"p-{index}"))
        self.assertEqual(state.phase, "READY")
        reopened = apply_delivery_failure(state, "github-checks:failed", at=110.0)
        self.assertEqual(reopened.phase, "REMEDIATE")
        self.assertIs(apply_delivery_failure(reopened, "github-checks:failed", at=110.0), reopened)

    def test_ready_loop_can_select_verified_local_commit_without_weakening_push(self) -> None:
        from chatgpt_dev_mcp.delivery_orchestrator import DeliveryOrchestrator

        orchestrator = DeliveryOrchestrator()
        commit = orchestrator.next_step(
            {"status": "ready", "receipt_id": "loop:ready"},
            {
                "committed": False,
                "verified_auto_commit_enabled": True,
                "verified_auto_commit_eligible": True,
                "verified_evidence_ref": "audit:verified",
            },
            {},
        )
        self.assertEqual(commit.action, "git_verified_commit_preflight")
        self.assertFalse(commit.approval_required)
        push = orchestrator.next_step(
            {"status": "ready"},
            {"committed": True, "pushed": False, "commit_receipt": "git:verified"},
            {},
        )
        self.assertEqual(push.action, "git_push_preflight")
        self.assertTrue(push.approval_required)


if __name__ == "__main__": unittest.main()
