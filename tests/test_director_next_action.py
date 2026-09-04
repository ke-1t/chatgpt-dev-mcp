from __future__ import annotations

import unittest


class DirectorNextActionTests(unittest.TestCase):
    def test_phase_maps_to_pure_next_action_and_identity_mismatch_blocks(self) -> None:
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState
        from chatgpt_dev_mcp.director_dispatch import DirectorNextAction
        state = DevelopmentLoopState.create(loop_id="loop", owner_id="owner", task_id="task", session_id="session", worktree_id="tree", started_at=100.0)
        first = DirectorNextAction.resolve(state, owner_id="owner", task_id="task", session_id="session", worktree_id="tree")
        second = DirectorNextAction.resolve(state, owner_id="owner", task_id="task", session_id="session", worktree_id="tree")
        self.assertEqual(first.action, "implement"); self.assertEqual(first.receipt_id, second.receipt_id); self.assertFalse(first.approval_required)
        blocked = DirectorNextAction.resolve(state, owner_id="other", task_id="task", session_id="session", worktree_id="tree")
        self.assertEqual(blocked.status, "blocked"); self.assertEqual(blocked.reason, "identity_mismatch")


if __name__ == "__main__": unittest.main()
