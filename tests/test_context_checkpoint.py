from __future__ import annotations

import unittest

from chatgpt_dev_mcp.context_checkpoint import ContextCheckpoint, ContextStateVector, compare_checkpoints


def _state(*, head: str = "a", active: tuple[str, ...] = ("task-1",), blockers: tuple[str, ...] = (), decisions: str = "d1") -> ContextStateVector:
    return ContextStateVector(
        workspace_id="demo",
        head=head * 40,
        changed_paths=("src/app.py",),
        active_task_ids=active,
        blocker_ids=blockers,
        decision_revision=decisions,
        verification_receipt_ids=("verify:1",),
        security_audit_receipt_ids=("audit:1",),
    )


class ContextCheckpointTests(unittest.TestCase):
    def test_checkpoint_round_trips_through_plain_mapping(self) -> None:
        checkpoint = ContextCheckpoint(
            _state(blockers=("awaiting-review",)),
            task_id="task-1",
            outcome="verified",
            next_action="commit the focused change",
        )

        restored = ContextCheckpoint.from_dict(checkpoint.as_dict())

        self.assertEqual(restored, checkpoint)
        self.assertEqual(restored.checkpoint_id, checkpoint.checkpoint_id)

    def test_unchanged_checkpoint_returns_empty_delta(self) -> None:
        checkpoint = ContextCheckpoint(_state(), task_id="task-1", outcome="running", next_action="continue")

        delta = compare_checkpoints(checkpoint, checkpoint)

        self.assertFalse(delta.changed)
        self.assertEqual(delta.completed_task_ids, ())

    def test_head_and_task_changes_are_reported(self) -> None:
        previous = ContextCheckpoint(_state(), task_id="task-1", outcome="running", next_action="continue")
        current = ContextCheckpoint(_state(head="b", active=(), blockers=("blocked",), decisions="d2"), task_id="task-1", outcome="done", next_action="next")

        delta = compare_checkpoints(previous, current)

        self.assertTrue(delta.changed)
        self.assertTrue(delta.head_changed)
        self.assertEqual(delta.completed_task_ids, ("task-1",))
        self.assertEqual(delta.new_blocker_ids, ("blocked",))
        self.assertTrue(delta.decision_revision_changed)

    def test_cross_workspace_comparison_is_rejected(self) -> None:
        previous = ContextCheckpoint(_state(), task_id="task-1", outcome="running", next_action="continue")
        other_state = ContextStateVector(workspace_id="other", head="a" * 40)
        current = ContextCheckpoint(other_state, task_id="task-1", outcome="done", next_action="next")

        with self.assertRaises(ValueError):
            compare_checkpoints(previous, current)


if __name__ == "__main__":
    unittest.main()
