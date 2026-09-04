from __future__ import annotations

import unittest


class AutoCheckpointPolicyTests(unittest.TestCase):
    def test_success_events_are_eligible(self) -> None:
        from chatgpt_dev_mcp.context_checkpoint_hooks import AutoCheckpointEvent, should_emit_checkpoint

        for kind in ("review_ready", "verified_commit", "integrated", "task_succeeded"):
            with self.subTest(kind=kind):
                event = AutoCheckpointEvent(kind, "verified local progress", "continue to next task")
                self.assertTrue(should_emit_checkpoint(event))

    def test_failure_like_events_are_not_eligible(self) -> None:
        from chatgpt_dev_mcp.context_checkpoint_hooks import AutoCheckpointEvent, should_emit_checkpoint

        for kind in ("failed", "blocked", "stale", "ambiguous", "outcome_unknown"):
            with self.subTest(kind=kind):
                event = AutoCheckpointEvent(kind, "bounded status", "inspect")
                self.assertFalse(should_emit_checkpoint(event))

    def test_text_is_normalized_and_bounded(self) -> None:
        from chatgpt_dev_mcp.context_checkpoint_hooks import AutoCheckpointEvent, normalized_checkpoint_text

        event = AutoCheckpointEvent("review_ready", "  verified   locally  ", "  commit   then continue ")
        outcome, next_action = normalized_checkpoint_text(event)
        self.assertEqual(outcome, "verified locally")
        self.assertEqual(next_action, "commit then continue")

        with self.assertRaises(ValueError):
            AutoCheckpointEvent("review_ready", "x" * 241, "continue")
        with self.assertRaises(ValueError):
            AutoCheckpointEvent("review_ready", "ok", "x" * 1001)

    def test_secret_like_text_is_rejected(self) -> None:
        from chatgpt_dev_mcp.context_checkpoint_hooks import AutoCheckpointEvent

        values = (
            "Author" + "ization: " + "Bear" + "er example-value",
            "OPENAI" + "_API" + "_KEY=" + "example-value",
            "pass" + "word=" + "example-value",
            "to" + "ken=" + "example-value",
            "cred" + "ential=" + "example-value",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    AutoCheckpointEvent("review_ready", value, "continue")


if __name__ == "__main__":
    unittest.main()
