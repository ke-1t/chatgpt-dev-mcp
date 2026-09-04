from __future__ import annotations

import unittest

from chatgpt_dev_mcp.context_checkpoint import ContextCheckpoint, ContextStateVector
from chatgpt_dev_mcp.context_engine import BootstrapInputs, ContextEngine, InstructionContext
from chatgpt_dev_mcp.decision_memory import DecisionRecord
from chatgpt_dev_mcp.project_capsule import CapsuleSection
from chatgpt_dev_mcp.repo_map import RepoMap, RepoMapEntry


class ContextEngineTests(unittest.TestCase):
    def _inputs(self, *, checkpoint: ContextCheckpoint | None = None) -> BootstrapInputs:
        decision = DecisionRecord(
            "d1", "demo", "broker.write", "active", "prohibited", "safety", "a" * 40
        )
        repo_map = RepoMap(
            entries=(RepoMapEntry("src/app.py:run", "src/app.py", "function", "run", 1, 70, ("definition",), ("tests/test_app.py",)),),
            used_bytes=128,
            max_bytes=4096,
            truncated=False,
        )
        return BootstrapInputs(
            workspace_id="demo",
            source_revision="a" * 40,
            base_sections=(CapsuleSection("current_state", 90, True, ("clean",)),),
            decisions=(decision,),
            repo_map=repo_map,
            checkpoint=checkpoint,
        )

    def test_bootstrap_prioritizes_safety_current_state_and_active_work(self) -> None:
        result = ContextEngine().bootstrap(self._inputs(), max_bytes=4096)

        self.assertLessEqual(result.used_bytes, 4096)
        self.assertIn("decisions", result.capsule.sections)
        self.assertIn("current_state", result.capsule.sections)
        self.assertFalse(result.decision_conflict)

    def test_previous_checkpoint_returns_delta(self) -> None:
        previous = ContextCheckpoint(ContextStateVector("demo", "a" * 40, active_task_ids=("task-1",)), "task-1", "running", "continue")
        current = ContextCheckpoint(ContextStateVector("demo", "b" * 40, active_task_ids=()), "task-1", "done", "next")

        result = ContextEngine().bootstrap(self._inputs(checkpoint=current), max_bytes=4096, previous_checkpoint=previous)

        self.assertIsNotNone(result.delta)
        self.assertTrue(result.delta.head_changed)
        self.assertEqual(result.delta.completed_task_ids, ("task-1",))

    def test_checkpoint_renders_compact_continuation_in_bootstrap(self) -> None:
        checkpoint = ContextCheckpoint(
            ContextStateVector("demo", "a" * 40, active_task_ids=("task-1",)),
            "task-1",
            "verified",
            "commit the focused change",
        )

        result = ContextEngine().bootstrap(self._inputs(checkpoint=checkpoint), max_bytes=4096)

        self.assertIn("continuation", result.capsule.sections)
        self.assertIn("outcome:verified", result.capsule.sections["continuation"])
        self.assertIn("next:commit the focused change", result.capsule.sections["continuation"])

    def test_bootstrap_renders_repository_instructions_ahead_of_repo_map(self) -> None:
        inputs = self._inputs()
        inputs = BootstrapInputs(
            workspace_id=inputs.workspace_id,
            source_revision=inputs.source_revision,
            base_sections=inputs.base_sections,
            decisions=inputs.decisions,
            repo_map=inputs.repo_map,
            instructions=InstructionContext(
                status="loaded",
                items=("Never push without explicit approval.", "Keep writes isolated."),
                source_hash="b" * 64,
            ),
        )

        result = ContextEngine().bootstrap(inputs, max_bytes=4096)

        self.assertIn("instructions", result.capsule.sections)
        self.assertEqual(
            result.capsule.sections["instructions"],
            ("Never push without explicit approval.", "Keep writes isolated."),
        )
        self.assertIn("repo_map", result.capsule.sections)

    def test_instruction_context_rejects_oversized_or_invalid_payloads(self) -> None:
        with self.assertRaises(ValueError):
            InstructionContext(status="loaded", items=("x" * 9000,), source_hash="b" * 64)
        with self.assertRaises(ValueError):
            InstructionContext(status="loaded", items=("bad\x00line",), source_hash="b" * 64)


if __name__ == "__main__":
    unittest.main()
