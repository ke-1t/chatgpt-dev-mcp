from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.plan_manifest import PlanTaskAttempt, plan_manifest_from_mapping


def _manifest(
    *,
    plan_id: str = "plan-a",
    revision: int = 1,
    status: str = "active",
    task_id: str = "task-a",
):
    return plan_manifest_from_mapping(
        {
            "plan_id": plan_id,
            "revision": revision,
            "workspace_id": "chatgpt-dev-mcp",
            "title": f"Plan {plan_id}",
            "status": status,
            "spec_path": "docs/superpowers/specs/example.md",
            "spec_hash": "a" * 64,
            "plan_path": "docs/superpowers/plans/example.md",
            "plan_hash": "b" * 64,
            "tasks": [
                {
                    "plan_task_id": task_id,
                    "title": f"Implement {task_id}",
                    "paths": ["src/chatgpt_dev_mcp/plan_manifest.py"],
                    "resources": [],
                    "dependencies": [],
                    "acceptance_criteria": ["state is durable"],
                    "delivery_requirements": ["focused tests pass"],
                }
            ],
        }
    )


class PlanLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-plan-ledger-")
        self.db_path = Path(self.tempdir.name) / "director.sqlite3"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _ledger(self):
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore
        from chatgpt_dev_mcp.plan_ledger import PlanLedger

        return PlanLedger(SqliteDirectorStore(self.db_path))

    def test_active_plan_task_state_and_attempt_survive_restart(self) -> None:
        ledger = self._ledger()
        manifest = ledger.activate(_manifest(), expected_revision=None)
        logical_task_id = manifest.tasks[0].logical_task_id

        ledger.set_task_state(
            "plan-a",
            "task-a",
            "review_ready",
            evidence={"verification_receipt": "verify:abc"},
        )
        ledger.append_attempt(
            PlanTaskAttempt(
                attempt_id="attempt:one",
                logical_task_id=logical_task_id,
                task_id="task-ledger-1",
                owner_id="chatgpt-plan-control-task2",
                session_id="session:one",
                working_tree_id="session:one",
                started_at="2026-08-19T14:00:00Z",
                finished_at="2026-08-19T14:01:00Z",
                outcome="review_ready",
            )
        )

        restarted = self._ledger()
        loaded = restarted.get("plan-a")

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.revision, 1)
        self.assertEqual(loaded.tasks[0].state, "review_ready")
        self.assertEqual(restarted.active("chatgpt-dev-mcp"), (loaded,))
        self.assertEqual(restarted.task("plan-a", "task-a"), loaded.tasks[0])
        attempts = restarted.attempts(logical_task_id)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].attempt_id, "attempt:one")

    def test_revision_update_requires_exact_expected_revision_and_never_rolls_back(self) -> None:
        from chatgpt_dev_mcp.plan_ledger import PlanLedgerError

        ledger = self._ledger()
        ledger.activate(_manifest(revision=1), expected_revision=None)

        with self.assertRaisesRegex(PlanLedgerError, "expected revision"):
            ledger.activate(_manifest(revision=2), expected_revision=0)
        with self.assertRaisesRegex(PlanLedgerError, "advance"):
            ledger.activate(_manifest(revision=1), expected_revision=1)

        updated = ledger.activate(_manifest(revision=2), expected_revision=1)
        self.assertEqual(updated.revision, 2)

    def test_supersession_is_atomic_and_survives_restart(self) -> None:
        ledger = self._ledger()
        source = ledger.activate(_manifest(plan_id="plan-old", task_id="old-task"), expected_revision=None)
        replacement = ledger.activate(_manifest(plan_id="plan-new", task_id="new-task"), expected_revision=None)

        ledger.supersede("plan-old", "plan-new", task_map={"old-task": "new-task"})

        restarted = self._ledger()
        loaded_source = restarted.get("plan-old")
        loaded_replacement = restarted.get("plan-new")
        self.assertIsNotNone(loaded_source)
        self.assertIsNotNone(loaded_replacement)
        assert loaded_source is not None
        self.assertEqual(loaded_source.status, "superseded")
        self.assertEqual(loaded_source.tasks[0].state, "superseded")
        self.assertEqual(loaded_replacement, replacement)
        self.assertNotEqual(source.plan_id, replacement.plan_id)

    def test_supersession_rejects_unknown_plan_or_task_targets(self) -> None:
        from chatgpt_dev_mcp.plan_ledger import PlanLedgerError

        ledger = self._ledger()
        ledger.activate(_manifest(plan_id="plan-old", task_id="old-task"), expected_revision=None)
        ledger.activate(_manifest(plan_id="plan-new", task_id="new-task"), expected_revision=None)

        with self.assertRaisesRegex(PlanLedgerError, "replacement"):
            ledger.supersede("plan-old", "missing-plan", task_map={"old-task": "new-task"})
        with self.assertRaisesRegex(PlanLedgerError, "source task"):
            ledger.supersede("plan-old", "plan-new", task_map={"missing-task": "new-task"})
        with self.assertRaisesRegex(PlanLedgerError, "replacement task"):
            ledger.supersede("plan-old", "plan-new", task_map={"old-task": "missing-task"})

    def test_attempt_identity_mismatch_fails_closed(self) -> None:
        from chatgpt_dev_mcp.plan_ledger import PlanLedgerError

        ledger = self._ledger()
        manifest = ledger.activate(_manifest(), expected_revision=None)
        logical_task_id = manifest.tasks[0].logical_task_id
        ledger.append_attempt(PlanTaskAttempt(attempt_id="attempt:stable", logical_task_id=logical_task_id))

        with self.assertRaisesRegex(PlanLedgerError, "attempt identity"):
            ledger.append_attempt(PlanTaskAttempt(attempt_id="attempt:stable", logical_task_id="logical:other"))
        with self.assertRaisesRegex(PlanLedgerError, "logical task"):
            ledger.append_attempt(PlanTaskAttempt(attempt_id="attempt:missing", logical_task_id="logical:missing"))

    def test_malformed_stored_json_fails_closed_after_restart(self) -> None:
        from chatgpt_dev_mcp.persistence import PersistenceCorruptError

        ledger = self._ledger()
        ledger.activate(_manifest(), expected_revision=None)
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                "UPDATE plan_tasks SET paths_json = ? WHERE plan_id = ? AND plan_task_id = ?",
                ("{broken", "plan-a", "task-a"),
            )
            connection.commit()
        finally:
            connection.close()

        restarted = self._ledger()
        with self.assertRaises(PersistenceCorruptError):
            restarted.get("plan-a")


if __name__ == "__main__":
    unittest.main()
