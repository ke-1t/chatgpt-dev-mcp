from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chatgpt_dev_mcp.persistence import PersistenceError, SqliteDirectorStore


class ApprovalDecisionPersistenceTests(unittest.TestCase):
    def test_round_trip_persists_metadata_only(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="approval-decisions-"))
        store = SqliteDirectorStore(root / "director.sqlite3")
        record = {
            "decision_id": "decision:abc123",
            "workspace_id": "fixture",
            "working_tree_id": "session:abc123",
            "session_id": "session:abc123",
            "task_id": "task:one",
            "owner_id": "chatgpt",
            "operation": "restart_dev_mcp_tunnel",
            "risk_class": "R2",
            "reason": "registered bounded local maintenance operation",
            "authorization_mode": "trusted_session_grant",
            "policy_digest": "a" * 64,
            "outcome": "succeeded",
            "recorded_at": "2026-08-15T05:00:00Z",
        }
        store.save_approval_decision(record)
        loaded = store.load_approval_decisions("fixture")
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0], record)
        self.assertNotIn("approval_token", loaded[0])
        self.assertNotIn("grant_id", loaded[0])

    def test_secret_or_grant_token_fields_are_rejected(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="approval-decisions-secret-"))
        store = SqliteDirectorStore(root / "director.sqlite3")
        base = {
            "decision_id": "decision:abc123",
            "workspace_id": "fixture",
            "working_tree_id": "session:abc123",
            "session_id": "session:abc123",
            "task_id": "task:one",
            "owner_id": "chatgpt",
            "operation": "restart_dev_mcp_tunnel",
            "risk_class": "R2",
            "reason": "bounded maintenance",
            "authorization_mode": "trusted_session_grant",
            "policy_digest": "a" * 64,
            "outcome": "succeeded",
            "recorded_at": "2026-08-15T05:00:00Z",
        }
        for forbidden in ("approval_token", "grant_id", "access_token"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(PersistenceError):
                    store.save_approval_decision({**base, forbidden: "secret-value"})


if __name__ == "__main__":
    unittest.main()
