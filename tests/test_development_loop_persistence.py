from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class DevelopmentLoopPersistenceTests(unittest.TestCase):
    def test_restart_preserves_loop_identity_history_and_pending_action(self) -> None:
        from chatgpt_dev_mcp.development_loop import DevelopmentLoopState, LoopEvent, advance
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "director.sqlite3"
            state = DevelopmentLoopState.create(loop_id="loop-one", owner_id="owner", task_id="task", session_id="session", worktree_id="tree", started_at=100.0)
            state = advance(state, LoopEvent("implemented", "implementation_complete", 101.0, progress_token="diff-one"))
            SqliteDirectorStore(path).save_development_loop(state, pending_action="verification_fast")
            loaded = SqliteDirectorStore(path).load_development_loop("loop-one")
            self.assertEqual(loaded["state"], state)
            self.assertEqual(loaded["pending_action"], "verification_fast")


if __name__ == "__main__": unittest.main()
