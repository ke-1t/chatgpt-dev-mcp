import unittest
import tempfile
from pathlib import Path

from chatgpt_dev_mcp.director import TaskLedger
from chatgpt_dev_mcp.director_review import ReviewController, ReviewError
from chatgpt_dev_mcp.director_integration import IntegrationPreflight


class DirectorReviewTests(unittest.TestCase):
    def _task(self, owner="implementer"):
        ledger = TaskLedger()
        base = "a" * 40
        task = ledger.enqueue("req-review", "repo", "Implement feature", allowed_paths=["src/app.py"], base_revision=base)
        return ledger, ledger.start(task.task_id, owner), base

    def test_independent_review_and_same_owner_are_distinct(self):
        ledger, task, base = self._task()
        controller = ReviewController()
        diff_hash = "b" * 64
        independent = controller.record(
            task,
            reviewer_owner="reviewer",
            base_revision=base,
            diff_hash=diff_hash,
            reviewed_paths=["src/app.py"],
            findings=[],
        )
        self.assertTrue(independent.independent)
        self.assertTrue(controller.readiness(task, diff_hash=diff_hash, require_independent=True)["ready"])
        same_owner = controller.record(
            task,
            reviewer_owner="implementer",
            base_revision=base,
            diff_hash="c" * 64,
            reviewed_paths=["src/app.py"],
            findings=[],
        )
        self.assertFalse(same_owner.independent)
        self.assertFalse(controller.readiness(task, diff_hash="c" * 64, require_independent=True)["ready"])

    def test_blocking_finding_blocks_readiness_and_creates_remediation(self):
        ledger, task, base = self._task()
        controller = ReviewController()
        receipt = controller.record(
            task,
            reviewer_owner="reviewer",
            base_revision=base,
            diff_hash="d" * 64,
            reviewed_paths=["src/app.py"],
            findings=[{"category": "security", "severity": "high", "message": "Unsafe boundary", "blocking": True, "path": "src/app.py"}],
        )
        self.assertTrue(receipt.blocking)
        self.assertFalse(controller.readiness(task, diff_hash="d" * 64, require_independent=True)["ready"])
        child = controller.create_remediation(ledger, receipt.receipt_id, request_id="req-remediate", title="Fix review finding")
        self.assertEqual(child.allowed_paths, ("src/app.py",))

    def test_stale_task_patch_hash_is_rejected(self):
        ledger, task, base = self._task()
        task = ledger.transition(task.task_id, "review_ready", owner_id="implementer", patch_hash="e" * 64)
        controller = ReviewController()
        with self.assertRaises(ReviewError) as cm:
            controller.record(
                task,
                reviewer_owner="reviewer",
                base_revision=base,
                diff_hash="f" * 64,
                reviewed_paths=["src/app.py"],
                findings=[],
            )
        self.assertEqual(cm.exception.code, "REVIEW_STALE_DIFF")

    def test_integration_status_exposes_review_block(self):
        preflight = IntegrationPreflight(
            "a" * 40, "a" * 40, True, False, True, "b" * 64, ("src/app.py",), False, False, "independent_review_required"
        )
        self.assertEqual(preflight.status, "review_blocked")
        self.assertFalse(preflight.as_dict()["integration_ready"])

    def test_review_receipt_can_be_restored_after_runtime_restart(self):
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore

        ledger, task, base = self._task()
        controller = ReviewController()
        receipt = controller.record(
            task,
            reviewer_owner="reviewer",
            base_revision=base,
            diff_hash="f" * 64,
            reviewed_paths=["src/app.py"],
            findings=[],
        )
        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-review-persistence-") as temp:
            store = SqliteDirectorStore(Path(temp) / "director.sqlite3")
            store.save_task(task.as_dict())
            store.save_review(receipt.as_dict())
            restarted = SqliteDirectorStore(Path(temp) / "director.sqlite3")
            restored = ReviewController(restarted.load_reviews())
            self.assertTrue(restored.readiness(task, diff_hash="f" * 64, require_independent=True)["ready"])


if __name__ == "__main__":
    unittest.main()
