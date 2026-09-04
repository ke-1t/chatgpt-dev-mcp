from __future__ import annotations

import unittest


class ParallelEvidenceInvalidationTests(unittest.TestCase):
    def test_disjoint_parallel_write_only_invalidates_overlapping_evidence(self) -> None:
        from chatgpt_dev_mcp.director_audit import SecurityAuditReceipt, SecurityAuditReport
        from chatgpt_dev_mcp.director_verification import VerificationPlan, VerificationReceipt
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = object.__new__(WrapperRuntime)
        worktree_id = "worktree:main"

        receipt_a = VerificationReceipt(
            workspace_id="project-x",
            plan=VerificationPlan("project-x", ("src/a.py",), ("test",), True, "TEST"),
            results=(),
            status="passed",
            base_revision="abc123",
            diff_hash="a" * 64,
            receipt_id="verify:a",
            working_tree_id=worktree_id,
        )
        receipt_b = VerificationReceipt(
            workspace_id="project-x",
            plan=VerificationPlan("project-x", ("src/b.py",), ("test",), True, "TEST"),
            results=(),
            status="passed",
            base_revision="abc123",
            diff_hash="b" * 64,
            receipt_id="verify:b",
            working_tree_id=worktree_id,
        )
        report = SecurityAuditReport("pass", (), "2026-08-14T00:00:00Z")
        audit_a = SecurityAuditReceipt(
            "project-x",
            report,
            "abc123",
            "a" * 64,
            "a" * 64,
            ("src/a.py",),
            receipt_a.receipt_id,
            "2026-08-14T00:00:00Z",
            "audit:a",
            working_tree_id=worktree_id,
        )
        audit_b = SecurityAuditReceipt(
            "project-x",
            report,
            "abc123",
            "b" * 64,
            "b" * 64,
            ("src/b.py",),
            receipt_b.receipt_id,
            "2026-08-14T00:00:00Z",
            "audit:b",
            working_tree_id=worktree_id,
        )

        runtime._director_receipt_history = {receipt_a.receipt_id: receipt_a, receipt_b.receipt_id: receipt_b}
        runtime._director_receipts = {"project-x": receipt_b}
        runtime._director_audit_receipt_history = {audit_a.receipt_id: audit_a, audit_b.receipt_id: audit_b}
        runtime._director_audit_receipts = {"project-x": audit_b}
        runtime._persistence = None
        runtime._persistence_error = None

        runtime._director_invalidate_evidence(
            "project-x",
            worktree_id,
            changed_paths=("src/a.py",),
        )

        self.assertTrue(runtime._director_receipt_history[receipt_a.receipt_id].stale)
        self.assertFalse(runtime._director_receipt_history[receipt_b.receipt_id].stale)
        self.assertTrue(runtime._director_audit_receipt_history[audit_a.receipt_id].stale)
        self.assertFalse(runtime._director_audit_receipt_history[audit_b.receipt_id].stale)


if __name__ == "__main__":
    unittest.main()
