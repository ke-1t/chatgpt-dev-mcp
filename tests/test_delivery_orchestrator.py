from __future__ import annotations

import unittest


class DeliveryOrchestratorTests(unittest.TestCase):
    def test_mutations_stay_approval_gated_and_failures_remediate(self) -> None:
        from chatgpt_dev_mcp.delivery_orchestrator import DeliveryOrchestrator
        orchestrator = DeliveryOrchestrator(); ready = {"status": "ready"}
        commit = orchestrator.next_step(ready, {"committed": False}, {})
        self.assertEqual(commit.action, "git_commit_preflight"); self.assertTrue(commit.approval_required); self.assertFalse(commit.side_effect_performed)
        self.assertTrue(orchestrator.next_step(ready, {"committed": True, "pushed": False}, {}).approval_required)
        self.assertEqual(orchestrator.next_step(ready, {"committed": True, "pushed": True}, {"pr_exists": True, "checks": "failed"}).status, "remediation_required")

    def test_verified_auto_commit_selects_only_fresh_eligible_path(self) -> None:
        from chatgpt_dev_mcp.delivery_orchestrator import DeliveryOrchestrator

        orchestrator = DeliveryOrchestrator()
        ready = {"status": "ready", "receipt_id": "ready:1"}
        verified = orchestrator.next_step(
            ready,
            {
                "committed": False,
                "verified_auto_commit_enabled": True,
                "verified_auto_commit_eligible": True,
                "verified_evidence_ref": "verify:1",
            },
            {},
        )
        self.assertEqual(verified.action, "git_verified_commit_preflight")
        self.assertEqual(verified.status, "ready")
        self.assertFalse(verified.approval_required)
        self.assertEqual(verified.evidence_ref, "verify:1")

        blocked = orchestrator.next_step(
            ready,
            {
                "committed": False,
                "verified_auto_commit_enabled": True,
                "verified_auto_commit_eligible": False,
                "verified_auto_commit_reason": "stale_evidence",
            },
            {},
        )
        self.assertEqual(blocked.action, "remediate")
        self.assertEqual(blocked.status, "remediation_required")
        self.assertEqual(blocked.reason, "verified_auto_commit_stale_evidence")
        self.assertFalse(blocked.approval_required)

    def test_verified_auto_commit_never_weakens_push_pr_or_merge_approval(self) -> None:
        from chatgpt_dev_mcp.delivery_orchestrator import DeliveryOrchestrator

        orchestrator = DeliveryOrchestrator()
        ready = {"status": "ready"}
        pushed = orchestrator.next_step(
            ready,
            {"committed": True, "pushed": False, "verified_auto_commit_enabled": True},
            {},
        )
        self.assertEqual(pushed.action, "git_push_preflight")
        self.assertTrue(pushed.approval_required)
        pr = orchestrator.next_step(
            ready,
            {"committed": True, "pushed": True, "verified_auto_commit_enabled": True},
            {"pr_exists": False},
        )
        self.assertEqual(pr.action, "github_pr_preflight")
        self.assertTrue(pr.approval_required)
        merge = orchestrator.next_step(
            ready,
            {"committed": True, "pushed": True, "verified_auto_commit_enabled": True},
            {"pr_exists": True, "checks": "passed", "reviews": "approved", "merged": False},
        )
        self.assertEqual(merge.action, "github_merge_preflight")
        self.assertTrue(merge.approval_required)


if __name__ == "__main__": unittest.main()
