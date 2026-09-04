from __future__ import annotations

import unittest

from chatgpt_dev_mcp.approval_policy import (
    ApprovalPolicyError,
    GrantBinding,
    RiskClass,
    RiskPolicyEngine,
    TrustedGrantStore,
)


class RiskPolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskPolicyEngine()

    def test_classifies_known_operations_and_fails_unknown_closed(self) -> None:
        self.assertEqual(self.engine.classify("workspace_status"), RiskClass.R0)
        self.assertEqual(self.engine.classify("run_task"), RiskClass.R1)
        self.assertEqual(self.engine.classify("apply_patch"), RiskClass.R1)
        self.assertEqual(self.engine.classify("git_stage_preflight"), RiskClass.R0)
        self.assertEqual(self.engine.classify("git_stage"), RiskClass.R1)
        self.assertEqual(self.engine.classify("git_stage_paths_preflight"), RiskClass.R0)
        self.assertEqual(self.engine.classify("git_stage_paths"), RiskClass.R1)
        self.assertEqual(self.engine.classify("git_verified_commit"), RiskClass.R1)
        self.assertEqual(self.engine.classify("restart_dev_mcp_tunnel"), RiskClass.R2)
        self.assertEqual(self.engine.classify("workspace_integrate_development_session"), RiskClass.R3)
        self.assertEqual(self.engine.classify("git_push"), RiskClass.R3)
        self.assertEqual(self.engine.classify("arbitrary_command"), RiskClass.R3)
        self.assertEqual(self.engine.classify("credential_grant"), RiskClass.R3)
        self.assertEqual(self.engine.classify("unknown_future_operation"), RiskClass.R3)


class TrustedGrantStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_000.0
        self.engine = RiskPolicyEngine()
        self.store = TrustedGrantStore(clock=lambda: self.now, policy_engine=self.engine)
        self.binding = GrantBinding(
            workspace_id="chatgpt-dev-mcp",
            working_tree_id="session:abc123",
            session_id="session:abc123",
            task_id="task:one",
            owner_id="chatgpt",
        )
        self.digest = "a" * 64

    def test_issue_caps_expiry_to_development_session_and_validates_exact_binding(self) -> None:
        grant = self.store.issue(
            self.binding,
            operations=("restart_dev_mcp_tunnel",),
            policy_digest=self.digest,
            ttl_seconds=7_200,
            session_expires_at=self.now + 3_600,
        )
        self.assertEqual(grant.expires_at, self.now + 3_600)
        validated = self.store.validate(
            grant.grant_id,
            binding=self.binding,
            operation="restart_dev_mcp_tunnel",
            policy_digest=self.digest,
        )
        self.assertEqual(validated.grant_id, grant.grant_id)

    def test_expired_grant_is_rejected(self) -> None:
        grant = self.store.issue(
            self.binding,
            operations=("restart_dev_mcp_tunnel",),
            policy_digest=self.digest,
            ttl_seconds=60,
            session_expires_at=self.now + 3_600,
        )
        self.now += 61
        with self.assertRaisesRegex(ApprovalPolicyError, "expired"):
            self.store.validate(
                grant.grant_id,
                binding=self.binding,
                operation="restart_dev_mcp_tunnel",
                policy_digest=self.digest,
            )

    def test_binding_or_policy_drift_is_rejected(self) -> None:
        grant = self.store.issue(
            self.binding,
            operations=("restart_dev_mcp_tunnel",),
            policy_digest=self.digest,
            ttl_seconds=600,
            session_expires_at=self.now + 3_600,
        )
        changed_binding = GrantBinding(
            workspace_id=self.binding.workspace_id,
            working_tree_id=self.binding.working_tree_id,
            session_id=self.binding.session_id,
            task_id="task:other",
            owner_id=self.binding.owner_id,
        )
        with self.assertRaisesRegex(ApprovalPolicyError, "binding"):
            self.store.validate(
                grant.grant_id,
                binding=changed_binding,
                operation="restart_dev_mcp_tunnel",
                policy_digest=self.digest,
            )
        with self.assertRaisesRegex(ApprovalPolicyError, "policy"):
            self.store.validate(
                grant.grant_id,
                binding=self.binding,
                operation="restart_dev_mcp_tunnel",
                policy_digest="b" * 64,
            )

    def test_r3_operation_cannot_be_placed_in_trusted_grant(self) -> None:
        for operation in (
            "git_push",
            "workspace_integrate_development_session",
            "arbitrary_command",
            "credential_grant",
        ):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ApprovalPolicyError, "R3"):
                    self.store.issue(
                        self.binding,
                        operations=(operation,),
                        policy_digest=self.digest,
                        ttl_seconds=600,
                        session_expires_at=self.now + 3_600,
                    )


if __name__ == "__main__":
    unittest.main()
