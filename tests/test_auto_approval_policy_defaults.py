from __future__ import annotations

import unittest


class AutoApprovalPolicyDefaultsTests(unittest.TestCase):
    def test_project_policy_effective_defaults_enable_safe_local_automation(self) -> None:
        from chatgpt_dev_mcp.project_policy import ProjectPolicyManager

        policy = ProjectPolicyManager._effective_policy({})
        self.assertIs(policy["auto_approve_safe_local"], True)
        self.assertIs(policy["auto_approve_local_maintenance"], True)
        self.assertEqual(policy["trust_level"], "standard")
        self.assertEqual(policy["manual_approval_ttl_seconds"], 1_800)
        self.assertEqual(policy["trusted_session_grant_ttl_seconds"], 7_200)
        self.assertIs(policy["integration_requires_approval"], True)
        self.assertIs(policy["commit_requires_approval"], True)
        self.assertIs(policy["push_requires_approval"], True)
        self.assertIs(policy["verified_auto_commit"], True)

    def test_provisioning_defaults_match_project_policy(self) -> None:
        from chatgpt_dev_mcp.provisioning import DEFAULT_ISOLATED_POLICY

        self.assertIs(DEFAULT_ISOLATED_POLICY["auto_approve_safe_local"], True)
        self.assertIs(DEFAULT_ISOLATED_POLICY["auto_approve_local_maintenance"], True)
        self.assertEqual(DEFAULT_ISOLATED_POLICY["manual_approval_ttl_seconds"], 1_800)
        self.assertEqual(DEFAULT_ISOLATED_POLICY["trusted_session_grant_ttl_seconds"], 7_200)
        self.assertIs(DEFAULT_ISOLATED_POLICY["integration_requires_approval"], True)
        self.assertIs(DEFAULT_ISOLATED_POLICY["commit_requires_approval"], True)
        self.assertIs(DEFAULT_ISOLATED_POLICY["push_requires_approval"], True)

    def test_default_manual_approval_ttl_is_thirty_minutes(self) -> None:
        from chatgpt_dev_mcp.approval import UnifiedApprovalStore
        from chatgpt_dev_mcp.development import APPROVAL_TTL_SECONDS

        now = 100.0
        store = UnifiedApprovalStore(clock=lambda: now)
        approval = store.issue("fixture", "workspace", "fingerprint", "confirm")
        self.assertEqual(approval.expires_at - approval.issued_at, 1_800)
        self.assertEqual(APPROVAL_TTL_SECONDS, 1_800)

    def test_server_metadata_parser_accepts_new_policy_keys_and_bounds(self) -> None:
        from chatgpt_dev_mcp.server import _parse_project_metadata

        metadata = _parse_project_metadata(
            {
                "isolated_development": {
                    "auto_create_sessions": True,
                    "auto_resume_sessions": True,
                    "auto_resume_policy": "same_owner_same_task_safe_local",
                    "max_parallel_sessions": 6,
                    "allowed_base": "registered_project",
                    "allow_workspace_wide": False,
                    "integration_requires_approval": True,
                    "commit_requires_approval": True,
                    "push_requires_approval": True,
                    "verified_auto_commit": True,
                    "auto_approve_safe_local": True,
                    "auto_approve_local_maintenance": True,
                    "manual_approval_ttl_seconds": 1_800,
                    "trusted_session_grant_ttl_seconds": 7_200,
                }
            }
        )
        policy = metadata["isolated_development"]
        self.assertIs(policy["auto_approve_safe_local"], True)
        self.assertIs(policy["auto_approve_local_maintenance"], True)
        self.assertEqual(policy["manual_approval_ttl_seconds"], 1_800)
        self.assertEqual(policy["trusted_session_grant_ttl_seconds"], 7_200)

        for key, value in (
            ("manual_approval_ttl_seconds", 59),
            ("manual_approval_ttl_seconds", 3_601),
            ("trusted_session_grant_ttl_seconds", 59),
            ("trusted_session_grant_ttl_seconds", 7_201),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    _parse_project_metadata({"isolated_development": {key: value}})


if __name__ == "__main__":
    unittest.main()
