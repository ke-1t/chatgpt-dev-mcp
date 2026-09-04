from __future__ import annotations

import unittest


class ManualApprovalTtlTests(unittest.TestCase):
    def test_all_manual_approval_controllers_default_to_thirty_minutes(self) -> None:
        from chatgpt_dev_mcp.approval import MANUAL_APPROVAL_TTL_SECONDS, UnifiedApprovalStore
        from chatgpt_dev_mcp.director_revert import RevertController
        from chatgpt_dev_mcp.git_workflow import GitWorkflowController
        from chatgpt_dev_mcp.git_write import GitWriteController
        from chatgpt_dev_mcp.github_workflow import GitHubPolicy, GitHubWorkflowController
        from chatgpt_dev_mcp.server import INTEGRATION_APPROVAL_TTL_SECONDS, REGISTRATION_PREFLIGHT_TTL_SECONDS

        self.assertEqual(MANUAL_APPROVAL_TTL_SECONDS, 1_800)
        self.assertEqual(UnifiedApprovalStore()._ttl_seconds, 1_800)
        self.assertEqual(GitWriteController()._approval_ttl_seconds, 1_800)
        self.assertEqual(GitWorkflowController()._approvals._ttl_seconds, 1_800)
        self.assertEqual(RevertController()._approvals._ttl_seconds, 1_800)
        github = GitHubWorkflowController(GitHubPolicy(owner="owner", repository="repo"))
        self.assertEqual(github._approvals._ttl_seconds, 1_800)
        self.assertEqual(REGISTRATION_PREFLIGHT_TTL_SECONDS, 1_800)
        self.assertEqual(INTEGRATION_APPROVAL_TTL_SECONDS, 1_800)


if __name__ == "__main__":
    unittest.main()
