from __future__ import annotations

import unittest


class GitHubDeliveryAdapterTests(unittest.TestCase):
    def test_provider_unavailable_uses_read_only_fallback_with_remote_pin(self) -> None:
        from chatgpt_dev_mcp.github_workflow import GitHubReadAdapter, GitHubWorkflowError
        class Primary:
            def read(self, *args, **kwargs): raise GitHubWorkflowError("GITHUB_NETWORK_UNAVAILABLE", "offline")
        fallback_calls = []
        def fallback(action, number):
            fallback_calls.append((action, number)); return {"status": "succeeded", "action": action, "remote_hash": "a" * 64, "data": {"ok": True}}
        adapter = GitHubReadAdapter(Primary(), fallback=fallback)
        result = adapter.read(None, project_id="repo", action="checks", number=1, expected_remote_hash="a" * 64)
        self.assertEqual(result["backend"], "gh_read_only_fallback")
        self.assertEqual(fallback_calls, [("checks", 1)])

    def test_auth_or_remote_mismatch_never_falls_back_and_mutation_is_rejected(self) -> None:
        from chatgpt_dev_mcp.github_workflow import GitHubReadAdapter, GitHubWorkflowError
        class Primary:
            def read(self, *args, **kwargs): raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", "auth")
        calls = []
        adapter = GitHubReadAdapter(Primary(), fallback=lambda action, number: calls.append((action, number)) or {})
        with self.assertRaises(GitHubWorkflowError): adapter.read(None, project_id="repo", action="checks", number=1, expected_remote_hash="a" * 64)
        self.assertEqual(calls, [])
        with self.assertRaises(GitHubWorkflowError): adapter.mutate("pr_merge")


if __name__ == "__main__": unittest.main()
