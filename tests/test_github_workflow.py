import subprocess
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.github_workflow import GitHubPolicy, GitHubWorkflowController, GitHubWorkflowError


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def repo_fixture(root: Path, remote="https://github.com/acme/demo.git"):
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    (repo / "a.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "base")
    git(repo, "switch", "-c", "feature")
    (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
    git(repo, "add", "feature.txt")
    git(repo, "commit", "-m", "feature")
    feature_head = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "main")
    git(repo, "remote", "add", "origin", remote)
    return repo, feature_head


class FakeTransport:
    def __init__(self, feature_head):
        self.feature_head = feature_head
        self.check_conclusion = "success"
        self.review_state = "APPROVED"
        self.timeout_create = False
        self.merged = False
        self.calls = []

    def pr(self, number):
        return {
            "number": number,
            "state": "open",
            "title": "Fixture PR",
            "draft": False,
            "merged": self.merged,
            "mergeable": True,
            "head": {"ref": "feature", "sha": self.feature_head, "repo": {"full_name": "acme/demo"}},
            "base": {"ref": "main"},
        }

    def request(self, method, path, *, headers, body=None):
        self.calls.append((method, path, body))
        if method == "POST" and path.endswith("/pulls"):
            if self.timeout_create:
                raise TimeoutError("fixture timeout")
            return 201, {"number": 2}
        if method == "PUT" and path.endswith("/merge"):
            self.merged = True
            return 200, {"merged": True}
        if method == "GET" and "/pulls/" in path and path.endswith("/reviews"):
            return 200, [{"user": {"login": "reviewer"}, "state": self.review_state, "submitted_at": "2026-08-13T00:00:00Z"}]
        if method == "GET" and path.endswith("/check-runs"):
            return 200, {"check_runs": [{"name": "unit", "status": "completed", "conclusion": self.check_conclusion}]}
        if method == "GET" and path.endswith("/protection"):
            return 404, {}
        if method == "GET" and "/pulls/" in path:
            number = int(path.split("/pulls/", 1)[1].split("/", 1)[0])
            return 200, self.pr(number)
        raise AssertionError((method, path))


class GitHubWorkflowTests(unittest.TestCase):
    def _controller(self, feature_head, **policy_kwargs):
        policy = GitHubPolicy(owner="acme", repository="demo", auth_required=False, required_checks=("unit",), required_approvals=1, **policy_kwargs)
        transport = FakeTransport(feature_head)
        return GitHubWorkflowController(policy, transport=transport), transport

    def test_ci_passed_and_requested_changes_affect_merge_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, feature_head = repo_fixture(Path(tmp))
            controller, transport = self._controller(feature_head)
            ready = controller.read(repo, project_id="repo", action="merge_readiness", number=1)
            self.assertTrue(ready["data"]["ready"])
            transport.check_conclusion = "failure"
            failed = controller.read(repo, project_id="repo", action="merge_readiness", number=1)
            self.assertIn("required_checks_not_passing", failed["data"]["reasons"])
            transport.check_conclusion = "success"
            transport.review_state = "CHANGES_REQUESTED"
            changed = controller.read(repo, project_id="repo", action="merge_readiness", number=1)
            self.assertIn("changes_requested", changed["data"]["reasons"])

    def test_pr_create_and_merge_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, feature_head = repo_fixture(Path(tmp))
            controller, _ = self._controller(feature_head)
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                project_id="repo",
                operation="pr_create",
                params={"title": "Fixture", "body": "Body", "head_branch": "feature", "base_branch": "main"},
            )
            created = controller.apply(
                pre["preflight_id"], project_id="repo",
                approval_id=pre["approval"]["approval_token"], confirmation=pre["approval"]["confirmation"], credential_grant_id="",
            )
            self.assertEqual(created["status"], "succeeded")
            merge_pre = controller.preflight(repo, workspace_id="repo", project_id="repo", operation="pr_merge", params={"number": 2})
            merged = controller.apply(
                merge_pre["preflight_id"], project_id="repo",
                approval_id=merge_pre["approval"]["approval_token"], confirmation=merge_pre["approval"]["confirmation"], credential_grant_id="",
            )
            self.assertEqual(merged["status"], "succeeded")
            self.assertTrue(merged["pr"]["merged"])

    def test_network_timeout_is_outcome_unknown_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, feature_head = repo_fixture(Path(tmp))
            controller, transport = self._controller(feature_head)
            transport.timeout_create = True
            pre = controller.preflight(
                repo, workspace_id="repo", project_id="repo", operation="pr_create",
                params={"title": "Fixture", "body": "Body", "head_branch": "feature", "base_branch": "main"},
            )
            result = controller.apply(
                pre["preflight_id"], project_id="repo",
                approval_id=pre["approval"]["approval_token"], confirmation=pre["approval"]["confirmation"], credential_grant_id="",
            )
            self.assertEqual(result["status"], "outcome_unknown")
            self.assertFalse(result["retry_safe"])
            self.assertEqual(sum(1 for method, path, _ in transport.calls if method == "POST" and path.endswith("/pulls")), 1)

    def test_repository_mismatch_auth_unavailable_and_merge_queue_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, feature_head = repo_fixture(Path(tmp), remote="https://github.com/other/demo.git")
            controller, _ = self._controller(feature_head)
            with self.assertRaises(GitHubWorkflowError) as mismatch:
                controller.read(repo, project_id="repo", action="pr_status", number=1)
            self.assertEqual(mismatch.exception.code, "GITHUB_REPOSITORY_MISMATCH")

            good_repo, good_head = repo_fixture(Path(tmp) / "second")
            auth_policy = GitHubPolicy(owner="acme", repository="demo", credential_slot="GITHUB_SLOT", auth_required=True)
            auth_controller = GitHubWorkflowController(auth_policy, transport=FakeTransport(good_head))
            with self.assertRaises(GitHubWorkflowError) as auth:
                auth_controller.preflight(
                    good_repo, workspace_id="repo", project_id="repo", operation="pr_create",
                    params={"title": "Fixture", "body": "Body", "head_branch": "feature", "base_branch": "main"},
                )
            self.assertEqual(auth.exception.code, "GITHUB_AUTH_UNAVAILABLE")

            queue_controller, _ = self._controller(good_head, merge_queue_required=True)
            with self.assertRaises(GitHubWorkflowError) as queue:
                queue_controller.preflight(good_repo, workspace_id="repo", project_id="repo", operation="pr_merge", params={"number": 1})
            self.assertEqual(queue.exception.code, "GITHUB_MERGE_QUEUE_REQUIRED")

    def test_authenticated_merge_reuses_grant_from_preflight_through_apply(self):
        from chatgpt_dev_mcp.credential_slots import CredentialSlotManager, CredentialSlotPolicy

        with tempfile.TemporaryDirectory() as tmp:
            repo, feature_head = repo_fixture(Path(tmp))
            slots = CredentialSlotManager(
                [
                    CredentialSlotPolicy(
                        slot="GITHUB_SLOT",
                        source_kind="env",
                        source_name="GITHUB_TOKEN",
                        allowed_profiles=("github",),
                        allowed_projects=("repo",),
                    )
                ],
                environ={"GITHUB_TOKEN": "fixture-token"},
            )
            policy = GitHubPolicy(
                owner="acme",
                repository="demo",
                credential_slot="GITHUB_SLOT",
                auth_required=True,
            )
            controller = GitHubWorkflowController(
                policy,
                credential_slots=slots,
                transport=FakeTransport(feature_head),
            )
            grant = slots.preflight("GITHUB_SLOT", project_id="repo", command_profile="github")["grant_id"]
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                project_id="repo",
                operation="pr_merge",
                params={"number": 1},
                credential_grant_id=grant,
            )
            merged = controller.apply(
                pre["preflight_id"],
                project_id="repo",
                approval_id=pre["approval"]["approval_token"],
                confirmation=pre["approval"]["confirmation"],
                credential_grant_id=grant,
            )
            self.assertEqual(merged["status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
