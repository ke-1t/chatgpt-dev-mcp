import subprocess
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.git_workflow import GitWorkflowController, GitWorkflowError


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check)
    return result.stdout.strip()


def init_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test Runner")
    (repo / "a.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "base")
    return repo


def apply_approved(controller: GitWorkflowController, repo: Path, pre: dict):
    return controller.apply(
        repo,
        preflight_id=pre["preflight_id"],
        approval_token=pre["approval"]["approval_token"],
        confirmation=pre["approval"]["confirmation"],
    )


class GitWorkflowTests(unittest.TestCase):
    def test_branch_create_does_not_checkout_and_stale_head_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            controller = GitWorkflowController()
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                working_tree_id="tree",
                operation="branch_create",
                params={"branch": "feature/safe"},
                managed_isolated=False,
            )
            original = pre["head"]
            result = apply_approved(controller, repo, pre)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(git(repo, "rev-parse", "feature/safe"), original)
            self.assertEqual(git(repo, "branch", "--show-current"), "main")

            stale = controller.preflight(
                repo,
                workspace_id="repo",
                working_tree_id="tree",
                operation="branch_create",
                params={"branch": "feature/stale"},
                managed_isolated=False,
            )
            (repo / "b.txt").write_text("advance\n", encoding="utf-8")
            git(repo, "add", "b.txt")
            git(repo, "commit", "-m", "advance")
            with self.assertRaises(GitWorkflowError) as cm:
                apply_approved(controller, repo, stale)
            self.assertEqual(cm.exception.code, "GIT_WORKFLOW_STALE")
            self.assertNotEqual(git(repo, "show-ref", "--verify", "--hash", "refs/heads/feature/stale", check=False), git(repo, "rev-parse", "HEAD"))

    def test_protected_or_existing_branch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            controller = GitWorkflowController()
            for branch in ("main", "production"):
                with self.subTest(branch=branch), self.assertRaises(GitWorkflowError):
                    controller.preflight(
                        repo,
                        workspace_id="repo",
                        working_tree_id="tree",
                        operation="branch_create",
                        params={"branch": branch},
                        managed_isolated=False,
                    )

    def test_fast_forward_merge_is_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            git(repo, "switch", "-c", "feature")
            (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
            git(repo, "add", "feature.txt")
            git(repo, "commit", "-m", "feature")
            feature_head = git(repo, "rev-parse", "HEAD")
            git(repo, "switch", "main")
            controller = GitWorkflowController()
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                working_tree_id="tree",
                operation="merge",
                params={"source_branch": "feature", "target_branch": "main", "policy": "ff_only"},
                managed_isolated=False,
            )
            self.assertFalse(pre["conflict_predicted"])
            self.assertEqual(pre["source_head"], feature_head)
            result = apply_approved(controller, repo, pre)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(git(repo, "rev-parse", "main"), feature_head)

    def test_merge_conflict_is_blocked_before_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            git(repo, "switch", "-c", "left")
            (repo / "a.txt").write_text("left\n", encoding="utf-8")
            git(repo, "add", "a.txt")
            git(repo, "commit", "-m", "left")
            git(repo, "switch", "main")
            git(repo, "switch", "-c", "right")
            (repo / "a.txt").write_text("right\n", encoding="utf-8")
            git(repo, "add", "a.txt")
            git(repo, "commit", "-m", "right")
            controller = GitWorkflowController()
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                working_tree_id="tree",
                operation="merge",
                params={"source_branch": "left", "target_branch": "right", "policy": "no_ff"},
                managed_isolated=False,
            )
            self.assertEqual(pre["status"], "blocked")
            self.assertTrue(pre["conflict_predicted"])
            self.assertIsNone(pre["approval"])

    def test_rebase_requires_managed_isolated_and_can_succeed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            git(repo, "switch", "-c", "feature")
            (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
            git(repo, "add", "feature.txt")
            git(repo, "commit", "-m", "feature")
            controller = GitWorkflowController()
            with self.assertRaises(GitWorkflowError) as cm:
                controller.preflight(
                    repo,
                    workspace_id="repo",
                    working_tree_id="tree",
                    operation="rebase",
                    params={"base_branch": "main"},
                    managed_isolated=False,
                )
            self.assertEqual(cm.exception.code, "REBASE_ISOLATION_REQUIRED")
            pre = controller.preflight(
                repo,
                workspace_id="repo",
                working_tree_id="isolated-tree",
                operation="rebase",
                params={"base_branch": "main"},
                managed_isolated=True,
            )
            result = apply_approved(controller, repo, pre)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(git(repo, "merge-base", "HEAD", "main"), git(repo, "rev-parse", "main"))


if __name__ == "__main__":
    unittest.main()
