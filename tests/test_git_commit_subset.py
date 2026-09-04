from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.git_write import GitTaskBinding, GitWriteController


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


class GitCommitSubsetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-git-commit-subset-")
        self.repo = Path(self.tempdir.name) / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "Git Commit Subset Test")
        _git(self.repo, "config", "user.email", "git-commit-subset@example.invalid")
        (self.repo / "README.md").write_text("initial\n", encoding="utf-8")
        (self.repo / "later.txt").write_text("initial later\n", encoding="utf-8")
        _git(self.repo, "add", "README.md", "later.txt")
        _git(self.repo, "commit", "-qm", "initial")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _task() -> GitTaskBinding:
        return GitTaskBinding(
            task_id="task-subset-commit",
            workspace_id="fixture",
            working_tree_id="tree",
            status="review_ready",
            allowed_paths=("README.md",),
            verification_receipt_id="verify:subset",
            security_audit_receipt_id="audit:subset",
            evidence_valid=True,
        )

    def test_commit_preserves_unrelated_unstaged_and_untracked_changes(self) -> None:
        (self.repo / "README.md").write_text("selected\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        (self.repo / "later.txt").write_text("leave unstaged\n", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("leave untracked\n", encoding="utf-8")

        controller = GitWriteController()
        task = self._task()
        preflight = controller.commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="tree",
            task=task,
            commit_message="feat: selected subset",
        )

        self.assertEqual(preflight.status, "ready", preflight.blocking_codes)
        receipt = controller.commit(
            self.repo,
            workspace_id="fixture",
            working_tree_id="tree",
            task_resolver=lambda _task_id: task,
            preflight_id=preflight.preflight_id,
            approval_token=preflight.approval.token,
            confirmation=preflight.approval.confirmation,
            commit_message="feat: selected subset",
            expected_head=preflight.snapshot.head,
            expected_staged_diff_hash=preflight.snapshot.staged_diff_hash,
            expected_index_state_hash=preflight.snapshot.index_state_hash,
        )

        self.assertEqual(receipt.status, "succeeded")
        committed = _git(self.repo, "show", "--format=", "--name-only", "HEAD").stdout.splitlines()
        self.assertEqual(committed, ["README.md"])
        status = _git(self.repo, "status", "--porcelain").stdout.splitlines()
        self.assertIn(" M later.txt", status)
        self.assertIn("?? untracked.txt", status)
        self.assertFalse(any(line.endswith("README.md") for line in status))

    def test_commit_rejects_partially_staged_selected_path(self) -> None:
        (self.repo / "README.md").write_text("staged version\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        (self.repo / "README.md").write_text("unstaged version\n", encoding="utf-8")

        preflight = GitWriteController().commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="tree",
            task=self._task(),
            commit_message="feat: blocked partial stage",
        )

        self.assertEqual(preflight.status, "blocked")
        self.assertIn("STAGED_PATH_HAS_UNSTAGED_CHANGES", preflight.blocking_codes)


if __name__ == "__main__":
    unittest.main()
