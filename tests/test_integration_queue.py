from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


def _git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True).stdout.strip()


class IntegrationQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="integration-queue-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.first_worktree = self.root / "first"
        self.second_worktree = self.root / "second"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "Test")
        (self.repo / "long.txt").write_text("".join(f"line-{index}\n" for index in range(40)), encoding="utf-8")
        (self.repo / "rename.txt").write_text("rename\n", encoding="utf-8")
        _git(self.repo, "add", "long.txt", "rename.txt")
        _git(self.repo, "commit", "-qm", "base")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        _git(self.repo, "worktree", "add", "--detach", str(self.first_worktree), self.base)
        _git(self.repo, "worktree", "add", "--detach", str(self.second_worktree), self.base)

    def tearDown(self) -> None:
        for worktree in (self.first_worktree, self.second_worktree):
            subprocess.run(
                ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(worktree)],
                check=False,
                capture_output=True,
            )
        self.tempdir.cleanup()

    def test_delivery_only_review_ready_task_is_not_code_queue_entry(self) -> None:
        from chatgpt_dev_mcp.integration_queue import is_code_integration_queue_entry

        self.assertFalse(
            is_code_integration_queue_entry(
                status="review_ready",
                paths=(),
                resources=("delivery:github-main-publish",),
            )
        )
        self.assertTrue(
            is_code_integration_queue_entry(
                status="review_ready",
                paths=("src/server.py",),
                patch_hash="a" * 64,
            )
        )

    def test_same_file_disjoint_hunks_are_compatible(self) -> None:
        from chatgpt_dev_mcp.director_integration import build_session_diff
        from chatgpt_dev_mcp.integration_queue import session_diffs_compatible

        first_lines = (self.first_worktree / "long.txt").read_text(encoding="utf-8").splitlines()
        first_lines[0] = "first"
        (self.first_worktree / "long.txt").write_text("\n".join(first_lines) + "\n", encoding="utf-8")
        second_lines = (self.second_worktree / "long.txt").read_text(encoding="utf-8").splitlines()
        second_lines[-1] = "second"
        (self.second_worktree / "long.txt").write_text("\n".join(second_lines) + "\n", encoding="utf-8")
        first = build_session_diff(self.repo, self.first_worktree, self.base)
        second = build_session_diff(self.repo, self.second_worktree, self.base)
        self.assertTrue(session_diffs_compatible(self.repo, first, second))

    def test_same_file_overlapping_hunks_are_not_compatible(self) -> None:
        from chatgpt_dev_mcp.director_integration import build_session_diff
        from chatgpt_dev_mcp.integration_queue import session_diffs_compatible

        for worktree, replacement in ((self.first_worktree, "first"), (self.second_worktree, "second")):
            lines = (worktree / "long.txt").read_text(encoding="utf-8").splitlines()
            lines[0] = replacement
            (worktree / "long.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        first = build_session_diff(self.repo, self.first_worktree, self.base)
        second = build_session_diff(self.repo, self.second_worktree, self.base)
        self.assertFalse(session_diffs_compatible(self.repo, first, second))

    def test_structural_same_path_change_remains_fail_closed(self) -> None:
        from chatgpt_dev_mcp.director_integration import build_session_diff
        from chatgpt_dev_mcp.integration_queue import session_diffs_compatible

        _git(self.first_worktree, "mv", "rename.txt", "renamed.txt")
        (self.second_worktree / "rename.txt").write_text("modified\n", encoding="utf-8")
        first = build_session_diff(self.repo, self.first_worktree, self.base)
        second = build_session_diff(self.repo, self.second_worktree, self.base)
        self.assertFalse(session_diffs_compatible(self.repo, first, second))


if __name__ == "__main__":
    unittest.main()
