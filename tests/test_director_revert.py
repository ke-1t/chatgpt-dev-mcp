import subprocess
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.director_revert import RevertController, RevertError


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def repo_fixture(root: Path) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    (repo / "a.txt").write_bytes(b"base\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "base")
    return repo, git(repo, "rev-parse", "HEAD")


class DirectorRevertTests(unittest.TestCase):
    def test_exact_inverse_reverts_only_managed_post_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, head = repo_fixture(Path(tmp))
            before = (repo / "a.txt").read_bytes()
            after = b"changed\n"
            (repo / "a.txt").write_bytes(after)
            controller = RevertController()
            managed = controller.register_patch(
                repo,
                workspace_id="repo",
                patch_hash="a" * 64,
                base_revision=head,
                head_revision=head,
                changes={"a.txt": (before, after)},
            )
            pre = controller.preflight(managed["patch_id"])
            result = controller.apply(
                pre["preflight_id"],
                approval_id=pre["approval"]["approval_token"],
                confirmation=pre["approval"]["confirmation"],
            )
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual((repo / "a.txt").read_bytes(), before)

    def test_downstream_change_blocks_revert(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, head = repo_fixture(Path(tmp))
            before = (repo / "a.txt").read_bytes()
            after = b"changed\n"
            (repo / "a.txt").write_bytes(after)
            controller = RevertController()
            managed = controller.register_patch(
                repo, workspace_id="repo", patch_hash="b" * 64, base_revision=head, head_revision=head,
                changes={"a.txt": (before, after)},
            )
            (repo / "a.txt").write_bytes(b"downstream\n")
            with self.assertRaises(RevertError) as cm:
                controller.preflight(managed["patch_id"])
            self.assertEqual(cm.exception.code, "REVERT_CONFLICT")

    def test_committed_head_change_is_stale_and_sensitive_path_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, head = repo_fixture(Path(tmp))
            controller = RevertController()
            with self.assertRaises(RevertError) as sensitive:
                controller.register_patch(
                    repo, workspace_id="repo", patch_hash="c" * 64, base_revision=head, head_revision=head,
                    changes={".env": (None, b"fixture")},
                )
            self.assertEqual(sensitive.exception.code, "REVERT_SENSITIVE_PATH_DENIED")
            before = (repo / "a.txt").read_bytes()
            after = b"changed\n"
            (repo / "a.txt").write_bytes(after)
            managed = controller.register_patch(
                repo, workspace_id="repo", patch_hash="d" * 64, base_revision=head, head_revision=head,
                changes={"a.txt": (before, after)},
            )
            (repo / "b.txt").write_text("new\n", encoding="utf-8")
            git(repo, "add", "b.txt", "a.txt")
            git(repo, "commit", "-m", "advance")
            with self.assertRaises(RevertError) as stale:
                controller.preflight(managed["patch_id"])
            self.assertEqual(stale.exception.code, "STALE_REVERT_BASE")


if __name__ == "__main__":
    unittest.main()
