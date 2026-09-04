from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class BaselineSnapshotTests(unittest.TestCase):
    def test_large_tracked_binary_deletion_uses_compact_snapshot_patch(self) -> None:
        import chatgpt_dev_mcp.baseline_snapshot as baseline_snapshot

        with tempfile.TemporaryDirectory(prefix="baseline-large-delete-") as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "large.bin").write_bytes(os.urandom(16 * 1024))
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
            (repo / "large.bin").unlink()

            original_limit = baseline_snapshot.MAX_TOTAL_BYTES
            baseline_snapshot.MAX_TOTAL_BYTES = 4 * 1024
            try:
                snapshot = baseline_snapshot.create_baseline_snapshot(
                    repo, workspace_id="project-x", artifact_root=root / "snapshots"
                )
                target = root / "target"
                subprocess.run(
                    ["git", "-C", str(repo), "worktree", "add", "--detach", str(target), "HEAD"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                baseline_snapshot.materialize_baseline_snapshot(snapshot, target)
            finally:
                baseline_snapshot.MAX_TOTAL_BYTES = original_limit

            self.assertIn("large.bin", snapshot.tracked_paths)
            self.assertFalse((target / "large.bin").exists())
            self.assertLess((snapshot.artifact_path / "tracked.patch").stat().st_size, 4 * 1024)

    def test_unborn_snapshot_captures_staged_files(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import UNBORN_HEAD, create_baseline_snapshot

        with tempfile.TemporaryDirectory(prefix="baseline-unborn-staged-") as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
            (repo / "README.md").write_text("recovery baseline\n", encoding="utf-8")
            (repo / "src").mkdir()
            (repo / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)

            snapshot = create_baseline_snapshot(repo, workspace_id="project-x", artifact_root=root / "snapshots")

            self.assertEqual(snapshot.head_revision, UNBORN_HEAD)
            self.assertTrue(snapshot.canonical_dirty)
            self.assertEqual(set(snapshot.untracked_paths), {"README.md", "src/app.py"})
            self.assertEqual(set(snapshot.included_paths), {"README.md", "src/app.py"})

    def test_tracked_secret_in_unchanged_context_does_not_block_snapshot(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot

        with tempfile.TemporaryDirectory(prefix="baseline-context-secret-") as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            (repo / "fixture.txt").write_text("token=fixture-value\nold value\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)

            (repo / "fixture.txt").write_text("token=fixture-value\nnew value\n", encoding="utf-8")
            snapshot = create_baseline_snapshot(repo, workspace_id="project-x", artifact_root=root / "snapshots")

            self.assertIn("fixture.txt", snapshot.tracked_paths)

    def test_tracked_secret_in_added_content_still_blocks_snapshot(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import BaselineSnapshotError, create_baseline_snapshot

        with tempfile.TemporaryDirectory(prefix="baseline-added-secret-") as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            (repo / "fixture.txt").write_text("ordinary\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)

            (repo / "fixture.txt").write_text("token=fixture-value\n", encoding="utf-8")
            with self.assertRaises(BaselineSnapshotError) as caught:
                create_baseline_snapshot(repo, workspace_id="project-x", artifact_root=root / "snapshots")

            self.assertEqual(caught.exception.code, "SNAPSHOT_SECRET_CONTENT")

    def test_dirty_baseline_is_immutable_and_excludes_secret_like_untracked_files(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import (
            create_baseline_snapshot,
            load_baseline_snapshot,
            materialize_baseline_snapshot,
        )
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore

        with tempfile.TemporaryDirectory(prefix="baseline-snapshot-") as raw:
            root = Path(raw)
            repo = root / "repo"
            repo.mkdir()
            (repo / "foundation.js").write_text("baseline\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
            (repo / "foundation.js").write_text("dirty foundation\n", encoding="utf-8")
            (repo / "foundation-new.js").write_text("new foundation\n", encoding="utf-8")
            (repo / ".env").write_text("TOKEN=must-not-copy\n", encoding="utf-8")

            snapshot = create_baseline_snapshot(repo, workspace_id="project-x", artifact_root=root / "snapshots")
            self.assertTrue(snapshot.canonical_dirty)
            self.assertIn("foundation.js", snapshot.tracked_paths)
            self.assertIn("foundation-new.js", snapshot.untracked_paths)
            self.assertNotIn(".env", snapshot.included_paths)
            self.assertEqual(dict(snapshot.excluded_reasons)[".env"], "credential_like_name")
            self.assertEqual(snapshot.snapshot_id, create_baseline_snapshot(repo, workspace_id="project-x", artifact_root=root / "snapshots").snapshot_id)

            store = SqliteDirectorStore(root / "state" / "director.sqlite3")
            try:
                store.save_baseline_snapshot(snapshot.as_dict())
                persisted = store.load_baseline_snapshots(workspace_id="project-x")
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0]["snapshot_id"], snapshot.snapshot_id)
                self.assertEqual(persisted[0]["excluded_reasons"][".env"], "credential_like_name")
            finally:
                store.close()

            target = root / "target"
            subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(target), "HEAD"], check=True, stdout=subprocess.DEVNULL)
            materialize_baseline_snapshot(snapshot, target)
            self.assertEqual((target / "foundation.js").read_text(encoding="utf-8"), "dirty foundation\n")
            self.assertEqual((target / "foundation-new.js").read_text(encoding="utf-8"), "new foundation\n")
            self.assertFalse((target / ".env").exists())

            (repo / "foundation.js").write_text("later canonical change\n", encoding="utf-8")
            loaded = load_baseline_snapshot(snapshot.snapshot_id, artifact_root=root / "snapshots")
            self.assertEqual(loaded.snapshot_id, snapshot.snapshot_id)
            self.assertEqual((target / "foundation.js").read_text(encoding="utf-8"), "dirty foundation\n")


if __name__ == "__main__":
    unittest.main()
