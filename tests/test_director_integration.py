from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class DirectorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="director-integration-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.worktree = self.root / "worktree"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "Test")
        (self.repo / "a.txt").write_text("base\n", encoding="utf-8")
        (self.repo / "long.txt").write_text(
            "".join(f"line {index}\n" for index in range(20)),
            encoding="utf-8",
        )
        (self.repo / "rename.txt").write_text("rename base\n", encoding="utf-8")
        (self.repo / "unrelated.txt").write_text("base unrelated\n", encoding="utf-8")
        _git(self.repo, "add", "a.txt", "long.txt", "rename.txt", "unrelated.txt")
        _git(self.repo, "commit", "-qm", "base")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        _git(self.repo, "worktree", "add", "--detach", str(self.worktree), self.base)

    def tearDown(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(self.worktree)],
            check=False,
            capture_output=True,
        )
        self.tempdir.cleanup()

    def test_session_diff_includes_tracked_and_untracked_and_applies_without_commit(self) -> None:
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        (self.worktree / "a.txt").write_text("changed\n", encoding="utf-8")
        (self.worktree / "b.txt").write_text("new\n", encoding="utf-8")

        diff = build_session_diff(self.repo, self.worktree, self.base)
        self.assertEqual(set(diff.changed_paths), {"a.txt", "b.txt"})
        self.assertEqual(len(diff.patch_hash), 64)

        preflight = integration_preflight(self.repo, self.worktree, self.base)
        self.assertTrue(preflight.integration_ready)
        self.assertEqual(preflight.status, "ready")
        self.assertTrue(preflight.canonical_clean)
        self.assertFalse(preflight.canonical_changed)
        self.assertTrue(preflight.conflict_free)

        before_head = _git(self.repo, "rev-parse", "HEAD")
        result = apply_integration_patch(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
        )
        self.assertTrue(result.applied)
        self.assertEqual((self.repo / "a.txt").read_text(encoding="utf-8"), "changed\n")
        self.assertEqual((self.repo / "b.txt").read_text(encoding="utf-8"), "new\n")
        self.assertEqual(_git(self.repo, "rev-parse", "HEAD"), before_head)

    def test_unborn_session_diff_preflight_and_apply_without_manufacturing_commit(self) -> None:
        from chatgpt_dev_mcp.development import UNBORN_HEAD
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        repo = self.root / "unborn-repo"
        worktree = self.root / "unborn-worktree"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@example.invalid")
        _git(repo, "config", "user.name", "Test")
        _git(repo, "worktree", "add", "--orphan", str(worktree))
        try:
            (worktree / "index.html").write_text("<h1>dashboard</h1>\n", encoding="utf-8")
            (worktree / "app.js").write_text("console.log('live');\n", encoding="utf-8")
            _git(worktree, "add", "index.html")

            diff = build_session_diff(repo, worktree, UNBORN_HEAD)
            self.assertEqual(set(diff.changed_paths), {"app.js", "index.html"})
            self.assertTrue(diff.patch)

            preflight = integration_preflight(repo, worktree, UNBORN_HEAD)
            self.assertEqual(preflight.canonical_revision, UNBORN_HEAD)
            self.assertFalse(preflight.canonical_changed)
            self.assertTrue(preflight.canonical_clean)
            self.assertTrue(preflight.conflict_free)
            self.assertTrue(preflight.integration_ready)

            result = apply_integration_patch(
                repo,
                diff.patch,
                expected_head=UNBORN_HEAD,
                expected_patch_hash=diff.patch_hash,
            )
            self.assertTrue(result.applied)
            self.assertEqual((repo / "index.html").read_text(encoding="utf-8"), "<h1>dashboard</h1>\n")
            self.assertEqual((repo / "app.js").read_text(encoding="utf-8"), "console.log('live');\n")
            head = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(head.returncode, 0)
        finally:
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
                check=False,
                capture_output=True,
            )

    def test_non_overlapping_canonical_dirty_change_allows_integration(self) -> None:
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        (self.worktree / "a.txt").write_text("session change\n", encoding="utf-8")
        (self.repo / "unrelated.txt").write_text("canonical dirty\n", encoding="utf-8")

        diff = build_session_diff(self.repo, self.worktree, self.base)
        preflight = integration_preflight(self.repo, self.worktree, self.base)

        self.assertEqual(preflight.status, "ready")
        self.assertTrue(preflight.canonical_clean)
        self.assertFalse(preflight.canonical_repository_clean)
        self.assertEqual(preflight.canonical_dirty_paths, ("unrelated.txt",))
        self.assertEqual(preflight.canonical_conflicting_paths, ())
        self.assertTrue(preflight.integration_ready)
        self.assertTrue(preflight.conflict_free)

        result = apply_integration_patch(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
        )

        self.assertTrue(result.applied)
        self.assertEqual((self.repo / "a.txt").read_text(encoding="utf-8"), "session change\n")
        self.assertEqual((self.repo / "unrelated.txt").read_text(encoding="utf-8"), "canonical dirty\n")
        self.assertIn(" M unrelated.txt", _git(self.repo, "status", "--porcelain=v1"))

    def test_disjoint_hunks_on_same_dirty_path_are_allowed(self) -> None:
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        session_lines = (self.worktree / "long.txt").read_text(encoding="utf-8").splitlines()
        session_lines[0] = "session change"
        (self.worktree / "long.txt").write_text("\n".join(session_lines) + "\n", encoding="utf-8")

        canonical_lines = (self.repo / "long.txt").read_text(encoding="utf-8").splitlines()
        canonical_lines[-1] = "canonical dirty"
        (self.repo / "long.txt").write_text("\n".join(canonical_lines) + "\n", encoding="utf-8")

        diff = build_session_diff(self.repo, self.worktree, self.base)
        preflight = integration_preflight(self.repo, self.worktree, self.base)

        self.assertEqual(preflight.status, "ready")
        self.assertTrue(preflight.canonical_clean)
        self.assertFalse(preflight.canonical_repository_clean)
        self.assertEqual(preflight.canonical_dirty_paths, ("long.txt",))
        self.assertEqual(preflight.canonical_conflicting_paths, ())
        self.assertEqual(preflight.changed_paths, ("long.txt",))
        self.assertTrue(preflight.integration_ready)
        self.assertTrue(preflight.conflict_free)

        result = apply_integration_patch(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
        )

        self.assertTrue(result.applied)
        merged_lines = (self.repo / "long.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(merged_lines[0], "session change")
        self.assertEqual(merged_lines[-1], "canonical dirty")

    def test_overlapping_hunk_on_same_dirty_path_is_rejected(self) -> None:
        from chatgpt_dev_mcp.director_integration import (
            IntegrationError,
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        session_lines = (self.worktree / "long.txt").read_text(encoding="utf-8").splitlines()
        session_lines[0] = "session change"
        (self.worktree / "long.txt").write_text("\n".join(session_lines) + "\n", encoding="utf-8")

        canonical_lines = (self.repo / "long.txt").read_text(encoding="utf-8").splitlines()
        canonical_lines[0] = "canonical dirty"
        (self.repo / "long.txt").write_text("\n".join(canonical_lines) + "\n", encoding="utf-8")

        diff = build_session_diff(self.repo, self.worktree, self.base)
        preflight = integration_preflight(self.repo, self.worktree, self.base)

        self.assertEqual(preflight.status, "canonical_dirty")
        self.assertFalse(preflight.canonical_clean)
        self.assertFalse(preflight.conflict_free)
        self.assertEqual(preflight.canonical_conflicting_paths, ("long.txt",))

        with self.assertRaises(IntegrationError) as caught:
            apply_integration_patch(
                self.repo,
                diff.patch,
                expected_head=preflight.canonical_revision,
                expected_patch_hash=diff.patch_hash,
            )
        self.assertEqual(caught.exception.code, "INTEGRATION_CANONICAL_DIRTY")

    def test_rename_source_dirty_is_treated_as_a_conflicting_path(self) -> None:
        from chatgpt_dev_mcp.director_integration import (
            IntegrationError,
            apply_integration_patch,
            build_session_diff,
            integration_preflight,
        )

        (self.worktree / "rename.txt").rename(self.worktree / "renamed.txt")
        _git(self.worktree, "add", "-A")
        (self.repo / "rename.txt").write_text("canonical dirty rename source\n", encoding="utf-8")

        diff = build_session_diff(self.repo, self.worktree, self.base)
        preflight = integration_preflight(self.repo, self.worktree, self.base)

        self.assertEqual(set(diff.changed_paths), {"rename.txt", "renamed.txt"})
        self.assertFalse(preflight.canonical_clean)
        self.assertEqual(preflight.canonical_conflicting_paths, ("rename.txt",))

        with self.assertRaises(IntegrationError) as caught:
            apply_integration_patch(
                self.repo,
                diff.patch,
                expected_head=preflight.canonical_revision,
                expected_patch_hash=diff.patch_hash,
            )
        self.assertEqual(caught.exception.code, "INTEGRATION_CANONICAL_DIRTY")

    def test_preflight_detects_canonical_revision_change_and_conflict(self) -> None:
        from chatgpt_dev_mcp.director_integration import integration_preflight

        (self.worktree / "a.txt").write_text("worktree\n", encoding="utf-8")
        (self.repo / "a.txt").write_text("canonical\n", encoding="utf-8")
        _git(self.repo, "add", "a.txt")
        _git(self.repo, "commit", "-qm", "canonical change")

        preflight = integration_preflight(self.repo, self.worktree, self.base)
        self.assertTrue(preflight.canonical_changed)
        self.assertEqual(preflight.status, "conflict")
        self.assertFalse(preflight.conflict_free)
        self.assertFalse(preflight.integration_ready)

    def test_integration_rejects_patch_hash_mismatch(self) -> None:
        from chatgpt_dev_mcp.director_integration import IntegrationError, apply_integration_patch

        patch = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-base\n+changed\n"
        with self.assertRaises(IntegrationError) as caught:
            apply_integration_patch(
                self.repo,
                patch,
                expected_head=self.base,
                expected_patch_hash="0" * 64,
            )
        self.assertEqual(caught.exception.code, "INTEGRATION_PATCH_CHANGED")

    def test_session_diff_rejects_symlink_changes(self) -> None:
        from chatgpt_dev_mcp.director_integration import IntegrationError, build_session_diff

        (self.worktree / "link.txt").symlink_to("a.txt")
        with self.assertRaises(IntegrationError) as caught:
            build_session_diff(self.repo, self.worktree, self.base)
        self.assertEqual(caught.exception.code, "INTEGRATION_SYMLINK_DENIED")

    def test_snapshot_preflight_does_not_patch_disjoint_excluded_baseline_file(self) -> None:
        import hashlib

        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot, materialize_baseline_snapshot
        from chatgpt_dev_mcp.director_integration import integration_preflight_since_snapshot

        # Keep this above the integration Git output bound: excluded baseline
        # binaries must stay opaque instead of being re-emitted as a patch.
        opaque = b"".join(
            hashlib.sha256(f"opaque-{index}".encode("utf-8")).digest()
            for index in range(30_000)
        )
        (self.repo / "opaque.bin").write_bytes(opaque)
        snapshot = create_baseline_snapshot(
            self.repo,
            workspace_id="project-x",
            artifact_root=self.root / "snapshots-excluded",
        )
        self.assertIn("opaque.bin", snapshot.excluded_paths)
        materialize_baseline_snapshot(snapshot, self.worktree)
        session_lines = (self.worktree / "long.txt").read_text(encoding="utf-8").splitlines()
        session_lines[18] = "session edit"
        (self.worktree / "long.txt").write_text("\n".join(session_lines) + "\n", encoding="utf-8")

        preflight = integration_preflight_since_snapshot(self.repo, self.worktree, self.base, snapshot)

        self.assertTrue(preflight.integration_ready, preflight)
        self.assertIn("opaque.bin", preflight.canonical_dirty_paths)
        self.assertNotIn("opaque.bin", preflight.canonical_conflicting_paths)

    def test_snapshot_session_diff_excludes_dirty_baseline_and_integrates_only_session_delta(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot, materialize_baseline_snapshot
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch_since_snapshot,
            build_session_diff_since_snapshot,
            integration_preflight_since_snapshot,
        )

        (self.repo / "a.txt").write_text("dirty baseline\n", encoding="utf-8")
        (self.repo / "baseline-new.txt").write_text("baseline untracked\n", encoding="utf-8")
        snapshot = create_baseline_snapshot(
            self.repo,
            workspace_id="project-x",
            artifact_root=self.root / "snapshots",
        )
        materialize_baseline_snapshot(snapshot, self.worktree)
        (self.worktree / "long.txt").write_text("session delta\n", encoding="utf-8")

        diff = build_session_diff_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertEqual(diff.changed_paths, ("long.txt",))
        self.assertNotIn("a.txt", diff.patch)
        self.assertNotIn("baseline-new.txt", diff.patch)

        preflight = integration_preflight_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertTrue(preflight.integration_ready, preflight)
        result = apply_integration_patch_since_snapshot(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
            base_revision=self.base,
            snapshot=snapshot,
        )
        self.assertTrue(result.applied)
        self.assertEqual((self.repo / "a.txt").read_text(encoding="utf-8"), "dirty baseline\n")
        self.assertEqual((self.repo / "baseline-new.txt").read_text(encoding="utf-8"), "baseline untracked\n")
        self.assertEqual((self.repo / "long.txt").read_text(encoding="utf-8"), "session delta\n")

    def test_snapshot_session_diff_treats_baseline_untracked_file_as_modification(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot, materialize_baseline_snapshot
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch_since_snapshot,
            build_session_diff_since_snapshot,
            integration_preflight_since_snapshot,
        )

        (self.repo / "scratch.txt").write_text("snapshot scratch\n", encoding="utf-8")
        snapshot = create_baseline_snapshot(
            self.repo,
            workspace_id="project-x",
            artifact_root=self.root / "snapshots-untracked",
        )
        materialize_baseline_snapshot(snapshot, self.worktree)
        (self.worktree / "scratch.txt").write_text("session scratch\n", encoding="utf-8")

        diff = build_session_diff_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertEqual(diff.changed_paths, ("scratch.txt",))
        self.assertIn("--- a/scratch.txt", diff.patch)
        self.assertIn("+++ b/scratch.txt", diff.patch)

        preflight = integration_preflight_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertTrue(preflight.integration_ready, preflight)
        apply_integration_patch_since_snapshot(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
            base_revision=self.base,
            snapshot=snapshot,
        )
        self.assertEqual((self.repo / "scratch.txt").read_text(encoding="utf-8"), "session scratch\n")

    def test_snapshot_preflight_allows_disjoint_same_file_canonical_drift(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot, materialize_baseline_snapshot
        from chatgpt_dev_mcp.director_integration import (
            apply_integration_patch_since_snapshot,
            build_session_diff_since_snapshot,
            integration_preflight_since_snapshot,
        )

        baseline_lines = [f"line {index}\n" for index in range(20)]
        baseline_lines[1] = "snapshot baseline edit\n"
        (self.repo / "long.txt").write_text("".join(baseline_lines), encoding="utf-8")
        snapshot = create_baseline_snapshot(
            self.repo,
            workspace_id="project-x",
            artifact_root=self.root / "snapshots-disjoint",
        )
        materialize_baseline_snapshot(snapshot, self.worktree)

        session_lines = baseline_lines.copy()
        session_lines[18] = "session edit\n"
        (self.worktree / "long.txt").write_text("".join(session_lines), encoding="utf-8")
        canonical_lines = baseline_lines.copy()
        canonical_lines[8] = "parallel canonical edit\n"
        (self.repo / "long.txt").write_text("".join(canonical_lines), encoding="utf-8")

        diff = build_session_diff_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertEqual(diff.changed_paths, ("long.txt",))
        preflight = integration_preflight_since_snapshot(self.repo, self.worktree, self.base, snapshot)
        self.assertTrue(preflight.integration_ready, preflight)
        self.assertTrue(preflight.conflict_free, preflight)
        apply_integration_patch_since_snapshot(
            self.repo,
            diff.patch,
            expected_head=preflight.canonical_revision,
            expected_patch_hash=diff.patch_hash,
            base_revision=self.base,
            snapshot=snapshot,
        )
        final_lines = (self.repo / "long.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(final_lines[1], "snapshot baseline edit")
        self.assertEqual(final_lines[8], "parallel canonical edit")
        self.assertEqual(final_lines[18], "session edit")

    def test_delivery_only_review_ready_task_is_not_code_integration_queue_entry(self) -> None:
        from chatgpt_dev_mcp.director_integration import is_code_integration_queue_entry

        self.assertFalse(
            is_code_integration_queue_entry(
                status="review_ready",
                paths=(),
                patch_hash="",
                resources=("delivery:github-main-publish",),
            )
        )

    def test_review_ready_code_task_remains_code_integration_queue_entry(self) -> None:
        from chatgpt_dev_mcp.director_integration import is_code_integration_queue_entry

        self.assertTrue(
            is_code_integration_queue_entry(
                status="review_ready",
                paths=("src/chatgpt_dev_mcp/server.py",),
                patch_hash="a" * 64,
                resources=(),
            )
        )


if __name__ == "__main__":
    unittest.main()
