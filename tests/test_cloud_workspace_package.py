from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class CloudWorkspacePackageTests(unittest.TestCase):
    def _repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        temp = tempfile.TemporaryDirectory()
        repo = Path(temp.name)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        (repo / "src").mkdir()
        (repo / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (repo / "asset.bin").write_bytes(b"\x00\x01\x02")
        (repo / ".env").write_text("TOKEN=secret-value\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "src/app.py", "asset.bin", ".env"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        return temp, repo, head

    def test_build_is_deterministic_and_excludes_sensitive_paths(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import build_cloud_workspace_package

        temp, repo, head = self._repo()
        self.addCleanup(temp.cleanup)
        first = build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")
        second = build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")
        self.assertEqual(first.package_id, second.package_id)
        self.assertEqual(first.payload, second.payload)
        self.assertEqual([entry.path for entry in first.entries], ["asset.bin", "src/app.py"])
        self.assertNotIn(b"secret-value", first.payload)
        self.assertIn(".env", first.excluded_paths)
        self.assertEqual(dict(first.excluded_reasons)[".env"], "credential_like_name")

    def test_package_is_bound_to_exact_source_revision(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackageError, build_cloud_workspace_package

        temp, repo, _head = self._repo()
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(CloudWorkspacePackageError, "source revision"):
            build_cloud_workspace_package(repo, source_revision="0" * 40, workspace_id="demo", workload_id="test_shard")

    def test_tracked_git_symlink_is_rejected_instead_of_materialized_as_text(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackageError, build_cloud_workspace_package

        temp, repo, _head = self._repo()
        self.addCleanup(temp.cleanup)
        (repo / "linked").symlink_to("src/app.py")
        subprocess.run(["git", "-C", str(repo), "add", "linked"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "add symlink"], check=True)
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        with self.assertRaisesRegex(CloudWorkspacePackageError, "symlink"):
            build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")

    def test_immutable_dirty_snapshot_changes_package_identity_without_reading_live_dirty_state(self) -> None:
        from chatgpt_dev_mcp.baseline_snapshot import create_baseline_snapshot
        from chatgpt_dev_mcp.cloud_workspace_package import build_cloud_workspace_package

        temp, repo, head = self._repo()
        self.addCleanup(temp.cleanup)
        (repo / "src" / "app.py").write_text("print('dirty')\n", encoding="utf-8")
        (repo / "notes.txt").write_text("safe note\n", encoding="utf-8")
        artifact_root = repo.parent / "snapshots"
        snapshot = create_baseline_snapshot(repo, workspace_id="demo", artifact_root=artifact_root)
        clean = build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")
        dirty = build_cloud_workspace_package(
            repo,
            source_revision=head,
            workspace_id="demo",
            workload_id="test_shard",
            dirty_snapshot=snapshot,
        )
        self.assertNotEqual(clean.package_id, dirty.package_id)
        self.assertEqual(dirty.dirty_snapshot_id, snapshot.snapshot_id)
        self.assertIn(b".devmcp/dirty/tracked.patch", dirty.payload)
        self.assertIn(b".devmcp/dirty/untracked/notes.txt", dirty.payload)

    def test_dependency_build_paths_and_file_count_size_bounds_are_enforced(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackageError, build_cloud_workspace_package

        temp, repo, _head = self._repo()
        self.addCleanup(temp.cleanup)
        (repo / "node_modules" / "pkg").mkdir(parents=True)
        (repo / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
        (repo / "build").mkdir()
        (repo / "build" / "output.txt").write_text("generated\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "node_modules/pkg/index.js", "build/output.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "add excluded trees"], check=True)
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        package = build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")
        self.assertIn("node_modules/pkg/index.js", package.excluded_paths)
        self.assertIn("build/output.txt", package.excluded_paths)

        with patch("chatgpt_dev_mcp.cloud_workspace_package.MAX_CLOUD_PACKAGE_FILES", 1):
            with self.assertRaisesRegex(CloudWorkspacePackageError, "too many files"):
                build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")
        with patch("chatgpt_dev_mcp.cloud_workspace_package.MAX_CLOUD_PACKAGE_FILE_BYTES", 2):
            with self.assertRaisesRegex(CloudWorkspacePackageError, "file exceeds"):
                build_cloud_workspace_package(repo, source_revision=head, workspace_id="demo", workload_id="test_shard")


if __name__ == "__main__":
    unittest.main()
