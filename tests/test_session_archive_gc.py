from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from chatgpt_dev_mcp.persistence import SqliteDirectorStore
from chatgpt_dev_mcp.session_archive import (
    ArchiveDisposition,
    ArchiveError,
    PhysicalWorktreeAssessment,
)
from chatgpt_dev_mcp.session_archive_gc import (
    prepare_archive_for_prune,
    revalidate_archive_prune_source_state,
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        shell=False,
    )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _dirty_repo(root: Path) -> tuple[str, PhysicalWorktreeAssessment]:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "archive-gc@example.invalid")
    _git(root, "config", "user.name", "Archive GC")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-q", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "tracked.txt").write_text("unique dirty delta\n", encoding="utf-8")
    (root / "untracked.bin").write_bytes(b"payload")
    assessment = PhysicalWorktreeAssessment(
        physical_worktree_id="session:physical-archive-gc",
        worktree_path=str(root),
        project_id="chatgpt-dev-mcp",
        logical_workspace_id="chatgpt-dev-mcp",
        workspace_id="chatgpt-dev-mcp",
        source_revision=base,
        base_revision=base,
        alias_session_ids=("session:archive-gc-alias",),
        disposition=ArchiveDisposition.ARCHIVE,
        reason_codes=("UNIQUE_DIRTY_DELTA",),
        dirty=True,
        all_expired=True,
        all_stale=True,
        worktree_available=True,
        canonical_subsumed=False,
        active_task=False,
        active_lease=False,
        active_session=False,
    )
    return base, assessment


class SessionArchivePrePruneTests(unittest.TestCase):
    def test_success_publishes_verifies_and_persists_before_authority(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(repo_tmp)
            _, assessment = _dirty_repo(repo)
            persistence = SqliteDirectorStore(Path(data_tmp) / "director.sqlite3")
            archive_root = Path(data_tmp) / "archives"

            result = prepare_archive_for_prune(
                assessment,
                repository_path=repo,
                persistence=persistence,
                archive_root=archive_root,
                free_space_reserve_bytes=0,
            )

            self.assertTrue(result.prune_authorized)
            self.assertTrue(Path(result.archive_path).is_dir())
            self.assertTrue(repo.is_dir())
            self.assertEqual((repo / "tracked.txt").read_text(encoding="utf-8"), "unique dirty delta\n")
            receipt = persistence.get_session_archive_receipt(result.archive_id)
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["state_hash"], result.state_hash)

    def test_persistence_failure_never_authorizes_prune_or_touches_source(self) -> None:
        class BrokenPersistence:
            def save_session_archive_receipt(self, _payload: object) -> None:
                raise RuntimeError("database unavailable")

        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(repo_tmp)
            _, assessment = _dirty_repo(repo)

            with self.assertRaises(ArchiveError) as caught:
                prepare_archive_for_prune(
                    assessment,
                    repository_path=repo,
                    persistence=BrokenPersistence(),
                    archive_root=Path(data_tmp) / "archives",
                    free_space_reserve_bytes=0,
                )

            self.assertEqual(caught.exception.code, "ARCHIVE_RECEIPT_PERSIST_FAILED")
            self.assertTrue(repo.is_dir())
            self.assertEqual((repo / "tracked.txt").read_text(encoding="utf-8"), "unique dirty delta\n")

    def test_non_archive_disposition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(repo_tmp)
            _, assessment = _dirty_repo(repo)
            assessment = PhysicalWorktreeAssessment(
                **{**assessment.__dict__, "disposition": ArchiveDisposition.KEEP}
            )

            with self.assertRaises(ArchiveError) as caught:
                prepare_archive_for_prune(
                    assessment,
                    repository_path=repo,
                    persistence=SqliteDirectorStore(Path(data_tmp) / "director.sqlite3"),
                    archive_root=Path(data_tmp) / "archives",
                    free_space_reserve_bytes=0,
                )

            self.assertEqual(caught.exception.code, "NOT_ARCHIVE_ELIGIBLE")

    def test_revalidation_rejects_source_mutation_after_archive_publish(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(repo_tmp)
            _, assessment = _dirty_repo(repo)
            persistence = SqliteDirectorStore(Path(data_tmp) / "director.sqlite3")
            preparation = prepare_archive_for_prune(
                assessment,
                repository_path=repo,
                persistence=persistence,
                archive_root=Path(data_tmp) / "archives",
                free_space_reserve_bytes=0,
            )

            revalidate_archive_prune_source_state(
                assessment,
                preparation=preparation,
                repository_path=repo,
            )

            (repo / "tracked.txt").write_text("mutated after archive publish\n", encoding="utf-8")

            with self.assertRaises(ArchiveError) as caught:
                revalidate_archive_prune_source_state(
                    assessment,
                    preparation=preparation,
                    repository_path=repo,
                )

            self.assertEqual(caught.exception.code, "ARCHIVE_SOURCE_STATE_CHANGED")
            self.assertTrue(repo.is_dir())
            self.assertEqual(
                (repo / "tracked.txt").read_text(encoding="utf-8"),
                "mutated after archive publish\n",
            )

    def test_server_prune_revalidates_immediately_before_force_remove(self) -> None:
        from unittest.mock import patch

        from chatgpt_dev_mcp import server as server_module
        from chatgpt_dev_mcp.development import DevelopmentSecurityError

        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as worktrees_tmp,
            tempfile.TemporaryDirectory() as data_tmp,
        ):
            source = Path(source_tmp)
            target = Path(worktrees_tmp) / "archived-session"
            _git(source, "init", "-q")
            _git(source, "config", "user.email", "archive-gc@example.invalid")
            _git(source, "config", "user.name", "Archive GC")
            (source / "tracked.txt").write_text("base\n", encoding="utf-8")
            _git(source, "add", "tracked.txt")
            _git(source, "commit", "-q", "-m", "base")
            base = _git(source, "rev-parse", "HEAD")
            _git(source, "worktree", "add", "--detach", str(target), base)
            (target / "tracked.txt").write_text("unique dirty delta\n", encoding="utf-8")
            (target / "untracked.bin").write_bytes(b"payload")
            assessment = PhysicalWorktreeAssessment(
                physical_worktree_id="session:physical-archive-race",
                worktree_path=str(target),
                project_id="chatgpt-dev-mcp",
                logical_workspace_id="chatgpt-dev-mcp",
                workspace_id="chatgpt-dev-mcp",
                source_revision=base,
                base_revision=base,
                alias_session_ids=("session:archive-race-alias",),
                disposition=ArchiveDisposition.ARCHIVE,
                reason_codes=("UNIQUE_DIRTY_DELTA",),
                dirty=True,
                all_expired=True,
                all_stale=True,
                worktree_available=True,
                canonical_subsumed=False,
                active_task=False,
                active_lease=False,
                active_session=False,
            )
            persistence = SqliteDirectorStore(Path(data_tmp) / "director.sqlite3")
            preparation = prepare_archive_for_prune(
                assessment,
                repository_path=source,
                persistence=persistence,
                archive_root=Path(data_tmp) / "archives",
                free_space_reserve_bytes=0,
            )
            original_get_receipt = persistence.get_session_archive_receipt

            def mutate_after_receipt_read(archive_id: str):
                receipt = original_get_receipt(archive_id)
                (target / "tracked.txt").write_text(
                    "mutated in prune race window\n",
                    encoding="utf-8",
                )
                return receipt

            with patch.object(
                persistence,
                "get_session_archive_receipt",
                side_effect=mutate_after_receipt_read,
            ):
                with self.assertRaises(DevelopmentSecurityError) as caught:
                    server_module.WrapperRuntime._remove_archived_session_worktree(
                        object(),
                        source=source,
                        target=target,
                        preparation=preparation,
                        store=persistence,
                    )

            self.assertEqual(caught.exception.code, "DEVELOPMENT_ARCHIVE_SOURCE_STATE_CHANGED")
            self.assertTrue(target.is_dir())
            self.assertEqual(
                (target / "tracked.txt").read_text(encoding="utf-8"),
                "mutated in prune race window\n",
            )


if __name__ == "__main__":
    unittest.main()
