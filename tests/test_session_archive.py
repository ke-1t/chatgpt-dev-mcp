from __future__ import annotations

import hashlib
from dataclasses import replace
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from chatgpt_dev_mcp.development import UNBORN_HEAD
from chatgpt_dev_mcp.session_archive import (
    ArchiveEntry,
    ArchiveDisposition,
    ArchiveError,
    SessionArchiveBuilder,
    SessionArchiveRestorer,
    SessionArchiveStore,
    SessionArchiveVerifier,
    SessionArchiveObservation,
    canonical_json_bytes,
    classify_archive_groups,
    classify_session_inventory,
    normalized_state_hash,
    observations_from_session_payloads,
    persist_published_archive,
    validate_archive_relative_path,
)


def _git(repo: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        shell=False,
    )


def _init_repo(root: Path) -> str:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "archive-test@example.invalid")
    _git(root, "config", "user.name", "Archive Test")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    (root / "binary.bin").write_bytes(b"\x00base\xff\n")
    (root / "delete-me.txt").write_text("delete me\n", encoding="utf-8")
    script = root / "script.sh"
    script.write_text("#!/bin/sh\necho base\n", encoding="utf-8")
    script.chmod(0o644)
    os.symlink("tracked.txt", root / "tracked-link")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    return _git(root, "rev-parse", "HEAD").stdout.decode().strip()


def observation(
    session_id: str,
    *,
    physical_worktree_id: str | None = None,
    worktree_path: str | None = None,
    status: str = "stale_dirty_retained",
    expired: bool = True,
    stale: bool = True,
    dirty: bool = True,
    worktree_available: bool = True,
    active_task: bool = False,
    active_lease: bool = False,
    active_session: bool = False,
    canonical_subsumed: bool = False,
    source_revision: str = "a" * 40,
    base_revision: str = "a" * 40,
) -> SessionArchiveObservation:
    return SessionArchiveObservation(
        session_id=session_id,
        project_id="chatgpt-dev-mcp",
        logical_workspace_id="chatgpt-dev-mcp",
        workspace_id="chatgpt-dev-mcp",
        physical_worktree_id=physical_worktree_id or session_id,
        worktree_path=worktree_path or f"/tmp/worktrees/{physical_worktree_id or session_id}",
        source_revision=source_revision,
        base_revision=base_revision,
        status=status,
        expired=expired,
        stale=stale,
        dirty=dirty,
        worktree_available=worktree_available,
        active_task=active_task,
        active_lease=active_lease,
        active_session=active_session,
        canonical_subsumed=canonical_subsumed,
    )


class SessionArchiveClassificationTests(unittest.TestCase):
    def test_aliases_are_grouped_by_physical_worktree(self) -> None:
        rows = (
            observation(
                "session:alias-a-1234567890",
                physical_worktree_id="session:physical-1234567890",
                worktree_path="/tmp/worktrees/physical",
            ),
            observation(
                "session:alias-b-1234567890",
                physical_worktree_id="session:physical-1234567890",
                worktree_path="/tmp/worktrees/physical",
            ),
        )

        result = classify_archive_groups(rows)

        self.assertEqual(len(result.groups), 1)
        self.assertEqual(
            result.groups[0].alias_session_ids,
            ("session:alias-a-1234567890", "session:alias-b-1234567890"),
        )
        self.assertEqual(result.groups[0].disposition, ArchiveDisposition.ARCHIVE)

    def test_active_alias_forces_keep(self) -> None:
        rows = (
            observation("session:old-1234567890123", physical_worktree_id="session:physical-1234567890"),
            observation(
                "session:active-123456789",
                physical_worktree_id="session:physical-1234567890",
                status="active",
                expired=False,
                stale=False,
                active_task=True,
            ),
        )

        group = classify_archive_groups(rows).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.KEEP)
        self.assertIn("ACTIVE_TASK", group.reason_codes)
        self.assertIn("NOT_ALL_EXPIRED", group.reason_codes)

    def test_active_lease_forces_keep(self) -> None:
        group = classify_archive_groups(
            (observation("session:lease-1234567890", active_lease=True),)
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.KEEP)
        self.assertIn("ACTIVE_LEASE", group.reason_codes)

    def test_active_clean_session_is_never_safe_to_close(self) -> None:
        group = classify_archive_groups(
            (
                observation(
                    "session:active-clean-12345",
                    status="active",
                    expired=False,
                    stale=False,
                    dirty=False,
                    active_session=True,
                ),
            )
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.KEEP)
        self.assertIn("ACTIVE_SESSION", group.reason_codes)

    def test_stale_clean_is_safe_to_close(self) -> None:
        group = classify_archive_groups(
            (
                observation(
                    "session:clean-1234567890",
                    status="stale_clean",
                    dirty=False,
                    canonical_subsumed=True,
                ),
            )
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.SAFE_TO_CLOSE)
        self.assertIn("ALL_CLEAN", group.reason_codes)

    def test_dirty_canonical_subsumed_is_safe_to_close(self) -> None:
        group = classify_archive_groups(
            (observation("session:subsumed-1234567", canonical_subsumed=True),)
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.SAFE_TO_CLOSE)
        self.assertIn("CANONICAL_SUBSUMED", group.reason_codes)

    def test_unique_expired_stale_unowned_dirty_is_archive_candidate(self) -> None:
        group = classify_archive_groups((observation("session:archive-12345678"),)).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.ARCHIVE)
        self.assertEqual(group.reason_codes, ("UNIQUE_DIRTY_DELTA",))

    def test_not_expired_dirty_is_kept(self) -> None:
        group = classify_archive_groups(
            (observation("session:fresh-1234567890", expired=False),)
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.KEEP)
        self.assertIn("NOT_ALL_EXPIRED", group.reason_codes)

    def test_unavailable_worktree_requires_review(self) -> None:
        group = classify_archive_groups(
            (observation("session:missing-12345678", worktree_available=False),)
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.REVIEW_REQUIRED)
        self.assertIn("WORKTREE_UNAVAILABLE", group.reason_codes)

    def test_alias_identity_mismatch_requires_review(self) -> None:
        rows = (
            observation(
                "session:mismatch-a-12345",
                physical_worktree_id="session:physical-1234567890",
                worktree_path="/tmp/worktrees/one",
            ),
            observation(
                "session:mismatch-b-12345",
                physical_worktree_id="session:physical-1234567890",
                worktree_path="/tmp/worktrees/two",
            ),
        )

        group = classify_archive_groups(rows).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.REVIEW_REQUIRED)
        self.assertIn("ALIAS_IDENTITY_MISMATCH", group.reason_codes)

    def test_source_revision_mismatch_requires_review(self) -> None:
        rows = (
            observation(
                "session:source-a-1234567",
                physical_worktree_id="session:physical-1234567890",
                source_revision="a" * 40,
                base_revision="a" * 40,
            ),
            observation(
                "session:source-b-1234567",
                physical_worktree_id="session:physical-1234567890",
                source_revision="b" * 40,
                base_revision="b" * 40,
            ),
        )

        group = classify_archive_groups(rows).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.REVIEW_REQUIRED)
        self.assertIn("ALIAS_IDENTITY_MISMATCH", group.reason_codes)

    def test_duplicate_session_id_with_conflicting_physical_identity_is_never_archiveable(self) -> None:
        rows = (
            observation(
                "session:duplicate-1234567",
                physical_worktree_id="session:physical-one-12345",
                worktree_path="/tmp/worktrees/one",
            ),
            observation(
                "session:duplicate-1234567",
                physical_worktree_id="session:physical-two-12345",
                worktree_path="/tmp/worktrees/two",
            ),
        )

        result = classify_archive_groups(rows)

        self.assertTrue(result.groups)
        self.assertTrue(
            all(group.disposition == ArchiveDisposition.REVIEW_REQUIRED for group in result.groups)
        )
        self.assertTrue(all("SESSION_ID_CONFLICT" in group.reason_codes for group in result.groups))

    def test_summary_counts_each_physical_worktree_once(self) -> None:
        rows = (
            observation("session:a1-123456789012", physical_worktree_id="session:physical-a-1234567"),
            observation("session:a2-123456789012", physical_worktree_id="session:physical-a-1234567"),
            observation(
                "session:b-1234567890123",
                physical_worktree_id="session:physical-b-1234567",
                dirty=False,
                status="stale_clean",
                canonical_subsumed=True,
            ),
        )

        result = classify_archive_groups(rows)

        self.assertEqual(result.physical_worktree_count, 2)
        self.assertEqual(result.alias_session_count, 3)
        self.assertEqual(result.counts[ArchiveDisposition.ARCHIVE.value], 1)
        self.assertEqual(result.counts[ArchiveDisposition.SAFE_TO_CLOSE.value], 1)

    def test_real_session_payload_adapter_uses_identity_worktree_id(self) -> None:
        payload = {
            "workspace_id": "session:alias-1234567890",
            "project_id": "chatgpt-dev-mcp",
            "logical_workspace_id": "chatgpt-dev-mcp",
            "source_commit": "a" * 40,
            "source_revision": "a" * 40,
            "task_id": "task-123",
            "session_id": "session:alias-1234567890",
            "identity": {
                "project_id": "chatgpt-dev-mcp",
                "logical_workspace_id": "chatgpt-dev-mcp",
                "workspace_id": "chatgpt-dev-mcp",
                "worktree_id": "session:physical-1234567890",
                "development_session_id": "session:alias-1234567890",
                "root_path": "~/.cache/local-dev-mcp/worktrees/physical",
                "source_revision": "a" * 40,
                "task_id": "task-123",
                "owner_id": "owner-123",
            },
            "worktree_path": "~/.cache/local-dev-mcp/worktrees/physical",
            "dirty": True,
            "worktree_available": True,
            "status": "stale_dirty_retained",
            "active": False,
            "expired": True,
            "stale": True,
        }

        rows = observations_from_session_payloads(
            (payload,),
            active_task_ids=frozenset({"task-other"}),
            active_lease_worktree_ids=frozenset(),
            canonical_subsumed_session_ids=frozenset(),
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].physical_worktree_id, "session:physical-1234567890")
        self.assertEqual(rows[0].session_id, "session:alias-1234567890")
        self.assertFalse(rows[0].active_task)
        self.assertFalse(rows[0].canonical_subsumed)

    def test_payload_adapter_never_infers_canonical_subsumption(self) -> None:
        payload = {
            "project_id": "chatgpt-dev-mcp",
            "logical_workspace_id": "chatgpt-dev-mcp",
            "source_commit": "a" * 40,
            "source_revision": "a" * 40,
            "task_id": None,
            "session_id": "session:clean-1234567890",
            "identity": {
                "workspace_id": "chatgpt-dev-mcp",
                "worktree_id": "session:physical-clean-1234",
                "root_path": "~/.cache/local-dev-mcp/worktrees/clean",
                "source_revision": "a" * 40,
            },
            "worktree_path": "~/.cache/local-dev-mcp/worktrees/clean",
            "dirty": True,
            "worktree_available": True,
            "status": "stale_dirty_retained",
            "active": False,
            "expired": True,
            "stale": True,
        }

        row = observations_from_session_payloads((payload,))[0]

        self.assertFalse(row.canonical_subsumed)

    def test_payload_adapter_marks_exact_task_and_worktree_lease(self) -> None:
        payload = {
            "project_id": "chatgpt-dev-mcp",
            "logical_workspace_id": "chatgpt-dev-mcp",
            "source_commit": "a" * 40,
            "source_revision": "a" * 40,
            "task_id": "task-live",
            "session_id": "session:live-12345678901",
            "identity": {
                "workspace_id": "chatgpt-dev-mcp",
                "worktree_id": "session:physical-live-1234",
                "root_path": "~/.cache/local-dev-mcp/worktrees/live",
                "source_revision": "a" * 40,
            },
            "worktree_path": "~/.cache/local-dev-mcp/worktrees/live",
            "dirty": True,
            "worktree_available": True,
            "status": "active",
            "active": True,
            "expired": False,
            "stale": False,
        }

        row = observations_from_session_payloads(
            (payload,),
            active_task_ids=frozenset({"task-live"}),
            active_lease_worktree_ids=frozenset({"session:physical-live-1234"}),
        )[0]

        self.assertTrue(row.active_session)
        self.assertTrue(row.active_task)
        self.assertTrue(row.active_lease)

    def test_payload_adapter_rejects_missing_physical_identity(self) -> None:
        payload = {
            "project_id": "chatgpt-dev-mcp",
            "logical_workspace_id": "chatgpt-dev-mcp",
            "source_commit": "a" * 40,
            "source_revision": "a" * 40,
            "session_id": "session:broken-123456789",
            "identity": {},
            "dirty": True,
            "worktree_available": True,
            "status": "stale_dirty_retained",
            "active": False,
            "expired": True,
            "stale": True,
        }

        row = observations_from_session_payloads((payload,))[0]
        group = classify_archive_groups((row,)).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.REVIEW_REQUIRED)
        self.assertIn("INVALID_OBSERVATION", group.reason_codes)


class SessionArchiveInventoryTests(unittest.TestCase):
    @staticmethod
    def _payload(
        session_id: str,
        *,
        project_id: str = "chatgpt-dev-mcp",
        physical_worktree_id: str | None = None,
        task_id: str | None = None,
        dirty: bool = True,
        active: bool = False,
        expired: bool = True,
        stale: bool = True,
    ) -> dict[str, object]:
        worktree_id = physical_worktree_id or session_id
        revision = "a" * 40
        return {
            "project_id": project_id,
            "logical_workspace_id": project_id,
            "source_commit": revision,
            "source_revision": revision,
            "task_id": task_id,
            "session_id": session_id,
            "identity": {
                "project_id": project_id,
                "logical_workspace_id": project_id,
                "workspace_id": project_id,
                "worktree_id": worktree_id,
                "root_path": f"~/.cache/local-dev-mcp/worktrees/{worktree_id.removeprefix('session:')}",
                "source_revision": revision,
                "task_id": task_id,
            },
            "worktree_path": f"~/.cache/local-dev-mcp/worktrees/{worktree_id.removeprefix('session:')}",
            "dirty": dirty,
            "worktree_available": True,
            "status": "active" if active else ("expired_clean" if not dirty else "expired_dirty_retained"),
            "active": active,
            "expired": expired,
            "stale": stale,
        }

    def test_inventory_groups_real_shaped_aliases_by_physical_worktree(self) -> None:
        physical = "session:Bt7P28jsL6E91s4xwPUxtqbZ"
        payloads = (
            self._payload("session:alias-one-12345678", physical_worktree_id=physical),
            self._payload("session:alias-two-12345678", physical_worktree_id=physical),
            self._payload("session:other-12345678901"),
        )
        control_plane = {"current": {"tasks": [], "leases": []}}

        result = classify_session_inventory(
            payloads,
            control_plane=control_plane,
            project_id="chatgpt-dev-mcp",
        )

        self.assertEqual(result.alias_session_count, 3)
        self.assertEqual(result.physical_worktree_count, 2)
        grouped = next(group for group in result.groups if group.physical_worktree_id == physical)
        self.assertEqual(len(grouped.alias_session_ids), 2)
        self.assertEqual(grouped.disposition, ArchiveDisposition.ARCHIVE)

    def test_inventory_filters_other_projects_before_classification(self) -> None:
        payloads = (
            self._payload("session:devmcp-1234567890"),
            self._payload("session:portfolio-1234567", project_id="portfolio-mcp"),
        )

        result = classify_session_inventory(
            payloads,
            control_plane={"current": {"tasks": [], "leases": []}},
            project_id="chatgpt-dev-mcp",
        )

        self.assertEqual(result.alias_session_count, 1)
        self.assertEqual(result.groups[0].project_id, "chatgpt-dev-mcp")

    def test_inventory_uses_current_task_and_lease_evidence_to_keep_group(self) -> None:
        physical = "session:physical-live-123456"
        payload = self._payload(
            "session:historical-alias-123",
            physical_worktree_id=physical,
            task_id="task-live",
        )
        control_plane = {
            "current": {
                "tasks": [{"task_id": "task-live", "status": "running"}],
                "leases": [{"task_id": "task-live", "working_tree_id": physical}],
            }
        }

        group = classify_session_inventory(
            (payload,),
            control_plane=control_plane,
            project_id="chatgpt-dev-mcp",
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.KEEP)
        self.assertTrue(group.active_task)
        self.assertTrue(group.active_lease)

    def test_inventory_fails_closed_when_control_plane_shape_is_missing(self) -> None:
        payloads = (
            self._payload("session:dirty-one-1234567"),
            self._payload("session:dirty-two-1234567"),
        )

        result = classify_session_inventory(
            payloads,
            control_plane={},
            project_id="chatgpt-dev-mcp",
        )

        self.assertTrue(result.groups)
        self.assertTrue(
            all(group.disposition == ArchiveDisposition.REVIEW_REQUIRED for group in result.groups)
        )
        self.assertTrue(all("INVALID_OBSERVATION" in group.reason_codes for group in result.groups))

    def test_inventory_accepts_only_explicit_exact_subsumption_evidence(self) -> None:
        session_id = "session:subsumed-real-12345"
        group = classify_session_inventory(
            (self._payload(session_id),),
            control_plane={"current": {"tasks": [], "leases": []}},
            project_id="chatgpt-dev-mcp",
            canonical_subsumed_session_ids=frozenset({session_id}),
        ).groups[0]

        self.assertEqual(group.disposition, ArchiveDisposition.SAFE_TO_CLOSE)
        self.assertEqual(group.reason_codes, ("CANONICAL_SUBSUMED",))

    def test_inventory_metadata_never_exposes_worktree_path_or_payload_material(self) -> None:
        result = classify_session_inventory(
            (self._payload("session:metadata-123456789"),),
            control_plane={"current": {"tasks": [], "leases": []}},
            project_id="chatgpt-dev-mcp",
        )

        metadata = result.to_metadata()
        group = metadata["groups"][0]
        self.assertNotIn("worktree_path", group)
        for forbidden in ("patch", "payload", "symlink_target", "approval_token", "command_output"):
            self.assertNotIn(forbidden, group)


class SessionArchivePrimitiveTests(unittest.TestCase):
    def test_canonical_json_bytes_are_deterministic(self) -> None:
        first = canonical_json_bytes({"z": 1, "a": [3, 2, 1], "nested": {"b": True, "a": None}})
        second = canonical_json_bytes({"nested": {"a": None, "b": True}, "a": [3, 2, 1], "z": 1})

        self.assertEqual(first, second)
        self.assertEqual(first, b'{"a":[3,2,1],"nested":{"a":null,"b":true},"z":1}')

    def test_normalized_state_hash_ignores_location_and_mtime(self) -> None:
        entries = (
            ArchiveEntry(path="nested/data.bin", kind="file", mode=0o640, size=3, content_hash="a" * 64),
            ArchiveEntry(path="link", kind="symlink", mode=0o777, size=0, content_hash="b" * 64, symlink_target="../target"),
        )

        first = normalized_state_hash(base_revision="c" * 40, patch_hash="d" * 64, entries=entries)
        second = normalized_state_hash(base_revision="c" * 40, patch_hash="d" * 64, entries=tuple(reversed(entries)))

        self.assertEqual(first, second)

    def test_validate_archive_relative_path_rejects_unsafe_paths(self) -> None:
        for value in ("", ".", "../escape", "a/../escape", "/absolute", "a\\b"):
            with self.subTest(value=value), self.assertRaises(ArchiveError):
                validate_archive_relative_path(value)

        self.assertEqual(validate_archive_relative_path("safe/nested.txt"), "safe/nested.txt")
        self.assertEqual(
            validate_archive_relative_path("~/.cache/local-dev-mcp/worktrees/legacy"),
            "~/.cache/local-dev-mcp/worktrees/legacy",
        )


class SessionArchiveBuilderTests(unittest.TestCase):
    def test_unborn_worktree_archives_after_canonical_gets_first_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            root = Path(tmp)
            repo = root / "repo"
            worktree = root / "unborn-worktree"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "archive-test@example.invalid")
            _git(repo, "config", "user.name", "Archive Test")
            _git(repo, "worktree", "add", "--orphan", str(worktree))
            (worktree / "session-only.txt").write_text("retained\n", encoding="utf-8")

            (repo / "canonical.txt").write_text("first commit\n", encoding="utf-8")
            _git(repo, "add", "canonical.txt")
            _git(repo, "commit", "-q", "-m", "first canonical commit")

            assessment = classify_archive_groups(
                (
                    observation(
                        "session:unborn-archive-1234",
                        physical_worktree_id="session:physical-unborn-archive",
                        worktree_path=str(worktree),
                        source_revision=UNBORN_HEAD,
                        base_revision=UNBORN_HEAD,
                    ),
                )
            ).groups[0]

            snapshot = SessionArchiveBuilder().build(assessment, repository_path=repo)
            verified = SessionArchiveVerifier().verify_snapshot(snapshot, repository_path=repo)
            published = SessionArchiveStore(
                root=Path(data_tmp) / "archives",
                free_space_reserve_bytes=0,
            ).publish(snapshot, verified)
            published_verified = SessionArchiveVerifier().verify_published(
                published.archive_path,
                repository_path=repo,
            )

            self.assertEqual(snapshot.base_revision, UNBORN_HEAD)
            self.assertEqual(snapshot.patch_bytes, b"")
            self.assertEqual(snapshot.tracked_paths, ())
            self.assertEqual(
                {entry.path for entry in snapshot.untracked_entries},
                {"session-only.txt"},
            )
            self.assertEqual(published_verified.state_hash, snapshot.state_hash)

    def test_builder_preserves_literal_tilde_untracked_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base = _init_repo(repo)
            nested = repo / "~" / ".cache" / "local-dev-mcp" / "worktrees" / "legacy" / "marker.txt"
            nested.parent.mkdir(parents=True)
            nested.write_text("legacy retained payload\n", encoding="utf-8")
            assessment = classify_archive_groups(
                (
                    observation(
                        "session:literal-tilde-123",
                        physical_worktree_id="session:physical-literal-tilde",
                        worktree_path=str(repo),
                        source_revision=base,
                        base_revision=base,
                    ),
                )
            ).groups[0]

            snapshot = SessionArchiveBuilder().build(assessment, repository_path=repo)

            by_path = {entry.path: entry for entry in snapshot.untracked_entries}
            self.assertIn("~/.cache/local-dev-mcp/worktrees/legacy/marker.txt", by_path)
            verified = SessionArchiveVerifier().verify_snapshot(snapshot, repository_path=repo)
            self.assertEqual(verified.archive_id, snapshot.archive_id)

    def test_builder_captures_binary_patch_and_untracked_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base = _init_repo(repo)
            (repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
            (repo / "binary.bin").write_bytes(b"\x00changed\xfe\xfd\n")
            (repo / "delete-me.txt").unlink()
            (repo / "script.sh").chmod(0o755)
            (repo / "tracked-link").unlink()
            os.symlink("binary.bin", repo / "tracked-link")
            nested = repo / "untracked" / "nested.txt"
            nested.parent.mkdir()
            nested.write_bytes(b"payload")
            os.symlink("untracked/nested.txt", repo / "shortcut")
            assessment = classify_archive_groups(
                (
                    observation(
                        "session:builder-123456789",
                        physical_worktree_id="session:physical-builder-123",
                        worktree_path=str(repo),
                        source_revision=base,
                        base_revision=base,
                    ),
                )
            ).groups[0]

            snapshot = SessionArchiveBuilder(payload_limit_bytes=1024 * 1024).build(
                assessment,
                repository_path=repo,
            )

            self.assertIn(b"GIT binary patch", snapshot.patch_bytes)
            self.assertEqual(
                set(snapshot.tracked_paths),
                {"binary.bin", "delete-me.txt", "script.sh", "tracked-link", "tracked.txt"},
            )
            by_path = {entry.path: entry for entry in snapshot.untracked_entries}
            self.assertEqual(by_path["untracked/nested.txt"].content_hash, hashlib.sha256(b"payload").hexdigest())
            self.assertEqual(by_path["shortcut"].kind, "symlink")
            self.assertEqual(by_path["shortcut"].symlink_target, "untracked/nested.txt")
            self.assertEqual(len(snapshot.state_hash), 64)
            self.assertTrue(snapshot.archive_id.startswith("archive-v1-"))

    def test_builder_rejects_non_head_index_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base = _init_repo(repo)
            (repo / "tracked.txt").write_text("staged\n", encoding="utf-8")
            _git(repo, "add", "tracked.txt")
            assessment = classify_archive_groups(
                (
                    observation(
                        "session:index-12345678901",
                        worktree_path=str(repo),
                        source_revision=base,
                        base_revision=base,
                    ),
                )
            ).groups[0]

            with self.assertRaises(ArchiveError) as caught:
                SessionArchiveBuilder().build(assessment, repository_path=repo)

            self.assertEqual(caught.exception.code, "INDEX_NOT_HEAD")

    def test_builder_rejects_payload_over_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base = _init_repo(repo)
            (repo / "large.bin").write_bytes(b"x" * 64)
            assessment = classify_archive_groups(
                (
                    observation(
                        "session:limit-1234567890",
                        worktree_path=str(repo),
                        source_revision=base,
                        base_revision=base,
                    ),
                )
            ).groups[0]

            with self.assertRaises(ArchiveError) as caught:
                SessionArchiveBuilder(payload_limit_bytes=16).build(assessment, repository_path=repo)

            self.assertEqual(caught.exception.code, "PAYLOAD_LIMIT_EXCEEDED")


class SessionArchiveVerifierStoreTests(unittest.TestCase):
    @staticmethod
    def _snapshot(repo: Path):
        base = _init_repo(repo)
        (repo / "tracked.txt").write_text("verified\n", encoding="utf-8")
        (repo / "binary.bin").write_bytes(b"\x00verified\xfe\x01")
        (repo / "delete-me.txt").unlink()
        (repo / "script.sh").chmod(0o755)
        (repo / "tracked-link").unlink()
        os.symlink("binary.bin", repo / "tracked-link")
        nested = repo / "payload" / "file.bin"
        nested.parent.mkdir()
        nested.write_bytes(b"archive payload")
        os.symlink("payload/file.bin", repo / "payload-link")
        assessment = classify_archive_groups(
            (
                observation(
                    "session:verify-1234567890",
                    physical_worktree_id="session:physical-verify-1234",
                    worktree_path=str(repo),
                    source_revision=base,
                    base_revision=base,
                ),
            )
        ).groups[0]
        return SessionArchiveBuilder().build(assessment, repository_path=repo)

    def test_private_index_verifier_accepts_exact_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            snapshot = self._snapshot(repo)

            verified = SessionArchiveVerifier().verify_snapshot(snapshot, repository_path=repo)

            self.assertEqual(verified.archive_id, snapshot.archive_id)
            self.assertEqual(verified.state_hash, snapshot.state_hash)
            self.assertEqual(verified.patch_hash, snapshot.patch_hash)
            self.assertEqual(len(verified.tracked_tree_hash), 40)

    def test_private_index_verifier_rejects_patch_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            snapshot = self._snapshot(repo)
            corrupted = replace(snapshot, patch_bytes=snapshot.patch_bytes + b"corrupt")

            with self.assertRaises(ArchiveError) as caught:
                SessionArchiveVerifier().verify_snapshot(corrupted, repository_path=repo)

            self.assertEqual(caught.exception.code, "PATCH_HASH_MISMATCH")

    def test_store_publishes_atomically_with_restrictive_permissions_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = self._snapshot(repo)
            verifier = SessionArchiveVerifier()
            verified = verifier.verify_snapshot(snapshot, repository_path=repo)
            root = Path(data_tmp) / "archives"
            store = SessionArchiveStore(root=root, free_space_reserve_bytes=0)

            first = store.publish(snapshot, verified)
            second = store.publish(snapshot, verified)

            self.assertEqual(first.archive_id, second.archive_id)
            self.assertEqual(first.archive_path, second.archive_path)
            archive = Path(first.archive_path)
            self.assertTrue((archive / "manifest.json").is_file())
            self.assertTrue((archive / "changes.patch").is_file())
            self.assertTrue((archive / "checksums.json").is_file())
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((archive / "manifest.json").stat().st_mode), 0o600)
            published_verified = verifier.verify_published(archive, repository_path=repo)
            self.assertEqual(published_verified.state_hash, snapshot.state_hash)

    def test_published_archive_checksum_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = self._snapshot(repo)
            verifier = SessionArchiveVerifier()
            published = SessionArchiveStore(
                root=Path(data_tmp) / "archives",
                free_space_reserve_bytes=0,
            ).publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            patch = Path(published.archive_path) / "changes.patch"
            patch.write_bytes(patch.read_bytes() + b"corrupt")

            with self.assertRaises(ArchiveError) as caught:
                verifier.verify_published(Path(published.archive_path), repository_path=repo)

            self.assertEqual(caught.exception.code, "PATCH_HASH_MISMATCH")

    def test_store_rejects_archive_id_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as data_tmp:
            store = SessionArchiveStore(root=Path(data_tmp) / "archives", free_space_reserve_bytes=0)

            with self.assertRaises(ArchiveError) as caught:
                store.load("archive-v1-../../escape")

            self.assertEqual(caught.exception.code, "INVALID_ARCHIVE_ID")

    def test_published_archive_rejects_symlinked_payload_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = self._snapshot(repo)
            verifier = SessionArchiveVerifier()
            published = SessionArchiveStore(
                root=Path(data_tmp) / "archives",
                free_space_reserve_bytes=0,
            ).publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            archive = Path(published.archive_path)
            payload_dir = archive / "untracked" / "payload"
            real_dir = archive / "untracked" / "payload-real"
            payload_dir.rename(real_dir)
            os.symlink("payload-real", payload_dir)

            with self.assertRaises(ArchiveError) as caught:
                verifier.verify_published(archive, repository_path=repo)

            self.assertEqual(caught.exception.code, "UNSAFE_STORED_SYMLINK")


class SessionArchiveRestoreTests(unittest.TestCase):
    def test_unborn_archive_restores_into_fresh_unborn_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            root = Path(tmp)
            repo = root / "repo"
            source = root / "unborn-source"
            target = root / "unborn-target"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "archive-test@example.invalid")
            _git(repo, "config", "user.name", "Archive Test")
            _git(repo, "worktree", "add", "--orphan", str(source))
            (source / "session-only.txt").write_text("retained\n", encoding="utf-8")

            (repo / "canonical.txt").write_text("first commit\n", encoding="utf-8")
            _git(repo, "add", "canonical.txt")
            _git(repo, "commit", "-q", "-m", "first canonical commit")

            assessment = classify_archive_groups(
                (
                    observation(
                        "session:unborn-restore-123",
                        physical_worktree_id="session:physical-unborn-restore",
                        worktree_path=str(source),
                        source_revision=UNBORN_HEAD,
                        base_revision=UNBORN_HEAD,
                    ),
                )
            ).groups[0]
            snapshot = SessionArchiveBuilder().build(assessment, repository_path=repo)
            verifier = SessionArchiveVerifier()
            store = SessionArchiveStore(root=Path(data_tmp) / "archives", free_space_reserve_bytes=0)
            published = store.publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            _git(repo, "worktree", "add", "--orphan", str(target))

            result = SessionArchiveRestorer(store=store, verifier=verifier).restore(
                published.archive_id,
                repository_path=repo,
                target_worktree_path=target,
            )

            self.assertEqual(result.state_hash, snapshot.state_hash)
            self.assertEqual((target / "session-only.txt").read_text(encoding="utf-8"), "retained\n")
            self.assertTrue(
                _git(target, "symbolic-ref", "--quiet", "HEAD").stdout.decode().strip().startswith("refs/heads/")
            )

    def test_persisted_archive_restores_exact_state_into_fresh_worktree(self) -> None:
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = SessionArchiveVerifierStoreTests._snapshot(repo)
            verifier = SessionArchiveVerifier()
            store = SessionArchiveStore(root=Path(data_tmp) / "archives", free_space_reserve_bytes=0)
            published = store.publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            db = SqliteDirectorStore(Path(data_tmp) / "director.sqlite3")

            persist_published_archive(db, published)

            receipt = db.find_session_archive_by_session_id("session:verify-1234567890")
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["archive_id"], published.archive_id)
            target = Path(data_tmp) / "restored-worktree"
            _git(repo, "worktree", "add", "--detach", str(target), snapshot.base_revision)

            result = SessionArchiveRestorer(store=store, verifier=verifier).restore(
                published.archive_id,
                repository_path=repo,
                target_worktree_path=target,
            )

            self.assertEqual(result.state_hash, snapshot.state_hash)
            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "verified\n")
            self.assertFalse((target / "delete-me.txt").exists())
            self.assertTrue(os.access(target / "script.sh", os.X_OK))
            self.assertTrue((target / "tracked-link").is_symlink())
            self.assertEqual(os.readlink(target / "tracked-link"), "binary.bin")
            self.assertEqual((target / "payload" / "file.bin").read_bytes(), b"archive payload")
            self.assertEqual(os.readlink(target / "payload-link"), "payload/file.bin")
            self.assertTrue((Path(published.archive_path) / "manifest.json").is_file())

    def test_same_immutable_archive_can_restore_to_multiple_fresh_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = SessionArchiveVerifierStoreTests._snapshot(repo)
            verifier = SessionArchiveVerifier()
            store = SessionArchiveStore(root=Path(data_tmp) / "archives", free_space_reserve_bytes=0)
            published = store.publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            restorer = SessionArchiveRestorer(store=store, verifier=verifier)

            hashes = []
            for name in ("restore-one", "restore-two"):
                target = Path(data_tmp) / name
                _git(repo, "worktree", "add", "--detach", str(target), snapshot.base_revision)
                hashes.append(
                    restorer.restore(
                        published.archive_id,
                        repository_path=repo,
                        target_worktree_path=target,
                    ).state_hash
                )

            self.assertEqual(hashes, [snapshot.state_hash, snapshot.state_hash])

    def test_restore_rejects_non_fresh_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as data_tmp:
            repo = Path(tmp)
            snapshot = SessionArchiveVerifierStoreTests._snapshot(repo)
            verifier = SessionArchiveVerifier()
            store = SessionArchiveStore(root=Path(data_tmp) / "archives", free_space_reserve_bytes=0)
            published = store.publish(snapshot, verifier.verify_snapshot(snapshot, repository_path=repo))
            target = Path(data_tmp) / "restored-worktree"
            _git(repo, "worktree", "add", "--detach", str(target), snapshot.base_revision)
            (target / "unexpected.txt").write_text("occupied", encoding="utf-8")

            with self.assertRaises(ArchiveError) as caught:
                SessionArchiveRestorer(store=store, verifier=verifier).restore(
                    published.archive_id,
                    repository_path=repo,
                    target_worktree_path=target,
                )

            self.assertEqual(caught.exception.code, "RESTORE_TARGET_NOT_CLEAN")


if __name__ == "__main__":
    unittest.main()
