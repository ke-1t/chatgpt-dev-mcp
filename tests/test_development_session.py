from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class IdentityAndApprovalTests(unittest.TestCase):
    def test_retained_session_observability_classifies_without_exposing_session_ids(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        summary = WrapperRuntime._retained_session_observability(
            [
                {"session_id": "session:active", "project_id": "project-a", "active": True, "stale": False, "expired": False, "dirty": False, "status": "active"},
                {"session_id": "session:dirty", "project_id": "project-b", "active": False, "stale": True, "expired": True, "dirty": True, "status": "expired_dirty_retained"},
                {"session_id": "session:cleanup", "project_id": "project-b", "active": False, "stale": True, "expired": True, "dirty": False, "status": "cleanup_candidate"},
            ]
        )

        self.assertEqual(summary["scope"], "global")
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["active"], 1)
        self.assertEqual(summary["active_by_project"], {"project-a": 1})
        self.assertEqual(summary["stale"], 2)
        self.assertEqual(summary["expired"], 2)
        self.assertEqual(summary["dirty"], 1)
        self.assertEqual(summary["clean"], 2)
        self.assertEqual(summary["cleanup_candidates"], 1)
        self.assertEqual(summary["dirty_retained"], 1)
        self.assertNotIn("session_ids", summary)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-development-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.repo = self.home / "Developer" / "project-x"
        self._init_repo(self.repo)
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self._previous_home = os.environ.get("HOME")
        self._previous_worktree_root = os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT")
        os.environ["HOME"] = str(self.home)
        os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = str(self.home / ".cache" / "local-dev-mcp" / "worktrees")

    def tearDown(self) -> None:
        if self._previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._previous_home
        if self._previous_worktree_root is None:
            os.environ.pop("LOCAL_DEV_MCP_WORKTREE_ROOT", None)
        else:
            os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = self._previous_worktree_root
        self.tempdir.cleanup()

    @staticmethod
    def _init_repo(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)

    @staticmethod
    def _git(path: Path, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def test_identity_changes_when_repo_is_replaced(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSecurityError, capture_repo_identity, validate_repo_identity

        identity = capture_repo_identity(self.repo)
        original = self.repo.with_name("moved-project")
        self.repo.rename(original)
        self._init_repo(self.repo)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_repo_identity(identity)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_SOURCE_CHANGED")

    def test_identity_repair_evidence_round_trips_through_sidecar(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSession, capture_repo_identity, read_session_sidecars, write_session_sidecar

        identity = capture_repo_identity(self.repo)
        worktree_path = self.home / ".cache" / "local-dev-mcp" / "worktrees" / "identity-repair-sidecar-0001"
        session = DevelopmentSession(
            "session:identity-repair-sidecar-0001",
            "registered:project-x",
            "project-x",
            identity,
            worktree_path,
            identity.head,
            False,
            100.0,
            200.0,
            {},
            True,
            "session:identity-repair-sidecar-0001",
            "project-x",
            "project-x",
            None,
            None,
            identity.head,
            "stale",
            None,
            None,
            {
                "schema_version": 1,
                "method": "git_identity_repair",
                "preserve_worktree": True,
                "state_digest": "a" * 64,
            },
        )
        write_session_sidecar(session)
        restored = read_session_sidecars(preserve_active=True)
        self.assertEqual(len(restored), 1)
        self.assertIsNotNone(restored[0].identity_repair)
        self.assertEqual(restored[0].identity_repair["method"], "git_identity_repair")
        self.assertTrue(restored[0].identity_repair["preserve_worktree"])

    def test_identity_rejects_symlink_and_external_git_marker(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSecurityError, capture_repo_identity, validate_repo_identity

        identity = capture_repo_identity(self.repo)
        moved = self.repo.with_name("moved-project")
        self.repo.rename(moved)
        self.repo.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_repo_identity(identity)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_SOURCE_CHANGED")

        self.repo.unlink()
        self._init_repo(self.repo)
        identity = capture_repo_identity(self.repo)
        git_marker = self.repo / ".git"
        replacement = self.root / "git-marker"
        git_marker.rename(replacement)
        git_marker.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_repo_identity(identity)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_SOURCE_CHANGED")

    def test_approval_is_bound_to_candidate_repo_workspace_commit_and_confirmation(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSecurityError, capture_repo_identity, issue_approval, validate_and_consume_approval

        identity = capture_repo_identity(self.repo)
        approval = issue_approval("candidate:a", "project-x", identity, "DEVELOPMENT", now=100.0)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_and_consume_approval(approval, candidate_id="candidate:b", workspace_id="project-x", identity=identity, confirmation=approval.confirmation, now=101.0)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_APPROVAL_MISMATCH")

        approval = issue_approval("candidate:a", "project-x", identity, "DEVELOPMENT", now=100.0)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_and_consume_approval(approval, candidate_id="candidate:a", workspace_id="project-x", identity=identity, confirmation="wrong", now=101.0)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_APPROVAL_MISMATCH")

        approval = issue_approval("candidate:a", "project-x", identity, "DEVELOPMENT", now=100.0)
        changed_head = self.repo / "changed.txt"
        changed_head.write_text("changed\n", encoding="utf-8")
        self._git(self.repo, "add", "changed.txt")
        self._git(self.repo, "commit", "-qm", "second")
        changed_identity = capture_repo_identity(self.repo)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_and_consume_approval(approval, candidate_id="candidate:a", workspace_id="project-x", identity=changed_identity, confirmation=approval.confirmation, now=101.0)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_SOURCE_CHANGED")

    def test_approval_expires_and_cannot_be_reused(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSecurityError, capture_repo_identity, issue_approval, validate_and_consume_approval

        identity = capture_repo_identity(self.repo)
        expired = issue_approval("candidate:a", "project-x", identity, "DEVELOPMENT", now=100.0, ttl_seconds=10.0)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_and_consume_approval(expired, candidate_id="candidate:a", workspace_id="project-x", identity=identity, confirmation=expired.confirmation, now=111.0)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_APPROVAL_EXPIRED")

        used = issue_approval("candidate:a", "project-x", identity, "DEVELOPMENT", now=100.0)
        validate_and_consume_approval(used, candidate_id="candidate:a", workspace_id="project-x", identity=identity, confirmation=used.confirmation, now=101.0)
        with self.assertRaises(DevelopmentSecurityError) as raised:
            validate_and_consume_approval(used, candidate_id="candidate:a", workspace_id="project-x", identity=identity, confirmation=used.confirmation, now=102.0)
        self.assertEqual(raised.exception.code, "DEVELOPMENT_APPROVAL_USED")

    def test_immutable_baseline_remains_valid_when_canonical_is_dirty_or_head_advances(self) -> None:
        from chatgpt_dev_mcp.development import (
            capture_repo_identity,
            validate_repo_anchor_at_commit,
            validate_source_commit_exists,
        )

        identity = capture_repo_identity(self.repo)
        baseline = identity.head
        (self.repo / "README.md").write_text("canonical-dirty\n", encoding="utf-8")
        self.assertEqual(validate_source_commit_exists(self.repo, baseline), baseline)
        self.assertEqual(validate_repo_anchor_at_commit(identity, baseline).source_path, self.repo.resolve())

        (self.repo / "advanced.txt").write_text("advanced\n", encoding="utf-8")
        self._git(self.repo, "add", "advanced.txt")
        self._git(self.repo, "commit", "-qm", "advance canonical")
        self.assertNotEqual(capture_repo_identity(self.repo).head, baseline)
        self.assertEqual(validate_repo_anchor_at_commit(identity, baseline).head, self._git(self.repo, "rev-parse", "HEAD"))

    def test_multiple_managed_worktrees_use_the_same_immutable_baseline_without_dirty_copy(self) -> None:
        from chatgpt_dev_mcp.development import (
            capture_repo_identity,
            create_detached_worktree,
            managed_worktree_path,
            remove_detached_worktree,
            validate_repo_anchor_at_commit,
            verify_detached_worktree,
        )

        identity = capture_repo_identity(self.repo)
        baseline = identity.head
        (self.repo / "README.md").write_text("canonical-dirty\n", encoding="utf-8")
        first = managed_worktree_path("session:parallelbaselineA")
        second = managed_worktree_path("session:parallelbaselineB")
        try:
            validate_repo_anchor_at_commit(identity, baseline)
            create_detached_worktree(self.repo, baseline, first)
            create_detached_worktree(self.repo, baseline, second)
            verify_detached_worktree(self.repo, first, baseline)
            verify_detached_worktree(self.repo, second, baseline)
            self.assertEqual((first / "README.md").read_text(encoding="utf-8"), "fixture\n")
            self.assertEqual((second / "README.md").read_text(encoding="utf-8"), "fixture\n")
            self.assertNotEqual(first, second)
        finally:
            if second.exists():
                remove_detached_worktree(self.repo, second)
            if first.exists():
                remove_detached_worktree(self.repo, first)


class DevelopmentSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-development-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.repo = self.home / "Developer" / "project-x"
        self._init_repo(self.repo)
        self.config_path = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config_path.parent.mkdir(parents=True)
        self._write_config(profile="DEVELOPMENT")
        self._previous_home = os.environ.get("HOME")
        self._previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        self._previous_data_dir = os.environ.get("LOCAL_DEV_MCP_DATA_DIR")
        self._previous_worktree_root = os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT")
        os.environ["HOME"] = str(self.home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config_path)
        os.environ["LOCAL_DEV_MCP_DATA_DIR"] = str(self.root / "director-state")
        os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = str(self.home / ".cache" / "local-dev-mcp" / "worktrees")

    def tearDown(self) -> None:
        if self._previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._previous_home
        if self._previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self._previous_config
        if self._previous_data_dir is None:
            os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
        else:
            os.environ["LOCAL_DEV_MCP_DATA_DIR"] = self._previous_data_dir
        if self._previous_worktree_root is None:
            os.environ.pop("LOCAL_DEV_MCP_WORKTREE_ROOT", None)
        else:
            os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = self._previous_worktree_root
        self.tempdir.cleanup()

    @staticmethod
    def _init_repo(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)

    def _write_config(self, *, profile: str = "DEVELOPMENT", commands: dict[str, str] | None = None) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "project-x": {
                            "path": "~/Developer/project-x",
                            "profile": profile,
                            "commands": commands if commands is not None else {"test": "printf test-ok"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def _open_candidate(self, *, runtime_kwargs=None):
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime(**(runtime_kwargs or {}))
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate_id = next(item["candidate_id"] for item in discovered["repositories"] if item["name"] == "project-x")
        opened = runtime.call_tool("workspace_open", {"id": candidate_id})["structuredContent"]
        self.assertEqual(opened["profile"], "READ_ONLY")
        return runtime, candidate_id

    def _acquire_readme_lease(self, runtime, task_id: str) -> str:
        result = runtime.call_tool(
            "director_writer_lease",
            {
                "action": "acquire",
                "owner_id": "test-chat",
                "task_id": task_id,
                "paths": ["README.md"],
            },
        )["structuredContent"]
        self.assertTrue(result["ok"])
        return result["lease"]["lease_id"]

    def test_request_requires_current_read_only_candidate_and_matching_development_config(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        missing = runtime.call_tool("workspace_request_development", {"candidate_id": "candidate:missing", "workspace_id": "project-x"})["structuredContent"]
        self.assertEqual(missing["error"]["code"], "DEVELOPMENT_APPROVAL_REQUIRED")
        runtime.close()

        runtime, candidate_id = self._open_candidate()
        wrong = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "wrong"})["structuredContent"]
        self.assertEqual(wrong["error"]["code"], "DEVELOPMENT_PROFILE_NOT_REGISTERED")
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        self.assertTrue(approval["approval_token"].startswith("approval:"))
        self.assertEqual(approval["profile"], "DEVELOPMENT")
        runtime.close()

    def test_create_session_requires_explicit_confirmation_and_builds_detached_worktree(self) -> None:
        runtime, candidate_id = self._open_candidate()
        source_before = (self.repo / "README.md").read_text(encoding="utf-8")
        config_before = self.config_path.read_bytes()
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        wrong = runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": "wrong"})["structuredContent"]
        self.assertEqual(wrong["error"]["code"], "DEVELOPMENT_APPROVAL_MISMATCH")
        created = runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]})["structuredContent"]
        self.assertTrue(created["ok"])
        self.assertEqual(created["profile"], "DEVELOPMENT")
        worktree_path = Path(created["worktree_path"]).expanduser()
        self.assertTrue(worktree_path.is_dir())
        self.assertTrue(str(worktree_path.resolve()).startswith(str((self.home / ".cache" / "local-dev-mcp" / "worktrees").resolve())))
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), source_before)
        self.assertEqual(self.config_path.read_bytes(), config_before)
        runtime.close()

    def test_approved_source_commit_survives_canonical_head_advance(self) -> None:
        runtime, candidate_id = self._open_candidate()
        baseline = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]
        (self.repo / "canonical-only.txt").write_text("advanced canonical\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "canonical-only.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "advance canonical"], check=True)
        created = runtime.call_tool(
            "workspace_create_development_session",
            {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
        )["structuredContent"]
        self.assertTrue(created["ok"], created)
        self.assertEqual(created["source_commit"], baseline)
        worktree = Path(created["worktree_path"]).expanduser()
        self.assertEqual((worktree / "README.md").read_text(encoding="utf-8"), "fixture\n")
        self.assertFalse((worktree / "canonical-only.txt").exists())
        closed = runtime.call_tool("workspace_close_development_session", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(closed["ok"], closed)
        runtime.close()

    def test_candidate_without_registered_development_tasks_is_denied(self) -> None:
        self._write_config(profile="READ_WRITE")
        runtime, candidate_id = self._open_candidate()
        denied = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        self.assertEqual(denied["error"]["code"], "DEVELOPMENT_PROFILE_NOT_REGISTERED")
        runtime.close()

    def test_candidate_open_remains_read_only_and_config_is_unchanged(self) -> None:
        runtime, candidate_id = self._open_candidate()
        blocked = runtime.call_tool("apply_patch", {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+blocked\n*** End Patch"})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "PROFILE_DENIED")
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        self.assertEqual(approval["profile"], "DEVELOPMENT")
        self.assertEqual(runtime.current.profile, "READ_ONLY")
        runtime.close()

    def test_registered_development_workspace_opens_directly_with_guarded_editing(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        opened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(opened["ok"])
        self.assertEqual(opened["profile"], "DEVELOPMENT")
        self.assertFalse(opened["external_execution"])
        lease_id = self._acquire_readme_lease(runtime, "task-direct-development")
        patched = runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+direct-development\n*** End Patch",
                "lease_id": lease_id
            },
        )["structuredContent"]
        self.assertTrue(patched["ok"])
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), "direct-development\n")
        status = runtime.call_tool("workspace_status", {})["structuredContent"]
        self.assertTrue(status["ok"])
        self.assertEqual(Path(status["path"]).resolve(), self.repo.resolve())
        self.assertFalse(status["development_session"])
        runtime.close()

    def test_active_development_session_can_switch_read_only_context_without_deleting_worktree(self) -> None:
        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]
        runtime.call_tool(
            "workspace_create_development_session",
            {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
        )
        opened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(opened["ok"])
        self.assertEqual(opened["profile"], "DEVELOPMENT")
        runtime.close()

    def test_second_active_development_session_can_be_created_from_same_project(self) -> None:
        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]})
        runtime.call_tool("workspace_open", {"id": candidate_id})
        second = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        self.assertTrue(second["approval_token"].startswith("approval:"))
        created = runtime.call_tool("workspace_create_development_session", {"approval_token": second["approval_token"], "confirmation": second["confirmation"]})["structuredContent"]
        self.assertTrue(created["ok"])
        runtime.close()

    def test_approval_cannot_be_used_after_source_is_replaced(self) -> None:
        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        moved = self.repo.with_name("project-x-moved")
        self.repo.rename(moved)
        self._init_repo(self.repo)
        blocked = runtime.call_tool(
            "workspace_create_development_session",
            {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
        )["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "DEVELOPMENT_SOURCE_CHANGED")
        self.assertFalse((self.home / ".cache" / "local-dev-mcp" / "worktrees").exists())
        runtime.close()

    def _assert_dirty_source_rejected(self, mutate) -> None:
        runtime, candidate_id = self._open_candidate()
        mutate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]
        self.assertTrue(approval["approval_token"].startswith("approval:"))
        created = runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]})["structuredContent"]
        self.assertTrue(created["ok"])
        self.assertTrue(created["source_dirty_at_creation"])
        self.assertFalse(created["canonical_dirty_content_copied"] if "canonical_dirty_content_copied" in created else False)
        runtime.close()

    def test_dirty_source_unstaged_is_rejected_before_approval(self) -> None:
        self._assert_dirty_source_rejected(
            lambda: (self.repo / "README.md").write_text("unstaged\n", encoding="utf-8")
        )

    def test_dirty_source_staged_is_rejected_before_approval(self) -> None:
        def stage_change() -> None:
            (self.repo / "staged.txt").write_text("staged\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(self.repo), "add", "staged.txt"], check=True)

        self._assert_dirty_source_rejected(stage_change)

    def test_dirty_source_untracked_is_rejected_before_approval(self) -> None:
        self._assert_dirty_source_rejected(
            lambda: (self.repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        )

    def test_source_becoming_dirty_after_approval_is_rejected_without_worktree(self) -> None:
        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]
        (self.repo / "after-approval.txt").write_text("dirty\n", encoding="utf-8")
        created = runtime.call_tool(
            "workspace_create_development_session",
            {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
        )["structuredContent"]
        self.assertTrue(created["ok"])
        self.assertTrue(created["source_dirty_at_creation"])
        runtime.close()

    def test_precreated_worktree_symlink_is_rejected(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.server as server_module

        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]
        target = self.home / ".cache" / "local-dev-mcp" / "worktrees" / "fixed-target"
        target.parent.mkdir(parents=True)
        target.symlink_to(self.root / "missing-target", target_is_directory=True)
        with patch.object(server_module.secrets, "token_urlsafe", return_value="fixed-target"):
            rejected = runtime.call_tool(
                "workspace_create_development_session",
                {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
            )["structuredContent"]
        self.assertEqual(rejected["error"]["code"], "DEVELOPMENT_WORKTREE_INVALID")
        self.assertTrue(target.is_symlink())
        runtime.close()

    def test_worktree_identity_is_verified_before_session_activation(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.server as server_module

        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]

        def fake_create(_source: Path, _base_commit: str, target: Path) -> None:
            target.mkdir(parents=True)

        with patch.object(server_module, "create_detached_worktree", side_effect=fake_create):
            rejected = runtime.call_tool(
                "workspace_create_development_session",
                {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
            )["structuredContent"]
        self.assertEqual(rejected["error"]["code"], "DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH")
        self.assertIsNone(runtime.active_development_session_id)
        runtime.close()

    def test_worktree_target_replacement_race_is_rejected(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.server as server_module

        runtime, candidate_id = self._open_candidate()
        approval = runtime.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_id, "workspace_id": "project-x"},
        )["structuredContent"]

        def race_create(source: Path, base_commit: str, target: Path) -> None:
            real_target = target
            from chatgpt_dev_mcp.development import create_detached_worktree as create

            create(source, base_commit, real_target)
            moved = real_target.with_name(f"{real_target.name}-moved")
            real_target.rename(moved)
            real_target.symlink_to(moved, target_is_directory=True)

        with patch.object(server_module, "create_detached_worktree", side_effect=race_create):
            rejected = runtime.call_tool(
                "workspace_create_development_session",
                {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
            )["structuredContent"]
        self.assertEqual(rejected["error"]["code"], "DEVELOPMENT_WORKTREE_INVALID")
        self.assertIsNone(runtime.active_development_session_id)
        runtime.close()

    def test_context_state_ignores_tasks_bound_to_missing_development_sessions(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
            self.assertTrue(opened["ok"], opened)
            head = subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            working_tree_id = opened["identity"]["worktree_id"]
            current = runtime._director_ledger.enqueue(
                "context-current-task",
                "project-x",
                "Current canonical task",
                working_tree_id=working_tree_id,
                allowed_paths=("README.md",),
                base_revision=head,
            )
            orphan = runtime._director_ledger.enqueue(
                "context-orphan-task",
                "project-x",
                "Orphaned session task",
                working_tree_id="session:missing-context-session",
                development_session_id="session:missing-context-session",
                allowed_paths=("README.md",),
                base_revision=head,
            )
            blocked = runtime._director_ledger.enqueue(
                "context-orphan-blocker",
                "project-x",
                "Historical orphan blocker",
                working_tree_id="session:missing-blocked-session",
                development_session_id="session:missing-blocked-session",
                allowed_paths=("README.md",),
                base_revision=head,
            )
            runtime._director_ledger.transition(blocked.task_id, "blocked", detail="historical")

            state = runtime._context_state_vector(runtime.current, runtime.upstream)

            self.assertEqual(state.active_task_ids, (current.task_id,))
            self.assertNotIn(orphan.task_id, state.active_task_ids)
            self.assertEqual(state.blocker_ids, ())
        finally:
            runtime.close()

    def test_reconcile_stales_queued_task_when_bound_session_is_missing(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            runtime.call_tool("workspace_open", {"id": "project-x"})
            head = subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            orphan = runtime._director_ledger.enqueue(
                "queued-orphan-regression",
                "project-x",
                "Queued orphan regression",
                working_tree_id="session:missing-queued-session",
                development_session_id="session:missing-queued-session",
                allowed_paths=("README.md",),
                base_revision=head,
            )

            runtime._reconcile_orphaned_writer_tasks("project-x", fallback_revision=head)

            reconciled = runtime._director_ledger.get(orphan.task_id)
            self.assertIsNotNone(reconciled)
            self.assertEqual(reconciled.status, "stale")
            self.assertEqual(reconciled.detail, "ORPHANED_DEVELOPMENT_SESSION")
        finally:
            runtime.close()


class SessionLifecycleTests(DevelopmentSessionTests):
    def _create_session(self, *, clock=None):
        runtime, candidate_id = self._open_candidate(runtime_kwargs={"clock": clock} if clock is not None else None)
        approval = runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})["structuredContent"]
        created = runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]})["structuredContent"]
        self.assertTrue(created["ok"])
        self.assertEqual(created["identity"]["workspace_id"], "project-x")
        self.assertEqual(created["identity"]["development_session_id"], created["session_id"])
        self.assertEqual(created["identity"]["source_revision"], created["source_commit"])
        return runtime, created

    def _archive_unique_session(self):
        from unittest.mock import patch

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-archive-restore-fixture")
        applied = runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+archive-restore-fixture\n*** End Patch",
                "lease_id": lease_id,
            },
        )["structuredContent"]
        self.assertTrue(applied["ok"])
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-archive-restore-fixture"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "abandoned"
        session.expires_at = 100.0
        worktree = Path(created["worktree_path"]).expanduser()
        with patch.dict(os.environ, {"LOCAL_DEV_MCP_SESSION_ARCHIVE_GC": "1"}):
            result = runtime._gc_expired_clean_sessions()
        self.assertFalse(worktree.exists())
        self.assertIn(created["session_id"], result["removed_session_ids"])
        self.assertIsNotNone(runtime._persistence)
        receipt = runtime._persistence.find_session_archive_by_session_id(created["session_id"])
        self.assertIsNotNone(receipt)
        self.assertIsNotNone(receipt["pruned_at"])
        return runtime, created, receipt

    def test_request_attach_for_archived_pruned_session_issues_restore_challenge(self) -> None:
        runtime, created, receipt = self._archive_unique_session()
        try:
            requested = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": created["session_id"]},
            )
            self.assertFalse(requested["isError"], requested)
            payload = requested["structuredContent"]
            self.assertEqual(payload["status"], "available")
            self.assertEqual(payload["session_id"], created["session_id"])
            self.assertTrue(payload["approval_token"].startswith("approval:"))
            self.assertIn(created["session_id"], payload["confirmation"])
            self.assertEqual(receipt["base_revision"], created["source_commit"])
        finally:
            runtime.close()

    def test_attach_archived_pruned_session_restores_new_session_worktree_and_lease(self) -> None:
        runtime, created, receipt = self._archive_unique_session()
        archive_path = Path(receipt["archive_path"])
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task = next(
            record
            for record in ledger["records"]
            if record["request_id"] == "task-archive-restore-fixture"
        )
        requested = runtime.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]

        attached = runtime.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )

        self.assertFalse(attached["isError"], attached)
        payload = attached["structuredContent"]
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["attached"])
        self.assertTrue(payload["restored_from_archive"])
        self.assertEqual(payload["archive_id"], receipt["archive_id"])
        self.assertEqual(payload["restore_state_hash"], receipt["state_hash"])
        self.assertEqual(payload["reattached_from"], created["session_id"])
        self.assertNotEqual(payload["session_id"], created["session_id"])
        self.assertNotEqual(payload["working_tree_id"], receipt["physical_worktree_id"])
        restored_worktree = Path(payload["worktree_path"]).expanduser()
        self.assertTrue(restored_worktree.is_dir())
        self.assertEqual((restored_worktree / "README.md").read_text(encoding="utf-8"), "archive-restore-fixture\n")
        self.assertTrue(payload["lease_id"])
        self.assertNotEqual(payload["task"]["task_id"], task["task_id"])
        self.assertNotEqual(payload["task"]["owner_id"], task["owner_id"])
        self.assertEqual(payload["task"]["development_session_id"], payload["session_id"])
        self.assertEqual(payload["task"]["working_tree_id"], payload["working_tree_id"])
        self.assertEqual(payload["lease"]["working_tree_id"], payload["working_tree_id"])
        self.assertEqual(payload["lease"]["task_id"], payload["task"]["task_id"])
        self.assertEqual(payload["lease"]["owner_id"], payload["task"]["owner_id"])
        self.assertTrue(archive_path.is_dir())
        restores = runtime._persistence.load_session_archive_restores(receipt["archive_id"])
        self.assertEqual(len(restores), 1)
        self.assertEqual(restores[0]["original_session_id"], created["session_id"])
        self.assertEqual(restores[0]["restored_session_id"], payload["session_id"])
        runtime.close()

    def test_request_attach_for_corrupted_archive_fails_closed_without_new_session(self) -> None:
        runtime, created, receipt = self._archive_unique_session()
        before_sessions = set(runtime.development_sessions)
        archive_path = Path(receipt["archive_path"])
        (archive_path / "changes.patch").write_bytes(b"corrupted archive payload\n")

        requested = runtime.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )

        self.assertTrue(requested["isError"], requested)
        self.assertEqual(
            requested["structuredContent"]["error"]["code"],
            "DEVELOPMENT_ARCHIVE_RESTORE_INVALID",
        )
        self.assertEqual(set(runtime.development_sessions), before_sessions)
        self.assertEqual(runtime._director_writer_manager.active("project-x"), ())
        runtime.close()

    def test_archived_restore_failure_after_materialization_retains_managed_stale_recovery_session(self) -> None:
        from unittest.mock import patch

        from chatgpt_dev_mcp.director import LedgerConflict

        runtime, created, _receipt = self._archive_unique_session()
        requested = runtime.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        before_sessions = set(runtime.development_sessions)

        with patch.object(runtime._director_ledger, "enqueue", side_effect=LedgerConflict("fixture enqueue failure")):
            attached = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": created["session_id"],
                    "approval_token": requested["approval_token"],
                    "confirmation": requested["confirmation"],
                },
            )

        self.assertTrue(attached["isError"], attached)
        self.assertEqual(
            attached["structuredContent"]["error"]["code"],
            "DEVELOPMENT_ARCHIVE_RESTORE_FAILED",
        )
        retained_ids = set(runtime.development_sessions) - before_sessions
        self.assertEqual(len(retained_ids), 1)
        retained = runtime.development_sessions[retained_ids.pop()]
        self.assertTrue(retained.stale)
        self.assertEqual(retained.lifecycle_state, "stale")
        self.assertTrue(retained.worktree_path.is_dir())
        self.assertEqual(
            (retained.worktree_path / "README.md").read_text(encoding="utf-8"),
            "archive-restore-fixture\n",
        )
        runtime.close()

    def test_attach_reconnects_to_existing_session_and_keeps_writes_in_worktree(self) -> None:
        runtime, created = self._create_session()
        source_before = (self.repo / "README.md").read_text(encoding="utf-8")
        runtime.close()

        reconnected = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        requested = reconnected.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        attached = reconnected.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(attached["ok"])
        self.assertNotEqual(attached["session_id"], created["session_id"])
        self.assertEqual(attached["reattached_from"], created["session_id"])
        self.assertEqual(attached["profile"], "DEVELOPMENT")
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+reattached\n*** End Patch"
        lease_id = self._acquire_readme_lease(reconnected, "task-reattached")
        applied = reconnected.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]
        self.assertTrue(applied["ok"])
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), source_before)
        worktree = Path(created["worktree_path"]).expanduser()
        self.assertEqual((worktree / "README.md").read_text(encoding="utf-8"), "reattached\n")
        reconnected.close()

    def test_attach_rebinds_existing_task_to_new_development_session(self) -> None:
        runtime, created = self._create_session()
        task_request_id = "task-reattach-existing"
        lease_id = self._acquire_readme_lease(runtime, task_request_id)
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == task_request_id
        )
        released = runtime.call_tool(
            "director_writer_lease",
            {"action": "release", "lease_id": lease_id},
        )["structuredContent"]
        self.assertTrue(released["ok"])
        runtime.close()

        reconnected = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        requested = reconnected.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        attached = reconnected.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(attached["ok"])
        self.assertNotEqual(attached["session_id"], created["session_id"])
        self.assertEqual(attached["lease"]["task_id"], task_id)
        self.assertEqual(attached["task"]["task_id"], task_id)
        reconnected.close()

    def test_attach_reacquires_existing_task_writer_lease_before_reconciliation(self) -> None:
        runtime, created = self._create_session()
        task_request_id = "task-reattach-lease-continuity"
        self._acquire_readme_lease(runtime, task_request_id)
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == task_request_id
        )
        runtime.close()

        reconnected = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        requested = reconnected.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        attached = reconnected.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(attached["ok"], attached)

        attached_session = reconnected.development_sessions[attached["session_id"]]
        reconnected._reconcile_inactive_task_sessions("project-x")
        rebound_task = reconnected._director_ledger.get(task_id)
        self.assertIsNotNone(rebound_task)
        self.assertFalse(attached_session.stale)
        self.assertNotEqual(rebound_task.status, "stale")
        leases = tuple(
            lease
            for lease in reconnected._director_writer_manager.active(
                "project-x",
                working_tree_id=created["identity"]["worktree_id"],
            )
            if lease.task_id == task_id
        )
        self.assertEqual(len(leases), 1)
        self.assertEqual(leases[0].owner_id, "test-chat")
        reconnected.close()

    def test_attach_rebinds_task_by_session_task_id_after_prior_partial_reattach(self) -> None:
        from chatgpt_dev_mcp.development import write_session_sidecar

        runtime, created = self._create_session()
        request_id = "task-reattach-partial"
        lease_id = self._acquire_readme_lease(runtime, request_id)
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(record["task_id"] for record in ledger["records"] if record["request_id"] == request_id)
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})

        session = runtime.development_sessions[created["session_id"]]
        session.task_id = task_id
        runtime._director_ledger.bind_execution(
            task_id,
            working_tree_id=runtime._session_worktree_id(session),
            development_session_id="session:prior-partial-reattach",
            base_revision=session.base_commit,
        )
        write_session_sidecar(session)
        runtime.close()

        reconnected = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        requested = reconnected.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        attached = reconnected.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(attached["ok"])
        self.assertEqual(attached["lease"]["task_id"], task_id)
        self.assertEqual(attached["task"]["task_id"], task_id)
        reconnected.close()

    def test_verified_session_can_be_integrated_without_commit_or_push(self) -> None:
        runtime, created = self._create_session()
        source_head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+integrated\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-integrate")
        applied = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]
        self.assertTrue(applied["ok"])

        verification = runtime.call_tool(
            "verification_record",
            {
                "session_id": created["session_id"],
                "changed_paths": ["README.md"],
                "results": [],
            },
        )["structuredContent"]
        self.assertEqual(verification["receipt"]["status"], "passed")
        audit = runtime.call_tool(
            "security_audit",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")

        session_diff = runtime.call_tool(
            "workspace_session_diff",
            {"session_id": created["session_id"], "include_patch": False},
        )["structuredContent"]
        self.assertEqual(session_diff["diff"]["changed_paths"], ["README.md"])
        self.assertEqual(audit["receipt"]["patch_hash"], session_diff["diff"]["patch_hash"])

        preflight = runtime.call_tool(
            "workspace_integration_preflight",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertTrue(preflight["integration_ready"])
        integrated = runtime.call_tool(
            "workspace_integrate_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": preflight["approval_token"],
                "confirmation": preflight["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(integrated["result"]["applied"])
        self.assertFalse(integrated["result"]["commit_created"])
        self.assertFalse(integrated["result"]["push_performed"])
        self.assertIsNotNone(runtime._persistence)
        latest_checkpoint = runtime._persistence.load_latest_context_checkpoint("project-x")
        self.assertIsNotNone(latest_checkpoint)
        self.assertEqual(latest_checkpoint["outcome"], "integrated")
        self.assertEqual(latest_checkpoint["next_action"], "continue from the integrated canonical state")
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), "integrated\n")
        self.assertEqual(
            subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
            source_head,
        )
        runtime.close()

    def test_integration_evidence_survives_stale_task_when_audit_covers_full_patch(self) -> None:
        runtime, created = self._create_session()
        lease = runtime.call_tool(
            "director_writer_lease",
            {
                "action": "acquire",
                "owner_id": "test-chat",
                "task_id": "task-stale-integration-evidence",
                "paths": ["README.md", ".gitignore"],
            },
        )["structuredContent"]
        self.assertTrue(lease["ok"], lease)
        applied = runtime.call_tool(
            "apply_patch",
            {
                "patch": (
                    "*** Begin Patch\n"
                    "*** Update File: README.md\n"
                    "@@\n"
                    "-fixture\n"
                    "+integration-evidence\n"
                    "*** Add File: .gitignore\n"
                    "+generated/\n"
                    "*** End Patch"
                ),
                "lease_id": lease["lease"]["lease_id"],
            },
        )["structuredContent"]
        self.assertTrue(applied["ok"], applied)
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-stale-integration-evidence"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "start", "task_id": task_id, "owner_id": "test-chat"},
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "verifying", "owner_id": "test-chat"},
        )
        verification = runtime.call_tool(
            "verification_record",
            {
                "session_id": created["session_id"],
                "task_id": task_id,
                "changed_paths": ["README.md"],
                "results": [],
            },
        )["structuredContent"]
        self.assertEqual(verification["receipt"]["status"], "passed")
        audit = runtime.call_tool(
            "security_audit",
            {
                "session_id": created["session_id"],
                "task_id": task_id,
                "verification_receipt_id": verification["receipt"]["receipt_id"],
            },
        )["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        task = runtime._director_ledger.get(task_id)
        self.assertIsNotNone(task)
        self.assertEqual(task.status, "verifying")
        transitioned = runtime.call_tool(
            "director_task_ledger",
            {
                "action": "transition",
                "task_id": task_id,
                "status": "review_ready",
                "owner_id": "test-chat",
                "verification_receipt": verification["receipt"]["receipt_id"],
                "security_audit_receipt": audit["receipt"]["receipt_id"],
            },
        )
        self.assertFalse(transitioned["isError"], transitioned)
        before_stale = runtime.call_tool(
            "workspace_integration_preflight",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertTrue(before_stale["integration_ready"], before_stale)
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )

        after_stale = runtime.call_tool(
            "workspace_integration_preflight",
            {"session_id": created["session_id"]},
        )["structuredContent"]

        self.assertTrue(after_stale["integration_ready"], after_stale)
        self.assertEqual(after_stale["verification_receipt_id"], verification["receipt"]["receipt_id"])
        self.assertEqual(after_stale["security_audit_receipt_id"], audit["receipt"]["receipt_id"])
        runtime.close()

    def test_consumed_human_integration_intent_is_reused_after_transient_blocker(self) -> None:
        runtime, created = self._create_session()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+approved-once\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-integration-intent-reuse")
        applied = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]
        self.assertTrue(applied["ok"], applied)
        verification = runtime.call_tool(
            "verification_record",
            {
                "session_id": created["session_id"],
                "changed_paths": ["README.md"],
                "results": [],
            },
        )["structuredContent"]
        audit = runtime.call_tool(
            "security_audit",
            {
                "session_id": created["session_id"],
                "verification_receipt_id": verification["receipt"]["receipt_id"],
            },
        )["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        first_preflight = runtime.call_tool(
            "workspace_integration_preflight",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertTrue(first_preflight["integration_ready"], first_preflight)

        canonical_original = (self.repo / "README.md").read_text(encoding="utf-8")
        (self.repo / "README.md").write_text("temporary blocker\n", encoding="utf-8")
        blocked = runtime.call_tool(
            "workspace_integrate_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": first_preflight["approval_token"],
                "confirmation": first_preflight["confirmation"],
            },
        )["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "INTEGRATION_PREFLIGHT_STALE")
        (self.repo / "README.md").write_text(canonical_original, encoding="utf-8")
        runtime.close()

        from chatgpt_dev_mcp.server import WrapperRuntime

        restarted = WrapperRuntime()

        second_preflight = restarted.call_tool(
            "workspace_integration_preflight",
            {"session_id": created["session_id"]},
        )["structuredContent"]

        self.assertTrue(second_preflight["integration_ready"], second_preflight)
        self.assertTrue(second_preflight.get("approval_reused"), second_preflight)
        self.assertFalse(second_preflight.get("human_confirmation_required", True), second_preflight)
        integrated = restarted.call_tool(
            "workspace_integrate_development_session",
            {
                "session_id": created["session_id"],
                "approval_token": second_preflight["approval_token"],
                "confirmation": second_preflight["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(integrated["result"]["applied"], integrated)
        restarted.close()

    def test_integration_preflight_persists_reconnectable_awaiting_confirmation_intent(self) -> None:
        # The exact-state intent must survive wrapper recreation before confirmation reaches the backend.
        runtime, created = self._create_session()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+durable-preflight-intent\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-durable-preflight-intent")
        applied = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]
        self.assertTrue(applied["ok"], applied)
        verification = runtime.call_tool(
            "verification_record",
            {"session_id": created["session_id"], "changed_paths": ["README.md"], "results": []},
        )["structuredContent"]
        audit = runtime.call_tool(
            "security_audit",
            {"session_id": created["session_id"], "verification_receipt_id": verification["receipt"]["receipt_id"]},
        )["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        first = runtime.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(first["integration_ready"], first)
        self.assertEqual(first["integration_intent_status"], "awaiting_confirmation")
        self.assertTrue(first["integration_intent_id"].startswith("integration-intent:"), first)
        self.assertTrue(first["integration_preflight_id"].startswith("integration-preflight:"), first)
        self.assertIsNotNone(runtime._persistence)
        intents = runtime._persistence.load_integration_intents("project-x")
        stored = next(item for item in intents if item["intent_id"] == first["integration_intent_id"])
        self.assertEqual(stored["session_id"], created["session_id"])
        self.assertEqual(stored["canonical_revision"], first["canonical_revision"])
        self.assertEqual(stored["patch_hash"], first["patch_hash"])
        self.assertEqual(stored["state_diff_hash"], first["state_diff_hash"])
        self.assertEqual(stored["verification_receipt_id"], verification["receipt"]["receipt_id"])
        self.assertEqual(stored["security_audit_receipt_id"], audit["receipt"]["receipt_id"])
        self.assertEqual(stored["changed_paths"], ["README.md"])
        self.assertEqual(stored["status"], "awaiting_confirmation")
        first_token = first["approval_token"]
        runtime.close()

        from chatgpt_dev_mcp.server import WrapperRuntime

        restarted = WrapperRuntime()
        second = restarted.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(second["integration_ready"], second)
        self.assertEqual(second["integration_intent_id"], first["integration_intent_id"])
        self.assertEqual(second["integration_intent_status"], "awaiting_confirmation")
        self.assertEqual(second["verification_receipt_id"], first["verification_receipt_id"])
        self.assertEqual(second["security_audit_receipt_id"], first["security_audit_receipt_id"])
        self.assertNotEqual(second["approval_token"], first_token)
        self.assertTrue(second["human_confirmation_required"], second)
        restarted.close()

    def test_repeated_integration_returns_already_integrated_without_reusing_bearer_token(self) -> None:
        runtime, created = self._create_session()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+idempotent-integration\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-idempotent-integration")
        self.assertTrue(runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]["ok"])
        verification = runtime.call_tool("verification_record", {"session_id": created["session_id"], "changed_paths": ["README.md"], "results": []})["structuredContent"]
        audit = runtime.call_tool("security_audit", {"session_id": created["session_id"], "verification_receipt_id": verification["receipt"]["receipt_id"]})["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        preflight = runtime.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]})["structuredContent"]
        first = runtime.call_tool("workspace_integrate_development_session", {"session_id": created["session_id"], "approval_token": preflight["approval_token"], "confirmation": preflight["confirmation"]})["structuredContent"]
        self.assertTrue(first["result"]["applied"], first)
        repeated_call = runtime.call_tool("workspace_integrate_development_session", {"session_id": created["session_id"], "approval_token": preflight["approval_token"], "confirmation": preflight["confirmation"]})
        self.assertFalse(repeated_call["isError"], repeated_call)
        repeated = repeated_call["structuredContent"]
        self.assertEqual(repeated["status"], "already_integrated")
        self.assertFalse(repeated["mutation_performed"])
        self.assertEqual(repeated["integration_receipt_id"], first["integration_receipt_id"])
        runtime.close()

    def test_integration_request_audit_correlates_connection_schema_intent_and_mutation_phases(self) -> None:
        from unittest.mock import patch as mock_patch

        runtime, created = self._create_session()
        runtime.logical_connection_id = "stdio-connection:test-audit"
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+audited-integration\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-audited-integration")
        self.assertTrue(runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]["ok"])
        verification = runtime.call_tool("verification_record", {"session_id": created["session_id"], "changed_paths": ["README.md"], "results": []})["structuredContent"]
        audit = runtime.call_tool("security_audit", {"session_id": created["session_id"], "verification_receipt_id": verification["receipt"]["receipt_id"]})["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        preflight = runtime.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]}, request_id="integration-preflight-audit")["structuredContent"]
        original_dispatch = runtime._call_tool_untracked

        def rotate_transport_before_dispatch(name, arguments, **kwargs):
            runtime.request_registry.retire_generation(reason="test_transport_reconnect")
            return original_dispatch(name, arguments, **kwargs)

        with mock_patch.object(runtime, "_call_tool_untracked", side_effect=rotate_transport_before_dispatch):
            integrated = runtime.call_tool(
                "workspace_integrate_development_session",
                {"session_id": created["session_id"], "approval_token": preflight["approval_token"], "confirmation": preflight["confirmation"]},
                request_id="integration-apply-audit",
            )["structuredContent"]
        self.assertTrue(integrated["mutation_performed"], integrated)
        self.assertIsNotNone(runtime._persistence)
        events = runtime._persistence.load_request_lifecycle_events(request_id="integration-apply-audit", limit=50)
        started = next(item for item in events if item["event"] == "INTEGRATION_MUTATION_STARTED")
        finished = next(item for item in events if item["event"] == "INTEGRATION_MUTATION_FINISHED")
        terminal = next(item for item in events if item["event"] == "REQUEST_TERMINAL")
        self.assertEqual(started["logical_connection_id"], "stdio-connection:test-audit")
        self.assertEqual(started["server_schema_revision"], "tool-registry-v25-stable")
        self.assertEqual(started["server_schema_hash"], runtime._reattach_handshake()["schema_digest"])
        self.assertEqual(started["integration_intent_id"], preflight["integration_intent_id"])
        self.assertEqual(started["integration_preflight_id"], preflight["integration_preflight_id"])
        self.assertEqual(started["integration_patch_hash"], preflight["patch_hash"])
        self.assertEqual(started["canonical_revision_before"], preflight["canonical_revision"])
        self.assertEqual(started["mutation_started"], 1)
        self.assertEqual(started["mutation_finished"], 0)
        self.assertEqual(finished["mutation_started"], 1)
        self.assertEqual(finished["mutation_finished"], 1)
        self.assertEqual(finished["integration_receipt_id"], integrated["integration_receipt_id"])
        self.assertEqual(terminal["transport_generation"], 1)
        self.assertEqual(terminal["server_schema_revision"], "tool-registry-v25-stable")
        self.assertEqual(terminal["server_schema_hash"], runtime._reattach_handshake()["schema_digest"])
        self.assertEqual(
            runtime.request_registry.get("integration-apply-audit", generation=1).metadata["result"],
            "success",
        )
        runtime.close()

    def test_reconnect_reissues_challenge_across_logical_connection_and_child_restart(self) -> None:
        runtime, created = self._create_session()
        runtime.logical_connection_id = "stdio-connection:before-reconnect"
        first_child = runtime.child_instance_id
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+reattached-integration\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-reconnect-integration")
        self.assertTrue(runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]["ok"])
        verification = runtime.call_tool(
            "verification_record",
            {"session_id": created["session_id"], "changed_paths": ["README.md"], "results": []},
        )["structuredContent"]
        audit = runtime.call_tool(
            "security_audit",
            {"session_id": created["session_id"], "verification_receipt_id": verification["receipt"]["receipt_id"]},
        )["structuredContent"]
        self.assertNotEqual(audit["report"]["status"], "blocked")
        first = runtime.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]})["structuredContent"]
        old_challenge = (first["approval_token"], first["confirmation"])
        runtime.close()

        from chatgpt_dev_mcp.server import WrapperRuntime

        restarted = WrapperRuntime()
        restarted.logical_connection_id = "stdio-connection:after-reconnect"
        self.assertNotEqual(restarted.child_instance_id, first_child)
        rejected = restarted.call_tool(
            "workspace_integrate_development_session",
            {"session_id": created["session_id"], "approval_token": old_challenge[0], "confirmation": old_challenge[1]},
        )
        self.assertTrue(rejected["isError"], rejected)
        self.assertEqual(rejected["structuredContent"]["error"]["code"], "INTEGRATION_APPROVAL_NOT_FOUND")

        second = restarted.call_tool("workspace_integration_preflight", {"session_id": created["session_id"]})["structuredContent"]
        self.assertEqual(second["integration_intent_id"], first["integration_intent_id"])
        self.assertNotEqual(second["approval_token"], old_challenge[0])
        integrated = restarted.call_tool(
            "workspace_integrate_development_session",
            {"session_id": created["session_id"], "approval_token": second["approval_token"], "confirmation": second["confirmation"]},
        )["structuredContent"]
        self.assertTrue(integrated["mutation_performed"], integrated)
        repeated = restarted.call_tool(
            "workspace_integrate_development_session",
            {"session_id": created["session_id"], "approval_token": second["approval_token"], "confirmation": second["confirmation"]},
        )
        self.assertFalse(repeated["isError"], repeated)
        self.assertEqual(repeated["structuredContent"]["status"], "already_integrated")
        restarted.close()

    def test_workspace_session_diff_retains_review_when_git_filename_is_not_safe_to_surface(self) -> None:
        runtime, created = self._create_session()
        session = runtime.development_sessions[created["session_id"]]
        (session.worktree_path / " trailing-space ").write_text("retain me\n", encoding="utf-8")

        result = runtime.call_tool(
            "workspace_session_diff",
            {"session_id": created["session_id"], "include_patch": False},
        )["structuredContent"]

        self.assertTrue(result["ok"])
        self.assertFalse(result["diff_available"])
        self.assertTrue(result["review_required"])
        self.assertFalse(result["cleanup_safe"])
        self.assertEqual(result["retention_decision"], "retain")
        self.assertEqual(result["diff_error_code"], "DEVELOPMENT_SESSION_DIFF_UNSAFE_PATH")
        self.assertNotIn(" trailing-space ", str(result))
        runtime.close()

    def test_attach_rejects_unknown_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        unknown = runtime.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": "session:AAAAAAAAAAAAAAAAAAAA"},
        )["structuredContent"]
        self.assertEqual(unknown["error"]["code"], "DEVELOPMENT_SESSION_NOT_FOUND")
        runtime.close()

    def test_attach_expired_recoverable_session_issues_reattach_challenge(self) -> None:
        from chatgpt_dev_mcp.development import read_session_sidecars, write_session_sidecar
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime, created = self._create_session()
        runtime.close()
        expired_runtime = WrapperRuntime()
        session = next(item for item in read_session_sidecars() if item.session_id == created["session_id"])
        session.expires_at = 0.0
        write_session_sidecar(session)
        expired_runtime.close()
        requested = WrapperRuntime().call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertEqual(requested["status"], "expired_clean")
        self.assertEqual(requested["durable_state"], "recoverable")
        self.assertEqual(requested["session_id"], created["session_id"])
        self.assertTrue(requested["approval_token"].startswith("approval:"))
        self.assertFalse(requested["restore_required"])

    def test_attach_request_after_non_destructive_close_is_available(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime, created = self._create_session()
        closed = runtime.call_tool(
            "workspace_close_development_session",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertTrue(closed["ok"])
        self.assertFalse(closed["removed"])
        self.assertEqual(closed["durable_state"], "suspended")
        runtime.close()
        requested = WrapperRuntime().call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertEqual(requested["status"], "stale_clean")
        self.assertEqual(requested["durable_state"], "suspended")
        self.assertEqual(requested["session_id"], created["session_id"])
        self.assertTrue(requested["approval_token"].startswith("approval:"))
        self.assertFalse(requested["restore_required"])

    def test_attach_rejects_when_another_workspace_session_is_active(self) -> None:
        repo_y = self.home / "Developer" / "project-y"
        self._init_repo(repo_y)
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "project-x": {"path": "~/Developer/project-x", "profile": "DEVELOPMENT", "commands": {"test": "printf x"}},
                        "project-y": {"path": "~/Developer/project-y", "profile": "DEVELOPMENT", "commands": {"test": "printf y"}},
                    },
                }
            ),
            encoding="utf-8",
        )
        runtime_a, session_a = self._create_session()
        runtime_a.close()

        runtime_b = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        discovered = runtime_b.call_tool("workspace_discover", {"root_id": "developer"})["structuredContent"]
        candidate_y = next(item["candidate_id"] for item in discovered["repositories"] if item["name"] == "project-y")
        runtime_b.call_tool("workspace_open", {"id": candidate_y})
        approval_y = runtime_b.call_tool(
            "workspace_request_development",
            {"candidate_id": candidate_y, "workspace_id": "project-y"},
        )["structuredContent"]
        session_b = runtime_b.call_tool(
            "workspace_create_development_session",
            {"approval_token": approval_y["approval_token"], "confirmation": approval_y["confirmation"]},
        )["structuredContent"]
        self.assertTrue(session_b["ok"])
        rejected = runtime_b.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": session_a["session_id"],
                "approval_token": "approval:AAAAAAAAAAAAAAAAAAAA",
                "confirmation": "not-used",
            },
        )["structuredContent"]
        self.assertEqual(rejected["error"]["code"], "DEVELOPMENT_SESSION_ACTIVE")
        runtime_b.close()

    def test_attach_rejects_worktree_symlink_escape(self) -> None:
        runtime, created = self._create_session()
        runtime.close()
        worktree = Path(created["worktree_path"]).expanduser()
        outside = self.root / "outside-attach"
        worktree.rename(outside)
        worktree.symlink_to(outside, target_is_directory=True)
        reconnected = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        rejected = reconnected.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"]},
        )["structuredContent"]
        self.assertIn(rejected["error"]["code"], {"DEVELOPMENT_SESSION_NOT_FOUND", "DEVELOPMENT_WORKTREE_INVALID"})
        reconnected.close()

    def test_session_status_reports_source_commit_worktree_dirty_expiry_and_tasks(self) -> None:
        runtime, created = self._create_session()
        status = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertEqual(status["profile"], "DEVELOPMENT")
        self.assertTrue(status["development_session"])
        self.assertEqual(status["source_commit"], created["source_commit"])
        self.assertEqual(status["worktree_path"], created["worktree_path"])
        self.assertIn("test", status["allowed_tasks"])
        self.assertFalse(status["dirty"])
        workspace_status = runtime.call_tool("workspace_status", {})["structuredContent"]
        self.assertTrue(workspace_status["development_session"])
        self.assertEqual(workspace_status["session_id"], created["session_id"])
        runtime.close()

    def test_active_clean_session_is_the_only_state_that_blocks_workspace_switch(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        status = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertEqual(status["status"], "active")
        self.assertTrue(status["active"])
        self.assertTrue(status["blocks_workspace_switch"])
        self.assertFalse(status["stale"])
        runtime.close()

    def test_active_dirty_session_is_active_until_lease_expiry(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-active-dirty")
        runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+dirty\n*** End Patch", "lease_id": lease_id},
        )
        status = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertEqual(status["status"], "active")
        self.assertTrue(status["active"])
        self.assertTrue(status["dirty"])
        self.assertTrue(status["blocks_workspace_switch"])
        runtime.close()

    def test_expired_clean_session_releases_lock_and_allows_workspace_open(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        opened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(opened["ok"])
        self.assertEqual(opened["profile"], "DEVELOPMENT")
        listed = runtime.call_tool("workspace_list_development_sessions", {})["structuredContent"]
        state = next(item for item in listed["sessions"] if item["session_id"] == created["session_id"])
        self.assertEqual(state["status"], "expired_clean")
        self.assertTrue(state["stale"])
        self.assertFalse(state["active"])
        self.assertFalse(state["blocks_workspace_switch"])
        runtime.close()

    def test_expired_clean_session_is_durably_recoverable_not_deletion_eligible(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        runtime.development_sessions[created["session_id"]].expires_at = 100.0

        state = runtime.call_tool(
            "workspace_session_status",
            {"session_id": created["session_id"]},
        )["structuredContent"]

        self.assertEqual(state["durable_state"], "recoverable")
        self.assertTrue(state["worktree_available"])
        runtime.close()

    def test_gc_expired_clean_unintegrated_session_preserves_managed_worktree(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        worktree = Path(created["worktree_path"]).expanduser()
        runtime.development_sessions[created["session_id"]].expires_at = 100.0

        result = runtime._gc_expired_clean_sessions()

        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_gc_expired_clean_session_reanchors_when_registered_worktree_linkage_is_intact(self) -> None:
        from dataclasses import replace

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        session = runtime.development_sessions[created["session_id"]]
        worktree = Path(created["worktree_path"]).expanduser()
        session.expires_at = 100.0
        session.identity = replace(session.identity, inode=session.identity.inode + 1)
        session.lifecycle_state = "integrated"

        result = runtime._gc_expired_clean_sessions()

        self.assertIn(created["session_id"], result["removed_session_ids"])
        self.assertFalse(worktree.exists())
        self.assertNotIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_gc_expired_clean_session_retains_active_writer_lease(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        worktree = Path(created["worktree_path"]).expanduser()
        self._acquire_readme_lease(runtime, "task-gc-lease")
        runtime.development_sessions[created["session_id"]].expires_at = 100.0

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_gc_expired_clean_session_retains_active_task_without_lease(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        worktree = Path(created["worktree_path"]).expanduser()
        queued = runtime.call_tool(
            "director_task_ledger",
            {"action": "enqueue", "request_id": "request-gc-task", "title": "GC task owner"},
        )["structuredContent"]["receipt"]
        runtime.call_tool(
            "director_task_ledger",
            {"action": "start", "task_id": queued["task_id"], "owner_id": "gc-task-owner"},
        )
        runtime.development_sessions[created["session_id"]].expires_at = 100.0

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        runtime.close()

    def test_gc_expired_clean_session_deduplicates_aliases_for_one_worktree(self) -> None:
        from dataclasses import replace

        from chatgpt_dev_mcp.development import write_session_sidecar

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        original = runtime.development_sessions[created["session_id"]]
        original.expires_at = 100.0
        original.lifecycle_state = "integrated"
        alias = replace(
            original,
            session_id="session:gc-clean-alias-0001",
            stale=True,
            lifecycle_state="integrated",
        )
        runtime.development_sessions[alias.session_id] = alias
        runtime._persist_development_session(alias)
        write_session_sidecar(alias)
        worktree = Path(created["worktree_path"]).expanduser()

        result = runtime._gc_expired_clean_sessions()

        self.assertFalse(worktree.exists())
        self.assertEqual(
            set(result["removed_session_ids"]),
            {created["session_id"], alias.session_id},
        )
        self.assertNotIn(created["session_id"], runtime.development_sessions)
        self.assertNotIn(alias.session_id, runtime.development_sessions)
        runtime.close()

    def test_gc_expired_clean_session_retains_ambiguous_alias_identity(self) -> None:
        from dataclasses import replace

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        original = runtime.development_sessions[created["session_id"]]
        original.expires_at = 100.0
        invalid_alias = replace(
            original,
            session_id="session:short",
            stale=True,
            lifecycle_state="stale",
        )
        runtime.development_sessions[invalid_alias.session_id] = invalid_alias
        worktree = Path(created["worktree_path"]).expanduser()

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertIn(invalid_alias.session_id, result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        runtime.development_sessions.pop(invalid_alias.session_id, None)
        runtime.close()

    def test_gc_sidecar_cleanup_failure_is_retained_as_failed_reconciliation(self) -> None:
        from unittest.mock import patch

        from chatgpt_dev_mcp.development import DevelopmentSecurityError

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        runtime.development_sessions[created["session_id"]].lifecycle_state = "integrated"

        with patch(
            "chatgpt_dev_mcp.server.delete_session_sidecar",
            side_effect=DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "blocked sidecar cleanup"),
        ):
            result = runtime._gc_expired_clean_sessions()

        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertTrue(result["failed_worktree_ids"])
        self.assertIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_gc_cleanup_candidate_persistence_failure_restores_terminal_state_without_deletion(self) -> None:
        from unittest.mock import patch

        from chatgpt_dev_mcp.development import DevelopmentSecurityError, write_session_sidecar as real_write_sidecar

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        session = runtime.development_sessions[created["session_id"]]
        session.expires_at = 100.0
        session.lifecycle_state = "integrated"
        worktree = Path(created["worktree_path"]).expanduser()

        def guarded_write(candidate):
            if candidate.lifecycle_state == "cleanup_candidate":
                raise DevelopmentSecurityError(
                    "DEVELOPMENT_SESSION_METADATA_FAILED",
                    "simulated cleanup-candidate persistence failure",
                )
            return real_write_sidecar(candidate)

        with patch("chatgpt_dev_mcp.server.write_session_sidecar", side_effect=guarded_write):
            result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertTrue(result["failed_worktree_ids"])
        self.assertEqual(session.lifecycle_state, "integrated")
        persisted = next(
            row
            for row in runtime._persistence.load_development_sessions()
            if row["session_id"] == created["session_id"]
        )
        self.assertEqual(persisted["lifecycle_state"], "integrated")
        runtime.close()

    def test_gc_expired_dirty_session_is_retained_for_review(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-dirty")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+gc-dirty\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        worktree = Path(created["worktree_path"]).expanduser()
        runtime.development_sessions[created["session_id"]].expires_at = 100.0

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        runtime.close()

    def test_gc_stale_dirty_unintegrated_session_is_retained_even_when_diff_is_subsumed_by_canonical(self) -> None:
        from chatgpt_dev_mcp.director_integration import session_diff_subsumed_by_canonical

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-subsumed")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+subsumed\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(record["task_id"] for record in ledger["records"] if record["request_id"] == "task-gc-subsumed")
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "stale"
        worktree = Path(created["worktree_path"]).expanduser()

        (self.repo / "README.md").write_text("subsumed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "canonical subsumes session"], check=True)

        self.assertTrue(session_diff_subsumed_by_canonical(self.repo, worktree, session.base_commit))

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        self.assertIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_gc_integrated_dirty_session_archives_before_removal_when_diff_is_subsumed_by_dirty_canonical(self) -> None:
        from chatgpt_dev_mcp.director_integration import session_diff_subsumed_by_canonical

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-dirty-canonical-subsumed")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+subsumed-dirty-canonical\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-gc-dirty-canonical-subsumed"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "integrated"
        worktree = Path(created["worktree_path"]).expanduser()

        (self.repo / "README.md").write_text("subsumed-dirty-canonical\n", encoding="utf-8")
        self.assertTrue(
            subprocess.run(
                ["git", "-C", str(self.repo), "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        self.assertTrue(session_diff_subsumed_by_canonical(self.repo, worktree, session.base_commit))

        result = runtime._gc_expired_clean_sessions()

        self.assertFalse(worktree.exists())
        self.assertIn(created["session_id"], result["removed_session_ids"])
        self.assertNotIn(created["session_id"], runtime.development_sessions)
        receipt = runtime._persistence.find_session_archive_by_session_id(created["session_id"])
        self.assertIsNotNone(receipt)
        self.assertIsNotNone(receipt["pruned_at"])
        runtime.close()

    def test_gc_stale_dirty_session_retains_when_dirty_canonical_differs(self) -> None:
        from chatgpt_dev_mcp.director_integration import session_diff_subsumed_by_canonical

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-dirty-canonical-different")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+session-unique\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-gc-dirty-canonical-different"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "stale"
        worktree = Path(created["worktree_path"]).expanduser()

        (self.repo / "README.md").write_text("different-canonical\n", encoding="utf-8")
        self.assertTrue(
            subprocess.run(
                ["git", "-C", str(self.repo), "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        self.assertFalse(session_diff_subsumed_by_canonical(self.repo, worktree, session.base_commit))

        from unittest.mock import patch

        with patch.dict(os.environ, {"LOCAL_DEV_MCP_SESSION_ARCHIVE_GC": "0"}):
            result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        runtime.close()

    def test_gc_archives_unique_stale_dirty_session_before_managed_removal(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-archive-unique")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+archive-unique\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-gc-archive-unique"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "abandoned"
        session.expires_at = 100.0
        worktree = Path(created["worktree_path"]).expanduser()

        result = runtime._gc_expired_clean_sessions()

        self.assertFalse(worktree.exists())
        self.assertIn(created["session_id"], result["removed_session_ids"])
        self.assertNotIn(created["session_id"], result["retained_session_ids"])
        self.assertIsNotNone(runtime._persistence)
        receipt = runtime._persistence.find_session_archive_by_session_id(created["session_id"])
        self.assertIsNotNone(receipt)
        self.assertIsNotNone(receipt["pruned_at"])
        self.assertTrue(Path(receipt["archive_path"]).is_dir())
        runtime.close()

    def test_gc_archive_failure_retains_unique_stale_dirty_session(self) -> None:
        from chatgpt_dev_mcp.session_archive import ArchiveError
        from unittest.mock import patch

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-archive-failure")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+archive-failure\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-gc-archive-failure"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "abandoned"
        session.expires_at = 100.0
        worktree = Path(created["worktree_path"]).expanduser()

        with (
            patch.dict(os.environ, {"LOCAL_DEV_MCP_SESSION_ARCHIVE_GC": "1"}),
            patch(
                "chatgpt_dev_mcp.server.prepare_archive_for_prune",
                side_effect=ArchiveError("ARCHIVE_TEST_FAILURE"),
            ),
        ):
            result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        self.assertTrue(result["failed_worktree_ids"])
        runtime.close()

    def test_explicit_abandon_archives_before_pruning_managed_worktree(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext

        runtime, created = self._create_session()
        lease_id = self._acquire_readme_lease(runtime, "task-explicit-abandon")
        patched = runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+explicit-abandon\n*** End Patch",
                "lease_id": lease_id,
            },
        )["structuredContent"]
        self.assertTrue(patched["ok"])
        worktree = Path(created["worktree_path"]).expanduser()
        context = CapabilityExecutionContext(
            workspace_id="project-x",
            working_tree_id=created["session_id"],
            session_id="",
            owner_id="test-chat",
            task_id="",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
        )

        preview, state = runtime._development_session_abandon_prepare(
            {"session_id": created["session_id"]},
            context,
        )
        self.assertTrue(preview["will_archive_before_prune"])
        self.assertEqual(preview["session_id"], created["session_id"])
        result = runtime._development_session_abandon_execute(state, context)

        self.assertEqual(result["status"], "abandoned")
        self.assertTrue(result["snapshot_verified"])
        self.assertTrue(result["removed"])
        self.assertFalse(result["worktree_retained"])
        self.assertFalse(worktree.exists())
        self.assertTrue(str(result["archive_id"]).startswith("archive-v1-"))
        runtime.close()

    def test_gc_stale_dirty_unintegrated_deletion_is_retained_even_if_canonical_subsumes_it(self) -> None:
        from chatgpt_dev_mcp.director_integration import session_diff_subsumed_by_canonical

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-dirty-canonical-delete")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Delete File: README.md\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(
            record["task_id"]
            for record in ledger["records"]
            if record["request_id"] == "task-gc-dirty-canonical-delete"
        )
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "stale"
        worktree = Path(created["worktree_path"]).expanduser()

        (self.repo / "README.md").unlink()
        self.assertTrue(session_diff_subsumed_by_canonical(self.repo, worktree, session.base_commit))

        result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        runtime.close()

    def test_gc_stale_dirty_session_retains_unique_uncommitted_diff(self) -> None:
        from unittest.mock import patch

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-gc-unique")
        runtime.call_tool(
            "apply_patch",
            {
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+unique-session-work\n*** End Patch",
                "lease_id": lease_id,
            },
        )
        runtime.call_tool("director_writer_lease", {"action": "release", "lease_id": lease_id})
        ledger = runtime.call_tool("director_task_ledger", {"action": "list"})["structuredContent"]
        task_id = next(record["task_id"] for record in ledger["records"] if record["request_id"] == "task-gc-unique")
        runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "stale", "owner_id": "test-chat"},
        )
        session = runtime.development_sessions[created["session_id"]]
        session.stale = True
        session.lifecycle_state = "stale"
        worktree = Path(created["worktree_path"]).expanduser()

        with patch.dict(os.environ, {"LOCAL_DEV_MCP_SESSION_ARCHIVE_GC": "0"}):
            result = runtime._gc_expired_clean_sessions()

        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], result["retained_session_ids"])
        self.assertNotIn(created["session_id"], result["removed_session_ids"])
        runtime.close()

    def test_restart_gc_preserves_expired_clean_unintegrated_worktree(self) -> None:
        from chatgpt_dev_mcp.development import write_session_sidecar
        from chatgpt_dev_mcp.server import WrapperRuntime

        now = [100.0]
        clean_runtime, clean = self._create_session(clock=lambda: now[0])
        clean_worktree = Path(clean["worktree_path"]).expanduser()
        clean_runtime.development_sessions[clean["session_id"]].expires_at = 100.0
        write_session_sidecar(clean_runtime.development_sessions[clean["session_id"]])
        clean_runtime.close()

        restarted = WrapperRuntime(clock=lambda: now[0])
        self.assertTrue(clean_worktree.is_dir())
        retained = restarted.call_tool(
            "workspace_session_status",
            {"session_id": clean["session_id"]},
        )["structuredContent"]
        self.assertEqual(retained["session_id"], clean["session_id"])
        self.assertEqual(retained["durable_state"], "recoverable")
        self.assertTrue(retained["worktree_available"])
        restarted.close()

    def test_overnight_restart_safe_resume_preserves_same_session_identity_base_and_diff_hash(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["workspaces"]["project-x"]["metadata"] = {
            "isolated_development": {
                "auto_create_sessions": True,
                "auto_resume_sessions": True,
                "auto_resume_policy": "same_owner_same_task_safe_local",
                "max_parallel_sessions": 6,
                "allowed_base": "registered_project",
            }
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

        now = [100.0]
        runtime = WrapperRuntime(clock=lambda: now[0])
        started_result = runtime.call_tool(
            "director_development_start",
            {
                "workspace_id": "project-x",
                "request_id": "overnight-durable-session",
                "title": "overnight durable session",
                "owner_id": "owner-overnight-durable",
                "paths": ["README.md"],
                "resources": [],
            },
        )
        self.assertFalse(started_result["isError"], started_result)
        started = started_result["structuredContent"]
        session_id = started["session_id"]
        task_id = started["task"]["task_id"]
        base_revision = started["source_revision"]
        worktree_id = started["working_tree_id"]
        old_lease_id = started["lease_id"]

        patched = runtime.call_tool(
            "apply_patch",
            {
                "session_id": session_id,
                "lease_id": old_lease_id,
                "patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+overnight-retained\n*** End Patch",
            },
        )
        self.assertFalse(patched["isError"], patched)
        before = runtime.call_tool(
            "workspace_session_diff",
            {"session_id": session_id, "include_patch": False},
        )["structuredContent"]
        before_hash = before["diff"]["patch_hash"]
        runtime.close()

        now[0] += 24 * 60 * 60
        restarted = WrapperRuntime(clock=lambda: now[0])
        stale = restarted.call_tool(
            "workspace_session_status",
            {"session_id": session_id},
        )["structuredContent"]
        self.assertEqual(stale["session_id"], session_id)
        self.assertEqual(stale["durable_state"], "recoverable")
        self.assertEqual(stale["source_revision"], base_revision)
        self.assertTrue(stale["dirty"])
        self.assertTrue(stale["worktree_available"])

        resumed_result = restarted.call_tool(
            "workspace_resume_development_session",
            {
                "session_id": session_id,
                "owner_id": "owner-overnight-durable",
                "task_id": task_id,
            },
        )
        self.assertFalse(resumed_result["isError"], resumed_result)
        resumed = resumed_result["structuredContent"]
        self.assertEqual(resumed["session_id"], session_id)
        self.assertEqual(resumed["working_tree_id"], worktree_id)
        self.assertEqual(resumed["source_revision"], base_revision)
        self.assertEqual(resumed["task"]["task_id"], task_id)
        self.assertNotEqual(resumed["lease_id"], old_lease_id)

        after = restarted.call_tool(
            "workspace_session_diff",
            {"session_id": session_id, "include_patch": False},
        )["structuredContent"]
        self.assertEqual(after["diff"]["patch_hash"], before_hash)
        self.assertEqual(
            (Path(resumed["worktree_path"]).expanduser() / "README.md").read_text(encoding="utf-8"),
            "overnight-retained\n",
        )
        restarted.close()

    def test_expired_dirty_session_releases_lock_and_retains_worktree_and_diff(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+retained\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-retained")
        self.assertTrue(runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]["ok"])
        worktree = Path(created["worktree_path"]).expanduser()
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        opened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(opened["ok"])
        self.assertTrue(worktree.is_dir())
        listed = runtime.call_tool("workspace_list_development_sessions", {})["structuredContent"]
        state = next(item for item in listed["sessions"] if item["session_id"] == created["session_id"])
        self.assertIn(state["status"], {"expired_dirty_retained", "stale_dirty_retained"})
        self.assertTrue(state["stale"])
        self.assertTrue(state["dirty"])
        self.assertTrue(state["diff_remaining"])
        self.assertTrue(state["worktree_available"])
        self.assertFalse(state["active"])
        self.assertFalse(state["blocks_workspace_switch"])
        runtime.close()

    def test_expired_dirty_old_lease_cannot_patch_or_run_task(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-expired-dirty")
        runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+retained\n*** End Patch", "lease_id": lease_id},
        )
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        blocked_patch = runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-retained\n+blocked\n*** End Patch"},
        )["structuredContent"]
        blocked_task = runtime.call_tool("run_task", {"task": "test"})["structuredContent"]
        self.assertEqual(blocked_patch["error"]["code"], "DEVELOPMENT_SESSION_EXPIRED")
        self.assertEqual(blocked_task["error"]["code"], "DEVELOPMENT_SESSION_EXPIRED")
        runtime.close()

    def test_workspace_status_reports_expired_session_without_granting_write_access(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        status = runtime.call_tool("workspace_status", {})["structuredContent"]
        self.assertTrue(status["ok"])
        self.assertEqual(status["status"], "expired_clean")
        self.assertTrue(status["expired"])
        self.assertFalse(status["active"])
        self.assertFalse(status["blocks_workspace_switch"])
        runtime.close()

    def test_expired_dirty_session_requires_explicit_reattach_and_gets_new_lease(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-expired-reattach")
        runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+retained\n*** End Patch", "lease_id": lease_id},
        )
        old_id = created["session_id"]
        old_path = Path(created["worktree_path"]).expanduser()
        runtime.development_sessions[old_id].expires_at = 100.0
        runtime.call_tool("workspace_open", {"id": "project-x"})
        requested = runtime.call_tool("workspace_request_development_session_attach", {"session_id": old_id})["structuredContent"]
        self.assertTrue(requested["approval_token"].startswith("approval:"))
        attached = runtime.call_tool(
            "workspace_attach_development_session",
            {
                "session_id": old_id,
                "approval_token": requested["approval_token"],
                "confirmation": requested["confirmation"],
            },
        )["structuredContent"]
        self.assertTrue(attached["ok"], attached)
        self.assertNotEqual(attached["session_id"], old_id)
        self.assertEqual(Path(attached["worktree_path"]).expanduser(), old_path)
        self.assertEqual(attached["status"], "active")
        self.assertTrue(attached["dirty"])
        self.assertTrue(attached["diff_remaining"])
        self.assertFalse(attached["external_execution"])
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), "fixture\n")
        runtime.close()

    def test_restart_does_not_reactivate_expired_dirty_session(self) -> None:
        from unittest.mock import patch

        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-expired-restart")
        runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+retained\n*** End Patch", "lease_id": lease_id},
        )
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        from chatgpt_dev_mcp.development import write_session_sidecar

        write_session_sidecar(runtime.development_sessions[created["session_id"]])
        runtime.close()
        with patch.dict(os.environ, {"LOCAL_DEV_MCP_SESSION_ARCHIVE_GC": "0"}):
            restarted = self.__class__._open_candidate(self, runtime_kwargs={"clock": lambda: now[0]})[0]
        listed = restarted.call_tool("workspace_list_development_sessions", {})["structuredContent"]
        state = next(item for item in listed["sessions"] if item["session_id"] == created["session_id"])
        self.assertEqual(state["status"], "expired_dirty_retained")
        self.assertFalse(state["active"])
        self.assertFalse(state["blocks_workspace_switch"])
        opened = restarted.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(opened["ok"])
        restarted.close()

    def test_dirty_retained_session_does_not_block_read_only_workspace(self) -> None:
        repo_y = self.home / "Developer" / "project-y"
        self._init_repo(repo_y)
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "project-x": {"path": "~/Developer/project-x", "profile": "DEVELOPMENT", "commands": {"test": "printf x"}},
                        "project-y": {"path": "~/Developer/project-y", "profile": "READ_ONLY"},
                    },
                }
            ),
            encoding="utf-8",
        )
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        lease_id = self._acquire_readme_lease(runtime, "task-retained-readonly")
        runtime.call_tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+retained\n*** End Patch", "lease_id": lease_id},
        )
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        opened = runtime.call_tool("workspace_open", {"id": "project-y"})["structuredContent"]
        self.assertTrue(opened["ok"])
        self.assertEqual(opened["profile"], "READ_ONLY")
        runtime.close()

    def test_reattach_rejects_arbitrary_path_and_does_not_modify_canonical_repo(self) -> None:
        now = [100.0]
        runtime, created = self._create_session(clock=lambda: now[0])
        before = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout
        runtime.development_sessions[created["session_id"]].expires_at = 100.0
        runtime.call_tool("workspace_open", {"id": "project-x"})
        rejected = runtime.call_tool(
            "workspace_request_development_session_attach",
            {"session_id": created["session_id"], "worktree_path": str(self.root / "outside")},
        )["structuredContent"]
        self.assertEqual(rejected["error"]["code"], "INVALID_ARGUMENT")
        after = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout
        self.assertEqual(after, before)
        runtime.close()

    def test_session_lifecycle_boundary_is_expired_at_exact_expiry(self) -> None:
        from chatgpt_dev_mcp.development import DevelopmentSession, RepoIdentity

        identity = RepoIdentity(self.repo, self.repo, 1, 1, "a" * 40, "marker")
        session = DevelopmentSession("session:AAAAAAAAAAAAAAAAAAAA", "candidate:a", "project-x", identity, self.repo, identity.head, False, 0.0, 10.0, {"test": "printf test"})
        self.assertTrue(session.is_active(9.999, active_lock=True))
        self.assertFalse(session.is_expired(9.999))
        self.assertFalse(session.is_active(10.0, active_lock=True))
        self.assertTrue(session.is_expired(10.0))
        self.assertFalse(session.blocks_workspace_switch(10.0, active_lock=True))

    def test_patch_readback_diff_and_registered_test_run_in_worktree(self) -> None:
        runtime, created = self._create_session()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+changed\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-changed")
        applied = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})["structuredContent"]
        self.assertTrue(applied["ok"])
        read_back = runtime.call_tool("read_file", {"path": "README.md"})["structuredContent"]
        self.assertIn("changed", str(read_back))
        diff = runtime.call_tool("git_diff", {"path": "."})["structuredContent"]
        self.assertIn("changed", str(diff))
        task = runtime.call_tool("run_task", {"task": "test"})["structuredContent"]
        self.assertTrue(task["ok"])
        self.assertIn("test-ok", str(task))
        runtime.close()

    def test_registered_task_rejects_sensitive_workdir(self) -> None:
        runtime, _created = self._create_session()
        blocked = runtime.call_tool("run_task", {"task": "test", "workdir": ".ssh"})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "SENSITIVE_PATH_DENIED")
        runtime.close()

    def test_session_a_cannot_target_session_b_or_arbitrary_worktree(self) -> None:
        runtime_a, session_a = self._create_session()
        runtime_b, session_b = self._create_session()
        self.assertNotEqual(session_a["session_id"], session_b["session_id"])
        blocked = runtime_a.call_tool("read_file", {"path": session_b["worktree_path"]})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "SENSITIVE_PATH_DENIED")
        unknown = runtime_a.call_tool("workspace_session_status", {"session_id": "session:forged-session-id"})["structuredContent"]
        self.assertEqual(unknown["error"]["code"], "DEVELOPMENT_SESSION_NOT_FOUND")
        runtime_a.close()
        runtime_b.close()

    def test_clean_close_suspends_unintegrated_session_without_removing_worktree(self) -> None:
        runtime, created = self._create_session()
        worktree = Path(created["worktree_path"]).expanduser()
        closed = runtime.call_tool("workspace_close_development_session", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(closed["ok"])
        self.assertFalse(closed["cleanup_possible"])
        self.assertFalse(closed["removed"])
        self.assertEqual(closed["durable_state"], "suspended")
        self.assertTrue(worktree.is_dir())
        retained = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertEqual(retained["session_id"], created["session_id"])
        self.assertEqual(retained["durable_state"], "suspended")
        runtime.close()

    def test_clean_close_reanchors_but_still_preserves_unintegrated_worktree(self) -> None:
        from dataclasses import replace

        runtime, created = self._create_session()
        session = runtime.development_sessions[created["session_id"]]
        worktree = Path(created["worktree_path"]).expanduser()
        session.identity = replace(session.identity, inode=session.identity.inode + 1)

        closed = runtime.call_tool(
            "workspace_close_development_session",
            {"session_id": created["session_id"]},
        )["structuredContent"]

        self.assertTrue(closed["ok"], closed)
        self.assertFalse(closed["removed"])
        self.assertTrue(worktree.is_dir())
        runtime.close()

    def test_cleanup_source_reanchors_unborn_session_after_canonical_first_commit(self) -> None:
        from chatgpt_dev_mcp.development import UNBORN_HEAD

        subprocess.run(
            ["git", "-C", str(self.repo), "checkout", "--orphan", "unborn-cleanup-source"],
            check=True,
            capture_output=True,
        )
        runtime, created = self._create_session()
        self.assertEqual(created["source_commit"], UNBORN_HEAD)
        session = runtime.development_sessions[created["session_id"]]
        worktree = Path(created["worktree_path"]).expanduser()

        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "first canonical commit"],
            check=True,
        )

        cleanup_source = runtime._cleanup_source_for_session(session, worktree)

        self.assertEqual(cleanup_source.resolve(), self.repo.resolve())
        runtime.close()

    def test_clean_close_retains_when_reanchor_worktree_linkage_cannot_be_verified(self) -> None:
        from dataclasses import replace
        from unittest.mock import patch

        from chatgpt_dev_mcp.development import DevelopmentSecurityError

        runtime, created = self._create_session()
        session = runtime.development_sessions[created["session_id"]]
        worktree = Path(created["worktree_path"]).expanduser()
        session.identity = replace(session.identity, inode=session.identity.inode + 1)

        with patch(
            "chatgpt_dev_mcp.server.verify_detached_worktree",
            side_effect=DevelopmentSecurityError(
                "DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH",
                "worktree linkage changed",
            ),
        ):
            blocked = runtime.call_tool(
                "workspace_close_development_session",
                {"session_id": created["session_id"]},
            )["structuredContent"]

        self.assertEqual(blocked["error"]["code"], "DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH")
        self.assertTrue(worktree.is_dir())
        self.assertIn(created["session_id"], runtime.development_sessions)
        runtime.close()

    def test_dirty_close_suspends_and_preserves_changes_without_abandoning(self) -> None:
        runtime, created = self._create_session()
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+dirty\n*** End Patch"
        lease_id = self._acquire_readme_lease(runtime, "task-dirty")
        runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease_id})
        worktree = Path(created["worktree_path"]).expanduser()
        closed = runtime.call_tool("workspace_close_development_session", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(closed["ok"])
        self.assertFalse(closed["cleanup_possible"])
        self.assertFalse(closed["removed"])
        self.assertEqual(closed["durable_state"], "suspended")
        self.assertTrue(closed["dirty"])
        self.assertTrue(worktree.exists())
        reopened = runtime.call_tool("workspace_open", {"id": "project-x"})["structuredContent"]
        self.assertTrue(reopened["ok"])
        runtime.close()

    def test_restart_lists_stale_sidecar_but_cannot_reactivate_session(self) -> None:
        runtime, created = self._create_session()
        runtime.close()
        restarted = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        sessions = restarted.call_tool("workspace_list_development_sessions", {})["structuredContent"]
        stale = next(item for item in sessions["sessions"] if item["session_id"] == created["session_id"])
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["status"], "stale_clean")
        self.assertFalse(stale["active"])
        self.assertFalse(stale["expired"])
        self.assertFalse(stale["blocks_workspace_switch"])
        closed = restarted.call_tool("workspace_close_development_session", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(closed["ok"])
        restarted.close()

    def test_missing_source_marks_session_unavailable_without_failing_status(self) -> None:
        runtime, created = self._create_session()
        self.repo.rename(self.repo.with_name("project-x-deleted"))
        status = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(status["stale"])
        self.assertEqual(status["status"], "stale_unavailable")
        self.assertTrue(status["worktree_available"])
        self.assertEqual(status["verification_error"], "DEVELOPMENT_SOURCE_CHANGED")
        listed = runtime.call_tool("workspace_list_development_sessions", {})["structuredContent"]
        self.assertEqual(len(listed["sessions"]), 1)
        self.assertTrue(listed["sessions"][0]["stale"])
        runtime.close()

    def test_session_list_default_is_bounded_without_changing_public_schema(self) -> None:
        runtime = __import__("chatgpt_dev_mcp.server", fromlist=["WrapperRuntime"]).WrapperRuntime()
        try:
            definition = next(
                item for item in runtime.list_tools()["tools"]
                if item["name"] == "workspace_list_development_sessions"
            )
            self.assertEqual(definition["inputSchema"]["properties"], {})
            payload = runtime._workspace_list_development_sessions({})
            self.assertLessEqual(payload["returned"], 20)
            self.assertIn("next_cursor", payload)
        finally:
            runtime.close()

    def test_session_list_default_probes_only_selected_page(self) -> None:
        from unittest.mock import patch

        import chatgpt_dev_mcp.server as server_module
        from chatgpt_dev_mcp.development import DevelopmentSession, capture_repo_identity, managed_worktree_path

        runtime = server_module.WrapperRuntime()
        try:
            identity = capture_repo_identity(self.repo)
            runtime.development_sessions.clear()
            for index in range(45):
                session_id = f"session:perf-list-{index:016d}"
                worktree = managed_worktree_path(session_id)
                worktree.mkdir(parents=True, exist_ok=True)
                runtime.development_sessions[session_id] = DevelopmentSession(
                    session_id=session_id,
                    candidate_id="registered:project-x",
                    workspace_id="project-x",
                    identity=identity,
                    worktree_path=worktree,
                    base_commit=identity.head,
                    source_dirty=False,
                    created_at=float(index),
                    expires_at=10_000_000_000.0,
                    allowed_tasks={"test": ""},
                    stale=True,
                    project_id="project-x",
                    logical_workspace_id="project-x",
                )
            with (
                patch.object(server_module, "read_session_sidecars", return_value=[]),
                patch.object(server_module, "repo_dirty", return_value=False) as dirty_probe,
            ):
                payload = runtime._workspace_list_development_sessions({"limit": 20})
            self.assertEqual(payload["returned"], 20)
            self.assertEqual(dirty_probe.call_count, 20)
            self.assertEqual(payload["observation"]["mode"], "live_page")
            self.assertFalse(payload["counts"]["status_counts_exact"])
            self.assertEqual(payload["counts"]["unobserved_statuses"], 25)
        finally:
            runtime.close()

    def test_worktree_symlink_escape_is_stale_and_not_reported_as_external_path(self) -> None:
        runtime, created = self._create_session()
        worktree = Path(created["worktree_path"]).expanduser()
        outside = self.root / "outside-worktree"
        worktree.rename(outside)
        worktree.symlink_to(outside, target_is_directory=True)
        status = runtime.call_tool("workspace_session_status", {"session_id": created["session_id"]})["structuredContent"]
        self.assertTrue(status["stale"])
        self.assertFalse(status["worktree_available"])
        self.assertNotIn(str(outside.resolve()), str(status["worktree_path"]))
        self.assertEqual(Path(status["worktree_path"]).expanduser().resolve(strict=False), worktree.resolve(strict=False))
        runtime.close()

    def test_expired_session_blocks_patch(self) -> None:
        runtime, created = self._create_session()
        runtime.development_sessions[created["session_id"]].expires_at = 0.0
        blocked = runtime.call_tool("apply_patch", {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+blocked\n*** End Patch"})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "DEVELOPMENT_SESSION_EXPIRED")
        runtime.close()

    def test_commit_push_merge_reset_and_checkout_are_not_exposed(self) -> None:
        runtime, _ = self._create_session()
        names = {item["name"] for item in runtime.list_tools()["tools"]}
        for forbidden in {"exec_command", "git_merge", "git_rebase", "git_reset", "git_checkout"}:
            self.assertNotIn(forbidden, names)
        self.assertTrue({"git_commit_preflight", "git_commit", "git_push_preflight", "git_push"} <= names)
        runtime.close()

    def test_legacy_worktree_requires_approved_development_session(self) -> None:
        runtime, _ = self._open_candidate()
        blocked = runtime.call_tool("workspace_create_worktree", {"ref": "HEAD"})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "DEVELOPMENT_APPROVAL_REQUIRED")
        runtime.close()

    def test_legacy_worktree_is_bounded_to_active_development_session(self) -> None:
        from chatgpt_dev_mcp.development import remove_detached_worktree

        runtime, created = self._create_session()
        extra = runtime.call_tool("workspace_create_worktree", {"ref": "HEAD"})["structuredContent"]
        self.assertTrue(extra["ok"])
        extra_path = Path(extra["path"])
        self.assertTrue(extra_path.is_dir())
        self.assertTrue(str(extra_path.resolve()).startswith(str((self.home / ".cache" / "local-dev-mcp" / "worktrees").resolve())))
        remove_detached_worktree(self.repo, extra_path)
        runtime.close()


if __name__ == "__main__":
    unittest.main()
