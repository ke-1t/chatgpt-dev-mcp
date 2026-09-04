from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.git_write import GitTaskBinding, GitWriteController, GitWriteError


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
    )


class VerifiedAutoCommitControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="verified-auto-commit-")
        self.repo = Path(self.tempdir.name) / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q", "-b", "feature/verified")
        _git(self.repo, "config", "user.name", "Verified Commit Test")
        _git(self.repo, "config", "user.email", "verified@example.invalid")
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "initial")
        self.controller = GitWriteController()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _task(*, allowed_paths: tuple[str, ...] = ("README.md", "new.txt"), status: str = "review_ready") -> GitTaskBinding:
        return GitTaskBinding(
            task_id="task-verified",
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            status=status,
            allowed_paths=allowed_paths,
            verification_receipt_id="verify:verified",
            security_audit_receipt_id="audit:verified",
            evidence_valid=True,
            title="Add verified commit",
        )

    def test_verified_preflight_is_read_only_and_includes_untracked(self) -> None:
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        (self.repo / "new.txt").write_text("new\n", encoding="utf-8")
        before_index = _git(self.repo, "ls-files", "--stage").stdout

        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=self._task(),
        )

        self.assertEqual(preflight.status, "ready", preflight.as_dict())
        self.assertEqual(preflight.candidate_paths, ("README.md", "new.txt"))
        self.assertTrue(preflight.candidate_staged_diff_hash)
        self.assertTrue(preflight.candidate_index_state_hash)
        self.assertEqual(preflight.commit_message, "chore: Add verified commit")
        self.assertEqual(_git(self.repo, "ls-files", "--stage").stdout, before_index)
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")

    def test_verified_commit_accepts_untracked_directory_scope_and_pins_leaf_paths(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: CI\n", encoding="utf-8")
        task = self._task(allowed_paths=(".github",))

        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=task,
        )

        self.assertEqual(preflight.status, "ready", preflight.as_dict())
        self.assertEqual(preflight.candidate_paths, (".github",))
        self.assertEqual(preflight.candidate_leaf_paths, (".github/workflows/ci.yml",))
        receipt = self.controller.verified_commit(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task_resolver=lambda _task_id: task,
            preflight_id=preflight.preflight_id,
            expected_head=preflight.snapshot.head,
            expected_candidate_staged_diff_hash=preflight.candidate_staged_diff_hash,
            expected_candidate_index_state_hash=preflight.candidate_index_state_hash,
        )
        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(
            _git(self.repo, "diff", "--name-only", "HEAD^", "HEAD").stdout.splitlines(),
            [".github/workflows/ci.yml"],
        )
        self.assertEqual(_git(self.repo, "status", "--porcelain").stdout, "")

    def test_verified_preflight_handles_large_candidate_without_binary_diff_capture(self) -> None:
        large = self.repo / "large.txt"
        large.write_text("x" * (5 * 1024 * 1024), encoding="utf-8")
        task = self._task(allowed_paths=("large.txt",))

        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=task,
        )

        self.assertEqual(preflight.status, "ready", preflight.as_dict())
        self.assertEqual(preflight.candidate_leaf_paths, ("large.txt",))
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")
        receipt = self.controller.verified_commit(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task_resolver=lambda _task_id: task,
            preflight_id=preflight.preflight_id,
            expected_head=preflight.snapshot.head,
            expected_candidate_staged_diff_hash=preflight.candidate_staged_diff_hash,
            expected_candidate_index_state_hash=preflight.candidate_index_state_hash,
        )
        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(_git(self.repo, "status", "--porcelain").stdout, "")

    def test_verified_preflight_still_blocks_sensitive_candidate_content(self) -> None:
        candidate_file = self.repo / "config.txt"
        marker = "api" + "_key" + "=" + "redactedfixturevalue123456789"
        candidate_file.write_text(marker + "\n", encoding="utf-8")

        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=self._task(allowed_paths=("config.txt",)),
        )

        self.assertEqual(preflight.status, "blocked", preflight.as_dict())
        self.assertIn("SENSITIVE_CONTENT_DENIED", preflight.blocking_codes)

    def test_verified_preflight_blocks_real_staged_state_and_out_of_scope_paths(self) -> None:
        (self.repo / "README.md").write_text("staged\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        staged = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=self._task(),
        )
        self.assertEqual(staged.status, "blocked")
        self.assertIn("REAL_INDEX_NOT_EMPTY", staged.blocking_codes)

        _git(self.repo, "reset", "--hard", "-q")
        (self.repo / "outside.txt").write_text("outside\n", encoding="utf-8")
        outside = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=self._task(allowed_paths=("README.md",)),
        )
        self.assertEqual(outside.status, "blocked")
        self.assertIn("TASK_PATH_OUTSIDE_SCOPE", outside.blocking_codes)

    def test_verified_commit_revalidates_and_commits_without_human_approval(self) -> None:
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        (self.repo / "new.txt").write_text("new\n", encoding="utf-8")
        task = self._task()
        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=task,
        )
        before = _git(self.repo, "rev-parse", "HEAD").stdout.strip()

        receipt = self.controller.verified_commit(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task_resolver=lambda _task_id: task,
            preflight_id=preflight.preflight_id,
            expected_head=preflight.snapshot.head,
            expected_candidate_staged_diff_hash=preflight.candidate_staged_diff_hash,
            expected_candidate_index_state_hash=preflight.candidate_index_state_hash,
        )

        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(receipt.operation, "verified_commit")
        self.assertEqual(receipt.head_before, before)
        self.assertNotEqual(receipt.head_after, before)
        self.assertEqual(_git(self.repo, "show", "-s", "--format=%s", "HEAD").stdout.strip(), "chore: Add verified commit")
        self.assertEqual(_git(self.repo, "diff", "--name-only", "HEAD^", "HEAD").stdout.splitlines(), ["README.md", "new.txt"])
        self.assertEqual(_git(self.repo, "status", "--porcelain").stdout, "")

    def test_verified_commit_rejects_stale_candidate_before_staging(self) -> None:
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        task = self._task(allowed_paths=("README.md",))
        preflight = self.controller.verified_commit_preflight(
            self.repo,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            task=task,
        )
        (self.repo / "README.md").write_text("changed again\n", encoding="utf-8")

        with self.assertRaises(GitWriteError) as raised:
            self.controller.verified_commit(
                self.repo,
                workspace_id="fixture",
                working_tree_id="worktree:fixture",
                task_resolver=lambda _task_id: task,
                preflight_id=preflight.preflight_id,
                expected_head=preflight.snapshot.head,
                expected_candidate_staged_diff_hash=preflight.candidate_staged_diff_hash,
                expected_candidate_index_state_hash=preflight.candidate_index_state_hash,
            )
        self.assertEqual(raised.exception.code, "GIT_VERIFIED_COMMIT_REJECTED")
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")
        self.assertEqual(_git(self.repo, "rev-parse", "HEAD").stdout.strip(), preflight.snapshot.head)


class VerifiedAutoCommitMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="verified-auto-commit-mcp-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q", "-b", "feature/verified")
        _git(self.repo, "config", "user.name", "Verified MCP Test")
        _git(self.repo, "config", "user.email", "verified-mcp@example.invalid")
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "initial")
        self.config = self.root / "config.json"
        self._write_config(enabled=True)
        self.previous = {
            key: os.environ.get(key)
            for key in ("LOCAL_DEV_MCP_CONFIG", "LOCAL_DEV_MCP_DATA_DIR", "LOCAL_DEV_MCP_WORKTREE_ROOT")
        }
        os.environ.update(
            {
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.root / "worktrees"),
            }
        )
        from chatgpt_dev_mcp.server import WrapperRuntime

        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

    def tearDown(self) -> None:
        self.runtime.close()
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def _write_config(self, *, enabled: bool) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": str(self.root), "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                            "isolated_development": {
                                "auto_create_sessions": True,
                                "auto_resume_sessions": True,
                                "auto_resume_policy": "same_owner_same_task_safe_local",
                                "max_parallel_sessions": 2,
                                "allowed_base": "registered_project",
                                "allow_workspace_wide": False,
                                "integration_requires_approval": True,
                                "commit_requires_approval": True,
                                "push_requires_approval": True,
                                "verified_auto_commit": enabled,
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _content(result: dict) -> dict:
        return result["structuredContent"]

    def _ready_task(self, *, title: str = "Add verified commit") -> str:
        queued = self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "request_id": f"request-{title.lower().replace(' ', '-')}",
                    "workspace_id": "fixture",
                    "title": title,
                    "allowed_paths": ["README.md"],
                },
            )
        )
        task_id = queued["receipt"]["task_id"]
        self.runtime.call_tool("director_task_ledger", {"action": "start", "task_id": task_id, "owner_id": "owner-a"})
        self.runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "verifying", "owner_id": "owner-a"},
        )
        verification = self._content(
            self.runtime.call_tool(
                "verification_record",
                {
                    "changed_paths": ["README.md"],
                    "task_id": task_id,
                    "results": [],
                },
            )
        )
        audit = self._content(
            self.runtime.call_tool(
                "security_audit",
                {"task_id": task_id, "verification_receipt_id": verification["receipt"]["receipt_id"]},
            )
        )
        self.assertNotEqual(audit["receipt"]["report"]["status"], "blocked")
        self.runtime.call_tool(
            "director_task_ledger",
            {
                "action": "transition",
                "task_id": task_id,
                "status": "review_ready",
                "owner_id": "owner-a",
                "verification_receipt": verification["receipt"]["receipt_id"],
                "security_audit_receipt": audit["receipt"]["receipt_id"],
            },
        )
        return task_id

    def _ready_scoped_task(self, *, title: str, allowed_path: str, verification_path: str) -> str:
        queued = self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "request_id": f"request-{title.lower().replace(' ', '-')}",
                    "workspace_id": "fixture",
                    "title": title,
                    "allowed_paths": [allowed_path],
                },
            )
        )
        task_id = queued["receipt"]["task_id"]
        self.runtime.call_tool("director_task_ledger", {"action": "start", "task_id": task_id, "owner_id": "owner-a"})
        self.runtime.call_tool(
            "director_task_ledger",
            {"action": "transition", "task_id": task_id, "status": "verifying", "owner_id": "owner-a"},
        )
        verification = self._content(
            self.runtime.call_tool(
                "verification_record",
                {
                    "changed_paths": [verification_path],
                    "task_id": task_id,
                    "results": [{"task": "test", "exit_code": 0, "output": "directory scope regression passed"}],
                },
            )
        )
        audit = self._content(
            self.runtime.call_tool(
                "security_audit",
                {"task_id": task_id, "verification_receipt_id": verification["receipt"]["receipt_id"]},
            )
        )
        self.assertNotEqual(audit["receipt"]["report"]["status"], "blocked")
        self.runtime.call_tool(
            "director_task_ledger",
            {
                "action": "transition",
                "task_id": task_id,
                "status": "review_ready",
                "owner_id": "owner-a",
                "verification_receipt": verification["receipt"]["receipt_id"],
                "security_audit_receipt": audit["receipt"]["receipt_id"],
            },
        )
        return task_id

    def test_mcp_verified_commit_is_approval_free_but_manual_commit_stays_approval_gated(self) -> None:
        (self.repo / "README.md").write_text("verified\n", encoding="utf-8")
        task_id = self._ready_task()
        preflight = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)
        self.assertIsNone(preflight["approval"])
        self.assertFalse(preflight["human_confirmation_required"])
        committed = self._content(
            self.runtime.call_tool(
                "git_verified_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
                    "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        self.assertEqual(committed["receipt"]["operation"], "verified_commit")
        replayed = self._content(
            self.runtime.call_tool(
                "git_verified_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
                    "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
                },
            )
        )
        self.assertTrue(replayed["idempotent_replay"], replayed)
        self.assertEqual(replayed["receipt"]["receipt_id"], committed["receipt"]["receipt_id"])
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["git_commit_receipt"], committed["receipt"]["receipt_id"])

        (self.repo / "README.md").write_text("manual\n", encoding="utf-8")
        manual_task = self._ready_task(title="Manual approval remains")
        _git(self.repo, "add", "README.md")
        manual = self._content(
            self.runtime.call_tool(
                "git_commit_preflight",
                {"workspace_id": "fixture", "task_id": manual_task, "commit_message": "chore: manual path"},
            )
        )
        self.assertEqual(manual["status"], "ready", manual)
        self.assertIsNotNone(manual["approval"])
        self.assertTrue(manual["approval"]["human_confirmation_required"])

    def test_mcp_verified_preflight_rejects_stale_evidence(self) -> None:
        (self.repo / "README.md").write_text("verified\n", encoding="utf-8")
        task_id = self._ready_task(title="Stale evidence")
        (self.repo / "README.md").write_text("changed after audit\n", encoding="utf-8")
        result = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(result["error"]["code"], "GIT_VERIFIED_EVIDENCE_STALE")

    def test_mcp_verified_preflight_accepts_directory_scope_for_more_than_128_tracked_files(self) -> None:
        bulk = self.repo / "bulk"
        bulk.mkdir()
        (self.repo / ".gitignore").write_text("bulk/ignored/\n", encoding="utf-8")
        for index in range(129):
            (bulk / f"item-{index:03d}.txt").write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", ".gitignore", "bulk")
        _git(self.repo, "commit", "-qm", "bulk baseline")
        for index in range(129):
            (bulk / f"item-{index:03d}.txt").write_text(f"changed {index}\n", encoding="utf-8")

        task_id = self._ready_scoped_task(
            title="Directory scoped verification",
            allowed_path="bulk",
            verification_path="bulk",
        )
        ignored = bulk / "ignored" / "generated.tmp"
        ignored.parent.mkdir()
        ignored.write_text("ignored generation should not invalidate Git evidence\n", encoding="utf-8")
        preflight = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )

        self.assertNotIn("error", preflight, preflight)
        self.assertEqual(preflight["status"], "ready", preflight)
        self.assertEqual(len(preflight["candidate_leaf_paths"]), 129)

    def test_mcp_verified_preflight_accepts_new_untracked_directory_scope(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: CI\n", encoding="utf-8")
        task_id = self._ready_scoped_task(
            title="CI directory scope",
            allowed_path=".github",
            verification_path=".github",
        )

        preflight = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )

        self.assertEqual(preflight["status"], "ready", preflight)
        self.assertEqual(preflight["candidate_paths"], [".github"])
        self.assertEqual(preflight["candidate_leaf_paths"], [".github/workflows/ci.yml"])

    def test_mcp_directory_scoped_evidence_becomes_stale_when_descendant_changes(self) -> None:
        bulk = self.repo / "bulk"
        bulk.mkdir()
        child = bulk / "item.txt"
        child.write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", "bulk")
        _git(self.repo, "commit", "-qm", "bulk baseline")
        child.write_text("verified\n", encoding="utf-8")
        task_id = self._ready_scoped_task(
            title="Directory scoped stale evidence",
            allowed_path="bulk",
            verification_path="bulk",
        )
        child.write_text("changed after audit\n", encoding="utf-8")

        result = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(result["error"]["code"], "GIT_VERIFIED_EVIDENCE_STALE")

    def test_mcp_verified_preflight_honors_policy_disable(self) -> None:
        self.runtime.close()
        self._write_config(enabled=False)
        from chatgpt_dev_mcp.server import WrapperRuntime

        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)
        (self.repo / "README.md").write_text("verified\n", encoding="utf-8")
        task_id = self._ready_task(title="Policy disabled")
        result = self._content(
            self.runtime.call_tool(
                "git_verified_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(result["error"]["code"], "GIT_VERIFIED_AUTO_COMMIT_DISABLED")


if __name__ == "__main__":
    unittest.main()
