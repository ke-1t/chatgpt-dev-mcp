from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
    )


class GitWriteMcpIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-git-mcp-")
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "MCP Git Test")
        _git(self.repo, "config", "user.email", "mcp-git-test@example.invalid")
        (self.repo / "README.md").write_text("initial\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "initial")
        _git(self.repo, "checkout", "-qb", "feature/v032")
        self.config = self.root / "config.json"
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
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)
        from chatgpt_dev_mcp.server import WrapperRuntime

        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

    def tearDown(self) -> None:
        self.runtime.close()
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        self.tempdir.cleanup()

    def _content(self, result: dict) -> dict:
        return result["structuredContent"]

    def _make_task(
        self,
        *,
        title: str = "Prepare commit",
        path: str = "README.md",
        paths: list[str] | None = None,
    ) -> str:
        queued = self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "request_id": f"request-{title.lower().replace(' ', '-')}",
                    "workspace_id": "fixture",
                    "title": title,
                    "allowed_paths": list(paths) if paths is not None else [path],
                },
            )
        )
        task_id = queued["receipt"]["task_id"]
        self._content(self.runtime.call_tool("director_task_ledger", {"action": "start", "task_id": task_id, "owner_id": "owner-a"}))
        self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {"action": "transition", "task_id": task_id, "status": "verifying", "owner_id": "owner-a"},
            )
        )
        return task_id

    def _make_evidence(
        self,
        task_id: str,
        *,
        path: str = "README.md",
        paths: list[str] | None = None,
    ) -> None:
        changed_paths = list(paths) if paths is not None else [path]
        plan = self._content(
            self.runtime.call_tool(
                "verification_plan",
                {"changed_paths": changed_paths},
            )
        )["plan"]
        tasks = list(plan["tasks"])
        results = [{"task": task, "exit_code": 0, "output": "ok"} for task in tasks]
        verification = self._content(
            self.runtime.call_tool(
                "verification_record",
                {
                    "changed_paths": changed_paths,
                    "task_id": task_id,
                    "results": results,
                },
            )
        )
        self.assertEqual(verification["receipt"]["status"], "passed")
        audit = self._content(
            self.runtime.call_tool(
                "security_audit",
                {"task_id": task_id, "verification_receipt_id": verification["receipt"]["receipt_id"]},
            )
        )
        self.assertIn(audit["receipt"]["report"]["status"], {"pass", "review"})
        transitioned = self._content(
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
        )
        self.assertEqual(transitioned["receipt"]["status"], "review_ready")

    def _prepare_staged_commit(self, *, task_title: str = "Prepare commit") -> tuple[str, dict]:
        (self.repo / "README.md").write_text("prepared\n", encoding="utf-8")
        task_id = self._make_task(title=task_title)
        self._make_evidence(task_id)
        _git(self.repo, "add", "README.md")
        preflight = self._content(
            self.runtime.call_tool(
                "git_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "commit_message": "feat: approved commit"},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)
        return task_id, preflight

    def _restart_runtime(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

    def test_uncommitted_review_ready_canonical_task_survives_restart_when_evidence_is_fresh(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "README.md").write_text("restart-safe review ready\n", encoding="utf-8")
        task_id = self._make_task(title="Restart-safe uncommitted review ready")
        self._make_evidence(task_id)

        before = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        task = next(item for item in before["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "review_ready", task)

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

        after = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        restored = next(item for item in after["records"] if item["task_id"] == task_id)
        self.assertEqual(restored["status"], "review_ready", restored)
        self.assertEqual(restored["git_commit_receipt"], "", restored)

        params = {"workspace_id": "fixture", "task_id": task_id, "paths": ["README.md"]}
        gateway = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {"workspace_id": "fixture", "capability_id": "git_stage_paths_preflight", "params": params},
            )
        )
        preflight = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway["preflight_id"],
                    "capability_id": "git_stage_paths_preflight",
                    "params": params,
                },
            )
        )["result"]
        self.assertEqual(preflight["status"], "ready", preflight)

    def test_stage_preflight_survives_wrapper_runtime_boundary(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "README.md").write_text("cross-child stage\n", encoding="utf-8")
        task_id = self._make_task(title="Cross child stage")
        self._make_evidence(task_id)

        preflight = self._content(
            self.runtime.call_tool(
                "git_stage_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)

        replacement = WrapperRuntime()
        try:
            opened = replacement.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened["isError"], opened)
            staged = replacement.call_tool(
                "git_stage",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
                    "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
                },
            )
            self.assertFalse(staged["isError"], staged)
            self.assertEqual(staged["structuredContent"]["receipt"]["status"], "succeeded")
        finally:
            replacement.close()

    def test_stage_preflight_survives_runtime_recreation(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "README.md").write_text("cross-process stage\n", encoding="utf-8")
        task_id = self._make_task(title="Cross process stage")
        self._make_evidence(task_id)
        preflight = self._content(
            self.runtime.call_tool(
                "git_stage_preflight",
                {"workspace_id": "fixture", "task_id": task_id},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)

        self.runtime.close()
        replacement = WrapperRuntime()
        try:
            opened = replacement.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened["isError"], opened)
            staged = replacement.call_tool(
                "git_stage",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
                    "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
                },
            )
            self.assertFalse(staged["isError"], staged)
            self.assertEqual(staged["structuredContent"]["receipt"]["status"], "succeeded")
        finally:
            replacement.close()
            self.runtime = WrapperRuntime()
            self.assertFalse(self.runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])

    def test_stage_claimed_before_mutation_recovers_as_not_applied_without_replay(self) -> None:
        (self.repo / "README.md").write_text("claimed but not staged\n", encoding="utf-8")
        task_id = self._make_task(title="Crash before stage mutation")
        self._make_evidence(task_id)
        preflight = self._content(
            self.runtime.call_tool("git_stage_preflight", {"workspace_id": "fixture", "task_id": task_id})
        )
        claim = self.runtime._persistence.claim_git_preflight_authority(
            preflight_id=preflight["preflight_id"],
            operation="stage",
            workspace_id="fixture",
            now=float(self.runtime._clock()),
        )
        self.assertEqual(claim["status"], "claimed", claim)
        self._restart_runtime()

        params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": preflight["preflight_id"],
            "expected_head": preflight["snapshot"]["head"],
            "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
            "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
        }
        recovered = self.runtime.call_tool("git_stage", params)
        self.assertTrue(recovered["isError"], recovered)
        self.assertEqual(recovered["structuredContent"]["error"]["code"], "GIT_STAGE_RECOVERED_NOT_APPLIED")
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")
        durable = self.runtime._persistence.load_git_preflight_authority(preflight["preflight_id"])
        self.assertEqual(durable["state"], "failed", durable)

    def test_stage_completed_before_receipt_is_recovered_after_restart_without_replay(self) -> None:
        (self.repo / "README.md").write_text("staged before crash\n", encoding="utf-8")
        task_id = self._make_task(title="Crash after stage mutation")
        self._make_evidence(task_id)
        preflight = self._content(
            self.runtime.call_tool("git_stage_preflight", {"workspace_id": "fixture", "task_id": task_id})
        )
        claim = self.runtime._persistence.claim_git_preflight_authority(
            preflight_id=preflight["preflight_id"],
            operation="stage",
            workspace_id="fixture",
            now=float(self.runtime._clock()),
        )
        self.assertEqual(claim["status"], "claimed", claim)
        _git(self.repo, "add", "README.md")
        self._restart_runtime()

        params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": preflight["preflight_id"],
            "expected_head": preflight["snapshot"]["head"],
            "expected_candidate_staged_diff_hash": preflight["candidate_staged_diff_hash"],
            "expected_candidate_index_state_hash": preflight["candidate_index_state_hash"],
        }
        recovered = self.runtime.call_tool("git_stage", params)
        self.assertFalse(recovered["isError"], recovered)
        receipt = recovered["structuredContent"]["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        self.assertTrue(receipt["receipt_id"].startswith("git-stage-recovery:"), receipt)
        durable = self.runtime._persistence.load_git_preflight_authority(preflight["preflight_id"])
        self.assertEqual(durable["state"], "succeeded", durable)
        replay = self.runtime.call_tool("git_stage", params)
        self.assertTrue(replay["isError"], replay)

    def test_commit_approval_survives_runtime_recreation_and_replay_is_rejected(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        task_id, preflight = self._prepare_staged_commit(task_title="Cross process approval")
        self.runtime.close()
        replacement = WrapperRuntime()
        try:
            opened = replacement.call_tool("workspace_open", {"id": "fixture"})
            self.assertFalse(opened["isError"], opened)
            params = {
                "workspace_id": "fixture",
                "task_id": task_id,
                "preflight_id": preflight["preflight_id"],
                "approval_token": preflight["approval"]["token"],
                "confirmation": preflight["approval"]["confirmation"],
                "commit_message": preflight["commit_message"],
                "expected_head": preflight["snapshot"]["head"],
                "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
            }
            committed = replacement.call_tool("git_commit", params)
            self.assertFalse(committed["isError"], committed)
            replay = replacement.call_tool("git_commit", params)
            self.assertTrue(replay["isError"], replay)
            self.assertIn(
                replay["structuredContent"]["error"]["code"],
                {"GIT_PREFLIGHT_NOT_FOUND", "GIT_PREFLIGHT_ALREADY_CONSUMED"},
            )
        finally:
            replacement.close()
            self.runtime = WrapperRuntime()
            self.assertFalse(self.runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])

    def test_commit_completed_before_receipt_is_recovered_after_restart_without_replay(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Crash after commit mutation")
        params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": preflight["preflight_id"],
            "approval_token": preflight["approval"]["token"],
            "confirmation": preflight["approval"]["confirmation"],
            "commit_message": preflight["commit_message"],
            "expected_head": preflight["snapshot"]["head"],
            "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
            "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
        }
        real_runner = self.runtime._git_write.default_runner

        class SimulatedProcessCrash(BaseException):
            pass

        def crash_after_commit(repo, argv, *, timeout_seconds, network):
            if argv and argv[0] == "commit":
                committed = _git(repo, *argv, check=False)
                self.assertEqual(committed.returncode, 0, committed.stderr)
                raise SimulatedProcessCrash()
            return real_runner(repo, argv, timeout_seconds=timeout_seconds, network=network)

        self.runtime._git_write._runner = crash_after_commit
        with self.assertRaises(SimulatedProcessCrash):
            self.runtime.call_tool("git_commit", params)
        committed_head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(committed_head, preflight["snapshot"]["head"])
        durable_before = self.runtime._persistence.load_git_preflight_authority(preflight["preflight_id"])
        self.assertEqual(durable_before["state"], "executing", durable_before)

        self._restart_runtime()
        recovered = self.runtime.call_tool("git_commit", params)
        self.assertFalse(recovered["isError"], recovered)
        receipt = recovered["structuredContent"]["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        self.assertTrue(receipt["receipt_id"].startswith("git-commit-recovery:"), receipt)
        self.assertEqual(receipt["head_after"], committed_head)
        durable_after = self.runtime._persistence.load_git_preflight_authority(preflight["preflight_id"])
        self.assertEqual(durable_after["state"], "succeeded", durable_after)
        replay = self.runtime.call_tool("git_commit", params)
        self.assertTrue(replay["isError"], replay)

    def test_canonical_delivery_can_verify_and_audit_across_runtime_restarts(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "README.md").write_text("restart-safe cross-call closeout\n", encoding="utf-8")
        queued = self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "enqueue",
                    "request_id": "request-cross-call-closeout",
                    "workspace_id": "fixture",
                    "title": "Cross-call canonical closeout",
                    "allowed_paths": ["README.md"],
                },
            )
        )["receipt"]
        task_id = queued["task_id"]

        self.runtime.close()
        self.runtime = WrapperRuntime()
        self.assertFalse(self.runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])
        verification = self._content(
            self.runtime.call_tool(
                "verification_record",
                {"task_id": task_id, "changed_paths": ["README.md"], "results": []},
            )
        )
        after_verification = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        verified_task = next(item for item in after_verification["records"] if item["task_id"] == task_id)
        self.assertEqual(verified_task["status"], "queued", verified_task)
        self.assertEqual(verified_task["verification_receipt"], verification["receipt"]["receipt_id"])

        self.runtime.close()
        self.runtime = WrapperRuntime()
        self.assertFalse(self.runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])
        audit = self._content(
            self.runtime.call_tool(
                "security_audit",
                {"task_id": task_id, "verification_receipt_id": verification["receipt"]["receipt_id"]},
            )
        )
        self.assertNotEqual(audit["report"]["status"], "blocked")

        self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {"action": "start", "task_id": task_id, "owner_id": "owner-cross-call"},
            )
        )
        self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {"action": "transition", "task_id": task_id, "status": "verifying", "owner_id": "owner-cross-call"},
            )
        )
        self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {
                    "action": "transition",
                    "task_id": task_id,
                    "status": "review_ready",
                    "owner_id": "owner-cross-call",
                    "verification_receipt": verification["receipt"]["receipt_id"],
                    "security_audit_receipt": audit["receipt"]["receipt_id"],
                },
            )
        )

        self.runtime.close()
        self.runtime = WrapperRuntime()
        self.assertFalse(self.runtime.call_tool("workspace_open", {"id": "fixture"})["isError"])
        restored = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        review_task = next(item for item in restored["records"] if item["task_id"] == task_id)
        self.assertEqual(review_task["status"], "review_ready", review_task)

        _git(self.repo, "add", "README.md")
        preflight = self._content(
            self.runtime.call_tool(
                "git_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "commit_message": "docs: cross-call closeout"},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)

    def test_uncommitted_review_ready_canonical_task_stales_after_restart_when_diff_drifts(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "README.md").write_text("verified before restart\n", encoding="utf-8")
        task_id = self._make_task(title="Restart review-ready drift")
        self._make_evidence(task_id)
        (self.repo / "README.md").write_text("drifted after verification\n", encoding="utf-8")

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

        listed = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        restored = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertNotEqual(restored["status"], "review_ready", restored)

    def test_manual_and_verified_git_tools_are_registered_on_current_surface(self) -> None:
        names = {tool["name"] for tool in self.runtime.list_tools()["tools"]}
        self.assertEqual(len(names), 52)
        self.assertTrue({"git_commit_preflight", "git_commit", "git_push_preflight", "git_push"} <= names)
        for capability_id in (
            "git_stage_preflight",
            "git_stage",
            "git_stage_paths_preflight",
            "git_stage_paths",
            "git_stage_hunks_preflight",
            "git_stage_hunks",
            "git_verified_commit_preflight",
            "git_verified_commit",
        ):
            self.assertNotIn(capability_id, names)
            described = self.runtime.call_tool(
                "capability_describe",
                {"capability_id": capability_id},
            )["structuredContent"]
            self.assertEqual(described["exposure"], "registry")
        stage_preflight = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage_preflight"},
        )["structuredContent"]
        stage = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage"},
        )["structuredContent"]
        self.assertEqual(stage_preflight["risk_class"], "R0")
        self.assertEqual(stage["risk_class"], "R1")
        stage_paths_preflight = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage_paths_preflight"},
        )["structuredContent"]
        stage_paths = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage_paths"},
        )["structuredContent"]
        self.assertEqual(stage_paths_preflight["risk_class"], "R0")
        self.assertEqual(stage_paths["risk_class"], "R1")
        stage_hunks_preflight = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage_hunks_preflight"},
        )["structuredContent"]
        stage_hunks = self.runtime.call_tool(
            "capability_describe",
            {"capability_id": "git_stage_hunks"},
        )["structuredContent"]
        self.assertEqual(stage_hunks_preflight["risk_class"], "R0")
        self.assertEqual(stage_hunks["risk_class"], "R1")

    def test_registry_stage_flow_stages_verified_changes_without_committing(self) -> None:
        (self.repo / "README.md").write_text("stage through gateway\n", encoding="utf-8")
        task_id = self._make_task(title="Stage through gateway")
        self._make_evidence(task_id)

        preflight_params = {"workspace_id": "fixture", "task_id": task_id}
        gateway_preflight = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage_preflight",
                    "params": preflight_params,
                },
            )
        )
        self.assertFalse(gateway_preflight["approval_required"])
        preflight_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway_preflight["preflight_id"],
                    "capability_id": "git_stage_preflight",
                    "params": preflight_params,
                },
            )
        )
        self.assertIn("result", preflight_exec, preflight_exec)
        stage_preflight = preflight_exec["result"]
        self.assertEqual(stage_preflight["status"], "ready", stage_preflight)
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")

        stage_params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": stage_preflight["preflight_id"],
            "expected_head": stage_preflight["snapshot"]["head"],
            "expected_candidate_staged_diff_hash": stage_preflight["candidate_staged_diff_hash"],
            "expected_candidate_index_state_hash": stage_preflight["candidate_index_state_hash"],
        }
        gateway_stage = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage",
                    "params": stage_params,
                },
            )
        )
        self.assertFalse(gateway_stage["approval_required"])
        staged_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway_stage["preflight_id"],
                    "capability_id": "git_stage",
                    "params": stage_params,
                },
            )
        )
        staged = staged_exec["result"]
        self.assertEqual(staged["status"], "succeeded", staged)
        self.assertEqual(staged["receipt"]["operation"], "stage")
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout.strip(), "README.md")
        self.assertEqual(_git(self.repo, "rev-list", "--count", "HEAD").stdout.strip(), "1")

    def test_registry_stage_paths_flow_stages_only_requested_verified_subset(self) -> None:
        (self.repo / "README.md").write_text("selected through gateway\n", encoding="utf-8")
        (self.repo / "later.txt").write_text("leave unstaged\n", encoding="utf-8")
        changed_paths = ["README.md"]
        task_id = self._make_task(title="Stage paths through gateway", paths=changed_paths)
        self._make_evidence(task_id, paths=changed_paths)

        preflight_params = {"workspace_id": "fixture", "task_id": task_id, "paths": ["README.md"]}
        gateway_preflight = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage_paths_preflight",
                    "params": preflight_params,
                },
            )
        )
        self.assertFalse(gateway_preflight["approval_required"])
        preflight_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway_preflight["preflight_id"],
                    "capability_id": "git_stage_paths_preflight",
                    "params": preflight_params,
                },
            )
        )
        stage_preflight = preflight_exec["result"]
        self.assertEqual(stage_preflight["status"], "ready", stage_preflight)
        self.assertEqual(stage_preflight["candidate_paths"], ["README.md"])
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")

        stage_params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": stage_preflight["preflight_id"],
            "expected_head": stage_preflight["snapshot"]["head"],
            "expected_candidate_staged_diff_hash": stage_preflight["candidate_staged_diff_hash"],
            "expected_candidate_index_state_hash": stage_preflight["candidate_index_state_hash"],
        }
        gateway_stage = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage_paths",
                    "params": stage_params,
                },
            )
        )
        self.assertFalse(gateway_stage["approval_required"])
        staged_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway_stage["preflight_id"],
                    "capability_id": "git_stage_paths",
                    "params": stage_params,
                },
            )
        )
        staged = staged_exec["result"]
        self.assertEqual(staged["status"], "succeeded", staged)
        self.assertEqual(staged["receipt"]["operation"], "stage_paths")
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout.strip(), "README.md")
        self.assertEqual(_git(self.repo, "ls-files", "--others", "--exclude-standard").stdout.strip(), "later.txt")
        self.assertEqual(_git(self.repo, "rev-list", "--count", "HEAD").stdout.strip(), "1")

    def test_registry_stage_paths_allows_subset_of_broader_verified_scope(self) -> None:
        (self.repo / "README.md").write_text("selected through broader evidence\n", encoding="utf-8")
        (self.repo / "later.txt").write_text("verified but not staged\n", encoding="utf-8")
        verified_paths = ["README.md", "later.txt"]
        task_id = self._make_task(title="Stage subset of broader evidence", paths=verified_paths)
        self._make_evidence(task_id, paths=verified_paths)

        preflight_params = {"workspace_id": "fixture", "task_id": task_id, "paths": ["README.md"]}
        gateway_preflight = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage_paths_preflight",
                    "params": preflight_params,
                },
            )
        )
        preflight_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": gateway_preflight["preflight_id"],
                    "capability_id": "git_stage_paths_preflight",
                    "params": preflight_params,
                },
            )
        )

        stage_preflight = preflight_exec["result"]
        self.assertEqual(stage_preflight["status"], "ready", stage_preflight)
        self.assertEqual(stage_preflight["candidate_paths"], ["README.md"])
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")
        self.assertEqual(_git(self.repo, "ls-files", "--others", "--exclude-standard").stdout.strip(), "later.txt")

    def test_registry_stage_paths_rejects_selection_outside_verified_scope(self) -> None:
        (self.repo / "README.md").write_text("verified change\n", encoding="utf-8")
        (self.repo / "later.txt").write_text("not verified\n", encoding="utf-8")
        task_paths = ["README.md", "later.txt"]
        task_id = self._make_task(title="Reject outside verified scope", paths=task_paths)
        self._make_evidence(task_id, paths=["README.md"])

        preflight_params = {"workspace_id": "fixture", "task_id": task_id, "paths": ["later.txt"]}
        gateway_preflight = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {
                    "workspace_id": "fixture",
                    "capability_id": "git_stage_paths_preflight",
                    "params": preflight_params,
                },
            )
        )
        result = self.runtime.call_tool(
            "capability_execute",
            {
                "workspace_id": "fixture",
                "preflight_id": gateway_preflight["preflight_id"],
                "capability_id": "git_stage_paths_preflight",
                "params": preflight_params,
            },
        )

        self.assertTrue(result["isError"], result)
        self.assertEqual(result["structuredContent"]["error"]["code"], "GIT_VERIFIED_EVIDENCE_STALE")
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")

    def test_registry_stage_hunks_flow_stages_only_selected_hunk(self) -> None:
        original = "".join(f"line-{index:02d}\n" for index in range(1, 31))
        (self.repo / "README.md").write_text(original, encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "expand fixture")
        changed = original.replace("line-03\n", "line-03 selected\n").replace("line-27\n", "line-27 later\n")
        (self.repo / "README.md").write_text(changed, encoding="utf-8")
        task_id = self._make_task(title="Stage hunk through gateway")
        self._make_evidence(task_id)

        inventory_params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "paths": ["README.md"],
            "hunk_ids": [],
        }
        inventory_gate = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {"workspace_id": "fixture", "capability_id": "git_stage_hunks_preflight", "params": inventory_params},
            )
        )
        inventory_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": inventory_gate["preflight_id"],
                    "capability_id": "git_stage_hunks_preflight",
                    "params": inventory_params,
                },
            )
        )
        inventory = inventory_exec["result"]
        self.assertEqual(inventory["status"], "selection_required", inventory)
        self.assertEqual(len(inventory["available_hunks"]), 2)
        selected_id = inventory["available_hunks"][0]["hunk_id"]

        selected_params = dict(inventory_params, hunk_ids=[selected_id])
        selected_gate = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {"workspace_id": "fixture", "capability_id": "git_stage_hunks_preflight", "params": selected_params},
            )
        )
        selected_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": selected_gate["preflight_id"],
                    "capability_id": "git_stage_hunks_preflight",
                    "params": selected_params,
                },
            )
        )
        selected = selected_exec["result"]
        self.assertEqual(selected["status"], "ready", selected)
        self.assertEqual(_git(self.repo, "diff", "--cached", "--name-only").stdout, "")

        stage_params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "paths": ["README.md"],
            "preflight_id": selected["preflight_id"],
            "expected_head": selected["snapshot"]["head"],
            "expected_candidate_patch_hash": selected["candidate_patch_hash"],
            "expected_candidate_staged_diff_hash": selected["candidate_staged_diff_hash"],
            "expected_candidate_index_state_hash": selected["candidate_index_state_hash"],
        }
        stage_gate = self._content(
            self.runtime.call_tool(
                "capability_preflight",
                {"workspace_id": "fixture", "capability_id": "git_stage_hunks", "params": stage_params},
            )
        )
        staged_exec = self._content(
            self.runtime.call_tool(
                "capability_execute",
                {
                    "workspace_id": "fixture",
                    "preflight_id": stage_gate["preflight_id"],
                    "capability_id": "git_stage_hunks",
                    "params": stage_params,
                },
            )
        )
        staged = staged_exec["result"]
        self.assertEqual(staged["status"], "succeeded", staged)
        self.assertEqual(staged["receipt"]["operation"], "stage_hunks")
        cached = _git(self.repo, "diff", "--cached", "--", "README.md").stdout
        unstaged = _git(self.repo, "diff", "--", "README.md").stdout
        self.assertIn("line-03 selected", cached)
        self.assertNotIn("line-27 later", cached)
        self.assertIn("line-27 later", unstaged)

    def test_clean_commit_binds_task_and_audit_receipts(self) -> None:
        task_id, preflight = self._prepare_staged_commit()
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        self.assertEqual(committed["receipt"]["status"], "succeeded")
        self.assertNotEqual(committed["receipt"]["head_before"], committed["receipt"]["head_after"])
        self.assertTrue(committed["receipt"]["commit_tree_hash"])
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["git_commit_receipt"], committed["receipt"]["receipt_id"])
        self.assertTrue(committed["audit_receipt"]["receipt_id"])
        self.assertEqual(_git(self.repo, "status", "--porcelain").stdout, "")

    def test_fresh_verified_task_can_explicitly_adopt_pinned_partial_stage(self) -> None:
        (self.repo / "README.md").write_text("staged version\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        (self.repo / "README.md").write_text("unstaged version\n", encoding="utf-8")
        task_id = self._make_task(title="Adopt partial stage")
        self._make_evidence(task_id)

        preflight = self._content(
            self.runtime.call_tool(
                "git_commit_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "commit_message": "feat: adopt partial stage"},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)
        self.assertTrue(preflight["partial_stage_adoption"])
        self.assertEqual(preflight["partial_stage_paths"], ["README.md"])
        self.assertIn("partial-stage adoption", preflight["approval"]["confirmation"])

        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: adopt partial stage",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        self.assertEqual(_git(self.repo, "show", "HEAD:README.md").stdout, "staged version\n")
        self.assertEqual((self.repo / "README.md").read_text(encoding="utf-8"), "unstaged version\n")
        self.assertIn(" M README.md", _git(self.repo, "status", "--porcelain").stdout)

    def test_untracked_and_staged_unstaged_mixed_state_are_blocked(self) -> None:
        task_id = self._make_task(title="Dirty commit")
        (self.repo / "README.md").write_text("staged\n", encoding="utf-8")
        (self.repo / "unstaged.txt").write_text("index\n", encoding="utf-8")
        _git(self.repo, "add", "README.md", "unstaged.txt")
        (self.repo / "unstaged.txt").write_text("worktree\n", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        result = self._content(
            self.runtime.call_tool("git_commit_preflight", {"workspace_id": "fixture", "task_id": task_id, "commit_message": "feat: blocked"})
        )
        self.assertEqual(result["status"], "blocked")
        self.assertIn("WORKTREE_NOT_STAGED_ONLY", result["blocking_codes"])
        self.assertEqual(result["snapshot"]["dirty_state"]["untracked_count"], 1)

    def test_stale_head_diff_expired_reused_and_wrong_confirmation_fail_closed(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Stale commit")
        (self.repo / "README.md").write_text("stale\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        rejected = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_COMMIT_REJECTED")
        self.assertEqual(rejected["error"]["details"]["status"], "rejected")
        replay = self._content(self.runtime.call_tool("git_commit", {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": preflight["preflight_id"],
            "approval_token": preflight["approval"]["token"],
            "confirmation": preflight["approval"]["confirmation"],
            "commit_message": "feat: approved commit",
            "expected_head": preflight["snapshot"]["head"],
            "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
            "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
        }))
        self.assertEqual(replay["error"]["code"], "GIT_PREFLIGHT_NOT_FOUND")

        task_id, preflight = self._prepare_staged_commit(task_title="Approval commit")
        wrong = dict(
            workspace_id="fixture",
            task_id=task_id,
            preflight_id=preflight["preflight_id"],
            approval_token=preflight["approval"]["token"],
            confirmation="wrong confirmation",
            commit_message="feat: approved commit",
            expected_head=preflight["snapshot"]["head"],
            expected_staged_diff_hash=preflight["snapshot"]["staged_diff_hash"],
            expected_index_state_hash=preflight["snapshot"]["index_state_hash"],
        )
        wrong_result = self._content(self.runtime.call_tool("git_commit", wrong))
        self.assertEqual(wrong_result["error"]["code"], "GIT_APPROVAL_CONFIRMATION_MISMATCH")

    def test_commit_timeout_blocks_task_without_binding_success_receipt(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Unknown commit")
        from chatgpt_dev_mcp.git_write import _CommandResult

        real_runner = self.runtime._git_write.default_runner

        def timeout_runner(repo, argv, *, timeout_seconds, network):
            if argv and argv[0] == "commit":
                return _CommandResult(124, timed_out=True)
            return real_runner(repo, argv, timeout_seconds=timeout_seconds, network=network)

        self.runtime._git_write._runner = timeout_runner
        unknown = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(unknown["error"]["code"], "GIT_COMMIT_OUTCOME_UNKNOWN")
        self.assertTrue(unknown["error"]["details"]["receipt"]["receipt_id"])
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "blocked")
        self.assertEqual(task["git_commit_receipt"], "")
        self.assertIn("outcome_unknown", task["detail"])

    def test_sensitive_file_and_detached_head_are_blocked(self) -> None:
        task_id = self._make_task(title="Sensitive commit", path="README.md")
        (self.repo / ".env").write_text("TOKEN=hidden\n", encoding="utf-8")
        _git(self.repo, "add", ".env")
        sensitive = self._content(self.runtime.call_tool("git_commit_preflight", {"workspace_id": "fixture", "task_id": task_id, "commit_message": "feat: sensitive"}))
        self.assertEqual(sensitive["status"], "blocked")
        self.assertIn("SENSITIVE_PATH_DENIED", sensitive["blocking_codes"])
        _git(self.repo, "reset", "--hard", "-q")
        _git(self.repo, "checkout", "--detach", "-q", "HEAD")
        (self.repo / "README.md").write_text("detached\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        detached = self._content(self.runtime.call_tool("git_commit_preflight", {"workspace_id": "fixture", "task_id": task_id, "commit_message": "feat: detached"}))
        self.assertEqual(detached["status"], "blocked")
        self.assertIn("DETACHED_HEAD", detached["blocking_codes"])

    def test_missing_and_invalid_remote_are_safe(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Remote preflight")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded")
        missing = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": committed["receipt"]["head_after"]}))
        self.assertEqual(missing["status"], "blocked")
        self.assertIn("REMOTE_NOT_FOUND", missing["blocking_codes"])
        invalid = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "origin;evil", "branch": "feature/v032", "expected_head": committed["receipt"]["head_after"]}))
        self.assertEqual(invalid["error"]["code"], "GIT_REMOTE_INVALID")
        _git(self.repo, "remote", "add", "unsafe", "ext::sh -c evil")
        unsafe = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "unsafe", "branch": "feature/v032", "expected_head": committed["receipt"]["head_after"]}))
        self.assertEqual(unsafe["status"], "blocked")
        self.assertIn("GIT_REMOTE_TRANSPORT_DENIED", unsafe["blocking_codes"])

    def test_successful_local_bare_push_binds_receipts(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Push commit")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded")
        bare = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        expected_head = committed["receipt"]["head_after"]
        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": expected_head},
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        pushed = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": push_preflight["preflight_id"],
                    "approval_token": push_preflight["approval"]["token"],
                    "confirmation": push_preflight["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                    "expected_remote_head": push_preflight["remote"]["expected_head"],
                    "expected_remote_url_hash": push_preflight["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(pushed.get("status"), "succeeded", pushed)
        remote_head = _git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip()
        self.assertEqual(remote_head, expected_head)
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["git_push_receipt"], pushed["receipt"]["receipt_id"])

    def test_push_completed_before_receipt_is_recovered_after_restart_without_replay(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Crash after push mutation")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": preflight["commit_message"],
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]
        bare = self.root / "crash-after-push.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": expected_head},
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        params = {
            "workspace_id": "fixture",
            "task_id": task_id,
            "preflight_id": push_preflight["preflight_id"],
            "approval_token": push_preflight["approval"]["token"],
            "confirmation": push_preflight["approval"]["confirmation"],
            "remote": "origin",
            "branch": "feature/v032",
            "expected_head": expected_head,
            "expected_remote_head": push_preflight["remote"]["expected_head"],
            "expected_remote_url_hash": push_preflight["remote"]["url_hash"],
        }
        real_runner = self.runtime._git_write.default_runner

        class SimulatedProcessCrash(BaseException):
            pass

        def crash_after_push(repo, argv, *, timeout_seconds, network):
            if argv and argv[0] == "push":
                pushed = _git(repo, *argv, check=False)
                self.assertEqual(pushed.returncode, 0, pushed.stderr)
                raise SimulatedProcessCrash()
            return real_runner(repo, argv, timeout_seconds=timeout_seconds, network=network)

        self.runtime._git_write._runner = crash_after_push
        with self.assertRaises(SimulatedProcessCrash):
            self.runtime.call_tool("git_push", params)
        remote_head = _git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip()
        self.assertEqual(remote_head, expected_head)
        durable_before = self.runtime._persistence.load_git_preflight_authority(push_preflight["preflight_id"])
        self.assertEqual(durable_before["state"], "executing", durable_before)

        self._restart_runtime()
        recovered = self.runtime.call_tool("git_push", params)
        self.assertFalse(recovered["isError"], recovered)
        receipt = recovered["structuredContent"]["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        self.assertTrue(receipt["receipt_id"].startswith("git-push-recovery:"), receipt)
        self.assertEqual(receipt["observed_remote_head"], expected_head)
        durable_after = self.runtime._persistence.load_git_preflight_authority(push_preflight["preflight_id"])
        self.assertEqual(durable_after["state"], "succeeded", durable_after)
        replay = self.runtime.call_tool("git_push", params)
        self.assertTrue(replay["isError"], replay)

    def test_push_allows_unrelated_unstaged_and_untracked_dirty_state(self) -> None:
        (self.repo / "other.txt").write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", "other.txt")
        _git(self.repo, "commit", "-qm", "add unrelated baseline")

        task_id, preflight = self._prepare_staged_commit(task_title="Push with unrelated dirty state")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]

        (self.repo / "other.txt").write_text("local only\n", encoding="utf-8")
        (self.repo / "scratch.txt").write_text("untracked local only\n", encoding="utf-8")
        bare = self.root / "dirty-push-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)

        pushed = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": push_preflight["preflight_id"],
                    "approval_token": push_preflight["approval"]["token"],
                    "confirmation": push_preflight["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                    "expected_remote_head": push_preflight["remote"]["expected_head"],
                    "expected_remote_url_hash": push_preflight["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(pushed.get("status"), "succeeded", pushed)
        self.assertEqual(_git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip(), expected_head)
        self.assertEqual((self.repo / "other.txt").read_text(encoding="utf-8"), "local only\n")
        self.assertTrue((self.repo / "scratch.txt").exists())

    def test_push_still_blocks_post_commit_staged_changes(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Push with staged drift")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]

        (self.repo / "README.md").write_text("post-commit staged drift\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        bare = self.root / "staged-drift-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "blocked", push_preflight)
        self.assertIn("WORKTREE_NOT_CLEAN", push_preflight["blocking_codes"])

    def test_exact_committed_task_can_push_after_task_is_marked_succeeded(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Succeeded commit delivery")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]
        finished = self._content(
            self.runtime.call_tool(
                "director_task_ledger",
                {"action": "finish", "task_id": task_id, "owner_id": "owner-a", "status": "succeeded"},
            )
        )
        self.assertEqual(finished["receipt"]["status"], "succeeded", finished)

        bare = self.root / "terminal-commit-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        self.assertNotIn("TASK_TERMINAL", push_preflight.get("blocking_codes", ()))

    def test_committed_canonical_task_survives_runtime_restart_for_push_preflight(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        task_id, preflight = self._prepare_staged_commit(task_title="Restart-safe push")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]
        commit_receipt_id = committed["receipt"]["receipt_id"]

        bare = self.root / "restart-safe-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

        listed = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "review_ready", task)
        self.assertEqual(task["git_commit_receipt"], commit_receipt_id)

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        self.assertNotIn("TASK_TERMINAL", push_preflight.get("blocking_codes", ()))

    def test_committed_canonical_task_survives_restart_with_unrelated_dirty_worktree(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.repo / "other.txt").write_text("baseline\n", encoding="utf-8")
        _git(self.repo, "add", "other.txt")
        _git(self.repo, "commit", "-qm", "add unrelated baseline")

        task_id, preflight = self._prepare_staged_commit(task_title="Restart-safe dirty push")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        expected_head = committed["receipt"]["head_after"]

        (self.repo / "other.txt").write_text("local-only change\n", encoding="utf-8")
        (self.repo / "scratch.txt").write_text("untracked local-only change\n", encoding="utf-8")
        bare = self.root / "restart-safe-dirty-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)

        listed = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "review_ready", task)

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        self.assertEqual((self.repo / "other.txt").read_text(encoding="utf-8"), "local-only change\n")
        self.assertTrue((self.repo / "scratch.txt").exists())

    def test_committed_task_is_not_restored_for_push_when_head_drifted_before_restart(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        task_id, preflight = self._prepare_staged_commit(task_title="Restart drift")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        (self.repo / "drift.txt").write_text("drift\n", encoding="utf-8")
        _git(self.repo, "add", "drift.txt")
        _git(self.repo, "commit", "-qm", "unrelated drift")

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)
        listed = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "stale", task)

    def test_push_preflight_rechecks_commit_outcome_after_safe_restart(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        task_id, preflight = self._prepare_staged_commit(task_title="Restart TOCTOU")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        self.assertEqual(committed["status"], "succeeded", committed)
        committed_head = committed["receipt"]["head_after"]
        bare = self.root / "restart-toctou-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))

        self.runtime.close()
        self.runtime = WrapperRuntime()
        opened = self.runtime.call_tool("workspace_open", {"id": "fixture"})
        self.assertFalse(opened["isError"], opened)
        listed = self._content(
            self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"})
        )
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "review_ready", task)

        (self.repo / "late-drift.txt").write_text("late drift\n", encoding="utf-8")
        _git(self.repo, "add", "late-drift.txt")
        _git(self.repo, "commit", "-qm", "late unrelated drift")
        drifted_head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(drifted_head, committed_head)
        rejected = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": drifted_head,
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_COMMIT_OUTCOME_STALE", rejected)

    def test_remote_default_branch_allows_guarded_fast_forward_when_not_main(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Default branch fast forward")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        expected_head = committed["receipt"]["head_after"]

        bare = self.root / "default-feature-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "push", "-q", str(bare), "HEAD^:refs/heads/feature/v032")
        _git(bare, "symbolic-ref", "HEAD", "refs/heads/feature/v032")
        _git(self.repo, "remote", "add", "origin", str(bare))

        push_preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                },
            )
        )
        self.assertEqual(push_preflight["status"], "ready", push_preflight)
        self.assertEqual(push_preflight["default_branch"], "feature/v032")
        self.assertEqual(push_preflight["protected_branch_policy"], "guarded_fast_forward")
        self.assertNotIn("PROTECTED_BRANCH_DENIED", push_preflight["blocking_codes"])
        self.assertNotIn("NON_FAST_FORWARD_DENIED", push_preflight["blocking_codes"])

    def test_main_push_allows_empty_remote_bootstrap_and_followup_fast_forward(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Bootstrap main")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        _git(self.repo, "branch", "-M", "main")
        bare = self.root / "main-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        initial_head = committed["receipt"]["head_after"]

        initial = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "main", "expected_head": initial_head},
            )
        )
        self.assertEqual(initial["status"], "ready", initial)
        self.assertEqual(initial["protected_branch_policy"], "guarded_fast_forward")
        self.assertNotIn("PROTECTED_BRANCH_DENIED", initial["blocking_codes"])
        first_push = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": initial["preflight_id"],
                    "approval_token": initial["approval"]["token"],
                    "confirmation": initial["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "main",
                    "expected_head": initial_head,
                    "expected_remote_head": "",
                    "expected_remote_url_hash": initial["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(first_push.get("status"), "succeeded", first_push)
        self.assertEqual(_git(bare, "rev-parse", "refs/heads/main").stdout.strip(), initial_head)

        (self.repo / "README.md").write_text("followup\n", encoding="utf-8")
        followup_task = self._make_task(title="Follow-up main")
        self._make_evidence(followup_task)
        _git(self.repo, "add", "README.md")
        followup_commit_preflight = self._content(
            self.runtime.call_tool(
                "git_commit_preflight",
                {"workspace_id": "fixture", "task_id": followup_task, "commit_message": "feat: follow-up main"},
            )
        )
        followup_commit = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": followup_task,
                    "preflight_id": followup_commit_preflight["preflight_id"],
                    "approval_token": followup_commit_preflight["approval"]["token"],
                    "confirmation": followup_commit_preflight["approval"]["confirmation"],
                    "commit_message": "feat: follow-up main",
                    "expected_head": followup_commit_preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": followup_commit_preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": followup_commit_preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        followup_head = followup_commit["receipt"]["head_after"]
        followup = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": followup_task, "remote": "origin", "branch": "main", "expected_head": followup_head},
            )
        )
        self.assertEqual(followup["status"], "ready", followup)
        self.assertEqual(followup["protected_branch_policy"], "guarded_fast_forward")
        self.assertEqual(followup["remote"]["expected_head"], initial_head)
        self.assertNotIn("PROTECTED_BRANCH_DENIED", followup["blocking_codes"])
        self.assertNotIn("NON_FAST_FORWARD_DENIED", followup["blocking_codes"])
        second_push = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": followup_task,
                    "preflight_id": followup["preflight_id"],
                    "approval_token": followup["approval"]["token"],
                    "confirmation": followup["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "main",
                    "expected_head": followup_head,
                    "expected_remote_head": initial_head,
                    "expected_remote_url_hash": followup["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(second_push.get("status"), "succeeded", second_push)
        self.assertEqual(_git(bare, "rev-parse", "refs/heads/main").stdout.strip(), followup_head)

    def test_initial_main_publish_requires_completely_empty_remote_and_rechecks_before_push(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Initial main safety")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        _git(self.repo, "branch", "-M", "main")
        expected_head = committed["receipt"]["head_after"]

        nonempty = self.root / "nonempty-main-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(nonempty)], check=True, capture_output=True, text=True)
        _git(self.repo, "push", "-q", str(nonempty), "HEAD:refs/heads/feature/existing")
        _git(self.repo, "remote", "add", "nonempty", str(nonempty))
        blocked = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "nonempty", "branch": "main", "expected_head": expected_head},
            )
        )
        self.assertEqual(blocked["status"], "blocked", blocked)
        self.assertIn("PROTECTED_BRANCH_DENIED", blocked["blocking_codes"])

        raced = self.root / "raced-main-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(raced)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "raced", str(raced))
        ready = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "raced", "branch": "main", "expected_head": expected_head},
            )
        )
        self.assertEqual(ready["status"], "ready", ready)
        _git(self.repo, "push", "-q", str(raced), "HEAD:refs/heads/feature/raced")
        rejected = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": ready["preflight_id"],
                    "approval_token": ready["approval"]["token"],
                    "confirmation": ready["approval"]["confirmation"],
                    "remote": "raced",
                    "branch": "main",
                    "expected_head": expected_head,
                    "expected_remote_head": "",
                    "expected_remote_url_hash": ready["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_PUSH_REJECTED", rejected)
        self.assertEqual(_git(raced, "show-ref", "--verify", "--quiet", "refs/heads/main", check=False).returncode, 1)

    def test_main_push_blocks_non_fast_forward_and_remote_movement_after_preflight(self) -> None:
        _git(self.repo, "branch", "-M", "main")
        bare = self.root / "ff-main-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        _git(self.repo, "push", "-q", str(bare), "HEAD:refs/heads/main")

        _git(self.repo, "checkout", "-qb", "remote-side", base)
        (self.repo / "remote-only.txt").write_text("remote\n", encoding="utf-8")
        _git(self.repo, "add", "remote-only.txt")
        _git(self.repo, "commit", "-qm", "remote side")
        remote_side = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        _git(self.repo, "push", "-q", str(bare), "remote-side:refs/heads/main")

        _git(self.repo, "checkout", "-q", "main")
        (self.repo / "README.md").write_text("local divergent\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "local divergent")
        local_divergent = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        divergent_task = self._make_task(title="Diverged main")
        self._make_evidence(divergent_task)
        blocked = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": divergent_task, "remote": "origin", "branch": "main", "expected_head": local_divergent},
            )
        )
        self.assertEqual(blocked["status"], "blocked", blocked)
        self.assertIn("NON_FAST_FORWARD_DENIED", blocked["blocking_codes"])
        self.assertEqual(blocked["remote"]["expected_head"], remote_side)

        _git(self.repo, "reset", "--hard", base)
        (self.repo / "README.md").write_text("local followup\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "local followup")
        local_followup = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        _git(self.repo, "push", "-q", str(bare), f"{base}:refs/heads/main", check=False)
        # Restore a known fast-forwardable remote with a normal direct update.
        _git(bare, "update-ref", "refs/heads/main", base)
        race_task = self._make_task(title="Raced main")
        self._make_evidence(race_task)
        ready = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": race_task, "remote": "origin", "branch": "main", "expected_head": local_followup},
            )
        )
        self.assertEqual(ready["status"], "ready", ready)

        _git(self.repo, "checkout", "-qb", "racer", base)
        (self.repo / "racer.txt").write_text("racer\n", encoding="utf-8")
        _git(self.repo, "add", "racer.txt")
        _git(self.repo, "commit", "-qm", "racer")
        raced_head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        _git(self.repo, "push", "-q", str(bare), "racer:refs/heads/main")
        _git(self.repo, "checkout", "-q", "main")

        rejected = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": race_task,
                    "preflight_id": ready["preflight_id"],
                    "approval_token": ready["approval"]["token"],
                    "confirmation": ready["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "main",
                    "expected_head": local_followup,
                    "expected_remote_head": base,
                    "expected_remote_url_hash": ready["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_PUSH_REJECTED", rejected)
        self.assertEqual(_git(bare, "rev-parse", "refs/heads/main").stdout.strip(), raced_head)

    def test_push_preflight_pins_configured_pushurl(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Push URL commit")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        fetch_bare = self.root / "fetch.git"
        push_bare = self.root / "push.git"
        subprocess.run(["git", "init", "--bare", "-q", str(fetch_bare)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "init", "--bare", "-q", str(push_bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(fetch_bare))
        _git(self.repo, "remote", "set-url", "--push", "origin", str(push_bare))
        expected_head = committed["receipt"]["head_after"]
        push_preflight = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": expected_head}))
        self.assertEqual(push_preflight["remote"]["display"], str(push_bare))
        pushed = self._content(self.runtime.call_tool("git_push", {"workspace_id": "fixture", "task_id": task_id, "preflight_id": push_preflight["preflight_id"], "approval_token": push_preflight["approval"]["token"], "confirmation": push_preflight["approval"]["confirmation"], "remote": "origin", "branch": "feature/v032", "expected_head": expected_head, "expected_remote_head": "", "expected_remote_url_hash": push_preflight["remote"]["url_hash"]}))
        self.assertEqual(pushed.get("status"), "succeeded", pushed)
        self.assertEqual(_git(push_bare, "rev-parse", "refs/heads/feature/v032").stdout.strip(), expected_head)

    def test_stale_remote_state_rejects_without_overwrite(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Stale remote")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        bare = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        expected_head = committed["receipt"]["head_after"]
        push_preflight = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": expected_head}))

        other = self.root / "other"
        subprocess.run(["git", "clone", "-q", str(bare), str(other)], check=True, capture_output=True, text=True)
        _git(other, "checkout", "-qb", "feature/v032")
        (other / "remote.txt").write_text("remote\n", encoding="utf-8")
        _git(other, "add", "remote.txt")
        _git(other, "config", "user.name", "Remote")
        _git(other, "config", "user.email", "remote@example.invalid")
        _git(other, "commit", "-qm", "remote advance")
        _git(other, "push", "-q", "origin", "feature/v032")

        rejected = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": push_preflight["preflight_id"],
                    "approval_token": push_preflight["approval"]["token"],
                    "confirmation": push_preflight["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                    "expected_remote_head": push_preflight["remote"]["expected_head"],
                    "expected_remote_url_hash": push_preflight["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_PUSH_REJECTED")
        self.assertEqual(rejected["error"]["details"]["status"], "rejected")
        self.assertNotEqual(_git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip(), expected_head)

    def test_non_fast_forward_is_a_normal_push_failure_without_overwrite(self) -> None:
        # Publish the common ancestor first, then diverge local and remote.
        bare = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        _git(self.repo, "push", "-q", "origin", "feature/v032")

        (self.repo / "local.txt").write_text("local\n", encoding="utf-8")
        _git(self.repo, "add", "local.txt")
        _git(self.repo, "commit", "-qm", "local advance")
        local_head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()

        other = self.root / "other-nff"
        subprocess.run(["git", "clone", "-q", str(bare), str(other)], check=True, capture_output=True, text=True)
        _git(other, "checkout", "-qB", "feature/v032", "origin/feature/v032")
        _git(other, "config", "user.name", "Remote")
        _git(other, "config", "user.email", "remote@example.invalid")
        (other / "remote.txt").write_text("remote\n", encoding="utf-8")
        _git(other, "add", "remote.txt")
        _git(other, "commit", "-qm", "remote advance")
        _git(other, "push", "-q", "origin", "feature/v032")
        remote_head = _git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip()

        task_id = self._make_task(title="Non fast forward")
        self._make_evidence(task_id)
        preflight = self._content(
            self.runtime.call_tool(
                "git_push_preflight",
                {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": local_head},
            )
        )
        self.assertEqual(preflight["status"], "ready", preflight)
        self.assertEqual(preflight["remote"]["expected_head"], remote_head)
        rejected = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": local_head,
                    "expected_remote_head": remote_head,
                    "expected_remote_url_hash": preflight["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(rejected["error"]["code"], "GIT_PUSH_FAILED")
        self.assertEqual(rejected["error"]["details"]["status"], "failed")
        self.assertEqual(_git(bare, "rev-parse", "refs/heads/feature/v032").stdout.strip(), remote_head)
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["git_push_receipt"], "")
        self.assertIn("failed", task["detail"])

    def test_push_timeout_is_outcome_unknown_and_not_success(self) -> None:
        task_id, preflight = self._prepare_staged_commit(task_title="Unknown push")
        committed = self._content(
            self.runtime.call_tool(
                "git_commit",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": preflight["preflight_id"],
                    "approval_token": preflight["approval"]["token"],
                    "confirmation": preflight["approval"]["confirmation"],
                    "commit_message": "feat: approved commit",
                    "expected_head": preflight["snapshot"]["head"],
                    "expected_staged_diff_hash": preflight["snapshot"]["staged_diff_hash"],
                    "expected_index_state_hash": preflight["snapshot"]["index_state_hash"],
                },
            )
        )
        bare = self.root / "unknown-remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True, text=True)
        _git(self.repo, "remote", "add", "origin", str(bare))
        expected_head = committed["receipt"]["head_after"]
        push_preflight = self._content(self.runtime.call_tool("git_push_preflight", {"workspace_id": "fixture", "task_id": task_id, "remote": "origin", "branch": "feature/v032", "expected_head": expected_head}))
        from chatgpt_dev_mcp.git_write import _CommandResult

        real_runner = self.runtime._git_write.default_runner

        def timeout_runner(repo, argv, *, timeout_seconds, network):
            if argv and argv[0] == "push":
                return _CommandResult(124, timed_out=True)
            return real_runner(repo, argv, timeout_seconds=timeout_seconds, network=network)

        self.runtime._git_write._runner = timeout_runner
        unknown = self._content(
            self.runtime.call_tool(
                "git_push",
                {
                    "workspace_id": "fixture",
                    "task_id": task_id,
                    "preflight_id": push_preflight["preflight_id"],
                    "approval_token": push_preflight["approval"]["token"],
                    "confirmation": push_preflight["approval"]["confirmation"],
                    "remote": "origin",
                    "branch": "feature/v032",
                    "expected_head": expected_head,
                    "expected_remote_head": "",
                    "expected_remote_url_hash": push_preflight["remote"]["url_hash"],
                },
            )
        )
        self.assertEqual(unknown["error"]["code"], "GIT_PUSH_OUTCOME_UNKNOWN")
        self.assertEqual(unknown["error"]["details"]["status"], "outcome_unknown")
        self.assertTrue(unknown["error"]["details"]["receipt"]["receipt_id"])
        listed = self._content(self.runtime.call_tool("director_task_ledger", {"action": "list", "workspace_id": "fixture"}))
        task = next(item for item in listed["records"] if item["task_id"] == task_id)
        self.assertEqual(task["status"], "blocked")
        self.assertEqual(task["git_push_receipt"], "")
        self.assertIn("outcome_unknown", task["detail"])
        self.assertFalse(_git(bare, "show-ref", "--verify", "--quiet", "refs/heads/feature/v032", check=False).returncode == 0)


if __name__ == "__main__":
    unittest.main()
