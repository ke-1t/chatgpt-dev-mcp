from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chatgpt_dev_mcp.director import TaskLedger
from chatgpt_dev_mcp.platform_runtime import build_platform_bundle, call_platform_tool, parse_platform_config
from chatgpt_dev_mcp.platform_runtime import PlatformConfigError


BASE = "a" * 40


class PlatformE2ETests(unittest.TestCase):
    def test_capture_only_desktop_profile_parses_and_routes_snapshot_by_profile(self) -> None:
        config = parse_platform_config(
            {
                "desktop_profiles": {
                    "managed-sample-tauri": {
                        "bundle_id": "com.example.sample-app",
                        "health_url": "http://127.0.0.1:8765/health",
                        "max_screenshot_bytes": 8 * 1024 * 1024,
                    }
                }
            }
        )
        bundle = build_platform_bundle(config, project_id="fixture", ledger=TaskLedger())
        calls = []

        class CaptureBackend:
            def capture(self, root, profile):
                calls.append((Path(root), profile.identifier, profile.bundle_id))
                return {
                    "status": "captured",
                    "profile": profile.identifier,
                    "bundle_id": profile.bundle_id,
                    "screenshot_path": "output/devmcp-desktop-qa/demo.png",
                    "external_execution": False,
                }

        bundle.desktop._capture_backend = CaptureBackend()
        with tempfile.TemporaryDirectory(prefix="capture-only-e2e-") as temp:
            result = call_platform_tool(
                bundle,
                "desktop_runtime",
                root=Path(temp),
                workspace_id="fixture",
                working_tree_id="worktree-fixture",
                managed_isolated=False,
                args={"action": "snapshot", "profile_id": "managed-sample-tauri"},
                ledger=TaskLedger(),
            )
        self.assertEqual(result["status"], "captured")
        self.assertEqual(calls[0][2], "com.example.sample-app")

    def test_capture_only_desktop_profile_rejects_launch_fields(self) -> None:
        with self.assertRaises(PlatformConfigError):
            parse_platform_config(
                {
                    "command_profiles": {
                        "launch": {"argv": ["python3", "app.py"], "allowed_args": {}}
                    },
                    "desktop_profiles": {
                        "managed-mixed": {
                            "command_profile": "launch",
                            "data_dir_id": "demo-data",
                            "bundle_id": "work.fixture.desktop",
                        }
                    },
                }
            )
    def test_platform_review_records_restore_into_a_new_bundle(self) -> None:
        saved = []
        ledger = TaskLedger()
        task = ledger.enqueue("review-persistence", "fixture", "Review persistence", allowed_paths=["src/app.py"], base_revision=BASE)
        first = build_platform_bundle(
            parse_platform_config({}),
            project_id="fixture",
            ledger=ledger,
            review_on_change=lambda receipt: saved.append(receipt.as_dict()),
        )
        with tempfile.TemporaryDirectory(prefix="platform-review-persistence-") as temp:
            recorded = call_platform_tool(
                first,
                "director_review",
                root=Path(temp),
                workspace_id="fixture",
                working_tree_id="worktree-fixture",
                managed_isolated=False,
                args={
                    "action": "record",
                    "task_id": task.task_id,
                    "reviewer_id": "reviewer",
                    "base_revision": BASE,
                    "diff_hash": "b" * 64,
                    "reviewed_paths": ["src/app.py"],
                    "findings": [],
                },
                ledger=ledger,
            )
            self.assertTrue(recorded["review"]["independent"])
        self.assertEqual(len(saved), 1)
        restarted = build_platform_bundle(parse_platform_config({}), project_id="fixture", ledger=ledger, review_records=saved)
        readiness = call_platform_tool(
            restarted,
            "director_review",
            root=Path(temp),
            workspace_id="fixture",
            working_tree_id="worktree-fixture",
            managed_isolated=False,
            args={"action": "readiness", "task_id": task.task_id, "diff_hash": "b" * 64, "require_independent": True},
            ledger=ledger,
        )
        self.assertTrue(readiness["ready"])

    def test_public_dispatch_runtime_uses_session_allocator_and_compensator(self) -> None:
        ledger = TaskLedger(max_records=64)
        allocations = []
        compensations = []

        def allocate(task, owner_id):
            allocations.append((task.task_id, owner_id))
            return {
                "session_id": "session-e2e",
                "working_tree_id": "session-e2e",
                "lease_id": "lease-e2e",
            }

        def compensate(task, owner_id, allocation):
            compensations.append((task.task_id, owner_id, dict(allocation)))

        bundle = build_platform_bundle(
            parse_platform_config({}),
            project_id="fixture",
            ledger=ledger,
            dispatch_claim_allocator=allocate,
            dispatch_claim_compensator=compensate,
        )
        with tempfile.TemporaryDirectory(prefix="platform-e2e-") as temp:
            root = Path(temp)
            planned = call_platform_tool(
                bundle,
                "director_plan_work",
                root=root,
                workspace_id="fixture",
                working_tree_id="worktree-fixture",
                managed_isolated=False,
                args={
                    "request_id": "public-dispatch",
                    "base_revision": BASE,
                    "max_concurrency": 2,
                    "tasks": [{"id": "one", "title": "One", "paths": ["src/one.py"]}],
                },
                ledger=ledger,
            )
            claimed = call_platform_tool(
                bundle,
                "director_claim_task",
                root=root,
                workspace_id="fixture",
                working_tree_id="worktree-fixture",
                managed_isolated=False,
                args={"plan_id": planned["plan"]["plan_id"], "owner_id": "chat-a"},
                ledger=ledger,
            )

        self.assertEqual(claimed["status"], "claimed")
        self.assertEqual(claimed["session_allocation"], "allocated")
        self.assertEqual(claimed["session_id"], "session-e2e")
        self.assertEqual(len(allocations), 1)
        self.assertEqual(compensations, [])

    def test_wrapper_dispatch_claim_provisions_real_managed_session_and_writer_lease(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="platform-wrapper-e2e-") as temp:
            home = Path(temp) / "home"
            repo = home / "Developer" / "fixture"
            repo.mkdir(parents=True)
            (repo / "README.md").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
            base = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            config = home / ".config" / "local-dev-mcp" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workspaces": {
                            "fixture": {
                                "path": str(repo),
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "printf test-ok"},
                                "metadata": {
                                    "isolated_development": {
                                        "auto_create_sessions": True,
                                        "max_parallel_sessions": 3,
                                        "allowed_base": "registered_project",
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": str(home),
                    "LOCAL_DEV_MCP_CONFIG": str(config),
                    "LOCAL_DEV_MCP_DATA_DIR": str(home / ".director-state"),
                    "LOCAL_DEV_MCP_WORKTREE_ROOT": str(home / ".cache" / "local-dev-mcp" / "worktrees"),
                },
            ):
                runtime = WrapperRuntime()
                try:
                    opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                    binding = {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    }
                    planned = runtime.call_tool(
                        "director_plan_work",
                        {
                            **binding,
                            "request_id": "dispatch-e2e",
                            "base_revision": base,
                            "tasks": [{"id": "one", "title": "One", "paths": ["src/one.py"]}],
                        },
                    )
                    self.assertFalse(planned["isError"], planned)
                    claimed = runtime.call_tool(
                        "director_claim_task",
                        {
                            **binding,
                            "plan_id": planned["structuredContent"]["plan"]["plan_id"],
                            "owner_id": "chat-e2e",
                        },
                    )
                    self.assertFalse(claimed["isError"], claimed)
                    payload = claimed["structuredContent"]
                    self.assertEqual(payload["status"], "claimed")
                    self.assertEqual(payload["session_allocation"], "allocated")
                    self.assertTrue(payload["session_id"].startswith("session:"))
                    self.assertEqual(payload["working_tree_id"], payload["session_id"])
                    self.assertTrue(payload["lease_id"])
                    task = runtime._director_ledger.get(payload["task"]["task_id"])
                    self.assertEqual(task.status, "running")
                    self.assertEqual(task.development_session_id, payload["session_id"])
                    self.assertEqual(task.lease_id, payload["lease_id"])
                    self.assertTrue(Path(runtime.development_sessions[payload["session_id"]].worktree_path).is_dir())

                    patch_result = runtime.call_tool(
                        "apply_patch",
                        {
                            "workspace_id": "fixture",
                            "working_tree_id": payload["working_tree_id"],
                            "session_id": payload["session_id"],
                            "lease_id": payload["lease_id"],
                            "patch": "*** Begin Patch\n*** Add File: src/one.py\n+value = 1\n*** End Patch",
                        },
                    )
                    self.assertFalse(patch_result["isError"], patch_result)
                    managed_revert = patch_result["structuredContent"]["managed_revert"]
                    self.assertEqual(managed_revert["status"], "registered")
                    self.assertTrue(managed_revert["patch_id"].startswith("patch-"))
                    target = Path(runtime.development_sessions[payload["session_id"]].worktree_path) / "src" / "one.py"
                    self.assertEqual(target.read_text(encoding="utf-8"), "value = 1\n")

                    revert_binding = {
                        "workspace_id": "fixture",
                        "working_tree_id": payload["working_tree_id"],
                        "session_id": payload["session_id"],
                    }
                    revert_preflight = runtime.call_tool(
                        "patch_revert_preflight",
                        {**revert_binding, "patch_id": managed_revert["patch_id"]},
                    )
                    self.assertFalse(revert_preflight["isError"], revert_preflight)
                    revert_ready = revert_preflight["structuredContent"]
                    reverted = runtime.call_tool(
                        "patch_revert",
                        {
                            **revert_binding,
                            "preflight_id": revert_ready["preflight_id"],
                            "approval_id": revert_ready["approval"]["approval_token"],
                            "confirmation": revert_ready["approval"]["confirmation"],
                        },
                    )
                    self.assertFalse(reverted["isError"], reverted)
                    self.assertEqual(reverted["structuredContent"]["status"], "succeeded")
                    self.assertFalse(target.exists())
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
