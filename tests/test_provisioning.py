from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ProvisioningToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-provisioning-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.developer = self.home / "Developer"
        self.developer.mkdir(parents=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self._write_config({})
        self.previous = {key: os.environ.get(key) for key in ("HOME", "LOCAL_DEV_MCP_CONFIG", "LOCAL_DEV_MCP_DATA_DIR", "LOCAL_DEV_MCP_WORKTREE_ROOT")}
        os.environ.update(
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.root / "worktrees"),
            }
        )

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def _write_config(self, workspaces: dict[str, object]) -> None:
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": workspaces,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _git(path: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(path), *args], check=False, capture_output=True, text=True).stdout.strip()

    def test_new_python_project_initializes_unborn_git_and_isolated_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            result = runtime.call_tool(
                "workspace_project_create",
                {
                    "project_id": "foo",
                    "project_type": "PYTHON",
                    "initialize_git": True,
                    "auto_start_development": True,
                    "request_id": "create-foo",
                    "owner_id": "test-owner",
                },
            )
            self.assertFalse(result["isError"], result)
            payload = result["structuredContent"]
            self.assertTrue(payload["registered"])
            self.assertTrue(payload["development_session_started"])
            self.assertTrue(payload["partial_provisioning"]["baseline_created"])
            self.assertEqual(payload["baseline_snapshot"]["head_revision"], "0" * 40)
            self.assertEqual(payload["source_commit"], "0" * 40)
            self.assertEqual(payload["lease"]["paths"], ["src"])
            project = self.developer / "foo"
            self.assertTrue((project / ".git").is_dir())
            self.assertTrue((project / "src").is_dir())
            self.assertTrue((project / "tests").is_dir())
            self.assertEqual(self._git(project, "remote"), "")
            self.assertEqual(self._git(project, "rev-parse", "--verify", "HEAD"), "")
            patch = "*** Begin Patch\n*** Add File: src/hello.py\n+print('ok')\n*** End Patch"
            changed = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": payload["lease_id"], "session_id": payload["session_id"]})
            self.assertFalse(changed["isError"], changed)
            self.assertFalse((project / "src" / "hello.py").exists())
            worktree = Path(payload["worktree_path"])
            self.assertTrue((worktree / "src" / "hello.py").exists())
            events = runtime._persistence.load_provisioning_events("foo")  # noqa: SLF001 - persistence audit assertion
            self.assertTrue({event["event_type"] for event in events} >= {"PROJECT_CREATE_REQUESTED", "PROJECT_DIRECTORY_CREATED", "LOCAL_GIT_INITIALIZED", "WORKSPACE_REGISTERED", "BASELINE_SNAPSHOT_CREATED", "DEVELOPMENT_SESSION_AUTO_STARTED"})
            self.assertEqual(sum(event["event_type"] == "BASELINE_SNAPSHOT_CREATED" for event in events), 1)
            self.assertEqual(sum(event["event_type"] == "DEVELOPMENT_SESSION_PROVISIONED" for event in events), 0)
            audit = runtime.call_tool(
                "director_audit_log",
                {"stream": "provisioning", "project_id": "foo", "limit": 100},
                request_id="audit-foo",
            )
            self.assertFalse(audit["isError"], audit)
            self.assertEqual(audit["structuredContent"]["stream"], "provisioning")
            self.assertTrue(audit["structuredContent"]["events"])
            runtime.call_tool("workspace_list", {}, request_id="audit-source")
            request_audit = runtime.call_tool(
                "director_audit_log",
                {"stream": "request", "request_id": "audit-source", "limit": 20},
            )
            self.assertFalse(request_audit["isError"], request_audit)
            self.assertTrue(any(event["event"] == "REQUEST_TERMINAL" for event in request_audit["structuredContent"]["events"]))
        finally:
            runtime.close()

    def test_runtime_candidate_control_operations_append_sanitized_provisioning_events(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext, StableCapabilityGatewayError
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        context = CapabilityExecutionContext(
            workspace_id="candidate-project",
            working_tree_id="worktree:candidate",
            session_id="session:candidate",
            owner_id="candidate-owner",
            task_id="task:candidate",
            policy_revision="project-policy-v1",
            policy_digest="a" * 64,
        )
        try:
            with patch.object(runtime, "_stable_capability_context", return_value=context), patch.object(
                runtime._stable_capability_gateway,
                "execute",
                return_value={"status": "succeeded", "output": "raw command output", "approval_token": "secret"},
            ):
                succeeded = runtime._stable_capability_call(
                    "capability_execute",
                    {
                        "capability_id": "runtime.candidate.prepare",
                        "preflight_id": "preflight:candidate",
                        "confirmation": "confirmed",
                        "params": {
                            "workspace_id": "candidate-project",
                            "artifact_role": "candidate",
                            "candidate_root": "/private/secret-candidate",
                            "approval_token": "secret",
                        },
                    },
                    request_id="candidate-request",
                )
            self.assertEqual(succeeded["status"], "succeeded")

            with patch.object(runtime, "_stable_capability_context", return_value=context), patch.object(
                runtime._stable_capability_gateway,
                "execute",
                side_effect=StableCapabilityGatewayError("CANDIDATE_EXECUTION_BLOCKED", "blocked"),
            ):
                with self.assertRaises(Exception):
                    runtime._stable_capability_call(
                        "capability_execute",
                        {
                            "capability_id": "runtime.candidate.activate",
                            "preflight_id": "preflight:activate",
                            "params": {"candidate_root": "/private/secret-candidate", "approval_token": "secret"},
                        },
                        request_id="activation-request",
                    )

            with patch.object(runtime, "_stable_capability_context", return_value=context), patch.object(
                runtime._stable_capability_gateway,
                "execute",
                return_value={"status": "IMPORTED", "source_database": "/private/raw-source", "approval_token": "secret"},
            ):
                imported = runtime._stable_capability_call(
                    "capability_execute",
                    {
                        "capability_id": "development.evidence.import_generation",
                        "preflight_id": "preflight:import",
                        "params": {
                            "source_database": "/private/raw-source",
                            "source_generation": "v25",
                            "session_id": "session:candidate",
                            "approval_token": "secret",
                        },
                    },
                    request_id="import-request",
                )
            self.assertEqual(imported["status"], "IMPORTED")

            with patch.object(runtime, "_stable_capability_context", return_value=context), patch.object(
                runtime._stable_capability_gateway,
                "execute",
                return_value={"status": "ARCHIVED", "approval_token": "secret"},
            ):
                archived = runtime._stable_capability_call(
                    "capability_execute",
                    {
                        "capability_id": "development.session.archive",
                        "preflight_id": "preflight:archive",
                        "params": {"session_id": "session:candidate", "source_path": "/private/raw-source"},
                    },
                    request_id="archive-request",
                )
            self.assertEqual(archived["status"], "ARCHIVED")

            events = runtime._persistence.load_provisioning_events("candidate-project")  # noqa: SLF001
            self.assertEqual(
                [event["event_type"] for event in events],
                [
                    "RUNTIME_CANDIDATE_PREPARE_REQUESTED",
                    "RUNTIME_CANDIDATE_PREPARE_SUCCEEDED",
                    "RUNTIME_CANDIDATE_ACTIVATE_REQUESTED",
                    "RUNTIME_CANDIDATE_ACTIVATE_FAILED",
                    "RUNTIME_EVIDENCE_IMPORT_REQUESTED",
                    "RUNTIME_EVIDENCE_IMPORT_SUCCEEDED",
                    "CONTROL_SESSION_ARCHIVE_REQUESTED",
                    "CONTROL_SESSION_ARCHIVE_SUCCEEDED",
                ],
            )
            serialized = repr(events)
            self.assertNotIn("approval_token", serialized)
            self.assertNotIn("secret-candidate", serialized)
            self.assertNotIn("raw command output", serialized)
            self.assertEqual(events[0]["result"]["artifact_role"], "candidate")
            self.assertEqual(events[3]["result"]["error_code"], "CANDIDATE_EXECUTION_BLOCKED")
        finally:
            runtime.close()

    def test_discovery_only_and_read_only_claim_cannot_promote(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "existing"
        project.mkdir()
        (project / "README.md").write_text("existing\n", encoding="utf-8")
        runtime = WrapperRuntime()
        try:
            discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
            candidate_id = discovered["repositories"][0]["candidate_id"]
            denied = runtime.call_tool("workspace_promote_development", {"candidate_id": candidate_id, "workspace_id": "existing", "intent": "READ_ONLY"})
            self.assertTrue(denied["isError"])
            self.assertEqual(denied["structuredContent"]["error"]["code"], "READ_ONLY_PROMOTION_DENIED")
            self.assertFalse((project / ".git").exists())
            discovery_only = runtime.call_tool("workspace_promote_development", {"candidate_id": candidate_id, "workspace_id": "existing", "intent": "DISCOVERY_ONLY"})
            self.assertTrue(discovery_only["isError"])
            self.assertEqual(discovery_only["structuredContent"]["error"]["code"], "READ_ONLY_PROMOTION_DENIED")
        finally:
            runtime.close()

    def test_existing_non_git_project_promotion_initializes_git_and_is_idempotent(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "existing"
        project.mkdir()
        (project / "README.md").write_text("keep\n", encoding="utf-8")
        (project / "tests").mkdir()
        runtime = WrapperRuntime()
        try:
            discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
            candidate_id = discovered["repositories"][0]["candidate_id"]
            self.assertEqual(discovered["repositories"][0]["kind"], "PROJECT_DIRECTORY")
            promoted = runtime.call_tool(
                "workspace_promote_development",
                {"candidate_id": candidate_id, "workspace_id": "existing", "intent": "EXPLICIT_USER_REQUEST", "initialize_git": True},
            )
            self.assertFalse(promoted["isError"], promoted)
            self.assertTrue((project / ".git").is_dir())
            self.assertEqual((project / "README.md").read_text(encoding="utf-8"), "keep\n")
            again = runtime.call_tool(
                "workspace_promote_development",
                {"candidate_id": candidate_id, "workspace_id": "existing", "intent": "EXPLICIT_USER_REQUEST", "initialize_git": True},
            )
            self.assertFalse(again["isError"], again)
            self.assertFalse(again["structuredContent"]["created"])
        finally:
            runtime.close()

    def test_non_git_promotion_rejects_same_path_directory_replacement(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "replacement-project"
        project.mkdir()
        (project / "README.md").write_text("original\n", encoding="utf-8")
        runtime = WrapperRuntime()
        try:
            discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
            candidate_id = next(item["candidate_id"] for item in discovered["repositories"] if item["name"] == "replacement-project")
            project.rename(self.root / "moved-replacement-project")
            project.mkdir()
            (project / "README.md").write_text("replacement\n", encoding="utf-8")
            blocked = runtime.call_tool(
                "workspace_promote_development",
                {"candidate_id": candidate_id, "workspace_id": "replacement-project", "intent": "EXPLICIT_USER_REQUEST"},
            )
            self.assertTrue(blocked["isError"], blocked)
            self.assertEqual(blocked["structuredContent"]["error"]["code"], "CANDIDATE_CHANGED")
            self.assertFalse((project / ".git").exists())
        finally:
            runtime.close()

    def test_existing_promotion_can_start_isolated_session_without_touching_canonical(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "portfolio-mcp"
        project.mkdir()
        (project / "README.md").write_text("canonical\n", encoding="utf-8")
        (project / "tests").mkdir()
        (project / "tests" / "test_keep.py").write_text("def test_keep():\n    assert True\n", encoding="utf-8")
        runtime = WrapperRuntime()
        try:
            discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
            candidate_id = next(item["candidate_id"] for item in discovered["repositories"] if item["name"] == "portfolio-mcp")
            promoted = runtime.call_tool(
                "workspace_promote_development",
                {"candidate_id": candidate_id, "workspace_id": "portfolio-mcp", "intent": "EXPLICIT_USER_REQUEST"},
            )
            self.assertFalse(promoted["isError"], promoted)
            original_token_urlsafe = secrets.token_urlsafe
            with patch(
                "chatgpt_dev_mcp.server.secrets.token_urlsafe",
                side_effect=lambda n: "-leading-session-token" if n == 18 else original_token_urlsafe(n),
            ):
                started = runtime.call_tool(
                    "director_development_start",
                    {
                        "workspace_id": "portfolio-mcp",
                        "request_id": "portfolio-start",
                        "title": "Implement portfolio",
                        "owner_id": "test-owner",
                        "paths": ["tests"],
                        "resources": [],
                        "depends_on": [],
                    },
                )
            self.assertFalse(started["isError"], started)
            payload = started["structuredContent"]
            self.assertEqual(payload["status"], "active")
            self.assertTrue(payload["lease"]["paths"], payload)
            events = runtime._persistence.load_provisioning_events("portfolio-mcp")  # noqa: SLF001
            session_events = [event for event in events if event["event_type"] == "DEVELOPMENT_SESSION_PROVISIONED"]
            self.assertEqual(len(session_events), 1)
            self.assertNotIn("paths", repr(session_events[0]))
            changed = runtime.call_tool(
                "apply_patch",
                {
                    "patch": "*** Begin Patch\n*** Add File: tests/test_isolated.py\n+def test_isolated():\n+    assert True\n*** End Patch",
                    "lease_id": payload["lease_id"],
                    "session_id": payload["session_id"],
                },
            )
            self.assertFalse(changed["isError"], changed)
            self.assertFalse((project / "tests" / "test_isolated.py").exists())
            self.assertEqual((project / "README.md").read_text(encoding="utf-8"), "canonical\n")
        finally:
            runtime.close()

    def test_project_name_and_existing_directory_are_rejected_without_mutation(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        (self.developer / "taken").mkdir()
        runtime = WrapperRuntime()
        try:
            invalid = runtime.call_tool("workspace_project_create", {"project_id": "../escape"})
            self.assertTrue(invalid["isError"])
            self.assertEqual(invalid["structuredContent"]["error"]["code"], "PROJECT_ID_INVALID")
            existing = runtime.call_tool("workspace_project_create", {"project_id": "taken"})
            self.assertTrue(existing["isError"])
            self.assertEqual(existing["structuredContent"]["error"]["code"], "PROJECT_ALREADY_EXISTS")
            self.assertFalse((self.developer / "escape").exists())
        finally:
            runtime.close()

    def test_workspace_registration_is_pinned_atomic_and_unregister_never_deletes_repo(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "open-design-knowledge"
        project.mkdir()
        (project / "README.md").write_text("keep\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.name", "Registration Test"], check=True)
        subprocess.run(["git", "-C", str(project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(project), "commit", "-qm", "initial"], check=True)
        before = self.config.read_bytes()
        runtime = WrapperRuntime()
        try:
            preflight = runtime.call_tool(
                "workspace_register_preflight",
                {"path": str(project), "workspace_id": "open-design-knowledge", "owner_id": "owner-1", "request_id": "register-1"},
            )
            self.assertFalse(preflight["isError"], preflight)
            preflight_payload = preflight["structuredContent"]
            self.assertEqual(preflight_payload["commands"], [])
            self.assertEqual(preflight_payload["policy"]["max_parallel_sessions"], 6)
            self.assertIs(preflight_payload["policy"]["verified_auto_commit"], True)
            self.assertIs(preflight_payload["policy"]["integration_requires_approval"], True)
            self.assertIs(preflight_payload["policy"]["commit_requires_approval"], True)
            self.assertIs(preflight_payload["policy"]["push_requires_approval"], True)
            self.assertEqual(self.config.read_bytes(), before)

            missing_confirmation = runtime.call_tool(
                "workspace_register",
                {"preflight_id": preflight_payload["preflight_id"], "confirmation": "wrong"},
            )
            self.assertTrue(missing_confirmation["isError"])
            self.assertEqual(missing_confirmation["structuredContent"]["error"]["code"], "REGISTRATION_CONFIRMATION_REQUIRED")

            registered = runtime.call_tool(
                "workspace_register",
                {
                    "preflight_id": preflight_payload["preflight_id"],
                    "confirmation": preflight_payload["approval"]["confirmation"],
                    "owner_id": "owner-1",
                    "request_id": "register-1",
                },
            )
            self.assertFalse(registered["isError"], registered)
            self.assertTrue(registered["structuredContent"]["registered"])
            self.assertEqual(registered["structuredContent"]["commands"], [])
            self.assertTrue(json.loads(self.config.read_text(encoding="utf-8"))["workspaces"]["open-design-knowledge"])

            command_update_before = self.config.read_bytes()
            command_update_preflight = runtime.call_tool(
                "workspace_registration_update_preflight",
                {
                    "workspace_id": "open-design-knowledge",
                    "commands": {"test": "python3 -m unittest discover -s tests -p test_*.py"},
                    "owner_id": "owner-1",
                    "request_id": "commands-1",
                },
            )
            self.assertFalse(command_update_preflight["isError"], command_update_preflight)
            command_update_payload = command_update_preflight["structuredContent"]
            self.assertEqual(command_update_payload["commands"], ["test"])
            self.assertEqual(self.config.read_bytes(), command_update_before)
            command_updated = runtime.call_tool(
                "workspace_registration_update",
                {
                    "preflight_id": command_update_payload["preflight_id"],
                    "confirmation": command_update_payload["approval"]["confirmation"],
                    "owner_id": "owner-1",
                    "request_id": "commands-1",
                },
            )
            self.assertFalse(command_updated["isError"], command_updated)
            self.assertEqual(command_updated["structuredContent"]["commands"], ["test"])
            stored_commands = json.loads(self.config.read_text(encoding="utf-8"))["workspaces"]["open-design-knowledge"]["commands"]
            self.assertEqual(stored_commands, {"test": "python3 -m unittest discover -s tests -p test_*.py"})

            update_preflight = runtime.call_tool(
                "workspace_registration_update_preflight",
                {"workspace_id": "open-design-knowledge", "new_workspace_id": "knowledge-mirror", "owner_id": "owner-1"},
            )
            self.assertFalse(update_preflight["isError"], update_preflight)
            update_payload = update_preflight["structuredContent"]
            updated = runtime.call_tool(
                "workspace_registration_update",
                {"preflight_id": update_payload["preflight_id"], "confirmation": update_payload["approval"]["confirmation"], "owner_id": "owner-1"},
            )
            self.assertFalse(updated["isError"], updated)
            self.assertIn("knowledge-mirror", json.loads(self.config.read_text(encoding="utf-8"))["workspaces"])

            unregister_preflight = runtime.call_tool("workspace_unregister_preflight", {"workspace_id": "knowledge-mirror"})
            self.assertFalse(unregister_preflight["isError"], unregister_preflight)
            unregister_payload = unregister_preflight["structuredContent"]
            unregistered = runtime.call_tool(
                "workspace_unregister",
                {"preflight_id": unregister_payload["preflight_id"], "confirmation": unregister_payload["approval"]["confirmation"]},
            )
            self.assertFalse(unregistered["isError"], unregistered)
            self.assertFalse(json.loads(self.config.read_text(encoding="utf-8"))["workspaces"])
            self.assertTrue(project.is_dir())
            self.assertTrue((project / "README.md").is_file())
            self.assertTrue((project / ".git").is_dir())
        finally:
            runtime.close()

    def test_workspace_unregister_preflight_blocks_live_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            created = runtime.call_tool(
                "workspace_project_create",
                {"project_id": "live-project", "initialize_git": True, "auto_start_development": True, "owner_id": "owner-live"},
            )
            self.assertFalse(created["isError"], created)
            blocked = runtime.call_tool("workspace_unregister_preflight", {"workspace_id": "live-project"})
            self.assertTrue(blocked["isError"], blocked)
            self.assertEqual(blocked["structuredContent"]["error"]["code"], "WORKSPACE_UNREGISTER_BLOCKED")
            self.assertTrue(any(item["kind"] == "development_session" for item in blocked["structuredContent"]["error"]["details"]["blockers"]))
            self.assertTrue((self.developer / "live-project").is_dir())
        finally:
            runtime.close()

    def test_workspace_unregister_preflight_ignores_superseded_persisted_active_task_state(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "orphan-project"
        project.mkdir()
        (project / "README.md").write_text("keep\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.name", "Registration Test"], check=True)
        subprocess.run(["git", "-C", str(project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(project), "commit", "-qm", "initial"], check=True)
        head = self._git(project, "rev-parse", "HEAD")
        self._write_config(
            {
                "orphan-project": {
                    "path": str(project),
                    "profile": "DEVELOPMENT",
                    "commands": {},
                }
            }
        )

        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "orphan-project"})
            self.assertFalse(opened["isError"], opened)
            task = runtime._director_ledger.enqueue(  # noqa: SLF001 - persisted-state regression setup
                "orphan-unregister-task",
                "orphan-project",
                "Orphan unregister task",
                working_tree_id="session:missing-unregister-session",
                development_session_id="session:missing-unregister-session",
                allowed_paths=("README.md",),
                base_revision=head,
            )
            running = runtime._director_ledger.transition(  # noqa: SLF001 - persisted-state regression setup
                task.task_id,
                "running",
                owner_id="orphan-owner",
            )
            runtime._director_ledger.transition(  # noqa: SLF001 - reconciled in-memory truth
                task.task_id,
                "stale",
                detail="ORPHANED_DEVELOPMENT_SESSION",
            )
            runtime._persistence.save_task(running.as_dict())  # noqa: SLF001 - simulate stale persisted shadow row

            summary = runtime.call_tool("director_status_summary", {"workspace_id": "orphan-project"})
            self.assertFalse(summary["isError"], summary)
            self.assertEqual(summary["structuredContent"]["current"]["task_count"], 0)

            preflight = runtime.call_tool("workspace_unregister_preflight", {"workspace_id": "orphan-project"})
            self.assertFalse(preflight["isError"], preflight)
        finally:
            runtime.close()

    def test_workspace_unregister_preflight_ignores_expired_persisted_active_lease(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "expired-lease-project"
        project.mkdir()
        (project / "README.md").write_text("keep\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.name", "Registration Test"], check=True)
        subprocess.run(["git", "-C", str(project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(project), "commit", "-qm", "initial"], check=True)
        head = self._git(project, "rev-parse", "HEAD")
        self._write_config(
            {
                "expired-lease-project": {
                    "path": str(project),
                    "profile": "DEVELOPMENT",
                    "commands": {},
                }
            }
        )

        runtime = WrapperRuntime()
        try:
            opened = runtime.call_tool("workspace_open", {"id": "expired-lease-project"})
            self.assertFalse(opened["isError"], opened)
            runtime._persistence.save_lease(  # noqa: SLF001 - persisted-state regression setup
                {
                    "lease_id": "expired-unregister-lease",
                    "workspace_id": "expired-lease-project",
                    "working_tree_id": "session:missing-expired-lease-session",
                    "task_id": "",
                    "owner_id": "expired-owner",
                    "paths": ["README.md"],
                    "resources": [],
                    "base_revision": head,
                    "scope_hashes": {},
                    "workspace_state_hash": "",
                    "workspace_wide": False,
                    "acquired_at": 1.0,
                    "expires_at": 2.0,
                },
                state="active",
            )

            summary = runtime.call_tool("director_status_summary", {"workspace_id": "expired-lease-project"})
            self.assertFalse(summary["isError"], summary)
            self.assertEqual(summary["structuredContent"]["current"]["lease_count"], 0)

            preflight = runtime.call_tool("workspace_unregister_preflight", {"workspace_id": "expired-lease-project"})
            self.assertFalse(preflight["isError"], preflight)
        finally:
            runtime.close()

    def test_workspace_unregister_supports_safe_non_git_read_only_entry(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "read-only-notes"
        project.mkdir()
        (project / "notes.txt").write_text("preserve\n", encoding="utf-8")
        self._write_config({"read-only-notes": {"path": str(project), "profile": "READ_ONLY", "commands": {}}})
        runtime = WrapperRuntime()
        try:
            preflight = runtime.call_tool("workspace_unregister_preflight", {"workspace_id": "read-only-notes"})
            self.assertFalse(preflight["isError"], preflight)
            payload = preflight["structuredContent"]
            removed = runtime.call_tool("workspace_unregister", {"preflight_id": payload["preflight_id"], "confirmation": payload["approval"]["confirmation"]})
            self.assertFalse(removed["isError"], removed)
            self.assertTrue(project.is_dir())
            self.assertEqual((project / "notes.txt").read_text(encoding="utf-8"), "preserve\n")
        finally:
            runtime.close()

    def test_workspace_unregister_supports_quarantined_non_git_development_entry_without_deleting_directory(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "project-container"
        project.mkdir()
        (project / "keep.txt").write_text("preserve\n", encoding="utf-8")
        self._write_config(
            {
                "project-container": {
                    "path": str(project),
                    "profile": "DEVELOPMENT",
                    "commands": {},
                }
            }
        )
        runtime = WrapperRuntime()
        try:
            preflight = runtime.call_tool(
                "workspace_unregister_preflight",
                {"workspace_id": "project-container", "owner_id": "cleanup-owner"},
            )
            self.assertFalse(preflight["isError"], preflight)
            payload = preflight["structuredContent"]
            self.assertFalse(payload["repository_deleted"])
            self.assertEqual(payload["unregister_effect"], "remove_registry_entry_only")
            removed = runtime.call_tool(
                "workspace_unregister",
                {
                    "preflight_id": payload["preflight_id"],
                    "confirmation": payload["approval"]["confirmation"],
                    "owner_id": "cleanup-owner",
                },
            )
            self.assertFalse(removed["isError"], removed)
            self.assertTrue(project.is_dir())
            self.assertEqual((project / "keep.txt").read_text(encoding="utf-8"), "preserve\n")
            self.assertFalse(json.loads(self.config.read_text(encoding="utf-8"))["workspaces"])
        finally:
            runtime.close()

    def test_registry_update_can_add_bounded_commands_without_replacing_existing_ones(self) -> None:
        from chatgpt_dev_mcp.provisioning import RegistryMutationManager

        project = self.developer / "docs-project"
        project.mkdir()
        self._write_config(
            {
                "docs-project": {
                    "path": str(project),
                    "profile": "DEVELOPMENT",
                    "commands": {"lint": "python3 -m compileall -q ."},
                }
            }
        )
        manager = RegistryMutationManager(self.config, home=self.home)
        _document, _raw, digest, _existed, _mode = manager.snapshot()

        result = manager.update_workspace_registration(
            workspace_id="docs-project",
            commands_patch={"test": "python3 -m unittest discover -s tests -p test_*.py"},
            expected_config_digest=digest,
            expected_path=project,
        )

        self.assertTrue(result["changed"])
        self.assertEqual(result["commands"], ["lint", "test"])
        stored = json.loads(self.config.read_text(encoding="utf-8"))["workspaces"]["docs-project"]["commands"]
        self.assertEqual(stored["lint"], "python3 -m compileall -q .")
        self.assertEqual(stored["test"], "python3 -m unittest discover -s tests -p test_*.py")

    def test_create_project_group_creates_plain_directory_without_git_or_registry_mutation(self) -> None:
        from chatgpt_dev_mcp.discovery import AllowedRoot, PROJECT_DISCOVERY
        from chatgpt_dev_mcp.provisioning import create_project_group

        before = self.config.read_bytes()
        result = create_project_group(AllowedRoot(id="developer", path=self.developer, mode=PROJECT_DISCOVERY), "finance")

        group = self.developer / "finance"
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["path"], str(group.resolve()))
        self.assertTrue(group.is_dir())
        self.assertFalse((group / ".git").exists())
        self.assertEqual(self.config.read_bytes(), before)

    def test_create_project_group_is_idempotent_for_existing_directory_and_rejects_unsafe_names(self) -> None:
        from chatgpt_dev_mcp.discovery import AllowedRoot, PROJECT_DISCOVERY
        from chatgpt_dev_mcp.provisioning import ProvisioningError, create_project_group

        root = AllowedRoot(id="developer", path=self.developer, mode=PROJECT_DISCOVERY)
        existing = self.developer / "finance"
        existing.mkdir()
        result = create_project_group(root, "finance")
        self.assertEqual(result["status"], "already_exists")

        for unsafe in ("../finance", "foo/bar", ".hidden", ".."):
            with self.subTest(unsafe=unsafe), self.assertRaises(ProvisioningError):
                create_project_group(root, unsafe)

        conflict = self.developer / "conflict"
        conflict.write_text("file\n", encoding="utf-8")
        with self.assertRaises(ProvisioningError) as raised:
            create_project_group(root, "conflict")
        self.assertEqual(raised.exception.code, "PROJECT_PATH_INVALID")

        symlink_target = self.developer / "real-group"
        symlink_target.mkdir()
        (self.developer / "linked-group").symlink_to(symlink_target, target_is_directory=True)
        with self.assertRaises(ProvisioningError) as raised:
            create_project_group(root, "linked-group")
        self.assertEqual(raised.exception.code, "SYMLINK_ESCAPE_BLOCKED")

    def test_registry_relocate_workspace_path_changes_only_path_and_pins_digest_and_old_path(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError, RegistryMutationManager

        source = self.developer / "portfolio-mcp"
        destination = self.developer / "finance" / "portfolio-mcp"
        source.mkdir()
        destination.parent.mkdir()
        self._write_config(
            {
                "portfolio-mcp": {
                    "path": str(source),
                    "profile": "DEVELOPMENT",
                    "commands": {"test": "python3 -m unittest"},
                    "metadata": {"tag": "finance"},
                    "isolated_development": {"max_parallel_sessions": 3},
                }
            }
        )
        manager = RegistryMutationManager(self.config, home=self.home)
        before_document = json.loads(self.config.read_text(encoding="utf-8"))
        _document, _raw, digest, _existed, _mode = manager.snapshot()

        result = manager.relocate_workspace_path(
            "portfolio-mcp",
            expected_old_path=source,
            new_path=destination,
            expected_config_digest=digest,
        )

        self.assertTrue(result["changed"])
        self.assertEqual(result["previous_path"], str(source.resolve()))
        self.assertEqual(result["path"], str(destination.resolve(strict=False)))
        after_document = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(after_document["workspaces"]["portfolio-mcp"]["path"], str(destination.resolve(strict=False)))
        expected_entry = dict(before_document["workspaces"]["portfolio-mcp"])
        expected_entry["path"] = str(destination.resolve(strict=False))
        self.assertEqual(after_document["workspaces"]["portfolio-mcp"], expected_entry)

        with self.assertRaises(ProvisioningError) as raised:
            manager.relocate_workspace_path(
                "portfolio-mcp",
                expected_old_path=destination,
                new_path=source,
                expected_config_digest=digest,
            )
        self.assertEqual(raised.exception.code, "CONFIG_CHANGED")

        _document, _raw, fresh_digest, _existed, _mode = manager.snapshot()
        with self.assertRaises(ProvisioningError) as raised:
            manager.relocate_workspace_path(
                "portfolio-mcp",
                expected_old_path=source,
                new_path=source,
                expected_config_digest=fresh_digest,
            )
        self.assertEqual(raised.exception.code, "WORKSPACE_SOURCE_CHANGED")


if __name__ == "__main__":
    unittest.main()
