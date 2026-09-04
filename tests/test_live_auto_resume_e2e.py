from __future__ import annotations

import json
import os
import selectors
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = ROOT / ".venv" / "bin" / "chatgpt-dev-mcp"


@unittest.skipUnless(EXECUTABLE.is_file(), "the repository live MCP executable is not installed")
class LiveAutoResumeE2ETests(unittest.TestCase):
    """Exercise safe auto-resume through separate live MCP processes."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-live-resume-")
        root = Path(self.tempdir.name)
        self.home = root / "home"
        self.repo = self.home / "Developer" / "fixture"
        self.repo.mkdir(parents=True)
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Live Auto Resume Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "printf test-ok"},
                            "isolated_development": {
                                "auto_create_sessions": True,
                                "auto_resume_sessions": True,
                                "auto_resume_policy": "same_owner_same_task_safe_local",
                                "max_parallel_sessions": 3,
                                "allow_workspace_wide": False,
                                "integration_requires_approval": True,
                                "commit_requires_approval": True,
                                "push_requires_approval": True,
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.root = root
        self.process: subprocess.Popen[str] | None = None

    def tearDown(self) -> None:
        self._stop()
        self.tempdir.cleanup()

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "director-state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.root / "worktrees"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CODING_TOOLS_MCP_TELEMETRY": "off",
            }
        )
        return environment

    def _start(self) -> None:
        self.process = subprocess.Popen(
            [str(EXECUTABLE)],
            cwd=str(ROOT),
            env=self._environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "live-auto-resume", "version": "1"}}, 1)
        self._notify("notifications/initialized")

    def _request(self, method: str, params: dict[str, object], request_id: int) -> dict[str, object]:
        process = self.process
        assert process is not None and process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, separators=(",", ":")) + "\n")
        process.stdin.flush()
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=10):
                raise AssertionError(f"timed out waiting for {method}; pid={process.pid}")
        finally:
            selector.close()
        line = process.stdout.readline()
        if not line:
            raise AssertionError(f"MCP exited during {method}; rc={process.poll()}")
        response = json.loads(line)
        if "error" in response:
            raise AssertionError((method, response))
        return response

    def _notify(self, method: str) -> None:
        process = self.process
        assert process is not None and process.stdin is not None
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": {}}, separators=(",", ":")) + "\n")
        process.stdin.flush()

    def _call(self, name: str, arguments: dict[str, object], request_id: int) -> dict[str, object]:
        response = self._request("tools/call", {"name": name, "arguments": arguments}, request_id)
        return response["result"]

    @staticmethod
    def _error_code(result: dict[str, object]) -> str:
        return str(result["structuredContent"]["error"]["code"])

    def _stop(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def test_live_safe_auto_resume_and_approval_boundaries(self) -> None:
        owner = "chatgpt-live-e2e"
        request_id = "auto-resume-live-e2e"
        start_args = {
            "workspace_id": "fixture",
            "request_id": request_id,
            "title": "live auto-resume",
            "owner_id": owner,
            "paths": ["resume-e2e.txt"],
            "resources": [],
        }

        self._start()
        first = self._call("director_development_start", start_args, 2)
        self.assertFalse(first.get("isError"), first)
        first_payload = first["structuredContent"]
        session_id = first_payload["session_id"]
        task_id = first_payload["task"]["task_id"]
        working_tree_id = first_payload["working_tree_id"]
        lease_id = first_payload["lease_id"]
        self.assertFalse(first_payload["policy"]["integration_requires_approval"] is False)
        self.assertFalse(first_payload["policy"]["commit_requires_approval"] is False)
        self.assertFalse(first_payload["policy"]["push_requires_approval"] is False)

        patched = self._call(
            "apply_patch",
            {
                "session_id": session_id,
                "lease_id": lease_id,
                "patch": "*** Begin Patch\n*** Add File: resume-e2e.txt\n+retained\n*** End Patch",
            },
            3,
        )
        self.assertFalse(patched.get("isError"), patched)
        self._stop()

        self._start()
        replay = self._call("director_development_start", start_args, 4)
        self.assertFalse(replay.get("isError"), replay)
        replay_payload = replay["structuredContent"]
        self.assertTrue(replay_payload["reused_existing_request"])
        self.assertTrue(replay_payload["resumed"])
        self.assertEqual(replay_payload["session_id"], session_id)
        self.assertEqual(replay_payload["task"]["task_id"], task_id)
        self.assertEqual(replay_payload["working_tree_id"], working_tree_id)

        read_back = self._call("read_file", {"session_id": session_id, "path": "resume-e2e.txt"}, 5)
        self.assertFalse(read_back.get("isError"), read_back)
        self.assertEqual(read_back["structuredContent"]["content"], "retained\n")
        second_patch = self._call(
            "apply_patch",
            {
                "session_id": session_id,
                "lease_id": replay_payload["lease_id"],
                "patch": "*** Begin Patch\n*** Update File: resume-e2e.txt\n@@\n-retained\n+retained-again\n*** End Patch",
            },
            6,
        )
        self.assertFalse(second_patch.get("isError"), second_patch)

        cross_owner = self._call(
            "workspace_resume_development_session",
            {"session_id": session_id, "owner_id": "different-owner", "task_id": task_id},
            7,
        )
        self.assertTrue(cross_owner.get("isError"), cross_owner)
        self.assertEqual(self._error_code(cross_owner), "AUTO_RESUME_NOT_ALLOWED")

        workspace_wide = self._call(
            "director_development_start",
            {
                "workspace_id": "fixture",
                "request_id": "workspace-wide-live",
                "title": "workspace-wide should stay gated",
                "owner_id": owner,
                "paths": [],
                "resources": [],
                "workspace_wide": True,
                "scope_reason": "live boundary check",
            },
            8,
        )
        self.assertTrue(workspace_wide.get("isError"), workspace_wide)
        self.assertEqual(self._error_code(workspace_wide), "WORKSPACE_WIDE_NOT_ALLOWED")

        integration = self._call("workspace_integrate_development_session", {"session_id": session_id}, 9)
        self.assertTrue(integration.get("isError"), integration)
        self.assertEqual(self._error_code(integration), "INTEGRATION_APPROVAL_REQUIRED")

        commit = self._call("git_commit", {"workspace_id": "fixture", "task_id": task_id}, 10)
        self.assertTrue(commit.get("isError"), commit)
        self.assertIn(self._error_code(commit), {"GIT_ARGUMENTS_INVALID", "GIT_APPROVAL_INVALID", "GIT_APPROVAL_NOT_FOUND"})

        push = self._call("git_push", {"workspace_id": "fixture", "task_id": task_id}, 11)
        self.assertTrue(push.get("isError"), push)
        self.assertIn(self._error_code(push), {"GIT_ARGUMENTS_INVALID", "GIT_APPROVAL_INVALID", "GIT_APPROVAL_NOT_FOUND"})


if __name__ == "__main__":
    unittest.main()
