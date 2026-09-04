from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch


class SecretSafeApiE2ETests(unittest.TestCase):
    def test_loopback_api_material_is_not_returned_or_persisted(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        material = "-".join(("fixture", "opaque", "value", "7f3a1d"))
        observed_authorization: list[str] = []
        head_sha = "a" * 40

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                observed_authorization.append(self.headers.get("Authorization", ""))
                if self.path != "/repos/acme/demo/pulls/1":
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = {
                    "number": 1,
                    "state": "open",
                    "title": "Fixture PR",
                    "draft": False,
                    "merged": False,
                    "mergeable": True,
                    "head": {"ref": "feature", "sha": head_sha, "repo": {"full_name": "acme/demo"}},
                    "base": {"ref": "main"},
                }
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        runtime = None
        try:
            port = server.server_address[1]
            with tempfile.TemporaryDirectory(prefix="api-e2e-") as temp:
                home = Path(temp) / "home"
                repo = home / "Developer" / "fixture"
                repo.mkdir(parents=True)
                (repo / "README.md").write_text("baseline\n", encoding="utf-8")
                subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
                subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
                subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
                subprocess.run(
                    ["git", "-C", str(repo), "remote", "add", "origin", f"http://127.0.0.1:{port}/acme/demo.git"],
                    check=True,
                )
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
                                    "platform": {
                                        "credential_slots": {
                                            "github-api": {
                                                "source_kind": "env",
                                                "source_name": "E2E_API_VALUE",
                                                "allowed_profiles": ["github"],
                                            }
                                        },
                                        "github": {
                                            "owner": "acme",
                                            "repository": "demo",
                                            "remote_name": "origin",
                                            "remote_host": "127.0.0.1",
                                            "api_origin": f"http://127.0.0.1:{port}",
                                            "credential_slot": "github-api",
                                            "auth_required": True,
                                            "allowed_base_branches": ["main"],
                                            "required_checks": [],
                                            "required_approvals": 0,
                                            "merge_method": "squash",
                                            "merge_queue_required": False,
                                            "enforce_branch_protection": False,
                                        },
                                    },
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                data_dir = home / ".director-state"
                with patch.dict(
                    os.environ,
                    {
                        "HOME": str(home),
                        "LOCAL_DEV_MCP_CONFIG": str(config),
                        "LOCAL_DEV_MCP_DATA_DIR": str(data_dir),
                        "LOCAL_DEV_MCP_WORKTREE_ROOT": str(home / ".cache" / "local-dev-mcp" / "worktrees"),
                        "E2E_API_VALUE": material,
                    },
                ):
                    runtime = WrapperRuntime()
                    opened = runtime.call_tool("workspace_open", {"id": "fixture"})["structuredContent"]
                    binding = {
                        "workspace_id": "fixture",
                        "working_tree_id": opened["identity"]["worktree_id"],
                    }
                    grant = runtime.call_tool(
                        "credential_slot_preflight",
                        {**binding, "slot_id": "github-api", "profile_id": "github"},
                    )
                    self.assertFalse(grant["isError"], grant)
                    grant_payload = grant["structuredContent"]
                    self.assertEqual(grant_payload["value"], "hidden")
                    result = runtime.call_tool(
                        "github_workflow_read",
                        {
                            **binding,
                            "action": "pr_status",
                            "number": 1,
                            "credential_grant_id": grant_payload["grant_id"],
                        },
                    )
                    self.assertFalse(result["isError"], result)
                    self.assertEqual(result["structuredContent"]["data"]["number"], 1)
                    self.assertEqual(observed_authorization, [f"Bearer {material}"])
                    visible = json.dumps(
                        {"grant": grant_payload, "result": result["structuredContent"]},
                        sort_keys=True,
                    )
                    self.assertNotIn(material, visible)
                    runtime.close()
                    runtime = None

                for path in data_dir.glob("**/*"):
                    if path.is_file():
                        self.assertNotIn(material.encode("utf-8"), path.read_bytes(), str(path))
        finally:
            if runtime is not None:
                runtime.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
