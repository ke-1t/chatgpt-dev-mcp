from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RESCUE_ID = "compat:workspace.trust.enable:fixture"


class StaleSchemaRescueServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-stale-rescue-")
        root = Path(self.tempdir.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        self.config = root / "config.json"
        self._write_config()
        self.previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config)

    def tearDown(self) -> None:
        if self.previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self.previous_config
        self.tempdir.cleanup()

    def _write_config(self, *, approval_ttl: int | None = None) -> None:
        isolated: dict[str, object] = {
            "auto_create_sessions": True,
            "integration_requires_approval": True,
            "commit_requires_approval": True,
            "push_requires_approval": True,
        }
        if approval_ttl is not None:
            isolated["manual_approval_ttl_seconds"] = approval_ttl
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest -q"},
                            "isolated_development": isolated,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def _runtime(self):
        from chatgpt_dev_mcp.server import WrapperRuntime

        return WrapperRuntime()

    def _trust_level(self, runtime) -> str:
        response = runtime.call_tool(
            "workspace_project_policy_get",
            {"workspace_id": "fixture"},
        )
        self.assertFalse(response["isError"], response)
        return response["structuredContent"]["policy"]["trust_level"]

    def test_rescue_uses_existing_r3_confirmation_and_is_one_shot(self) -> None:
        runtime = self._runtime()
        try:
            self.assertEqual(self._trust_level(runtime), "standard")
            preflight = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": RESCUE_ID},
            )
            self.assertFalse(preflight["isError"], preflight)
            prepared = preflight["structuredContent"]
            self.assertTrue(prepared["compatibility_rescue"])
            self.assertEqual(prepared["operation"], "workspace.trust.enable")
            self.assertEqual(prepared["workspace_id"], "fixture")
            self.assertTrue(prepared["approval_required"])
            self.assertEqual(self._trust_level(runtime), "standard")

            wrong = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": RESCUE_ID,
                    "approval_token": prepared["approval_token"],
                    "confirmation": "wrong-confirmation",
                },
            )
            self.assertTrue(wrong["isError"], wrong)
            self.assertEqual(wrong["structuredContent"]["error"]["code"], "CAPABILITY_APPROVAL_REQUIRED")
            self.assertEqual(self._trust_level(runtime), "standard")

            enabled = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": RESCUE_ID,
                    "approval_token": prepared["approval_token"],
                    "confirmation": prepared["confirmation"],
                },
            )
            self.assertFalse(enabled["isError"], enabled)
            self.assertTrue(enabled["structuredContent"]["compatibility_rescue"])
            self.assertEqual(self._trust_level(runtime), "trusted_development")

            replay = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": RESCUE_ID,
                    "approval_token": prepared["approval_token"],
                    "confirmation": prepared["confirmation"],
                },
            )
            self.assertTrue(replay["isError"], replay)
            self.assertEqual(replay["structuredContent"]["error"]["code"], "CAPABILITY_PREFLIGHT_REPLAY")

            idempotent = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": RESCUE_ID},
            )
            self.assertFalse(idempotent["isError"], idempotent)
            self.assertEqual(idempotent["structuredContent"]["status"], "already_enabled")
            self.assertFalse(idempotent["structuredContent"]["approval_required"])
            self.assertNotIn("approval_token", idempotent["structuredContent"])
        finally:
            runtime.close()

    def test_rescue_fails_closed_on_config_drift_and_unknown_compat_operation(self) -> None:
        runtime = self._runtime()
        try:
            preflight = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": RESCUE_ID},
            )
            self.assertFalse(preflight["isError"], preflight)
            prepared = preflight["structuredContent"]
            self._write_config(approval_ttl=900)

            drifted = runtime.call_tool(
                "workspace_attach_development_session",
                {
                    "session_id": RESCUE_ID,
                    "approval_token": prepared["approval_token"],
                    "confirmation": prepared["confirmation"],
                },
            )
            self.assertTrue(drifted["isError"], drifted)
            self.assertIn(
                drifted["structuredContent"]["error"]["code"],
                {"CAPABILITY_ARGS_CHANGED", "CAPABILITY_CONTEXT_CHANGED", "CAPABILITY_POLICY_CHANGED"},
            )

            unknown = runtime.call_tool(
                "workspace_request_development_session_attach",
                {"session_id": "compat:capability.execute:fixture"},
            )
            self.assertTrue(unknown["isError"], unknown)
            self.assertEqual(
                unknown["structuredContent"]["error"]["code"],
                "COMPAT_RESCUE_OPERATION_DENIED",
            )
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
