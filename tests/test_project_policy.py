from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class ProjectPolicyToolTests(unittest.TestCase):
    def _fixture(self):
        root = Path(tempfile.mkdtemp(prefix="project-policy-tool-"))
        home = root / "home"
        repo = home / "Developer" / "fixture"
        repo.mkdir(parents=True)
        (repo / "README.md").write_text("baseline\n", encoding="utf-8")
        config = home / ".config" / "local-dev-mcp" / "config.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "fixture": {
                            "path": str(repo),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "printf test-ok"},
                            "isolated_development": {
                                "auto_create_sessions": True,
                                "max_parallel_sessions": 3,
                                "allowed_base": "registered_project",
                                "integration_requires_approval": True,
                                "commit_requires_approval": True,
                                "push_requires_approval": True,
                            },
                            "platform": {
                                "credential_slots": {
                                    "fixture": {
                                        "source_kind": "env",
                                        "source_name": "FIXTURE_TOKEN",
                                        "allowed_profiles": ["github"],
                                    }
                                }
                            },
                        },
                        "readonly-fixture": {
                            "path": str(repo),
                            "profile": "READ_ONLY",
                        },
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return root, home, repo, config

    @staticmethod
    def _error(result: dict[str, object]) -> str:
        return str(result["structuredContent"]["error"]["code"])

    def test_get_update_and_read_back_change_only_allowlisted_policy(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        root, home, _repo, config = self._fixture()
        with patch.dict(
            os.environ,
            {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "state"),
                "CHATGPT_DEV_MCP_SURFACE": "legacy",
            },
        ):
            runtime = WrapperRuntime()
            try:
                before = runtime.call_tool("workspace_project_policy_get", {"workspace_id": "fixture"})
                self.assertFalse(before["isError"], before)
                before_payload = before["structuredContent"]
                before_digest = before_payload["config_digest"]
                self.assertIs(before_payload["policy"]["verified_auto_commit"], True)
                self.assertIs(before_payload["policy"]["integration_requires_approval"], True)
                self.assertIs(before_payload["policy"]["commit_requires_approval"], True)
                self.assertIs(before_payload["policy"]["push_requires_approval"], True)
                before_document = json.loads(config.read_text(encoding="utf-8"))

                updated = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "fixture",
                        "expected_config_digest": before_digest,
                        "isolated_development": {
                            "auto_resume_sessions": True,
                            "auto_resume_policy": "same_owner_same_task_safe_local",
                            "verified_auto_commit": False,
                        },
                    },
                )
                self.assertFalse(updated["isError"], updated)
                payload = updated["structuredContent"]
                self.assertNotEqual(payload["config_digest"], before_digest)
                self.assertEqual(payload["policy"]["auto_resume_sessions"], True)
                self.assertEqual(payload["policy"]["auto_resume_policy"], "same_owner_same_task_safe_local")
                self.assertIs(payload["policy"]["verified_auto_commit"], False)
                self.assertIs(payload["policy"]["commit_requires_approval"], True)
                self.assertTrue(payload["receipt"]["receipt_id"].startswith("policy:"))
                self.assertEqual(payload["audit"]["status"], "passed")

                after_document = json.loads(config.read_text(encoding="utf-8"))
                self.assertEqual(after_document["version"], before_document["version"])
                self.assertEqual(after_document["roots"], before_document["roots"])
                self.assertEqual(after_document["workspaces"]["fixture"]["path"], before_document["workspaces"]["fixture"]["path"])
                self.assertEqual(after_document["workspaces"]["fixture"]["commands"], before_document["workspaces"]["fixture"]["commands"])
                self.assertEqual(after_document["workspaces"]["fixture"]["platform"], before_document["workspaces"]["fixture"]["platform"])
                self.assertEqual(
                    hashlib.sha256(config.read_bytes()).hexdigest(),
                    payload["config_digest"],
                )

                reread = runtime.call_tool("workspace_project_policy_get", {"workspace_id": "fixture"})
                self.assertFalse(reread["isError"], reread)
                self.assertEqual(reread["structuredContent"]["config_digest"], payload["config_digest"])
                self.assertEqual(reread["structuredContent"]["policy"]["auto_resume_sessions"], True)
                self.assertIs(reread["structuredContent"]["policy"]["verified_auto_commit"], False)
            finally:
                runtime.close()

    def test_policy_update_fails_closed_for_stale_digest_unknown_key_and_approval_downgrade(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        root, home, _repo, config = self._fixture()
        with patch.dict(
            os.environ,
            {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "state"),
                "CHATGPT_DEV_MCP_SURFACE": "legacy",
            },
        ):
            runtime = WrapperRuntime()
            try:
                digest = runtime.call_tool("workspace_project_policy_get", {"workspace_id": "fixture"})["structuredContent"]["config_digest"]
                config.write_text(config.read_text(encoding="utf-8").replace('"max_parallel_sessions": 3', '"max_parallel_sessions": 4'), encoding="utf-8")
                stale = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "fixture",
                        "expected_config_digest": digest,
                        "isolated_development": {"auto_resume_sessions": True},
                    },
                )
                self.assertTrue(stale["isError"], stale)
                self.assertEqual(self._error(stale), "CONFIG_CHANGED")

                fresh_digest = hashlib.sha256(config.read_bytes()).hexdigest()
                unknown = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "fixture",
                        "expected_config_digest": fresh_digest,
                        "isolated_development": {"commands": {"test": "unsafe"}},
                    },
                )
                self.assertTrue(unknown["isError"], unknown)
                self.assertEqual(self._error(unknown), "UNKNOWN_POLICY_KEY")

                downgrade = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "fixture",
                        "expected_config_digest": fresh_digest,
                        "isolated_development": {"commit_requires_approval": False},
                    },
                )
                self.assertTrue(downgrade["isError"], downgrade)
                self.assertEqual(self._error(downgrade), "PROJECT_POLICY_UPDATE_DENIED")

                invalid_auto_commit = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "fixture",
                        "expected_config_digest": fresh_digest,
                        "isolated_development": {"verified_auto_commit": "yes"},
                    },
                )
                self.assertTrue(invalid_auto_commit["isError"], invalid_auto_commit)
                self.assertEqual(self._error(invalid_auto_commit), "INVALID_POLICY_VALUE")
            finally:
                runtime.close()

    def test_policy_update_rejects_symlink_config_and_non_development_workspace(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        root, home, _repo, config = self._fixture()
        symlink = config.with_name("config-link.json")
        symlink.symlink_to(config)
        with patch.dict(
            os.environ,
            {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(symlink),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "state-symlink"),
                "CHATGPT_DEV_MCP_SURFACE": "legacy",
            },
        ):
            runtime = WrapperRuntime()
            try:
                denied = runtime.call_tool("workspace_project_policy_get", {"workspace_id": "fixture"})
                self.assertTrue(denied["isError"], denied)
                self.assertEqual(self._error(denied), "CONFIG_IDENTITY_CHANGED")
            finally:
                runtime.close()

        with patch.dict(
            os.environ,
            {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "state-readonly"),
                "CHATGPT_DEV_MCP_SURFACE": "legacy",
            },
        ):
            runtime = WrapperRuntime()
            try:
                digest = runtime.call_tool("workspace_project_policy_get", {"workspace_id": "readonly-fixture"})["structuredContent"]["config_digest"]
                denied = runtime.call_tool(
                    "workspace_project_policy_update",
                    {
                        "workspace_id": "readonly-fixture",
                        "expected_config_digest": digest,
                        "isolated_development": {"auto_resume_sessions": True},
                    },
                )
                self.assertTrue(denied["isError"], denied)
                self.assertEqual(self._error(denied), "PROJECT_POLICY_UPDATE_DENIED")
            finally:
                runtime.close()

    def test_config_identity_change_during_snapshot_read_fails_closed(self) -> None:
        from chatgpt_dev_mcp.project_policy import ConfigIdentity, ProjectPolicyError, _read

        _root, _home, _repo, config = self._fixture()
        stat_result = config.lstat()
        first = ConfigIdentity(stat_result.st_dev, stat_result.st_ino, stat_result.st_mode & 0o777)
        replaced = ConfigIdentity(first.device, first.inode + 1, first.mode)
        with patch("chatgpt_dev_mcp.project_policy._identity", side_effect=[first, replaced]):
            with self.assertRaises(ProjectPolicyError) as raised:
                _read(config)
        self.assertEqual(raised.exception.code, "CONFIG_IDENTITY_CHANGED")


if __name__ == "__main__":
    unittest.main()
