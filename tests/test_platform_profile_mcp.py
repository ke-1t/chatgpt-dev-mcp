from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class CredentialSlotRegistrationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-credential-slot-service-")
        self.home = Path(self.tempdir.name)
        self.repo = self.home / "repo"
        self.repo.mkdir()
        self.config = self.home / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspaces": {
                        "fixture": {
                            "path": str(self.repo),
                            "profile": "DEVELOPMENT",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_env_credential_slot_registration_is_read_only_until_one_shot_apply(self) -> None:
        from chatgpt_dev_mcp.platform_profile_mcp import CredentialSlotRegistrationService
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        service = CredentialSlotRegistrationService(
            self.config,
            home=self.home,
            now=lambda: 1000.0,
            ttl_seconds=600,
        )
        before = self.config.read_text(encoding="utf-8")
        preflight = service.preflight(
            workspace_id="fixture",
            slot_id="example-token",
            source_kind="env",
            source_name="EXAMPLE_TOKEN",
            allowed_profiles=["external-tool"],
        )

        self.assertEqual(self.config.read_text(encoding="utf-8"), before)
        self.assertEqual(preflight["status"], "new")
        self.assertTrue(preflight["approval_required"])
        self.assertNotIn("value", preflight)
        self.assertNotIn("EXAMPLE_TOKEN=", json.dumps(preflight))

        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "registered")
        document = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(
            document["workspaces"]["fixture"]["platform"]["credential_slots"]["example-token"],
            {
                "source_kind": "env",
                "source_name": "EXAMPLE_TOKEN",
                "allowed_profiles": ["external-tool"],
            },
        )

        with self.assertRaises(ProvisioningError) as replay:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(replay.exception.code, "CREDENTIAL_SLOT_PREFLIGHT_NOT_FOUND")

    def test_keychain_defaults_resolve_only_after_grant_consumption(self) -> None:
        from chatgpt_dev_mcp.credential_slots import CredentialSlotManager, CredentialSlotPolicy
        from chatgpt_dev_mcp.process_runner import BoundedProcessResult

        calls: list[tuple[str, ...]] = []

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            if "-w" in argv:
                return BoundedProcessResult(0, "secret-value\n", "", False, False, False, 1)
            return BoundedProcessResult(0, "", "", False, False, False, 1)

        with patch("chatgpt_dev_mcp.credential_slots.run_bounded", side_effect=fake_run):
            manager = CredentialSlotManager(
                [
                    CredentialSlotPolicy(
                        slot="example-token",
                        source_kind="keychain",
                        source_name="example-token-key",
                        allowed_profiles=("external-tool",),
                        allowed_projects=("fixture",),
                    )
                ],
                environ={},
            )
            listed = manager.list_slots(project_id="fixture")
            self.assertTrue(listed[0]["available"])
            self.assertEqual(listed[0]["value"], "hidden")
            grant = manager.preflight("example-token", project_id="fixture", command_profile="external-tool")
            resolved, redact_values = manager.consume_grants(
                [grant["grant_id"]],
                project_id="fixture",
                command_profile="external-tool",
            )

        self.assertEqual(resolved, {"example-token": "secret-value"})
        self.assertEqual(redact_values, ("secret-value",))
        self.assertTrue(any("-w" not in call for call in calls))
        self.assertTrue(any("-w" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
