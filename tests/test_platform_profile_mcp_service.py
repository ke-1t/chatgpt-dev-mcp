from __future__ import annotations

from datetime import datetime, timezone
import json
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.provisioning import ProvisioningError


class PlatformProfileMcpServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-platform-profile-service-")
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

    def _service(self):
        from chatgpt_dev_mcp.platform_profile_mcp import PlatformProfileRegistrationService

        return PlatformProfileRegistrationService(
            self.config,
            home=self.home,
            now=lambda: 1000.0,
            ttl_seconds=600,
        )

    def _command_service(self):
        from chatgpt_dev_mcp.platform_profile_mcp import CommandProfileRegistrationService

        return CommandProfileRegistrationService(
            self.config,
            home=self.home,
            now=lambda: 1000.0,
            ttl_seconds=600,
        )

    def _cleanup_service(self, *, now: float | None = None):
        from chatgpt_dev_mcp.platform_profile_mcp import CommandProfileCleanupService

        current = now if now is not None else datetime(2026, 8, 21, 2, 0, tzinfo=timezone.utc).timestamp()
        return CommandProfileCleanupService(
            self.config,
            home=self.home,
            now=lambda: current,
            ttl_seconds=600,
        )

    def _seed_command_profiles(self) -> None:
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["fixture"]["platform"] = {
            "command_profiles": {
                "managed-expired": {
                    "argv": ["echo", "expired"],
                    "lifecycle": {
                        "kind": "ephemeral",
                        "purpose": "expired",
                        "owner": "fixture",
                        "created_at": "2026-08-21T00:00:00Z",
                        "expires_at": "2026-08-21T01:00:00Z",
                    },
                },
                "managed-future": {
                    "argv": ["echo", "future"],
                    "lifecycle": {
                        "kind": "ephemeral",
                        "purpose": "future",
                        "owner": "fixture",
                        "created_at": "2026-08-21T00:00:00Z",
                        "expires_at": "2026-08-21T06:00:00Z",
                    },
                },
                "managed-once-name-only": {"argv": ["echo", "permanent"]},
            }
        }
        self.config.write_text(json.dumps(document), encoding="utf-8")

    def test_browser_preflight_is_read_only_and_apply_is_one_shot(self) -> None:
        service = self._service()
        before = self.config.read_text(encoding="utf-8")

        preflight = service.preflight(
            workspace_id="fixture",
            kind="browser",
            profile_id="managed-fixture-browser",
            allowed_origins=["http://127.0.0.1:8765"],
            viewport_width=1280,
            viewport_height=720,
        )

        self.assertEqual(self.config.read_text(encoding="utf-8"), before)
        self.assertEqual(preflight["status"], "new")
        self.assertTrue(preflight["approval_required"])
        self.assertEqual(preflight["kind"], "browser")
        self.assertFalse(preflight["external_execution"])

        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "registered")
        self.assertFalse(applied["external_execution"])

        document = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(
            document["workspaces"]["fixture"]["platform"]["browser_profiles"]["managed-fixture-browser"]["allowed_origins"],
            ["http://127.0.0.1:8765"],
        )

        with self.assertRaises(ProvisioningError) as replay:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(replay.exception.code, "PLATFORM_PROFILE_PREFLIGHT_NOT_FOUND")

    def test_desktop_preflight_and_apply_register_capture_only_profile(self) -> None:
        service = self._service()
        preflight = service.preflight(
            workspace_id="fixture",
            kind="desktop",
            profile_id="managed-fixture-desktop",
            bundle_id="com.example.fixture",
            health_url="http://127.0.0.1:8765/health",
        )

        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "registered")
        document = json.loads(self.config.read_text(encoding="utf-8"))
        desktop = document["workspaces"]["fixture"]["platform"]["desktop_profiles"]["managed-fixture-desktop"]
        self.assertEqual(desktop["bundle_id"], "com.example.fixture")
        self.assertEqual(desktop["health_url"], "http://127.0.0.1:8765/health")

    def test_apply_fails_closed_if_registry_changes_after_preflight(self) -> None:
        service = self._service()
        preflight = service.preflight(
            workspace_id="fixture",
            kind="browser",
            profile_id="managed-fixture-browser",
            allowed_origins=["http://127.0.0.1:8765"],
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["other"] = {"path": str(self.home / "other"), "profile": "READ_ONLY"}
        self.config.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaises(ProvisioningError) as stale:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(stale.exception.code, "CONFIG_CHANGED")

    def test_preflight_rejects_non_development_workspace_and_unmanaged_profile_id(self) -> None:
        service = self._service()
        with self.assertRaises(ProvisioningError) as unmanaged:
            service.preflight(
                workspace_id="fixture",
                kind="browser",
                profile_id="fixture-browser",
                allowed_origins=["http://127.0.0.1:8765"],
            )
        self.assertEqual(unmanaged.exception.code, "PLATFORM_PROFILE_ID_DENIED")

        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["fixture"]["profile"] = "READ_ONLY"
        self.config.write_text(json.dumps(document), encoding="utf-8")
        service = self._service()
        with self.assertRaises(ProvisioningError) as read_only:
            service.preflight(
                workspace_id="fixture",
                kind="desktop",
                profile_id="managed-fixture-desktop",
                bundle_id="com.example.fixture",
            )
        self.assertEqual(read_only.exception.code, "PLATFORM_PROFILE_WORKSPACE_DENIED")

    def test_command_profile_preflight_is_read_only_and_apply_is_one_shot(self) -> None:
        service = self._command_service()
        before = self.config.read_text(encoding="utf-8")

        preflight = service.preflight(
            workspace_id="fixture",
            profile_id="managed-ai-editorial-live-eval",
            argv=["python3", "tools/run_ai_editorial_eval.py"],
            allowed_args={},
            timeout_ms=120000,
            max_output_bytes=131072,
            resources=[],
            credential_slots=[],
            network_class="api-test",
        )

        self.assertEqual(self.config.read_text(encoding="utf-8"), before)
        self.assertEqual(preflight["status"], "new")
        self.assertTrue(preflight["approval_required"])
        self.assertEqual(preflight["network_class"], "api-test")

        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "registered")
        document = json.loads(self.config.read_text(encoding="utf-8"))
        command = document["workspaces"]["fixture"]["platform"]["command_profiles"]["managed-ai-editorial-live-eval"]
        self.assertEqual(command["network_class"], "api-test")

        with self.assertRaises(ProvisioningError) as replay:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(replay.exception.code, "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND")

    def test_command_profile_registration_service_passes_lifecycle_through(self) -> None:
        service = self._command_service()
        lifecycle = {
            "kind": "ephemeral",
            "purpose": "github-bootstrap",
            "owner": "fixture",
            "created_at": "2026-08-21T00:00:00Z",
            "expires_at": "2026-08-21T06:00:00Z",
        }
        preflight = service.preflight(
            workspace_id="fixture",
            profile_id="managed-github-bootstrap",
            argv=["gh", "repo", "view"],
            allowed_args={},
            network_class="github",
            lifecycle=lifecycle,
        )
        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "registered")
        document = json.loads(self.config.read_text(encoding="utf-8"))
        stored = document["workspaces"]["fixture"]["platform"]["command_profiles"]["managed-github-bootstrap"]
        self.assertEqual(stored["lifecycle"], lifecycle)

    def test_command_profile_registration_spec_hash_includes_lifecycle(self) -> None:
        service = self._command_service()
        base = {
            "kind": "ephemeral",
            "purpose": "github-bootstrap",
            "owner": "fixture",
            "created_at": "2026-08-21T00:00:00Z",
            "expires_at": "2026-08-21T06:00:00Z",
        }
        first = service.preflight(
            workspace_id="fixture",
            profile_id="managed-github-bootstrap",
            argv=["gh", "repo", "view"],
            allowed_args={},
            network_class="github",
            lifecycle=base,
        )
        changed = dict(base)
        changed["purpose"] = "different-purpose"
        second = service.preflight(
            workspace_id="fixture",
            profile_id="managed-github-bootstrap",
            argv=["gh", "repo", "view"],
            allowed_args={},
            network_class="github",
            lifecycle=changed,
        )
        self.assertNotEqual(first["spec_hash"], second["spec_hash"])

    def test_cleanup_preflight_selects_expired_deterministically_and_ignores_name_only_profiles(self) -> None:
        self._seed_command_profiles()
        before = self.config.read_bytes()
        first = self._cleanup_service().preflight(workspace_id="fixture", mode="expired")
        second = self._cleanup_service().preflight(workspace_id="fixture", mode="expired")

        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(first["status"], "ready")
        self.assertEqual([item["profile_id"] for item in first["candidates"]], ["managed-expired"])
        self.assertEqual(first["candidate_set_hash"], second["candidate_set_hash"])
        self.assertTrue(first["approval_required"])
        self.assertNotIn("managed-once-name-only", [item["profile_id"] for item in first["candidates"]])

        all_profiles = self._cleanup_service().preflight(workspace_id="fixture", mode="all_ephemeral")
        self.assertEqual(
            [item["profile_id"] for item in all_profiles["candidates"]],
            ["managed-expired", "managed-future"],
        )

    def test_cleanup_preflight_noop_has_no_destructive_approval(self) -> None:
        preflight = self._cleanup_service().preflight(workspace_id="fixture", mode="expired")
        self.assertEqual(preflight["status"], "noop")
        self.assertFalse(preflight["approval_required"])
        self.assertNotIn("approval", preflight)
        self.assertEqual(preflight["candidates"], [])

    def test_cleanup_apply_is_one_shot_and_removes_exact_preflight_set(self) -> None:
        self._seed_command_profiles()
        service = self._cleanup_service()
        preflight = service.preflight(workspace_id="fixture", mode="expired")
        with self.assertRaises(ProvisioningError) as wrong:
            service.apply(preflight_id=preflight["preflight_id"], confirmation="wrong")
        self.assertEqual(wrong.exception.code, "COMMAND_PROFILE_CONFIRMATION_REQUIRED")

        applied = service.apply(
            preflight_id=preflight["preflight_id"],
            confirmation=preflight["approval"]["confirmation"],
        )
        self.assertEqual(applied["status"], "cleaned")
        self.assertTrue(applied["approval_consumed"])
        self.assertEqual(applied["removed_profile_ids"], ["managed-expired"])
        document = json.loads(self.config.read_text(encoding="utf-8"))
        remaining = document["workspaces"]["fixture"]["platform"]["command_profiles"]
        self.assertNotIn("managed-expired", remaining)
        self.assertIn("managed-future", remaining)
        self.assertIn("managed-once-name-only", remaining)

        with self.assertRaises(ProvisioningError) as replay:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(replay.exception.code, "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND")

    def test_cleanup_apply_fails_closed_if_registry_drifts_after_preflight(self) -> None:
        self._seed_command_profiles()
        service = self._cleanup_service()
        preflight = service.preflight(workspace_id="fixture", mode="expired")
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["fixture"]["metadata"] = {"drift": True}
        self.config.write_text(json.dumps(document), encoding="utf-8")
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as drift:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(drift.exception.code, "CONFIG_CHANGED")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_apply_rejects_expired_preflight(self) -> None:
        from chatgpt_dev_mcp.platform_profile_mcp import CommandProfileCleanupService

        self._seed_command_profiles()
        clock = [datetime(2026, 8, 21, 2, 0, tzinfo=timezone.utc).timestamp()]
        service = CommandProfileCleanupService(
            self.config,
            home=self.home,
            now=lambda: clock[0],
            ttl_seconds=60,
        )
        preflight = service.preflight(workspace_id="fixture", mode="expired")
        clock[0] += 61
        with self.assertRaises(ProvisioningError) as expired:
            service.apply(
                preflight_id=preflight["preflight_id"],
                confirmation=preflight["approval"]["confirmation"],
            )
        self.assertEqual(expired.exception.code, "COMMAND_PROFILE_PREFLIGHT_EXPIRED")


if __name__ == "__main__":
    unittest.main()
