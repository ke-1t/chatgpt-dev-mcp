from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path


class PlatformProfileRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="platform-profile-registry-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.project = self.home / "Developer" / "sample-workspace"
        self.project.mkdir(parents=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self._write_config()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_config(self) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "sample-workspace": {
                            "path": str(self.project),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "python3 -m unittest"},
                            "platform": {
                                "browser_profiles": {},
                                "github": {"owner": "keep", "repository": "keep"},
                            },
                        },
                        "other": {
                            "path": str(self.home / "Developer" / "other"),
                            "profile": "READ_ONLY",
                            "commands": {},
                            "metadata": {"keep": "unchanged"},
                        },
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def _digest(self) -> str:
        return hashlib.sha256(self.config.read_bytes()).hexdigest()

    @staticmethod
    def _profile_hash(profile: dict[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()

    def _manager(self):
        from chatgpt_dev_mcp.platform_profile_registry import PlatformProfileRegistryManager

        return PlatformProfileRegistryManager(self.config, home=self.home)

    def test_register_browser_profile_preserves_unrelated_config(self) -> None:
        before = json.loads(self.config.read_text(encoding="utf-8"))
        result = self._manager().register_browser(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-sample-local",
            allowed_origins=("http://127.0.0.1:8765",),
            viewport_width=1280,
            viewport_height=720,
            max_screenshot_bytes=8 * 1024 * 1024,
        )
        after = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "registered")
        self.assertFalse(result["external_execution"])
        self.assertEqual(result["profile_id"], "managed-sample-local")
        self.assertEqual(result["kind"], "browser")
        self.assertEqual(after["workspaces"]["other"], before["workspaces"]["other"])
        self.assertEqual(
            after["workspaces"]["sample-workspace"]["platform"]["github"],
            before["workspaces"]["sample-workspace"]["platform"]["github"],
        )
        self.assertEqual(
            after["workspaces"]["sample-workspace"]["platform"]["browser_profiles"]["managed-sample-local"],
            {
                "allowed_origins": ["http://127.0.0.1:8765"],
                "viewport_width": 1280,
                "viewport_height": 720,
                "max_screenshot_bytes": 8 * 1024 * 1024,
            },
        )

    def test_identical_browser_registration_is_idempotent(self) -> None:
        manager = self._manager()
        first = manager.register_browser(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-sample-local",
            allowed_origins=("http://127.0.0.1:8765",),
        )
        first_bytes = self.config.read_bytes()
        second = manager.register_browser(
            workspace_id="sample-workspace",
            expected_config_digest=first["config_digest"],
            expected_workspace_path=self.project,
            profile_id="managed-sample-local",
            allowed_origins=("http://127.0.0.1:8765",),
        )
        self.assertEqual(second["status"], "idempotent")
        self.assertEqual(self.config.read_bytes(), first_bytes)

    def test_stale_digest_is_rejected_without_mutation(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            self._manager().register_browser(
                workspace_id="sample-workspace",
                expected_config_digest="0" * 64,
                expected_workspace_path=self.project,
                profile_id="managed-sample-local",
                allowed_origins=("http://127.0.0.1:8765",),
            )
        self.assertEqual(raised.exception.code, "CONFIG_CHANGED")
        self.assertEqual(self.config.read_bytes(), before)

    def test_workspace_path_pin_is_rejected_without_mutation(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            self._manager().register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.home / "Developer" / "replacement",
                profile_id="managed-sample-local",
                allowed_origins=("http://127.0.0.1:8765",),
            )
        self.assertEqual(raised.exception.code, "WORKSPACE_SOURCE_CHANGED")
        self.assertEqual(self.config.read_bytes(), before)

    def test_same_id_with_different_spec_is_conflict(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        first = manager.register_browser(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-sample-local",
            allowed_origins=("http://127.0.0.1:8765",),
        )
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=first["config_digest"],
                expected_workspace_path=self.project,
                profile_id="managed-sample-local",
                allowed_origins=("http://localhost:8765",),
            )
        self.assertEqual(raised.exception.code, "PLATFORM_PROFILE_CONFLICT")
        self.assertEqual(self.config.read_bytes(), before)

    def test_browser_profile_id_requires_managed_prefix(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        with self.assertRaises(ProvisioningError) as raised:
            self._manager().register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="personal-profile",
                allowed_origins=("http://127.0.0.1:8765",),
            )
        self.assertEqual(raised.exception.code, "PLATFORM_PROFILE_ID_DENIED")

    def test_browser_origin_and_screenshot_bounds_are_rejected(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        with self.assertRaises(ProvisioningError) as origin_error:
            manager.register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="managed-sample-local",
                allowed_origins=("http://user:pass@127.0.0.1:8765",),
            )
        self.assertEqual(origin_error.exception.code, "PLATFORM_PROFILE_INVALID")
        with self.assertRaises(ProvisioningError) as byte_error:
            manager.register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="managed-sample-local",
                allowed_origins=("http://127.0.0.1:8765",),
                max_screenshot_bytes=128 * 1024 * 1024,
            )
        self.assertEqual(byte_error.exception.code, "PLATFORM_PROFILE_INVALID")

    def test_registration_rejects_unrelated_invalid_platform_without_mutation(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["workspaces"]["other"]["platform"] = {"unknown_platform_key": True}
        self.config.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            self._manager().register_browser(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="managed-sample-local",
                allowed_origins=("http://127.0.0.1:8765",),
            )
        self.assertEqual(raised.exception.code, "CONFIG_INVALID")
        self.assertEqual(self.config.read_bytes(), before)

    def test_register_capture_only_desktop_profile_preserves_unrelated_config(self) -> None:
        before = json.loads(self.config.read_text(encoding="utf-8"))
        result = self._manager().register_desktop(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-sample-workspace-tauri",
            bundle_id="work.sample-workspace.market-ops",
            max_screenshot_bytes=8 * 1024 * 1024,
        )
        after = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["kind"], "desktop")
        self.assertEqual(after["workspaces"]["other"], before["workspaces"]["other"])
        self.assertEqual(
            after["workspaces"]["sample-workspace"]["platform"]["desktop_profiles"]["managed-sample-workspace-tauri"],
            {
                "bundle_id": "work.sample-workspace.market-ops",
                "max_screenshot_bytes": 8 * 1024 * 1024,
            },
        )

    def test_identical_desktop_registration_is_idempotent(self) -> None:
        manager = self._manager()
        first = manager.register_desktop(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-sample-workspace-tauri",
            bundle_id="work.sample-workspace.market-ops",
        )
        first_bytes = self.config.read_bytes()
        second = manager.register_desktop(
            workspace_id="sample-workspace",
            expected_config_digest=first["config_digest"],
            expected_workspace_path=self.project,
            profile_id="managed-sample-workspace-tauri",
            bundle_id="work.sample-workspace.market-ops",
        )
        self.assertEqual(second["status"], "idempotent")
        self.assertEqual(self.config.read_bytes(), first_bytes)

    def test_desktop_registration_rejects_unmanaged_id_and_non_loopback_health(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        with self.assertRaises(ProvisioningError) as id_error:
            manager.register_desktop(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="personal-tauri",
                bundle_id="work.sample-workspace.market-ops",
            )
        self.assertEqual(id_error.exception.code, "PLATFORM_PROFILE_ID_DENIED")
        with self.assertRaises(ProvisioningError) as health_error:
            manager.register_desktop(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="managed-sample-workspace-tauri",
                bundle_id="work.sample-workspace.market-ops",
                health_url="https://example.com/health",
            )
        self.assertEqual(health_error.exception.code, "PLATFORM_PROFILE_INVALID")

    def test_register_command_profile_preserves_unrelated_config(self) -> None:
        before = json.loads(self.config.read_text(encoding="utf-8"))
        result = self._manager().register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-ai-editorial-live-eval",
            argv=(
                "python3",
                "tools/run_ai_editorial_eval.py",
                "--profile",
                "config/ai/profiles/luna-assisted.json",
            ),
            allowed_args={},
            timeout_ms=120000,
            max_output_bytes=131072,
            resources=(),
            credential_slots=(),
            network_class="api-test",
        )
        after = json.loads(self.config.read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["profile_id"], "managed-ai-editorial-live-eval")
        self.assertEqual(after["workspaces"]["other"], before["workspaces"]["other"])
        profile = after["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-ai-editorial-live-eval"]
        self.assertEqual(profile["network_class"], "api-test")
        self.assertEqual(profile["credential_slots"], [])
        self.assertEqual(profile["resources"], [])
        self.assertEqual(profile["argv"][0], "python3")

    def test_register_ephemeral_command_profile_stores_lifecycle_and_conflicts_on_change(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        lifecycle = {
            "kind": "ephemeral",
            "purpose": "github-bootstrap",
            "owner": "sample-workspace",
            "created_at": "2026-08-21T00:00:00Z",
            "expires_at": "2026-08-21T06:00:00Z",
        }
        first = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-github-bootstrap",
            argv=("gh", "repo", "view"),
            allowed_args={},
            network_class="github",
            lifecycle=lifecycle,
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        stored = document["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-github-bootstrap"]
        self.assertEqual(stored["lifecycle"], lifecycle)

        second = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=first["config_digest"],
            expected_workspace_path=self.project,
            profile_id="managed-github-bootstrap",
            argv=("gh", "repo", "view"),
            allowed_args={},
            network_class="github",
            lifecycle=lifecycle,
        )
        self.assertEqual(second["status"], "idempotent")

        changed = dict(lifecycle)
        changed["purpose"] = "different-purpose"
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.register_command_profile(
                workspace_id="sample-workspace",
                expected_config_digest=second["config_digest"],
                expected_workspace_path=self.project,
                profile_id="managed-github-bootstrap",
                argv=("gh", "repo", "view"),
                allowed_args={},
                network_class="github",
                lifecycle=changed,
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_CONFLICT")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_expired_ephemeral_command_profiles_removes_only_pinned_candidates(self) -> None:
        manager = self._manager()
        digest = self._digest()
        for profile_id, lifecycle in (
            (
                "managed-expired",
                {"kind": "ephemeral", "purpose": "expired", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-21T01:00:00Z"},
            ),
            (
                "managed-future",
                {"kind": "ephemeral", "purpose": "future", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-21T06:00:00Z"},
            ),
        ):
            result = manager.register_command_profile(
                workspace_id="sample-workspace",
                expected_config_digest=digest,
                expected_workspace_path=self.project,
                profile_id=profile_id,
                argv=("echo", profile_id),
                allowed_args={},
                lifecycle=lifecycle,
            )
            digest = result["config_digest"]
        permanent = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=digest,
            expected_workspace_path=self.project,
            profile_id="managed-once-but-permanent",
            argv=("echo", "permanent"),
            allowed_args={},
        )
        before = json.loads(self.config.read_text(encoding="utf-8"))
        profiles = before["workspaces"]["sample-workspace"]["platform"]["command_profiles"]
        expired_hash = self._profile_hash(profiles["managed-expired"])

        result = manager.cleanup_ephemeral_command_profiles(
            workspace_id="sample-workspace",
            expected_config_digest=permanent["config_digest"],
            expected_workspace_path=self.project,
            candidate_profile_hashes={"managed-expired": expired_hash},
            mode="expired",
            evaluation_time="2026-08-21T02:00:00Z",
        )
        after = json.loads(self.config.read_text(encoding="utf-8"))
        remaining = after["workspaces"]["sample-workspace"]["platform"]["command_profiles"]
        self.assertEqual(result["status"], "cleaned")
        self.assertEqual(result["removed_profile_ids"], ["managed-expired"])
        self.assertEqual(result["removed_profile_hashes"], {"managed-expired": expired_hash})
        self.assertNotIn("managed-expired", remaining)
        self.assertIn("managed-future", remaining)
        self.assertIn("managed-once-but-permanent", remaining)

    def test_cleanup_ephemeral_command_profiles_fails_closed_on_candidate_drift(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        registered = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-expired",
            argv=("echo", "expired"),
            allowed_args={},
            lifecycle={"kind": "ephemeral", "purpose": "expired", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-21T01:00:00Z"},
        )
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.cleanup_ephemeral_command_profiles(
                workspace_id="sample-workspace",
                expected_config_digest=registered["config_digest"],
                expected_workspace_path=self.project,
                candidate_profile_hashes={"managed-expired": "0" * 64},
                mode="expired",
                evaluation_time="2026-08-21T02:00:00Z",
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_CHANGED")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_ephemeral_rejects_permanent_candidate_without_mutation(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        registered = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-temp-name-only",
            argv=("echo", "permanent"),
            allowed_args={},
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        profile = document["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-temp-name-only"]
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.cleanup_ephemeral_command_profiles(
                workspace_id="sample-workspace",
                expected_config_digest=registered["config_digest"],
                expected_workspace_path=self.project,
                candidate_profile_hashes={"managed-temp-name-only": self._profile_hash(profile)},
                mode="all_ephemeral",
                evaluation_time="2026-08-21T02:00:00Z",
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_NOT_EPHEMERAL")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_ephemeral_fails_closed_when_candidate_disappears(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-expired",
            argv=("echo", "expired"),
            allowed_args={},
            lifecycle={"kind": "ephemeral", "purpose": "expired", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-21T01:00:00Z"},
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        profile = document["workspaces"]["sample-workspace"]["platform"]["command_profiles"].pop("managed-expired")
        pinned_hash = self._profile_hash(profile)
        self.config.write_text(json.dumps(document), encoding="utf-8")
        current_digest = self._digest()
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.cleanup_ephemeral_command_profiles(
                workspace_id="sample-workspace",
                expected_config_digest=current_digest,
                expected_workspace_path=self.project,
                candidate_profile_hashes={"managed-expired": pinned_hash},
                mode="expired",
                evaluation_time="2026-08-21T02:00:00Z",
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_NOT_FOUND")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_ephemeral_fails_closed_when_candidate_is_no_longer_ephemeral(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-expired",
            argv=("echo", "expired"),
            allowed_args={},
            lifecycle={"kind": "ephemeral", "purpose": "expired", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-21T01:00:00Z"},
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        profile = document["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-expired"]
        profile.pop("lifecycle")
        self.config.write_text(json.dumps(document), encoding="utf-8")
        current_digest = self._digest()
        pinned_hash = self._profile_hash(profile)
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.cleanup_ephemeral_command_profiles(
                workspace_id="sample-workspace",
                expected_config_digest=current_digest,
                expected_workspace_path=self.project,
                candidate_profile_hashes={"managed-expired": pinned_hash},
                mode="all_ephemeral",
                evaluation_time="2026-08-21T02:00:00Z",
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_NOT_EPHEMERAL")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cleanup_expired_rejects_ephemeral_candidate_without_expiry(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        registered = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-no-expiry",
            argv=("echo", "no-expiry"),
            allowed_args={},
            lifecycle={"kind": "ephemeral", "purpose": "manual-teardown", "owner": "sample-workspace", "created_at": "2026-08-21T00:00:00Z"},
        )
        document = json.loads(self.config.read_text(encoding="utf-8"))
        profile = document["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-no-expiry"]
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.cleanup_ephemeral_command_profiles(
                workspace_id="sample-workspace",
                expected_config_digest=registered["config_digest"],
                expected_workspace_path=self.project,
                candidate_profile_hashes={"managed-no-expiry": self._profile_hash(profile)},
                mode="expired",
                evaluation_time="2026-08-21T02:00:00Z",
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_NOT_ELIGIBLE")
        self.assertEqual(self.config.read_bytes(), before)

    def test_unregister_command_profile_removes_only_exact_pinned_profile(self) -> None:
        manager = self._manager()
        registered = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-ai-editorial-live-eval",
            argv=("python3", "tools/run_ai_editorial_eval.py"),
            allowed_args={},
            network_class="api-test",
        )
        before = json.loads(self.config.read_text(encoding="utf-8"))
        profile = before["workspaces"]["sample-workspace"]["platform"]["command_profiles"]["managed-ai-editorial-live-eval"]
        profile_hash = hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()

        result = manager.unregister_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=registered["config_digest"],
            expected_workspace_path=self.project,
            profile_id="managed-ai-editorial-live-eval",
            expected_profile_hash=profile_hash,
        )
        after = json.loads(self.config.read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "unregistered")
        self.assertNotIn(
            "managed-ai-editorial-live-eval",
            after["workspaces"]["sample-workspace"]["platform"]["command_profiles"],
        )
        self.assertEqual(after["workspaces"]["sample-workspace"]["platform"]["github"], before["workspaces"]["sample-workspace"]["platform"]["github"])
        self.assertEqual(after["workspaces"]["other"], before["workspaces"]["other"])

    def test_unregister_command_profile_rejects_changed_profile_without_mutation(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        manager = self._manager()
        registered = manager.register_command_profile(
            workspace_id="sample-workspace",
            expected_config_digest=self._digest(),
            expected_workspace_path=self.project,
            profile_id="managed-ai-editorial-live-eval",
            argv=("python3", "tools/run_ai_editorial_eval.py"),
            allowed_args={},
            network_class="api-test",
        )
        before = self.config.read_bytes()
        with self.assertRaises(ProvisioningError) as raised:
            manager.unregister_command_profile(
                workspace_id="sample-workspace",
                expected_config_digest=registered["config_digest"],
                expected_workspace_path=self.project,
                profile_id="managed-ai-editorial-live-eval",
                expected_profile_hash="0" * 64,
            )
        self.assertEqual(raised.exception.code, "COMMAND_PROFILE_CHANGED")
        self.assertEqual(self.config.read_bytes(), before)

    def test_command_profile_registration_rejects_unmanaged_id(self) -> None:
        from chatgpt_dev_mcp.provisioning import ProvisioningError

        with self.assertRaises(ProvisioningError) as raised:
            self._manager().register_command_profile(
                workspace_id="sample-workspace",
                expected_config_digest=self._digest(),
                expected_workspace_path=self.project,
                profile_id="ai-editorial-live-eval",
                argv=("python3", "tools/run_ai_editorial_eval.py"),
                allowed_args={},
                network_class="api-test",
            )
        self.assertEqual(raised.exception.code, "PLATFORM_PROFILE_ID_DENIED")


if __name__ == "__main__":
    unittest.main()
