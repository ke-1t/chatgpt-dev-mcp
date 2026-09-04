from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from chatgpt_dev_mcp.host_files import HostFileController, HostFileError, HostFilePolicy


class HostFileControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        (self.home / "Library" / "Caches").mkdir(parents=True)
        (self.home / "Library" / "Logs").mkdir(parents=True)
        (self.home / ".cache").mkdir()
        (self.home / ".codex" / ".tmp").mkdir(parents=True)
        (self.home / ".codex" / "plugins" / "cache").mkdir(parents=True)
        (self.home / ".Trash").mkdir()
        self.apps = Path(self.temp.name) / "Applications"
        self.apps.mkdir()
        self.policy = HostFilePolicy(home=self.home, applications_root=self.apps, receipt_ttl_seconds=60)
        self.controller = HostFileController(policy=self.policy, capability_epoch="child-a")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_default_receipt_ttl_is_one_hour(self) -> None:
        policy = HostFilePolicy(home=self.home, applications_root=self.apps)

        self.assertEqual(policy.receipt_ttl_seconds, 3600.0)

    def test_trash_moves_ordinary_home_directory_and_returns_destination(self) -> None:
        target = self.home / "Library" / "Application Support" / "Zed"
        target.mkdir(parents=True)
        (target / "cache.bin").write_bytes(b"x" * 32)

        preflight = self.controller.preflight(operation="trash", paths=[str(target)])
        result = self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )

        self.assertFalse(target.exists())
        destination = Path(result["items"][0]["destination"])
        self.assertTrue(destination.exists())
        self.assertEqual(destination.parent.resolve(), (self.home / ".Trash").resolve())

    def test_trash_uses_unique_destination_when_name_already_exists(self) -> None:
        target = self.home / "Downloads" / "Thing"
        target.mkdir(parents=True)
        (self.home / ".Trash" / "Thing").mkdir()

        preflight = self.controller.preflight(operation="trash", paths=[str(target)])
        result = self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )

        destination = Path(result["items"][0]["destination"])
        self.assertNotEqual(destination.name, "Thing")
        self.assertTrue(destination.exists())

    def test_delete_permanently_removes_disposable_cache_directory(self) -> None:
        target = self.home / "Library" / "Caches" / "Example"
        target.mkdir()
        (target / "item").write_text("cache", encoding="utf-8")

        preflight = self.controller.preflight(operation="delete", paths=[str(target)])
        self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )

        self.assertFalse(target.exists())

    def test_delete_rejects_non_disposable_user_data(self) -> None:
        target = self.home / "Documents" / "important"
        target.mkdir(parents=True)

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="delete", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PERMANENT_DELETE_DENIED")

    def test_delete_allows_cache_like_application_support_subtrees(self) -> None:
        targets = (
            self.home / "Library" / "Application Support" / "Example" / "Cache",
            self.home / "Library" / "Application Support" / "Example" / "Code Cache",
            self.home / "Library" / "Application Support" / "Example" / "CachedData",
            self.home / "Library" / "Application Support" / "Example" / "CachedExtensionVSIXs",
            self.home / "Library" / "Application Support" / "Google" / "GoogleUpdater" / "crx_cache",
            self.home / "Library" / "Application Support" / "Zed" / "node" / "cache",
            self.home / "Library" / "Application Support" / "Example" / "staging",
        )
        for target in targets:
            with self.subTest(target=target):
                target.mkdir(parents=True, exist_ok=True)
                (target / "payload").write_text("cache", encoding="utf-8")
                preflight = self.controller.preflight(operation="delete", paths=[str(target)])
                self.controller.apply(
                    preflight_id=str(preflight["preflight_id"]),
                    confirmation=str(preflight["confirmation"]),
                )
                self.assertFalse(target.exists())

    def test_delete_rejects_application_support_app_root_and_non_cache_state(self) -> None:
        app_root = self.home / "Library" / "Application Support" / "Example"
        workspace_state = app_root / "User" / "workspaceStorage"
        workspace_state.mkdir(parents=True)

        for target in (app_root, workspace_state):
            with self.subTest(target=target):
                with self.assertRaises(HostFileError) as caught:
                    self.controller.preflight(operation="delete", paths=[str(target)])
                self.assertEqual(caught.exception.code, "HOST_FILE_PERMANENT_DELETE_DENIED")

    def test_delete_rejects_too_shallow_application_support_cache_name(self) -> None:
        target = self.home / "Library" / "Application Support" / "Cache"
        target.mkdir(parents=True)

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="delete", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PERMANENT_DELETE_DENIED")

    def test_delete_allows_codex_plugin_staging_but_not_plugin_root(self) -> None:
        staging = self.home / ".codex" / "plugins" / "marketplace" / "example" / "staging"
        plugin_root = self.home / ".codex" / "plugins" / "marketplace" / "example"
        staging.mkdir(parents=True)
        (staging / "payload").write_text("cache", encoding="utf-8")

        preflight = self.controller.preflight(operation="delete", paths=[str(staging)])
        self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )
        self.assertFalse(staging.exists())

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="delete", paths=[str(plugin_root)])
        self.assertEqual(caught.exception.code, "HOST_FILE_PERMANENT_DELETE_DENIED")

    def test_mutation_rejects_sensitive_home_subtree(self) -> None:
        target = self.home / ".ssh"
        target.mkdir()

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="trash", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PATH_DENIED")

    def test_mutation_rejects_parent_that_contains_sensitive_home_subtree(self) -> None:
        target = self.home / "Library"
        (target / "Keychains").mkdir(parents=True)

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="trash", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PATH_DENIED")

    def test_delete_rejects_parent_that_contains_internal_receipt_state(self) -> None:
        target = self.home / ".cache"

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="delete", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PATH_DENIED")

    def test_mutation_rejects_path_outside_allowed_roots(self) -> None:
        target = Path(self.temp.name) / "outside"
        target.mkdir()

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="trash", paths=[str(target)])

        self.assertEqual(caught.exception.code, "HOST_FILE_PATH_DENIED")

    def test_top_level_symlink_is_rejected(self) -> None:
        real = self.home / "Library" / "Caches" / "real"
        real.mkdir()
        link = self.home / "Library" / "Caches" / "link"
        link.symlink_to(real, target_is_directory=True)

        with self.assertRaises(HostFileError) as caught:
            self.controller.preflight(operation="delete", paths=[str(link)])

        self.assertEqual(caught.exception.code, "HOST_FILE_SYMLINK_DENIED")

    def test_nested_change_after_preflight_is_rejected_as_stale(self) -> None:
        target = self.home / "Library" / "Caches" / "changing"
        nested = target / "nested"
        nested.mkdir(parents=True)
        payload = nested / "payload"
        payload.write_text("before", encoding="utf-8")
        preflight = self.controller.preflight(operation="delete", paths=[str(target)])
        payload.write_text("after-after", encoding="utf-8")

        with self.assertRaises(HostFileError) as caught:
            self.controller.apply(
                preflight_id=str(preflight["preflight_id"]),
                confirmation=str(preflight["confirmation"]),
            )

        self.assertEqual(caught.exception.code, "HOST_FILE_TARGET_STALE")
        self.assertTrue(target.exists())

    def test_receipt_is_one_time(self) -> None:
        target = self.home / "Library" / "Caches" / "once"
        target.mkdir()
        preflight = self.controller.preflight(operation="delete", paths=[str(target)])
        self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )

        with self.assertRaises(HostFileError) as caught:
            self.controller.apply(
                preflight_id=str(preflight["preflight_id"]),
                confirmation=str(preflight["confirmation"]),
            )

        self.assertEqual(caught.exception.code, "HOST_FILE_PREFLIGHT_UNKNOWN")

    def test_receipt_survives_controller_recreation(self) -> None:
        target = self.home / "Library" / "Caches" / "persistent"
        target.mkdir()
        preflight = self.controller.preflight(operation="delete", paths=[str(target)])

        replacement = HostFileController(policy=self.policy, capability_epoch="child-a")
        replacement.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )

        self.assertFalse(target.exists())

    def test_receipt_cannot_be_consumed_by_a_different_runtime_capability_epoch(self) -> None:
        target = self.home / "Library" / "Caches" / "cross-child"
        target.mkdir()
        preflight = self.controller.preflight(operation="delete", paths=[str(target)])

        replacement = HostFileController(policy=self.policy, capability_epoch="child-b")
        with self.assertRaises(HostFileError) as caught:
            replacement.apply(
                preflight_id=str(preflight["preflight_id"]),
                confirmation=str(preflight["confirmation"]),
            )

        self.assertEqual(caught.exception.code, "HOST_FILE_PREFLIGHT_CAPABILITY_MISMATCH")
        self.assertTrue(target.exists())

        self.controller.apply(
            preflight_id=str(preflight["preflight_id"]),
            confirmation=str(preflight["confirmation"]),
        )
        self.assertFalse(target.exists())

    def test_expired_receipt_is_rejected(self) -> None:
        target = self.home / "Library" / "Caches" / "expires"
        target.mkdir()
        controller = HostFileController(
            policy=HostFilePolicy(home=self.home, applications_root=self.apps, receipt_ttl_seconds=0.01)
        )
        preflight = controller.preflight(operation="delete", paths=[str(target)])
        time.sleep(0.02)

        with self.assertRaises(HostFileError) as caught:
            controller.apply(
                preflight_id=str(preflight["preflight_id"]),
                confirmation=str(preflight["confirmation"]),
            )

        self.assertEqual(caught.exception.code, "HOST_FILE_PREFLIGHT_EXPIRED")


if __name__ == "__main__":
    unittest.main()
