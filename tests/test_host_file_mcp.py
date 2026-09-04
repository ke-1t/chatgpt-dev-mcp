from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chatgpt_dev_mcp.host_files import HostFileController, HostFilePolicy


class HostFileMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="host-file-mcp-")
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        (self.home / ".Trash").mkdir()
        (self.home / ".cache").mkdir()
        (self.home / "Library" / "Caches").mkdir(parents=True)
        (self.home / "Library" / "Logs").mkdir(parents=True)
        (self.home / ".codex" / ".tmp").mkdir(parents=True)
        (self.home / ".codex" / "plugins" / "cache").mkdir(parents=True)
        self.apps = Path(self.temp.name) / "Applications"
        self.apps.mkdir()
        self.controller = HostFileController(
            policy=HostFilePolicy(home=self.home, applications_root=self.apps, receipt_ttl_seconds=60)
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_public_tools_are_two_phase_and_fail_closed(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        runtime._host_files = self.controller
        try:
            by_name = {item["name"]: item for item in runtime.list_tools()["tools"]}
            for capability_id in ("host_file_preflight", "host_file_apply"):
                self.assertNotIn(capability_id, by_name)
                described = runtime.call_tool(
                    "capability_describe",
                    {"capability_id": capability_id},
                )["structuredContent"]
                self.assertEqual(described["exposure"], "registry")
                self.assertEqual(described["risk_class"], "R3")

            target = self.home / "Downloads" / "Disposable"
            target.mkdir(parents=True)
            (target / "payload.bin").write_bytes(b"x" * 8)

            preflight_result = runtime.call_tool(
                "host_file_preflight",
                {"operation": "trash", "paths": [str(target)]},
            )
            self.assertFalse(preflight_result["isError"], preflight_result)
            preflight = preflight_result["structuredContent"]
            self.assertEqual(preflight["operation"], "trash")
            self.assertEqual(preflight["risk_class"], "R2")
            self.assertTrue(preflight["approval_required"])
            self.assertTrue(target.exists())

            wrong = runtime.call_tool(
                "host_file_apply",
                {"preflight_id": preflight["preflight_id"], "confirmation": "wrong"},
            )
            self.assertTrue(wrong["isError"])
            self.assertTrue(target.exists())

            applied = runtime.call_tool(
                "host_file_apply",
                {"preflight_id": preflight["preflight_id"], "confirmation": preflight["confirmation"]},
            )
            self.assertFalse(applied["isError"], applied)
            payload = applied["structuredContent"]
            self.assertEqual(payload["operation"], "trash")
            self.assertEqual(payload["risk_class"], "R2")
            self.assertTrue(payload["reversible"])
            self.assertFalse(target.exists())
            self.assertTrue(Path(payload["items"][0]["destination"]).exists())

            cache_target = self.home / "Library" / "Caches" / "DeleteMe"
            cache_target.mkdir()
            delete_preflight = runtime.call_tool(
                "host_file_preflight",
                {"operation": "delete", "paths": [str(cache_target)]},
            )["structuredContent"]
            self.assertEqual(delete_preflight["risk_class"], "R3")
            self.assertTrue(delete_preflight["approval_required"])
            delete_result = runtime.call_tool(
                "host_file_apply",
                {
                    "preflight_id": delete_preflight["preflight_id"],
                    "confirmation": delete_preflight["confirmation"],
                },
            )
            self.assertFalse(delete_result["isError"], delete_result)
            self.assertEqual(delete_result["structuredContent"]["risk_class"], "R3")
            self.assertFalse(cache_target.exists())

            important = self.home / "Documents" / "Important"
            important.mkdir(parents=True)
            denied = runtime.call_tool(
                "host_file_preflight",
                {"operation": "delete", "paths": [str(important)]},
            )
            self.assertTrue(denied["isError"])
            self.assertEqual(denied["structuredContent"]["error"]["code"], "HOST_FILE_PERMANENT_DELETE_DENIED")
        finally:
            runtime.close()

    def test_host_file_receipt_survives_wrapper_runtime_boundary(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        first = WrapperRuntime()
        second = WrapperRuntime()
        policy = HostFilePolicy(home=self.home, applications_root=self.apps, receipt_ttl_seconds=60)
        first._host_files = HostFileController(
            policy=policy,
            capability_epoch=first.runtime_capability_epoch,
        )
        second._host_files = HostFileController(
            policy=policy,
            capability_epoch=second.runtime_capability_epoch,
        )
        try:
            target = self.home / "Downloads" / "CrossRuntimeDisposable"
            target.mkdir(parents=True)
            (target / "payload.bin").write_bytes(b"x" * 8)

            preflight_result = first.call_tool(
                "host_file_preflight",
                {"operation": "trash", "paths": [str(target)]},
            )
            self.assertFalse(preflight_result["isError"], preflight_result)
            preflight = preflight_result["structuredContent"]

            applied = second.call_tool(
                "host_file_apply",
                {
                    "preflight_id": preflight["preflight_id"],
                    "confirmation": preflight["confirmation"],
                },
            )

            self.assertFalse(applied["isError"], applied)
            self.assertFalse(target.exists())
        finally:
            second.close()
            first.close()


if __name__ == "__main__":
    unittest.main()
