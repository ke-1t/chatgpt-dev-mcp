from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chatgpt_dev_mcp.process_runner import BoundedProcessResult

from chatgpt_dev_mcp.system_inspection import SystemInspectionController, SystemInspectionError


class SystemInspectionTests(unittest.TestCase):
    @staticmethod
    def _result(stdout: str = "", *, returncode: int = 0, truncated: bool = False) -> BoundedProcessResult:
        return BoundedProcessResult(
            returncode=returncode,
            stdout=stdout,
            stderr="",
            timed_out=False,
            stdout_truncated=truncated,
            stderr_truncated=False,
            elapsed_ms=1,
        )

    def test_disk_usage_is_shell_free_and_fixed_argv(self) -> None:
        controller = SystemInspectionController()
        home = str(Path.home())
        completed = self._result("1.0G\tUsers\n")
        with patch("chatgpt_dev_mcp.system_inspection.shutil.which", return_value="/usr/bin/du"), patch(
            "chatgpt_dev_mcp.system_inspection.run_bounded", return_value=completed
        ) as run:
            result = controller.inspect({"action": "disk_usage", "path": home, "depth": 1})
        argv = run.call_args.args[0]
        self.assertEqual(argv[:5], ["/usr/bin/du", "-x", "-h", "-d", "1"])
        self.assertEqual(argv[-1], home)
        self.assertTrue(run.call_args.kwargs["merge_stderr"])
        self.assertTrue(result["read_only"])

    def test_root_is_only_allowed_for_filesystem_summary(self) -> None:
        controller = SystemInspectionController()
        completed = self._result("df\n")
        with patch("chatgpt_dev_mcp.system_inspection.shutil.which", return_value="/bin/df"), patch(
            "chatgpt_dev_mcp.system_inspection.run_bounded", return_value=completed
        ):
            result = controller.inspect({"action": "filesystem", "path": "/"})
        self.assertEqual(result["status"], "succeeded")
        with self.assertRaises(SystemInspectionError) as caught:
            controller.inspect({"action": "disk_usage", "path": "/", "depth": 1})
        self.assertEqual(caught.exception.code, "SYSTEM_INSPECTION_PATH_DENIED")

    def test_private_system_paths_are_denied(self) -> None:
        controller = SystemInspectionController()
        for path in ("/System", "/private", "/dev"):
            with self.subTest(path=path), self.assertRaises(SystemInspectionError) as caught:
                controller.inspect({"action": "disk_usage", "path": path, "depth": 1})
            self.assertEqual(caught.exception.code, "SYSTEM_INSPECTION_PATH_DENIED")

    def test_external_arbitrary_path_is_denied(self) -> None:
        controller = SystemInspectionController()
        with self.assertRaises(SystemInspectionError) as caught:
            controller.inspect({"action": "stat", "paths": ["/opt/secret"]})
        self.assertEqual(caught.exception.code, "SYSTEM_INSPECTION_PATH_DENIED")

    def test_metadata_uses_fixed_attribute_allowlist(self) -> None:
        controller = SystemInspectionController()
        completed = self._result("metadata\n")
        with patch("chatgpt_dev_mcp.system_inspection.shutil.which", return_value="/usr/bin/mdls"), patch(
            "chatgpt_dev_mcp.system_inspection.run_bounded", return_value=completed
        ) as run:
            controller.inspect({"action": "metadata", "paths": [str(Path.home())]})
        argv = run.call_args.args[0]
        self.assertIn("kMDItemFSSize", argv)
        self.assertIn("kMDItemIsUbiquitous", argv)
        self.assertNotIn("-raw", argv)

    def test_output_is_bounded(self) -> None:
        controller = SystemInspectionController()
        completed = self._result("x" * 131_072, truncated=True)
        with patch("chatgpt_dev_mcp.system_inspection.shutil.which", return_value="/bin/df"), patch(
            "chatgpt_dev_mcp.system_inspection.run_bounded", return_value=completed
        ):
            result = controller.inspect({"action": "filesystem", "path": "/"})
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["output"].encode()), 131_072)

    def test_registry_capability_is_read_only_and_idempotent(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            tools = {item["name"]: item for item in runtime.list_tools()["tools"]}
            self.assertNotIn("system_inspect", tools)
            described = runtime.call_tool(
                "capability_describe",
                {"capability_id": "system_inspect"},
            )["structuredContent"]
            self.assertEqual(described["risk_class"], "R0")
            self.assertEqual(described["approval_policy"], "none")
            self.assertEqual(described["idempotency"], "idempotent")
            self.assertEqual(described["exposure"], "registry")
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
