from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chatgpt_dev_mcp.approval import UnifiedApprovalStore
from chatgpt_dev_mcp.arbitrary_commands import (
    ArbitraryCommandController,
    ArbitraryCommandError,
    CommandExecPolicy,
    WorkspaceCommandBinding,
)


class ArbitraryCommandControllerTests(unittest.TestCase):
    def _binding(self, root: Path, *, revision: str = "a" * 40, state_hash: str = "b" * 64) -> WorkspaceCommandBinding:
        stat = root.stat()
        return WorkspaceCommandBinding(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            root=str(root.resolve()),
            root_device=int(stat.st_dev),
            root_inode=int(stat.st_ino),
            revision=revision,
            state_hash=state_hash,
        )

    def test_preflight_and_consume_bind_exact_workspace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "sub").mkdir()
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)

            preflight = controller.preflight(
                binding,
                argv=["python3", "-V"],
                workdir="sub",
                timeout_ms=5000,
                max_output_bytes=4096,
            )

            self.assertEqual(preflight["status"], "ready")
            self.assertEqual(preflight["workspace_id"], "fixture")
            self.assertEqual(preflight["working_tree_id"], "worktree:fixture")
            self.assertNotIn("python3", preflight["fingerprint"])

            request = controller.consume(
                preflight["approval_token"],
                preflight["confirmation"],
                current_binding=binding,
            )
            self.assertEqual(request.argv, ("python3", "-V"))
            self.assertEqual(request.workdir, "sub")
            self.assertEqual(request.timeout_ms, 5000)

    def test_preflight_is_one_shot(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            preflight = controller.preflight(binding, argv=["python3", "-V"])
            controller.consume(preflight["approval_token"], preflight["confirmation"], current_binding=binding)
            with self.assertRaises(ArbitraryCommandError) as caught:
                controller.consume(preflight["approval_token"], preflight["confirmation"], current_binding=binding)
            self.assertEqual(caught.exception.code, "COMMAND_EXEC_PREFLIGHT_INVALID")

    def test_stale_workspace_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            preflight = controller.preflight(binding, argv=["python3", "-V"])
            changed = self._binding(root, revision="c" * 40)
            with self.assertRaises(ArbitraryCommandError) as caught:
                controller.consume(preflight["approval_token"], preflight["confirmation"], current_binding=changed)
            self.assertEqual(caught.exception.code, "WORKSPACE_BINDING_STALE")

    def test_workdir_must_stay_inside_bound_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            with self.assertRaises(ArbitraryCommandError) as caught:
                controller.preflight(binding, argv=["python3", "-V"], workdir="../outside")
            self.assertEqual(caught.exception.code, "COMMAND_EXEC_WORKDIR_INVALID")

    def test_shell_mode_is_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            with self.assertRaises(ArbitraryCommandError) as caught:
                controller.preflight(binding, shell_command="printf hello")
            self.assertEqual(caught.exception.code, "COMMAND_EXEC_SHELL_DENIED")

    def test_shell_mode_requires_explicit_operator_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(
                UnifiedApprovalStore(),
                policy=CommandExecPolicy(allow_shell=True),
            )
            binding = self._binding(root)
            preflight = controller.preflight(binding, shell_command="printf hello")
            self.assertIn("shell_expansion", preflight["required_permissions"])
            request = controller.consume(
                preflight["approval_token"],
                preflight["confirmation"],
                current_binding=binding,
            )
            self.assertEqual(request.shell_command, "printf hello")

    def test_caller_cannot_inject_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            with self.assertRaises(TypeError):
                controller.preflight(binding, argv=["python3", "-V"], environment={"X": "1"})

    def test_argv_rejects_shell_and_privileged_composition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            for argv, code in (
                (["sh", "-c", "printf unsafe"], "COMMAND_EXECUTABLE_DENIED"),
                (["sudo", "printf", "unsafe"], "COMMAND_EXECUTABLE_DENIED"),
                (["printf", "unsafe;touch", "file"], "COMMAND_EXEC_ARGUMENT_INVALID"),
                (["cat", "/tmp/outside"], "COMMAND_EXEC_PATH_DENIED"),
                (["git", "-C", "../outside", "status"], "COMMAND_EXEC_PATH_DENIED"),
            ):
                with self.subTest(argv=argv):
                    with self.assertRaises(ArbitraryCommandError) as caught:
                        controller.preflight(binding, argv=argv)
                    self.assertEqual(caught.exception.code, code)

    def test_execute_uses_shell_false_and_bounds_timeout_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            controller = ArbitraryCommandController(UnifiedApprovalStore())
            binding = self._binding(root)
            preflight = controller.preflight(binding, argv=["yes", "bounded"], timeout_ms=20, max_output_bytes=32)
            request = controller.consume(preflight["approval_token"], preflight["confirmation"], current_binding=binding)
            result = controller.execute(request)
            self.assertEqual(result["status"], "timeout")
            self.assertLessEqual(len(result["output"].encode("utf-8")), 32)
            self.assertTrue(result["output_truncated"])
            self.assertEqual(result["working_tree_id"], "worktree:fixture")


if __name__ == "__main__":
    unittest.main()
