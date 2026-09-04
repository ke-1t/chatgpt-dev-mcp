from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class ProjectRuntimeBindingTests(unittest.TestCase):
    def test_select_project_test_command_narrows_unittest_discovery(self) -> None:
        from chatgpt_dev_mcp.project_runtime import select_project_test_command

        narrowed = select_project_test_command(
            "python3 -m unittest discover -s tests -p 'test_*.py' -q",
            ("tests/test_alpha.py", "tests/nested/test_beta.py"),
        )
        self.assertEqual(
            narrowed,
            "python3 -m unittest tests/test_alpha.py tests/nested/test_beta.py",
        )

    def test_select_project_test_command_rejects_parent_traversal(self) -> None:
        from chatgpt_dev_mcp.project_runtime import ProjectRuntimeError, select_project_test_command

        with self.assertRaisesRegex(ProjectRuntimeError, "ordinary relative POSIX paths"):
            select_project_test_command(
                "python3 -m unittest discover -s tests",
                ("../tests/test_escape.py",),
            )

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-project-runtime-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.developer = self.home / "Developer"
        self.developer.mkdir(parents=True)
        self.config = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config.parent.mkdir(parents=True)
        self.previous = {
            key: os.environ.get(key)
            for key in (
                "HOME",
                "LOCAL_DEV_MCP_CONFIG",
                "LOCAL_DEV_MCP_DATA_DIR",
                "LOCAL_DEV_MCP_WORKTREE_ROOT",
            )
        }
        os.environ.update(
            {
                "HOME": str(self.home),
                "LOCAL_DEV_MCP_CONFIG": str(self.config),
                "LOCAL_DEV_MCP_DATA_DIR": str(self.root / "state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(self.root / "worktrees"),
            }
        )

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    @staticmethod
    def _git(path: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _project(self) -> Path:
        project = self.developer / "runtime-fixture"
        (project / "src" / "runtime_fixture").mkdir(parents=True)
        (project / "tests").mkdir()
        (project / "src" / "runtime_fixture" / "__init__.py").write_text(
            "VALUE = 'worktree'\n",
            encoding="utf-8",
        )
        (project / "tests" / "test_fixture.py").write_text(
            "def test_fixture():\n    assert True\n",
            encoding="utf-8",
        )
        (project / "pyproject.toml").write_text(
            "[project]\nname = 'runtime-fixture'\nversion = '0.0.0'\n",
            encoding="utf-8",
        )
        runtime_python = project / ".venv" / "bin" / "python"
        runtime_python.parent.mkdir(parents=True)
        runtime_python.write_text(
            "#!/bin/sh\n"
            "printf 'RUNTIME=%s\\n' \"$0\"\n"
            "printf 'PWD=%s\\n' \"$PWD\"\n"
            "printf 'PYTHONPATH=%s\\n' \"${PYTHONPATH:-}\"\n"
            "printf 'ARGS=%s\\n' \"$*\"\n",
            encoding="utf-8",
        )
        runtime_python.chmod(0o755)
        subprocess.run(["git", "-C", str(project), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.email", "runtime@example.com"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.name", "Runtime Fixture"], check=True)
        subprocess.run(["git", "-C", str(project), "add", "pyproject.toml", "src", "tests"], check=True)
        subprocess.run(["git", "-C", str(project), "commit", "-qm", "initial"], check=True)
        return project

    def _write_config(self, project: Path) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [
                        {"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}
                    ],
                    "workspaces": {
                        "runtime-fixture": {
                            "path": str(project),
                            "profile": "DEVELOPMENT",
                            "commands": {"test": ".venv/bin/python -m pytest"},
                            "metadata": {
                                "isolated_development": {
                                    "auto_create_sessions": True,
                                    "auto_resume_sessions": True,
                                    "auto_resume_policy": "same_owner_same_task_safe_local",
                                    "max_parallel_sessions": 2,
                                    "allowed_base": "registered_project",
                                    "allow_workspace_wide": False,
                                    "integration_requires_approval": True,
                                    "commit_requires_approval": True,
                                    "push_requires_approval": True,
                                }
                            },
                        }
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def test_isolated_run_task_uses_registered_project_venv_and_worktree_sources(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self._project()
        self._write_config(project)
        runtime = WrapperRuntime()
        try:
            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "runtime-fixture",
                    "request_id": "runtime-binding",
                    "title": "Verify project runtime binding",
                    "owner_id": "runtime-owner",
                    "paths": ["src", "tests"],
                    "source_revision": self._git(project, "rev-parse", "HEAD"),
                },
            )
            self.assertFalse(started["isError"], started)
            payload = started["structuredContent"]
            worktree = Path(payload["worktree_path"])
            self.assertFalse((worktree / ".venv").exists())

            result = runtime.call_tool(
                "run_task",
                {
                    "task": "test",
                    "workspace_id": "runtime-fixture",
                    "working_tree_id": payload["working_tree_id"],
                    "session_id": payload["session_id"],
                },
            )
            self.assertFalse(result["isError"], result)
            task = result["structuredContent"]
            self.assertEqual(task["exit_code"], 0, task)
            preview = task.get("preview", "")
            self.assertIn(f"PWD={worktree}", preview)
            self.assertIn(f"PYTHONPATH={worktree / 'src'}", preview)
            self.assertIn("ARGS=-m pytest", preview)
        finally:
            runtime.close()

    def test_runtime_binding_does_not_require_explicit_session_id_when_worktree_is_bound(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self._project()
        self._write_config(project)
        runtime = WrapperRuntime()
        try:
            started = runtime.call_tool(
                "director_development_start",
                {
                    "workspace_id": "runtime-fixture",
                    "request_id": "runtime-binding-by-tree",
                    "title": "Verify runtime binding by worktree",
                    "owner_id": "runtime-owner",
                    "paths": ["src", "tests"],
                    "source_revision": self._git(project, "rev-parse", "HEAD"),
                },
            )
            self.assertFalse(started["isError"], started)
            payload = started["structuredContent"]
            worktree = Path(payload["worktree_path"])
            result = runtime.call_tool(
                "run_task",
                {
                    "task": "test",
                    "workspace_id": "runtime-fixture",
                    "working_tree_id": payload["working_tree_id"],
                },
            )
            self.assertFalse(result["isError"], result)
            task = result["structuredContent"]
            self.assertEqual(task["exit_code"], 0, task)
            self.assertIn(f"PWD={worktree}", task.get("preview", ""))
        finally:
            runtime.close()

    def test_project_runtime_allows_leaf_python_symlink_inside_venv_bin(self) -> None:
        from chatgpt_dev_mcp.project_runtime import resolve_project_task_command

        source = self.root / "source-symlink"
        worktree = self.root / "worktree-symlink"
        for root in (source, worktree):
            (root / "src").mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                "[project]\nname = 'fixture'\nversion = '0.0.0'\n",
                encoding="utf-8",
            )
        real_python = source / ".venv" / "bin" / "python-real"
        real_python.parent.mkdir(parents=True)
        real_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        real_python.chmod(0o755)
        (source / ".venv" / "bin" / "python").symlink_to("python-real")

        resolved = resolve_project_task_command(
            ".venv/bin/python -m pytest",
            source_root=source,
            worktree_root=worktree,
        )
        self.assertIsNotNone(resolved)
        expected_entrypoint = source.resolve() / ".venv" / "bin" / "python"
        self.assertEqual(resolved.executable, expected_entrypoint)
        self.assertIn(str(expected_entrypoint), resolved.command)
        self.assertNotIn(str(real_python.resolve()), resolved.command)

    def test_non_dependency_pyproject_change_can_reuse_project_runtime(self) -> None:
        from chatgpt_dev_mcp.project_runtime import resolve_project_task_command

        source = self.root / "source-metadata-change"
        worktree = self.root / "worktree-metadata-change"
        for root in (source, worktree):
            (root / "src").mkdir(parents=True)
        (source / "pyproject.toml").write_text(
            "[project]\nname = 'fixture'\nversion = '0.0.0'\ndependencies = ['demo>=1']\n",
            encoding="utf-8",
        )
        (worktree / "pyproject.toml").write_text(
            "[project]\nname = 'fixture'\nversion = '0.0.1'\ndependencies = ['demo>=1']\n"
            "[project.scripts]\nfixture = 'fixture:main'\n",
            encoding="utf-8",
        )
        runtime_python = source / ".venv" / "bin" / "python"
        runtime_python.parent.mkdir(parents=True)
        runtime_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runtime_python.chmod(0o755)

        resolved = resolve_project_task_command(
            ".venv/bin/python -m pytest",
            source_root=source,
            worktree_root=worktree,
        )
        self.assertIsNotNone(resolved)

    def test_dependency_change_fails_closed_before_reusing_project_runtime(self) -> None:
        from chatgpt_dev_mcp.project_runtime import ProjectRuntimeError, resolve_project_task_command

        source = self.root / "source-dependency-change"
        worktree = self.root / "worktree-dependency-change"
        for root in (source, worktree):
            (root / "src").mkdir(parents=True)
        (source / "pyproject.toml").write_text(
            "[project]\nname = 'fixture'\nversion = '0.0.0'\ndependencies = ['demo>=1']\n",
            encoding="utf-8",
        )
        (worktree / "pyproject.toml").write_text(
            "[project]\nname = 'fixture'\nversion = '0.0.0'\ndependencies = ['demo>=2']\n",
            encoding="utf-8",
        )
        runtime_python = source / ".venv" / "bin" / "python"
        runtime_python.parent.mkdir(parents=True)
        runtime_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runtime_python.chmod(0o755)

        with self.assertRaises(ProjectRuntimeError) as caught:
            resolve_project_task_command(
                ".venv/bin/python -m pytest",
                source_root=source,
                worktree_root=worktree,
            )
        self.assertEqual(caught.exception.code, "RUNTIME_DEPENDENCY_MISMATCH")


if __name__ == "__main__":
    unittest.main()
