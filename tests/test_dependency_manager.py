import sys
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.command_profiles import CommandProfileController
from chatgpt_dev_mcp.dependency_manager import DependencyError, DependencyManager
from chatgpt_dev_mcp.runtime_policy import parse_command_profile


class DependencyManagerTests(unittest.TestCase):
    def test_detect_python_manifest_and_reject_unbounded_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            manager = DependencyManager(CommandProfileController({}), ecosystem_profiles={})
            detected = manager.detect(repo)
            self.assertEqual(detected["ecosystem"], "python")
            self.assertEqual(detected["manifest"], "pyproject.toml")
            for package in ("git+https://example.invalid/x", "../local", "https://example.invalid/x", "/tmp/pkg"):
                with self.subTest(package=package), self.assertRaises(DependencyError):
                    manager.preflight(repo, project_id="repo", action="add", package=package, version="1.0")

    def test_stale_manifest_blocks_apply_before_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            profile = parse_command_profile(
                "python-add",
                {
                    "argv": [sys.executable, "-V"],
                    "allowed_args": {"package": {"type": "selector", "flag": ""}},
                    "network_class": "dependency",
                },
            )
            controller = CommandProfileController({"python-add": profile})
            manager = DependencyManager(controller, ecosystem_profiles={"python:add": "python-add"})
            pre = manager.preflight(repo, project_id="repo", action="add", package="demo-pkg", version="1.2.3")
            (repo / "pyproject.toml").write_text("[project]\nname='changed'\n", encoding="utf-8")
            with self.assertRaises(DependencyError) as cm:
                manager.apply(repo, pre["preflight_id"])
            self.assertEqual(cm.exception.code, "DEPENDENCY_PREFLIGHT_STALE")

    def test_apply_uses_registered_dependency_profile_and_records_hash_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            (repo / "dep_tool.py").write_text(
                "from pathlib import Path\nimport sys\n"
                "Path('pyproject.toml').write_text(Path('pyproject.toml').read_text()+'# '+sys.argv[1]+'\\n')\n"
                "Path('uv.lock').write_text(Path('uv.lock').read_text()+'# changed\\n')\n",
                encoding="utf-8",
            )
            profile = parse_command_profile(
                "python-add",
                {
                    "argv": [sys.executable, "dep_tool.py"],
                    "allowed_args": {"package": {"type": "selector", "flag": ""}},
                    "network_class": "dependency",
                },
            )
            controller = CommandProfileController({"python-add": profile})
            manager = DependencyManager(controller, ecosystem_profiles={"python:add": "python-add"})
            pre = manager.preflight(repo, project_id="repo", action="add", package="demo-pkg", version="1.2.3")
            result = manager.apply(repo, pre["preflight_id"])
            self.assertEqual(result["status"], "succeeded")
            self.assertNotEqual(result["manifest_hash_before"], result["manifest_hash_after"])
            self.assertTrue(result["lockfile_changed"])
            self.assertEqual(result["command_profile"], "python-add")

    def test_lifecycle_risk_is_reported_for_node_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package.json").write_text(
                '{"name":"fixture","scripts":{"preinstall":"node setup.js"}}', encoding="utf-8"
            )
            (repo / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
            profile = parse_command_profile(
                "node-add",
                {"argv": ["npm", "install"], "allowed_args": {"package": {"type": "selector", "flag": ""}}, "network_class": "dependency"},
            )
            manager = DependencyManager(CommandProfileController({"node-add": profile}), ecosystem_profiles={"node:add": "node-add"})
            pre = manager.preflight(repo, project_id="repo", action="add", package="left-pad", version="1.3.0")
            self.assertTrue(pre["lifecycle_script_risk"])


if __name__ == "__main__":
    unittest.main()
