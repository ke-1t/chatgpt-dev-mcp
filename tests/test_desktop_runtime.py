import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from chatgpt_dev_mcp.desktop_runtime import DesktopProfile, DesktopRuntimeError, DesktopRuntimeManager
from chatgpt_dev_mcp.runtime_policy import parse_command_profile


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def fixture_repo(root: Path) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    (repo / "fixture.py").write_text(
        "import os,time\nprint(os.environ.get('DEMO_SLOT','ready'), flush=True)\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    git(repo, "add", "fixture.py")
    git(repo, "commit", "-m", "fixture")
    return repo, git(repo, "rev-parse", "HEAD")


class DesktopRuntimeTests(unittest.TestCase):
    def _manager(self, cache: Path):
        command = parse_command_profile("desktop-fixture", {"argv": [sys.executable, "fixture.py"], "allowed_args": {}})
        profile = DesktopProfile("fixture", command, "fixture-data")
        return DesktopRuntimeManager({"fixture": profile}, cache_root=cache)

    def test_start_logs_status_stop_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, head = fixture_repo(root)
            manager = self._manager(root / "cache")
            started = manager.start(
                repo, project_id="repo", worktree_id="worktree-fixture", revision=head, profile_id="fixture",
                child_environment={"DEMO_SLOT": "opaque-fixture-value"}, redact_values=("opaque-fixture-value",),
            )
            self.assertEqual(started["status"], "running")
            time.sleep(0.05)
            logs = manager.logs(started["instance_id"])
            self.assertIn("[REDACTED]", logs["output"])
            self.assertNotIn("opaque-fixture-value", logs["output"])
            stopped = manager.stop(started["instance_id"])
            self.assertTrue(stopped["managed_stop"])
            self.assertNotEqual(stopped["status"], "running")

    def test_wrong_revision_and_duplicate_instance_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, head = fixture_repo(root)
            manager = self._manager(root / "cache")
            with self.assertRaises(DesktopRuntimeError) as cm:
                manager.start(repo, project_id="repo", worktree_id="tree", revision="0" * 40, profile_id="fixture")
            self.assertEqual(cm.exception.code, "DESKTOP_REVISION_MISMATCH")
            first = manager.start(repo, project_id="repo", worktree_id="tree", revision=head, profile_id="fixture")
            with self.assertRaises(DesktopRuntimeError) as cm2:
                manager.start(repo, project_id="repo", worktree_id="tree", revision=head, profile_id="fixture")
            self.assertEqual(cm2.exception.code, "DESKTOP_INSTANCE_CONFLICT")
            manager.stop(first["instance_id"])

    def test_unknown_instance_cannot_target_unrelated_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root / "cache")
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            try:
                with self.assertRaises(DesktopRuntimeError):
                    manager.stop("desktop-not-managed")
                self.assertIsNone(unrelated.poll())
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=2)

    def test_capture_only_profile_snapshots_running_app_without_starting_process(self):
        class CaptureBackend:
            def __init__(self):
                self.calls = []

            def capture(self, root, profile):
                self.calls.append((Path(root), profile))
                return {
                    "status": "captured",
                    "profile": profile.identifier,
                    "bundle_id": profile.bundle_id,
                    "screenshot_path": "output/devmcp-desktop-qa/demo.png",
                    "external_execution": False,
                }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = CaptureBackend()
            profile = DesktopProfile(
                "managed-fixture-capture",
                bundle_id="work.fixture.desktop",
                max_screenshot_bytes=1024 * 1024,
            )
            manager = DesktopRuntimeManager(
                {profile.identifier: profile},
                cache_root=root / "cache",
                capture_backend=backend,
            )

            captured = manager.capture_profile(root, profile.identifier)
            self.assertEqual(captured["status"], "captured")
            self.assertEqual(captured["bundle_id"], "work.fixture.desktop")
            self.assertEqual(len(backend.calls), 1)
            with self.assertRaises(DesktopRuntimeError) as cm:
                manager.start(
                    root,
                    project_id="fixture",
                    worktree_id="tree",
                    revision="a" * 40,
                    profile_id=profile.identifier,
                )
            self.assertEqual(cm.exception.code, "DESKTOP_CAPTURE_ONLY")

    def test_profile_rejects_mixed_launch_and_capture_configuration(self):
        command = parse_command_profile("desktop-fixture", {"argv": [sys.executable, "fixture.py"], "allowed_args": {}})
        with self.assertRaises(DesktopRuntimeError) as cm:
            DesktopProfile(
                "managed-mixed",
                command,
                "fixture-data",
                bundle_id="work.fixture.desktop",
            )
        self.assertEqual(cm.exception.code, "DESKTOP_PROFILE_MODE_INVALID")


if __name__ == "__main__":
    unittest.main()
