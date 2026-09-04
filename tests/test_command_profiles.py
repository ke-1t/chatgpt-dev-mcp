import sys
import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.command_profiles import CommandProfileController, CommandProfileError
from chatgpt_dev_mcp.credential_slots import CredentialSlotManager, CredentialSlotPolicy
from chatgpt_dev_mcp.runtime_policy import parse_command_profile


class CommandProfileControllerTests(unittest.TestCase):
    def test_run_fixed_profile_and_redact_injected_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "probe.py").write_text(
                "import os,sys\nprint(sys.argv[1])\nprint(os.environ.get('DEMO_SLOT','missing'))\n",
                encoding="utf-8",
            )
            profile = parse_command_profile(
                "probe",
                {
                    "argv": [sys.executable, "probe.py"],
                    "allowed_args": {"value": {"type": "selector", "flag": ""}},
                    "credential_slots": ["DEMO_SLOT"],
                    "timeout_ms": 5000,
                },
            )
            slots = CredentialSlotManager(
                [CredentialSlotPolicy("DEMO_SLOT", "env", "DEMO_SOURCE", ("probe",), ("repo",))],
                environ={"DEMO_SOURCE": "opaque-fixture-value"},
            )
            grant = slots.preflight("DEMO_SLOT", project_id="repo", command_profile="probe")
            controller = CommandProfileController({"probe": profile}, credential_slots=slots)
            preflight = controller.preflight(repo, "probe", {"value": "safe-value"}, project_id="repo", credential_grants=[grant["grant_id"]])
            result = controller.run(repo, preflight["preflight_id"])
            self.assertEqual(result["status"], "succeeded")
            self.assertIn("safe-value", result["stdout"])
            self.assertIn("[REDACTED]", result["stdout"])
            self.assertNotIn("opaque-fixture-value", repr(result))

    def test_unknown_profile_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = CommandProfileController({})
            with self.assertRaises(CommandProfileError):
                controller.preflight(Path(tmp), "missing", {}, project_id="repo")

    def test_timeout_is_bounded_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "sleep.py").write_text("import time\ntime.sleep(1)\n", encoding="utf-8")
            profile = parse_command_profile("sleep", {"argv": [sys.executable, "sleep.py"], "allowed_args": {}, "timeout_ms": 50})
            controller = CommandProfileController({"sleep": profile})
            preflight = controller.preflight(repo, "sleep", {}, project_id="repo")
            result = controller.run(repo, preflight["preflight_id"])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error_code"], "COMMAND_TIMEOUT")

    def test_output_is_bounded_during_command_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "large.py").write_text("print('x' * 200000)", encoding="utf-8")
            profile = parse_command_profile(
                "large",
                {
                    "argv": [sys.executable, "large.py"],
                    "allowed_args": {},
                    "max_output_bytes": 1024,
                },
            )
            controller = CommandProfileController({"large": profile})
            preflight = controller.preflight(repo, "large", {}, project_id="repo")
            result = controller.run(repo, preflight["preflight_id"])
            self.assertEqual(result["status"], "succeeded")
            self.assertLessEqual(len(result["stdout"].encode("utf-8")), 1024)
            self.assertTrue(result["output_truncated"])

    def test_preflight_is_stale_when_working_directory_identity_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            profile = parse_command_profile("noop", {"argv": [sys.executable, "-V"], "allowed_args": {}})
            controller = CommandProfileController({"noop": profile})
            preflight = controller.preflight(repo, "noop", {}, project_id="repo")
            repo.rename(root / "old")
            repo.mkdir()
            with self.assertRaises(CommandProfileError) as cm:
                controller.run(repo, preflight["preflight_id"])
            self.assertEqual(cm.exception.code, "COMMAND_PREFLIGHT_STALE")


if __name__ == "__main__":
    unittest.main()
