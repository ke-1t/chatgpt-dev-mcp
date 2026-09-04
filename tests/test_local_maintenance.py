from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import chatgpt_dev_mcp.local_maintenance as local_maintenance
from chatgpt_dev_mcp.approval_policy import GrantBinding, RiskClass, RiskPolicyEngine, TrustedGrantStore
from chatgpt_dev_mcp.local_maintenance import (
    LocalMaintenanceController,
    LocalMaintenanceError,
    MaintenanceRunResult,
    _default_runner,
    _run_detached_restart,
)


class LocalMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_000.0
        self.binding = GrantBinding(
            workspace_id="chatgpt-dev-mcp",
            working_tree_id="session:abc123",
            session_id="session:abc123",
            task_id="task:one",
            owner_id="chatgpt",
        )
        self.digest = "a" * 64
        self.grants = TrustedGrantStore(clock=lambda: self.now, policy_engine=RiskPolicyEngine())
        self.grant = self.grants.issue(
            self.binding,
            operations=("restart_dev_mcp_tunnel",),
            policy_digest=self.digest,
            ttl_seconds=7_200,
            session_expires_at=self.now + 7_200,
        )

    def test_restart_uses_only_fixed_launchctl_argv(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(argv: tuple[str, ...]) -> MaintenanceRunResult:
            calls.append(argv)
            return MaintenanceRunResult(exit_code=0, outcome_known=True, detail="restarted")

        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=runner,
            uid_provider=lambda: 501,
        )
        receipt = controller.execute(
            action="restart_dev_mcp_tunnel",
            binding=self.binding,
            grant_id=self.grant.grant_id,
            policy_digest=self.digest,
            policy_enabled=True,
        )
        self.assertEqual(
            calls,
            [("launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-tunnel")],
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["risk_class"], "R2")
        self.assertNotIn("grant_id", receipt)

    def test_install_dev_toolchain_is_r2_and_uses_only_fixed_installer(self) -> None:
        self.assertEqual(RiskPolicyEngine().classify("install_dev_toolchain"), RiskClass.R2)
        calls: list[str] = []
        grant = self.grants.issue(
            self.binding,
            operations=("install_dev_toolchain",),
            policy_digest=self.digest,
            ttl_seconds=7_200,
            session_expires_at=self.now + 7_200,
        )
        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=lambda argv: self.fail(f"generic runner must not be used: {argv!r}"),
            toolchain_installer=lambda: calls.append("install") or MaintenanceRunResult(0, True, "installed"),
            uid_provider=lambda: 501,
        )
        receipt = controller.execute(
            action="install_dev_toolchain",
            binding=self.binding,
            grant_id=grant.grant_id,
            policy_digest=self.digest,
            policy_enabled=True,
        )
        self.assertEqual(calls, ["install"])
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["action"], "install_dev_toolchain")
        self.assertEqual(receipt["risk_class"], "R2")

    def test_install_dev_toolchain_nonzero_result_fails_closed(self) -> None:
        grant = self.grants.issue(
            self.binding,
            operations=("install_dev_toolchain",),
            policy_digest=self.digest,
            ttl_seconds=7_200,
            session_expires_at=self.now + 7_200,
        )
        controller = LocalMaintenanceController(
            grant_store=self.grants,
            toolchain_installer=lambda: MaintenanceRunResult(1, True, "failed"),
            uid_provider=lambda: 501,
        )
        with self.assertRaisesRegex(LocalMaintenanceError, "failed"):
            controller.execute(
                action="install_dev_toolchain",
                binding=self.binding,
                grant_id=grant.grant_id,
                policy_digest=self.digest,
                policy_enabled=True,
            )

    def test_fixed_toolchain_installer_uses_only_allowlisted_brew_and_npm_argv(self) -> None:
        present = {"/opt/homebrew/bin/brew"}
        calls: list[tuple[str, ...]] = []

        def exists(path: str) -> bool:
            return path in present

        def runner(argv: tuple[str, ...]) -> MaintenanceRunResult:
            calls.append(argv)
            if argv[0] == "/opt/homebrew/bin/brew":
                present.update({
                    "/opt/homebrew/bin/gh", "/opt/homebrew/bin/node", "/opt/homebrew/bin/npm",
                    "/opt/homebrew/bin/npx", "/opt/homebrew/bin/uv", "/opt/homebrew/bin/uvx",
                })
            elif argv[0] == "/opt/homebrew/bin/npm":
                present.update({
                    "/opt/homebrew/bin/playwright", "/opt/homebrew/bin/playwright-mcp",
                    "/opt/homebrew/bin/chrome-devtools-mcp", "/opt/homebrew/bin/context7-mcp",
                })
            elif argv[0] == "/opt/homebrew/bin/uv":
                present.add("/opt/homebrew/bin/serena")
            return MaintenanceRunResult(0, True, "ok")

        result = local_maintenance._install_fixed_dev_toolchain(exists=exists, runner=runner)
        self.assertEqual(
            calls,
            [
                ("/opt/homebrew/bin/brew", "install", "gh", "node", "uv"),
                (
                    "/opt/homebrew/bin/npm", "install", "--global", "playwright@latest",
                    "@playwright/mcp@latest", "chrome-devtools-mcp@latest",
                    "@upstash/context7-mcp@latest",
                ),
                ("/opt/homebrew/bin/uv", "tool", "install", "-p", "3.13", "serena-agent"),
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.outcome_known)
        self.assertIn("gh", result.detail)
        self.assertIn("Context7", result.detail)
        self.assertIn("Serena", result.detail)
        self.assertNotIn("sudo", " ".join(" ".join(argv) for argv in calls))

    def test_fixed_toolchain_installer_fails_without_homebrew(self) -> None:
        with self.assertRaisesRegex(LocalMaintenanceError, "Homebrew"):
            local_maintenance._install_fixed_dev_toolchain(
                exists=lambda _path: False,
                runner=lambda argv: self.fail(f"runner must not be used: {argv!r}"),
            )

    def test_fixed_toolchain_installer_surfaces_bounded_brew_failure_detail(self) -> None:
        with self.assertRaisesRegex(LocalMaintenanceError, "formula conflict"):
            local_maintenance._install_fixed_dev_toolchain(
                exists=lambda path: path == "/opt/homebrew/bin/brew",
                runner=lambda _argv: MaintenanceRunResult(1, True, "formula conflict"),
            )

    def test_fixed_toolchain_command_rejects_every_non_allowlisted_argv(self) -> None:
        for argv in (
            ("sudo", "brew", "install", "gh"),
            ("/opt/homebrew/bin/brew", "install", "wget"),
            ("/opt/homebrew/bin/npm", "install", "--global", "some-other-package@latest"),
            ("/opt/homebrew/bin/uv", "tool", "install", "serena-agent"),
            ("curl", "https://example.com/install.sh"),
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(LocalMaintenanceError, "fixed"):
                    local_maintenance._run_fixed_toolchain_command(argv)

    def test_unknown_action_and_disabled_policy_are_denied_before_runner(self) -> None:
        calls: list[tuple[str, ...]] = []
        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=lambda argv: calls.append(argv) or MaintenanceRunResult(0, True, "ok"),
            uid_provider=lambda: 501,
        )
        with self.assertRaisesRegex(LocalMaintenanceError, "unknown"):
            controller.execute(
                action="restart_other_service",
                binding=self.binding,
                grant_id=self.grant.grant_id,
                policy_digest=self.digest,
                policy_enabled=True,
            )
        with self.assertRaisesRegex(LocalMaintenanceError, "disabled"):
            controller.execute(
                action="restart_dev_mcp_tunnel",
                binding=self.binding,
                grant_id=self.grant.grant_id,
                policy_digest=self.digest,
                policy_enabled=False,
            )
        self.assertEqual(calls, [])

    def test_create_restart_shortcut_uses_only_fixed_writer(self) -> None:
        calls: list[str] = []
        shortcut_grant = self.grants.issue(
            self.binding,
            operations=("create_mcp_restart_shortcut",),
            policy_digest=self.digest,
            ttl_seconds=7_200,
            session_expires_at=self.now + 7_200,
        )

        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=lambda argv: self.fail(f"runner must not be used: {argv!r}"),
            shortcut_writer=lambda: calls.append("write") or MaintenanceRunResult(0, True, "~/Desktop/Restart ChatGPT Dev MCP.command"),
            uid_provider=lambda: 501,
        )
        receipt = controller.execute(
            action="create_mcp_restart_shortcut",
            binding=self.binding,
            grant_id=shortcut_grant.grant_id,
            policy_digest=self.digest,
            policy_enabled=True,
        )

        self.assertEqual(calls, ["write"])
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["action"], "create_mcp_restart_shortcut")
        self.assertEqual(receipt["risk_class"], "R2")

    def test_bootstrap_cli_allows_only_shortcut_or_fixed_tunnel_restart(self) -> None:
        shortcut_calls: list[str] = []
        restart_calls: list[tuple[str, ...]] = []

        def shortcut_writer() -> MaintenanceRunResult:
            shortcut_calls.append("write")
            return MaintenanceRunResult(0, True, "~/Desktop/Restart ChatGPT Dev MCP.command")

        def restart_scheduler(argv: tuple[str, ...]) -> MaintenanceRunResult:
            restart_calls.append(argv)
            return MaintenanceRunResult(0, True, "queued", deferred=True)

        self.assertEqual(
            local_maintenance._bootstrap_main(
                ["shortcut"],
                shortcut_writer=shortcut_writer,
                restart_scheduler=restart_scheduler,
                uid_provider=lambda: 501,
            ),
            0,
        )
        self.assertEqual(shortcut_calls, ["write"])
        self.assertEqual(restart_calls, [])

        self.assertEqual(
            local_maintenance._bootstrap_main(
                ["restart"],
                shortcut_writer=shortcut_writer,
                restart_scheduler=restart_scheduler,
                uid_provider=lambda: 501,
            ),
            0,
        )
        self.assertEqual(
            restart_calls,
            [("launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-tunnel")],
        )
        self.assertEqual(shortcut_calls, ["write"])
        self.assertEqual(
            local_maintenance._bootstrap_main(
                ["other"],
                shortcut_writer=shortcut_writer,
                restart_scheduler=restart_scheduler,
                uid_provider=lambda: 501,
            ),
            2,
        )

    def test_bootstrap_cli_allows_fixed_v26_runtime_repin(self) -> None:
        calls: list[str] = []

        def reloader() -> MaintenanceRunResult:
            calls.append("repin")
            return MaintenanceRunResult(0, True, "v26 runtime repinned")

        self.assertEqual(
            local_maintenance._bootstrap_main(
                ["repin-v26-runtime"],
                v26_runtime_reloader=reloader,
                uid_provider=lambda: 501,
            ),
            0,
        )
        self.assertEqual(calls, ["repin"])

    def test_fixed_v26_runtime_repin_updates_identity_and_kickstarts_only_fixed_service(self) -> None:
        head = "a" * 40
        old_hash = "0" * 64
        diff_bytes = b"current tracked diff"
        expected_hash = hashlib.sha256(diff_bytes).hexdigest()
        calls: list[tuple[str, ...]] = []

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "repo"
            deployment = tmp_path / "deployment"
            root.mkdir()
            deployment.mkdir()
            runtime = deployment / "runtime-run"
            manifest = deployment / "deployment-manifest.json"
            runtime.write_text(
                "#!/bin/sh\n"
                'SOURCE_ROOT="/private/tmp/chatgpt-dev-mcp-session-lifecycle-ef"\n'
                f'EXPECTED_BASE="{head}"\n'
                f'EXPECTED_PATCH="{old_hash}"\n',
                encoding="utf-8",
            )
            manifest.write_text(
                json.dumps(
                    {
                        "source_root": "/private/tmp/chatgpt-dev-mcp-session-lifecycle-ef",
                        "base_revision": head,
                        "patch_hash": old_hash,
                    }
                ),
                encoding="utf-8",
            )

            result = local_maintenance._repin_v26_runtime(
                source_root=root,
                runtime_path=runtime,
                manifest_path=manifest,
                uid_provider=lambda: 501,
                git_head_reader=lambda _root: head,
                git_diff_reader=lambda _root: diff_bytes,
                restart_runner=lambda argv: calls.append(argv) or MaintenanceRunResult(0, True, "restarted"),
            )

            runtime_after = runtime.read_text(encoding="utf-8")
            manifest_after = json.loads(manifest.read_text(encoding="utf-8"))
            resolved_root = root.resolve()

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.outcome_known)
        self.assertIn(f'SOURCE_ROOT="{resolved_root}"', runtime_after)
        self.assertIn(f'EXPECTED_BASE="{head}"', runtime_after)
        self.assertIn(f'EXPECTED_PATCH="{expected_hash}"', runtime_after)
        self.assertEqual(manifest_after["source_root"], str(resolved_root))
        self.assertEqual(manifest_after["base_revision"], head)
        self.assertEqual(manifest_after["patch_hash"], expected_hash)
        self.assertEqual(
            calls,
            [("launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-v26-runtime")],
        )

    def test_fixed_v26_runtime_repin_advances_base_from_immediate_parent_after_commit(self) -> None:
        parent = "a" * 40
        head = "b" * 40
        old_hash = "0" * 64
        diff_bytes = b""
        expected_hash = hashlib.sha256(diff_bytes).hexdigest()
        calls: list[tuple[str, ...]] = []

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "repo"
            deployment = tmp_path / "deployment"
            root.mkdir()
            deployment.mkdir()
            runtime = deployment / "runtime-run"
            manifest = deployment / "deployment-manifest.json"
            runtime.write_text(
                "#!/bin/sh\n"
                f'SOURCE_ROOT="{root.resolve()}"\n'
                f'EXPECTED_BASE="{parent}"\n'
                f'EXPECTED_PATCH="{old_hash}"\n',
                encoding="utf-8",
            )
            manifest.write_text(
                json.dumps(
                    {
                        "source_root": str(root.resolve()),
                        "base_revision": parent,
                        "patch_hash": old_hash,
                    }
                ),
                encoding="utf-8",
            )

            result = local_maintenance._repin_v26_runtime(
                source_root=root,
                runtime_path=runtime,
                manifest_path=manifest,
                uid_provider=lambda: 501,
                git_head_reader=lambda _root: head,
                git_parent_reader=lambda _root: parent,
                git_diff_reader=lambda _root: diff_bytes,
                restart_runner=lambda argv: calls.append(argv) or MaintenanceRunResult(0, True, "restarted"),
            )

            runtime_after = runtime.read_text(encoding="utf-8")
            manifest_after = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 0)
        self.assertIn(f'EXPECTED_BASE="{head}"', runtime_after)
        self.assertIn(f'EXPECTED_PATCH="{expected_hash}"', runtime_after)
        self.assertEqual(manifest_after["base_revision"], head)
        self.assertEqual(manifest_after["patch_hash"], expected_hash)
        self.assertEqual(
            calls,
            [("launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-v26-runtime")],
        )

    def test_fixed_v26_runtime_repin_rejects_non_parent_base_drift(self) -> None:
        parent = "a" * 40
        head = "b" * 40
        unrelated = "c" * 40

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "repo"
            deployment = tmp_path / "deployment"
            root.mkdir()
            deployment.mkdir()
            runtime = deployment / "runtime-run"
            manifest = deployment / "deployment-manifest.json"
            runtime.write_text(
                "#!/bin/sh\n"
                f'SOURCE_ROOT="{root.resolve()}"\n'
                f'EXPECTED_BASE="{unrelated}"\n'
                f'EXPECTED_PATCH="{"0" * 64}"\n',
                encoding="utf-8",
            )
            manifest.write_text(
                json.dumps(
                    {
                        "source_root": str(root.resolve()),
                        "base_revision": unrelated,
                        "patch_hash": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(LocalMaintenanceError, "base does not match"):
                local_maintenance._repin_v26_runtime(
                    source_root=root,
                    runtime_path=runtime,
                    manifest_path=manifest,
                    uid_provider=lambda: 501,
                    git_head_reader=lambda _root: head,
                    git_parent_reader=lambda _root: parent,
                    git_diff_reader=lambda _root: b"",
                    restart_runner=lambda _argv: MaintenanceRunResult(0, True, "restarted"),
                )

    def test_runner_exception_is_outcome_unknown_and_not_retried(self) -> None:
        calls = 0

        def runner(_argv: tuple[str, ...]) -> MaintenanceRunResult:
            nonlocal calls
            calls += 1
            raise OSError("transport disappeared after launchctl")

        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=runner,
            uid_provider=lambda: 501,
        )
        with self.assertRaisesRegex(LocalMaintenanceError, "outcome is unknown"):
            controller.execute(
                action="restart_dev_mcp_tunnel",
                binding=self.binding,
                grant_id=self.grant.grant_id,
                policy_digest=self.digest,
                policy_enabled=True,
            )
        self.assertEqual(calls, 1)

    def test_nonzero_restart_result_is_reported_as_failed(self) -> None:
        controller = LocalMaintenanceController(
            grant_store=self.grants,
            runner=lambda _argv: MaintenanceRunResult(1, True, "launchctl failed"),
            uid_provider=lambda: 501,
        )
        with self.assertRaisesRegex(LocalMaintenanceError, "command failed"):
            controller.execute(
                action="restart_dev_mcp_tunnel",
                binding=self.binding,
                grant_id=self.grant.grant_id,
                policy_digest=self.digest,
                policy_enabled=True,
            )

    def test_default_restart_runner_detaches_before_kickstart(self) -> None:
        argv = ("launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-tunnel")
        with patch("chatgpt_dev_mcp.local_maintenance.subprocess.Popen") as popen:
            result = _default_runner(argv)

        self.assertTrue(result.deferred)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("response flush", result.detail)
        popen.assert_called_once()
        child_argv = popen.call_args.args[0]
        self.assertEqual(child_argv[:3], (popen.call_args.args[0][0], "-m", "chatgpt_dev_mcp.local_maintenance"))
        self.assertEqual(child_argv[3], "--detached-restart")
        self.assertEqual(child_argv[4], argv[3])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_detached_restart_retries_launch_and_waits_for_readiness(self) -> None:
        argv = ("/bin/launchctl", "kickstart", "-k", "gui/501/com.openai.chatgpt-dev-mcp-tunnel")
        runs = [
            type("Completed", (), {"returncode": 1})(),
            type("Completed", (), {"returncode": 0})(),
        ]
        with (
            patch("chatgpt_dev_mcp.local_maintenance.time.sleep"),
            patch("chatgpt_dev_mcp.local_maintenance.subprocess.run", side_effect=runs) as runner,
            patch("chatgpt_dev_mcp.local_maintenance._probe_tunnel_readiness", return_value=True) as probe,
        ):
            self.assertEqual(_run_detached_restart(argv[3]), 0)

        self.assertEqual(runner.call_count, 2)
        self.assertGreaterEqual(probe.call_count, 1)


if __name__ == "__main__":
    unittest.main()
