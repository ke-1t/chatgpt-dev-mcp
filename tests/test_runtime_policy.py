import unittest

from chatgpt_dev_mcp.approval import ApprovalError, UnifiedApprovalStore
from chatgpt_dev_mcp.runtime_policy import PolicyError, normalize_resource, parse_command_profile, render_typed_args


class RuntimePolicyTests(unittest.TestCase):
    def test_resource_aliases_normalize(self):
        self.assertEqual(normalize_resource("PORT:008765"), "port:8765")
        self.assertEqual(normalize_resource("browser-profile:UITest"), "browser-profile:uitest")
        self.assertEqual(normalize_resource("path:src/./app.py"), "path:src/app.py")

    def test_resource_escape_and_unknown_namespace_rejected(self):
        for value in ("path:../outside", "port:70000", "socket:x", "sqlite:"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                normalize_resource(value)

    def test_command_profile_is_fixed_argv_and_rejects_shell_composition(self):
        profile = parse_command_profile(
            "unit",
            {
                "argv": [".venv/bin/python", "-m", "unittest"],
                "allowed_args": {"test_selector": {"type": "selector", "flag": "", "max_length": 80}},
            },
        )
        self.assertEqual(
            render_typed_args(profile, {"test_selector": "tests.test_policy"}),
            (".venv/bin/python", "-m", "unittest", "tests.test_policy"),
        )
        for bad in ("x|cat", "$(id)", "x > y", "x;whoami", "`id`"):
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                render_typed_args(profile, {"test_selector": bad})

    def test_shell_executable_rejected_even_in_operator_profile(self):
        for executable in ("sh", "bash", "/bin/zsh", "powershell"):
            with self.subTest(executable=executable), self.assertRaises(PolicyError):
                parse_command_profile("bad", {"argv": [executable, "-c"], "allowed_args": {}})

    def test_typed_path_and_choice(self):
        profile = parse_command_profile(
            "tool",
            {
                "argv": ["tool"],
                "allowed_args": {
                    "path": {"type": "path", "flag": "--path"},
                    "mode": {"type": "choice", "flag": "--mode", "choices": ["test", "build"]},
                },
            },
        )
        self.assertEqual(
            render_typed_args(profile, {"path": "tests/test_policy.py", "mode": "test"}),
            ("tool", "--path", "tests/test_policy.py", "--mode", "test"),
        )
        with self.assertRaises(PolicyError):
            render_typed_args(profile, {"path": "../outside", "mode": "test"})
        with self.assertRaises(PolicyError):
            render_typed_args(profile, {"path": "tests", "mode": "deploy"})

    def test_command_profile_without_lifecycle_remains_permanent(self):
        profile = parse_command_profile("managed-example", {"argv": ["echo"]})
        self.assertIsNone(profile.lifecycle)

    def test_command_profile_parses_ephemeral_lifecycle_and_hashes_it(self):
        raw = {
            "argv": ["echo"],
            "lifecycle": {
                "kind": "ephemeral",
                "purpose": "github-bootstrap",
                "owner": "portfolio-mcp",
                "created_at": "2026-08-21T00:00:00Z",
                "expires_at": "2026-08-21T06:00:00Z",
            },
        }
        profile = parse_command_profile("managed-example", raw)
        self.assertIsNotNone(profile.lifecycle)
        self.assertEqual(profile.lifecycle.kind, "ephemeral")
        self.assertEqual(profile.lifecycle.purpose, "github-bootstrap")
        self.assertEqual(profile.lifecycle.owner, "portfolio-mcp")
        self.assertEqual(profile.lifecycle.created_at, "2026-08-21T00:00:00Z")
        self.assertEqual(profile.lifecycle.expires_at, "2026-08-21T06:00:00Z")
        permanent = parse_command_profile("managed-example", {"argv": ["echo"]})
        self.assertNotEqual(profile.definition_hash, permanent.definition_hash)

    def test_command_profile_rejects_invalid_ephemeral_lifecycle(self):
        invalid_lifecycles = (
            {"kind": "permanent", "purpose": "x", "owner": "y", "created_at": "2026-08-21T00:00:00Z"},
            {"kind": "ephemeral", "owner": "y", "created_at": "2026-08-21T00:00:00Z"},
            {"kind": "ephemeral", "purpose": "x", "created_at": "2026-08-21T00:00:00Z"},
            {"kind": "ephemeral", "purpose": "x", "owner": "y"},
            {"kind": "ephemeral", "purpose": "x", "owner": "y", "created_at": "2026-08-21T00:00:00+09:00"},
            {"kind": "ephemeral", "purpose": "x", "owner": "y", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-20T23:59:59Z"},
            {"kind": "ephemeral", "purpose": "x", "owner": "y", "created_at": "2026-08-21T00:00:00Z", "expires_at": "2026-08-28T00:00:01Z"},
            {"kind": "ephemeral", "purpose": "x", "owner": "y", "created_at": "2026-08-21T00:00:00Z", "unexpected": True},
        )
        for lifecycle in invalid_lifecycles:
            with self.subTest(lifecycle=lifecycle), self.assertRaises(PolicyError):
                parse_command_profile("managed-example", {"argv": ["echo"], "lifecycle": lifecycle})


class UnifiedApprovalTests(unittest.TestCase):
    def test_one_shot_exact_binding_and_expiry(self):
        clock = [100.0]
        store = UnifiedApprovalStore(clock=lambda: clock[0], ttl_seconds=60)
        approval = store.issue("merge", "repo", "a" * 64, "Approve exact merge.")
        self.assertTrue(approval.as_dict()["one_shot"])
        store.consume(approval.approval_id, "Approve exact merge.", operation="merge", workspace_id="repo", fingerprint="a" * 64)
        with self.assertRaises(ApprovalError):
            store.consume(approval.approval_id, "Approve exact merge.", operation="merge", workspace_id="repo", fingerprint="a" * 64)

        second = store.issue("merge", "repo", "b" * 64, "Approve another merge.")
        clock[0] = 161.0
        with self.assertRaises(ApprovalError):
            store.consume(second.approval_id, "Approve another merge.", operation="merge", workspace_id="repo", fingerprint="b" * 64)

    def test_wrong_confirmation_or_fingerprint_rejected(self):
        store = UnifiedApprovalStore(ttl_seconds=60)
        approval = store.issue("branch_create", "repo", "c" * 64, "Approve branch.")
        with self.assertRaises(ApprovalError):
            store.consume(approval.approval_id, "wrong", operation="branch_create", workspace_id="repo", fingerprint="c" * 64)
        with self.assertRaises(ApprovalError):
            store.consume(approval.approval_id, "Approve branch.", operation="branch_create", workspace_id="repo", fingerprint="d" * 64)


if __name__ == "__main__":
    unittest.main()
