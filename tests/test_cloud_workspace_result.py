from __future__ import annotations

import hashlib
import unittest


class CloudWorkspaceResultTests(unittest.TestCase):
    def _package(self):
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackage

        return CloudWorkspacePackage("package:abc", "demo", "a" * 40, "test_shard", (), "f" * 64, 0, b"")

    def _result(self, patch: str, **overrides):
        from chatgpt_dev_mcp.cloud_workspace_transport import CloudWorkspaceResultPackage

        values = dict(
            source_revision="a" * 40,
            package_id="package:abc",
            workload_id="test_shard",
            changed_paths=("src/app.py",),
            patch=patch,
            patch_hash=hashlib.sha256(patch.encode()).hexdigest(),
            execution_summary="ok",
            stage_metrics=(),
            input_bytes=10,
            output_bytes=len(patch.encode()),
            cloud_fingerprint="cloud:test",
            artifact_hashes=(),
            billable_api=False,
        )
        values.update(overrides)
        return CloudWorkspaceResultPackage(**values)

    def test_valid_result_is_accepted(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_result import validate_cloud_workspace_result

        patch = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        validated = validate_cloud_workspace_result(self._result(patch), expected_package=self._package(), allowed_paths=("src",), current_revision="a" * 40)
        self.assertEqual(validated.patch_hash, hashlib.sha256(patch.encode()).hexdigest())

    def test_stale_or_billable_managed_result_is_rejected(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_result import CloudWorkspaceResultError, validate_cloud_workspace_result

        patch = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        with self.assertRaisesRegex(CloudWorkspaceResultError, "stale"):
            validate_cloud_workspace_result(self._result(patch), expected_package=self._package(), allowed_paths=("src",), current_revision="b" * 40)
        with self.assertRaisesRegex(CloudWorkspaceResultError, "billable"):
            validate_cloud_workspace_result(self._result(patch, billable_api=True), expected_package=self._package(), allowed_paths=("src",), current_revision="a" * 40)

    def test_identity_hash_scope_secret_and_size_violations_are_rejected(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_result import CloudWorkspaceResultError, validate_cloud_workspace_result

        patch = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        cases = (
            (self._result(patch, package_id="package:other"), "identity"),
            (self._result(patch, source_revision="b" * 40), "identity"),
            (self._result(patch, patch_hash="0" * 64), "hash"),
            (self._result(patch, changed_paths=("outside.txt",)), "scope"),
        )
        for result, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(CloudWorkspaceResultError):
                    validate_cloud_workspace_result(result, expected_package=self._package(), allowed_paths=("src",), current_revision="a" * 40)

        secret_assignment = "api" + "_key=" + ("x" * 48)
        secret_patch = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+" + secret_assignment + "\n"
        with self.assertRaisesRegex(CloudWorkspaceResultError, "SECRET"):
            validate_cloud_workspace_result(self._result(secret_patch), expected_package=self._package(), allowed_paths=("src",), current_revision="a" * 40)

        huge_patch = "x" * (512 * 1024 + 1)
        with self.assertRaisesRegex(CloudWorkspaceResultError, "size"):
            validate_cloud_workspace_result(self._result(huge_patch), expected_package=self._package(), allowed_paths=("src",), current_revision="a" * 40)


if __name__ == "__main__":
    unittest.main()
