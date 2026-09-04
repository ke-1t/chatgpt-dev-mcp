from __future__ import annotations

import hashlib
import unittest


class ChatGPTCloudAdapterTests(unittest.TestCase):
    def _package(self):
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackage

        return CloudWorkspacePackage("package:abc", "demo", "a" * 40, "test_shard", (), "f" * 64, 0, b"")

    def test_default_adapter_is_explicitly_unavailable_without_supported_file_handoff(self) -> None:
        from chatgpt_dev_mcp.chatgpt_cloud_adapter import ChatGPTManagedCloudAdapter

        status = ChatGPTManagedCloudAdapter().status()
        self.assertFalse(status["available"])
        self.assertEqual(status["reason"], "supported_file_handoff_unavailable")
        self.assertFalse(status["billable_api"])
        self.assertFalse(status["credential_required"])

    def test_injected_supported_transport_executes_without_api_credentials(self) -> None:
        from chatgpt_dev_mcp.chatgpt_cloud_adapter import ChatGPTManagedCloudAdapter
        from chatgpt_dev_mcp.cloud_workspace_transport import CloudWorkspaceResultPackage, InMemoryCloudWorkspaceTransport

        transport = InMemoryCloudWorkspaceTransport()

        def execute(ref):
            patch = ""
            result = CloudWorkspaceResultPackage(
                source_revision="a" * 40,
                package_id=ref.package_id,
                workload_id="test_shard",
                changed_paths=(),
                patch=patch,
                patch_hash=hashlib.sha256(patch.encode()).hexdigest(),
                execution_summary="ok",
                stage_metrics=(),
                input_bytes=0,
                output_bytes=0,
                cloud_fingerprint="cloud:test",
                artifact_hashes=(),
                billable_api=False,
            )
            return transport.set_result(ref.ref_id, result)

        adapter = ChatGPTManagedCloudAdapter(transport=transport, executor=execute)
        self.assertTrue(adapter.status()["available"])
        result = adapter.execute(self._package())
        self.assertEqual(result.package_id, "package:abc")
        self.assertFalse(result.billable_api)


if __name__ == "__main__":
    unittest.main()
