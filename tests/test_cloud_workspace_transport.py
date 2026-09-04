from __future__ import annotations

import unittest


class CloudWorkspaceTransportTests(unittest.TestCase):
    def test_in_memory_transport_pins_package_and_provider_identity(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackage
        from chatgpt_dev_mcp.cloud_workspace_transport import InMemoryCloudWorkspaceTransport

        package = CloudWorkspacePackage("package:abc", "demo", "a" * 40, "test_shard", (), "f" * 64, 0, b"")
        transport = InMemoryCloudWorkspaceTransport()
        status = transport.status()
        self.assertTrue(status.available)
        self.assertEqual(status.provider_id, "chatgpt_managed_cloud")
        ref = transport.stage(package)
        self.assertEqual(ref.package_id, package.package_id)
        self.assertEqual(ref.provider_id, "chatgpt_managed_cloud")

    def test_unavailable_transport_fails_closed(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackage
        from chatgpt_dev_mcp.cloud_workspace_transport import InMemoryCloudWorkspaceTransport, CloudWorkspaceTransportError

        package = CloudWorkspacePackage("package:abc", "demo", "a" * 40, "test_shard", (), "f" * 64, 0, b"")
        transport = InMemoryCloudWorkspaceTransport(available=False, reason="unsupported")
        self.assertFalse(transport.status().available)
        with self.assertRaises(CloudWorkspaceTransportError):
            transport.stage(package)

    def test_diagnostic_transport_enforces_stage_byte_bound(self) -> None:
        from chatgpt_dev_mcp.cloud_workspace_package import CloudWorkspacePackage
        from chatgpt_dev_mcp.cloud_workspace_transport import CloudWorkspaceTransportError, InMemoryCloudWorkspaceTransport

        package = CloudWorkspacePackage(
            "package:abc",
            "demo",
            "a" * 40,
            "test_shard",
            (),
            "f" * 64,
            1_048_577,
            b"x",
        )
        with self.assertRaisesRegex(CloudWorkspaceTransportError, "byte limit"):
            InMemoryCloudWorkspaceTransport().stage(package)


if __name__ == "__main__":
    unittest.main()
