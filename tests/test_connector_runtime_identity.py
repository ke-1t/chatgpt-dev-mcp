from __future__ import annotations

import subprocess
import sys
import unittest

from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager
from chatgpt_dev_mcp.server import WrapperRuntime


def initialize_request(request_id: int, connection_id: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": False}},
            "clientInfo": {"name": "chatgpt", "version": "test"},
            "_meta": {"connection_id": connection_id},
        },
    }


class ConnectorRuntimeIdentityTests(unittest.TestCase):
    def test_logical_reconnect_preserves_physical_child_identity(self) -> None:
        runtime = WrapperRuntime()
        manager = ConnectionRuntimeManager(lambda: WrapperRuntime(), initial_runtime=runtime)
        physical_child_id = runtime.child_instance_id
        capability_epoch = runtime.runtime_capability_epoch
        try:
            first = manager.dispatch(initialize_request(1, "connection-a"))
            self.assertIsNotNone(first)
            self.assertNotIn("error", first or {})
            first_logical_connection_id = runtime.logical_connection_id
            first_request_registry = runtime.request_registry
            self.assertEqual(runtime.child_instance_id, physical_child_id)
            self.assertEqual(runtime.runtime_capability_epoch, capability_epoch)

            second = manager.dispatch(initialize_request(1, "connection-b"))
            self.assertIsNotNone(second)
            self.assertNotIn("error", second or {})
            self.assertNotEqual(runtime.logical_connection_id, first_logical_connection_id)
            self.assertIsNot(runtime.request_registry, first_request_registry)
            self.assertEqual(runtime.child_instance_id, physical_child_id)
            self.assertEqual(runtime.runtime_capability_epoch, capability_epoch)
        finally:
            manager.close()

    def test_new_wrapper_runtime_rotates_child_identity_but_keeps_process_capability_epoch(self) -> None:
        first = WrapperRuntime()
        second = WrapperRuntime()
        try:
            self.assertNotEqual(first.child_instance_id, second.child_instance_id)
            self.assertEqual(first.runtime_capability_epoch, second.runtime_capability_epoch)
        finally:
            first.close()
            second.close()

    def test_new_physical_process_rotates_capability_epoch(self) -> None:
        runtime = WrapperRuntime()
        try:
            child_epoch = subprocess.check_output(
                [
                    sys.executable,
                    "-c",
                    (
                        "from chatgpt_dev_mcp.server import WrapperRuntime; "
                        "runtime = WrapperRuntime(); "
                        "print(runtime.runtime_capability_epoch); "
                        "runtime.close()"
                    ),
                ],
                text=True,
            ).strip()
            self.assertNotEqual(runtime.runtime_capability_epoch, child_epoch)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
