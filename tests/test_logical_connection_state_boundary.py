from __future__ import annotations

import unittest

from coding_tools_mcp.telemetry import SessionTelemetry
from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager
from chatgpt_dev_mcp.request_lifecycle import SideEffectClass


def initialize_request(request_id: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": False}},
            "clientInfo": {"name": "boundary-test", "version": "1"},
        },
    }


class ProcessScopedRuntime:
    protocol_version = "2025-11-25"

    def __init__(self) -> None:
        self.initialized = False
        self.closed = False
        self.logical_close_calls = 0
        self.protocol_reset_calls = 0
        self.handoff_state: dict[str, str] = {}
        self.live_process = False
        self.telemetry = SessionTelemetry(permission_mode="safe", transport="test")

    def initialize(
        self,
        client_info: dict[str, object] | None = None,
        protocol_version: str = protocol_version,
    ) -> dict[str, object]:
        self.initialized = True
        return {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "boundary-test", "version": "1"},
        }

    def list_tools(self) -> dict[str, object]:
        return {"tools": []}

    def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
        *,
        context: object | None = None,
    ) -> dict[str, object]:
        return {
            "name": name,
            "arguments": arguments,
            "context_protocol_version": getattr(context, "protocol_version", None),
        }

    def cancel_request(self, request_id: str | int) -> None:
        return None

    def reset_protocol_session(self) -> None:
        self.initialized = False
        self.protocol_reset_calls += 1

    def close_for_logical_connection(self) -> None:
        self.logical_close_calls += 1
        self.handoff_state.clear()

    def connection_replacement_block_reason(self) -> str | None:
        return "outcome_unknown" if self.live_process else None

    def close(self) -> None:
        self.closed = True
        self.telemetry.finish()

    def server_identity(self) -> dict[str, object]:
        return {"name": "boundary-test", "version": "1"}


class LogicalConnectionStateBoundaryTests(unittest.TestCase):
    def test_rotation_reuses_physical_runtime_and_preserves_handoff_state(self) -> None:
        runtimes: list[ProcessScopedRuntime] = []

        def factory() -> ProcessScopedRuntime:
            runtime = ProcessScopedRuntime()
            runtimes.append(runtime)
            return runtime

        manager = ConnectionRuntimeManager(factory)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            self.assertNotIn(
                "error",
                manager.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {},
            )
            first_identity = runtimes[0].logical_connection_id
            runtimes[0].handoff_state["approval"] = "keep-across-logical-connections"

            self.assertNotIn("error", manager.dispatch(initialize_request(3)) or {})

            self.assertEqual(len(runtimes), 1)
            self.assertEqual(runtimes[0].handoff_state["approval"], "keep-across-logical-connections")
            self.assertEqual(runtimes[0].protocol_reset_calls, 1)
            self.assertEqual(runtimes[0].logical_close_calls, 0)
            self.assertNotEqual(first_identity, runtimes[0].logical_connection_id)
        finally:
            manager.close()

    def test_live_process_does_not_block_protocol_only_rotation(self) -> None:
        runtimes: list[ProcessScopedRuntime] = []

        def factory() -> ProcessScopedRuntime:
            runtime = ProcessScopedRuntime()
            runtimes.append(runtime)
            return runtime

        manager = ConnectionRuntimeManager(factory)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            self.assertNotIn(
                "error",
                manager.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {},
            )
            runtimes[0].live_process = True

            rotated = manager.dispatch(initialize_request(3))

            self.assertIsNotNone(rotated)
            self.assertNotIn("error", rotated or {})
            self.assertEqual(len(runtimes), 1)
            self.assertTrue(runtimes[0].live_process)
        finally:
            manager.close()

    def test_inflight_read_only_request_blocks_registry_swap_without_outcome_unknown(self) -> None:
        runtime = ProcessScopedRuntime()
        manager = ConnectionRuntimeManager(lambda: runtime)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            self.assertNotIn(
                "error",
                manager.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {},
            )
            session = manager.current_session
            assert session is not None
            session.state.request_registry.accept(
                "active-read",
                "tools/list",
                side_effect_class=SideEffectClass.READ_ONLY,
            )
            session.state.request_registry.start("active-read")

            blocked = manager.dispatch(initialize_request(3))

            self.assertIsNotNone(blocked)
            assert blocked is not None
            self.assertEqual(blocked["error"]["data"]["reason"], "request_in_progress")
            self.assertNotEqual(blocked["error"]["data"].get("outcome"), "outcome_unknown")
            self.assertEqual(runtime.protocol_reset_calls, 0)
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
