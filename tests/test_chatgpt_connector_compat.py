from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import traceback
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import chatgpt_dev_mcp.chatgpt_connector_compat as connector_compat
from chatgpt_dev_mcp.chatgpt_connector_compat import dispatch_rpc_compat, serve_stdio_compat


class CountingRuntime:
    protocol_version = "2025-11-25"
    initialized = False

    def __init__(self) -> None:
        self.initialize_calls: list[dict[str, object] | None] = []
        self.closed = False

    def initialize(self, client_info: dict[str, object] | None = None) -> dict[str, object]:
        self.initialize_calls.append(client_info)
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "counting-runtime", "version": "test"},
        }

    def list_tools(self) -> dict[str, object]:
        return {"tools": [{"name": "ping"}]}

    def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
        *,
        request_id: str | int | None = None,
    ) -> dict[str, object]:
        return {"name": name, "arguments": arguments, "request_id": request_id}

    def cancel_request(self, request_id: str | int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class BlockingRuntime(CountingRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.initialize_started = threading.Event()
        self.release_initialize = threading.Event()

    def initialize(self, client_info: dict[str, object] | None = None) -> dict[str, object]:
        self.initialize_started.set()
        if not self.release_initialize.wait(timeout=5):
            raise RuntimeError("initialize test gate timed out")
        return super().initialize(client_info)


def run_requests(runtime: CountingRuntime, requests: list[dict[str, object]]) -> list[dict[str, object]]:
    input_stream = StringIO("".join(json.dumps(request) + "\n" for request in requests))
    output_stream = StringIO()
    serve_stdio_compat(runtime, input_stream=input_stream, output_stream=output_stream)
    return [json.loads(line) for line in output_stream.getvalue().splitlines()]


def run_requests_with_factory(
    runtime_factory: object,
    requests: list[dict[str, object]],
) -> list[dict[str, object]]:
    input_stream = StringIO("".join(json.dumps(request) + "\n" for request in requests))
    output_stream = StringIO()
    serve_stdio_compat(runtime_factory=runtime_factory, input_stream=input_stream, output_stream=output_stream)  # type: ignore[arg-type]
    return [json.loads(line) for line in output_stream.getvalue().splitlines()]


def dispatch_requests(runtime: CountingRuntime, requests: list[dict[str, object]]) -> list[dict[str, object] | None]:
    state = connector_compat.InitializeReplayState()
    return [dispatch_rpc_compat(runtime, request, state) for request in requests]


def initialize_request(request_id: int, *, client_name: str = "chatgpt") -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {"listChanged": False}},
            "clientInfo": {"name": client_name, "version": "test"},
        },
    }


class ChatGPTConnectorCompatTests(unittest.TestCase):
    def test_one_logical_connection_reuses_one_runtime_for_bounded_duplicate(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        responses = run_requests_with_factory(
            factory,
            [
                initialize_request(1),
                initialize_request(0),
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ping", "arguments": {}},
                },
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 1)
        self.assertNotIn("error", responses[1])
        self.assertNotIn("error", responses[2])
        self.assertNotIn("error", responses[3])

    def test_notifications_initialized_does_not_consume_duplicate_initialize_budget(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        responses = run_requests_with_factory(
            factory,
            [
                initialize_request(1),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                initialize_request(0),
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertNotIn("error", responses[0])
        self.assertNotIn("error", responses[1])

    def test_initialize_after_operation_uses_a_fresh_protocol_session(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        responses = run_requests_with_factory(
            factory,
            [
                initialize_request(1),
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                initialize_request(3),
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertTrue(runtimes[0].closed)
        self.assertEqual(len(runtimes[0].initialize_calls), 2)
        self.assertTrue(all("error" not in response for response in responses))

    def test_initialize_after_operation_does_not_compare_handshake_params(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        changed = initialize_request(3, client_name="new-client")
        responses = run_requests_with_factory(
            factory,
            [
                initialize_request(1),
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "ping", "arguments": {}},
                },
                changed,
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 2)
        self.assertNotIn("error", responses[2])

    def test_three_logical_connections_reuse_one_process_runtime(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        requests: list[dict[str, object]] = []
        for connection in range(3):
            requests.extend(
                [
                    initialize_request(connection),
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                ]
            )

        responses = run_requests_with_factory(factory, requests)

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 3)
        self.assertTrue(runtimes[0].closed)
        self.assertTrue(all("error" not in response for response in responses))

    def test_logical_connection_history_records_request_completion_and_rotation_reason(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager

        runtime = CountingRuntime()
        manager = ConnectionRuntimeManager(lambda: CountingRuntime(), initial_runtime=runtime)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            self.assertNotIn(
                "error",
                manager.dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "ping", "arguments": {}},
                    }
                )
                or {},
            )
            self.assertNotIn("error", manager.dispatch(initialize_request(3)) or {})

            history = getattr(runtime, "logical_connection_history")
            self.assertEqual(len(history), 2)
            first, second = history
            self.assertEqual(first["logical_connection_id"], "stdio-connection:1")
            self.assertEqual(first["request_count"], 2)
            self.assertEqual(first["last_request_method"], "tools/call")
            self.assertIsNotNone(first["last_request_at"])
            self.assertIsNotNone(first["last_completed_at"])
            self.assertIsNotNone(first["closed_at"])
            self.assertEqual(first["close_reason"], "post_operation_initialize")
            self.assertEqual(second["logical_connection_id"], "stdio-connection:2")
            self.assertEqual(second["request_count"], 1)
            self.assertEqual(second["last_request_method"], "initialize")
            self.assertIsNone(second["closed_at"])
            self.assertEqual(first["child_instance_id"], second["child_instance_id"])
        finally:
            manager.close()

    def test_logical_connection_history_is_bounded(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager

        runtime = CountingRuntime()
        manager = ConnectionRuntimeManager(lambda: CountingRuntime(), initial_runtime=runtime)
        try:
            for index in range(70):
                self.assertNotIn("error", manager.dispatch(initialize_request(index * 2 + 1)) or {})
                self.assertNotIn(
                    "error",
                    manager.dispatch({"jsonrpc": "2.0", "id": index * 2 + 2, "method": "tools/list"}) or {},
                )
            history = getattr(runtime, "logical_connection_history")
            self.assertEqual(len(history), 64)
            self.assertEqual(history[0]["logical_connection_id"], "stdio-connection:7")
            self.assertEqual(history[-1]["logical_connection_id"], "stdio-connection:70")
        finally:
            manager.close()

    def test_server_health_exposes_bounded_logical_connection_history(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager
        from chatgpt_dev_mcp.server import WrapperRuntime

        physical = WrapperRuntime()
        manager = ConnectionRuntimeManager(lambda: WrapperRuntime(), initial_runtime=physical)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            self.assertNotIn("error", manager.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {})

            runtime_health = physical._health_snapshot()["runtime"]
            history = runtime_health["logical_connection_history"]
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["logical_connection_id"], "stdio-connection:1")
            self.assertEqual(history[0]["last_request_method"], "tools/list")
            self.assertEqual(history[0]["request_count"], 2)
            self.assertEqual(history[0]["child_instance_id"], runtime_health["child_instance_id"])
        finally:
            manager.close()

    def test_logical_reconnect_and_same_process_wrapper_keep_physical_capability_epoch(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager
        from chatgpt_dev_mcp.server import WrapperRuntime

        physical = WrapperRuntime()
        initial_epoch = physical.runtime_capability_epoch
        manager = ConnectionRuntimeManager(lambda: WrapperRuntime(), initial_runtime=physical)
        replacement = None
        try:
            first = manager.dispatch(initialize_request(1))
            self.assertNotIn("error", first or {})
            listed = manager.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertNotIn("error", listed or {})
            second = manager.dispatch(initialize_request(3))
            self.assertNotIn("error", second or {})
            current = manager.current_session
            self.assertIsNotNone(current)
            assert current is not None
            self.assertIs(current.runtime, physical)
            self.assertEqual(current.runtime.runtime_capability_epoch, initial_epoch)
        finally:
            manager.close()

        replacement = WrapperRuntime()
        try:
            self.assertEqual(replacement.runtime_capability_epoch, initial_epoch)
        finally:
            replacement.close()

    def test_inflight_write_blocks_runtime_replacement_without_replay(self) -> None:
        class BlockingWriteRuntime(CountingRuntime):
            def __init__(self) -> None:
                super().__init__()
                self.write_started = threading.Event()
                self.release_write = threading.Event()
                self.write_calls = 0

            def call_tool(
                self,
                name: str,
                arguments: dict[str, object],
                *,
                request_id: str | int | None = None,
            ) -> dict[str, object]:
                if name == "write":
                    self.write_calls += 1
                    self.write_started.set()
                    if not self.release_write.wait(timeout=5):
                        raise RuntimeError("write test gate timed out")
                return super().call_tool(name, arguments, request_id=request_id)

        runtimes: list[BlockingWriteRuntime] = []

        def factory() -> BlockingWriteRuntime:
            runtime = BlockingWriteRuntime()
            runtimes.append(runtime)
            return runtime

        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager

        manager = ConnectionRuntimeManager(factory)
        try:
            self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
            write_result: list[dict[str, object] | None] = [None]
            worker = threading.Thread(
                target=lambda: write_result.__setitem__(
                    0,
                    manager.dispatch(
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {"name": "write", "arguments": {}},
                        }
                    ),
                )
            )
            worker.start()
            self.assertTrue(runtimes[0].write_started.wait(timeout=5))

            blocked = manager.dispatch(initialize_request(3))

            self.assertIsNotNone(blocked)
            assert blocked is not None
            self.assertEqual(blocked["error"]["data"]["reason"], "outcome_unknown")
            self.assertEqual(len(runtimes), 1)
            self.assertEqual(runtimes[0].write_calls, 1)
            runtimes[0].release_write.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", write_result[0] or {})
        finally:
            manager.close()

    def test_replays_measured_discovery_initialize_without_reinitializing(self) -> None:
        runtime = CountingRuntime()
        responses = run_requests(
            runtime,
            [
                {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
                initialize_request(1),
                initialize_request(0),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ],
        )

        self.assertEqual(runtime.initialize_calls, [{"name": "chatgpt", "version": "test"}])
        self.assertEqual(responses[0]["id"], "openai-mcp-discover")
        self.assertEqual(responses[0]["error"]["code"], -32002)
        self.assertEqual(responses[1]["id"], 1)
        self.assertEqual(responses[2]["id"], 0)
        self.assertEqual(responses[1]["result"], responses[2]["result"])
        self.assertEqual(responses[3]["id"], 2)
        self.assertEqual(responses[3]["result"]["tools"], [{"name": "ping"}])
        self.assertTrue(runtime.initialized)
        self.assertTrue(runtime.closed)

    def test_rejects_incompatible_duplicate_initialize(self) -> None:
        runtime = CountingRuntime()
        responses = run_requests(runtime, [initialize_request(1), initialize_request(0, client_name="other")])

        self.assertEqual(len(runtime.initialize_calls), 1)
        self.assertEqual(responses[1]["id"], 0)
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertEqual(responses[1]["error"]["data"]["reason"], "incompatible_initialize")
        self.assertTrue(runtime.initialized)

    def test_locks_out_duplicate_after_normal_operation(self) -> None:
        runtime = CountingRuntime()
        responses = dispatch_requests(
            runtime,
            [
                initialize_request(1),
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                initialize_request(3),
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "server_info", "arguments": {}}},
            ],
        )

        self.assertEqual(len(runtime.initialize_calls), 1)
        self.assertEqual(responses[1]["id"], 2)
        assert responses[2] is not None
        self.assertEqual(responses[2]["id"], 3)
        self.assertEqual(responses[2]["error"]["code"], -32600)
        self.assertEqual(responses[2]["error"]["data"]["reason"], "operation_already_started")
        assert responses[3] is not None
        self.assertEqual(responses[3]["id"], 4)
        self.assertNotIn("error", responses[3])

    def test_allows_compatible_duplicate_replay_bursts_before_operation(self) -> None:
        runtime = CountingRuntime()
        requests = [initialize_request(1)]
        requests.extend(initialize_request(request_id) for request_id in range(10, 42))
        responses = run_requests(runtime, requests)

        self.assertEqual(len(runtime.initialize_calls), 1)
        for response, expected_id in zip(responses[1:], range(10, 42), strict=True):
            self.assertEqual(response["id"], expected_id)
            self.assertNotIn("error", response)
            self.assertEqual(response["result"]["serverInfo"], {"name": "counting-runtime", "version": "test"})

    def test_rejects_different_protocol_version_without_resetting_state(self) -> None:
        runtime = CountingRuntime()
        incompatible = initialize_request(0)
        incompatible["params"]["protocolVersion"] = "2025-06-18"
        responses = run_requests(runtime, [initialize_request(1), incompatible])

        self.assertEqual(len(runtime.initialize_calls), 1)
        self.assertEqual(responses[1]["id"], 0)
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertEqual(responses[1]["error"]["data"]["reason"], "incompatible_initialize")
        self.assertTrue(runtime.initialized)

    def test_actual_wrapper_replays_initialize_and_lists_current_tools(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        responses = run_requests(
            runtime,
            [
                {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
                initialize_request(1),
                initialize_request(0),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ],
        )

        tool_names = {item["name"] for item in responses[-1]["result"]["tools"]}
        from chatgpt_dev_mcp.stable_surface import STABLE_PUBLIC_TOOL_NAMES

        self.assertEqual(len(tool_names), 52)
        self.assertEqual(tool_names, set(STABLE_PUBLIC_TOOL_NAMES))
        self.assertTrue(responses[1]["result"]["capabilities"]["tools"]["listChanged"])
        self.assertEqual(responses[1]["result"], responses[2]["result"])
        self.assertTrue(all("id" in response for response in responses))
        self.assertTrue(all(response.get("method") != "notifications/tools/list_changed" for response in responses))

    def test_connector_reconnect_rotates_protocol_generation_after_discovery(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(1)["params"]
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover"},
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                # The broker ignores request-id epochs and creates a fresh
                # protocol session after the completed tools/list operation.
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertTrue(runtimes[0].closed)
        self.assertNotIn("error", responses[3])
        self.assertNotIn("error", responses[4])
        self.assertEqual(runtimes[0].transport_generation, 1)
        self.assertEqual(runtimes[0].protocol_session_generation, 1)
        self.assertEqual(runtimes[0].protocol_state, "CLOSED")
        self.assertEqual(len(runtimes[0].initialize_calls), 2)

    def test_connector_reconnect_rotates_after_server_info_without_discovery(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(1)["params"]
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "server_info", "arguments": {}},
                },
                # A reconnect can omit server/discover and reuse any id; the
                # post-operation initialize is the only raw-STDIO fallback.
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "workspace_list", "arguments": {}},
                },
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertNotIn("error", responses[2])
        self.assertNotIn("error", responses[3])
        self.assertTrue(runtimes[0].closed)
        self.assertEqual(runtimes[0].transport_generation, 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 2)

    def test_connector_reconnect_accepts_numeric_string_request_id_epoch(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(1)["params"]
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": "2", "method": "tools/list"},
                {"jsonrpc": "2.0", "id": "0", "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": "3", "method": "tools/list"},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 2)
        self.assertNotIn("error", responses[2])
        self.assertNotIn("error", responses[3])

    def test_connector_reconnect_rotates_on_reused_request_id(self) -> None:
        """A persistent Tunnel can reuse id=0 across fresh protocol sessions."""

        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(0)["params"]
        requests: list[dict[str, object]] = [
            {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "tools/call",
                "params": {"name": "server_info", "arguments": {}},
            },
        ]
        for _ in range(10):
            requests.extend(
                [
                    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {
                        "jsonrpc": "2.0",
                        "id": 0,
                        "method": "tools/call",
                        "params": {"name": "server_info", "arguments": {}},
                    },
                ]
            )

        responses = run_requests_with_factory(factory, requests)

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 11)
        self.assertTrue(all("error" not in response for response in responses))
        self.assertTrue(runtimes[0].closed)
        self.assertEqual(runtimes[0].transport_generation, 1)
        self.assertEqual(runtimes[0].protocol_session_generation, 1)

    def test_monotonic_duplicate_initialize_after_operation_remains_protocol_error(self) -> None:
        runtime = CountingRuntime()
        params = initialize_request(1)["params"]
        responses = dispatch_requests(
            runtime,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": params},
            ],
        )

        self.assertEqual(len(runtime.initialize_calls), 1)
        assert responses[2] is not None
        self.assertEqual(responses[2]["error"]["data"]["reason"], "operation_already_started")

    def test_compatible_initialize_after_tool_call_rotates_transport_without_user_error(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(1)["params"]
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "server_info", "arguments": {}},
                },
                {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": params},
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "task_poll", "arguments": {"session_id": "process:test"}},
                },
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(len(runtimes[0].initialize_calls), 2)
        self.assertNotIn("error", responses[2])
        self.assertNotIn("error", responses[3])
        self.assertTrue(runtimes[0].closed)
        self.assertEqual(runtimes[0].transport_generation, 1)

    def test_incompatible_initialize_after_tool_call_does_not_rotate_transport(self) -> None:
        runtime = CountingRuntime()
        params = initialize_request(1)["params"]
        incompatible = initialize_request(3, client_name="other")
        responses = dispatch_requests(
            runtime,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "server_info", "arguments": {}},
                },
                incompatible,
            ],
        )

        self.assertEqual(len(runtime.initialize_calls), 1)
        assert responses[2] is not None
        self.assertEqual(responses[2]["error"]["data"]["reason"], "operation_already_started")
        self.assertEqual(runtime.transport_generation, 1)

    def test_nonzero_reused_request_id_after_operation_remains_protocol_error(self) -> None:
        runtime = CountingRuntime()
        params = initialize_request(7)["params"]
        responses = dispatch_requests(
            runtime,
            [
                {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": params},
            ],
        )

        self.assertEqual(len(runtime.initialize_calls), 1)
        assert responses[2] is not None
        self.assertEqual(responses[2]["error"]["data"]["reason"], "operation_already_started")

    def test_actual_wrapper_server_info_then_reconnect_workspace_list(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-connector-") as temp:
            config = Path(temp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roots": [{"id": "developer", "path": str(project_root), "mode": "PROJECT_DISCOVERY"}],
                        "workspaces": {
                            "fixture-one": {"path": str(project_root), "profile": "READ_ONLY"},
                            "fixture-two": {"path": str(project_root / "src"), "profile": "READ_ONLY"},
                            "fixture-three": {"path": str(project_root / "tests"), "profile": "READ_ONLY"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"LOCAL_DEV_MCP_CONFIG": str(config)}):
                runtimes: list[WrapperRuntime] = []

                def factory() -> WrapperRuntime:
                    runtime = WrapperRuntime()
                    runtimes.append(runtime)
                    return runtime

                params = initialize_request(1)["params"]
                responses = run_requests_with_factory(
                    factory,
                    [
                        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {"name": "server_info", "arguments": {}},
                        },
                        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {"name": "workspace_list", "arguments": {}},
                        },
                    ],
                )

        self.assertNotIn("error", responses[1])
        self.assertNotIn("error", responses[2])
        self.assertNotIn("error", responses[3])
        self.assertEqual(responses[1]["result"]["structuredContent"]["tool_count"], 52)
        self.assertEqual(len(responses[3]["result"]["structuredContent"]["workspaces"]), 3)
        first_identity = responses[1]["result"]["structuredContent"]["health"]["runtime"]["logical_connection_id"]
        self.assertEqual(len(runtimes), 1)
        second_identity = runtimes[0].logical_connection_id
        self.assertIsInstance(first_identity, str)
        self.assertNotEqual(first_identity, second_identity)

    def test_persistent_development_session_is_resumed_by_explicit_handle(self) -> None:
        from chatgpt_dev_mcp.chatgpt_connector_compat import ConnectionRuntimeManager
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-session-") as temp:
            root = Path(temp)
            home = root / "home"
            repo = home / "Developer" / "project-x"
            repo.mkdir(parents=True)
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Connector Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            config = home / ".config" / "local-dev-mcp" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                        "workspaces": {
                            "project-x": {
                                "path": "~/Developer/project-x",
                                "profile": "DEVELOPMENT",
                                "commands": {"test": "printf test-ok"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            runtimes: list[WrapperRuntime] = []

            def factory() -> WrapperRuntime:
                runtime = WrapperRuntime(preserve_persistent_state=True)
                runtimes.append(runtime)
                return runtime

            env = {
                "HOME": str(home),
                "LOCAL_DEV_MCP_CONFIG": str(config),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "director-state"),
                "LOCAL_DEV_MCP_WORKTREE_ROOT": str(home / ".cache" / "local-dev-mcp" / "worktrees"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
            }
            with patch.dict(os.environ, env, clear=False):
                manager = ConnectionRuntimeManager(factory)

                def call(request_id: int, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
                    response = manager.dispatch(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": arguments or {}},
                        }
                    )
                    assert response is not None
                    result = response["result"]
                    assert isinstance(result, dict)
                    structured = result["structuredContent"]
                    assert isinstance(structured, dict), response
                    assert not result.get("isError"), response
                    return structured

                try:
                    self.assertNotIn("error", manager.dispatch(initialize_request(1)) or {})
                    discovered = call(2, "workspace_discover")
                    candidate_id = next(
                        item["candidate_id"]
                        for item in discovered["repositories"]
                        if item["name"] == "project-x"
                    )
                    call(3, "workspace_open", {"id": candidate_id})
                    approval = call(4, "workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "project-x"})
                    created = call(
                        5,
                        "workspace_create_development_session",
                        {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]},
                    )
                    session_id = created["session_id"]

                    # Normal operation has started. The next initialize must
                    # rotate only protocol state and preserve the physical
                    # WrapperRuntime plus its live DEVELOPMENT session.
                    self.assertNotIn("error", manager.dispatch(initialize_request(0)) or {})
                    self.assertEqual(len(runtimes), 1)
                    self.assertFalse(runtimes[0].development_sessions[session_id].stale)
                    status = call(7, "workspace_session_status", {"session_id": session_id})
                    self.assertTrue(status["active"], status)
                    self.assertEqual(status["session_id"], session_id)
                finally:
                    manager.close()

    def test_stale_connection_marker_is_not_forwarded_to_new_generation(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        old_params = initialize_request(1)["params"]
        old_params["_meta"] = {"connection_id": "old"}
        new_params = initialize_request(0)["params"]
        new_params["_meta"] = {"connection_id": "new"}
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": old_params},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": {"connection_id": "old"}}},
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": new_params},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": {"connection_id": "old"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {"_meta": {"connection_id": "new"}}},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(responses[3]["error"]["data"]["reason"], "stale_transport_generation")
        self.assertNotIn("error", responses[4])

    def test_explicit_marker_discovery_starts_the_new_runtime(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        old_params = initialize_request(1)["params"]
        old_params["_meta"] = {"connection_id": "old"}
        new_params = initialize_request(0)["params"]
        new_params["_meta"] = {"connection_id": "new"}
        responses = run_requests_with_factory(
            factory,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": old_params},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": {"connection_id": "old"}}},
                {"jsonrpc": "2.0", "id": "discover-new", "method": "server/discover", "params": {"_meta": {"connection_id": "new"}}},
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": new_params},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": {"connection_id": "new"}}},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertEqual(responses[2]["error"]["code"], -32002)
        self.assertNotIn("error", responses[3])
        self.assertNotIn("error", responses[4])

    def test_repeated_marker_can_refresh_without_becoming_stale(self) -> None:
        runtimes: list[CountingRuntime] = []

        def factory() -> CountingRuntime:
            runtime = CountingRuntime()
            runtimes.append(runtime)
            return runtime

        params = initialize_request(1)["params"]
        params["_meta"] = {"connection_id": "same"}
        responses = run_requests_with_factory(
            factory,
            [
                {
                    "jsonrpc": "2.0",
                    "id": "openai-mcp-discover",
                    "method": "server/discover",
                    "params": {"_meta": {"connection_id": "same"}},
                },
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": {"connection_id": "same"}}},
                {
                    "jsonrpc": "2.0",
                    "id": "openai-mcp-discover-2",
                    "method": "server/discover",
                    "params": {"_meta": {"connection_id": "same"}},
                },
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": {"connection_id": "same"}}},
            ],
        )

        self.assertEqual(len(runtimes), 1)
        self.assertNotIn("error", responses[4])
        self.assertNotIn("error", responses[5])
        self.assertEqual(runtimes[0].transport_generation, 1)
        self.assertEqual(runtimes[0].protocol_state, "CLOSED")

    def test_protocol_reset_keeps_wrapper_runtime_and_development_lease(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        upstream = object()
        runtime.upstream = upstream  # type: ignore[assignment]
        runtime.active_development_session_id = "session:existing"
        runtime.initialized = True

        runtime.reset_protocol_session()

        self.assertFalse(runtime.initialized)
        self.assertIs(runtime.upstream, upstream)
        self.assertEqual(runtime.active_development_session_id, "session:existing")

    def test_concurrent_initialize_has_one_owner_and_bounded_second_error(self) -> None:
        runtime = BlockingRuntime()
        state = connector_compat.InitializeReplayState()
        first_request = initialize_request(1)
        second_request = initialize_request(2)
        results: list[dict[str, object] | None] = [None, None]

        first = threading.Thread(target=lambda: results.__setitem__(0, dispatch_rpc_compat(runtime, first_request, state)))
        first.start()
        self.assertTrue(runtime.initialize_started.wait(timeout=5))
        results[1] = dispatch_rpc_compat(runtime, second_request, state)
        runtime.release_initialize.set()
        first.join(timeout=5)

        self.assertFalse(first.is_alive())
        self.assertEqual(len(runtime.initialize_calls), 1)
        self.assertNotIn("error", results[0] or {})
        self.assertEqual((results[1] or {})["error"]["data"]["reason"], "initialization_in_progress")

    def test_operation_already_started_stack_identifies_compat_dispatch(self) -> None:
        runtime = CountingRuntime()
        captured: list[str] = []
        original_jsonrpc_error = connector_compat.jsonrpc_error

        def capture_stack(*args: object, **kwargs: object) -> dict[str, object]:
            if len(args) >= 4 and isinstance(args[3], dict) and args[3].get("reason") == "operation_already_started":
                captured.append("".join(traceback.format_stack()))
            return original_jsonrpc_error(*args, **kwargs)

        with patch.object(connector_compat, "jsonrpc_error", side_effect=capture_stack):
            dispatch_requests(
                runtime,
                [initialize_request(1), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, initialize_request(3)],
            )

        self.assertEqual(len(captured), 1)
        self.assertIn("dispatch_rpc_compat", captured[0])
        self.assertIn("state.replay", captured[0])

    def test_server_info_and_workspace_list_soak_preserves_protocol_state(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        requests: list[dict[str, object]] = [initialize_request(1)]
        request_id = 2
        for _ in range(100):
            for name in ("server_info", "workspace_list"):
                requests.append(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": {}},
                    }
                )
                request_id += 1
        responses = run_requests(runtime, requests)

        self.assertEqual(len(responses), 201)
        self.assertTrue(all("error" not in response for response in responses))
        self.assertEqual(runtime.protocol_state, "CLOSED")
        self.assertEqual(runtime.transport_generation, 1)

    def test_repeated_global_diagnostics_do_not_change_connection_generation(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        requests: list[dict[str, object]] = [initialize_request(1)]
        request_id = 2
        for _ in range(10):
            for name in (
                "server_info",
                "director_health",
                "director_usage",
                "workspace_list",
                "workspace_list_development_sessions",
                "check_exec_environment",
            ):
                requests.append(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": {}},
                    }
                )
                request_id += 1

        responses = run_requests(runtime, requests)

        self.assertEqual(len(responses), 61)
        self.assertTrue(all("error" not in response for response in responses))
        self.assertEqual(runtime.protocol_state, "CLOSED")
        self.assertEqual(runtime.transport_generation, 1)
        self.assertEqual(runtime.protocol_session_generation, 1)

    def test_check_exec_environment_is_binding_free_and_read_only(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            result = runtime.call_tool("check_exec_environment", {})

            self.assertFalse(result["isError"])
            self.assertIsNone(result["structuredContent"]["workspace"])
            self.assertIsNone(runtime.current)
            self.assertIsNone(runtime.upstream)
            self.assertFalse(runtime._workspace_bindings)
        finally:
            runtime.close()

    def test_global_diagnostics_do_not_synchronize_active_session(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            with patch.object(runtime, "_synchronize_active_session", side_effect=AssertionError("global diagnostic synchronized session")):
                for name in (
                    "server_info",
                    "check_exec_environment",
                    "director_health",
                    "director_usage",
                    "security_audit",
                    "workspace_list",
                    "workspace_list_development_sessions",
                ):
                    result = runtime.call_tool(name, {})
                    if name == "security_audit":
                        self.assertTrue(result["isError"], name)
                        self.assertEqual(
                            result["structuredContent"]["error"]["code"],
                            "WORKSPACE_NOT_SELECTED",
                        )
                    else:
                        self.assertFalse(result["isError"], name)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
