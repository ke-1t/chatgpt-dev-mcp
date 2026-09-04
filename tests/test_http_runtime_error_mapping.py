from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import patch

from chatgpt_dev_mcp.request_lifecycle import RequestRegistry
from chatgpt_dev_mcp.transport_http import (
    HTTPSessionRecord,
    HTTPTransportError,
    WrapperMCPHandler,
)


class HttpRuntimeErrorMappingTests(unittest.TestCase):
    def _record(self) -> HTTPSessionRecord:
        return HTTPSessionRecord(
            session_id="mcp_test",
            runtime=object(),  # type: ignore[arg-type]
            created_at=time.monotonic(),
            last_seen=time.monotonic(),
            lock=threading.RLock(),
            request_registry=RequestRegistry(),
        )

    def test_local_runtime_error_is_not_mislabeled_as_upstream_502(self) -> None:
        handler = object.__new__(WrapperMCPHandler)
        request = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {"name": "director_development_start", "arguments": {}},
        }

        with patch(
            "chatgpt_dev_mcp.transport_http.dispatch_rpc",
            side_effect=RuntimeError("local director preflight failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "local director preflight failed"):
                handler._dispatch_with_recovery(self._record(), request)

    def test_connection_error_remains_upstream_502(self) -> None:
        handler = object.__new__(WrapperMCPHandler)
        request = {
            "jsonrpc": "2.0",
            "id": "req-2",
            "method": "tools/call",
            "params": {"name": "director_development_start", "arguments": {}},
        }

        with patch(
            "chatgpt_dev_mcp.transport_http.dispatch_rpc",
            side_effect=ConnectionError("upstream closed"),
        ):
            with self.assertRaises(HTTPTransportError) as raised:
                handler._dispatch_with_recovery(self._record(), request)

        self.assertEqual(502, raised.exception.status)
        self.assertEqual("upstream_transport_unavailable", raised.exception.reason)


if __name__ == "__main__":
    unittest.main()
