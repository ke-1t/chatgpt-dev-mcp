from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class _FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = headers or {}

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class LoopbackHttpProbeTests(unittest.TestCase):
    def test_probe_rejects_non_loopback_and_unsafe_urls_before_opening(self) -> None:
        from chatgpt_dev_mcp.loopback_http import LoopbackHttpProbe, LoopbackHttpProbeError

        calls: list[object] = []
        probe = LoopbackHttpProbe(opener=lambda *args, **kwargs: calls.append((args, kwargs)))

        invalid = (
            "https://127.0.0.1:8766/healthz",
            "http://example.com:8766/healthz",
            "http://127.0.0.1/healthz",
            "http://user:pass@127.0.0.1:8766/healthz",
            "http://127.0.0.1:8766/healthz#fragment",
        )
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(LoopbackHttpProbeError) as caught:
                probe.probe({"url": url})
            self.assertEqual(caught.exception.code, "LOOPBACK_HTTP_URL_INVALID")
        self.assertEqual(calls, [])

    def test_probe_rewrites_localhost_sends_no_credentials_and_returns_bounded_metadata(self) -> None:
        from chatgpt_dev_mcp.loopback_http import LoopbackHttpProbe

        seen: list[tuple[object, float]] = []

        def opener(request, *, timeout):
            seen.append((request, timeout))
            return _FakeResponse(
                200,
                b'{"ok":true,"bridge":{"readOnly":true},"executionAuthority":false}',
                {
                    "Content-Type": "application/json; charset=utf-8",
                    "Cache-Control": "no-store",
                    "Set-Cookie": "must-not-leak=1",
                },
            )

        probe = LoopbackHttpProbe(opener=opener)
        result = probe.probe(
            {
                "url": "http://localhost:8766/api/portfolio?refresh=true",
                "method": "GET",
                "timeout_ms": 1500,
                "max_bytes": 4096,
                "include_body": True,
                "json_assertions": [
                    {"pointer": "/bridge/readOnly", "equals": True},
                    {"pointer": "/executionAuthority", "equals": False},
                ],
            }
        )

        self.assertEqual(len(seen), 1)
        request, timeout = seen[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8766/api/portfolio?refresh=true")
        self.assertEqual(request.get_method(), "GET")
        request_headers = {key.lower(): value for key, value in request.header_items()}
        self.assertNotIn("authorization", request_headers)
        self.assertNotIn("cookie", request_headers)
        self.assertEqual(timeout, 1.5)

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["host"], "127.0.0.1")
        self.assertEqual(result["port"], 8766)
        self.assertEqual(result["headers"], {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"})
        self.assertNotIn("set-cookie", result["headers"])
        self.assertTrue(result["json_valid"])
        self.assertEqual([item["passed"] for item in result["assertions"]], [True, True])
        self.assertIn('"readOnly":true', result["body_text"])
        self.assertRegex(result["body_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(result["truncated"])

    def test_probe_never_follows_redirects_and_bounds_body(self) -> None:
        from chatgpt_dev_mcp.loopback_http import LoopbackHttpProbe

        calls = 0

        def opener(request, *, timeout):
            nonlocal calls
            calls += 1
            del request, timeout
            return _FakeResponse(302, b"0123456789", {"Location": "https://example.com/secret"})

        result = LoopbackHttpProbe(opener=opener).probe(
            {"url": "http://127.0.0.1:8766/redirect", "max_bytes": 4, "include_body": True}
        )
        self.assertEqual(calls, 1)
        self.assertEqual(result["status"], 302)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["body_text"], "0123")
        self.assertNotIn("location", result["headers"])

    def test_binding_is_r0_workspace_bound_without_general_network_permission(self) -> None:
        from chatgpt_dev_mcp.capability_gateway_mcp import CapabilityExecutionContext
        from chatgpt_dev_mcp.loopback_http import build_loopback_http_probe_binding

        calls: list[dict[str, object]] = []

        def execute(params):
            calls.append(dict(params))
            return {"status": 200, "ok": True}

        spec, handler = build_loopback_http_probe_binding(execute)
        self.assertEqual(spec.capability_id, "loopback.http_probe")
        self.assertEqual(spec.risk_class, "R0")
        self.assertEqual(spec.approval_policy, "none")
        self.assertEqual(spec.workspace_binding, "required")
        self.assertFalse(spec.network_required)
        self.assertEqual(spec.credential_requirements, ())
        self.assertEqual(spec.input_schema["properties"]["method"]["enum"], ["GET", "HEAD"])

        context = CapabilityExecutionContext(
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            session_id="",
            owner_id="owner",
            task_id="task",
            policy_revision="policy-v1",
            policy_digest="a" * 64,
            workspace_trust_level="standard",
        )
        params = {"url": "http://127.0.0.1:8766/healthz"}
        preview, state = handler.preflight(params, context)
        self.assertEqual(preview["host"], "127.0.0.1")
        self.assertEqual(preview["port"], 8766)
        self.assertNotIn("url", preview)
        self.assertEqual(handler.execute(params, context, state)["status"], 200)
        self.assertEqual(calls, [params])

    def test_server_catalog_registers_loopback_probe_without_expanding_direct_surface(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {
                "HOME": str(root / "home"),
                "LOCAL_DEV_MCP_CONFIG": str(root / "config.json"),
                "LOCAL_DEV_MCP_DATA_DIR": str(root / "data"),
                "LOCAL_DEV_MCP_TUNNEL_HEALTH_URL": "disabled",
                "CHATGPT_DEV_MCP_SURFACE": "stable_gateway",
            }
            with patch.dict(os.environ, env):
                runtime = WrapperRuntime()
                try:
                    self.assertEqual(len(runtime.list_tools()["tools"]), 52)
                    catalog_result = runtime.call_tool("capability_catalog", {"query": "loopback", "limit": 100})
                    self.assertFalse(catalog_result["isError"], catalog_result)
                    capabilities = {
                        item["capability_id"]: item
                        for item in catalog_result["structuredContent"]["capabilities"]
                    }
                    self.assertIn("loopback.http_probe", capabilities)
                    self.assertEqual(capabilities["loopback.http_probe"]["risk_class"], "R0")
                    self.assertFalse(capabilities["loopback.http_probe"]["network_required"])
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
