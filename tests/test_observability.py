from __future__ import annotations

import unittest
from urllib.parse import urlsplit


class _FakeResponse:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self._body = body.encode("utf-8")

    def read(self, _limit: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _FakeOpener:
    def __init__(self, responses: dict[str, _FakeResponse | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, float]] = []

    def __call__(self, request: object, *, timeout: float) -> _FakeResponse:
        url = str(getattr(request, "full_url"))
        self.calls.append((url, timeout))
        response = self.responses[urlsplit(url).path]
        if isinstance(response, Exception):
            raise response
        return response


class SchemaObservabilityTests(unittest.TestCase):
    def test_tool_schema_metadata_allows_explicit_revision_without_changing_default(self) -> None:
        from chatgpt_dev_mcp.observability import TOOL_SCHEMA_REVISION, schema_consistency, tool_schema_metadata

        definitions = [{"name": "example", "inputSchema": {"type": "object"}}]
        self.assertEqual(tool_schema_metadata(definitions)["revision"], TOOL_SCHEMA_REVISION)
        metadata = tool_schema_metadata(definitions, revision="tool-registry-v25-stable")
        self.assertEqual(metadata["revision"], "tool-registry-v25-stable")
        consistency = schema_consistency(definitions, definitions, revision="tool-registry-v25-stable")
        self.assertEqual(consistency["status"], "consistent")
        self.assertEqual(consistency["local_tool_schema"]["revision"], "tool-registry-v25-stable")

    def test_schema_consistency_matches_reordered_visible_definitions(self) -> None:
        from chatgpt_dev_mcp.observability import schema_consistency

        definitions = [
            {"name": "workspace_list", "inputSchema": {"type": "object"}},
            {"name": "server_info", "inputSchema": {"type": "object"}},
        ]
        result = schema_consistency(definitions, list(reversed(definitions)))

        self.assertEqual(result["status"], "consistent")
        self.assertTrue(result["checks"]["count_match"])
        self.assertTrue(result["checks"]["hash_match"])
        self.assertTrue(result["checks"]["revision_match"])
        self.assertEqual(result["local_tool_schema"], result["listed_tool_schema"])

    def test_schema_consistency_detects_stale_definition_snapshot(self) -> None:
        from chatgpt_dev_mcp.observability import schema_consistency

        current = [{"name": "workspace_list", "inputSchema": {"type": "object"}}]
        stale = []
        result = schema_consistency(current, stale)

        self.assertEqual(result["status"], "inconsistent")
        self.assertFalse(result["checks"]["count_match"])
        self.assertFalse(result["checks"]["hash_match"])

    def test_client_observation_distinguishes_unavailable_match_and_mismatch(self) -> None:
        from chatgpt_dev_mcp.observability import compare_client_observation, tool_schema_metadata

        local = tool_schema_metadata([{"name": "workspace_list", "inputSchema": {"type": "object"}}])
        self.assertEqual(compare_client_observation(local, None), "not_available")
        self.assertEqual(compare_client_observation(local, dict(local)), "matched")
        stale = dict(local)
        stale["count"] = 23
        self.assertEqual(compare_client_observation(local, stale), "mismatched")


class RegistryHealthTests(unittest.TestCase):
    def test_registry_health_omits_paths_and_classifies_errors(self) -> None:
        from chatgpt_dev_mcp.observability import registry_health

        valid = registry_health(
            config_present=True,
            root_descriptors=[{"id": "developer", "mode": "PROJECT_DISCOVERY", "path": "/private/user/Developer"}],
            workspace_descriptors=[{"id": "project", "profile": "READ_ONLY", "path": "/private/user/project", "commands": ["test"]}],
            error_codes=[],
        )
        degraded = registry_health(
            config_present=True,
            root_descriptors=[],
            workspace_descriptors=[],
            error_codes=["ROOT_NOT_FOUND"],
        )
        invalid = registry_health(
            config_present=True,
            root_descriptors=[],
            workspace_descriptors=[],
            error_codes=["CONFIG_INVALID"],
        )

        self.assertEqual(valid["status"], "valid")
        self.assertEqual(valid["root_count"], 1)
        self.assertEqual(valid["workspace_count"], 1)
        self.assertNotIn("/private/user", str(valid))
        self.assertEqual(degraded["status"], "degraded")
        self.assertEqual(invalid["status"], "invalid")

    def test_missing_registry_uses_valid_default_state(self) -> None:
        from chatgpt_dev_mcp.observability import registry_health

        result = registry_health(
            config_present=False,
            root_descriptors=[{"id": "developer", "mode": "PROJECT_DISCOVERY"}],
            workspace_descriptors=[],
            error_codes=[],
        )

        self.assertEqual(result["status"], "valid")
        self.assertFalse(result["config_present"])
        self.assertEqual(result["config_error_codes"], [])


class TunnelHealthTests(unittest.TestCase):
    def test_loopback_probe_requires_live_and_ready(self) -> None:
        from chatgpt_dev_mcp.observability import probe_loopback_tunnel

        opener = _FakeOpener({"/healthz": _FakeResponse(200, "live\n"), "/readyz": _FakeResponse(200, "ready\n")})
        result = probe_loopback_tunnel("http://127.0.0.1:8080", opener=opener)

        self.assertEqual(result["status"], "healthy")
        self.assertEqual([urlsplit(url).path for url, _ in opener.calls], ["/healthz", "/readyz"])
        self.assertTrue(all(timeout <= 0.25 for _, timeout in opener.calls))

    def test_loopback_probe_rejects_external_url_without_request(self) -> None:
        from chatgpt_dev_mcp.observability import probe_loopback_tunnel

        opener = _FakeOpener({"/healthz": _FakeResponse(200, "live"), "/readyz": _FakeResponse(200, "ready")})
        result = probe_loopback_tunnel("https://example.com/healthz", opener=opener)

        self.assertEqual(result["status"], "misconfigured")
        self.assertEqual(opener.calls, [])

    def test_loopback_probe_reports_unavailable_without_leaking_body(self) -> None:
        from chatgpt_dev_mcp.observability import probe_loopback_tunnel

        opener = _FakeOpener({"/healthz": ConnectionRefusedError("fixture-secret"), "/readyz": TimeoutError("fixture-secret")})
        result = probe_loopback_tunnel("http://127.0.0.1:8080", opener=opener)

        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("fixture-secret", str(result))


if __name__ == "__main__":
    unittest.main()
