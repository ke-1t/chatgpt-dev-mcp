from __future__ import annotations

import unittest


def _healthy_local() -> dict[str, object]:
    return {
        "checked_at": "2026-08-20T05:16:43Z",
        "runtime": {
            "status": "alive",
            "restart_required": False,
            "child_instance_id": "child-a",
            "transport_generation": 1,
        },
        "tunnel": {"status": "healthy"},
        "director_persistence": {"status": "healthy"},
        "registry": {"status": "valid"},
        "schema_consistency": {
            "status": "consistent",
            "local_tool_schema": {
                "revision": "tool-registry-v25-stable",
                "count": 52,
                "hash": "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
            },
        },
    }


def _observation() -> dict[str, object]:
    return {
        "server_instance_id": "http-a",
        "child_instance_id": "child-a",
        "transport_generation": "http-v26-canary",
        "last_initialize_at": "2026-08-20T05:09:44Z",
        "last_list_tools_at": "2026-08-20T05:09:45Z",
        "last_tool_call_at": "2026-08-20T05:09:45Z",
        "last_disconnect_at": None,
        "disconnect_reason": None,
        "registry_revision": "tool-registry-v25-stable",
        "schema_hash": "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
        "tool_count": 52,
    }


class ConnectionDoctorTests(unittest.TestCase):
    def test_healthy_local_with_detached_client_classifies_chatgpt_attachment(self) -> None:
        from chatgpt_dev_mcp.connection_doctor import ConnectionFailureClass, diagnose_connection

        result = diagnose_connection(
            _healthy_local(),
            _observation(),
            client_schema={
                "available": False,
                "revision": "tool-registry-v25-stable",
                "count": 52,
                "hash": "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
            },
        )

        self.assertEqual(result["failure_class"], ConnectionFailureClass.CHATGPT_DYNAMIC_TOOL_ATTACHMENT.value)
        self.assertIn("refresh_or_rescan_chatgpt_tools", result["recommended_actions"])
        self.assertNotIn("restart_mcp_child", result["recommended_actions"])

    def test_backend_transport_failure_precedes_client_attachment_inference(self) -> None:
        from chatgpt_dev_mcp.connection_doctor import ConnectionFailureClass, diagnose_connection

        observation = _observation()
        observation["last_disconnect_at"] = "2026-08-20T05:12:10Z"
        observation["disconnect_reason"] = "transport_failure"

        result = diagnose_connection(
            _healthy_local(),
            observation,
            client_schema={"available": False},
        )

        self.assertEqual(result["failure_class"], ConnectionFailureClass.TRANSPORT_SESSION_FAILURE.value)

    def test_classifier_covers_bounded_failure_classes(self) -> None:
        from chatgpt_dev_mcp.connection_doctor import ConnectionFailureClass, diagnose_connection

        healthy = _healthy_local()
        observation = _observation()
        current_client = {
            "available": True,
            "revision": "tool-registry-v25-stable",
            "count": 52,
            "hash": "6aea21f8d49e043decf962304f5f609d07f6de54ac8f2c4b324538fc27c3111c",
        }
        self.assertEqual(
            diagnose_connection(healthy, observation, current_client)["failure_class"],
            ConnectionFailureClass.HEALTHY.value,
        )

        stale = dict(current_client)
        stale["hash"] = "b" * 64
        self.assertEqual(
            diagnose_connection(healthy, observation, stale)["failure_class"],
            ConnectionFailureClass.CLIENT_TOOL_SCHEMA_STALE.value,
        )

        restarted = _healthy_local()
        restarted_runtime = dict(restarted["runtime"])
        restarted_runtime["child_instance_id"] = "child-b"
        restarted["runtime"] = restarted_runtime
        self.assertEqual(
            diagnose_connection(restarted, observation)["failure_class"],
            ConnectionFailureClass.MCP_CHILD_RESTART.value,
        )

        tunnel_down = _healthy_local()
        tunnel_down["tunnel"] = {"status": "unavailable"}
        self.assertEqual(
            diagnose_connection(tunnel_down, observation, {"available": False})["failure_class"],
            ConnectionFailureClass.TUNNEL_UNAVAILABLE.value,
        )

        director_down = _healthy_local()
        director_down["director_persistence"] = {"status": "unhealthy"}
        self.assertEqual(
            diagnose_connection(director_down, observation, {"available": False})["failure_class"],
            ConnectionFailureClass.DIRECTOR_UNHEALTHY.value,
        )

        schema_bad = _healthy_local()
        schema_bad["schema_consistency"] = {
            "status": "mismatch",
            "local_tool_schema": healthy["schema_consistency"]["local_tool_schema"],
        }
        self.assertEqual(
            diagnose_connection(schema_bad, observation, {"available": False})["failure_class"],
            ConnectionFailureClass.REGISTRY_SCHEMA_MISMATCH.value,
        )

    def test_missing_transport_health_is_not_treated_as_transport_failure(self) -> None:
        from chatgpt_dev_mcp.connection_doctor import ConnectionFailureClass, diagnose_connection

        result = diagnose_connection(_healthy_local(), _observation())
        self.assertEqual(result["failure_class"], ConnectionFailureClass.HEALTHY.value)

    def test_result_is_metadata_only(self) -> None:
        from chatgpt_dev_mcp.connection_doctor import diagnose_connection

        observation = _observation()
        observation["tool_arguments"] = {"token": "must-not-leak"}
        observation["file_content"] = "must-not-leak"

        result = diagnose_connection(_healthy_local(), observation)
        rendered = repr(result)
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn("tool_arguments", rendered)
        self.assertNotIn("file_content", rendered)
        self.assertEqual(result["registry_schema"]["count"], 52)


if __name__ == "__main__":
    unittest.main()
