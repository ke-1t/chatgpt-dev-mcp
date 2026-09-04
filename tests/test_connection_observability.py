from __future__ import annotations

import unittest


class ConnectionObservabilityTests(unittest.TestCase):
    def test_records_redacted_identity_and_bounded_lifecycle_metadata(self) -> None:
        from chatgpt_dev_mcp.connection_observability import ConnectionObservabilityStore

        now = [1_700_000_000.0]
        store = ConnectionObservabilityStore(
            server_instance_id="srv-test",
            max_records=2,
            clock=lambda: now[0],
        )

        created = store.create_session(
            "mcp_raw-secret-session-id",
            transport_generation="http-v26",
            registry_revision="tool-registry-v26-canary",
            schema_hash="a" * 64,
            tool_count=61,
        )
        self.assertEqual(created["connection_epoch"], 1)
        self.assertEqual(created["server_instance_id"], "srv-test")
        self.assertEqual(created["transport_generation"], "http-v26")
        self.assertRegex(created["hashed_client_session_id"], r"^[0-9a-f]{64}$")
        self.assertNotIn("mcp_raw-secret-session-id", repr(created))
        self.assertNotIn("session_id", created)
        self.assertEqual(created["registry_revision"], "tool-registry-v26-canary")
        self.assertEqual(created["schema_hash"], "a" * 64)
        self.assertEqual(created["tool_count"], 61)

        now[0] += 1
        store.record_initialize("mcp_raw-secret-session-id")
        now[0] += 1
        store.record_tools_list(
            "mcp_raw-secret-session-id",
            registry_revision="tool-registry-v26-canary.2",
            schema_hash="b" * 64,
            tool_count=62,
        )
        now[0] += 1
        store.record_tool_call("mcp_raw-secret-session-id")
        now[0] += 1
        store.record_disconnect("mcp_raw-secret-session-id", reason="deleted_session")

        snapshot = store.snapshot("mcp_raw-secret-session-id")
        assert snapshot is not None
        self.assertIsNotNone(snapshot["last_initialize_at"])
        self.assertIsNotNone(snapshot["last_list_tools_at"])
        self.assertIsNotNone(snapshot["schema_advertised_at"])
        self.assertIsNotNone(snapshot["last_tool_call_at"])
        self.assertIsNotNone(snapshot["last_disconnect_at"])
        self.assertEqual(snapshot["disconnect_reason"], "deleted_session")
        self.assertEqual(snapshot["registry_revision"], "tool-registry-v26-canary.2")
        self.assertEqual(snapshot["schema_hash"], "b" * 64)
        self.assertEqual(snapshot["tool_count"], 62)
        self.assertNotIn("mcp_raw-secret-session-id", repr(store.snapshot()))

        store.create_session("mcp_second", transport_generation="http-v26")
        third = store.create_session("mcp_third", transport_generation="http-v26")
        self.assertEqual(third["connection_epoch"], 3)
        all_records = store.snapshot()
        self.assertEqual(len(all_records), 2)
        self.assertIsNone(store.snapshot("mcp_raw-secret-session-id"))


if __name__ == "__main__":
    unittest.main()
