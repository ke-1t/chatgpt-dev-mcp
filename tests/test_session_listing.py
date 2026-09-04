from __future__ import annotations

import unittest


def _session(index: int, *, status: str = "stale_dirty_retained", active: bool = False, workspace_id: str = "demo") -> dict[str, object]:
    return {
        "session_id": f"session:{index:03d}",
        "workspace_id": workspace_id,
        "status": status,
        "active": active,
        "created_at": float(index),
    }


class SessionListingTests(unittest.TestCase):
    def test_metadata_pagination_does_not_require_lifecycle_fields(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListQuery, paginate_session_metadata

        inventory = tuple(
            {
                "session_id": f"session:metadata-{index:03d}",
                "logical_workspace_id": "demo" if index % 2 == 0 else "other",
                "created_at": float(index),
            }
            for index in range(30)
        )
        page = paginate_session_metadata(
            inventory,
            SessionListQuery(workspace_id="demo", limit=5),
        )
        self.assertEqual(page["returned"], 5)
        self.assertEqual(page["counts"]["inventory_total"], 30)
        self.assertEqual(page["counts"]["filtered_total"], 15)
        self.assertEqual(
            [item["session_id"] for item in page["sessions"]],
            ["session:metadata-028", "session:metadata-026", "session:metadata-024", "session:metadata-022", "session:metadata-020"],
        )
        self.assertTrue(page["next_cursor"])

    def test_metadata_pagination_rejects_lifecycle_filters(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListError, SessionListQuery, paginate_session_metadata

        with self.assertRaises(SessionListError):
            paginate_session_metadata((), SessionListQuery(active_only=True))
        with self.assertRaises(SessionListError):
            paginate_session_metadata((), SessionListQuery(statuses=("active",)))

    def test_default_page_is_twenty_and_has_cursor(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListQuery, paginate_session_payloads

        page = paginate_session_payloads(tuple(_session(index) for index in range(45)), SessionListQuery())
        self.assertEqual(page["returned"], 20)
        self.assertEqual(len(page["sessions"]), 20)
        self.assertEqual(page["sessions"][0]["session_id"], "session:044")
        self.assertTrue(page["next_cursor"])
        self.assertEqual(page["counts"]["filtered_total"], 45)

    def test_cursor_pages_are_deterministic_and_non_overlapping(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListQuery, paginate_session_payloads

        inventory = tuple(_session(index) for index in range(25))
        first = paginate_session_payloads(inventory, SessionListQuery(limit=10))
        second = paginate_session_payloads(inventory, SessionListQuery(limit=10, cursor=first["next_cursor"]))
        first_ids = {item["session_id"] for item in first["sessions"]}
        second_ids = {item["session_id"] for item in second["sessions"]}
        self.assertEqual(len(first_ids), 10)
        self.assertEqual(len(second_ids), 10)
        self.assertFalse(first_ids & second_ids)

    def test_filters_compose_and_cursor_is_query_bound(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListError, SessionListQuery, paginate_session_payloads

        inventory = (
            _session(1, status="active", active=True),
            _session(2),
            _session(3, status="active", active=True, workspace_id="other"),
        )
        query = SessionListQuery(active_only=True, statuses=("active",), workspace_id="demo", limit=1)
        first = paginate_session_payloads(inventory, query)
        self.assertEqual([item["session_id"] for item in first["sessions"]], ["session:001"])
        self.assertIsNone(first["next_cursor"])

        page = paginate_session_payloads(tuple(_session(index) for index in range(3)), SessionListQuery(limit=1))
        with self.assertRaises(SessionListError):
            paginate_session_payloads(
                tuple(_session(index) for index in range(3)),
                SessionListQuery(limit=2, cursor=page["next_cursor"]),
            )

    def test_rejects_invalid_limits_statuses_and_malformed_cursor(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListError, SessionListQuery, paginate_session_payloads

        for limit in (0, 101):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    SessionListQuery(limit=limit)
        with self.assertRaises(ValueError):
            SessionListQuery(statuses=("../../bad",))
        with self.assertRaises(SessionListError):
            paginate_session_payloads((), SessionListQuery(cursor="not-a-valid-cursor"))

    def test_workspace_filter_uses_logical_workspace_from_real_session_payload(self) -> None:
        from chatgpt_dev_mcp.session_listing import SessionListQuery, paginate_session_payloads

        payload = {
            "session_id": "session:real-1",
            "workspace_id": "session:real-1",
            "logical_workspace_id": "chatgpt-dev-mcp",
            "status": "active",
            "active": True,
            "created_at": 100.0,
        }

        page = paginate_session_payloads(
            (payload,),
            SessionListQuery(workspace_id="chatgpt-dev-mcp"),
        )

        self.assertEqual(page["returned"], 1)
        self.assertEqual(page["sessions"][0]["session_id"], "session:real-1")


if __name__ == "__main__":
    unittest.main()
