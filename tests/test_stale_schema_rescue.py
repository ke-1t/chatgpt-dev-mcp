from __future__ import annotations

import unittest

from chatgpt_dev_mcp.stale_schema_rescue import (
    StaleSchemaRescueError,
    parse_trust_enable_rescue_identifier,
)


class StaleSchemaRescueIdentifierTests(unittest.TestCase):
    def test_non_compat_session_identifier_is_not_intercepted(self) -> None:
        self.assertIsNone(parse_trust_enable_rescue_identifier("session:abc123"))

    def test_exact_trust_enable_identifier_returns_workspace(self) -> None:
        self.assertEqual(
            parse_trust_enable_rescue_identifier(
                "compat:workspace.trust.enable:chatgpt-dev-mcp"
            ),
            "chatgpt-dev-mcp",
        )

    def test_unknown_compat_operation_is_denied(self) -> None:
        with self.assertRaises(StaleSchemaRescueError) as raised:
            parse_trust_enable_rescue_identifier(
                "compat:capability.execute:chatgpt-dev-mcp"
            )
        self.assertEqual(raised.exception.code, "COMPAT_RESCUE_OPERATION_DENIED")

    def test_malformed_or_encoded_identifier_is_denied(self) -> None:
        invalid = (
            "compat:workspace.trust.enable:",
            "compat:workspace.trust.enable:chatgpt-dev-mcp:extra",
            "compat:workspace.trust.enable:chatgpt%2Ddev%2Dmcp",
            "compat:workspace.trust.enable:chatgpt-dev-mcp?x=1",
            "compat:workspace.trust.enable:.hidden",
            "compat:workspace.trust.enable:bad/name",
        )
        for identifier in invalid:
            with self.subTest(identifier=identifier):
                with self.assertRaises(StaleSchemaRescueError) as raised:
                    parse_trust_enable_rescue_identifier(identifier)
                self.assertEqual(
                    raised.exception.code,
                    "COMPAT_RESCUE_IDENTIFIER_INVALID",
                )


if __name__ == "__main__":
    unittest.main()
