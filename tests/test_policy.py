from __future__ import annotations

import unittest


class PolicyTests(unittest.TestCase):
    def test_server_info_schema_and_health_are_stable_across_reads(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = WrapperRuntime()
        try:
            first = runtime.call_tool("server_info", {})["structuredContent"]
            second = runtime.call_tool("server_info", {})["structuredContent"]
            self.assertEqual(first["tool_schema"], second["tool_schema"])
            self.assertEqual(first["health"]["schema_consistency"], second["health"]["schema_consistency"])
            self.assertEqual(first["health"]["registry"]["config_digest"], second["health"]["registry"]["config_digest"])
            self.assertEqual(first["health"]["runtime"]["pid"], second["health"]["runtime"]["pid"])
            self.assertEqual(first["health"]["runtime"]["started_at"], second["health"]["runtime"]["started_at"])
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
