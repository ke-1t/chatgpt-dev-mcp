from __future__ import annotations

import unittest


class V25SmokeScriptTests(unittest.TestCase):
    def test_schema_health_smoke(self) -> None:
        from scripts.smoke_schema_health import main

        main()

    def test_http_session_smoke(self) -> None:
        from scripts.smoke_http_session import main

        main()

    def test_public_surface_audit(self) -> None:
        from scripts.audit_public_surface import main

        main()


if __name__ == "__main__":
    unittest.main()
