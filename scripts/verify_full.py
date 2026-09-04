from __future__ import annotations

from verify_common import run_step


def main() -> int:
    run_step("full unittest discovery", ["-m", "unittest", "discover", "-s", "tests"])
    for script, label in (
        ("scripts/audit_public_surface.py", "public surface audit"),
        ("scripts/smoke_discovery.py", "discovery smoke"),
        ("scripts/smoke_disposable.py", "disposable policy smoke"),
        ("scripts/smoke_development_session.py", "development-session smoke"),
        ("scripts/smoke_schema_health.py", "schema health smoke"),
        ("scripts/smoke_http_session.py", "HTTP session smoke"),
    ):
        run_step(label, [script])
    print("\nverify_full: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
