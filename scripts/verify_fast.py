from __future__ import annotations

from verify_common import run_step


def main() -> int:
    run_step("connector lifecycle tests", ["-m", "unittest", "tests.test_chatgpt_connector_compat"])
    run_step(
        "read-only server_info stability",
        [
            "-m",
            "unittest",
            "tests.test_policy.PolicyTests.test_server_info_schema_and_health_are_stable_across_reads",
        ],
    )
    run_step("public surface audit", ["scripts/audit_public_surface.py"])
    run_step("schema health smoke", ["scripts/smoke_schema_health.py"])
    print("\nverify_fast: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
