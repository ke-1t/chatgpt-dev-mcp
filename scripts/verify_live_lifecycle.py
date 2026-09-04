from __future__ import annotations

import os
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from verify_common import REPOSITORY_ROOT, run_step


def check_managed_tunnel() -> None:
    base_url = os.environ.get("LOCAL_DEV_MCP_TUNNEL_HEALTH_URL", "http://127.0.0.1:8080").rstrip("/")
    if base_url.lower() == "disabled":
        raise SystemExit("[verify] FAIL: LOCAL_DEV_MCP_TUNNEL_HEALTH_URL=disabled; live Tunnel check is required")

    for endpoint, expected in (("/healthz", "live"), ("/readyz", "ready")):
        url = f"{base_url}{endpoint}"
        try:
            with urlopen(url, timeout=5) as response:
                body = response.read().decode("utf-8").strip()
                status = response.status
        except (HTTPError, URLError, TimeoutError) as exc:
            raise SystemExit(f"[verify] FAIL: managed Tunnel {url}: {exc}") from exc
        if status != 200 or body != expected:
            raise SystemExit(f"[verify] FAIL: managed Tunnel {url}: status={status} body={body!r}")
        print(f"[verify] PASS: managed Tunnel {endpoint}={body}", flush=True)


def main() -> int:
    executable = REPOSITORY_ROOT / ".venv" / "bin" / "chatgpt-dev-mcp"
    if not executable.is_file():
        raise SystemExit(f"[verify] FAIL: live executable is missing: {executable}")
    os.environ["DEVMCP_RUN_LIVE_TESTS"] = "1"
    run_step("raw executable lifecycle and multi-client E2E", ["-m", "unittest", "tests.test_live_schema"])
    check_managed_tunnel()
    print("\nverify_live_lifecycle: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
