#!/usr/bin/env python3
"""Create a one-click macOS Desktop shortcut for restarting DevMCP Tunnel."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat


LABEL = "com.openai.chatgpt-dev-mcp-tunnel"
SHORTCUT_NAME = "Restart ChatGPT Dev MCP.command"


def render_shortcut() -> str:
    return f"""#!/bin/zsh
set -u

label={LABEL!r}
target="gui/$(/usr/bin/id -u)/$label"

echo "Restarting ChatGPT Dev MCP Tunnel..."
if /bin/launchctl kickstart -k "$target"; then
  for _ in {{1..60}}; do
    if /usr/bin/curl --fail --silent --show-error --max-time 1 http://127.0.0.1:8080/healthz | /usr/bin/grep -qx live \
      && /usr/bin/curl --fail --silent --show-error --max-time 1 http://127.0.0.1:8080/readyz | /usr/bin/grep -qx ready; then
      echo "Tunnel is ready."
      exit 0
    fi
    /bin/sleep 0.5
  done
  echo "Restart was requested but Tunnel readiness was not confirmed."
  exit 75
fi

status=$?
echo "Restart failed with exit code $status."
echo "Target: $target"
sleep 5
exit "$status"
"""


def create_shortcut(desktop_dir: Path) -> Path:
    desktop = desktop_dir.expanduser().resolve()
    desktop.mkdir(parents=True, exist_ok=True)
    target = desktop / SHORTCUT_NAME
    target.write_text(render_shortcut(), encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--desktop-dir",
        type=Path,
        default=Path.home() / "Desktop",
        help="Desktop directory to receive the .command shortcut.",
    )
    args = parser.parse_args()
    path = create_shortcut(args.desktop_dir)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
