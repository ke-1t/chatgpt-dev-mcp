from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def run_step(label: str, arguments: list[str]) -> None:
    """Run one verification step with the current virtualenv interpreter."""

    command = [sys.executable, *arguments]
    display = " ".join(command)
    print(f"\n[verify] {label}: {display}", flush=True)
    started = time.monotonic()
    completed = subprocess.run(command, cwd=REPOSITORY_ROOT)
    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        raise SystemExit(f"[verify] FAIL ({elapsed:.1f}s): {label} (exit {completed.returncode})")
    print(f"[verify] PASS ({elapsed:.1f}s): {label}", flush=True)
