"""Bounded subprocess execution for local policy-controlled integrations."""

from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_ms: int

    @property
    def output_truncated(self) -> bool:
        return self.stdout_truncated or self.stderr_truncated


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        process.wait()


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    timeout_seconds: float,
    max_output_bytes: int,
    merge_stderr: bool = False,
) -> BoundedProcessResult:
    """Run fixed argv while bounding captured bytes and process lifetime.

    Both pipes are drained incrementally so a child cannot exhaust the parent
    memory by emitting output faster than the caller can consume it.  When a
    timeout fires the whole process group is terminated, including descendants
    that could otherwise keep a pipe open indefinitely.
    """

    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise ValueError("argv must be a non-empty sequence of NUL-free strings")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")

    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        cwd=None if cwd is None else str(cwd),
        env=None if env is None else dict(env),
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
        shell=False,
        start_new_session=os.name == "posix",
    )
    streams: dict[int, str] = {}
    if process.stdout is not None:
        streams[process.stdout.fileno()] = "stdout"
    if not merge_stderr and process.stderr is not None:
        streams[process.stderr.fileno()] = "stderr"
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    truncated = {"stdout": False, "stderr": False}
    timed_out = False
    selector = selectors.DefaultSelector()
    feeder: threading.Thread | None = None
    try:
        if input_text is not None and process.stdin is not None:
            data = input_text.encode("utf-8")

            def feed_stdin() -> None:
                try:
                    process.stdin.write(data)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    try:
                        process.stdin.close()
                    except OSError:
                        pass

            feeder = threading.Thread(target=feed_stdin, name="bounded-process-input", daemon=True)
            feeder.start()
        for stream in tuple((process.stdout, process.stderr if not merge_stderr else None)):
            if stream is not None:
                selector.register(stream, selectors.EVENT_READ, streams[stream.fileno()])
        while selector.get_map():
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                break
            ready = selector.select(remaining)
            if not ready:
                timed_out = True
                break
            for key, _ in ready:
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    try:
                        key.fileobj.close()
                    except OSError:
                        pass
                    continue
                name = str(key.data)
                totals[name] += len(chunk)
                if len(buffers[name]) < max_output_bytes:
                    buffers[name].extend(chunk[: max_output_bytes - len(buffers[name])])
                if totals[name] > max_output_bytes:
                    truncated[name] = True
        if timed_out:
            _terminate_process_group(process)
        else:
            process.wait(timeout=max(0.1, timeout_seconds - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if feeder is not None:
            feeder.join(timeout=0.25)

    return BoundedProcessResult(
        returncode=None if timed_out else process.returncode,
        stdout=bytes(buffers["stdout"]).decode("utf-8", "replace"),
        stderr=bytes(buffers["stderr"]).decode("utf-8", "replace"),
        timed_out=timed_out,
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


__all__ = ["BoundedProcessResult", "run_bounded"]
