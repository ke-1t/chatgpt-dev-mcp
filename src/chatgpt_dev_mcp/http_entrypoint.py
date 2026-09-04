"""Command-line entrypoint for the disposable loopback Streamable HTTP prototype."""

from __future__ import annotations

import argparse

from .server import WrapperRuntime
from .production_runtime import build_production_runtime
from .transport_http import (
    DEFAULT_HTTP_SESSION_TTL_SECONDS,
    DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_HTTP_INFLIGHT,
    DEFAULT_MAX_HTTP_SESSIONS,
    DEFAULT_MAX_RETIRED_SESSION_IDS,
    DEFAULT_MAX_SESSION_CREATIONS,
    DEFAULT_SESSION_CREATION_WINDOW_SECONDS,
    serve_http,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the disposable chatgpt-dev-mcp Streamable HTTP transport.")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="TCP port (0 selects an ephemeral port when embedded)")
    parser.add_argument("--max-sessions", type=int, default=DEFAULT_MAX_HTTP_SESSIONS)
    parser.add_argument("--session-ttl", type=float, default=DEFAULT_HTTP_SESSION_TTL_SECONDS)
    parser.add_argument("--max-retired-session-ids", type=int, default=DEFAULT_MAX_RETIRED_SESSION_IDS)
    parser.add_argument("--max-session-creations", type=int, default=DEFAULT_MAX_SESSION_CREATIONS)
    parser.add_argument("--session-creation-window", type=float, default=DEFAULT_SESSION_CREATION_WINDOW_SECONDS)
    parser.add_argument("--request-timeout", type=float, default=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS)
    parser.add_argument("--max-inflight", type=int, default=DEFAULT_MAX_HTTP_INFLIGHT)
    return parser


def _runtime_factory() -> WrapperRuntime:
    return build_production_runtime(preserve_persistent_state=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return serve_http(
        _runtime_factory,
        host=args.host,
        port=args.port,
        max_sessions=args.max_sessions,
        session_ttl_seconds=args.session_ttl,
        max_retired_session_ids=args.max_retired_session_ids,
        max_session_creations=args.max_session_creations,
        session_creation_window_seconds=args.session_creation_window,
        request_timeout_seconds=args.request_timeout,
        max_inflight=args.max_inflight,
    )


if __name__ == "__main__":
    raise SystemExit(main())
