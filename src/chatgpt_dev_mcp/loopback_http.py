"""Bounded HTTP probes for local development services only."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .capability_gateway_mcp import CapabilityExecutionContext, CapabilityHandler, StableCapabilityGatewayError
from .capability_registry import CapabilitySpec


_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_SAFE_RESPONSE_HEADERS = frozenset({"content-type", "content-length", "cache-control", "etag", "last-modified"})
_MAX_RESPONSE_BYTES = 65_536
_MAX_ASSERTIONS = 16
_MISSING = object()


class LoopbackHttpProbeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler)


def _validated_target(raw_url: object) -> tuple[str, str, int, str]:
    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > 2048:
        raise LoopbackHttpProbeError("LOOPBACK_HTTP_URL_INVALID", "A bounded loopback URL is required.")
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LoopbackHttpProbeError("LOOPBACK_HTTP_URL_INVALID", "The loopback URL is invalid.") from exc
    if (
        parsed.scheme != "http"
        or hostname not in _ALLOWED_HOSTS
        or port is None
        or not 1 <= port <= 65_535
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.fragment)
    ):
        raise LoopbackHttpProbeError("LOOPBACK_HTTP_URL_INVALID", "Only explicit-port HTTP loopback URLs are allowed.")
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise LoopbackHttpProbeError("LOOPBACK_HTTP_URL_INVALID", "The loopback URL path is invalid.")
    canonical_host = "127.0.0.1" if hostname == "localhost" else hostname
    netloc = f"[{canonical_host}]:{port}" if canonical_host == "::1" else f"{canonical_host}:{port}"
    canonical = urlunsplit(SplitResult("http", netloc, path, parsed.query, ""))
    return canonical, canonical_host, port, path


def _json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 256:
        return _MISSING
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _type_name(value: Any) -> str:
    if value is _MISSING:
        return "missing"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return type(value).__name__


class LoopbackHttpProbe:
    """Perform one credential-free, redirect-free request to loopback only."""

    def __init__(self, *, opener: Callable[..., Any] | None = None) -> None:
        self._opener = opener or _NO_REDIRECT_OPENER.open

    def probe(self, params: Mapping[str, Any]) -> dict[str, Any]:
        canonical_url, host, port, path = _validated_target(params.get("url"))
        method = str(params.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_METHOD_INVALID", "Only GET and HEAD are allowed.")
        timeout_ms = params.get("timeout_ms", 2000)
        max_bytes = params.get("max_bytes", 16_384)
        include_body = params.get("include_body", False)
        assertions = params.get("json_assertions", [])
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 50 <= timeout_ms <= 10_000:
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_LIMIT_INVALID", "timeout_ms is outside safe bounds.")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= _MAX_RESPONSE_BYTES:
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_LIMIT_INVALID", "max_bytes is outside safe bounds.")
        if not isinstance(include_body, bool):
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_LIMIT_INVALID", "include_body must be boolean.")
        if not isinstance(assertions, list) or len(assertions) > _MAX_ASSERTIONS:
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_ASSERTION_INVALID", "json_assertions is outside safe bounds.")

        request = Request(
            canonical_url,
            headers={
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.1",
                "User-Agent": "chatgpt-dev-mcp-loopback-probe/1",
            },
            method=method,
        )
        try:
            response = self._opener(request, timeout=timeout_ms / 1000.0)
        except HTTPError as exc:
            response = exc
        except (URLError, OSError, TimeoutError, ValueError) as exc:
            raise LoopbackHttpProbeError("LOOPBACK_HTTP_REQUEST_FAILED", "The loopback HTTP request failed.") from exc

        try:
            raw_status = getattr(response, "status", None)
            status = int(raw_status if raw_status is not None else response.getcode())
            raw_headers = getattr(response, "headers", {})
            header_items = raw_headers.items() if hasattr(raw_headers, "items") else ()
            safe_headers = {
                str(key).lower(): str(value)[:2048]
                for key, value in header_items
                if str(key).lower() in _SAFE_RESPONSE_HEADERS
            }
            raw_body = b"" if method == "HEAD" else response.read(max_bytes + 1)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

        truncated = len(raw_body) > max_bytes
        body = raw_body[:max_bytes]
        body_text = body.decode("utf-8", "replace")
        parsed_json: Any = _MISSING
        if body and not truncated:
            try:
                parsed_json = json.loads(body_text)
            except (json.JSONDecodeError, UnicodeError):
                parsed_json = _MISSING

        assertion_results: list[dict[str, Any]] = []
        for assertion in assertions:
            if not isinstance(assertion, Mapping) or "pointer" not in assertion or "equals" not in assertion:
                raise LoopbackHttpProbeError("LOOPBACK_HTTP_ASSERTION_INVALID", "Each JSON assertion requires pointer and equals.")
            pointer = assertion["pointer"]
            if not isinstance(pointer, str) or len(pointer) > 256 or (pointer and not pointer.startswith("/")):
                raise LoopbackHttpProbeError("LOOPBACK_HTTP_ASSERTION_INVALID", "JSON assertion pointer is invalid.")
            actual = _json_pointer(parsed_json, pointer) if parsed_json is not _MISSING else _MISSING
            assertion_results.append(
                {
                    "pointer": pointer,
                    "passed": actual is not _MISSING and actual == assertion["equals"],
                    "actual_type": _type_name(actual),
                }
            )

        result: dict[str, Any] = {
            "status": status,
            "method": method,
            "host": host,
            "port": port,
            "path": path,
            "headers": safe_headers,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "truncated": truncated,
            "json_valid": parsed_json is not _MISSING,
            "assertions": assertion_results,
            "external_execution": False,
        }
        if include_body:
            result["body_text"] = body_text
        return result


def build_loopback_http_probe_binding(
    typed_execute: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> tuple[CapabilitySpec, CapabilityHandler]:
    if not callable(typed_execute):
        raise TypeError("typed_execute must be callable")
    capability_id = "loopback.http_probe"
    spec = CapabilitySpec(
        capability_id=capability_id,
        version="1.0.0",
        description="Probe one explicit-port HTTP loopback endpoint without general network authority, redirects, or request credentials.",
        category="platform_runtime",
        shard="platform_integrations",
        exposure="registry",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 2048},
                "method": {"type": "string", "enum": ["GET", "HEAD"]},
                "timeout_ms": {"type": "integer", "minimum": 50, "maximum": 10000},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": _MAX_RESPONSE_BYTES},
                "include_body": {"type": "boolean"},
                "json_assertions": {
                    "type": "array",
                    "maxItems": _MAX_ASSERTIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "pointer": {"type": "string", "maxLength": 256},
                            "equals": {},
                        },
                        "required": ["pointer", "equals"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "additionalProperties": True},
        risk_class="R0",
        approval_policy="none",
        workspace_binding="required",
        session_required=False,
        writer_lease_required=False,
        network_required=False,
        credential_requirements=(),
        timeout_ms=15_000,
        idempotency="handler_defined",
        audit_category=capability_id,
        deprecated=False,
        replacement=None,
        handler=capability_id,
        handler_version="1",
    )

    def preflight(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
    ) -> tuple[Mapping[str, Any], Any]:
        del context
        _canonical, host, port, _path = _validated_target(params.get("url"))
        return (
            {
                "operation": capability_id,
                "host": host,
                "port": port,
                "method": str(params.get("method", "GET")).upper(),
                "include_body": params.get("include_body", False) is True,
                "assertion_count": len(params.get("json_assertions", [])),
                "external_execution": False,
            },
            dict(params),
        )

    def execute(
        params: dict[str, Any],
        context: CapabilityExecutionContext,
        state: Any,
    ) -> Mapping[str, Any]:
        del context, state
        try:
            result = typed_execute(dict(params))
        except LoopbackHttpProbeError as exc:
            raise StableCapabilityGatewayError(exc.code, str(exc)) from exc
        if not isinstance(result, Mapping):
            raise StableCapabilityGatewayError(
                "CAPABILITY_HANDLER_RESULT_INVALID",
                "Loopback HTTP probe returned an invalid result.",
            )
        return dict(result)

    return spec, CapabilityHandler(
        handler_id=capability_id,
        handler_version="1",
        preflight=preflight,
        execute=execute,
    )


__all__ = ["LoopbackHttpProbe", "LoopbackHttpProbeError", "build_loopback_http_probe_binding"]
