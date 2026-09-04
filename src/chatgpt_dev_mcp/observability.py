"""Non-secret runtime, schema, registry, and loopback health diagnostics."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


TOOL_SCHEMA_REVISION = "tool-registry-v25-stable"
HEALTH_SCHEMA_REVISION = "health-v1"
DEFAULT_TUNNEL_HEALTH_URL = "http://127.0.0.1:8080"
TUNNEL_HEALTH_TIMEOUT_SECONDS = 0.25
_INVALID_REGISTRY_ERROR_CODES = frozenset({"CONFIG_INVALID", "CONFIG_NOT_FILE", "CONFIG_VERSION_UNSUPPORTED"})
_ACCELERATION_KINDS = frozenset({"semantic", "context", "performance", "verification_selection", "verification_cache", "loop", "qa", "review_link", "capability", "delivery", "readiness"})
_DENIED_ACCELERATION_METADATA_KEYS = frozenset({"source", "source_text", "content", "payload", "secret", "token", "password", "credential"})


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_tool_definitions(definitions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted((dict(item) for item in definitions), key=lambda item: str(item.get("name", "")))


def tool_schema_metadata(
    definitions: Sequence[Mapping[str, Any]],
    *,
    revision: str = TOOL_SCHEMA_REVISION,
) -> dict[str, Any]:
    canonical = _canonical_tool_definitions(definitions)
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "revision": revision,
        "count": len(definitions),
        "hash": hashlib.sha256(encoded).hexdigest(),
    }


def schema_consistency(
    definitions: Sequence[Mapping[str, Any]],
    listed: Sequence[Mapping[str, Any]],
    *,
    revision: str = TOOL_SCHEMA_REVISION,
) -> dict[str, Any]:
    local_schema = tool_schema_metadata(definitions, revision=revision)
    listed_schema = tool_schema_metadata(listed, revision=revision)
    checks = {
        "count_match": local_schema["count"] == listed_schema["count"],
        "hash_match": local_schema["hash"] == listed_schema["hash"],
        "revision_match": local_schema["revision"] == listed_schema["revision"],
    }
    return {
        "status": "consistent" if all(checks.values()) else "inconsistent",
        "local_tool_schema": local_schema,
        "listed_tool_schema": listed_schema,
        "checks": checks,
        "client_observation": "not_available",
    }


def compare_client_observation(local_schema: Mapping[str, Any], observed: Mapping[str, Any] | None) -> str:
    if observed is None:
        return "not_available"
    fields = ("revision", "count", "hash")
    return "matched" if all(observed.get(field) == local_schema.get(field) for field in fields) else "mismatched"


def registry_health(
    *,
    config_present: bool,
    root_descriptors: Sequence[Mapping[str, Any]],
    workspace_descriptors: Sequence[Mapping[str, Any]],
    error_codes: Sequence[str],
) -> dict[str, Any]:
    normalized_errors = sorted({str(code) for code in error_codes if str(code)})
    if any(code in _INVALID_REGISTRY_ERROR_CODES for code in normalized_errors):
        status = "invalid"
    elif normalized_errors:
        status = "degraded"
    else:
        status = "valid"
    digest_input = {
        "roots": sorted(
            [
                {
                    "id": str(item.get("id", "")),
                    "mode": str(item.get("mode", "")),
                }
                for item in root_descriptors
            ],
            key=lambda item: (item["id"], item["mode"]),
        ),
        "workspaces": sorted(
            [
                {
                    "id": str(item.get("id", "")),
                    "profile": str(item.get("profile", "")),
                    "commands": sorted(str(command) for command in (item.get("commands", []) or [])),
                }
                for item in workspace_descriptors
            ],
            key=lambda item: (item["id"], item["profile"]),
        ),
    }
    encoded = json.dumps(digest_input, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "status": status,
        "config_present": bool(config_present),
        "root_count": len(root_descriptors),
        "workspace_count": len(workspace_descriptors),
        "config_error_count": len(normalized_errors),
        "config_error_codes": normalized_errors,
        "config_digest": hashlib.sha256(encoded).hexdigest(),
    }


def _valid_loopback_base(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1"}
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
            and parsed.port is not None
            and 1 <= parsed.port <= 65535
        )
    except ValueError:
        return False


def probe_loopback_tunnel(
    url: str | None,
    *,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if url is None or url.strip().lower() in {"", "disabled", "off"}:
        return {"status": "unknown", "probe": "loopback_admin", "checked_at": _utc_now(), "latency_ms": 0}
    if not _valid_loopback_base(url):
        return {"status": "misconfigured", "probe": "loopback_admin", "checked_at": _utc_now(), "latency_ms": 0}

    request_opener = opener or _NO_REDIRECT_OPENER.open
    started = time.monotonic()
    endpoint_results: dict[str, bool] = {}
    expected = {"/healthz": "live", "/readyz": "ready"}
    for path, expected_body in expected.items():
        endpoint = urlunsplit((*urlsplit(url)[:2], path, "", ""))
        try:
            request = Request(endpoint, headers={"Accept": "text/plain"}, method="GET")
            with request_opener(request, timeout=TUNNEL_HEALTH_TIMEOUT_SECONDS) as response:
                raw_status = getattr(response, "status", None)
                status = int(raw_status if raw_status is not None else response.getcode())
                body = response.read(64).decode("utf-8", "replace").strip()
            endpoint_results[path] = status == 200 and body == expected_body
        except (HTTPError, URLError, OSError, TimeoutError, ValueError):
            endpoint_results[path] = False
    successes = sum(endpoint_results.values())
    if successes == len(expected):
        status = "healthy"
    elif successes:
        status = "degraded"
    else:
        status = "unavailable"
    return {
        "status": status,
        "probe": "loopback_admin",
        "healthz": "live" if endpoint_results.get("/healthz") else "unavailable",
        "readyz": "ready" if endpoint_results.get("/readyz") else "unavailable",
        "checked_at": _utc_now(),
        "latency_ms": round((time.monotonic() - started) * 1000, 2),
    }


class AccelerationObserver:
    """Metadata-only receipts and counters for acceleration subsystems."""

    def __init__(self, *, store: object | None = None, clock: Callable[[], str] = _utc_now) -> None:
        if store is not None and not callable(getattr(store, "save_acceleration_receipt", None)):
            raise ValueError("acceleration observer store is invalid")
        if not callable(clock):
            raise ValueError("acceleration observer clock is invalid")
        self._store = store
        self._clock = clock
        self._counters = {kind: 0 for kind in sorted(_ACCELERATION_KINDS)}

    @staticmethod
    def _identifier(value: object, name: str, maximum: int = 160) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
            raise ValueError(f"{name} is invalid")
        return value

    def record(
        self,
        kind: str,
        *,
        subject_id: str,
        reason: str,
        evidence_hashes: tuple[str, ...] = (),
        refs: tuple[str, ...] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if kind not in _ACCELERATION_KINDS:
            raise ValueError("acceleration receipt kind is invalid")
        subject = self._identifier(subject_id, "subject_id")
        parsed_reason = self._identifier(reason, "reason", 400)
        if not isinstance(evidence_hashes, tuple) or len(evidence_hashes) > 128 or any(not isinstance(item, str) or len(item) != 64 or any(char not in "0123456789abcdef" for char in item) for item in evidence_hashes):
            raise ValueError("evidence_hashes are invalid")
        if not isinstance(refs, tuple) or len(refs) > 128 or any(not isinstance(item, str) or not item or len(item) > 512 for item in refs):
            raise ValueError("refs are invalid")
        safe_metadata = dict(metadata or {})
        if any(str(key).casefold() in _DENIED_ACCELERATION_METADATA_KEYS for key in safe_metadata):
            raise ValueError("acceleration metadata contains a denied field")
        try:
            encoded_metadata = json.dumps(safe_metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("acceleration metadata must be JSON serializable") from exc
        if len(encoded_metadata.encode("utf-8")) > 8192:
            raise ValueError("acceleration metadata is outside bounds")
        created_at = self._identifier(self._clock(), "created_at", 128)
        payload = {"kind": kind, "subject_id": subject, "reason": parsed_reason, "evidence_hashes": sorted(evidence_hashes), "refs": sorted(refs), "metadata": safe_metadata, "created_at": created_at}
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        receipt = {"receipt_id": f"acceleration:{digest[:32]}", **payload, "external_execution": False}
        if self._store is not None:
            self._store.save_acceleration_receipt(receipt)
        self._counters[kind] += 1
        return receipt

    def status(self) -> dict[str, object]:
        return {"counters": dict(self._counters), "persisted": self._store is not None, "external_execution": False}
