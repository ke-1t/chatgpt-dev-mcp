"""Bounded filtering and cursor pagination for development-session payloads."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Sequence


_STATUS_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CURSOR_VERSION = 1


class SessionListError(ValueError):
    """Raised when a cursor or session payload cannot be trusted."""


@dataclass(frozen=True, slots=True)
class SessionListQuery:
    active_only: bool = False
    statuses: tuple[str, ...] = ()
    workspace_id: str | None = None
    limit: int = 20
    cursor: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.active_only, bool):
            raise ValueError("active_only must be boolean")
        if not isinstance(self.statuses, tuple) or len(self.statuses) > 32 or len(self.statuses) != len(set(self.statuses)):
            raise ValueError("statuses are invalid")
        if any(not isinstance(value, str) or not _STATUS_RE.fullmatch(value) for value in self.statuses):
            raise ValueError("statuses are invalid")
        if self.workspace_id is not None and (
            not isinstance(self.workspace_id, str)
            or not self.workspace_id
            or len(self.workspace_id) > 160
            or "\x00" in self.workspace_id
        ):
            raise ValueError("workspace_id is invalid")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= 100:
            raise ValueError("limit is outside bounds")
        if self.cursor is not None and (
            not isinstance(self.cursor, str) or not self.cursor or len(self.cursor) > 1024 or "\x00" in self.cursor
        ):
            raise ValueError("cursor is invalid")


def _query_fingerprint(query: SessionListQuery) -> str:
    payload = {
        "active_only": query.active_only,
        "statuses": list(query.statuses),
        "workspace_id": query.workspace_id,
        "limit": query.limit,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _encode_cursor(*, query_fingerprint: str, created_at: float, session_id: str) -> str:
    body = json.dumps(
        {"v": _CURSOR_VERSION, "q": query_fingerprint, "created_at": created_at, "session_id": session_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    checksum = hashlib.sha256(body).hexdigest()[:24].encode("ascii")
    return base64.urlsafe_b64encode(checksum + b"." + body).decode("ascii").rstrip("=")


def _decode_cursor(value: str, *, query_fingerprint: str) -> tuple[float, str]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        checksum, body = raw.split(b".", 1)
        if checksum.decode("ascii") != hashlib.sha256(body).hexdigest()[:24]:
            raise SessionListError("cursor checksum mismatch")
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("v") != _CURSOR_VERSION:
            raise SessionListError("cursor version is invalid")
        if payload.get("q") != query_fingerprint:
            raise SessionListError("cursor does not match the current query")
        created_at = float(payload["created_at"])
        session_id = str(payload["session_id"])
        if not session_id or len(session_id) > 160 or "\x00" in session_id:
            raise SessionListError("cursor session id is invalid")
        return created_at, session_id
    except SessionListError:
        raise
    except (UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SessionListError("cursor is invalid") from exc


def _normalize(payload: Mapping[str, object]) -> tuple[Mapping[str, object], float, str, str, bool, str]:
    if not isinstance(payload, Mapping):
        raise SessionListError("session payload is invalid")
    session_id = str(payload.get("session_id", ""))
    workspace_id = str(
        payload.get("logical_workspace_id")
        or payload.get("project_id")
        or payload.get("workspace_id", "")
    )
    status = str(payload.get("status", ""))
    active = payload.get("active", False)
    try:
        created_at = float(payload.get("created_at", 0.0))
    except (TypeError, ValueError) as exc:
        raise SessionListError("session created_at is invalid") from exc
    if not session_id or len(session_id) > 160 or "\x00" in session_id:
        raise SessionListError("session id is invalid")
    if not workspace_id or len(workspace_id) > 160 or "\x00" in workspace_id:
        raise SessionListError("workspace id is invalid")
    if not _STATUS_RE.fullmatch(status) or not isinstance(active, bool):
        raise SessionListError("session lifecycle metadata is invalid")
    return payload, created_at, session_id, status, active, workspace_id


def _normalize_metadata(payload: Mapping[str, object]) -> tuple[Mapping[str, object], float, str, str]:
    """Normalize only fields that do not require a live worktree observation."""

    if not isinstance(payload, Mapping):
        raise SessionListError("session payload is invalid")
    session_id = str(payload.get("session_id", ""))
    workspace_id = str(
        payload.get("logical_workspace_id")
        or payload.get("project_id")
        or payload.get("workspace_id", "")
    )
    try:
        created_at = float(payload.get("created_at", 0.0))
    except (TypeError, ValueError) as exc:
        raise SessionListError("session created_at is invalid") from exc
    if not session_id or len(session_id) > 160 or "\x00" in session_id:
        raise SessionListError("session id is invalid")
    if not workspace_id or len(workspace_id) > 160 or "\x00" in workspace_id:
        raise SessionListError("workspace id is invalid")
    return payload, created_at, session_id, workspace_id


def paginate_session_metadata(
    payloads: Sequence[Mapping[str, object]],
    query: SessionListQuery,
) -> dict[str, object]:
    """Page cheap session metadata before callers perform live Git probes."""

    if not isinstance(query, SessionListQuery):
        raise TypeError("query must be SessionListQuery")
    if query.active_only or query.statuses:
        raise SessionListError("lifecycle filters require observed session payloads")
    normalized = [_normalize_metadata(payload) for payload in payloads]
    filtered = [
        record
        for record in normalized
        if query.workspace_id is None or record[3] == query.workspace_id
    ]
    filtered.sort(key=lambda record: (record[1], record[2]), reverse=True)
    fingerprint = _query_fingerprint(query)
    start = 0
    if query.cursor is not None:
        cursor_key = _decode_cursor(query.cursor, query_fingerprint=fingerprint)
        keys = [(record[1], record[2]) for record in filtered]
        try:
            start = keys.index(cursor_key) + 1
        except ValueError as exc:
            raise SessionListError("cursor no longer references this inventory") from exc
    selected = filtered[start : start + query.limit]
    next_cursor = None
    if selected and start + len(selected) < len(filtered):
        last = selected[-1]
        next_cursor = _encode_cursor(
            query_fingerprint=fingerprint,
            created_at=last[1],
            session_id=last[2],
        )
    return {
        "sessions": [record[0] for record in selected],
        "returned": len(selected),
        "next_cursor": next_cursor,
        "counts": {
            "inventory_total": len(normalized),
            "filtered_total": len(filtered),
        },
    }


def paginate_session_payloads(
    payloads: Sequence[Mapping[str, object]],
    query: SessionListQuery,
) -> dict[str, object]:
    if not isinstance(query, SessionListQuery):
        raise TypeError("query must be SessionListQuery")
    normalized = [_normalize(payload) for payload in payloads]
    filtered = [
        record
        for record in normalized
        if (not query.active_only or record[4])
        and (not query.statuses or record[3] in query.statuses)
        and (query.workspace_id is None or record[5] == query.workspace_id)
    ]
    filtered.sort(key=lambda record: (record[1], record[2]), reverse=True)
    fingerprint = _query_fingerprint(query)
    start = 0
    if query.cursor is not None:
        cursor_key = _decode_cursor(query.cursor, query_fingerprint=fingerprint)
        keys = [(record[1], record[2]) for record in filtered]
        try:
            start = keys.index(cursor_key) + 1
        except ValueError as exc:
            raise SessionListError("cursor no longer references this inventory") from exc
    selected = filtered[start : start + query.limit]
    next_cursor = None
    if selected and start + len(selected) < len(filtered):
        last = selected[-1]
        next_cursor = _encode_cursor(query_fingerprint=fingerprint, created_at=last[1], session_id=last[2])

    status_counts: dict[str, int] = {}
    active_count = 0
    for record in filtered:
        status_counts[record[3]] = status_counts.get(record[3], 0) + 1
        if record[4]:
            active_count += 1
    return {
        "sessions": [record[0] for record in selected],
        "returned": len(selected),
        "next_cursor": next_cursor,
        "counts": {
            "inventory_total": len(normalized),
            "filtered_total": len(filtered),
            "active": active_count,
            "statuses": dict(sorted(status_counts.items())),
        },
    }


__all__ = [
    "SessionListError",
    "SessionListQuery",
    "paginate_session_metadata",
    "paginate_session_payloads",
]
