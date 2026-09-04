from __future__ import annotations

from dataclasses import dataclass
import secrets
import time
from typing import Callable


MANUAL_APPROVAL_TTL_SECONDS = 30 * 60


class ApprovalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ApprovalRecord:
    approval_id: str
    operation: str
    workspace_id: str
    fingerprint: str
    confirmation: str
    issued_at: float
    expires_at: float
    consumed_at: float | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "approval_token": self.approval_id,
            "operation": self.operation,
            "workspace_id": self.workspace_id,
            "fingerprint": self.fingerprint,
            "confirmation": self.confirmation,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "one_shot": True,
        }
        if self.consumed_at is not None:
            payload["consumed_at"] = self.consumed_at
        return payload


class UnifiedApprovalStore:
    """Memory-only, one-shot approvals for bounded mutation controllers."""

    def __init__(self, *, clock: Callable[[], float] | None = None, ttl_seconds: float = MANUAL_APPROVAL_TTL_SECONDS, max_records: int = 256) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._clock = clock or time.time
        self._ttl_seconds = float(ttl_seconds)
        self._max_records = max(16, int(max_records))
        self._records: dict[str, ApprovalRecord] = {}

    def _prune(self) -> None:
        now = float(self._clock())
        expired = [key for key, record in self._records.items() if record.expires_at < now or record.consumed_at is not None]
        for key in expired:
            self._records.pop(key, None)
        if len(self._records) > self._max_records:
            oldest = sorted(self._records.values(), key=lambda item: item.issued_at)
            for record in oldest[: len(self._records) - self._max_records]:
                self._records.pop(record.approval_id, None)

    def issue(self, operation: str, workspace_id: str, fingerprint: str, confirmation: str) -> ApprovalRecord:
        for name, value, limit in (
            ("operation", operation, 80),
            ("workspace_id", workspace_id, 128),
            ("fingerprint", fingerprint, 256),
            ("confirmation", confirmation, 400),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise ApprovalError("APPROVAL_ARGUMENT_INVALID", f"{name} is invalid")
        self._prune()
        now = float(self._clock())
        approval_id = secrets.token_urlsafe(24)
        record = ApprovalRecord(approval_id, operation, workspace_id, fingerprint, confirmation, now, now + self._ttl_seconds)
        self._records[approval_id] = record
        return record

    def consume(self, approval_id: str, confirmation: str, *, operation: str, workspace_id: str, fingerprint: str) -> ApprovalRecord:
        record = self._records.get(approval_id)
        if record is None or record.consumed_at is not None:
            raise ApprovalError("APPROVAL_INVALID_OR_CONSUMED", "approval is unknown or already consumed")
        now = float(self._clock())
        if now > record.expires_at:
            self._records.pop(approval_id, None)
            raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
        if record.operation != operation or record.workspace_id != workspace_id or record.fingerprint != fingerprint:
            raise ApprovalError("APPROVAL_BINDING_MISMATCH", "approval target has changed")
        if record.confirmation != confirmation:
            raise ApprovalError("APPROVAL_CONFIRMATION_MISMATCH", "confirmation does not match")
        record.consumed_at = now
        return record

    def invalidate_all(self) -> None:
        self._records.clear()
