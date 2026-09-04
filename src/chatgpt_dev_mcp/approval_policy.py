"""Fail-closed risk classification and bounded trusted local grants.

This module does not execute operations.  It only classifies named platform
operations and, for the narrow R2 maintenance tier, binds an in-memory grant
to an exact managed development context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import secrets
import time
from typing import Callable, Iterable


class ApprovalPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RiskClass(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


@dataclass(frozen=True)
class RiskDecision:
    operation: str
    risk_class: RiskClass
    authorization_mode: str
    reason: str


@dataclass(frozen=True)
class GrantBinding:
    workspace_id: str
    working_tree_id: str
    session_id: str
    task_id: str
    owner_id: str


@dataclass(frozen=True)
class TrustedSessionGrant:
    grant_id: str
    binding: GrantBinding
    operations: tuple[str, ...]
    policy_digest: str
    issued_at: float
    expires_at: float


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class RiskPolicyEngine:
    """Classify exact platform operations; anything unknown is R3."""

    _R0 = frozenset(
        {
            "workspace_status",
            "workspace_list",
            "workspace_profile",
            "workspace_project_policy_get",
            "director_health",
            "director_status_summary",
            "git_status",
            "git_diff",
            "read_file",
            "search_text",
            "security_audit",
            "git_stage_preflight",
            "git_stage_paths_preflight",
            "git_stage_hunks_preflight",
        }
    )
    _R1 = frozenset(
        {
            "run_task",
            "apply_patch",
            "patch_preflight",
            "workspace_resume_development_session",
            "director_writer_lease",
            "git_stage",
            "git_stage_paths",
            "git_stage_hunks",
            "git_verified_commit_preflight",
            "git_verified_commit",
        }
    )
    _R2 = frozenset({"restart_dev_mcp_tunnel", "create_mcp_restart_shortcut", "install_dev_toolchain", "host_file_trash"})
    _R3 = frozenset(
        {
            "workspace_integrate_development_session",
            "git_commit",
            "git_push",
            "github_workflow_apply",
            "git_workflow_apply",
            "arbitrary_command",
            "arbitrary_command_preflight",
            "credential_grant",
            "credential_read",
            "privileged_command",
            "destructive_filesystem",
            "host_file_delete",
            "destructive_git",
        }
    )

    def classify(self, operation: object) -> RiskClass:
        if not isinstance(operation, str) or not operation:
            return RiskClass.R3
        if operation in self._R0:
            return RiskClass.R0
        if operation in self._R1:
            return RiskClass.R1
        if operation in self._R2:
            return RiskClass.R2
        return RiskClass.R3

    def decide(self, operation: object) -> RiskDecision:
        normalized = operation if isinstance(operation, str) and operation else "<invalid>"
        risk_class = self.classify(operation)
        if risk_class is RiskClass.R0:
            return RiskDecision(normalized, risk_class, "automatic", "read-only operation")
        if risk_class is RiskClass.R1:
            return RiskDecision(normalized, risk_class, "automatic", "bounded safe-local development operation")
        if risk_class is RiskClass.R2:
            return RiskDecision(normalized, risk_class, "trusted_session_grant", "registered bounded local maintenance operation")
        reason = "explicit high-risk operation" if normalized in self._R3 else "unknown operation fails closed"
        return RiskDecision(normalized, risk_class, "human_approval", reason)


def _validate_binding(binding: GrantBinding) -> None:
    if not isinstance(binding, GrantBinding):
        raise ApprovalPolicyError("TRUSTED_GRANT_BINDING_INVALID", "trusted grant binding is invalid")
    for field in ("workspace_id", "working_tree_id", "session_id", "task_id", "owner_id"):
        value = getattr(binding, field)
        if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
            raise ApprovalPolicyError("TRUSTED_GRANT_BINDING_INVALID", f"{field} is invalid")


def _validate_policy_digest(policy_digest: object) -> str:
    if not isinstance(policy_digest, str) or _DIGEST_RE.fullmatch(policy_digest) is None:
        raise ApprovalPolicyError("TRUSTED_GRANT_POLICY_INVALID", "policy digest is invalid")
    return policy_digest


class TrustedGrantStore:
    """Memory-only trusted grants for exact R2 operations."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        policy_engine: RiskPolicyEngine | None = None,
        max_records: int = 256,
    ) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not 16 <= max_records <= 4096:
            raise ValueError("max_records is outside bounds")
        self._clock = clock or time.time
        self._policy_engine = policy_engine or RiskPolicyEngine()
        self._max_records = max_records
        self._records: dict[str, TrustedSessionGrant] = {}

    def _prune(self) -> None:
        now = float(self._clock())
        for grant_id, grant in list(self._records.items()):
            if now > grant.expires_at:
                self._records.pop(grant_id, None)
        if len(self._records) > self._max_records:
            oldest = sorted(self._records.values(), key=lambda item: item.issued_at)
            for grant in oldest[: len(self._records) - self._max_records]:
                self._records.pop(grant.grant_id, None)

    def issue(
        self,
        binding: GrantBinding,
        *,
        operations: Iterable[str],
        policy_digest: str,
        ttl_seconds: float,
        session_expires_at: float,
    ) -> TrustedSessionGrant:
        _validate_binding(binding)
        digest = _validate_policy_digest(policy_digest)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not 60 <= float(ttl_seconds) <= 7_200:
            raise ApprovalPolicyError("TRUSTED_GRANT_TTL_INVALID", "trusted grant TTL is outside bounds")
        parsed_operations = tuple(dict.fromkeys(operations))
        if not parsed_operations:
            raise ApprovalPolicyError("TRUSTED_GRANT_OPERATION_INVALID", "trusted grant requires at least one operation")
        for operation in parsed_operations:
            if self._policy_engine.classify(operation) is not RiskClass.R2:
                raise ApprovalPolicyError("TRUSTED_GRANT_R3_DENIED", "only R2 operations may be placed in a trusted grant; R3 remains human-approved")
        now = float(self._clock())
        if not isinstance(session_expires_at, (int, float)) or isinstance(session_expires_at, bool) or float(session_expires_at) <= now:
            raise ApprovalPolicyError("TRUSTED_GRANT_SESSION_EXPIRED", "development session is already expired")
        expires_at = min(now + float(ttl_seconds), float(session_expires_at))
        self._prune()
        grant = TrustedSessionGrant(
            grant_id="grant:" + secrets.token_urlsafe(24),
            binding=binding,
            operations=parsed_operations,
            policy_digest=digest,
            issued_at=now,
            expires_at=expires_at,
        )
        self._records[grant.grant_id] = grant
        return grant

    def validate(
        self,
        grant_id: object,
        *,
        binding: GrantBinding,
        operation: str,
        policy_digest: str,
    ) -> TrustedSessionGrant:
        _validate_binding(binding)
        digest = _validate_policy_digest(policy_digest)
        if not isinstance(grant_id, str):
            raise ApprovalPolicyError("TRUSTED_GRANT_INVALID", "trusted grant is unknown")
        grant = self._records.get(grant_id)
        if grant is None:
            raise ApprovalPolicyError("TRUSTED_GRANT_INVALID", "trusted grant is unknown")
        now = float(self._clock())
        if now > grant.expires_at:
            self._records.pop(grant_id, None)
            raise ApprovalPolicyError("TRUSTED_GRANT_EXPIRED", "trusted grant has expired")
        if grant.binding != binding:
            raise ApprovalPolicyError("TRUSTED_GRANT_BINDING_MISMATCH", "trusted grant binding has changed")
        if grant.policy_digest != digest:
            raise ApprovalPolicyError("TRUSTED_GRANT_POLICY_MISMATCH", "trusted grant policy has changed")
        if operation not in grant.operations or self._policy_engine.classify(operation) is not RiskClass.R2:
            raise ApprovalPolicyError("TRUSTED_GRANT_OPERATION_DENIED", "operation is not authorized by this trusted grant")
        return grant

    def invalidate_all(self) -> None:
        self._records.clear()


__all__ = [
    "ApprovalPolicyError",
    "GrantBinding",
    "RiskClass",
    "RiskDecision",
    "RiskPolicyEngine",
    "TrustedGrantStore",
    "TrustedSessionGrant",
]
