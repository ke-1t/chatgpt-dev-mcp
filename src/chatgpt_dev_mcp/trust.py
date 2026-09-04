"""Pure workspace-level trust decisions for normal DEVELOPMENT operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TrustLevel(str, Enum):
    STANDARD = "standard"
    TRUSTED_DEVELOPMENT = "trusted_development"


class AuthorizationMode(str, Enum):
    AUTOMATIC_GLOBAL_READ = "automatic_global_read"
    AUTOMATIC_TRUSTED_WORKSPACE = "automatic_trusted_workspace"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    DENIED = "denied"


@dataclass(frozen=True)
class TrustDecision:
    operation: str
    trust_level: TrustLevel
    authorization_mode: AuthorizationMode
    reason: str


def normalize_trust_level(value: object) -> TrustLevel:
    if value is None:
        return TrustLevel.STANDARD
    if isinstance(value, TrustLevel):
        return value
    if isinstance(value, str):
        try:
            return TrustLevel(value)
        except ValueError:
            pass
    raise ValueError("unsupported workspace trust level")


class WorkspaceTrustPolicy:
    """Fail-closed authorization policy; this class never executes mutations."""

    _GLOBAL_READ = frozenset({
        "workspace_status", "workspace_list", "workspace_profile", "workspace_project_policy_get",
        "director_health", "director_status_summary", "git_status", "git_diff", "read_file",
        "search_text", "security_audit", "capability_catalog", "capability_describe",
    })
    _TRUSTED_NORMAL = frozenset({
        "director_development_start", "workspace_resume_development_session",
        "workspace_close_development_session", "director_writer_lease", "apply_patch",
        "run_task", "local_maintenance", "external_open", "git_verified_commit",
        "workspace_integrate_development_session", "git_registered_normal_push",
    })
    _READY_REQUIRED = frozenset({"git_verified_commit", "workspace_integrate_development_session", "git_registered_normal_push"})
    _EXCEPTIONAL = frozenset({
        "git_force_push", "git_non_fast_forward_push", "destructive_git", "destructive_filesystem",
        "arbitrary_command", "privileged_command", "workspace_outside_write", "policy_weakening", "trust_expansion",
    })

    def decide(self, operation: object, trust_level: object = TrustLevel.STANDARD, *, preflight_ready: bool = True, secret_required: bool = False, external_transaction: bool = False) -> TrustDecision:
        level = normalize_trust_level(trust_level)
        if not isinstance(operation, str) or not operation:
            return TrustDecision("<invalid>", level, AuthorizationMode.DENIED, "operation name is invalid")
        if secret_required:
            return TrustDecision(operation, level, AuthorizationMode.HUMAN_APPROVAL_REQUIRED, "separate sensitive-read authorization is required")
        if external_transaction:
            return TrustDecision(operation, level, AuthorizationMode.HUMAN_APPROVAL_REQUIRED, "external transaction is outside workspace trust")
        if operation in self._GLOBAL_READ:
            return TrustDecision(operation, level, AuthorizationMode.AUTOMATIC_GLOBAL_READ, "bounded read-only operation")
        if operation in self._EXCEPTIONAL:
            return TrustDecision(operation, level, AuthorizationMode.HUMAN_APPROVAL_REQUIRED, "exceptional operation is outside workspace trust")
        if operation not in self._TRUSTED_NORMAL:
            return TrustDecision(operation, level, AuthorizationMode.HUMAN_APPROVAL_REQUIRED, "unknown or unclassified mutation fails closed")
        if level is not TrustLevel.TRUSTED_DEVELOPMENT:
            return TrustDecision(operation, level, AuthorizationMode.HUMAN_APPROVAL_REQUIRED, "workspace is not trusted for automatic DEVELOPMENT mutation")
        if operation in self._READY_REQUIRED and not preflight_ready:
            return TrustDecision(operation, level, AuthorizationMode.DENIED, "trusted workspace cannot bypass an unready technical preflight")
        return TrustDecision(operation, level, AuthorizationMode.AUTOMATIC_TRUSTED_WORKSPACE, "bounded operation is covered by persistent workspace trust")
