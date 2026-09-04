"""Durable integration recovery without persisted bearer challenges."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .contracts import ControlPlaneError


@dataclass(frozen=True)
class ExactIntegrationState:
    workspace_id: str
    session_id: str
    canonical_revision: str
    patch_hash: str
    source_snapshot_id: str
    verification_receipt_id: str
    security_audit_receipt_id: str


@dataclass(frozen=True)
class DurableIntegrationIntent:
    intent_id: str
    exact_state: ExactIntegrationState
    control_plane_release_id: str
    schema_identity: str = ""


@dataclass(frozen=True)
class DurableApprovalDecision:
    decision_id: str
    intent_id: str
    state: str
    expires_at: float
    consumed: bool = False


@dataclass(frozen=True)
class ResumeChallenge:
    challenge_id: str
    intent_id: str
    exact_state: ExactIntegrationState


ChallengeFactory = Callable[[DurableIntegrationIntent, ExactIntegrationState], ResumeChallenge]


def resume_integration(
    intent: DurableIntegrationIntent,
    decision: DurableApprovalDecision,
    current_state: ExactIntegrationState,
    *,
    current_control_plane_release_id: str,
    now: float,
    issue_challenge: ChallengeFactory,
) -> ResumeChallenge:
    if decision.intent_id != intent.intent_id:
        raise ControlPlaneError("CONTROL_PLANE_APPROVAL_INTENT_MISMATCH", "approval decision does not belong to this integration intent")
    if decision.state != "approved":
        raise ControlPlaneError("CONTROL_PLANE_APPROVAL_NOT_APPROVED", "integration intent does not have an approved durable decision")
    if decision.consumed:
        raise ControlPlaneError("CONTROL_PLANE_APPROVAL_CONSUMED", "durable approval decision has already been consumed")
    if float(now) > float(decision.expires_at):
        raise ControlPlaneError("CONTROL_PLANE_APPROVAL_EXPIRED", "durable approval decision has expired")
    if current_control_plane_release_id != intent.control_plane_release_id:
        raise ControlPlaneError("CONTROL_PLANE_RELEASE_MISMATCH", "Control Plane release identity changed since preflight")
    if current_state != intent.exact_state:
        raise ControlPlaneError("CONTROL_PLANE_EXACT_STATE_DRIFT", "integration exact-state evidence changed since approval")
    if not callable(issue_challenge):
        raise ControlPlaneError("CONTROL_PLANE_CHALLENGE_ISSUE_FAILED", "execution challenge factory is unavailable")
    try:
        challenge = issue_challenge(intent, current_state)
    except Exception as exc:
        raise ControlPlaneError("CONTROL_PLANE_CHALLENGE_ISSUE_FAILED", "fresh execution challenge could not be issued") from exc
    if not isinstance(challenge, ResumeChallenge):
        raise ControlPlaneError("CONTROL_PLANE_CHALLENGE_ISSUE_FAILED", "challenge factory returned an invalid challenge")
    if challenge.intent_id != intent.intent_id or challenge.exact_state != current_state or not challenge.challenge_id:
        raise ControlPlaneError("CONTROL_PLANE_CHALLENGE_ISSUE_FAILED", "challenge is not bound to the revalidated integration state")
    return challenge


__all__ = ["DurableApprovalDecision", "DurableIntegrationIntent", "ExactIntegrationState", "ResumeChallenge", "resume_integration"]
