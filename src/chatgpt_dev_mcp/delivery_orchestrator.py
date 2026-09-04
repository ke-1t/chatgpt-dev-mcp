"""Pure delivery next-step decisions over existing Git/GitHub evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping


class DeliveryOrchestratorError(ValueError):
    pass


@dataclass(frozen=True)
class DeliveryState:
    readiness: str
    committed: bool
    pushed: bool
    pr_exists: bool
    checks: str
    reviews: str
    merged: bool


@dataclass(frozen=True)
class DeliveryStep:
    action: str
    status: str
    approval_required: bool = False
    evidence_ref: str = ""
    reason: str = ""
    receipt_id: str = ""
    side_effect_performed: bool = False
    approval_consumed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {"action": self.action, "status": self.status, "approval_required": self.approval_required, "evidence_ref": self.evidence_ref, "reason": self.reason, "receipt_id": self.receipt_id, "side_effect_performed": self.side_effect_performed, "approval_consumed": self.approval_consumed, "external_execution": False}


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DeliveryOrchestratorError(f"{name} must be an object")
    return value


class DeliveryOrchestrator:
    @staticmethod
    def _step(action: str, status: str, *, approval_required: bool = False, evidence_ref: str = "", reason: str = "") -> DeliveryStep:
        payload = json.dumps({"action": action, "status": status, "approval_required": approval_required, "evidence_ref": evidence_ref, "reason": reason}, sort_keys=True, separators=(",", ":"))
        return DeliveryStep(action=action, status=status, approval_required=approval_required, evidence_ref=evidence_ref, reason=reason, receipt_id="delivery-step:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32])

    @staticmethod
    def _state(readiness: Mapping[str, object], git_state: Mapping[str, object], github_state: Mapping[str, object]) -> DeliveryState:
        return DeliveryState(readiness=str(readiness.get("status", "unknown")), committed=git_state.get("committed") is True, pushed=git_state.get("pushed") is True, pr_exists=github_state.get("pr_exists") is True, checks=str(github_state.get("checks", "unknown")), reviews=str(github_state.get("reviews", "unknown")), merged=github_state.get("merged") is True)

    def next_step(self, readiness: Mapping[str, object], git_state: Mapping[str, object], github_state: Mapping[str, object]) -> DeliveryStep:
        readiness = _mapping(readiness, "readiness")
        git_state = _mapping(git_state, "git_state")
        github_state = _mapping(github_state, "github_state")
        state = self._state(readiness, git_state, github_state)
        if state.readiness != "ready":
            return self._step("remediate", "remediation_required", evidence_ref=str(readiness.get("receipt_id", ""))[:512], reason="work_not_ready")
        if not state.committed:
            if git_state.get("verified_auto_commit_enabled") is True:
                if git_state.get("verified_auto_commit_eligible") is True:
                    return self._step(
                        "git_verified_commit_preflight",
                        "ready",
                        approval_required=False,
                        evidence_ref=str(git_state.get("verified_evidence_ref", ""))[:512],
                        reason="verified_auto_commit_eligible",
                    )
                raw_reason = str(git_state.get("verified_auto_commit_reason", "ineligible"))
                reason = raw_reason if raw_reason in {
                    "stale_evidence",
                    "verification_failed",
                    "security_blocked",
                    "review_missing",
                    "scope_mismatch",
                    "ineligible",
                } else "ineligible"
                return self._step(
                    "remediate",
                    "remediation_required",
                    approval_required=False,
                    evidence_ref=str(git_state.get("verified_evidence_ref", ""))[:512],
                    reason=f"verified_auto_commit_{reason}",
                )
            return self._step("git_commit_preflight", "blocked_for_approval", approval_required=True, reason="commit_requires_approval")
        if not state.pushed:
            return self._step("git_push_preflight", "blocked_for_approval", approval_required=True, evidence_ref=str(git_state.get("commit_receipt", ""))[:512], reason="push_requires_approval")
        if not state.pr_exists:
            return self._step("github_pr_preflight", "blocked_for_approval", approval_required=True, evidence_ref=str(git_state.get("push_receipt", ""))[:512], reason="pr_create_requires_approval")
        if state.checks == "failed":
            return self._step("remediate", "remediation_required", evidence_ref=str(github_state.get("checks_ref", ""))[:512], reason="github_checks_failed")
        if state.checks != "passed":
            return self._step("github_checks", "read_only", reason="checks_not_confirmed")
        if state.reviews in {"changes_requested", "failed"}:
            return self._step("remediate", "remediation_required", evidence_ref=str(github_state.get("reviews_ref", ""))[:512], reason="github_review_blocking")
        if state.reviews != "approved":
            return self._step("github_reviews", "read_only", reason="reviews_not_confirmed")
        if state.merged:
            return self._step("complete", "complete", reason="delivery_complete")
        return self._step("github_merge_preflight", "blocked_for_approval", approval_required=True, reason="merge_requires_approval")


__all__ = ["DeliveryOrchestrator", "DeliveryOrchestratorError", "DeliveryState", "DeliveryStep"]
