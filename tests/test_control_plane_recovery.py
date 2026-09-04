from __future__ import annotations

import unittest
from dataclasses import fields

from chatgpt_dev_mcp.control_plane import ControlPlaneError
from chatgpt_dev_mcp.control_plane.recovery import DurableApprovalDecision, DurableIntegrationIntent, ExactIntegrationState, ResumeChallenge, resume_integration


def _state(**overrides):
    values = {"workspace_id":"chatgpt-dev-mcp","session_id":"session:control-plane","canonical_revision":"a"*40,"patch_hash":"b"*64,"source_snapshot_id":"snapshot:source","verification_receipt_id":"verify:green","security_audit_receipt_id":"audit:clean"}
    values.update(overrides); return ExactIntegrationState(**values)


def _intent(state=None): return DurableIntegrationIntent("integration-intent:control-plane", state or _state(), "control-plane-release:n", "tool-registry-v25-stable:52:hash")
def _decision(**overrides):
    values = {"decision_id":"approval-decision:control-plane","intent_id":"integration-intent:control-plane","state":"approved","expires_at":2000.0,"consumed":False}; values.update(overrides); return DurableApprovalDecision(**values)


def test_valid_resume_issues_fresh_challenge_after_exact_state_revalidation() -> None:
    issued=[]
    def issue(intent, current):
        challenge=ResumeChallenge(f"execution-challenge:{len(issued)+1}", intent.intent_id, current); issued.append(challenge.challenge_id); return challenge
    first=resume_integration(_intent(),_decision(),_state(),current_control_plane_release_id="control-plane-release:n",now=1000.0,issue_challenge=issue)
    second=resume_integration(_intent(),_decision(),_state(),current_control_plane_release_id="control-plane-release:n",now=1001.0,issue_challenge=issue)
    assert first.challenge_id != second.challenge_id


def test_durable_models_cannot_persist_bearer_approval_tokens() -> None:
    names={field.name for model in (DurableIntegrationIntent,DurableApprovalDecision,ExactIntegrationState) for field in fields(model)}
    assert "approval_token" not in names and "token" not in names and "execution_challenge" not in names


def test_resume_rejects_invalid_approval_release_and_state_drift() -> None:
    cases=((_decision(state="denied"),1000.0,"CONTROL_PLANE_APPROVAL_NOT_APPROVED"),(_decision(consumed=True),1000.0,"CONTROL_PLANE_APPROVAL_CONSUMED"),(_decision(expires_at=999.0),1000.0,"CONTROL_PLANE_APPROVAL_EXPIRED"),(_decision(intent_id="other"),1000.0,"CONTROL_PLANE_APPROVAL_INTENT_MISMATCH"))
    for decision,now,code in cases:
        with unittest.TestCase().assertRaises(ControlPlaneError) as error:
            resume_integration(_intent(),decision,_state(),current_control_plane_release_id="control-plane-release:n",now=now,issue_challenge=lambda i,s: ResumeChallenge("x",i.intent_id,s))
        assert error.exception.code == code
    with unittest.TestCase().assertRaises(ControlPlaneError) as error:
        resume_integration(_intent(),_decision(),_state(),current_control_plane_release_id="control-plane-release:n+1",now=1000.0,issue_challenge=lambda i,s: ResumeChallenge("x",i.intent_id,s))
    assert error.exception.code == "CONTROL_PLANE_RELEASE_MISMATCH"
    with unittest.TestCase().assertRaises(ControlPlaneError) as error:
        resume_integration(_intent(),_decision(),_state(patch_hash="c"*64),current_control_plane_release_id="control-plane-release:n",now=1000.0,issue_challenge=lambda i,s: ResumeChallenge("x",i.intent_id,s))
    assert error.exception.code == "CONTROL_PLANE_EXACT_STATE_DRIFT"


def load_tests(loader, tests, pattern):
    del loader, tests, pattern
    return unittest.TestSuite(unittest.FunctionTestCase(value) for value in (test_valid_resume_issues_fresh_challenge_after_exact_state_revalidation,test_durable_models_cannot_persist_bearer_approval_tokens,test_resume_rejects_invalid_approval_release_and_state_drift))
