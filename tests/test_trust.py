from __future__ import annotations
import unittest
from chatgpt_dev_mcp.trust import AuthorizationMode, TrustLevel, WorkspaceTrustPolicy, normalize_trust_level

class WorkspaceTrustPolicyTests(unittest.TestCase):
    def setUp(self) -> None: self.policy = WorkspaceTrustPolicy()
    def test_default_and_normalization(self) -> None:
        self.assertEqual(normalize_trust_level(None), TrustLevel.STANDARD)
        self.assertEqual(normalize_trust_level("trusted_development"), TrustLevel.TRUSTED_DEVELOPMENT)
        with self.assertRaises(ValueError): normalize_trust_level("unsupported")
    def test_standard_workspace_keeps_mutations_human_approved(self) -> None:
        for op in ("apply_patch", "run_task", "external_open", "git_verified_commit"):
            self.assertEqual(self.policy.decide(op, TrustLevel.STANDARD).authorization_mode, AuthorizationMode.HUMAN_APPROVAL_REQUIRED)
    def test_trusted_workspace_auto_authorizes_normal_local_development(self) -> None:
        for op in ("director_development_start", "workspace_resume_development_session", "director_writer_lease", "apply_patch", "run_task", "local_maintenance", "external_open"):
            self.assertEqual(self.policy.decide(op, TrustLevel.TRUSTED_DEVELOPMENT).authorization_mode, AuthorizationMode.AUTOMATIC_TRUSTED_WORKSPACE)
    def test_trusted_delivery_requires_ready_preflight(self) -> None:
        for op in ("git_verified_commit", "workspace_integrate_development_session", "git_registered_normal_push"):
            self.assertEqual(self.policy.decide(op, TrustLevel.TRUSTED_DEVELOPMENT, preflight_ready=True).authorization_mode, AuthorizationMode.AUTOMATIC_TRUSTED_WORKSPACE)
            self.assertEqual(self.policy.decide(op, TrustLevel.TRUSTED_DEVELOPMENT, preflight_ready=False).authorization_mode, AuthorizationMode.DENIED)
    def test_exceptional_sensitive_external_and_unknown_fail_closed(self) -> None:
        self.assertEqual(self.policy.decide("git_force_push", TrustLevel.TRUSTED_DEVELOPMENT).authorization_mode, AuthorizationMode.HUMAN_APPROVAL_REQUIRED)
        self.assertEqual(self.policy.decide("read_file", TrustLevel.TRUSTED_DEVELOPMENT, secret_required=True).authorization_mode, AuthorizationMode.HUMAN_APPROVAL_REQUIRED)
        self.assertEqual(self.policy.decide("external_open", TrustLevel.TRUSTED_DEVELOPMENT, external_transaction=True).authorization_mode, AuthorizationMode.HUMAN_APPROVAL_REQUIRED)
        self.assertEqual(self.policy.decide("future_unknown_mutation", TrustLevel.TRUSTED_DEVELOPMENT).authorization_mode, AuthorizationMode.HUMAN_APPROVAL_REQUIRED)
        self.assertEqual(self.policy.decide("", TrustLevel.TRUSTED_DEVELOPMENT).authorization_mode, AuthorizationMode.DENIED)
