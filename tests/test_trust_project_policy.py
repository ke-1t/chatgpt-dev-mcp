from __future__ import annotations
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from chatgpt_dev_mcp.project_policy import ProjectPolicyError, ProjectPolicyManager
from chatgpt_dev_mcp.provisioning import DEFAULT_ISOLATED_POLICY, ProvisioningError, RegistryMutationManager

def _write_config(path: Path, *, trust_level: str | None = None) -> None:
    policy: dict[str, object] = {"auto_create_sessions": True, "integration_requires_approval": True, "commit_requires_approval": True, "push_requires_approval": True}
    if trust_level is not None: policy["trust_level"] = trust_level
    path.write_text(json.dumps({"version": 1, "workspaces": {"fixture": {"path": "/tmp/fixture", "profile": "DEVELOPMENT", "isolated_development": policy}}}), encoding="utf-8")

class TrustProjectPolicyTests(unittest.TestCase):
    def _manager(self, config: Path) -> ProjectPolicyManager: return ProjectPolicyManager(config, normalize_policy=ProjectPolicyManager._effective_policy)
    def test_defaults_and_generic_promotion_denied(self) -> None:
        self.assertEqual(ProjectPolicyManager._effective_policy({})["trust_level"], "standard")
        self.assertEqual(DEFAULT_ISOLATED_POLICY["trust_level"], "standard")
        with TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"; _write_config(config); manager = self._manager(config); before = manager.get("fixture")
            with self.assertRaises(ProjectPolicyError) as raised: manager.update("fixture", before["config_digest"], {"trust_level": "trusted_development"})
            self.assertEqual(raised.exception.code, "PROJECT_POLICY_UPDATE_DENIED")
    def test_dedicated_lifecycle_promotes_and_stale_digest_fails(self) -> None:
        with TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"; _write_config(config); manager = self._manager(config); before = manager.get("fixture")
            result = manager.set_trust_level("fixture", before["config_digest"], "trusted_development")
            self.assertEqual(result["policy"]["trust_level"], "trusted_development")
            with self.assertRaises(ProjectPolicyError) as raised: manager.set_trust_level("fixture", before["config_digest"], "standard")
            self.assertEqual(raised.exception.code, "CONFIG_CHANGED")
    def test_revoke_and_invalid_values(self) -> None:
        with TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"; _write_config(config, trust_level="trusted_development"); manager = self._manager(config); before = manager.get("fixture")
            self.assertEqual(manager.update("fixture", before["config_digest"], {"trust_level": "standard"})["policy"]["trust_level"], "standard")
            current = manager.get("fixture")
            with self.assertRaises(ProjectPolicyError): manager.set_trust_level("fixture", current["config_digest"], "unbounded")
    def test_registration_cannot_promote_but_can_revoke(self) -> None:
        entry = {"profile": "DEVELOPMENT", "isolated_development": dict(DEFAULT_ISOLATED_POLICY)}
        with self.assertRaises(ProvisioningError) as raised: RegistryMutationManager._apply_policy_patch(entry, {"trust_level": "trusted_development"})
        self.assertEqual(raised.exception.code, "REGISTRATION_POLICY_DOWNGRADE_DENIED")
        trusted = dict(DEFAULT_ISOLATED_POLICY); trusted["trust_level"] = "trusted_development"
        self.assertEqual(RegistryMutationManager._apply_policy_patch({"profile": "DEVELOPMENT", "isolated_development": trusted}, {"trust_level": "standard"})["trust_level"], "standard")
