from __future__ import annotations

import unittest

from chatgpt_dev_mcp.tool_contract_policy import (
    INTEGRATION_EXECUTE_CONTRACT,
    INTEGRATION_PREFLIGHT_CONTRACT,
    validate_contract,
)


class ToolContractPolicyTests(unittest.TestCase):
    def test_integration_execute_contract_is_safety_rich(self) -> None:
        findings = validate_contract(INTEGRATION_EXECUTE_CONTRACT)
        self.assertEqual([], findings)
        description = INTEGRATION_EXECUTE_CONTRACT.description.lower()
        for phrase in (
            "explicitly approves",
            "cannot provide arbitrary patch",
            "canonical head",
            "patch hash",
            "verification receipt",
            "security audit",
            "one-shot",
            "fails closed",
            "never commits",
            "never pushes",
            "never resets",
            "never stashes",
            "never cleans",
            "never executes arbitrary shell commands",
        ):
            self.assertIn(phrase, description)

    def test_integration_execute_parameter_provenance_is_explicit(self) -> None:
        params = INTEGRATION_EXECUTE_CONTRACT.parameters
        self.assertIn("workspace_integration_preflight", params["session_id"].lower())
        self.assertIn("short-lived", params["approval_token"].lower())
        self.assertIn("one-shot", params["approval_token"].lower())
        self.assertIn("do not reuse", params["approval_token"].lower())
        self.assertIn("exact human confirmation", params["confirmation"].lower())
        self.assertIn("do not synthesize", params["confirmation"].lower())

    def test_preflight_and_execute_contracts_link_each_other(self) -> None:
        self.assertIn(
            "workspace_integrate_development_session",
            INTEGRATION_PREFLIGHT_CONTRACT.description,
        )
        self.assertIn(
            "workspace_integration_preflight",
            INTEGRATION_EXECUTE_CONTRACT.description,
        )

    def test_annotations_match_bounded_mutation_semantics(self) -> None:
        annotations = INTEGRATION_EXECUTE_CONTRACT.annotations
        self.assertFalse(annotations["readOnlyHint"])
        self.assertTrue(annotations["destructiveHint"])
        self.assertFalse(annotations["idempotentHint"])
        self.assertFalse(annotations["openWorldHint"])


if __name__ == "__main__":
    unittest.main()
