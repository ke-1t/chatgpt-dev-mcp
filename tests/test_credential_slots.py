import unittest

from chatgpt_dev_mcp.credential_slots import CredentialSlotError, CredentialSlotManager, CredentialSlotPolicy


class CredentialSlotTests(unittest.TestCase):
    def _manager(self):
        return CredentialSlotManager(
            [CredentialSlotPolicy("DEMO_SLOT", "env", "DEMO_SOURCE", ("probe",), ("repo",))],
            environ={"DEMO_SOURCE": "opaque-fixture-value"},
        )

    def test_list_never_returns_material(self):
        listed = self._manager().list_slots(project_id="repo")
        self.assertEqual(listed[0]["slot"], "DEMO_SLOT")
        self.assertTrue(listed[0]["available"])
        self.assertEqual(listed[0]["value"], "hidden")
        self.assertNotIn("opaque-fixture-value", repr(listed))

    def test_unauthorized_profile_or_project_denied(self):
        manager = self._manager()
        with self.assertRaises(CredentialSlotError):
            manager.preflight("DEMO_SLOT", project_id="repo", command_profile="other")
        with self.assertRaises(CredentialSlotError):
            manager.preflight("DEMO_SLOT", project_id="other", command_profile="probe")

    def test_grant_is_one_shot_and_value_not_exposed(self):
        manager = self._manager()
        grant = manager.preflight("DEMO_SLOT", project_id="repo", command_profile="probe")
        self.assertEqual(grant["value"], "hidden")
        env, redact_values = manager.consume_grants([grant["grant_id"]], project_id="repo", command_profile="probe")
        self.assertEqual(env, {"DEMO_SLOT": "opaque-fixture-value"})
        self.assertEqual(redact_values, ("opaque-fixture-value",))
        with self.assertRaises(CredentialSlotError):
            manager.consume_grants([grant["grant_id"]], project_id="repo", command_profile="probe")

    def test_validate_slot_access_checks_policy_and_availability_without_reading_material(self):
        reads = []
        manager = CredentialSlotManager(
            [CredentialSlotPolicy("DEMO_SLOT", "keychain", "demo-service", ("probe",), ("repo",))],
            environ={},
            keychain_available=lambda source_name: source_name == "demo-service",
            keychain_reader=lambda source_name: reads.append(source_name) or "must-not-be-read",
        )

        slot = manager.validate_slot_access("DEMO_SLOT", project_id="repo", command_profile="probe")

        self.assertEqual(slot, "DEMO_SLOT")
        self.assertEqual(reads, [])
        with self.assertRaises(CredentialSlotError):
            manager.validate_slot_access("DEMO_SLOT", project_id="repo", command_profile="other")

    def test_restart_has_no_grants(self):
        manager = self._manager()
        grant = manager.preflight("DEMO_SLOT", project_id="repo", command_profile="probe")
        restarted = self._manager()
        with self.assertRaises(CredentialSlotError):
            restarted.consume_grants([grant["grant_id"]], project_id="repo", command_profile="probe")


if __name__ == "__main__":
    unittest.main()
