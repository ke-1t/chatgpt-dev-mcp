from __future__ import annotations

import unittest

from chatgpt_dev_mcp.request_lifecycle import (
    RequestConflict,
    RequestRegistry,
    RequestState,
    SideEffectClass,
    recovery_activity_evidence,
    safe_retry_decision,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class RequestLifecycleRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.registry = RequestRegistry(
            child_instance_id="child-test",
            transport_generation=1,
            clock=self.clock,
            heartbeat_timeout_seconds=5,
            terminal_ttl_seconds=20,
            max_entries=8,
        )

    def test_request_state_machine_has_idempotent_terminal_completion(self) -> None:
        record = self.registry.accept(
            1,
            "server_info",
            side_effect_class=SideEffectClass.READ_ONLY,
        )
        self.assertEqual(record.state, RequestState.ACCEPTED)
        self.assertEqual(self.registry.start(1).state, RequestState.RUNNING)
        self.assertEqual(self.registry.mark_completing(1).state, RequestState.COMPLETING)
        self.assertEqual(self.registry.complete(1).state, RequestState.COMPLETED)
        self.assertEqual(self.registry.complete(1).state, RequestState.COMPLETED)
        self.assertEqual(self.registry.snapshot()["active_request_count"], 0)

    def test_terminal_event_contains_duration_and_is_forwarded_to_sink(self) -> None:
        events: list[dict[str, object]] = []
        registry = RequestRegistry(child_instance_id="child-sink", clock=self.clock, event_sink=events.append)
        registry.accept("request-1", "server_info")
        registry.start("request-1")
        self.clock.advance(0.25)
        record = registry.complete("request-1")
        self.assertEqual(record.duration_ms, 250.0)
        terminal = next(event for event in events if event["event"] == "REQUEST_TERMINAL")
        self.assertEqual(terminal["duration_ms"], 250.0)
        self.assertEqual(terminal["request_id"], "request-1")
        self.assertNotIn("arguments", terminal)

    def test_stale_terminal_request_id_is_reaped_before_next_request(self) -> None:
        self.registry.accept("same", "ping")
        self.registry.start("same")
        self.registry.complete("same")
        self.clock.advance(21)
        replacement = self.registry.accept("same", "ping")
        self.assertEqual(replacement.state, RequestState.ACCEPTED)
        self.assertEqual(self.registry.snapshot()["reconciled_request_count"], 1)

    def test_completed_id_can_be_reused_for_a_different_method(self) -> None:
        self.registry.accept(0, "initialize")
        self.registry.start(0)
        self.registry.complete(0)
        replacement = self.registry.accept(0, "server_info")
        self.assertEqual(replacement.state, RequestState.ACCEPTED)

    def test_completed_read_only_id_can_be_reused_for_the_same_method(self) -> None:
        self.registry.accept("same-read", "workspace_status", side_effect_class=SideEffectClass.READ_ONLY)
        self.registry.start("same-read")
        self.registry.complete("same-read")

        replacement = self.registry.accept(
            "same-read",
            "workspace_status",
            side_effect_class=SideEffectClass.READ_ONLY,
        )

        self.assertEqual(replacement.state, RequestState.ACCEPTED)
        self.assertEqual(replacement.key.request_id, "same-read")

    def test_failed_read_only_id_can_be_reused_for_the_same_method_before_ttl(self) -> None:
        self.registry.accept("failed-read", "workspace_list", side_effect_class=SideEffectClass.READ_ONLY)
        self.registry.start("failed-read")
        self.registry.fail("failed-read", reason="upstream_transport_unavailable")

        replacement = self.registry.accept(
            "failed-read",
            "workspace_list",
            side_effect_class=SideEffectClass.READ_ONLY,
        )

        self.assertEqual(replacement.state, RequestState.ACCEPTED)

    def test_same_id_is_still_blocked_while_read_only_request_is_active(self) -> None:
        self.registry.accept("active-read", "workspace_status", side_effect_class=SideEffectClass.READ_ONLY)
        self.registry.start("active-read")

        with self.assertRaises(RequestConflict) as raised:
            self.registry.accept("active-read", "workspace_status", side_effect_class=SideEffectClass.READ_ONLY)

        self.assertEqual(raised.exception.reason, "request_already_active")

    def test_completed_write_id_can_be_reused_after_response(self) -> None:
        self.registry.accept("write-id", "apply_patch", side_effect_class=SideEffectClass.LOCAL_WRITE)
        self.registry.start("write-id")
        self.registry.mark_side_effect_started("write-id")
        self.registry.complete("write-id")

        replacement = self.registry.accept("write-id", "apply_patch", side_effect_class=SideEffectClass.LOCAL_WRITE)

        self.assertEqual(replacement.state, RequestState.ACCEPTED)

    def test_ambiguous_write_id_reuse_remains_fail_closed(self) -> None:
        self.registry.accept("write-id", "apply_patch", side_effect_class=SideEffectClass.LOCAL_WRITE)
        self.registry.start("write-id")
        self.registry.mark_side_effect_started("write-id")
        self.registry.disconnect("write-id", reason="response_lost")

        with self.assertRaises(RequestConflict) as raised:
            self.registry.accept("write-id", "apply_patch", side_effect_class=SideEffectClass.LOCAL_WRITE)

        self.assertEqual(raised.exception.reason, "request_id_reuse")
        self.assertTrue(raised.exception.record.side_effect_started)
        self.assertEqual(raised.exception.record.state, RequestState.OUTCOME_UNKNOWN)

    def test_live_operation_remains_blocked(self) -> None:
        self.registry.accept(
            "running",
            "run_task",
            operation_key="task:one",
            side_effect_class=SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
        )
        self.registry.start("running")
        self.clock.advance(6)
        with self.assertRaises(RequestConflict) as raised:
            self.registry.accept("next", "run_task", operation_key="task:one")
        self.assertEqual(raised.exception.record.state, RequestState.RUNNING)
        self.assertEqual(raised.exception.reason, "operation_already_started")

    def test_stale_operation_without_side_effect_is_recovered(self) -> None:
        self.registry.accept("stale", "read", operation_key="read:one")
        self.registry.start("stale")
        self.clock.advance(6)
        replacement = self.registry.accept("next", "read", operation_key="read:one")
        self.assertEqual(replacement.state, RequestState.ACCEPTED)
        self.assertEqual(self.registry.get("stale").state, RequestState.DISCONNECTED)

    def test_disconnect_after_side_effect_is_outcome_unknown(self) -> None:
        self.registry.accept("write", "apply_patch", side_effect_class=SideEffectClass.LOCAL_WRITE)
        self.registry.start("write")
        self.registry.mark_side_effect_started("write")
        record = self.registry.disconnect("write", reason="client_disconnect")
        self.assertEqual(record.state, RequestState.OUTCOME_UNKNOWN)
        self.assertTrue(record.side_effect_started)
        self.assertEqual(self.registry.snapshot()["outcome_unknown_count"], 1)

    def test_old_generation_cannot_complete_current_request(self) -> None:
        self.registry.accept("old", "server_info")
        old_key = self.registry.key("old")
        self.registry.retire_generation()
        self.registry.accept("new", "server_info")
        self.assertIsNone(self.registry.complete_key(old_key))
        self.assertEqual(self.registry.get("new").state, RequestState.ACCEPTED)

    def test_late_event_keeps_record_generation_and_accepted_schema_identity(self) -> None:
        events: list[dict[str, object]] = []
        registry = RequestRegistry(
            child_instance_id="child-generation",
            transport_generation=1,
            clock=self.clock,
            event_sink=events.append,
        )
        registry.accept(
            "old",
            "server_info",
            metadata={
                "logical_connection_id": "logical:old",
                "server_schema_revision": "tool-registry-v25-stable",
                "server_schema_hash": "a" * 64,
                "request_accepted": "1",
            },
        )
        old = registry.get("old")
        registry.retire_generation()
        registry.emit("old", "LATE_DIAGNOSTIC", generation=old.key.transport_generation)
        registry.annotate(
            "old",
            generation=old.key.transport_generation,
            server_schema_revision="tool-registry-v26-canary",
            server_schema_hash="b" * 64,
            logical_connection_id="logical:new",
        )
        late = next(event for event in events if event["event"] == "LATE_DIAGNOSTIC")
        self.assertEqual(late["transport_generation"], old.key.transport_generation)
        self.assertEqual(late["server_schema_revision"], "tool-registry-v25-stable")
        self.assertEqual(late["server_schema_hash"], "a" * 64)
        self.assertEqual(late["logical_connection_id"], "logical:old")

    def test_process_probe_reconciles_exited_but_not_live_process(self) -> None:
        self.registry.accept("exited", "run_task", operation_key="process:e")
        self.registry.start("exited")
        self.registry.attach_process("exited", "proc-exited")
        self.registry.accept("live", "run_task", operation_key="process:l")
        self.registry.start("live")
        self.registry.attach_process("live", "proc-live")
        self.clock.advance(6)
        self.registry.reconcile_processes(lambda process_id: process_id == "proc-live")
        self.assertEqual(self.registry.get("exited").state, RequestState.TIMED_OUT)
        self.assertEqual(self.registry.get("live").state, RequestState.RUNNING)

    def test_retry_policy_allows_only_one_read_only_pre_side_effect_retry(self) -> None:
        self.assertTrue(safe_retry_decision(SideEffectClass.READ_ONLY, side_effect_started=False, attempts=0))
        self.assertFalse(safe_retry_decision(SideEffectClass.READ_ONLY, side_effect_started=False, attempts=1))
        self.assertFalse(safe_retry_decision(SideEffectClass.LOCAL_WRITE, side_effect_started=False, attempts=0))
        self.assertFalse(safe_retry_decision(SideEffectClass.READ_ONLY, side_effect_started=True, attempts=0))

    def test_recovery_activity_is_scoped_to_target_integration_session(self) -> None:
        self.registry.accept(
            "integrating",
            "workspace_integrate_development_session",
            side_effect_class=SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
            development_session_id="session:target",
        )
        self.registry.start("integrating")
        self.registry.mark_side_effect_started("integrating")

        target = recovery_activity_evidence(
            self.registry.active_records(),
            development_session_id="session:target",
            external_capability=lambda _capability_id: False,
        )
        sibling = recovery_activity_evidence(
            self.registry.active_records(),
            development_session_id="session:sibling",
            external_capability=lambda _capability_id: False,
        )

        self.assertTrue(target.integration_in_progress)
        self.assertFalse(sibling.integration_in_progress)
        self.assertFalse(target.external_execution_in_progress)

    def test_recovery_activity_detects_external_git_and_network_capability(self) -> None:
        self.registry.accept(
            "push",
            "git_push",
            side_effect_class=SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
        )
        self.registry.start("push")
        self.registry.accept(
            "external",
            "capability_execute",
            side_effect_class=SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
            metadata={"capability_id": "external.capability.invoke"},
        )
        self.registry.start("external")

        evidence = recovery_activity_evidence(
            self.registry.active_records(),
            development_session_id="session:target",
            external_capability=lambda capability_id: capability_id == "external.capability.invoke",
        )

        self.assertFalse(evidence.integration_in_progress)
        self.assertTrue(evidence.external_execution_in_progress)

    def test_recovery_activity_fails_closed_for_unclassified_active_capability(self) -> None:
        self.registry.accept(
            "capability",
            "capability_execute",
            side_effect_class=SideEffectClass.OUTCOME_AMBIGUOUS_CAPABLE,
        )
        self.registry.start("capability")

        evidence = recovery_activity_evidence(
            self.registry.active_records(),
            development_session_id="session:target",
            external_capability=lambda _capability_id: False,
        )

        self.assertTrue(evidence.external_execution_in_progress)

    def test_registry_remains_bounded_after_many_cycles(self) -> None:
        for index in range(1000):
            request_id = f"request-{index}"
            self.registry.accept(request_id, "server_info")
            self.registry.start(request_id)
            self.registry.complete(request_id)
            self.clock.advance(0.1)
            self.registry.reconcile()
        self.assertLessEqual(self.registry.size, 8)
        self.assertLessEqual(self.registry.snapshot()["terminal_request_count"], 8)


if __name__ == "__main__":
    unittest.main()
