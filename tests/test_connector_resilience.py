from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from chatgpt_dev_mcp.connector_resilience import (
    ClientSchemaEvidence,
    RecoveryInputs,
    build_reattach_handshake,
    classify_client_schema_evidence,
    evaluate_safe_resume,
    persistence_db_identity,
)


LOCAL_SCHEMA = {
    "revision": "tool-registry-v25-stable",
    "count": 52,
    "hash": "a" * 64,
}


def test_client_schema_is_explicitly_unsupported_when_transport_cannot_observe_chatgpt_injection() -> None:
    evidence = classify_client_schema_evidence(
        local_schema=LOCAL_SCHEMA,
        client_schema=None,
        transport_reports_client_schema=False,
    )

    assert evidence.status == "unsupported"
    assert evidence.reason == "CLIENT_INJECTED_SCHEMA_NOT_REPORTED_BY_MCP_TRANSPORT"
    assert evidence.caller_provided is False
    assert evidence.server_observed is False
    assert evidence.safe_for_server_side_recovery is True


def test_client_schema_exact_match_is_current() -> None:
    evidence = classify_client_schema_evidence(
        local_schema=LOCAL_SCHEMA,
        client_schema=dict(LOCAL_SCHEMA),
        transport_reports_client_schema=False,
    )

    assert evidence.status == "current"
    assert evidence.reason == "CLIENT_SCHEMA_MATCH"
    assert evidence.caller_provided is True
    assert evidence.safe_for_server_side_recovery is True


def test_client_schema_revision_change_is_stale_and_hash_change_is_mismatch() -> None:
    stale = classify_client_schema_evidence(
        local_schema=LOCAL_SCHEMA,
        client_schema={**LOCAL_SCHEMA, "revision": "tool-registry-v24-stable"},
        transport_reports_client_schema=False,
    )
    mismatch = classify_client_schema_evidence(
        local_schema=LOCAL_SCHEMA,
        client_schema={**LOCAL_SCHEMA, "hash": "b" * 64},
        transport_reports_client_schema=False,
    )

    assert stale.status == "stale"
    assert stale.safe_for_server_side_recovery is False
    assert mismatch.status == "mismatch"
    assert mismatch.safe_for_server_side_recovery is False


def test_safe_resume_requires_every_recovery_predicate() -> None:
    inputs = RecoveryInputs.safe_fixture(schema_evidence=ClientSchemaEvidence.unsupported_transport())
    decision = evaluate_safe_resume(inputs)

    assert decision.safe_to_resume is True
    assert decision.reasons == ()

    changed_head = evaluate_safe_resume(inputs.replace(canonical_head_compatible=False))
    assert changed_head.safe_to_resume is False
    assert "CANONICAL_HEAD_CHANGED" in changed_head.reasons

    conflict = evaluate_safe_resume(inputs.replace(conflicting_writer_lease=True))
    assert conflict.safe_to_resume is False
    assert "CONFLICTING_WRITER_LEASE" in conflict.reasons

    external = evaluate_safe_resume(inputs.replace(external_execution=False, external_execution_in_progress=True))
    assert external.safe_to_resume is False
    assert "EXTERNAL_EXECUTION_IN_PROGRESS" in external.reasons


def test_safe_resume_rejects_stale_or_mismatched_client_schema_evidence() -> None:
    stale = ClientSchemaEvidence(
        status="stale",
        reason="CLIENT_SCHEMA_REVISION_STALE",
        caller_provided=True,
        server_observed=False,
        safe_for_server_side_recovery=False,
    )
    decision = evaluate_safe_resume(RecoveryInputs.safe_fixture(schema_evidence=stale))

    assert decision.safe_to_resume is False
    assert "CLIENT_SCHEMA_STALE" in decision.reasons


def test_persistence_db_identity_changes_when_underlying_database_is_replaced(tmp_path: Path) -> None:
    db = tmp_path / "director.sqlite3"
    db.write_bytes(b"one")
    first = persistence_db_identity(db, schema_version=10)

    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(b"two")
    replacement.replace(db)
    second = persistence_db_identity(db, schema_version=10)

    assert first != second
    assert len(first) == 64
    assert len(second) == 64


def test_reattach_handshake_contains_only_explicit_identity_evidence(tmp_path: Path) -> None:
    db = tmp_path / "director.sqlite3"
    db.write_bytes(b"fixture")
    db_identity = persistence_db_identity(db, schema_version=10)

    handshake = build_reattach_handshake(
        child_instance_id="child-a",
        logical_connection_id="stdio-connection:3",
        server_revision="0.41",
        registry_version="tool-registry-v25-stable",
        registry_hash="b" * 64,
        schema_revision="tool-registry-v25-stable",
        schema_digest="c" * 64,
        director_generation="director-generation-a",
        persistence_db_identity=db_identity,
    )

    assert handshake["child_instance_id"] == "child-a"
    assert handshake["logical_connection_id"] == "stdio-connection:3"
    assert handshake["server_revision"] == "0.41"
    assert handshake["registry_hash"] == "b" * 64
    assert handshake["schema_digest"] == "c" * 64
    assert handshake["director_generation"] == "director-generation-a"
    assert handshake["persistence_db_identity"] == db_identity


class StaleSchemaCanonicalBindingTests(unittest.TestCase):
    def test_stale_schema_rescue_pins_registered_canonical_worktree(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        runtime = object.__new__(WrapperRuntime)
        registered_entry = SimpleNamespace(profile="DEVELOPMENT")
        with (
            patch(
                "chatgpt_dev_mcp.server.load_registry",
                return_value=(Path("/tmp/config.json"), {"fixture": registered_entry}, [], []),
            ),
            patch.object(
                runtime,
                "_director_working_tree_id",
                return_value="worktree:canonical-fixture",
            ),
        ):
            args = runtime._stale_schema_canonical_context_args("fixture")

        self.assertEqual(
            args,
            {
                "workspace_id": "fixture",
                "working_tree_id": "worktree:canonical-fixture",
            },
        )
