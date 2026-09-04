from __future__ import annotations

from dataclasses import dataclass, replace as dataclass_replace
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


CLIENT_SCHEMA_UNSUPPORTED_REASON = "CLIENT_INJECTED_SCHEMA_NOT_REPORTED_BY_MCP_TRANSPORT"


@dataclass(frozen=True, slots=True)
class ClientSchemaEvidence:
    status: str
    reason: str
    caller_provided: bool
    server_observed: bool
    safe_for_server_side_recovery: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "caller_provided": self.caller_provided,
            "server_observed": self.server_observed,
            "safe_for_server_side_recovery": self.safe_for_server_side_recovery,
        }

    @classmethod
    def unsupported_transport(cls) -> "ClientSchemaEvidence":
        return cls(
            status="unsupported",
            reason=CLIENT_SCHEMA_UNSUPPORTED_REASON,
            caller_provided=False,
            server_observed=False,
            safe_for_server_side_recovery=True,
        )


def classify_client_schema_evidence(
    *,
    local_schema: Mapping[str, Any],
    client_schema: Mapping[str, Any] | None,
    transport_reports_client_schema: bool,
) -> ClientSchemaEvidence:
    """Classify only explicit client-schema evidence; never infer it from server tools/list."""

    if client_schema is None:
        if not transport_reports_client_schema:
            return ClientSchemaEvidence.unsupported_transport()
        return ClientSchemaEvidence(
            status="unavailable",
            reason="CLIENT_SCHEMA_EVIDENCE_MISSING",
            caller_provided=False,
            server_observed=False,
            safe_for_server_side_recovery=False,
        )

    server_observed = bool(transport_reports_client_schema)
    caller_provided = not server_observed

    if str(client_schema.get("revision", "")) != str(local_schema.get("revision", "")):
        return ClientSchemaEvidence(
            status="stale",
            reason="CLIENT_SCHEMA_REVISION_STALE",
            caller_provided=caller_provided,
            server_observed=server_observed,
            safe_for_server_side_recovery=False,
        )

    if (
        client_schema.get("count") != local_schema.get("count")
        or str(client_schema.get("hash", "")) != str(local_schema.get("hash", ""))
    ):
        return ClientSchemaEvidence(
            status="mismatch",
            reason="CLIENT_SCHEMA_METADATA_MISMATCH",
            caller_provided=caller_provided,
            server_observed=server_observed,
            safe_for_server_side_recovery=False,
        )

    return ClientSchemaEvidence(
        status="current",
        reason="CLIENT_SCHEMA_MATCH",
        caller_provided=caller_provided,
        server_observed=server_observed,
        safe_for_server_side_recovery=True,
    )


@dataclass(frozen=True, slots=True)
class RecoveryInputs:
    same_workspace: bool
    same_owner: bool
    same_task: bool
    canonical_head_compatible: bool
    worktree_exists: bool
    conflicting_writer_lease: bool
    newer_superseding_session: bool
    integration_in_progress: bool
    external_execution: bool
    external_execution_in_progress: bool
    persistence_healthy: bool
    registry_current: bool
    approval_boundary_unchanged: bool
    session_recoverable: bool
    client_schema_evidence: ClientSchemaEvidence

    def replace(self, **changes: Any) -> "RecoveryInputs":
        return dataclass_replace(self, **changes)

    @classmethod
    def safe_fixture(cls, *, schema_evidence: ClientSchemaEvidence) -> "RecoveryInputs":
        return cls(
            same_workspace=True,
            same_owner=True,
            same_task=True,
            canonical_head_compatible=True,
            worktree_exists=True,
            conflicting_writer_lease=False,
            newer_superseding_session=False,
            integration_in_progress=False,
            external_execution=False,
            external_execution_in_progress=False,
            persistence_healthy=True,
            registry_current=True,
            approval_boundary_unchanged=True,
            session_recoverable=True,
            client_schema_evidence=schema_evidence,
        )


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    safe_to_resume: bool
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"safe_to_resume": self.safe_to_resume, "reasons": list(self.reasons)}


def evaluate_safe_resume(inputs: RecoveryInputs) -> RecoveryDecision:
    """Evaluate all recovery gates as one deterministic fail-closed AND decision."""

    reasons: list[str] = []
    if not inputs.same_workspace:
        reasons.append("WORKSPACE_MISMATCH")
    if not inputs.same_owner:
        reasons.append("OWNER_MISMATCH")
    if not inputs.same_task:
        reasons.append("TASK_MISMATCH")
    if not inputs.canonical_head_compatible:
        reasons.append("CANONICAL_HEAD_CHANGED")
    if not inputs.worktree_exists:
        reasons.append("WORKTREE_MISSING")
    if inputs.conflicting_writer_lease:
        reasons.append("CONFLICTING_WRITER_LEASE")
    if inputs.newer_superseding_session:
        reasons.append("NEWER_SUPERSEDING_SESSION")
    if inputs.integration_in_progress:
        reasons.append("INTEGRATION_IN_PROGRESS")
    if inputs.external_execution:
        reasons.append("EXTERNAL_EXECUTION_ENABLED")
    if inputs.external_execution_in_progress:
        reasons.append("EXTERNAL_EXECUTION_IN_PROGRESS")
    if not inputs.persistence_healthy:
        reasons.append("PERSISTENCE_UNHEALTHY")
    if not inputs.registry_current:
        reasons.append("REGISTRY_STALE")
    if not inputs.approval_boundary_unchanged:
        reasons.append("APPROVAL_BOUNDARY_CHANGED")
    if not inputs.session_recoverable:
        reasons.append("SESSION_NOT_RECOVERABLE")

    evidence = inputs.client_schema_evidence
    if not evidence.safe_for_server_side_recovery:
        status_reason = {
            "stale": "CLIENT_SCHEMA_STALE",
            "mismatch": "CLIENT_SCHEMA_MISMATCH",
            "unavailable": "CLIENT_SCHEMA_UNAVAILABLE",
        }.get(evidence.status, "CLIENT_SCHEMA_UNSAFE")
        reasons.append(status_reason)

    return RecoveryDecision(safe_to_resume=not reasons, reasons=tuple(reasons))


def persistence_db_identity(path: Path, *, schema_version: int) -> str:
    """Fingerprint the durable DB file identity, not its mutable contents."""

    resolved = path.expanduser().resolve(strict=True)
    stat_result = resolved.stat()
    payload = {
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "path": str(resolved),
        "schema_version": int(schema_version),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_reattach_handshake(
    *,
    child_instance_id: str,
    logical_connection_id: str,
    server_revision: str,
    registry_version: str,
    registry_hash: str,
    schema_revision: str,
    schema_digest: str,
    director_generation: str,
    persistence_db_identity: str,
) -> dict[str, str]:
    """Return only explicit identity evidence required to reason about a reattach."""

    return {
        "child_instance_id": child_instance_id,
        "logical_connection_id": logical_connection_id,
        "server_revision": server_revision,
        "registry_version": registry_version,
        "registry_hash": registry_hash,
        "schema_revision": schema_revision,
        "schema_digest": schema_digest,
        "director_generation": director_generation,
        "persistence_db_identity": persistence_db_identity,
    }
