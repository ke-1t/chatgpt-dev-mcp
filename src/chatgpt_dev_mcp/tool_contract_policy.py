"""Shared public-tool contract semantics for Stable and Canary adapters.

This module deliberately contains no public-registry version checks.  It
describes safety semantics that may be rendered by v25 Stable, v26 Canary,
or a local CLI adapter without changing the underlying control capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ToolContract:
    name: str
    description: str
    parameters: Mapping[str, str]
    annotations: Mapping[str, bool | str]


INTEGRATION_PREFLIGHT_CONTRACT = ToolContract(
    name="workspace_integration_preflight",
    description=(
        "Read-only preflight for one managed DEVELOPMENT session. It checks "
        "canonical state, exact patch identity, verification evidence, security "
        "evidence, and conflicts without mutating the repository, task, session, "
        "or lease state. It appends only bounded, non-secret preflight evidence "
        "and an exact integration intent needed by the paired execute path. When ready, "
        "it returns the only short-lived human approval challenge accepted by "
        "workspace_integrate_development_session for that exact state; it never "
        "applies the patch or grants repository authority."
    ),
    parameters={
        "session_id": (
            "Managed DEVELOPMENT session identifier whose exact current patch "
            "and evidence should be evaluated."
        ),
    },
    annotations={
        "title": "Preflight DEVELOPMENT integration",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)


INTEGRATION_EXECUTE_CONTRACT = ToolContract(
    name="workspace_integrate_development_session",
    description=(
        "Apply exactly one previously verified managed DEVELOPMENT-session patch "
        "to the canonical working tree. Use this only after the user explicitly "
        "approves the current challenge returned by workspace_integration_preflight. "
        "The caller cannot provide arbitrary patch content or arbitrary paths. "
        "Before writing, the server revalidates the managed session identity, "
        "canonical HEAD, exact patch hash, verification receipt, security audit "
        "receipt, and the short-lived one-shot approval. Any mismatch fails closed "
        "before mutation. This operation only applies the preflight-pinned patch; "
        "it never commits, never pushes, never checks out branches, never resets, "
        "never stashes, never cleans, never deletes unrelated changes, and never "
        "executes arbitrary shell commands."
    ),
    parameters={
        "session_id": (
            "Managed DEVELOPMENT session ID from the successful current "
            "workspace_integration_preflight. It must identify the exact session "
            "bound to the approval challenge."
        ),
        "approval_token": (
            "Short-lived, one-shot execution challenge issued by the current "
            "workspace_integration_preflight for the exact session and state. "
            "Do not reuse a token from an older preflight, another session, or a "
            "different canonical revision."
        ),
        "confirmation": (
            "Exact human confirmation string returned by the current preflight. "
            "Do not synthesize, paraphrase, or reconstruct this confirmation."
        ),
    },
    annotations={
        "title": "Integrate verified DEVELOPMENT session",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)


_REQUIRED_DESCRIPTION_MARKERS = (
    "explicitly approves",
    "cannot provide arbitrary",
    "canonical head",
    "patch hash",
    "verification receipt",
    "security audit",
    "one-shot",
    "fails closed",
)


def validate_contract(contract: ToolContract) -> list[str]:
    """Return bounded human-readable contract findings; empty means compliant."""

    findings: list[str] = []
    description = contract.description.lower()
    if contract.name == "workspace_integrate_development_session":
        for marker in _REQUIRED_DESCRIPTION_MARKERS:
            if marker not in description:
                findings.append(f"missing description marker: {marker}")
        for parameter in ("session_id", "approval_token", "confirmation"):
            if not contract.parameters.get(parameter):
                findings.append(f"missing parameter guidance: {parameter}")
        expected = {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        }
        for key, value in expected.items():
            if contract.annotations.get(key) is not value:
                findings.append(f"incorrect annotation: {key}")
    return findings


__all__ = [
    "INTEGRATION_EXECUTE_CONTRACT",
    "INTEGRATION_PREFLIGHT_CONTRACT",
    "ToolContract",
    "validate_contract",
]
