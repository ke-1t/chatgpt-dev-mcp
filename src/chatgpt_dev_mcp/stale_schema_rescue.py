"""Narrow compatibility primitives for stale ChatGPT tool snapshots."""

from __future__ import annotations

import re


TRUST_ENABLE_RESCUE_PREFIX = "compat:workspace.trust.enable:"
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class StaleSchemaRescueError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_trust_enable_rescue_identifier(identifier: object) -> str | None:
    if not isinstance(identifier, str) or not identifier.startswith("compat:"):
        return None
    if not identifier.startswith(TRUST_ENABLE_RESCUE_PREFIX):
        raise StaleSchemaRescueError(
            "COMPAT_RESCUE_OPERATION_DENIED",
            "Only the reserved workspace.trust.enable compatibility operation is supported.",
        )
    workspace_id = identifier[len(TRUST_ENABLE_RESCUE_PREFIX) :]
    if not _WORKSPACE_ID_RE.fullmatch(workspace_id):
        raise StaleSchemaRescueError(
            "COMPAT_RESCUE_IDENTIFIER_INVALID",
            "The compatibility rescue identifier contains an invalid workspace id.",
        )
    return workspace_id


__all__ = [
    "StaleSchemaRescueError",
    "TRUST_ENABLE_RESCUE_PREFIX",
    "parse_trust_enable_rescue_identifier",
]
