"""Registry-independent Control Plane capability contracts."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


CONTROL_PLANE_CONTRACT_REVISION = "control-plane-capabilities-v1"

REQUIRED_CAPABILITIES = (
    "control.session.status",
    "control.integration.preflight",
    "control.integration.apply",
    "control.integration.resume",
    "control.git.stage_paths",
    "control.git.commit_preflight",
    "control.doctor",
)


class ControlPlaneError(ValueError):
    """Bounded, fail-closed Control Plane contract error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AdapterBinding:
    """Translate public operation names to common Control Plane capabilities."""

    adapter_id: str
    operations: Mapping[str, str]
    public_schema_revision: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not self.adapter_id.strip():
            raise ControlPlaneError("CONTROL_PLANE_ADAPTER_INVALID", "adapter id is required")
        normalized: dict[str, str] = {}
        for public_name, capability_id in dict(self.operations).items():
            if not isinstance(public_name, str) or not public_name.strip():
                raise ControlPlaneError("CONTROL_PLANE_ADAPTER_INVALID", "public operation name is invalid")
            if capability_id not in REQUIRED_CAPABILITIES:
                raise ControlPlaneError(
                    "CONTROL_PLANE_ADAPTER_CAPABILITY_UNKNOWN",
                    "adapter references an unknown Control Plane capability",
                )
            normalized[public_name] = capability_id
        object.__setattr__(self, "operations", MappingProxyType(normalized))


__all__ = [
    "AdapterBinding",
    "CONTROL_PLANE_CONTRACT_REVISION",
    "ControlPlaneError",
    "REQUIRED_CAPABILITIES",
]
