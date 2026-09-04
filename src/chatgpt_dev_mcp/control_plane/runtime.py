"""Versioned Control Plane runtime independent of public tool registries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .contracts import (
    CONTROL_PLANE_CONTRACT_REVISION,
    REQUIRED_CAPABILITIES,
    AdapterBinding,
    ControlPlaneError,
)


CapabilityHandler = Callable[[dict[str, object]], Mapping[str, object]]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class ControlPlaneRelease:
    """Identity of one installed Control Plane release."""

    release_id: str
    contract_revision: str
    install_root: Path
    development_root: Path

    def __post_init__(self) -> None:
        if not isinstance(self.release_id, str) or not self.release_id.strip():
            raise ControlPlaneError("CONTROL_PLANE_RELEASE_INVALID", "release id is required")
        if self.contract_revision != CONTROL_PLANE_CONTRACT_REVISION:
            raise ControlPlaneError(
                "CONTROL_PLANE_CONTRACT_UNSUPPORTED",
                "release contract revision is unsupported",
            )
        install = Path(self.install_root).expanduser().resolve()
        development = Path(self.development_root).expanduser().resolve()
        if install == development or _is_relative_to(install, development) or _is_relative_to(development, install):
            raise ControlPlaneError(
                "CONTROL_PLANE_ROOTS_OVERLAP",
                "Control Plane release and development roots must be disjoint",
            )
        object.__setattr__(self, "install_root", install)
        object.__setattr__(self, "development_root", development)


class ControlPlaneRuntime:
    """Dispatch common capability ids without consulting public schema versions."""

    def __init__(self, release: ControlPlaneRelease, handlers: Mapping[str, CapabilityHandler]) -> None:
        supplied = dict(handlers)
        missing = [capability_id for capability_id in REQUIRED_CAPABILITIES if capability_id not in supplied]
        if missing:
            raise ControlPlaneError("CONTROL_PLANE_HANDLER_MISSING", "required capability handler is missing")
        unknown = [capability_id for capability_id in supplied if capability_id not in REQUIRED_CAPABILITIES]
        if unknown:
            raise ControlPlaneError("CONTROL_PLANE_HANDLER_UNKNOWN", "unknown capability handler was supplied")
        if any(not callable(supplied[capability_id]) for capability_id in REQUIRED_CAPABILITIES):
            raise ControlPlaneError("CONTROL_PLANE_HANDLER_INVALID", "capability handler must be callable")
        self.release = release
        self._handlers = MappingProxyType(supplied)

    def call(self, capability_id: str, params: Mapping[str, object] | None = None) -> Mapping[str, object]:
        if capability_id not in REQUIRED_CAPABILITIES:
            raise ControlPlaneError("CONTROL_PLANE_CAPABILITY_UNKNOWN", "unknown Control Plane capability")
        handler = self._handlers.get(capability_id)
        if handler is None:
            raise ControlPlaneError("CONTROL_PLANE_HANDLER_MISSING", "capability handler is unavailable")
        return handler(dict(params or {}))

    def diagnostics(self) -> dict[str, object]:
        return {
            "release_id": self.release.release_id,
            "contract_revision": self.release.contract_revision,
            "install_root": str(self.release.install_root),
            "development_root": str(self.release.development_root),
            "capabilities": list(REQUIRED_CAPABILITIES),
        }


class ControlPlaneAdapter:
    """Thin public adapter over one common Control Plane runtime."""

    def __init__(self, runtime: ControlPlaneRuntime, binding: AdapterBinding) -> None:
        self.runtime = runtime
        self.binding = binding

    def call(self, public_name: str, params: Mapping[str, object] | None = None) -> Mapping[str, object]:
        capability_id = self.binding.operations.get(public_name)
        if capability_id is None:
            raise ControlPlaneError(
                "CONTROL_PLANE_ADAPTER_OPERATION_UNKNOWN",
                "public operation is not mapped by this adapter",
            )
        return self.runtime.call(capability_id, params)

    def diagnostics(self) -> dict[str, object]:
        return {
            "adapter_id": self.binding.adapter_id,
            "public_schema_revision": self.binding.public_schema_revision,
            "control_plane_release_id": self.runtime.release.release_id,
            "contract_revision": self.runtime.release.contract_revision,
        }


__all__ = ["CapabilityHandler", "ControlPlaneAdapter", "ControlPlaneRelease", "ControlPlaneRuntime"]
