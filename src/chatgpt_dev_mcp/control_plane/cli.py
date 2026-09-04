"""Local CLI adapter over the common Control Plane runtime."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .contracts import ControlPlaneError
from .runtime import ControlPlaneRuntime


CLI_CAPABILITY_MAP = MappingProxyType({
    "session status": "control.session.status",
    "integration preflight": "control.integration.preflight",
    "integration apply": "control.integration.apply",
    "integration resume": "control.integration.resume",
    "git stage-paths": "control.git.stage_paths",
    "git commit-preflight": "control.git.commit_preflight",
    "doctor": "control.doctor",
})


class LocalCLIAdapter:
    def __init__(self, runtime: ControlPlaneRuntime) -> None:
        self.runtime = runtime

    def call(self, command: str, params: Mapping[str, object] | None = None) -> Mapping[str, object]:
        capability_id = CLI_CAPABILITY_MAP.get(command)
        if capability_id is None:
            raise ControlPlaneError("CONTROL_PLANE_CLI_COMMAND_UNKNOWN", "local CLI command is not mapped to a Control Plane capability")
        return self.runtime.call(capability_id, params)


__all__ = ["CLI_CAPABILITY_MAP", "LocalCLIAdapter"]
