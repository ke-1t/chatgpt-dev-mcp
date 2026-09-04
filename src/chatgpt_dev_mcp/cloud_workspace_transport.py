"""Transport-neutral models for ChatGPT-managed workspace handoff."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from .cloud_workspace_package import CloudWorkspacePackage


PROVIDER_ID = "chatgpt_managed_cloud"
MAX_DIAGNOSTIC_STAGE_BYTES = 1 * 1024 * 1024


class CloudWorkspaceTransportError(RuntimeError):
    pass


@dataclass(frozen=True)
class CloudWorkspaceTransportStatus:
    available: bool
    reason: str
    provider_id: str = PROVIDER_ID


@dataclass(frozen=True)
class CloudWorkspaceRef:
    ref_id: str
    package_id: str
    provider_id: str
    staged_bytes: int


@dataclass(frozen=True)
class CloudWorkspaceResultRef:
    ref_id: str
    package_id: str
    provider_id: str = PROVIDER_ID


@dataclass(frozen=True)
class CloudWorkspaceResultPackage:
    source_revision: str
    package_id: str
    workload_id: str
    changed_paths: tuple[str, ...]
    patch: str
    patch_hash: str
    execution_summary: str
    stage_metrics: tuple[tuple[str, float], ...]
    input_bytes: int
    output_bytes: int
    cloud_fingerprint: str
    artifact_hashes: tuple[tuple[str, str], ...]
    billable_api: bool


class CloudWorkspaceTransport(Protocol):
    def status(self) -> CloudWorkspaceTransportStatus: ...
    def stage(self, package: CloudWorkspacePackage) -> CloudWorkspaceRef: ...
    def fetch_result(self, ref: CloudWorkspaceResultRef) -> CloudWorkspaceResultPackage: ...


class InMemoryCloudWorkspaceTransport:
    """Bounded test transport; it is not a production ChatGPT handoff."""

    def __init__(self, *, available: bool = True, reason: str = "ready") -> None:
        self._available = bool(available)
        self._reason = str(reason)[:160]
        self._packages: dict[str, CloudWorkspacePackage] = {}
        self._results: dict[str, CloudWorkspaceResultPackage] = {}

    def status(self) -> CloudWorkspaceTransportStatus:
        return CloudWorkspaceTransportStatus(self._available, self._reason)

    def stage(self, package: CloudWorkspacePackage) -> CloudWorkspaceRef:
        if not self._available:
            raise CloudWorkspaceTransportError("managed cloud transport is unavailable")
        if not isinstance(package, CloudWorkspacePackage):
            raise CloudWorkspaceTransportError("package is invalid")
        if package.payload_bytes < 0 or package.payload_bytes > MAX_DIAGNOSTIC_STAGE_BYTES:
            raise CloudWorkspaceTransportError("diagnostic transport byte limit exceeded")
        if package.payload_bytes != len(package.payload):
            raise CloudWorkspaceTransportError("package byte count does not match payload")
        ref_id = f"cloud-workspace:{hashlib.sha256((package.package_id + package.manifest_hash).encode()).hexdigest()[:32]}"
        self._packages[ref_id] = package
        return CloudWorkspaceRef(ref_id, package.package_id, PROVIDER_ID, package.payload_bytes)

    def set_result(self, ref_id: str, result: CloudWorkspaceResultPackage) -> CloudWorkspaceResultRef:
        package = self._packages.get(ref_id)
        if package is None or result.package_id != package.package_id:
            raise CloudWorkspaceTransportError("result does not match staged package")
        result_ref = f"cloud-result:{hashlib.sha256((ref_id + result.patch_hash).encode()).hexdigest()[:32]}"
        self._results[result_ref] = result
        return CloudWorkspaceResultRef(result_ref, result.package_id)

    def fetch_result(self, ref: CloudWorkspaceResultRef) -> CloudWorkspaceResultPackage:
        if not self._available:
            raise CloudWorkspaceTransportError("managed cloud transport is unavailable")
        result = self._results.get(ref.ref_id)
        if result is None or result.package_id != ref.package_id or ref.provider_id != PROVIDER_ID:
            raise CloudWorkspaceTransportError("result reference is invalid")
        return result


__all__ = [
    "CloudWorkspaceRef",
    "CloudWorkspaceResultPackage",
    "CloudWorkspaceResultRef",
    "CloudWorkspaceTransport",
    "CloudWorkspaceTransportError",
    "CloudWorkspaceTransportStatus",
    "InMemoryCloudWorkspaceTransport",
    "MAX_DIAGNOSTIC_STAGE_BYTES",
]
