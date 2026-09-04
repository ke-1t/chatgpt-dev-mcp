"""ChatGPT-managed cloud adapter over an orchestration-provided file transport."""

from __future__ import annotations

from collections.abc import Callable

from .cloud_workspace_package import CloudWorkspacePackage
from .cloud_workspace_transport import (
    CloudWorkspaceRef,
    CloudWorkspaceResultPackage,
    CloudWorkspaceResultRef,
    CloudWorkspaceTransport,
    CloudWorkspaceTransportError,
    PROVIDER_ID,
)


class ChatGPTManagedCloudAdapterError(RuntimeError):
    pass


class ChatGPTManagedCloudAdapter:
    """Use a supported ChatGPT file-handoff transport when orchestration injects one.

    DevMCP deliberately has no built-in private ChatGPT path, URL, credential, or
    Responses-API substitute. Without an orchestration-owned transport/executor
    pair the managed substrate is explicitly unavailable.
    """

    def __init__(
        self,
        *,
        transport: CloudWorkspaceTransport | None = None,
        executor: Callable[[CloudWorkspaceRef], CloudWorkspaceResultRef] | None = None,
    ) -> None:
        self._transport = transport
        self._executor = executor

    def status(self) -> dict[str, object]:
        base = {
            "provider_id": PROVIDER_ID,
            "billable_api": False,
            "credential_required": False,
        }
        if self._transport is None or self._executor is None:
            return {**base, "available": False, "reason": "supported_file_handoff_unavailable"}
        status = self._transport.status()
        if status.provider_id != PROVIDER_ID:
            return {**base, "available": False, "reason": "provider_identity_mismatch"}
        return {**base, "available": status.available is True, "reason": str(status.reason)[:160]}

    def execute(self, payload: object) -> CloudWorkspaceResultPackage:
        status = self.status()
        if status["available"] is not True or self._transport is None or self._executor is None:
            raise ChatGPTManagedCloudAdapterError(str(status["reason"]))
        if not isinstance(payload, CloudWorkspacePackage):
            raise ChatGPTManagedCloudAdapterError("managed cloud payload must be a CloudWorkspacePackage")
        try:
            workspace_ref = self._transport.stage(payload)
            if workspace_ref.provider_id != PROVIDER_ID or workspace_ref.package_id != payload.package_id:
                raise ChatGPTManagedCloudAdapterError("staged workspace reference does not match package")
            result_ref = self._executor(workspace_ref)
            if not isinstance(result_ref, CloudWorkspaceResultRef):
                raise ChatGPTManagedCloudAdapterError("executor returned an invalid result reference")
            if result_ref.provider_id != PROVIDER_ID or result_ref.package_id != payload.package_id:
                raise ChatGPTManagedCloudAdapterError("result reference does not match package")
            result = self._transport.fetch_result(result_ref)
        except ChatGPTManagedCloudAdapterError:
            raise
        except CloudWorkspaceTransportError as exc:
            raise ChatGPTManagedCloudAdapterError("managed cloud transport failed") from exc
        if result.billable_api:
            raise ChatGPTManagedCloudAdapterError("managed cloud result unexpectedly consumed billable API")
        if result.package_id != payload.package_id or result.source_revision != payload.source_revision:
            raise ChatGPTManagedCloudAdapterError("managed cloud result identity mismatch")
        return result


__all__ = ["ChatGPTManagedCloudAdapter", "ChatGPTManagedCloudAdapterError"]
