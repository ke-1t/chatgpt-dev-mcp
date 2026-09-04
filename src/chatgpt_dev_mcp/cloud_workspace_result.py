"""Mac-side validation of result packages returned from managed cloud workspaces."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .cloud_workspace_package import CloudWorkspacePackage
from .cloud_workspace_transport import CloudWorkspaceResultPackage
from .director import contains_secret_like_content, evaluate_patch, normalize_relative_path


MAX_RESULT_PATCH_BYTES = 512 * 1024


class CloudWorkspaceResultError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedCloudWorkspaceResult:
    source_revision: str
    package_id: str
    workload_id: str
    changed_paths: tuple[str, ...]
    patch: str
    patch_hash: str
    cloud_fingerprint: str
    input_bytes: int
    output_bytes: int


def _within_scope(path: str, allowed_paths: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in allowed_paths)


def validate_cloud_workspace_result(
    result: CloudWorkspaceResultPackage,
    *,
    expected_package: CloudWorkspacePackage,
    allowed_paths: tuple[str, ...],
    current_revision: str,
) -> ValidatedCloudWorkspaceResult:
    if not isinstance(result, CloudWorkspaceResultPackage):
        raise CloudWorkspaceResultError("result is invalid")
    if result.package_id != expected_package.package_id or result.source_revision != expected_package.source_revision:
        raise CloudWorkspaceResultError("result package identity mismatch")
    if current_revision != expected_package.source_revision:
        raise CloudWorkspaceResultError("stale canonical revision")
    if result.workload_id != expected_package.workload_id:
        raise CloudWorkspaceResultError("workload identity mismatch")
    if result.billable_api:
        raise CloudWorkspaceResultError("billable API result cannot represent managed cloud")
    if len(result.patch.encode("utf-8")) > MAX_RESULT_PATCH_BYTES:
        raise CloudWorkspaceResultError("result patch exceeds size limit")
    if contains_secret_like_content(result.patch):
        raise CloudWorkspaceResultError("result patch contains secret-like content")
    expected_hash = hashlib.sha256(result.patch.encode("utf-8")).hexdigest()
    if result.patch_hash != expected_hash:
        raise CloudWorkspaceResultError("result patch hash mismatch")
    try:
        normalized_allowed = tuple(normalize_relative_path(path) for path in allowed_paths)
        normalized_changed = tuple(normalize_relative_path(path) for path in result.changed_paths)
    except ValueError as exc:
        raise CloudWorkspaceResultError("result path is invalid") from exc
    if any(not _within_scope(path, normalized_allowed) for path in normalized_changed):
        raise CloudWorkspaceResultError("result path escapes allowed scope")
    if result.patch:
        decision = evaluate_patch(result.patch, max_bytes=MAX_RESULT_PATCH_BYTES, allowed_prefixes=normalized_allowed)
        if not decision.allowed:
            raise CloudWorkspaceResultError(f"result patch denied:{decision.reason}")
        if set(decision.paths) != set(normalized_changed):
            raise CloudWorkspaceResultError("result changed-path manifest mismatch")
    elif normalized_changed:
        raise CloudWorkspaceResultError("no-change result lists changed paths")
    return ValidatedCloudWorkspaceResult(
        source_revision=result.source_revision,
        package_id=result.package_id,
        workload_id=result.workload_id,
        changed_paths=normalized_changed,
        patch=result.patch,
        patch_hash=result.patch_hash,
        cloud_fingerprint=result.cloud_fingerprint,
        input_bytes=result.input_bytes,
        output_bytes=result.output_bytes,
    )


__all__ = ["CloudWorkspaceResultError", "ValidatedCloudWorkspaceResult", "validate_cloud_workspace_result"]
