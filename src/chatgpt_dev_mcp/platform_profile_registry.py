"""Bounded platform-profile mutation for an existing registered workspace.

This module intentionally does not expose a general config editor.  The first
public mutation is browser-profile registration; capture-only desktop profiles
are added only after the runtime schema can consume them.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from .browser_runtime import BrowserProfile, BrowserRuntimeError
from .credential_slots import CredentialSlotError, CredentialSlotPolicy
from .desktop_capture import DesktopCaptureError, DesktopCaptureProfile
from .platform_runtime import PlatformConfigError, parse_platform_config
from .provisioning import ProvisioningError, RegistryMutationManager, validate_project_id
from .runtime_policy import PolicyError, parse_command_profile


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MIN_SCREENSHOT_BYTES = 64 * 1024
_MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024


class PlatformProfileRegistryManager(RegistryMutationManager):
    """Register only allowlisted QA profiles inside one workspace entry."""

    def __init__(
        self,
        path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        super().__init__(path, home=home, validate_document=validate_document)

    @staticmethod
    def _entry_platform(entry: dict[str, Any]) -> tuple[dict[str, Any], str]:
        metadata = entry.get("metadata")
        metadata_platform = metadata.get("platform") if isinstance(metadata, Mapping) else None
        top_platform = entry.get("platform")
        if top_platform is not None and metadata_platform is not None:
            raise ProvisioningError(
                "CONFIG_INVALID",
                "platform is declared twice for the workspace.",
                category="validation",
            )
        raw = metadata_platform if metadata_platform is not None else top_platform
        if raw is None:
            return {}, "metadata" if isinstance(metadata, Mapping) and "platform" in metadata else "top"
        if not isinstance(raw, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "workspace platform must be an object.", category="validation")
        return copy.deepcopy(dict(raw)), "metadata" if metadata_platform is not None else "top"

    @staticmethod
    def _store_platform(entry: dict[str, Any], platform: Mapping[str, Any], location: str) -> None:
        if location == "metadata":
            metadata = dict(entry.get("metadata", {})) if isinstance(entry.get("metadata"), Mapping) else {}
            metadata["platform"] = copy.deepcopy(dict(platform))
            entry["metadata"] = metadata
            entry.pop("platform", None)
        else:
            entry["platform"] = copy.deepcopy(dict(platform))

    @classmethod
    def _validate_workspace_platforms(cls, document: Mapping[str, Any]) -> None:
        workspaces = document.get("workspaces")
        if not isinstance(workspaces, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
        for workspace_id, raw_entry in workspaces.items():
            if not isinstance(raw_entry, Mapping):
                raise ProvisioningError("CONFIG_INVALID", "workspace entries must be objects.", category="validation")
            platform, _location = cls._entry_platform(dict(raw_entry))
            if not platform:
                continue
            try:
                parse_platform_config(platform)
            except PlatformConfigError as exc:
                raise ProvisioningError(
                    "CONFIG_INVALID",
                    "An existing workspace platform configuration is invalid.",
                    category="validation",
                    details={"workspace_id": str(workspace_id), "reason": str(exc)},
                ) from exc

    @staticmethod
    def _browser_spec(
        profile_id: str,
        allowed_origins: tuple[str, ...],
        viewport_width: int,
        viewport_height: int,
        max_screenshot_bytes: int,
    ) -> dict[str, object]:
        if not profile_id.startswith("managed-"):
            raise ProvisioningError(
                "PLATFORM_PROFILE_ID_DENIED",
                "browser QA profile ids must start with 'managed-'.",
                category="permission",
            )
        if isinstance(max_screenshot_bytes, bool) or not isinstance(max_screenshot_bytes, int) or not _MIN_SCREENSHOT_BYTES <= max_screenshot_bytes <= _MAX_SCREENSHOT_BYTES:
            raise ProvisioningError(
                "PLATFORM_PROFILE_INVALID",
                "browser screenshot byte bound is outside the safe range.",
                category="validation",
            )
        try:
            profile = BrowserProfile(
                profile_id,
                tuple(allowed_origins),
                viewport_width,
                viewport_height,
                max_screenshot_bytes,
            )
        except (BrowserRuntimeError, ValueError, TypeError) as exc:
            raise ProvisioningError(
                "PLATFORM_PROFILE_INVALID",
                "browser QA profile failed runtime validation.",
                category="validation",
                details={"reason": str(exc)},
            ) from exc
        return {
            "allowed_origins": list(profile.origins),
            "viewport_width": profile.viewport_width,
            "viewport_height": profile.viewport_height,
            "max_screenshot_bytes": profile.max_screenshot_bytes,
        }

    @staticmethod
    def _desktop_spec(
        profile_id: str,
        bundle_id: str,
        health_url: str,
        max_screenshot_bytes: int,
    ) -> dict[str, object]:
        if not profile_id.startswith("managed-"):
            raise ProvisioningError(
                "PLATFORM_PROFILE_ID_DENIED",
                "desktop QA profile ids must start with 'managed-'.",
                category="permission",
            )
        try:
            profile = DesktopCaptureProfile(
                profile_id,
                bundle_id,
                health_url,
                max_screenshot_bytes,
            )
        except (DesktopCaptureError, ValueError, TypeError) as exc:
            raise ProvisioningError(
                "PLATFORM_PROFILE_INVALID",
                "desktop QA profile failed capture-only runtime validation.",
                category="validation",
                details={"reason": str(exc)},
            ) from exc
        spec: dict[str, object] = {
            "bundle_id": profile.bundle_id,
            "max_screenshot_bytes": profile.max_screenshot_bytes,
        }
        if profile.health_url:
            spec["health_url"] = profile.health_url
        return spec

    @staticmethod
    def _credential_slot_spec(
        slot_id: str,
        source_kind: str,
        source_name: str,
        allowed_profiles: tuple[str, ...],
    ) -> dict[str, object]:
        if not allowed_profiles or len(set(allowed_profiles)) != len(allowed_profiles):
            raise ProvisioningError(
                "CREDENTIAL_SLOT_INVALID",
                "credential slot allowed_profiles must be non-empty and unique.",
                category="validation",
            )
        try:
            policy = CredentialSlotPolicy(
                slot=slot_id,
                source_kind=source_kind,
                source_name=source_name,
                allowed_profiles=allowed_profiles,
                allowed_projects=("validation",),
            )
        except CredentialSlotError as exc:
            raise ProvisioningError("CREDENTIAL_SLOT_INVALID", str(exc), category="validation") from exc
        return {
            "source_kind": policy.source_kind,
            "source_name": policy.source_name,
            "allowed_profiles": list(policy.allowed_profiles),
        }

    @staticmethod
    def _command_profile_spec(
        profile_id: str,
        argv: tuple[str, ...],
        allowed_args: Mapping[str, object],
        timeout_ms: int,
        max_output_bytes: int,
        resources: tuple[str, ...],
        credential_slots: tuple[str, ...],
        network_class: str,
        lifecycle: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if not profile_id.startswith("managed-"):
            raise ProvisioningError(
                "PLATFORM_PROFILE_ID_DENIED",
                "command profile ids must start with 'managed-'.",
                category="permission",
            )
        spec: dict[str, object] = {
            "argv": list(argv),
            "allowed_args": copy.deepcopy(dict(allowed_args)),
            "timeout_ms": timeout_ms,
            "max_output_bytes": max_output_bytes,
            "resources": list(resources),
            "credential_slots": list(credential_slots),
            "network_class": network_class,
        }
        if lifecycle is not None:
            spec["lifecycle"] = copy.deepcopy(dict(lifecycle))
        try:
            parse_command_profile(profile_id, spec)
        except (PolicyError, TypeError, ValueError) as exc:
            raise ProvisioningError(
                "COMMAND_PROFILE_INVALID",
                "The command profile failed runtime validation.",
                category="validation",
                details={"reason": str(exc)},
            ) from exc
        return spec

    def register_browser(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        profile_id: str,
        allowed_origins: tuple[str, ...],
        viewport_width: int = 1280,
        viewport_height: int = 720,
        max_screenshot_bytes: int = 8 * 1024 * 1024,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        spec = self._browser_spec(
            profile_id,
            allowed_origins,
            viewport_width,
            viewport_height,
            max_screenshot_bytes,
        )
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                profiles = platform.get("browser_profiles")
                if profiles is None:
                    profiles = {}
                if not isinstance(profiles, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "browser_profiles must be an object.", category="validation")
                browser_profiles = copy.deepcopy(dict(profiles))
                existing = browser_profiles.get(profile_id)
                if existing is not None:
                    if existing == spec:
                        return {
                            "status": "idempotent",
                            "workspace_id": identifier,
                            "kind": "browser",
                            "profile_id": profile_id,
                            "config_digest": before_digest,
                            "receipt": {
                                "status": "idempotent",
                                "before_config_digest": before_digest,
                                "after_config_digest": before_digest,
                                "changed_keys": [],
                            },
                            "external_execution": False,
                        }
                    raise ProvisioningError(
                        "PLATFORM_PROFILE_CONFLICT",
                        "The browser profile id is already bound to a different specification.",
                        category="conflict",
                    )
                browser_profiles[profile_id] = spec
                platform["browser_profiles"] = browser_profiles
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "PLATFORM_PROFILE_INVALID",
                        "The updated platform profile failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.platform.browser_profiles.{profile_id}"],
                )
                return {
                    "status": "registered",
                    "workspace_id": identifier,
                    "kind": "browser",
                    "profile_id": profile_id,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()

    def register_desktop(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        profile_id: str,
        bundle_id: str,
        health_url: str = "",
        max_screenshot_bytes: int = 8 * 1024 * 1024,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        spec = self._desktop_spec(profile_id, bundle_id, health_url, max_screenshot_bytes)
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                profiles = platform.get("desktop_profiles")
                if profiles is None:
                    profiles = {}
                if not isinstance(profiles, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "desktop_profiles must be an object.", category="validation")
                desktop_profiles = copy.deepcopy(dict(profiles))
                existing = desktop_profiles.get(profile_id)
                if existing is not None:
                    if existing == spec:
                        return {
                            "status": "idempotent",
                            "workspace_id": identifier,
                            "kind": "desktop",
                            "profile_id": profile_id,
                            "config_digest": before_digest,
                            "receipt": {
                                "status": "idempotent",
                                "before_config_digest": before_digest,
                                "after_config_digest": before_digest,
                                "changed_keys": [],
                            },
                            "external_execution": False,
                        }
                    raise ProvisioningError(
                        "PLATFORM_PROFILE_CONFLICT",
                        "The desktop profile id is already bound to a different specification.",
                        category="conflict",
                    )
                desktop_profiles[profile_id] = spec
                platform["desktop_profiles"] = desktop_profiles
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "PLATFORM_PROFILE_INVALID",
                        "The updated platform profile failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.platform.desktop_profiles.{profile_id}"],
                )
                return {
                    "status": "registered",
                    "workspace_id": identifier,
                    "kind": "desktop",
                    "profile_id": profile_id,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()

    def register_credential_slot(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        slot_id: str,
        source_kind: str,
        source_name: str,
        allowed_profiles: tuple[str, ...],
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        spec = self._credential_slot_spec(slot_id, source_kind, source_name, allowed_profiles)
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                slots = platform.get("credential_slots")
                if slots is None:
                    slots = {}
                if not isinstance(slots, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "credential_slots must be an object.", category="validation")
                credential_slots = copy.deepcopy(dict(slots))
                existing = credential_slots.get(slot_id)
                if existing is not None:
                    if existing == spec:
                        return {
                            "status": "idempotent",
                            "workspace_id": identifier,
                            "slot_id": slot_id,
                            "config_digest": before_digest,
                            "receipt": {
                                "status": "idempotent",
                                "before_config_digest": before_digest,
                                "after_config_digest": before_digest,
                                "changed_keys": [],
                            },
                            "external_execution": False,
                        }
                    raise ProvisioningError(
                        "CREDENTIAL_SLOT_CONFLICT",
                        "The credential slot id is already bound to a different specification.",
                        category="conflict",
                    )
                credential_slots[slot_id] = spec
                platform["credential_slots"] = credential_slots
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "CREDENTIAL_SLOT_INVALID",
                        "The updated credential slot failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.platform.credential_slots.{slot_id}"],
                )
                return {
                    "status": "registered",
                    "workspace_id": identifier,
                    "slot_id": slot_id,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()

    def register_command_profile(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        profile_id: str,
        argv: tuple[str, ...],
        allowed_args: Mapping[str, object],
        timeout_ms: int = 30000,
        max_output_bytes: int = 65536,
        resources: tuple[str, ...] = (),
        credential_slots: tuple[str, ...] = (),
        network_class: str = "none",
        lifecycle: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        spec = self._command_profile_spec(
            profile_id,
            argv,
            allowed_args,
            timeout_ms,
            max_output_bytes,
            resources,
            credential_slots,
            network_class,
            lifecycle,
        )
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                profiles = platform.get("command_profiles")
                if profiles is None:
                    profiles = {}
                if not isinstance(profiles, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")
                command_profiles = copy.deepcopy(dict(profiles))
                existing = command_profiles.get(profile_id)
                if existing is not None:
                    if existing == spec:
                        return {
                            "status": "idempotent",
                            "workspace_id": identifier,
                            "profile_id": profile_id,
                            "config_digest": before_digest,
                            "receipt": {
                                "status": "idempotent",
                                "before_config_digest": before_digest,
                                "after_config_digest": before_digest,
                                "changed_keys": [],
                            },
                            "external_execution": False,
                        }
                    raise ProvisioningError(
                        "COMMAND_PROFILE_CONFLICT",
                        "The command profile id is already bound to a different specification.",
                        category="conflict",
                    )
                command_profiles[profile_id] = spec
                platform["command_profiles"] = command_profiles
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "COMMAND_PROFILE_INVALID",
                        "The updated command profile failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.platform.command_profiles.{profile_id}"],
                )
                return {
                    "status": "registered",
                    "workspace_id": identifier,
                    "profile_id": profile_id,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()

    @staticmethod
    def _command_profile_hash(profile: Mapping[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(dict(profile), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _cleanup_utc_timestamp(value: object, *, field: str) -> datetime:
        if not isinstance(value, str) or not value or len(value) > 64 or not value.endswith("Z"):
            raise ProvisioningError(
                "COMMAND_PROFILE_CLEANUP_INVALID",
                f"{field} must be a UTC RFC 3339 timestamp.",
                category="validation",
            )
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ProvisioningError(
                "COMMAND_PROFILE_CLEANUP_INVALID",
                f"{field} must be a UTC RFC 3339 timestamp.",
                category="validation",
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ProvisioningError(
                "COMMAND_PROFILE_CLEANUP_INVALID",
                f"{field} must be UTC.",
                category="validation",
            )
        return parsed.astimezone(timezone.utc)

    def cleanup_ephemeral_command_profiles(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        candidate_profile_hashes: Mapping[str, str],
        mode: str,
        evaluation_time: str,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if mode not in {"expired", "all_ephemeral"}:
            raise ProvisioningError("COMMAND_PROFILE_CLEANUP_INVALID", "cleanup mode is invalid.", category="validation")
        evaluation_dt = self._cleanup_utc_timestamp(evaluation_time, field="evaluation_time")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        if not isinstance(candidate_profile_hashes, Mapping) or len(candidate_profile_hashes) > 128:
            raise ProvisioningError("COMMAND_PROFILE_CLEANUP_INVALID", "candidate profile hashes are invalid.", category="validation")
        pinned: dict[str, str] = {}
        for profile_id, profile_hash in candidate_profile_hashes.items():
            if not isinstance(profile_id, str) or not profile_id.startswith("managed-"):
                raise ProvisioningError(
                    "PLATFORM_PROFILE_ID_DENIED",
                    "command profile ids must start with 'managed-'.",
                    category="permission",
                )
            if not isinstance(profile_hash, str) or not _SHA256_RE.fullmatch(profile_hash):
                raise ProvisioningError(
                    "COMMAND_PROFILE_CHANGED",
                    "expected command profile hash is invalid.",
                    category="conflict",
                )
            pinned[profile_id] = profile_hash
        if not pinned:
            return {
                "status": "noop",
                "workspace_id": identifier,
                "mode": mode,
                "evaluation_time": evaluation_time,
                "removed_profile_ids": [],
                "removed_profile_hashes": {},
                "removed_lifecycle": {},
                "config_digest": expected_config_digest,
                "receipt": {
                    "status": "noop",
                    "before_config_digest": expected_config_digest,
                    "after_config_digest": expected_config_digest,
                    "changed_keys": [],
                },
                "external_execution": False,
            }

        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, file_mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                profiles = platform.get("command_profiles")
                if not isinstance(profiles, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")
                command_profiles = copy.deepcopy(dict(profiles))
                ordered_ids = sorted(pinned)
                removed_hashes: dict[str, str] = {}
                removed_lifecycle: dict[str, object] = {}
                for profile_id in ordered_ids:
                    existing = command_profiles.get(profile_id)
                    if not isinstance(existing, Mapping):
                        raise ProvisioningError(
                            "COMMAND_PROFILE_NOT_FOUND",
                            "A cleanup candidate is no longer registered.",
                            category="not_found",
                        )
                    existing_hash = self._command_profile_hash(existing)
                    if existing_hash != pinned[profile_id]:
                        raise ProvisioningError(
                            "COMMAND_PROFILE_CHANGED",
                            "A cleanup candidate changed after preflight.",
                            category="conflict",
                        )
                    try:
                        parsed = parse_command_profile(profile_id, existing)
                    except PolicyError as exc:
                        raise ProvisioningError(
                            "COMMAND_PROFILE_INVALID",
                            "A cleanup candidate failed runtime validation.",
                            category="validation",
                            details={"reason": str(exc)},
                        ) from exc
                    lifecycle = parsed.lifecycle
                    if lifecycle is None or lifecycle.kind != "ephemeral":
                        raise ProvisioningError(
                            "COMMAND_PROFILE_NOT_EPHEMERAL",
                            "Cleanup candidates must be explicitly ephemeral.",
                            category="permission",
                        )
                    if mode == "expired":
                        if lifecycle.expires_at is None:
                            raise ProvisioningError(
                                "COMMAND_PROFILE_NOT_ELIGIBLE",
                                "An ephemeral cleanup candidate has no expiry.",
                                category="conflict",
                            )
                        expires_dt = self._cleanup_utc_timestamp(lifecycle.expires_at, field="lifecycle expires_at")
                        if expires_dt > evaluation_dt:
                            raise ProvisioningError(
                                "COMMAND_PROFILE_NOT_ELIGIBLE",
                                "An ephemeral cleanup candidate is not expired at the pinned evaluation time.",
                                category="conflict",
                            )
                    removed_hashes[profile_id] = existing_hash
                    removed_lifecycle[profile_id] = {
                        "kind": lifecycle.kind,
                        "purpose": lifecycle.purpose,
                        "owner": lifecycle.owner,
                        "created_at": lifecycle.created_at,
                        "expires_at": lifecycle.expires_at,
                    }

                for profile_id in ordered_ids:
                    command_profiles.pop(profile_id)
                platform["command_profiles"] = command_profiles
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "COMMAND_PROFILE_INVALID",
                        "The updated command profile configuration failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                changed_keys = [f"workspaces.{identifier}.platform.command_profiles.{profile_id}" for profile_id in ordered_ids]
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=file_mode,
                    changed_keys=changed_keys,
                )
                readback_document, _readback_raw, readback_digest, _readback_existed, _readback_mode = self._snapshot()
                if readback_digest != after_digest:
                    raise ProvisioningError(
                        "CONFIG_RECONCILIATION_REQUIRED",
                        "Cleanup write succeeded but registry read-back digest is ambiguous.",
                        category="conflict",
                    )
                readback_workspaces = readback_document.get("workspaces")
                readback_entry = readback_workspaces.get(identifier) if isinstance(readback_workspaces, Mapping) else None
                if not isinstance(readback_entry, Mapping):
                    raise ProvisioningError(
                        "CONFIG_RECONCILIATION_REQUIRED",
                        "Cleanup write succeeded but workspace read-back failed.",
                        category="conflict",
                    )
                readback_platform, _ = self._entry_platform(dict(readback_entry))
                readback_profiles = readback_platform.get("command_profiles", {})
                if not isinstance(readback_profiles, Mapping) or any(profile_id in readback_profiles for profile_id in ordered_ids):
                    raise ProvisioningError(
                        "CONFIG_RECONCILIATION_REQUIRED",
                        "Cleanup write succeeded but candidate removal read-back failed.",
                        category="conflict",
                    )
                return {
                    "status": "cleaned",
                    "workspace_id": identifier,
                    "mode": mode,
                    "evaluation_time": evaluation_time,
                    "removed_profile_ids": ordered_ids,
                    "removed_profile_hashes": removed_hashes,
                    "removed_lifecycle": removed_lifecycle,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()

    def unregister_command_profile(
        self,
        *,
        workspace_id: str,
        expected_config_digest: str,
        expected_workspace_path: Path,
        profile_id: str,
        expected_profile_hash: str,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if not isinstance(expected_config_digest, str) or not _SHA256_RE.fullmatch(expected_config_digest):
            raise ProvisioningError("CONFIG_CHANGED", "expected config digest is invalid.", category="conflict")
        if not isinstance(expected_profile_hash, str) or not _SHA256_RE.fullmatch(expected_profile_hash):
            raise ProvisioningError("COMMAND_PROFILE_CHANGED", "expected command profile hash is invalid.", category="conflict")
        if not isinstance(profile_id, str) or not profile_id.startswith("managed-"):
            raise ProvisioningError(
                "PLATFORM_PROFILE_ID_DENIED",
                "command profile ids must start with 'managed-'.",
                category="permission",
            )
        with self._lock():
            lock_handle = self._lock_file()
            try:
                document, raw, before_digest, existed, mode = self._snapshot()
                if before_digest != expected_config_digest:
                    raise ProvisioningError(
                        "CONFIG_CHANGED",
                        "The project registry changed after the expected digest was captured.",
                        category="conflict",
                        details={"current_digest": before_digest},
                    )
                workspaces = document.get("workspaces")
                if not isinstance(workspaces, dict):
                    raise ProvisioningError("CONFIG_INVALID", "workspaces must be an object.", category="validation")
                raw_entry = workspaces.get(identifier)
                if not isinstance(raw_entry, Mapping):
                    raise ProvisioningError("WORKSPACE_NOT_FOUND", "The requested workspace is not registered.", category="not_found")
                registered_path = Path(os.path.expandvars(str(raw_entry.get("path", "")))).expanduser().resolve(strict=False)
                if registered_path != Path(expected_workspace_path).expanduser().resolve(strict=False):
                    raise ProvisioningError(
                        "WORKSPACE_SOURCE_CHANGED",
                        "The registered workspace path changed after preflight.",
                        category="security",
                    )

                candidate = copy.deepcopy(document)
                entry = candidate["workspaces"][identifier]
                if not isinstance(entry, dict):
                    entry = dict(entry)
                    candidate["workspaces"][identifier] = entry
                platform, location = self._entry_platform(entry)
                profiles = platform.get("command_profiles")
                if not isinstance(profiles, Mapping):
                    raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")
                command_profiles = copy.deepcopy(dict(profiles))
                existing = command_profiles.get(profile_id)
                if not isinstance(existing, Mapping):
                    raise ProvisioningError(
                        "COMMAND_PROFILE_NOT_FOUND",
                        "The command profile is no longer registered.",
                        category="not_found",
                    )
                existing_hash = hashlib.sha256(
                    json.dumps(dict(existing), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                ).hexdigest()
                if existing_hash != expected_profile_hash:
                    raise ProvisioningError(
                        "COMMAND_PROFILE_CHANGED",
                        "The command profile changed after preflight.",
                        category="conflict",
                    )
                command_profiles.pop(profile_id)
                platform["command_profiles"] = command_profiles
                try:
                    parse_platform_config(platform)
                except PlatformConfigError as exc:
                    raise ProvisioningError(
                        "COMMAND_PROFILE_INVALID",
                        "The updated command profile configuration failed schema validation.",
                        category="validation",
                        details={"reason": str(exc)},
                    ) from exc
                self._store_platform(entry, platform, location)
                self._validate_workspace_platforms(candidate)
                after_digest, receipt = self._atomic_write_document(
                    document=candidate,
                    previous_raw=raw,
                    previous_digest=before_digest,
                    previous_existed=existed,
                    mode=mode,
                    changed_keys=[f"workspaces.{identifier}.platform.command_profiles.{profile_id}"],
                )
                return {
                    "status": "unregistered",
                    "workspace_id": identifier,
                    "profile_id": profile_id,
                    "config_digest": after_digest,
                    "receipt": receipt,
                    "external_execution": False,
                }
            finally:
                lock_handle.close()


__all__ = ["PlatformProfileRegistryManager"]
