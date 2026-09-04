"""Approval-gated service for bounded platform profile registration.

This module owns only the read-only preflight and one-shot apply lifecycle.
The actual registry mutation remains delegated to PlatformProfileRegistryManager,
so it does not create a second config persistence mechanism or a generic editor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import time
from typing import Any, Callable, Mapping

from .platform_profile_registry import PlatformProfileRegistryManager
from .provisioning import ProvisioningError, validate_project_id
from .runtime_policy import PolicyError, parse_command_profile


DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS = 1800


@dataclass(frozen=True)
class PlatformProfilePreflight:
    preflight_id: str
    confirmation: str
    workspace_id: str
    workspace_path: Path
    kind: str
    profile_id: str
    spec: Mapping[str, object]
    spec_hash: str
    config_digest: str
    status: str
    created_at: float
    expires_at: float


class PlatformProfileRegistrationService:
    """Create bounded profile-registration preflights and consume them once."""

    def __init__(
        self,
        config_path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise ProvisioningError(
                "PLATFORM_PROFILE_PREFLIGHT_TTL_INVALID",
                "platform profile preflight TTL is outside the safe range.",
                category="validation",
            )
        self._manager = PlatformProfileRegistryManager(
            Path(config_path),
            home=Path(home),
            validate_document=validate_document,
        )
        self._now = now
        self._ttl_seconds = ttl_seconds
        self._preflights: dict[str, PlatformProfilePreflight] = {}

    @staticmethod
    def _spec_hash(spec: Mapping[str, object]) -> str:
        encoded = json.dumps(dict(spec), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _workspace_entry(document: Mapping[str, Any], workspace_id: str) -> tuple[Mapping[str, Any], Path]:
        workspaces = document.get("workspaces")
        entry = workspaces.get(workspace_id) if isinstance(workspaces, Mapping) else None
        if not isinstance(entry, Mapping):
            raise ProvisioningError(
                "WORKSPACE_NOT_FOUND",
                "The requested workspace is not registered.",
                category="not_found",
            )
        if str(entry.get("profile", "READ_ONLY")) != "DEVELOPMENT":
            raise ProvisioningError(
                "PLATFORM_PROFILE_WORKSPACE_DENIED",
                "platform QA profiles may only be registered for a DEVELOPMENT workspace.",
                category="permission",
            )
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ProvisioningError(
                "WORKSPACE_PATH_INVALID",
                "The registered workspace path is invalid.",
                category="security",
            )
        return entry, Path(raw_path).expanduser().resolve(strict=False)

    def preflight(
        self,
        *,
        workspace_id: str,
        kind: str,
        profile_id: str,
        allowed_origins: list[str] | tuple[str, ...] | None = None,
        viewport_width: int = 1280,
        viewport_height: int = 720,
        bundle_id: str = "",
        health_url: str = "",
        max_screenshot_bytes: int = 8 * 1024 * 1024,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        document, _raw, config_digest, _existed, _mode = self._manager.snapshot()
        self._manager._validate_workspace_platforms(document)
        entry, workspace_path = self._workspace_entry(document, identifier)

        if kind == "browser":
            if allowed_origins is None:
                raise ProvisioningError(
                    "PLATFORM_PROFILE_INVALID",
                    "browser profile allowed_origins are required.",
                    category="validation",
                )
            spec = self._manager._browser_spec(
                profile_id,
                tuple(allowed_origins),
                viewport_width,
                viewport_height,
                max_screenshot_bytes,
            )
            collection_name = "browser_profiles"
        elif kind == "desktop":
            spec = self._manager._desktop_spec(
                profile_id,
                bundle_id,
                health_url,
                max_screenshot_bytes,
            )
            collection_name = "desktop_profiles"
        else:
            raise ProvisioningError(
                "PLATFORM_PROFILE_KIND_INVALID",
                "platform profile kind must be browser or desktop.",
                category="validation",
            )

        platform, _location = self._manager._entry_platform(dict(entry))
        profiles = platform.get(collection_name, {})
        if not isinstance(profiles, Mapping):
            raise ProvisioningError(
                "CONFIG_INVALID",
                f"{collection_name} must be an object.",
                category="validation",
            )
        existing = profiles.get(profile_id)
        if existing is None:
            status = "new"
        elif existing == spec:
            status = "idempotent"
        else:
            raise ProvisioningError(
                "PLATFORM_PROFILE_CONFLICT",
                "The profile id is already bound to a different specification.",
                category="conflict",
            )

        created_at = float(self._now())
        preflight_id = f"platform-profile-preflight:{secrets.token_urlsafe(24)}"
        confirmation = f"REGISTER_PLATFORM_PROFILE:{identifier}:{profile_id}:{secrets.token_urlsafe(8)}"
        preflight = PlatformProfilePreflight(
            preflight_id=preflight_id,
            confirmation=confirmation,
            workspace_id=identifier,
            workspace_path=workspace_path,
            kind=kind,
            profile_id=profile_id,
            spec=dict(spec),
            spec_hash=self._spec_hash(spec),
            config_digest=config_digest,
            status=status,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        self._preflights[preflight_id] = preflight
        return {
            "preflight_id": preflight.preflight_id,
            "workspace_id": preflight.workspace_id,
            "kind": preflight.kind,
            "profile_id": preflight.profile_id,
            "status": preflight.status,
            "config_digest": preflight.config_digest,
            "spec_hash": preflight.spec_hash,
            "approval_required": True,
            "approval": {
                "preflight_id": preflight.preflight_id,
                "confirmation": preflight.confirmation,
                "expires_at": preflight.expires_at,
            },
            "expires_at": preflight.expires_at,
            "external_execution": False,
        }

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        if not isinstance(preflight_id, str) or not preflight_id:
            raise ProvisioningError(
                "PLATFORM_PROFILE_PREFLIGHT_REQUIRED",
                "A current platform profile preflight is required.",
                category="permission",
            )
        preflight = self._preflights.get(preflight_id)
        if preflight is None:
            raise ProvisioningError(
                "PLATFORM_PROFILE_PREFLIGHT_NOT_FOUND",
                "The platform profile preflight is unknown, expired, or already consumed.",
                category="not_found",
            )
        if float(self._now()) >= preflight.expires_at:
            self._preflights.pop(preflight_id, None)
            raise ProvisioningError(
                "PLATFORM_PROFILE_PREFLIGHT_EXPIRED",
                "The platform profile preflight has expired; create a new preflight.",
                category="permission",
            )
        if confirmation != preflight.confirmation:
            raise ProvisioningError(
                "PLATFORM_PROFILE_CONFIRMATION_REQUIRED",
                "Return the exact confirmation from the preflight approval object.",
                category="permission",
            )

        if preflight.kind == "browser":
            mutation = self._manager.register_browser(
                workspace_id=preflight.workspace_id,
                expected_config_digest=preflight.config_digest,
                expected_workspace_path=preflight.workspace_path,
                profile_id=preflight.profile_id,
                allowed_origins=tuple(preflight.spec["allowed_origins"]),
                viewport_width=int(preflight.spec["viewport_width"]),
                viewport_height=int(preflight.spec["viewport_height"]),
                max_screenshot_bytes=int(preflight.spec["max_screenshot_bytes"]),
            )
        else:
            mutation = self._manager.register_desktop(
                workspace_id=preflight.workspace_id,
                expected_config_digest=preflight.config_digest,
                expected_workspace_path=preflight.workspace_path,
                profile_id=preflight.profile_id,
                bundle_id=str(preflight.spec["bundle_id"]),
                health_url=str(preflight.spec.get("health_url", "")),
                max_screenshot_bytes=int(preflight.spec["max_screenshot_bytes"]),
            )

        self._preflights.pop(preflight_id, None)
        payload = dict(mutation)
        payload.update(
            {
                "preflight_id": preflight_id,
                "spec_hash": preflight.spec_hash,
                "approval_consumed": True,
                "external_execution": False,
            }
        )
        return payload


@dataclass(frozen=True)
class CredentialSlotPreflight:
    preflight_id: str
    confirmation: str
    workspace_id: str
    workspace_path: Path
    slot_id: str
    spec: Mapping[str, object]
    spec_hash: str
    config_digest: str
    status: str
    created_at: float
    expires_at: float


class CredentialSlotRegistrationService:
    """Register only credential references; secret material is never accepted."""

    def __init__(
        self,
        config_path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise ProvisioningError(
                "CREDENTIAL_SLOT_PREFLIGHT_TTL_INVALID",
                "credential slot preflight TTL is outside the safe range.",
                category="validation",
            )
        self._manager = PlatformProfileRegistryManager(
            Path(config_path),
            home=Path(home),
            validate_document=validate_document,
        )
        self._now = now
        self._ttl_seconds = ttl_seconds
        self._preflights: dict[str, CredentialSlotPreflight] = {}

    @staticmethod
    def _spec_hash(spec: Mapping[str, object]) -> str:
        encoded = json.dumps(dict(spec), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def preflight(
        self,
        *,
        workspace_id: str,
        slot_id: str,
        source_kind: str,
        source_name: str,
        allowed_profiles: list[str] | tuple[str, ...],
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        document, _raw, config_digest, _existed, _mode = self._manager.snapshot()
        self._manager._validate_workspace_platforms(document)
        entry, workspace_path = PlatformProfileRegistrationService._workspace_entry(document, identifier)
        spec = self._manager._credential_slot_spec(
            slot_id,
            source_kind,
            source_name,
            tuple(allowed_profiles),
        )
        platform, _location = self._manager._entry_platform(dict(entry))
        slots = platform.get("credential_slots", {})
        if not isinstance(slots, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "credential_slots must be an object.", category="validation")
        existing = slots.get(slot_id)
        if existing is None:
            status = "new"
        elif existing == spec:
            status = "idempotent"
        else:
            raise ProvisioningError(
                "CREDENTIAL_SLOT_CONFLICT",
                "The credential slot id is already bound to a different specification.",
                category="conflict",
            )

        created_at = float(self._now())
        preflight_id = f"credential-slot-preflight:{secrets.token_urlsafe(24)}"
        confirmation = f"REGISTER_CREDENTIAL_SLOT:{identifier}:{slot_id}:{secrets.token_urlsafe(8)}"
        preflight = CredentialSlotPreflight(
            preflight_id=preflight_id,
            confirmation=confirmation,
            workspace_id=identifier,
            workspace_path=workspace_path,
            slot_id=slot_id,
            spec=dict(spec),
            spec_hash=self._spec_hash(spec),
            config_digest=config_digest,
            status=status,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        self._preflights[preflight_id] = preflight
        return {
            "preflight_id": preflight.preflight_id,
            "workspace_id": preflight.workspace_id,
            "slot_id": preflight.slot_id,
            "source_kind": preflight.spec["source_kind"],
            "source_name": preflight.spec["source_name"],
            "allowed_profiles": list(preflight.spec["allowed_profiles"]),
            "status": preflight.status,
            "config_digest": preflight.config_digest,
            "spec_hash": preflight.spec_hash,
            "approval_required": True,
            "approval": {
                "preflight_id": preflight.preflight_id,
                "confirmation": preflight.confirmation,
                "expires_at": preflight.expires_at,
            },
            "expires_at": preflight.expires_at,
            "external_execution": False,
        }

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        if not isinstance(preflight_id, str) or not preflight_id:
            raise ProvisioningError(
                "CREDENTIAL_SLOT_PREFLIGHT_REQUIRED",
                "A current credential slot preflight is required.",
                category="permission",
            )
        preflight = self._preflights.get(preflight_id)
        if preflight is None:
            raise ProvisioningError(
                "CREDENTIAL_SLOT_PREFLIGHT_NOT_FOUND",
                "The credential slot preflight is unknown, expired, or already consumed.",
                category="not_found",
            )
        if float(self._now()) >= preflight.expires_at:
            self._preflights.pop(preflight_id, None)
            raise ProvisioningError(
                "CREDENTIAL_SLOT_PREFLIGHT_EXPIRED",
                "The credential slot preflight has expired; create a new preflight.",
                category="permission",
            )
        if confirmation != preflight.confirmation:
            raise ProvisioningError(
                "CREDENTIAL_SLOT_CONFIRMATION_REQUIRED",
                "Return the exact confirmation from the preflight approval object.",
                category="permission",
            )

        mutation = self._manager.register_credential_slot(
            workspace_id=preflight.workspace_id,
            expected_config_digest=preflight.config_digest,
            expected_workspace_path=preflight.workspace_path,
            slot_id=preflight.slot_id,
            source_kind=str(preflight.spec["source_kind"]),
            source_name=str(preflight.spec["source_name"]),
            allowed_profiles=tuple(str(item) for item in preflight.spec["allowed_profiles"]),
        )
        self._preflights.pop(preflight_id, None)
        payload = dict(mutation)
        payload.update(
            {
                "preflight_id": preflight_id,
                "spec_hash": preflight.spec_hash,
                "approval_consumed": True,
                "external_execution": False,
            }
        )
        return payload


@dataclass(frozen=True)
class CommandProfilePreflight:
    preflight_id: str
    confirmation: str
    workspace_id: str
    workspace_path: Path
    profile_id: str
    spec: Mapping[str, object]
    spec_hash: str
    config_digest: str
    status: str
    created_at: float
    expires_at: float


class CommandProfileRegistrationService:
    """Register bounded command profiles without exposing generic config writes."""

    def __init__(
        self,
        config_path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_TTL_INVALID",
                "command profile preflight TTL is outside the safe range.",
                category="validation",
            )
        self._manager = PlatformProfileRegistryManager(
            Path(config_path),
            home=Path(home),
            validate_document=validate_document,
        )
        self._now = now
        self._ttl_seconds = ttl_seconds
        self._preflights: dict[str, CommandProfilePreflight] = {}

    @staticmethod
    def _spec_hash(spec: Mapping[str, object]) -> str:
        encoded = json.dumps(dict(spec), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def preflight(
        self,
        *,
        workspace_id: str,
        profile_id: str,
        argv: list[str] | tuple[str, ...],
        allowed_args: Mapping[str, object],
        timeout_ms: int = 30000,
        max_output_bytes: int = 65536,
        resources: list[str] | tuple[str, ...] = (),
        credential_slots: list[str] | tuple[str, ...] = (),
        network_class: str = "none",
        lifecycle: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        document, _raw, config_digest, _existed, _mode = self._manager.snapshot()
        self._manager._validate_workspace_platforms(document)
        entry, workspace_path = PlatformProfileRegistrationService._workspace_entry(document, identifier)
        spec = self._manager._command_profile_spec(
            profile_id,
            tuple(argv),
            allowed_args,
            timeout_ms,
            max_output_bytes,
            tuple(resources),
            tuple(credential_slots),
            network_class,
            lifecycle,
        )
        platform, _location = self._manager._entry_platform(dict(entry))
        profiles = platform.get("command_profiles", {})
        if not isinstance(profiles, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")
        existing = profiles.get(profile_id)
        if existing is None:
            status = "new"
        elif existing == spec:
            status = "idempotent"
        else:
            raise ProvisioningError(
                "COMMAND_PROFILE_CONFLICT",
                "The command profile id is already bound to a different specification.",
                category="conflict",
            )

        created_at = float(self._now())
        preflight_id = f"command-profile-preflight:{secrets.token_urlsafe(24)}"
        confirmation = f"REGISTER_COMMAND_PROFILE:{identifier}:{profile_id}:{secrets.token_urlsafe(8)}"
        preflight = CommandProfilePreflight(
            preflight_id=preflight_id,
            confirmation=confirmation,
            workspace_id=identifier,
            workspace_path=workspace_path,
            profile_id=profile_id,
            spec=dict(spec),
            spec_hash=self._spec_hash(spec),
            config_digest=config_digest,
            status=status,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        self._preflights[preflight_id] = preflight
        return {
            "preflight_id": preflight.preflight_id,
            "workspace_id": preflight.workspace_id,
            "profile_id": preflight.profile_id,
            "network_class": preflight.spec["network_class"],
            "credential_slots": list(preflight.spec["credential_slots"]),
            "status": preflight.status,
            "config_digest": preflight.config_digest,
            "spec_hash": preflight.spec_hash,
            "approval_required": True,
            "approval": {
                "preflight_id": preflight.preflight_id,
                "confirmation": preflight.confirmation,
                "expires_at": preflight.expires_at,
            },
            "expires_at": preflight.expires_at,
            "external_execution": False,
        }

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        if not isinstance(preflight_id, str) or not preflight_id:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_REQUIRED",
                "A current command profile preflight is required.",
                category="permission",
            )
        preflight = self._preflights.get(preflight_id)
        if preflight is None:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND",
                "The command profile preflight is unknown, expired, or already consumed.",
                category="not_found",
            )
        if float(self._now()) >= preflight.expires_at:
            self._preflights.pop(preflight_id, None)
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_EXPIRED",
                "The command profile preflight has expired; create a new preflight.",
                category="permission",
            )
        if confirmation != preflight.confirmation:
            raise ProvisioningError(
                "COMMAND_PROFILE_CONFIRMATION_REQUIRED",
                "Return the exact confirmation from the preflight approval object.",
                category="permission",
            )

        mutation = self._manager.register_command_profile(
            workspace_id=preflight.workspace_id,
            expected_config_digest=preflight.config_digest,
            expected_workspace_path=preflight.workspace_path,
            profile_id=preflight.profile_id,
            argv=tuple(str(item) for item in preflight.spec["argv"]),
            allowed_args=dict(preflight.spec["allowed_args"]),
            timeout_ms=int(preflight.spec["timeout_ms"]),
            max_output_bytes=int(preflight.spec["max_output_bytes"]),
            resources=tuple(str(item) for item in preflight.spec["resources"]),
            credential_slots=tuple(str(item) for item in preflight.spec["credential_slots"]),
            network_class=str(preflight.spec["network_class"]),
            lifecycle=(dict(preflight.spec["lifecycle"]) if isinstance(preflight.spec.get("lifecycle"), Mapping) else None),
        )
        self._preflights.pop(preflight_id, None)
        payload = dict(mutation)
        payload.update(
            {
                "preflight_id": preflight_id,
                "spec_hash": preflight.spec_hash,
                "approval_consumed": True,
                "external_execution": False,
            }
        )
        return payload


@dataclass(frozen=True)
class CommandProfileCleanupPreflight:
    preflight_id: str
    confirmation: str
    workspace_id: str
    workspace_path: Path
    mode: str
    evaluation_time: str
    candidates: tuple[Mapping[str, object], ...]
    candidate_set_hash: str
    config_digest: str
    created_at: float
    expires_at: float


class CommandProfileCleanupService:
    """Reclaim only explicitly ephemeral command profiles from one pinned registry snapshot."""

    def __init__(
        self,
        config_path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_TTL_INVALID",
                "command profile preflight TTL is outside the safe range.",
                category="validation",
            )
        self._manager = PlatformProfileRegistryManager(
            Path(config_path),
            home=Path(home),
            validate_document=validate_document,
        )
        self._now = now
        self._ttl_seconds = ttl_seconds
        self._preflights: dict[str, CommandProfileCleanupPreflight] = {}

    @staticmethod
    def _profile_hash(profile: Mapping[str, object]) -> str:
        encoded = json.dumps(dict(profile), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _lifecycle_payload(profile_id: str, profile: Mapping[str, object]) -> tuple[dict[str, object] | None, str]:
        try:
            parsed = parse_command_profile(profile_id, profile)
        except PolicyError as exc:
            raise ProvisioningError(
                "COMMAND_PROFILE_INVALID",
                "A command profile failed runtime validation during cleanup preflight.",
                category="validation",
                details={"reason": str(exc)},
            ) from exc
        lifecycle = parsed.lifecycle
        if lifecycle is None:
            return None, "permanent"
        return {
            "kind": lifecycle.kind,
            "purpose": lifecycle.purpose,
            "owner": lifecycle.owner,
            "created_at": lifecycle.created_at,
            "expires_at": lifecycle.expires_at,
        }, "ephemeral"

    @staticmethod
    def _candidate_set_hash(
        *,
        workspace_id: str,
        mode: str,
        evaluation_time: str,
        config_digest: str,
        candidates: list[dict[str, object]],
    ) -> str:
        document = {
            "workspace_id": workspace_id,
            "mode": mode,
            "evaluation_time": evaluation_time,
            "config_digest": config_digest,
            "candidates": candidates,
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def preflight(self, *, workspace_id: str, mode: str = "expired") -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        if mode not in {"expired", "all_ephemeral"}:
            raise ProvisioningError(
                "COMMAND_PROFILE_CLEANUP_INVALID",
                "cleanup mode must be expired or all_ephemeral.",
                category="validation",
            )
        document, _raw, config_digest, _existed, _file_mode = self._manager.snapshot()
        self._manager._validate_workspace_platforms(document)
        entry, workspace_path = PlatformProfileRegistrationService._workspace_entry(document, identifier)
        platform, _location = self._manager._entry_platform(dict(entry))
        profiles = platform.get("command_profiles", {})
        if not isinstance(profiles, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")

        created_at = float(self._now())
        evaluation_dt = datetime.fromtimestamp(created_at, tz=timezone.utc)
        evaluation_time = evaluation_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
        candidates: list[dict[str, object]] = []
        permanent: list[str] = []
        not_expired: list[str] = []
        no_expiry: list[str] = []
        for profile_id in sorted(profiles):
            raw_profile = profiles[profile_id]
            if not isinstance(raw_profile, Mapping):
                raise ProvisioningError("CONFIG_INVALID", "command profile must be an object.", category="validation")
            lifecycle, lifecycle_kind = self._lifecycle_payload(str(profile_id), raw_profile)
            if lifecycle_kind == "permanent" or lifecycle is None:
                permanent.append(str(profile_id))
                continue
            eligible = mode == "all_ephemeral"
            reason = "all_ephemeral"
            if mode == "expired":
                expires_at = lifecycle.get("expires_at")
                if not isinstance(expires_at, str) or not expires_at:
                    no_expiry.append(str(profile_id))
                    continue
                expires_dt = datetime.fromisoformat(expires_at[:-1] + "+00:00")
                if expires_dt > evaluation_dt:
                    not_expired.append(str(profile_id))
                    continue
                eligible = True
                reason = "expired"
            if eligible:
                candidates.append(
                    {
                        "profile_id": str(profile_id),
                        "profile_hash": self._profile_hash(raw_profile),
                        "lifecycle": lifecycle,
                        "eligibility_reason": reason,
                    }
                )

        candidate_set_hash = self._candidate_set_hash(
            workspace_id=identifier,
            mode=mode,
            evaluation_time=evaluation_time,
            config_digest=config_digest,
            candidates=candidates,
        )
        ineligible = {
            "permanent": permanent,
            "not_expired": not_expired,
            "no_expiry": no_expiry,
        }
        common: dict[str, object] = {
            "workspace_id": identifier,
            "mode": mode,
            "evaluation_time": evaluation_time,
            "config_digest": config_digest,
            "candidate_set_hash": candidate_set_hash,
            "candidates": candidates,
            "ineligible": ineligible,
            "external_execution": False,
        }
        if not candidates:
            common.update({"status": "noop", "approval_required": False})
            return common

        preflight_id = f"command-profile-cleanup-preflight:{secrets.token_urlsafe(24)}"
        confirmation = f"CLEANUP_EPHEMERAL_COMMAND_PROFILES:{identifier}:{candidate_set_hash[:16]}:{secrets.token_urlsafe(8)}"
        preflight = CommandProfileCleanupPreflight(
            preflight_id=preflight_id,
            confirmation=confirmation,
            workspace_id=identifier,
            workspace_path=workspace_path,
            mode=mode,
            evaluation_time=evaluation_time,
            candidates=tuple(dict(item) for item in candidates),
            candidate_set_hash=candidate_set_hash,
            config_digest=config_digest,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        self._preflights[preflight_id] = preflight
        common.update(
            {
                "preflight_id": preflight_id,
                "status": "ready",
                "approval_required": True,
                "approval": {
                    "preflight_id": preflight_id,
                    "confirmation": confirmation,
                    "expires_at": preflight.expires_at,
                },
                "expires_at": preflight.expires_at,
            }
        )
        return common

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        if not isinstance(preflight_id, str) or not preflight_id:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_REQUIRED",
                "A current command profile cleanup preflight is required.",
                category="permission",
            )
        preflight = self._preflights.get(preflight_id)
        if preflight is None:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND",
                "The command profile cleanup preflight is unknown, expired, or already consumed.",
                category="not_found",
            )
        if float(self._now()) >= preflight.expires_at:
            self._preflights.pop(preflight_id, None)
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_EXPIRED",
                "The command profile cleanup preflight has expired; create a new preflight.",
                category="permission",
            )
        if confirmation != preflight.confirmation:
            raise ProvisioningError(
                "COMMAND_PROFILE_CONFIRMATION_REQUIRED",
                "Return the exact confirmation from the cleanup preflight approval object.",
                category="permission",
            )
        candidate_hashes = {
            str(item["profile_id"]): str(item["profile_hash"])
            for item in preflight.candidates
        }
        mutation = self._manager.cleanup_ephemeral_command_profiles(
            workspace_id=preflight.workspace_id,
            expected_config_digest=preflight.config_digest,
            expected_workspace_path=preflight.workspace_path,
            candidate_profile_hashes=candidate_hashes,
            mode=preflight.mode,
            evaluation_time=preflight.evaluation_time,
        )
        self._preflights.pop(preflight_id, None)
        payload = dict(mutation)
        payload.update(
            {
                "preflight_id": preflight_id,
                "candidate_set_hash": preflight.candidate_set_hash,
                "approval_consumed": True,
                "external_execution": False,
            }
        )
        return payload


@dataclass(frozen=True)
class CommandProfileUnregisterPreflight:
    preflight_id: str
    confirmation: str
    workspace_id: str
    workspace_path: Path
    profile_id: str
    profile_hash: str
    config_digest: str
    created_at: float
    expires_at: float


class CommandProfileUnregistrationService:
    """Remove one exact managed command profile after a pinned human approval."""

    def __init__(
        self,
        config_path: Path,
        *,
        home: Path,
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_TTL_INVALID",
                "command profile preflight TTL is outside the safe range.",
                category="validation",
            )
        self._manager = PlatformProfileRegistryManager(
            Path(config_path),
            home=Path(home),
            validate_document=validate_document,
        )
        self._now = now
        self._ttl_seconds = ttl_seconds
        self._preflights: dict[str, CommandProfileUnregisterPreflight] = {}

    @staticmethod
    def _profile_hash(profile: Mapping[str, object]) -> str:
        encoded = json.dumps(dict(profile), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def preflight(self, *, workspace_id: str, profile_id: str) -> dict[str, object]:
        identifier = validate_project_id(workspace_id, name="workspace_id")
        document, _raw, config_digest, _existed, _mode = self._manager.snapshot()
        self._manager._validate_workspace_platforms(document)
        entry, workspace_path = PlatformProfileRegistrationService._workspace_entry(document, identifier)
        platform, _location = self._manager._entry_platform(dict(entry))
        profiles = platform.get("command_profiles", {})
        if not isinstance(profiles, Mapping):
            raise ProvisioningError("CONFIG_INVALID", "command_profiles must be an object.", category="validation")
        existing = profiles.get(profile_id)
        if not isinstance(existing, Mapping):
            raise ProvisioningError(
                "COMMAND_PROFILE_NOT_FOUND",
                "The command profile is not registered.",
                category="not_found",
            )
        profile_hash = self._profile_hash(existing)
        created_at = float(self._now())
        preflight_id = f"command-profile-unregister-preflight:{secrets.token_urlsafe(24)}"
        confirmation = f"UNREGISTER_COMMAND_PROFILE:{identifier}:{profile_id}:{secrets.token_urlsafe(8)}"
        preflight = CommandProfileUnregisterPreflight(
            preflight_id=preflight_id,
            confirmation=confirmation,
            workspace_id=identifier,
            workspace_path=workspace_path,
            profile_id=profile_id,
            profile_hash=profile_hash,
            config_digest=config_digest,
            created_at=created_at,
            expires_at=created_at + self._ttl_seconds,
        )
        self._preflights[preflight_id] = preflight
        return {
            "preflight_id": preflight.preflight_id,
            "workspace_id": preflight.workspace_id,
            "profile_id": preflight.profile_id,
            "profile_hash": preflight.profile_hash,
            "config_digest": preflight.config_digest,
            "status": "ready",
            "approval_required": True,
            "approval": {
                "preflight_id": preflight.preflight_id,
                "confirmation": preflight.confirmation,
                "expires_at": preflight.expires_at,
            },
            "expires_at": preflight.expires_at,
            "external_execution": False,
        }

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        if not isinstance(preflight_id, str) or not preflight_id:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_REQUIRED",
                "A current command profile unregister preflight is required.",
                category="permission",
            )
        preflight = self._preflights.get(preflight_id)
        if preflight is None:
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_NOT_FOUND",
                "The command profile unregister preflight is unknown, expired, or already consumed.",
                category="not_found",
            )
        if float(self._now()) >= preflight.expires_at:
            self._preflights.pop(preflight_id, None)
            raise ProvisioningError(
                "COMMAND_PROFILE_PREFLIGHT_EXPIRED",
                "The command profile unregister preflight has expired; create a new preflight.",
                category="permission",
            )
        if confirmation != preflight.confirmation:
            raise ProvisioningError(
                "COMMAND_PROFILE_CONFIRMATION_REQUIRED",
                "Return the exact confirmation from the preflight approval object.",
                category="permission",
            )
        mutation = self._manager.unregister_command_profile(
            workspace_id=preflight.workspace_id,
            expected_config_digest=preflight.config_digest,
            expected_workspace_path=preflight.workspace_path,
            profile_id=preflight.profile_id,
            expected_profile_hash=preflight.profile_hash,
        )
        self._preflights.pop(preflight_id, None)
        payload = dict(mutation)
        payload.update(
            {
                "preflight_id": preflight_id,
                "profile_hash": preflight.profile_hash,
                "approval_consumed": True,
                "external_execution": False,
            }
        )
        return payload


__all__ = [
    "CommandProfileCleanupPreflight",
    "CommandProfileCleanupService",
    "CommandProfilePreflight",
    "CommandProfileRegistrationService",
    "CommandProfileUnregisterPreflight",
    "CommandProfileUnregistrationService",
    "CredentialSlotPreflight",
    "CredentialSlotRegistrationService",
    "DEFAULT_PLATFORM_PROFILE_PREFLIGHT_TTL_SECONDS",
    "PlatformProfilePreflight",
    "PlatformProfileRegistrationService",
]
