from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import time
from typing import Callable, Mapping, Sequence

from .process_runner import run_bounded
from .runtime_policy import PolicyError, validate_identifier


class CredentialSlotError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_MACOS_SECURITY = Path("/usr/bin/security")


def _default_keychain_available(source_name: str) -> bool:
    """Check a generic-password service without reading secret material."""

    if not _MACOS_SECURITY.is_file():
        return False
    try:
        result = run_bounded(
            [str(_MACOS_SECURITY), "find-generic-password", "-s", source_name],
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            timeout_seconds=3.0,
            max_output_bytes=4096,
        )
    except (OSError, ValueError):
        return False
    return not result.timed_out and result.returncode == 0


def _default_keychain_reader(source_name: str) -> str | None:
    """Resolve one generic-password value only at grant-consumption time."""

    if not _MACOS_SECURITY.is_file():
        return None
    try:
        result = run_bounded(
            [str(_MACOS_SECURITY), "find-generic-password", "-s", source_name, "-w"],
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            timeout_seconds=3.0,
            max_output_bytes=64 * 1024,
        )
    except (OSError, ValueError):
        return None
    if result.timed_out or result.output_truncated or result.returncode != 0:
        return None
    value = result.stdout.rstrip("\r\n")
    return value or None


@dataclass(frozen=True)
class CredentialSlotPolicy:
    slot: str
    source_kind: str
    source_name: str
    allowed_profiles: tuple[str, ...]
    allowed_projects: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.slot, field="credential slot", max_length=80)
            validate_identifier(self.source_name, field="credential source", max_length=128)
            for item in self.allowed_profiles:
                validate_identifier(item, field="command profile", max_length=80)
            for item in self.allowed_projects:
                validate_identifier(item, field="project", max_length=80)
        except PolicyError as exc:
            raise CredentialSlotError("CREDENTIAL_SLOT_POLICY_INVALID", str(exc)) from exc
        if self.source_kind not in {"env", "keychain"}:
            raise CredentialSlotError("CREDENTIAL_SLOT_POLICY_INVALID", "source kind must be env or keychain")
        if not self.allowed_profiles or not self.allowed_projects:
            raise CredentialSlotError("CREDENTIAL_SLOT_POLICY_INVALID", "slot policy must bind profiles and projects")


@dataclass
class _Grant:
    grant_id: str
    slot: str
    project_id: str
    command_profile: str
    expires_at: float
    consumed_at: float | None = None


class CredentialSlotManager:
    """Resolves credential material only at child-process injection time."""

    def __init__(
        self,
        policies: Sequence[CredentialSlotPolicy],
        *,
        environ: Mapping[str, str] | None = None,
        keychain_reader: Callable[[str], str | None] | None = None,
        keychain_available: Callable[[str], bool] | None = None,
        clock: Callable[[], float] | None = None,
        grant_ttl_seconds: float = 120.0,
    ) -> None:
        self._policies = {policy.slot: policy for policy in policies}
        if len(self._policies) != len(tuple(policies)):
            raise CredentialSlotError("CREDENTIAL_SLOT_POLICY_INVALID", "duplicate slot")
        self._environ = dict(os.environ if environ is None else environ)
        self._keychain_reader = keychain_reader or _default_keychain_reader
        self._keychain_available = keychain_available or _default_keychain_available
        self._clock = clock or time.time
        self._grant_ttl = float(grant_ttl_seconds)
        self._grants: dict[str, _Grant] = {}

    def _policy(self, slot: str) -> CredentialSlotPolicy:
        policy = self._policies.get(slot)
        if policy is None:
            raise CredentialSlotError("CREDENTIAL_SLOT_UNKNOWN", "credential slot is not registered")
        return policy

    def _available(self, policy: CredentialSlotPolicy) -> bool:
        if policy.source_kind == "env":
            return bool(self._environ.get(policy.source_name))
        return bool(self._keychain_available and self._keychain_available(policy.source_name))

    def list_slots(self, *, project_id: str) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for policy in sorted(self._policies.values(), key=lambda item: item.slot):
            if project_id not in policy.allowed_projects:
                continue
            result.append({
                "slot": policy.slot,
                "available": self._available(policy),
                "value": "hidden",
                "allowed_profiles": list(policy.allowed_profiles),
                "source": policy.source_kind,
            })
        return result

    def validate_slot_access(self, slot: str, *, project_id: str, command_profile: str) -> str:
        """Validate one slot policy and availability without reading credential material."""

        policy = self._policy(slot)
        if project_id not in policy.allowed_projects or command_profile not in policy.allowed_profiles:
            raise CredentialSlotError("CREDENTIAL_SLOT_DENIED", "slot is not allowed for this project/profile")
        if not self._available(policy):
            raise CredentialSlotError("CREDENTIAL_SLOT_UNAVAILABLE", "slot material is unavailable")
        return policy.slot

    def preflight(self, slot: str, *, project_id: str, command_profile: str) -> dict[str, object]:
        slot = self.validate_slot_access(slot, project_id=project_id, command_profile=command_profile)
        now = float(self._clock())
        grant_id = secrets.token_urlsafe(18)
        self._grants[grant_id] = _Grant(grant_id, slot, project_id, command_profile, now + self._grant_ttl)
        return {
            "grant_id": grant_id,
            "slot": slot,
            "available": True,
            "value": "hidden",
            "project_id": project_id,
            "command_profile": command_profile,
            "expires_at": now + self._grant_ttl,
            "one_shot": True,
        }

    def validate_grants(self, grant_ids: Sequence[str], *, project_id: str, command_profile: str) -> tuple[str, ...]:
        now = float(self._clock())
        slots: list[str] = []
        for grant_id in grant_ids:
            grant = self._grants.get(grant_id)
            if grant is None or grant.consumed_at is not None:
                raise CredentialSlotError("CREDENTIAL_GRANT_INVALID", "grant is unknown or consumed")
            if now > grant.expires_at:
                raise CredentialSlotError("CREDENTIAL_GRANT_EXPIRED", "grant has expired")
            if grant.project_id != project_id or grant.command_profile != command_profile:
                raise CredentialSlotError("CREDENTIAL_GRANT_SCOPE_MISMATCH", "grant scope does not match")
            slots.append(grant.slot)
        if len(set(slots)) != len(slots):
            raise CredentialSlotError("CREDENTIAL_GRANT_INVALID", "duplicate slot grants are not allowed")
        return tuple(slots)

    def _resolve_material(self, policy: CredentialSlotPolicy) -> str:
        if policy.source_kind == "env":
            material = self._environ.get(policy.source_name)
        else:
            material = self._keychain_reader(policy.source_name) if self._keychain_reader else None
        if not isinstance(material, str) or not material:
            raise CredentialSlotError("CREDENTIAL_SLOT_UNAVAILABLE", "slot material became unavailable")
        return material

    def resolve_grants(self, grant_ids: Sequence[str], *, project_id: str, command_profile: str) -> tuple[dict[str, str], tuple[str, ...]]:
        """Resolve validated grant material without consuming one-shot grants.

        Read-only preflight operations may need the same credential grant that
        a later approved mutation will consume.  Resolution is deliberately
        separate from consumption so a preflight cannot invalidate its own
        apply step.
        """

        self.validate_grants(grant_ids, project_id=project_id, command_profile=command_profile)
        child_env: dict[str, str] = {}
        redact_values: list[str] = []
        for grant_id in grant_ids:
            grant = self._grants[grant_id]
            policy = self._policy(grant.slot)
            material = self._resolve_material(policy)
            child_env[policy.slot] = material
            redact_values.append(material)
        return child_env, tuple(redact_values)

    def consume_grants(self, grant_ids: Sequence[str], *, project_id: str, command_profile: str) -> tuple[dict[str, str], tuple[str, ...]]:
        child_env, redact_values = self.resolve_grants(
            grant_ids,
            project_id=project_id,
            command_profile=command_profile,
        )
        now = float(self._clock())
        for grant_id in grant_ids:
            grant = self._grants[grant_id]
            grant.consumed_at = now
        return child_env, redact_values

    def invalidate_all_grants(self) -> None:
        self._grants.clear()
