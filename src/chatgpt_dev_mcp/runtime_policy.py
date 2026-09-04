from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import posixpath
import re
from typing import Any, Mapping


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHELL_META_RE = re.compile(r"[|;&<>`]|\$\(|\$\{|\n|\r|\x00")
SHELL_EXECUTABLES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "pwsh", "powershell", "cmd", "cmd.exe"})
RESOURCE_NAMESPACES = frozenset({"path", "port", "sqlite", "browser-profile", "desktop-instance", "dev-server", "output-dir", "test-account", "tauri"})


class PolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_identifier(value: object, *, field: str = "identifier", max_length: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or not IDENTIFIER_RE.fullmatch(value):
        raise PolicyError("POLICY_IDENTIFIER_INVALID", f"{field} is invalid")
    return value


def normalize_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 240 or "\x00" in value:
        raise PolicyError("POLICY_PATH_INVALID", "path must be a bounded relative path")
    text = value.replace("\\", "/")
    if text.startswith(("/", "~/")):
        raise PolicyError("POLICY_PATH_INVALID", "absolute paths are not allowed")
    normalized = posixpath.normpath(text)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise PolicyError("POLICY_PATH_INVALID", "path escapes the workspace")
    return normalized


def normalize_resource(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 240 or ":" not in value:
        raise PolicyError("RESOURCE_INVALID", "resource must use a known namespace")
    namespace, raw = value.split(":", 1)
    namespace = namespace.strip().lower()
    if namespace not in RESOURCE_NAMESPACES:
        raise PolicyError("RESOURCE_NAMESPACE_DENIED", "resource namespace is not allowed")
    raw = raw.strip()
    if not raw:
        raise PolicyError("RESOURCE_INVALID", "resource value is required")
    if namespace == "port":
        if not raw.isdigit():
            raise PolicyError("RESOURCE_PORT_INVALID", "port must be numeric")
        port = int(raw, 10)
        if not 1 <= port <= 65535:
            raise PolicyError("RESOURCE_PORT_INVALID", "port is outside the allowed range")
        return f"port:{port}"
    if namespace in {"path", "output-dir"}:
        return f"{namespace}:{normalize_relative_path(raw)}"
    normalized_id = validate_identifier(raw.lower(), field="resource", max_length=128)
    return f"{namespace}:{normalized_id}"


def _validate_safe_scalar(value: str, *, field: str, max_length: int) -> str:
    if not value or len(value) > max_length or SHELL_META_RE.search(value):
        raise PolicyError("COMMAND_ARGUMENT_DENIED", f"{field} contains unsupported command composition")
    return value


@dataclass(frozen=True)
class ArgSpec:
    name: str
    kind: str
    flag: str
    choices: tuple[str, ...] = ()
    max_length: int = 160
    required: bool = False


@dataclass(frozen=True)
class CommandProfileLifecycle:
    kind: str
    purpose: str
    owner: str
    created_at: str
    expires_at: str | None = None


@dataclass(frozen=True)
class CommandProfile:
    identifier: str
    argv: tuple[str, ...]
    allowed_args: tuple[ArgSpec, ...]
    timeout_ms: int = 30000
    max_output_bytes: int = 65536
    resources: tuple[str, ...] = ()
    credential_slots: tuple[str, ...] = ()
    network_class: str = "none"
    lifecycle: CommandProfileLifecycle | None = None

    @property
    def definition_hash(self) -> str:
        document = {
            "identifier": self.identifier,
            "argv": self.argv,
            "allowed_args": [spec.__dict__ for spec in self.allowed_args],
            "timeout_ms": self.timeout_ms,
            "max_output_bytes": self.max_output_bytes,
            "resources": self.resources,
            "credential_slots": self.credential_slots,
            "network_class": self.network_class,
        }
        if self.lifecycle is not None:
            document["lifecycle"] = {
                "kind": self.lifecycle.kind,
                "purpose": self.lifecycle.purpose,
                "owner": self.lifecycle.owner,
                "created_at": self.lifecycle.created_at,
                "expires_at": self.lifecycle.expires_at,
            }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


def _parse_utc_rfc3339(value: object, *, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value or len(value) > 64 or not value.endswith("Z"):
        raise PolicyError("COMMAND_PROFILE_INVALID", f"{field} must be a UTC RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PolicyError("COMMAND_PROFILE_INVALID", f"{field} must be a UTC RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise PolicyError("COMMAND_PROFILE_INVALID", f"{field} must be UTC")
    return value, parsed.astimezone(timezone.utc)


def _parse_command_profile_lifecycle(raw: object) -> CommandProfileLifecycle | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle must be an object")
    allowed_keys = {"kind", "purpose", "owner", "created_at", "expires_at"}
    if set(raw) - allowed_keys:
        raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle contains unknown keys")
    kind = raw.get("kind")
    if kind != "ephemeral":
        raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle kind must be ephemeral")
    purpose = raw.get("purpose")
    owner = raw.get("owner")
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 160 or any(ch in purpose for ch in "\n\r\x00"):
        raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle purpose is invalid")
    if not isinstance(owner, str) or not owner.strip() or len(owner) > 160 or any(ch in owner for ch in "\n\r\x00"):
        raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle owner is invalid")
    created_at, created = _parse_utc_rfc3339(raw.get("created_at"), field="lifecycle created_at")
    expires_at_raw = raw.get("expires_at")
    expires_at: str | None = None
    if expires_at_raw is not None:
        expires_at, expires = _parse_utc_rfc3339(expires_at_raw, field="lifecycle expires_at")
        lifetime = expires - created
        if lifetime <= timedelta(0) or lifetime > timedelta(days=7):
            raise PolicyError("COMMAND_PROFILE_INVALID", "lifecycle expiry is outside the allowed lifetime")
    return CommandProfileLifecycle(
        kind="ephemeral",
        purpose=purpose,
        owner=owner,
        created_at=created_at,
        expires_at=expires_at,
    )


def parse_command_profile(identifier: str, raw: Mapping[str, Any]) -> CommandProfile:
    validate_identifier(identifier, field="command profile", max_length=80)
    if not isinstance(raw, Mapping):
        raise PolicyError("COMMAND_PROFILE_INVALID", "command profile must be an object")
    allowed_keys = {"argv", "allowed_args", "timeout_ms", "max_output_bytes", "resources", "credential_slots", "network_class", "lifecycle"}
    if set(raw) - allowed_keys:
        raise PolicyError("COMMAND_PROFILE_INVALID", "command profile contains unknown keys")
    argv_raw = raw.get("argv")
    if not isinstance(argv_raw, list) or not 1 <= len(argv_raw) <= 32:
        raise PolicyError("COMMAND_PROFILE_INVALID", "argv must be a non-empty bounded list")
    argv: list[str] = []
    for item in argv_raw:
        if not isinstance(item, str) or not item or len(item) > 240 or "\x00" in item or "\n" in item or "\r" in item or SHELL_META_RE.search(item):
            raise PolicyError("COMMAND_PROFILE_INVALID", "argv contains an invalid item")
        argv.append(item)
    executable = os.path.basename(argv[0]).lower()
    if executable in SHELL_EXECUTABLES:
        raise PolicyError("COMMAND_EXECUTABLE_DENIED", "shell executables are not allowed")

    args_raw = raw.get("allowed_args", {})
    if not isinstance(args_raw, Mapping) or len(args_raw) > 32:
        raise PolicyError("COMMAND_PROFILE_INVALID", "allowed_args must be a bounded object")
    specs: list[ArgSpec] = []
    for name, spec_raw in args_raw.items():
        validate_identifier(name, field="argument name", max_length=80)
        if not isinstance(spec_raw, Mapping) or set(spec_raw) - {"type", "flag", "choices", "max_length", "required"}:
            raise PolicyError("COMMAND_PROFILE_INVALID", "argument spec is invalid")
        kind = spec_raw.get("type")
        if kind not in {"path", "selector", "choice", "integer", "boolean"}:
            raise PolicyError("COMMAND_PROFILE_INVALID", "unsupported argument type")
        flag = spec_raw.get("flag", "")
        if not isinstance(flag, str) or len(flag) > 80 or SHELL_META_RE.search(flag):
            raise PolicyError("COMMAND_PROFILE_INVALID", "argument flag is invalid")
        if flag and not re.fullmatch(r"--?[A-Za-z0-9][A-Za-z0-9_-]*", flag):
            raise PolicyError("COMMAND_PROFILE_INVALID", "argument flag is not fixed")
        choices_raw = spec_raw.get("choices", [])
        if kind == "choice":
            if not isinstance(choices_raw, list) or not choices_raw or len(choices_raw) > 32:
                raise PolicyError("COMMAND_PROFILE_INVALID", "choice arguments require choices")
            choices = tuple(_validate_safe_scalar(str(item), field=name, max_length=80) for item in choices_raw)
        else:
            if choices_raw not in ([], None):
                raise PolicyError("COMMAND_PROFILE_INVALID", "choices are only valid for choice arguments")
            choices = ()
        max_length = spec_raw.get("max_length", 160)
        if isinstance(max_length, bool) or not isinstance(max_length, int) or not 1 <= max_length <= 1000:
            raise PolicyError("COMMAND_PROFILE_INVALID", "max_length is invalid")
        required = spec_raw.get("required", False)
        if not isinstance(required, bool):
            raise PolicyError("COMMAND_PROFILE_INVALID", "required must be boolean")
        specs.append(ArgSpec(name, kind, flag, choices, max_length, required))

    timeout_ms = raw.get("timeout_ms", 30000)
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 120000:
        raise PolicyError("COMMAND_PROFILE_INVALID", "timeout_ms is invalid")
    max_output = raw.get("max_output_bytes", 65536)
    if isinstance(max_output, bool) or not isinstance(max_output, int) or not 1024 <= max_output <= 1048576:
        raise PolicyError("COMMAND_PROFILE_INVALID", "max_output_bytes is invalid")
    resources_raw = raw.get("resources", [])
    if not isinstance(resources_raw, list) or len(resources_raw) > 32:
        raise PolicyError("COMMAND_PROFILE_INVALID", "resources are invalid")
    resources = tuple(normalize_resource(value) for value in resources_raw)
    if len(set(resources)) != len(resources):
        raise PolicyError("COMMAND_PROFILE_INVALID", "resources contain aliases or duplicates")
    slots_raw = raw.get("credential_slots", [])
    if not isinstance(slots_raw, list) or len(slots_raw) > 16:
        raise PolicyError("COMMAND_PROFILE_INVALID", "credential slots are invalid")
    slots = tuple(validate_identifier(value, field="credential slot", max_length=80) for value in slots_raw)
    network_class = raw.get("network_class", "none")
    if network_class not in {"none", "github", "dependency", "browser", "api-test"}:
        raise PolicyError("COMMAND_PROFILE_INVALID", "network_class is invalid")
    lifecycle = _parse_command_profile_lifecycle(raw.get("lifecycle"))
    return CommandProfile(identifier, tuple(argv), tuple(specs), timeout_ms, max_output, resources, slots, network_class, lifecycle)


def render_typed_args(profile: CommandProfile, values: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(values, Mapping):
        raise PolicyError("COMMAND_ARGUMENTS_INVALID", "arguments must be an object")
    specs = {spec.name: spec for spec in profile.allowed_args}
    if set(values) - set(specs):
        raise PolicyError("COMMAND_ARGUMENTS_INVALID", "unknown command argument")
    argv = list(profile.argv)
    for spec in profile.allowed_args:
        if spec.name not in values:
            if spec.required:
                raise PolicyError("COMMAND_ARGUMENTS_INVALID", f"missing required argument: {spec.name}")
            continue
        raw = values[spec.name]
        rendered: str | None
        if spec.kind == "boolean":
            if not isinstance(raw, bool):
                raise PolicyError("COMMAND_ARGUMENTS_INVALID", f"{spec.name} must be boolean")
            if not raw:
                continue
            rendered = None
        elif spec.kind == "integer":
            if isinstance(raw, bool) or not isinstance(raw, int) or abs(raw) > 1_000_000_000:
                raise PolicyError("COMMAND_ARGUMENTS_INVALID", f"{spec.name} must be a bounded integer")
            rendered = str(raw)
        elif spec.kind == "path":
            rendered = normalize_relative_path(raw)
        else:
            if not isinstance(raw, str):
                raise PolicyError("COMMAND_ARGUMENTS_INVALID", f"{spec.name} must be a string")
            rendered = _validate_safe_scalar(raw, field=spec.name, max_length=spec.max_length)
            if spec.kind == "choice" and rendered not in spec.choices:
                raise PolicyError("COMMAND_ARGUMENTS_INVALID", f"{spec.name} is not an allowed choice")
        if spec.flag:
            argv.append(spec.flag)
        if rendered is not None:
            argv.append(rendered)
    return tuple(argv)
