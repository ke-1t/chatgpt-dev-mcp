"""Validated project profiles for the opt-in Director control plane.

Profiles are data, not an execution authority.  The active MCP registry is not
read or modified here; a later adapter can translate a validated profile into
the existing workspace configuration after an explicit review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .director import contains_secret_like_content, normalize_relative_path, validate_workspace_id


PROFILE_NAMES = ("READ_ONLY", "READ_WRITE", "DEVELOPMENT")
TASK_NAMES = ("test", "lint", "build", "dev", "format")
_MAX_TEXT = 160
_MAX_COMMAND = 400
_MAX_PATHS = 32
_FORBIDDEN_COMMAND_SYNTAX = re.compile(r"(?:\r|\n|;|\|\||(?<!\|)\|(?!\|)|`|\$\(|[<>])")


class ProfileValidationError(ValueError):
    """Raised when a project profile is outside the safe data contract."""


def _text(value: object, *, name: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ProfileValidationError(f"{name} must be text")
    if not allow_empty and not value.strip():
        raise ProfileValidationError(f"{name} must not be empty")
    if len(value) > maximum or "\x00" in value or contains_secret_like_content(value):
        raise ProfileValidationError(f"{name} is outside the safety bound")
    return value.strip()


def _command(value: object, *, name: str) -> str:
    command = _text(value, name=name, maximum=_MAX_COMMAND)
    if _FORBIDDEN_COMMAND_SYNTAX.search(command):
        raise ProfileValidationError(f"{name} contains shell composition syntax")
    return command


@dataclass(frozen=True)
class ProjectProfile:
    """A bounded, reviewable description of one workspace."""

    workspace_id: str
    profile: str
    language: str
    framework: str
    canonical_paths: tuple[str, ...]
    commands: Mapping[str, str]
    verification_tasks: tuple[str, ...]
    external_execution: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "workspace_id", validate_workspace_id(self.workspace_id))
        if self.profile not in PROFILE_NAMES:
            raise ProfileValidationError("profile is invalid")
        object.__setattr__(self, "language", _text(self.language, name="language", maximum=_MAX_TEXT))
        object.__setattr__(self, "framework", _text(self.framework, name="framework", maximum=_MAX_TEXT))
        if not isinstance(self.external_execution, bool):
            raise ProfileValidationError("external_execution must be boolean")

        if not isinstance(self.canonical_paths, (tuple, list)):
            raise ProfileValidationError("canonical_paths must be a sequence")
        normalized_paths = tuple(normalize_relative_path(path) for path in self.canonical_paths)
        if not normalized_paths or len(normalized_paths) > _MAX_PATHS or len(set(normalized_paths)) != len(normalized_paths):
            raise ProfileValidationError("canonical_paths is invalid")
        object.__setattr__(self, "canonical_paths", normalized_paths)

        if not isinstance(self.commands, Mapping):
            raise ProfileValidationError("commands must be a mapping")
        parsed_commands: dict[str, str] = {}
        for task, command in self.commands.items():
            if task not in TASK_NAMES:
                raise ProfileValidationError("commands contains an unknown task")
            parsed_commands[task] = _command(command, name=f"commands.{task}")
        object.__setattr__(self, "commands", MappingProxyType(parsed_commands))

        if not isinstance(self.verification_tasks, (tuple, list)):
            raise ProfileValidationError("verification_tasks must be a sequence")
        parsed_verification = tuple(self.verification_tasks)
        if any(task not in parsed_commands or task not in {"test", "lint", "build"} for task in parsed_verification):
            raise ProfileValidationError("verification_tasks must reference test, lint, or build commands")
        if len(set(parsed_verification)) != len(parsed_verification):
            raise ProfileValidationError("verification_tasks contains duplicates")
        object.__setattr__(self, "verification_tasks", parsed_verification)

    @classmethod
    def from_mapping(cls, raw: object) -> "ProjectProfile":
        if not isinstance(raw, dict):
            raise ProfileValidationError("profile must be an object")
        allowed = {
            "workspace_id",
            "profile",
            "language",
            "framework",
            "canonical_paths",
            "commands",
            "verification_tasks",
            "external_execution",
        }
        if set(raw) - allowed:
            raise ProfileValidationError("profile contains unknown keys")
        raw_paths = raw.get("canonical_paths")
        if not isinstance(raw_paths, list):
            raise ProfileValidationError("canonical_paths must be a list")
        raw_commands = raw.get("commands")
        if not isinstance(raw_commands, dict):
            raise ProfileValidationError("commands must be an object")
        raw_verification = raw.get("verification_tasks")
        if raw_verification is None:
            raw_verification = [task for task in ("test", "lint", "build") if task in raw_commands]
        if not isinstance(raw_verification, list) or any(not isinstance(task, str) for task in raw_verification):
            raise ProfileValidationError("verification_tasks must be a list of task names")
        return cls(
            workspace_id=raw.get("workspace_id"),
            profile=raw.get("profile"),
            language=raw.get("language", "unknown"),
            framework=raw.get("framework", "unknown"),
            canonical_paths=tuple(raw_paths),
            commands=raw_commands,
            verification_tasks=tuple(raw_verification),
            external_execution=raw.get("external_execution", False),
        )

    def command_for(self, task: str) -> str:
        if task not in self.commands:
            raise ProfileValidationError(f"task is not configured: {task}")
        return self.commands[task]

    def as_dict(self, *, include_commands: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "workspace_id": self.workspace_id,
            "profile": self.profile,
            "language": self.language,
            "framework": self.framework,
            "canonical_paths": list(self.canonical_paths),
            "commands": sorted(self.commands),
            "verification_tasks": list(self.verification_tasks),
            "external_execution": self.external_execution,
        }
        if include_commands:
            payload["command_profiles"] = dict(self.commands)
        return payload
