"""Bounded dependency-management workflows."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time
import uuid
from typing import Mapping, Sequence

from .command_profiles import CommandProfileController, CommandProfileError


PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
NODE_PACKAGE_RE = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._-]{0,63}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")


class DependencyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _Preflight:
    preflight_id: str
    project_id: str
    ecosystem: str
    manifest: str
    manifest_hash: str
    lock_hashes: tuple[tuple[str, str], ...]
    action: str
    package: str
    version: str
    command_profile: str
    lifecycle_script_risk: bool
    created_at: float


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class DependencyManager:
    def __init__(self, command_profiles: CommandProfileController, *, ecosystem_profiles: Mapping[str, str], audit_profiles: Mapping[str, str] | None = None) -> None:
        self._commands = command_profiles
        self._profiles = dict(ecosystem_profiles)
        self._audit_profiles = dict(audit_profiles or {})
        self._preflights: dict[str, _Preflight] = {}

    @staticmethod
    def _locks(repo: Path, ecosystem: str) -> tuple[str, ...]:
        choices = {"python": ("uv.lock", "poetry.lock", "requirements.lock"), "node": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"), "rust": ("Cargo.lock",)}[ecosystem]
        return tuple(name for name in choices if (repo / name).is_file())

    def detect(self, repo: Path) -> dict[str, object]:
        root = repo.resolve(strict=True)
        if (root / "pyproject.toml").is_file():
            ecosystem, manifest = "python", "pyproject.toml"
        elif (root / "package.json").is_file():
            ecosystem, manifest = "node", "package.json"
        elif (root / "Cargo.toml").is_file():
            ecosystem, manifest = "rust", "Cargo.toml"
        else:
            raise DependencyError("DEPENDENCY_ECOSYSTEM_UNSUPPORTED", "no supported manifest was detected")
        return {"ecosystem": ecosystem, "manifest": manifest, "lockfiles": list(self._locks(root, ecosystem))}

    @staticmethod
    def _package(ecosystem: str, value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 160:
            raise DependencyError("DEPENDENCY_PACKAGE_INVALID", "package name is invalid")
        lowered = value.casefold()
        if "://" in value or lowered.startswith(("git+", "file:", "path:", ".", "/", "~")) or "\\" in value or ".." in value:
            raise DependencyError("DEPENDENCY_SOURCE_DENIED", "git, URL, and path dependencies are denied by default")
        matcher = NODE_PACKAGE_RE if ecosystem == "node" else PACKAGE_RE
        if not matcher.fullmatch(value):
            raise DependencyError("DEPENDENCY_PACKAGE_INVALID", "package name is outside policy")
        return value

    @staticmethod
    def _version(value: object, action: str) -> str:
        if action == "remove" and value in (None, ""):
            return ""
        if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
            raise DependencyError("DEPENDENCY_VERSION_INVALID", "an exact bounded registry version is required")
        return value

    @staticmethod
    def _lifecycle_risk(repo: Path, ecosystem: str) -> bool:
        if ecosystem == "node":
            try:
                document = json.loads((repo / "package.json").read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                return True
            scripts = document.get("scripts", {}) if isinstance(document, dict) else {}
            return isinstance(scripts, dict) and any(name in scripts for name in ("preinstall", "install", "postinstall"))
        if ecosystem == "python":
            if (repo / "setup.py").exists():
                return True
            try:
                return "build-backend" in (repo / "pyproject.toml").read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return True
        return (repo / "build.rs").exists()

    def _profile_metadata(self, profile_id: str) -> dict[str, object]:
        for item in self._commands.list_profiles():
            if item["profile"] == profile_id:
                return item
        raise DependencyError("DEPENDENCY_PROFILE_UNAVAILABLE", "registered dependency profile is unavailable")

    def preflight(self, repo: Path, *, project_id: str, action: str, package: str, version: str = "") -> dict[str, object]:
        if action not in {"add", "remove"}:
            raise DependencyError("DEPENDENCY_ACTION_INVALID", "action must be add or remove")
        root = repo.resolve(strict=True)
        detected = self.detect(root)
        ecosystem = str(detected["ecosystem"])
        package_name = self._package(ecosystem, package)
        version_text = self._version(version, action)
        profile_id = self._profiles.get(f"{ecosystem}:{action}")
        if not profile_id:
            raise DependencyError("DEPENDENCY_PROFILE_UNAVAILABLE", "operator did not register this dependency action")
        if self._profile_metadata(profile_id).get("network_class") != "dependency":
            raise DependencyError("DEPENDENCY_NETWORK_POLICY_INVALID", "dependency action requires dependency-specific network policy")
        manifest = str(detected["manifest"])
        manifest_hash = _hash_file(root / manifest)
        lock_hashes = tuple((name, _hash_file(root / name)) for name in detected["lockfiles"])
        lifecycle_risk = self._lifecycle_risk(root, ecosystem)
        preflight_id = "dep-" + uuid.uuid4().hex
        self._preflights[preflight_id] = _Preflight(
            preflight_id, project_id, ecosystem, manifest, manifest_hash, lock_hashes,
            action, package_name, version_text, profile_id, lifecycle_risk, time.time(),
        )
        return {
            "preflight_id": preflight_id,
            "status": "ready",
            "ecosystem": ecosystem,
            "action": action,
            "package": package_name,
            "version": version_text,
            "manifest": manifest,
            "manifest_hash": manifest_hash,
            "lockfiles": [{"path": name, "hash": value} for name, value in lock_hashes],
            "command_profile": profile_id,
            "network_class": "dependency",
            "lifecycle_script_risk": lifecycle_risk,
            "transitive_delta": "known_after_apply",
            "vulnerability_audit": "known_after_apply",
            "license_audit": "best_effort_after_apply",
            "external_execution": False,
        }

    def _pins_unchanged(self, root: Path, record: _Preflight) -> None:
        if not (root / record.manifest).is_file() or _hash_file(root / record.manifest) != record.manifest_hash:
            raise DependencyError("DEPENDENCY_PREFLIGHT_STALE", "manifest changed after preflight")
        current = tuple((name, _hash_file(root / name)) for name, _ in record.lock_hashes if (root / name).is_file())
        if current != record.lock_hashes:
            raise DependencyError("DEPENDENCY_PREFLIGHT_STALE", "lockfile changed after preflight")

    @staticmethod
    def _spec(record: _Preflight) -> str:
        if record.action == "remove":
            return record.package
        return f"{record.package}=={record.version}" if record.ecosystem == "python" else f"{record.package}@{record.version}"

    def apply(self, repo: Path, preflight_id: str) -> dict[str, object]:
        record = self._preflights.pop(preflight_id, None)
        if record is None:
            raise DependencyError("DEPENDENCY_PREFLIGHT_INVALID", "preflight is unknown or consumed")
        root = repo.resolve(strict=True)
        self._pins_unchanged(root, record)
        try:
            command_pre = self._commands.preflight(
                root, record.command_profile, {"package": self._spec(record)}, project_id=record.project_id,
            )
            command_result = self._commands.run(root, str(command_pre["preflight_id"]))
        except CommandProfileError as exc:
            raise DependencyError(exc.code, str(exc)) from exc
        manifest_after = _hash_file(root / record.manifest) if (root / record.manifest).is_file() else "missing"
        after_locks = {name: _hash_file(root / name) for name in self._locks(root, record.ecosystem)}
        before_locks = dict(record.lock_hashes)
        return {
            "status": command_result["status"],
            "ecosystem": record.ecosystem,
            "action": record.action,
            "package": record.package,
            "version": record.version,
            "command_profile": record.command_profile,
            "manifest_hash_before": record.manifest_hash,
            "manifest_hash_after": manifest_after,
            "manifest_changed": record.manifest_hash != manifest_after,
            "lockfiles_before": before_locks,
            "lockfiles_after": after_locks,
            "lockfile_changed": before_locks != after_locks,
            "lifecycle_script_risk": record.lifecycle_script_risk,
            "command": command_result,
            "recommended_verification": ["test", "build"],
            "external_execution": False,
        }

    def audit(self, repo: Path, *, project_id: str) -> dict[str, object]:
        root = repo.resolve(strict=True)
        detected = self.detect(root)
        ecosystem = str(detected["ecosystem"])
        manifest = str(detected["manifest"])
        return {
            "ecosystem": ecosystem,
            "manifest": manifest,
            "manifest_hash": _hash_file(root / manifest),
            "lockfiles": [{"path": name, "hash": _hash_file(root / name)} for name in detected["lockfiles"]],
            "lifecycle_script_risk": self._lifecycle_risk(root, ecosystem),
            "vulnerabilities": {"status": "audit_profile_not_configured"},
            "licenses": {"status": "best_effort_unavailable"},
            "project_id": project_id,
            "external_execution": False,
        }
