"""Fail-closed, allowlisted updates for registered project policy."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


POLICY_KEYS = frozenset(
    {
        "auto_create_sessions",
        "auto_resume_sessions",
        "auto_resume_policy",
        "max_parallel_sessions",
        "allow_workspace_wide",
        "integration_requires_approval",
        "commit_requires_approval",
        "push_requires_approval",
        "verified_auto_commit",
        "auto_approve_safe_local",
        "auto_approve_local_maintenance",
        "manual_approval_ttl_seconds",
        "trusted_session_grant_ttl_seconds",
        "trust_level",
    }
)
APPROVAL_KEYS = frozenset(
    {
        "integration_requires_approval",
        "commit_requires_approval",
        "push_requires_approval",
    }
)
MAX_PARALLEL_SESSIONS = 16
POLICY_DIGEST_RE = r"^[0-9a-f]{64}$"


class ProjectPolicyError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        category: str = "validation",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.details = details or {}


@dataclass(frozen=True)
class ConfigIdentity:
    device: int
    inode: int
    mode: int

    def as_dict(self) -> dict[str, int]:
        return {"device": self.device, "inode": self.inode}


@dataclass(frozen=True)
class ConfigSnapshot:
    path: Path
    raw: bytes
    document: dict[str, Any]
    digest: str
    identity: ConfigIdentity


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(path: Path) -> ConfigIdentity:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise ProjectPolicyError("CONFIG_NOT_FOUND", "The local project registry does not exist.", category="not_found") from None
    except OSError as exc:
        raise ProjectPolicyError("CONFIG_IDENTITY_CHANGED", "The local project registry could not be inspected.", category="runtime", details={"reason": str(exc)}) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProjectPolicyError("CONFIG_IDENTITY_CHANGED", "The local project registry must be a regular non-symlink file.", category="security")
    return ConfigIdentity(int(info.st_dev), int(info.st_ino), stat.S_IMODE(info.st_mode))


def _read(path: Path) -> ConfigSnapshot:
    identity = _identity(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectPolicyError("CONFIG_INVALID", "The local project registry is not valid UTF-8 JSON.", category="validation", details={"reason": str(exc)}) from None
    # Pin the file identity across the read.  A replacement between lstat and
    # read must never be accepted as a coherent config snapshot.
    if _identity(path) != identity:
        raise ProjectPolicyError("CONFIG_IDENTITY_CHANGED", "The local project registry identity changed while it was being read.", category="conflict")
    if not isinstance(document, dict):
        raise ProjectPolicyError("CONFIG_INVALID", "The local project registry must contain a JSON object.", category="validation")
    return ConfigSnapshot(path, raw, document, _digest(raw), identity)


def _workspace(document: Mapping[str, Any], workspace_id: object) -> tuple[str, dict[str, Any]]:
    if not isinstance(workspace_id, str) or not workspace_id or len(workspace_id) > 64:
        raise ProjectPolicyError("PROJECT_POLICY_UPDATE_DENIED", "workspace_id must identify one registered workspace.", category="validation")
    workspaces = document.get("workspaces")
    if not isinstance(workspaces, dict) or workspace_id not in workspaces or not isinstance(workspaces[workspace_id], dict):
        raise ProjectPolicyError("PROJECT_POLICY_UPDATE_DENIED", "The requested workspace is not registered.", category="not_found")
    return workspace_id, workspaces[workspace_id]


def _policy_location(entry: Mapping[str, Any]) -> tuple[str, ...]:
    if "isolated_development" in entry:
        return ("isolated_development",)
    metadata = entry.get("metadata")
    if isinstance(metadata, dict) and "isolated_development" in metadata:
        return ("metadata", "isolated_development")
    return ("isolated_development",)


def _get_at(entry: Mapping[str, Any], location: tuple[str, ...]) -> Mapping[str, Any]:
    value: object = entry
    for key in location:
        value = value.get(key) if isinstance(value, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _set_at(entry: dict[str, Any], location: tuple[str, ...], value: dict[str, Any]) -> None:
    if location == ("isolated_development",):
        entry[location[0]] = value
        return
    metadata = entry.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        entry["metadata"] = metadata
    metadata[location[-1]] = value


class ProjectPolicyManager:
    """Manage only the isolated-development policy in one fixed config file."""

    _locks: dict[str, threading.RLock] = {}
    _locks_guard = threading.Lock()

    def __init__(
        self,
        path: Path,
        *,
        normalize_policy: Callable[[object], dict[str, Any]],
        validate_document: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._normalize_policy = normalize_policy
        self._validate_document = validate_document

    def _lock(self) -> threading.RLock:
        key = str(self.path.absolute())
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock

    def _validated_snapshot(self) -> ConfigSnapshot:
        snapshot = _read(self.path)
        if self._validate_document is not None:
            try:
                self._validate_document(snapshot.document)
            except ProjectPolicyError:
                raise
            except Exception as exc:
                raise ProjectPolicyError("CONFIG_INVALID", "The local project registry failed schema validation.", category="validation", details={"reason": str(exc)}) from exc
        return snapshot

    @staticmethod
    def _effective_policy(raw: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(raw)
        normalized.setdefault("auto_create_sessions", False)
        normalized.setdefault("auto_resume_sessions", False)
        normalized.setdefault("auto_resume_policy", "same_owner_same_task_safe_local")
        normalized.setdefault("max_parallel_sessions", 1)
        normalized.setdefault("allow_workspace_wide", False)
        normalized.setdefault("integration_requires_approval", True)
        normalized.setdefault("commit_requires_approval", True)
        normalized.setdefault("push_requires_approval", True)
        normalized.setdefault("verified_auto_commit", True)
        normalized.setdefault("auto_approve_safe_local", True)
        normalized.setdefault("auto_approve_local_maintenance", True)
        normalized.setdefault("manual_approval_ttl_seconds", 1800)
        normalized.setdefault("trusted_session_grant_ttl_seconds", 7200)
        normalized.setdefault("trust_level", "standard")
        return {key: normalized[key] for key in sorted(POLICY_KEYS)}

    def get(self, workspace_id: object) -> dict[str, object]:
        with self._lock():
            snapshot = self._validated_snapshot()
            identifier, entry = _workspace(snapshot.document, workspace_id)
            policy = self._effective_policy(_get_at(entry, _policy_location(entry)))
            return {
                "workspace_id": identifier,
                "profile": entry.get("profile", "READ_ONLY"),
                "config_digest": snapshot.digest,
                "config_identity": snapshot.identity.as_dict(),
                "policy": policy,
                "policy_location": ".".join(_policy_location(entry)),
                "external_execution": False,
            }

    def set_trust_level(self, workspace_id: object, expected_config_digest: object, trust_level: object) -> dict[str, object]:
        if trust_level not in {"standard", "trusted_development"}:
            raise ProjectPolicyError("INVALID_POLICY_VALUE", "trust_level is not supported.", category="validation")
        return self.update(workspace_id, expected_config_digest, {"trust_level": trust_level}, _allow_trust_expansion=True)

    def update(self, workspace_id: object, expected_config_digest: object, patch: object, *, _allow_trust_expansion: bool = False) -> dict[str, object]:
        if not isinstance(expected_config_digest, str) or not re.fullmatch(POLICY_DIGEST_RE, expected_config_digest):
            raise ProjectPolicyError("CONFIG_CHANGED", "expected_config_digest must be the current SHA-256 config digest.", category="conflict")
        if not isinstance(patch, Mapping) or not patch:
            raise ProjectPolicyError("INVALID_POLICY_VALUE", "isolated_development must contain at least one allowlisted key.", category="validation")
        unknown = sorted((key for key in patch if not isinstance(key, str) or key not in POLICY_KEYS), key=str)
        if unknown:
            raise ProjectPolicyError("UNKNOWN_POLICY_KEY", "The requested policy contains an unsupported key.", category="permission", details={"keys": unknown})

        with self._lock():
            snapshot = self._validated_snapshot()
            if snapshot.digest != expected_config_digest:
                raise ProjectPolicyError("CONFIG_CHANGED", "The project registry changed after the expected digest was captured.", category="conflict", details={"current_digest": snapshot.digest})
            identifier, entry = _workspace(snapshot.document, workspace_id)
            if entry.get("profile", "READ_ONLY") != "DEVELOPMENT":
                raise ProjectPolicyError("PROJECT_POLICY_UPDATE_DENIED", "Only registered DEVELOPMENT workspaces may change isolated_development policy.", category="permission")
            location = _policy_location(entry)
            raw_policy = dict(_get_at(entry, location))
            before_policy = self._effective_policy(raw_policy)
            candidate_policy = dict(raw_policy)
            for key, value in patch.items():
                if key in {"auto_create_sessions", "auto_resume_sessions", "allow_workspace_wide", "verified_auto_commit", "auto_approve_safe_local", "auto_approve_local_maintenance", *APPROVAL_KEYS}:
                    if not isinstance(value, bool):
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", f"{key} must be boolean.", category="validation")
                elif key == "auto_resume_policy":
                    if value != "same_owner_same_task_safe_local":
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", "auto_resume_policy is not supported.", category="validation")
                elif key == "max_parallel_sessions":
                    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_PARALLEL_SESSIONS:
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", "max_parallel_sessions is outside the safe bound.", category="validation")
                elif key == "manual_approval_ttl_seconds":
                    if isinstance(value, bool) or not isinstance(value, int) or not 60 <= value <= 3600:
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", "manual_approval_ttl_seconds is outside the safe bound.", category="validation")
                elif key == "trusted_session_grant_ttl_seconds":
                    if isinstance(value, bool) or not isinstance(value, int) or not 60 <= value <= 7200:
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", "trusted_session_grant_ttl_seconds is outside the safe bound.", category="validation")
                elif key == "trust_level":
                    if value not in {"standard", "trusted_development"}:
                        raise ProjectPolicyError("INVALID_POLICY_VALUE", "trust_level is not supported.", category="validation")
                candidate_policy[key] = value
            if not _allow_trust_expansion and before_policy.get("trust_level", "standard") != "trusted_development" and candidate_policy.get("trust_level", before_policy.get("trust_level")) == "trusted_development":
                raise ProjectPolicyError(
                    "PROJECT_POLICY_UPDATE_DENIED",
                    "Trusted DEVELOPMENT must be enabled through the dedicated workspace-trust approval lifecycle.",
                    category="permission",
                    details={"key": "trust_level"},
                )
            for key in APPROVAL_KEYS:
                if before_policy.get(key) is True and candidate_policy.get(key, before_policy.get(key)) is False:
                    raise ProjectPolicyError("PROJECT_POLICY_UPDATE_DENIED", "Approval requirements cannot be downgraded by the project policy tool.", category="permission", details={"key": key})
            try:
                normalized_after = self._normalize_policy(candidate_policy)
            except Exception as exc:
                raise ProjectPolicyError("INVALID_POLICY_VALUE", "The project policy failed schema validation.", category="validation", details={"reason": str(exc)}) from exc
            candidate_document = copy.deepcopy(snapshot.document)
            candidate_entry = candidate_document["workspaces"][identifier]
            # Preserve omitted/defaulted keys exactly as they were written by
            # the operator; only the explicitly requested allowlisted keys
            # are changed in the JSON document.
            _set_at(candidate_entry, location, candidate_policy)
            if self._validate_document is not None:
                try:
                    self._validate_document(candidate_document)
                except ProjectPolicyError:
                    raise
                except Exception as exc:
                    raise ProjectPolicyError("CONFIG_INVALID", "The updated project registry failed schema validation.", category="validation", details={"reason": str(exc)}) from exc

            current_identity = _identity(self.path)
            if current_identity != snapshot.identity:
                raise ProjectPolicyError("CONFIG_IDENTITY_CHANGED", "The project registry identity changed during policy update.", category="conflict")
            current_raw = self.path.read_bytes()
            if _digest(current_raw) != expected_config_digest:
                raise ProjectPolicyError("CONFIG_CHANGED", "The project registry changed during policy update.", category="conflict")
            encoded = (json.dumps(candidate_document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            temporary_name: str | None = None
            try:
                fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
                os.fchmod(fd, snapshot.identity.mode)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_name, self.path)
                temporary_name = None
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name)
                    except OSError:
                        pass
                raise ProjectPolicyError("CONFIG_WRITE_FAILED", "The project policy update could not be committed atomically.", category="runtime", details={"reason": str(exc)}) from exc

            read_back = self._validated_snapshot()
            read_back_identifier, read_back_entry = _workspace(read_back.document, identifier)
            after_policy = self._effective_policy(_get_at(read_back_entry, _policy_location(read_back_entry)))
            if read_back_identifier != identifier or after_policy != self._effective_policy(normalized_after):
                raise ProjectPolicyError("CONFIG_READBACK_FAILED", "The project policy update failed read-back validation.", category="runtime")
            receipt_id = f"policy:{secrets.token_urlsafe(16)}"
            changed_keys = sorted(key for key in POLICY_KEYS if before_policy.get(key) != after_policy.get(key))
            receipt = {
                "receipt_id": receipt_id,
                "workspace_id": identifier,
                "before_config_digest": snapshot.digest,
                "after_config_digest": read_back.digest,
                "changed_keys": changed_keys,
                "before_policy": before_policy,
                "after_policy": after_policy,
                "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "succeeded",
            }
            return {
                "workspace_id": identifier,
                "profile": "DEVELOPMENT",
                "config_digest": read_back.digest,
                "config_identity": read_back.identity.as_dict(),
                "policy": after_policy,
                "policy_location": ".".join(location),
                "receipt": receipt,
                "audit": {"status": "passed", "changed_keys": changed_keys, "before_config_digest": snapshot.digest, "after_config_digest": read_back.digest},
                "external_execution": False,
            }
