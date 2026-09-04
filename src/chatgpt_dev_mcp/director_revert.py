"""Exact inverse reverts for MCP-managed patches only."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from typing import Mapping

from .approval import ApprovalError, UnifiedApprovalStore
from .director import ValidationError, normalize_relative_path


class RevertError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _digest(value: bytes | None) -> str:
    if value is None:
        return "missing"
    return hashlib.sha256(value).hexdigest()


def _sensitive(path: str) -> bool:
    parts = tuple(item.casefold() for item in Path(path).parts)
    if ".git" in parts:
        return True
    name = parts[-1] if parts else ""
    return name in {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.json"} or "keychain" in name


@dataclass(frozen=True)
class _Change:
    path: str
    before: bytes | None
    after: bytes | None
    before_hash: str
    after_hash: str
    before_mode: int


@dataclass
class _PatchRecord:
    patch_id: str
    workspace_id: str
    root: Path
    patch_hash: str
    base_revision: str
    head_revision: str
    changes: tuple[_Change, ...]
    created_at: float


@dataclass
class _RevertPreflight:
    preflight_id: str
    patch_id: str
    fingerprint: str
    approval_id: str
    confirmation: str
    created_at: float


class RevertController:
    def __init__(self, *, approval_store: UnifiedApprovalStore | None = None) -> None:
        self._approvals = approval_store or UnifiedApprovalStore()
        self._patches: dict[str, _PatchRecord] = {}
        self._preflights: dict[str, _RevertPreflight] = {}

    @staticmethod
    def _head(root: Path) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            check=False,
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "GIT_TERMINAL_PROMPT": "0"},
        )
        value = result.stdout.strip().lower()
        if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise RevertError("REVERT_HEAD_UNAVAILABLE", "current repository head could not be verified")
        return value

    def register_patch(
        self,
        root: Path,
        *,
        workspace_id: str,
        patch_hash: str,
        base_revision: str,
        head_revision: str,
        changes: Mapping[str, tuple[bytes | None, bytes | None]],
        before_modes: Mapping[str, int] | None = None,
    ) -> dict[str, object]:
        if not re.fullmatch(r"[0-9a-f]{64}", patch_hash or ""):
            raise RevertError("REVERT_PATCH_HASH_INVALID", "patch hash must be sha256")
        if not re.fullmatch(r"[0-9a-f]{40}", base_revision or "") or not re.fullmatch(r"[0-9a-f]{40}", head_revision or ""):
            raise RevertError("REVERT_REVISION_INVALID", "base/head revision must be full commit ids")
        resolved = root.resolve(strict=True)
        if self._head(resolved) != head_revision:
            raise RevertError("STALE_REVERT_BASE", "repository head does not match managed patch metadata")
        if not changes or len(changes) > 512:
            raise RevertError("REVERT_CHANGES_INVALID", "managed patch changes are empty or too large")
        parsed: list[_Change] = []
        modes = dict(before_modes or {})
        for raw_path, pair in changes.items():
            try:
                path = normalize_relative_path(raw_path)
            except ValidationError:
                raise RevertError("REVERT_SENSITIVE_PATH_DENIED", "sensitive paths are not eligible for managed revert") from None
            if _sensitive(path):
                raise RevertError("REVERT_SENSITIVE_PATH_DENIED", "sensitive paths are not eligible for managed revert")
            if not isinstance(pair, tuple) or len(pair) != 2 or any(item is not None and not isinstance(item, bytes) for item in pair):
                raise RevertError("REVERT_CHANGES_INVALID", "managed patch bytes are invalid")
            before, after = pair
            mode = int(modes.get(path, 0o600)) & 0o777
            parsed.append(_Change(path, before, after, _digest(before), _digest(after), mode))
        patch_id = "patch-" + uuid.uuid4().hex
        self._patches[patch_id] = _PatchRecord(
            patch_id, workspace_id, resolved, patch_hash, base_revision, head_revision, tuple(parsed), time.time()
        )
        return {
            "patch_id": patch_id,
            "patch_hash": patch_hash,
            "base_revision": base_revision,
            "head_revision": head_revision,
            "changed_paths": [item.path for item in parsed],
            "raw_inverse_persistent": False,
        }

    @staticmethod
    def _current_bytes(root: Path, change: _Change) -> bytes | None:
        path = root / change.path
        if not path.exists():
            return None
        if not path.is_file() or path.is_symlink():
            raise RevertError("REVERT_CONFLICT", "managed path is no longer a regular file")
        return path.read_bytes()

    def _verify_current(self, record: _PatchRecord) -> None:
        if self._head(record.root) != record.head_revision:
            raise RevertError("STALE_REVERT_BASE", "repository head changed after the managed patch")
        for change in record.changes:
            current = self._current_bytes(record.root, change)
            if _digest(current) != change.after_hash:
                raise RevertError("REVERT_CONFLICT", f"downstream changes detected at {change.path}")

    def preflight(self, patch_id: str) -> dict[str, object]:
        record = self._patches.get(patch_id)
        if record is None:
            raise RevertError("REVERT_PATCH_UNKNOWN", "managed patch is unavailable in this runtime")
        self._verify_current(record)
        fingerprint = hashlib.sha256(
            (record.workspace_id + "\x00" + record.patch_hash + "\x00" + record.head_revision).encode()
        ).hexdigest()
        confirmation = f"Approve exact revert for managed patch {record.patch_hash[:12]}."
        approval = self._approvals.issue("patch_revert", record.workspace_id, fingerprint, confirmation)
        preflight_id = "revert-" + uuid.uuid4().hex
        self._preflights[preflight_id] = _RevertPreflight(
            preflight_id, patch_id, fingerprint, approval.approval_id, confirmation, time.time()
        )
        return {
            "preflight_id": preflight_id,
            "patch_id": patch_id,
            "patch_hash": record.patch_hash,
            "changed_paths": [item.path for item in record.changes],
            "base_revision": record.base_revision,
            "head_revision": record.head_revision,
            "approval": approval.as_dict(),
            "status": "ready",
            "external_execution": False,
        }

    @staticmethod
    def _restore(root: Path, change: _Change) -> None:
        target = root / change.path
        if change.before is None:
            if target.exists():
                target.unlink()
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.parent / f".{target.name}.mcp-revert-{uuid.uuid4().hex}.tmp"
        try:
            temporary.write_bytes(change.before)
            os.chmod(temporary, change.before_mode or 0o600)
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()

    def apply(self, preflight_id: str, *, approval_id: str, confirmation: str) -> dict[str, object]:
        preflight = self._preflights.pop(preflight_id, None)
        if preflight is None:
            raise RevertError("REVERT_PREFLIGHT_INVALID", "revert preflight is unknown or consumed")
        record = self._patches.get(preflight.patch_id)
        if record is None:
            raise RevertError("REVERT_PATCH_UNKNOWN", "managed patch inverse is no longer available")
        self._verify_current(record)
        try:
            self._approvals.consume(
                approval_id,
                confirmation,
                operation="patch_revert",
                workspace_id=record.workspace_id,
                fingerprint=preflight.fingerprint,
            )
        except ApprovalError as exc:
            raise RevertError(exc.code, str(exc)) from exc
        for change in record.changes:
            self._restore(record.root, change)
        for change in record.changes:
            if _digest(self._current_bytes(record.root, change)) != change.before_hash:
                raise RevertError("REVERT_OUTCOME_UNKNOWN", "exact inverse read-back did not match the managed pre-image")
        self._patches.pop(record.patch_id, None)
        return {
            "status": "succeeded",
            "patch_id": record.patch_id,
            "reverted_patch_hash": record.patch_hash,
            "changed_paths": [item.path for item in record.changes],
            "head_revision": self._head(record.root),
            "external_execution": False,
        }
