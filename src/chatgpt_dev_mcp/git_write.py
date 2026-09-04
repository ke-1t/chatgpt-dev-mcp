"""Fail-closed, fixed-argv Git commit/push control plane.

This module deliberately does not accept shell text, repository paths from the
caller, or Git flags.  ``WrapperRuntime`` supplies the already registered
workspace path and task binding; this module snapshots that path and performs
only the small Git argv allowlist declared below.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .approval import MANUAL_APPROVAL_TTL_SECONDS
from .capability_adapters import _trusted_executable_path
from .director import contains_secret_like_content
from .git_hunks import GitHunk, GitHunkSelectionError, build_hunk_patch, enumerate_file_hunks
from .persistence import PersistenceError, SqliteDirectorStore
from .process_runner import run_bounded


_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,240}$")
_FORBIDDEN_REF_RE = re.compile(r"(?:\.\.|//|\.@|@\{|[~^:?*\[\\]|/$|/\.|^\.|\.lock$)")
_SENSITIVE_NAMES = frozenset(
    {
        ".aws",
        ".config",
        ".git",
        ".ssh",
        "keychains",
        "browser profiles",
        "chromedata",
        "chrome",
        "mozilla",
    }
)
_SENSITIVE_BASENAME_RE = re.compile(
    r"^(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|known_hosts|"
    r"credentials(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|key|p12|pfx|kdbx))$",
    re.IGNORECASE,
)
_PROTECTED_BRANCHES = frozenset({"main", "master", "production"})
# Git preflight hashes the complete staged binary diff and scans it for
# secret-like content. Keep the capture bounded, but allow a normal
# multi-module closeout to be reviewed without silently truncating its
# safety evidence. The bound remains finite so pathological repositories
# still fail closed rather than consuming unbounded memory.
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_PATHS = 4096
_MAX_HUNK_PATHS = 128
_MAX_HUNKS = 1024
_MAX_SECRET_SCAN_BYTES = 256 * 1024 * 1024
_SECRET_SCAN_CHUNK_BYTES = 64 * 1024
_SECRET_SCAN_OVERLAP = 4096
_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
_SECRET_GREP_PATTERN = r"(password|passwd|token|secret|api[_-]?key|access[_-]?key|bearer|private key|sk-|gh[pousr]_|AKIA)"
_UNBORN_HEAD = "0" * 40
_GITHUB_HTTPS_HOST = "github.com"
_TRUSTED_GH_ROOTS = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))


class GitWriteError(ValueError):
    """A bounded validation, policy, or Git mutation failure."""

    def __init__(self, code: str, message: str, *, status: str = "rejected", details: Mapping[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = dict(details or {})


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _validate_hex(value: object, *, name: str, length: int) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise GitWriteError(f"GIT_{name.upper()}_INVALID", f"{name} must be lowercase {length}-hex.", status="rejected")
    return value


def validate_remote_name(value: object) -> str:
    if not isinstance(value, str) or not _REMOTE_RE.fullmatch(value) or value in {".", ".."}:
        raise GitWriteError("GIT_REMOTE_INVALID", "remote must be a configured Git remote name.")
    return value


def validate_branch_name(value: object) -> str:
    if not isinstance(value, str) or value in {"HEAD", "@"} or not _BRANCH_RE.fullmatch(value) or _FORBIDDEN_REF_RE.search(value):
        raise GitWriteError("GIT_BRANCH_INVALID", "branch is not a safe Git branch name.")
    return value


def validate_commit_message(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2000 or "\x00" in value or "\n" in value or "\r" in value:
        raise GitWriteError("GIT_COMMIT_MESSAGE_INVALID", "commit_message must be one non-empty line of at most 2000 characters.")
    if contains_secret_like_content(value):
        raise GitWriteError("GIT_SECRET_CONTENT_DENIED", "commit_message looks like credential material.", status="blocked")
    return value


def _sensitive_path(value: str) -> bool:
    parts = [part.casefold() for part in value.replace("\\", "/").split("/") if part]
    return bool(parts and (any(part in _SENSITIVE_NAMES for part in parts) or _SENSITIVE_BASENAME_RE.fullmatch(parts[-1])))


def _safe_rel_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or value.startswith(("/", "~")) or "\\" in value:
        raise GitWriteError("GIT_PATH_INVALID", "Git reported an unsafe path.", status="blocked")
    pieces = value.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise GitWriteError("GIT_PATH_INVALID", "Git reported an unsafe path.", status="blocked") from None
    path = str(PurePosixPath(*pieces))
    if path != value:
        raise GitWriteError("GIT_PATH_INVALID", "Git reported an unsafe path.", status="blocked")
    return path


def _github_https_network_target(argv: tuple[str, ...]) -> bool:
    """Return true only when fixed Git argv targets GitHub over HTTPS."""

    for value in argv:
        if not value.startswith("https://"):
            continue
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            continue
        if (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.hostname.casefold() == _GITHUB_HTTPS_HOST
            and port in {None, 443}
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        ):
            return True
    return False


def _trusted_github_cli() -> str:
    """Resolve only a trusted system-installed GitHub CLI executable."""

    for root in _TRUSTED_GH_ROOTS:
        candidate = root / "gh"
        if _trusted_executable_path(candidate, root=root):
            try:
                return str(candidate.resolve(strict=True))
            except OSError:
                return ""
    return ""


def _github_cli_config_dir() -> str:
    """Return gh's normal per-user config directory without reading it."""

    return str(Path.home() / ".config" / "gh")


def _github_cli_state_dir() -> str:
    """Return a dedicated absolute state directory for gh credential use."""

    return str(Path.home() / ".cache" / "local-dev-mcp" / "gh-state")


@dataclass(frozen=True)
class GitTaskBinding:
    task_id: str
    workspace_id: str
    working_tree_id: str
    status: str
    title: str = ""
    allowed_paths: tuple[str, ...] = ()
    verification_receipt_id: str = ""
    security_audit_receipt_id: str = ""
    evidence_valid: bool = False
    allow_partial_stage_adoption: bool = False


@dataclass(frozen=True)
class GitStateSnapshot:
    repository_id: str
    workspace_id: str
    working_tree_id: str
    branch: str
    head: str
    staged: tuple[str, ...]
    unstaged: tuple[str, ...]
    untracked: tuple[str, ...]
    changed_paths: tuple[str, ...]
    index_state_hash: str
    staged_diff_hash: str
    worktree_state_hash: str
    policy_findings: tuple[str, ...] = ()

    @property
    def dirty(self) -> bool:
        return bool(self.staged or self.unstaged or self.untracked)

    def as_dict(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "branch": self.branch,
            "head": self.head,
            "staged": list(self.staged),
            "unstaged": list(self.unstaged),
            "untracked": list(self.untracked),
            "changed_paths": list(self.changed_paths),
            "index_state_hash": self.index_state_hash,
            "staged_diff_hash": self.staged_diff_hash,
            "worktree_state_hash": self.worktree_state_hash,
            "dirty": self.dirty,
            "dirty_state": {
                "staged_count": len(self.staged),
                "unstaged_count": len(self.unstaged),
                "untracked_count": len(self.untracked),
            },
            "policy_findings": list(self.policy_findings),
            "external_execution": False,
        }


@dataclass(frozen=True)
class GitApproval:
    token: str
    confirmation: str
    operation: str
    preflight_id: str
    workspace_id: str
    expires_at: float
    one_shot: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "token": self.token,
            "confirmation": self.confirmation,
            "operation": self.operation,
            "preflight_id": self.preflight_id,
            "expires_at": self.expires_at,
            "one_shot": self.one_shot,
            "human_confirmation_required": True,
        }


@dataclass(frozen=True)
class CommitPreflight:
    preflight_id: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    commit_message: str
    commit_message_hash: str
    snapshot: GitStateSnapshot
    candidate_paths: tuple[str, ...] = ()
    candidate_leaf_paths: tuple[str, ...] = ()
    candidate_staged_diff_hash: str = ""
    candidate_index_state_hash: str = ""
    preserved_staged_paths: tuple[str, ...] = ()
    preserved_staged_scope_hash: str = ""
    partial_stage_adoption: bool = False
    partial_stage_paths: tuple[str, ...] = ()
    blocking_codes: tuple[str, ...] = ()
    approval: GitApproval | None = None
    audit_receipt_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "preflight_id": self.preflight_id,
            "operation": "commit",
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "commit_message": self.commit_message,
            "commit_message_hash": self.commit_message_hash,
            "snapshot": self.snapshot.as_dict(),
            "candidate_paths": list(self.candidate_paths),
            "candidate_leaf_paths": list(self.candidate_leaf_paths),
            "candidate_staged_diff_hash": self.candidate_staged_diff_hash,
            "candidate_index_state_hash": self.candidate_index_state_hash,
            "preserved_staged_paths": list(self.preserved_staged_paths),
            "preserved_staged_scope_hash": self.preserved_staged_scope_hash,
            "partial_stage_adoption": self.partial_stage_adoption,
            "partial_stage_paths": list(self.partial_stage_paths),
            "blocking_codes": list(self.blocking_codes),
            "approval": self.approval.as_dict() if self.approval else None,
            "audit_receipt_id": self.audit_receipt_id,
            "external_execution": False,
        }


@dataclass(frozen=True)
class StagePreflight:
    preflight_id: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    operation: str
    snapshot: GitStateSnapshot
    candidate_paths: tuple[str, ...]
    candidate_leaf_paths: tuple[str, ...]
    candidate_staged_diff_hash: str
    candidate_index_state_hash: str
    created_at: float
    expires_at: float
    blocking_codes: tuple[str, ...] = ()
    audit_receipt_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "preflight_id": self.preflight_id,
            "operation": self.operation,
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "snapshot": self.snapshot.as_dict(),
            "candidate_paths": list(self.candidate_paths),
            "candidate_leaf_paths": list(self.candidate_leaf_paths),
            "candidate_staged_diff_hash": self.candidate_staged_diff_hash,
            "candidate_index_state_hash": self.candidate_index_state_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "blocking_codes": list(self.blocking_codes),
            "approval": None,
            "human_confirmation_required": False,
            "audit_receipt_id": self.audit_receipt_id,
            "external_execution": False,
        }


@dataclass(frozen=True)
class HunkStagePreflight:
    preflight_id: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    snapshot: GitStateSnapshot
    requested_paths: tuple[str, ...]
    available_hunks: tuple[GitHunk, ...]
    selected_hunk_ids: tuple[str, ...]
    candidate_paths: tuple[str, ...]
    candidate_leaf_paths: tuple[str, ...]
    candidate_patch_hash: str
    candidate_staged_diff_hash: str
    candidate_index_state_hash: str
    created_at: float
    expires_at: float
    blocking_codes: tuple[str, ...] = ()
    audit_receipt_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "preflight_id": self.preflight_id,
            "operation": "stage_hunks",
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "snapshot": self.snapshot.as_dict(),
            "requested_paths": list(self.requested_paths),
            "available_hunks": [hunk.as_dict() for hunk in self.available_hunks],
            "selected_hunk_ids": list(self.selected_hunk_ids),
            "candidate_paths": list(self.candidate_paths),
            "candidate_leaf_paths": list(self.candidate_leaf_paths),
            "candidate_patch_hash": self.candidate_patch_hash,
            "candidate_staged_diff_hash": self.candidate_staged_diff_hash,
            "candidate_index_state_hash": self.candidate_index_state_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "blocking_codes": list(self.blocking_codes),
            "approval": None,
            "human_confirmation_required": False,
            "audit_receipt_id": self.audit_receipt_id,
            "external_execution": False,
        }


@dataclass(frozen=True)
class VerifiedCommitPreflight:
    preflight_id: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    commit_message: str
    commit_message_hash: str
    snapshot: GitStateSnapshot
    candidate_paths: tuple[str, ...]
    candidate_leaf_paths: tuple[str, ...]
    candidate_staged_diff_hash: str
    candidate_index_state_hash: str
    created_at: float
    expires_at: float
    blocking_codes: tuple[str, ...] = ()
    audit_receipt_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "preflight_id": self.preflight_id,
            "operation": "verified_commit",
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "commit_message": self.commit_message,
            "commit_message_hash": self.commit_message_hash,
            "snapshot": self.snapshot.as_dict(),
            "candidate_paths": list(self.candidate_paths),
            "candidate_leaf_paths": list(self.candidate_leaf_paths),
            "candidate_staged_diff_hash": self.candidate_staged_diff_hash,
            "candidate_index_state_hash": self.candidate_index_state_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "blocking_codes": list(self.blocking_codes),
            "approval": None,
            "human_confirmation_required": False,
            "audit_receipt_id": self.audit_receipt_id,
            "external_execution": False,
        }


@dataclass(frozen=True)
class PushPreflight:
    preflight_id: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    snapshot: GitStateSnapshot
    remote_name: str
    remote_url_hash: str
    remote_display: str
    expected_remote_head: str
    default_branch: str
    protected_branch: bool
    blocking_codes: tuple[str, ...] = ()
    approval: GitApproval | None = None
    audit_receipt_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "preflight_id": self.preflight_id,
            "operation": "push",
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "snapshot": self.snapshot.as_dict(),
            "remote": {
                "name": self.remote_name,
                "display": self.remote_display,
                "url_hash": self.remote_url_hash,
                "expected_head": self.expected_remote_head,
            },
            "default_branch": self.default_branch,
            "protected_branch": self.protected_branch,
            "protected_branch_policy": (
                "guarded_fast_forward"
                if self.snapshot.branch == "main" or self.snapshot.branch == self.default_branch
                else "deny"
            ),
            "blocking_codes": list(self.blocking_codes),
            "approval": self.approval.as_dict() if self.approval else None,
            "audit_receipt_id": self.audit_receipt_id,
            "external_execution": False,
        }


@dataclass(frozen=True)
class GitMutationReceipt:
    receipt_id: str
    audit_receipt_id: str
    operation: str
    status: str
    workspace_id: str
    working_tree_id: str
    task_id: str
    preflight_id: str
    branch: str
    head_before: str
    head_after: str
    staged_diff_hash: str
    index_state_hash: str
    commit_tree_hash: str = ""
    commit_diff_hash: str = ""
    remote_name: str = ""
    remote_url_hash: str = ""
    expected_remote_head: str = ""
    observed_remote_head: str = ""
    error_code: str = ""
    external_effect: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "audit_receipt_id": self.audit_receipt_id,
            "operation": self.operation,
            "status": self.status,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "task_id": self.task_id,
            "preflight_id": self.preflight_id,
            "branch": self.branch,
            "head_before": self.head_before,
            "head_after": self.head_after,
            "staged_diff_hash": self.staged_diff_hash,
            "index_state_hash": self.index_state_hash,
            "commit_tree_hash": self.commit_tree_hash,
            "commit_diff_hash": self.commit_diff_hash,
            "remote_name": self.remote_name,
            "remote_url_hash": self.remote_url_hash,
            "expected_remote_head": self.expected_remote_head,
            "observed_remote_head": self.observed_remote_head,
            "error_code": self.error_code,
            "external_effect": self.external_effect,
            "external_execution": self.operation == "push",
        }


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    transport_error: bool = False
    truncated: bool = False


@dataclass
class _StoredApproval:
    approval: GitApproval
    consumed: bool = False


def _persisted_snapshot(value: object) -> GitStateSnapshot:
    if not isinstance(value, Mapping):
        raise PersistenceError("stored Git snapshot is invalid")

    def items(name: str) -> tuple[str, ...]:
        raw = value.get(name, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise PersistenceError(f"stored Git snapshot {name} is invalid")
        return tuple(raw)

    return GitStateSnapshot(
        repository_id=str(value.get("repository_id", "")),
        workspace_id=str(value.get("workspace_id", "")),
        working_tree_id=str(value.get("working_tree_id", "")),
        branch=str(value.get("branch", "")),
        head=str(value.get("head", "")),
        staged=items("staged"),
        unstaged=items("unstaged"),
        untracked=items("untracked"),
        changed_paths=items("changed_paths"),
        index_state_hash=str(value.get("index_state_hash", "")),
        staged_diff_hash=str(value.get("staged_diff_hash", "")),
        worktree_state_hash=str(value.get("worktree_state_hash", "")),
        policy_findings=items("policy_findings"),
    )


def _persisted_preflight(record: Mapping[str, Any]) -> CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight:
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        raise PersistenceError("stored Git preflight payload is invalid")
    operation = str(record.get("operation", payload.get("operation", "")))
    snapshot = _persisted_snapshot(payload.get("snapshot"))

    def strings(name: str) -> tuple[str, ...]:
        raw = payload.get(name, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise PersistenceError(f"stored Git preflight {name} is invalid")
        return tuple(raw)

    common = {
        "preflight_id": str(payload.get("preflight_id", record.get("preflight_id", ""))),
        "status": str(payload.get("status", record.get("state", ""))),
        "workspace_id": str(payload.get("workspace_id", record.get("workspace_id", ""))),
        "working_tree_id": str(payload.get("working_tree_id", record.get("working_tree_id", ""))),
        "task_id": str(payload.get("task_id", record.get("task_id", ""))),
    }
    if operation in {"stage", "stage_paths"}:
        return StagePreflight(
            **common,
            operation=operation,
            snapshot=snapshot,
            candidate_paths=strings("candidate_paths"),
            candidate_leaf_paths=strings("candidate_leaf_paths"),
            candidate_staged_diff_hash=str(payload.get("candidate_staged_diff_hash", "")),
            candidate_index_state_hash=str(payload.get("candidate_index_state_hash", "")),
            created_at=float(payload.get("created_at", record.get("created_at", 0.0))),
            expires_at=float(payload.get("expires_at", record.get("expires_at", 0.0))),
            blocking_codes=strings("blocking_codes"),
            audit_receipt_id=str(payload.get("audit_receipt_id", "")),
        )
    if operation == "stage_hunks":
        return HunkStagePreflight(
            **common,
            snapshot=snapshot,
            requested_paths=strings("requested_paths"),
            # The hunk text itself is intentionally not persisted. Execution
            # re-inventories the live diff and verifies selected IDs/hash.
            available_hunks=(),
            selected_hunk_ids=strings("selected_hunk_ids"),
            candidate_paths=strings("candidate_paths"),
            candidate_leaf_paths=strings("candidate_leaf_paths"),
            candidate_patch_hash=str(payload.get("candidate_patch_hash", "")),
            candidate_staged_diff_hash=str(payload.get("candidate_staged_diff_hash", "")),
            candidate_index_state_hash=str(payload.get("candidate_index_state_hash", "")),
            created_at=float(payload.get("created_at", record.get("created_at", 0.0))),
            expires_at=float(payload.get("expires_at", record.get("expires_at", 0.0))),
            blocking_codes=strings("blocking_codes"),
            audit_receipt_id=str(payload.get("audit_receipt_id", "")),
        )
    if operation == "verified_commit":
        return VerifiedCommitPreflight(
            **common,
            commit_message=str(payload.get("commit_message", "")),
            commit_message_hash=str(payload.get("commit_message_hash", "")),
            snapshot=snapshot,
            candidate_paths=strings("candidate_paths"),
            candidate_leaf_paths=strings("candidate_leaf_paths"),
            candidate_staged_diff_hash=str(payload.get("candidate_staged_diff_hash", "")),
            candidate_index_state_hash=str(payload.get("candidate_index_state_hash", "")),
            created_at=float(payload.get("created_at", record.get("created_at", 0.0))),
            expires_at=float(payload.get("expires_at", record.get("expires_at", 0.0))),
            blocking_codes=strings("blocking_codes"),
            audit_receipt_id=str(payload.get("audit_receipt_id", "")),
        )
    if operation == "commit":
        return CommitPreflight(
            **common,
            commit_message=str(payload.get("commit_message", "")),
            commit_message_hash=str(payload.get("commit_message_hash", "")),
            snapshot=snapshot,
            candidate_paths=strings("candidate_paths"),
            candidate_leaf_paths=strings("candidate_leaf_paths"),
            candidate_staged_diff_hash=str(payload.get("candidate_staged_diff_hash", "")),
            candidate_index_state_hash=str(payload.get("candidate_index_state_hash", "")),
            preserved_staged_paths=strings("preserved_staged_paths"),
            preserved_staged_scope_hash=str(payload.get("preserved_staged_scope_hash", "")),
            partial_stage_adoption=bool(payload.get("partial_stage_adoption", False)),
            partial_stage_paths=strings("partial_stage_paths"),
            blocking_codes=strings("blocking_codes"),
            approval=None,
            audit_receipt_id=str(payload.get("audit_receipt_id", "")),
        )
    if operation == "push":
        remote = payload.get("remote", {})
        if not isinstance(remote, Mapping):
            raise PersistenceError("stored Git push remote is invalid")
        return PushPreflight(
            **common,
            snapshot=snapshot,
            remote_name=str(remote.get("name", "")),
            remote_url_hash=str(remote.get("url_hash", "")),
            remote_display=str(remote.get("display", "")),
            expected_remote_head=str(remote.get("expected_head", "")),
            default_branch=str(payload.get("default_branch", "")),
            protected_branch=bool(payload.get("protected_branch", False)),
            blocking_codes=strings("blocking_codes"),
            approval=None,
            audit_receipt_id=str(payload.get("audit_receipt_id", "")),
        )
    raise PersistenceError("stored Git preflight operation is invalid")


def _persisted_receipt(value: object) -> GitMutationReceipt:
    if not isinstance(value, Mapping):
        raise PersistenceError("stored Git mutation receipt is invalid")
    return GitMutationReceipt(
        receipt_id=str(value.get("receipt_id", "")),
        audit_receipt_id=str(value.get("audit_receipt_id", "")),
        operation=str(value.get("operation", "")),
        status=str(value.get("status", "")),
        workspace_id=str(value.get("workspace_id", "")),
        working_tree_id=str(value.get("working_tree_id", "")),
        task_id=str(value.get("task_id", "")),
        preflight_id=str(value.get("preflight_id", "")),
        branch=str(value.get("branch", "")),
        head_before=str(value.get("head_before", "")),
        head_after=str(value.get("head_after", "")),
        staged_diff_hash=str(value.get("staged_diff_hash", "")),
        index_state_hash=str(value.get("index_state_hash", "")),
        commit_tree_hash=str(value.get("commit_tree_hash", "")),
        commit_diff_hash=str(value.get("commit_diff_hash", "")),
        remote_name=str(value.get("remote_name", "")),
        remote_url_hash=str(value.get("remote_url_hash", "")),
        expected_remote_head=str(value.get("expected_remote_head", "")),
        observed_remote_head=str(value.get("observed_remote_head", "")),
        error_code=str(value.get("error_code", "")),
        external_effect=str(value.get("external_effect", "")),
    )


class GitWriteStore:
    """Cache plus durable one-shot Git delivery authority.

    SQLite is authoritative when configured. The in-memory dictionaries remain
    only a hot cache and compatibility fallback for isolated unit tests.
    """

    def __init__(self, persistence: SqliteDirectorStore | None = None) -> None:
        self.persistence = persistence
        self.lock = threading.RLock()
        self.approvals: dict[str, _StoredApproval] = {}
        self.preflights: dict[
            str,
            CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight,
        ] = {}
        self.trusted_partial_stage_states: set[tuple[str, str, str, str, str, str, str]] = set()
        self.receipts: dict[str, GitMutationReceipt] = {}

    @staticmethod
    def _payload(preflight: CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight) -> dict[str, object]:
        payload = dict(preflight.as_dict())
        payload.pop("approval", None)
        payload.pop("human_confirmation_required", None)
        payload.pop("external_execution", None)
        return payload

    @staticmethod
    def _partial_stage_hash(state: tuple[str, str, str, str, str, str, str]) -> str:
        return _sha256_text("\0".join(state))

    def put_preflight(
        self,
        preflight: CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight,
        *,
        created_at: float,
        expires_at: float,
    ) -> None:
        approval = getattr(preflight, "approval", None)
        if self.persistence is not None:
            self.persistence.save_git_preflight_authority(
                {
                    "preflight_id": preflight.preflight_id,
                    "operation": preflight.as_dict()["operation"],
                    "workspace_id": preflight.workspace_id,
                    "working_tree_id": preflight.working_tree_id,
                    "task_id": preflight.task_id,
                    "state": preflight.status,
                    "payload": self._payload(preflight),
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "schema_version": self.persistence.schema_version,
                    "approval_token_hash": _sha256_text(approval.token) if approval is not None else "",
                    "approval_confirmation_hash": _sha256_text(approval.confirmation) if approval is not None else "",
                    "approval_expires_at": approval.expires_at if approval is not None else expires_at,
                }
            )
        with self.lock:
            self.preflights[preflight.preflight_id] = preflight
            if approval is not None:
                self.approvals.setdefault(approval.token, _StoredApproval(approval))

    def get_preflight(
        self,
        preflight_id: str,
    ) -> CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight | None:
        with self.lock:
            cached = self.preflights.get(preflight_id)
        if cached is not None:
            return cached
        if self.persistence is None:
            return None
        record = self.persistence.load_git_preflight_authority(preflight_id)
        if record is None or record.get("state") not in {"ready", "blocked", "selection_required", "executing", "outcome_unknown"}:
            return None
        preflight = _persisted_preflight(record)
        with self.lock:
            self.preflights[preflight_id] = preflight
        return preflight

    def authority_state(self, preflight_id: str) -> str | None:
        if self.persistence is None:
            with self.lock:
                return "ready" if preflight_id in self.preflights else None
        record = self.persistence.load_git_preflight_authority(preflight_id)
        return str(record.get("state")) if record is not None else None

    def receipt_for_preflight(self, preflight_id: str) -> GitMutationReceipt | None:
        if self.persistence is None:
            with self.lock:
                for receipt in self.receipts.values():
                    if receipt.preflight_id == preflight_id:
                        return receipt
            return None
        record = self.persistence.load_git_mutation_outcome_for_preflight(preflight_id)
        if record is None:
            return None
        receipt = _persisted_receipt(record.get("payload"))
        with self.lock:
            self.receipts[receipt.receipt_id] = receipt
        return receipt

    def claim_preflight(
        self,
        *,
        preflight_id: str,
        operation: str,
        workspace_id: str,
        now: float,
        approval_token: object = "",
        confirmation: object = "",
    ) -> None:
        if self.persistence is None:
            return
        token_hash = _sha256_text(approval_token) if isinstance(approval_token, str) and approval_token else ""
        confirmation_hash = _sha256_text(confirmation) if isinstance(confirmation, str) and confirmation else ""
        result = self.persistence.claim_git_preflight_authority(
            preflight_id=preflight_id,
            operation=operation,
            workspace_id=workspace_id,
            now=now,
            approval_token_hash=token_hash,
            confirmation_hash=confirmation_hash,
        )
        status = str(result.get("status", ""))
        errors = {
            "not_found": ("GIT_PREFLIGHT_NOT_FOUND", "Git preflight is unknown or expired."),
            "schema_mismatch": ("GIT_PREFLIGHT_SCHEMA_MISMATCH", "Git preflight schema does not match this runtime."),
            "binding_mismatch": ("GIT_PREFLIGHT_BINDING_MISMATCH", "Git preflight is bound to another operation or workspace."),
            "already_consumed": ("GIT_PREFLIGHT_ALREADY_CONSUMED", "Git preflight has already been consumed."),
            "expired": ("GIT_PREFLIGHT_EXPIRED", "Git preflight expired before mutation."),
            "not_ready": ("GIT_PREFLIGHT_NOT_READY", "Git preflight is not ready for mutation."),
            "approval_required": ("GIT_APPROVAL_INVALID", "approval token and confirmation are required."),
            "approval_not_found": ("GIT_APPROVAL_NOT_FOUND", "approval token is unknown for this preflight."),
            "approval_confirmation_mismatch": ("GIT_APPROVAL_CONFIRMATION_MISMATCH", "confirmation does not match the preflight challenge."),
            "approval_mismatch": ("GIT_APPROVAL_MISMATCH", "approval is bound to another operation or workspace."),
            "approval_consumed": ("GIT_APPROVAL_REUSED", "approval token has already been consumed."),
            "approval_expired": ("GIT_APPROVAL_EXPIRED", "approval token expired; run preflight again."),
        }
        if status != "claimed":
            code, message = errors.get(status, ("GIT_AUTHORITY_PERSISTENCE_FAILED", "Git authority could not be claimed safely."))
            raise GitWriteError(code, message, status="rejected")
        with self.lock:
            self.preflights.pop(preflight_id, None)

    def finish_preflight(self, preflight_id: str, state: str, *, now: float) -> None:
        if self.persistence is not None:
            self.persistence.finish_git_preflight_authority(preflight_id, state, now=now)
        with self.lock:
            self.preflights.pop(preflight_id, None)

    def invalidate_preflight(self, preflight_id: str, *, now: float) -> None:
        if self.persistence is not None:
            self.persistence.finish_git_preflight_authority(preflight_id, "invalidated", now=now)
        with self.lock:
            preflight = self.preflights.pop(preflight_id, None)
            approval = getattr(preflight, "approval", None)
            if approval is not None:
                stored = self.approvals.get(approval.token)
                if stored is not None:
                    stored.consumed = True

    def put_receipt(self, receipt: GitMutationReceipt, *, created_at: float) -> None:
        if self.persistence is not None:
            self.persistence.save_git_mutation_outcome(
                {
                    "receipt_id": receipt.receipt_id,
                    "preflight_id": receipt.preflight_id,
                    "operation": receipt.operation,
                    "workspace_id": receipt.workspace_id,
                    "working_tree_id": receipt.working_tree_id,
                    "task_id": receipt.task_id,
                    "status": receipt.status,
                    "payload": receipt.as_dict(),
                    "created_at": created_at,
                }
            )
        with self.lock:
            self.receipts[receipt.receipt_id] = receipt

    def trust_partial_stage(self, state: tuple[str, str, str, str, str, str, str], *, created_at: float) -> None:
        if self.persistence is not None:
            self.persistence.save_git_trusted_partial_stage_state(
                {
                    "state_hash": self._partial_stage_hash(state),
                    "repository_id": state[0],
                    "workspace_id": state[1],
                    "working_tree_id": state[2],
                    "task_id": state[3],
                    "head": state[4],
                    "staged_diff_hash": state[5],
                    "index_state_hash": state[6],
                    "created_at": created_at,
                }
            )
        with self.lock:
            self.trusted_partial_stage_states.add(state)

    def has_trusted_partial_stage(self, state: tuple[str, str, str, str, str, str, str]) -> bool:
        with self.lock:
            if state in self.trusted_partial_stage_states:
                return True
        if self.persistence is None:
            return False
        return self.persistence.has_git_trusted_partial_stage_state(self._partial_stage_hash(state))


class GitWriteController:
    """Fixed Git adapter with fail-closed durable mutation authority."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        approval_ttl_seconds: float = MANUAL_APPROVAL_TTL_SECONDS,
        runner: Callable[..., _CommandResult] | None = None,
        store: GitWriteStore | None = None,
    ) -> None:
        if not 1 <= approval_ttl_seconds <= 60 * 60:
            raise GitWriteError("GIT_APPROVAL_TTL_INVALID", "approval TTL is outside the safe bound.")
        self._clock = clock
        self._approval_ttl_seconds = float(approval_ttl_seconds)
        self._runner = runner or self.default_runner
        self._store = store or GitWriteStore()
        self._lock = self._store.lock
        self._approvals = self._store.approvals
        self._preflights = self._store.preflights
        self._trusted_partial_stage_states = self._store.trusted_partial_stage_states
        self.receipts = self._store.receipts

    def _store_preflight(
        self,
        preflight: CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight,
    ) -> None:
        now = float(getattr(preflight, "created_at", self._clock()))
        approval = getattr(preflight, "approval", None)
        expires_at = float(
            getattr(
                preflight,
                "expires_at",
                approval.expires_at if approval is not None else now + self._approval_ttl_seconds,
            )
        )
        try:
            self._store.put_preflight(preflight, created_at=now, expires_at=expires_at)
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git preflight authority could not be persisted safely.",
                status="blocked",
            ) from exc

    def _load_preflight(
        self,
        preflight_id: str,
    ) -> CommitPreflight | StagePreflight | HunkStagePreflight | VerifiedCommitPreflight | PushPreflight | None:
        try:
            return self._store.get_preflight(preflight_id)
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git preflight authority could not be loaded safely.",
                status="blocked",
            ) from exc

    def _claim_preflight(
        self,
        *,
        preflight_id: str,
        operation: str,
        workspace_id: str,
        approval_token: object = "",
        confirmation: object = "",
    ) -> None:
        if self._store.persistence is None:
            if operation in {"commit", "push"}:
                self.consume_approval(
                    approval_token,
                    confirmation,
                    operation=operation,
                    preflight_id=preflight_id,
                    workspace_id=workspace_id,
                )
            return
        try:
            self._store.claim_preflight(
                preflight_id=preflight_id,
                operation=operation,
                workspace_id=workspace_id,
                now=float(self._clock()),
                approval_token=approval_token,
                confirmation=confirmation,
            )
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git mutation authority could not be claimed safely.",
                status="blocked",
            ) from exc

    def _finish_preflight(self, preflight_id: str, state: str) -> None:
        try:
            self._store.finish_preflight(preflight_id, state, now=float(self._clock()))
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git mutation completed but terminal authority could not be persisted.",
                status="outcome_unknown",
            ) from exc

    def _record_receipt(self, receipt: GitMutationReceipt) -> None:
        try:
            self._store.put_receipt(receipt, created_at=float(self._clock()))
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_MUTATION_RECEIPT_PERSIST_FAILED",
                "Git mutation outcome could not be persisted safely.",
                status="outcome_unknown",
                details={"receipt": receipt.as_dict()},
            ) from exc

    def _authority_state(self, preflight_id: str) -> str | None:
        try:
            return self._store.authority_state(preflight_id)
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git mutation authority state could not be loaded safely.",
                status="blocked",
            ) from exc

    def executing_preflight_binding(self, preflight_id: str, *, operation: str) -> tuple[str, str, str] | None:
        """Return the immutable task/workspace binding only for claimed authority recovery."""

        if self._authority_state(preflight_id) != "executing":
            return None
        preflight = self._load_preflight(preflight_id)
        if preflight is None or str(preflight.as_dict().get("operation", "")) != operation:
            raise GitWriteError(
                "GIT_PREFLIGHT_BINDING_MISMATCH",
                "Executing Git authority does not match the requested operation.",
                status="rejected",
            )
        return preflight.task_id, preflight.workspace_id, preflight.working_tree_id

    def _resume_recorded_outcome(self, preflight_id: str) -> GitMutationReceipt | None:
        if self._authority_state(preflight_id) != "executing":
            return None
        try:
            receipt = self._store.receipt_for_preflight(preflight_id)
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git mutation outcome could not be loaded safely.",
                status="blocked",
            ) from exc
        if receipt is None:
            return None
        terminal = receipt.status if receipt.status in {"succeeded", "failed", "outcome_unknown"} else "outcome_unknown"
        self._finish_preflight(preflight_id, terminal)
        if receipt.status == "succeeded":
            return receipt
        raise GitWriteError(
            receipt.error_code or "GIT_RECOVERED_OUTCOME_UNKNOWN",
            "A prior Git mutation was recovered from its durable receipt; it was not replayed.",
            status=receipt.status if receipt.status in {"failed", "outcome_unknown"} else "outcome_unknown",
            details={"receipt": receipt.as_dict(), "recovered": True},
        )

    def _reconcile_executing_stage(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        preflight_id: str,
    ) -> GitMutationReceipt | None:
        if self._authority_state(preflight_id) != "executing":
            return None
        recorded = self._resume_recorded_outcome(preflight_id)
        if recorded is not None:
            return recorded
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, (StagePreflight, HunkStagePreflight)):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_RECOVERY_UNKNOWN",
                "Executing stage authority could not be reconstructed safely.",
                status="outcome_unknown",
            )
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        operation = str(preflight.as_dict()["operation"])
        if current == preflight.snapshot:
            receipt = GitMutationReceipt(
                f"git-{operation}-recovery:{secrets.token_urlsafe(12)}",
                self._audit_id(operation, preflight_id, current, "recovered-not-applied"),
                operation,
                "failed",
                workspace_id,
                working_tree_id,
                preflight.task_id,
                preflight_id,
                current.branch,
                preflight.snapshot.head,
                current.head,
                current.staged_diff_hash,
                current.index_state_hash,
                error_code="GIT_STAGE_RECOVERED_NOT_APPLIED",
                external_effect="local_git_index",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "failed")
            raise GitWriteError(
                "GIT_STAGE_RECOVERED_NOT_APPLIED",
                "The prior stage authority was claimed but the index is provably unchanged; staging was not replayed.",
                status="failed",
                details={"receipt": receipt.as_dict(), "recovered": True},
            )

        if isinstance(preflight, HunkStagePreflight):
            success = (
                current.head == preflight.snapshot.head
                and current.branch == preflight.snapshot.branch
                and current.staged == preflight.candidate_leaf_paths
                and current.staged_diff_hash == preflight.candidate_staged_diff_hash
                and current.index_state_hash == preflight.candidate_index_state_hash
                and not current.policy_findings
            )
        elif preflight.operation == "stage_paths":
            remaining_paths = tuple(sorted(set(current.unstaged) | set(current.untracked)))
            selected_still_dirty = any(
                self._scopes_overlap(selected, remaining)
                for selected in preflight.candidate_paths
                for remaining in remaining_paths
            )
            success = (
                current.head == preflight.snapshot.head
                and current.branch == preflight.snapshot.branch
                and current.staged == preflight.candidate_leaf_paths
                and not selected_still_dirty
                and current.staged_diff_hash == preflight.candidate_staged_diff_hash
                and current.index_state_hash == preflight.candidate_index_state_hash
                and not current.policy_findings
            )
        else:
            success = (
                current.head == preflight.snapshot.head
                and current.branch == preflight.snapshot.branch
                and current.staged == preflight.candidate_leaf_paths
                and not current.unstaged
                and not current.untracked
                and current.staged_diff_hash == preflight.candidate_staged_diff_hash
                and current.index_state_hash == preflight.candidate_index_state_hash
                and not current.policy_findings
            )

        status = "succeeded" if success else "outcome_unknown"
        receipt = GitMutationReceipt(
            f"git-{operation}-recovery:{secrets.token_urlsafe(12)}",
            self._audit_id(operation, preflight_id, current, "recovered"),
            operation,
            status,
            workspace_id,
            working_tree_id,
            preflight.task_id,
            preflight_id,
            current.branch,
            preflight.snapshot.head,
            current.head,
            current.staged_diff_hash,
            current.index_state_hash,
            error_code="" if success else "GIT_STAGE_RECOVERY_UNKNOWN",
            external_effect="local_git_index",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, status)
        if success:
            return receipt
        raise GitWriteError(
            "GIT_STAGE_RECOVERY_UNKNOWN",
            "The claimed stage authority has an ambiguous index read-back; staging was not replayed.",
            status="outcome_unknown",
            details={"receipt": receipt.as_dict(), "recovered": True},
        )

    def _reconcile_executing_commit(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        preflight_id: str,
    ) -> GitMutationReceipt | None:
        if self._authority_state(preflight_id) != "executing":
            return None
        recorded = self._resume_recorded_outcome(preflight_id)
        if recorded is not None:
            return recorded
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, (CommitPreflight, VerifiedCommitPreflight)):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_COMMIT_RECOVERY_UNKNOWN",
                "Executing commit authority could not be reconstructed safely.",
                status="outcome_unknown",
            )
        if preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            raise GitWriteError(
                "GIT_PREFLIGHT_BINDING_MISMATCH",
                "Executing commit authority is bound to another working tree.",
                status="rejected",
            )

        operation = "verified_commit" if isinstance(preflight, VerifiedCommitPreflight) else "commit"
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if current == preflight.snapshot:
            receipt = GitMutationReceipt(
                f"git-{operation}-recovery:{secrets.token_urlsafe(12)}",
                self._audit_id(operation, preflight_id, current, "recovered-not-applied"),
                operation,
                "failed",
                workspace_id,
                working_tree_id,
                preflight.task_id,
                preflight_id,
                current.branch,
                preflight.snapshot.head,
                current.head,
                preflight.candidate_staged_diff_hash,
                preflight.candidate_index_state_hash,
                error_code="GIT_COMMIT_RECOVERED_NOT_APPLIED",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "failed")
            raise GitWriteError(
                "GIT_COMMIT_RECOVERED_NOT_APPLIED",
                "The prior commit authority was claimed but repository state is provably unchanged; commit was not replayed.",
                status="failed",
                details={"receipt": receipt.as_dict(), "recovered": True},
            )

        success = False
        commit_tree_hash = ""
        commit_diff_hash = ""
        old_head = preflight.snapshot.head
        if current.head and current.head != old_head and current.branch == preflight.snapshot.branch:
            parent = self._run(repo, ("show", "-s", "--format=%P", current.head))
            subject = self._run(repo, ("show", "-s", "--format=%s", current.head))
            tree = self._run(repo, ("show", "-s", "--format=%T", current.head))
            if old_head == _UNBORN_HEAD:
                diff = self._run(repo, ("show", "--format=", "--binary", "--no-ext-diff", current.head, "--"))
                names = self._run(repo, ("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", current.head, "--"))
            else:
                diff = self._run(repo, ("diff", "--binary", "--no-ext-diff", old_head, current.head, "--"))
                names = self._run(repo, ("diff", "--name-only", old_head, current.head, "--"))
            readbacks = (parent, subject, tree, diff, names)
            readback_ok = all(
                not result.timed_out
                and not result.transport_error
                and not result.truncated
                and result.returncode == 0
                for result in readbacks
            )
            expected_parent = "" if old_head == _UNBORN_HEAD else old_head
            committed_paths: tuple[str, ...] = ()
            if readback_ok:
                try:
                    committed_paths = tuple(sorted(_safe_rel_path(line) for line in names.stdout.splitlines() if line.strip()))
                except GitWriteError:
                    readback_ok = False
            if (
                readback_ok
                and parent.stdout.strip() == expected_parent
                and subject.stdout.strip() == preflight.commit_message
                and _HEX40.fullmatch(tree.stdout.strip())
                and committed_paths == preflight.candidate_leaf_paths
            ):
                if isinstance(preflight, VerifiedCommitPreflight):
                    success = not current.dirty and not current.policy_findings
                elif preflight.preserved_staged_paths:
                    try:
                        preserved_hash_matches = (
                            current.staged == preflight.preserved_staged_paths
                            and self._staged_scope_hash(repo, preflight.preserved_staged_paths)
                            == preflight.preserved_staged_scope_hash
                        )
                    except GitWriteError:
                        preserved_hash_matches = False
                    success = (
                        preserved_hash_matches
                        and current.unstaged == preflight.snapshot.unstaged
                        and current.untracked == preflight.snapshot.untracked
                        and not current.policy_findings
                    )
                else:
                    success = (
                        not current.staged
                        and current.unstaged == preflight.snapshot.unstaged
                        and current.untracked == preflight.snapshot.untracked
                        and not current.policy_findings
                    )
                if success:
                    commit_tree_hash = tree.stdout.strip()
                    commit_diff_hash = _sha256_bytes(diff.stdout.encode("utf-8"))

        status = "succeeded" if success else "outcome_unknown"
        receipt = GitMutationReceipt(
            f"git-{operation}-recovery:{secrets.token_urlsafe(12)}",
            self._audit_id(operation, preflight_id, current, "recovered"),
            operation,
            status,
            workspace_id,
            working_tree_id,
            preflight.task_id,
            preflight_id,
            current.branch,
            old_head,
            current.head,
            preflight.candidate_staged_diff_hash,
            preflight.candidate_index_state_hash,
            commit_tree_hash,
            commit_diff_hash,
            error_code="" if success else "GIT_COMMIT_RECOVERY_UNKNOWN",
            external_effect="local_git_commit",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, status)
        if success:
            return receipt
        raise GitWriteError(
            "GIT_COMMIT_RECOVERY_UNKNOWN",
            "The claimed commit authority has an ambiguous repository read-back; commit was not replayed.",
            status="outcome_unknown",
            details={"receipt": receipt.as_dict(), "recovered": True},
        )

    def _reconcile_executing_push(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        preflight_id: str,
    ) -> GitMutationReceipt | None:
        if self._authority_state(preflight_id) != "executing":
            return None
        recorded = self._resume_recorded_outcome(preflight_id)
        if recorded is not None:
            return recorded
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, PushPreflight):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_PUSH_RECOVERY_UNKNOWN",
                "Executing push authority could not be reconstructed safely.",
                status="outcome_unknown",
            )
        if preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            raise GitWriteError(
                "GIT_PREFLIGHT_BINDING_MISMATCH",
                "Executing push authority is bound to another working tree.",
                status="rejected",
            )

        observed = ""
        status = "outcome_unknown"
        error_code = "GIT_PUSH_RECOVERY_UNKNOWN"
        try:
            url_info = self._remote_url(repo, preflight.remote_name)
            if url_info is not None and _sha256_text(url_info[0]) == preflight.remote_url_hash:
                observed = self._remote_head(repo, url_info[0], preflight.snapshot.branch)
                if observed == preflight.snapshot.head:
                    status = "succeeded"
                    error_code = ""
                elif observed == preflight.expected_remote_head:
                    status = "failed"
                    error_code = "GIT_PUSH_RECOVERED_NOT_APPLIED"
        except (GitWriteError, OSError, ValueError):
            status = "outcome_unknown"
            error_code = "GIT_PUSH_RECOVERY_UNKNOWN"

        receipt = GitMutationReceipt(
            f"git-push-recovery:{secrets.token_urlsafe(12)}",
            self._audit_id("push", preflight_id, preflight.snapshot, "recovered"),
            "push",
            status,
            workspace_id,
            working_tree_id,
            preflight.task_id,
            preflight_id,
            preflight.snapshot.branch,
            preflight.snapshot.head,
            preflight.snapshot.head,
            preflight.snapshot.staged_diff_hash,
            preflight.snapshot.index_state_hash,
            remote_name=preflight.remote_name,
            remote_url_hash=preflight.remote_url_hash,
            expected_remote_head=preflight.expected_remote_head,
            observed_remote_head=observed,
            error_code=error_code,
            external_effect="remote_git_push",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, status)
        if status == "succeeded":
            return receipt
        if status == "failed":
            raise GitWriteError(
                "GIT_PUSH_RECOVERED_NOT_APPLIED",
                "The prior push authority was claimed but the remote is provably unchanged; push was not replayed.",
                status="failed",
                details={"receipt": receipt.as_dict(), "recovered": True},
            )
        raise GitWriteError(
            "GIT_PUSH_RECOVERY_UNKNOWN",
            "The claimed push authority has an ambiguous remote read-back; push was not replayed.",
            status="outcome_unknown",
            details={"receipt": receipt.as_dict(), "recovered": True},
        )

    @staticmethod
    def default_runner(repo: Path, argv: tuple[str, ...], *, timeout_seconds: float, network: bool) -> _CommandResult:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        command = ["git", "-C", str(repo), *argv]

        def run_command(current_command: list[str], current_env: dict[str, str]) -> _CommandResult:
            try:
                result = run_bounded(
                    current_command,
                    env=current_env,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=_MAX_OUTPUT,
                )
            except (OSError, ValueError):
                return _CommandResult(125, timed_out=True, transport_error=True)
            if result.timed_out:
                return _CommandResult(
                    124,
                    result.stdout,
                    result.stderr,
                    timed_out=True,
                    truncated=result.output_truncated,
                )
            return _CommandResult(
                result.returncode if result.returncode is not None else 125,
                result.stdout,
                result.stderr,
                truncated=result.output_truncated,
            )

        github_target = network and _github_https_network_target(argv)
        github_read = github_target and bool(argv) and argv[0] == "ls-remote"
        if github_read:
            unauthenticated = ["git", "-c", "credential.helper=", "-C", str(repo), *argv]
            first = run_command(unauthenticated, env)
            if first.returncode == 0 or first.timed_out or first.transport_error or first.truncated:
                return first

        if github_target:
            gh = _trusted_github_cli()
            if not gh:
                return _CommandResult(126, stderr="GitHub credential bridge unavailable.")
            env["GH_CONFIG_DIR"] = _github_cli_config_dir()
            env["GH_PROMPT_DISABLED"] = "1"
            env["XDG_STATE_HOME"] = _github_cli_state_dir()
            command = [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                f"credential.https://github.com.helper=!{gh} auth git-credential",
                "-C",
                str(repo),
                *argv,
            ]
        return run_command(command, env)

    def _run(self, repo: Path, argv: Iterable[str], *, network: bool = False, timeout_seconds: float = 30) -> _CommandResult:
        parsed = tuple(argv)
        if not parsed or any(not isinstance(arg, str) or "\x00" in arg for arg in parsed):
            raise GitWriteError("GIT_ARGV_INVALID", "internal Git argv is invalid.", status="blocked")
        return self._runner(repo, parsed, timeout_seconds=timeout_seconds, network=network)

    @staticmethod
    def _run_with_input(
        repo: Path,
        argv: Iterable[str],
        input_text: str,
        *,
        index_path: Path | None = None,
        timeout_seconds: float = 30,
    ) -> _CommandResult:
        parsed = tuple(argv)
        if not parsed or any(not isinstance(arg, str) or "\x00" in arg for arg in parsed):
            raise GitWriteError("GIT_ARGV_INVALID", "internal Git argv is invalid.", status="blocked")
        if not isinstance(input_text, str) or len(input_text.encode("utf-8")) > _MAX_OUTPUT:
            raise GitWriteError("GIT_HUNK_PATCH_LIMIT", "hunk patch exceeds the bounded input limit.", status="blocked")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        if index_path is not None:
            env["GIT_INDEX_FILE"] = str(index_path)
        try:
            result = run_bounded(
                ["git", "-C", str(repo), *parsed],
                env=env,
                input_text=input_text,
                timeout_seconds=timeout_seconds,
                max_output_bytes=_MAX_OUTPUT,
            )
        except (OSError, ValueError):
            return _CommandResult(125, timed_out=True, transport_error=True)
        if result.timed_out:
            return _CommandResult(124, result.stdout, result.stderr, timed_out=True, truncated=result.output_truncated)
        return _CommandResult(
            result.returncode if result.returncode is not None else 125,
            result.stdout,
            result.stderr,
            truncated=result.output_truncated,
        )

    @staticmethod
    def _run_with_index(repo: Path, argv: Iterable[str], index_path: Path, *, timeout_seconds: float = 30) -> _CommandResult:
        """Run fixed local Git argv against a private temporary index.

        This helper is intentionally internal and never accepts caller-provided
        environment values.  It lets verified preflight model the exact commit
        candidate without mutating the repository's real index.
        """

        parsed = tuple(argv)
        if not parsed or any(not isinstance(arg, str) or "\x00" in arg for arg in parsed):
            raise GitWriteError("GIT_ARGV_INVALID", "internal Git argv is invalid.", status="blocked")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_INDEX_FILE": str(index_path),
        }
        try:
            result = run_bounded(
                ["git", "-C", str(repo), *parsed],
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=_MAX_OUTPUT,
            )
        except (OSError, ValueError):
            return _CommandResult(125, timed_out=True, transport_error=True)
        if result.timed_out:
            return _CommandResult(124, result.stdout, result.stderr, timed_out=True, truncated=result.output_truncated)
        return _CommandResult(
            result.returncode if result.returncode is not None else 125,
            result.stdout,
            result.stderr,
            truncated=result.output_truncated,
        )

    @staticmethod
    def _repo_identity(repo: Path) -> tuple[Path, str]:
        if repo.is_symlink() or not repo.is_dir():
            raise GitWriteError("GIT_REPOSITORY_INVALID", "registered workspace is not a real directory.", status="blocked")
        try:
            resolved = repo.resolve(strict=True)
            stat = resolved.stat()
        except OSError:
            raise GitWriteError("GIT_REPOSITORY_INVALID", "registered workspace cannot be resolved.", status="blocked") from None
        return resolved, _sha256_text(f"{resolved}\0{stat.st_dev}\0{stat.st_ino}")[:32]

    @staticmethod
    def _parse_status(output: str) -> tuple[set[str], set[str], set[str], set[str]]:
        staged: set[str] = set()
        unstaged: set[str] = set()
        untracked: set[str] = set()
        findings: set[str] = set()
        records = output.split("\x00") if "\x00" in output else output.splitlines()
        index = 0
        while index < len(records):
            line = records[index].rstrip("\n")
            index += 1
            if not line or line.startswith("#"):
                continue
            if line.startswith("?"):
                raw = line[2:] if line.startswith("? ") else line[1:].lstrip()
                if raw.endswith("/"):
                    raw = raw[:-1]
                untracked.add(_safe_rel_path(raw))
                continue
            if len(line) < 4 or line[0] not in {"1", "2", "u"}:
                findings.add("GIT_STATUS_MALFORMED")
                continue
            xy = line[2:4]
            if "\t" in line:
                raw = line.split("\t", 1)[1]
                paths = [_safe_rel_path(raw)]
                if line.startswith("2"):
                    if index >= len(records) or not records[index]:
                        findings.add("GIT_STATUS_MALFORMED")
                        continue
                    paths.append(_safe_rel_path(records[index]))
                    index += 1
            else:
                fields = line.split(" ")
                if line.startswith("1") and len(fields) >= 9:
                    paths = [_safe_rel_path(fields[-1])]
                elif line.startswith("u") and len(fields) >= 11:
                    paths = [_safe_rel_path(fields[-1])]
                else:
                    findings.add("GIT_STATUS_MALFORMED")
                    continue
            if xy[0] not in {".", " "}:
                staged.update(paths)
            if xy[1] not in {".", " "}:
                unstaged.update(paths)
        return staged, unstaged, untracked, findings

    @staticmethod
    def _path_findings(repo: Path, paths: Iterable[str]) -> set[str]:
        findings: set[str] = set()
        root = repo.resolve(strict=True)
        for path in paths:
            if _sensitive_path(path):
                findings.add("SENSITIVE_PATH_DENIED")
            target = repo / path
            try:
                if target.is_symlink():
                    findings.add("SYMLINK_PATH_DENIED")
                resolved = target.resolve(strict=False)
                resolved.relative_to(root)
            except ValueError:
                findings.add("PATH_ESCAPE_DENIED")
            except OSError:
                findings.add("PATH_VALIDATION_FAILED")
        return findings

    @staticmethod
    def _scopes_match_leaves(scopes: tuple[str, ...], leaves: tuple[str, ...]) -> bool:
        """Return true when compressed status scopes and exact staged leaves are equivalent."""

        if not scopes or not leaves:
            return False
        leaves_covered = all(
            any(leaf == scope or leaf.startswith(scope + "/") for scope in scopes)
            for leaf in leaves
        )
        scopes_represented = all(
            any(leaf == scope or leaf.startswith(scope + "/") for leaf in leaves)
            for scope in scopes
        )
        return leaves_covered and scopes_represented

    @staticmethod
    def _scopes_overlap(left: str, right: str) -> bool:
        return left == right or left.startswith(right + "/") or right.startswith(left + "/")

    @classmethod
    def _requested_paths_match_changes(cls, requested: tuple[str, ...], changed: tuple[str, ...]) -> bool:
        return bool(requested) and all(
            any(cls._scopes_overlap(path, scope) for scope in changed)
            for path in requested
        )

    @staticmethod
    def _normalize_requested_stage_paths(paths: Iterable[str]) -> tuple[str, ...]:
        if isinstance(paths, (str, bytes)):
            raise GitWriteError("GIT_PATHS_INVALID", "paths must be a non-empty bounded path collection.")
        try:
            normalized = tuple(sorted({_safe_rel_path(path) for path in paths}))
        except TypeError:
            raise GitWriteError("GIT_PATHS_INVALID", "paths must be a non-empty bounded path collection.") from None
        if not normalized:
            raise GitWriteError("GIT_PATHS_REQUIRED", "paths must contain at least one repository-relative path.")
        if len(normalized) > _MAX_PATHS:
            raise GitWriteError("GIT_PATH_LIMIT", f"paths exceeds the {_MAX_PATHS}-path safety limit.", status="blocked")
        return normalized

    @staticmethod
    def _normalize_hunk_ids(hunk_ids: Iterable[str]) -> tuple[str, ...]:
        if isinstance(hunk_ids, (str, bytes)):
            raise GitWriteError("GIT_HUNK_IDS_INVALID", "hunk_ids must be a bounded collection.")
        try:
            values = tuple(hunk_ids)
        except TypeError:
            raise GitWriteError("GIT_HUNK_IDS_INVALID", "hunk_ids must be a bounded collection.") from None
        if any(not isinstance(value, str) or not re.fullmatch(r"hunk:[0-9a-f]{64}", value) for value in values):
            raise GitWriteError("GIT_HUNK_IDS_INVALID", "hunk ids must be content-derived hunk:<64-hex> values.")
        if len(set(values)) != len(values):
            raise GitWriteError("GIT_HUNK_DUPLICATE", "duplicate hunk ids are not allowed.")
        if len(values) > _MAX_HUNKS:
            raise GitWriteError("GIT_HUNK_LIMIT", f"hunk selection exceeds the {_MAX_HUNKS}-hunk safety limit.", status="blocked")
        return values

    def _hunk_inventory(
        self,
        repo: Path,
        requested_paths: tuple[str, ...],
    ) -> tuple[dict[str, str], tuple[GitHunk, ...]]:
        if len(requested_paths) > _MAX_HUNK_PATHS:
            raise GitWriteError(
                "GIT_HUNK_PATH_LIMIT",
                f"hunk staging accepts at most {_MAX_HUNK_PATHS} exact file paths.",
                status="blocked",
            )
        names = self._run(
            repo,
            ("diff", "--name-only", "-z", "--diff-filter=M", "--no-renames", "--no-ext-diff", "--", *requested_paths),
        )
        if names.returncode != 0 or names.timed_out or names.transport_error or names.truncated:
            raise GitWriteError("GIT_HUNK_DIFF_UNAVAILABLE", "tracked text change paths could not be read safely.", status="blocked")
        modified = tuple(sorted(_safe_rel_path(path) for path in names.stdout.split("\x00") if path))
        if modified != requested_paths:
            raise GitWriteError(
                "GIT_HUNK_PATH_NOT_TRACKED_MODIFICATION",
                "hunk staging requires exact tracked modified file paths; use path staging for other change types.",
                status="blocked",
            )
        diffs: dict[str, str] = {}
        hunks: list[GitHunk] = []
        total_bytes = 0
        for path in requested_paths:
            result = self._run(
                repo,
                ("diff", "--no-ext-diff", "--no-renames", "--no-color", "--no-textconv", "--unified=1", "--", path),
            )
            if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
                raise GitWriteError("GIT_HUNK_DIFF_UNAVAILABLE", "file diff could not be read safely.", status="blocked")
            total_bytes += len(result.stdout.encode("utf-8"))
            if total_bytes > _MAX_OUTPUT:
                raise GitWriteError("GIT_HUNK_PATCH_LIMIT", "hunk inventory exceeds the bounded diff limit.", status="blocked")
            try:
                parsed = enumerate_file_hunks(path, result.stdout)
            except GitHunkSelectionError as exc:
                raise GitWriteError(exc.code, exc.message, status="blocked") from exc
            diffs[path] = result.stdout
            hunks.extend(parsed)
        if len(hunks) > _MAX_HUNKS:
            raise GitWriteError("GIT_HUNK_LIMIT", f"hunk inventory exceeds the {_MAX_HUNKS}-hunk safety limit.", status="blocked")
        return diffs, tuple(hunks)

    @staticmethod
    def _selected_hunk_patch(
        diffs: Mapping[str, str],
        available_hunks: tuple[GitHunk, ...],
        selected_hunk_ids: tuple[str, ...],
    ) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        by_id = {hunk.hunk_id: hunk for hunk in available_hunks}
        if any(hunk_id not in by_id for hunk_id in selected_hunk_ids):
            raise GitWriteError("GIT_HUNK_UNKNOWN", "one or more selected hunks no longer match the current diff.", status="blocked")
        selected_set = set(selected_hunk_ids)
        candidate_paths = tuple(sorted({by_id[hunk_id].path for hunk_id in selected_hunk_ids}))
        patch_parts: list[str] = []
        ordered_ids: list[str] = []
        for path in candidate_paths:
            path_ids = tuple(
                hunk.hunk_id for hunk in available_hunks if hunk.path == path and hunk.hunk_id in selected_set
            )
            try:
                selection = build_hunk_patch(path, diffs[path], path_ids)
            except GitHunkSelectionError as exc:
                raise GitWriteError(exc.code, exc.message, status="blocked") from exc
            patch_parts.append(selection.patch)
            ordered_ids.extend(selection.hunk_ids)
        return "".join(patch_parts), tuple(ordered_ids), candidate_paths

    def _candidate_hunk_index_evidence(
        self,
        repo: Path,
        *,
        head: str,
        patch_text: str,
        candidate_paths: tuple[str, ...],
        seed_from_real_index: bool = False,
    ) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
        if not head or not _HEX40.fullmatch(head):
            raise GitWriteError("GIT_HEAD_INVALID", "hunk staging requires a full existing HEAD commit id.", status="blocked")
        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-hunk-index-") as directory:
            index_path = Path(directory) / "index"
            if seed_from_real_index:
                resolved_index = self._run(repo, ("rev-parse", "--git-path", "index"))
                if (
                    resolved_index.returncode != 0
                    or resolved_index.timed_out
                    or resolved_index.transport_error
                    or resolved_index.truncated
                ):
                    raise GitWriteError(
                        "GIT_HUNK_INDEX_UNAVAILABLE",
                        "real Git index path could not be resolved safely.",
                        status="blocked",
                    )
                raw_index_path = resolved_index.stdout.strip()
                if not raw_index_path or "\x00" in raw_index_path:
                    raise GitWriteError("GIT_HUNK_INDEX_UNAVAILABLE", "real Git index path is invalid.", status="blocked")
                source_index = Path(raw_index_path)
                if not source_index.is_absolute():
                    source_index = repo / source_index
                try:
                    if source_index.is_symlink() or not source_index.is_file():
                        raise OSError("index is not a regular file")
                    shutil.copyfile(source_index, index_path)
                except OSError:
                    raise GitWriteError(
                        "GIT_HUNK_INDEX_UNAVAILABLE",
                        "real Git index could not be copied into the private hunk index.",
                        status="blocked",
                    ) from None
            else:
                initialized = self._run_with_index(repo, ("read-tree", head), index_path)
                if initialized.returncode != 0 or initialized.timed_out or initialized.transport_error or initialized.truncated:
                    raise GitWriteError("GIT_HUNK_INDEX_UNAVAILABLE", "temporary hunk index could not be initialized.", status="blocked")
            applied = self._run_with_input(
                repo,
                ("apply", "--cached", "--whitespace=nowarn", "-"),
                patch_text,
                index_path=index_path,
            )
            if applied.returncode != 0 or applied.timed_out or applied.transport_error or applied.truncated:
                raise GitWriteError("GIT_HUNK_PATCH_REJECTED", "selected hunk patch does not apply cleanly to the pinned HEAD.", status="blocked")
            diff = self._run_with_index(
                repo,
                ("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--"),
                index_path,
            )
            names = self._run_with_index(
                repo,
                ("diff", "--cached", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--"),
                index_path,
            )
            for result in (diff, names):
                if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
                    raise GitWriteError("GIT_HUNK_INDEX_UNAVAILABLE", "candidate hunk index evidence could not be read safely.", status="blocked")
            rendered_paths = tuple(sorted(_safe_rel_path(path) for path in names.stdout.split("\x00") if path))
            findings = self._secret_content_findings(repo, candidate_paths, index_path=index_path)
            diff_hash, index_hash = self._compact_index_hashes(diff.stdout, names.stdout)
            return diff_hash, index_hash, rendered_paths, tuple(sorted(findings))

    @staticmethod
    def _compact_index_hashes(raw_diff: str, names: str) -> tuple[str, str]:
        raw = raw_diff.encode("utf-8")
        rendered_names = names.encode("utf-8")
        return (
            _sha256_bytes(b"DIFF\0" + raw),
            _sha256_bytes(b"INDEX\0" + raw + b"\0" + rendered_names),
        )

    @staticmethod
    def _path_in_scopes(path: str, scopes: tuple[str, ...]) -> bool:
        return any(path == scope or path.startswith(scope + "/") for scope in scopes)

    def _commit_scoped_staged_paths(
        self,
        task: GitTaskBinding,
        snapshot: GitStateSnapshot,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if not task.allowed_paths:
            return snapshot.staged, ()
        candidate = tuple(
            path for path in snapshot.staged if self._path_in_scopes(path, task.allowed_paths)
        )
        preserved = tuple(path for path in snapshot.staged if path not in set(candidate))
        return candidate, preserved

    def _staged_patch_for_paths(self, repo: Path, paths: tuple[str, ...]) -> str:
        if not paths:
            return ""
        result = self._run(
            repo,
            (
                "diff",
                "--cached",
                "--binary",
                "--full-index",
                "--no-renames",
                "--no-ext-diff",
                "--",
                *paths,
            ),
        )
        if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
            raise GitWriteError(
                "GIT_COMMIT_INDEX_UNAVAILABLE",
                "task-owned staged patch could not be read safely.",
                status="blocked",
            )
        return result.stdout

    def _staged_scope_hash(self, repo: Path, paths: tuple[str, ...]) -> str:
        if not paths:
            return _sha256_bytes(b"")
        result = self._run(
            repo,
            (
                "diff",
                "--cached",
                "--raw",
                "-z",
                "--no-abbrev",
                "--no-renames",
                "--no-ext-diff",
                "--",
                *paths,
            ),
        )
        if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
            raise GitWriteError(
                "GIT_COMMIT_INDEX_UNAVAILABLE",
                "preserved staged scope could not be read safely.",
                status="blocked",
            )
        return _sha256_bytes(result.stdout.encode("utf-8"))

    def _candidate_staged_subset_index_evidence(
        self,
        repo: Path,
        *,
        head: str,
        candidate_paths: tuple[str, ...],
    ) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
        patch_text = self._staged_patch_for_paths(repo, candidate_paths)
        if not patch_text:
            return _sha256_bytes(b""), _sha256_bytes(b""), (), ()
        return self._candidate_hunk_index_evidence(
            repo,
            head=head,
            patch_text=patch_text,
            candidate_paths=candidate_paths,
            seed_from_real_index=False,
        )

    def _secret_content_findings(
        self,
        repo: Path,
        paths: Iterable[str],
        *,
        index_path: Path | None = None,
    ) -> set[str]:
        """Block only newly introduced secret-shaped lines, bounded and fail-closed.

        Candidate files are streamed instead of rendering their full diff, so
        large safe files remain supported.  When a suspicious line already
        exists verbatim in ``HEAD`` it is treated as baseline debt rather than
        a newly introduced credential.  Added or changed suspicious lines are
        still blocked. ``index_path`` is accepted for temporary-index callers;
        verified candidates are sourced from the same worktree bytes staged in
        that private index.
        """

        del index_path  # the candidate index is populated from these exact worktree paths
        findings: set[str] = set()
        scanned = 0
        root = repo.resolve(strict=True)
        for raw_path in paths:
            path = _safe_rel_path(raw_path)
            target = repo / path
            try:
                if target.is_symlink():
                    findings.add("SYMLINK_PATH_DENIED")
                    continue
                resolved = target.resolve(strict=False)
                resolved.relative_to(root)
                if not resolved.exists():
                    continue
                if not resolved.is_file():
                    findings.add("PATH_VALIDATION_FAILED")
                    continue
                candidate_suspicious: Counter[str] = Counter()
                with resolved.open("rb") as handle:
                    for raw_line in handle:
                        scanned += len(raw_line)
                        if scanned > _MAX_SECRET_SCAN_BYTES:
                            findings.add("SECRET_SCAN_LIMIT_EXCEEDED")
                            return findings
                        line = raw_line.decode("latin-1").rstrip("\r\n")
                        if _PRIVATE_KEY_HEADER_RE.search(line) or contains_secret_like_content(line):
                            candidate_suspicious[line] += 1
                if not candidate_suspicious:
                    continue

                baseline = self._run(
                    repo,
                    (
                        "grep",
                        "-I",
                        "-h",
                        "-i",
                        "-E",
                        _SECRET_GREP_PATTERN,
                        "HEAD",
                        "--",
                        path,
                    ),
                )
                if baseline.timed_out or baseline.transport_error or baseline.truncated or baseline.returncode not in {0, 1}:
                    findings.add("SENSITIVE_CONTENT_DENIED")
                    return findings
                baseline_suspicious: Counter[str] = Counter()
                if baseline.returncode == 0:
                    for line in baseline.stdout.splitlines():
                        if _PRIVATE_KEY_HEADER_RE.search(line) or contains_secret_like_content(line):
                            baseline_suspicious[line] += 1
                if any(count > baseline_suspicious.get(line, 0) for line, count in candidate_suspicious.items()):
                    findings.add("SENSITIVE_CONTENT_DENIED")
                    return findings
            except (OSError, ValueError):
                findings.add("PATH_VALIDATION_FAILED")
        return findings

    def verified_candidate_leaf_paths(self, repo: Path, snapshot: GitStateSnapshot) -> tuple[str, ...]:
        """Expand only untracked status scopes into exact leaf paths without staging."""

        leaves = set(snapshot.unstaged)
        if snapshot.untracked:
            result = self._run(
                repo,
                ("ls-files", "--others", "--exclude-standard", "-z", "--", *snapshot.untracked),
            )
            if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
                raise GitWriteError(
                    "GIT_VERIFIED_CANDIDATE_UNAVAILABLE",
                    "exact untracked candidate paths could not be read safely.",
                    status="blocked",
                )
            untracked_leaves = tuple(
                sorted(_safe_rel_path(path) for path in result.stdout.split("\x00") if path)
            )
            for scope in snapshot.untracked:
                leaves.update(
                    leaf
                    for leaf in untracked_leaves
                    if leaf == scope or leaf.startswith(scope + "/")
                )
        rendered = tuple(sorted(leaves))
        if len(rendered) > _MAX_PATHS:
            raise GitWriteError(
                "GIT_PATH_LIMIT",
                f"verified commit candidate exceeds {_MAX_PATHS} exact paths.",
                status="blocked",
            )
        return rendered

    def snapshot(self, repo: Path, *, workspace_id: str, working_tree_id: str) -> GitStateSnapshot:
        resolved, repository_id = self._repo_identity(repo)
        top = self._run(resolved, ("rev-parse", "--show-toplevel"))
        if top.returncode != 0 or Path(top.stdout.strip()).resolve(strict=False) != resolved:
            raise GitWriteError("GIT_REPOSITORY_INVALID", "registered workspace is not the verified Git root.", status="blocked")
        head_result = self._run(resolved, ("rev-parse", "--verify", "HEAD"))
        head = head_result.stdout.strip().lower() if head_result.returncode == 0 else ""
        if head and not _HEX40.fullmatch(head):
            raise GitWriteError("GIT_HEAD_INVALID", "repository HEAD is not a full commit id.", status="blocked")
        branch_result = self._run(resolved, ("symbolic-ref", "--quiet", "--short", "HEAD"))
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""
        if branch:
            branch = validate_branch_name(branch)
            if not head:
                head = _UNBORN_HEAD
        status_result = self._run(resolved, ("status", "--porcelain=v2", "-z", "--branch"))
        if status_result.returncode != 0:
            raise GitWriteError("GIT_STATUS_UNAVAILABLE", "repository status could not be read safely.", status="blocked")
        if status_result.truncated:
            raise GitWriteError("GIT_OUTPUT_TRUNCATED", "Git status output exceeded the safety bound.", status="blocked")
        try:
            staged, unstaged, untracked, status_findings = self._parse_status(status_result.stdout)
        except GitWriteError:
            raise
        paths = tuple(sorted(staged | unstaged | untracked))
        if len(paths) > _MAX_PATHS:
            status_findings.add("GIT_PATH_LIMIT")
        path_findings = self._path_findings(resolved, paths)
        diff_result = self._run(
            resolved,
            ("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--"),
        )
        names_result = self._run(
            resolved,
            ("diff", "--cached", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--"),
        )
        if diff_result.returncode != 0 or names_result.returncode != 0:
            raise GitWriteError("GIT_INDEX_UNAVAILABLE", "staged Git state could not be read safely.", status="blocked")
        if diff_result.truncated or names_result.truncated:
            raise GitWriteError("GIT_OUTPUT_TRUNCATED", "Git index/diff output exceeded the safety bound.", status="blocked")
        staged_diff_hash, index_state_hash = self._compact_index_hashes(diff_result.stdout, names_result.stdout)
        status_bytes = status_result.stdout.encode("utf-8")
        path_findings.update(self._secret_content_findings(resolved, staged))
        path_findings.update(self._hooks_findings(resolved))
        return GitStateSnapshot(
            repository_id=repository_id,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            branch=branch,
            head=head,
            staged=tuple(sorted(staged)),
            unstaged=tuple(sorted(unstaged)),
            untracked=tuple(sorted(untracked)),
            changed_paths=paths,
            index_state_hash=index_state_hash,
            staged_diff_hash=staged_diff_hash,
            worktree_state_hash=_sha256_bytes(
                status_bytes
                + b"\0"
                + index_state_hash.encode("ascii")
                + b"\0"
                + staged_diff_hash.encode("ascii")
            ),
            policy_findings=tuple(sorted(status_findings | path_findings)),
        )

    def _hooks_findings(self, repo: Path) -> set[str]:
        """Reject repository-controlled hooks rather than executing shell code implicitly."""

        findings: set[str] = set()
        configured = self._run(repo, ("config", "--local", "--get", "core.hooksPath"))
        if configured.returncode == 0 and configured.stdout.strip():
            findings.add("GIT_HOOKS_PATH_DENIED")
        git_dir_result = self._run(repo, ("rev-parse", "--git-dir"))
        if git_dir_result.returncode != 0 or not git_dir_result.stdout.strip():
            findings.add("GIT_HOOKS_STATE_UNAVAILABLE")
            return findings
        git_dir = Path(git_dir_result.stdout.strip())
        if not git_dir.is_absolute():
            git_dir = (repo / git_dir).resolve(strict=False)
        hooks_dir = git_dir / "hooks"
        try:
            if hooks_dir.exists() and hooks_dir.is_dir():
                for hook in hooks_dir.iterdir():
                    if hook.is_file() and not hook.name.endswith(".sample") and hook.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                        findings.add("GIT_HOOKS_PRESENT")
                        break
        except OSError:
            findings.add("GIT_HOOKS_STATE_UNAVAILABLE")
        return findings

    def issue_approval(
        self,
        operation: str,
        preflight_id: str,
        workspace_id: str,
        *,
        confirmation_action: str | None = None,
    ) -> tuple[str, str, float]:
        if operation not in {"commit", "push"}:
            raise GitWriteError("GIT_OPERATION_INVALID", "operation is invalid.")
        now = float(self._clock())
        token = f"git-approval:{secrets.token_urlsafe(24)}"
        action = confirmation_action.strip() if isinstance(confirmation_action, str) and confirmation_action.strip() else f"Git {operation}"
        confirmation = f"Approve {action} for {workspace_id} using preflight {preflight_id}."
        approval = GitApproval(token, confirmation, operation, preflight_id, workspace_id, now + self._approval_ttl_seconds)
        self._approvals[token] = _StoredApproval(approval)
        return token, confirmation, approval.expires_at

    def consume_approval(self, token: object, confirmation: object, *, operation: str, preflight_id: str, workspace_id: str) -> None:
        if not isinstance(token, str) or not isinstance(confirmation, str):
            raise GitWriteError("GIT_APPROVAL_INVALID", "approval token and confirmation are required.")
        stored = self._approvals.get(token)
        if stored is None:
            raise GitWriteError("GIT_APPROVAL_NOT_FOUND", "approval token is unknown or expired.")
        if stored.consumed:
            raise GitWriteError("GIT_APPROVAL_REUSED", "approval token has already been consumed.")
        if float(self._clock()) >= stored.approval.expires_at:
            raise GitWriteError("GIT_APPROVAL_EXPIRED", "approval token has expired.")
        if stored.approval.operation != operation or stored.approval.preflight_id != preflight_id or stored.approval.workspace_id != workspace_id:
            raise GitWriteError("GIT_APPROVAL_MISMATCH", "approval token is bound to a different Git operation.")
        if confirmation != stored.approval.confirmation:
            raise GitWriteError("GIT_APPROVAL_CONFIRMATION_MISMATCH", "confirmation does not match the preflight challenge.")
        stored.consumed = True

    def invalidate_preflight(self, preflight_id: str) -> None:
        """Retire a failed mutation target so every retry requires fresh evidence."""

        try:
            self._store.invalidate_preflight(preflight_id, now=float(self._clock()))
        except PersistenceError as exc:
            raise GitWriteError(
                "GIT_AUTHORITY_PERSISTENCE_FAILED",
                "Git preflight could not be invalidated safely.",
                status="blocked",
            ) from exc

    def commit_preflight_scope(self, preflight_id: str) -> tuple[tuple[str, ...], bool]:
        """Return the exact commit scope and whether this preflight adopts partial staging."""

        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, CommitPreflight):
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "commit preflight is unknown or expired.")
        return preflight.candidate_paths, preflight.partial_stage_adoption

    def stage_paths_preflight_scope(self, preflight_id: str) -> tuple[str, ...]:
        """Return the immutable selected path scope pinned by a live stage-paths preflight."""

        preflight = self._load_preflight(preflight_id)
        if (
            not isinstance(preflight, StagePreflight)
            or preflight.operation != "stage_paths"
            or preflight.status != "ready"
        ):
            raise GitWriteError(
                "GIT_STAGE_PATHS_PREFLIGHT_NOT_FOUND",
                "stage-paths preflight is unknown, expired, or no longer ready.",
                status="rejected",
            )
        return preflight.candidate_paths

    @staticmethod
    def _task_findings(
        task: GitTaskBinding,
        *,
        workspace_id: str,
        working_tree_id: str,
        snapshot: GitStateSnapshot,
        allow_unrelated_staged: bool = False,
    ) -> set[str]:
        findings: set[str] = set()
        if task.task_id == "":
            findings.add("TASK_REQUIRED")
        if task.workspace_id != workspace_id:
            findings.add("TASK_WORKSPACE_MISMATCH")
        if task.working_tree_id != working_tree_id:
            findings.add("TASK_WORKTREE_MISMATCH")
        if task.status in {"succeeded", "failed", "cancelled", "blocked", "stale"}:
            findings.add("TASK_TERMINAL")
        if not task.evidence_valid or not task.verification_receipt_id or not task.security_audit_receipt_id:
            findings.add("EVIDENCE_INCOMPLETE")
        if not allow_unrelated_staged and task.allowed_paths and any(
            not any(path == allowed or path.startswith(allowed + "/") for allowed in task.allowed_paths)
            for path in snapshot.staged
        ):
            findings.add("TASK_PATH_OUTSIDE_SCOPE")
        return findings

    @staticmethod
    def _common_findings(task_findings: set[str], snapshot: GitStateSnapshot, *, require_clean: bool = True) -> set[str]:
        findings = set(task_findings) | set(snapshot.policy_findings)
        if not snapshot.head:
            findings.add("HEAD_UNAVAILABLE")
        if not snapshot.branch:
            findings.add("DETACHED_HEAD")
        if require_clean and (snapshot.unstaged or snapshot.untracked):
            findings.add("WORKTREE_NOT_STAGED_ONLY")
        return findings

    def _commit_findings(
        self,
        task_findings: set[str],
        snapshot: GitStateSnapshot,
        *,
        task_id: str,
        commit_paths: tuple[str, ...] | None = None,
        allow_partial_stage_adoption: bool = False,
    ) -> set[str]:
        """Allow unrelated dirty state while rejecting partial staging of a commit path."""

        findings = self._common_findings(task_findings, snapshot, require_clean=False)
        staged_scope = set(snapshot.staged if commit_paths is None else commit_paths)
        partial_scope = staged_scope & set(snapshot.unstaged)
        if not partial_scope and "EVIDENCE_INCOMPLETE" in task_findings:
            partial_scope = set(snapshot.staged) & set(snapshot.unstaged)
        if partial_scope:
            trusted = self._store.has_trusted_partial_stage((
                snapshot.repository_id,
                snapshot.workspace_id,
                snapshot.working_tree_id,
                task_id,
                snapshot.head,
                snapshot.staged_diff_hash,
                snapshot.index_state_hash,
            ))
            if not trusted and not allow_partial_stage_adoption:
                findings.add("STAGED_PATH_HAS_UNSTAGED_CHANGES")
                findings.add("WORKTREE_NOT_STAGED_ONLY")
        return findings

    def _audit_id(self, operation: str, preflight_id: str, snapshot: GitStateSnapshot, extra: str = "") -> str:
        return f"audit:git-{_sha256_text(repr((operation, preflight_id, snapshot.repository_id, snapshot.head, snapshot.staged_diff_hash, extra)))[:32]}"

    @staticmethod
    def verified_commit_message(task: GitTaskBinding) -> str:
        """Build one deterministic bounded commit subject from Task Ledger truth."""

        title = task.title.strip() if isinstance(task.title, str) else ""
        if not title:
            title = f"Complete {task.task_id}"
        explicit = re.match(r"^(feat|fix|docs|test|refactor|perf|build|ci|chore)(?::|\s)", title, re.IGNORECASE)
        kind = explicit.group(1).lower() if explicit else "chore"
        if explicit and title.lower().startswith(kind + ":"):
            title = title[len(kind) + 1 :].strip()
        return validate_commit_message(f"{kind}: {title}")

    @staticmethod
    def _verified_task_findings(
        task: GitTaskBinding,
        *,
        workspace_id: str,
        working_tree_id: str,
        candidate_paths: tuple[str, ...],
    ) -> set[str]:
        findings: set[str] = set()
        if not task.task_id:
            findings.add("TASK_REQUIRED")
        if task.workspace_id != workspace_id:
            findings.add("TASK_WORKSPACE_MISMATCH")
        if task.working_tree_id != working_tree_id:
            findings.add("TASK_WORKTREE_MISMATCH")
        if task.status != "review_ready":
            findings.add("TASK_NOT_REVIEW_READY")
        if not task.evidence_valid or not task.verification_receipt_id or not task.security_audit_receipt_id:
            findings.add("EVIDENCE_INCOMPLETE")
        if not task.allowed_paths:
            findings.add("TASK_SCOPE_REQUIRED")
        elif any(
            not any(path == allowed or path.startswith(allowed + "/") for allowed in task.allowed_paths)
            for path in candidate_paths
        ):
            findings.add("TASK_PATH_OUTSIDE_SCOPE")
        return findings

    def _candidate_index_evidence(
        self,
        repo: Path,
        *,
        head: str,
        candidate_paths: tuple[str, ...],
        seed_from_real_index: bool = False,
    ) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
        """Return exact would-be staged diff/index evidence via a private index."""

        if not head or not _HEX40.fullmatch(head):
            raise GitWriteError("GIT_HEAD_INVALID", "verified commit requires a full HEAD commit id.", status="blocked")
        if not candidate_paths:
            return _sha256_bytes(b""), _sha256_bytes(b""), (), ()
        findings: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-index-") as directory:
            index_path = Path(directory) / "index"
            if seed_from_real_index:
                resolved_index = self._run(repo, ("rev-parse", "--git-path", "index"))
                if (
                    resolved_index.returncode != 0
                    or resolved_index.timed_out
                    or resolved_index.transport_error
                    or resolved_index.truncated
                ):
                    raise GitWriteError(
                        "GIT_VERIFIED_INDEX_UNAVAILABLE",
                        "real Git index path could not be resolved safely.",
                        status="blocked",
                    )
                raw_index_path = resolved_index.stdout.strip()
                if not raw_index_path or "\x00" in raw_index_path:
                    raise GitWriteError(
                        "GIT_VERIFIED_INDEX_UNAVAILABLE",
                        "real Git index path is invalid.",
                        status="blocked",
                    )
                source_index = Path(raw_index_path)
                if not source_index.is_absolute():
                    source_index = repo / source_index
                try:
                    if source_index.is_symlink() or not source_index.is_file():
                        raise OSError("index is not a regular file")
                    shutil.copyfile(source_index, index_path)
                except OSError:
                    raise GitWriteError(
                        "GIT_VERIFIED_INDEX_UNAVAILABLE",
                        "real Git index could not be copied into the private preflight index.",
                        status="blocked",
                    ) from None
            else:
                read_tree_argv = ("read-tree", "--empty") if head == _UNBORN_HEAD else ("read-tree", head)
                read_tree = self._run_with_index(repo, read_tree_argv, index_path)
                if read_tree.returncode != 0 or read_tree.timed_out or read_tree.transport_error or read_tree.truncated:
                    raise GitWriteError("GIT_VERIFIED_INDEX_UNAVAILABLE", "temporary Git index could not be initialized.", status="blocked")
            staged = self._run_with_index(repo, ("add", "--", *candidate_paths), index_path)
            if staged.returncode != 0 or staged.timed_out or staged.transport_error or staged.truncated:
                raise GitWriteError("GIT_VERIFIED_INDEX_UNAVAILABLE", "candidate paths could not be staged in the temporary index.", status="blocked")
            diff = self._run_with_index(
                repo,
                ("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--"),
                index_path,
            )
            names = self._run_with_index(
                repo,
                ("diff", "--cached", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--"),
                index_path,
            )
            for result in (diff, names):
                if result.returncode != 0 or result.timed_out or result.transport_error or result.truncated:
                    raise GitWriteError("GIT_VERIFIED_INDEX_UNAVAILABLE", "candidate Git evidence could not be read safely.", status="blocked")
            rendered_paths = tuple(sorted(_safe_rel_path(path) for path in names.stdout.split("\x00") if path))
            findings.update(self._secret_content_findings(repo, rendered_paths, index_path=index_path))
            diff_hash, index_hash = self._compact_index_hashes(diff.stdout, names.stdout)
            return (
                diff_hash,
                index_hash,
                rendered_paths,
                tuple(sorted(findings)),
            )

    def stage_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
    ) -> StagePreflight:
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        candidate_paths = tuple(sorted(set(snapshot.unstaged) | set(snapshot.untracked)))
        findings = set(snapshot.policy_findings)
        if not snapshot.head:
            findings.add("HEAD_UNAVAILABLE")
        if snapshot.staged:
            findings.add("REAL_INDEX_NOT_EMPTY")
        if not candidate_paths:
            findings.add("CHANGES_REQUIRED")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=candidate_paths,
            )
        )
        candidate_diff_hash = ""
        candidate_index_hash = ""
        candidate_leaf_paths: tuple[str, ...] = ()
        if not snapshot.staged and candidate_paths and snapshot.head:
            candidate_diff_hash, candidate_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=snapshot.head,
                candidate_paths=candidate_paths,
            )
            findings.update(candidate_findings)
            candidate_leaf_paths = rendered_paths
            if not self._scopes_match_leaves(candidate_paths, rendered_paths):
                findings.add("CANDIDATE_PATH_MISMATCH")
            if not rendered_paths:
                findings.add("CANDIDATE_DIFF_EMPTY")
        now = float(self._clock())
        preflight_id = f"git-stage-preflight:{secrets.token_urlsafe(16)}"
        preflight = StagePreflight(
            preflight_id=preflight_id,
            status="blocked" if findings else "ready",
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            task_id=task.task_id,
            operation="stage",
            snapshot=snapshot,
            candidate_paths=candidate_paths,
            candidate_leaf_paths=candidate_leaf_paths,
            candidate_staged_diff_hash=candidate_diff_hash,
            candidate_index_state_hash=candidate_index_hash,
            created_at=now,
            expires_at=now + self._approval_ttl_seconds,
            blocking_codes=tuple(sorted(findings)),
            audit_receipt_id=self._audit_id("stage", preflight_id, snapshot),
        )
        self._store_preflight(preflight)
        return preflight

    def stage_paths_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        paths: Iterable[str],
    ) -> StagePreflight:
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        candidate_paths = self._normalize_requested_stage_paths(paths)
        changed_paths = tuple(sorted(set(snapshot.unstaged) | set(snapshot.untracked)))
        findings = set(snapshot.policy_findings)
        if not snapshot.head:
            findings.add("HEAD_UNAVAILABLE")
        if not self._requested_paths_match_changes(candidate_paths, changed_paths):
            findings.add("CANDIDATE_PATH_NOT_CHANGED")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=candidate_paths,
            )
        )
        candidate_diff_hash = ""
        candidate_index_hash = ""
        candidate_leaf_paths: tuple[str, ...] = ()
        if snapshot.head and "CANDIDATE_PATH_NOT_CHANGED" not in findings:
            candidate_diff_hash, candidate_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=snapshot.head,
                candidate_paths=candidate_paths,
                seed_from_real_index=bool(snapshot.staged),
            )
            findings.update(candidate_findings)
            candidate_leaf_paths = rendered_paths
            selected_rendered_paths = tuple(
                leaf
                for leaf in rendered_paths
                if any(self._scopes_overlap(selected, leaf) for selected in candidate_paths)
            )
            if not self._scopes_match_leaves(candidate_paths, selected_rendered_paths):
                findings.add("CANDIDATE_PATH_MISMATCH")
            if not rendered_paths:
                findings.add("CANDIDATE_DIFF_EMPTY")
        now = float(self._clock())
        preflight_id = f"git-stage-paths-preflight:{secrets.token_urlsafe(16)}"
        preflight = StagePreflight(
            preflight_id=preflight_id,
            status="blocked" if findings else "ready",
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            task_id=task.task_id,
            operation="stage_paths",
            snapshot=snapshot,
            candidate_paths=candidate_paths,
            candidate_leaf_paths=candidate_leaf_paths,
            candidate_staged_diff_hash=candidate_diff_hash,
            candidate_index_state_hash=candidate_index_hash,
            created_at=now,
            expires_at=now + self._approval_ttl_seconds,
            blocking_codes=tuple(sorted(findings)),
            audit_receipt_id=self._audit_id("stage_paths", preflight_id, snapshot),
        )
        self._store_preflight(preflight)
        return preflight

    def stage_hunks_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        paths: Iterable[str],
        hunk_ids: Iterable[str],
    ) -> HunkStagePreflight:
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        requested_paths = self._normalize_requested_stage_paths(paths)
        selected_hunk_ids = self._normalize_hunk_ids(hunk_ids)
        findings = set(snapshot.policy_findings)
        if not snapshot.head or snapshot.head == _UNBORN_HEAD:
            findings.add("HEAD_UNAVAILABLE")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=requested_paths,
            )
        )

        diffs: dict[str, str] = {}
        available_hunks: tuple[GitHunk, ...] = ()
        if not findings:
            try:
                diffs, available_hunks = self._hunk_inventory(repo, requested_paths)
            except GitWriteError as exc:
                findings.add(exc.code)

        candidate_paths: tuple[str, ...] = ()
        candidate_patch_hash = ""
        candidate_diff_hash = ""
        candidate_index_hash = ""
        candidate_leaf_paths: tuple[str, ...] = ()
        ordered_selected_ids: tuple[str, ...] = ()
        if selected_hunk_ids and not findings:
            try:
                patch_text, ordered_selected_ids, candidate_paths = self._selected_hunk_patch(
                    diffs,
                    available_hunks,
                    selected_hunk_ids,
                )
                candidate_patch_hash = _sha256_text(patch_text)
                candidate_diff_hash, candidate_index_hash, rendered_paths, candidate_findings = self._candidate_hunk_index_evidence(
                    repo,
                    head=snapshot.head,
                    patch_text=patch_text,
                    candidate_paths=candidate_paths,
                    seed_from_real_index=bool(snapshot.staged),
                )
                findings.update(candidate_findings)
                candidate_leaf_paths = rendered_paths
                expected_leaf_paths = tuple(sorted(set(snapshot.staged) | set(candidate_paths)))
                if rendered_paths != expected_leaf_paths:
                    findings.add("CANDIDATE_PATH_MISMATCH")
                if not rendered_paths:
                    findings.add("CANDIDATE_DIFF_EMPTY")
            except GitWriteError as exc:
                findings.add(exc.code)

        now = float(self._clock())
        preflight_id = f"git-stage-hunks-preflight:{secrets.token_urlsafe(16)}"
        status = "blocked" if findings else ("selection_required" if not selected_hunk_ids else "ready")
        preflight = HunkStagePreflight(
            preflight_id=preflight_id,
            status=status,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            task_id=task.task_id,
            snapshot=snapshot,
            requested_paths=requested_paths,
            available_hunks=available_hunks,
            selected_hunk_ids=ordered_selected_ids if selected_hunk_ids else (),
            candidate_paths=candidate_paths,
            candidate_leaf_paths=candidate_leaf_paths,
            candidate_patch_hash=candidate_patch_hash,
            candidate_staged_diff_hash=candidate_diff_hash,
            candidate_index_state_hash=candidate_index_hash,
            created_at=now,
            expires_at=now + self._approval_ttl_seconds,
            blocking_codes=tuple(sorted(findings)),
            audit_receipt_id=self._audit_id("stage_hunks", preflight_id, snapshot, candidate_patch_hash),
        )
        self._store_preflight(preflight)
        return preflight

    def stage(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        expected_head: object,
        expected_candidate_staged_diff_hash: object,
        expected_candidate_index_state_hash: object,
    ) -> GitMutationReceipt:
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, StagePreflight) or preflight.operation != "stage":
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "stage preflight is unknown or expired.")
        if preflight.status != "ready" or preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            self._reject("GIT_STAGE_REJECTED", "stage preflight is not ready for this working tree.")
        head = _validate_hex(expected_head, name="head", length=40)
        diff_hash = _validate_hex(expected_candidate_staged_diff_hash, name="candidate_staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_candidate_index_state_hash, name="candidate_index_state_hash", length=64)
        if head != preflight.snapshot.head or diff_hash != preflight.candidate_staged_diff_hash or index_hash != preflight.candidate_index_state_hash:
            self._reject("GIT_STAGE_REJECTED", "stage target hash changed after preflight.", details={"reason": "STALE_GIT_STATE"})
        recovered = self._reconcile_executing_stage(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        if float(self._clock()) >= preflight.expires_at:
            self.invalidate_preflight(preflight_id)
            self._reject("GIT_STAGE_REJECTED", "stage preflight expired; run a fresh preflight.", details={"reason": "PREFLIGHT_EXPIRED"})
        task = task_resolver(preflight.task_id)
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        current_paths = tuple(sorted(set(current.unstaged) | set(current.untracked)))
        findings = set(current.policy_findings)
        if current.staged:
            findings.add("REAL_INDEX_NOT_EMPTY")
        if current.head != preflight.snapshot.head or current.branch != preflight.snapshot.branch or current.repository_id != preflight.snapshot.repository_id:
            findings.add("STALE_GIT_STATE")
        if current_paths != preflight.candidate_paths:
            findings.add("CANDIDATE_PATH_MISMATCH")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=current_paths,
            )
        )
        if not findings:
            current_diff_hash, current_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=current.head,
                candidate_paths=current_paths,
            )
            findings.update(candidate_findings)
            if rendered_paths != preflight.candidate_leaf_paths:
                findings.add("CANDIDATE_PATH_MISMATCH")
            if current_diff_hash != preflight.candidate_staged_diff_hash or current_index_hash != preflight.candidate_index_state_hash:
                findings.add("STALE_GIT_STATE")
        if findings:
            self._reject(
                "GIT_STAGE_REJECTED",
                "stage safety evidence is stale or incomplete.",
                details={"blocking_codes": sorted(findings), "reason": "STALE_GIT_STATE" if "STALE_GIT_STATE" in findings else "POLICY_BLOCKED"},
            )

        self._claim_preflight(
            preflight_id=preflight_id,
            operation="stage",
            workspace_id=workspace_id,
        )
        result = self._run(repo, ("add", "--", *preflight.candidate_paths))
        if result.timed_out or result.transport_error:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_OUTCOME_UNKNOWN",
                "staging outcome is unknown; inspect the real index before any retry.",
                status="outcome_unknown",
                details={"index_may_have_changed": True},
            )
        if result.returncode != 0 or result.truncated:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_FAILED",
                "staging failed; inspect the real index before any retry.",
                status="failed",
                details={"index_may_have_changed": True},
            )
        def _matches_preflight(snapshot: GitStateSnapshot) -> bool:
            return not (
                snapshot.head != preflight.snapshot.head
                or snapshot.branch != preflight.snapshot.branch
                or snapshot.staged != preflight.candidate_leaf_paths
                or snapshot.unstaged
                or snapshot.untracked
                or snapshot.staged_diff_hash != preflight.candidate_staged_diff_hash
                or snapshot.index_state_hash != preflight.candidate_index_state_hash
                or snapshot.policy_findings
            )

        staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if not _matches_preflight(staged_snapshot):
            staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if not _matches_preflight(staged_snapshot):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_MISMATCH",
                "real index does not exactly match the stage preflight.",
                status="blocked",
                details={"index_may_have_changed": True},
            )
        receipt = GitMutationReceipt(
            f"git-stage:{secrets.token_urlsafe(12)}",
            self._audit_id("stage", preflight_id, staged_snapshot),
            "stage",
            "succeeded",
            workspace_id,
            working_tree_id,
            task.task_id,
            preflight_id,
            staged_snapshot.branch,
            staged_snapshot.head,
            staged_snapshot.head,
            staged_snapshot.staged_diff_hash,
            staged_snapshot.index_state_hash,
            external_effect="local_git_index",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, "succeeded")
        return receipt

    def stage_paths(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        expected_head: object,
        expected_candidate_staged_diff_hash: object,
        expected_candidate_index_state_hash: object,
    ) -> GitMutationReceipt:
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, StagePreflight) or preflight.operation != "stage_paths":
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "stage-paths preflight is unknown or expired.")
        if preflight.status != "ready" or preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            self._reject("GIT_STAGE_PATHS_REJECTED", "stage-paths preflight is not ready for this working tree.")
        head = _validate_hex(expected_head, name="head", length=40)
        diff_hash = _validate_hex(expected_candidate_staged_diff_hash, name="candidate_staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_candidate_index_state_hash, name="candidate_index_state_hash", length=64)
        if head != preflight.snapshot.head or diff_hash != preflight.candidate_staged_diff_hash or index_hash != preflight.candidate_index_state_hash:
            self._reject(
                "GIT_STAGE_PATHS_REJECTED",
                "stage-paths target hash changed after preflight.",
                details={"reason": "STALE_GIT_STATE"},
            )
        recovered = self._reconcile_executing_stage(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        if float(self._clock()) >= preflight.expires_at:
            self.invalidate_preflight(preflight_id)
            self._reject(
                "GIT_STAGE_PATHS_REJECTED",
                "stage-paths preflight expired; run a fresh preflight.",
                details={"reason": "PREFLIGHT_EXPIRED"},
            )

        task = task_resolver(preflight.task_id)
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        current_changed_paths = tuple(sorted(set(current.unstaged) | set(current.untracked)))
        findings = set(current.policy_findings)
        if current.head != preflight.snapshot.head or current.branch != preflight.snapshot.branch or current.repository_id != preflight.snapshot.repository_id:
            findings.add("STALE_GIT_STATE")
        if (
            current.staged != preflight.snapshot.staged
            or current.staged_diff_hash != preflight.snapshot.staged_diff_hash
            or current.index_state_hash != preflight.snapshot.index_state_hash
        ):
            findings.add("STALE_GIT_STATE")
        if not self._requested_paths_match_changes(preflight.candidate_paths, current_changed_paths):
            findings.add("CANDIDATE_PATH_MISMATCH")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=preflight.candidate_paths,
            )
        )
        if not findings:
            current_diff_hash, current_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=current.head,
                candidate_paths=preflight.candidate_paths,
                seed_from_real_index=bool(current.staged),
            )
            findings.update(candidate_findings)
            if rendered_paths != preflight.candidate_leaf_paths:
                findings.add("CANDIDATE_PATH_MISMATCH")
            if current_diff_hash != preflight.candidate_staged_diff_hash or current_index_hash != preflight.candidate_index_state_hash:
                findings.add("STALE_GIT_STATE")
        if findings:
            self._reject(
                "GIT_STAGE_PATHS_REJECTED",
                "stage-paths safety evidence is stale or incomplete.",
                details={"blocking_codes": sorted(findings), "reason": "STALE_GIT_STATE" if "STALE_GIT_STATE" in findings else "POLICY_BLOCKED"},
            )

        self._claim_preflight(
            preflight_id=preflight_id,
            operation="stage_paths",
            workspace_id=workspace_id,
        )
        result = self._run(repo, ("add", "--", *preflight.candidate_paths))
        if result.timed_out or result.transport_error:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_PATHS_OUTCOME_UNKNOWN",
                "selective staging outcome is unknown; inspect the real index before any retry.",
                status="outcome_unknown",
                details={"index_may_have_changed": True},
            )
        if result.returncode != 0 or result.truncated:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_PATHS_FAILED",
                "selective staging failed; inspect the real index before any retry.",
                status="failed",
                details={"index_may_have_changed": True},
            )

        def _matches_preflight(snapshot: GitStateSnapshot) -> bool:
            remaining_paths = tuple(sorted(set(snapshot.unstaged) | set(snapshot.untracked)))
            selected_still_dirty = any(
                self._scopes_overlap(selected, remaining)
                for selected in preflight.candidate_paths
                for remaining in remaining_paths
            )
            return not (
                snapshot.head != preflight.snapshot.head
                or snapshot.branch != preflight.snapshot.branch
                or snapshot.staged != preflight.candidate_leaf_paths
                or selected_still_dirty
                or snapshot.staged_diff_hash != preflight.candidate_staged_diff_hash
                or snapshot.index_state_hash != preflight.candidate_index_state_hash
                or snapshot.policy_findings
            )

        staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if not _matches_preflight(staged_snapshot):
            staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if not _matches_preflight(staged_snapshot):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_PATHS_MISMATCH",
                "real index does not exactly match the selective-stage preflight.",
                status="blocked",
                details={"index_may_have_changed": True},
            )
        receipt = GitMutationReceipt(
            f"git-stage-paths:{secrets.token_urlsafe(12)}",
            self._audit_id("stage_paths", preflight_id, staged_snapshot),
            "stage_paths",
            "succeeded",
            workspace_id,
            working_tree_id,
            task.task_id,
            preflight_id,
            staged_snapshot.branch,
            staged_snapshot.head,
            staged_snapshot.head,
            staged_snapshot.staged_diff_hash,
            staged_snapshot.index_state_hash,
            external_effect="local_git_index",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, "succeeded")
        return receipt

    def stage_hunks(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        expected_head: object,
        expected_candidate_patch_hash: object,
        expected_candidate_staged_diff_hash: object,
        expected_candidate_index_state_hash: object,
    ) -> GitMutationReceipt:
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, HunkStagePreflight):
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "stage-hunks preflight is unknown or expired.")
        if preflight.status != "ready" or preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            self._reject("GIT_STAGE_HUNKS_REJECTED", "stage-hunks preflight is not ready for this working tree.")
        head = _validate_hex(expected_head, name="head", length=40)
        patch_hash = _validate_hex(expected_candidate_patch_hash, name="candidate_patch_hash", length=64)
        diff_hash = _validate_hex(expected_candidate_staged_diff_hash, name="candidate_staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_candidate_index_state_hash, name="candidate_index_state_hash", length=64)
        if (
            head != preflight.snapshot.head
            or patch_hash != preflight.candidate_patch_hash
            or diff_hash != preflight.candidate_staged_diff_hash
            or index_hash != preflight.candidate_index_state_hash
        ):
            self._reject(
                "GIT_STAGE_HUNKS_REJECTED",
                "stage-hunks target hash changed after preflight.",
                details={"reason": "STALE_GIT_STATE"},
            )
        recovered = self._reconcile_executing_stage(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        if float(self._clock()) >= preflight.expires_at:
            self.invalidate_preflight(preflight_id)
            self._reject(
                "GIT_STAGE_HUNKS_REJECTED",
                "stage-hunks preflight expired; run a fresh preflight.",
                details={"reason": "PREFLIGHT_EXPIRED"},
            )

        task = task_resolver(preflight.task_id)
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        findings = set(current.policy_findings)
        if (
            current.head != preflight.snapshot.head
            or current.branch != preflight.snapshot.branch
            or current.repository_id != preflight.snapshot.repository_id
        ):
            findings.add("STALE_GIT_STATE")
        if (
            current.staged != preflight.snapshot.staged
            or current.staged_diff_hash != preflight.snapshot.staged_diff_hash
            or current.index_state_hash != preflight.snapshot.index_state_hash
        ):
            findings.add("STALE_GIT_STATE")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=preflight.candidate_paths,
            )
        )

        patch_text = ""
        if not findings:
            try:
                diffs, available_hunks = self._hunk_inventory(repo, preflight.requested_paths)
                patch_text, ordered_ids, candidate_paths = self._selected_hunk_patch(
                    diffs,
                    available_hunks,
                    preflight.selected_hunk_ids,
                )
                if ordered_ids != preflight.selected_hunk_ids or candidate_paths != preflight.candidate_paths:
                    findings.add("STALE_GIT_STATE")
                if _sha256_text(patch_text) != preflight.candidate_patch_hash:
                    findings.add("STALE_GIT_STATE")
                if not findings:
                    current_diff_hash, current_index_hash, rendered_paths, candidate_findings = self._candidate_hunk_index_evidence(
                        repo,
                        head=current.head,
                        patch_text=patch_text,
                        candidate_paths=candidate_paths,
                        seed_from_real_index=bool(current.staged),
                    )
                    findings.update(candidate_findings)
                    if rendered_paths != preflight.candidate_leaf_paths:
                        findings.add("CANDIDATE_PATH_MISMATCH")
                    if current_diff_hash != preflight.candidate_staged_diff_hash or current_index_hash != preflight.candidate_index_state_hash:
                        findings.add("STALE_GIT_STATE")
            except GitWriteError as exc:
                findings.add(exc.code)
        if findings:
            self._reject(
                "GIT_STAGE_HUNKS_REJECTED",
                "stage-hunks safety evidence is stale or incomplete.",
                details={
                    "blocking_codes": sorted(findings),
                    "reason": "STALE_GIT_STATE" if "STALE_GIT_STATE" in findings else "POLICY_BLOCKED",
                },
            )

        self._claim_preflight(
            preflight_id=preflight_id,
            operation="stage_hunks",
            workspace_id=workspace_id,
        )
        result = self._run_with_input(
            repo,
            ("apply", "--cached", "--whitespace=nowarn", "-"),
            patch_text,
        )
        if result.timed_out or result.transport_error:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_HUNKS_OUTCOME_UNKNOWN",
                "hunk staging outcome is unknown; inspect the real index before any retry.",
                status="outcome_unknown",
                details={"index_may_have_changed": True},
            )
        if result.returncode != 0 or result.truncated:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_HUNKS_FAILED",
                "Git rejected hunk staging; inspect the real index before any retry.",
                status="failed",
                details={"index_may_have_changed": True},
            )

        staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if not (
            staged_snapshot.head == preflight.snapshot.head
            and staged_snapshot.branch == preflight.snapshot.branch
            and staged_snapshot.staged == preflight.candidate_leaf_paths
            and staged_snapshot.staged_diff_hash == preflight.candidate_staged_diff_hash
            and staged_snapshot.index_state_hash == preflight.candidate_index_state_hash
            and not staged_snapshot.policy_findings
        ):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_STAGE_HUNKS_MISMATCH",
                "real index does not exactly match the hunk-stage preflight.",
                status="blocked",
                details={"index_may_have_changed": True},
            )

        receipt = GitMutationReceipt(
            f"git-stage-hunks:{secrets.token_urlsafe(12)}",
            self._audit_id("stage_hunks", preflight_id, staged_snapshot, preflight.candidate_patch_hash),
            "stage_hunks",
            "succeeded",
            workspace_id,
            working_tree_id,
            task.task_id,
            preflight_id,
            staged_snapshot.branch,
            staged_snapshot.head,
            staged_snapshot.head,
            staged_snapshot.staged_diff_hash,
            staged_snapshot.index_state_hash,
            external_effect="local_git_index",
        )
        self._record_receipt(receipt)
        self._store.trust_partial_stage(
            (
                staged_snapshot.repository_id,
                workspace_id,
                working_tree_id,
                task.task_id,
                staged_snapshot.head,
                staged_snapshot.staged_diff_hash,
                staged_snapshot.index_state_hash,
            ),
            created_at=float(self._clock()),
        )
        self._finish_preflight(preflight_id, "succeeded")
        return receipt

    def verified_commit_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
    ) -> VerifiedCommitPreflight:
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        candidate_paths = tuple(sorted(set(snapshot.unstaged) | set(snapshot.untracked)))
        message = self.verified_commit_message(task)
        findings = set(snapshot.policy_findings)
        if not snapshot.head:
            findings.add("HEAD_UNAVAILABLE")
        if not snapshot.branch:
            findings.add("DETACHED_HEAD")
        if snapshot.staged:
            findings.add("REAL_INDEX_NOT_EMPTY")
        if not candidate_paths:
            findings.add("CHANGES_REQUIRED")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=candidate_paths,
            )
        )
        candidate_diff_hash = ""
        candidate_index_hash = ""
        candidate_leaf_paths: tuple[str, ...] = ()
        if not snapshot.staged and candidate_paths and snapshot.head:
            candidate_diff_hash, candidate_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=snapshot.head,
                candidate_paths=candidate_paths,
            )
            findings.update(candidate_findings)
            candidate_leaf_paths = rendered_paths
            if not self._scopes_match_leaves(candidate_paths, rendered_paths):
                findings.add("CANDIDATE_PATH_MISMATCH")
            if not rendered_paths:
                findings.add("CANDIDATE_DIFF_EMPTY")
        now = float(self._clock())
        preflight_id = f"git-verified-commit-preflight:{secrets.token_urlsafe(16)}"
        preflight = VerifiedCommitPreflight(
            preflight_id=preflight_id,
            status="blocked" if findings else "ready",
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            task_id=task.task_id,
            commit_message=message,
            commit_message_hash=_sha256_text(message),
            snapshot=snapshot,
            candidate_paths=candidate_paths,
            candidate_leaf_paths=candidate_leaf_paths,
            candidate_staged_diff_hash=candidate_diff_hash,
            candidate_index_state_hash=candidate_index_hash,
            created_at=now,
            expires_at=now + self._approval_ttl_seconds,
            blocking_codes=tuple(sorted(findings)),
            audit_receipt_id=self._audit_id("verified_commit", preflight_id, snapshot, message),
        )
        self._store_preflight(preflight)
        return preflight

    def verified_commit(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        expected_head: object,
        expected_candidate_staged_diff_hash: object,
        expected_candidate_index_state_hash: object,
    ) -> GitMutationReceipt:
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, VerifiedCommitPreflight):
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "verified commit preflight is unknown or expired.")
        if preflight.status != "ready" or preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id:
            self._reject("GIT_VERIFIED_COMMIT_REJECTED", "verified commit preflight is not ready for this working tree.")
        head = _validate_hex(expected_head, name="head", length=40)
        diff_hash = _validate_hex(expected_candidate_staged_diff_hash, name="candidate_staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_candidate_index_state_hash, name="candidate_index_state_hash", length=64)
        if head != preflight.snapshot.head or diff_hash != preflight.candidate_staged_diff_hash or index_hash != preflight.candidate_index_state_hash:
            self._reject("GIT_VERIFIED_COMMIT_REJECTED", "verified commit target hash changed after preflight.", details={"reason": "STALE_GIT_STATE"})
        recovered = self._reconcile_executing_commit(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        if float(self._clock()) >= preflight.expires_at:
            self.invalidate_preflight(preflight_id)
            self._reject("GIT_VERIFIED_COMMIT_REJECTED", "verified commit preflight expired; run a fresh preflight.", details={"reason": "PREFLIGHT_EXPIRED"})
        task = task_resolver(preflight.task_id)
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        current_paths = tuple(sorted(set(current.unstaged) | set(current.untracked)))
        findings = set(current.policy_findings)
        if current.staged:
            findings.add("REAL_INDEX_NOT_EMPTY")
        if current.head != preflight.snapshot.head or current.branch != preflight.snapshot.branch or current.repository_id != preflight.snapshot.repository_id:
            findings.add("STALE_GIT_STATE")
        if current_paths != preflight.candidate_paths:
            findings.add("CANDIDATE_PATH_MISMATCH")
        findings.update(
            self._verified_task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                candidate_paths=current_paths,
            )
        )
        if not findings:
            current_diff_hash, current_index_hash, rendered_paths, candidate_findings = self._candidate_index_evidence(
                repo,
                head=current.head,
                candidate_paths=current_paths,
            )
            findings.update(candidate_findings)
            if rendered_paths != preflight.candidate_leaf_paths:
                findings.add("CANDIDATE_PATH_MISMATCH")
            if current_diff_hash != preflight.candidate_staged_diff_hash or current_index_hash != preflight.candidate_index_state_hash:
                findings.add("STALE_GIT_STATE")
        if findings:
            self._reject(
                "GIT_VERIFIED_COMMIT_REJECTED",
                "verified commit safety evidence is stale or incomplete.",
                details={"blocking_codes": sorted(findings), "reason": "STALE_GIT_STATE" if "STALE_GIT_STATE" in findings else "POLICY_BLOCKED"},
            )

        self._claim_preflight(
            preflight_id=preflight_id,
            operation="verified_commit",
            workspace_id=workspace_id,
        )
        stage = self._run(repo, ("add", "--", *preflight.candidate_paths))
        if stage.timed_out or stage.transport_error:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_VERIFIED_STAGE_OUTCOME_UNKNOWN",
                "candidate staging outcome is unknown; inspect the real index before any retry.",
                status="outcome_unknown",
                details={"index_may_have_changed": True},
            )
        if stage.returncode != 0 or stage.truncated:
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_VERIFIED_STAGE_FAILED",
                "candidate staging failed; inspect the real index before any retry.",
                status="failed",
                details={"index_may_have_changed": True},
            )
        staged_snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if (
            staged_snapshot.head != preflight.snapshot.head
            or staged_snapshot.branch != preflight.snapshot.branch
            or staged_snapshot.staged != preflight.candidate_leaf_paths
            or staged_snapshot.unstaged
            or staged_snapshot.untracked
            or staged_snapshot.staged_diff_hash != preflight.candidate_staged_diff_hash
            or staged_snapshot.index_state_hash != preflight.candidate_index_state_hash
            or staged_snapshot.policy_findings
        ):
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_VERIFIED_STAGE_MISMATCH",
                "real index does not exactly match the verified preflight; no commit was attempted.",
                status="blocked",
                details={"index_may_have_changed": True},
            )

        result = self._run(repo, ("commit", "--message", preflight.commit_message))
        if result.timed_out or result.transport_error:
            receipt = GitMutationReceipt(
                f"git-verified-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("verified_commit", preflight_id, staged_snapshot),
                "verified_commit",
                "outcome_unknown",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight_id,
                staged_snapshot.branch,
                staged_snapshot.head,
                "",
                staged_snapshot.staged_diff_hash,
                staged_snapshot.index_state_hash,
                error_code="GIT_VERIFIED_COMMIT_OUTCOME_UNKNOWN",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_VERIFIED_COMMIT_OUTCOME_UNKNOWN",
                "verified commit result is unknown; inspect Git state before any retry.",
                status="outcome_unknown",
                details={"receipt": receipt.as_dict()},
            )
        if result.returncode != 0:
            receipt = GitMutationReceipt(
                f"git-verified-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("verified_commit", preflight_id, staged_snapshot),
                "verified_commit",
                "failed",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight_id,
                staged_snapshot.branch,
                staged_snapshot.head,
                staged_snapshot.head,
                staged_snapshot.staged_diff_hash,
                staged_snapshot.index_state_hash,
                error_code="GIT_VERIFIED_COMMIT_FAILED",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "failed")
            raise GitWriteError(
                "GIT_VERIFIED_COMMIT_FAILED",
                "Git rejected the verified local commit; no push was attempted.",
                status="failed",
                details={"receipt": receipt.as_dict()},
            )

        after: GitStateSnapshot | None = None
        try:
            after = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
            if not after.head or after.head == staged_snapshot.head or after.dirty:
                raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit read-back is inconclusive.", status="outcome_unknown")
            parent = self._run(repo, ("show", "-s", "--format=%P", after.head))
            subject = self._run(repo, ("show", "-s", "--format=%s", after.head))
            tree = self._run(repo, ("show", "-s", "--format=%T", after.head))
            if staged_snapshot.head == _UNBORN_HEAD:
                diff = self._run(
                    repo,
                    ("diff-tree", "--root", "--no-commit-id", "--raw", "-z", "--no-abbrev", "--no-renames", "-r", after.head, "--"),
                )
                names = self._run(repo, ("diff-tree", "--root", "--no-commit-id", "--name-only", "-z", "-r", after.head, "--"))
            else:
                diff = self._run(
                    repo,
                    ("diff", "--raw", "-z", "--no-abbrev", "--no-renames", staged_snapshot.head, after.head, "--"),
                )
                names = self._run(repo, ("diff", "--name-only", "-z", staged_snapshot.head, after.head, "--"))
            for readback in (parent, subject, tree, diff, names):
                if readback.timed_out or readback.transport_error or readback.truncated or readback.returncode != 0:
                    raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit evidence could not be read back.", status="outcome_unknown")
            expected_parent = "" if staged_snapshot.head == _UNBORN_HEAD else staged_snapshot.head
            if parent.stdout.strip() != expected_parent:
                raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit parent does not match the pinned HEAD.", status="outcome_unknown")
            if subject.stdout.strip() != preflight.commit_message:
                raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit subject does not match the deterministic message.", status="outcome_unknown")
            if not _HEX40.fullmatch(tree.stdout.strip()):
                raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit tree is malformed.", status="outcome_unknown")
            committed_paths = tuple(sorted(_safe_rel_path(line) for line in names.stdout.split("\x00") if line))
            if committed_paths != preflight.candidate_leaf_paths:
                raise GitWriteError("GIT_VERIFIED_COMMIT_READBACK_UNKNOWN", "verified commit paths differ from the preflight candidate.", status="outcome_unknown")
            commit_tree_hash = tree.stdout.strip()
            commit_diff_hash = _sha256_bytes(b"DIFF\0" + diff.stdout.encode("utf-8"))
        except (GitWriteError, OSError, ValueError) as exc:
            head_after = after.head if after is not None else ""
            receipt = GitMutationReceipt(
                f"git-verified-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("verified_commit", preflight_id, staged_snapshot, head_after),
                "verified_commit",
                "outcome_unknown",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight_id,
                after.branch if after is not None else staged_snapshot.branch,
                staged_snapshot.head,
                head_after,
                staged_snapshot.staged_diff_hash,
                staged_snapshot.index_state_hash,
                error_code="GIT_VERIFIED_COMMIT_READBACK_UNKNOWN",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_VERIFIED_COMMIT_OUTCOME_UNKNOWN",
                "verified commit executed but read-back is inconclusive; do not retry automatically.",
                status="outcome_unknown",
                details={"receipt": receipt.as_dict()},
            ) from exc
        receipt = GitMutationReceipt(
            f"git-verified-commit:{secrets.token_urlsafe(12)}",
            self._audit_id("verified_commit", preflight_id, staged_snapshot, after.head),
            "verified_commit",
            "succeeded",
            workspace_id,
            working_tree_id,
            task.task_id,
            preflight_id,
            after.branch,
            staged_snapshot.head,
            after.head,
            staged_snapshot.staged_diff_hash,
            staged_snapshot.index_state_hash,
            commit_tree_hash,
            commit_diff_hash,
            external_effect="local_git_commit",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight_id, "succeeded")
        return receipt

    def commit_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        commit_message: object,
    ) -> CommitPreflight:
        message = validate_commit_message(commit_message)
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        candidate_paths, preserved_staged_paths = self._commit_scoped_staged_paths(task, snapshot)
        partial_stage_paths = tuple(sorted(set(candidate_paths) & set(snapshot.unstaged)))
        trusted_partial_stage = self._store.has_trusted_partial_stage((
            snapshot.repository_id,
            snapshot.workspace_id,
            snapshot.working_tree_id,
            task.task_id,
            snapshot.head,
            snapshot.staged_diff_hash,
            snapshot.index_state_hash,
        ))
        partial_stage_adoption = bool(
            partial_stage_paths
            and task.allow_partial_stage_adoption
            and not trusted_partial_stage
        )
        findings = self._commit_findings(
            self._task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                snapshot=snapshot,
                allow_unrelated_staged=True,
            ),
            snapshot,
            task_id=task.task_id,
            commit_paths=candidate_paths,
            allow_partial_stage_adoption=partial_stage_adoption,
        )
        if not candidate_paths:
            findings.add("STAGED_CHANGES_REQUIRED")
        candidate_leaf_paths = candidate_paths
        candidate_staged_diff_hash = snapshot.staged_diff_hash
        candidate_index_state_hash = snapshot.index_state_hash
        preserved_staged_scope_hash = ""
        if preserved_staged_paths:
            if not snapshot.head or snapshot.head == _UNBORN_HEAD:
                findings.add("HEAD_UNAVAILABLE")
            elif candidate_paths:
                try:
                    (
                        candidate_staged_diff_hash,
                        candidate_index_state_hash,
                        candidate_leaf_paths,
                        candidate_findings,
                    ) = self._candidate_staged_subset_index_evidence(
                        repo,
                        head=snapshot.head,
                        candidate_paths=candidate_paths,
                    )
                    findings.update(candidate_findings)
                    if candidate_leaf_paths != candidate_paths:
                        findings.add("CANDIDATE_PATH_MISMATCH")
                    preserved_staged_scope_hash = self._staged_scope_hash(repo, preserved_staged_paths)
                except GitWriteError as exc:
                    findings.add(exc.code)
        if candidate_paths and candidate_staged_diff_hash == _sha256_bytes(b""):
            findings.add("STAGED_DIFF_EMPTY")
        preflight_id = f"git-commit-preflight:{secrets.token_urlsafe(16)}"
        if findings:
            preflight = CommitPreflight(
                preflight_id=preflight_id,
                status="blocked",
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                task_id=task.task_id,
                commit_message=message,
                commit_message_hash=_sha256_text(message),
                snapshot=snapshot,
                candidate_paths=candidate_paths,
                candidate_leaf_paths=candidate_leaf_paths,
                candidate_staged_diff_hash=candidate_staged_diff_hash,
                candidate_index_state_hash=candidate_index_state_hash,
                preserved_staged_paths=preserved_staged_paths,
                preserved_staged_scope_hash=preserved_staged_scope_hash,
                partial_stage_adoption=partial_stage_adoption,
                partial_stage_paths=partial_stage_paths,
                blocking_codes=tuple(sorted(findings)),
                approval=None,
                audit_receipt_id=self._audit_id("commit", preflight_id, snapshot, message),
            )
        else:
            token, confirmation, expires_at = self.issue_approval(
                "commit",
                preflight_id,
                workspace_id,
                confirmation_action=(
                    "Git commit with partial-stage adoption"
                    if partial_stage_adoption
                    else None
                ),
            )
            approval = GitApproval(token, confirmation, "commit", preflight_id, workspace_id, expires_at)
            preflight = CommitPreflight(
                preflight_id=preflight_id,
                status="ready",
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                task_id=task.task_id,
                commit_message=message,
                commit_message_hash=_sha256_text(message),
                snapshot=snapshot,
                candidate_paths=candidate_paths,
                candidate_leaf_paths=candidate_leaf_paths,
                candidate_staged_diff_hash=candidate_staged_diff_hash,
                candidate_index_state_hash=candidate_index_state_hash,
                preserved_staged_paths=preserved_staged_paths,
                preserved_staged_scope_hash=preserved_staged_scope_hash,
                partial_stage_adoption=partial_stage_adoption,
                partial_stage_paths=partial_stage_paths,
                blocking_codes=(),
                approval=approval,
                audit_receipt_id=self._audit_id("commit", preflight_id, snapshot, message),
            )
        self._store_preflight(preflight)
        return preflight

    def _reject(self, code: str, message: str, *, details: Mapping[str, object] | None = None) -> None:
        raise GitWriteError(code, message, status="rejected", details=details)

    def _verify_commit_target(
        self,
        repo: Path,
        preflight: CommitPreflight,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        commit_message: object,
        expected_head: object,
        expected_staged_diff_hash: object,
        expected_index_state_hash: object,
    ) -> GitStateSnapshot:
        message = validate_commit_message(commit_message)
        head = _validate_hex(expected_head, name="head", length=40)
        staged_hash = _validate_hex(expected_staged_diff_hash, name="staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_index_state_hash, name="index_state_hash", length=64)
        if preflight.status != "ready" or preflight.workspace_id != workspace_id or preflight.working_tree_id != working_tree_id or preflight.task_id != task.task_id:
            self._reject("GIT_COMMIT_REJECTED", "commit preflight is not ready for this task.", details={"status": "rejected"})
        if message != preflight.commit_message or _sha256_text(message) != preflight.commit_message_hash:
            self._reject("GIT_COMMIT_REJECTED", "commit message changed after preflight.", details={"status": "rejected"})
        if head != preflight.snapshot.head or staged_hash != preflight.snapshot.staged_diff_hash or index_hash != preflight.snapshot.index_state_hash:
            self._reject("GIT_COMMIT_REJECTED", "commit target hash changed after preflight.", details={"status": "rejected", "reason": "STALE_GIT_STATE"})
        current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        if current != preflight.snapshot:
            self._reject("GIT_COMMIT_REJECTED", "commit target is stale; run preflight again.", details={"status": "rejected", "reason": "STALE_GIT_STATE"})
        candidate_paths, preserved_staged_paths = self._commit_scoped_staged_paths(task, current)
        if candidate_paths != preflight.candidate_paths or preserved_staged_paths != preflight.preserved_staged_paths:
            self._reject(
                "GIT_COMMIT_REJECTED",
                "commit path scope changed after preflight.",
                details={"status": "rejected", "reason": "STALE_GIT_STATE"},
            )
        current_partial_stage_paths = tuple(sorted(set(candidate_paths) & set(current.unstaged)))
        if current_partial_stage_paths != preflight.partial_stage_paths:
            self._reject(
                "GIT_COMMIT_REJECTED",
                "partial-stage scope changed after preflight.",
                details={"status": "rejected", "reason": "STALE_GIT_STATE"},
            )
        if preflight.partial_stage_adoption and not task.allow_partial_stage_adoption:
            self._reject(
                "GIT_COMMIT_REJECTED",
                "partial-stage adoption is no longer authorized for this task.",
                details={"status": "rejected", "reason": "STALE_GIT_STATE"},
            )
        findings = self._commit_findings(
            self._task_findings(
                task,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                snapshot=current,
                allow_unrelated_staged=True,
            ),
            current,
            task_id=task.task_id,
            commit_paths=candidate_paths,
            allow_partial_stage_adoption=preflight.partial_stage_adoption,
        )
        if not candidate_paths:
            findings.add("STAGED_CHANGES_REQUIRED")
        if preserved_staged_paths and not findings:
            try:
                candidate_diff_hash, candidate_index_hash, candidate_leaf_paths, candidate_findings = (
                    self._candidate_staged_subset_index_evidence(
                        repo,
                        head=current.head,
                        candidate_paths=candidate_paths,
                    )
                )
                findings.update(candidate_findings)
                if (
                    candidate_leaf_paths != preflight.candidate_leaf_paths
                    or candidate_diff_hash != preflight.candidate_staged_diff_hash
                    or candidate_index_hash != preflight.candidate_index_state_hash
                    or self._staged_scope_hash(repo, preserved_staged_paths) != preflight.preserved_staged_scope_hash
                ):
                    findings.add("STALE_GIT_STATE")
            except GitWriteError as exc:
                findings.add(exc.code)
        if findings:
            self._reject("GIT_COMMIT_REJECTED", "commit safety evidence is no longer valid.", details={"status": "rejected", "blocking_codes": sorted(findings)})
        return current

    def _commit_preserving_unrelated_staged(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        preflight: CommitPreflight,
        current: GitStateSnapshot,
    ) -> GitMutationReceipt:
        patch_text = self._staged_patch_for_paths(repo, preflight.candidate_paths)
        with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-commit-index-") as directory:
            index_path = Path(directory) / "index"
            initialized = self._run_with_index(repo, ("read-tree", current.head), index_path)
            if initialized.returncode != 0 or initialized.timed_out or initialized.transport_error or initialized.truncated:
                self._finish_preflight(preflight.preflight_id, "failed")
                raise GitWriteError(
                    "GIT_COMMIT_INDEX_UNAVAILABLE",
                    "temporary commit index could not be initialized.",
                    status="blocked",
                )
            applied = self._run_with_input(
                repo,
                ("apply", "--cached", "--whitespace=nowarn", "-"),
                patch_text,
                index_path=index_path,
            )
            if applied.returncode != 0 or applied.timed_out or applied.transport_error or applied.truncated:
                self._finish_preflight(preflight.preflight_id, "failed")
                raise GitWriteError(
                    "GIT_COMMIT_INDEX_UNAVAILABLE",
                    "task-owned staged patch could not be reproduced in the temporary commit index.",
                    status="blocked",
                )
            result = self._run_with_index(
                repo,
                ("commit", "--message", preflight.commit_message),
                index_path,
            )

        receipt_diff_hash = preflight.candidate_staged_diff_hash
        receipt_index_hash = preflight.candidate_index_state_hash
        if result.timed_out or result.transport_error:
            receipt = GitMutationReceipt(
                f"git-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("commit", preflight.preflight_id, current, receipt_diff_hash),
                "commit",
                "outcome_unknown",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight.preflight_id,
                current.branch,
                current.head,
                "",
                receipt_diff_hash,
                receipt_index_hash,
                error_code="GIT_COMMIT_OUTCOME_UNKNOWN",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight.preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_COMMIT_OUTCOME_UNKNOWN",
                "commit result is unknown; perform read-only Git status before any retry.",
                status="outcome_unknown",
                details={"receipt": receipt.as_dict()},
            )
        if result.returncode != 0:
            receipt = GitMutationReceipt(
                f"git-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("commit", preflight.preflight_id, current, receipt_diff_hash),
                "commit",
                "failed",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight.preflight_id,
                current.branch,
                current.head,
                current.head,
                receipt_diff_hash,
                receipt_index_hash,
                error_code="GIT_COMMIT_FAILED",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight.preflight_id, "failed")
            raise GitWriteError(
                "GIT_COMMIT_FAILED",
                "Git rejected the task-scoped commit; no push was attempted.",
                status="failed",
                details={"stderr": result.stderr[:1000], "receipt": receipt.as_dict()},
            )

        after: GitStateSnapshot | None = None
        head_after = ""
        try:
            head_result = self._run(repo, ("rev-parse", "HEAD"))
            if (
                head_result.returncode != 0
                or head_result.timed_out
                or head_result.transport_error
                or head_result.truncated
                or not _HEX40.fullmatch(head_result.stdout.strip())
            ):
                raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "new commit HEAD could not be read safely.", status="outcome_unknown")
            head_after = head_result.stdout.strip()
            if head_after == current.head:
                raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit did not advance HEAD.", status="outcome_unknown")

            synced = self._run(
                repo,
                ("restore", "--staged", "--source", head_after, "--", *preflight.candidate_paths),
            )
            if synced.returncode != 0 or synced.timed_out or synced.transport_error or synced.truncated:
                raise GitWriteError(
                    "GIT_COMMIT_READBACK_UNKNOWN",
                    "commit succeeded but the real index could not be synchronized to the new HEAD.",
                    status="outcome_unknown",
                )

            after = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
            if after.head != head_after or after.branch != current.branch:
                raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit HEAD/branch read-back is inconsistent.", status="outcome_unknown")
            if after.staged != preflight.preserved_staged_paths:
                raise GitWriteError(
                    "GIT_COMMIT_READBACK_UNKNOWN",
                    "unrelated staged paths changed during task-scoped commit.",
                    status="outcome_unknown",
                )
            if self._staged_scope_hash(repo, preflight.preserved_staged_paths) != preflight.preserved_staged_scope_hash:
                raise GitWriteError(
                    "GIT_COMMIT_READBACK_UNKNOWN",
                    "unrelated staged index content changed during task-scoped commit.",
                    status="outcome_unknown",
                )
            if after.unstaged != current.unstaged or after.untracked != current.untracked or after.policy_findings:
                raise GitWriteError(
                    "GIT_COMMIT_READBACK_UNKNOWN",
                    "unrelated worktree state changed during task-scoped commit.",
                    status="outcome_unknown",
                )

            tree = self._run(repo, ("show", "-s", "--format=%T", head_after))
            diff = self._run(repo, ("diff", "--binary", "--no-ext-diff", current.head, head_after, "--"))
            names = self._run(repo, ("diff", "--name-only", current.head, head_after, "--"))
            if tree.timed_out or diff.timed_out or names.timed_out or tree.transport_error or diff.transport_error or names.transport_error:
                raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit tree/diff read-back timed out.", status="outcome_unknown")
            if (
                tree.truncated
                or diff.truncated
                or names.truncated
                or tree.returncode != 0
                or diff.returncode != 0
                or names.returncode != 0
                or not _HEX40.fullmatch(tree.stdout.strip())
            ):
                raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit tree/diff read-back was unavailable or malformed.", status="outcome_unknown")
            committed_paths = tuple(sorted(_safe_rel_path(line) for line in names.stdout.splitlines() if line.strip()))
            if committed_paths != preflight.candidate_leaf_paths:
                raise GitWriteError(
                    "GIT_COMMIT_READBACK_UNKNOWN",
                    "commit tree changed paths do not match the task-owned preflight paths.",
                    status="outcome_unknown",
                )
            commit_tree_hash = tree.stdout.strip()
            commit_diff_hash = _sha256_bytes(diff.stdout.encode("utf-8"))
        except (GitWriteError, OSError, ValueError) as exc:
            receipt = GitMutationReceipt(
                f"git-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("commit", preflight.preflight_id, current, head_after),
                "commit",
                "outcome_unknown",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight.preflight_id,
                after.branch if after is not None else current.branch,
                current.head,
                head_after,
                receipt_diff_hash,
                receipt_index_hash,
                error_code="GIT_COMMIT_READBACK_UNKNOWN",
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight.preflight_id, "outcome_unknown")
            raise GitWriteError(
                "GIT_COMMIT_OUTCOME_UNKNOWN",
                "commit was executed but task-scoped read-back is inconclusive; inspect Git status before any retry.",
                status="outcome_unknown",
                details={"receipt": receipt.as_dict()},
            ) from exc

        receipt = GitMutationReceipt(
            f"git-commit:{secrets.token_urlsafe(12)}",
            self._audit_id("commit", preflight.preflight_id, current, head_after),
            "commit",
            "succeeded",
            workspace_id,
            working_tree_id,
            task.task_id,
            preflight.preflight_id,
            after.branch,
            current.head,
            head_after,
            receipt_diff_hash,
            receipt_index_hash,
            commit_tree_hash,
            commit_diff_hash,
            external_effect="local_git_commit",
        )
        self._record_receipt(receipt)
        self._finish_preflight(preflight.preflight_id, "succeeded")
        return receipt

    def commit(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        approval_token: object,
        confirmation: object,
        commit_message: object,
        expected_head: object,
        expected_staged_diff_hash: object,
        expected_index_state_hash: object,
    ) -> GitMutationReceipt:
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, CommitPreflight):
            raise GitWriteError("GIT_PREFLIGHT_NOT_FOUND", "commit preflight is unknown or expired.")
        message = validate_commit_message(commit_message)
        head = _validate_hex(expected_head, name="head", length=40)
        staged_hash = _validate_hex(expected_staged_diff_hash, name="staged_diff_hash", length=64)
        index_hash = _validate_hex(expected_index_state_hash, name="index_state_hash", length=64)
        if (
            preflight.workspace_id != workspace_id
            or preflight.working_tree_id != working_tree_id
            or message != preflight.commit_message
            or _sha256_text(message) != preflight.commit_message_hash
            or head != preflight.snapshot.head
            or staged_hash != preflight.snapshot.staged_diff_hash
            or index_hash != preflight.snapshot.index_state_hash
        ):
            self._reject(
                "GIT_COMMIT_REJECTED",
                "commit retry does not match the durable preflight binding.",
                details={"status": "rejected", "reason": "STALE_GIT_STATE"},
            )
        recovered = self._reconcile_executing_commit(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        task = task_resolver(preflight.task_id)
        with self._lock:
            current = self._verify_commit_target(
                repo,
                preflight,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                task=task,
                commit_message=commit_message,
                expected_head=expected_head,
                expected_staged_diff_hash=expected_staged_diff_hash,
                expected_index_state_hash=expected_index_state_hash,
            )
            self._claim_preflight(
                preflight_id=preflight_id,
                operation="commit",
                workspace_id=workspace_id,
                approval_token=approval_token,
                confirmation=confirmation,
            )
            if preflight.preserved_staged_paths:
                return self._commit_preserving_unrelated_staged(
                    repo,
                    workspace_id=workspace_id,
                    working_tree_id=working_tree_id,
                    task=task,
                    preflight=preflight,
                    current=current,
                )
            result = self._run(repo, ("commit", "--message", preflight.commit_message))
            if result.timed_out or result.transport_error:
                receipt = GitMutationReceipt(
                    f"git-commit:{secrets.token_urlsafe(12)}",
                    self._audit_id("commit", preflight_id, current),
                    "commit",
                    "outcome_unknown",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    current.branch,
                    current.head,
                    "",
                    current.staged_diff_hash,
                    current.index_state_hash,
                    error_code="GIT_COMMIT_OUTCOME_UNKNOWN",
                    external_effect="local_git_commit",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "outcome_unknown")
                raise GitWriteError("GIT_COMMIT_OUTCOME_UNKNOWN", "commit result is unknown; perform read-only Git status before any retry.", status="outcome_unknown", details={"receipt": receipt.as_dict()})
            if result.returncode != 0:
                receipt = GitMutationReceipt(
                    f"git-commit:{secrets.token_urlsafe(12)}",
                    self._audit_id("commit", preflight_id, current),
                    "commit",
                    "failed",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    current.branch,
                    current.head,
                    current.head,
                    current.staged_diff_hash,
                    current.index_state_hash,
                    error_code="GIT_COMMIT_FAILED",
                    external_effect="local_git_commit",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "failed")
                raise GitWriteError("GIT_COMMIT_FAILED", "Git rejected the commit; no push was attempted.", status="failed", details={"stderr": result.stderr[:1000], "receipt": receipt.as_dict()})

            after: GitStateSnapshot | None = None
            try:
                after = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
                if not after.head or after.head == current.head or after.staged:
                    raise GitWriteError(
                        "GIT_COMMIT_READBACK_UNKNOWN",
                        "commit read-back did not produce the expected new HEAD with an empty index.",
                        status="outcome_unknown",
                    )
                if after.unstaged != current.unstaged or after.untracked != current.untracked or after.policy_findings:
                    raise GitWriteError(
                        "GIT_COMMIT_READBACK_UNKNOWN",
                        "unrelated dirty state changed during commit read-back.",
                        status="outcome_unknown",
                    )
                tree = self._run(repo, ("show", "-s", "--format=%T", after.head))
                if current.head == _UNBORN_HEAD:
                    diff = self._run(repo, ("show", "--format=", "--binary", "--no-ext-diff", after.head, "--"))
                    names = self._run(repo, ("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", after.head, "--"))
                else:
                    diff = self._run(repo, ("diff", "--binary", "--no-ext-diff", current.head, after.head, "--"))
                    names = self._run(repo, ("diff", "--name-only", current.head, after.head, "--"))
                if tree.timed_out or diff.timed_out or names.timed_out or tree.transport_error or diff.transport_error or names.transport_error:
                    raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit tree/diff read-back timed out.", status="outcome_unknown")
                if tree.truncated or diff.truncated or names.truncated or tree.returncode != 0 or diff.returncode != 0 or names.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", tree.stdout.strip()):
                    raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit tree/diff read-back was unavailable or malformed.", status="outcome_unknown")
                committed_paths = tuple(sorted(_safe_rel_path(line) for line in names.stdout.splitlines() if line.strip()))
                if committed_paths != current.staged:
                    raise GitWriteError("GIT_COMMIT_READBACK_UNKNOWN", "commit tree changed paths do not match the preflight staged paths.", status="outcome_unknown")
                commit_tree_hash = tree.stdout.strip()
                commit_diff_hash = _sha256_bytes(diff.stdout.encode("utf-8"))
            except (GitWriteError, OSError, ValueError) as exc:
                head_after = after.head if after is not None else ""
                receipt = GitMutationReceipt(
                    f"git-commit:{secrets.token_urlsafe(12)}",
                    self._audit_id("commit", preflight_id, current, head_after),
                    "commit",
                    "outcome_unknown",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    after.branch if after is not None else current.branch,
                    current.head,
                    head_after,
                    current.staged_diff_hash,
                    current.index_state_hash,
                    error_code="GIT_COMMIT_READBACK_UNKNOWN",
                    external_effect="local_git_commit",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "outcome_unknown")
                raise GitWriteError("GIT_COMMIT_OUTCOME_UNKNOWN", "commit was executed but read-back is inconclusive; inspect Git status before any retry.", status="outcome_unknown", details={"receipt": receipt.as_dict()}) from exc
            receipt = GitMutationReceipt(
                f"git-commit:{secrets.token_urlsafe(12)}",
                self._audit_id("commit", preflight_id, current, after.head),
                "commit",
                "succeeded",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight_id,
                after.branch,
                current.head,
                after.head,
                current.staged_diff_hash,
                current.index_state_hash,
                commit_tree_hash,
                commit_diff_hash,
                external_effect="local_git_commit",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "succeeded")
            return receipt

    def _remote_url(self, repo: Path, remote: str) -> tuple[str, str] | None:
        # Pin the URL Git will actually use for push.  Fetch URL and push URL
        # may differ; a fetch-only read would leave a pushurl TOCTOU gap.
        result = self._run(repo, ("remote", "get-url", "--push", "--all", "--", remote), network=False)
        if result.returncode != 0:
            return None
        if result.truncated:
            raise GitWriteError("GIT_REMOTE_URL_TRUNCATED", "remote push URL output exceeded the safety bound.", status="blocked")
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(urls) != 1:
            raise GitWriteError("GIT_REMOTE_MULTIPLE_PUSH_URLS", "remote must have exactly one configured push URL.", status="blocked")
        raw = urls[0]
        if not self._safe_push_url(raw):
            raise GitWriteError("GIT_REMOTE_TRANSPORT_DENIED", "remote push URL uses an unsupported or unsafe transport.", status="blocked")
        display = raw if len(raw) <= 240 else raw[:240]
        return raw, display

    @staticmethod
    def _safe_push_url(raw: str) -> bool:
        if not raw or any(char.isspace() for char in raw) or "\x00" in raw:
            return False
        if raw.startswith("/"):
            return True
        if raw.startswith("git@") and ":" in raw:
            host_path = raw[4:]
            return bool(host_path.split(":", 1)[0]) and "@" not in host_path.split(":", 1)[0]
        parsed = urlsplit(raw)
        if parsed.scheme not in {"file", "https", "ssh"} or parsed.fragment or parsed.query:
            return False
        if parsed.username is not None or parsed.password is not None:
            return parsed.scheme == "ssh" and parsed.username == "git" and parsed.password is None
        return bool(parsed.netloc or parsed.scheme == "file")

    def _remote_config_findings(self, repo: Path, remote: str) -> set[str]:
        findings: set[str] = set()
        for key, allowed in (
            (f"remote.{remote}.receivepack", {"git-receive-pack"}),
            (f"remote.{remote}.vcs", set()),
        ):
            result = self._run(repo, ("config", "--local", "--get-all", key))
            if result.truncated:
                findings.add("GIT_REMOTE_HELPER_DENIED")
                continue
            if result.returncode == 0:
                values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                if not values or any(value not in allowed for value in values):
                    findings.add("GIT_REMOTE_HELPER_DENIED")
        for key in ("core.sshCommand", "core.gitProxy"):
            result = self._run(repo, ("config", "--local", "--get-all", key))
            if result.truncated:
                findings.add("GIT_REMOTE_HELPER_DENIED")
                continue
            if result.returncode == 0 and any(line.strip() for line in result.stdout.splitlines()):
                # These repository-local settings can replace the transport
                # executable or proxy used by `git push`; fixed push argv and
                # approval do not make those helpers safe.
                findings.add("GIT_REMOTE_HELPER_DENIED")
        return findings

    def _remote_head(self, repo: Path, remote: str, branch: str) -> str:
        result = self._run(repo, ("ls-remote", "--heads", remote, branch), network=True)
        if result.timed_out or result.transport_error:
            raise GitWriteError("GIT_REMOTE_STATE_UNKNOWN", "remote branch state could not be read safely.", status="outcome_unknown")
        if result.returncode != 0:
            raise GitWriteError("GIT_REMOTE_STATE_UNAVAILABLE", "remote branch state could not be read safely.", status="blocked")
        lines = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return ""
        if len(lines) != 1 or not _HEX40.fullmatch(lines[0]):
            raise GitWriteError("GIT_REMOTE_STATE_INVALID", "remote branch state was malformed.", status="blocked")
        return lines[0]

    def _default_branch(self, repo: Path, remote: str) -> str:
        result = self._run(repo, ("ls-remote", "--symref", remote, "HEAD"), network=True)
        if result.timed_out or result.transport_error:
            raise GitWriteError("GIT_REMOTE_DEFAULT_UNKNOWN", "remote default branch could not be read safely.", status="outcome_unknown")
        if result.returncode != 0:
            raise GitWriteError("GIT_REMOTE_DEFAULT_UNAVAILABLE", "remote default branch could not be read safely.", status="blocked")
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return ""
        refs = [line.split("\t", 1)[0][len("ref: refs/heads/") :] for line in lines if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD")]
        if len(refs) != 1:
            raise GitWriteError("GIT_REMOTE_DEFAULT_INVALID", "remote default branch response was malformed.", status="blocked")
        return validate_branch_name(refs[0])

    def _remote_is_empty(self, repo: Path, remote: str) -> bool:
        """Return true only when the remote advertises no refs at all."""

        result = self._run(repo, ("ls-remote", remote), network=True)
        if result.timed_out or result.transport_error:
            raise GitWriteError("GIT_REMOTE_STATE_UNKNOWN", "remote state could not be read safely.", status="outcome_unknown")
        if result.returncode != 0:
            raise GitWriteError("GIT_REMOTE_STATE_UNAVAILABLE", "remote state could not be read safely.", status="blocked")
        if result.truncated:
            raise GitWriteError("GIT_REMOTE_STATE_INVALID", "remote state exceeded the safety bound.", status="blocked")
        return not any(line.strip() for line in result.stdout.splitlines())

    def _is_ancestor(self, repo: Path, ancestor: str, descendant: str) -> bool:
        """Check local commit ancestry without fetching or mutating repository refs."""

        ancestor_sha = _validate_hex(ancestor, name="remote_head", length=40)
        descendant_sha = _validate_hex(descendant, name="head", length=40)
        result = self._run(repo, ("merge-base", "--is-ancestor", ancestor_sha, descendant_sha))
        if result.timed_out or result.transport_error:
            raise GitWriteError("GIT_ANCESTRY_UNKNOWN", "commit ancestry could not be verified safely.", status="outcome_unknown")
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise GitWriteError("GIT_ANCESTRY_UNAVAILABLE", "commit ancestry could not be verified from local objects.", status="blocked")

    def push_preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task: GitTaskBinding,
        remote: object,
        branch: object,
        expected_head: object,
    ) -> PushPreflight:
        remote_name = validate_remote_name(remote)
        branch_name = validate_branch_name(branch)
        local_head = _validate_hex(expected_head, name="head", length=40)
        snapshot = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        findings = self._common_findings(
            self._task_findings(task, workspace_id=workspace_id, working_tree_id=working_tree_id, snapshot=snapshot),
            snapshot,
            require_clean=False,
        )
        if snapshot.head != local_head:
            findings.add("HEAD_MISMATCH")
        if snapshot.branch != branch_name:
            findings.add("BRANCH_MISMATCH")
        url_info: tuple[str, str] | None = None
        remote_head = ""
        default_branch = ""
        remote_empty = False
        protected_fast_forward = False
        try:
            url_info = self._remote_url(repo, remote_name)
            if url_info is None:
                findings.add("REMOTE_NOT_FOUND")
            else:
                findings.update(self._remote_config_findings(repo, remote_name))
                remote_head = self._remote_head(repo, url_info[0], branch_name)
                default_branch = self._default_branch(repo, url_info[0])
                guarded_branch = branch_name == "main" or (bool(default_branch) and branch_name == default_branch)
                if branch_name == "main" and remote_head == "":
                    remote_empty = self._remote_is_empty(repo, url_info[0])
                elif guarded_branch and remote_head:
                    protected_fast_forward = self._is_ancestor(repo, remote_head, local_head)
                    if not protected_fast_forward:
                        findings.add("NON_FAST_FORWARD_DENIED")
        except GitWriteError as exc:
            findings.add(exc.code)
        protected_branch = branch_name.startswith("release/") or branch_name in _PROTECTED_BRANCHES or branch_name == default_branch
        initial_main_publish = branch_name == "main" and remote_head == "" and default_branch == "" and remote_empty
        guarded_branch_push = initial_main_publish or (
            (branch_name == "main" or (bool(default_branch) and branch_name == default_branch))
            and bool(remote_head)
            and protected_fast_forward
        )
        if protected_branch and not guarded_branch_push:
            findings.add("PROTECTED_BRANCH_DENIED")
        if snapshot.staged:
            findings.add("WORKTREE_NOT_CLEAN")
        preflight_id = f"git-push-preflight:{secrets.token_urlsafe(16)}"
        if findings or url_info is None:
            preflight_status = "outcome_unknown" if any(code.endswith("_UNKNOWN") for code in findings) else "blocked"
            preflight = PushPreflight(
                preflight_id,
                preflight_status,
                workspace_id,
                working_tree_id,
                task.task_id,
                snapshot,
                remote_name,
                _sha256_text(url_info[0]) if url_info else "",
                url_info[1] if url_info else "",
                remote_head,
                default_branch,
                "PROTECTED_BRANCH_DENIED" in findings,
                tuple(sorted(findings)),
                None,
                self._audit_id("push", preflight_id, snapshot, remote_name + branch_name),
            )
        else:
            token, confirmation, expires_at = self.issue_approval("push", preflight_id, workspace_id)
            approval = GitApproval(token, confirmation, "push", preflight_id, workspace_id, expires_at)
            preflight = PushPreflight(
                preflight_id,
                "ready",
                workspace_id,
                working_tree_id,
                task.task_id,
                snapshot,
                remote_name,
                _sha256_text(url_info[0]),
                url_info[1],
                remote_head,
                default_branch,
                False,
                (),
                approval,
                self._audit_id("push", preflight_id, snapshot, remote_name + branch_name),
            )
        self._store_preflight(preflight)
        return preflight

    def push(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        task_resolver: Callable[[str], GitTaskBinding],
        preflight_id: str,
        approval_token: object,
        confirmation: object,
        remote: object,
        branch: object,
        expected_head: object,
        expected_remote_head: object,
        expected_remote_url_hash: object,
    ) -> GitMutationReceipt:
        remote_name = validate_remote_name(remote)
        branch_name = validate_branch_name(branch)
        local_head = _validate_hex(expected_head, name="head", length=40)
        remote_hash = _validate_hex(expected_remote_url_hash, name="remote_url_hash", length=64)
        if not isinstance(expected_remote_head, str):
            raise GitWriteError("GIT_REMOTE_HEAD_INVALID", "expected_remote_head must be a 40-hex commit or empty.")
        if expected_remote_head == "":
            expected_remote = ""
        else:
            expected_remote = _validate_hex(expected_remote_head, name="remote_head", length=40)
        preflight = self._load_preflight(preflight_id)
        if not isinstance(preflight, PushPreflight) or preflight.status != "ready":
            raise GitWriteError("GIT_PUSH_REJECTED", "push preflight is not ready.", details={"status": "rejected"})
        if (
            preflight.workspace_id != workspace_id
            or preflight.working_tree_id != working_tree_id
            or preflight.remote_name != remote_name
            or preflight.snapshot.branch != branch_name
            or preflight.snapshot.head != local_head
            or preflight.remote_url_hash != remote_hash
            or preflight.expected_remote_head != expected_remote
        ):
            self._reject("GIT_PUSH_REJECTED", "push target changed after preflight.", details={"status": "rejected", "reason": "STALE_REMOTE_STATE"})
        recovered = self._reconcile_executing_push(
            repo,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            preflight_id=preflight_id,
        )
        if recovered is not None:
            return recovered
        task = task_resolver(preflight.task_id)
        with self._lock:
            current = self.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
            findings = self._common_findings(
                self._task_findings(task, workspace_id=workspace_id, working_tree_id=working_tree_id, snapshot=current),
                current,
                require_clean=False,
            )
            if current.staged:
                findings.add("WORKTREE_NOT_CLEAN")
            if current != preflight.snapshot or current.head != local_head or current.branch != branch_name or findings:
                self._reject("GIT_PUSH_REJECTED", "push local state is stale or unsafe.", details={"status": "rejected", "blocking_codes": sorted(findings)})
            url_info = self._remote_url(repo, remote_name)
            if url_info is None or _sha256_text(url_info[0]) != remote_hash:
                self._reject("GIT_PUSH_REJECTED", "remote URL changed or is unavailable.", details={"status": "rejected", "reason": "STALE_REMOTE_STATE"})
            remote_findings = self._remote_config_findings(repo, remote_name)
            if remote_findings:
                self._reject("GIT_PUSH_REJECTED", "remote helper configuration is not allowed.", details={"status": "rejected", "blocking_codes": sorted(remote_findings)})
            observed_before = self._remote_head(repo, url_info[0], branch_name)
            if observed_before != expected_remote:
                self._reject("GIT_PUSH_REJECTED", "remote branch advanced after preflight; no overwrite was attempted.", details={"status": "rejected", "reason": "STALE_REMOTE_STATE", "observed_remote_head": observed_before})
            initial_main_publish = branch_name == "main" and expected_remote == "" and preflight.default_branch == ""
            if initial_main_publish and not self._remote_is_empty(repo, url_info[0]):
                self._reject("GIT_PUSH_REJECTED", "remote is no longer empty; initial main publish was not attempted.", details={"status": "rejected", "reason": "STALE_REMOTE_STATE"})
            if branch_name == "main" and expected_remote and not self._is_ancestor(repo, expected_remote, local_head):
                self._reject("GIT_PUSH_REJECTED", "main push is no longer a verified fast-forward.", details={"status": "rejected", "reason": "NON_FAST_FORWARD_DENIED"})
            self._claim_preflight(
                preflight_id=preflight_id,
                operation="push",
                workspace_id=workspace_id,
                approval_token=approval_token,
                confirmation=confirmation,
            )
            # Use the already revalidated push URL directly.  Passing the
            # remote name here would re-resolve a mutable pushurl after the
            # final check and reopen the TOCTOU window.
            result = self._run(repo, ("push", "--porcelain", url_info[0], f"{branch_name}:{branch_name}"), network=True)
            if result.timed_out or result.transport_error:
                observed = ""
                try:
                    observed = self._remote_head(repo, url_info[0], branch_name)
                except GitWriteError:
                    pass
                receipt = GitMutationReceipt(
                    f"git-push:{secrets.token_urlsafe(12)}",
                    self._audit_id("push", preflight_id, current, remote_name + branch_name),
                    "push",
                    "outcome_unknown",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    branch_name,
                    current.head,
                    current.head,
                    current.staged_diff_hash,
                    current.index_state_hash,
                    remote_name=remote_name,
                    remote_url_hash=remote_hash,
                    expected_remote_head=expected_remote,
                    observed_remote_head=observed,
                    error_code="GIT_PUSH_OUTCOME_UNKNOWN",
                    external_effect="remote_git_push",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "outcome_unknown")
                raise GitWriteError("GIT_PUSH_OUTCOME_UNKNOWN", "push result is unknown; do not retry until remote state is reviewed.", status="outcome_unknown", details={"receipt": receipt.as_dict()})
            if result.returncode != 0:
                receipt = GitMutationReceipt(
                    f"git-push:{secrets.token_urlsafe(12)}",
                    self._audit_id("push", preflight_id, current, remote_name + branch_name),
                    "push",
                    "failed",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    branch_name,
                    current.head,
                    current.head,
                    current.staged_diff_hash,
                    current.index_state_hash,
                    remote_name=remote_name,
                    remote_url_hash=remote_hash,
                    expected_remote_head=expected_remote,
                    error_code="GIT_PUSH_FAILED",
                    external_effect="remote_git_push",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "failed")
                raise GitWriteError("GIT_PUSH_FAILED", "remote rejected the normal push; no overwrite was attempted.", status="failed", details={"stderr": result.stderr[:1000], "receipt": receipt.as_dict()})
            try:
                observed = self._remote_head(repo, url_info[0], branch_name)
                if observed != current.head:
                    raise GitWriteError("GIT_PUSH_READBACK_UNKNOWN", "push read-back does not match the pinned commit.", status="outcome_unknown")
            except (GitWriteError, OSError, ValueError) as exc:
                observed_after = observed if "observed" in locals() else ""
                receipt = GitMutationReceipt(
                    f"git-push:{secrets.token_urlsafe(12)}",
                    self._audit_id("push", preflight_id, current, remote_name + branch_name),
                    "push",
                    "outcome_unknown",
                    workspace_id,
                    working_tree_id,
                    task.task_id,
                    preflight_id,
                    branch_name,
                    current.head,
                    current.head,
                    current.staged_diff_hash,
                    current.index_state_hash,
                    remote_name=remote_name,
                    remote_url_hash=remote_hash,
                    expected_remote_head=expected_remote,
                    observed_remote_head=observed_after,
                    error_code="GIT_PUSH_READBACK_UNKNOWN",
                    external_effect="remote_git_push",
                )
                self._record_receipt(receipt)
                self._finish_preflight(preflight_id, "outcome_unknown")
                raise GitWriteError("GIT_PUSH_OUTCOME_UNKNOWN", "push was executed but remote read-back is inconclusive; inspect remote state before any retry.", status="outcome_unknown", details={"receipt": receipt.as_dict()}) from exc
            receipt = GitMutationReceipt(
                f"git-push:{secrets.token_urlsafe(12)}",
                self._audit_id("push", preflight_id, current, remote_name + branch_name),
                "push",
                "succeeded",
                workspace_id,
                working_tree_id,
                task.task_id,
                preflight_id,
                branch_name,
                current.head,
                current.head,
                current.staged_diff_hash,
                current.index_state_hash,
                remote_name=remote_name,
                remote_url_hash=remote_hash,
                expected_remote_head=expected_remote,
                observed_remote_head=observed,
                external_effect="remote_git_push",
            )
            self._record_receipt(receipt)
            self._finish_preflight(preflight_id, "succeeded")
            return receipt


__all__ = [
    "CommitPreflight",
    "GitApproval",
    "GitMutationReceipt",
    "GitStateSnapshot",
    "GitTaskBinding",
    "GitWriteController",
    "GitWriteError",
    "PushPreflight",
    "validate_branch_name",
    "validate_commit_message",
    "validate_remote_name",
]
