from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .process_runner import run_bounded


APPROVAL_TTL_SECONDS = 30 * 60
SESSION_TTL_SECONDS = 2 * 60 * 60
SESSION_ID_RE = re.compile(r"^session:[A-Za-z0-9_-]{16,96}$")
APPROVAL_ID_RE = re.compile(r"^approval:[A-Za-z0-9_-]{16,128}$")
# Git represents an unborn branch with no commit object.  The Director still
# needs a stable, non-secret revision token so an isolated orphan worktree can
# be bound without manufacturing an unapproved empty commit.
UNBORN_HEAD = "0" * 40


class DevelopmentSecurityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DevelopmentSessionStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RECOVERABLE = "recoverable"
    INTEGRATED = "integrated"
    ABANDONED = "abandoned"
    CLEANUP_CANDIDATE = "cleanup_candidate"
    EXPIRED_DIRTY_RETAINED = "expired_dirty_retained"
    EXPIRED_CLEAN = "expired_clean"
    STALE_DIRTY_RETAINED = "stale_dirty_retained"
    STALE_CLEAN = "stale_clean"
    STALE_UNAVAILABLE = "stale_unavailable"
    EXPIRED_UNAVAILABLE = "expired_unavailable"
    CLOSED = "closed"


@dataclass(frozen=True)
class SessionLifecycle:
    status: DevelopmentSessionStatus
    expired: bool
    active: bool
    stale: bool
    blocks_workspace_switch: bool
    dirty: bool
    worktree_available: bool


@dataclass(frozen=True)
class RepoIdentity:
    source_path: Path
    git_root: Path
    device: int
    inode: int
    head: str
    git_marker: str


@dataclass
class DevelopmentApproval:
    token: str
    candidate_id: str
    workspace_id: str
    identity: RepoIdentity
    profile: str
    expires_at: float
    confirmation: str
    used: bool = False


@dataclass
class DevelopmentAttachApproval:
    token: str
    session_id: str
    workspace_id: str
    identity: RepoIdentity
    expires_at: float
    confirmation: str
    used: bool = False


@dataclass
class DevelopmentSession:
    session_id: str
    candidate_id: str
    workspace_id: str
    identity: RepoIdentity
    worktree_path: Path
    base_commit: str
    source_dirty: bool
    created_at: float
    expires_at: float
    allowed_tasks: dict[str, str]
    stale: bool = False
    worktree_id: str | None = None
    # These identifiers describe the logical request, rather than the mutable
    # canonical checkout.  They are optional while v0.32/v0.33 sidecars remain
    # readable, but newly provisioned parallel sessions should populate them.
    project_id: str | None = None
    logical_workspace_id: str | None = None
    task_id: str | None = None
    owner_id: str | None = None
    source_revision: str | None = None
    lifecycle_state: str | None = None
    source_snapshot_id: str | None = None
    source_snapshot_hash: str | None = None
    # Formal, bounded evidence for a source-identity repair.  It is optional
    # so older v0.34 sidecars and positional constructors remain compatible.
    identity_repair: dict[str, Any] | None = None

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def durable_state(
        self,
        now: float,
        *,
        active_lock: bool = False,
        worktree_available: bool = True,
    ) -> str:
        """Classify durable DEVELOPMENT ownership independently of connection TTL."""

        terminal = {
            DevelopmentSessionStatus.INTEGRATED.value,
            DevelopmentSessionStatus.ABANDONED.value,
            DevelopmentSessionStatus.CLEANUP_CANDIDATE.value,
            DevelopmentSessionStatus.CLOSED.value,
        }
        if self.lifecycle_state in terminal:
            return str(self.lifecycle_state)
        if not worktree_available:
            return DevelopmentSessionStatus.STALE_UNAVAILABLE.value
        if active_lock and not self.stale and not self.is_expired(now):
            return DevelopmentSessionStatus.ACTIVE.value
        if self.is_expired(now):
            return DevelopmentSessionStatus.RECOVERABLE.value
        return DevelopmentSessionStatus.SUSPENDED.value

    def __post_init__(self) -> None:
        if self.worktree_id is None:
            self.worktree_id = self.session_id
        if self.project_id is None:
            self.project_id = self.workspace_id
        if self.logical_workspace_id is None:
            self.logical_workspace_id = self.workspace_id
        if self.source_revision is None:
            self.source_revision = self.base_commit
        if self.source_revision != self.base_commit:
            raise DevelopmentSecurityError(
                "DEVELOPMENT_SOURCE_CHANGED",
                "The session source revision must match its immutable base commit.",
            )

    def lifecycle(
        self,
        now: float,
        *,
        active_lock: bool = False,
        worktree_available: bool = True,
        dirty: bool = False,
        verification_ok: bool = True,
        closed: bool = False,
    ) -> SessionLifecycle:
        expired = self.is_expired(now)
        if closed:
            status = DevelopmentSessionStatus.CLOSED
        elif not verification_ok:
            status = DevelopmentSessionStatus.EXPIRED_UNAVAILABLE if expired else DevelopmentSessionStatus.STALE_UNAVAILABLE
        elif self.lifecycle_state == DevelopmentSessionStatus.CLEANUP_CANDIDATE.value:
            status = DevelopmentSessionStatus.CLEANUP_CANDIDATE
        elif self.lifecycle_state == DevelopmentSessionStatus.INTEGRATED.value:
            status = DevelopmentSessionStatus.INTEGRATED
        elif expired:
            status = DevelopmentSessionStatus.EXPIRED_DIRTY_RETAINED if dirty else DevelopmentSessionStatus.EXPIRED_CLEAN
        elif active_lock and not self.stale and worktree_available:
            status = DevelopmentSessionStatus.ACTIVE
        else:
            status = DevelopmentSessionStatus.STALE_DIRTY_RETAINED if dirty else DevelopmentSessionStatus.STALE_CLEAN
        active = status is DevelopmentSessionStatus.ACTIVE
        stale = status in {
            DevelopmentSessionStatus.STALE_DIRTY_RETAINED,
            DevelopmentSessionStatus.STALE_CLEAN,
            DevelopmentSessionStatus.STALE_UNAVAILABLE,
            DevelopmentSessionStatus.EXPIRED_DIRTY_RETAINED,
            DevelopmentSessionStatus.EXPIRED_CLEAN,
            DevelopmentSessionStatus.EXPIRED_UNAVAILABLE,
        }
        return SessionLifecycle(
            status=status,
            expired=expired,
            active=active,
            stale=stale,
            blocks_workspace_switch=active,
            dirty=dirty,
            worktree_available=worktree_available,
        )

    def is_active(
        self,
        now: float,
        *,
        active_lock: bool = False,
        worktree_available: bool = True,
        dirty: bool = False,
        verification_ok: bool = True,
    ) -> bool:
        return self.lifecycle(
            now,
            active_lock=active_lock,
            worktree_available=worktree_available,
            dirty=dirty,
            verification_ok=verification_ok,
        ).active

    def blocks_workspace_switch(
        self,
        now: float,
        *,
        active_lock: bool = False,
        worktree_available: bool = True,
        dirty: bool = False,
        verification_ok: bool = True,
    ) -> bool:
        return self.lifecycle(
            now,
            active_lock=active_lock,
            worktree_available=worktree_available,
            dirty=dirty,
            verification_ok=verification_ok,
        ).blocks_workspace_switch


def _managed_root() -> Path:
    raw = os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT")
    if raw:
        return Path(raw).expanduser().resolve(strict=False)
    return (Path.home() / ".cache" / "local-dev-mcp" / "worktrees").resolve(strict=False)


def _managed_root_literal() -> Path:
    raw = os.environ.get("LOCAL_DEV_MCP_WORKTREE_ROOT")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".cache" / "local-dev-mcp" / "worktrees"


def _session_sidecar_root() -> Path:
    return (Path.home() / ".cache" / "local-dev-mcp" / "sessions").resolve(strict=False)


def managed_worktree_root() -> Path:
    """Return the current runtime-managed worktree root for read-only evidence."""

    # Preserve the configured lexical spelling (for example ``/var`` on
    # macOS) so reconciliation can distinguish an explicitly configured root
    # from an intermediate symlink supplied by a sidecar path.  Callers that
    # need the physical identity resolve this value explicitly.
    return _managed_root_literal()


def session_sidecar_root() -> Path:
    """Return the current runtime-managed sidecar root for read-only evidence."""

    return _session_sidecar_root()


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _git_run(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    try:
        result = run_bounded(
            ["git", "-C", str(repo), *args],
            env=env,
            timeout_seconds=5,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository could not be verified.") from exc
    if result.timed_out or result.output_truncated or result.returncode != 0:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository could not be verified.")
    return result.stdout.strip()


def _git_optional(repo: Path, *args: str) -> str | None:
    """Run a fixed read-only Git probe where a missing object is expected."""

    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    try:
        result = run_bounded(
            ["git", "-C", str(repo), *args],
            env=env,
            timeout_seconds=5,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError):
        return None
    return result.stdout.strip() if not result.timed_out and not result.output_truncated and result.returncode == 0 else None


def _safe_git_marker(repo: Path) -> tuple[Path, str]:
    marker = repo / ".git"
    try:
        marker_stat = marker.lstat()
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source Git metadata is unavailable.") from exc
    if stat.S_ISLNK(marker_stat.st_mode):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source Git metadata uses an unsafe symlink.")
    if stat.S_ISREG(marker_stat.st_mode):
        try:
            header = marker.read_text(encoding="utf-8", errors="replace")[:4096]
        except OSError as exc:
            raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source Git metadata is unreadable.") from exc
        if header.startswith("gitdir:"):
            target = (marker.parent / header.split(":", 1)[1].strip()).resolve(strict=False)
            if not _within(repo, target):
                raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source Git metadata escapes the repository.")
    elif not stat.S_ISDIR(marker_stat.st_mode):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source Git metadata is invalid.")
    signature = f"{marker_stat.st_dev}:{marker_stat.st_ino}:{marker_stat.st_mode}:{marker_stat.st_size}:{marker_stat.st_mtime_ns}"
    return marker, signature


def capture_repo_identity(repo: Path) -> RepoIdentity:
    try:
        if repo.is_symlink() or not repo.is_dir():
            raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository path is not a real directory.")
        resolved = repo.resolve(strict=True)
        source_stat = resolved.stat()
    except DevelopmentSecurityError:
        raise
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository path is unavailable.") from exc
    git_root = Path(_git_run(resolved, "rev-parse", "--show-toplevel")).resolve(strict=False)
    if git_root != resolved:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source path is not the verified Git root.")
    head = _git_optional(resolved, "rev-parse", "--verify", "HEAD")
    if head is None:
        # An initialized repository with a valid symbolic branch but no
        # commits is safe to provision.  It remains explicitly unborn; no
        # empty commit is created on the user's behalf.
        symbolic_head = _git_optional(resolved, "symbolic-ref", "--quiet", "HEAD")
        if symbolic_head is None or not symbolic_head.startswith("refs/heads/"):
            raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository has no valid committed HEAD.")
        head = UNBORN_HEAD
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository has no valid committed HEAD.")
    _, marker_signature = _safe_git_marker(resolved)
    return RepoIdentity(resolved, git_root, source_stat.st_dev, source_stat.st_ino, head, marker_signature)


def validate_repo_identity(identity: RepoIdentity) -> RepoIdentity:
    current = capture_repo_identity(identity.source_path)
    if current != identity:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository identity changed.")
    return current


def validate_repo_anchor(identity: RepoIdentity) -> RepoIdentity:
    """Validate the source location after Git has updated worktree metadata.

    ``git worktree add`` legitimately changes the source repository's Git
    metadata timestamps. Cleanup therefore validates the path/inode/repository
    anchor and safe metadata shape, while the approval/create boundary keeps
    the stricter full identity comparison including HEAD and marker signature.
    """

    current = capture_repo_identity(identity.source_path)
    if (
        current.source_path != identity.source_path
        or current.git_root != identity.git_root
        or current.device != identity.device
        or current.inode != identity.inode
        or current.head != identity.head
    ):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository identity changed.")
    return current


def validate_source_commit_exists(repo: Path, source_commit: str) -> str:
    """Return a verified immutable commit object available from ``repo``.

    A development session is intentionally based on a commit object, not on
    the canonical checkout's *current* HEAD.  This keeps a previously
    approved baseline usable when another session advances canonical HEAD,
    while rejecting abbreviated refs, tags, and missing/pruned objects.
    """

    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_commit):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source revision is not a full commit ID.")
    if source_commit.lower() == UNBORN_HEAD:
        current_head = _git_optional(repo, "rev-parse", "--verify", "HEAD")
        symbolic_head = _git_optional(repo, "symbolic-ref", "--quiet", "HEAD")
        if current_head is None and symbolic_head is not None and symbolic_head.startswith("refs/heads/"):
            return UNBORN_HEAD
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The approved source repository is no longer unborn.")
    try:
        resolved = _git_run(repo, "rev-parse", "--verify", f"{source_commit}^{{commit}}")
    except DevelopmentSecurityError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The approved source commit is unavailable.") from exc
    if not re.fullmatch(r"[0-9a-f]{40}", resolved) or resolved.lower() != source_commit.lower():
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The approved source commit changed unexpectedly.")
    return resolved


def validate_repo_anchor_at_commit(identity: RepoIdentity, source_commit: str) -> RepoIdentity:
    """Validate a source repository anchor without pinning canonical HEAD.

    The repository root/inode and safe Git shape remain immutable security
    anchors.  HEAD and the Git marker timestamp are deliberately excluded:
    Git changes both during normal worktree operations, and a separate
    session may legitimately advance canonical HEAD after this baseline was
    approved.  The requested commit must still exist as an exact commit.
    """

    current = capture_repo_identity(identity.source_path)
    if (
        current.source_path != identity.source_path
        or current.git_root != identity.git_root
        or current.device != identity.device
        or current.inode != identity.inode
    ):
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository identity changed.")
    validate_source_commit_exists(current.source_path, source_commit)
    return current


def repo_dirty(repo: Path) -> bool:
    status = _git_run(repo, "status", "--porcelain")
    return bool(status)


def validate_repo_head(repo: Path, expected_head: str) -> None:
    """Validate a Git worktree HEAD without requiring a canonical .git directory."""

    current_head = _git_optional(repo, "rev-parse", "--verify", "HEAD") or UNBORN_HEAD
    if current_head != expected_head:
        raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The development worktree HEAD changed.")


def validate_repo_clean(repo: Path) -> None:
    """Fail closed when the canonical source has any local Git changes."""

    if repo_dirty(repo):
        raise DevelopmentSecurityError(
            "SOURCE_NOT_CLEAN",
            "The canonical source repository has staged, unstaged, or untracked changes.",
        )


def issue_approval(
    candidate_id: str,
    workspace_id: str,
    identity: RepoIdentity,
    profile: str,
    *,
    now: float | None = None,
    ttl_seconds: float = APPROVAL_TTL_SECONDS,
) -> DevelopmentApproval:
    if profile != "DEVELOPMENT":
        raise DevelopmentSecurityError("DEVELOPMENT_PROFILE_NOT_REGISTERED", "Development approval requires profile DEVELOPMENT.")
    issued_at = time.time() if now is None else now
    token = f"approval:{secrets.token_urlsafe(24)}"
    confirmation = f"Approve DEVELOPMENT for {workspace_id} at commit {identity.head[:12]}."
    return DevelopmentApproval(token, candidate_id, workspace_id, identity, profile, issued_at + ttl_seconds, confirmation)


def validate_and_consume_approval(
    approval: DevelopmentApproval,
    *,
    candidate_id: str,
    workspace_id: str,
    identity: RepoIdentity,
    confirmation: str,
    now: float | None = None,
    allow_head_advance: bool = False,
) -> None:
    current_time = time.time() if now is None else now
    if approval.used:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_USED", "The development approval was already consumed.")
    if current_time >= approval.expires_at:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_EXPIRED", "The development approval has expired.")
    if not APPROVAL_ID_RE.fullmatch(approval.token) or approval.candidate_id != candidate_id or approval.workspace_id != workspace_id or approval.profile != "DEVELOPMENT":
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_MISMATCH", "The development approval does not match this repository and request.")
    if approval.identity != identity:
        if not allow_head_advance or (
            identity.source_path != approval.identity.source_path
            or identity.git_root != approval.identity.git_root
            or identity.device != approval.identity.device
            or identity.inode != approval.identity.inode
        ):
            raise DevelopmentSecurityError("DEVELOPMENT_SOURCE_CHANGED", "The source repository identity changed.")
        validate_source_commit_exists(identity.source_path, approval.identity.head)
    if confirmation != approval.confirmation:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_MISMATCH", "The development approval does not match this repository and request.")
    approval.used = True


def issue_attach_approval(
    session: DevelopmentSession,
    *,
    now: float,
    ttl_seconds: float = APPROVAL_TTL_SECONDS,
) -> DevelopmentAttachApproval:
    token = f"approval:{secrets.token_urlsafe(24)}"
    confirmation = f"Approve DEVELOPMENT reattach for {session.workspace_id} from session {session.session_id} at commit {session.base_commit[:12]}."
    return DevelopmentAttachApproval(
        token,
        session.session_id,
        session.workspace_id,
        session.identity,
        now + ttl_seconds,
        confirmation,
    )


def validate_and_consume_attach_approval(
    approval: DevelopmentAttachApproval,
    *,
    session: DevelopmentSession,
    confirmation: str,
    now: float,
) -> None:
    if approval.used:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_USED", "The development attach approval was already consumed.")
    if now >= approval.expires_at:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_EXPIRED", "The development attach approval has expired.")
    if (
        not APPROVAL_ID_RE.fullmatch(approval.token)
        or approval.session_id != session.session_id
        or approval.workspace_id != session.workspace_id
        or approval.identity != session.identity
    ):
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_MISMATCH", "The development attach approval does not match this session.")
    if confirmation != approval.confirmation:
        raise DevelopmentSecurityError("DEVELOPMENT_APPROVAL_MISMATCH", "The development attach approval does not match this session.")
    approval.used = True


def managed_worktree_path(session_id: str) -> Path:
    target = managed_worktree_location(session_id)
    if not _within(_managed_root(), target):
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The worktree path is outside the managed root.")
    return target


def managed_worktree_location(session_id: str) -> Path:
    """Return the non-resolved managed location for safe status reporting."""

    if not SESSION_ID_RE.fullmatch(session_id):
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The session ID is invalid.")
    return _managed_root() / session_id.removeprefix("session:")


def _assert_managed_target(target: Path, *, allow_missing: bool) -> Path:
    """Validate the managed worktree container and target without following an attacker-controlled link."""

    managed_root = _managed_root()
    literal_root = _managed_root_literal()
    try:
        if literal_root.is_symlink():
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree root cannot be a symlink.")
        if not _within(managed_root, target):
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree path is outside the managed root.")
        managed_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_root = managed_root.resolve(strict=True)
        if resolved_root != managed_root:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree root changed unexpectedly.")
        root_stat = managed_root.stat()
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o022:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree root ownership is unsafe.")
        parent = target.parent
        if parent.resolve(strict=False) != managed_root:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree parent is invalid.")
        if parent.is_symlink():
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree parent cannot be a symlink.")
        parent_stat = parent.stat()
        if parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o022:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree parent ownership is unsafe.")
        if target.is_symlink():
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree cannot be a symlink.")
        if not allow_missing and not target.exists():
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree does not exist.")
        if allow_missing and target.exists():
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The target worktree path is already occupied.")
    except DevelopmentSecurityError:
        raise
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree path could not be verified.") from exc
    return managed_root


def verify_detached_worktree(source: Path, target: Path, base_commit: str) -> None:
    """Verify that Git created the exact detached worktree requested by the server."""

    _assert_managed_target(target, allow_missing=False)
    try:
        target_stat = target.stat()
        if target_stat.st_uid != os.getuid() or target_stat.st_mode & 0o022:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree ownership is unsafe.")
        top_level = Path(_git_run(target, "rev-parse", "--show-toplevel")).resolve(strict=True)
        head = _git_optional(target, "rev-parse", "--verify", "HEAD") or UNBORN_HEAD
        if top_level != target.resolve(strict=True) or head != base_commit:
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree identity does not match the approved commit.")
        worktrees = _git_run(source, "worktree", "list", "--porcelain")
    except DevelopmentSecurityError as exc:
        if exc.code == "DEVELOPMENT_WORKTREE_INVALID":
            raise
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree could not be verified.") from exc
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree could not be verified.") from exc
    target_text = str(target.resolve(strict=True))
    match_found = False
    for block in worktrees.split("\n\n"):
        lines = block.splitlines()
        worktree_line = next((line for line in lines if line.startswith("worktree ")), None)
        head_line = next((line for line in lines if line.startswith("HEAD ")), None)
        if worktree_line != f"worktree {target_text}":
            continue
        if head_line != f"HEAD {base_commit}":
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree is not at the approved revision.")
        if base_commit == UNBORN_HEAD:
            if not any(line.startswith("branch refs/heads/") for line in lines):
                raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created unborn worktree is not bound to a branch.")
        elif any(line.startswith("branch ") for line in lines):
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree is not detached at the approved commit.")
        match_found = True
        break
    if not match_found:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_IDENTITY_MISMATCH", "The created worktree is not registered at the expected path.")


def create_detached_worktree(source: Path, base_commit: str, target: Path) -> None:
    managed_root = _assert_managed_target(target, allow_missing=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    try:
        command = (
            [
                "git",
                "-C",
                str(source),
                "worktree",
                "add",
                "--orphan",
                "-b",
                f"devmcp-orphan-{target.name}",
                str(target),
            ]
            if base_commit == UNBORN_HEAD
            else ["git", "-C", str(source), "worktree", "add", "--detach", str(target), base_commit]
        )
        result = run_bounded(
            command,
            env=env,
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_CREATE_FAILED", "The detached worktree could not be created.") from exc
    if result.timed_out or result.output_truncated or result.returncode != 0 or not target.is_dir() or target.is_symlink() or not _within(managed_root, target):
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_CREATE_FAILED", "The detached worktree could not be created.")


def remove_detached_worktree(source: Path, target: Path) -> None:
    """Remove a clean managed worktree through Git's worktree bookkeeping."""

    managed_root = _assert_managed_target(target, allow_missing=False)
    if target.is_symlink() or not _within(managed_root, target) or not target.is_dir():
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The managed worktree could not be verified for cleanup.")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    try:
        result = run_bounded(
            ["git", "-C", str(source), "worktree", "remove", str(target)],
            env=env,
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_CLEANUP_FAILED", "The managed worktree could not be cleaned up.") from exc
    if result.timed_out or result.output_truncated or result.returncode != 0 or target.exists():
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_CLEANUP_FAILED", "The managed worktree could not be cleaned up.")


def _identity_to_dict(identity: RepoIdentity) -> dict[str, Any]:
    return {
        "source_path": str(identity.source_path),
        "git_root": str(identity.git_root),
        "device": identity.device,
        "inode": identity.inode,
        "head": identity.head,
        "git_marker": identity.git_marker,
    }


def _identity_from_dict(raw: dict[str, Any]) -> RepoIdentity:
    return RepoIdentity(Path(str(raw["source_path"])), Path(str(raw["git_root"])), int(raw["device"]), int(raw["inode"]), str(raw["head"]), str(raw["git_marker"]))


def write_session_sidecar(session: DevelopmentSession) -> None:
    try:
        root = _session_sidecar_root()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = root / f"{session.session_id.removeprefix('session:')}.json"
        if not _within(root, path):
            raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The session sidecar path is outside the managed root.")
        payload = {
            "session_id": session.session_id,
            "candidate_id": session.candidate_id,
            "workspace_id": session.workspace_id,
            "identity": _identity_to_dict(session.identity),
            "worktree_path": str(session.worktree_path),
            "worktree_id": session.worktree_id or session.session_id,
            "base_commit": session.base_commit,
            "source_dirty": session.source_dirty,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "allowed_tasks": sorted(session.allowed_tasks),
            "stale": session.stale,
            "project_id": session.project_id,
            "logical_workspace_id": session.logical_workspace_id,
            "task_id": session.task_id,
            "owner_id": session.owner_id,
            "source_revision": session.source_revision,
            "lifecycle_state": session.lifecycle_state,
            "source_snapshot_id": session.source_snapshot_id,
            "source_snapshot_hash": session.source_snapshot_hash,
        }
        if session.identity_repair is not None:
            payload["identity_repair"] = dict(session.identity_repair)
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
    except DevelopmentSecurityError:
        raise
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_SESSION_METADATA_FAILED", "The development session metadata could not be stored.") from exc


def read_session_sidecars(*, preserve_active: bool = False) -> list[DevelopmentSession]:
    """Read retained session metadata without implicit lease reactivation.

    Process restarts keep the conservative stale result by default. A
    connection-local WrapperRuntime can explicitly request the stored state
    while the broker remains in the same process.
    """

    root = _session_sidecar_root()
    if not root.is_dir():
        return []
    sessions: list[DevelopmentSession] = []
    for path in sorted(root.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            session_id = str(raw["session_id"])
            if not SESSION_ID_RE.fullmatch(session_id):
                continue
            identity = _identity_from_dict(raw["identity"])
            worktree_path = Path(str(raw["worktree_path"]))
            worktree_id = str(raw.get("worktree_id", session_id))
            expected_path = managed_worktree_path(worktree_id)
            if worktree_path.resolve(strict=False) != expected_path.resolve(strict=False):
                continue
            sessions.append(
                DevelopmentSession(
                    session_id,
                    str(raw["candidate_id"]),
                    str(raw["workspace_id"]),
                    identity,
                    worktree_path,
                    str(raw["base_commit"]),
                    bool(raw["source_dirty"]),
                    float(raw["created_at"]),
                    float(raw["expires_at"]),
                    {str(task): "" for task in raw.get("allowed_tasks", [])},
                    bool(raw.get("stale", False)) if preserve_active else True,
                    worktree_id,
                    _optional_sidecar_text(raw, "project_id"),
                    _optional_sidecar_text(raw, "logical_workspace_id"),
                    _optional_sidecar_text(raw, "task_id"),
                    _optional_sidecar_text(raw, "owner_id"),
                    _optional_sidecar_text(raw, "source_revision"),
                    _optional_sidecar_text(raw, "lifecycle_state"),
                    _optional_sidecar_text(raw, "source_snapshot_id"),
                    _optional_sidecar_text(raw, "source_snapshot_hash"),
                    _optional_sidecar_mapping(raw, "identity_repair"),
                )
            )
        except (DevelopmentSecurityError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return sessions


def _optional_sidecar_text(raw: dict[str, Any], key: str) -> str | None:
    """Read optional v0.34 session metadata without trusting JSON coercion."""

    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def _optional_sidecar_mapping(raw: dict[str, Any], key: str) -> dict[str, Any] | None:
    """Read optional bounded mapping metadata without trusting JSON coercion."""

    value = raw.get(key)
    if not isinstance(value, dict) or len(value) > 64:
        return None
    return dict(value)


def delete_session_sidecar(session_id: str) -> None:
    if not SESSION_ID_RE.fullmatch(session_id):
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The session ID is invalid.")
    path = _session_sidecar_root() / f"{session_id.removeprefix('session:')}.json"
    if not _within(_session_sidecar_root(), path):
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The session sidecar path is outside the managed root.")
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise DevelopmentSecurityError("DEVELOPMENT_WORKTREE_INVALID", "The session sidecar could not be removed.") from exc
