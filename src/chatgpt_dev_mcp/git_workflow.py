from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
import uuid
from typing import Mapping

from .approval import ApprovalError, UnifiedApprovalStore
from .git_write import GitWriteController, GitWriteError, validate_branch_name
from .process_runner import run_bounded


PROTECTED_BRANCHES = frozenset({"main", "master", "production"})
MERGE_POLICIES = frozenset({"ff_only", "no_ff"})
OPERATIONS = frozenset({"branch_create", "merge", "rebase", "merge_abort", "rebase_abort"})


class GitWorkflowError(ValueError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass(frozen=True)
class _RunResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class _Preflight:
    preflight_id: str
    operation: str
    workspace_id: str
    working_tree_id: str
    repository_id: str
    fingerprint: str
    details: dict[str, object]
    managed_isolated: bool
    created_at: float
    consumed: bool = False


def _fingerprint(document: Mapping[str, object]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class GitWorkflowController:
    """Fixed-argv branch/merge/rebase workflows with pinned preflights."""

    def __init__(self, *, approval_store: UnifiedApprovalStore | None = None) -> None:
        self._approvals = approval_store or UnifiedApprovalStore()
        self._snapshotter = GitWriteController()
        self._preflights: dict[str, _Preflight] = {}

    @staticmethod
    def _run(repo: Path, argv: tuple[str, ...], *, timeout: float = 20.0) -> _RunResult:
        if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
            raise GitWorkflowError("GIT_ARGV_INVALID", "internal Git argv is invalid")
        try:
            result = run_bounded(
                ["git", "-C", str(repo), *argv],
                env={"PATH": __import__("os").environ.get("PATH", ""), "HOME": __import__("os").environ.get("HOME", ""), "GIT_TERMINAL_PROMPT": "0", "GIT_MERGE_AUTOEDIT": "no"},
                timeout_seconds=timeout,
                max_output_bytes=128 * 1024,
            )
        except (OSError, ValueError) as exc:
            raise GitWorkflowError("GIT_EXECUTION_FAILED", "bounded Git command could not complete") from exc
        if result.timed_out or result.output_truncated or result.returncode is None:
            raise GitWorkflowError("GIT_EXECUTION_FAILED", "bounded Git command could not complete")
        return _RunResult(result.returncode, result.stdout, result.stderr)

    @staticmethod
    def _translate_snapshot_error(exc: GitWriteError) -> GitWorkflowError:
        return GitWorkflowError(exc.code, str(exc), details=exc.details)

    def _snapshot(self, repo: Path, workspace_id: str, working_tree_id: str):
        try:
            return self._snapshotter.snapshot(repo, workspace_id=workspace_id, working_tree_id=working_tree_id)
        except GitWriteError as exc:
            raise self._translate_snapshot_error(exc) from exc

    def _branch_head(self, repo: Path, branch: str) -> str | None:
        validate_branch_name(branch)
        result = self._run(repo, ("rev-parse", "--verify", f"refs/heads/{branch}"))
        value = result.stdout.strip().lower()
        if result.returncode != 0:
            return None
        if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
            raise GitWorkflowError("GIT_REF_INVALID", "branch did not resolve to a full commit id")
        return value

    def _merge_base(self, repo: Path, left: str, right: str) -> str:
        result = self._run(repo, ("merge-base", left, right))
        value = result.stdout.strip().lower()
        if result.returncode != 0 or len(value) != 40:
            raise GitWorkflowError("GIT_MERGE_BASE_UNAVAILABLE", "merge base could not be determined")
        return value

    def _conflict_preview(self, repo: Path, base: str, left: str, right: str) -> bool:
        preview = self._run(repo, ("merge-tree", base, left, right))
        text = (preview.stdout + "\n" + preview.stderr).casefold()
        markers = ("<<<<<<<", ">>>>>>>", "changed in both", "conflict")
        return preview.returncode != 0 or any(marker in text for marker in markers)

    def _approval(self, operation: str, workspace_id: str, fingerprint: str, summary: str) -> dict[str, object]:
        confirmation = f"Approve {summary}."
        return self._approvals.issue(operation, workspace_id, fingerprint, confirmation).as_dict()

    def preflight(
        self,
        repo: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        operation: str,
        params: Mapping[str, object],
        managed_isolated: bool,
    ) -> dict[str, object]:
        if operation not in OPERATIONS:
            raise GitWorkflowError("GIT_WORKFLOW_OPERATION_INVALID", "operation is not supported")
        if not isinstance(params, Mapping):
            raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "params must be an object")
        snapshot = self._snapshot(repo, workspace_id, working_tree_id)
        if snapshot.policy_findings:
            raise GitWorkflowError("GIT_WORKFLOW_POLICY_BLOCKED", "repository policy findings block workflow", details={"findings": list(snapshot.policy_findings)})

        details: dict[str, object] = {
            "head": snapshot.head,
            "branch": snapshot.branch,
            "repository_id": snapshot.repository_id,
            "worktree_state_hash": snapshot.worktree_state_hash,
        }
        status = "ready"
        conflict_predicted = False
        approval: dict[str, object] | None

        if operation == "branch_create":
            if set(params) != {"branch"}:
                raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "branch_create accepts only branch")
            try:
                branch = validate_branch_name(params.get("branch"))
            except GitWriteError as exc:
                raise self._translate_snapshot_error(exc) from exc
            if branch in PROTECTED_BRANCHES:
                raise GitWorkflowError("GIT_PROTECTED_BRANCH", "protected/default branch cannot be created by this workflow")
            if self._branch_head(repo, branch) is not None:
                raise GitWorkflowError("GIT_BRANCH_EXISTS", "branch already exists")
            details.update({"new_branch": branch, "source_head": snapshot.head})

        elif operation == "merge":
            if set(params) != {"source_branch", "target_branch", "policy"}:
                raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "merge requires source_branch, target_branch, and policy")
            try:
                source = validate_branch_name(params.get("source_branch"))
                target = validate_branch_name(params.get("target_branch"))
            except GitWriteError as exc:
                raise self._translate_snapshot_error(exc) from exc
            policy = params.get("policy")
            if policy not in MERGE_POLICIES:
                raise GitWorkflowError("GIT_MERGE_POLICY_INVALID", "merge policy must be ff_only or no_ff")
            if snapshot.dirty:
                raise GitWorkflowError("GIT_WORKTREE_DIRTY", "merge requires a clean working tree")
            if snapshot.branch != target:
                raise GitWorkflowError("GIT_TARGET_BRANCH_MISMATCH", "current branch must equal the pinned merge target")
            source_head = self._branch_head(repo, source)
            target_head = self._branch_head(repo, target)
            if source_head is None or target_head is None:
                raise GitWorkflowError("GIT_BRANCH_NOT_FOUND", "source or target branch does not exist")
            merge_base = self._merge_base(repo, target_head, source_head)
            conflict_predicted = self._conflict_preview(repo, merge_base, target_head, source_head)
            if policy == "ff_only" and merge_base != target_head:
                status = "blocked"
            if conflict_predicted:
                status = "blocked"
            details.update({
                "source_branch": source,
                "target_branch": target,
                "source_head": source_head,
                "target_head": target_head,
                "merge_base": merge_base,
                "policy": policy,
                "protected_target": target in PROTECTED_BRANCHES,
            })

        elif operation == "rebase":
            if set(params) != {"base_branch"}:
                raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "rebase accepts only base_branch")
            if not managed_isolated:
                raise GitWorkflowError("REBASE_ISOLATION_REQUIRED", "rebase is allowed only in a managed isolated DEVELOPMENT worktree")
            if snapshot.dirty:
                raise GitWorkflowError("GIT_WORKTREE_DIRTY", "rebase requires a clean working tree")
            if snapshot.branch in PROTECTED_BRANCHES:
                raise GitWorkflowError("GIT_PROTECTED_BRANCH", "rebase of a protected/default branch is denied")
            try:
                base_branch = validate_branch_name(params.get("base_branch"))
            except GitWriteError as exc:
                raise self._translate_snapshot_error(exc) from exc
            base_head = self._branch_head(repo, base_branch)
            if base_head is None:
                raise GitWorkflowError("GIT_BRANCH_NOT_FOUND", "rebase base branch does not exist")
            merge_base = self._merge_base(repo, snapshot.head, base_head)
            conflict_predicted = self._conflict_preview(repo, merge_base, base_head, snapshot.head)
            if conflict_predicted:
                status = "blocked"
            commits = self._run(repo, ("rev-list", "--reverse", f"{base_head}..{snapshot.head}"))
            if commits.returncode != 0:
                raise GitWorkflowError("GIT_REBASE_RANGE_UNAVAILABLE", "rebase commit range could not be determined")
            replay = [item for item in commits.stdout.splitlines() if item]
            details.update({
                "base_branch": base_branch,
                "base_head": base_head,
                "merge_base": merge_base,
                "history_rewrite_commits": replay[:256],
                "history_rewrite_count": len(replay),
            })

        elif operation == "merge_abort":
            if params:
                raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "merge_abort accepts no params")
            state = self._run(repo, ("rev-parse", "--verify", "MERGE_HEAD"))
            if state.returncode != 0:
                raise GitWorkflowError("GIT_MERGE_NOT_IN_PROGRESS", "no merge is in progress")
            details["merge_head"] = state.stdout.strip().lower()

        else:
            if params:
                raise GitWorkflowError("GIT_WORKFLOW_ARGUMENTS_INVALID", "rebase_abort accepts no params")
            git_path = self._run(repo, ("rev-parse", "--git-path", "rebase-merge"))
            git_path2 = self._run(repo, ("rev-parse", "--git-path", "rebase-apply"))
            if not any(Path(item.stdout.strip()).exists() for item in (git_path, git_path2) if item.returncode == 0 and item.stdout.strip()):
                raise GitWorkflowError("GIT_REBASE_NOT_IN_PROGRESS", "no rebase is in progress")

        document = {
            "operation": operation,
            "workspace_id": workspace_id,
            "working_tree_id": working_tree_id,
            "repository_id": snapshot.repository_id,
            "managed_isolated": managed_isolated,
            "details": details,
        }
        fingerprint = _fingerprint(document)
        preflight_id = "gitwf-" + uuid.uuid4().hex
        if status == "ready":
            approval = self._approval(operation, workspace_id, fingerprint, operation.replace("_", " "))
        else:
            approval = None
        self._preflights[preflight_id] = _Preflight(
            preflight_id, operation, workspace_id, working_tree_id, snapshot.repository_id,
            fingerprint, details, managed_isolated, time.time()
        )
        payload = dict(details)
        payload.update({
            "preflight_id": preflight_id,
            "operation": operation,
            "status": status,
            "conflict_predicted": conflict_predicted,
            "approval": approval,
            "external_execution": False,
        })
        return payload

    def _revalidate(self, repo: Path, preflight: _Preflight):
        snapshot = self._snapshot(repo, preflight.workspace_id, preflight.working_tree_id)
        if snapshot.repository_id != preflight.repository_id:
            raise GitWorkflowError("GIT_WORKFLOW_STALE", "repository identity changed")
        details = preflight.details
        operation = preflight.operation
        if operation == "branch_create":
            if snapshot.head != details["source_head"] or self._branch_head(repo, str(details["new_branch"])) is not None:
                raise GitWorkflowError("GIT_WORKFLOW_STALE", "branch source or destination changed")
        elif operation == "merge":
            if snapshot.dirty or snapshot.branch != details["target_branch"] or snapshot.head != details["target_head"]:
                raise GitWorkflowError("GIT_WORKFLOW_STALE", "merge target state changed")
            if self._branch_head(repo, str(details["source_branch"])) != details["source_head"]:
                raise GitWorkflowError("GIT_WORKFLOW_STALE", "merge source changed")
        elif operation == "rebase":
            if not preflight.managed_isolated or snapshot.dirty or snapshot.head != details["head"]:
                raise GitWorkflowError("GIT_WORKFLOW_STALE", "rebase worktree changed")
            if self._branch_head(repo, str(details["base_branch"])) != details["base_head"]:
                raise GitWorkflowError("GIT_WORKFLOW_STALE", "rebase base changed")
        return snapshot

    def apply(self, repo: Path, *, preflight_id: str, approval_token: str, confirmation: str) -> dict[str, object]:
        preflight = self._preflights.get(preflight_id)
        if preflight is None or preflight.consumed:
            raise GitWorkflowError("GIT_WORKFLOW_PREFLIGHT_INVALID", "preflight is unknown or consumed")
        snapshot = self._revalidate(repo, preflight)
        try:
            self._approvals.consume(
                approval_token,
                confirmation,
                operation=preflight.operation,
                workspace_id=preflight.workspace_id,
                fingerprint=preflight.fingerprint,
            )
        except ApprovalError as exc:
            raise GitWorkflowError(exc.code, str(exc)) from exc
        preflight.consumed = True
        details = preflight.details
        operation = preflight.operation

        if operation == "branch_create":
            result = self._run(repo, ("branch", str(details["new_branch"]), str(details["source_head"])))
            if result.returncode != 0:
                raise GitWorkflowError("GIT_BRANCH_CREATE_FAILED", "branch creation failed", details={"stderr": result.stderr})
            readback = self._branch_head(repo, str(details["new_branch"]))
            if readback != details["source_head"]:
                raise GitWorkflowError("GIT_WORKFLOW_OUTCOME_UNKNOWN", "branch read-back did not match", details={"outcome": "outcome_unknown"})
            return {"status": "succeeded", "operation": operation, "head": snapshot.head, "branch_head": readback, "external_execution": False}

        if operation == "merge":
            policy = str(details["policy"])
            argv = ("merge", "--ff-only", str(details["source_branch"])) if policy == "ff_only" else ("merge", "--no-ff", "--no-edit", str(details["source_branch"]))
            result = self._run(repo, argv, timeout=60.0)
            if result.returncode != 0:
                merge_state = self._run(repo, ("rev-parse", "--verify", "MERGE_HEAD"))
                if merge_state.returncode == 0:
                    return {"status": "conflict", "operation": operation, "conflict": True, "merge_in_progress": True, "external_execution": False}
                raise GitWorkflowError("GIT_MERGE_FAILED", "merge failed without a recoverable merge state", details={"stderr": result.stderr})
            readback = self._branch_head(repo, str(details["target_branch"]))
            if readback is None:
                raise GitWorkflowError("GIT_WORKFLOW_OUTCOME_UNKNOWN", "merge read-back unavailable", details={"outcome": "outcome_unknown"})
            return {"status": "succeeded", "operation": operation, "head": readback, "external_execution": False}

        if operation == "rebase":
            result = self._run(repo, ("rebase", str(details["base_branch"])), timeout=90.0)
            if result.returncode != 0:
                return {"status": "conflict", "operation": operation, "conflict": True, "rebase_in_progress": True, "external_execution": False}
            after = self._snapshot(repo, preflight.workspace_id, preflight.working_tree_id)
            if self._merge_base(repo, after.head, str(details["base_head"])) != details["base_head"]:
                raise GitWorkflowError("GIT_WORKFLOW_OUTCOME_UNKNOWN", "rebase read-back did not contain the pinned base", details={"outcome": "outcome_unknown"})
            return {"status": "succeeded", "operation": operation, "head": after.head, "external_execution": False}

        if operation == "merge_abort":
            result = self._run(repo, ("merge", "--abort"), timeout=30.0)
            if result.returncode != 0:
                raise GitWorkflowError("GIT_MERGE_ABORT_FAILED", "bounded merge abort failed")
            return {"status": "succeeded", "operation": operation, "external_execution": False}

        result = self._run(repo, ("rebase", "--abort"), timeout=30.0)
        if result.returncode != 0:
            raise GitWorkflowError("GIT_REBASE_ABORT_FAILED", "bounded rebase abort failed")
        return {"status": "succeeded", "operation": operation, "external_execution": False}
