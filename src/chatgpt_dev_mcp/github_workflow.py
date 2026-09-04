"""Repository-pinned GitHub PR, CI, review, and merge workflows."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Mapping, Protocol, Sequence
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import uuid

from .approval import ApprovalError, UnifiedApprovalStore
from .credential_slots import CredentialSlotError, CredentialSlotManager
from .director import contains_secret_like_content
from .git_write import GitWriteError, validate_branch_name
from .process_runner import run_bounded


class GitHubWorkflowError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GitHubPolicy:
    owner: str
    repository: str
    remote_name: str = "origin"
    remote_host: str = "github.com"
    api_origin: str = "https://api.github.com"
    credential_slot: str = ""
    auth_required: bool = True
    allowed_base_branches: tuple[str, ...] = ("main",)
    required_checks: tuple[str, ...] = ()
    required_approvals: int = 0
    merge_method: str = "squash"
    merge_queue_required: bool = False
    enforce_branch_protection: bool = True

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", self.owner):
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "owner is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", self.repository):
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "repository is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", self.remote_name):
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "remote name is invalid")
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", self.remote_host):
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "remote host is invalid")
        parsed = urlsplit(self.api_origin)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if not parsed.hostname or parsed.username or parsed.password or (parsed.scheme != "https" and not (loopback and parsed.scheme == "http")):
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "API origin must be HTTPS or loopback HTTP")
        if self.merge_method not in {"merge", "squash", "rebase"}:
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "merge method is invalid")
        if not 0 <= self.required_approvals <= 20:
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", "required approvals is invalid")
        try:
            for branch in self.allowed_base_branches:
                validate_branch_name(branch)
        except GitWriteError as exc:
            raise GitHubWorkflowError("GITHUB_POLICY_INVALID", str(exc)) from exc


class GitHubTransport(Protocol):
    def request(self, method: str, path: str, *, headers: Mapping[str, str], body: Mapping[str, object] | None = None) -> tuple[int, object]: ...


class _UrlTransport:
    def __init__(self, origin: str) -> None:
        self._origin = origin.rstrip("/")

    def request(self, method: str, path: str, *, headers: Mapping[str, str], body: Mapping[str, object] | None = None) -> tuple[int, object]:
        if not path.startswith("/") or ".." in path or "\x00" in path:
            raise GitHubWorkflowError("GITHUB_PATH_INVALID", "internal GitHub path is invalid")
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = Request(self._origin + path, data=data, method=method, headers=dict(headers))
        try:
            with urlopen(request, timeout=15.0) as response:
                raw = response.read(1024 * 1024)
                status = int(getattr(response, "status", 0) or 0)
        except HTTPError as exc:
            raw = exc.read(1024 * 1024)
            status = int(exc.code)
        payload: object
        if not raw:
            payload = {}
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"parse_error": True}
        return status, payload


@dataclass(frozen=True)
class GitHubReceipt:
    receipt_id: str
    operation: str
    remote_hash: str
    status: str
    pr_number: int | None
    head_sha: str
    outcome: str
    created_at: float

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


@dataclass
class _MutationPreflight:
    preflight_id: str
    operation: str
    workspace_id: str
    root: Path
    remote_hash: str
    fingerprint: str
    approval_id: str
    confirmation: str
    credential_grant_id: str
    params: dict[str, object]
    created_at: float


class GitHubWorkflowController:
    def __init__(
        self,
        policy: GitHubPolicy,
        *,
        credential_slots: CredentialSlotManager | None = None,
        transport: GitHubTransport | None = None,
        approval_store: UnifiedApprovalStore | None = None,
    ) -> None:
        self._policy = policy
        self._credential_slots = credential_slots
        self._transport = transport or _UrlTransport(policy.api_origin)
        self._approvals = approval_store or UnifiedApprovalStore()
        self._preflights: dict[str, _MutationPreflight] = {}
        self._receipts: list[GitHubReceipt] = []

    @staticmethod
    def _git(root: Path, argv: Sequence[str]) -> str:
        result = run_bounded(
            ["git", "-C", str(root), *argv],
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "GIT_TERMINAL_PROMPT": "0"},
            timeout_seconds=10,
            max_output_bytes=128 * 1024,
        )
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise GitHubWorkflowError("GITHUB_GIT_STATE_UNAVAILABLE", "registered Git state could not be verified")
        return result.stdout.strip()

    def _remote_identity(self, root: Path) -> tuple[str, str]:
        remote_url = self._git(root, ("remote", "get-url", self._policy.remote_name))
        host = ""
        path = ""
        if remote_url.startswith("git@") and ":" in remote_url:
            prefix, path = remote_url.split(":", 1)
            host = prefix.split("@", 1)[1]
        else:
            parsed = urlsplit(remote_url)
            host = parsed.hostname or ""
            path = parsed.path.lstrip("/")
        if host.casefold() != self._policy.remote_host.casefold():
            raise GitHubWorkflowError("GITHUB_REPOSITORY_MISMATCH", "registered remote host does not match policy")
        if path.endswith(".git"):
            path = path[:-4]
        parts = path.split("/")
        if len(parts) != 2 or parts[0] != self._policy.owner or parts[1] != self._policy.repository:
            raise GitHubWorkflowError("GITHUB_REPOSITORY_MISMATCH", "registered remote repository does not match policy")
        return remote_url, hashlib.sha256(remote_url.encode()).hexdigest()

    def _branch_head(self, root: Path, branch: str) -> str:
        try:
            branch_name = validate_branch_name(branch)
        except GitWriteError as exc:
            raise GitHubWorkflowError("GITHUB_BRANCH_INVALID", str(exc)) from exc
        value = self._git(root, ("rev-parse", "--verify", f"refs/heads/{branch_name}")).lower()
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise GitHubWorkflowError("GITHUB_BRANCH_INVALID", "branch did not resolve to a full commit id")
        return value

    def _validate_grant(self, grant_id: str, *, project_id: str) -> None:
        if not self._policy.auth_required:
            return
        if not grant_id or self._credential_slots is None or not self._policy.credential_slot:
            raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", "GitHub credential grant is unavailable")
        try:
            slots = self._credential_slots.validate_grants([grant_id], project_id=project_id, command_profile="github")
        except CredentialSlotError as exc:
            raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", str(exc)) from exc
        if slots != (self._policy.credential_slot,):
            raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", "credential grant is not bound to the configured GitHub slot")

    def _headers(self, grant_id: str, *, project_id: str, consume: bool = True) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if not self._policy.auth_required:
            return headers
        self._validate_grant(grant_id, project_id=project_id)
        assert self._credential_slots is not None
        try:
            resolver = self._credential_slots.consume_grants if consume else self._credential_slots.resolve_grants
            child_env, _ = resolver([grant_id], project_id=project_id, command_profile="github")
        except CredentialSlotError as exc:
            raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", str(exc)) from exc
        auth_material = child_env.get(self._policy.credential_slot, "")
        if not auth_material:
            raise GitHubWorkflowError("GITHUB_AUTH_UNAVAILABLE", "configured GitHub credential material is unavailable")
        headers["Authorization"] = "Bearer " + auth_material
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, object] | None = None,
    ) -> tuple[int, object]:
        try:
            return self._transport.request(method, path, headers=headers, body=body)
        except (TimeoutError, OSError) as exc:
            raise GitHubWorkflowError("GITHUB_NETWORK_UNAVAILABLE", "GitHub request did not complete") from exc

    @property
    def _repo_prefix(self) -> str:
        return f"/repos/{self._policy.owner}/{self._policy.repository}"

    @staticmethod
    def _dict(value: object, *, code: str) -> dict[str, object]:
        if not isinstance(value, dict):
            raise GitHubWorkflowError(code, "GitHub response shape was unexpected")
        return value

    def _pr_status(self, number: int, headers: Mapping[str, str]) -> dict[str, object]:
        if not 1 <= number <= 2_000_000_000:
            raise GitHubWorkflowError("GITHUB_PR_INVALID", "pull request number is invalid")
        status, raw = self._request("GET", f"{self._repo_prefix}/pulls/{number}", headers=headers)
        if status != 200:
            raise GitHubWorkflowError("GITHUB_PR_READ_FAILED", f"pull request read returned HTTP {status}")
        pr = self._dict(raw, code="GITHUB_PR_READ_FAILED")
        head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
        base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
        head_repo = head.get("repo") if isinstance(head.get("repo"), dict) else {}
        return {
            "number": int(pr.get("number", number)),
            "state": str(pr.get("state", ""))[:32],
            "title": str(pr.get("title", ""))[:300],
            "draft": bool(pr.get("draft", False)),
            "merged": bool(pr.get("merged", False)),
            "mergeable": pr.get("mergeable"),
            "head_branch": str(head.get("ref", ""))[:200],
            "head_sha": str(head.get("sha", ""))[:64],
            "head_repository": str(head_repo.get("full_name", ""))[:220],
            "base_branch": str(base.get("ref", ""))[:200],
        }

    def _checks(self, head_sha: str, headers: Mapping[str, str]) -> list[dict[str, object]]:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha or ""):
            raise GitHubWorkflowError("GITHUB_CHECKS_INVALID", "check-run head sha is invalid")
        status, raw = self._request("GET", f"{self._repo_prefix}/commits/{head_sha}/check-runs", headers=headers)
        if status != 200:
            raise GitHubWorkflowError("GITHUB_CHECKS_READ_FAILED", f"check runs returned HTTP {status}")
        payload = self._dict(raw, code="GITHUB_CHECKS_READ_FAILED")
        runs = payload.get("check_runs", [])
        if not isinstance(runs, list):
            raise GitHubWorkflowError("GITHUB_CHECKS_READ_FAILED", "check runs response is invalid")
        result: list[dict[str, object]] = []
        for item in runs[:500]:
            if not isinstance(item, dict):
                continue
            result.append({
                "name": str(item.get("name", ""))[:200],
                "status": str(item.get("status", ""))[:40],
                "conclusion": str(item.get("conclusion", ""))[:40],
            })
        return result

    def _reviews(self, number: int, headers: Mapping[str, str]) -> list[dict[str, object]]:
        status, raw = self._request("GET", f"{self._repo_prefix}/pulls/{number}/reviews", headers=headers)
        if status != 200:
            raise GitHubWorkflowError("GITHUB_REVIEWS_READ_FAILED", f"pull request reviews returned HTTP {status}")
        if not isinstance(raw, list):
            raise GitHubWorkflowError("GITHUB_REVIEWS_READ_FAILED", "pull request reviews response is invalid")
        reviews: list[dict[str, object]] = []
        for item in raw[:500]:
            if not isinstance(item, dict):
                continue
            user = item.get("user") if isinstance(item.get("user"), dict) else {}
            reviews.append({
                "user": str(user.get("login", ""))[:100],
                "state": str(item.get("state", ""))[:40].upper(),
                "submitted_at": str(item.get("submitted_at", ""))[:64],
            })
        return reviews

    def _branch_protection(self, branch: str, headers: Mapping[str, str]) -> dict[str, object]:
        status, raw = self._request("GET", f"{self._repo_prefix}/branches/{branch}/protection", headers=headers)
        # A repository without branch protection is a valid read result.  The
        # local policy still controls whether that absence blocks a mutation.
        if status == 404:
            return {"available": False, "required_reviews": 0, "required_checks": []}
        if status != 200:
            raise GitHubWorkflowError("GITHUB_PROTECTION_READ_FAILED", f"branch protection returned HTTP {status}")
        protection = self._dict(raw, code="GITHUB_PROTECTION_READ_FAILED")
        reviews = protection.get("required_pull_request_reviews")
        required_reviews = 0
        if isinstance(reviews, dict):
            required_reviews = int(reviews.get("required_approving_review_count", 0) or 0)
        checks = protection.get("required_status_checks")
        required_checks: list[str] = []
        if isinstance(checks, dict) and isinstance(checks.get("contexts"), list):
            required_checks = [str(value)[:200] for value in checks["contexts"][:100] if isinstance(value, str)]
        return {
            "available": True,
            "required_reviews": required_reviews,
            "required_checks": required_checks,
        }

    def _merge_readiness(
        self,
        pr: Mapping[str, object],
        checks: Sequence[Mapping[str, object]],
        reviews: Sequence[Mapping[str, object]],
        protection: Mapping[str, object],
    ) -> dict[str, object]:
        reasons: list[str] = []
        number = int(pr.get("number", 0) or 0)
        state = str(pr.get("state", ""))
        if bool(pr.get("merged")):
            reasons.append("already_merged")
        elif state != "open":
            reasons.append("pr_not_open")
        if bool(pr.get("draft")):
            reasons.append("draft")
        base_branch = str(pr.get("base_branch", ""))
        if base_branch not in self._policy.allowed_base_branches:
            reasons.append("base_branch_not_allowed")
        if pr.get("mergeable") is False:
            reasons.append("not_mergeable")
        elif pr.get("mergeable") is None:
            reasons.append("mergeability_unknown")

        required_checks = tuple(dict.fromkeys((*self._policy.required_checks, *(
            str(value) for value in protection.get("required_checks", []) if isinstance(value, str)
        ))))
        check_by_name = {str(item.get("name", "")): item for item in checks}
        failed_checks = [
            name for name in required_checks
            if (
                name not in check_by_name
                or str(check_by_name[name].get("status", "")) != "completed"
                or str(check_by_name[name].get("conclusion", "")) != "success"
            )
        ]
        if failed_checks:
            reasons.append("required_checks_not_passing")

        latest_by_user: dict[str, str] = {}
        for review in reviews:
            user = str(review.get("user", ""))
            state_value = str(review.get("state", "")).upper()
            if user:
                latest_by_user[user] = state_value
        if any(state_value == "CHANGES_REQUESTED" for state_value in latest_by_user.values()):
            reasons.append("changes_requested")
        approvals = sum(1 for state_value in latest_by_user.values() if state_value == "APPROVED")
        required_approvals = max(self._policy.required_approvals, int(protection.get("required_reviews", 0) or 0))
        if approvals < required_approvals:
            reasons.append("required_approvals_missing")
        if self._policy.merge_queue_required:
            reasons.append("merge_queue_required")
        return {
            "number": number,
            "ready": not reasons,
            "reasons": reasons,
            "required_checks": list(required_checks),
            "passing_checks": [
                name for name in required_checks
                if name in check_by_name
                and str(check_by_name[name].get("status", "")) == "completed"
                and str(check_by_name[name].get("conclusion", "")) == "success"
            ],
            "approved_reviewers": sorted(user for user, state_value in latest_by_user.items() if state_value == "APPROVED"),
            "required_approvals": required_approvals,
            "branch_protection": dict(protection),
        }

    @staticmethod
    def _fingerprint(operation: str, remote_hash: str, params: Mapping[str, object]) -> str:
        encoded = json.dumps(
            {"operation": operation, "remote_hash": remote_hash, "params": params},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _receipt(
        self,
        *,
        operation: str,
        remote_hash: str,
        status: str,
        pr_number: int | None,
        head_sha: str,
        outcome: str,
    ) -> dict[str, object]:
        receipt = GitHubReceipt(
            receipt_id="github:" + uuid.uuid4().hex,
            operation=operation,
            remote_hash=remote_hash,
            status=status,
            pr_number=pr_number,
            head_sha=head_sha,
            outcome=outcome,
            created_at=time.time(),
        )
        self._receipts.append(receipt)
        del self._receipts[:-256]
        return receipt.as_dict()

    def read(
        self,
        root: Path,
        *,
        project_id: str,
        action: str,
        number: int,
        credential_grant_id: str = "",
    ) -> dict[str, object]:
        """Perform a bounded, repository-pinned GitHub read operation."""
        if not isinstance(project_id, str) or not project_id.strip():
            raise GitHubWorkflowError("GITHUB_PROJECT_INVALID", "project_id is required")
        _, remote_hash = self._remote_identity(root)
        headers = self._headers(credential_grant_id, project_id=project_id)
        action_name = str(action).strip().lower()
        if action_name == "pr_status":
            data: object = self._pr_status(number, headers)
        elif action_name == "checks":
            pr = self._pr_status(number, headers)
            data = {"pr": pr, "checks": self._checks(str(pr["head_sha"]), headers)}
        elif action_name == "reviews":
            data = {"number": number, "reviews": self._reviews(number, headers)}
        elif action_name == "merge_readiness":
            pr = self._pr_status(number, headers)
            checks = self._checks(str(pr["head_sha"]), headers)
            reviews = self._reviews(number, headers)
            protection = self._branch_protection(str(pr["base_branch"]), headers)
            readiness = self._merge_readiness(pr, checks, reviews, protection)
            data = {
                "pr": pr,
                "checks": checks,
                "reviews": reviews,
                "readiness": readiness,
                **readiness,
            }
        else:
            raise GitHubWorkflowError("GITHUB_ACTION_INVALID", "GitHub read action is not registered")
        return {
            "status": "succeeded",
            "action": action_name,
            "project_id": project_id,
            "remote_hash": remote_hash,
            "data": data,
            "external_execution": True,
        }
    def preflight(
        self,
        root: Path,
        *,
        workspace_id: str,
        project_id: str,
        operation: str,
        params: Mapping[str, object],
        credential_grant_id: str = "",
    ) -> dict[str, object]:
        """Pin repository state and issue a one-shot approval for a mutation."""
        if not isinstance(workspace_id, str) or not workspace_id.strip() or project_id != workspace_id:
            raise GitHubWorkflowError("GITHUB_WORKSPACE_MISMATCH", "workspace_id and project_id must identify the same registered project")
        if not isinstance(params, Mapping):
            raise GitHubWorkflowError("GITHUB_PARAMS_INVALID", "mutation params must be an object")
        operation_name = str(operation).strip().lower()
        if operation_name not in {"pr_create", "pr_merge"}:
            raise GitHubWorkflowError("GITHUB_OPERATION_INVALID", "GitHub mutation operation is not registered")
        _, remote_hash = self._remote_identity(root)
        self._validate_grant(credential_grant_id, project_id=project_id)
        safe_params: dict[str, object]
        if operation_name == "pr_create":
            title = params.get("title")
            body = params.get("body", "")
            head_branch = validate_branch_name(params.get("head_branch"))
            base_branch = validate_branch_name(params.get("base_branch", self._policy.allowed_base_branches[0]))
            if base_branch not in self._policy.allowed_base_branches:
                raise GitHubWorkflowError("GITHUB_BASE_BRANCH_DENIED", "base branch is not allowed by policy")
            if not isinstance(title, str) or not title.strip() or len(title) > 300 or contains_secret_like_content(title):
                raise GitHubWorkflowError("GITHUB_TITLE_INVALID", "pull request title is invalid")
            if not isinstance(body, str) or len(body) > 20_000 or contains_secret_like_content(body):
                raise GitHubWorkflowError("GITHUB_BODY_INVALID", "pull request body is invalid")
            safe_params = {
                "title": title,
                "body": body,
                "head_branch": head_branch,
                "base_branch": base_branch,
                "head_sha": self._branch_head(root, head_branch),
                "base_sha": self._branch_head(root, base_branch),
            }
        else:
            try:
                number = int(params.get("number", 0))
            except (TypeError, ValueError) as exc:
                raise GitHubWorkflowError("GITHUB_PR_INVALID", "pull request number is invalid") from exc
            # Preflight reads are read-only.  Resolve the grant for GitHub's
            # checks without consuming the one-shot token needed by apply.
            headers = self._headers(credential_grant_id, project_id=project_id, consume=False)
            pr = self._pr_status(number, headers)
            checks = self._checks(str(pr["head_sha"]), headers)
            reviews = self._reviews(number, headers)
            protection = self._branch_protection(str(pr["base_branch"]), headers)
            readiness = self._merge_readiness(pr, checks, reviews, protection)
            if self._policy.merge_queue_required:
                raise GitHubWorkflowError("GITHUB_MERGE_QUEUE_REQUIRED", "merge queue policy requires a queue operation")
            if not readiness["ready"]:
                reason = ", ".join(str(value) for value in readiness["reasons"])
                raise GitHubWorkflowError("GITHUB_MERGE_NOT_READY", reason or "pull request is not mergeable")
            safe_params = {
                "number": number,
                "head_sha": str(pr["head_sha"]),
                "base_branch": str(pr["base_branch"]),
                "merge_method": self._policy.merge_method,
            }
        fingerprint = self._fingerprint(operation_name, remote_hash, safe_params)
        approval = self._approvals.issue(
            operation_name,
            workspace_id,
            fingerprint,
            f"Approve GitHub {operation_name} for {workspace_id} using preflight.",
        )
        preflight_id = "github-preflight:" + uuid.uuid4().hex
        self._preflights[preflight_id] = _MutationPreflight(
            preflight_id=preflight_id,
            operation=operation_name,
            workspace_id=workspace_id,
            root=Path(root),
            remote_hash=remote_hash,
            fingerprint=fingerprint,
            approval_id=approval.approval_id,
            confirmation=approval.confirmation,
            credential_grant_id=credential_grant_id,
            params=safe_params,
            created_at=time.time(),
        )
        return {
            "preflight_id": preflight_id,
            "operation": operation_name,
            "status": "ready",
            "workspace_id": workspace_id,
            "remote_hash": remote_hash,
            "params": dict(safe_params),
            "approval": approval.as_dict(),
            "external_execution": False,
        }

    def apply(
        self,
        preflight_id: str,
        *,
        project_id: str,
        approval_id: str,
        confirmation: str,
        credential_grant_id: str = "",
    ) -> dict[str, object]:
        """Consume the pinned approval, perform one mutation, and read back."""
        preflight = self._preflights.pop(preflight_id, None)
        if preflight is None or preflight.workspace_id != project_id:
            raise GitHubWorkflowError("GITHUB_PREFLIGHT_INVALID", "preflight is unknown or bound to another project")
        _, current_remote_hash = self._remote_identity(preflight.root)
        if current_remote_hash != preflight.remote_hash:
            raise GitHubWorkflowError("GITHUB_PREFLIGHT_STALE", "configured GitHub remote changed after preflight")
        try:
            self._approvals.consume(
                approval_id,
                confirmation,
                operation=preflight.operation,
                workspace_id=preflight.workspace_id,
                fingerprint=preflight.fingerprint,
            )
        except ApprovalError as exc:
            raise GitHubWorkflowError(exc.code, str(exc)) from exc
        grant_id = credential_grant_id or preflight.credential_grant_id
        try:
            headers = self._headers(grant_id, project_id=project_id)
            if preflight.operation == "pr_create":
                params = preflight.params
                if self._branch_head(preflight.root, str(params["head_branch"])) != params["head_sha"] or self._branch_head(preflight.root, str(params["base_branch"])) != params["base_sha"]:
                    raise GitHubWorkflowError("GITHUB_PREFLIGHT_STALE", "branch head changed after preflight")
                status, raw = self._request(
                    "POST",
                    f"{self._repo_prefix}/pulls",
                    headers=headers,
                    body={
                        "title": params["title"],
                        "body": params["body"],
                        "head": params["head_branch"],
                        "base": params["base_branch"],
                    },
                )
                if status not in {200, 201}:
                    raise GitHubWorkflowError("GITHUB_PR_CREATE_FAILED", f"pull request create returned HTTP {status}")
                payload = self._dict(raw, code="GITHUB_PR_CREATE_FAILED")
                number = int(payload.get("number", 0) or 0)
                if number <= 0:
                    raise GitHubWorkflowError("GITHUB_PR_CREATE_FAILED", "pull request create response did not include a number")
                pr = self._pr_status(number, headers)
                receipt = self._receipt(
                    operation=preflight.operation,
                    remote_hash=preflight.remote_hash,
                    status="succeeded",
                    pr_number=number,
                    head_sha=str(params["head_sha"]),
                    outcome="succeeded",
                )
                return {"status": "succeeded", "pr": pr, "receipt": receipt, "external_execution": True}

            number = int(preflight.params["number"])
            current = self._pr_status(number, headers)
            if str(current.get("head_sha", "")) != str(preflight.params["head_sha"]):
                raise GitHubWorkflowError("GITHUB_PREFLIGHT_STALE", "pull request head changed after preflight")
            checks = self._checks(str(current["head_sha"]), headers)
            reviews = self._reviews(number, headers)
            protection = self._branch_protection(str(current["base_branch"]), headers)
            readiness = self._merge_readiness(current, checks, reviews, protection)
            if not readiness["ready"]:
                raise GitHubWorkflowError("GITHUB_MERGE_NOT_READY", ", ".join(str(value) for value in readiness["reasons"]))
            status, raw = self._request(
                "PUT",
                f"{self._repo_prefix}/pulls/{number}/merge",
                headers=headers,
                body={"sha": preflight.params["head_sha"], "merge_method": preflight.params["merge_method"]},
            )
            if status != 200:
                raise GitHubWorkflowError("GITHUB_PR_MERGE_FAILED", f"pull request merge returned HTTP {status}")
            payload = self._dict(raw, code="GITHUB_PR_MERGE_FAILED")
            if payload.get("merged") is False:
                raise GitHubWorkflowError("GITHUB_PR_MERGE_FAILED", "GitHub did not confirm the merge")
            merged = self._pr_status(number, headers)
            if not bool(merged.get("merged")):
                raise GitHubWorkflowError("GITHUB_PR_MERGE_READBACK_UNKNOWN", "merge read-back did not confirm the merge")
            receipt = self._receipt(
                operation=preflight.operation,
                remote_hash=preflight.remote_hash,
                status="succeeded",
                pr_number=number,
                head_sha=str(preflight.params["head_sha"]),
                outcome="succeeded",
            )
            return {"status": "succeeded", "pr": merged, "receipt": receipt, "external_execution": True}
        except GitHubWorkflowError as exc:
            if exc.code != "GITHUB_NETWORK_UNAVAILABLE":
                raise
            number = int(preflight.params.get("number", 0) or 0) if preflight.operation == "pr_merge" else None
            receipt = self._receipt(
                operation=preflight.operation,
                remote_hash=preflight.remote_hash,
                status="outcome_unknown",
                pr_number=number,
                head_sha=str(preflight.params.get("head_sha", "")),
                outcome="outcome_unknown",
            )
            return {
                "status": "outcome_unknown",
                "outcome": "outcome_unknown",
                "retry_safe": False,
                "side_effect_may_have_applied": True,
                "receipt": receipt,
                "external_execution": True,
            }


class GitHubReadAdapter:
    """Primary-controller reads with a strictly read-only optional fallback."""

    _READ_ACTIONS = frozenset({"pr_status", "checks", "reviews", "merge_readiness"})
    _FALLBACK_CODES = frozenset({"GITHUB_NETWORK_UNAVAILABLE", "GITHUB_PROVIDER_UNAVAILABLE"})

    def __init__(self, primary: object, *, fallback=None) -> None:
        if not callable(getattr(primary, "read", None)):
            raise GitHubWorkflowError("GITHUB_ADAPTER_INVALID", "primary GitHub reader is invalid")
        if fallback is not None and not callable(fallback):
            raise GitHubWorkflowError("GITHUB_ADAPTER_INVALID", "fallback GitHub reader is invalid")
        self._primary = primary
        self._fallback = fallback

    @staticmethod
    def _remote_hash(value: object) -> str:
        text = str(value or "")
        if not re.fullmatch(r"[0-9a-f]{64}", text):
            raise GitHubWorkflowError("GITHUB_REPOSITORY_MISMATCH", "GitHub fallback remote identity is invalid")
        return text

    def read(
        self,
        root: Path | None,
        *,
        project_id: str,
        action: str,
        number: int,
        expected_remote_hash: str,
        credential_grant_id: str = "",
    ) -> dict[str, object]:
        action_name = str(action).strip().lower()
        if action_name not in self._READ_ACTIONS:
            raise GitHubWorkflowError("GITHUB_ACTION_INVALID", "GitHub adapter supports read actions only")
        expected = self._remote_hash(expected_remote_hash)
        try:
            result = self._primary.read(root, project_id=project_id, action=action_name, number=number, credential_grant_id=credential_grant_id)
        except GitHubWorkflowError as exc:
            if exc.code not in self._FALLBACK_CODES or self._fallback is None:
                raise
            fallback_result = self._fallback(action_name, number)
            if not isinstance(fallback_result, Mapping):
                raise GitHubWorkflowError("GITHUB_PROVIDER_UNAVAILABLE", "GitHub fallback returned invalid evidence")
            if self._remote_hash(fallback_result.get("remote_hash")) != expected:
                raise GitHubWorkflowError("GITHUB_REPOSITORY_MISMATCH", "GitHub fallback does not match the pinned remote")
            return {**dict(fallback_result), "backend": "gh_read_only_fallback", "external_execution": True}
        if not isinstance(result, Mapping):
            raise GitHubWorkflowError("GITHUB_PR_READ_FAILED", "primary GitHub reader returned invalid evidence")
        if self._remote_hash(result.get("remote_hash")) != expected:
            raise GitHubWorkflowError("GITHUB_REPOSITORY_MISMATCH", "primary GitHub evidence no longer matches the pinned remote")
        return {**dict(result), "backend": "primary", "external_execution": True}

    @staticmethod
    def mutate(operation: str) -> None:
        raise GitHubWorkflowError("GITHUB_MUTATION_APPROVAL_REQUIRED", f"{operation} must use the existing approval-gated GitHub workflow")
