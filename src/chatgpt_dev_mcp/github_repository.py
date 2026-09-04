from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .git_write import (
    GitWriteError,
    _github_cli_config_dir,
    _github_cli_state_dir,
    _trusted_github_cli,
    validate_branch_name,
)
from .process_runner import run_bounded


_REPOSITORY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SSH_REMOTE_RE = re.compile(
    r"^git@github\.com:(?P<owner>[A-Za-z0-9_.-]{1,100})/(?P<repo>[A-Za-z0-9_.-]{1,100}?)(?:\.git)?$"
)
_API_PATH_RE = re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.%/?=&-]+)?$")
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_MAX_GITHUB_OUTPUT = 512 * 1024


class GitHubRepositoryError(ValueError):
    def __init__(self, code: str, message: str, *, status: str = "rejected") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class RepositoryIdentity:
    owner: str
    repository: str
    remote_hash: str

    def as_dict(self) -> dict[str, str]:
        return {
            "owner": self.owner,
            "repository": self.repository,
            "remote_identity_hash": self.remote_hash,
        }


@dataclass(frozen=True)
class _VisibilityPreflight:
    preflight_id: str
    approval_id: str
    confirmation: str
    workspace_id: str
    workspace_identity_hash: str
    owner: str
    repository: str
    remote_hash: str
    current_visibility: str
    target_visibility: str
    fingerprint: str
    expires_at: float


def _unsupported_remote() -> GitHubRepositoryError:
    return GitHubRepositoryError(
        "GITHUB_REPOSITORY_UNSUPPORTED",
        "registered Git remote is not an accepted GitHub repository remote",
    )


def _identity(owner: str, repository: str, remote_url: str) -> RepositoryIdentity:
    if not _REPOSITORY_COMPONENT_RE.fullmatch(owner) or not _REPOSITORY_COMPONENT_RE.fullmatch(repository):
        raise _unsupported_remote()
    if owner in {".", ".."} or repository in {".", ".."}:
        raise _unsupported_remote()
    return RepositoryIdentity(
        owner=owner,
        repository=repository,
        remote_hash=hashlib.sha256(remote_url.encode("utf-8")).hexdigest(),
    )


def parse_github_remote(remote_url: object) -> RepositoryIdentity:
    if not isinstance(remote_url, str) or not remote_url or "\x00" in remote_url:
        raise _unsupported_remote()

    ssh = _SSH_REMOTE_RE.fullmatch(remote_url)
    if ssh is not None:
        return _identity(ssh.group("owner"), ssh.group("repo"), remote_url)

    try:
        parsed = urlsplit(remote_url)
        port = parsed.port
    except ValueError:
        raise _unsupported_remote() from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise _unsupported_remote()
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0] != "" or not parts[1] or not parts[2]:
        raise _unsupported_remote()
    owner, repository = parts[1], parts[2]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not repository:
        raise _unsupported_remote()
    return _identity(owner, repository, remote_url)


class GitHubCliTransport:
    """Bounded GitHub API transport backed only by the trusted system `gh` CLI."""

    @staticmethod
    def _parse_output(output: str) -> tuple[int, object]:
        normalized = output.replace("\r\n", "\n")
        match = re.match(r"^HTTP/\S+\s+(\d{3})(?:\s+[^\n]*)?\n", normalized)
        if match is None:
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub CLI returned an unexpected bounded response",
            )
        status = int(match.group(1))
        separator = normalized.find("\n\n")
        body_text = "" if separator < 0 else normalized[separator + 2 :].strip()
        if not body_text:
            return status, {}
        try:
            payload = json.loads(body_text)
        except json.JSONDecodeError:
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub CLI returned invalid JSON",
            ) from None
        return status, payload

    @staticmethod
    def _validate_request(method: object, path: object, body: object) -> tuple[str, str, Mapping[str, object] | None]:
        if method not in {"GET", "PATCH"}:
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "internal GitHub method is not allowed")
        if not isinstance(path, str) or not _API_PATH_RE.fullmatch(path) or ".." in path or "\x00" in path:
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "internal GitHub API path is invalid")
        if body is not None and not isinstance(body, Mapping):
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "internal GitHub request body is invalid")
        return str(method), path, body

    def request(self, method: str, path: str, *, body: Mapping[str, object] | None = None) -> tuple[int, object]:
        parsed_method, parsed_path, parsed_body = self._validate_request(method, path, body)
        gh = _trusted_github_cli()
        if not gh:
            raise GitHubRepositoryError(
                "GITHUB_AUTH_UNAVAILABLE",
                "authenticated trusted GitHub CLI is unavailable",
            )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GH_CONFIG_DIR": _github_cli_config_dir(),
            "GH_PROMPT_DISABLED": "1",
            "XDG_STATE_HOME": _github_cli_state_dir(),
            "NO_COLOR": "1",
        }
        argv = [gh, "api", "--include", "--method", parsed_method, parsed_path]
        input_text = None
        if parsed_body is not None:
            argv.extend(("--input", "-"))
            input_text = json.dumps(dict(parsed_body), sort_keys=True, separators=(",", ":"))
        try:
            result = run_bounded(
                argv,
                env=env,
                input_text=input_text,
                timeout_seconds=30,
                max_output_bytes=_MAX_GITHUB_OUTPUT,
            )
        except (OSError, ValueError):
            raise GitHubRepositoryError(
                "GITHUB_NETWORK_UNAVAILABLE",
                "GitHub request did not complete",
                status="error",
            ) from None
        if result.timed_out:
            raise GitHubRepositoryError(
                "GITHUB_NETWORK_UNAVAILABLE",
                "GitHub request timed out",
                status="error",
            )
        if result.output_truncated:
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub response exceeded the bounded output limit",
                status="error",
            )
        if result.returncode not in {0, 1}:
            raise GitHubRepositoryError(
                "GITHUB_AUTH_UNAVAILABLE" if result.returncode == 4 else "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub CLI request failed",
                status="error",
            )
        return self._parse_output(result.stdout)


class GitHubRepositoryController:
    _READ_ACTIONS = frozenset({"summary", "forks", "secret_scanning_alerts", "branch_protection", "actions"})

    def __init__(
        self,
        *,
        transport: object | None = None,
        clock: Callable[[], float] = time.time,
        approval_ttl_seconds: float = 1800.0,
    ) -> None:
        if (
            isinstance(approval_ttl_seconds, bool)
            or not isinstance(approval_ttl_seconds, (int, float))
            or not 1 <= float(approval_ttl_seconds) <= 7200
        ):
            raise ValueError("approval_ttl_seconds is outside bounds")
        self._transport = transport or GitHubCliTransport()
        self._clock = clock
        self._approval_ttl_seconds = float(approval_ttl_seconds)
        self._preflights: dict[str, _VisibilityPreflight] = {}
        self._ambiguity_latch: set[str] = set()

    @staticmethod
    def _git_remote_identity(root: Path, remote_name: str = "origin") -> RepositoryIdentity:
        try:
            resolved = root.resolve(strict=True)
        except OSError:
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_UNSUPPORTED",
                "registered workspace root is unavailable",
            ) from None
        if not resolved.is_dir() or resolved.is_symlink():
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_UNSUPPORTED",
                "registered workspace root is invalid",
            )
        result = run_bounded(
            ["git", "-C", str(resolved), "remote", "get-url", remote_name],
            env={
                "PATH": os.environ.get("PATH", ""),
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        if result.timed_out or result.output_truncated or result.returncode != 0:
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_UNSUPPORTED",
                "registered GitHub remote could not be derived",
            )
        return parse_github_remote(result.stdout.strip())

    def _request(self, method: str, path: str, *, body: Mapping[str, object] | None = None) -> tuple[int, object]:
        request = getattr(self._transport, "request", None)
        if not callable(request):
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "GitHub transport is invalid")
        try:
            return request(method, path, body=body)
        except GitHubRepositoryError:
            raise
        except (TimeoutError, OSError):
            raise GitHubRepositoryError(
                "GITHUB_NETWORK_UNAVAILABLE",
                "GitHub request did not complete",
                status="error",
            ) from None

    @staticmethod
    def _bounded_text(value: object, maximum: int = 220) -> str:
        return str(value or "")[:maximum]

    @staticmethod
    def _dict(value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub response shape was unexpected",
                status="error",
            )
        return value

    @staticmethod
    def _list(value: object) -> list[object]:
        if not isinstance(value, list):
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_READ_FAILED",
                "GitHub response shape was unexpected",
                status="error",
            )
        return value

    @staticmethod
    def _availability(status: int) -> str:
        if status in {401, 403}:
            return "permission_denied"
        if status == 404:
            return "unsupported"
        return "error"

    @classmethod
    def _security_and_analysis(cls, value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            return {}
        result: dict[str, object] = {}
        for key in ("advanced_security", "secret_scanning", "secret_scanning_push_protection"):
            raw = value.get(key)
            if isinstance(raw, dict):
                result[key] = {"status": cls._bounded_text(raw.get("status"), 32)}
        return result

    def _repository_metadata(self, identity: RepositoryIdentity) -> dict[str, object]:
        status, raw = self._request("GET", f"/repos/{identity.owner}/{identity.repository}")
        if status != 200:
            code = "GITHUB_PERMISSION_DENIED" if status in {401, 403, 404} else "GITHUB_REPOSITORY_READ_FAILED"
            raise GitHubRepositoryError(code, "repository metadata is unavailable", status="error")
        data = self._dict(raw)
        expected_name = f"{identity.owner}/{identity.repository}"
        full_name = self._bounded_text(data.get("full_name"))
        if full_name.casefold() != expected_name.casefold():
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_MISMATCH",
                "GitHub repository metadata does not match the registered remote",
            )
        visibility = self._bounded_text(data.get("visibility"), 16).lower()
        if visibility not in {"public", "private", "internal"}:
            if data.get("private") is True:
                visibility = "private"
            elif data.get("private") is False:
                visibility = "public"
            else:
                raise GitHubRepositoryError(
                    "GITHUB_REPOSITORY_READ_FAILED",
                    "repository visibility is unavailable",
                    status="error",
                )
        return {
            "full_name": full_name,
            "visibility": visibility,
            "private": bool(data.get("private")),
            "archived": bool(data.get("archived")),
            "disabled": bool(data.get("disabled")),
            "default_branch": self._bounded_text(data.get("default_branch"), 240),
            "forks_count": max(0, int(data.get("forks_count", 0))) if isinstance(data.get("forks_count", 0), int) else 0,
            "security_and_analysis": self._security_and_analysis(data.get("security_and_analysis")),
        }

    @staticmethod
    def _result(identity: RepositoryIdentity, availability: str, *, data: object | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "availability": availability,
            "remote_identity_hash": identity.remote_hash,
            "external_execution": True,
        }
        if data is not None:
            result["data"] = data
        return result

    def _read_forks(self, identity: RepositoryIdentity, limit: int) -> dict[str, object]:
        status, raw = self._request("GET", f"/repos/{identity.owner}/{identity.repository}/forks?per_page={limit}")
        if status != 200:
            return self._result(identity, self._availability(status))
        items = []
        for value in self._list(raw)[:limit]:
            if not isinstance(value, dict):
                continue
            items.append(
                {
                    "full_name": self._bounded_text(value.get("full_name")),
                    "visibility": self._bounded_text(value.get("visibility"), 16),
                    "private": bool(value.get("private")),
                    "archived": bool(value.get("archived")),
                    "created_at": self._bounded_text(value.get("created_at"), 64),
                    "updated_at": self._bounded_text(value.get("updated_at"), 64),
                }
            )
        return self._result(identity, "available", data=items)

    def _read_secret_scanning(self, identity: RepositoryIdentity) -> dict[str, object]:
        repository = self._repository_metadata(identity)
        security = repository.get("security_and_analysis")
        configured = ""
        if isinstance(security, dict):
            scanning = security.get("secret_scanning")
            if isinstance(scanning, dict):
                configured = self._bounded_text(scanning.get("status"), 32).lower()
        status, raw = self._request("GET", f"/repos/{identity.owner}/{identity.repository}/secret-scanning/alerts?per_page=100")
        if status == 404 and configured == "disabled":
            return self._result(identity, "not_configured")
        if status != 200:
            return self._result(identity, self._availability(status))
        alerts = []
        for value in self._list(raw)[:100]:
            if not isinstance(value, dict):
                continue
            location: dict[str, object] = {}
            locations = value.get("locations")
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                first = locations[0]
                location["type"] = self._bounded_text(first.get("type"), 48)
                details = first.get("details")
                if isinstance(details, dict):
                    location.update(
                        {
                            "path": self._bounded_text(details.get("path"), 512),
                            "start_line": details.get("start_line") if isinstance(details.get("start_line"), int) else None,
                            "end_line": details.get("end_line") if isinstance(details.get("end_line"), int) else None,
                        }
                    )
            alerts.append(
                {
                    "number": value.get("number") if isinstance(value.get("number"), int) else None,
                    "state": self._bounded_text(value.get("state"), 32),
                    "secret_type": self._bounded_text(value.get("secret_type"), 120),
                    "secret_type_display_name": self._bounded_text(value.get("secret_type_display_name"), 160),
                    "resolution": self._bounded_text(value.get("resolution"), 64),
                    "resolved_at": self._bounded_text(value.get("resolved_at"), 64),
                    "location": location,
                }
            )
        return self._result(identity, "available", data=alerts)

    def _read_branch_protection(self, identity: RepositoryIdentity, branch: str | None) -> dict[str, object]:
        repository = self._repository_metadata(identity)
        selected = branch or self._bounded_text(repository.get("default_branch"), 240)
        try:
            selected = validate_branch_name(selected)
        except GitWriteError:
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "branch is invalid") from None
        status, raw = self._request("GET", f"/repos/{identity.owner}/{identity.repository}/branches/{selected}/protection")
        if status == 404:
            return self._result(identity, "not_configured", data={"branch": selected, "present": False})
        if status != 200:
            return self._result(identity, self._availability(status))
        data = self._dict(raw)
        checks: list[str] = []
        required_checks = data.get("required_status_checks")
        if isinstance(required_checks, dict) and isinstance(required_checks.get("contexts"), list):
            checks = [self._bounded_text(item, 160) for item in required_checks["contexts"][:100]]
        reviews = data.get("required_pull_request_reviews")
        review_count = 0
        if isinstance(reviews, dict) and isinstance(reviews.get("required_approving_review_count"), int):
            review_count = max(0, min(int(reviews["required_approving_review_count"]), 100))
        admins = data.get("enforce_admins")
        return self._result(
            identity,
            "available",
            data={
                "branch": selected,
                "present": True,
                "enforce_admins": bool(admins.get("enabled")) if isinstance(admins, dict) else False,
                "required_checks": checks,
                "required_approving_reviews": review_count,
                "restrictions_present": data.get("restrictions") is not None,
            },
        )

    def _read_actions(self, identity: RepositoryIdentity, limit: int) -> dict[str, object]:
        workflow_status, workflow_raw = self._request(
            "GET", f"/repos/{identity.owner}/{identity.repository}/actions/workflows?per_page={limit}"
        )
        if workflow_status != 200:
            return self._result(identity, self._availability(workflow_status))
        run_status, run_raw = self._request(
            "GET", f"/repos/{identity.owner}/{identity.repository}/actions/runs?per_page={limit}"
        )
        if run_status != 200:
            return self._result(identity, self._availability(run_status))
        workflow_data = self._dict(workflow_raw)
        run_data = self._dict(run_raw)
        workflows = []
        raw_workflows = workflow_data.get("workflows")
        if isinstance(raw_workflows, list):
            for value in raw_workflows[:limit]:
                if isinstance(value, dict):
                    workflows.append(
                        {
                            "id": value.get("id") if isinstance(value.get("id"), int) else None,
                            "name": self._bounded_text(value.get("name"), 200),
                            "state": self._bounded_text(value.get("state"), 48),
                            "path": self._bounded_text(value.get("path"), 512),
                        }
                    )
        runs = []
        raw_runs = run_data.get("workflow_runs")
        if isinstance(raw_runs, list):
            for value in raw_runs[:limit]:
                if isinstance(value, dict):
                    head_sha = self._bounded_text(value.get("head_sha"), 40)
                    runs.append(
                        {
                            "id": value.get("id") if isinstance(value.get("id"), int) else None,
                            "name": self._bounded_text(value.get("name"), 200),
                            "status": self._bounded_text(value.get("status"), 48),
                            "conclusion": self._bounded_text(value.get("conclusion"), 48),
                            "branch": self._bounded_text(value.get("head_branch"), 240),
                            "head_sha": head_sha if re.fullmatch(r"[0-9a-fA-F]{40}", head_sha) else "",
                            "event": self._bounded_text(value.get("event"), 80),
                            "created_at": self._bounded_text(value.get("created_at"), 64),
                            "updated_at": self._bounded_text(value.get("updated_at"), 64),
                        }
                    )
        return self._result(identity, "available", data={"workflows": workflows, "runs": runs})

    def read(self, root: Path, *, action: str, branch: str | None = None, limit: int = 50) -> dict[str, object]:
        if action not in self._READ_ACTIONS:
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "repository read action is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise GitHubRepositoryError("GITHUB_REPOSITORY_READ_FAILED", "limit is outside bounds")
        identity = self._git_remote_identity(root)
        if action == "summary":
            data = self._repository_metadata(identity)
            self._ambiguity_latch.discard(identity.remote_hash)
            return self._result(identity, "available", data=data)
        if action == "forks":
            return self._read_forks(identity, limit)
        if action == "secret_scanning_alerts":
            return self._read_secret_scanning(identity)
        if action == "branch_protection":
            return self._read_branch_protection(identity, branch)
        return self._read_actions(identity, limit)

    @staticmethod
    def _workspace_identity(root: Path, workspace_id: str) -> str:
        try:
            resolved = root.resolve(strict=True)
        except OSError:
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "workspace identity is unavailable") from None
        return hashlib.sha256(f"{workspace_id}\0{resolved}".encode("utf-8")).hexdigest()

    @staticmethod
    def _fingerprint(
        identity: RepositoryIdentity,
        *,
        workspace_id: str,
        workspace_identity_hash: str,
        current_visibility: str,
        target_visibility: str,
    ) -> str:
        payload = {
            "repository": f"{identity.owner}/{identity.repository}",
            "remote_identity_hash": identity.remote_hash,
            "workspace_id": workspace_id,
            "workspace_identity_hash": workspace_identity_hash,
            "current_visibility": current_visibility,
            "target_visibility": target_visibility,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_workspace_id(workspace_id: object) -> str:
        if not isinstance(workspace_id, str) or _WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "workspace identity is invalid")
        return workspace_id

    @staticmethod
    def _validate_visibility(visibility: object) -> str:
        if visibility not in {"private", "public", "internal"}:
            raise GitHubRepositoryError("GITHUB_VISIBILITY_INVALID", "visibility target is invalid")
        return str(visibility)

    def preflight(
        self,
        root: Path,
        *,
        workspace_id: str,
        operation: str,
        visibility: str,
    ) -> dict[str, object]:
        workspace = self._validate_workspace_id(workspace_id)
        if operation != "set_visibility":
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "repository mutation operation is invalid")
        target = self._validate_visibility(visibility)
        identity = self._git_remote_identity(root)
        if identity.remote_hash in self._ambiguity_latch:
            raise GitHubRepositoryError(
                "GITHUB_VISIBILITY_READBACK_UNKNOWN",
                "repository visibility is ambiguous and requires an authoritative read reconciliation",
                status="outcome_unknown",
            )
        repository = self._repository_metadata(identity)
        current = str(repository["visibility"])
        workspace_hash = self._workspace_identity(root, workspace)
        fingerprint = self._fingerprint(
            identity,
            workspace_id=workspace,
            workspace_identity_hash=workspace_hash,
            current_visibility=current,
            target_visibility=target,
        )
        common = {
            "operation": "set_visibility",
            "workspace_id": workspace,
            "repository": f"{identity.owner}/{identity.repository}",
            "remote_identity_hash": identity.remote_hash,
            "current_visibility": current,
            "target_visibility": target,
            "fingerprint": fingerprint,
            "external_execution": True,
        }
        if current == target:
            return {"status": "no_change", **common}

        preflight_id = "github-repository-preflight:" + secrets.token_urlsafe(18)
        approval_id = "github-repository-approval:" + secrets.token_urlsafe(18)
        expires_at = float(self._clock()) + self._approval_ttl_seconds
        confirmation = (
            f"Set GitHub repository {identity.owner}/{identity.repository} visibility "
            f"from {current} to {target} for workspace {workspace} using preflight {preflight_id}."
        )
        self._preflights[preflight_id] = _VisibilityPreflight(
            preflight_id=preflight_id,
            approval_id=approval_id,
            confirmation=confirmation,
            workspace_id=workspace,
            workspace_identity_hash=workspace_hash,
            owner=identity.owner,
            repository=identity.repository,
            remote_hash=identity.remote_hash,
            current_visibility=current,
            target_visibility=target,
            fingerprint=fingerprint,
            expires_at=expires_at,
        )
        return {
            "status": "ready",
            "preflight_id": preflight_id,
            **common,
            "approval": {
                "approval_id": approval_id,
                "confirmation": confirmation,
                "expires_at": expires_at,
                "one_shot": True,
            },
        }

    def _consume_preflight(
        self,
        *,
        workspace_id: str,
        preflight_id: object,
        approval_id: object,
        confirmation: object,
    ) -> _VisibilityPreflight:
        if not isinstance(preflight_id, str):
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "repository preflight is invalid")
        record = self._preflights.get(preflight_id)
        if record is None:
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "repository preflight is unknown or already consumed")
        if record.workspace_id != workspace_id:
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "repository preflight workspace does not match")
        if approval_id != record.approval_id or confirmation != record.confirmation:
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_INVALID", "repository approval does not match the pinned preflight")
        if float(self._clock()) >= record.expires_at:
            self._preflights.pop(preflight_id, None)
            raise GitHubRepositoryError("GITHUB_PREFLIGHT_STALE", "repository preflight approval has expired")
        self._preflights.pop(preflight_id, None)
        return record

    def _unknown_outcome(self, record: _VisibilityPreflight, *, reason: str) -> dict[str, object]:
        self._ambiguity_latch.add(record.remote_hash)
        material = json.dumps(
            {"preflight_id": record.preflight_id, "fingerprint": record.fingerprint, "reason": reason},
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "status": "outcome_unknown",
            "retry_safe": False,
            "operation": "set_visibility",
            "repository": f"{record.owner}/{record.repository}",
            "remote_identity_hash": record.remote_hash,
            "target_visibility": record.target_visibility,
            "receipt_id": "github-repository-receipt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
            "external_execution": True,
        }

    def apply(
        self,
        root: Path,
        *,
        workspace_id: str,
        preflight_id: str,
        approval_id: str,
        confirmation: str,
    ) -> dict[str, object]:
        workspace = self._validate_workspace_id(workspace_id)
        record = self._consume_preflight(
            workspace_id=workspace,
            preflight_id=preflight_id,
            approval_id=approval_id,
            confirmation=confirmation,
        )
        identity = self._git_remote_identity(root)
        if (
            identity.remote_hash != record.remote_hash
            or identity.owner != record.owner
            or identity.repository != record.repository
            or self._workspace_identity(root, workspace) != record.workspace_identity_hash
        ):
            raise GitHubRepositoryError(
                "GITHUB_REPOSITORY_MISMATCH",
                "registered repository identity changed after preflight",
            )
        repository = self._repository_metadata(identity)
        if repository["visibility"] != record.current_visibility:
            raise GitHubRepositoryError(
                "GITHUB_PREFLIGHT_STALE",
                "repository visibility changed after preflight",
            )
        try:
            status, _raw = self._request(
                "PATCH",
                f"/repos/{identity.owner}/{identity.repository}",
                body={"visibility": record.target_visibility},
            )
        except GitHubRepositoryError as exc:
            if exc.code == "GITHUB_NETWORK_UNAVAILABLE":
                return self._unknown_outcome(record, reason="mutation_network_ambiguous")
            raise GitHubRepositoryError(
                "GITHUB_VISIBILITY_UPDATE_FAILED",
                "repository visibility update failed",
            ) from None
        if not 200 <= status < 300:
            raise GitHubRepositoryError(
                "GITHUB_VISIBILITY_UPDATE_FAILED",
                f"repository visibility update returned HTTP {status}",
            )
        try:
            readback = self._repository_metadata(identity)
        except GitHubRepositoryError as exc:
            if exc.code in {"GITHUB_NETWORK_UNAVAILABLE", "GITHUB_REPOSITORY_READ_FAILED", "GITHUB_PERMISSION_DENIED"}:
                return self._unknown_outcome(record, reason="readback_unavailable")
            raise
        if readback["visibility"] != record.target_visibility:
            return self._unknown_outcome(record, reason="readback_mismatch")
        self._ambiguity_latch.discard(record.remote_hash)
        material = json.dumps(
            {
                "fingerprint": record.fingerprint,
                "visibility": record.target_visibility,
                "remote_identity_hash": record.remote_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "status": "succeeded",
            "operation": "set_visibility",
            "repository": f"{record.owner}/{record.repository}",
            "remote_identity_hash": record.remote_hash,
            "visibility": record.target_visibility,
            "receipt_id": "github-repository-receipt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
            "external_execution": True,
        }


__all__ = [
    "GitHubCliTransport",
    "GitHubRepositoryController",
    "GitHubRepositoryError",
    "RepositoryIdentity",
    "parse_github_remote",
]
