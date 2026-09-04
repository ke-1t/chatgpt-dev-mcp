from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .browser_runtime import BrowserProfile, BrowserRuntimeManager
from .command_profiles import CommandProfileController
from .credential_slots import CredentialSlotManager, CredentialSlotPolicy
from .dependency_manager import DependencyManager
from .desktop_runtime import DesktopProfile, DesktopRuntimeManager
from .director import TaskLedger
from .director_dispatch import DirectorDispatchController, PlannedTask
from .director_revert import RevertController
from .director_review import ReviewController, ReviewReceipt
from .git_workflow import GitWorkflowController
from .github_workflow import GitHubPolicy, GitHubWorkflowController
from .runtime_policy import CommandProfile, PolicyError, parse_command_profile, validate_identifier


class PlatformConfigError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PlatformExecutionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PlatformConfig:
    command_profiles: Mapping[str, CommandProfile]
    credential_slots: Mapping[str, Mapping[str, object]]
    ecosystem_profiles: Mapping[str, str]
    audit_profiles: Mapping[str, str]
    browser_profiles: Mapping[str, Mapping[str, object]]
    desktop_profiles: Mapping[str, Mapping[str, object]]
    github: Mapping[str, object] | None


@dataclass
class PlatformBundle:
    command_profiles: CommandProfileController
    credential_slots: CredentialSlotManager
    dependencies: DependencyManager
    browsers: BrowserRuntimeManager
    desktop: DesktopRuntimeManager
    desktop_profiles: Mapping[str, DesktopProfile]
    git: GitWorkflowController
    github: GitHubWorkflowController | None
    reviews: ReviewController
    revert: RevertController
    dispatch: DirectorDispatchController


def _mapping(value: object, *, field: str, maximum: int = 128) -> Mapping[str, object]:
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping) or len(value) > maximum:
        raise PlatformConfigError("PLATFORM_CONFIG_INVALID", f"{field} must be a bounded object")
    return value


def _string_list(value: object, *, field: str, maximum: int = 32) -> tuple[str, ...]:
    if value in (None, []):
        return ()
    if not isinstance(value, list) or len(value) > maximum:
        raise PlatformConfigError("PLATFORM_CONFIG_INVALID", f"{field} must be a bounded list")
    result: list[str] = []
    for item in value:
        try:
            result.append(validate_identifier(item, field=field, max_length=128))
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
    if len(set(result)) != len(result):
        raise PlatformConfigError("PLATFORM_CONFIG_INVALID", f"{field} contains duplicates")
    return tuple(result)


def parse_platform_config(raw: object) -> PlatformConfig:
    document = _mapping(raw, field="platform", maximum=16)
    allowed = {
        "command_profiles",
        "credential_slots",
        "dependencies",
        "browser_profiles",
        "desktop_profiles",
        "github",
    }
    if set(document) - allowed:
        raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "platform contains unknown keys")

    profiles: dict[str, CommandProfile] = {}
    for identifier, value in _mapping(document.get("command_profiles"), field="command_profiles").items():
        try:
            profiles[str(identifier)] = parse_command_profile(str(identifier), value if isinstance(value, Mapping) else {})
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc

    slots: dict[str, Mapping[str, object]] = {}
    for identifier, value in _mapping(document.get("credential_slots"), field="credential_slots", maximum=64).items():
        try:
            slot_id = validate_identifier(identifier, field="credential slot", max_length=80)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
        spec = _mapping(value, field=f"credential_slots.{slot_id}", maximum=8)
        if set(spec) - {"source_kind", "source_name", "allowed_profiles"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "credential slot contains unknown keys")
        source_kind, source_name = spec.get("source_kind"), spec.get("source_name")
        if source_kind not in {"env", "keychain"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "credential slot source_kind is invalid")
        try:
            source = validate_identifier(source_name, field="credential source", max_length=128)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
        allowed_profiles = _string_list(spec.get("allowed_profiles"), field="allowed_profiles", maximum=32)
        if not allowed_profiles:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "credential slot requires allowed_profiles")
        slots[slot_id] = {"source_kind": source_kind, "source_name": source, "allowed_profiles": allowed_profiles}

    dependency = _mapping(document.get("dependencies"), field="dependencies", maximum=4)
    if set(dependency) - {"ecosystem_profiles", "audit_profiles"}:
        raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "dependencies contains unknown keys")
    ecosystems: dict[str, str] = {}
    for key, value in _mapping(dependency.get("ecosystem_profiles"), field="ecosystem_profiles", maximum=16).items():
        if key not in {"python:add", "python:remove", "node:add", "node:remove", "rust:add", "rust:remove"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "dependency ecosystem profile key is invalid")
        try:
            ecosystems[str(key)] = validate_identifier(value, field="command profile", max_length=80)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
    audits: dict[str, str] = {}
    for key, value in _mapping(dependency.get("audit_profiles"), field="audit_profiles", maximum=8).items():
        if key not in {"python", "node", "rust"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "dependency audit profile key is invalid")
        try:
            audits[str(key)] = validate_identifier(value, field="command profile", max_length=80)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc

    browser_specs: dict[str, Mapping[str, object]] = {}
    for identifier, value in _mapping(document.get("browser_profiles"), field="browser_profiles", maximum=32).items():
        try:
            profile_id = validate_identifier(identifier, field="browser profile", max_length=80)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
        spec = _mapping(value, field=f"browser_profiles.{profile_id}", maximum=8)
        if set(spec) - {"allowed_origins", "viewport_width", "viewport_height", "max_screenshot_bytes"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "browser profile contains unknown keys")
        origins = spec.get("allowed_origins")
        if not isinstance(origins, list) or not origins or len(origins) > 16 or any(not isinstance(item, str) for item in origins):
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "browser allowed_origins is invalid")
        browser_specs[profile_id] = dict(spec)

    desktop_specs: dict[str, Mapping[str, object]] = {}
    for identifier, value in _mapping(document.get("desktop_profiles"), field="desktop_profiles", maximum=32).items():
        try:
            profile_id = validate_identifier(identifier, field="desktop profile", max_length=80)
        except PolicyError as exc:
            raise PlatformConfigError(exc.code, str(exc)) from exc
        spec = _mapping(value, field=f"desktop_profiles.{profile_id}", maximum=8)
        if set(spec) - {"command_profile", "data_dir_id", "health_url", "bundle_id", "max_screenshot_bytes"}:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop profile contains unknown keys")
        has_capture = bool(spec.get("bundle_id"))
        has_launch = spec.get("command_profile") is not None or spec.get("data_dir_id") is not None
        if has_capture and has_launch:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop profile cannot mix launch and capture-only fields")
        if not has_capture:
            for key in ("command_profile", "data_dir_id"):
                try:
                    validate_identifier(spec.get(key), field=key, max_length=80)
                except PolicyError as exc:
                    raise PlatformConfigError(exc.code, str(exc)) from exc
        else:
            bundle_id = spec.get("bundle_id")
            if not isinstance(bundle_id, str) or not bundle_id or len(bundle_id) > 160:
                raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop bundle_id is invalid")
            maximum = spec.get("max_screenshot_bytes", 8 * 1024 * 1024)
            if isinstance(maximum, bool) or not isinstance(maximum, int) or not 64 * 1024 <= maximum <= 16 * 1024 * 1024:
                raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop screenshot byte bound is invalid")
        health_url = spec.get("health_url", "")
        if not isinstance(health_url, str) or len(health_url) > 2048:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop health_url is invalid")
        desktop_specs[profile_id] = dict(spec)

    github_raw = document.get("github")
    github = None if github_raw in (None, {}) else dict(_mapping(github_raw, field="github", maximum=16))
    if github is not None:
        allowed_github = {
            "owner", "repository", "remote_name", "remote_host", "api_origin", "credential_slot",
            "auth_required", "allowed_base_branches", "required_checks", "required_approvals",
            "merge_method", "merge_queue_required", "enforce_branch_protection",
        }
        if set(github) - allowed_github:
            raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "github policy contains unknown keys")

    return PlatformConfig(profiles, slots, ecosystems, audits, browser_specs, desktop_specs, github)


def _cache_root() -> Path:
    configured = os.environ.get("LOCAL_DEV_MCP_DATA_DIR", "").strip()
    root = Path(configured).expanduser() if configured else Path.home() / ".cache" / "local-dev-mcp"
    return root.resolve(strict=False) / "platform"


def build_platform_bundle(
    config: PlatformConfig,
    *,
    project_id: str,
    ledger: TaskLedger,
    dispatch_claim_allocator: Callable[[PlannedTask, str], Mapping[str, object]] | None = None,
    dispatch_claim_compensator: Callable[[PlannedTask, str, Mapping[str, object]], None] | None = None,
    review_records: Iterable[Mapping[str, object]] = (),
    review_on_change: Callable[[ReviewReceipt], None] | None = None,
) -> PlatformBundle:
    slot_policies = [
        CredentialSlotPolicy(
            slot=slot_id,
            source_kind=str(spec["source_kind"]),
            source_name=str(spec["source_name"]),
            allowed_profiles=tuple(spec["allowed_profiles"]),
            allowed_projects=(project_id,),
        )
        for slot_id, spec in config.credential_slots.items()
    ]
    slots = CredentialSlotManager(slot_policies)
    commands = CommandProfileController(config.command_profiles, credential_slots=slots)
    dependencies = DependencyManager(commands, ecosystem_profiles=config.ecosystem_profiles, audit_profiles=config.audit_profiles)
    browser_profiles = {
        identifier: BrowserProfile(
            identifier,
            tuple(str(item) for item in spec["allowed_origins"]),
            int(spec.get("viewport_width", 1280)),
            int(spec.get("viewport_height", 720)),
            int(spec.get("max_screenshot_bytes", 8 * 1024 * 1024)),
        )
        for identifier, spec in config.browser_profiles.items()
    }
    browsers = BrowserRuntimeManager(browser_profiles, cache_root=_cache_root() / "browser")
    desktop_profiles: dict[str, DesktopProfile] = {}
    for identifier, spec in config.desktop_profiles.items():
        if spec.get("bundle_id"):
            desktop_profiles[identifier] = DesktopProfile(
                identifier,
                health_url=str(spec.get("health_url", "")),
                bundle_id=str(spec["bundle_id"]),
                max_screenshot_bytes=int(spec.get("max_screenshot_bytes", 8 * 1024 * 1024)),
            )
        else:
            command_id = str(spec["command_profile"])
            command = config.command_profiles.get(command_id)
            if command is None:
                raise PlatformConfigError("PLATFORM_CONFIG_INVALID", "desktop profile references an unknown command profile")
            desktop_profiles[identifier] = DesktopProfile(
                identifier,
                command,
                str(spec["data_dir_id"]),
                str(spec.get("health_url", "")),
                False,
            )
    desktop = DesktopRuntimeManager(desktop_profiles, cache_root=_cache_root() / "desktop")
    github_controller: GitHubWorkflowController | None = None
    if config.github is not None:
        github_controller = GitHubWorkflowController(GitHubPolicy(**dict(config.github)), credential_slots=slots)
    return PlatformBundle(
        commands,
        slots,
        dependencies,
        browsers,
        desktop,
        desktop_profiles,
        GitWorkflowController(),
        github_controller,
        ReviewController(review_records, on_change=review_on_change),
        RevertController(),
        DirectorDispatchController(
            ledger,
            claim_allocator=dispatch_claim_allocator,
            claim_compensator=dispatch_claim_compensator,
        ),
    )


def _controller_call(callback: Any, *args: object, **kwargs: object) -> Any:
    try:
        return callback(*args, **kwargs)
    except ValueError as exc:
        raise PlatformExecutionError(str(getattr(exc, "code", "PLATFORM_RUNTIME_ERROR")), str(exc)) from exc


def call_platform_tool(
    bundle: PlatformBundle,
    name: str,
    *,
    root: Path,
    workspace_id: str,
    working_tree_id: str,
    managed_isolated: bool,
    args: Mapping[str, Any],
    ledger: TaskLedger,
) -> dict[str, object]:
    if name == "command_profile_list":
        return {"profiles": bundle.command_profiles.list_profiles(), "external_execution": False}
    if name == "command_profile_preflight":
        return _controller_call(
            bundle.command_profiles.preflight,
            root,
            str(args.get("profile_id", "")),
            args.get("arguments", {}),
            project_id=workspace_id,
            credential_grants=tuple(args.get("credential_grant_ids", [])),
        )
    if name == "command_profile_run":
        return _controller_call(bundle.command_profiles.run, root, str(args.get("preflight_id", "")))
    if name == "credential_slot_list":
        return {"slots": bundle.credential_slots.list_slots(project_id=workspace_id), "external_execution": False}
    if name == "credential_slot_preflight":
        return _controller_call(
            bundle.credential_slots.preflight,
            str(args.get("slot_id", "")),
            project_id=workspace_id,
            command_profile=str(args.get("profile_id", "")),
        )
    if name == "dependency_change_preflight":
        return _controller_call(
            bundle.dependencies.preflight,
            root,
            project_id=workspace_id,
            action=str(args.get("action", "")),
            package=str(args.get("package", "")),
            version=str(args.get("version", "")),
        )
    if name == "dependency_apply":
        return _controller_call(bundle.dependencies.apply, root, str(args.get("preflight_id", "")))
    if name == "dependency_audit":
        return _controller_call(bundle.dependencies.audit, root, project_id=workspace_id)
    if name == "git_workflow_preflight":
        return _controller_call(
            bundle.git.preflight,
            root,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            operation=str(args.get("operation", "")),
            params=args.get("params", {}),
            managed_isolated=managed_isolated,
        )
    if name == "git_workflow_apply":
        return _controller_call(
            bundle.git.apply,
            root,
            preflight_id=str(args.get("preflight_id", "")),
            approval_token=str(args.get("approval_id", "")),
            confirmation=str(args.get("confirmation", "")),
        )
    if name == "github_workflow_read":
        if bundle.github is None:
            raise PlatformExecutionError("PLATFORM_FEATURE_UNAVAILABLE", "GitHub workflow is not configured for this workspace")
        return _controller_call(
            bundle.github.read,
            root,
            project_id=workspace_id,
            action=str(args.get("action", "")),
            number=int(args.get("number", 0)),
            credential_grant_id=str(args.get("credential_grant_id", "")),
        )
    if name == "github_workflow_preflight":
        if bundle.github is None:
            raise PlatformExecutionError("PLATFORM_FEATURE_UNAVAILABLE", "GitHub workflow is not configured for this workspace")
        return _controller_call(
            bundle.github.preflight,
            root,
            workspace_id=workspace_id,
            project_id=workspace_id,
            operation=str(args.get("operation", "")),
            params=args.get("params", {}),
            credential_grant_id=str(args.get("credential_grant_id", "")),
        )
    if name == "github_workflow_apply":
        if bundle.github is None:
            raise PlatformExecutionError("PLATFORM_FEATURE_UNAVAILABLE", "GitHub workflow is not configured for this workspace")
        return _controller_call(
            bundle.github.apply,
            str(args.get("preflight_id", "")),
            project_id=workspace_id,
            approval_id=str(args.get("approval_id", "")),
            confirmation=str(args.get("confirmation", "")),
        )
    if name == "browser_test_session":
        action = str(args.get("action", ""))
        if action == "profiles":
            return {"profiles": bundle.browsers.list_profiles(), "external_execution": False}
        if action == "start":
            return _controller_call(bundle.browsers.start, project_id=workspace_id, profile_id=str(args.get("profile_id", "")))
        if action == "close":
            return _controller_call(bundle.browsers.close, str(args.get("browser_session_id", "")))
        raise PlatformExecutionError("BROWSER_ACTION_INVALID", "browser session action is invalid")
    if name == "browser_inspect":
        return _controller_call(
            bundle.browsers.inspect,
            str(args.get("browser_session_id", "")),
            str(args.get("kind", "")),
            baseline_id=str(args.get("baseline_id", "")),
            threshold=float(args.get("threshold", 0.01)),
        )
    if name == "browser_action":
        return _controller_call(
            bundle.browsers.action,
            str(args.get("browser_session_id", "")),
            str(args.get("action", "")),
            args.get("params", {}),
        )
    if name == "desktop_runtime":
        action = str(args.get("action", ""))
        if action == "profiles":
            profiles = [
                {
                    "profile": profile.identifier,
                    "mode": "capture_only" if profile.capture_only else "managed_process",
                    "command_profile": profile.command.identifier if profile.command is not None else None,
                    "data_dir_id": profile.data_dir_id or None,
                    "bundle_id": profile.bundle_id or None,
                    "health_configured": bool(profile.health_url),
                    "auto_restart": False,
                }
                for profile in sorted(bundle.desktop_profiles.values(), key=lambda item: item.identifier)
            ]
            return {"profiles": profiles, "external_execution": False}
        if action == "start":
            profile_id = str(args.get("profile_id", ""))
            profile = bundle.desktop_profiles.get(profile_id)
            if profile is None:
                raise PlatformExecutionError("DESKTOP_PROFILE_UNKNOWN", "desktop profile is not registered")
            if profile.capture_only:
                raise PlatformExecutionError("DESKTOP_CAPTURE_ONLY", "capture-only desktop profile cannot start a managed process")
            grants = tuple(args.get("credential_grant_ids", []))
            child_environment: dict[str, str] = {}
            redact_values: tuple[str, ...] = ()
            if grants:
                child_environment, redact_values = _controller_call(
                    bundle.credential_slots.consume_grants,
                    grants,
                    project_id=workspace_id,
                    command_profile=profile.command.identifier if profile.command is not None else "",
                )
            return _controller_call(
                bundle.desktop.start,
                root,
                project_id=workspace_id,
                worktree_id=working_tree_id,
                revision=str(args.get("revision", "")),
                profile_id=profile_id,
                child_environment=child_environment,
                redact_values=redact_values,
            )
        instance_id = str(args.get("instance_id", ""))
        if action == "status":
            return _controller_call(bundle.desktop.status, instance_id)
        if action == "logs":
            return _controller_call(bundle.desktop.logs, instance_id, max_bytes=int(args.get("max_bytes", 65536)))
        if action == "snapshot":
            if instance_id:
                return _controller_call(bundle.desktop.snapshot, instance_id)
            profile_id = str(args.get("profile_id", ""))
            if profile_id:
                return _controller_call(bundle.desktop.capture_profile, root, profile_id)
            raise PlatformExecutionError("DESKTOP_SNAPSHOT_TARGET_REQUIRED", "desktop snapshot requires instance_id or capture-only profile_id")
        if action == "stop":
            return _controller_call(bundle.desktop.stop, instance_id)
        raise PlatformExecutionError("DESKTOP_ACTION_INVALID", "desktop runtime action is invalid")
    if name == "director_review":
        action = str(args.get("action", ""))
        task_id = str(args.get("task_id", ""))
        if action == "list":
            return {"reviews": [item.as_dict() for item in bundle.reviews.list(task_id=task_id)], "external_execution": False}
        if action in {"record", "readiness"}:
            task = ledger.get(task_id)
            if task.workspace_id != workspace_id:
                raise PlatformExecutionError("REVIEW_WORKSPACE_MISMATCH", "review task belongs to another workspace")
            if action == "record":
                receipt = _controller_call(
                    bundle.reviews.record,
                    task,
                    reviewer_owner=str(args.get("reviewer_id", "")),
                    base_revision=str(args.get("base_revision", "")),
                    diff_hash=str(args.get("diff_hash", "")),
                    reviewed_paths=args.get("reviewed_paths", []),
                    findings=args.get("findings", []),
                )
                return {"review": receipt.as_dict(), "external_execution": False}
            return _controller_call(
                bundle.reviews.readiness,
                task,
                diff_hash=str(args.get("diff_hash", "")),
                require_independent=bool(args.get("require_independent", True)),
            )
        if action == "remediate":
            receipt = _controller_call(
                bundle.reviews.create_remediation,
                ledger,
                str(args.get("receipt_id", "")),
                request_id=str(args.get("request_id", "")),
                title=str(args.get("title", "")),
            )
            if receipt.workspace_id != workspace_id:
                raise PlatformExecutionError("REVIEW_WORKSPACE_MISMATCH", "remediation task belongs to another workspace")
            return {"task": receipt.as_dict(), "external_execution": False}
        raise PlatformExecutionError("REVIEW_ACTION_INVALID", "review action is invalid")
    if name == "patch_revert_preflight":
        return _controller_call(bundle.revert.preflight, str(args.get("patch_id", "")))
    if name == "patch_revert":
        return _controller_call(
            bundle.revert.apply,
            str(args.get("preflight_id", "")),
            approval_id=str(args.get("approval_id", "")),
            confirmation=str(args.get("confirmation", "")),
        )
    if name == "director_plan_work":
        plan = _controller_call(
            bundle.dispatch.plan_work,
            request_id=str(args.get("request_id", "")),
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            base_revision=str(args.get("base_revision", "")),
            tasks=args.get("tasks", []),
            max_concurrency=int(args.get("max_concurrency", 3)),
        )
        return {"plan": plan.as_dict(), "external_execution": False}
    if name == "director_claim_task":
        return _controller_call(bundle.dispatch.claim_task, plan_id=str(args.get("plan_id", "")), owner_id=str(args.get("owner_id", "")))
    if name == "director_dispatch_status":
        return _controller_call(bundle.dispatch.status, str(args.get("plan_id", "")))
    raise PlatformExecutionError("PLATFORM_TOOL_UNKNOWN", "platform tool is not registered")
