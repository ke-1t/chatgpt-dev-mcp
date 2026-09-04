"""Explicitly gated verification planning and receipt normalization."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal, Mapping

from .change_impact import classify_change_impact
from .director import normalize_relative_path, redact_secrets, sha256_text, validate_workspace_id
from .director_profile import ProjectProfile
from .selective_verification import VerificationSelection, VerificationSelector
from .semantic_index import SemanticIndexSnapshot
from .verification_cache import VerificationCache, VerificationCacheKey


VerificationStatus = Literal["passed", "failed", "timed_out", "skipped"]
ReceiptStatus = Literal["passed", "failed", "incomplete", "not_run", "stale"]
_MAX_OUTPUT_BYTES = 16 * 1024
_TASK_RE = re.compile(r"^(?:test|lint|build)$")
_CODE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".java", ".rb")
_BUILD_MARKERS = frozenset({"pyproject.toml", "package.json", "package-lock.json", "Cargo.toml", "go.mod"})


class VerificationError(ValueError):
    """Base class for verification planning and receipt errors."""


class VerificationSafetyError(VerificationError):
    """Raised when execution is attempted without both safety gates."""


@dataclass(frozen=True)
class VerificationPlan:
    workspace_id: str
    changed_paths: tuple[str, ...]
    tasks: tuple[str, ...]
    eligible: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "changed_paths": list(self.changed_paths),
            "tasks": list(self.tasks),
            "eligible": self.eligible,
            "reason": self.reason,
            "external_execution": False,
        }


@dataclass(frozen=True)
class VerificationResult:
    task: str
    status: VerificationStatus
    exit_code: int | None
    duration_ms: float
    output: str
    output_truncated: bool
    external_execution: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "task": self.task,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "output_truncated": self.output_truncated,
            "external_execution": self.external_execution,
        }


@dataclass(frozen=True)
class VerificationReceipt:
    workspace_id: str
    plan: VerificationPlan
    results: tuple[VerificationResult, ...]
    status: ReceiptStatus
    base_revision: str = "unknown"
    diff_hash: str = ""
    recorded_at: str = ""
    receipt_id: str = ""
    working_tree_id: str = ""

    @property
    def stale(self) -> bool:
        return self.status == "stale"

    def invalidate(self) -> "VerificationReceipt":
        from dataclasses import replace

        return replace(self, status="stale")

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "plan": self.plan.as_dict(),
            "results": [result.as_dict() for result in self.results],
            "status": self.status,
            "base_revision": self.base_revision,
            "diff_hash": self.diff_hash,
            "recorded_at": self.recorded_at,
            "receipt_id": self.receipt_id,
            "working_tree_id": self.working_tree_id,
            "stale": self.stale,
            "external_execution": False,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_output(value: object) -> tuple[str, bool]:
    if value is None:
        return "", False
    if not isinstance(value, str) or "\x00" in value:
        raise VerificationError("verification output must be text")
    redacted = redact_secrets(value)
    encoded = redacted.encode("utf-8")
    if len(encoded) <= _MAX_OUTPUT_BYTES:
        return redacted, False
    return encoded[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore"), True


def make_verification_plan(profile: ProjectProfile, changed_paths: Iterable[str]) -> VerificationPlan:
    """Select safe, non-interactive checks from a validated project profile."""

    if not isinstance(profile, ProjectProfile):
        raise VerificationError("profile must be a ProjectProfile")
    parsed_paths = tuple(normalize_relative_path(path) for path in changed_paths)
    if len(parsed_paths) != len(set(parsed_paths)):
        raise VerificationError("changed_paths must be unique")
    workspace = validate_workspace_id(profile.workspace_id)
    if profile.profile != "DEVELOPMENT":
        return VerificationPlan(workspace, parsed_paths, (), False, "PROFILE_NOT_DEVELOPMENT")

    tasks: list[str] = []
    for task in profile.verification_tasks:
        if task not in profile.commands or task not in {"test", "lint", "build"}:
            continue
        if task == "lint" and not any(path.endswith(_CODE_SUFFIXES) for path in parsed_paths):
            continue
        if task == "build" and not any(path in _BUILD_MARKERS for path in parsed_paths):
            continue
        tasks.append(task)
    if not tasks and "test" in profile.verification_tasks:
        tasks.append("test")
    if not tasks:
        return VerificationPlan(workspace, parsed_paths, (), False, "NO_VERIFICATION_TASK_CONFIGURED")
    impact = classify_change_impact(parsed_paths)
    if not impact.execution_required:
        return VerificationPlan(workspace, parsed_paths, (), True, "NO_EXECUTION_REQUIRED")
    return VerificationPlan(workspace, parsed_paths, tuple(dict.fromkeys(tasks)), True, "VERIFICATION_TASKS_SELECTED")


def normalize_verification_result(
    task: str,
    *,
    exit_code: int | None,
    output: object = "",
    duration_ms: float = 0,
    timed_out: bool = False,
) -> VerificationResult:
    if not isinstance(task, str) or not _TASK_RE.fullmatch(task):
        raise VerificationError("verification task is invalid")
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool) or not -255 <= exit_code <= 255):
        raise VerificationError("exit_code is invalid")
    if not isinstance(duration_ms, (int, float)) or isinstance(duration_ms, bool) or not 0 <= duration_ms <= 2 * 60 * 60 * 1000:
        raise VerificationError("duration_ms is invalid")
    if not isinstance(timed_out, bool):
        raise VerificationError("timed_out must be boolean")
    bounded, truncated = _bounded_output(output)
    if timed_out:
        status: VerificationStatus = "timed_out"
    elif exit_code is None:
        status = "skipped"
    elif exit_code == 0:
        status = "passed"
    else:
        status = "failed"
    return VerificationResult(task, status, exit_code, round(float(duration_ms), 2), bounded, truncated)


class VerificationPipeline:
    """Plan and optionally execute checks through an injected, isolated runner."""

    def __init__(
        self,
        profile: ProjectProfile,
        *,
        runner: Callable[[str, str], Mapping[str, Any]] | None = None,
    ) -> None:
        if not isinstance(profile, ProjectProfile):
            raise VerificationError("profile must be a ProjectProfile")
        self._profile = profile
        self._runner = runner

    def plan(self, changed_paths: Iterable[str]) -> VerificationPlan:
        return make_verification_plan(self._profile, changed_paths)

    def record(
        self,
        plan: VerificationPlan,
        results: Iterable[VerificationResult],
        *,
        base_revision: str = "unknown",
        diff_hash: str = "",
        recorded_at: str | None = None,
        working_tree_id: str = "",
    ) -> VerificationReceipt:
        if not isinstance(plan, VerificationPlan) or plan.workspace_id != self._profile.workspace_id:
            raise VerificationError("plan does not belong to this profile")
        parsed = tuple(results)
        if any(not isinstance(result, VerificationResult) for result in parsed):
            raise VerificationError("results must contain VerificationResult values")
        task_names = tuple(result.task for result in parsed)
        if len(task_names) != len(set(task_names)) or any(task not in plan.tasks for task in task_names):
            raise VerificationError("results do not match the verification plan")
        if not parsed and plan.eligible and not plan.tasks and plan.reason == "NO_EXECUTION_REQUIRED":
            status: ReceiptStatus = "passed"
        elif not parsed:
            status: ReceiptStatus = "not_run"
        elif any(result.status in {"failed", "timed_out"} for result in parsed):
            status = "failed"
        elif len(parsed) < len(plan.tasks) or any(result.status == "skipped" for result in parsed):
            status = "incomplete"
        else:
            status = "passed"
        if not isinstance(base_revision, str) or not base_revision or len(base_revision) > 128:
            raise VerificationError("base_revision is invalid")
        if diff_hash and (not isinstance(diff_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", diff_hash)):
            raise VerificationError("diff_hash is invalid")
        if not isinstance(working_tree_id, str) or len(working_tree_id) > 160 or "\x00" in working_tree_id:
            raise VerificationError("working_tree_id is invalid")
        created_at = recorded_at or _utc_now()
        if not isinstance(created_at, str) or not created_at:
            raise VerificationError("recorded_at is invalid")
        fingerprint = sha256_text(
            repr(
                (
                    self._profile.workspace_id,
                    plan.changed_paths,
                    plan.tasks,
                    tuple((result.task, result.status, result.exit_code) for result in parsed),
                    status,
                    base_revision,
                    diff_hash,
                    working_tree_id,
                )
            )
        )
        return VerificationReceipt(
            self._profile.workspace_id,
            plan,
            parsed,
            status,
            base_revision,
            diff_hash,
            created_at,
            f"verify:{fingerprint[:32]}",
            working_tree_id,
        )

    def execute(
        self,
        plan: VerificationPlan,
        *,
        isolated_workspace: bool,
        allow_execution: bool = False,
    ) -> VerificationReceipt:
        """Execute only through a caller-supplied runner after two explicit gates.

        The active MCP server does not call this method.  The gates make a later
        adapter prove both isolation and explicit execution approval rather than
        silently turning a planning feature into arbitrary command execution.
        """

        if not isolated_workspace:
            raise VerificationSafetyError("VERIFICATION_ISOLATION_REQUIRED")
        if not allow_execution:
            raise VerificationSafetyError("VERIFICATION_APPROVAL_REQUIRED")
        if not plan.eligible:
            raise VerificationError("PLAN_NOT_ELIGIBLE")
        if self._runner is None:
            raise VerificationSafetyError("VERIFICATION_RUNNER_NOT_CONFIGURED")
        results: list[VerificationResult] = []
        for task in plan.tasks:
            raw = self._runner(task, self._profile.command_for(task))
            if not isinstance(raw, Mapping):
                raise VerificationError("verification runner must return an object")
            results.append(
                normalize_verification_result(
                    task,
                    exit_code=raw.get("exit_code"),
                    output=raw.get("output", ""),
                    duration_ms=raw.get("duration_ms", 0),
                    timed_out=raw.get("timed_out", False),
                )
            )
        return self.record(plan, results)


@dataclass(frozen=True)
class VerificationRunResult:
    task: str
    status: VerificationStatus
    exit_code: int | None
    duration_ms: float
    output: str
    cache_status: str
    selected_tests: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "task": self.task,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "cache_status": self.cache_status,
            "selected_tests": list(self.selected_tests),
            "external_execution": False,
        }


@dataclass(frozen=True)
class VerificationRunReceipt:
    receipt_id: str
    task_id: str
    mode: str
    selection: VerificationSelection
    results: tuple[VerificationRunResult, ...]
    status: ReceiptStatus
    worktree_id: str
    head: str
    relevant_diff_hash: str
    pending_work_units: int = 0
    continuation_required: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "mode": self.mode,
            "selection": self.selection.as_dict(),
            "results": [item.as_dict() for item in self.results],
            "status": self.status,
            "worktree_id": self.worktree_id,
            "head": self.head,
            "relevant_diff_hash": self.relevant_diff_hash,
            "pending_work_units": self.pending_work_units,
            "continuation_required": self.continuation_required,
            "external_execution": False,
        }


class VerificationEngine:
    """FAST selective verification plus authoritative FULL verification."""

    def __init__(
        self,
        profile: ProjectProfile,
        *,
        cache: VerificationCache,
        runner: Callable[[str, tuple[str, ...]], Mapping[str, Any]],
        selector: VerificationSelector | None = None,
        full_test_shards: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        if not isinstance(profile, ProjectProfile) or not isinstance(cache, VerificationCache) or not callable(runner):
            raise VerificationError("verification engine configuration is invalid")
        if any(not shard or len(shard) != len(set(shard)) for shard in full_test_shards):
            raise VerificationError("full test shards are invalid")
        self._profile = profile
        self._cache = cache
        self._runner = runner
        self._selector = selector or VerificationSelector()
        self._full_test_shards = tuple(tuple(shard) for shard in full_test_shards)

    @staticmethod
    def _status(results: tuple[VerificationRunResult, ...]) -> ReceiptStatus:
        if not results:
            return "not_run"
        if any(item.status in {"failed", "timed_out"} for item in results):
            return "failed"
        if any(item.status == "skipped" for item in results):
            return "incomplete"
        return "passed"

    @staticmethod
    def _result_digest(task: str, status: str, exit_code: int | None, output: str) -> str:
        return sha256_text(repr((task, status, exit_code, output)))

    def _cache_key(
        self,
        *,
        task: str,
        selected_tests: tuple[str, ...],
        worktree_id: str,
        head: str,
        relevant_diff_hash: str,
        env_fingerprint: str,
        dependency_fingerprint: str,
        cache_namespace: str = "fast",
    ) -> VerificationCacheKey:
        if cache_namespace not in {"fast", "full"}:
            raise VerificationError("verification cache namespace is invalid")
        command = self._profile.command_for(task)
        command_fingerprint = sha256_text(repr((cache_namespace, task, command, selected_tests)))
        return VerificationCacheKey(
            worktree_id=worktree_id,
            head=head,
            relevant_diff_hash=relevant_diff_hash,
            command_fingerprint=command_fingerprint,
            env_fingerprint=env_fingerprint,
            dependency_fingerprint=dependency_fingerprint,
        )

    def _cached_result(
        self,
        task: str,
        selected_tests: tuple[str, ...],
        *,
        worktree_id: str,
        head: str,
        relevant_diff_hash: str,
        env_fingerprint: str,
        dependency_fingerprint: str,
        cache_namespace: str,
    ) -> VerificationRunResult | None:
        key = self._cache_key(
            task=task,
            selected_tests=selected_tests,
            worktree_id=worktree_id,
            head=head,
            relevant_diff_hash=relevant_diff_hash,
            env_fingerprint=env_fingerprint,
            dependency_fingerprint=dependency_fingerprint,
            cache_namespace=cache_namespace,
        )
        lookup = self._cache.get(key)
        if not lookup.hit or lookup.entry is None:
            return None
        entry = lookup.entry
        if cache_namespace == "full":
            # FULL may require several bounded continuation calls.  Refresh
            # exact-identity hits so early shards cannot expire while later
            # shards are still running and force the suite to start over.
            entry = self._cache.put(
                key,
                relevant_paths=entry.relevant_paths,
                status=entry.status,
                result_digest=entry.result_digest,
                output_summary=entry.output_summary,
            )
        return VerificationRunResult(
            task,
            entry.status,
            0 if entry.status == "passed" else 1 if entry.status == "failed" else None,
            0.0,
            entry.output_summary,
            "hit",
            selected_tests,
        )

    def _execute_one(
        self,
        task: str,
        selected_tests: tuple[str, ...],
        relevant_paths: tuple[str, ...],
        *,
        worktree_id: str,
        head: str,
        relevant_diff_hash: str,
        env_fingerprint: str,
        dependency_fingerprint: str,
        use_cache: bool,
        cache_namespace: str = "fast",
    ) -> VerificationRunResult:
        key = self._cache_key(task=task, selected_tests=selected_tests, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, cache_namespace=cache_namespace)
        if use_cache:
            cached = self._cached_result(task, selected_tests, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, cache_namespace=cache_namespace)
            if cached is not None:
                return cached
        raw = self._runner(task, selected_tests)
        if not isinstance(raw, Mapping):
            raise VerificationError("verification runner must return an object")
        normalized = normalize_verification_result(task, exit_code=raw.get("exit_code"), output=raw.get("output", ""), duration_ms=raw.get("duration_ms", 0), timed_out=raw.get("timed_out", False))
        if use_cache and normalized.status in {"passed", "failed", "timed_out"}:
            self._cache.put(key, relevant_paths=relevant_paths, status=normalized.status, result_digest=self._result_digest(task, normalized.status, normalized.exit_code, normalized.output), output_summary=normalized.output[:2048])
        return VerificationRunResult(task, normalized.status, normalized.exit_code, normalized.duration_ms, normalized.output, "miss" if use_cache else "bypass", selected_tests)

    def run(
        self,
        *,
        mode: str,
        task_id: str,
        changed_paths: tuple[str, ...],
        semantic_snapshot: SemanticIndexSnapshot,
        worktree_id: str,
        head: str,
        relevant_diff_hash: str,
        env_fingerprint: str,
        dependency_fingerprint: str,
    ) -> VerificationRunReceipt:
        if mode not in {"fast", "full"}:
            raise VerificationError("verification mode is invalid")
        if not isinstance(task_id, str) or not task_id:
            raise VerificationError("task_id is invalid")
        selection = self._selector.select(changed_paths, semantic_snapshot, self._profile)
        results: list[VerificationRunResult] = []
        pending_work_units = 0
        execution_free = (
            mode == "fast"
            and not selection.fallback_full
            and not selection.tests
            and "documentation_only" in selection.global_reasons
        )
        if mode == "full":
            tasks = tuple(task for task in self._profile.verification_tasks if task in self._profile.commands and task in {"test", "lint", "build"})
            for task_index, task in enumerate(tasks):
                if task == "test" and self._full_test_shards:
                    if len(self._full_test_shards) > 2:
                        resolved: dict[int, VerificationRunResult] = {}
                        missing: list[int] = []
                        for index, shard in enumerate(self._full_test_shards):
                            cached = self._cached_result(task, shard, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, cache_namespace="full")
                            if cached is None:
                                missing.append(index)
                            else:
                                resolved[index] = cached

                        execute_now = tuple(missing[:2])
                        pending_work_units += max(0, len(missing) - len(execute_now))

                        def execute_index(index: int) -> tuple[int, VerificationRunResult]:
                            shard = self._full_test_shards[index]
                            relevant = tuple(sorted(set((*changed_paths, *shard))))
                            return index, self._execute_one(task, shard, relevant, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, use_cache=True, cache_namespace="full")

                        if execute_now:
                            workers = min(2, len(execute_now))
                            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="verification-full") as executor:
                                for index, result in executor.map(execute_index, execute_now):
                                    resolved[index] = result
                        results.extend(resolved[index] for index in sorted(resolved))
                        continue

                    def execute_shard(shard: tuple[str, ...]) -> VerificationRunResult:
                        relevant = tuple(sorted(set((*changed_paths, *shard))))
                        return self._execute_one(task, shard, relevant, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, use_cache=True, cache_namespace="full")

                    workers = min(2, len(self._full_test_shards))
                    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="verification-full") as executor:
                        results.extend(executor.map(execute_shard, self._full_test_shards))
                else:
                    results.append(self._execute_one(task, (), tuple(changed_paths), worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, use_cache=True, cache_namespace="full"))
        else:
            if execution_free:
                pass
            elif selection.fallback_full:
                # FAST is intentionally bounded.  An uncertain dependency graph
                # means that FULL is required before delivery, not that a FAST
                # request may silently expand into the entire project suite.
                # Run only tests we can name defensibly and leave the receipt
                # incomplete so integration remains fail-closed until an
                # explicit FULL verification is requested.
                if selection.tests and "test" in self._profile.commands and "test" in self._profile.verification_tasks:
                    relevant = tuple(sorted(set((*changed_paths, *selection.tests))))
                    results.append(self._execute_one("test", selection.tests, relevant, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, use_cache=True))
            elif "test" in self._profile.commands and "test" in self._profile.verification_tasks:
                relevant = tuple(sorted(set((*changed_paths, *selection.tests))))
                results.append(self._execute_one("test", selection.tests, relevant, worktree_id=worktree_id, head=head, relevant_diff_hash=relevant_diff_hash, env_fingerprint=env_fingerprint, dependency_fingerprint=dependency_fingerprint, use_cache=True))
        parsed = tuple(results)
        status = "passed" if execution_free else self._status(parsed)
        if mode == "fast" and selection.fallback_full and status in {"passed", "not_run"}:
            status = "incomplete"
        if pending_work_units and status in {"passed", "not_run"}:
            status = "incomplete"
        continuation_required = pending_work_units > 0
        fingerprint = sha256_text(repr((task_id, mode, worktree_id, head, relevant_diff_hash, pending_work_units, tuple((item.task, item.status, item.cache_status, item.selected_tests) for item in parsed))))
        return VerificationRunReceipt(f"verification-run:{fingerprint[:32]}", task_id, mode, selection, parsed, status, worktree_id, head, relevant_diff_hash, pending_work_units, continuation_required)
