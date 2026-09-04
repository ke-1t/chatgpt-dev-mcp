"""Persistent task-graph planning and atomic ready-task claiming."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
import re
import threading
import time
import uuid
from typing import Callable, Iterable, Mapping, Sequence

from .director import TaskLedger, TaskReceipt, normalize_relative_path, normalize_resource_id
from .development_loop import DevelopmentLoopState


class DispatchError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PlannedTask:
    local_id: str
    task_id: str
    title: str
    kind: str
    dependencies: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    resources: tuple[str, ...]
    requires: tuple[str, ...]
    batch: int


@dataclass(frozen=True)
class DispatchPlan:
    plan_id: str
    request_id: str
    workspace_id: str
    working_tree_id: str
    base_revision: str
    max_concurrency: int
    tasks: tuple[PlannedTask, ...]
    created_at: float

    def as_dict(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "base_revision": self.base_revision,
            "max_concurrency": self.max_concurrency,
            "tasks": [task.__dict__ for task in self.tasks],
            "integration_order": [task.task_id for task in sorted(self.tasks, key=lambda item: (item.batch, item.local_id))],
            "hosted_chat_creation": False,
            "created_at": self.created_at,
        }


def _identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
        raise DispatchError("DISPATCH_IDENTIFIER_INVALID", f"{field} is invalid")
    return value


def _path_conflict(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


class DirectorDispatchController:
    def __init__(
        self,
        ledger: TaskLedger,
        *,
        on_change: Callable[[DispatchPlan], None] | None = None,
        claim_allocator: Callable[[PlannedTask, str], Mapping[str, object]] | None = None,
        claim_compensator: Callable[[PlannedTask, str, Mapping[str, object]], None] | None = None,
    ) -> None:
        self._ledger = ledger
        self._plans: dict[str, DispatchPlan] = {}
        self._task_plan: dict[str, str] = {}
        self._on_change = on_change
        self._claim_allocator = claim_allocator
        self._claim_compensator = claim_compensator
        self._lock = threading.RLock()

    @staticmethod
    def _validate_specs(raw_tasks: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
        if not isinstance(raw_tasks, Sequence) or isinstance(raw_tasks, (str, bytes)) or not 1 <= len(raw_tasks) <= 64:
            raise DispatchError("DISPATCH_TASKS_INVALID", "task plan must contain between one and sixty-four tasks")
        parsed: list[dict[str, object]] = []
        seen: set[str] = set()
        for raw in raw_tasks:
            if not isinstance(raw, Mapping) or set(raw) - {"id", "title", "kind", "depends_on", "paths", "resources", "requires"}:
                raise DispatchError("DISPATCH_TASK_INVALID", "task spec contains unsupported fields")
            local_id = _identifier(raw.get("id"), field="task id")
            if local_id in seen:
                raise DispatchError("DISPATCH_TASK_INVALID", "task ids must be unique")
            seen.add(local_id)
            title = raw.get("title")
            if not isinstance(title, str) or not title.strip() or len(title) > 240:
                raise DispatchError("DISPATCH_TASK_INVALID", "task title is invalid")
            kind = raw.get("kind", "implementation")
            if kind not in {"implementation", "verification", "review", "security", "integration", "cleanup"}:
                raise DispatchError("DISPATCH_TASK_INVALID", "task kind is invalid")
            dependencies = tuple(_identifier(item, field="dependency") for item in raw.get("depends_on", ()))
            paths = tuple(normalize_relative_path(item) for item in raw.get("paths", ()))
            resources = tuple(normalize_resource_id(item) for item in raw.get("resources", ()))
            requires = tuple(_identifier(item, field="requirement") for item in raw.get("requires", ()))
            if len(set(dependencies)) != len(dependencies) or len(set(paths)) != len(paths) or len(set(resources)) != len(resources) or len(set(requires)) != len(requires):
                raise DispatchError("DISPATCH_TASK_INVALID", "task dependencies/paths/resources must be unique")
            parsed.append({"id": local_id, "title": title.strip(), "kind": kind, "depends_on": dependencies, "paths": paths, "resources": resources, "requires": requires})
        for item in parsed:
            if item["id"] in item["depends_on"] or any(dep not in seen for dep in item["depends_on"]):
                raise DispatchError("DISPATCH_DEPENDENCY_INVALID", "dependency references are invalid")
        return parsed

    @staticmethod
    def _topological(parsed: Sequence[Mapping[str, object]]) -> list[str]:
        dependencies = {str(item["id"]): set(item["depends_on"]) for item in parsed}
        order: list[str] = []
        ready = sorted(key for key, values in dependencies.items() if not values)
        while ready:
            current = ready.pop(0)
            order.append(current)
            for key in sorted(dependencies):
                values = dependencies[key]
                if current in values:
                    values.remove(current)
                    if not values and key not in order and key not in ready:
                        ready.append(key)
                        ready.sort()
        if len(order) != len(parsed):
            raise DispatchError("DISPATCH_DEPENDENCY_CYCLE", "task graph contains a dependency cycle")
        return order

    @staticmethod
    def _batch_map(parsed: Sequence[Mapping[str, object]], order: Sequence[str], max_concurrency: int) -> dict[str, int]:
        by_id = {str(item["id"]): item for item in parsed}
        batches: dict[int, list[str]] = {}
        assigned: dict[str, int] = {}
        for local_id in order:
            item = by_id[local_id]
            dependencies = tuple(str(dep) for dep in item["depends_on"])
            candidate = max((assigned[dep] + 1 for dep in dependencies), default=0)
            while True:
                members = batches.get(candidate, [])
                if len(members) >= max_concurrency:
                    candidate += 1
                    continue
                conflict = False
                for member_id in members:
                    other = by_id[member_id]
                    if set(item["resources"]) & set(other["resources"]):
                        conflict = True
                        break
                if conflict:
                    candidate += 1
                    continue
                break
            assigned[local_id] = candidate
            batches.setdefault(candidate, []).append(local_id)
        return assigned

    def plan_work(
        self,
        *,
        request_id: str,
        workspace_id: str,
        working_tree_id: str,
        base_revision: str,
        tasks: Sequence[Mapping[str, object]],
        max_concurrency: int = 3,
    ) -> DispatchPlan:
        request = _identifier(request_id, field="request id")
        if not isinstance(working_tree_id, str) or not working_tree_id or len(working_tree_id) > 160:
            raise DispatchError("DISPATCH_WORKTREE_INVALID", "working tree identity is required")
        if not re.fullmatch(r"[0-9a-f]{40}", base_revision or ""):
            raise DispatchError("DISPATCH_BASE_INVALID", "base revision must be a full commit id")
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or not 1 <= max_concurrency <= 6:
            raise DispatchError("DISPATCH_CONCURRENCY_INVALID", "max concurrency must be between one and six")
        parsed = self._validate_specs(tasks)
        order = self._topological(parsed)
        batches = self._batch_map(parsed, order, max_concurrency)
        by_id = {str(item["id"]): item for item in parsed}
        task_ids: dict[str, str] = {}
        planned: list[PlannedTask] = []
        for local_id in order:
            item = by_id[local_id]
            child_request = f"{request}-{local_id}"
            if len(child_request) > 120:
                raise DispatchError("DISPATCH_IDENTIFIER_INVALID", "request/task id combination is too long")
            receipt = self._ledger.enqueue(
                child_request,
                workspace_id,
                str(item["title"]),
                # The plan's tree is planning context only. Execution must be
                # bound to a fresh allocator result at claim time; retaining
                # the selected session here lets queued tasks impersonate it.
                working_tree_id="",
                allowed_paths=item["paths"],
                resources=item["resources"],
                depends_on=tuple(task_ids[dep] for dep in item["depends_on"]),
                base_revision=base_revision,
            )
            task_ids[local_id] = receipt.task_id
            planned.append(PlannedTask(
                local_id,
                receipt.task_id,
                str(item["title"]),
                str(item["kind"]),
                tuple(task_ids[dep] for dep in item["depends_on"]),
                tuple(item["paths"]),
                tuple(item["resources"]),
                tuple(item["requires"]),
                batches[local_id],
            ))
        plan = DispatchPlan(
            "plan-" + uuid.uuid4().hex,
            request,
            workspace_id,
            working_tree_id,
            base_revision,
            max_concurrency,
            tuple(planned),
            time.time(),
        )
        with self._lock:
            self._plans[plan.plan_id] = plan
            for item in plan.tasks:
                self._task_plan[item.task_id] = plan.plan_id
            if self._on_change:
                self._on_change(plan)
        return plan

    @staticmethod
    def _active_conflict(candidate: PlannedTask, active: Iterable[TaskReceipt]) -> bool:
        for receipt in active:
            if set(candidate.resources) & set(receipt.resources):
                return True
        return False

    def _dependency_state(self, task: PlannedTask) -> tuple[bool, str]:
        for dependency in task.dependencies:
            receipt = self._ledger.get(dependency)
            if receipt.status in {"failed", "cancelled", "blocked", "stale"}:
                return False, "dependency_failed"
            if receipt.status != "succeeded":
                return False, "dependency_wait"
        return True, "ready"

    def claim_task(self, *, plan_id: str, owner_id: str, capabilities: tuple[str, ...] = ()) -> dict[str, object]:
        if not isinstance(owner_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", owner_id):
            raise DispatchError("DISPATCH_OWNER_INVALID", "claim owner is invalid")
        parsed_capabilities = tuple(_identifier(item, field="capability") for item in capabilities)
        if len(parsed_capabilities) != len(set(parsed_capabilities)):
            raise DispatchError("DISPATCH_CAPABILITIES_INVALID", "worker capabilities must be unique")
        available_capabilities = set(parsed_capabilities)
        with self._lock:
            plan = self._plans.get(plan_id)
            if plan is None:
                raise DispatchError("DISPATCH_PLAN_UNKNOWN", "dispatch plan is unknown")
            receipts = {item.task_id: self._ledger.get(item.task_id) for item in plan.tasks}
            active_receipts = [
                receipt for receipt in receipts.values()
                if receipt.status in {"leased", "running", "verifying", "review_ready"}
            ]
            if len(active_receipts) >= plan.max_concurrency:
                return {"status": "queued", "reason": "max_concurrency", "plan_id": plan_id, "task": None}
            for task in sorted(plan.tasks, key=lambda item: (item.batch, item.local_id)):
                receipt = receipts[task.task_id]
                if receipt.status not in {"queued", "ready"} or receipt.owner_id is not None:
                    continue
                if not set(task.requires) <= available_capabilities:
                    continue
                ready, reason = self._dependency_state(task)
                if not ready:
                    continue
                others = [item for item in active_receipts if item.task_id != task.task_id]
                if self._active_conflict(task, others):
                    continue
                allocation: Mapping[str, object] | None = None
                if self._claim_allocator is not None:
                    allocation = self._claim_allocator(task, owner_id)
                    try:
                        session_id = allocation.get("session_id")
                        allocated_tree_id = allocation.get("working_tree_id")
                        lease_id = allocation.get("lease_id")
                        if not all(isinstance(value, str) and value for value in (session_id, allocated_tree_id, lease_id)):
                            raise DispatchError(
                                "DISPATCH_SESSION_ALLOCATION_INVALID",
                                "claim allocator returned incomplete session or lease identity",
                            )
                        if any(
                            other.task_id != task.task_id
                            and other.status in {"leased", "running", "verifying", "review_ready"}
                            and other.working_tree_id == allocated_tree_id
                            for other in self._ledger.list(workspace_id=plan.workspace_id)
                        ):
                            raise DispatchError(
                                "DISPATCH_WORKTREE_REUSED",
                                "claim allocator returned a working tree already bound to another active task",
                            )
                        self._ledger.bind_execution(
                            task.task_id,
                            working_tree_id=allocated_tree_id,
                            development_session_id=session_id,
                            base_revision=plan.base_revision,
                            allowed_paths=task.allowed_paths,
                            resources=task.resources,
                        )
                        if receipt.status == "queued":
                            self._ledger.transition(task.task_id, "ready")
                        self._ledger.transition(
                            task.task_id,
                            "leased",
                            owner_id=owner_id,
                            lease_id=lease_id,
                        )
                    except Exception:
                        if self._claim_compensator is not None:
                            self._claim_compensator(task, owner_id, allocation)
                        raise
                try:
                    claimed = self._ledger.start(task.task_id, owner_id)
                except Exception:
                    if allocation is not None:
                        try:
                            self._ledger.rollback_claim(
                                task.task_id,
                                detail="allocator claim could not be started",
                            )
                        except Exception:
                            # The external compensator remains the final
                            # cleanup boundary when local rollback itself is
                            # unavailable.
                            pass
                        if self._claim_compensator is not None:
                            self._claim_compensator(task, owner_id, allocation)
                    raise
                allocation_payload = dict(allocation or {})
                return {
                    "status": "claimed",
                    "plan_id": plan_id,
                    "task": {
                        "task_id": claimed.task_id,
                        "title": claimed.title,
                        "kind": task.kind,
                        "owner_id": claimed.owner_id,
                        "paths": list(task.allowed_paths),
                        "resources": list(task.resources),
                        "requires": list(task.requires),
                        "dependencies": list(task.dependencies),
                        "batch": task.batch,
                        "working_tree_id": claimed.working_tree_id,
                        "development_session_id": claimed.development_session_id,
                    },
                    "session_allocation": (
                        "allocated"
                        if allocation is not None
                        else ("existing" if claimed.development_session_id else "pending_policy")
                    ),
                    **allocation_payload,
                    "external_execution": False,
                }
            blocked = any(self._dependency_state(task)[1] == "dependency_failed" for task in plan.tasks if receipts[task.task_id].status in {"queued", "ready"})
            capability_blocked = any(
                receipts[task.task_id].status in {"queued", "ready"}
                and self._dependency_state(task)[0]
                and not set(task.requires) <= available_capabilities
                for task in plan.tasks
            )
            return {
                "status": "blocked" if blocked else "queued",
                "reason": "dependency_failed" if blocked else "capability_unavailable" if capability_blocked else "no_ready_unclaimed_task",
                "plan_id": plan_id,
                "task": None,
                "external_execution": False,
            }

    def status(self, plan_id: str) -> dict[str, object]:
        plan = self._plans.get(plan_id)
        if plan is None:
            raise DispatchError("DISPATCH_PLAN_UNKNOWN", "dispatch plan is unknown")
        items: list[dict[str, object]] = []
        for task in sorted(plan.tasks, key=lambda item: (item.batch, item.local_id)):
            receipt = self._ledger.get(task.task_id)
            ready, reason = self._dependency_state(task)
            items.append({
                "task_id": task.task_id,
                "title": task.title,
                "kind": task.kind,
                "batch": task.batch,
                "status": receipt.status,
                "owner_id": receipt.owner_id,
                "ready": ready and receipt.status in {"queued", "ready"},
                "blocking_reason": "" if ready else reason,
                "development_session_id": receipt.development_session_id,
                "requires": list(task.requires),
            })
        return {
            "plan_id": plan.plan_id,
            "workspace_id": plan.workspace_id,
            "max_concurrency": plan.max_concurrency,
            "tasks": items,
            "integration_order": [task.task_id for task in sorted(plan.tasks, key=lambda item: (item.batch, item.local_id))],
            "external_execution": False,
        }

    def list_plans(self, *, workspace_id: str = "") -> list[DispatchPlan]:
        plans = list(self._plans.values())
        if workspace_id:
            plans = [item for item in plans if item.workspace_id == workspace_id]
        return sorted(plans, key=lambda item: item.created_at)


@dataclass(frozen=True)
class DirectorActionDecision:
    action: str
    status: str
    reason: str
    receipt_id: str
    loop_id: str
    task_id: str
    session_id: str
    worktree_id: str
    approval_required: bool = False
    external_execution: bool = False

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class DirectorNextAction:
    """Resolve the next local action without performing any side effect."""

    _PHASE_ACTION = {
        "IMPLEMENT": "implement",
        "FAST_VERIFY": "verification_fast",
        "REMEDIATE": "remediate",
        "QA": "browser_qa",
        "REVIEW": "independent_review",
        "FULL_VERIFY": "verification_full",
        "READY": "delivery",
        "BLOCKED": "blocked",
        "FAILED": "blocked",
    }

    @staticmethod
    def resolve(
        state: DevelopmentLoopState,
        *,
        owner_id: str,
        task_id: str,
        session_id: str,
        worktree_id: str,
        delivery_action: str = "",
    ) -> DirectorActionDecision:
        if not isinstance(state, DevelopmentLoopState):
            raise DispatchError("DIRECTOR_LOOP_INVALID", "loop state is invalid")
        identity_matches = (owner_id, task_id, session_id, worktree_id) == (state.owner_id, state.task_id, state.session_id, state.worktree_id)
        if not identity_matches:
            action, status, reason = "blocked", "blocked", "identity_mismatch"
        else:
            action = DirectorNextAction._PHASE_ACTION[state.phase]
            status = "ready"
            reason = state.stop_reason or state.phase.lower()
            if state.phase in {"BLOCKED", "FAILED"}:
                status = "blocked"
            elif state.phase == "READY" and delivery_action:
                action, reason = delivery_action, "delivery_ready"
        payload = json.dumps({"loop_id": state.loop_id, "phase": state.phase, "owner_id": owner_id, "task_id": task_id, "session_id": session_id, "worktree_id": worktree_id, "action": action, "status": status, "reason": reason, "history": [(item.event_id, item.event_fingerprint) for item in state.history]}, sort_keys=True, separators=(",", ":"))
        receipt_id = "director-action:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
        return DirectorActionDecision(action, status, reason, receipt_id, state.loop_id, state.task_id, state.session_id, state.worktree_id, approval_required=False)
