"""Independent code-review receipts and remediation planning."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import threading
import time
import uuid
from typing import Callable, Iterable, Mapping

from .director import TaskLedger, TaskReceipt, normalize_relative_path
from .development_loop import DevelopmentLoopState, LoopEvent, advance


REVIEW_CATEGORIES = frozenset({
    "correctness", "regression_risk", "security", "concurrency",
    "api_schema_compatibility", "test_coverage", "maintainability",
})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class ReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ReviewFinding:
    category: str
    severity: str
    message: str
    blocking: bool = False
    path: str = ""


@dataclass(frozen=True)
class ReviewReceipt:
    receipt_id: str
    task_id: str
    implementer_owner: str
    reviewer_owner: str
    independent: bool
    base_revision: str
    diff_hash: str
    reviewed_paths: tuple[str, ...]
    findings: tuple[ReviewFinding, ...]
    blocking: bool
    reviewed_at: float

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "implementer_owner": self.implementer_owner,
            "reviewer_owner": self.reviewer_owner,
            "independent": self.independent,
            "base_revision": self.base_revision,
            "diff_hash": self.diff_hash,
            "reviewed_paths": list(self.reviewed_paths),
            "findings": [finding.__dict__ for finding in self.findings],
            "blocking": self.blocking,
            "reviewed_at": self.reviewed_at,
        }


class ReviewController:
    def __init__(
        self,
        initial_records: Iterable[Mapping[str, object]] = (),
        *,
        on_change: Callable[[ReviewReceipt], None] | None = None,
    ) -> None:
        self._records: dict[str, ReviewReceipt] = {}
        self._task_records: dict[str, list[str]] = {}
        self._on_change = on_change
        self._lock = threading.RLock()
        self.restore(initial_records)

    @staticmethod
    def _finding(raw: Mapping[str, object]) -> ReviewFinding:
        category = raw.get("category")
        severity = raw.get("severity")
        message = raw.get("message")
        blocking = raw.get("blocking", False)
        path = raw.get("path", "")
        if category not in REVIEW_CATEGORIES or severity not in SEVERITIES:
            raise ReviewError("REVIEW_FINDING_INVALID", "finding category or severity is invalid")
        if not isinstance(message, str) or not message.strip() or len(message) > 2000:
            raise ReviewError("REVIEW_FINDING_INVALID", "finding message is invalid")
        if not isinstance(blocking, bool):
            raise ReviewError("REVIEW_FINDING_INVALID", "finding blocking flag must be boolean")
        normalized_path = normalize_relative_path(path) if path else ""
        return ReviewFinding(str(category), str(severity), message.strip(), blocking, normalized_path)

    @classmethod
    def _receipt_from_mapping(cls, raw: Mapping[str, object]) -> ReviewReceipt:
        if not isinstance(raw, Mapping):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review receipt must be an object")
        receipt_id = raw.get("receipt_id")
        task_id = raw.get("task_id")
        implementer = raw.get("implementer_owner")
        reviewer = raw.get("reviewer_owner")
        base_revision = raw.get("base_revision")
        diff_hash = raw.get("diff_hash")
        if not isinstance(receipt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", receipt_id):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review receipt id is invalid")
        if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", task_id):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review task id is invalid")
        if not isinstance(implementer, str) or not implementer or len(implementer) > 128:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored implementer owner is invalid")
        if not isinstance(reviewer, str) or not reviewer or len(reviewer) > 128:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored reviewer owner is invalid")
        if not isinstance(raw.get("independent"), bool):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored independent flag is invalid")
        if implementer == reviewer and raw["independent"]:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored independent flag is inconsistent")
        if implementer != reviewer and not raw["independent"]:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored independent flag is inconsistent")
        if not isinstance(base_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", base_revision):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review base is invalid")
        if not isinstance(diff_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", diff_hash):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review diff is invalid")
        paths = raw.get("reviewed_paths")
        if not isinstance(paths, (list, tuple)) or not paths or len(paths) > 512:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored reviewed paths are invalid")
        try:
            normalized_paths = tuple(normalize_relative_path(path) for path in paths)
        except (TypeError, ValueError) as exc:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored reviewed paths are invalid") from exc
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored reviewed paths contain duplicates")
        findings = raw.get("findings")
        if not isinstance(findings, (list, tuple)) or len(findings) > 200:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored findings are invalid")
        parsed_findings = tuple(cls._finding(item) for item in findings)
        blocking = raw.get("blocking")
        if not isinstance(blocking, bool):
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored blocking flag is invalid")
        expected_blocking = any(item.blocking or item.severity in {"high", "critical"} for item in parsed_findings)
        if blocking != expected_blocking:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored blocking flag is inconsistent")
        try:
            reviewed_at = float(raw.get("reviewed_at"))
        except (TypeError, ValueError) as exc:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review timestamp is invalid") from exc
        if not math.isfinite(reviewed_at) or reviewed_at <= 0:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review timestamp is invalid")
        return ReviewReceipt(
            receipt_id,
            task_id,
            implementer,
            reviewer,
            bool(raw["independent"]),
            base_revision,
            diff_hash,
            normalized_paths,
            parsed_findings,
            blocking,
            reviewed_at,
        )

    def restore(self, records: Iterable[Mapping[str, object]]) -> None:
        if records is None:
            return
        try:
            values = tuple(records)
        except TypeError as exc:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review records are not iterable") from exc
        if len(values) > 512:
            raise ReviewError("REVIEW_RECEIPT_INVALID", "stored review records exceed the safety bound")
        with self._lock:
            for raw in values:
                receipt = self._receipt_from_mapping(raw)
                existing = self._records.get(receipt.receipt_id)
                if existing is not None:
                    if existing != receipt:
                        raise ReviewError("REVIEW_RECEIPT_INVALID", "duplicate review receipt id has different content")
                    continue
                self._records[receipt.receipt_id] = receipt
                self._task_records.setdefault(receipt.task_id, []).append(receipt.receipt_id)

    def record(
        self,
        task: TaskReceipt,
        *,
        reviewer_owner: str,
        base_revision: str,
        diff_hash: str,
        reviewed_paths: Iterable[str],
        findings: Iterable[Mapping[str, object]],
    ) -> ReviewReceipt:
        if not isinstance(reviewer_owner, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", reviewer_owner):
            raise ReviewError("REVIEWER_INVALID", "reviewer owner is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", base_revision or ""):
            raise ReviewError("REVIEW_BASE_INVALID", "review base must be a full commit id")
        if not re.fullmatch(r"[0-9a-f]{64}", diff_hash or ""):
            raise ReviewError("REVIEW_DIFF_INVALID", "review diff hash must be sha256")
        if task.base_revision and task.base_revision != base_revision:
            raise ReviewError("REVIEW_STALE_BASE", "task base revision no longer matches the review")
        if task.patch_hash and task.patch_hash != diff_hash:
            raise ReviewError("REVIEW_STALE_DIFF", "task diff hash no longer matches the review")
        paths = tuple(normalize_relative_path(path) for path in reviewed_paths)
        if not paths or len(paths) > 512 or len(set(paths)) != len(paths):
            raise ReviewError("REVIEW_PATHS_INVALID", "reviewed paths are empty, duplicated, or too large")
        parsed_findings = tuple(self._finding(item) for item in findings)
        if len(parsed_findings) > 200:
            raise ReviewError("REVIEW_FINDINGS_TOO_LARGE", "review findings exceed the safety bound")
        implementer = task.owner_id or "unassigned"
        independent = implementer != reviewer_owner
        blocking = any(item.blocking or item.severity in {"high", "critical"} for item in parsed_findings)
        receipt = ReviewReceipt(
            "review-" + uuid.uuid4().hex,
            task.task_id,
            implementer,
            reviewer_owner,
            independent,
            base_revision,
            diff_hash,
            paths,
            parsed_findings,
            blocking,
            time.time(),
        )
        with self._lock:
            self._records[receipt.receipt_id] = receipt
            self._task_records.setdefault(task.task_id, []).append(receipt.receipt_id)
            if self._on_change:
                try:
                    self._on_change(receipt)
                except Exception as exc:
                    self._records.pop(receipt.receipt_id, None)
                    task_receipts = self._task_records.get(task.task_id, [])
                    if receipt.receipt_id in task_receipts:
                        task_receipts.remove(receipt.receipt_id)
                    if not task_receipts:
                        self._task_records.pop(task.task_id, None)
                    if isinstance(exc, ReviewError):
                        raise
                    raise ReviewError("REVIEW_PERSISTENCE_FAILED", "review receipt could not be persisted") from exc
        return receipt

    def list(self, *, task_id: str = "") -> list[ReviewReceipt]:
        with self._lock:
            if task_id:
                return [self._records[item] for item in self._task_records.get(task_id, []) if item in self._records]
            return sorted(self._records.values(), key=lambda item: item.reviewed_at)

    def readiness(self, task: TaskReceipt, *, diff_hash: str, require_independent: bool) -> dict[str, object]:
        reviews = [item for item in self.list(task_id=task.task_id) if item.diff_hash == diff_hash]
        current = reviews[-1] if reviews else None
        if current is None:
            return {"ready": False, "reason": "review_missing", "independent_required": require_independent}
        if current.blocking:
            return {"ready": False, "reason": "blocking_findings", "review": current.as_dict()}
        if require_independent and not current.independent:
            return {"ready": False, "reason": "independent_review_required", "review": current.as_dict()}
        return {"ready": True, "reason": "review_current", "review": current.as_dict()}

    def create_remediation(self, ledger: TaskLedger, receipt_id: str, *, request_id: str, title: str) -> TaskReceipt:
        receipt = self._records.get(receipt_id)
        if receipt is None:
            raise ReviewError("REVIEW_RECEIPT_UNKNOWN", "review receipt is unknown")
        blocking_paths = tuple(sorted({item.path for item in receipt.findings if item.blocking and item.path}))
        allowed_paths = blocking_paths or receipt.reviewed_paths
        return ledger.enqueue(
            request_id,
            ledger.get(receipt.task_id).workspace_id,
            title,
            allowed_paths=allowed_paths,
            base_revision=receipt.base_revision,
        )

    def apply_to_loop(
        self,
        ledger: TaskLedger,
        receipt_id: str,
        state: DevelopmentLoopState,
        *,
        at: float,
        remediation_request_id: str = "",
        remediation_title: str = "Address blocking review findings",
    ) -> dict[str, object]:
        """Apply a current review receipt to a REVIEW loop without granting writer authority."""

        if not isinstance(ledger, TaskLedger) or not isinstance(state, DevelopmentLoopState):
            raise ReviewError("REVIEW_LOOP_INVALID", "review loop inputs are invalid")
        receipt = self._records.get(receipt_id)
        if receipt is None:
            raise ReviewError("REVIEW_RECEIPT_UNKNOWN", "review receipt is unknown")
        if receipt.task_id != state.task_id:
            raise ReviewError("REVIEW_LOOP_IDENTITY_MISMATCH", "review receipt does not belong to the loop task")
        if state.phase != "REVIEW":
            raise ReviewError("REVIEW_LOOP_PHASE_INVALID", "review evidence can only advance a REVIEW loop")
        kind = "review_blocking" if receipt.blocking else "review_passed"
        event = LoopEvent(
            event_id=f"review:{receipt.receipt_id}",
            kind=kind,
            at=at,
            failure_fingerprint=receipt.diff_hash if receipt.blocking else "",
            progress_token=receipt.receipt_id,
        )
        next_state = advance(state, event)
        remediation: TaskReceipt | None = None
        if receipt.blocking and next_state.phase == "REMEDIATE":
            request_id = remediation_request_id or f"remediate-{receipt.receipt_id}"
            remediation = self.create_remediation(ledger, receipt.receipt_id, request_id=request_id, title=remediation_title)
        return {
            "state": next_state,
            "review": receipt.as_dict(),
            "remediation_task": remediation.as_dict() if remediation is not None else None,
            "writer_authority_granted": False,
            "external_execution": False,
        }
