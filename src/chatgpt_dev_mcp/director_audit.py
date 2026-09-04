"""Fail-closed, non-secret audit reports for Director decisions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Iterable, Literal

from .director import PatchDecision, normalize_relative_path, sha256_text, validate_workspace_id
from .director_profile import ProjectProfile
from .director_verification import VerificationReceipt
from .director_watchdog import WatchdogResult


AuditSeverity = Literal["low", "medium", "high"]
AuditStatus = Literal["pass", "review", "blocked"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditFinding:
    code: str
    severity: AuditSeverity
    message: str
    blocking: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "blocking": self.blocking,
        }


@dataclass(frozen=True)
class SecurityAuditReport:
    status: AuditStatus
    findings: tuple[AuditFinding, ...]
    audited_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "findings": [finding.as_dict() for finding in self.findings],
            "audited_at": self.audited_at,
            "external_execution": False,
        }


@dataclass(frozen=True)
class SecurityAuditReceipt:
    workspace_id: str
    report: SecurityAuditReport
    base_revision: str
    diff_hash: str
    patch_hash: str
    changed_paths: tuple[str, ...]
    verification_receipt_id: str
    audited_at: str
    receipt_id: str
    stale: bool = False
    working_tree_id: str = ""

    def invalidate(self) -> "SecurityAuditReceipt":
        return replace(self, stale=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "working_tree_id": self.working_tree_id,
            "workspace_id": self.workspace_id,
            "report": self.report.as_dict(),
            "base_revision": self.base_revision,
            "diff_hash": self.diff_hash,
            "patch_hash": self.patch_hash,
            "changed_paths": list(self.changed_paths),
            "verification_receipt_id": self.verification_receipt_id,
            "audited_at": self.audited_at,
            "stale": self.stale,
            "external_execution": False,
        }


def build_security_audit_receipt(
    report: SecurityAuditReport,
    *,
    workspace_id: str = "",
    base_revision: str,
    diff_hash: str,
    patch_hash: str,
    changed_paths: Iterable[str],
    verification_receipt_id: str = "",
    audited_at: str | None = None,
    working_tree_id: str = "",
) -> SecurityAuditReceipt:
    if not isinstance(report, SecurityAuditReport):
        raise ValueError("report must be a SecurityAuditReport")
    workspace = validate_workspace_id(workspace_id) if workspace_id else ""
    if not isinstance(base_revision, str) or not base_revision or len(base_revision) > 128:
        raise ValueError("base_revision is invalid")
    for name, digest in (("diff_hash", diff_hash), ("patch_hash", patch_hash)):
        if digest and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ValueError(f"{name} is invalid")
    paths = tuple(normalize_relative_path(path) for path in changed_paths)
    if len(paths) != len(set(paths)):
        raise ValueError("changed_paths must be unique")
    if not isinstance(verification_receipt_id, str) or len(verification_receipt_id) > 128:
        raise ValueError("verification_receipt_id is invalid")
    if not isinstance(working_tree_id, str) or "\x00" in working_tree_id or len(working_tree_id) > 256:
        raise ValueError("working_tree_id is invalid")
    created_at = audited_at or _utc_now()
    fingerprint = sha256_text(
        repr(
            (
                report.status,
                workspace,
                working_tree_id,
                tuple((finding.code, finding.severity, finding.blocking) for finding in report.findings),
                base_revision,
                diff_hash,
                patch_hash,
                paths,
                verification_receipt_id,
            )
        )
    )
    return SecurityAuditReceipt(
        workspace,
        report,
        base_revision,
        diff_hash,
        patch_hash,
        paths,
        verification_receipt_id,
        created_at,
        f"audit:{fingerprint[:32]}",
        False,
        working_tree_id,
    )


def _report(findings: Iterable[AuditFinding]) -> SecurityAuditReport:
    parsed = tuple(findings)
    if any(finding.blocking and finding.severity == "high" for finding in parsed):
        status: AuditStatus = "blocked"
    elif parsed:
        status = "review"
    else:
        status = "pass"
    return SecurityAuditReport(status, parsed, _utc_now())


def audit_profile(profile: ProjectProfile) -> SecurityAuditReport:
    if not isinstance(profile, ProjectProfile):
        raise ValueError("profile must be a ProjectProfile")
    findings: list[AuditFinding] = []
    if profile.external_execution:
        findings.append(
            AuditFinding(
                "PROFILE_EXTERNAL_EXECUTION_ENABLED",
                "high",
                "Profile requests external execution and cannot be activated by the safe Director path.",
                True,
            )
        )
    if profile.profile == "DEVELOPMENT" and "test" not in profile.commands:
        findings.append(
            AuditFinding(
                "VERIFY_TEST_NOT_CONFIGURED",
                "medium",
                "DEVELOPMENT profile has no registered test command.",
                False,
            )
        )
    if "dev" in profile.commands:
        findings.append(
            AuditFinding(
                "LONG_RUNNING_TASK_NOT_AUTOMATIC",
                "medium",
                "The dev task is available for explicit use but is never selected automatically.",
                False,
            )
        )
    return _report(findings)

def audit_patch(decision: PatchDecision) -> SecurityAuditReport:
    if not isinstance(decision, PatchDecision):
        raise ValueError("decision must be a PatchDecision")
    if decision.status == "deny":
        return _report(
            [AuditFinding("PATCH_DENIED", "high", "Patch preflight denied the proposed change.", True)]
        )
    if decision.requires_review:
        return _report(
            [AuditFinding("PATCH_REVIEW_REQUIRED", "medium", "Patch contains a destructive operation requiring approval.", True)]
        )
    return _report(())


def audit_watchdog(result: WatchdogResult) -> SecurityAuditReport:
    if not isinstance(result, WatchdogResult):
        raise ValueError("result must be a WatchdogResult")
    if result.status == "blocked":
        return _report([AuditFinding("WATCHDOG_BLOCKED", "high", "Connection or schema health is not safe for continuation.", True)])
    if result.status == "stale":
        return _report([AuditFinding("WATCHDOG_STALE", "medium", "Health evidence is stale and must be refreshed.", True)])
    if result.status in {"degraded", "unknown"}:
        return _report([AuditFinding("WATCHDOG_UNCERTAIN", "medium", "Health evidence is incomplete or degraded.", False)])
    return _report(())


def audit_verification(receipt: VerificationReceipt) -> SecurityAuditReport:
    if not isinstance(receipt, VerificationReceipt):
        raise ValueError("receipt must be a VerificationReceipt")
    if receipt.status == "stale":
        return _report([AuditFinding("VERIFICATION_STALE", "high", "Verification evidence no longer matches the current diff.", True)])
    if receipt.status == "failed":
        return _report([AuditFinding("VERIFICATION_FAILED", "high", "A verification task failed or timed out.", True)])
    if receipt.status in {"incomplete", "not_run"}:
        return _report([AuditFinding("VERIFICATION_INCOMPLETE", "medium", "Verification evidence is incomplete.", True)])
    return _report(())


def combine_audits(*reports: SecurityAuditReport) -> SecurityAuditReport:
    if any(not isinstance(report, SecurityAuditReport) for report in reports):
        raise ValueError("reports must contain SecurityAuditReport values")
    findings = tuple(finding for report in reports for finding in report.findings)
    return _report(findings)
