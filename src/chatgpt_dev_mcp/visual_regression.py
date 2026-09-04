"""Hash- and artifact-reference based visual regression evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_HASH40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HASH64_RE = re.compile(r"^[0-9a-f]{64}$")


class VisualRegressionError(ValueError):
    pass


@dataclass(frozen=True)
class VisualBaselineIdentity:
    scenario_id: str
    revision: str
    viewport: tuple[int, int]
    theme: str

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or not _ID_RE.fullmatch(self.scenario_id):
            raise VisualRegressionError("scenario_id is invalid")
        if not isinstance(self.revision, str) or not _HASH40_RE.fullmatch(self.revision):
            raise VisualRegressionError("revision is invalid")
        if not isinstance(self.viewport, tuple) or len(self.viewport) != 2 or any(isinstance(value, bool) or not isinstance(value, int) for value in self.viewport) or not 240 <= self.viewport[0] <= 7680 or not 200 <= self.viewport[1] <= 4320:
            raise VisualRegressionError("viewport is invalid")
        if not isinstance(self.theme, str) or not _ID_RE.fullmatch(self.theme):
            raise VisualRegressionError("theme is invalid")

    def as_dict(self) -> dict[str, object]:
        return {"scenario_id": self.scenario_id, "revision": self.revision.lower(), "viewport": list(self.viewport), "theme": self.theme}


@dataclass(frozen=True)
class VisualEvidence:
    screenshot_digest: str
    screenshot_ref: str
    dom_fingerprint: str
    accessibility_fingerprint: str
    text_fingerprint: str
    boxes_fingerprint: str

    def __post_init__(self) -> None:
        for name, value in (("screenshot_digest", self.screenshot_digest), ("dom_fingerprint", self.dom_fingerprint), ("accessibility_fingerprint", self.accessibility_fingerprint), ("text_fingerprint", self.text_fingerprint), ("boxes_fingerprint", self.boxes_fingerprint)):
            if not isinstance(value, str) or not _HASH64_RE.fullmatch(value):
                raise VisualRegressionError(f"{name} must be sha256 hex")
        if not isinstance(self.screenshot_ref, str) or not self.screenshot_ref.startswith("artifact:") or len(self.screenshot_ref) > 512:
            raise VisualRegressionError("screenshot_ref is invalid")

    def as_dict(self) -> dict[str, str]:
        return {"screenshot_digest": self.screenshot_digest, "screenshot_ref": self.screenshot_ref, "dom_fingerprint": self.dom_fingerprint, "accessibility_fingerprint": self.accessibility_fingerprint, "text_fingerprint": self.text_fingerprint, "boxes_fingerprint": self.boxes_fingerprint}


@dataclass(frozen=True)
class VisualRegressionBaseline:
    baseline_id: str
    identity: VisualBaselineIdentity
    evidence: VisualEvidence
    created_at: str

    def as_dict(self) -> dict[str, object]:
        return {"baseline_id": self.baseline_id, "identity": self.identity.as_dict(), "evidence": self.evidence.as_dict(), "created_at": self.created_at}


@dataclass(frozen=True)
class VisualRegressionReceipt:
    receipt_id: str
    baseline_id: str
    status: str
    changed_dimensions: tuple[str, ...]
    baseline_screenshot_ref: str
    current_screenshot_ref: str


class VisualRegressionEngine:
    @staticmethod
    def create_baseline(identity: VisualBaselineIdentity, evidence: VisualEvidence, *, created_at: str | None = None) -> VisualRegressionBaseline:
        if not isinstance(identity, VisualBaselineIdentity) or not isinstance(evidence, VisualEvidence):
            raise VisualRegressionError("baseline identity/evidence is invalid")
        payload = json.dumps(identity.as_dict(), sort_keys=True, separators=(",", ":"))
        baseline_id = "visual-baseline:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
        timestamp = created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if not isinstance(timestamp, str) or not timestamp or len(timestamp) > 128:
            raise VisualRegressionError("created_at is invalid")
        return VisualRegressionBaseline(baseline_id, identity, evidence, timestamp)

    @staticmethod
    def compare(baseline: VisualRegressionBaseline, current: VisualEvidence) -> VisualRegressionReceipt:
        if not isinstance(baseline, VisualRegressionBaseline) or not isinstance(current, VisualEvidence):
            raise VisualRegressionError("visual comparison input is invalid")
        changed = tuple(name for name, before, after in (("screenshot", baseline.evidence.screenshot_digest, current.screenshot_digest), ("dom", baseline.evidence.dom_fingerprint, current.dom_fingerprint), ("accessibility", baseline.evidence.accessibility_fingerprint, current.accessibility_fingerprint), ("text", baseline.evidence.text_fingerprint, current.text_fingerprint), ("boxes", baseline.evidence.boxes_fingerprint, current.boxes_fingerprint)) if before != after)
        payload = json.dumps({"baseline_id": baseline.baseline_id, "current": current.as_dict(), "changed": changed}, sort_keys=True, separators=(",", ":"))
        return VisualRegressionReceipt(receipt_id="visual-compare:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32], baseline_id=baseline.baseline_id, status="changed" if changed else "match", changed_dimensions=changed, baseline_screenshot_ref=baseline.evidence.screenshot_ref, current_screenshot_ref=current.screenshot_ref)


__all__ = ["VisualBaselineIdentity", "VisualEvidence", "VisualRegressionBaseline", "VisualRegressionEngine", "VisualRegressionError", "VisualRegressionReceipt"]
