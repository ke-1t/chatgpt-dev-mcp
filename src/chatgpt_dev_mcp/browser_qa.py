"""High-level bounded browser QA normalization over managed browser adapters."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Mapping

from .director import redact_secrets

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_INLINE_SECRET_RE = re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s\"',;}]+")
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
MAX_FINDINGS = 200
MAX_EVIDENCE_BYTES = 2048


class BrowserQAError(ValueError):
    pass


def _redact(text: str) -> str:
    return _INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", redact_secrets(text))


def _bounded_text(value: object, maximum: int = 1000) -> str:
    return _redact(str(value)).encode("utf-8")[:maximum].decode("utf-8", errors="ignore")


def _bounded_evidence(value: object) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            text = repr(value)
    return _redact(text).encode("utf-8")[:MAX_EVIDENCE_BYTES].decode("utf-8", errors="ignore")


@dataclass(frozen=True)
class BrowserQAScenario:
    scenario_id: str
    title: str

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or not _ID_RE.fullmatch(self.scenario_id):
            raise BrowserQAError("scenario_id is invalid")
        if not isinstance(self.title, str) or not self.title.strip() or len(self.title) > 240:
            raise BrowserQAError("scenario title is invalid")


@dataclass(frozen=True)
class BrowserQAFinding:
    kind: str
    severity: str
    message: str
    scenario_id: str
    viewport: tuple[int, int]
    theme: str
    evidence: str
    evidence_hash: str

    def as_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "severity": self.severity, "message": self.message, "scenario_id": self.scenario_id, "viewport": list(self.viewport), "theme": self.theme, "evidence": self.evidence, "evidence_hash": self.evidence_hash}


@dataclass(frozen=True)
class BrowserQAReceipt:
    receipt_id: str
    profile: str
    run_count: int
    findings: tuple[BrowserQAFinding, ...]
    artifact_refs: tuple[str, ...]
    status: str

    def as_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, "profile": self.profile, "run_count": self.run_count, "findings": [finding.as_dict() for finding in self.findings], "artifact_refs": list(self.artifact_refs), "status": self.status, "external_execution": False}


def _severity(value: object, *, default: str = "medium") -> str:
    text = str(value).lower()
    if text in {"critical", "fatal", "error", "high"}:
        return "high"
    if text in {"warning", "warn", "medium", "moderate"}:
        return "medium"
    if text == "low":
        return "low"
    if text in {"info", "debug"}:
        return "info"
    return default


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


class BrowserQAEngine:
    def __init__(self, adapter: object) -> None:
        if not callable(getattr(adapter, "capture", None)):
            raise BrowserQAError("browser QA adapter must expose capture")
        self._adapter = adapter

    @staticmethod
    def _profile(profile: str) -> str:
        if not isinstance(profile, str) or not _ID_RE.fullmatch(profile) or not profile.startswith("managed-"):
            raise BrowserQAError("browser QA requires an explicitly managed profile")
        return profile

    @staticmethod
    def _viewports(viewports: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
        if not isinstance(viewports, tuple) or not 1 <= len(viewports) <= 12:
            raise BrowserQAError("viewports are invalid")
        for viewport in viewports:
            if not isinstance(viewport, tuple) or len(viewport) != 2 or any(isinstance(value, bool) or not isinstance(value, int) for value in viewport) or not 240 <= viewport[0] <= 7680 or not 200 <= viewport[1] <= 4320:
                raise BrowserQAError("viewport is invalid")
        return viewports

    @staticmethod
    def _themes(themes: tuple[str, ...]) -> tuple[str, ...]:
        if not isinstance(themes, tuple) or not 1 <= len(themes) <= 8 or len(set(themes)) != len(themes) or any(not isinstance(theme, str) or not _ID_RE.fullmatch(theme) for theme in themes):
            raise BrowserQAError("themes are invalid")
        return themes

    @staticmethod
    def _finding(*, kind: str, severity: str, message: object, scenario: BrowserQAScenario, viewport: tuple[int, int], theme: str, evidence: object) -> BrowserQAFinding:
        parsed_message, parsed_evidence = _bounded_text(message), _bounded_evidence(evidence)
        return BrowserQAFinding(kind, severity, parsed_message, scenario.scenario_id, viewport, theme, parsed_evidence, hashlib.sha256(parsed_evidence.encode("utf-8")).hexdigest())

    def _normalize_payload(self, payload: Mapping[str, object], scenario: BrowserQAScenario, viewport: tuple[int, int], theme: str) -> tuple[list[BrowserQAFinding], list[str]]:
        findings: list[BrowserQAFinding] = []
        artifacts: list[str] = []
        console = payload.get("console", [])
        if isinstance(console, list):
            for item in console[:100]:
                if not isinstance(item, Mapping):
                    continue
                severity = _severity(item.get("level", "info"), default="info")
                if severity != "info":
                    findings.append(self._finding(kind="console", severity=severity, message=item.get("message", "console issue"), scenario=scenario, viewport=viewport, theme=theme, evidence=item))
        network = payload.get("network", [])
        if isinstance(network, list):
            for item in network[:100]:
                if not isinstance(item, Mapping):
                    continue
                status = item.get("status")
                if isinstance(status, bool) or not isinstance(status, int) or status < 400:
                    continue
                method, url = _bounded_text(item.get("method", "GET"), 40), _bounded_text(item.get("url", "unknown"), 500)
                findings.append(self._finding(kind="network", severity="high" if status >= 500 else "medium", message=f"{method} {url} returned {status}", scenario=scenario, viewport=viewport, theme=theme, evidence=item))
        accessibility = payload.get("accessibility", [])
        if isinstance(accessibility, list):
            for item in accessibility[:100]:
                if isinstance(item, Mapping):
                    findings.append(self._finding(kind="accessibility", severity=_severity(item.get("severity", "medium")), message=item.get("message", "accessibility issue"), scenario=scenario, viewport=viewport, theme=theme, evidence=item))
        visible_text = payload.get("visible_text", {})
        if isinstance(visible_text, Mapping):
            for item in visible_text.get("missing", []) if isinstance(visible_text.get("missing", []), list) else []:
                findings.append(self._finding(kind="visible_text", severity="medium", message=f"missing expected text: {item}", scenario=scenario, viewport=viewport, theme=theme, evidence={"missing": item}))
            for item in visible_text.get("unexpected", []) if isinstance(visible_text.get("unexpected", []), list) else []:
                findings.append(self._finding(kind="visible_text", severity="low", message=f"unexpected visible text: {item}", scenario=scenario, viewport=viewport, theme=theme, evidence={"unexpected": item}))
        screenshot_ref = payload.get("screenshot_ref")
        if isinstance(screenshot_ref, str) and screenshot_ref.startswith("artifact:"):
            artifacts.append(screenshot_ref)
        boxes: list[dict[str, object]] = []
        raw_boxes = payload.get("boxes", [])
        if isinstance(raw_boxes, list):
            for raw in raw_boxes[:100]:
                if not isinstance(raw, Mapping):
                    continue
                x, y, width, height = _number(raw.get("x")), _number(raw.get("y")), _number(raw.get("width")), _number(raw.get("height"))
                if None in {x, y, width, height} or width is None or height is None or width < 0 or height < 0:
                    continue
                boxes.append({"id": _bounded_text(raw.get("id", f"box-{len(boxes)}"), 160), "x": x, "y": y, "width": width, "height": height, "clipped": raw.get("clipped") is True})
        viewport_width, viewport_height = viewport
        for box in boxes:
            x, y, width, height, box_id = float(box["x"]), float(box["y"]), float(box["width"]), float(box["height"]), str(box["id"])
            if x < 0 or y < 0 or x + width > viewport_width or y + height > viewport_height:
                findings.append(self._finding(kind="layout", severity="medium", message=f"overflow: {box_id} exceeds viewport {viewport_width}x{viewport_height}", scenario=scenario, viewport=viewport, theme=theme, evidence=box))
            if box["clipped"]:
                findings.append(self._finding(kind="layout", severity="medium", message=f"clipped: {box_id} is visually clipped", scenario=scenario, viewport=viewport, theme=theme, evidence=box))
        for index, left in enumerate(boxes):
            for right in boxes[index + 1:]:
                intersection_w = min(float(left["x"]) + float(left["width"]), float(right["x"]) + float(right["width"])) - max(float(left["x"]), float(right["x"]))
                intersection_h = min(float(left["y"]) + float(left["height"]), float(right["y"]) + float(right["height"])) - max(float(left["y"]), float(right["y"]))
                if intersection_w > 0 and intersection_h > 0:
                    pair = tuple(sorted((str(left["id"]), str(right["id"]))))
                    findings.append(self._finding(kind="layout", severity="medium", message=f"overlap: {pair[0]} overlaps {pair[1]}", scenario=scenario, viewport=viewport, theme=theme, evidence={"left": left, "right": right, "intersection": [intersection_w, intersection_h]}))
        return findings, artifacts

    def run(self, profile: str, scenarios: tuple[BrowserQAScenario, ...], viewports: tuple[tuple[int, int], ...], themes: tuple[str, ...]) -> BrowserQAReceipt:
        parsed_profile = self._profile(profile)
        if not isinstance(scenarios, tuple) or not 1 <= len(scenarios) <= 32 or any(not isinstance(item, BrowserQAScenario) for item in scenarios) or len({item.scenario_id for item in scenarios}) != len(scenarios):
            raise BrowserQAError("scenarios are invalid")
        viewports, themes = self._viewports(viewports), self._themes(themes)
        run_count = len(scenarios) * len(viewports) * len(themes)
        if run_count > 128:
            raise BrowserQAError("browser QA run matrix exceeds safety bound")
        deduped: dict[tuple[str, str, str], BrowserQAFinding] = {}
        artifacts: list[str] = []
        for scenario in scenarios:
            for viewport in viewports:
                for theme in themes:
                    raw = self._adapter.capture(parsed_profile, scenario, viewport, theme)
                    if not isinstance(raw, Mapping):
                        raise BrowserQAError("browser QA adapter returned invalid evidence")
                    findings, refs = self._normalize_payload(raw, scenario, viewport, theme)
                    for finding in findings:
                        key = (finding.kind, finding.scenario_id, finding.message)
                        current = deduped.get(key)
                        if current is None or _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[current.severity]:
                            deduped[key] = finding
                    for ref in refs:
                        if ref not in artifacts and len(artifacts) < 64:
                            artifacts.append(ref)
                    if len(deduped) > MAX_FINDINGS:
                        raise BrowserQAError("browser QA findings exceed safety bound")
        findings = tuple(sorted(deduped.values(), key=lambda item: (-_SEVERITY_ORDER[item.severity], item.kind, item.scenario_id, item.message)))
        status = "failed" if any(item.severity == "high" for item in findings) else "warning" if findings else "passed"
        digest = hashlib.sha256(json.dumps({"profile": parsed_profile, "runs": run_count, "findings": [[item.kind, item.severity, item.message, item.scenario_id, item.evidence_hash] for item in findings], "artifacts": artifacts}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return BrowserQAReceipt(f"browser-qa:{digest[:32]}", parsed_profile, run_count, findings, tuple(artifacts), status)


__all__ = ["BrowserQAEngine", "BrowserQAError", "BrowserQAFinding", "BrowserQAReceipt", "BrowserQAScenario"]
