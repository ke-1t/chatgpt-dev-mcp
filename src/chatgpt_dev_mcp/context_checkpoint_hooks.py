"""Pure policy helpers for best-effort automatic Context checkpoints."""

from __future__ import annotations

from dataclasses import dataclass
import re


_EVENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ELIGIBLE_EVENTS = frozenset({"review_ready", "verified_commit", "integrated", "task_succeeded"})
_SENSITIVE_RE = re.compile(
    r"(?:authorization\s*:\s*bearer\b|(?:api[_-]?key|password|token|credential|secret)\s*=)",
    re.IGNORECASE,
)


def _bounded_text(value: str, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{name} is invalid")
    if _SENSITIVE_RE.search(normalized):
        raise ValueError(f"{name} contains secret-like content")
    return normalized


@dataclass(frozen=True, slots=True)
class AutoCheckpointEvent:
    kind: str
    outcome: str
    next_action: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not _EVENT_RE.fullmatch(self.kind):
            raise ValueError("checkpoint event kind is invalid")
        object.__setattr__(self, "outcome", _bounded_text(self.outcome, name="checkpoint outcome", maximum=240))
        object.__setattr__(self, "next_action", _bounded_text(self.next_action, name="checkpoint next action", maximum=1000))


def should_emit_checkpoint(event: AutoCheckpointEvent) -> bool:
    if not isinstance(event, AutoCheckpointEvent):
        raise TypeError("event must be AutoCheckpointEvent")
    return event.kind in _ELIGIBLE_EVENTS


def normalized_checkpoint_text(event: AutoCheckpointEvent) -> tuple[str, str]:
    if not isinstance(event, AutoCheckpointEvent):
        raise TypeError("event must be AutoCheckpointEvent")
    return event.outcome, event.next_action


__all__ = ["AutoCheckpointEvent", "normalized_checkpoint_text", "should_emit_checkpoint"]
