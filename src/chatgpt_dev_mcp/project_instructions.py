"""Bounded parsing of repository-root AGENTS.md instructions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re


_MARKDOWN_PREFIX_RE = re.compile(r"^\s*(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+)")


@dataclass(frozen=True, slots=True)
class ProjectInstructionResult:
    status: str
    items: tuple[str, ...]
    source_hash: str
    used_bytes: int

    @classmethod
    def missing(cls) -> "ProjectInstructionResult":
        return cls("missing", (), "", 0)


def parse_project_instructions(
    content: str,
    *,
    max_bytes: int = 2048,
    hard_max_bytes: int = 8192,
) -> ProjectInstructionResult:
    if not isinstance(content, str) or "\x00" in content:
        raise ValueError("AGENTS.md content is invalid")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("instruction budget is invalid")
    if isinstance(hard_max_bytes, bool) or not isinstance(hard_max_bytes, int) or hard_max_bytes < 1:
        raise ValueError("instruction hard limit is invalid")
    if max_bytes > hard_max_bytes:
        raise ValueError("instruction budget exceeds the hard limit")

    raw = content.encode("utf-8")
    if len(raw) > hard_max_bytes:
        raise ValueError("AGENTS.md content exceeds the hard limit")

    items: list[str] = []
    used_bytes = 0
    for raw_line in content.splitlines():
        line = _MARKDOWN_PREFIX_RE.sub("", raw_line).strip()
        if not line:
            continue
        line_bytes = len(line.encode("utf-8"))
        if used_bytes + line_bytes > max_bytes:
            break
        items.append(line)
        used_bytes += line_bytes

    return ProjectInstructionResult(
        "loaded" if items else "empty",
        tuple(items),
        hashlib.sha256(raw).hexdigest(),
        used_bytes,
    )


__all__ = ["ProjectInstructionResult", "parse_project_instructions"]
