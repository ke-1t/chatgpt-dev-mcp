"""Deterministic, fail-closed helpers for selecting ordinary Git text hunks."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_UNSUPPORTED_PREFIXES = (
    "new file mode ",
    "deleted file mode ",
    "old mode ",
    "new mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Binary files ",
    "GIT binary patch",
)


class GitHunkSelectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class GitHunk:
    hunk_id: str
    path: str
    header: str
    text: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "hunk_id": self.hunk_id,
            "path": self.path,
            "header": self.header,
            "old_start": self.old_start,
            "old_count": self.old_count,
            "new_start": self.new_start,
            "new_count": self.new_count,
        }


@dataclass(frozen=True)
class GitHunkSelection:
    patch: str
    patch_hash: str
    hunk_ids: tuple[str, ...]
    paths: tuple[str, ...]


def _stable_hunk_id(path: str, text: str) -> str:
    return f"hunk:{hashlib.sha256((path + chr(0) + text).encode('utf-8')).hexdigest()}"


def _validate_path(path: object) -> str:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise GitHunkSelectionError("GIT_HUNK_PATH_INVALID", "path must be a non-empty NUL-free string.")
    return path


def _split_single_file_diff(path: str, diff_text: object) -> tuple[str, list[str]]:
    _validate_path(path)
    if not isinstance(diff_text, str) or not diff_text:
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "diff text is required.")
    lines = diff_text.splitlines(keepends=True)
    if not lines or not lines[0].startswith("diff --git "):
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "expected one ordinary Git file diff.")
    if sum(1 for line in lines if line.startswith("diff --git ")) != 1:
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "hunk parser accepts exactly one file diff.")
    for line in lines:
        stripped = line.rstrip("\r\n")
        if stripped.startswith(_UNSUPPORTED_PREFIXES):
            raise GitHunkSelectionError(
                "GIT_HUNK_UNSUPPORTED_CHANGE",
                "hunk staging supports only ordinary tracked text modifications.",
            )
    first_hunk = next((index for index, line in enumerate(lines) if line.startswith("@@ ")), -1)
    if first_hunk < 0:
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "ordinary text diff contains no selectable hunks.")
    prefix = "".join(lines[:first_hunk])
    if "--- " not in prefix or "+++ " not in prefix:
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "ordinary text diff is missing file headers.")
    if "--- /dev/null" in prefix or "+++ /dev/null" in prefix:
        raise GitHunkSelectionError(
            "GIT_HUNK_UNSUPPORTED_CHANGE",
            "new and deleted files are not supported by hunk staging.",
        )
    return prefix, lines[first_hunk:]


def enumerate_file_hunks(path: str, diff_text: str) -> tuple[GitHunk, ...]:
    path = _validate_path(path)
    _prefix, hunk_lines = _split_single_file_diff(path, diff_text)
    starts = [index for index, line in enumerate(hunk_lines) if line.startswith("@@ ")]
    if not starts or starts[0] != 0:
        raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "malformed unified diff hunk stream.")
    starts.append(len(hunk_lines))
    hunks: list[GitHunk] = []
    for start, end in zip(starts, starts[1:]):
        text = "".join(hunk_lines[start:end])
        header = hunk_lines[start].rstrip("\r\n")
        match = _HUNK_HEADER_RE.fullmatch(header)
        if match is None:
            raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "malformed unified diff hunk header.")
        for line in hunk_lines[start + 1 : end]:
            if not line or line[0] not in {" ", "+", "-", "\\"}:
                raise GitHunkSelectionError("GIT_HUNK_DIFF_INVALID", "malformed unified diff hunk body.")
        hunks.append(
            GitHunk(
                hunk_id=_stable_hunk_id(path, text),
                path=path,
                header=header,
                text=text,
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or "1"),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or "1"),
            )
        )
    return tuple(hunks)


def build_hunk_patch(path: str, diff_text: str, hunk_ids: Iterable[str]) -> GitHunkSelection:
    path = _validate_path(path)
    if isinstance(hunk_ids, (str, bytes)):
        raise GitHunkSelectionError("GIT_HUNK_IDS_INVALID", "hunk_ids must be a non-empty collection.")
    try:
        requested = tuple(hunk_ids)
    except TypeError:
        raise GitHunkSelectionError("GIT_HUNK_IDS_INVALID", "hunk_ids must be a non-empty collection.") from None
    if not requested or any(not isinstance(value, str) or not value for value in requested):
        raise GitHunkSelectionError("GIT_HUNK_IDS_INVALID", "hunk_ids must be a non-empty collection.")
    if len(set(requested)) != len(requested):
        raise GitHunkSelectionError("GIT_HUNK_DUPLICATE", "duplicate hunk ids are not allowed.")

    prefix, _ = _split_single_file_diff(path, diff_text)
    prefix = "".join(line for line in prefix.splitlines(keepends=True) if not line.startswith("index "))
    available = enumerate_file_hunks(path, diff_text)
    by_id = {hunk.hunk_id: hunk for hunk in available}
    unknown = [hunk_id for hunk_id in requested if hunk_id not in by_id]
    if unknown:
        raise GitHunkSelectionError("GIT_HUNK_UNKNOWN", "one or more hunk ids do not match the current diff.")
    requested_set = set(requested)
    selected = tuple(hunk for hunk in available if hunk.hunk_id in requested_set)
    patch = prefix + "".join(hunk.text for hunk in selected)
    return GitHunkSelection(
        patch=patch,
        patch_hash=hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        hunk_ids=tuple(hunk.hunk_id for hunk in selected),
        paths=(path,),
    )


__all__ = [
    "GitHunk",
    "GitHunkSelection",
    "GitHunkSelectionError",
    "build_hunk_patch",
    "enumerate_file_hunks",
]
