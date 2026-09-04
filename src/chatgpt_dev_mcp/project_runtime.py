"""Trusted project runtime reuse for isolated development worktrees."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import tomllib


DEPENDENCY_FILES = (
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "setup.cfg",
    "setup.py",
)


class ProjectRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ProjectRuntimeResolution:
    command: str
    executable: Path
    source_root: Path
    worktree_root: Path
    dependency_fingerprint: str


def _selected_unittest_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_SELECTED_TEST_INVALID",
            "Selective verification test paths must be ordinary relative POSIX paths.",
        )
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_SELECTED_TEST_INVALID",
            "Selective verification test paths must be ordinary relative POSIX paths.",
        )
    name = parsed.name
    if parsed.suffix != ".py" or not (
        value.startswith("tests/") or name.startswith("test_") or name.endswith("_test.py")
    ):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_SELECTED_TEST_INVALID",
            "Selective verification may execute only Python test paths.",
        )
    return parsed.as_posix()


def select_project_test_command(command: str, selected_tests: tuple[str, ...]) -> str | None:
    """Narrow a registered Python unittest command to server-selected tests."""

    if not selected_tests:
        return None
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_COMMAND_INVALID",
            "Task command could not be parsed safely.",
        ) from exc
    try:
        module_index = argv.index("-m")
    except ValueError:
        return None
    if module_index == 0 or module_index + 1 >= len(argv) or argv[module_index + 1] != "unittest":
        return None
    selected = tuple(_selected_unittest_path(path) for path in selected_tests)
    if len(selected) != len(set(selected)):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_SELECTED_TEST_INVALID",
            "Selective verification test paths must be unique.",
        )
    # Preserve only the trusted interpreter prefix through ``-m unittest``.
    # Discovery patterns/options are dropped so FAST cannot expand to full.
    return shlex.join([*argv[: module_index + 2], *selected])


def _ordinary_directory(path: Path, *, code: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ProjectRuntimeError(code, "Project runtime binding requires an ordinary directory.")
    return path.resolve(strict=True)


def _manifest_hashes(root: Path) -> dict[str, str]:
    names = set(DEPENDENCY_FILES)
    try:
        names.update(path.name for path in root.glob("requirements*.txt"))
    except OSError as exc:
        raise ProjectRuntimeError(
            "RUNTIME_DEPENDENCY_UNAVAILABLE",
            "Dependency manifests could not be inspected safely.",
        ) from exc
    result: dict[str, str] = {}
    for name in sorted(names):
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise ProjectRuntimeError(
                "RUNTIME_DEPENDENCY_UNSAFE",
                f"Dependency manifest is not an ordinary file: {name}",
            )
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ProjectRuntimeError(
                "RUNTIME_DEPENDENCY_UNAVAILABLE",
                f"Dependency manifest could not be read: {name}",
            ) from exc
        if name == "pyproject.toml":
            try:
                document = tomllib.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise ProjectRuntimeError(
                    "RUNTIME_DEPENDENCY_UNAVAILABLE",
                    "pyproject.toml could not be parsed for dependency comparison.",
                ) from exc
            project = document.get("project", {}) if isinstance(document, dict) else {}
            build_system = document.get("build-system", {}) if isinstance(document, dict) else {}
            tool = document.get("tool", {}) if isinstance(document, dict) else {}
            poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
            pdm = tool.get("pdm", {}) if isinstance(tool, dict) else {}
            dependency_view = {
                "project.dependencies": project.get("dependencies") if isinstance(project, dict) else None,
                "project.optional-dependencies": project.get("optional-dependencies") if isinstance(project, dict) else None,
                "project.requires-python": project.get("requires-python") if isinstance(project, dict) else None,
                "build-system.requires": build_system.get("requires") if isinstance(build_system, dict) else None,
                "dependency-groups": document.get("dependency-groups") if isinstance(document, dict) else None,
                "tool.poetry.dependencies": poetry.get("dependencies") if isinstance(poetry, dict) else None,
                "tool.poetry.dev-dependencies": poetry.get("dev-dependencies") if isinstance(poetry, dict) else None,
                "tool.poetry.group": poetry.get("group") if isinstance(poetry, dict) else None,
                "tool.pdm.dev-dependencies": pdm.get("dev-dependencies") if isinstance(pdm, dict) else None,
            }
            payload = json.dumps(
                dependency_view,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        result[name] = hashlib.sha256(payload).hexdigest()
    return result


def dependency_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for name, content_hash in sorted(_manifest_hashes(root).items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _runtime_executable(source_root: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute() or len(relative_path.parts) != 3 or relative_path.parts[:2] != (".venv", "bin"):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_COMMAND_INVALID",
            "Only project-local .venv/bin executables may be rebound.",
        )
    venv = source_root / ".venv"
    bin_dir = venv / "bin"
    executable = source_root / relative_path
    if venv.is_symlink() or bin_dir.is_symlink():
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_UNSAFE",
            "The registered project virtual environment contains an unsafe symlink boundary.",
        )
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_UNAVAILABLE",
            "The registered project runtime executable is unavailable or unsafe.",
        )
    try:
        resolved = executable.resolve(strict=True)
    except OSError as exc:
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_UNAVAILABLE",
            "The registered project runtime executable could not be resolved safely.",
        ) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ProjectRuntimeError(
            "PROJECT_RUNTIME_UNAVAILABLE",
            "The registered project runtime target is unavailable or not executable.",
        )
    return executable


def resolve_project_task_command(
    command: str,
    *,
    source_root: Path,
    worktree_root: Path,
) -> ProjectRuntimeResolution | None:
    """Rebind a registered ``.venv/bin/*`` command to its canonical runtime.

    The executable remains owned by the registered canonical project while the
    process cwd and Python import path remain rooted in the isolated worktree.
    Non-venv commands are returned unchanged by signalling ``None``.
    """

    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ProjectRuntimeError("PROJECT_RUNTIME_COMMAND_INVALID", "Task command could not be parsed safely.") from exc
    if not argv or not argv[0].startswith(".venv/bin/"):
        return None

    source = _ordinary_directory(source_root, code="PROJECT_RUNTIME_SOURCE_UNSAFE")
    worktree = _ordinary_directory(worktree_root, code="PROJECT_RUNTIME_WORKTREE_UNSAFE")
    source_manifests = _manifest_hashes(source)
    worktree_manifests = _manifest_hashes(worktree)
    if source_manifests != worktree_manifests:
        raise ProjectRuntimeError(
            "RUNTIME_DEPENDENCY_MISMATCH",
            "The isolated worktree dependency manifests differ from the registered project runtime.",
        )
    executable = _runtime_executable(source, argv[0])
    python_path = worktree / "src" if (worktree / "src").is_dir() else worktree
    rebound = shlex.join(
        [
            "env",
            f"PYTHONPATH={python_path}",
            str(executable),
            *argv[1:],
        ]
    )
    return ProjectRuntimeResolution(
        command=rebound,
        executable=executable,
        source_root=source,
        worktree_root=worktree,
        dependency_fingerprint=dependency_fingerprint(source),
    )


__all__ = [
    "ProjectRuntimeError",
    "ProjectRuntimeResolution",
    "dependency_fingerprint",
    "resolve_project_task_command",
    "select_project_test_command",
]
