"""Bounded local maintenance actions authorized by trusted R2 grants."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Sequence
from urllib.error import URLError
from urllib.request import urlopen

from .approval_policy import ApprovalPolicyError, GrantBinding, TrustedGrantStore
from .connector_resilience import persistence_db_identity
from .runtime_activation import (
    ActivationPlan,
    RuntimeActivationError,
    V26_PYTHON_LOCATOR,
    validate_v26_bootstrap_contract,
)


class LocalMaintenanceError(RuntimeError):
    def __init__(self, code: str, message: str, *, outcome_unknown: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.outcome_unknown = outcome_unknown


@dataclass(frozen=True)
class MaintenanceRunResult:
    exit_code: int | None
    outcome_known: bool
    detail: str
    deferred: bool = False


_RESTART_MODULE = "chatgpt_dev_mcp.local_maintenance"
_DETACHED_RESTART_FLAG = "--detached-restart"
_RESTART_GRACE_SECONDS = 2.0
_READINESS_TIMEOUT_SECONDS = 30.0
_READINESS_POLL_SECONDS = 0.5
_V26_RUNTIME_LABEL = "com.openai.chatgpt-dev-mcp-v26-runtime"
_V26_RUNTIME_RUN = Path("/tmp/opencode/v26-canary/deployment/runtime-run")
_V26_RUNTIME_MANIFEST = Path("/tmp/opencode/v26-canary/deployment/deployment-manifest.json")
_V26_RUNTIME_NAME = "v26-canary"
_V26_MCP_ENDPOINT = "/mcp/v26-canary"
_TOOLCHAIN_BREW_CANDIDATES = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
_TOOLCHAIN_NPM_CANDIDATES = ("/opt/homebrew/bin/npm", "/usr/local/bin/npm")
_TOOLCHAIN_REQUIRED_EXECUTABLES = (
    "gh",
    "node",
    "npm",
    "npx",
    "uv",
    "uvx",
    "playwright",
    "playwright-mcp",
    "chrome-devtools-mcp",
    "context7-mcp",
    "serena",
)


def _toolchain_executable_candidates(name: str) -> tuple[str, str]:
    return (f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}")


def _first_existing_fixed_path(candidates: Sequence[str], *, exists: Callable[[str], bool]) -> str | None:
    return next((candidate for candidate in candidates if exists(candidate)), None)


def _is_fixed_toolchain_command(argv: Sequence[str]) -> bool:
    command = tuple(argv)
    return command in {
        ("/opt/homebrew/bin/brew", "install", "gh", "node", "uv"),
        ("/usr/local/bin/brew", "install", "gh", "node", "uv"),
        (
            "/opt/homebrew/bin/npm",
            "install",
            "--global",
            "playwright@latest",
            "@playwright/mcp@latest",
            "chrome-devtools-mcp@latest",
            "@upstash/context7-mcp@latest",
        ),
        (
            "/usr/local/bin/npm",
            "install",
            "--global",
            "playwright@latest",
            "@playwright/mcp@latest",
            "chrome-devtools-mcp@latest",
            "@upstash/context7-mcp@latest",
        ),
        ("/opt/homebrew/bin/uv", "tool", "install", "-p", "3.13", "serena-agent"),
        ("/usr/local/bin/uv", "tool", "install", "-p", "3.13", "serena-agent"),
    }


def _run_fixed_toolchain_command(argv: tuple[str, ...]) -> MaintenanceRunResult:
    if not _is_fixed_toolchain_command(argv):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_ACTION_INVALID", "developer toolchain command is not fixed")
    try:
        completed = subprocess.run(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=900,
            check=False,
            env={
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(Path.home()),
                "CI": "1",
                "NONINTERACTIVE": "1",
                "HOMEBREW_NO_AUTO_UPDATE": "1",
                "HOMEBREW_NO_ENV_HINTS": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "developer toolchain installation outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        ) from exc
    detail = (completed.stdout or "").strip()[-1000:]
    return MaintenanceRunResult(completed.returncode, True, detail)


def _safe_toolchain_failure_detail(value: str) -> str:
    blocked_markers = ("token", "password", "passwd", "secret", "bearer", "authorization", "api_key", "apikey")
    safe_lines = [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not any(marker in line.casefold() for marker in blocked_markers)
    ]
    return " | ".join(safe_lines)[-500:]


def _install_fixed_dev_toolchain(
    *,
    exists: Callable[[str], bool] | None = None,
    runner: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
) -> MaintenanceRunResult:
    path_exists = exists or (lambda value: Path(value).is_file())
    command_runner = runner or _run_fixed_toolchain_command
    brew = _first_existing_fixed_path(_TOOLCHAIN_BREW_CANDIDATES, exists=path_exists)
    if brew is None:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_HOMEBREW_REQUIRED",
            "Homebrew is required for the fixed developer toolchain installer",
        )

    brew_result = command_runner((brew, "install", "gh", "node", "uv"))
    if not isinstance(brew_result, MaintenanceRunResult) or not brew_result.outcome_known:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "developer toolchain installation outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        )
    if brew_result.exit_code != 0:
        detail = _safe_toolchain_failure_detail(brew_result.detail)
        message = "Homebrew developer tool installation failed"
        if detail:
            message += f": {detail}"
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", message)

    npm = _first_existing_fixed_path(_TOOLCHAIN_NPM_CANDIDATES, exists=path_exists)
    if npm is None:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "npm was not available after fixed Node installation")
    npm_result = command_runner(
        (
            npm,
            "install",
            "--global",
            "playwright@latest",
            "@playwright/mcp@latest",
            "chrome-devtools-mcp@latest",
            "@upstash/context7-mcp@latest",
        )
    )
    if not isinstance(npm_result, MaintenanceRunResult) or not npm_result.outcome_known:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "developer toolchain installation outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        )
    if npm_result.exit_code != 0:
        detail = _safe_toolchain_failure_detail(npm_result.detail)
        message = "fixed npm developer tool installation failed"
        if detail:
            message += f": {detail}"
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", message)

    uv = _first_existing_fixed_path(_toolchain_executable_candidates("uv"), exists=path_exists)
    if uv is None:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "uv was not available after fixed toolchain installation")
    uv_result = command_runner((uv, "tool", "install", "-p", "3.13", "serena-agent"))
    if not isinstance(uv_result, MaintenanceRunResult) or not uv_result.outcome_known:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "developer toolchain installation outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        )
    if uv_result.exit_code != 0:
        detail = _safe_toolchain_failure_detail(uv_result.detail)
        message = "fixed uv developer tool installation failed"
        if detail:
            message += f": {detail}"
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", message)

    missing = [
        name
        for name in _TOOLCHAIN_REQUIRED_EXECUTABLES
        if _first_existing_fixed_path(_toolchain_executable_candidates(name), exists=path_exists) is None
    ]
    if missing:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_FAILED",
            f"developer toolchain verification failed: missing {', '.join(missing)}",
        )
    return MaintenanceRunResult(
        0,
        True,
        "installed and verified: gh, node/npm/npx, uv/uvx, Playwright, Playwright MCP, Chrome DevTools MCP, Context7, Serena",
    )


def _is_fixed_restart_target(target: object) -> bool:
    if not isinstance(target, str):
        return False
    parts = target.split("/")
    return (
        len(parts) == 3
        and parts[0] == "gui"
        and parts[1].isdigit()
        and parts[2] == LocalMaintenanceController._DEV_MCP_LABEL
    )


def _is_fixed_restart_argv(argv: Sequence[str]) -> bool:
    return (
        len(argv) == 4
        and tuple(argv[:3]) == ("launchctl", "kickstart", "-k")
        and _is_fixed_restart_target(argv[3])
    )


def _probe_tunnel_readiness(*, opener: Callable[..., object] = urlopen) -> bool:
    """Prove local Tunnel liveness/readiness without contacting the network."""

    for path, expected in (("/healthz", "live"), ("/readyz", "ready")):
        try:
            response = opener(f"http://127.0.0.1:8080{path}", timeout=0.75)
            with response as body:  # type: ignore[union-attr]
                status = getattr(body, "status", 200)
                payload = body.read(128).decode("utf-8", "replace").strip()
            if status != 200 or payload != expected:
                return False
        except (OSError, URLError, ValueError):
            return False
    return True


def _run_detached_restart(target: str) -> int:
    """Restart the LaunchAgent outside the MCP child, then await readiness."""

    if not _is_fixed_restart_target(target):
        return 2
    time.sleep(_RESTART_GRACE_SECONDS)
    for attempt in range(3):
        try:
            result = subprocess.run(
                ("/bin/launchctl", "kickstart", "-k", target),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            deadline = time.monotonic() + _READINESS_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if _probe_tunnel_readiness():
                    return 0
                time.sleep(_READINESS_POLL_SECONDS)
        if attempt < 2:
            time.sleep(0.5 * (2**attempt))
    return 1


def _schedule_detached_restart(argv: tuple[str, ...]) -> MaintenanceRunResult:
    if not _is_fixed_restart_argv(argv):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_ACTION_INVALID", "local maintenance action is not fixed")
    target = argv[3]
    try:
        subprocess.Popen(
            (sys.executable, "-m", _RESTART_MODULE, _DETACHED_RESTART_FLAG, target),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except OSError as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "local maintenance outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        ) from exc
    return MaintenanceRunResult(
        0,
        True,
        "restart queued after response flush; readiness will be verified",
        deferred=True,
    )


def _default_runner(argv: tuple[str, ...]) -> MaintenanceRunResult:
    if _is_fixed_restart_argv(argv):
        return _schedule_detached_restart(argv)
    try:
        completed = subprocess.run(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "local maintenance outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        ) from exc
    return MaintenanceRunResult(completed.returncode, True, (completed.stdout or "").strip()[:1000])


def _default_git_head_reader(root: Path) -> str:
    try:
        completed = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime source revision could not be read safely",
            outcome_unknown=True,
        ) from exc
    head = (completed.stdout or "").strip()
    if completed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime source revision is invalid")
    return head


def _default_git_parent_reader(root: Path) -> str:
    try:
        completed = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "rev-parse", "HEAD^"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime parent revision could not be read safely",
            outcome_unknown=True,
        ) from exc
    parent = (completed.stdout or "").strip()
    if completed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", parent):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime parent revision is invalid")
    return parent


def _default_git_diff_reader(root: Path) -> bytes:
    try:
        staged = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "diff", "--cached", "--quiet"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        if staged.returncode != 0:
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_FAILED",
                "v26 runtime repin requires a clean Git index",
            )
        completed = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "diff", "--binary"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except LocalMaintenanceError:
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime patch identity could not be read safely",
            outcome_unknown=True,
        ) from exc
    if completed.returncode != 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime patch identity is invalid")
    return bytes(completed.stdout or b"")


def _run_fixed_v26_runtime_restart(argv: tuple[str, ...]) -> MaintenanceRunResult:
    if (
        len(argv) != 4
        or tuple(argv[:3]) != ("launchctl", "kickstart", "-k")
        or not re.fullmatch(rf"gui/[0-9]+/{re.escape(_V26_RUNTIME_LABEL)}", argv[3])
    ):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_ACTION_INVALID", "v26 runtime restart action is not fixed")
    try:
        completed = subprocess.run(
            ("/bin/launchctl", "kickstart", "-k", argv[3]),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime restart outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        ) from exc
    return MaintenanceRunResult(completed.returncode, True, (completed.stdout or "").strip()[:1000])


def _atomic_replace_text(target: Path, content: str) -> None:
    mode = target.stat().st_mode
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as handle:
            handle.write(content)
            temporary_path = Path(handle.name)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, target)
    except OSError as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime deployment identity update is incomplete or unknown",
            outcome_unknown=True,
        ) from exc


@dataclass(frozen=True)
class _V26DeploymentSnapshot:
    runtime_text: str
    manifest: dict[str, object]


def _read_private_deployment_file(path: Path, *, label: str) -> str:
    """Read one installed deployment file without following a final symlink."""

    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"{label} is not a regular file")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"{label} ownership or permissions are unsafe")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"{label} is unreadable") from exc


def _shell_assignment_value(value: Path | str, *, label: str) -> str:
    text = str(value)
    # Values are inserted into a double-quoted shell assignment in the fixed
    # wrapper.  Reject expansion/control characters rather than attempting to
    # shell-escape an operator-owned deployment file here.
    if not text or any(character in text for character in ("\n", "\r", '"', "\\", "$", "`")):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"{label} cannot be represented safely")
    return text


def _replace_required_shell_assignment(content: str, name: str, value: Path | str) -> str:
    safe_value = _shell_assignment_value(value, label=name)
    pattern = rf'^{re.escape(name)}="[^"]*"$'
    replaced, count = re.subn(pattern, f'{name}="{safe_value}"', content, count=1, flags=re.MULTILINE)
    if count != 1:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", f"v26 runtime wrapper is missing {name}")
    return replaced


_V26_PORTABLE_PYTHON_BOOTSTRAP = f'''# V26_PYTHON_LOCATOR={V26_PYTHON_LOCATOR}
WORKSPACE_LOCATOR="${{LOCAL_DEV_MCP_WORKSPACE_ROOT:-$HOME/.local/bin/local-dev-mcp-workspace-root}}"
if [[ ! -x "$WORKSPACE_LOCATOR" ]]; then
  echo "v26 workspace locator is unavailable" >&2
  exit 78
fi
CANONICAL_ROOT="$("$WORKSPACE_LOCATOR" "chatgpt-dev-mcp")"
case "$CANONICAL_ROOT" in
  /*) ;;
  *) echo "v26 workspace locator returned a non-absolute root" >&2; exit 78 ;;
esac
if [[ "$CANONICAL_ROOT" == *$'\\n'* || "$CANONICAL_ROOT" == *$'\\r'* || ! -d "$CANONICAL_ROOT/.git" || ! -x "$CANONICAL_ROOT/.venv/bin/python" ]]; then
  echo "v26 workspace locator returned an invalid canonical workspace" >&2
  exit 78
fi
PYTHON_BIN="$CANONICAL_ROOT/.venv/bin/python"
'''


def _replace_v26_python_bootstrap(content: str) -> str:
    if (
        f"# V26_PYTHON_LOCATOR={V26_PYTHON_LOCATOR}" in content
        and "LOCAL_DEV_MCP_WORKSPACE_ROOT" in content
        and 'PYTHON_BIN="$CANONICAL_ROOT/.venv/bin/python"' in content
    ):
        return content
    replaced, count = re.subn(
        r'^PYTHON_BIN="[^"]*"$\n?',
        lambda _match: _V26_PORTABLE_PYTHON_BOOTSTRAP,
        content,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime wrapper is missing PYTHON_BIN")
    return replaced


def _default_v26_runtime_pid_reader(label: str) -> int | None:
    uid = os.getuid()
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_UID_INVALID", "local user identity is invalid")
    try:
        result = subprocess.run(
            ("/bin/launchctl", "print", f"gui/{uid}/{label}"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime process state is unavailable",
            outcome_unknown=True,
        ) from exc
    if result.returncode != 0:
        return None
    match = re.search(r"(?:^|\n)\s*pid\s*=\s*(\d+)\b", result.stdout or "")
    return int(match.group(1)) if match else None


def _default_v26_git_patch_hash_reader(root: Path) -> str:
    try:
        result = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "show", "--format=", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD", "--"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime patch identity could not be read safely",
            outcome_unknown=True,
        ) from exc
    if result.returncode != 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime patch identity is invalid")
    return hashlib.sha256(bytes(result.stdout or b"")).hexdigest()


def _default_v26_git_ancestry_reader(root: Path, base: str, head: str) -> bool:
    try:
        result = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "merge-base", "--is-ancestor", base, head),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime ancestry could not be read safely",
            outcome_unknown=True,
        ) from exc
    return result.returncode == 0


def _default_v26_git_clean_reader(root: Path) -> bool:
    try:
        result = subprocess.run(
            ("/usr/bin/git", "-C", str(root), "status", "--porcelain=v1", "-z"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime source cleanliness could not be read safely",
            outcome_unknown=True,
        ) from exc
    if result.returncode != 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime source cleanliness is unavailable")
    return not bool(result.stdout)


def _default_v26_database_identity_reader(path: Path) -> str:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            row = connection.execute(
                "SELECT version FROM schema_meta WHERE schema_name = 'director'"
            ).fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.DatabaseError) as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database cannot be opened read-only") from exc
    if integrity != "ok" or row is None or int(row[0]) != 14:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database is not a healthy schema-14 state")
    return persistence_db_identity(path, schema_version=14)


class V26RuntimeDeployment:
    """Official production deployment adapter used by candidate activation.

    The activation controller owns candidate validation and approval.  This
    adapter is the only component allowed to translate an approved plan into
    the fixed v26 wrapper/manifest and LaunchAgent kickstart operation.  It is
    deliberately injectable in tests; production callers must supply the
    fixed paths from :class:`production_runtime.ProductionRuntimePaths`.
    """

    def __init__(
        self,
        *,
        runtime_path: Path,
        manifest_path: Path,
        state_dir: Path,
        uid_provider: Callable[[], int] | None = None,
        restart_runner: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
        label: str = "com.openai.chatgpt-dev-mcp-v26-runtime",
    ) -> None:
        self.runtime_path = Path(runtime_path)
        self.manifest_path = Path(manifest_path)
        self.state_dir = Path(state_dir)
        self._uid_provider = uid_provider or os.getuid
        self._restart_runner = restart_runner or _run_fixed_v26_runtime_restart
        self._label = label
        self._last_snapshot: _V26DeploymentSnapshot | None = None

    def _read_snapshot(self) -> _V26DeploymentSnapshot:
        runtime_text = _read_private_deployment_file(self.runtime_path, label="v26 runtime wrapper")
        manifest_text = _read_private_deployment_file(self.manifest_path, label="v26 runtime manifest")
        try:
            manifest = json.loads(manifest_text)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime manifest is invalid")
        source_match = re.search(r'^SOURCE_ROOT="([^"]+)"$', runtime_text, re.MULTILINE)
        base_match = re.search(r'^EXPECTED_BASE="([^"]+)"$', runtime_text, re.MULTILINE)
        patch_match = re.search(r'^EXPECTED_PATCH="([^"]+)"$', runtime_text, re.MULTILINE)
        mode_match = re.search(r'^EXPECTED_PATCH_MODE="([^"]+)"$', runtime_text, re.MULTILINE)
        if source_match is None or base_match is None or patch_match is None or mode_match is None:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime wrapper identity is incomplete")
        if (
            manifest.get("source_root") != source_match.group(1)
            or manifest.get("base_revision") != base_match.group(1)
            or manifest.get("patch_hash") != patch_match.group(1)
            or manifest.get("patch_mode") != mode_match.group(1)
        ):
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment identities disagree")
        return _V26DeploymentSnapshot(runtime_text=runtime_text, manifest=dict(manifest))

    def _restart(self) -> MaintenanceRunResult:
        uid = self._uid_provider()
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_UID_INVALID", "local user identity is invalid")
        argv = ("launchctl", "kickstart", "-k", f"gui/{uid}/{self._label}")
        try:
            result = self._restart_runner(argv)
        except LocalMaintenanceError:
            raise
        except Exception as exc:  # noqa: BLE001 - restart outcome is fail-closed
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "v26 runtime restart outcome is unknown; automatic retry is forbidden",
                outcome_unknown=True,
            ) from exc
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known:
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "v26 runtime restart outcome is unknown; automatic retry is forbidden",
                outcome_unknown=True,
            )
        if result.exit_code != 0:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime restart failed")
        return result

    def _restore_snapshot(self, snapshot: _V26DeploymentSnapshot) -> None:
        try:
            _atomic_replace_text(self.runtime_path, snapshot.runtime_text)
            _atomic_replace_text(self.manifest_path, json.dumps(snapshot.manifest, indent=2) + "\n")
            readback = self._read_snapshot()
        except LocalMaintenanceError:
            raise
        except Exception as exc:  # noqa: BLE001 - restoration is fail-closed
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "v26 runtime deployment rollback outcome is unknown",
                outcome_unknown=True,
            ) from exc
        if readback != snapshot:
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "v26 runtime deployment rollback read-back is ambiguous",
                outcome_unknown=True,
            )

    def _portable_rollback_snapshot(
        self,
        snapshot: _V26DeploymentSnapshot,
        current: object,
    ) -> _V26DeploymentSnapshot:
        runtime_text = _replace_v26_python_bootstrap(snapshot.runtime_text)
        manifest = dict(snapshot.manifest)
        manifest.update(
            {
                "format_version": 1,
                "runtime": _V26_RUNTIME_NAME,
                "mcp_endpoint": _V26_MCP_ENDPOINT,
                "listen_host": str(snapshot.manifest.get("listen_host") or "127.0.0.1"),
                "listen_port": int(snapshot.manifest.get("listen_port") or 8899),
                "python_path": V26_PYTHON_LOCATOR,
                "schema_version": int(getattr(current, "schema_version", 14) or 14),
                "source_head": str(getattr(current, "head", "") or ""),
            }
        )
        database_identity = str(getattr(current, "state_database_identity", "") or "")
        if database_identity:
            manifest["database_identity"] = database_identity
        return _V26DeploymentSnapshot(runtime_text=runtime_text, manifest=manifest)

    def _assert_source_scope(self, source_root: Path) -> None:
        source = Path(source_root).expanduser().resolve(strict=False)
        managed_root = (self.state_dir.parent / "worktrees").resolve(strict=False)
        try:
            source.relative_to(managed_root)
        except (OSError, ValueError) as exc:
            raise LocalMaintenanceError(
                "CANDIDATE_SOURCE_SCOPE",
                "candidate source is outside the managed runtime worktree root",
            ) from exc

    def activate(self, plan: ActivationPlan) -> dict[str, object]:
        snapshot = self._read_snapshot()
        candidate = plan.candidate
        current = plan.current
        if snapshot.manifest.get("source_root") != str(current.source_root):
            raise LocalMaintenanceError("CURRENT_RUNTIME_DRIFT", "current runtime source changed after preflight")
        if snapshot.manifest.get("base_revision") not in {current.head, current.base_revision}:
            raise LocalMaintenanceError("CURRENT_RUNTIME_DRIFT", "current runtime deployment revision changed after preflight")
        if str(candidate.state_dir.resolve(strict=False)) != str(self.state_dir.resolve(strict=False)):
            raise LocalMaintenanceError("CANDIDATE_STATE_SCOPE", "candidate state is not the production v26 state directory")
        self._assert_source_scope(candidate.source_root)
        self._last_snapshot = self._portable_rollback_snapshot(snapshot, current)
        runtime_after = snapshot.runtime_text
        runtime_after = _replace_required_shell_assignment(runtime_after, "SOURCE_ROOT", candidate.source_root)
        runtime_after = _replace_required_shell_assignment(
            runtime_after,
            "EXPECTED_BASE",
            candidate.expected_base_revision or current.head,
        )
        runtime_after = _replace_required_shell_assignment(runtime_after, "EXPECTED_PATCH", candidate.expected_patch_hash)
        runtime_after = _replace_required_shell_assignment(runtime_after, "EXPECTED_PATCH_MODE", "commit")
        runtime_after = _replace_v26_python_bootstrap(runtime_after)
        manifest = dict(snapshot.manifest)
        manifest.update(
            {
                "format_version": 1,
                "runtime": _V26_RUNTIME_NAME,
                "mcp_endpoint": _V26_MCP_ENDPOINT,
                "listen_host": str(snapshot.manifest.get("listen_host") or "127.0.0.1"),
                "listen_port": int(snapshot.manifest.get("listen_port") or 8899),
                "source_root": str(candidate.source_root),
                "base_revision": candidate.expected_base_revision or current.head,
                "patch_hash": candidate.expected_patch_hash,
                "patch_mode": "commit",
                "python_path": V26_PYTHON_LOCATOR,
                "schema_version": candidate.expected_schema_version,
                "source_head": candidate.expected_head,
            }
        )
        if current.state_database_identity:
            manifest["database_identity"] = current.state_database_identity
        else:
            manifest.pop("database_identity", None)
        try:
            _atomic_replace_text(self.runtime_path, runtime_after)
            _atomic_replace_text(self.manifest_path, json.dumps(manifest, indent=2) + "\n")
            readback = self._read_snapshot()
            if readback.manifest != manifest or readback.runtime_text != runtime_after:
                raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment read-back verification failed")
            restart = self._restart()
        except Exception as exc:  # noqa: BLE001 - restore before surfacing any write/restart error
            try:
                self._restore_snapshot(self._last_snapshot or snapshot)
            except LocalMaintenanceError as restore_exc:
                raise restore_exc from exc
            if isinstance(exc, LocalMaintenanceError):
                raise
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_OUTCOME_UNKNOWN", "v26 activation outcome is unknown", outcome_unknown=True) from exc
        return {
            "status": "started",
            "source_root": str(candidate.source_root),
            "head": candidate.expected_head,
            "schema_version": candidate.expected_schema_version,
            "restart_deferred": bool(restart.deferred),
            "detail": restart.detail,
        }

    def rollback(self, plan: ActivationPlan) -> dict[str, object]:
        del plan
        snapshot = self._last_snapshot
        if snapshot is None:
            raise LocalMaintenanceError("NO_SAFE_RUNTIME_ROLLBACK", "no production deployment snapshot is available")
        self._restore_snapshot(snapshot)
        restart = self._restart()
        return {"status": "rolled_back", "restart_deferred": bool(restart.deferred), "detail": restart.detail}


def _bootstrap_v26_runtime(
    *,
    data_dir: Path | None = None,
    durable_root: Path | None = None,
    runtime_path: Path | None = None,
    manifest_path: Path | None = None,
    pid_reader: Callable[[str], int | None] | None = None,
    git_head_reader: Callable[[Path], str] | None = None,
    git_clean_reader: Callable[[Path], bool] | None = None,
    git_diff_hash_reader: Callable[[Path], str] | None = None,
    git_ancestry_reader: Callable[[Path, str, str], bool] | None = None,
    database_identity_reader: Callable[[Path], str] | None = None,
) -> MaintenanceRunResult:
    """Validate the existing v26 cold-start contract without mutating state.

    The installed LaunchAgent invokes this check before importing the server.
    It is intentionally read-only: a missing or incompatible deployment is an
    operator-visible failure, never a reason to copy the v25 database, create a
    new generation, or invoke candidate activation.
    """

    raw_data_dir = os.environ.get("LOCAL_DEV_MCP_DATA_DIR") if data_dir is None else str(data_dir)
    if not raw_data_dir:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable state directory is not configured")
    state_dir = Path(raw_data_dir).expanduser()
    if not state_dir.is_absolute() or state_dir.is_symlink() or not state_dir.is_dir():
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable state directory is unavailable")
    if durable_root is None:
        raw_root = os.environ.get("LOCAL_DEV_MCP_V26_DURABLE_ROOT")
        durable_root = Path(raw_root).expanduser() if raw_root else None
    if durable_root is None:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable root is not configured")
    root = durable_root
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable root is unsafe")
    try:
        state_dir.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 state is outside its durable root") from exc
    database = state_dir / "director.sqlite3"
    try:
        info = os.lstat(database)
    except OSError as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database is unsafe")
    identity_reader = database_identity_reader or _default_v26_database_identity_reader
    try:
        database_identity = identity_reader(database)
    except LocalMaintenanceError:
        raise
    except Exception as exc:  # noqa: BLE001 - persistence identity must fail closed
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database identity is unavailable") from exc
    if not isinstance(database_identity, str) or not re.fullmatch(r"[0-9a-f]{64}", database_identity):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 durable database identity is invalid")

    deployment_dir = root / "deployment"
    runtime_file = Path(runtime_path).expanduser() if runtime_path is not None else deployment_dir / "runtime-run"
    manifest_file = Path(manifest_path).expanduser() if manifest_path is not None else deployment_dir / "deployment-manifest.json"
    runtime_text = _read_private_deployment_file(runtime_file, label="v26 runtime wrapper")
    manifest_text = _read_private_deployment_file(manifest_file, label="v26 runtime manifest")
    if not os.access(runtime_file, os.X_OK):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime wrapper is not executable")
    try:
        manifest = json.loads(manifest_text)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime manifest is invalid")
    if manifest.get("format_version") != 1:
        raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime manifest format is unsupported")
    for key, expected in (("runtime_path", runtime_file), ("manifest_path", manifest_file)):
        if manifest.get(key) is not None and manifest.get(key) != str(expected):
            raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime deployment paths disagree")

    def assignment(name: str) -> str:
        match = re.search(rf'^{re.escape(name)}="([^"]+)"$', runtime_text, re.MULTILINE)
        if match is None:
            raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", f"v26 runtime wrapper is missing {name}")
        return match.group(1)

    source_value = assignment("SOURCE_ROOT")
    base_value = assignment("EXPECTED_BASE")
    patch_value = assignment("EXPECTED_PATCH")
    mode_value = assignment("EXPECTED_PATCH_MODE")
    source = Path(source_value).expanduser()
    if (
        not source.is_absolute()
        or source.is_symlink()
        or not source.is_dir()
        or manifest.get("source_root") != source_value
        or manifest.get("base_revision") != base_value
        or manifest.get("patch_hash") != patch_value
        or manifest.get("patch_mode") != mode_value
    ):
        raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime deployment identities disagree")
    try:
        source.resolve(strict=True).relative_to((root / "worktrees").resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise LocalMaintenanceError(
            "V26_BOOTSTRAP_SOURCE_SCOPE",
            "v26 runtime source is outside the managed runtime worktree root",
        ) from exc
    if (
        manifest.get("runtime") != _V26_RUNTIME_NAME
        or manifest.get("mcp_endpoint") != _V26_MCP_ENDPOINT
        or manifest.get("listen_host") != "127.0.0.1"
        or manifest.get("listen_port") != 8899
        or manifest.get("schema_version") != 14
        or manifest.get("python_path") != V26_PYTHON_LOCATOR
        or manifest.get("source_head") is None
        or not isinstance(manifest.get("database_identity"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("database_identity")))
    ):
        raise LocalMaintenanceError("RUNTIME_BOOTSTRAP_IDENTITY_MISMATCH", "v26 runtime identity is not the approved v26 contract")
    if not re.fullmatch(r"[0-9a-f]{40}", base_value) or not re.fullmatch(r"[0-9a-f]{64}", patch_value) or mode_value != "commit":
        raise LocalMaintenanceError("RUNTIME_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime deployment pin is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_head"))):
        raise LocalMaintenanceError("V26_BOOTSTRAP_IDENTITY_INVALID", "v26 runtime source HEAD pin is invalid")
    developer_segment = re.escape("Developer")
    repo_segment = re.escape("chatgpt-dev-mcp")
    canonical_path_pattern = (
        r"(?:/Users/[^\s\"]+/"
        + developer_segment
        + "/"
        + repo_segment
        + r"|~/"
        + developer_segment
        + "/"
        + repo_segment
        + r")(?:/[^\"]+|[\"\s])"
    )
    if (
        f"# V26_PYTHON_LOCATOR={V26_PYTHON_LOCATOR}" not in runtime_text
        or "LOCAL_DEV_MCP_WORKSPACE_ROOT" not in runtime_text
        or 'CANONICAL_ROOT="$("$WORKSPACE_LOCATOR" "chatgpt-dev-mcp")"' not in runtime_text
        or 'PYTHON_BIN="$CANONICAL_ROOT/.venv/bin/python"' not in runtime_text
        or 'export PYTHONPATH="$SOURCE_ROOT/src"' not in runtime_text
        or '"$PYTHON_BIN" -m chatgpt_dev_mcp.local_maintenance bootstrap-v26-runtime' not in runtime_text
        or 'exec "$PYTHON_BIN" -m chatgpt_dev_mcp.http_entrypoint --host 127.0.0.1 --port 8899' not in runtime_text
        or re.search(canonical_path_pattern, runtime_text)
    ):
        raise LocalMaintenanceError("V26_RUNTIME_BOOTSTRAP_NOT_PORTABLE", "v26 runtime wrapper retains a canonical repository locator")

    process_reader = pid_reader or _default_v26_runtime_pid_reader
    try:
        existing_pid = process_reader(_V26_RUNTIME_LABEL)
    except LocalMaintenanceError:
        raise
    except Exception as exc:  # noqa: BLE001 - process ownership must fail closed
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_OUTCOME_UNKNOWN", "v26 runtime process state is unavailable", outcome_unknown=True) from exc
    if existing_pid is not None and existing_pid not in {os.getpid(), os.getppid()}:
        raise LocalMaintenanceError("V26_RUNTIME_ALREADY_RUNNING", "v26 production runtime is already running")

    head_reader = git_head_reader or _default_git_head_reader
    clean_reader = git_clean_reader or _default_v26_git_clean_reader
    patch_reader = git_diff_hash_reader or _default_v26_git_patch_hash_reader
    ancestry_reader = git_ancestry_reader or _default_v26_git_ancestry_reader
    try:
        source_head = head_reader(source)
        source_clean = clean_reader(source)
        source_patch = patch_reader(source)
    except LocalMaintenanceError:
        raise
    except Exception as exc:  # noqa: BLE001 - source identity must fail closed
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_UNKNOWN", "v26 runtime source identity is unavailable") from exc
    if source_head != manifest.get("source_head"):
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_MISMATCH", "v26 runtime source HEAD differs from the deployment pin")
    if manifest.get("database_identity") != database_identity:
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_DATABASE_IDENTITY_MISMATCH", "v26 runtime database identity differs from the deployment pin")
    if source_clean is not True:
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_SOURCE_DIRTY", "v26 runtime rollback source is dirty")
    if source_patch != patch_value:
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_PATCH_MISMATCH", "v26 runtime source patch differs from the deployment pin")
    try:
        is_ancestor = ancestry_reader(source, base_value, source_head)
    except Exception as exc:  # noqa: BLE001 - ancestry must fail closed
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_UNKNOWN", "v26 runtime ancestry is unavailable") from exc
    if is_ancestor is not True:
        raise LocalMaintenanceError("RUNTIME_ROLLBACK_ANCESTRY_MISMATCH", "v26 runtime source is not descended from the deployment base")
    try:
        contract = validate_v26_bootstrap_contract(
            source,
            expected_head=source_head,
            git_head_reader=lambda _root: source_head,
            git_clean_reader=lambda _root: source_clean,
        )
        revalidated_database_identity = identity_reader(database)
        revalidated_head = head_reader(source)
        revalidated_clean = clean_reader(source)
        revalidated_patch = patch_reader(source)
    except RuntimeActivationError as exc:
        raise LocalMaintenanceError(exc.code, str(exc)) from exc
    except LocalMaintenanceError:
        raise
    except Exception as exc:  # noqa: BLE001 - TOCTOU identity must fail closed
        raise LocalMaintenanceError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_UNKNOWN",
            "v26 runtime deployment identity changed or could not be revalidated",
        ) from exc
    if (
        str(contract.get("status", "")).upper() != "PASS"
        or str(contract.get("head", "")) != source_head
        or revalidated_database_identity != database_identity
        or revalidated_head != source_head
        or revalidated_clean is not True
        or revalidated_patch != source_patch
    ):
        if revalidated_database_identity != database_identity:
            raise LocalMaintenanceError(
                "RUNTIME_ROLLBACK_DATABASE_IDENTITY_MISMATCH",
                "v26 runtime database identity changed during bootstrap validation",
            )
        if revalidated_clean is not True:
            raise LocalMaintenanceError("RUNTIME_ROLLBACK_SOURCE_DIRTY", "v26 runtime rollback source changed during bootstrap validation")
        raise LocalMaintenanceError(
            "RUNTIME_ROLLBACK_BOOTSTRAP_IDENTITY_MISMATCH",
            "v26 runtime source identity changed during bootstrap validation",
        )
    return MaintenanceRunResult(
        0,
        True,
        f"v26 bootstrap contract validated: source_head={source_head}; database_identity={database_identity}; no activation performed",
    )


def _repin_v26_runtime(
    *,
    source_root: Path | None = None,
    runtime_path: Path | None = None,
    manifest_path: Path | None = None,
    uid_provider: Callable[[], int] | None = None,
    git_head_reader: Callable[[Path], str] | None = None,
    git_parent_reader: Callable[[Path], str] | None = None,
    git_diff_reader: Callable[[Path], bytes] | None = None,
    restart_runner: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
) -> MaintenanceRunResult:
    root = (source_root or Path(__file__).resolve().parents[2]).resolve()
    runtime = runtime_path or _V26_RUNTIME_RUN
    manifest_file = manifest_path or _V26_RUNTIME_MANIFEST
    head_reader = git_head_reader or _default_git_head_reader
    parent_reader = git_parent_reader or _default_git_parent_reader
    diff_reader = git_diff_reader or _default_git_diff_reader
    provider = uid_provider or os.getuid
    runner = restart_runner or _run_fixed_v26_runtime_restart

    if not (root / "src" / "chatgpt_dev_mcp").is_dir() and source_root is None:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "canonical v26 runtime source is unavailable")
    uid = provider()
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_UID_INVALID", "local user identity is invalid")

    head = head_reader(root)
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime source revision is invalid")
    patch_hash = hashlib.sha256(diff_reader(root)).hexdigest()

    try:
        runtime_text = runtime.read_text(encoding="utf-8")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment identity is unreadable") from exc
    if not isinstance(manifest, dict):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime manifest is invalid")

    source_match = re.search(r'^SOURCE_ROOT="([^"]+)"$', runtime_text, re.MULTILINE)
    base_match = re.search(r'^EXPECTED_BASE="([^"]+)"$', runtime_text, re.MULTILINE)
    patch_match = re.search(r'^EXPECTED_PATCH="([^"]+)"$', runtime_text, re.MULTILINE)
    if source_match is None or base_match is None or patch_match is None:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime wrapper format is invalid")
    if manifest.get("source_root") != source_match.group(1):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment source identities disagree")
    deployment_base = base_match.group(1)
    if manifest.get("base_revision") != deployment_base:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment base identities disagree")
    if deployment_base != head:
        parent = parent_reader(root)
        if deployment_base != parent or source_match.group(1) != str(root):
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_FAILED",
                "v26 runtime deployment base does not match current HEAD or its immediate parent",
            )

    runtime_after = re.sub(r'^SOURCE_ROOT="[^"]+"$', f'SOURCE_ROOT="{root}"', runtime_text, flags=re.MULTILINE)
    runtime_after = re.sub(r'^EXPECTED_BASE="[^"]+"$', f'EXPECTED_BASE="{head}"', runtime_after, flags=re.MULTILINE)
    runtime_after = re.sub(r'^EXPECTED_PATCH="[^"]+"$', f'EXPECTED_PATCH="{patch_hash}"', runtime_after, flags=re.MULTILINE)
    manifest["source_root"] = str(root)
    manifest["base_revision"] = head
    manifest["patch_hash"] = patch_hash

    _atomic_replace_text(runtime, runtime_after)
    _atomic_replace_text(manifest_file, json.dumps(manifest, indent=2) + "\n")

    readback_runtime = runtime.read_text(encoding="utf-8")
    readback_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if (
        f'SOURCE_ROOT="{root}"' not in readback_runtime
        or f'EXPECTED_BASE="{head}"' not in readback_runtime
        or f'EXPECTED_PATCH="{patch_hash}"' not in readback_runtime
        or readback_manifest.get("source_root") != str(root)
        or readback_manifest.get("base_revision") != head
        or readback_manifest.get("patch_hash") != patch_hash
    ):
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime deployment read-back verification failed")

    result = runner(("launchctl", "kickstart", "-k", f"gui/{uid}/{_V26_RUNTIME_LABEL}"))
    if not isinstance(result, MaintenanceRunResult) or not result.outcome_known:
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "v26 runtime restart outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        )
    if result.exit_code != 0:
        raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "v26 runtime restart failed")
    return MaintenanceRunResult(0, True, f"source={root}; base={head}; patch={patch_hash}; runtime restarted")


def _default_shortcut_writer() -> MaintenanceRunResult:
    desktop = Path.home() / "Desktop"
    target = desktop / "Restart ChatGPT Dev MCP.command"
    temporary = desktop / ".Restart ChatGPT Dev MCP.command.tmp"
    content = """#!/bin/zsh
set -u

label='com.openai.chatgpt-dev-mcp-tunnel'
target="gui/$(/usr/bin/id -u)/$label"

echo "Restarting ChatGPT Dev MCP Tunnel..."
if /bin/launchctl kickstart -k "$target"; then
  for _ in {1..60}; do
    if /usr/bin/curl --fail --silent --show-error --max-time 1 http://127.0.0.1:8080/healthz | /usr/bin/grep -qx live \
      && /usr/bin/curl --fail --silent --show-error --max-time 1 http://127.0.0.1:8080/readyz | /usr/bin/grep -qx ready; then
      echo "Tunnel is ready."
      exit 0
    fi
    /bin/sleep 0.5
  done
  echo "Restart was requested but Tunnel readiness was not confirmed."
  exit 75
fi

status=$?
echo "Restart failed with exit code $status."
echo "Target: $target"
sleep 5
exit "$status"
"""
    try:
        desktop.mkdir(parents=True, exist_ok=True)
        temporary.write_text(content, encoding="utf-8")
        temporary.chmod(0o755)
        os.replace(temporary, target)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise LocalMaintenanceError(
            "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
            "local maintenance outcome is unknown; automatic retry is forbidden",
            outcome_unknown=True,
        ) from exc
    return MaintenanceRunResult(0, True, str(target))


class LocalMaintenanceController:
    _DEV_MCP_LABEL = "com.openai.chatgpt-dev-mcp-tunnel"

    def __init__(
        self,
        *,
        grant_store: TrustedGrantStore,
        runner: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
        shortcut_writer: Callable[[], MaintenanceRunResult] | None = None,
        toolchain_installer: Callable[[], MaintenanceRunResult] | None = None,
        uid_provider: Callable[[], int] | None = None,
        restart_scheduler: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
    ) -> None:
        self._grant_store = grant_store
        self._runner = runner or _default_runner
        self._shortcut_writer = shortcut_writer or _default_shortcut_writer
        self._toolchain_installer = toolchain_installer or _install_fixed_dev_toolchain
        self._uid_provider = uid_provider or os.getuid
        self._restart_scheduler = restart_scheduler

    def execute(
        self,
        *,
        action: object,
        binding: GrantBinding,
        grant_id: object,
        policy_digest: str,
        policy_enabled: bool,
    ) -> dict[str, object]:
        if policy_enabled is not True:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_POLICY_DISABLED", "local maintenance auto-approval is disabled")
        if action not in {"restart_dev_mcp_tunnel", "create_mcp_restart_shortcut", "install_dev_toolchain"}:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_ACTION_UNKNOWN", "unknown local maintenance action")
        try:
            self._grant_store.validate(
                grant_id,
                binding=binding,
                operation=action,
                policy_digest=policy_digest,
            )
        except ApprovalPolicyError as exc:
            raise LocalMaintenanceError(exc.code, str(exc)) from exc
        if action in {"create_mcp_restart_shortcut", "install_dev_toolchain"}:
            fixed_action = self._shortcut_writer if action == "create_mcp_restart_shortcut" else self._toolchain_installer
            if fixed_action is None:
                raise LocalMaintenanceError("LOCAL_MAINTENANCE_TOOLCHAIN_UNAVAILABLE", "developer toolchain installer is unavailable")
            try:
                result = fixed_action()
            except LocalMaintenanceError:
                raise
            except Exception as exc:
                raise LocalMaintenanceError(
                    "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                    "local maintenance outcome is unknown; automatic retry is forbidden",
                    outcome_unknown=True,
                ) from exc
            if not isinstance(result, MaintenanceRunResult) or not result.outcome_known:
                raise LocalMaintenanceError(
                    "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                    "local maintenance outcome is unknown; automatic retry is forbidden",
                    outcome_unknown=True,
                )
            if result.exit_code != 0:
                raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "local maintenance action failed")
            return {
                "status": "succeeded",
                "action": action,
                "risk_class": "R2",
                "authorization_mode": "trusted_session_grant",
                "detail": result.detail,
                "external_execution": False,
            }
        uid = self._uid_provider()
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_UID_INVALID", "local user identity is invalid")
        argv = ("launchctl", "kickstart", "-k", f"gui/{uid}/{self._DEV_MCP_LABEL}")
        try:
            runner = self._restart_scheduler or self._runner
            result = runner(argv)
        except LocalMaintenanceError:
            raise
        except Exception as exc:
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "local maintenance outcome is unknown; automatic retry is forbidden",
                outcome_unknown=True,
            ) from exc
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known:
            raise LocalMaintenanceError(
                "LOCAL_MAINTENANCE_OUTCOME_UNKNOWN",
                "local maintenance outcome is unknown; automatic retry is forbidden",
                outcome_unknown=True,
            )
        if result.exit_code != 0:
            raise LocalMaintenanceError("LOCAL_MAINTENANCE_FAILED", "local maintenance command failed")
        status = "recovering" if result.deferred else "succeeded"
        receipt = {
            "status": status,
            "action": action,
            "risk_class": "R2",
            "authorization_mode": "trusted_session_grant",
            "detail": result.detail,
            "external_execution": False,
        }
        return receipt


def _bootstrap_main(
    argv: Sequence[str],
    *,
    shortcut_writer: Callable[[], MaintenanceRunResult] | None = None,
    restart_scheduler: Callable[[tuple[str, ...]], MaintenanceRunResult] | None = None,
    v26_runtime_reloader: Callable[[], MaintenanceRunResult] | None = None,
    uid_provider: Callable[[], int] | None = None,
) -> int:
    """Run one fixed local maintenance action without requiring an MCP session."""

    args = tuple(argv)
    if args == ("shortcut",):
        writer = shortcut_writer or _default_shortcut_writer
        try:
            result = writer()
        except Exception:
            return 1
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known or result.exit_code != 0:
            return 1
        if result.detail:
            print(result.detail)
        return 0
    if args == ("restart",):
        provider = uid_provider or os.getuid
        uid = provider()
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            return 2
        runner = restart_scheduler or _schedule_detached_restart
        target = f"gui/{uid}/{LocalMaintenanceController._DEV_MCP_LABEL}"
        try:
            result = runner(("launchctl", "kickstart", "-k", target))
        except Exception:
            return 1
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known or result.exit_code != 0:
            return 1
        if result.detail:
            print(result.detail)
        return 0
    if args == ("repin-v26-runtime",):
        reloader = v26_runtime_reloader or _repin_v26_runtime
        try:
            result = reloader()
        except Exception:
            return 1
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known or result.exit_code != 0:
            return 1
        if result.detail:
            print(result.detail)
        return 0
    if args == ("bootstrap-v26-runtime",):
        try:
            result = _bootstrap_v26_runtime()
        except Exception:
            return 1
        if not isinstance(result, MaintenanceRunResult) or not result.outcome_known or result.exit_code != 0:
            return 1
        if result.detail:
            print(result.detail)
        return 0
    return 2


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == _DETACHED_RESTART_FLAG:
        raise SystemExit(_run_detached_restart(sys.argv[2]))
    raise SystemExit(_bootstrap_main(sys.argv[1:]))


__all__ = [
    "LocalMaintenanceController",
    "LocalMaintenanceError",
    "MaintenanceRunResult",
    "V26RuntimeDeployment",
]
