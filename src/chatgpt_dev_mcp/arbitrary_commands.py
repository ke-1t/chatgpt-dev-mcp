"""Approval-bound argv command execution for DEVELOPMENT workspaces.

The controller creates an immutable one-shot request and executes only the
exact, revalidated argv in the bound managed worktree.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
from typing import Sequence

from .approval import ApprovalError, UnifiedApprovalStore


class ArbitraryCommandError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WorkspaceCommandBinding:
    workspace_id: str
    working_tree_id: str
    root: str
    root_device: int
    root_inode: int
    revision: str
    state_hash: str
    task_id: str | None = None

    def fingerprint_payload(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "working_tree_id": self.working_tree_id,
            "root": self.root,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "revision": self.revision,
            "state_hash": self.state_hash,
            "task_id": self.task_id,
        }


@dataclass(frozen=True)
class CommandExecPolicy:
    enabled: bool = True
    allow_shell: bool = False
    max_argv_items: int = 64
    max_arg_length: int = 4096
    max_shell_length: int = 16000
    max_timeout_ms: int = 120000
    max_output_bytes: int = 1048576


@dataclass(frozen=True)
class CommandExecutionRequest:
    binding: WorkspaceCommandBinding
    argv: tuple[str, ...]
    shell_command: str
    workdir: str
    timeout_ms: int
    yield_time_ms: int
    max_output_bytes: int
    required_permissions: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class _PendingCommand:
    request: CommandExecutionRequest


_SHELL_EXECUTABLES = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "pwsh", "powershell", "cmd", "cmd.exe"}
)
_PRIVILEGED_EXECUTABLES = frozenset({"sudo", "doas", "su", "runas"})
_COMPOSITION_EXECUTABLES = frozenset({"env", "xargs", "busybox"})
_SHELL_META_RE = re.compile(r"[|;&<>`]|\x24\(|\x24\{|\n|\r|\x00")
_INTERPRETER_FLAGS = frozenset({"-c", "--command", "-e", "--eval", "-exec", "--exec"})


def _bounded_string(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", f"{field} is invalid")
    return value


def _normalize_workdir(root: Path, raw: object) -> str:
    text = _bounded_string(raw, field="workdir", maximum=512)
    candidate = Path(text)
    if candidate.is_absolute() or any(part in {"", ".."} for part in candidate.parts):
        raise ArbitraryCommandError("COMMAND_EXEC_WORKDIR_INVALID", "workdir must stay inside the bound workspace")
    resolved_root = root.resolve(strict=True)
    try:
        resolved = (resolved_root / candidate).resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ArbitraryCommandError("COMMAND_EXEC_WORKDIR_INVALID", "workdir must stay inside the bound workspace") from exc
    if not resolved.is_dir():
        raise ArbitraryCommandError("COMMAND_EXEC_WORKDIR_INVALID", "workdir must be a directory")
    relative = resolved.relative_to(resolved_root)
    return "." if not relative.parts else relative.as_posix()


def _validate_binding(binding: WorkspaceCommandBinding) -> None:
    if not isinstance(binding, WorkspaceCommandBinding):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "workspace binding is required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", binding.workspace_id):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "workspace id is invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", binding.working_tree_id):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "working tree id is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", binding.revision):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "revision is invalid")
    if binding.state_hash and not re.fullmatch(r"[0-9a-f]{64}", binding.state_hash):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "state hash is invalid")
    if binding.task_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", binding.task_id):
        raise ArbitraryCommandError("WORKSPACE_BINDING_INVALID", "task id is invalid")
    try:
        root = Path(binding.root).resolve(strict=True)
        stat = root.stat()
    except OSError as exc:
        raise ArbitraryCommandError("WORKSPACE_BINDING_STALE", "workspace root is unavailable") from exc
    if not root.is_dir() or int(stat.st_dev) != binding.root_device or int(stat.st_ino) != binding.root_inode:
        raise ArbitraryCommandError("WORKSPACE_BINDING_STALE", "workspace root identity changed")


def _permission_hints(argv: Sequence[str], shell_command: str) -> tuple[str, ...]:
    permissions: set[str] = set()
    if shell_command:
        permissions.update({"shell_expansion", "inline_script"})
    executable = Path(argv[0]).name.lower() if argv else ""
    if executable in {"sudo", "doas", "su"}:
        permissions.add("privileged_executable")
    return tuple(sorted(permissions))


def _validate_argv(argv: Sequence[str]) -> None:
    executable = Path(argv[0]).name.casefold()
    if executable in _SHELL_EXECUTABLES or executable in _PRIVILEGED_EXECUTABLES:
        raise ArbitraryCommandError("COMMAND_EXECUTABLE_DENIED", "shell or privileged executables are not allowed")
    if executable in _COMPOSITION_EXECUTABLES:
        raise ArbitraryCommandError("COMMAND_EXECUTABLE_DENIED", "command composition executables are not allowed")
    for item in argv:
        if _SHELL_META_RE.search(item):
            raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "argv contains unsupported command composition")
        path_value = item.split("=", 1)[1] if "=" in item else item
        if (
            path_value.startswith(("/", "~/", "~\\", "\\"))
            or re.match(r"^[A-Za-z]:[\\/]", path_value) is not None
            or ".." in Path(path_value).parts
        ):
            raise ArbitraryCommandError(
                "COMMAND_EXEC_PATH_DENIED",
                "argv may not select an absolute, parent-relative, or external workspace path",
            )
    if any(item.casefold() in _INTERPRETER_FLAGS for item in argv[1:]):
        raise ArbitraryCommandError("COMMAND_EXECUTABLE_DENIED", "inline interpreter execution is not allowed")


class ArbitraryCommandController:
    def __init__(self, approvals: UnifiedApprovalStore, *, policy: CommandExecPolicy | None = None) -> None:
        self._approvals = approvals
        self._policy = policy or CommandExecPolicy()
        self._pending: dict[str, _PendingCommand] = {}

    @staticmethod
    def _fingerprint(request: CommandExecutionRequest) -> str:
        payload = {
            "binding": request.binding.fingerprint_payload(),
            "argv_hash": hashlib.sha256("\x00".join(request.argv).encode()).hexdigest(),
            "shell_hash": hashlib.sha256(request.shell_command.encode()).hexdigest() if request.shell_command else "",
            "workdir": request.workdir,
            "timeout_ms": request.timeout_ms,
            "yield_time_ms": request.yield_time_ms,
            "max_output_bytes": request.max_output_bytes,
            "required_permissions": request.required_permissions,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def preflight(
        self,
        binding: WorkspaceCommandBinding,
        *,
        argv: Sequence[str] | None = None,
        shell_command: str | None = None,
        workdir: str = ".",
        timeout_ms: int = 30000,
        yield_time_ms: int = 10000,
        max_output_bytes: int = 65536,
    ) -> dict[str, object]:
        if not self._policy.enabled:
            raise ArbitraryCommandError("COMMAND_EXEC_DISABLED", "arbitrary command execution is disabled")
        _validate_binding(binding)
        if (argv is None) == (shell_command is None):
            raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "choose exactly one command mode")
        parsed_argv: tuple[str, ...] = ()
        parsed_shell = ""
        if argv is not None:
            if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not 1 <= len(argv) <= self._policy.max_argv_items:
                raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "argv must be a bounded non-empty list")
            parsed_argv = tuple(_bounded_string(item, field="argv", maximum=self._policy.max_arg_length) for item in argv)
            _validate_argv(parsed_argv)
        else:
            if not self._policy.allow_shell:
                raise ArbitraryCommandError("COMMAND_EXEC_SHELL_DENIED", "shell command mode is disabled by operator policy")
            parsed_shell = _bounded_string(shell_command, field="shell_command", maximum=self._policy.max_shell_length)
            if _SHELL_META_RE.search(parsed_shell):
                raise ArbitraryCommandError("COMMAND_EXEC_SHELL_COMPOSITION_DENIED", "shell composition is not allowed")
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= self._policy.max_timeout_ms:
            raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "timeout is outside the policy bound")
        if isinstance(yield_time_ms, bool) or not isinstance(yield_time_ms, int) or not 0 <= yield_time_ms <= 30000:
            raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "yield time is outside the policy bound")
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= self._policy.max_output_bytes:
            raise ArbitraryCommandError("COMMAND_EXEC_ARGUMENT_INVALID", "output bound is outside the policy limit")
        normalized_workdir = _normalize_workdir(Path(binding.root), workdir)
        permissions = _permission_hints(parsed_argv, parsed_shell)
        draft = CommandExecutionRequest(
            binding=binding,
            argv=parsed_argv,
            shell_command=parsed_shell,
            workdir=normalized_workdir,
            timeout_ms=timeout_ms,
            yield_time_ms=yield_time_ms,
            max_output_bytes=max_output_bytes,
            required_permissions=permissions,
            fingerprint="",
        )
        fingerprint = self._fingerprint(draft)
        request = CommandExecutionRequest(
            binding=draft.binding,
            argv=draft.argv,
            shell_command=draft.shell_command,
            workdir=draft.workdir,
            timeout_ms=draft.timeout_ms,
            yield_time_ms=draft.yield_time_ms,
            max_output_bytes=draft.max_output_bytes,
            required_permissions=draft.required_permissions,
            fingerprint=fingerprint,
        )
        confirmation = f"Run approved command in {binding.workspace_id} at {binding.working_tree_id}"
        approval = self._approvals.issue("command_exec", binding.workspace_id, fingerprint, confirmation)
        self._pending[approval.approval_id] = _PendingCommand(request)
        return {
            "status": "ready",
            "approval_token": approval.approval_id,
            "confirmation": confirmation,
            "workspace_id": binding.workspace_id,
            "working_tree_id": binding.working_tree_id,
            "fingerprint": fingerprint,
            "required_permissions": list(permissions),
            "timeout_ms": timeout_ms,
            "max_output_bytes": max_output_bytes,
            "one_shot": True,
        }

    def consume(
        self,
        approval_token: str,
        confirmation: str,
        *,
        current_binding: WorkspaceCommandBinding,
    ) -> CommandExecutionRequest:
        pending = self._pending.pop(approval_token, None)
        if pending is None:
            raise ArbitraryCommandError("COMMAND_EXEC_PREFLIGHT_INVALID", "command preflight is unknown or already consumed")
        request = pending.request
        _validate_binding(current_binding)
        if current_binding != request.binding:
            raise ArbitraryCommandError("WORKSPACE_BINDING_STALE", "workspace binding changed after command preflight")
        try:
            self._approvals.consume(
                approval_token,
                confirmation,
                operation="command_exec",
                workspace_id=request.binding.workspace_id,
                fingerprint=request.fingerprint,
            )
        except ApprovalError as exc:
            raise ArbitraryCommandError(exc.code, str(exc)) from exc
        return request

    @staticmethod
    def _safe_environment() -> dict[str, str]:
        """Return a small non-secret environment; caller input is never merged."""

        allowed = {"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "TERM"}
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in allowed and isinstance(value, str) and "\x00" not in value and "\n" not in value and "\r" not in value
        }
        environment.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        return environment

    def execute(self, request: CommandExecutionRequest) -> dict[str, object]:
        """Run one consumed argv request with shell=False and bounded output."""

        if not isinstance(request, CommandExecutionRequest):
            raise ArbitraryCommandError("COMMAND_EXEC_REQUEST_INVALID", "command request is invalid")
        if request.shell_command:
            raise ArbitraryCommandError("COMMAND_EXEC_SHELL_DENIED", "shell command mode is not available for public execution")
        _validate_binding(request.binding)
        _validate_argv(request.argv)
        root = Path(request.binding.root).resolve(strict=True)
        workdir = _normalize_workdir(root, request.workdir)
        cwd = root if workdir == "." else root / workdir
        started = time.monotonic()
        command_id = "command:" + hashlib.sha256(
            f"{request.fingerprint}:{started}".encode("utf-8")
        ).hexdigest()[:24]
        try:
            process = subprocess.Popen(
                list(request.argv),
                cwd=str(cwd),
                env=self._safe_environment(),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ArbitraryCommandError("COMMAND_EXECUTABLE_NOT_FOUND", "the requested executable is unavailable") from exc
        except (OSError, ValueError) as exc:
            raise ArbitraryCommandError("COMMAND_EXEC_START_FAILED", "the command could not be started") from exc

        maximum = request.max_output_bytes
        output_buffer = bytearray()
        output_total = 0
        output_truncated = False

        def drain_output() -> None:
            nonlocal output_total, output_truncated
            stream = process.stdout
            if stream is None:
                return
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                output_total += len(chunk)
                if len(output_buffer) < maximum:
                    remaining = maximum - len(output_buffer)
                    output_buffer.extend(chunk[:remaining])
                if output_total > maximum:
                    output_truncated = True

        reader = threading.Thread(target=drain_output, name="arbitrary-command-output", daemon=True)
        reader.start()
        timed_out = False
        try:
            process.wait(timeout=request.timeout_ms / 1000.0)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    process.kill()
                process.wait()
        reader.join(timeout=1.0)
        if reader.is_alive():
            # The process group has already been terminated.  Close the pipe
            # so a detached descendant cannot keep a reader thread alive.
            if process.stdout is not None:
                process.stdout.close()
            reader.join(timeout=0.25)
        elif process.stdout is not None:
            process.stdout.close()
        bounded = bytes(output_buffer).decode("utf-8", "replace")
        # Keep output redaction local to this controller so secrets printed by
        # a child do not cross the public tool boundary.
        from .director import redact_secrets

        output = redact_secrets(bounded)
        return {
            "command_execution_id": command_id,
            "status": "timeout" if timed_out else ("succeeded" if process.returncode == 0 else "failed"),
            "exit_code": None if timed_out else process.returncode,
            "output": output,
            "output_truncated": output_truncated,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "workspace_id": request.binding.workspace_id,
            "working_tree_id": request.binding.working_tree_id,
            "task_id": request.binding.task_id,
            "session_id": request.binding.working_tree_id if request.binding.working_tree_id.startswith("session:") else None,
            "revision": request.binding.revision,
            "receipt": {
                "receipt_id": command_id,
                "workspace_id": request.binding.workspace_id,
                "working_tree_id": request.binding.working_tree_id,
                "task_id": request.binding.task_id,
                "session_id": request.binding.working_tree_id if request.binding.working_tree_id.startswith("session:") else None,
                "status": "timeout" if timed_out else ("succeeded" if process.returncode == 0 else "failed"),
            },
            "external_execution": False,
        }
