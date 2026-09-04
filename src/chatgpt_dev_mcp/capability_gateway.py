"""Bounded fail-soft gateway for optional local capability providers."""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import selectors
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .director import contains_secret_like_content, redact_secrets

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_CAP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INLINE_SECRET_RE = re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s\"',;}]+")
_MAX_REQUEST_BYTES = 64 * 1024


class CapabilityGatewayError(ValueError):
    pass


class StdioMCPProvider:
    """Minimal configured MCP stdio client with fixed argv and no shell."""

    def __init__(self, *, argv: tuple[str, ...], capability_tools: Mapping[str, str | tuple[str, ...]], timeout_ms: int = 5000) -> None:
        if not isinstance(argv, tuple) or not 1 <= len(argv) <= 32 or any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in argv):
            raise CapabilityGatewayError("stdio provider argv is invalid")
        executable = argv[0]
        resolved = str(Path(executable).resolve()) if Path(executable).is_absolute() else (shutil.which(executable) or "")
        if not resolved or not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
            raise CapabilityGatewayError("stdio provider executable is unavailable")
        if not isinstance(capability_tools, Mapping) or not capability_tools:
            raise CapabilityGatewayError("capability tool mapping is invalid")
        mapping: dict[str, tuple[str, ...]] = {}
        for capability, raw_names in capability_tools.items():
            if isinstance(raw_names, str):
                names = (raw_names,)
            else:
                names = raw_names
            if (
                not isinstance(capability, str)
                or not _CAP_RE.fullmatch(capability)
                or not isinstance(names, tuple)
                or not names
                or len(names) > 16
                or len(set(names)) != len(names)
                or any(not isinstance(name, str) or not _CAP_RE.fullmatch(name) for name in names)
            ):
                raise CapabilityGatewayError("capability tool mapping is invalid")
            mapping[capability] = names
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 120_000:
            raise CapabilityGatewayError("stdio provider timeout is outside bounds")
        self._argv = (resolved, *argv[1:])
        self._capability_tools = dict(sorted(mapping.items()))
        self._timeout_ms = timeout_ms
        self._last_tool_names: tuple[str, ...] = ()
        self._process: subprocess.Popen[str] | None = None
        self._request_id = 0
        self._child_generation = 0
        self._last_invocation_reused = False
        self._lock = threading.RLock()

    @staticmethod
    def select_advertised_tool(
        capability: str,
        capability_tools: Mapping[str, str | tuple[str, ...]],
        advertised_names: tuple[str, ...],
    ) -> str:
        if not isinstance(capability, str) or not _CAP_RE.fullmatch(capability):
            raise CapabilityGatewayError("capability is invalid")
        raw_names = capability_tools.get(capability)
        if raw_names is None:
            raise CapabilityGatewayError("capability is not mapped by stdio provider")
        names = (raw_names,) if isinstance(raw_names, str) else raw_names
        if (
            not isinstance(names, tuple)
            or not names
            or len(names) > 16
            or len(set(names)) != len(names)
            or any(not isinstance(name, str) or not _CAP_RE.fullmatch(name) for name in names)
        ):
            raise CapabilityGatewayError("capability tool mapping is invalid")
        advertised = set(advertised_names)
        for name in names:
            if name in advertised:
                return name
        raise CapabilityGatewayError("mapped MCP tool is not advertised")

    @property
    def shell_enabled(self) -> bool:
        return False

    @property
    def last_tool_names(self) -> tuple[str, ...]:
        with self._lock:
            return self._last_tool_names

    @property
    def last_invocation_reused(self) -> bool:
        with self._lock:
            return self._last_invocation_reused

    def process_environment(self) -> dict[str, str]:
        current = os.environ.get("PATH", "")
        entries = [str(Path(self._argv[0]).parent)]
        entries.extend(item for item in current.split(os.pathsep) if item)
        return {"PATH": os.pathsep.join(dict.fromkeys(entries))}

    def status(self) -> dict[str, object]:
        executable = Path(self._argv[0])
        available = executable.is_file() and os.access(executable, os.X_OK)
        with self._lock:
            process = self._process
            child_alive = process is not None and process.poll() is None
            return {
                "status": "available" if available else "unavailable",
                "detail": "configured_stdio_mcp" if available else "executable_unavailable",
                "child_state": "ready" if child_alive else "stopped",
                "child_generation": self._child_generation,
                "child_pid": process.pid if child_alive else None,
                "last_invocation_reused": self._last_invocation_reused,
            }

    @staticmethod
    def _send(process: subprocess.Popen[str], message: Mapping[str, object]) -> None:
        if process.stdin is None:
            raise RuntimeError("stdio provider stdin is unavailable")
        process.stdin.write(json.dumps(dict(message), ensure_ascii=False, separators=(",", ":")) + "\n")
        process.stdin.flush()

    def _receive(self, process: subprocess.Popen[str], request_id: int) -> Mapping[str, object]:
        if process.stdout is None:
            raise RuntimeError("stdio provider stdout is unavailable")
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                events = selector.select(self._timeout_ms / 1000.0)
                if not events:
                    raise TimeoutError("stdio MCP response timed out")
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("stdio MCP provider exited before response")
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(message, Mapping) or message.get("id") != request_id:
                    continue
                if "error" in message:
                    raise RuntimeError("stdio MCP provider returned JSON-RPC error")
                result = message.get("result")
                if not isinstance(result, Mapping):
                    raise RuntimeError("stdio MCP provider returned invalid result")
                return result
        finally:
            selector.close()

    def _request(self, process: subprocess.Popen[str], request_id: int, method: str, params: Mapping[str, object] | None = None) -> Mapping[str, object]:
        message: dict[str, object] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = dict(params)
        self._send(process, message)
        return self._receive(process, request_id)

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    @staticmethod
    def _stop(process: subprocess.Popen[str]) -> None:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=0.2)
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()

    def _stop_owned_child(self) -> None:
        process = self._process
        self._process = None
        self._last_tool_names = ()
        self._request_id = 0
        if process is not None:
            self._stop(process)

    def _start_owned_child(self) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            list(self._argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            shell=False,
            env=self.process_environment(),
        )
        self._process = process
        self._child_generation += 1
        self._request_id = 0
        try:
            self._request(
                process,
                self._next_request_id(),
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "chatgpt-dev-mcp-capability-gateway", "version": "1"},
                },
            )
            self._send(process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            listed = self._request(process, self._next_request_id(), "tools/list", {})
            raw_tools = listed.get("tools", [])
            self._last_tool_names = (
                tuple(
                    sorted(
                        str(item.get("name"))
                        for item in raw_tools
                        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                    )
                )
                if isinstance(raw_tools, list)
                else ()
            )
        except Exception:
            self._stop_owned_child()
            raise
        return process

    def _ready_child(self) -> tuple[subprocess.Popen[str], bool]:
        process = self._process
        if process is not None and process.poll() is None and self._last_tool_names:
            return process, True
        if process is not None:
            self._stop_owned_child()
        return self._start_owned_child(), False

    def invoke(self, capability: str, request: dict[str, object]) -> object:
        if capability not in self._capability_tools:
            raise CapabilityGatewayError("capability is not mapped by stdio provider")
        with self._lock:
            process, reused = self._ready_child()
            self._last_invocation_reused = reused
            tool_name = self.select_advertised_tool(capability, self._capability_tools, self._last_tool_names)
            try:
                return self._request(
                    process,
                    self._next_request_id(),
                    "tools/call",
                    {"name": tool_name, "arguments": request},
                )
            except Exception:
                self._stop_owned_child()
                raise

    def restart(self) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._last_invocation_reused = False
            self._stop_owned_child()


@dataclass(frozen=True)
class CapabilityDescriptor:
    provider_id: str
    capabilities: tuple[str, ...]
    timeout_ms: int = 5000
    max_output_bytes: int = 16 * 1024
    restart_budget: int = 0
    optional: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not _ID_RE.fullmatch(self.provider_id):
            raise CapabilityGatewayError("provider_id is invalid")
        if not isinstance(self.capabilities, tuple) or not self.capabilities or len(self.capabilities) > 64 or len(set(self.capabilities)) != len(self.capabilities) or any(not isinstance(item, str) or not _CAP_RE.fullmatch(item) for item in self.capabilities):
            raise CapabilityGatewayError("capabilities are invalid")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int) or not 1 <= self.timeout_ms <= 120_000:
            raise CapabilityGatewayError("timeout_ms is outside bounds")
        if isinstance(self.max_output_bytes, bool) or not isinstance(self.max_output_bytes, int) or not 128 <= self.max_output_bytes <= 1024 * 1024:
            raise CapabilityGatewayError("max_output_bytes is outside bounds")
        if isinstance(self.restart_budget, bool) or not isinstance(self.restart_budget, int) or not 0 <= self.restart_budget <= 8:
            raise CapabilityGatewayError("restart_budget is outside bounds")
        if not isinstance(self.optional, bool):
            raise CapabilityGatewayError("optional must be boolean")


@dataclass
class _ProviderRecord:
    descriptor: CapabilityDescriptor
    provider: object | None
    restarts_used: int = 0


def _request(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CapabilityGatewayError("request must be an object")
    candidate = dict(value)
    try:
        encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise CapabilityGatewayError("request is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_REQUEST_BYTES:
        raise CapabilityGatewayError("request exceeds safety bound")
    if contains_secret_like_content(encoded) or _INLINE_SECRET_RE.search(encoded):
        raise CapabilityGatewayError("raw secret-like request content is not allowed")
    return candidate


def _bounded_output(value: object, maximum: int) -> tuple[str, bool]:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            text = repr(value)
    text = _INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", redact_secrets(text))
    encoded = text.encode("utf-8")
    return (text, False) if len(encoded) <= maximum else (encoded[:maximum].decode("utf-8", errors="ignore"), True)


class CapabilityGateway:
    def __init__(self) -> None:
        self._providers: dict[str, _ProviderRecord] = {}

    def register(self, descriptor: CapabilityDescriptor, provider: object | None) -> None:
        if not isinstance(descriptor, CapabilityDescriptor):
            raise CapabilityGatewayError("descriptor is invalid")
        if descriptor.provider_id in self._providers:
            raise CapabilityGatewayError("provider is already registered")
        if provider is not None and (not callable(getattr(provider, "status", None)) or not callable(getattr(provider, "invoke", None))):
            raise CapabilityGatewayError("provider does not implement status/invoke")
        self._providers[descriptor.provider_id] = _ProviderRecord(descriptor, provider)

    @staticmethod
    def _provider_status(record: _ProviderRecord) -> dict[str, object]:
        descriptor = record.descriptor
        if record.provider is None:
            return {"provider_id": descriptor.provider_id, "status": "unavailable", "capabilities": list(descriptor.capabilities), "optional": descriptor.optional, "restarts_used": record.restarts_used}
        try:
            raw = record.provider.status()
        except Exception:
            status, detail = "degraded", "status_failed"
        else:
            if isinstance(raw, Mapping):
                status, detail = str(raw.get("status", "available")), str(raw.get("detail", ""))
            else:
                status, detail = "available", ""
            if status not in {"available", "degraded", "unavailable"}:
                status = "degraded"
        result = {"provider_id": descriptor.provider_id, "status": status, "capabilities": list(descriptor.capabilities), "optional": descriptor.optional, "restarts_used": record.restarts_used}
        if detail:
            result["detail"] = redact_secrets(detail)[:512]
        return result

    def status(self) -> dict[str, object]:
        return {"providers": [self._provider_status(self._providers[key]) for key in sorted(self._providers)], "external_execution": False}

    def close(self) -> None:
        for key in sorted(self._providers):
            provider = self._providers[key].provider
            close = getattr(provider, "close", None) if provider is not None else None
            if not callable(close):
                continue
            try:
                close()
            except Exception:
                continue

    def _record_for_capability(self, capability: str) -> _ProviderRecord | None:
        if not isinstance(capability, str) or not _CAP_RE.fullmatch(capability):
            raise CapabilityGatewayError("capability is invalid")
        candidates = [record for _key, record in sorted(self._providers.items()) if capability in record.descriptor.capabilities]
        for record in candidates:
            if self._provider_status(record)["status"] == "available":
                return record
        return candidates[0] if candidates else None

    @staticmethod
    def _invoke_once(record: _ProviderRecord, capability: str, request: dict[str, object]) -> tuple[str, object]:
        assert record.provider is not None
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="capability-gateway")
        future = pool.submit(record.provider.invoke, capability, request)
        try:
            return "succeeded", future.result(timeout=record.descriptor.timeout_ms / 1000.0)
        except concurrent.futures.TimeoutError:
            future.cancel()
            return "timed_out", None
        except Exception as exc:
            return "crashed", exc
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def invoke(self, capability: str, request: Mapping[str, object]) -> dict[str, object]:
        parsed_request = _request(request)
        record = self._record_for_capability(capability)
        if record is None:
            return {"status": "unavailable", "reason": "capability_unregistered", "capability": capability, "provider_id": "", "restarted": False, "provider_reused": False, "output": "", "output_truncated": False, "external_execution": False}
        descriptor = record.descriptor
        if record.provider is None or self._provider_status(record)["status"] != "available":
            return {"status": "unavailable", "reason": "provider_unavailable", "capability": capability, "provider_id": descriptor.provider_id, "restarted": False, "provider_reused": False, "output": "", "output_truncated": False, "external_execution": False}
        restarted = False
        while True:
            outcome, value = self._invoke_once(record, capability, parsed_request)
            provider_reused = bool(getattr(record.provider, "last_invocation_reused", False))
            if outcome == "succeeded":
                output, truncated = _bounded_output(value, descriptor.max_output_bytes)
                return {"status": "succeeded", "reason": "provider_result", "capability": capability, "provider_id": descriptor.provider_id, "restarted": restarted, "provider_reused": provider_reused, "output": output, "output_truncated": truncated, "external_execution": False}
            if outcome == "timed_out":
                return {"status": "timed_out", "reason": "provider_timeout", "capability": capability, "provider_id": descriptor.provider_id, "restarted": restarted, "provider_reused": provider_reused, "output": "", "output_truncated": False, "external_execution": False}
            can_restart = record.restarts_used < descriptor.restart_budget and callable(getattr(record.provider, "restart", None))
            if not can_restart:
                return {"status": "crashed", "reason": "provider_crash", "capability": capability, "provider_id": descriptor.provider_id, "restarted": restarted, "provider_reused": provider_reused, "output": "", "output_truncated": False, "external_execution": False}
            try:
                record.provider.restart()
            except Exception:
                record.restarts_used += 1
                return {"status": "crashed", "reason": "provider_restart_failed", "capability": capability, "provider_id": descriptor.provider_id, "restarted": restarted, "provider_reused": provider_reused, "output": "", "output_truncated": False, "external_execution": False}
            record.restarts_used += 1
            restarted = True


__all__ = ["CapabilityDescriptor", "CapabilityGateway", "CapabilityGatewayError", "StdioMCPProvider"]
