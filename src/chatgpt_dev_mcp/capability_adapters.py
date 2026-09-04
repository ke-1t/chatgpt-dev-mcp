"""Static optional capability-adapter metadata and side-effect-free discovery."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .capability_gateway import CapabilityDescriptor, StdioMCPProvider
from .director import redact_secrets

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_CAP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INLINE_SECRET_RE = re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s\"',;}]+")


class CapabilityAdapterError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityAdapterSpec:
    provider_id: str
    capabilities: tuple[str, ...]
    executable_candidates: tuple[str, ...]
    transport: str
    managed_profile_required: bool = False
    read_only: bool = True
    timeout_ms: int = 5000
    max_output_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not _ID_RE.fullmatch(self.provider_id):
            raise CapabilityAdapterError("provider_id is invalid")
        if not isinstance(self.capabilities, tuple) or not self.capabilities or len(set(self.capabilities)) != len(self.capabilities) or any(not isinstance(item, str) or not _CAP_RE.fullmatch(item) for item in self.capabilities):
            raise CapabilityAdapterError("capabilities are invalid")
        if not isinstance(self.executable_candidates, tuple) or not self.executable_candidates or len(self.executable_candidates) > 8 or any(not isinstance(item, str) or not item or len(item) > 128 for item in self.executable_candidates):
            raise CapabilityAdapterError("executable candidates are invalid")
        if self.transport not in {"cli", "stdio_mcp"}:
            raise CapabilityAdapterError("transport is invalid")
        if not isinstance(self.managed_profile_required, bool) or not isinstance(self.read_only, bool):
            raise CapabilityAdapterError("adapter flags are invalid")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int) or not 1 <= self.timeout_ms <= 120_000:
            raise CapabilityAdapterError("timeout is outside bounds")
        if isinstance(self.max_output_bytes, bool) or not isinstance(self.max_output_bytes, int) or not 128 <= self.max_output_bytes <= 1024 * 1024:
            raise CapabilityAdapterError("output bound is invalid")


DEFAULT_ADAPTER_SPECS = (
    CapabilityAdapterSpec("playwright-cli", ("browser.navigate", "browser.inspect", "browser.screenshot"), ("playwright",), "cli", managed_profile_required=True, read_only=False),
    CapabilityAdapterSpec("playwright-mcp", ("browser.navigate", "browser.inspect", "browser.screenshot"), ("playwright-mcp", "mcp-server-playwright"), "stdio_mcp", managed_profile_required=True, read_only=False),
    CapabilityAdapterSpec("chrome-devtools-mcp", ("browser.console", "browser.network", "browser.performance"), ("chrome-devtools-mcp",), "stdio_mcp", managed_profile_required=True, read_only=True),
    CapabilityAdapterSpec("serena", ("semantic.query", "semantic.references", "semantic.symbols"), ("serena",), "stdio_mcp"),
    CapabilityAdapterSpec("context7", ("docs.resolve", "docs.lookup"), ("context7-mcp",), "stdio_mcp"),
    CapabilityAdapterSpec("github-gh", ("github.status", "github.checks", "github.reviews", "github.merge_readiness"), ("gh",), "cli"),
)


STDIO_CAPABILITY_TOOL_ALIASES: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "playwright-mcp": {
        "browser.navigate": ("browser_navigate", "navigate"),
        "browser.inspect": ("browser_snapshot", "snapshot"),
        "browser.screenshot": ("browser_take_screenshot", "take_screenshot", "screenshot"),
    },
    "chrome-devtools-mcp": {
        "browser.console": ("list_console_messages", "get_console_messages"),
        "browser.network": ("list_network_requests", "get_network_requests"),
        "browser.performance": ("performance_start_trace", "performance_analyze_insight"),
    },
    "serena": {
        "semantic.query": ("find_symbol", "search_for_pattern"),
        "semantic.references": ("find_referencing_symbols",),
        "semantic.symbols": ("get_symbols_overview",),
    },
    "context7": {
        "docs.resolve": ("resolve-library-id", "resolve_library_id"),
        "docs.lookup": ("get-library-docs", "get_library_docs", "query-docs", "query_docs"),
    },
}


# Fixed, diagnostic-only launcher metadata. Discovery never invokes these
# launchers and never performs package installation or network access.
ADAPTER_LAUNCHERS: Mapping[str, tuple[tuple[str, ...], str]] = {
    "playwright-cli": (("npx",), "playwright"),
    "playwright-mcp": (("npx",), "@playwright/mcp@latest"),
    "chrome-devtools-mcp": (("npx",), "chrome-devtools-mcp@latest"),
    "context7": (("npx",), "@upstash/context7-mcp@latest"),
    "serena": (("uvx",), "serena-agent"),
}


def _default_search_roots() -> tuple[Path, ...]:
    home = Path.home()
    roots = (
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
        Path(sys.executable).resolve().parent,
        home / ".cargo" / "bin",
        home / ".local" / "bin",
        home / ".npm-global" / "bin",
        home / "Library" / "pnpm",
    )
    return tuple(dict.fromkeys(roots))


def _trusted_resolution_prefix(root: Path) -> Path:
    resolved = root.resolve(strict=False)
    if resolved == Path("/opt/homebrew/bin"):
        return Path("/opt/homebrew")
    if resolved == Path("/usr/local/bin"):
        return Path("/usr/local")
    user_local = (Path.home() / ".local").resolve(strict=False)
    if resolved == user_local / "bin":
        return user_local
    return resolved


def _trusted_executable_path(path: Path, *, root: Path) -> bool:
    try:
        if not path.exists():
            return False
        resolved = path.resolve(strict=True)
        resolved.relative_to(_trusted_resolution_prefix(root))
        return resolved.is_file() and os.access(resolved, os.X_OK)
    except (OSError, ValueError):
        return False


def _artifact_refs(value: object, *, limit: int = 32) -> list[str]:
    found: list[str] = []
    def visit(candidate: object) -> None:
        if len(found) >= limit:
            return
        if isinstance(candidate, Mapping):
            for key, nested in candidate.items():
                if len(found) >= limit:
                    break
                if isinstance(key, str) and key.endswith("_ref") and isinstance(nested, str) and nested.startswith("artifact:"):
                    if nested not in found:
                        found.append(nested)
                else:
                    visit(nested)
        elif isinstance(candidate, (list, tuple)):
            for nested in candidate:
                visit(nested)
    visit(value)
    return found


def normalize_adapter_output(value: object, *, max_bytes: int = 16 * 1024) -> dict[str, object]:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 128 <= max_bytes <= 1024 * 1024:
        raise CapabilityAdapterError("output bound is invalid")
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            text = repr(value)
    text = _INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", redact_secrets(text))
    encoded = text.encode("utf-8")
    truncated = len(encoded) > max_bytes
    if truncated:
        text = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return {"text": text, "truncated": truncated, "artifact_refs": _artifact_refs(value)}


class CapabilityAdapterCatalog:
    def __init__(
        self,
        *,
        resolver: Callable[[str], str | None] | None = None,
        specs: tuple[CapabilityAdapterSpec, ...] = DEFAULT_ADAPTER_SPECS,
        search_roots: tuple[Path, ...] | None = None,
    ) -> None:
        if not callable(resolver or shutil.which):
            raise CapabilityAdapterError("resolver is invalid")
        if not isinstance(specs, tuple) or not specs or any(not isinstance(item, CapabilityAdapterSpec) for item in specs) or len({item.provider_id for item in specs}) != len(specs):
            raise CapabilityAdapterError("adapter specs are invalid")
        self._resolver = resolver or shutil.which
        self._specs = {item.provider_id: item for item in specs}
        roots = _default_search_roots() if search_roots is None else search_roots
        if not isinstance(roots, tuple) or len(roots) > 16 or any(not isinstance(item, Path) for item in roots):
            raise CapabilityAdapterError("search roots are invalid")
        self._search_roots = roots

    def spec(self, provider_id: str) -> CapabilityAdapterSpec:
        if provider_id not in self._specs:
            raise CapabilityAdapterError("adapter provider is unknown")
        return self._specs[provider_id]

    def gateway_descriptor(self, provider_id: str) -> CapabilityDescriptor:
        spec = self.spec(provider_id)
        return CapabilityDescriptor(provider_id=spec.provider_id, capabilities=spec.capabilities, timeout_ms=spec.timeout_ms, max_output_bytes=spec.max_output_bytes, restart_budget=1 if spec.transport == "stdio_mcp" else 0, optional=True)

    def _resolve_candidates(self, candidates: tuple[str, ...]) -> str:
        for candidate in candidates:
            value = self._resolver(candidate)
            if isinstance(value, str) and value:
                return value
            for root in self._search_roots:
                path = root / candidate
                if _trusted_executable_path(path, root=root):
                    return str(path)
        return ""

    def _resolve(self, spec: CapabilityAdapterSpec) -> str:
        return self._resolve_candidates(spec.executable_candidates)

    def _launcher_details(self, provider_id: str) -> tuple[str, str]:
        launcher = ADAPTER_LAUNCHERS.get(provider_id)
        if launcher is None:
            return "", ""
        candidates, package = launcher
        return self._resolve_candidates(candidates), package

    def _launcher_argv(self, provider_id: str) -> tuple[str, ...]:
        executable, package = self._launcher_details(provider_id)
        if not executable or not package:
            return ()
        name = Path(executable).name
        if name == "npx":
            return (executable, "--yes", package)
        if name == "uvx":
            return (executable, package)
        return ()

    def build_provider(self, provider_id: str) -> object | None:
        spec = self.spec(provider_id)
        if spec.transport != "stdio_mcp":
            return None
        aliases = STDIO_CAPABILITY_TOOL_ALIASES.get(provider_id)
        if aliases is None:
            return None
        executable = self._resolve(spec)
        argv = (executable,) if executable else self._launcher_argv(provider_id)
        if not argv:
            return None
        return StdioMCPProvider(
            argv=argv,
            capability_tools=aliases,
            timeout_ms=spec.timeout_ms,
        )

    def status(self) -> dict[str, object]:
        providers = []
        for provider_id in sorted(self._specs):
            spec = self._specs[provider_id]
            executable = self._resolve(spec)
            launcher_executable, launcher_package = self._launcher_details(provider_id)
            providers.append(
                {
                    "provider_id": spec.provider_id,
                    "status": "available" if executable else "unavailable",
                    "transport": spec.transport,
                    "capabilities": list(spec.capabilities),
                    "managed_profile_required": spec.managed_profile_required,
                    "read_only": spec.read_only,
                    "executable": executable,
                    "launcher_status": "available" if launcher_executable else "unavailable",
                    "launcher_executable": launcher_executable,
                    "launcher_package": launcher_package,
                    "provisioning_required": bool(not executable and launcher_executable and launcher_package),
                    "provisioning_network_required": bool(not executable and launcher_executable and launcher_package),
                }
            )
        return {"providers": providers, "process_started": False, "network_used": False, "external_execution": False}


__all__ = ["ADAPTER_LAUNCHERS", "CapabilityAdapterCatalog", "CapabilityAdapterError", "CapabilityAdapterSpec", "DEFAULT_ADAPTER_SPECS", "STDIO_CAPABILITY_TOOL_ALIASES", "normalize_adapter_output"]
