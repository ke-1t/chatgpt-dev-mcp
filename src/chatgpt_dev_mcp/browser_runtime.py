"""Managed browser testing without personal-profile or cookie access."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import time
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit
import uuid

from .director import contains_secret_like_content, redact_secrets
from .runtime_policy import validate_identifier


class BrowserRuntimeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise BrowserRuntimeError("BROWSER_ORIGIN_INVALID", "only bounded http/https origins are allowed")
    port = parsed.port
    default = 80 if parsed.scheme == "http" else 443
    suffix = "" if port in (None, default) else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.lower()}{suffix}"


@dataclass(frozen=True)
class BrowserProfile:
    identifier: str
    allowed_origins: tuple[str, ...]
    viewport_width: int = 1280
    viewport_height: int = 720
    max_screenshot_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        validate_identifier(self.identifier, field="browser profile", max_length=80)
        if not self.allowed_origins or len(self.allowed_origins) > 16:
            raise BrowserRuntimeError("BROWSER_PROFILE_INVALID", "allowed_origins must be non-empty and bounded")
        normalized = tuple(_origin(item) for item in self.allowed_origins)
        if len(set(normalized)) != len(normalized):
            raise BrowserRuntimeError("BROWSER_PROFILE_INVALID", "allowed origins contain duplicates")
        if not 320 <= self.viewport_width <= 3840 or not 240 <= self.viewport_height <= 2160:
            raise BrowserRuntimeError("BROWSER_PROFILE_INVALID", "viewport is outside safety bounds")

    @property
    def origins(self) -> tuple[str, ...]:
        return tuple(_origin(item) for item in self.allowed_origins)


class BrowserBackend(Protocol):
    def navigate(self, url: str) -> None: ...
    def click(self, selector: str) -> None: ...
    def type_text(self, selector: str, value: str) -> None: ...
    def press(self, key: str) -> None: ...
    def set_viewport(self, width: int, height: int) -> None: ...
    def wait(self, milliseconds: int) -> None: ...
    def inspect(self, kind: str) -> object: ...
    def screenshot(self) -> bytes: ...
    def close(self) -> None: ...


class _PlaywrightBackend:
    def __init__(self, profile_dir: Path, profile: BrowserProfile) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserRuntimeError("BROWSER_RUNTIME_UNAVAILABLE", "Playwright is not installed") from exc
        self._runtime = sync_playwright().start()
        self._context = self._runtime.chromium.launch_persistent_context(
            str(profile_dir),
            headless=True,
            accept_downloads=False,
            viewport={"width": profile.viewport_width, "height": profile.viewport_height},
        )
        self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
        self._console: list[dict[str, str]] = []
        self._network: list[dict[str, object]] = []
        self._page.on("console", self._on_console)
        self._page.on("requestfailed", self._on_failed)
        self._page.on("response", self._on_response)

    def _on_console(self, message: object) -> None:
        text = str(getattr(message, "text", ""))[:4096]
        level = str(getattr(message, "type", "log"))[:32]
        self._console.append({"type": level, "text": text})
        del self._console[:-200]

    def _on_failed(self, request: object) -> None:
        failure = getattr(request, "failure", None)
        self._network.append({
            "url": str(getattr(request, "url", ""))[:2048],
            "method": str(getattr(request, "method", ""))[:16],
            "status": None,
            "error": str(failure or "request_failed")[:256],
        })
        del self._network[:-500]

    def _on_response(self, response: object) -> None:
        request = getattr(response, "request", None)
        self._network.append({
            "url": str(getattr(response, "url", ""))[:2048],
            "method": str(getattr(request, "method", ""))[:16],
            "status": int(getattr(response, "status", 0) or 0),
            "error": "",
        })
        del self._network[:-500]

    def navigate(self, url: str) -> None:
        self._page.goto(url, wait_until="domcontentloaded", timeout=30000)

    def click(self, selector: str) -> None:
        self._page.locator(selector).click(timeout=10000)

    def type_text(self, selector: str, value: str) -> None:
        self._page.locator(selector).fill(value, timeout=10000)

    def press(self, key: str) -> None:
        self._page.keyboard.press(key)

    def set_viewport(self, width: int, height: int) -> None:
        self._page.set_viewport_size({"width": width, "height": height})

    def wait(self, milliseconds: int) -> None:
        self._page.wait_for_timeout(milliseconds)

    def inspect(self, kind: str) -> object:
        if kind == "snapshot":
            return self._page.content()[:131072]
        if kind == "visible_text":
            return self._page.locator("body").inner_text(timeout=5000)[:65536]
        if kind == "accessibility":
            body = self._page.locator("body")
            method = getattr(body, "aria_snapshot", None)
            return method(timeout=5000)[:65536] if callable(method) else body.inner_text(timeout=5000)[:65536]
        if kind == "console":
            return list(self._console)
        if kind == "network":
            return list(self._network)
        raise BrowserRuntimeError("BROWSER_INSPECT_INVALID", "inspect kind is not supported")

    def screenshot(self) -> bytes:
        return bytes(self._page.screenshot(full_page=True))

    def close(self) -> None:
        try:
            self._context.close()
        finally:
            self._runtime.stop()


@dataclass
class _Session:
    session_id: str
    project_id: str
    profile: BrowserProfile
    backend: BrowserBackend
    profile_dir: Path
    artifact_dir: Path
    created_at: float
    baseline_images: dict[str, bytes]


class BrowserRuntimeManager:
    ACTIONS = frozenset({"navigate", "click", "type", "keyboard", "viewport", "wait"})
    INSPECT = frozenset({"snapshot", "visible_text", "accessibility", "console", "network", "screenshot", "visual_diff"})

    def __init__(
        self,
        profiles: Mapping[str, BrowserProfile],
        *,
        cache_root: Path,
        backend_factory: Callable[[Path, BrowserProfile], BrowserBackend] | None = None,
    ) -> None:
        self._profiles = dict(profiles)
        self._cache_root = cache_root.resolve(strict=False)
        self._backend_factory = backend_factory or (lambda directory, profile: _PlaywrightBackend(directory, profile))
        self._sessions: dict[str, _Session] = {}

    def list_profiles(self) -> list[dict[str, object]]:
        return [
            {
                "profile": profile.identifier,
                "allowed_origins": list(profile.origins),
                "viewport": {"width": profile.viewport_width, "height": profile.viewport_height},
            }
            for profile in sorted(self._profiles.values(), key=lambda item: item.identifier)
        ]

    def start(self, *, project_id: str, profile_id: str) -> dict[str, object]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise BrowserRuntimeError("BROWSER_PROFILE_UNKNOWN", "browser profile is not registered")
        validate_identifier(project_id, field="project", max_length=80)
        session_id = "browser-" + uuid.uuid4().hex
        profile_dir = self._cache_root / "profiles" / project_id / profile.identifier
        artifact_dir = self._cache_root / "artifacts" / session_id
        profile_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        backend = self._backend_factory(profile_dir, profile)
        self._sessions[session_id] = _Session(
            session_id, project_id, profile, backend, profile_dir, artifact_dir, time.time(), {},
        )
        return {
            "status": "started",
            "session_id": session_id,
            "profile": profile.identifier,
            "allowed_origins": list(profile.origins),
            "external_execution": False,
        }

    def _session(self, session_id: str) -> _Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise BrowserRuntimeError("BROWSER_SESSION_INVALID", "browser session is unknown or closed")
        return session

    def close(self, session_id: str) -> dict[str, object]:
        session = self._sessions.pop(session_id, None)
        if session is None:
            raise BrowserRuntimeError("BROWSER_SESSION_INVALID", "browser session is unknown or closed")
        session.backend.close()
        return {"status": "closed", "session_id": session_id, "external_execution": False}

    @staticmethod
    def _selector(value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 500 or "\x00" in value or "\n" in value:
            raise BrowserRuntimeError("BROWSER_SELECTOR_INVALID", "selector is invalid")
        return value

    def action(self, session_id: str, action: str, params: Mapping[str, object]) -> dict[str, object]:
        session = self._session(session_id)
        if action not in self.ACTIONS or not isinstance(params, Mapping):
            raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "browser action is unsupported")
        if action == "navigate":
            if set(params) != {"url"} or not isinstance(params.get("url"), str):
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "navigate requires url")
            url = str(params["url"])
            if _origin(url) not in session.profile.origins:
                raise BrowserRuntimeError("BROWSER_ORIGIN_DENIED", "navigation origin is not allowed by profile")
            session.backend.navigate(url)
        elif action == "click":
            if set(params) != {"selector"}:
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "click requires selector")
            session.backend.click(self._selector(params.get("selector")))
        elif action == "type":
            if set(params) != {"selector", "value"} or not isinstance(params.get("value"), str):
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "type requires selector and value")
            value = str(params["value"])
            if len(value) > 4096 or contains_secret_like_content(value):
                raise BrowserRuntimeError("BROWSER_INPUT_DENIED", "raw secret-like or oversized browser input is denied")
            session.backend.type_text(self._selector(params.get("selector")), value)
        elif action == "keyboard":
            if set(params) != {"key"} or not isinstance(params.get("key"), str) or not re.fullmatch(r"[A-Za-z0-9+_-]{1,40}", str(params["key"])):
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "keyboard requires a bounded key chord")
            session.backend.press(str(params["key"]))
        elif action == "viewport":
            if set(params) != {"width", "height"}:
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "viewport requires width and height")
            width, height = params.get("width"), params.get("height")
            if isinstance(width, bool) or isinstance(height, bool) or not isinstance(width, int) or not isinstance(height, int) or not 320 <= width <= 3840 or not 240 <= height <= 2160:
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "viewport is outside safety bounds")
            session.backend.set_viewport(width, height)
        else:
            if set(params) != {"milliseconds"}:
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "wait requires milliseconds")
            milliseconds = params.get("milliseconds")
            if isinstance(milliseconds, bool) or not isinstance(milliseconds, int) or not 0 <= milliseconds <= 30000:
                raise BrowserRuntimeError("BROWSER_ACTION_INVALID", "wait duration is outside safety bounds")
            session.backend.wait(milliseconds)
        return {"status": "succeeded", "session_id": session_id, "action": action, "external_execution": False}

    @staticmethod
    def _redact_payload(value: object) -> object:
        if isinstance(value, str):
            return redact_secrets(value)
        if isinstance(value, list):
            return [BrowserRuntimeManager._redact_payload(item) for item in value[:500]]
        if isinstance(value, dict):
            return {str(key)[:80]: BrowserRuntimeManager._redact_payload(item) for key, item in list(value.items())[:100]}
        return value

    @staticmethod
    def _diff_metric(left: bytes, right: bytes) -> float:
        if not left and not right:
            return 0.0
        maximum = max(len(left), len(right))
        common = min(len(left), len(right))
        changed = abs(len(left) - len(right)) + sum(1 for index in range(common) if left[index] != right[index])
        return changed / maximum

    def inspect(self, session_id: str, kind: str, *, baseline_id: str = "", threshold: float = 0.01) -> dict[str, object]:
        session = self._session(session_id)
        if kind not in self.INSPECT:
            raise BrowserRuntimeError("BROWSER_INSPECT_INVALID", "inspect kind is unsupported")
        if kind in {"snapshot", "visible_text", "accessibility", "console", "network"}:
            value = self._redact_payload(session.backend.inspect(kind))
            return {"status": "succeeded", "session_id": session_id, "kind": kind, "data": value, "external_execution": False}
        image = session.backend.screenshot()
        if len(image) > session.profile.max_screenshot_bytes:
            raise BrowserRuntimeError("BROWSER_SCREENSHOT_TOO_LARGE", "screenshot exceeded the configured bound")
        image_hash = hashlib.sha256(image).hexdigest()
        if kind == "screenshot":
            artifact_id = "shot-" + image_hash[:20]
            path = session.artifact_dir / f"{artifact_id}.png"
            path.write_bytes(image)
            session.baseline_images[artifact_id] = image
            return {
                "status": "succeeded",
                "session_id": session_id,
                "kind": kind,
                "artifact_id": artifact_id,
                "sha256": image_hash,
                "bytes": len(image),
                "external_execution": False,
            }
        if not 0.0 <= threshold <= 1.0:
            raise BrowserRuntimeError("BROWSER_VISUAL_THRESHOLD_INVALID", "visual threshold must be between zero and one")
        baseline = session.baseline_images.get(baseline_id)
        if baseline is None:
            raise BrowserRuntimeError("BROWSER_BASELINE_UNKNOWN", "visual baseline is unknown in this managed session")
        metric = self._diff_metric(baseline, image)
        return {
            "status": "succeeded",
            "session_id": session_id,
            "kind": kind,
            "baseline_id": baseline_id,
            "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
            "current_sha256": image_hash,
            "diff_metric": metric,
            "threshold": threshold,
            "passed": metric <= threshold,
            "external_execution": False,
        }
