import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.browser_runtime import BrowserProfile, BrowserRuntimeError, BrowserRuntimeManager


class FakeBackend:
    def __init__(self):
        self.url = ""
        self.typed = []
        self.clicks = []
        self.viewport = (1280, 720)
        self.image = b"image-a"
        self.closed = False

    def navigate(self, url): self.url = url
    def click(self, selector): self.clicks.append(selector)
    def type_text(self, selector, value): self.typed.append((selector, value))
    def press(self, key): self.key = key
    def set_viewport(self, width, height): self.viewport = (width, height)
    def wait(self, milliseconds): self.waited = milliseconds
    def inspect(self, kind):
        if kind == "network":
            return [{"url": "http://127.0.0.1:8080/fail", "status": 500, "error": "failed"}]
        if kind == "console":
            return [{"type": "error", "text": "fixture console error"}]
        return f"fixture-{kind}"
    def screenshot(self): return self.image
    def close(self): self.closed = True


class BrowserRuntimeTests(unittest.TestCase):
    def _manager(self, root):
        self.backends = []
        def factory(_directory, _profile):
            backend = FakeBackend()
            self.backends.append(backend)
            return backend
        profile = BrowserProfile("ui", ("http://127.0.0.1:8080",))
        return BrowserRuntimeManager({"ui": profile}, cache_root=Path(root), backend_factory=factory)

    def test_managed_profile_and_origin_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self._manager(tmp)
            started = manager.start(project_id="repo", profile_id="ui")
            session_id = started["session_id"]
            manager.action(session_id, "navigate", {"url": "http://127.0.0.1:8080/app"})
            self.assertEqual(self.backends[0].url, "http://127.0.0.1:8080/app")
            with self.assertRaises(BrowserRuntimeError) as cm:
                manager.action(session_id, "navigate", {"url": "https://example.com/"})
            self.assertEqual(cm.exception.code, "BROWSER_ORIGIN_DENIED")

    def test_actions_snapshot_console_network_and_visual_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self._manager(tmp)
            session_id = manager.start(project_id="repo", profile_id="ui")["session_id"]
            manager.action(session_id, "click", {"selector": "#go"})
            manager.action(session_id, "type", {"selector": "#name", "value": "Sample User"})
            manager.action(session_id, "viewport", {"width": 390, "height": 844})
            self.assertEqual(manager.inspect(session_id, "console")["data"][0]["type"], "error")
            self.assertEqual(manager.inspect(session_id, "network")["data"][0]["status"], 500)
            shot = manager.inspect(session_id, "screenshot")
            self.backends[0].image = b"image-b"
            diff = manager.inspect(session_id, "visual_diff", baseline_id=shot["artifact_id"], threshold=0.0)
            self.assertFalse(diff["passed"])
