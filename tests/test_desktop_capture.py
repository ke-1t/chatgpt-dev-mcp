from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


PNG = b"\x89PNG\r\n\x1a\n" + b"capture"


class FakeRunner:
    def __init__(self, *, metadata: dict[str, object] | None = None, capture_returncode: int = 0, capture_stderr: str = "", png: bytes = PNG) -> None:
        self.metadata = metadata or {
            "running": True,
            "window": True,
            "pid": 1234,
            "process_name": "Sample App Window",
            "frontmost": True,
            "title": "Sample App Window",
            "position": [100, 80],
            "size": [1280, 800],
            "focused_role": "AXWebArea",
            "focused_title": "Sample App Window",
        }
        self.capture_returncode = capture_returncode
        self.capture_stderr = capture_stderr
        self.png = png
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if argv[0] == "/usr/bin/osascript":
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.metadata), "")
        if argv[0] == "/usr/sbin/screencapture":
            if self.capture_returncode == 0:
                Path(argv[-1]).write_bytes(self.png)
            return subprocess.CompletedProcess(argv, self.capture_returncode, "", self.capture_stderr)
        raise AssertionError(argv)


class DesktopCaptureTests(unittest.TestCase):
    def test_capture_uses_fixed_jxa_and_bounded_workspace_output(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureProfile, MacOSDesktopCaptureBackend

        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            root = Path(temp)
            runner = FakeRunner()
            backend = MacOSDesktopCaptureBackend(runner=runner, platform_name="Darwin")
            result = backend.capture(root, DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app"))

            self.assertEqual(result["status"], "captured")
            self.assertFalse(result["external_execution"])
            self.assertEqual(result["bundle_id"], "com.example.sample-app")
            self.assertEqual(result["pid"], 1234)
            self.assertEqual(result["window"]["width"], 1280)
            self.assertEqual(result["window"]["height"], 800)
            self.assertEqual(result["bytes"], len(PNG))
            screenshot = root / str(result["screenshot_path"])
            self.assertTrue(screenshot.is_file())
            self.assertEqual(screenshot.read_bytes(), PNG)
            self.assertEqual(screenshot.parent, root / "output" / "devmcp-desktop-qa")
            self.assertEqual(runner.calls[0][0:4], ("/usr/bin/osascript", "-l", "JavaScript", "-e"))
            self.assertEqual(runner.calls[0][-1], "com.example.sample-app")
            self.assertEqual(runner.calls[1][0], "/usr/sbin/screencapture")
            self.assertIn("-R100,80,1280,800", runner.calls[1])

    def test_capture_rejects_non_macos(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=FakeRunner(), platform_name="Linux").capture(
                    Path(temp), DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app")
                )
        self.assertEqual(raised.exception.code, "DESKTOP_CAPTURE_UNSUPPORTED")

    def test_capture_rejects_missing_or_zero_sized_window(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        profile = DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app")
        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            missing = FakeRunner(metadata={"running": False})
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=missing, platform_name="Darwin").capture(Path(temp), profile)
            self.assertEqual(raised.exception.code, "DESKTOP_APP_NOT_RUNNING")

            zero = FakeRunner(metadata={"running": True, "window": True, "pid": 1, "position": [0, 0], "size": [0, 800]})
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=zero, platform_name="Darwin").capture(Path(temp), profile)
            self.assertEqual(raised.exception.code, "DESKTOP_WINDOW_INVALID")

    def test_capture_reports_screen_recording_permission_failure(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            runner = FakeRunner(capture_returncode=1, capture_stderr="could not create image from display")
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=runner, platform_name="Darwin").capture(
                    Path(temp), DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app")
                )
        self.assertEqual(raised.exception.code, "DESKTOP_SCREEN_RECORDING_REQUIRED")

    def test_capture_reports_accessibility_permission_failure(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        class DeniedRunner(FakeRunner):
            def __call__(self, argv: tuple[str, ...], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
                self.calls.append(tuple(argv))
                return subprocess.CompletedProcess(argv, 1, "", "System Events got an error: Not authorized to send Apple events")

        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=DeniedRunner(), platform_name="Darwin").capture(
                    Path(temp), DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app")
                )
        self.assertEqual(raised.exception.code, "DESKTOP_ACCESSIBILITY_REQUIRED")

    def test_capture_rejects_non_frontmost_window_to_avoid_occluded_evidence(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        metadata = {
            "running": True,
            "window": True,
            "pid": 1234,
            "frontmost": False,
            "position": [100, 80],
            "size": [1280, 800],
        }
        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=FakeRunner(metadata=metadata), platform_name="Darwin").capture(
                    Path(temp), DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app")
                )
        self.assertEqual(raised.exception.code, "DESKTOP_WINDOW_NOT_FRONTMOST")

    def test_capture_rejects_oversized_or_non_png_output(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile, MacOSDesktopCaptureBackend

        with tempfile.TemporaryDirectory(prefix="desktop-capture-") as temp:
            profile = DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app", max_screenshot_bytes=64 * 1024)
            oversized = FakeRunner(png=b"\x89PNG\r\n\x1a\n" + b"x" * (64 * 1024))
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=oversized, platform_name="Darwin").capture(Path(temp), profile)
            self.assertEqual(raised.exception.code, "DESKTOP_SCREENSHOT_TOO_LARGE")

            invalid = FakeRunner(png=b"not-png")
            with self.assertRaises(DesktopCaptureError) as raised:
                MacOSDesktopCaptureBackend(runner=invalid, platform_name="Darwin").capture(Path(temp), profile)
            self.assertEqual(raised.exception.code, "DESKTOP_SCREENSHOT_INVALID")

    def test_profile_rejects_invalid_bundle_identifier_and_health_url(self) -> None:
        from chatgpt_dev_mcp.desktop_capture import DesktopCaptureError, DesktopCaptureProfile

        with self.assertRaises(DesktopCaptureError) as bundle_error:
            DesktopCaptureProfile("managed-sample-tauri", "../bad")
        self.assertEqual(bundle_error.exception.code, "DESKTOP_CAPTURE_PROFILE_INVALID")
        with self.assertRaises(DesktopCaptureError) as health_error:
            DesktopCaptureProfile("managed-sample-tauri", "com.example.sample-app", health_url="https://example.com/health")
        self.assertEqual(health_error.exception.code, "DESKTOP_CAPTURE_PROFILE_INVALID")


if __name__ == "__main__":
    unittest.main()
