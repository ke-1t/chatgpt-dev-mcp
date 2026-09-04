from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from chatgpt_dev_mcp.external_open import ExternalOpenController, ExternalOpenError, ExternalOpenKind

class _Result:
    def __init__(self, returncode: int = 0) -> None: self.returncode = returncode

class ExternalOpenControllerTests(unittest.TestCase):
    def test_bundle_and_urls_build_fixed_open_argv(self) -> None:
        c = ExternalOpenController()
        self.assertEqual(c.prepare(ExternalOpenKind.APP_BUNDLE, "com.apple.TextEdit").argv, ("/usr/bin/open", "-b", "com.apple.TextEdit"))
        self.assertEqual(c.prepare("url", "https://example.com").argv, ("/usr/bin/open", "https://example.com"))
        self.assertEqual(c.prepare("custom_url", "slack://open?team=T123").argv, ("/usr/bin/open", "slack://open?team=T123"))
    def test_local_targets_require_existing_matching_paths(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp); app = root / "App.app"; app.mkdir(); f = root / "a b.txt"; f.write_text("x"); d = root / "資料"; d.mkdir(); c = ExternalOpenController()
            self.assertEqual(c.prepare("app_path", str(app)).argv, ("/usr/bin/open", str(app.resolve())))
            self.assertEqual(c.prepare("file", str(f)).argv, ("/usr/bin/open", str(f.resolve())))
            self.assertEqual(c.prepare("directory", str(d)).argv, ("/usr/bin/open", str(d.resolve())))
            with self.assertRaises(ExternalOpenError): c.prepare("file", str(d))
    def test_unsafe_urls_sensitive_paths_and_control_characters_are_rejected(self) -> None:
        c = ExternalOpenController()
        for kind, target in (("url", "java" + "script:alert(1)"), ("url", "https://user:pass@example.com"), ("custom_url", "da" + "ta:text/plain,x"), ("url", "https://example.com/\nnext")):
            with self.assertRaises(ExternalOpenError): c.prepare(kind, target)
        with TemporaryDirectory() as temp:
            p = Path(temp) / ("." + "env.production"); p.write_text("x")
            with self.assertRaises(ExternalOpenError): c.prepare("file", str(p))
    def test_execute_uses_prepared_argv(self) -> None:
        seen = []
        c = ExternalOpenController(launcher=lambda argv: seen.append(argv) or _Result())
        result = c.execute(c.prepare("url", "https://example.com"))
        self.assertTrue(result.ok); self.assertEqual(seen, [("/usr/bin/open", "https://example.com")])
