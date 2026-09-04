from __future__ import annotations

import unittest


class _Adapter:
    def capture(self, profile, scenario, viewport, theme):
        return {"console": [{"level": "error", "message": "boom"}], "network": [{"status": 500, "method": "GET", "url": "/api"}], "accessibility": [{"severity": "medium", "message": "missing name"}], "visible_text": {"missing": ["Submit"]}, "boxes": [{"id": "a", "x": 0, "y": 0, "width": 100, "height": 100}, {"id": "b", "x": 50, "y": 50, "width": 100, "height": 100}], "screenshot_ref": "artifact:screen"}


class BrowserQATests(unittest.TestCase):
    def test_normalizes_findings_and_requires_managed_profile(self) -> None:
        from chatgpt_dev_mcp.browser_qa import BrowserQAEngine, BrowserQAError, BrowserQAScenario
        engine = BrowserQAEngine(_Adapter())
        receipt = engine.run("managed-fixture", (BrowserQAScenario("home", "Home"),), ((240, 220),), ("dark",))
        self.assertEqual(receipt.status, "failed")
        self.assertIn("artifact:screen", receipt.artifact_refs)
        self.assertTrue(any(item.kind == "layout" for item in receipt.findings))
        with self.assertRaises(BrowserQAError):
            engine.run("personal-profile", (BrowserQAScenario("home", "Home"),), ((240, 220),), ("dark",))


if __name__ == "__main__": unittest.main()
