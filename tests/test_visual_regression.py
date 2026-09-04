from __future__ import annotations

import hashlib
import unittest


class VisualRegressionTests(unittest.TestCase):
    @staticmethod
    def _evidence(seed: str):
        from chatgpt_dev_mcp.visual_regression import VisualEvidence
        h = lambda value: hashlib.sha256((seed + value).encode()).hexdigest()
        return VisualEvidence(h("screen"), f"artifact:{seed}", h("dom"), h("a11y"), h("text"), h("boxes"))

    def test_compare_uses_screenshot_dom_a11y_text_and_boxes(self) -> None:
        from chatgpt_dev_mcp.visual_regression import VisualBaselineIdentity, VisualRegressionEngine
        baseline = VisualRegressionEngine.create_baseline(VisualBaselineIdentity("home", "a" * 40, (1280, 720), "dark"), self._evidence("one"), created_at="2026-08-14T00:00:00Z")
        self.assertEqual(VisualRegressionEngine.compare(baseline, self._evidence("one")).status, "match")
        changed = VisualRegressionEngine.compare(baseline, self._evidence("two"))
        self.assertEqual(set(changed.changed_dimensions), {"screenshot", "dom", "accessibility", "text", "boxes"})


if __name__ == "__main__": unittest.main()
