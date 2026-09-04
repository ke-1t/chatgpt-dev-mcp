from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path: sys.path.insert(0, str(SRC))


class SemanticBackendTests(unittest.TestCase):
    def _index(self):
        from chatgpt_dev_mcp.semantic_index import SemanticIndex
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        (root / "service.py").write_text("def run(value):\n    return value + 1\n", encoding="utf-8")
        index = SemanticIndex(root, identity="session:test"); index.build(); return temporary, index

    def test_unconfigured_optional_providers_are_unavailable_without_breaking_builtin_query(self) -> None:
        from chatgpt_dev_mcp.semantic_backends import BuiltinProvider, LspProvider, ProviderRegistry, SerenaProvider, TreeSitterProvider
        from chatgpt_dev_mcp.semantic_index import SemanticQuery
        temporary, index = self._index(); self.addCleanup(temporary.cleanup)
        registry = ProviderRegistry(BuiltinProvider(index), optional=(TreeSitterProvider(), LspProvider(), SerenaProvider()))
        statuses = registry.status(); self.assertEqual(statuses[0]["status"], "available"); self.assertTrue(all(item["status"] == "unavailable" for item in statuses[1:]))
        results = registry.query(SemanticQuery(symbol="service:run", relations=("definition",)))
        self.assertEqual(results[0].symbol_id, "service:run"); self.assertEqual(results[0].provider, "builtin")

    def test_unhealthy_optional_provider_cannot_override_higher_confidence_builtin_identity(self) -> None:
        from chatgpt_dev_mcp.semantic_backends import BuiltinProvider, ProviderRegistry, ProviderResult
        from chatgpt_dev_mcp.semantic_index import SemanticMatch, SemanticQuery
        temporary, index = self._index(); self.addCleanup(temporary.cleanup)
        class UnhealthyProvider:
            name = "unhealthy"
            def status(self): return {"provider": self.name, "status": "degraded", "reason": "stale_index"}
            def query(self, _query): return (ProviderResult(provider=self.name, match=SemanticMatch(relation="definition", symbol_id="service:run", path="service.py", line=1, score=999, confidence=1.0, reason="untrusted_override", source_hash="f" * 64)),)
            def refresh(self, _changed_paths): return self.status()
        results = ProviderRegistry(BuiltinProvider(index), optional=(UnhealthyProvider(),)).query(SemanticQuery(symbol="service:run", relations=("definition",)))
        self.assertEqual(len(results), 1); self.assertEqual(results[0].provider, "builtin"); self.assertNotEqual(results[0].match.reason, "untrusted_override")


if __name__ == "__main__": unittest.main()
