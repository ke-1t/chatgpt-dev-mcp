from __future__ import annotations

import unittest


class _Resource:
    def __init__(self): self.closed = 0
    def close(self): self.closed += 1


class WarmRuntimeTests(unittest.TestCase):
    def test_reuse_lru_and_path_invalidation(self) -> None:
        from chatgpt_dev_mcp.warm_runtime import WarmRuntimeManager
        manager = WarmRuntimeManager(max_entries=1, ttl_seconds=60)
        one = manager.get_or_create("semantic", "one", _Resource, paths=("src/a.py",))
        self.assertIs(manager.get_or_create("semantic", "one", _Resource), one)
        two = manager.get_or_create("semantic", "two", _Resource, paths=("docs",))
        self.assertEqual(one.closed, 1); self.assertEqual(manager.invalidate(path="docs/readme.md"), 1); self.assertEqual(two.closed, 1)


if __name__ == "__main__": unittest.main()
