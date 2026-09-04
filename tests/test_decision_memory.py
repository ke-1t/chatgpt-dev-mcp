from __future__ import annotations

import unittest

from chatgpt_dev_mcp.decision_memory import DecisionRecord, resolve_active_decisions


def _decision(decision_id: str, *, status: str = "active", rule: str = "private only", superseded_by: str = "") -> DecisionRecord:
    return DecisionRecord(
        decision_id=decision_id,
        workspace_id="demo",
        scope="delivery.visibility",
        status=status,
        rule=rule,
        rationale="safety",
        source_revision="a" * 40,
        superseded_by=superseded_by,
    )


class DecisionMemoryTests(unittest.TestCase):
    def test_superseded_decision_is_not_active(self) -> None:
        result = resolve_active_decisions((_decision("d1", status="superseded", superseded_by="d2"), _decision("d2")))

        self.assertEqual(tuple(item.decision_id for item in result.active), ("d2",))
        self.assertFalse(result.conflicted)

    def test_conflicting_active_rules_fail_closed(self) -> None:
        result = resolve_active_decisions((_decision("d1", rule="private only"), _decision("d2", rule="public allowed")))

        self.assertTrue(result.conflicted)
        self.assertEqual(result.conflict_ids, ("d1", "d2"))

    def test_duplicate_ids_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            resolve_active_decisions((_decision("d1"), _decision("d1")))


if __name__ == "__main__":
    unittest.main()
