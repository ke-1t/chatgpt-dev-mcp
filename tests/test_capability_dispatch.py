from __future__ import annotations

import unittest


class CapabilityDispatchTests(unittest.TestCase):
    def test_parallel_helper_and_dispatch_require_declared_capabilities(self) -> None:
        from chatgpt_dev_mcp.director import TaskLedger
        from chatgpt_dev_mcp.director_dispatch import DirectorDispatchController
        from chatgpt_dev_mcp.director_parallel import ProjectTask, capability_eligible_task_ids
        tasks = [
            ProjectTask("one", "repo", "repo", "owner", "session-one", "tree-one", "a" * 40, ("tests/ui.py",), (), requires=("browser.qa",)),
            ProjectTask("two", "repo", "repo", "owner", "session-two", "tree-two", "a" * 40, ("src/a.py",), ()),
        ]
        self.assertEqual(capability_eligible_task_ids(tasks, ("browser.qa",)), ("one", "two"))
        self.assertEqual(capability_eligible_task_ids(tasks, ()), ("two",))
        ledger = TaskLedger(max_records=64)
        controller = DirectorDispatchController(ledger)
        plan = controller.plan_work(request_id="capability-plan", workspace_id="repo", working_tree_id="tree", base_revision="a" * 40, tasks=[{"id": "one", "title": "Browser QA", "paths": ["tests/ui.py"], "requires": ["browser.qa"]}, {"id": "two", "title": "Pure", "paths": ["src/a.py"]}], max_concurrency=2)
        claimed = controller.claim_task(plan_id=plan.plan_id, owner_id="worker", capabilities=())
        self.assertEqual(claimed["task"]["title"], "Pure")
        self.assertEqual(claimed["task"]["requires"], [])


if __name__ == "__main__": unittest.main()
