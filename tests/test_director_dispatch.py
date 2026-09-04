import threading
import unittest

from chatgpt_dev_mcp.director import TaskLedger
from chatgpt_dev_mcp.director_dispatch import DirectorDispatchController, DispatchError


BASE = "a" * 40


class DirectorDispatchTests(unittest.TestCase):
    def test_allocator_success_is_bound_to_claim_and_allocator_failure_leaves_task_ready(self):
        ledger = TaskLedger(max_records=64)
        allocations = []

        def allocate(task, owner_id):
            allocations.append((task.task_id, owner_id))
            if task.local_id == "one":
                raise DispatchError("DISPATCH_SESSION_ALLOCATION_FAILED", "fixture allocation failed")
            return {
                "session_id": "session-fixture",
                "working_tree_id": "session-fixture",
                "lease_id": "lease-fixture",
            }

        controller = DirectorDispatchController(ledger, claim_allocator=allocate)
        plan = controller.plan_work(
            request_id="allocation",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            tasks=[
                {"id": "one", "title": "One", "paths": ["src/one.py"]},
                {"id": "two", "title": "Two", "paths": ["src/two.py"]},
            ],
            max_concurrency=2,
        )
        self.assertEqual(
            {ledger.get(item.task_id).working_tree_id for item in plan.tasks},
            {""},
            "queued tasks must not inherit the planner's selected worktree",
        )

        with self.assertRaises(DispatchError) as caught:
            controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")
        self.assertEqual(caught.exception.code, "DISPATCH_SESSION_ALLOCATION_FAILED")
        first_task = next(item for item in plan.tasks if item.local_id == "one")
        self.assertIn(ledger.get(first_task.task_id).status, {"queued", "ready"})
        self.assertIsNone(ledger.get(first_task.task_id).owner_id)

        ledger.transition(first_task.task_id, "blocked", detail="fixture skip")
        claimed = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-b")
        self.assertEqual(claimed["status"], "claimed")
        self.assertEqual(claimed["session_allocation"], "allocated")
        self.assertEqual(claimed["session_id"], "session-fixture")
        self.assertEqual(claimed["working_tree_id"], "session-fixture")
        self.assertEqual(claimed["lease_id"], "lease-fixture")
        second_task = next(item for item in plan.tasks if item.local_id == "two")
        receipt = ledger.get(second_task.task_id)
        self.assertEqual(receipt.status, "running")
        self.assertEqual(receipt.owner_id, "chat-b")
        self.assertEqual(receipt.development_session_id, "session-fixture")
        self.assertEqual(receipt.working_tree_id, "session-fixture")
        self.assertEqual(receipt.lease_id, "lease-fixture")

    def test_claim_rejects_allocator_reusing_an_active_worktree(self):
        ledger = TaskLedger(max_records=64)

        def allocate(_task, _owner_id):
            return {
                "session_id": "session-same",
                "working_tree_id": "session-same",
                "lease_id": "lease-same",
            }

        controller = DirectorDispatchController(ledger, claim_allocator=allocate)
        plan = controller.plan_work(
            request_id="worktree-reuse",
            workspace_id="repo",
            working_tree_id="selected-session",
            base_revision=BASE,
            tasks=[
                {"id": "one", "title": "One", "paths": ["src/one.py"]},
                {"id": "two", "title": "Two", "paths": ["src/two.py"]},
            ],
            max_concurrency=2,
        )

        first = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")
        self.assertEqual(first["status"], "claimed")
        with self.assertRaises(DispatchError) as caught:
            controller.claim_task(plan_id=plan.plan_id, owner_id="chat-b")
        self.assertEqual(caught.exception.code, "DISPATCH_WORKTREE_REUSED")
        second = ledger.get(next(item for item in plan.tasks if item.local_id == "two").task_id)
        self.assertEqual(second.status, "queued")
        self.assertEqual(second.working_tree_id, "")

    def test_claim_compensates_external_allocation_when_ledger_binding_fails(self):
        class FailingLedger(TaskLedger):
            def bind_execution(self, *args, **kwargs):
                raise RuntimeError("fixture ledger failure")

        ledger = FailingLedger(max_records=64)
        compensated = []

        def allocate(task, owner_id):
            return {
                "session_id": "session-fixture",
                "working_tree_id": "session-fixture",
                "lease_id": "lease-fixture",
            }

        def compensate(task, owner_id, allocation):
            compensated.append((task.task_id, owner_id, dict(allocation)))

        controller = DirectorDispatchController(
            ledger,
            claim_allocator=allocate,
            claim_compensator=compensate,
        )
        plan = controller.plan_work(
            request_id="allocation-compensation",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            tasks=[{"id": "one", "title": "One", "paths": ["src/one.py"]}],
        )

        with self.assertRaises(RuntimeError):
            controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")

        self.assertEqual(len(compensated), 1)
        self.assertEqual(compensated[0][1], "chat-a")
        self.assertEqual(compensated[0][2]["lease_id"], "lease-fixture")
        receipt = ledger.get(plan.tasks[0].task_id)
        self.assertIn(receipt.status, {"queued", "ready"})
        self.assertIsNone(receipt.owner_id)

    def test_claim_compensates_and_rolls_back_when_ledger_start_fails(self):
        class FailingStartLedger(TaskLedger):
            def start(self, *args, **kwargs):
                raise RuntimeError("fixture start failure")

        ledger = FailingStartLedger(max_records=64)
        compensated = []

        def allocate(_task, _owner_id):
            return {
                "session_id": "session-start-failure",
                "working_tree_id": "tree-start-failure",
                "lease_id": "lease-start-failure",
            }

        controller = DirectorDispatchController(
            ledger,
            claim_allocator=allocate,
            claim_compensator=lambda task, owner, allocation: compensated.append((task.task_id, owner, dict(allocation))),
        )
        plan = controller.plan_work(
            request_id="start-failure",
            workspace_id="repo",
            working_tree_id="tree",
            base_revision=BASE,
            tasks=[{"id": "one", "title": "One", "paths": ["src/one.py"]}],
        )

        with self.assertRaises(RuntimeError):
            controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")

        self.assertEqual(len(compensated), 1)
        receipt = ledger.get(plan.tasks[0].task_id)
        self.assertEqual(receipt.status, "ready")
        self.assertIsNone(receipt.owner_id)
        self.assertEqual(receipt.working_tree_id, "")
        self.assertEqual(receipt.development_session_id, "")
        self.assertEqual(receipt.lease_id, "")

    def test_decomposition_allows_same_path_tasks_in_same_batch_without_dependency_or_resource_conflict(self):
        ledger = TaskLedger(max_records=128)
        controller = DirectorDispatchController(ledger)
        plan = controller.plan_work(
            request_id="feature-set",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            max_concurrency=3,
            tasks=[
                {"id": "a", "title": "A", "paths": ["src/a.py"]},
                {"id": "b", "title": "B", "paths": ["src/b.py"]},
                {"id": "c", "title": "C", "paths": ["src/a.py"]},
                {"id": "d", "title": "D", "depends_on": ["a"], "paths": ["src/d.py"]},
                {"id": "e", "title": "Review", "kind": "review", "depends_on": ["b"], "paths": ["src/b.py"]},
                {"id": "f", "title": "Security", "kind": "security", "depends_on": ["d"], "paths": ["src/d.py"]},
                {"id": "g", "title": "Cleanup", "kind": "cleanup", "depends_on": ["e", "f"], "paths": ["output/tmp"]},
            ],
        )
        by_local = {item.local_id: item for item in plan.tasks}
        self.assertEqual(by_local["a"].batch, by_local["c"].batch)
        self.assertGreater(by_local["d"].batch, by_local["a"].batch)
        self.assertEqual(len(plan.tasks), 7)

    def test_same_path_tasks_can_be_claimed_concurrently(self):
        ledger = TaskLedger(max_records=64)
        controller = DirectorDispatchController(ledger)
        plan = controller.plan_work(
            request_id="same-path",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            tasks=[
                {"id": "one", "title": "One", "paths": ["src/shared.py"]},
                {"id": "two", "title": "Two", "paths": ["src/shared.py"]},
            ],
            max_concurrency=2,
        )
        first = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")
        second = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-b")
        self.assertEqual(first["status"], "claimed")
        self.assertEqual(second["status"], "claimed")

    def test_two_concurrent_claimers_get_distinct_tasks(self):
        ledger = TaskLedger(max_records=64)
        controller = DirectorDispatchController(ledger)
        plan = controller.plan_work(
            request_id="parallel",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            tasks=[
                {"id": "one", "title": "One", "paths": ["src/one.py"]},
                {"id": "two", "title": "Two", "paths": ["src/two.py"]},
                {"id": "three", "title": "Three", "depends_on": ["one"], "paths": ["src/three.py"]},
            ],
            max_concurrency=2,
        )
        results = []
        barrier = threading.Barrier(2)
        def claim(owner):
            barrier.wait()
            results.append(controller.claim_task(plan_id=plan.plan_id, owner_id=owner))
        threads = [threading.Thread(target=claim, args=("chat-a",)), threading.Thread(target=claim, args=("chat-b",))]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        claimed = [item["task"]["task_id"] for item in results if item["status"] == "claimed"]
        self.assertEqual(len(claimed), 2)
        self.assertEqual(len(set(claimed)), 2)

    def test_resource_conflict_blocks_second_claim_until_first_finishes(self):
        ledger = TaskLedger(max_records=64)
        controller = DirectorDispatchController(ledger)
        plan = controller.plan_work(
            request_id="resource",
            workspace_id="repo",
            working_tree_id="worktree-fixture",
            base_revision=BASE,
            tasks=[
                {"id": "one", "title": "One", "resources": ["port:9000"]},
                {"id": "two", "title": "Two", "resources": ["port:9000"]},
            ],
            max_concurrency=2,
        )
        first = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-a")
        second = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-b")
        self.assertEqual(first["status"], "claimed")
        self.assertNotEqual(second["status"], "claimed")
        ledger.finish(first["task"]["task_id"], "succeeded", owner_id="chat-a")
        retry = controller.claim_task(plan_id=plan.plan_id, owner_id="chat-b")
        self.assertEqual(retry["status"], "claimed")

    def test_cycle_is_rejected(self):
        controller = DirectorDispatchController(TaskLedger())
        with self.assertRaises(DispatchError) as cm:
            controller.plan_work(
                request_id="cycle",
                workspace_id="repo",
                working_tree_id="tree",
                base_revision=BASE,
                tasks=[
                    {"id": "a", "title": "A", "depends_on": ["b"]},
                    {"id": "b", "title": "B", "depends_on": ["a"]},
                ],
            )
        self.assertEqual(cm.exception.code, "DISPATCH_DEPENDENCY_CYCLE")


if __name__ == "__main__":
    unittest.main()
