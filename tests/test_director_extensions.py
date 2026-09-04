from __future__ import annotations

import unittest


def _profile(**overrides: object):
    from chatgpt_dev_mcp.director_profile import ProjectProfile

    payload = {
        "workspace_id": "sample-project",
        "profile": "DEVELOPMENT",
        "language": "Python",
        "framework": "stdlib",
        "canonical_paths": ["src", "tests"],
        "commands": {
            "test": "PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -q",
            "lint": "python3 -m compileall -q src",
            "build": "python3 -m build",
        },
        "verification_tasks": ["test", "lint", "build"],
    }
    payload.update(overrides)
    return ProjectProfile.from_mapping(payload)


class ProjectProfileTests(unittest.TestCase):
    def test_profile_is_bounded_and_hides_commands_by_default(self) -> None:
        profile = _profile()
        payload = profile.as_dict()
        self.assertEqual(payload["workspace_id"], "sample-project")
        self.assertEqual(payload["commands"], ["build", "lint", "test"])
        self.assertNotIn("PYTHONPATH=src", str(payload))
        self.assertFalse(profile.external_execution)

    def test_profile_rejects_shell_composition_and_sensitive_command_text(self) -> None:
        from chatgpt_dev_mcp.director_profile import ProfileValidationError

        with self.assertRaises(ProfileValidationError):
            _profile(commands={"test": "pytest; rm -rf ."})
        with self.assertRaises(ProfileValidationError):
            _profile(commands={"test": "token=secret pytest"})

    def test_profile_with_no_commands_is_inspectable_but_not_verifiable(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline

        profile = _profile(commands={}, verification_tasks=[])

        self.assertEqual(profile.as_dict()["commands"], [])
        plan = VerificationPipeline(profile).plan(("README.md",))
        self.assertFalse(plan.eligible)
        self.assertEqual(plan.tasks, ())
        self.assertEqual(plan.reason, "NO_VERIFICATION_TASK_CONFIGURED")


class WatchdogTests(unittest.TestCase):
    def test_watchdog_distinguishes_healthy_mismatch_stale_and_unknown(self) -> None:
        from chatgpt_dev_mcp.director_watchdog import SchemaObservation, WatchdogSnapshot, evaluate_watchdog

        schema = SchemaObservation("tool-registry-v3", 32, "a" * 64)
        healthy = evaluate_watchdog(
            WatchdogSnapshot(100, "connected", True, schema, schema, "valid"),
            now=101,
        )
        self.assertEqual(healthy.status, "healthy")
        mismatch = evaluate_watchdog(
            WatchdogSnapshot(100, "connected", True, schema, SchemaObservation("tool-registry-v3", 31, "b" * 64), "valid"),
            now=101,
        )
        self.assertEqual(mismatch.status, "blocked")
        stale = evaluate_watchdog(
            WatchdogSnapshot(100, "connected", True, schema, schema, "valid"),
            now=401,
        )
        self.assertEqual(stale.status, "stale")
        unknown = evaluate_watchdog(WatchdogSnapshot(100, "connected", None, schema, None, "valid"), now=101)
        self.assertEqual(unknown.status, "unknown")


class VerificationTests(unittest.TestCase):
    def test_plan_selects_test_lint_and_build_only_when_relevant(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline

        pipeline = VerificationPipeline(_profile())
        source_plan = pipeline.plan(("src/app.py",))
        self.assertEqual(source_plan.tasks, ("test", "lint"))
        build_plan = pipeline.plan(("pyproject.toml",))
        self.assertEqual(build_plan.tasks, ("test", "build"))

    def test_execute_requires_isolation_and_explicit_approval(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, VerificationSafetyError

        calls: list[tuple[str, str]] = []

        def runner(task: str, command: str) -> dict[str, object]:
            calls.append((task, command))
            return {"exit_code": 0, "output": f"{task} ok", "duration_ms": 5}

        pipeline = VerificationPipeline(_profile(), runner=runner)
        plan = pipeline.plan(("src/app.py",))
        with self.assertRaises(VerificationSafetyError):
            pipeline.execute(plan, isolated_workspace=False, allow_execution=True)
        with self.assertRaises(VerificationSafetyError):
            pipeline.execute(plan, isolated_workspace=True)
        receipt = pipeline.execute(plan, isolated_workspace=True, allow_execution=True)
        self.assertEqual(receipt.status, "passed")
        self.assertEqual([task for task, _ in calls], ["test", "lint"])
        self.assertFalse(receipt.as_dict()["external_execution"])

    def test_result_redacts_output_and_classifies_failure(self) -> None:
        from chatgpt_dev_mcp.director_verification import normalize_verification_result

        result = normalize_verification_result("test", exit_code=1, output="token=secret\nfailed", duration_ms=12)
        self.assertEqual(result.status, "failed")
        self.assertNotIn("secret", result.output)

    def test_receipt_is_pinned_to_revision_and_diff_and_can_be_invalidated(self) -> None:
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, normalize_verification_result

        pipeline = VerificationPipeline(_profile())
        plan = pipeline.plan(("src/app.py",))
        receipt = pipeline.record(
            plan,
            [
                normalize_verification_result("test", exit_code=0),
                normalize_verification_result("lint", exit_code=0),
            ],
            base_revision="abc123",
            diff_hash="a" * 64,
            recorded_at="2026-08-12T00:00:00Z",
        )
        self.assertEqual(receipt.status, "passed")
        self.assertEqual(receipt.base_revision, "abc123")
        self.assertEqual(receipt.diff_hash, "a" * 64)
        self.assertTrue(receipt.receipt_id.startswith("verify:"))
        stale = receipt.invalidate()
        self.assertEqual(stale.status, "stale")
        self.assertTrue(stale.stale)


class AuditTests(unittest.TestCase):
    def test_audit_combines_profile_patch_and_verification_findings(self) -> None:
        from chatgpt_dev_mcp.director import evaluate_patch
        from chatgpt_dev_mcp.director_audit import audit_patch, audit_profile, audit_verification, combine_audits
        from chatgpt_dev_mcp.director_verification import VerificationPipeline, normalize_verification_result

        profile = _profile(external_execution=True)
        profile_report = audit_profile(profile)
        self.assertEqual(profile_report.status, "blocked")
        patch_report = audit_patch(evaluate_patch("*** Begin Patch\n*** Delete File: src/old.py\n*** End Patch\n"))
        self.assertEqual(patch_report.status, "review")
        pipeline = VerificationPipeline(_profile())
        plan = pipeline.plan(("src/app.py",))
        failed_report = combine_audits(
            profile_report,
            patch_report,
            audit_verification(pipeline.record(plan, [normalize_verification_result("test", exit_code=1)])),
        )
        self.assertEqual(failed_report.status, "blocked")
        self.assertGreaterEqual(len(failed_report.findings), 3)

    def test_security_audit_receipt_is_pinned_to_patch_and_diff(self) -> None:
        from chatgpt_dev_mcp.director_audit import build_security_audit_receipt, combine_audits

        receipt = build_security_audit_receipt(
            combine_audits(),
            base_revision="abc123",
            diff_hash="a" * 64,
            patch_hash="b" * 64,
            changed_paths=("src/app.py",),
            verification_receipt_id="verify:abc",
            audited_at="2026-08-12T00:00:00Z",
        )
        self.assertTrue(receipt.receipt_id.startswith("audit:"))
        self.assertEqual(receipt.diff_hash, "a" * 64)
        self.assertEqual(receipt.patch_hash, "b" * 64)
        self.assertFalse(receipt.stale)
        self.assertTrue(receipt.invalidate().stale)

    def test_security_audit_receipt_identity_is_bound_to_worktree(self) -> None:
        from chatgpt_dev_mcp.director_audit import build_security_audit_receipt, combine_audits

        common = {
            "workspace_id": "sample-project",
            "base_revision": "abc123",
            "diff_hash": "a" * 64,
            "patch_hash": "b" * 64,
            "changed_paths": ("src/app.py",),
            "verification_receipt_id": "verify:abc",
        }
        worktree_a = build_security_audit_receipt(
            combine_audits(),
            **common,
            audited_at="2026-08-12T00:00:00Z",
            working_tree_id="worktree:aaa",
        )
        replay_a = build_security_audit_receipt(
            combine_audits(),
            **common,
            audited_at="2026-08-12T00:01:00Z",
            working_tree_id="worktree:aaa",
        )
        worktree_b = build_security_audit_receipt(
            combine_audits(),
            **common,
            audited_at="2026-08-12T00:00:00Z",
            working_tree_id="worktree:bbb",
        )

        self.assertEqual(worktree_a.receipt_id, replay_a.receipt_id)
        self.assertNotEqual(worktree_a.receipt_id, worktree_b.receipt_id)
        self.assertEqual(worktree_a.working_tree_id, "worktree:aaa")
        self.assertEqual(worktree_b.working_tree_id, "worktree:bbb")


class OrchestrationTests(unittest.TestCase):
    def test_plan_parallelizes_readers_and_disjoint_writers(self) -> None:
        from chatgpt_dev_mcp.director_orchestration import AgentTask, build_orchestration_plan

        plan = build_orchestration_plan(
            [
                AgentTask("inspect-a", "sample-project", "Inspect API", ("src/api.py",)),
                AgentTask("inspect-b", "sample-project", "Inspect tests", ("tests/test_api.py",)),
                AgentTask("writer-a", "sample-project", "Apply change A", ("src/api.py",), mode="writer"),
                AgentTask("writer-b", "sample-project", "Apply change B", ("tests/test_api.py",), mode="writer"),
            ]
        )
        self.assertEqual(plan.batches[0], ("inspect-a", "inspect-b", "writer-a", "writer-b"))
        self.assertEqual(plan.max_safe_parallel_writers, 2)
        self.assertEqual({item["task_id"] for item in plan.suggested_leases}, {"writer-a", "writer-b"})
        self.assertEqual(set(plan.shared_paths), {"src/api.py", "tests/test_api.py"})
        self.assertTrue(plan.executable)
        self.assertFalse(plan.external_chat_creation)

    def test_plan_marks_overlapping_writers_and_rejects_cycles(self) -> None:
        from chatgpt_dev_mcp.director_orchestration import AgentTask, OrchestrationValidationError, build_orchestration_plan

        conflicting = build_orchestration_plan(
            [
                AgentTask("writer-a", "sample-project", "A", ("src/api.py",), mode="writer"),
                AgentTask("writer-b", "sample-project", "B", ("src/api.py",), mode="writer"),
            ]
        )
        self.assertFalse(conflicting.executable)
        self.assertEqual(conflicting.conflicts[0].reason, "MULTIPLE_WRITERS_OVERLAP")
        self.assertEqual(conflicting.batches, (("writer-a",), ("writer-b",)))
        self.assertEqual(conflicting.max_safe_parallel_writers, 1)
        with self.assertRaises(OrchestrationValidationError):
            build_orchestration_plan(
                [
                    AgentTask("a", "sample-project", "A", ("src/a.py",), depends_on=("b",)),
                    AgentTask("b", "sample-project", "B", ("src/b.py",), depends_on=("a",)),
                ]
            )

    def test_dependency_order_allows_overlapping_writers(self) -> None:
        from chatgpt_dev_mcp.director_orchestration import AgentTask, build_orchestration_plan

        plan = build_orchestration_plan(
            [
                AgentTask("writer-a", "sample-project", "A", ("src/api.py",), mode="writer"),
                AgentTask(
                    "writer-b",
                    "sample-project",
                    "B",
                    ("src/api.py",),
                    mode="writer",
                    depends_on=("writer-a",),
                ),
            ]
        )
        self.assertTrue(plan.executable)
        self.assertEqual(plan.conflicts, ())
        self.assertEqual(plan.batches, (("writer-a",), ("writer-b",)))

    def test_runtime_resources_conflict_for_parallel_writers(self) -> None:
        from chatgpt_dev_mcp.director_orchestration import AgentTask, build_orchestration_plan

        plan = build_orchestration_plan(
            [
                AgentTask("writer-a", "sample-project", "A", ("src/a.py",), mode="writer", resources=("port:8765",)),
                AgentTask("writer-b", "sample-project", "B", ("src/b.py",), mode="writer", resources=("port:8765",)),
            ]
        )
        self.assertFalse(plan.executable)
        self.assertEqual(plan.conflicts[0].reason, "MULTIPLE_WRITERS_RESOURCE_OVERLAP")
        self.assertEqual(plan.conflicts[0].resources, ("port:8765",))
        self.assertEqual(plan.shared_resources, ("port:8765",))
        self.assertEqual(plan.batches, (("writer-a",), ("writer-b",)))
        self.assertEqual(plan.max_safe_parallel_writers, 1)

    def test_conflicting_writers_are_split_into_deterministic_safe_waves(self) -> None:
        from chatgpt_dev_mcp.director_orchestration import AgentTask, build_orchestration_plan

        plan = build_orchestration_plan(
            [
                AgentTask("writer-a", "sample-project", "A", ("src/shared.py",), mode="writer"),
                AgentTask("writer-b", "sample-project", "B", ("src/shared.py",), mode="writer"),
                AgentTask("writer-c", "sample-project", "C", ("src/independent.py",), mode="writer"),
                AgentTask("inspect", "sample-project", "Inspect", ("src/shared.py",)),
            ]
        )

        self.assertFalse(plan.executable)
        self.assertEqual(plan.batches, (("inspect", "writer-a", "writer-c"), ("writer-b",)))
        self.assertEqual(plan.max_safe_parallel_writers, 2)
        self.assertEqual(plan.conflicts[0].task_ids, ("writer-a", "writer-b"))


if __name__ == "__main__":
    unittest.main()
