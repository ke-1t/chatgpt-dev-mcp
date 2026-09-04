from __future__ import annotations

import unittest


class _ParametrizeShim:
    def parametrize(self, *_args: object, **_kwargs: object):
        return lambda function: function


class _PytestShim:
    mark = _ParametrizeShim()


pytest = _PytestShim()

from chatgpt_dev_mcp.session_reconciliation import (
    DeepSessionEvidence,
    PatchApplicationProbe,
    PatchSnapshot,
    SessionReconciliationError,
    SuccessorPatch,
    build_deep_evidence,
    classify_retained_session,
    reconcile_retained_sessions,
)


def _session(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "session_id": "session:one",
        "task_id": "task:one",
        "owner_id": "owner-one",
        "dirty": True,
        "active": False,
        "status": "expired_dirty_retained",
        "worktree_available": True,
    }
    value.update(overrides)
    return value


def _task(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "task_id": "task:one",
        "status": "stale",
        "integration_receipt": "",
        "result": "",
    }
    value.update(overrides)
    return value


def test_active_dirty_session_is_not_treated_as_retained_cleanup_work() -> None:
    result = classify_retained_session(
        session=_session(active=True, status="active"),
        task=_task(status="running"),
    )

    assert result.classification == "active"
    assert result.confidence == "high"
    assert result.cleanup_allowed is False
    assert result.needs_deep_reconciliation is False


def test_clean_session_is_classified_without_deep_reconciliation() -> None:
    result = classify_retained_session(session=_session(dirty=False, status="expired_clean"), task=None)

    assert result.classification == "clean"
    assert result.cleanup_allowed is False
    assert result.needs_deep_reconciliation is False


def test_unavailable_dirty_worktree_is_not_guessed_about() -> None:
    result = classify_retained_session(
        session=_session(status="expired_unavailable", worktree_available=False),
        task=_task(status="stale"),
    )

    assert result.classification == "unavailable"
    assert result.confidence == "high"
    assert "WORKTREE_UNAVAILABLE" in result.reason_codes
    assert result.cleanup_allowed is False


@pytest.mark.parametrize(
    ("session_status", "integration_receipt"),
    [
        ("integrated", ""),
        ("expired_dirty_retained", "integration:abc123"),
    ],
)
def test_recorded_integration_is_high_confidence_already_integrated(
    session_status: str,
    integration_receipt: str,
) -> None:
    result = classify_retained_session(
        session=_session(status=session_status),
        task=_task(status="succeeded", integration_receipt=integration_receipt),
    )

    assert result.classification == "already_integrated"
    assert result.confidence == "high"
    assert result.cleanup_allowed is False
    assert result.needs_deep_reconciliation is False


def test_canonical_patch_equivalence_marks_already_integrated() -> None:
    result = classify_retained_session(
        session=_session(),
        task=_task(status="stale"),
        deep_evidence=DeepSessionEvidence(canonical_contains_diff=True),
    )

    assert result.classification == "already_integrated"
    assert "CANONICAL_CONTAINS_DIFF" in result.reason_codes
    assert result.confidence == "high"


def test_successor_patch_equivalence_marks_superseded() -> None:
    result = classify_retained_session(
        session=_session(),
        task=_task(status="stale"),
        deep_evidence=DeepSessionEvidence(
            canonical_contains_diff=False,
            successor_contains_diff=True,
            successor_task_id="task:two",
        ),
    )

    assert result.classification == "superseded"
    assert result.successor_task_id == "task:two"
    assert result.confidence == "high"
    assert result.cleanup_allowed is False


def test_patch_conflict_is_preserved_for_manual_reconciliation() -> None:
    result = classify_retained_session(
        session=_session(),
        task=_task(status="stale"),
        deep_evidence=DeepSessionEvidence(
            canonical_contains_diff=False,
            successor_contains_diff=False,
            patch_conflicts=True,
        ),
    )

    assert result.classification == "conflicted"
    assert result.confidence == "high"
    assert "PATCH_CONFLICT" in result.reason_codes
    assert result.cleanup_allowed is False


@pytest.mark.parametrize("task_status", ["failed", "cancelled", "blocked", "stale"])
def test_terminal_unsuccessful_task_is_only_an_orphan_candidate(task_status: str) -> None:
    result = classify_retained_session(session=_session(), task=_task(status=task_status))

    assert result.classification == "orphaned_candidate"
    assert result.confidence == "low"
    assert result.cleanup_allowed is False
    assert result.needs_deep_reconciliation is True


@pytest.mark.parametrize("task_status", ["queued", "ready", "leased", "running", "verifying", "review_ready", "succeeded"])
def test_nonterminal_or_successful_unintegrated_task_is_recoverable(task_status: str) -> None:
    result = classify_retained_session(session=_session(), task=_task(status=task_status))

    assert result.classification == "recoverable_unmerged"
    assert result.cleanup_allowed is False
    assert result.needs_deep_reconciliation is True


def test_missing_task_metadata_is_conservatively_recoverable() -> None:
    result = classify_retained_session(session=_session(task_id=""), task=None)

    assert result.classification == "recoverable_unmerged"
    assert result.confidence == "low"
    assert "TASK_METADATA_MISSING" in result.reason_codes
    assert result.cleanup_allowed is False


def test_batch_matches_tasks_and_reports_deterministic_counts() -> None:
    sessions = [
        _session(session_id="session:z", task_id="task:z", status="integrated"),
        _session(session_id="session:a", task_id="task:a"),
        _session(session_id="session:c", task_id="task:c"),
    ]
    tasks = [
        _task(task_id="task:a", status="stale"),
        _task(task_id="task:c", status="review_ready"),
        _task(task_id="task:z", status="succeeded"),
    ]
    report = reconcile_retained_sessions(sessions=sessions, tasks=tasks)

    assert [item.session_id for item in report.sessions] == ["session:a", "session:c", "session:z"]
    assert report.counts == {
        "already_integrated": 1,
        "orphaned_candidate": 1,
        "recoverable_unmerged": 1,
    }
    assert all(item.cleanup_allowed is False for item in report.sessions)


def test_batch_accepts_deep_evidence_by_session() -> None:
    report = reconcile_retained_sessions(
        sessions=[_session(session_id="session:one", task_id="task:one")],
        tasks=[_task(task_id="task:one", status="stale")],
        deep_evidence_by_session={
            "session:one": DeepSessionEvidence(
                canonical_contains_diff=False,
                successor_contains_diff=True,
                successor_task_id="task:new",
            )
        },
    )

    assert report.sessions[0].classification == "superseded"
    assert report.sessions[0].successor_task_id == "task:new"


def test_duplicate_task_ids_are_rejected_in_batch_input() -> None:
    with pytest.raises(SessionReconciliationError, match="duplicate task_id"):
        reconcile_retained_sessions(
            sessions=[_session()],
            tasks=[_task(), _task(status="failed")],
        )


def test_boolean_fields_are_not_coerced_from_strings() -> None:
    with pytest.raises(SessionReconciliationError, match="dirty"):
        classify_retained_session(session=_session(dirty="true"), task=None)


class SessionReconciliationUnittestTests(unittest.TestCase):
    def test_active_dirty_session_is_not_retained_cleanup_work(self) -> None:
        result = classify_retained_session(
            session=_session(active=True, status="active"),
            task=_task(status="running"),
        )
        self.assertEqual(result.classification, "active")
        self.assertEqual(result.confidence, "high")
        self.assertFalse(result.cleanup_allowed)
        self.assertFalse(result.needs_deep_reconciliation)

    def test_integrated_and_canonical_evidence_are_already_integrated(self) -> None:
        recorded = classify_retained_session(
            session=_session(status="integrated"),
            task=_task(status="succeeded"),
        )
        canonical = classify_retained_session(
            session=_session(),
            task=_task(status="stale"),
            deep_evidence=DeepSessionEvidence(canonical_contains_diff=True),
        )
        self.assertEqual(recorded.classification, "already_integrated")
        self.assertEqual(canonical.classification, "already_integrated")
        self.assertFalse(recorded.cleanup_allowed)
        self.assertFalse(canonical.cleanup_allowed)

    def test_successor_patch_equivalence_marks_superseded(self) -> None:
        result = classify_retained_session(
            session=_session(),
            task=_task(status="stale"),
            deep_evidence=DeepSessionEvidence(
                canonical_contains_diff=False,
                successor_contains_diff=True,
                successor_task_id="task:two",
            ),
        )
        self.assertEqual(result.classification, "superseded")
        self.assertEqual(result.successor_task_id, "task:two")
        self.assertFalse(result.cleanup_allowed)

    def test_conflict_and_orphan_candidate_remain_non_destructive(self) -> None:
        conflicted = classify_retained_session(
            session=_session(),
            task=_task(status="stale"),
            deep_evidence=DeepSessionEvidence(
                canonical_contains_diff=False,
                successor_contains_diff=False,
                patch_conflicts=True,
            ),
        )
        orphan = classify_retained_session(session=_session(), task=_task(status="failed"))
        self.assertEqual(conflicted.classification, "conflicted")
        self.assertEqual(orphan.classification, "orphaned_candidate")
        self.assertEqual(orphan.confidence, "low")
        self.assertFalse(conflicted.cleanup_allowed)
        self.assertFalse(orphan.cleanup_allowed)

    def test_unintegrated_work_is_recoverable(self) -> None:
        result = classify_retained_session(session=_session(), task=_task(status="review_ready"))
        self.assertEqual(result.classification, "recoverable_unmerged")
        self.assertTrue(result.needs_deep_reconciliation)
        self.assertFalse(result.cleanup_allowed)

    def test_clean_unavailable_and_missing_task_are_conservative(self) -> None:
        clean = classify_retained_session(session=_session(dirty=False, status="expired_clean"), task=None)
        unavailable = classify_retained_session(
            session=_session(status="expired_unavailable", worktree_available=False),
            task=_task(status="stale"),
        )
        missing = classify_retained_session(session=_session(task_id=""), task=None)
        self.assertEqual(clean.classification, "clean")
        self.assertEqual(unavailable.classification, "unavailable")
        self.assertEqual(missing.classification, "recoverable_unmerged")
        self.assertEqual(missing.confidence, "low")
        self.assertIn("WORKTREE_UNAVAILABLE", unavailable.reason_codes)
        self.assertIn("TASK_METADATA_MISSING", missing.reason_codes)
        self.assertTrue(all(item.cleanup_allowed is False for item in (clean, unavailable, missing)))

    def test_batch_matches_task_ids_and_counts(self) -> None:
        report = reconcile_retained_sessions(
            sessions=[
                _session(session_id="session:z", task_id="task:z", status="integrated"),
                _session(session_id="session:a", task_id="task:a"),
                _session(session_id="session:c", task_id="task:c"),
            ],
            tasks=[
                _task(task_id="task:a", status="stale"),
                _task(task_id="task:c", status="review_ready"),
                _task(task_id="task:z", status="succeeded"),
            ],
        )
        self.assertEqual([item.session_id for item in report.sessions], ["session:a", "session:c", "session:z"])
        self.assertEqual(
            report.counts,
            {"already_integrated": 1, "orphaned_candidate": 1, "recoverable_unmerged": 1},
        )
        self.assertTrue(all(item.cleanup_allowed is False for item in report.sessions))

    def test_batch_deep_evidence_marks_successor(self) -> None:
        report = reconcile_retained_sessions(
            sessions=[_session(session_id="session:one", task_id="task:one")],
            tasks=[_task(task_id="task:one", status="stale")],
            deep_evidence_by_session={
                "session:one": DeepSessionEvidence(
                    canonical_contains_diff=False,
                    successor_contains_diff=True,
                    successor_task_id="task:new",
                )
            },
        )
        self.assertEqual(report.sessions[0].classification, "superseded")
        self.assertEqual(report.sessions[0].successor_task_id, "task:new")

    def test_duplicate_tasks_and_boolean_coercion_are_rejected(self) -> None:
        with self.assertRaisesRegex(SessionReconciliationError, "duplicate task_id"):
            reconcile_retained_sessions(sessions=[_session()], tasks=[_task(), _task(status="failed")])
        with self.assertRaisesRegex(SessionReconciliationError, "dirty"):
            classify_retained_session(session=_session(dirty="true"), task=None)


class DeepSessionReconciliationTests(unittest.TestCase):
    def test_stale_task_with_durable_work_evidence_is_recoverable(self) -> None:
        for task in (
            _task(status="stale", verification_receipt="verify:x"),
            _task(status="stale", security_audit_receipt="audit:x"),
            _task(status="stale", patch_hash="a" * 64),
        ):
            result = classify_retained_session(session=_session(), task=task)
            self.assertEqual(result.classification, "recoverable_unmerged")
            self.assertIn("DURABLE_WORK_EVIDENCE_PRESENT", result.reason_codes)

    def test_exact_successor_patch_equivalence_is_superseded(self) -> None:
        candidate = PatchSnapshot(
            base_revision="1" * 40,
            patch_hash="a" * 64,
            changed_paths=("src/a.py", "tests/test_a.py"),
        )
        evidence = build_deep_evidence(
            candidate=candidate,
            successors=(
                SuccessorPatch(
                    task_id="task:new",
                    patch=PatchSnapshot(
                        base_revision="2" * 40,
                        patch_hash="a" * 64,
                        changed_paths=("tests/test_a.py", "src/a.py"),
                    ),
                ),
            ),
        )
        result = classify_retained_session(session=_session(), task=_task(), deep_evidence=evidence)
        self.assertEqual(result.classification, "superseded")
        self.assertEqual(result.successor_task_id, "task:new")
        self.assertIn("SUCCESSOR_EXACT_PATCH_EQUIVALENCE", result.reason_codes)

    def test_reverse_forward_and_conflict_probes_are_distinct(self) -> None:
        candidate = PatchSnapshot(
            base_revision="1" * 40,
            patch_hash="b" * 64,
            changed_paths=("src/a.py",),
        )
        integrated = build_deep_evidence(
            candidate=candidate,
            canonical_probe=PatchApplicationProbe(reverse_apply_clean=True, forward_apply_clean=False),
        )
        unmerged = build_deep_evidence(
            candidate=candidate,
            canonical_probe=PatchApplicationProbe(reverse_apply_clean=False, forward_apply_clean=True),
        )
        conflicted = build_deep_evidence(
            candidate=candidate,
            canonical_probe=PatchApplicationProbe(reverse_apply_clean=False, forward_apply_clean=False),
        )
        self.assertTrue(integrated.canonical_contains_diff)
        self.assertFalse(unmerged.canonical_contains_diff)
        self.assertFalse(unmerged.patch_conflicts)
        self.assertTrue(conflicted.patch_conflicts)

    def test_unborn_base_is_limited_not_conflicted(self) -> None:
        candidate = PatchSnapshot(
            base_revision="0" * 40,
            patch_hash="c" * 64,
            changed_paths=("README.md",),
        )
        evidence = build_deep_evidence(candidate=candidate)
        self.assertTrue(candidate.unborn_base)
        self.assertIsNone(evidence.canonical_contains_diff)
        self.assertIsNone(evidence.patch_conflicts)
        self.assertIn("UNBORN_BASE_COMPARISON_LIMITED", evidence.reason_codes)

    def test_ambiguous_successors_and_path_mismatch_fail_closed(self) -> None:
        candidate = PatchSnapshot(
            base_revision="1" * 40,
            patch_hash="d" * 64,
            changed_paths=("src/a.py",),
        )
        ambiguous = build_deep_evidence(
            candidate=candidate,
            successors=tuple(
                SuccessorPatch(
                    task_id=task_id,
                    patch=PatchSnapshot(
                        base_revision="2" * 40,
                        patch_hash="d" * 64,
                        changed_paths=("src/a.py",),
                    ),
                )
                for task_id in ("task:new-a", "task:new-b")
            ),
        )
        mismatch = build_deep_evidence(
            candidate=candidate,
            successors=(
                SuccessorPatch(
                    task_id="task:new",
                    patch=PatchSnapshot(
                        base_revision="2" * 40,
                        patch_hash="d" * 64,
                        changed_paths=("src/b.py",),
                    ),
                ),
            ),
        )
        self.assertIsNone(ambiguous.successor_contains_diff)
        self.assertIn("AMBIGUOUS_EXACT_SUCCESSORS", ambiguous.reason_codes)
        self.assertIsNone(mismatch.successor_contains_diff)

    def test_patch_snapshot_validation_is_strict(self) -> None:
        for kwargs in (
            {"base_revision": "bad", "patch_hash": "a" * 64, "changed_paths": ("src/a.py",)},
            {"base_revision": "1" * 40, "patch_hash": "bad", "changed_paths": ("src/a.py",)},
            {"base_revision": "1" * 40, "patch_hash": "a" * 64, "changed_paths": ("../escape",)},
        ):
            with self.assertRaises(SessionReconciliationError):
                PatchSnapshot(**kwargs)
