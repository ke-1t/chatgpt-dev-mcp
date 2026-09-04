from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class EvidenceGenerationImportTests(unittest.TestCase):
    def _store(self, path: Path):
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore

        return SqliteDirectorStore(path)

    def _seed(self, store, *, session_id: str = "session:A6io38MVK3gdZfErKtFqMISN", task_id: str = "task:a6-import-0001"):
        store.save_task(
            {
                "task_id": task_id,
                "request_id": "request:a6-import-0001",
                "title": "A6 import fixture",
                "owner_id": "chatgpt",
                "workspace_id": "arb-scout",
                "working_tree_id": session_id,
                "development_session_id": session_id,
                "allowed_paths": ["docs/migration"],
                "resources": [],
                "dependencies": [],
                "lease_id": "lease:a6-import-0001",
                "base_revision": "2" * 40,
                "patch_hash": "",
                "state": "stale",
                "created_at": "2026-08-24T03:36:01Z",
                "updated_at": "2026-08-24T03:37:02Z",
                "detail": "DEVELOPMENT_SESSION_CLOSED_CLEAN",
            }
        )
        store.save_development_session(
            {
                "session_id": session_id,
                "project_id": "arb-scout",
                "logical_workspace_id": "arb-scout",
                "worktree_id": session_id,
                "workspace_id": "arb-scout",
                "candidate_id": "registered:arb-scout",
                "source_revision": "2" * 40,
                "base_commit": "2" * 40,
                "root_path": "/tmp/a6-import-worktree",
                "task_id": task_id,
                "owner_id": "chatgpt",
                "source_dirty": True,
                "created_at": 1.0,
                "expires_at": 7201.0,
                "lifecycle_state": "stale",
                "stale": True,
                "metadata": {"source_generation": "v25"},
            }
        )
        store.save_lease(
            {
                "lease_id": "lease:a6-import-0001",
                "workspace_id": "arb-scout",
                "working_tree_id": session_id,
                "task_id": task_id,
                "owner_id": "chatgpt",
                "paths": ["docs/migration"],
                "resources": [],
                "base_revision": "2" * 40,
                "scope_hashes": {"docs/migration": "3" * 64},
                "workspace_state_hash": "",
                "workspace_wide": False,
                "acquired_at": 1.0,
                "expires_at": 2.0,
                "released_at": 3.0,
                "state": "released",
            }
        )
        return session_id, task_id

    def test_bounded_v25_session_import_preserves_identity_and_source(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, task_id = self._seed(source)
            before = source_path.read_bytes()
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            result = importer.execute(plan)
            self.assertEqual(result["status"], "IMPORTED")
            self.assertEqual(result["session_id"], session_id)
            self.assertIn(task_id, result["task_ids"])
            self.assertEqual(source_path.read_bytes(), before)
            self.assertEqual(destination.load_development_sessions()[0]["session_id"], session_id)
            self.assertEqual(destination.load_tasks()[0]["task_id"], task_id)
            self.assertEqual(destination.load_leases()[0]["lease_id"], "lease:a6-import-0001")
            self.assertEqual(destination.load_evidence_generation_imports()[0]["source_generation"], "v25")

    def test_identical_second_import_is_idempotent(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            self.assertEqual(importer.execute(plan)["status"], "IMPORTED")
            second = importer.execute(importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout"))
            self.assertEqual(second["status"], "ALREADY_IMPORTED_IDENTICAL")
            self.assertEqual(len(destination.load_development_sessions()), 1)

    def test_different_same_id_fails_without_destination_mutation(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            destination = self._store(destination_path)
            self._seed(destination, session_id=session_id, task_id="task:conflict-0001")
            before = destination_path.read_bytes()
            from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImporter

            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.execute(plan)
            self.assertEqual(raised.exception.code, "EVIDENCE_IDENTITY_CONFLICT")
            self.assertEqual(destination_path.read_bytes(), before)

    def test_corrupt_source_fails_closed(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "corrupt.sqlite3"
            source_path.write_bytes(b"not sqlite")
            source_path.chmod(0o600)
            destination = self._store(root / "v26.sqlite3")
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.preflight(source_path, session_id="session:A6io38MVK3gdZfErKtFqMISN", workspace_id="arb-scout")
            self.assertEqual(raised.exception.code, "SOURCE_DATABASE_INVALID")

    def test_missing_dependency_fails_before_any_write(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            source = self._store(source_path)
            session_id, task_id = self._seed(source)
            source.run_write(
                lambda conn: conn.execute(
                    "UPDATE task_ledger SET dependencies_json = ? WHERE task_id = ?",
                    ('["task:missing-dependency"]', task_id),
                )
            )
            destination_path = root / "v26.sqlite3"
            destination = self._store(destination_path)
            before = destination_path.read_bytes()
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            self.assertEqual(raised.exception.code, "MISSING_DEPENDENCY")
            self.assertEqual(destination_path.read_bytes(), before)

    def test_sidecar_is_read_as_provenance_without_copying_or_editing_source(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, task_id = self._seed(source)
            sidecar_root = root / "sessions"
            sidecar_root.mkdir()
            sidecar_path = sidecar_root / f"{session_id.removeprefix('session:')}.json"
            sidecar_path.write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "workspace_id": "arb-scout",
                        "task_id": task_id,
                        "lifecycle_state": "suspended",
                        "stale": True,
                        "source_dirty": True,
                    }
                ),
                encoding="utf-8",
            )
            sidecar_path.chmod(0o600)
            before = sidecar_path.read_bytes()
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(
                destination,
                allowed_source_roots=(root,),
                source_sidecar_root=sidecar_root,
            )
            plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            result = importer.execute(plan)
            self.assertEqual(result["status"], "IMPORTED")
            self.assertTrue(plan.bundle.source_state["sidecar"]["present"])
            self.assertEqual(sidecar_path.read_bytes(), before)
            imported = destination.load_evidence_generation_imports()[0]
            self.assertEqual(imported["source_state"]["sidecar"]["fields"]["lifecycle_state"], "suspended")

    def test_source_and_destination_must_be_distinct(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            importer = EvidenceGenerationImporter(source, allowed_source_roots=(root,))
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            self.assertEqual(raised.exception.code, "SOURCE_DESTINATION_SAME")

    def test_source_database_identity_swap_fails_before_destination_write(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            replacement = root / "replacement.sqlite3"
            replacement.write_bytes(source_path.read_bytes())
            replacement.chmod(0o600)
            source_path.unlink()
            replacement.rename(source_path)
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.execute(plan)
            self.assertEqual(raised.exception.code, "SOURCE_DATABASE_CHANGED")
            self.assertEqual(destination.load_evidence_generation_imports(), [])

    def test_preflight_rejects_nul_and_non_path_inputs_with_contract_errors(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))
            cases = (
                ({"source_database": f"{source_path}\x00"}, "SOURCE_DATABASE_INVALID"),
                ({"source_database": object()}, "SOURCE_DATABASE_INVALID"),
                ({"session_id": f"{session_id}\x00"}, "SESSION_ID_INVALID"),
                ({"workspace_id": "arb-scout\x00"}, "WORKSPACE_IDENTITY_INVALID"),
                ({"source_generation": "v25\x00"}, "SOURCE_GENERATION_INVALID"),
            )
            for overrides, expected_code in cases:
                params = {
                    "source_database": source_path,
                    "session_id": session_id,
                    "workspace_id": "arb-scout",
                    "source_generation": "v25",
                }
                params.update(overrides)
                with self.subTest(field=next(iter(overrides))):
                    with self.assertRaises(EvidenceGenerationImportError) as raised:
                        importer.preflight(**params)
                    self.assertEqual(raised.exception.code, expected_code)

    def test_source_and_destination_database_helpers_report_their_role(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import (
            EvidenceGenerationImportError,
            _database_asset_hash,
            _read_only_data_version,
            _regular_database,
        )

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.sqlite3"
            cases = (
                (_regular_database, "UNAVAILABLE", {"field": "database", "role": "source"}),
                (_regular_database, "UNAVAILABLE", {"field": "database", "role": "destination"}),
                (_database_asset_hash, "UNAVAILABLE", {"role": "source"}),
                (_database_asset_hash, "UNAVAILABLE", {"role": "destination"}),
                (_read_only_data_version, "INVALID", {"role": "source"}),
                (_read_only_data_version, "INVALID", {"role": "destination"}),
            )
            for helper, suffix, kwargs in cases:
                with self.subTest(helper=helper.__name__, role=kwargs["role"]):
                    with self.assertRaises(EvidenceGenerationImportError) as raised:
                        helper(missing, **kwargs)
                    prefix = "SOURCE_DATABASE" if kwargs["role"] == "source" else "DESTINATION_DATABASE"
                    self.assertEqual(raised.exception.code, f"{prefix}_{suffix}")

    def test_preflight_and_execute_use_destination_classification_and_pin_changes(self) -> None:
        from chatgpt_dev_mcp import evidence_generation_import as importer_module
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            destination_path = root / "v26.sqlite3"
            source = self._store(source_path)
            session_id, _ = self._seed(source)
            destination = self._store(destination_path)
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,))

            with patch.object(importer_module, "_database_asset_hash", wraps=importer_module._database_asset_hash) as hash_helper:
                with patch.object(
                    importer_module,
                    "_read_only_data_version",
                    wraps=importer_module._read_only_data_version,
                ) as data_version_helper:
                    plan = importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            self.assertEqual(hash_helper.call_args_list[0].kwargs["role"], "destination")
            self.assertEqual(data_version_helper.call_args_list[0].kwargs["role"], "destination")
            self.assertIn("source", {call.kwargs["role"] for call in hash_helper.call_args_list})

            destination.run_write(lambda connection: connection.execute("PRAGMA user_version = 1"))
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.execute(plan)
            self.assertEqual(raised.exception.code, "DESTINATION_DATABASE_CHANGED")
            self.assertEqual(destination.load_evidence_generation_imports(), [])

    def test_sidecar_boolean_fields_are_not_coerced(self) -> None:
        from chatgpt_dev_mcp.evidence_generation_import import EvidenceGenerationImportError, EvidenceGenerationImporter

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "v25.sqlite3"
            source = self._store(source_path)
            session_id, task_id = self._seed(source)
            sidecar_root = root / "sessions"
            sidecar_root.mkdir()
            sidecar_path = sidecar_root / f"{session_id.removeprefix('session:')}.json"
            sidecar_path.write_text(json.dumps({"session_id": session_id, "workspace_id": "arb-scout", "task_id": task_id, "stale": "true"}), encoding="utf-8")
            sidecar_path.chmod(0o600)
            destination = self._store(root / "v26.sqlite3")
            importer = EvidenceGenerationImporter(destination, allowed_source_roots=(root,), source_sidecar_root=sidecar_root)
            with self.assertRaises(EvidenceGenerationImportError) as raised:
                importer.preflight(source_path, session_id=session_id, workspace_id="arb-scout")
            self.assertEqual(raised.exception.code, "SOURCE_SIDECAR_INVALID")


if __name__ == "__main__":
    unittest.main()
