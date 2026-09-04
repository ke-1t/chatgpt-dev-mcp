from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.acceleration_runtime import (
    AccelerationRuntimeServices,
    WorkspaceStateEvidence,
    workspace_state_evidence,
)
from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog
from chatgpt_dev_mcp.capability_gateway import CapabilityGateway
from chatgpt_dev_mcp.observability import AccelerationObserver
from chatgpt_dev_mcp.project_capsule import CapsuleSection
from chatgpt_dev_mcp.semantic_index import SemanticQuery
from chatgpt_dev_mcp.warm_runtime import WarmRuntimeManager


class _LoopStore:
    def __init__(self) -> None:
        self.value = None

    def load_development_loop(self, _loop_id: str):
        return self.value

    def save_development_loop(self, state, *, pending_action: str = "") -> None:
        self.value = {"state": state, "pending_action": pending_action}


class AccelerationRuntimeServicesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="acceleration-runtime-")
        self.root = Path(self.tempdir.name)
        (self.root / "app.py").write_text(
            "def greet(name: str) -> str:\n    return f'hello {name}'\n",
            encoding="utf-8",
        )
        tests = self.root / "tests"
        tests.mkdir()
        (tests / "test_app.py").write_text(
            "from app import greet\n\ndef test_greet():\n    assert greet('world') == 'hello world'\n",
            encoding="utf-8",
        )
        self.service = AccelerationRuntimeServices(
            persistence=None,
            warm_runtimes=WarmRuntimeManager(max_entries=4, ttl_seconds=60.0),
            observer=AccelerationObserver(),
            capability_catalog=CapabilityAdapterCatalog(resolver=lambda _name: None),
            capability_gateway=CapabilityGateway(),
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_workspace_state_evidence_is_deterministic(self) -> None:
        clean = workspace_state_evidence({"clean": True, "entries": []})
        dirty_a = workspace_state_evidence(
            {"clean": False, "entries": [{"path": "app.py", "index_status": " ", "worktree_status": "M"}]}
        )
        dirty_b = workspace_state_evidence(
            {"clean": False, "entries": [{"path": "app.py", "index_status": " ", "worktree_status": "M"}]}
        )
        self.assertTrue(clean.clean)
        self.assertEqual(clean.fingerprint, "clean")
        self.assertFalse(dirty_a.clean)
        self.assertEqual(dirty_a, dirty_b)

    def test_semantic_query_returns_definition_and_receipt(self) -> None:
        payload = self.service.semantic_query(
            self.root,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            source_revision="a" * 40,
            state=WorkspaceStateEvidence(True, "clean"),
            query=SemanticQuery(text="greet", relations=("definition", "tests"), limit=20),
            updated_at="2026-08-15T00:00:00Z",
        )
        self.assertTrue(any(str(item["symbol_id"]).endswith(":greet") for item in payload["matches"]))
        self.assertTrue(str(payload["receipt_id"]).startswith("acceleration:"))
        self.assertFalse(payload["external_execution"])

    def test_dirty_semantic_query_does_not_use_warm_cache(self) -> None:
        state = WorkspaceStateEvidence(False, "dirty-state")
        first = self.service.semantic_query(
            self.root,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            source_revision="a" * 40,
            state=state,
            query=SemanticQuery(text="greet", relations=("definition",), limit=20),
            updated_at="2026-08-15T00:00:00Z",
        )
        (self.root / "app.py").write_text("def farewell() -> str:\n    return 'bye'\n", encoding="utf-8")
        second = self.service.semantic_query(
            self.root,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            source_revision="a" * 40,
            state=state,
            query=SemanticQuery(text="greet", relations=("definition",), limit=20),
            updated_at="2026-08-15T00:00:01Z",
        )
        self.assertTrue(first["matches"])
        self.assertFalse(any(str(item["symbol_id"]).endswith(":greet") for item in second["matches"]))

    def test_development_context_uses_injected_safe_readers(self) -> None:
        payload = self.service.development_context(
            self.root,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            source_revision="a" * 40,
            state=WorkspaceStateEvidence(True, "clean"),
            task_id="task-1",
            query="greet",
            target_paths=("app.py",),
            diff_paths=("app.py",),
            max_bytes=8192,
            safe_reader=lambda path: (self.root / path).read_text(encoding="utf-8"),
            diff_reader=lambda _path: "+def greet(name): ...",
            updated_at="2026-08-15T00:00:00Z",
        )
        self.assertEqual(payload["task_id"], "task-1")
        self.assertGreater(payload["used_bytes"], 0)
        self.assertFalse(payload["external_execution"])

    def test_clean_context_bootstrap_reuses_exact_capsule(self) -> None:
        (self.root / "AGENTS.md").write_text("Never push without explicit approval.\n", encoding="utf-8")
        kwargs = {
            "root": self.root,
            "workspace_id": "fixture",
            "working_tree_id": "worktree:fixture",
            "source_revision": "a" * 40,
            "state": WorkspaceStateEvidence(True, "clean"),
            "base_sections": (CapsuleSection("current_state", 90, True, ("clean",)),),
            "query": "greet",
            "max_bytes": 4096,
            "instructions_reader": lambda path: (self.root / path).read_text(encoding="utf-8"),
            "updated_at": "2026-08-17T00:00:00Z",
        }

        first = self.service.context_bootstrap(**kwargs)
        second = self.service.context_bootstrap(**kwargs)

        self.assertEqual(first["cache_status"], "miss")
        self.assertEqual(second["cache_status"], "hit")
        self.assertEqual(first["capsule"]["capsule_id"], second["capsule"]["capsule_id"])
        self.assertLessEqual(second["used_bytes"], 4096)
        self.assertEqual(second["instructions_status"], "loaded")
        self.assertIn("instructions", second["capsule"]["sections"])

    def test_context_bootstrap_missing_agents_is_non_fatal(self) -> None:
        payload = self.service.context_bootstrap(
            self.root,
            workspace_id="fixture",
            working_tree_id="worktree:fixture",
            source_revision="a" * 40,
            state=WorkspaceStateEvidence(True, "clean"),
            query="greet",
            max_bytes=4096,
            instructions_reader=lambda path: (self.root / path).read_text(encoding="utf-8"),
            updated_at="2026-08-17T00:00:00Z",
        )

        self.assertEqual(payload["instructions_status"], "missing")
        self.assertNotIn("instructions", payload["capsule"]["sections"])

    def test_dirty_context_bootstrap_rereads_agents_contents(self) -> None:
        agents = self.root / "AGENTS.md"
        agents.write_text("first instruction\n", encoding="utf-8")
        kwargs = {
            "root": self.root,
            "workspace_id": "fixture",
            "working_tree_id": "worktree:fixture",
            "source_revision": "a" * 40,
            "state": WorkspaceStateEvidence(False, "same-dirty-path-fingerprint"),
            "query": "greet",
            "max_bytes": 4096,
            "instructions_reader": lambda path: (self.root / path).read_text(encoding="utf-8"),
            "updated_at": "2026-08-17T00:00:00Z",
        }

        first = self.service.context_bootstrap(**kwargs)
        agents.write_text("second instruction\n", encoding="utf-8")
        second = self.service.context_bootstrap(**kwargs)

        self.assertEqual(first["cache_status"], "bypass_dirty")
        self.assertEqual(second["cache_status"], "bypass_dirty")
        self.assertIn("first instruction", first["capsule"]["sections"]["instructions"])
        self.assertIn("second instruction", second["capsule"]["sections"]["instructions"])
        self.assertNotEqual(first["instructions_hash"], second["instructions_hash"])

    def test_dirty_context_focus_rebuilds_when_contents_change_but_paths_do_not(self) -> None:
        state = WorkspaceStateEvidence(False, "same-dirty-path-fingerprint")
        kwargs = {
            "root": self.root,
            "workspace_id": "fixture",
            "working_tree_id": "worktree:fixture",
            "source_revision": "a" * 40,
            "state": state,
            "task_id": "task-context",
            "query": "greet",
            "target_paths": ("app.py",),
            "diff_paths": (),
            "max_bytes": 4096,
            "safe_reader": lambda path: (self.root / path).read_text(encoding="utf-8"),
            "diff_reader": lambda _path: "",
            "updated_at": "2026-08-17T00:00:00Z",
        }

        first = self.service.context_focus(**kwargs)
        (self.root / "app.py").write_text("def farewell() -> str:\n    return 'bye'\n", encoding="utf-8")
        second = self.service.context_focus(**kwargs)

        self.assertEqual(first["freshness"], "dirty_rebuild")
        self.assertEqual(second["freshness"], "dirty_rebuild")
        self.assertTrue(any(item["kind"] == "definition" for item in first["items"]))
        self.assertFalse(any(str(item["path"]) == "app.py" and "greet" in str(item["content"]) for item in second["items"]))

    def test_capability_status_does_not_start_process_or_network(self) -> None:
        payload = self.service.external_capability_status()
        self.assertFalse(payload["process_started"])
        self.assertFalse(payload["network_used"])
        self.assertFalse(payload["external_execution"])

    def test_next_action_is_restart_safe_and_idempotent(self) -> None:
        store = _LoopStore()
        service = AccelerationRuntimeServices(
            persistence=store,
            warm_runtimes=WarmRuntimeManager(max_entries=4, ttl_seconds=60.0),
            observer=AccelerationObserver(),
            capability_catalog=CapabilityAdapterCatalog(resolver=lambda _name: None),
            capability_gateway=CapabilityGateway(),
        )
        first = service.director_next_action(
            loop_id="loop-1",
            owner_id="owner-1",
            task_id="task-1",
            session_id="session:1",
            worktree_id="worktree:1",
            now=100.0,
            create=True,
            event={"event_id": "event-1", "kind": "implementation_complete", "at": 101.0},
        )
        second = service.director_next_action(
            loop_id="loop-1",
            owner_id="owner-1",
            task_id="task-1",
            session_id="session:1",
            worktree_id="worktree:1",
            now=102.0,
            event={"event_id": "event-1", "kind": "implementation_complete", "at": 101.0},
        )
        self.assertEqual(first["state"]["phase"], "FAST_VERIFY")
        self.assertEqual(second["state"]["history_count"], 1)
        self.assertEqual(second["decision"]["action"], "verification_fast")

    def test_next_action_identity_mismatch_is_blocked_without_advancing(self) -> None:
        store = _LoopStore()
        service = AccelerationRuntimeServices(
            persistence=store,
            warm_runtimes=WarmRuntimeManager(max_entries=4, ttl_seconds=60.0),
            observer=AccelerationObserver(),
            capability_catalog=CapabilityAdapterCatalog(resolver=lambda _name: None),
            capability_gateway=CapabilityGateway(),
        )
        service.director_next_action(
            loop_id="loop-2",
            owner_id="owner-1",
            task_id="task-1",
            session_id="session:1",
            worktree_id="worktree:1",
            now=100.0,
            create=True,
        )
        mismatch = service.director_next_action(
            loop_id="loop-2",
            owner_id="other-owner",
            task_id="task-1",
            session_id="session:1",
            worktree_id="worktree:1",
            now=101.0,
            event={"event_id": "event-2", "kind": "implementation_complete", "at": 101.0},
        )
        self.assertEqual(mismatch["decision"]["status"], "blocked")
        self.assertEqual(mismatch["state"]["history_count"], 0)


if __name__ == "__main__":
    unittest.main()
