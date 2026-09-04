from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class GlobalRuntimeResourceLeaseTests(unittest.TestCase):
    def test_persistence_rejects_same_runtime_resource_across_workspaces(self) -> None:
        from chatgpt_dev_mcp.persistence import PersistenceError, SqliteDirectorStore

        with tempfile.TemporaryDirectory(prefix="global-resource-lease-") as tempdir:
            store = SqliteDirectorStore(Path(tempdir) / "director.sqlite3")
            for workspace, task in (("project-a", "task-a"), ("project-b", "task-b")):
                store.save_task(
                    {
                        "task_id": task,
                        "request_id": f"request-{task}",
                        "title": task,
                        "workspace_id": workspace,
                        "state": "queued",
                        "created_at": "now",
                        "updated_at": "now",
                    }
                )

            def lease(lease_id: str, workspace: str, task: str, resource: str) -> dict[str, object]:
                return {
                    "lease_id": lease_id,
                    "workspace_id": workspace,
                    "working_tree_id": f"worktree:{workspace}",
                    "task_id": task,
                    "owner_id": f"owner-{workspace}",
                    "paths": [f"src/{workspace}.py"],
                    "resources": [resource],
                    "base_revision": "a" * 40,
                    "scope_hashes": {},
                    "acquired_at": 1.0,
                    "expires_at": 4102444800.0,
                    "state": "active",
                }

            store.save_lease(lease("lease-a", "project-a", "task-a", "port:8765"))
            with self.assertRaises(PersistenceError):
                store.save_lease(lease("lease-b", "project-b", "task-b", "port:8765"))

            # Ordinary path scopes are still project-local: identical relative
            # paths in unrelated projects do not conflict unless a shared
            # runtime resource is also declared.
            store.save_lease(lease("lease-c", "project-b", "task-b", "port:9999"))


if __name__ == "__main__":
    unittest.main()
