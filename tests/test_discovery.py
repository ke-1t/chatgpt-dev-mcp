from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class RootConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-discovery-")
        self.home = Path(self.tempdir.name) / "home"
        (self.home / "Developer").mkdir(parents=True)
        (self.home / "Documents").mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_default_roots_include_only_developer(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots

        roots, errors = load_allowed_roots({"version": 1}, self.home)
        self.assertEqual([(root.id, root.mode) for root in roots], [("developer", "PROJECT_DISCOVERY")])
        self.assertEqual(errors, [])

    def test_explicit_roots_replace_defaults_and_reject_broad_paths(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots

        roots, errors = load_allowed_roots(
            {
                "version": 1,
                "roots": [
                    {"id": "documents", "path": "~/Documents", "mode": "READ_ONLY"},
                    {"id": "home", "path": "~", "mode": "READ_ONLY"},
                ],
            },
            self.home,
        )
        self.assertEqual([root.id for root in roots], ["documents"])
        self.assertTrue(any(error["code"] == "ROOT_PATH_DENIED" for error in errors))

    def test_sensitive_mac_roots_are_rejected(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots

        (self.home / "Library").mkdir()
        (self.home / "Documents" / "Application Support").mkdir(parents=True)
        roots, errors = load_allowed_roots(
            {
                "version": 1,
                "roots": [
                    {"id": "library", "path": "~/Library", "mode": "READ_ONLY"},
                    {"id": "app-support", "path": "~/Documents/Application Support", "mode": "READ_ONLY"},
                ],
            },
            self.home,
        )
        self.assertEqual(roots, [])
        self.assertEqual({error["code"] for error in errors}, {"ROOT_PATH_DENIED"})

    def test_icloud_management_roots_are_rejected_even_when_explicit(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots

        for relative in ("Mobile Documents", "CloudStorage", "iCloud Drive"):
            (self.home / relative).mkdir(parents=True)
        roots, errors = load_allowed_roots(
            {
                "version": 1,
                "roots": [
                    {"id": "mobile-documents", "path": "~/Mobile Documents", "mode": "READ_ONLY"},
                    {"id": "cloud-storage", "path": "~/CloudStorage", "mode": "READ_ONLY"},
                    {"id": "icloud-drive", "path": "~/iCloud Drive", "mode": "READ_ONLY"},
                ],
            },
            self.home,
        )
        self.assertEqual(roots, [])
        self.assertEqual({error["code"] for error in errors}, {"ROOT_PATH_DENIED"})

    def test_invalid_modes_and_duplicate_ids_are_reported(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots

        roots, errors = load_allowed_roots(
            {
                "version": 1,
                "roots": [
                    {"id": "developer", "path": "~/Developer", "mode": "READ_WRITE"},
                    {"id": "developer", "path": "~/Documents", "mode": "READ_ONLY"},
                ],
            },
            self.home,
        )
        self.assertEqual(roots, [])
        self.assertEqual({error["code"] for error in errors}, {"ROOT_MODE_INVALID", "ROOT_ID_DUPLICATE"})


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-discovery-")
        self.root = Path(self.tempdir.name)
        self.home = self.root / "home"
        self.developer = self.home / "Developer"
        self.developer.mkdir(parents=True)
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self._previous_home = os.environ.get("HOME")
        self._previous_config = os.environ.get("LOCAL_DEV_MCP_CONFIG")
        self._previous_data_dir = os.environ.get("LOCAL_DEV_MCP_DATA_DIR")
        os.environ["HOME"] = str(self.home)
        self.config_path = self.home / ".config" / "local-dev-mcp" / "config.json"
        self.config_path.parent.mkdir(parents=True)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(self.config_path)
        os.environ["LOCAL_DEV_MCP_DATA_DIR"] = str(self.root / "director-state")

        self.parent_repo = self.developer / "parent-repo"
        self.nested_repo = self.parent_repo / "nested-repo"
        self._init_repo(self.parent_repo)
        self._init_repo(self.nested_repo)
        (self.developer / "ordinary-directory").mkdir()
        hidden_repo = self.developer / ".hidden-repo"
        hidden_repo.mkdir()
        self._init_repo(hidden_repo)
        cache_repo = self.developer / "node_modules" / "cache-repo"
        cache_repo.mkdir(parents=True)
        self._init_repo(cache_repo)
        escaped_git_repo = self.developer / "escaped-git-repo"
        escaped_git_repo.mkdir()
        (escaped_git_repo / "README.md").write_text("outside metadata\n", encoding="utf-8")
        (escaped_git_repo / ".git").symlink_to(self.outside, target_is_directory=True)
        (self.outside / "outside.txt").write_text("outside\n", encoding="utf-8")

    def tearDown(self) -> None:
        if self._previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._previous_home
        if self._previous_config is None:
            os.environ.pop("LOCAL_DEV_MCP_CONFIG", None)
        else:
            os.environ["LOCAL_DEV_MCP_CONFIG"] = self._previous_config
        if self._previous_data_dir is None:
            os.environ.pop("LOCAL_DEV_MCP_DATA_DIR", None)
        else:
            os.environ["LOCAL_DEV_MCP_DATA_DIR"] = self._previous_data_dir
        self.tempdir.cleanup()

    @staticmethod
    def _init_repo(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)

    def _write_config(self, *, include_write_entries: bool = True) -> None:
        workspaces = {}
        if include_write_entries:
            workspaces = {
                "developer-root": {"path": "~/Developer", "profile": "READ_WRITE"},
                "parent": {"path": "~/Developer/parent-repo", "profile": "READ_WRITE"},
            }
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": workspaces,
                }
            ),
            encoding="utf-8",
        )

    def test_discovers_nested_git_repositories_without_descending_into_git_data(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots, discover_git_repositories

        roots, errors = load_allowed_roots(
            {"version": 1, "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}]},
            self.home,
        )
        self.assertEqual(errors, [])
        report = discover_git_repositories(roots[0], max_depth=4, max_results=10)
        discovered = {Path(item["path"]).resolve() for item in report["repositories"]}
        self.assertIn(self.parent_repo.resolve(), discovered)
        self.assertIn(self.nested_repo.resolve(), discovered)
        self.assertNotIn((self.developer / ".hidden-repo").resolve(), discovered)
        self.assertNotIn((self.developer / "node_modules" / "cache-repo").resolve(), discovered)
        self.assertNotIn((self.developer / "escaped-git-repo").resolve(), discovered)
        self.assertLessEqual(report["visited_directories"], 2000)

    def test_discovery_requires_a_valid_git_root_and_head(self) -> None:
        from chatgpt_dev_mcp.discovery import load_allowed_roots, discover_git_repositories

        fake = self.developer / "fake-marker"
        fake.mkdir()
        (fake / ".git").write_text("not a gitdir marker\n", encoding="utf-8")
        empty = self.developer / "empty-repo"
        subprocess.run(["git", "init", "-q", str(empty)], check=True)
        roots, errors = load_allowed_roots(
            {"version": 1, "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}]},
            self.home,
        )
        self.assertEqual(errors, [])
        report = discover_git_repositories(roots[0], max_depth=2, max_results=20)
        discovered = {Path(item["path"]).resolve() for item in report["repositories"]}
        self.assertNotIn(fake.resolve(), discovered)
        self.assertNotIn(empty.resolve(), discovered)
        self.assertIn(self.parent_repo.resolve(), discovered)

    def test_git_metadata_reports_all_dirty_sources(self) -> None:
        from chatgpt_dev_mcp.discovery import git_metadata

        (self.parent_repo / "README.md").write_text("unstaged\n", encoding="utf-8")
        (self.parent_repo / "staged.txt").write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.parent_repo), "add", "staged.txt"], check=True)
        (self.parent_repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        metadata = git_metadata(self.parent_repo)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertTrue(metadata["dirty"])
        self.assertTrue(metadata["staged"])
        self.assertTrue(metadata["unstaged"])
        self.assertTrue(metadata["untracked"])

    def test_candidate_id_is_opaque_and_unknown_or_forged_ids_are_rejected(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate_id = discovered["repositories"][0]["candidate_id"]
        self.assertTrue(candidate_id.startswith("candidate:"))
        self.assertNotIn(str(self.parent_repo), candidate_id)
        forged = runtime.call_tool("workspace_open", {"id": "candidate:forged"})["structuredContent"]
        self.assertEqual(forged["error"]["code"], "DISCOVERY_CANDIDATE_NOT_FOUND")
        runtime.close()

    def test_candidate_is_invalid_after_runtime_restart(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        first = WrapperRuntime()
        candidate_id = first.call_tool("workspace_discover", {})["structuredContent"]["repositories"][0]["candidate_id"]
        first.close()
        second = WrapperRuntime()
        expired = second.call_tool("workspace_open", {"id": candidate_id})["structuredContent"]
        self.assertEqual(expired["error"]["code"], "DISCOVERY_CANDIDATE_NOT_FOUND")
        second.close()

    def test_candidate_rechecks_symlink_containment_at_open_time(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate = next(item for item in discovered["repositories"] if item["name"] == "parent-repo")
        original = self.parent_repo
        moved = self.root / "moved-parent"
        original.rename(moved)
        original.symlink_to(self.outside, target_is_directory=True)
        invalid = runtime.call_tool("workspace_open", {"id": candidate["candidate_id"]})["structuredContent"]
        self.assertEqual(invalid["error"]["code"], "DISCOVERY_CANDIDATE_INVALID")
        runtime.close()

    def test_candidate_open_rejects_same_path_repository_replacement(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate = next(item for item in discovered["repositories"] if item["name"] == "parent-repo")
        moved = self.root / "moved-parent"
        self.parent_repo.rename(moved)
        self._init_repo(self.parent_repo)
        invalid = runtime.call_tool("workspace_open", {"id": candidate["candidate_id"]})["structuredContent"]
        self.assertEqual(invalid["error"]["code"], "CANDIDATE_CHANGED")
        runtime.close()

    def test_candidate_open_rejects_git_marker_change(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate = next(item for item in discovered["repositories"] if item["name"] == "parent-repo")
        marker = self.parent_repo / ".git"
        marker.rename(self.root / "moved-git-marker")
        invalid = runtime.call_tool("workspace_open", {"id": candidate["candidate_id"]})["structuredContent"]
        self.assertEqual(invalid["error"]["code"], "CANDIDATE_CHANGED")
        runtime.close()

    def test_candidate_open_rejects_head_change(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
        candidate = next(item for item in discovered["repositories"] if item["name"] == "parent-repo")
        (self.parent_repo / "changed.txt").write_text("changed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.parent_repo), "add", "changed.txt"], check=True)
        subprocess.run(["git", "-C", str(self.parent_repo), "commit", "-qm", "second"], check=True)
        invalid = runtime.call_tool("workspace_open", {"id": candidate["candidate_id"]})["structuredContent"]
        self.assertEqual(invalid["error"]["code"], "CANDIDATE_CHANGED")
        runtime.close()

    def test_project_candidate_open_rejects_same_path_directory_replacement(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        project = self.developer / "ordinary-project"
        project.mkdir()
        (project / "README.md").write_text("original\n", encoding="utf-8")
        self._write_config(include_write_entries=False)
        runtime = WrapperRuntime()
        try:
            discovered = runtime.call_tool("workspace_discover", {})["structuredContent"]
            candidate = next(item for item in discovered["repositories"] if item["name"] == "ordinary-project")
            moved = self.root / "moved-ordinary-project"
            project.rename(moved)
            project.mkdir()
            (project / "README.md").write_text("replacement\n", encoding="utf-8")
            invalid = runtime.call_tool("workspace_open", {"id": candidate["candidate_id"]})["structuredContent"]
            self.assertEqual(invalid["error"]["code"], "CANDIDATE_CHANGED")
        finally:
            runtime.close()

    def test_discovery_root_never_inherits_write_profile(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=True)
        runtime = WrapperRuntime()
        denied = runtime.call_tool("workspace_open", {"id": "developer-root"})["structuredContent"]
        self.assertEqual(denied["error"]["code"], "ROOT_PROFILE_DENIED")
        candidate_id = runtime.call_tool("workspace_discover", {})["structuredContent"]["repositories"][0]["candidate_id"]
        opened = runtime.call_tool("workspace_open", {"id": candidate_id})["structuredContent"]
        self.assertEqual(opened["profile"], "READ_ONLY")
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+changed\n*** End Patch"
        blocked = runtime.call_tool("apply_patch", {"patch": patch})["structuredContent"]
        self.assertEqual(blocked["error"]["code"], "PROFILE_DENIED")
        runtime.close()

    def test_individual_project_can_still_use_existing_write_profile(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config(include_write_entries=True)
        runtime = WrapperRuntime()
        opened = runtime.call_tool("workspace_open", {"id": "parent"})["structuredContent"]
        self.assertEqual(opened["profile"], "READ_WRITE")
        patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-fixture\n+changed\n*** End Patch"
        lease = runtime.call_tool(
            "director_writer_lease",
            {"action": "acquire", "owner_id": "test", "task_id": "task-a", "paths": ["README.md"]},
        )["structuredContent"]["lease"]
        result = runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease["lease_id"]})["structuredContent"]
        self.assertTrue(result["ok"])
        runtime.close()


class FileDiscoveryTests(DiscoveryTests):
    def setUp(self) -> None:
        super().setUp()
        self.documents = self.home / "Documents"
        self.documents.mkdir()
        (self.documents / "spec.md").write_text("needle specification\nsecond line\n", encoding="utf-8")
        hidden = self.documents / ".hidden.md"
        hidden.write_text("needle hidden\n", encoding="utf-8")
        cache = self.documents / "node_modules" / "package"
        cache.mkdir(parents=True)
        (cache / "cache.txt").write_text("needle cache\n", encoding="utf-8")
        (self.documents / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
        ssh = self.documents / ".ssh"
        ssh.mkdir()
        (ssh / "id_ed25519").write_text("private\n", encoding="utf-8")
        keychains = self.documents / "Library" / "Keychains"
        keychains.mkdir(parents=True)
        (keychains / "login.keychain-db").write_text("secret\n", encoding="utf-8")
        browser_profile = self.documents / "Library" / "Application Support" / "Browser"
        browser_profile.mkdir(parents=True)
        (browser_profile / "profile.db").write_text("browser credential\n", encoding="utf-8")
        containers = self.documents / "Containers" / "example" / "session"
        containers.mkdir(parents=True)
        (containers / "token.json").write_text("token\n", encoding="utf-8")
        group_containers = self.documents / "Group Containers" / "example"
        group_containers.mkdir(parents=True)
        (group_containers / "credentials.json").write_text("credentials\n", encoding="utf-8")
        (self.documents / "image.bin").write_bytes(b"\x00\x01binary")
        (self.documents / "invalid-utf8.bin").write_bytes(b"\xff\xfe\x00binary")
        (self.documents / "large.txt").write_text("x" * (256 * 1024 + 1), encoding="utf-8")
        (self.documents / "escape").symlink_to(self.outside, target_is_directory=True)

    def _write_file_config(self) -> None:
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [
                        {"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"},
                        {"id": "documents", "path": "~/Documents", "mode": "READ_ONLY"},
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_file_tools_require_explicit_read_only_root(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_config()
        runtime = WrapperRuntime()
        denied = runtime.call_tool("list_allowed_files", {"root_id": "documents"})["structuredContent"]
        self.assertEqual(denied["error"]["code"], "ROOT_NOT_FOUND")
        self._write_file_config()
        allowed = runtime.call_tool("list_allowed_files", {"root_id": "documents"})["structuredContent"]
        self.assertTrue(allowed["ok"])
        runtime.close()

    def test_list_and_search_skip_hidden_cache_sensitive_binary_and_oversized_files(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_file_config()
        runtime = WrapperRuntime()
        listed = runtime.call_tool("list_allowed_files", {"root_id": "documents", "max_depth": 3})["structuredContent"]
        listed_paths = {item["path"] for item in listed["files"]}
        self.assertIn("spec.md", listed_paths)
        self.assertNotIn(".hidden.md", listed_paths)
        self.assertNotIn(".env", listed_paths)
        self.assertNotIn("image.bin", listed_paths)
        self.assertNotIn("invalid-utf8.bin", listed_paths)
        self.assertNotIn("large.txt", listed_paths)
        self.assertFalse(any("node_modules" in path or "Keychains" in path for path in listed_paths))
        self.assertFalse(any("Library" in path or "Containers" in path or "Group Containers" in path for path in listed_paths))
        searched = runtime.call_tool("search_allowed_files", {"root_id": "documents", "query": "needle", "max_depth": 3})["structuredContent"]
        self.assertTrue(searched["ok"])
        self.assertEqual({item["path"] for item in searched["matches"]}, {"spec.md"})
        self.assertNotIn("secret", str(searched))
        runtime.close()

    def test_file_discovery_caps_directory_entries_and_depth(self) -> None:
        from chatgpt_dev_mcp.discovery import MAX_ENTRIES_PER_DIRECTORY
        from chatgpt_dev_mcp.server import WrapperRuntime

        for index in range(MAX_ENTRIES_PER_DIRECTORY + 8):
            (self.documents / f"entry-{index:03d}.txt").write_text("entry\n", encoding="utf-8")
        deep = self.documents / "deep" / "one" / "two"
        deep.mkdir(parents=True)
        (deep / "hidden-by-depth.txt").write_text("depth\n", encoding="utf-8")
        self._write_file_config()
        runtime = WrapperRuntime()
        listed = runtime.call_tool("list_allowed_files", {"root_id": "documents", "max_depth": 0, "max_results": 100})["structuredContent"]
        self.assertTrue(listed["truncated"])
        self.assertGreaterEqual(listed["omitted"].get("directory_entries", 0), 8)
        self.assertFalse(any(item["path"].startswith("deep/") for item in listed["files"]))
        runtime.close()

    def test_file_tools_reject_parent_paths_and_symlink_escape(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        self._write_file_config()
        runtime = WrapperRuntime()
        parent = runtime.call_tool("list_allowed_files", {"root_id": "documents", "path": "../"})["structuredContent"]
        self.assertEqual(parent["error"]["code"], "FILE_ROOT_PATH_DENIED")
        escape = runtime.call_tool("list_allowed_files", {"root_id": "documents", "path": "escape"})["structuredContent"]
        self.assertEqual(escape["error"]["code"], "FILE_ROOT_PATH_DENIED")
        runtime.close()

    def test_file_tools_report_depth_and_output_limits_without_unbounded_reads(self) -> None:
        from chatgpt_dev_mcp.server import WrapperRuntime

        for index in range(8):
            (self.documents / f"file-{index}.txt").write_text(f"needle {index}\n", encoding="utf-8")
        self._write_file_config()
        runtime = WrapperRuntime()
        listed = runtime.call_tool("list_allowed_files", {"root_id": "documents", "max_results": 2})["structuredContent"]
        self.assertEqual(len(listed["files"]), 2)
        self.assertTrue(listed["truncated"])
        searched = runtime.call_tool("search_allowed_files", {"root_id": "documents", "query": "needle", "max_results": 1})["structuredContent"]
        self.assertEqual(len(searched["matches"]), 1)
        self.assertTrue(searched["truncated"])
        runtime.close()


if __name__ == "__main__":
    unittest.main()
