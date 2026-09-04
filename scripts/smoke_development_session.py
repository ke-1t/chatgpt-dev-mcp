from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def structured(result: dict) -> dict:
    return result.get("structuredContent", {})


def assert_ok(result: dict, label: str) -> dict:
    payload = structured(result)
    assert result.get("isError") is False and payload.get("ok") is True, (label, result)
    return payload


def assert_error(result: dict, code: str, label: str) -> None:
    payload = structured(result)
    assert result.get("isError") is True, (label, result)
    assert payload.get("error", {}).get("code") == code, (label, result)


def init_repo(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "README.md").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "smoke@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Smoke"], check=True)
    subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-development-smoke-") as temp:
        root = Path(temp)
        home = root / "home"
        repo = home / "Developer" / "smoke-repo"
        init_repo(repo)
        config = home / ".config" / "local-dev-mcp" / "config.json"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roots": [{"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"}],
                    "workspaces": {
                        "smoke-repo": {
                            "path": "~/Developer/smoke-repo",
                            "profile": "DEVELOPMENT",
                            "commands": {"test": "printf smoke-development-ok"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        previous = {key: os.environ.get(key) for key in ("HOME", "LOCAL_DEV_MCP_CONFIG", "LOCAL_DEV_MCP_WORKTREE_ROOT")}
        os.environ["HOME"] = str(home)
        os.environ["LOCAL_DEV_MCP_CONFIG"] = str(config)
        os.environ["LOCAL_DEV_MCP_WORKTREE_ROOT"] = str(home / ".cache" / "local-dev-mcp" / "worktrees")
        try:
            from chatgpt_dev_mcp.server import WrapperRuntime

            source_before = (repo / "README.md").read_text(encoding="utf-8")
            source_status_before = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout
            runtime = WrapperRuntime()
            discovered = assert_ok(runtime.call_tool("workspace_discover", {}), "discover")
            candidate_id = next(item["candidate_id"] for item in discovered["repositories"] if item["name"] == "smoke-repo")
            opened = assert_ok(runtime.call_tool("workspace_open", {"id": candidate_id}), "open read-only")
            assert opened["profile"] == "READ_ONLY", opened
            assert_error(runtime.call_tool("apply_patch", {"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-before\n+blocked\n*** End Patch"}), "PROFILE_DENIED", "read-only denied")
            approval = assert_ok(runtime.call_tool("workspace_request_development", {"candidate_id": candidate_id, "workspace_id": "smoke-repo"}), "request approval")
            assert_error(runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": "wrong"}), "DEVELOPMENT_APPROVAL_MISMATCH", "wrong confirmation")
            session = assert_ok(runtime.call_tool("workspace_create_development_session", {"approval_token": approval["approval_token"], "confirmation": approval["confirmation"]}), "create session")
            worktree = Path(session["worktree_path"]).expanduser()
            assert worktree.is_dir() and str(worktree.resolve()).startswith(str((home / ".cache" / "local-dev-mcp" / "worktrees").resolve())), session
            patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-before\n+after\n*** End Patch"
            lease = assert_ok(
                runtime.call_tool(
                    "director_writer_lease",
                    {
                        "action": "acquire",
                        "owner_id": "smoke-chat",
                        "task_id": "smoke-patch",
                        "paths": ["README.md"],
                    },
                ),
                "acquire writer lease",
            )["lease"]
            assert_ok(runtime.call_tool("apply_patch", {"patch": patch, "lease_id": lease["lease_id"]}), "apply patch")
            read_back = assert_ok(runtime.call_tool("read_file", {"path": "README.md"}), "read back")
            assert "after" in str(read_back), read_back
            diff = assert_ok(runtime.call_tool("git_diff", {"path": "."}), "git diff")
            assert "after" in str(diff), diff
            task = assert_ok(runtime.call_tool("run_task", {"task": "test"}), "registered test")
            assert "smoke-development-ok" in str(task), task
            names = {item["name"] for item in runtime.list_tools()["tools"]}
            assert "exec_command" not in names and {"git_commit_preflight", "git_commit", "git_push_preflight", "git_push"} <= names, names
            assert (repo / "README.md").read_text(encoding="utf-8") == source_before
            source_status_after = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout
            assert source_status_after == source_status_before, (source_status_before, source_status_after)
            dirty_close = assert_ok(runtime.call_tool("workspace_close_development_session", {"session_id": session["session_id"]}), "dirty cleanup retained")
            assert dirty_close.get("durable_state") == "suspended", dirty_close
            assert dirty_close.get("dirty") is True and dirty_close.get("removed") is False, dirty_close
            assert dirty_close.get("worktree_available") is True, dirty_close
            runtime.close()
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    print("smoke_development_session: PASS")


if __name__ == "__main__":
    main()
