from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def init_repo(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "smoke@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Discovery Smoke"], check=True)
    subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="chatgpt-dev-mcp-discovery-smoke-") as temp:
        root = Path(temp)
        home = root / "home"
        developer = home / "Developer"
        documents = home / "Documents"
        developer.mkdir(parents=True)
        documents.mkdir()

        valid = developer / "valid-repo"
        nested = valid / "nested-repo"
        init_repo(valid)
        init_repo(nested)
        fake = developer / "fake-marker"
        fake.mkdir()
        (fake / ".git").write_text("not a gitdir marker\n", encoding="utf-8")
        empty = developer / "empty-repo"
        subprocess.run(["git", "init", "-q", str(empty)], check=True)

        (documents / "00-spec.md").write_text("needle specification\n", encoding="utf-8")
        (documents / ".env").write_text("TOKEN=fixture-only\n", encoding="utf-8")
        (documents / "session.json").write_text("session=fixture-only\n", encoding="utf-8")
        (documents / "binary.bin").write_bytes(b"\x00binary\n")
        (documents / "invalid-utf8.bin").write_bytes(b"\xff\xfebinary\n")
        (documents / "large.txt").write_text("x" * (256 * 1024 + 1), encoding="utf-8")
        browser = documents / "Library" / "Application Support" / "Browser"
        browser.mkdir(parents=True)
        (browser / "profile.db").write_text("credential fixture\n", encoding="utf-8")
        containers = documents / "Containers" / "example" / "session"
        containers.mkdir(parents=True)
        (containers / "token.json").write_text("token fixture\n", encoding="utf-8")
        for index in range(264):
            (documents / f"entry-{index:03d}.txt").write_text("entry\n", encoding="utf-8")
        deep = documents / "deep" / "one" / "two"
        deep.mkdir(parents=True)
        (deep / "outside-depth.txt").write_text("depth\n", encoding="utf-8")

        from chatgpt_dev_mcp.discovery import (
            PROJECT_DISCOVERY,
            READ_ONLY,
            discover_git_repositories,
            git_metadata,
            list_allowed_files,
            load_allowed_roots,
            search_allowed_files,
        )

        roots, errors = load_allowed_roots(
            {
                "version": 1,
                "roots": [
                    {"id": "developer", "path": "~/Developer", "mode": PROJECT_DISCOVERY},
                    {"id": "documents", "path": "~/Documents", "mode": READ_ONLY},
                ],
            },
            home,
        )
        assert errors == [], errors
        developer_root = next(root for root in roots if root.id == "developer")
        documents_root = next(root for root in roots if root.id == "documents")

        report = discover_git_repositories(developer_root, max_depth=4, max_results=20)
        discovered = {Path(item["path"]).resolve() for item in report["repositories"]}
        assert valid.resolve() in discovered and nested.resolve() in discovered, discovered
        assert fake.resolve() not in discovered and empty.resolve() not in discovered, discovered

        (valid / "README.md").write_text("unstaged\n", encoding="utf-8")
        (valid / "staged.txt").write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(valid), "add", "staged.txt"], check=True)
        (valid / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        metadata = git_metadata(valid)
        assert metadata is not None and metadata["dirty"] is True
        assert metadata["staged"] is True and metadata["unstaged"] is True and metadata["untracked"] is True, metadata

        listed = list_allowed_files(documents_root, ".", max_depth=0, max_results=100)
        listed_paths = {item["path"] for item in listed["files"]}
        assert listed["truncated"] is True
        assert listed["omitted"].get("directory_entries", 0) >= 8, listed
        assert "00-spec.md" in listed_paths
        assert not any(
            any(part in path for part in ("Library", "Containers", "Group Containers"))
            or path in {".env", "session.json", "binary.bin", "invalid-utf8.bin", "large.txt"}
            or path.startswith("deep/")
            for path in listed_paths
        ), listed_paths

        searched = search_allowed_files(documents_root, ".", "needle", max_depth=2, max_results=10)
        assert {item["path"] for item in searched["matches"]} == {"00-spec.md"}, searched

    print("smoke_discovery: PASS")


if __name__ == "__main__":
    main()
