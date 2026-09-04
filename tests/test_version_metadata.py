from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

from chatgpt_dev_mcp import __version__


class VersionMetadataTests(unittest.TestCase):
    def test_package_and_project_metadata_are_v041(self) -> None:
        project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(__version__, "0.41")
        self.assertEqual(project["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
