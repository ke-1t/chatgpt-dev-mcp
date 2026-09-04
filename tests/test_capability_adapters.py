from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class CapabilityAdapterTests(unittest.TestCase):
    def test_discovery_is_side_effect_free_and_reports_expected_catalog(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog
        calls = []
        catalog = CapabilityAdapterCatalog(resolver=lambda name: calls.append(name) or (f"/usr/bin/{name}" if name == "gh" else None))
        status = catalog.status()
        ids = {item["provider_id"] for item in status["providers"]}
        self.assertTrue({"playwright-cli", "playwright-mcp", "chrome-devtools-mcp", "serena", "context7", "github-gh"} <= ids)
        self.assertFalse(status["process_started"])
        self.assertFalse(status["network_used"])
        self.assertIn("gh", calls)

    def test_discovery_falls_back_to_exact_trusted_bin_root_without_recursive_scan(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "playwright-mcp"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | 0o111)
            nested = root / "nested"
            nested.mkdir()
            (nested / "context7-mcp").write_text("not executable discovery", encoding="utf-8")

            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))
            status = {item["provider_id"]: item for item in catalog.status()["providers"]}

            self.assertEqual(status["playwright-mcp"]["status"], "available")
            self.assertEqual(status["playwright-mcp"]["executable"], str(executable))
            self.assertEqual(status["context7"]["status"], "unavailable")

    def test_discovery_allows_executable_symlink_that_resolves_inside_trusted_root(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real-playwright"
            real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            real.chmod(real.stat().st_mode | 0o111)
            link = root / "playwright"
            link.symlink_to(real.name)

            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))
            status = {item["provider_id"]: item for item in catalog.status()["providers"]}

            self.assertEqual(status["playwright-cli"]["status"], "available")
            self.assertEqual(status["playwright-cli"]["executable"], str(link))

    def test_discovery_rejects_symlink_that_escapes_trusted_root(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "bin"
            root.mkdir()
            outside = parent / "outside-playwright"
            outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            outside.chmod(outside.stat().st_mode | 0o111)
            (root / "playwright").symlink_to(outside)

            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))
            status = {item["provider_id"]: item for item in catalog.status()["providers"]}

            self.assertEqual(status["playwright-cli"]["status"], "unavailable")

    def test_discovery_allows_uv_tool_symlink_within_user_local_tree(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            root = home / ".local" / "bin"
            root.mkdir(parents=True)
            real = home / ".local" / "share" / "uv" / "tools" / "serena-agent" / "bin" / "serena"
            real.parent.mkdir(parents=True)
            real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            real.chmod(real.stat().st_mode | 0o111)
            link = root / "serena"
            link.symlink_to(real)

            with mock.patch("chatgpt_dev_mcp.capability_adapters.Path.home", return_value=home):
                catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))
                status = {item["provider_id"]: item for item in catalog.status()["providers"]}

            self.assertEqual(status["serena"]["status"], "available")
            self.assertEqual(status["serena"]["executable"], str(link))

    def test_stdio_provider_factory_uses_only_fixed_catalog_mapping(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog
        from chatgpt_dev_mcp.capability_gateway import StdioMCPProvider

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "context7-mcp"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(executable, executable.stat().st_mode | 0o111)
            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))

            provider = catalog.build_provider("context7")
            self.assertIsInstance(provider, StdioMCPProvider)
            self.assertIsNone(catalog.build_provider("github-gh"))

    def test_stdio_provider_factory_can_use_fixed_launcher_without_starting_process(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog
        from chatgpt_dev_mcp.capability_gateway import StdioMCPProvider

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npx = root / "npx"
            npx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            npx.chmod(npx.stat().st_mode | 0o111)
            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))

            provider = catalog.build_provider("context7")

            self.assertIsInstance(provider, StdioMCPProvider)
            self.assertEqual(provider.status()["status"], "available")

    def test_status_reports_safe_launcher_provisioning_without_launching_or_network(self) -> None:
        from chatgpt_dev_mcp.capability_adapters import CapabilityAdapterCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npx = root / "npx"
            npx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            npx.chmod(npx.stat().st_mode | 0o111)
            uvx = root / "uvx"
            uvx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            uvx.chmod(uvx.stat().st_mode | 0o111)

            catalog = CapabilityAdapterCatalog(resolver=lambda _name: None, search_roots=(root,))
            status = {item["provider_id"]: item for item in catalog.status()["providers"]}

            playwright = status["playwright-mcp"]
            self.assertEqual(playwright["status"], "unavailable")
            self.assertEqual(playwright["launcher_status"], "available")
            self.assertEqual(playwright["launcher_executable"], str(npx))
            self.assertEqual(playwright["launcher_package"], "@playwright/mcp@latest")
            self.assertTrue(playwright["provisioning_required"])
            self.assertTrue(playwright["provisioning_network_required"])

            serena = status["serena"]
            self.assertEqual(serena["launcher_status"], "available")
            self.assertEqual(serena["launcher_executable"], str(uvx))
            self.assertEqual(serena["launcher_package"], "serena-agent")

            self.assertFalse(catalog.status()["process_started"])
            self.assertFalse(catalog.status()["network_used"])


if __name__ == "__main__": unittest.main()
