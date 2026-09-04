from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.control_plane import CONTROL_PLANE_CONTRACT_REVISION, REQUIRED_CAPABILITIES, ControlPlaneError, ControlPlaneRelease, ControlPlaneRuntime


def _handlers():
    return {cap: (lambda params, _cap=cap: {"capability_id": _cap}) for cap in REQUIRED_CAPABILITIES}


def test_release_accepts_disjoint_install_and_development_roots() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); install = root / "installed"; dev = root / "development"; install.mkdir(); dev.mkdir()
        release = ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install, dev)
        assert release.install_root == install.resolve(); assert release.development_root == dev.resolve()


def test_release_rejects_overlapping_roots() -> None:
    for layout in ("same", "install-parent", "development-parent"):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if layout == "same": install = dev = root / "shared"
            elif layout == "install-parent": install = root / "shared"; dev = install / "checkout"
            else: dev = root / "shared"; install = dev / "release"
            install.mkdir(parents=True, exist_ok=True); dev.mkdir(parents=True, exist_ok=True)
            with unittest.TestCase().assertRaises(ControlPlaneError) as error:
                ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install, dev)
            assert error.exception.code == "CONTROL_PLANE_ROOTS_OVERLAP"


def test_runtime_requires_handlers_and_rejects_unknown_capability() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); install = root / "i"; dev = root / "d"; install.mkdir(); dev.mkdir()
        handlers = _handlers(); handlers.pop("control.integration.resume")
        with unittest.TestCase().assertRaises(ControlPlaneError) as error:
            ControlPlaneRuntime(ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install, dev), handlers)
        assert error.exception.code == "CONTROL_PLANE_HANDLER_MISSING"
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); install = root / "i"; dev = root / "d"; install.mkdir(); dev.mkdir()
        runtime = ControlPlaneRuntime(ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install, dev), _handlers())
        with unittest.TestCase().assertRaises(ControlPlaneError) as error:
            runtime.call("control.hidden.shell", {})
        assert error.exception.code == "CONTROL_PLANE_CAPABILITY_UNKNOWN"


def test_runtime_diagnostics_are_public_registry_independent() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw); install = root / "i"; dev = root / "d"; install.mkdir(); dev.mkdir()
        runtime = ControlPlaneRuntime(ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install, dev), _handlers())
        diagnostics = runtime.diagnostics()
        assert diagnostics["capabilities"] == list(REQUIRED_CAPABILITIES)
        assert "public_schema_revision" not in diagnostics


def load_tests(loader, tests, pattern):
    del loader, tests, pattern
    return unittest.TestSuite(unittest.FunctionTestCase(value) for value in (
        test_release_accepts_disjoint_install_and_development_roots,
        test_release_rejects_overlapping_roots,
        test_runtime_requires_handlers_and_rejects_unknown_capability,
        test_runtime_diagnostics_are_public_registry_independent,
    ))
