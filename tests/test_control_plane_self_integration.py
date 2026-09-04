from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.control_plane import CONTROL_PLANE_CONTRACT_REVISION, REQUIRED_CAPABILITIES, AdapterBinding, ControlPlaneAdapter, ControlPlaneRelease, ControlPlaneRuntime
from chatgpt_dev_mcp.control_plane.cli import LocalCLIAdapter


def test_self_integration_does_not_replace_running_control_plane_release() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root=Path(raw); install=root/"control-plane-releases"/"release-n"; dev=root/"developer"/"chatgpt-dev-mcp"; install.mkdir(parents=True); dev.mkdir(parents=True)
        (install/"release-id.txt").write_text("control-plane-release:n\n")
        server=dev/"src"/"chatgpt_dev_mcp"/"server.py"; registry=dev/"src"/"chatgpt_dev_mcp"/"stable_surface.py"; server.parent.mkdir(parents=True); server.write_text("before\n"); registry.write_text("before\n")
        def handler(cap): return lambda params: {"capability_id":cap,"release_id":"control-plane-release:n"}
        runtime=ControlPlaneRuntime(ControlPlaneRelease("control-plane-release:n",CONTROL_PLANE_CONTRACT_REVISION,install,dev),{cap:handler(cap) for cap in REQUIRED_CAPABILITIES})
        v25a=ControlPlaneAdapter(runtime,AdapterBinding("v25:a",{"preflight":"control.integration.preflight"},"tool-registry-v25-stable")); v26a=ControlPlaneAdapter(runtime,AdapterBinding("v26:a",{"doctor":"control.doctor"},"tool-registry-v26-canary")); cli=LocalCLIAdapter(runtime)
        assert v25a.call("preflight",{})["release_id"]=="control-plane-release:n"; assert v26a.call("doctor",{})["release_id"]=="control-plane-release:n"
        server.write_text("after\n"); registry.write_text("after\n")
        v25b=ControlPlaneAdapter(runtime,AdapterBinding("v25:b",{"apply":"control.integration.apply"},"tool-registry-v25-stable")); v26b=ControlPlaneAdapter(runtime,AdapterBinding("v26:b",{"doctor":"control.doctor"},"tool-registry-v26-canary"))
        assert v25b.call("apply",{})["release_id"]=="control-plane-release:n"; assert v26b.call("doctor",{})["release_id"]=="control-plane-release:n"; assert cli.call("session status",{})["release_id"]=="control-plane-release:n"
        assert runtime.diagnostics()["install_root"]==str(install.resolve())
        assert (install/"release-id.txt").read_text()=="control-plane-release:n\n"


def load_tests(loader, tests, pattern):
    del loader, tests, pattern
    return unittest.TestSuite([unittest.FunctionTestCase(test_self_integration_does_not_replace_running_control_plane_release)])
