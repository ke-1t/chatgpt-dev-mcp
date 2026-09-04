from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from chatgpt_dev_mcp.control_plane import (
    CONTROL_PLANE_CONTRACT_REVISION,
    REQUIRED_CAPABILITIES,
    AdapterBinding,
    ControlPlaneAdapter,
    ControlPlaneError,
    ControlPlaneRelease,
    ControlPlaneRuntime,
)
from chatgpt_dev_mcp.control_plane.cli import LocalCLIAdapter


EXPECTED_CAPABILITIES = (
    "control.session.status",
    "control.integration.preflight",
    "control.integration.apply",
    "control.integration.resume",
    "control.git.stage_paths",
    "control.git.commit_preflight",
    "control.doctor",
)


def _runtime(root: Path) -> ControlPlaneRuntime:
    install_root = root / "releases" / "release-n"
    development_root = root / "workspaces" / "chatgpt-dev-mcp"
    install_root.mkdir(parents=True)
    development_root.mkdir(parents=True)
    calls: list[tuple[str, dict[str, object]]] = []

    def handler(capability_id: str):
        def invoke(params: dict[str, object]) -> dict[str, object]:
            calls.append((capability_id, dict(params)))
            return {"capability_id": capability_id, "params": dict(params)}
        return invoke

    runtime = ControlPlaneRuntime(
        ControlPlaneRelease("control-plane-release:n", CONTROL_PLANE_CONTRACT_REVISION, install_root, development_root),
        {capability_id: handler(capability_id) for capability_id in REQUIRED_CAPABILITIES},
    )
    runtime._test_calls = calls  # type: ignore[attr-defined]
    return runtime


def test_common_capability_contract_is_frozen_and_public_registry_agnostic() -> None:
    assert CONTROL_PLANE_CONTRACT_REVISION == "control-plane-capabilities-v1"
    assert REQUIRED_CAPABILITIES == EXPECTED_CAPABILITIES
    assert all("v25" not in item and "v26" not in item for item in REQUIRED_CAPABILITIES)


def test_v25_and_v26_bindings_dispatch_to_the_same_common_capability() -> None:
    with tempfile.TemporaryDirectory() as raw:
        runtime = _runtime(Path(raw))
        v25 = ControlPlaneAdapter(runtime, AdapterBinding("v25-stable", {"workspace_status": "control.session.status"}, "tool-registry-v25-stable"))
        v26 = ControlPlaneAdapter(runtime, AdapterBinding("v26-canary", {"workspace_status": "control.session.status"}, "tool-registry-v26-canary"))
        assert v25.call("workspace_status", {"workspace_id": "chatgpt-dev-mcp"})["capability_id"] == "control.session.status"
        assert v26.call("workspace_status", {"workspace_id": "chatgpt-dev-mcp"})["capability_id"] == "control.session.status"
        assert v25.diagnostics()["control_plane_release_id"] == v26.diagnostics()["control_plane_release_id"]


def test_public_schema_revision_is_diagnostic_metadata_not_dispatch_input() -> None:
    with tempfile.TemporaryDirectory() as raw:
        runtime = _runtime(Path(raw))
        a = ControlPlaneAdapter(runtime, AdapterBinding("a", {"doctor": "control.doctor"}, "public-a"))
        b = ControlPlaneAdapter(runtime, AdapterBinding("b", {"doctor": "control.doctor"}, "public-b"))
        assert a.call("doctor", {})["capability_id"] == "control.doctor"
        assert b.call("doctor", {})["capability_id"] == "control.doctor"
        assert runtime.diagnostics()["release_id"] == "control-plane-release:n"


def test_adapter_binding_and_call_fail_closed() -> None:
    with unittest.TestCase().assertRaises(ControlPlaneError) as error:
        AdapterBinding("bad", {"danger": "control.internal.not_registered"})
    assert error.exception.code == "CONTROL_PLANE_ADAPTER_CAPABILITY_UNKNOWN"
    with tempfile.TemporaryDirectory() as raw:
        runtime = _runtime(Path(raw))
        adapter = ControlPlaneAdapter(runtime, AdapterBinding("v25", {"status": "control.session.status"}))
        with unittest.TestCase().assertRaises(ControlPlaneError) as error:
            adapter.call("arbitrary_git", {})
        assert error.exception.code == "CONTROL_PLANE_ADAPTER_OPERATION_UNKNOWN"


def test_local_cli_uses_fixed_common_capability_mappings_only() -> None:
    expected = {
        "session status": "control.session.status",
        "integration preflight": "control.integration.preflight",
        "integration apply": "control.integration.apply",
        "integration resume": "control.integration.resume",
        "git stage-paths": "control.git.stage_paths",
        "git commit-preflight": "control.git.commit_preflight",
        "doctor": "control.doctor",
    }
    with tempfile.TemporaryDirectory() as raw:
        cli = LocalCLIAdapter(_runtime(Path(raw)))
        for command, capability_id in expected.items():
            assert cli.call(command, {})["capability_id"] == capability_id
        with unittest.TestCase().assertRaises(ControlPlaneError) as error:
            cli.call("git raw", {"argv": ["reset", "--hard"]})
        assert error.exception.code == "CONTROL_PLANE_CLI_COMMAND_UNKNOWN"


def load_tests(loader, tests, pattern):
    del loader, tests, pattern
    return unittest.TestSuite(unittest.FunctionTestCase(value) for value in (
        test_common_capability_contract_is_frozen_and_public_registry_agnostic,
        test_v25_and_v26_bindings_dispatch_to_the_same_common_capability,
        test_public_schema_revision_is_diagnostic_metadata_not_dispatch_input,
        test_adapter_binding_and_call_fail_closed,
        test_local_cli_uses_fixed_common_capability_mappings_only,
    ))
