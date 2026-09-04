#!/usr/bin/env python3
"""Run the bounded disposable-fixture E2E gates for the v0.41 platform."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


TESTS = (
    "tests.test_platform_e2e.PlatformE2ETests.test_public_dispatch_runtime_uses_session_allocator_and_compensator",
    "tests.test_platform_e2e.PlatformE2ETests.test_wrapper_dispatch_claim_provisions_real_managed_session_and_writer_lease",
    "tests.test_secret_safe_api_e2e.SecretSafeApiE2ETests.test_loopback_api_material_is_not_returned_or_persisted",
)


def main() -> int:
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in TESTS)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
