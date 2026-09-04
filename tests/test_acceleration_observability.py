from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class AccelerationObservabilityTests(unittest.TestCase):
    def test_observer_accepts_bounded_performance_metadata(self) -> None:
        from chatgpt_dev_mcp.observability import AccelerationObserver

        observer = AccelerationObserver()
        receipt = observer.record(
            "performance",
            subject_id="context.bootstrap",
            reason="runtime_metric",
            metadata={
                "duration_ms": 12.5,
                "output_bytes": 128,
                "cache_status": "hit",
                "success": True,
                "failure_fingerprint": "",
            },
        )

        self.assertEqual(receipt["kind"], "performance")
        self.assertEqual(receipt["metadata"]["duration_ms"], 12.5)
        self.assertFalse(receipt["external_execution"])

    def test_receipt_is_bounded_persisted_and_counted_without_raw_content(self) -> None:
        from chatgpt_dev_mcp.observability import AccelerationObserver
        from chatgpt_dev_mcp.persistence import SqliteDirectorStore
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteDirectorStore(Path(tmp) / "director.sqlite3")
            observer = AccelerationObserver(store=store, clock=lambda: "2026-08-14T00:00:00Z")
            receipt = observer.record("qa", subject_id="task-one", reason="browser checks", evidence_hashes=("f" * 64,), refs=("artifact:screen",), metadata={"status": "passed"})
            self.assertEqual(receipt["kind"], "qa")
            self.assertEqual(observer.status()["counters"]["qa"], 1)
            self.assertEqual(store.load_acceleration_receipts(kind="qa")[0]["receipt_id"], receipt["receipt_id"])
            with self.assertRaises(ValueError):
                observer.record("qa", subject_id="task-two", reason="bad", metadata={"source_text": "not allowed"})


if __name__ == "__main__": unittest.main()
