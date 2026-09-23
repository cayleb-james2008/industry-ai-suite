"""Integration check that the shared command always emits ten honest receipts."""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUN_ALL = ROOT / "scripts" / "run_all.py"
EXPECTED = {
    "ledgerbridge", "marketbrief", "chainwatch", "backtestguard", "replycraft",
    "handoffhub", "sentineldesk", "searchlift", "pipelinerelay", "onboardpath",
}


class AggregatorTests(unittest.TestCase):
    def test_missing_app_is_named_instead_of_crashing(self) -> None:
        namespace = runpy.run_path(str(RUN_ALL))
        receipt = namespace["_run_one"]("missing_p4_test_app")
        self.assertEqual(receipt["status"], "MISSING")
        self.assertIn("apps.missing_p4_test_app.flow", receipt["error"])

    def test_ten_receipts_are_written_and_partial_suites_are_named_incomplete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="suite-aggregator-test-") as runtime:
            completed = subprocess.run(
                [sys.executable, str(RUN_ALL), "--out-dir", runtime],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            files = sorted(Path(runtime).glob("*.json"))
            self.assertEqual({path.stem for path in files}, EXPECTED)
            receipts = {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in files}
            self.assertEqual(len(receipts), 10)
            self.assertIn(completed.returncode, (0, 1))
            if completed.returncode:
                self.assertIn("INCOMPLETE", completed.stdout)
            else:
                self.assertTrue(all(receipt["status"] == "VERIFIED AI" for receipt in receipts.values()))
            missing = [slug for slug, receipt in receipts.items() if receipt["status"] == "MISSING"]
            for slug in missing:
                self.assertIn(slug, completed.stdout)


if __name__ == "__main__":
    unittest.main()
