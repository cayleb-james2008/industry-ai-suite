"""Exercise the local workbench's user-input and same-origin boundaries."""

import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from scripts.export_public_lab import _receipt
from webapp.runner import run
from webapp.server import WorkbenchServer


class WorkbenchInputTests(unittest.TestCase):
    def test_public_ai_label_requires_matching_grounded_witness_record(self):
        source = {
            "app_slug": "marketbrief", "task_result": {"record_count": 1},
            "ai_output": "A bounded observation [evidence:record-1].",
            "ai_evidence": {
                "grounded": True, "provider_id": "call-1",
                "provider_request_sha256": "a" * 64,
                "provider_response_sha256": "b" * 64,
            },
        }
        proof = {
            "model": "local", "provider_id": "call-1",
            "request_sha256": "a" * 64, "response_sha256": "b" * 64,
            "cited_output": source["ai_output"], "evidence_ids": ["record-1"],
            "review_note": "Source checked.",
        }
        public = _receipt("marketbrief", source, "2026-09-26T00:00:00Z", proof)
        self.assertEqual(public["ai_status"], "WITNESSED LOCAL MODEL / CITED OUTPUT")
        with self.assertRaisesRegex(ValueError, "does not match"):
            _receipt("marketbrief", source, "2026-09-26T00:00:00Z", proof | {"response_sha256": "c" * 64})

    def test_chainwatch_user_input_requires_authorization(self):
        row = {
            "event_id": "E-1", "chain": "ethereum",
            "address": "0x" + "a" * 40,
            "rate_units_per_hour": 8, "baseline_units_per_hour": 2,
            "sample_hours": 12, "owner": "my-watch",
        }
        with self.assertRaisesRegex(ValueError, "authorized"):
            run("chainwatch", {"mode": "user", "rows": [row]})
        result = run("chainwatch", {"mode": "user", "authorized": True, "rows": [row]})
        self.assertEqual(result["task_result"]["alerts"][0]["event_id"], "E-1")
        self.assertEqual(result["side_effect_count"], 0)
        self.assertFalse(result["ai_invoked"])

    def test_ledgerbridge_reconciles_supplied_rows_without_calling_live_source(self):
        rows = [
            {"row_id": "L1", "reference": "R1", "side": "ledger", "amount_cents": 2500, "owner": "me"},
            {"row_id": "B1", "reference": "R1", "side": "bank", "amount_cents": 2400, "owner": "me"},
        ]
        result = run("ledgerbridge", {"mode": "user", "rows": rows})
        self.assertEqual(result["task_result"]["owner_queue"][0]["variance_cents"], -100)
        self.assertEqual(result["task_result"]["accounted_row_count"], 2)
        self.assertEqual(result["source_status"], "USER_SUPPLIED / OWNERSHIP UNVERIFIED")


class WorkbenchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = WorkbenchServer(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_cross_origin_and_missing_token_are_denied(self):
        for origin, token in [("https://example.com", self.server.token), (self.base, "wrong")]:
            request = Request(
                self.base + "/api/run/chainwatch", data=b"{}", method="POST",
                headers={"Origin": origin, "Content-Type": "application/json", "X-Workbench-Token": token},
            )
            with self.assertRaises(HTTPError) as caught:
                urlopen(request, timeout=3)
            self.assertEqual(caught.exception.code, 403)

    def test_authorized_request_runs_without_chain_network(self):
        request = Request(
            self.base + "/api/run/chainwatch", data=json.dumps({"mode": "public"}).encode(), method="POST",
            headers={"Origin": self.base, "Content-Type": "application/json", "X-Workbench-Token": self.server.token},
        )
        with urlopen(request, timeout=3) as response:
            value = json.load(response)
        self.assertEqual(value["status"], "UNVERIFIED")
        self.assertIsNone(value["task_result"])


if __name__ == "__main__":
    unittest.main()
