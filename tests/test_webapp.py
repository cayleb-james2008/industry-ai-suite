"""Exercise the local workbench's user-input and same-origin boundaries."""

import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from scripts import run_all
from scripts.export_public_lab import _receipt
from webapp.runner import run
from webapp.server import WorkbenchServer
from suite_core import DataUnavailable


class WorkbenchInputTests(unittest.TestCase):
    def test_configured_model_does_not_break_deterministic_public_paths(self):
        for slug in ("replycraft", "handoffhub"):
            with self.subTest(slug=slug):
                with patch(f"apps.{slug}.flow.run_live", return_value={
                    "status": "UNVERIFIED", "source_status": "VERIFIED_SOURCE",
                    "task_result": {"document_id": "public-sample"},
                    "ai_status": "NOT REQUESTED", "ai_invoked": False,
                }) as live:
                    receipt = run_all._run_one(slug, ai_client=object())
                live.assert_called_once_with(ai_client=None)
                self.assertEqual(receipt["source_status"], "VERIFIED_SOURCE")

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


class WorkbenchSourceFailureHttpTests(unittest.TestCase):
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

    def test_typed_live_source_failure_returns_a_truthful_receipt(self):
        request = Request(
            self.base + "/api/run/ledgerbridge",
            data=json.dumps({"mode": "public"}).encode(), method="POST",
            headers={
                "Origin": self.base,
                "Content-Type": "application/json",
                "X-Workbench-Token": self.server.token,
            },
        )
        with patch("webapp.server.run", side_effect=DataUnavailable("test-only source outage")):
            try:
                with urlopen(request, timeout=3) as response:
                    http_status = response.status
                    receipt = json.load(response)
            except HTTPError as error:
                http_status = error.code
                receipt = json.load(error)
        self.assertEqual(http_status, 200)
        self.assertEqual(receipt["status"], "DATA_UNAVAILABLE")
        self.assertEqual(receipt["source_status"], "DATA_UNAVAILABLE")
        self.assertIsNone(receipt["task_result"])
        self.assertEqual(receipt["evidence"], [])
        self.assertFalse(receipt["ai_invoked"])
        self.assertEqual(receipt["side_effect_count"], 0)
        self.assertEqual(receipt["workbench_status"]["label"], "DATA UNAVAILABLE")
        self.assertIn("No fixture, cache, or substitute was used", receipt["uncertainty"])

    def test_unverified_source_keeps_a_distinct_workbench_label(self):
        request = Request(
            self.base + "/api/run/ledgerbridge",
            data=json.dumps({"mode": "public"}).encode(), method="POST",
            headers={
                "Origin": self.base,
                "Content-Type": "application/json",
                "X-Workbench-Token": self.server.token,
            },
        )
        receipt_value = {
            "status": "UNVERIFIED",
            "source_status": "UNVERIFIED",
            "task_result": None,
            "evidence": [],
            "uncertainty": "Source terms or task fit could not be established.",
            "ai_invoked": False,
            "side_effect_count": 0,
        }
        with patch("webapp.server.run", return_value=receipt_value):
            with urlopen(request, timeout=3) as response:
                receipt = json.load(response)
        self.assertEqual(receipt["workbench_status"]["label"], "SOURCE UNVERIFIED")
        self.assertIn("could not be established", receipt["workbench_status"]["explanation"])
        self.assertNotIn("retry the same source later", receipt["workbench_status"]["explanation"])


if __name__ == "__main__":
    unittest.main()
