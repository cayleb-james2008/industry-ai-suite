"""Cross-app receipt, failure-state, tenant-denial, and side-effect checks."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apps._ai_receipts import (
    MODEL_MAX_TOKENS,
    MODEL_TIMEOUT_SECONDS,
    build_grounded_prompt,
)
from suite_core import AccessDenied

from apps.handoffhub.flow import ACTION, DOC_EVIDENCE, _security_stack
from scripts.run_all import (
    APP_SLUGS,
    _normalize_receipt,
    _probe_model,
    main,
    run_suite,
)


def _fabricated_local_receipt() -> dict[str, object]:
    """ADVERSARIAL REGRESSION ONLY: deliberately fabricated self-asserted AI data."""
    response = "A fabricated local claim [evidence:E-1]."
    return {
        "ai_status": "AI / LOCAL",
        "ai_invoked": True,
        "ai_evidence": {
            "route": "http://127.0.0.1:52652/v1",
            "model": "invented-model",
            "request_sha256": "a" * 64,
            "response_sha256": hashlib.sha256(response.encode()).hexdigest(),
            "response": response,
            "evidence_ids": ["E-1"],
            "grounded": True,
            "lead_observation": True,
        },
        "result": {"task": "fixture"},
        "evidence": ["E-1"],
        "source_hash": "b" * 64,
        "risk": {"level": "unknown"},
        "handoff": {"owner": "human"},
        "adapter": "fabricated local receipt",
        "side_effect_count": 0,
    }


class SuiteIntegrationTests(unittest.TestCase):
    def test_live_prompt_names_allowlist_and_requires_short_cited_final_answer(self) -> None:
        prompt = build_grounded_prompt("App-specific task context", ("E-1", "E-2"))
        self.assertIn("App-specific task context", prompt)
        self.assertIn("Allowed evidence IDs: E-1, E-2", prompt)
        self.assertIn("one short sentence", prompt)
        self.assertIn("exact [evidence:ID]", prompt)
        self.assertIn("[evidence:ID]", prompt)
        self.assertEqual(MODEL_TIMEOUT_SECONDS, 150)
        self.assertEqual(MODEL_MAX_TOKENS, 256)

    def test_adversarial_worker_shapes_normalize_without_inventing_ai_evidence(self) -> None:
        """Synthetic fixture-shaped values are confined to this normalization regression."""
        one_hash = "a" * 64
        two_hash = "b" * 64
        p2 = _normalize_receipt({
            "task_result": {"rows": 1}, "evidence_ids": ["LB-A-001"],
            "source_hashes": {"tenant-alpha/ledger.json": one_hash},
            "risk": "review required", "human_handoff": {"owner": "finance"},
            "integration_adapter": "FixtureAdapter", "ai_evidence": None,
        })
        self.assertEqual(p2["result"], {"rows": 1})
        self.assertEqual(p2["evidence"], ["LB-A-001"])
        self.assertEqual(p2["source_hash"], one_hash)
        self.assertEqual(p2["handoff"], {"owner": "finance"})
        self.assertEqual(p2["adapter"], "FixtureAdapter")
        self.assertIsNone(p2["ai_evidence"])

        p3 = _normalize_receipt({
            "task_result": {"answer": "synthetic"},
            "evidence": [{"id": "HR-001", "sha256": one_hash}, {"id": "HR-002", "sha256": two_hash}],
            "source_hashes": {"policy.csv": one_hash, "request.json": two_hash},
            "risk": ["human review"], "handoff": {"owner": "HR"},
            "integration_adapter": {"type": "FixtureAdapter"},
        })
        self.assertEqual(p3["result"], {"answer": "synthetic"})
        self.assertEqual(_evidence_ids_for_test(p3["evidence"]), {"HR-001", "HR-002"})
        self.assertEqual(p3["source_hash"], hashlib.sha256(
            json.dumps({"policy.csv": one_hash, "request.json": two_hash}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())
        self.assertEqual(p3["adapter"], {"type": "FixtureAdapter"})

        p4 = _normalize_receipt({
            "result": {"alerts": 1}, "evidence": [{"evidence_id": "SD-A-001"}],
            "source_hash": one_hash, "risk": {"level": "high"},
            "handoff": {"owner": "security"}, "adapter": "local fixture",
        })
        self.assertEqual(p4["result"], {"alerts": 1})
        self.assertEqual(p4["source_hash"], one_hash)
        self.assertIsNone(p4.get("ai_evidence"))

    def test_adversarial_fabricated_receipt_and_copied_metadata_cannot_certify(self) -> None:
        """Test-only fabricated receipt data must never pass the production live runner."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation_path = root / "lead-observations.json"
            output_path = root / "receipts"
            fabricated = _fabricated_local_receipt()
            proof = fabricated["ai_evidence"]
            copied_observation = {
                key: proof[key]
                for key in ("route", "model", "request_sha256", "response_sha256")
            }
            observation_path.write_text(
                json.dumps({slug: copied_observation for slug in APP_SLUGS}), encoding="utf-8",
            )

            # The unsupported sidecar option fails before any receipt is written.
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as rejected:
                    main([
                        "--out-dir", str(output_path), "--lead-observations", str(observation_path),
                    ])
            self.assertEqual(rejected.exception.code, 2)
            self.assertFalse(output_path.exists())

            # Even the complete self-consistent receipt and copied metadata have no admission path.
            fake_flow = SimpleNamespace(
                run_live=lambda ai_client=None: fabricated,
                run_demo=lambda ai_client=None: self.fail("production runner called run_demo"),
            )
            with patch("scripts.run_all.importlib.import_module", return_value=fake_flow):
                with redirect_stdout(io.StringIO()) as output:
                    exit_code, _, receipts = run_suite(output_path)

            self.assertEqual(exit_code, 1)
            self.assertEqual(len(receipts), 10)
            self.assertTrue(all(receipt["status"] == "UNVERIFIED" for receipt in receipts))
            self.assertTrue(all(receipt["ai_status"] == "AI / LOCAL" for receipt in receipts))
            self.assertTrue(all(receipt["ai_verification_status"] == "AI CANDIDATE" for receipt in receipts))
            self.assertTrue(all(receipt["ai_evidence"]["lead_observation"] is True for receipt in receipts))
            saved = [json.loads(path.read_text(encoding="utf-8")) for path in output_path.glob("*.json")]
            self.assertEqual(len(saved), 10)
            self.assertTrue(all(receipt["status"] == "UNVERIFIED" for receipt in saved))
            self.assertTrue(all(receipt["ai_status"] == "AI / LOCAL" for receipt in saved))
            self.assertTrue(all(receipt["ai_verification_status"] == "AI CANDIDATE" for receipt in saved))
            self.assertNotIn("VERIFIED AI", output.getvalue())
            self.assertFalse(any(line.startswith("COMPLETE:") for line in output.getvalue().splitlines()))

    def test_adversarial_available_model_route_is_only_candidate_without_observer(self) -> None:
        fake_flow = SimpleNamespace(
            run_live=lambda ai_client=None: _fabricated_local_receipt(),
            run_demo=lambda ai_client=None: self.fail("production runner called run_demo"),
        )
        available_route = object()
        route_probe = {"available": True, "reason": "test double only", "route": "http://127.0.0.1:52652/v1"}
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("scripts.run_all._probe_model", return_value=(available_route, route_probe)),
                patch("scripts.run_all.importlib.import_module", return_value=fake_flow),
                redirect_stdout(io.StringIO()),
            ):
                exit_code, _, receipts = run_suite(Path(directory), "http://127.0.0.1:52652/v1")

        self.assertEqual(exit_code, 1)
        self.assertEqual(len(receipts), 10)
        self.assertTrue(all(receipt["status"] == "UNVERIFIED" for receipt in receipts))
        self.assertTrue(all(receipt["ai_verification_status"] == "AI CANDIDATE" for receipt in receipts))
        self.assertTrue(all("cannot verify model execution" in receipt["ai_verification_basis"] for receipt in receipts))

    def test_default_runner_calls_only_run_live_and_keeps_ten_receipts_incomplete(self) -> None:
        """No-argument CLI dispatch uses only live flows, never demos or fixture fallback."""
        live_calls: list[str] = []
        demo_calls: list[str] = []

        def import_live_module(name: str) -> SimpleNamespace:
            slug = name.split(".")[1]

            def run_live(ai_client: object | None = None) -> dict[str, object]:
                live_calls.append(slug)
                return {
                    "status": "VERIFIED_SOURCE",
                    "source_status": "VERIFIED_SOURCE",
                    "data_status": "AVAILABLE",
                    "workflow_status": "UNVERIFIED — test job has no independent AI observer",
                    "task_result": {"decision": "review public record"},
                    "source": {
                        "provider": "test-provider",
                        "request_url": "https://example.invalid/read-only",
                        "source_id": f"record-{slug}",
                        "as_of": "2026-09-22",
                        "retrieved_at_utc": "2026-09-23T00:00:00Z",
                        "terms_url": "https://example.invalid/terms",
                    },
                    "evidence": [f"record-{slug}"],
                    "human_handoff": {"owner": "test reviewer", "next_action": "Review this test-only record."},
                    "ai_status": "AI / LOCAL",
                    "ai_invoked": True,
                    "ai_evidence": {"self_asserted": True},
                    "side_effect_count": 0,
                }

            def run_demo(ai_client: object | None = None) -> dict[str, object]:
                demo_calls.append(slug)
                return {"task_result": {"fixture": True}}

            return SimpleNamespace(run_live=run_live, run_demo=run_demo)

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("scripts.run_all.tempfile.mkdtemp", return_value=directory),
                patch("scripts.run_all.importlib.import_module", side_effect=import_live_module),
                redirect_stdout(io.StringIO()),
            ):
                code = main([])

            self.assertEqual(code, 1)
            self.assertEqual(live_calls, list(APP_SLUGS))
            self.assertEqual(demo_calls, [])
            destination = Path(directory)
            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in destination.glob("*.json")
            ]
            self.assertEqual(len(receipts), 10)
            self.assertEqual({receipt["app_slug"] for receipt in receipts}, set(APP_SLUGS))
            self.assertEqual(len(list(destination.glob("*.json"))), 10)
            for receipt in receipts:
                with self.subTest(app=receipt["app_slug"]):
                    self.assertEqual(receipt["source_status"], "VERIFIED_SOURCE")
                    self.assertEqual(receipt["status"], "UNVERIFIED")
                    self.assertEqual(receipt["workflow_status"], "UNVERIFIED")
                    self.assertEqual(receipt["ai_verification_status"], "AI CANDIDATE")
                    self.assertEqual(receipt["source"]["source_id"], f"record-{receipt['app_slug']}")
                    self.assertEqual(receipt["side_effect_count"], 0)
                    self.assertEqual(receipt["result"], {"decision": "review public record"})
                    self.assertEqual(receipt["handoff"]["owner"], "test reviewer")
                    self.assertNotIn(receipt["status"], {"VERIFIED", "COMPLETE", "VERIFIED AI"})

    def test_plain_english_and_json_suite_summaries_agree_on_incomplete_jobs(self) -> None:
        fake_flow = SimpleNamespace(
            run_live=lambda ai_client=None: {
                "status": "UNVERIFIED",
                "reason": "Independent AI evidence is absent.",
                "side_effect_count": 0,
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("scripts.run_all.importlib.import_module", return_value=fake_flow),
                redirect_stdout(io.StringIO()) as output,
            ):
                code, _, receipts = run_suite(Path(directory))

        lines = output.getvalue().splitlines()
        json_record = next(line for line in lines if line.startswith("JSON summary: "))
        summary = json.loads(json_record.removeprefix("JSON summary: "))
        self.assertEqual(code, 1)
        self.assertIn("Suite status: INCOMPLETE", lines[0])
        self.assertEqual(summary["suite_status"], "INCOMPLETE")
        self.assertEqual(summary["job_count"], 10)
        self.assertEqual(summary["job_status_counts"], {
            "UNVERIFIED": 10,
            "DATA_UNAVAILABLE": 0,
            "MISSING": 0,
        })
        self.assertEqual(summary["job_statuses"], [
            {"app_slug": receipt["app_slug"], "status": receipt["status"]}
            for receipt in receipts
        ])
        self.assertEqual(summary["ai_candidates_pending_independent_verification"], 0)
        self.assertEqual(
            lines[1],
            "Workflow job statuses: UNVERIFIED=10, DATA_UNAVAILABLE=0, MISSING=0",
        )
        self.assertNotIn("INCOMPLETE=0", output.getvalue())
        self.assertTrue(all(receipt["status"] == "UNVERIFIED" for receipt in receipts))

    def test_adversarial_live_source_failures_never_emit_demo_records(self) -> None:
        """403/429/timeouts stay empty and fail closed; fake demos are never selected."""
        failures = (
            ("DATA_UNAVAILABLE", "HTTP 403: provider denied this read-only request"),
            ("DATA_UNAVAILABLE", "HTTP 429: provider rate limit"),
            ("DATA_UNAVAILABLE", "TimeoutError: public source request timed out"),
        )
        demo_calls: list[str] = []

        class _SourceUnavailable(Exception):
            def __init__(self, status: str, reason: str) -> None:
                self.status = status
                super().__init__(reason)

        def import_failure_module(name: str) -> SimpleNamespace:
            index = APP_SLUGS.index(name.split(".")[1])
            if index < len(failures):
                status, reason = failures[index]
            else:
                status, reason = "UNVERIFIED", "No authorized private workflow source is configured."

            def run_live(ai_client: object | None = None) -> dict[str, object]:
                if index < len(failures):
                    status, reason = failures[index]
                    if index == 2:
                        raise TimeoutError("public source request timed out")
                    raise _SourceUnavailable(status, reason)
                return {
                    "status": status,
                    "reason": reason,
                    "task_result": None,
                    "evidence": [],
                    "side_effect_count": 0,
                }

            def run_demo(ai_client: object | None = None) -> dict[str, object]:
                demo_calls.append(name)
                return {"task_result": {"fixture": "must not appear"}, "evidence": ["fixture-id"]}

            return SimpleNamespace(run_live=run_live, run_demo=run_demo)

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("scripts.run_all.importlib.import_module", side_effect=import_failure_module),
                redirect_stdout(io.StringIO()),
            ):
                code, destination, receipts = run_suite(Path(directory))

            self.assertEqual(code, 1)
            self.assertEqual(len(receipts), 10)
            self.assertEqual(demo_calls, [])
            for index, (status, reason) in enumerate(failures):
                receipt = receipts[index]
                self.assertEqual(receipt["status"], status)
                self.assertIn(reason.split(": ", 1)[-1], receipt["reason"])
                self.assertIsNone(receipt["result"])
                self.assertEqual(receipt["evidence"], [])
                self.assertEqual(receipt["side_effect_count"], 0)
                saved = json.loads((destination / f"{receipt['app_slug']}.json").read_text(encoding="utf-8"))
                self.assertIsNone(saved["result"])
                self.assertEqual(saved["evidence"], [])

    def test_non_loopback_model_url_is_refused_without_a_probe(self) -> None:
        client, probe = _probe_model("https://example.com/v1")
        self.assertIsNone(client)
        self.assertFalse(probe["available"])
        self.assertIn("route refused", str(probe["reason"]))

    def test_cross_tenant_request_is_denied_without_protected_output(self) -> None:
        with tempfile.TemporaryDirectory() as runtime:
            auth, core, actor, audit = _security_stack(Path(runtime))
            token = auth.issue(actor, expires_at=int(time.time()) + 60)
            with self.assertRaises(AccessDenied) as denied:
                core.authorize(
                    token, tenant_id="tenant-beta", action=ACTION,
                    evidence_ids=("handoff-guide-b06",),
                )
            self.assertEqual(str(denied.exception), "request denied")
            audit_text = json.dumps(audit.records(), sort_keys=True)
            self.assertNotIn("restricted-personnel-206", audit_text)
            self.assertNotIn("TENANT_B_HANDOFF_CANARY_7B20", audit_text)

    def test_explicit_adversarial_fixture_harness_keeps_demo_checks_in_tests_only(self) -> None:
        """Regression harness calls run_demo directly; the production runner is never involved."""
        for slug in APP_SLUGS:
            with self.subTest(app=slug):
                flow = importlib.import_module(f"apps.{slug}.flow")
                receipt = _normalize_receipt(flow.run_demo())
                self.assertEqual(receipt["ai_status"], "NON-AI / DETERMINISTIC FALLBACK")
                self.assertFalse(receipt["ai_invoked"])
                self.assertEqual(receipt["side_effect_count"], 0)
                self.assertTrue(receipt["result"])
                self.assertTrue(receipt["evidence"])
                self.assertTrue(receipt["source_hash"])
                self.assertTrue(receipt["handoff"])
                self.assertTrue(receipt["adapter"])


def _evidence_ids_for_test(evidence: list[object]) -> set[str]:
    return {item["id"] for item in evidence if isinstance(item, dict) and isinstance(item.get("id"), str)}


if __name__ == "__main__":
    unittest.main()
