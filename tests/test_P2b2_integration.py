"""P2b2 checks using recorded real-source projections and labeled adversarial stubs."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from apps.onboardpath.flow import run_live as run_onboardpath
from apps.pipelinerelay.flow import run_live as run_pipelinerelay
from suite_core import DataUnavailable, Provider, SourceRecord, SourceResult, TaskFit, UnverifiedSource
import suite_core.live_sources as live_sources
from suite_core.live_sources import fetch_federal_register_opm_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _Transport:
    def __init__(self, body: bytes, content_type: str, *, status: int = 200):
        self.response = live_sources._HTTPResponse(
            status, {"Content-Type": content_type}, body,
        )
        self.calls: list[tuple[str, float, int]] = []

    def get(self, url: str, *, timeout: float, max_bytes: int):
        self.calls.append((url, timeout, max_bytes))
        return self.response


def _opm_record() -> SourceRecord:
    payload = {"results": [{
        "document_number": "2026-19222",
        "publication_date": "2026-09-18",
        "title": "Employment in the Excepted Service",
        "type": "Proposed Rule",
        "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/example",
        "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
    }]}
    body = json.dumps(payload).encode()
    with patch("suite_core.live_sources._retrieved_at", return_value="2026-09-24T10:00:00Z"):
        result = live_sources._fetch_with_transport(
            Provider.FEDERAL_REGISTER_OPM,
            task_fit=TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
            owner=None, repo=None, timeout=2.0,
            transport=_Transport(body, "application/json"),
        )
    return result.records[0]


def _github_source() -> SourceResult:
    fixture = json.loads((
        PROJECT_ROOT / "apps/pipelinerelay/tests/fixtures/recorded_github_repository_2026-09-24.json"
    ).read_text(encoding="utf-8"))
    if fixture.get("fixture_kind") != "recorded_real_source_projection_not_raw_response":
        raise AssertionError("PipelineRelay fixture is not a recorded real-source projection")
    source, raw = fixture["source"], fixture["record"]
    record = SourceRecord(
        provider=source["provider"], source_id=raw["source_id"],
        source_url=raw["source_url"], response_status=source["response_status"],
        response_sha256=source["response_sha256"], request_body_sha256=None,
        as_of=raw["as_of"], as_of_precision=raw["as_of_precision"],
        retrieved_at_utc=source["retrieved_at_utc"], terms_url=source["terms_url"],
        read_only=True, task_fit=source["task_fit"], data=raw["data"],
    )
    return SourceResult(
        provider=source["provider"], status="VERIFIED_SOURCE", request_url=source["request_url"],
        response_status=source["response_status"], response_sha256=source["response_sha256"], request_body_sha256=None,
        retrieved_at_utc=record.retrieved_at_utc, task_fit=record.task_fit,
        records=(record,),
    )


def _recorded_opm_source() -> SourceResult:
    fixture = json.loads((
        PROJECT_ROOT / "apps/onboardpath/tests/fixtures/recorded_federal_register_opm_2026-09-24.json"
    ).read_text(encoding="utf-8"))
    if fixture.get("fixture_kind") != "recorded_real_source_projection_not_raw_response":
        raise AssertionError("OnboardPath fixture is not a recorded real-source projection")
    source, raw = fixture["source"], fixture["record"]
    record = SourceRecord(
        provider=source["provider"], source_id=raw["source_id"],
        source_url=raw["source_url"], response_status=source["response_status"],
        response_sha256=source["response_sha256"], request_body_sha256=None,
        as_of=raw["as_of"], as_of_precision=raw["as_of_precision"],
        retrieved_at_utc=source["retrieved_at_utc"], terms_url=source["terms_url"],
        read_only=True, task_fit=source["task_fit"], data=raw["data"],
    )
    return SourceResult(
        provider=source["provider"], status="VERIFIED_SOURCE", request_url=source["request_url"],
        response_status=source["response_status"], response_sha256=source["response_sha256"],
        request_body_sha256=None, retrieved_at_utc=record.retrieved_at_utc,
        task_fit=record.task_fit, records=(record,),
    )


class P2b2IntegrationTests(unittest.TestCase):
    def test_pipelinerelay_handoff_is_public_research_not_a_sales_account(self):
        with patch("apps.pipelinerelay.flow.fetch_live", return_value=_github_source()):
            result = run_pipelinerelay()
        self.assertEqual(result["task_result"]["status"], "PUBLIC_REPOSITORY_RESEARCH_ONLY")
        self.assertEqual(result["task_result"]["review_checks"][-1]["status"], "UNVERIFIED")
        self.assertIn("UNVERIFIED", result["workflow_status"])
        self.assertEqual(result["ai_status"], "NON-AI / DETERMINISTIC FALLBACK")
        self.assertEqual(result["side_effect_count"], 0)

    def test_onboardpath_recorded_real_metadata_stays_discovery_only_without_safe_title(self):
        with (
            patch("apps.onboardpath.flow.fetch_live", return_value=_recorded_opm_source()),
            patch("apps.onboardpath.flow.fetch_federal_register_opm_text", side_effect=AssertionError("no safe title in the projection")),
        ):
            result = run_onboardpath()
        self.assertEqual(result["source_status"], "VERIFIED_SOURCE")
        self.assertEqual(result["evidence"][0]["source_id"], "2026-19222")
        self.assertEqual(result["task_result"]["status"], "PUBLIC_OPM_METADATA_DISCOVERY_ONLY")
        self.assertEqual(result["ai_verification_status"], "UNVERIFIED — no admitted public rule text")
        self.assertEqual(result["side_effect_count"], 0)

    def test_opm_text_source_is_bounded_to_the_verified_public_document(self):
        metadata = _opm_record()
        html = (
            b"<html><head><title>Federal Register</title></head><body>"
            b"<nav><p>Navigation is not policy text.</p></nav>"
            b"<p>The proposed rule describes a federal employment process for review.</p>"
            b"<p>Contact Jane Doe at jane@example.invalid for a personal case.</p>"
            b"</body></html>"
        )
        transport = _Transport(html, "text/html; charset=utf-8")
        with (
            patch("suite_core.live_sources._UrllibTransport", return_value=transport),
            patch("suite_core.live_sources._retrieved_at", return_value="2026-09-24T10:01:00Z"),
        ):
            text = fetch_federal_register_opm_text(metadata)
        self.assertEqual(transport.calls[0][0], metadata.source_url)
        self.assertEqual(text.source_id, metadata.source_id)
        self.assertEqual(text.as_of, metadata.as_of)
        self.assertEqual(text.task_fit, "public_opm_policy_text")
        self.assertEqual(text.response_sha256, hashlib.sha256(html).hexdigest())
        self.assertEqual(text.data["document_text"], [
            "The proposed rule describes a federal employment process for review."
        ])
        exposed = json.dumps(text.data, sort_keys=True)
        self.assertNotIn("Jane Doe", exposed)
        self.assertNotIn("jane@example.invalid", exposed)
        self.assertNotIn("Navigation", exposed)

    def test_opm_text_refuses_a_mismatched_source_record_before_network_access(self):
        metadata = _opm_record()
        forged = replace(metadata, source_url="https://example.invalid/documents/2026/09/18/2026-19222/example")
        transport = _Transport(b"<html></html>", "text/html")
        with patch("suite_core.live_sources._UrllibTransport", return_value=transport):
            with self.assertRaises(UnverifiedSource):
                fetch_federal_register_opm_text(forged)
        self.assertEqual(transport.calls, [])

    def test_opm_text_redirect_is_rejected_without_following_it(self):
        metadata = _opm_record()
        transport = _Transport(b"", "text/html", status=302)
        with patch("suite_core.live_sources._UrllibTransport", return_value=transport):
            with self.assertRaises(DataUnavailable) as raised:
                fetch_federal_register_opm_text(metadata)
        self.assertIn("HTTP 302", str(raised.exception))
        self.assertEqual(len(transport.calls), 1)


if __name__ == "__main__":
    unittest.main()
