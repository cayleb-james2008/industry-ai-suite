"""P2b1 integration guards; all source rows here are explicitly synthetic test data."""

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from apps.sentineldesk.flow import run_live as run_sentineldesk
from suite_core import SourceRecord, SourceResult
from suite_core.live_sources import (
    Provider, TaskFit, UnverifiedSource, _HTTPResponse, _fetch_with_transport,
    fetch_federal_register_opm_text,
)


class _Transport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, timeout, max_bytes):
        self.calls.append(url)
        return self.response


def _metadata_transport():
    document = {
        "document_number": "2026-19222", "publication_date": "2026-09-18",
        "title": "Employment in the Excepted Service", "type": "Rule",
        "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/rule",
        "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
    }
    body = json.dumps({"results": [document]}).encode()
    return _Transport(_HTTPResponse(200, {"Content-Type": "application/json"}, body))


def _cisa_source():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    record = SourceRecord(
        provider=Provider.CISA_KEV.value, source_id="CVE-2026-93952", source_url=url,
        response_status=200, response_sha256="c" * 64, request_body_sha256=None,
        as_of="2026-09-22", as_of_precision="day", retrieved_at_utc="2026-09-24T12:00:00Z",
        terms_url="https://creativecommons.org/publicdomain/zero/1.0/", read_only=True,
        task_fit=TaskFit.PUBLIC_KEV_CONTEXT.value,
        data={
            "cveID": "CVE-2026-93952", "dateAdded": "2026-09-22", "dueDate": "2026-10-22",
            "vendorProject": "Arista", "product": "VeloCloud Orchestrator",
            "shortDescription": "Arista VeloCloud Orchestrator has an input-validation vulnerability.",
        },
    )
    return SourceResult(
        provider=record.provider, status="VERIFIED_SOURCE", request_url=url,
        response_status=200, response_sha256=record.response_sha256, request_body_sha256=None,
        retrieved_at_utc=record.retrieved_at_utc, task_fit=record.task_fit, records=(record,),
    )


class P2b1IntegrationTests(unittest.TestCase):
    def test_opm_public_text_is_bound_to_metadata_and_pii_shaped_paragraphs_are_omitted(self):
        metadata_transport = _metadata_transport()
        with patch("suite_core.live_sources._retrieved_at", return_value="2026-09-24T12:00:00Z"):
            metadata = _fetch_with_transport(
                Provider.FEDERAL_REGISTER_OPM, task_fit=TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
                owner=None, repo=None, timeout=2.0, transport=metadata_transport,
            )
        record = metadata.records[0]
        html = (
            b"<html><head><title>Public rule</title></head><body><nav><p>skip navigation</p></nav>"
            b"<article><h1>Public rule</h1><p>The rule defines a public review procedure.</p>"
            b"<p>Contact Jane Doe at jane@example.invalid.</p></article></body></html>"
        )
        text_transport = _Transport(_HTTPResponse(200, {"Content-Type": "text/html; charset=utf-8"}, html))
        with patch("suite_core.live_sources._UrllibTransport", return_value=text_transport), patch(
            "suite_core.live_sources._retrieved_at", return_value="2026-09-24T12:00:00Z",
        ):
            text = fetch_federal_register_opm_text(record)

        self.assertEqual(text.source_id, record.source_id)
        self.assertEqual(text.as_of, record.as_of)
        self.assertEqual(text.task_fit, "public_opm_policy_text")
        self.assertEqual(text.terms_url, record.terms_url)
        self.assertEqual(text.response_sha256, hashlib.sha256(html).hexdigest())
        self.assertEqual(text_transport.calls, [record.source_url])
        self.assertEqual(text.data["document_text"], ["The rule defines a public review procedure."])
        self.assertNotIn("Jane Doe", repr(text.data))
        self.assertNotIn("jane@example.invalid", repr(text.data))
        denied_transport = _Transport(_HTTPResponse(200, {"Content-Type": "text/html"}, html))
        with patch("suite_core.live_sources._UrllibTransport", return_value=denied_transport):
            with self.assertRaises(UnverifiedSource):
                fetch_federal_register_opm_text(replace(record, source_url="https://evil.invalid/document"))
        self.assertEqual(denied_transport.calls, [])

    def test_sentineldesk_grounds_one_current_cisa_record_without_organization_claims(self):
        source = _cisa_source()
        model_result = {
            "ai_output": "Review the cited public vulnerability before assessing assets [evidence:CVE-2026-93952]",
            "ai_status": "AI / PROVIDER", "ai_invoked": True,
            "ai_evidence": {"grounded": True}, "ai_handoff": None,
        }
        with patch("apps.sentineldesk.flow.fetch_live", return_value=source), patch(
            "apps.sentineldesk.flow.complete_grounded", return_value=model_result,
        ):
            result = run_sentineldesk(ai_client=object())
        self.assertEqual(result["status"], "VERIFIED_SOURCE")
        self.assertIn("no authorized organizational alert or asset source", result["workflow_status"])
        self.assertEqual(result["ai_review_source_id"], "CVE-2026-93952")
        self.assertEqual(result["ai_verification_status"], "AI CANDIDATE (unwitnessed)")
        self.assertEqual(result["evidence"][0]["source_id"], "CVE-2026-93952")
        self.assertEqual(result["side_effect_count"], 0)


if __name__ == "__main__":
    unittest.main()
