"""Adversarial regression tests using synthetic stub transports only.

These test fixtures are intentionally synthetic attacks/edge cases and are not
production data or evidence that a provider endpoint is live.
"""

import hashlib
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch

from suite_core.live_sources import (
    MAX_RESPONSE_BYTES,
    DataUnavailable,
    Provider,
    TaskFit,
    UnverifiedSource,
    _HTTPResponse,
    _fetch_with_transport,
    fetch_govinfo_opm_text,
    govinfo_opm_url,
)

_TEST_NOW = "2026-09-23T12:00:00Z"
_TEST_TIME = datetime.fromisoformat(_TEST_NOW.replace("Z", "+00:00"))


class AdversarialStubTransport:
    """Synthetic transport used only to attack the parser and network boundary."""

    def __init__(self, response=None, error=None, responses=None):
        self.response = response
        self.error = error
        self.responses = list(responses) if responses is not None else None
        self.calls = []

    def get(self, url, *, timeout, max_bytes):
        self.calls.append((url, timeout, max_bytes))
        if self.error:
            raise self.error
        if self.responses is not None:
            if not self.responses:
                raise AssertionError("unexpected extra source request")
            return self.responses.pop(0)
        return self.response


def _reply(payload, *, status=200, content_type="application/json"):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return _HTTPResponse(status, {"Content-Type": content_type}, body)


def _world_bank_license_reply(text="License : CC BY-4.0", *, status=200):
    body = f'<html><div class="license meta">{text}</div></html>'.encode()
    return _reply(body, status=status, content_type="text/html")


def _cisa_reply(first, *, count=1721, pad_date="2026-09-22"):
    rows = [first]
    rows.extend({
        "cveID": f"CVE-2025-{1_000_000 + index}",
        "dateAdded": pad_date,
        "dueDate": "2026-10-22",
        "vendorProject": "synthetic test row",
    } for index in range(count - 1))
    return _reply({"vulnerabilities": rows})


def _fetch(provider, transport, task_fit, **kwargs):
    with patch("suite_core.live_sources._retrieved_at", return_value=_TEST_NOW):
        return _fetch_with_transport(
            provider,
            task_fit=task_fit,
            owner=kwargs.get("owner"),
            repo=kwargs.get("repo"),
            timeout=2.0,
            transport=transport,
        )


def _opm_document(publication_date):
    year, month, day = publication_date.split("-")
    document_number = f"{year}-19222"
    return {
        "document_number": document_number,
        "publication_date": publication_date,
        "title": "Employment in the Excepted Service",
        "type": "Notice",
        "html_url": (
            f"https://www.federalregister.gov/documents/{year}/{month}/{day}/"
            f"{document_number}/example"
        ),
        "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
    }


def _github_payload(updated_at):
    return {
        "id": 123,
        "full_name": "acme/widget",
        "updated_at": updated_at,
        "license": {"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"},
    }


def _world_bank_reply(years):
    observations = [{
        "countryiso3code": "USA",
        "country": {"id": "US"},
        "indicator": {"id": "NY.GDP.MKTP.CD"},
        "date": str(year),
        "value": year * 100,
    } for year in years]
    return _reply([{"page": 1}, observations])


def _format_timestamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class LiveSourcesAdversarialTests(unittest.TestCase):
    """All cases here are adversarial stub-transport regressions, never live data."""

    def test_adversarial_treasury_row_has_exact_body_identity_and_day_precision(self):
        transport = AdversarialStubTransport(_reply({"data": [{
            "record_date": "2026-09-21", "table_nbr": "1", "line_nbr": "2",
            "closing_balance_amt": "10.00",
        }]}))
        result = _fetch(Provider.TREASURY_DTS, transport, TaskFit.PUBLIC_TREASURY_CASH)
        record = result.records[0]
        self.assertEqual(record.source_id, "2026-09-21:1:2")
        self.assertEqual(record.as_of_precision, "day")
        self.assertEqual(record.response_sha256, result.response_sha256)
        self.assertEqual(record.response_sha256, hashlib.sha256(transport.response.body).hexdigest())
        self.assertIsNone(record.request_body_sha256)
        self.assertTrue(record.read_only)
        self.assertIn("api-documentation", record.terms_url)

    def test_adversarial_treasury_freshness_boundary_and_stale_http_200(self):
        for record_date, expected_status in (
            ((_TEST_TIME.date() - timedelta(days=14)).isoformat(), "VERIFIED_SOURCE"),
            ((_TEST_TIME.date() - timedelta(days=15)).isoformat(), "UNVERIFIED"),
        ):
            with self.subTest(record_date=record_date):
                transport = AdversarialStubTransport(_reply({"data": [{
                    "record_date": record_date, "table_nbr": "1", "line_nbr": "2",
                }]}))
                result = _fetch(
                    Provider.TREASURY_DTS, transport, TaskFit.PUBLIC_TREASURY_CASH,
                )
                self.assertEqual(result.response_status, 200)
                self.assertEqual(result.status, expected_status)
                if expected_status == "UNVERIFIED":
                    self.assertEqual(result.records, ())
                    self.assertIn("older than 14 days", result.reason)
                else:
                    self.assertEqual(result.records[0].as_of, record_date)

    def test_adversarial_treasury_future_date_is_unavailable(self):
        future = (_TEST_TIME.date() + timedelta(days=1)).isoformat()
        transport = AdversarialStubTransport(_reply({"data": [{
            "record_date": future, "table_nbr": "1", "line_nbr": "2",
        }]}))
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.TREASURY_DTS, transport, TaskFit.PUBLIC_TREASURY_CASH)

    def test_adversarial_cisa_parser_uses_source_id_and_cc0_reference(self):
        transport = AdversarialStubTransport(_cisa_reply({
            "cveID": "CVE-2026-12345", "dateAdded": "2026-09-20",
            "dueDate": "2026-10-20",
            "shortDescription": "Contact test@example.invalid",
        }))
        record = _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT).records[0]
        self.assertEqual(record.source_id, "CVE-2026-12345")
        self.assertEqual(record.as_of_precision, "day")
        self.assertEqual(record.data["dateAdded"], "2026-09-20")
        self.assertEqual(record.data["dueDate"], "2026-10-20")
        self.assertEqual(record.data["shortDescription"], "Contact [REDACTED]")
        self.assertEqual(record.terms_url, "https://creativecommons.org/publicdomain/zero/1.0/")

    def test_adversarial_cisa_projection_keeps_public_iso_dates(self):
        transport = AdversarialStubTransport(_cisa_reply({
            "cveID": "CVE-2026-23456", "dateAdded": "2026-09-21",
            "dueDate": "2026-11-01", "vendorProject": "Example Vendor",
        }))
        record = _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT).records[0]
        self.assertEqual(record.as_of, "2026-09-21")
        self.assertEqual(record.data["dateAdded"], "2026-09-21")
        self.assertEqual(record.data["dueDate"], "2026-11-01")
        self.assertEqual(record.data["vendorProject"], "Example Vendor")

    def test_adversarial_cisa_public_dates_do_not_relax_pii_or_secret_redaction(self):
        transport = AdversarialStubTransport(_cisa_reply({
            "cveID": "CVE-2026-34567", "dateAdded": "2026-09-22",
            "dueDate": "2026-12-02",
            "shortDescription": "Call +1 (555) 123-4567 or mail analyst@example.invalid",
            "api_secret": "tenant-b-secret-canary",
        }))
        record = _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT).records[0]
        self.assertEqual(record.data["dateAdded"], "2026-09-22")
        self.assertEqual(record.data["dueDate"], "2026-12-02")
        self.assertEqual(record.data["shortDescription"], "Call [REDACTED] or mail [REDACTED]")
        self.assertEqual(record.data["api_secret"], "[REDACTED]")
        self.assertNotIn("tenant-b-secret-canary", repr(record.data))

    def test_adversarial_cisa_injected_due_date_canary_is_rejected_without_echo(self):
        canary = "TENANT-B-CANARY-555-867-5309"
        transport = AdversarialStubTransport(_cisa_reply({
            "cveID": "CVE-2026-45678", "dateAdded": "2026-09-22",
            "dueDate": canary, "shortDescription": "public vulnerability",
        }))
        with self.assertRaises(DataUnavailable) as raised:
            _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT)
        self.assertEqual(raised.exception.status, "DATA_UNAVAILABLE")
        self.assertNotIn(canary, str(raised.exception))

    def test_adversarial_cisa_missing_due_date_is_unverified_without_records(self):
        transport = AdversarialStubTransport(_cisa_reply({
            "cveID": "CVE-2026-56789", "dateAdded": "2026-09-22",
            "shortDescription": "no synthetic due date",
        }))
        result = _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT)
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertNotIn("no synthetic due date", repr(result))

    def test_adversarial_world_bank_parser_preserves_year_precision(self):
        payload = [{"page": 1}, [{
            "countryiso3code": "USA", "country": {"id": "US"},
            "indicator": {"id": "NY.GDP.MKTP.CD"},
            "date": "2025", "value": 100,
        }]]
        record = _fetch(
            Provider.WORLD_BANK_USA_GDP, AdversarialStubTransport(responses=[
                _world_bank_license_reply(), _reply(payload),
            ]),
            TaskFit.PUBLIC_US_GDP,
        ).records[0]
        self.assertEqual(record.source_id, "USA:NY.GDP.MKTP.CD:2025")
        self.assertEqual(record.as_of_precision, "year")

    def test_adversarial_world_bank_history_requests_and_preserves_15_years(self):
        observations = [{
            "countryiso3code": "USA", "country": {"id": "US"},
            "indicator": {"id": "NY.GDP.MKTP.CD"},
            "date": str(year), "value": year * 100,
        } for year in range(2025, 2010, -1)]
        transport = AdversarialStubTransport(responses=[
            _world_bank_license_reply(), _reply([{"page": 1}, observations]),
        ])
        result = _fetch(Provider.WORLD_BANK_USA_GDP, transport, TaskFit.PUBLIC_US_GDP)
        self.assertEqual(len(result.records), 15)
        self.assertEqual(result.records[0].source_id, "USA:NY.GDP.MKTP.CD:2025")
        self.assertEqual(result.records[-1].source_id, "USA:NY.GDP.MKTP.CD:2011")
        self.assertTrue(all(record.as_of_precision == "year" for record in result.records))
        self.assertEqual(
            transport.calls[0][0],
            "https://data.worldbank.org/indicator/NY.GDP.MKTP.CD",
        )
        self.assertIn("per_page=15", transport.calls[1][0])
        self.assertEqual(result.records[0].terms_url, transport.calls[0][0])

    def test_adversarial_world_bank_dataset_license_failure_is_unverified_without_gdp(self):
        for response in (
            _world_bank_license_reply("License : Apache-2.0"),
            _world_bank_license_reply(status=403),
        ):
            with self.subTest(status=response.status, body=response.body[:40]):
                transport = AdversarialStubTransport(responses=[response])
                result = _fetch(
                    Provider.WORLD_BANK_USA_GDP, transport, TaskFit.PUBLIC_US_GDP,
                )
                self.assertEqual(result.status, "UNVERIFIED")
                self.assertEqual(result.records, ())
                self.assertEqual(result.request_url, "https://data.worldbank.org/indicator/NY.GDP.MKTP.CD")
                self.assertEqual(len(transport.calls), 1, "GDP is not fetched without dataset rights")

    def test_adversarial_world_bank_license_timeout_is_unverified_without_gdp(self):
        transport = AdversarialStubTransport(error=TimeoutError("synthetic license timeout"))
        result = _fetch(
            Provider.WORLD_BANK_USA_GDP, transport, TaskFit.PUBLIC_US_GDP,
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertEqual(result.response_status, 0)
        self.assertEqual(result.response_sha256, "")
        self.assertEqual(len(transport.calls), 1)

    def test_adversarial_cisa_record_count_and_source_freshness_are_bounded(self):
        current = {
            "cveID": "CVE-2026-23457", "dateAdded": "2026-09-22",
            "dueDate": "2026-10-22",
        }
        for count in (1720, 5001):
            with self.subTest(count=count):
                too_many_or_few = AdversarialStubTransport(_cisa_reply(current, count=count))
                with self.assertRaises(DataUnavailable):
                    _fetch(Provider.CISA_KEV, too_many_or_few, TaskFit.PUBLIC_KEV_CONTEXT)
        stale = AdversarialStubTransport(_cisa_reply(
            dict(current, dateAdded="2026-01-01"), pad_date="2026-01-01",
        ))
        result = _fetch(Provider.CISA_KEV, stale, TaskFit.PUBLIC_KEV_CONTEXT)
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertIn("older than 60 days", result.reason)

    def test_adversarial_cisa_accepts_exact_60_day_boundary(self):
        boundary = (_TEST_TIME.date() - timedelta(days=60)).isoformat()
        response = _cisa_reply({
            "cveID": "CVE-2026-23458", "dateAdded": boundary,
            "dueDate": "2026-10-22",
        }, pad_date=boundary)
        result = _fetch(
            Provider.CISA_KEV, AdversarialStubTransport(response),
            TaskFit.PUBLIC_KEV_CONTEXT,
        )
        self.assertEqual(result.status, "VERIFIED_SOURCE")
        self.assertEqual(len(result.records), 1721)

    def test_adversarial_cisa_future_date_is_unavailable(self):
        future = (_TEST_TIME.date() + timedelta(days=1)).isoformat()
        response = _cisa_reply({
            "cveID": "CVE-2026-23459", "dateAdded": future,
            "dueDate": "2026-10-22",
        }, pad_date=future)
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.CISA_KEV, AdversarialStubTransport(response),
                TaskFit.PUBLIC_KEV_CONTEXT,
            )

    def test_adversarial_eight_thousand_rows_fail_before_record_projection(self):
        row = {"record_date": "2026-09-21", "table_nbr": "1", "line_nbr": "1"}
        response = _reply({"data": [row] * 8000})
        self.assertLess(len(response.body), MAX_RESPONSE_BYTES)
        transport = AdversarialStubTransport(response)
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.TREASURY_DTS, transport, TaskFit.PUBLIC_TREASURY_CASH)
        self.assertEqual(len(transport.calls), 1)

    def test_adversarial_duplicate_stable_ids_are_rejected(self):
        duplicate = {"record_date": "2026-09-21", "table_nbr": "1", "line_nbr": "2"}
        transport = AdversarialStubTransport(_reply({"data": [duplicate, duplicate]}))
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.TREASURY_DTS, transport, TaskFit.PUBLIC_TREASURY_CASH)

    def test_adversarial_portfolio_extracts_safe_text_with_http_as_of(self):
        html = b"""<!doctype html><html><head><title>Proof portfolio</title>
        <meta name='description' content='Public portfolio description'>
        <script>do-not-return()</script></head><body><nav><p>do-not-return-nav</p></nav>
        <svg><title>do-not-return-svg-title</title></svg><h1>Case studies</h1>
        <p>Evidence, not claims. <a href='https://evil.invalid'>Read</a></p>
        <style>.hidden{display:none}</style></body></html>"""
        response = _HTTPResponse(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Last-Modified": "Tue, 22 Sep 2026 12:49:24 GMT",
        }, html)
        transport = AdversarialStubTransport(response)
        result = _fetch(
            Provider.OWN_PORTFOLIO_HTML, transport, TaskFit.OWN_PORTFOLIO_CONTENT,
        )
        record = result.records[0]
        self.assertEqual(result.request_url, "https://cayleb-james2008.github.io/agentic-resume/")
        self.assertEqual(record.source_id, "cayleb-james2008.github.io:/agentic-resume/")
        self.assertEqual(record.as_of, "2026-09-22T12:49:24Z")
        self.assertEqual(record.as_of_precision, "second")
        self.assertEqual(record.data["title"], "Proof portfolio")
        self.assertEqual(record.data["headings"], ["Case studies"])
        self.assertEqual(record.data["paragraphs"], ["Evidence, not claims. Read"])
        self.assertNotIn("do-not-return", repr(record.data))
        self.assertNotIn("do-not-return-nav", repr(record.data))
        self.assertNotIn("do-not-return-svg-title", repr(record.data))
        self.assertNotIn("evil.invalid", repr(record.data))
        self.assertEqual(record.response_sha256, hashlib.sha256(html).hexdigest())
        self.assertEqual(record.terms_url, "https://api.github.com/licenses/mit")

    def test_adversarial_portfolio_accepts_exact_30_day_boundary_and_small_clock_skew(self):
        html = b"<html><head><title>Portfolio</title></head><body><h1>Work</h1></body></html>"
        for modified_at in (
            _TEST_TIME - timedelta(days=30),
            _TEST_TIME + timedelta(minutes=4),
        ):
            with self.subTest(modified_at=modified_at):
                response = _HTTPResponse(200, {
                    "Content-Type": "text/html",
                    "Last-Modified": format_datetime(modified_at, usegmt=True),
                }, html)
                result = _fetch(
                    Provider.OWN_PORTFOLIO_HTML,
                    AdversarialStubTransport(response),
                    TaskFit.OWN_PORTFOLIO_CONTENT,
                )
                self.assertEqual(result.status, "VERIFIED_SOURCE")
                self.assertEqual(result.records[0].as_of, _format_timestamp(modified_at))

    def test_adversarial_portfolio_future_last_modified_beyond_clock_skew_is_unavailable(self):
        future = _TEST_TIME + timedelta(minutes=6)
        response = _HTTPResponse(200, {
            "Content-Type": "text/html",
            "Last-Modified": format_datetime(future, usegmt=True),
        }, b"<html><head><title>Portfolio</title></head><body><h1>Work</h1></body></html>")
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.OWN_PORTFOLIO_HTML, AdversarialStubTransport(response),
                TaskFit.OWN_PORTFOLIO_CONTENT,
            )

    def test_adversarial_portfolio_missing_last_modified_is_unverified_without_records(self):
        response = _reply(
            b"<html><head><title>Portfolio</title></head><body><h1>Work</h1></body></html>",
            content_type="text/html",
        )
        result = _fetch(
            Provider.OWN_PORTFOLIO_HTML, AdversarialStubTransport(response),
            TaskFit.OWN_PORTFOLIO_CONTENT,
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertIn("Last-Modified", result.reason)

    def test_adversarial_stale_portfolio_last_modified_is_unverified(self):
        html = b"<html><head><title>Portfolio</title></head><body><h1>Work</h1></body></html>"
        response = _HTTPResponse(200, {
            "Content-Type": "text/html",
            "Last-Modified": "Tue, 01 Jan 2001 00:00:00 GMT",
        }, html)
        result = _fetch(
            Provider.OWN_PORTFOLIO_HTML, AdversarialStubTransport(response),
            TaskFit.OWN_PORTFOLIO_CONTENT,
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertIn("older than 30 days", result.reason)

    def test_adversarial_federal_register_opm_uses_source_document_identity_and_date(self):
        document = {
            "document_number": "2026-19222",
            "publication_date": "2026-09-18",
            "title": "Employment in the Excepted Service",
            "type": "Proposed Rule",
            "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/example",
            "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
        }
        result = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [document]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        )
        record = result.records[0]
        self.assertEqual(record.source_id, "2026-19222")
        self.assertEqual(record.as_of, "2026-09-18")
        self.assertEqual(record.as_of_precision, "day")
        self.assertEqual(
            record.source_url,
            "https://www.federalregister.gov/documents/2026/09/18/2026-19222",
        )
        self.assertEqual(record.data["title"], "Employment in the Excepted Service")
        self.assertEqual(record.data["html_url"], record.source_url)
        self.assertEqual(record.data["type"], "Proposed Rule")
        self.assertEqual(record.terms_url,
                         "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site")
        self.assertIn("agency_ids", result.request_url)
        self.assertIn("406", result.request_url)

    def test_adversarial_federal_register_slug_is_discarded_after_identity_match(self):
        slug = "avery-morgan-19-example-road"
        document = dict(
            _opm_document("2026-09-18"),
            type="Proposed Rule",
            html_url=(
                "https://www.federalregister.gov/documents/2026/09/18/"
                f"2026-19222/{slug}"
            ),
        )
        result = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [document]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        )
        record = result.records[0]
        canonical = "https://www.federalregister.gov/documents/2026/09/18/2026-19222"
        self.assertEqual(record.source_url, canonical)
        self.assertEqual(record.data["html_url"], canonical)
        self.assertNotIn(slug, repr(record))
        self.assertEqual(record.source_id, "2026-19222")
        self.assertEqual(record.data["document_number"], "2026-19222")
        self.assertEqual(record.as_of, "2026-09-18")
        self.assertEqual(record.data["publication_date"], "2026-09-18")
        self.assertEqual(record.response_sha256, result.response_sha256)
        self.assertEqual(record.terms_url,
                         "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site")

    def test_adversarial_federal_register_rejects_nonofficial_host_userinfo_query_and_fragment(self):
        base = "https://www.federalregister.gov/documents/2026/09/18/2026-19222"
        bad_urls = (
            "https://evil.invalid/documents/2026/09/18/2026-19222",
            "https://avery@www.federalregister.gov/documents/2026/09/18/2026-19222",
            f"{base}?person=avery-morgan-19-example-road",
            f"{base}#avery-morgan-19-example-road",
        )
        for url in bad_urls:
            with self.subTest(url=url), self.assertRaises(DataUnavailable):
                _fetch(
                    Provider.FEDERAL_REGISTER_OPM,
                    AdversarialStubTransport(_reply({"results": [dict(
                        _opm_document("2026-09-18"), type="Proposed Rule", html_url=url,
                    )]})),
                    TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
                )

    def test_adversarial_govinfo_text_is_directly_bound_to_opm_number_and_date(self):
        metadata = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [dict(
                _opm_document("2026-09-18"), type="Proposed Rule",
            )]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        ).records[0]
        html = (
            b"<html><body><pre>FR Doc No: 2026-19222\n\n"
            b"September 18, 2026\n\nEmployment in the Excepted Service\n\n"
            b"DATES: Comments must be received by November 17, 2026.\n\n"
            b"ADDRESSES: Use the Federal eRulemaking Portal.\n\n"
            b"Contact Jane Doe at jane@example.invalid for details.</pre></body></html>"
        )
        transport = AdversarialStubTransport(_HTTPResponse(
            200, {"Content-Type": "text/html; charset=utf-8"}, html,
        ))
        with patch("suite_core.live_sources._UrllibTransport", return_value=transport):
            text = fetch_govinfo_opm_text(metadata)
        self.assertEqual(
            govinfo_opm_url(metadata),
            "https://www.govinfo.gov/content/pkg/FR-2026-09-18/html/2026-19222.htm",
        )
        self.assertEqual(transport.calls[0][0], govinfo_opm_url(metadata))
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(text.source_id, metadata.source_id)
        self.assertEqual(text.as_of, metadata.as_of)
        self.assertEqual(text.as_of_precision, "day")
        self.assertEqual(text.task_fit, "public_opm_policy_text")
        self.assertEqual(text.data["sections"]["DATES"], ["Comments must be received by November 17, 2026."])
        self.assertEqual(text.data["sections"]["ADDRESSES"], ["Use the Federal eRulemaking Portal."])
        self.assertNotIn("Jane Doe", repr(text.data))
        self.assertNotIn("jane@example.invalid", repr(text.data))
        self.assertEqual(text.terms_url, "https://www.govinfo.gov/about/policies#copyright")
        self.assertEqual(text.data["metadata_source_url"], metadata.source_url)
        self.assertEqual(text.data["metadata_response_sha256"], metadata.response_sha256)

    def test_adversarial_govinfo_redirect_is_refused_without_second_request(self):
        metadata = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [dict(
                _opm_document("2026-09-18"), type="Proposed Rule",
            )]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        ).records[0]
        transport = AdversarialStubTransport(_HTTPResponse(
            302,
            {"Content-Type": "text/html", "Location": "https://unblock.federalregister.gov/"},
            b"",
        ))
        with patch("suite_core.live_sources._UrllibTransport", return_value=transport):
            with self.assertRaisesRegex(DataUnavailable, "HTTP 302"):
                fetch_govinfo_opm_text(metadata)
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("govinfo.gov/content/pkg/FR-", transport.calls[0][0])

    def test_adversarial_govinfo_issue_date_mismatch_returns_no_text(self):
        metadata = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [dict(
                _opm_document("2026-09-18"), type="Proposed Rule",
            )]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        ).records[0]
        body = (
            b"<html><body><p>FR Doc No: 2026-19222</p>"
            b"<p>September 19, 2026</p><p>Employment in the Excepted Service</p>"
            b"<p>DATES: A sample date.</p></body></html>"
        )
        transport = AdversarialStubTransport(_HTTPResponse(
            200, {"Content-Type": "text/html"}, body,
        ))
        with patch("suite_core.live_sources._UrllibTransport", return_value=transport):
            with self.assertRaisesRegex(DataUnavailable, "document number, title, or issue date"):
                fetch_govinfo_opm_text(metadata)
        self.assertEqual(len(transport.calls), 1)

    def test_adversarial_govinfo_metadata_url_must_remain_exact_official_identity(self):
        metadata = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [dict(
                _opm_document("2026-09-18"), type="Proposed Rule",
            )]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        ).records[0]
        for url in (
            "https://evil.invalid/content/pkg/FR-2026-09-18/html/2026-19222.htm",
            metadata.source_url + "?redirect=1",
        ):
            transport = AdversarialStubTransport(_HTTPResponse(
                200, {"Content-Type": "text/html"}, b"",
            ))
            with self.subTest(url=url), patch(
                "suite_core.live_sources._UrllibTransport", return_value=transport,
            ):
                with self.assertRaises(UnverifiedSource):
                    fetch_govinfo_opm_text(replace(metadata, source_url=url))
                self.assertEqual(transport.calls, [])

    def test_adversarial_opm_freshness_boundary_and_stale_http_200(self):
        for publication_date, expected_status in (
            ((_TEST_TIME.date() - timedelta(days=90)).isoformat(), "VERIFIED_SOURCE"),
            ((_TEST_TIME.date() - timedelta(days=91)).isoformat(), "UNVERIFIED"),
        ):
            with self.subTest(publication_date=publication_date):
                result = _fetch(
                    Provider.FEDERAL_REGISTER_OPM,
                    AdversarialStubTransport(_reply({"results": [
                        _opm_document(publication_date),
                    ]})),
                    TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
                )
                self.assertEqual(result.response_status, 200)
                self.assertEqual(result.status, expected_status)
                if expected_status == "UNVERIFIED":
                    self.assertEqual(result.records, ())
                    self.assertIn("older than 90 days", result.reason)
                else:
                    self.assertEqual(result.records[0].as_of, publication_date)

    def test_adversarial_opm_future_publication_date_is_unavailable(self):
        future = (_TEST_TIME.date() + timedelta(days=1)).isoformat()
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.FEDERAL_REGISTER_OPM,
                AdversarialStubTransport(_reply({"results": [_opm_document(future)]})),
                TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
            )

    def test_adversarial_federal_register_rejects_non_opm_documents(self):
        document = {
            "document_number": "2026-19222", "publication_date": "2026-09-18",
            "title": "Not OPM", "type": "Notice",
            "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/example",
            "agencies": [{"id": 1, "raw_name": "OTHER AGENCY"}],
        }
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.FEDERAL_REGISTER_OPM,
                AdversarialStubTransport(_reply({"results": [document]})),
                TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
            )

    def test_adversarial_federal_register_url_must_match_number_and_publication_date(self):
        document = {
            "document_number": "2026-19222", "publication_date": "2026-09-18",
            "title": "Employment in the Excepted Service", "type": "Proposed Rule",
            "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/example",
            "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
        }
        bad_urls = (
            "https://www.federalregister.gov/documents/2026/09/18/2026-19042/example",
            "https://www.federalregister.gov/documents/2026/09/19/2026-19222/example",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                with self.assertRaises(DataUnavailable):
                    _fetch(
                        Provider.FEDERAL_REGISTER_OPM,
                        AdversarialStubTransport(_reply({"results": [dict(document, html_url=url)]})),
                        TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
                    )

    def test_adversarial_opm_record_count_ceiling_applies_before_projection(self):
        transport = AdversarialStubTransport(_reply({"results": [{}] * 101}))
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.FEDERAL_REGISTER_OPM, transport,
                TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
            )
        self.assertEqual(len(transport.calls), 1)

    def test_adversarial_world_bank_record_count_ceiling_applies_before_projection(self):
        transport = AdversarialStubTransport(responses=[
            _world_bank_license_reply(), _reply([{"page": 1}, [{}] * 101]),
        ])
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.WORLD_BANK_USA_GDP, transport, TaskFit.PUBLIC_US_GDP)
        self.assertEqual(len(transport.calls), 2)

    def test_adversarial_federal_register_omits_personal_name_and_street_address_title(self):
        document = {
            "document_number": "2026-19222", "publication_date": "2026-09-18",
            "title": "Notice for Jane Doe, 123 Main Street", "type": "Notice",
            "html_url": "https://www.federalregister.gov/documents/2026/09/18/2026-19222/example",
            "agencies": [{"id": 406, "raw_name": "OFFICE OF PERSONNEL MANAGEMENT"}],
        }
        record = _fetch(
            Provider.FEDERAL_REGISTER_OPM,
            AdversarialStubTransport(_reply({"results": [document]})),
            TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        ).records[0]
        self.assertNotIn("title", record.data)
        self.assertEqual(record.data["document_number"], "2026-19222")
        self.assertEqual(record.data["publication_date"], "2026-09-18")
        self.assertEqual(record.data["type"], "Notice")
        self.assertNotIn("Jane Doe", repr(record.data))
        self.assertNotIn("123 Main Street", repr(record.data))

    def test_adversarial_github_metadata_requires_actual_repo_license(self):
        payload = {
            "id": 123, "full_name": "acme/widget", "updated_at": "2026-09-22T10:00:00Z",
            "license": {"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"},
            "description": "Maintainer test@example.invalid",
        }
        record = _fetch(
            Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(payload)),
            TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
        ).records[0]
        self.assertEqual(record.source_id, "123")
        self.assertEqual(record.as_of_precision, "second")
        self.assertNotIn("description", record.data)

    def test_adversarial_github_activity_freshness_boundary_and_stale_http_200(self):
        for updated_at, expected_status in (
            (_format_timestamp(_TEST_TIME - timedelta(days=365)), "VERIFIED_SOURCE"),
            (_format_timestamp(_TEST_TIME - timedelta(days=366)), "UNVERIFIED"),
        ):
            with self.subTest(updated_at=updated_at):
                result = _fetch(
                    Provider.GITHUB_REPOSITORY,
                    AdversarialStubTransport(_reply(_github_payload(updated_at))),
                    TaskFit.PUBLIC_REPOSITORY_METADATA,
                    owner="acme", repo="widget",
                )
                self.assertEqual(result.response_status, 200)
                self.assertEqual(result.status, expected_status)
                if expected_status == "UNVERIFIED":
                    self.assertEqual(result.records, ())
                    self.assertIn("older than 365 days", result.reason)
                else:
                    self.assertEqual(result.records[0].as_of, updated_at)

    def test_adversarial_github_future_timestamp_beyond_clock_skew_is_unavailable(self):
        future = _format_timestamp(_TEST_TIME + timedelta(minutes=6))
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.GITHUB_REPOSITORY,
                AdversarialStubTransport(_reply(_github_payload(future))),
                TaskFit.PUBLIC_REPOSITORY_METADATA,
                owner="acme", repo="widget",
            )

    def test_adversarial_github_timestamp_within_clock_skew_is_accepted(self):
        future = _format_timestamp(_TEST_TIME + timedelta(minutes=4))
        result = _fetch(
            Provider.GITHUB_REPOSITORY,
            AdversarialStubTransport(_reply(_github_payload(future))),
            TaskFit.PUBLIC_REPOSITORY_METADATA,
            owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "VERIFIED_SOURCE")
        self.assertEqual(result.records[0].as_of, future)

    def test_adversarial_gdp_latest_year_cutoff_and_historical_years(self):
        for years, expected_status in (
            ([2024], "UNVERIFIED"),
            ([2025, 2011], "VERIFIED_SOURCE"),
        ):
            with self.subTest(years=years):
                result = _fetch(
                    Provider.WORLD_BANK_USA_GDP,
                    AdversarialStubTransport(responses=[
                        _world_bank_license_reply(), _world_bank_reply(years),
                    ]),
                    TaskFit.PUBLIC_US_GDP,
                )
                self.assertEqual(result.status, expected_status)
                if expected_status == "UNVERIFIED":
                    self.assertEqual(result.records, ())
                    self.assertIn("at least two years", result.reason)
                else:
                    self.assertEqual(
                        [record.as_of for record in result.records], ["2025", "2011"],
                    )

    def test_adversarial_gdp_future_year_is_unavailable(self):
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.WORLD_BANK_USA_GDP,
                AdversarialStubTransport(responses=[
                    _world_bank_license_reply(), _world_bank_reply([2027]),
                ]),
                TaskFit.PUBLIC_US_GDP,
            )

    def test_adversarial_github_spdx_and_license_slug_must_match(self):
        payload = {
            "id": 123, "full_name": "acme/widget", "updated_at": "2026-09-22T10:00:00Z",
            "license": {"spdx_id": "Apache-2.0", "url": "https://api.github.com/licenses/mit"},
        }
        result = _fetch(
            Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(payload)),
            TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())

    def test_adversarial_github_metadata_must_match_requested_repository_scope(self):
        payload = {
            "id": 123, "full_name": "someone/else", "updated_at": "2026-09-22T10:00:00Z",
            "license": {"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"},
        }
        result = _fetch(
            Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(payload)),
            TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())

    def test_adversarial_cross_host_redirect_is_never_followed(self):
        transport = AdversarialStubTransport(
            _HTTPResponse(302, {"Location": "https://evil.example/collect"}, b"")
        )
        with self.assertRaises(DataUnavailable) as raised:
            _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT)
        self.assertEqual(raised.exception.status, "DATA_UNAVAILABLE")
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("evil.example", transport.response.headers["Location"])
        self.assertNotIn("evil.example", transport.calls[0][0])

    def test_adversarial_oversize_response_fails_closed(self):
        transport = AdversarialStubTransport(_reply(b"x" * (MAX_RESPONSE_BYTES + 1)))
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT)

    def test_adversarial_bad_timestamp_is_a_schema_failure(self):
        payload = {
            "id": 123, "full_name": "acme/widget", "updated_at": "yesterday",
            "license": {"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"},
        }
        with self.assertRaises(DataUnavailable):
            _fetch(
                Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(payload)),
                TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
            )

    def test_adversarial_http_403_and_429_are_data_unavailable(self):
        for status in (403, 429):
            with self.subTest(status=status):
                transport = AdversarialStubTransport(_reply({}, status=status))
                with self.assertRaises(DataUnavailable) as raised:
                    _fetch(
                        Provider.CISA_KEV,
                        transport,
                        TaskFit.PUBLIC_KEV_CONTEXT,
                    )
                self.assertEqual(raised.exception.status, "DATA_UNAVAILABLE")
                self.assertEqual(len(transport.calls), 1, "no fallback request is attempted")

    def test_adversarial_timeout_is_data_unavailable(self):
        with self.assertRaises(DataUnavailable) as raised:
            _fetch(
                Provider.CISA_KEV,
                AdversarialStubTransport(error=TimeoutError("synthetic timeout")),
                TaskFit.PUBLIC_KEV_CONTEXT,
            )
        self.assertEqual(raised.exception.status, "DATA_UNAVAILABLE")

    def test_adversarial_missing_terms_or_as_of_is_unverified(self):
        no_license = {
            "id": 123, "full_name": "acme/widget", "updated_at": "2026-09-22T10:00:00Z",
            "license": None,
        }
        result = _fetch(
            Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(no_license)),
            TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        no_as_of = dict(no_license, license={"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"})
        no_as_of.pop("updated_at")
        result = _fetch(
            Provider.GITHUB_REPOSITORY, AdversarialStubTransport(_reply(no_as_of)),
            TaskFit.PUBLIC_REPOSITORY_METADATA, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())

    def test_adversarial_github_user_content_without_terms_or_as_of_is_not_admitted(self):
        readme = {"name": "README.md", "path": "README.md", "sha": "abc123", "encoding": "base64", "content": ""}
        result = _fetch(
            Provider.GITHUB_README, AdversarialStubTransport(_reply(readme)),
            TaskFit.PUBLIC_REPOSITORY_README, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertIn("as-of timestamp", result.reason)
        result = _fetch(
            Provider.GITHUB_ADVISORIES, AdversarialStubTransport(_reply([])),
            TaskFit.PUBLIC_REPOSITORY_ADVISORIES, owner="acme", repo="widget",
        )
        self.assertEqual(result.status, "UNVERIFIED")
        self.assertEqual(result.records, ())
        self.assertIn("terms", result.reason)

    def test_adversarial_github_schema_mismatch_is_not_mislabelled_unverified(self):
        with self.assertRaises(DataUnavailable) as raised:
            _fetch(
                Provider.GITHUB_README, AdversarialStubTransport(_reply({})),
                TaskFit.PUBLIC_REPOSITORY_README, owner="acme", repo="widget",
            )
        self.assertEqual(raised.exception.status, "DATA_UNAVAILABLE")

    def test_adversarial_schema_mismatch_and_missing_task_fit_never_fall_back(self):
        transport = AdversarialStubTransport(_reply({"items": []}))
        with self.assertRaises(DataUnavailable):
            _fetch(Provider.CISA_KEV, transport, TaskFit.PUBLIC_KEV_CONTEXT)
        self.assertEqual(len(transport.calls), 1)
        no_fit_transport = AdversarialStubTransport(_reply({}))
        with self.assertRaises(UnverifiedSource):
            _fetch(Provider.CISA_KEV, no_fit_transport, None)
        self.assertEqual(no_fit_transport.calls, [])

    def test_adversarial_untrusted_github_path_is_rejected_before_transport(self):
        transport = AdversarialStubTransport(_reply({}))
        with self.assertRaises(UnverifiedSource):
            _fetch(
                Provider.GITHUB_REPOSITORY, transport, TaskFit.PUBLIC_REPOSITORY_METADATA,
                owner="../../evil.example", repo="repo",
            )
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
