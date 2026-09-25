"""Regression tests for SearchLift's one fixed current Pages source."""

import json
import unittest
from unittest.mock import patch

from apps.searchlift.flow import _portfolio_metrics, run_live
from suite_core import Provider, SourceRecord, SourceResult, TaskFit
from suite_core.sources.core import (
    DataUnavailable,
    _HTTPResponse,
    _fetch_with_transport,
    _request_url,
    _validate_url,
)
from suite_core.sources.portfolio import PortfolioHTMLParser

PAGES_URL = "https://cayleb-james2008.github.io/agentic-resume/"
PAGES_SOURCE_ID = "cayleb-james2008.github.io:/agentic-resume/"
VERCEL_URL = "https://agentic-resume-nine.vercel.app/"
RETRIEVED_AT = "2026-09-25T16:20:00Z"
LAST_MODIFIED = "Fri, 25 Sep 2026 14:50:52 GMT"
H4_ROSTER = [
    "LedgerBridge", "MarketBrief", "ChainWatch", "BacktestGuard", "ReplyCraft",
    "HandoffHub", "SentinelDesk", "PipelineRelay", "OnboardPath", "SearchLift",
]
BOUNDED_H4_FIXTURE = (
    b"<html><head><title>Current portfolio</title></head><body><main>"
    b"<h4>LedgerBridge</h4><h4>MarketBrief</h4><h4>ChainWatch</h4>"
    b"<h4>BacktestGuard</h4><h4>ReplyCraft</h4><h4>HandoffHub</h4>"
    b"<h4>SentinelDesk</h4><h4>PipelineRelay</h4><h4>OnboardPath</h4>"
    b"<h4>SearchLift</h4></main></body></html>"
)


class StubTransport:
    def __init__(self, response: _HTTPResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, float, int]] = []

    def get(self, url: str, *, timeout: float, max_bytes: int) -> _HTTPResponse:
        self.calls.append((url, timeout, max_bytes))
        return self.response


def _portfolio_result(text: str) -> SourceResult:
    record = SourceRecord(
        provider=Provider.OWN_PORTFOLIO_HTML.value,
        source_id=PAGES_SOURCE_ID,
        source_url=PAGES_URL,
        response_status=200,
        response_sha256="a" * 64,
        request_body_sha256=None,
        as_of="2026-09-25T14:50:52Z",
        as_of_precision="second",
        retrieved_at_utc=RETRIEVED_AT,
        terms_url="https://api.github.com/licenses/mit",
        read_only=True,
        task_fit=TaskFit.OWN_PORTFOLIO_CONTENT.value,
        data={
            "title": "Current portfolio",
            "description": "A factual portfolio summary for review.",
            "headings": ["Selected work"],
            "paragraphs": [text],
        },
    )
    return SourceResult(
        provider=Provider.OWN_PORTFOLIO_HTML.value,
        status="VERIFIED_SOURCE",
        request_url=PAGES_URL,
        response_status=200,
        response_sha256="a" * 64,
        request_body_sha256=None,
        retrieved_at_utc=RETRIEVED_AT,
        task_fit=TaskFit.OWN_PORTFOLIO_CONTENT.value,
        records=(record,),
    )


def _fetch_pages_html(body: bytes) -> SourceResult:
    transport = StubTransport(_HTTPResponse(
        200,
        {"Content-Type": "text/html; charset=utf-8", "Last-Modified": LAST_MODIFIED},
        body,
    ))
    return _fetch_with_transport(
        Provider.OWN_PORTFOLIO_HTML,
        task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
        owner=None,
        repo=None,
        timeout=5.0,
        transport=transport,
        _clock=lambda: RETRIEVED_AT,
    )


class SearchLiftCurrentSourceTests(unittest.TestCase):
    def test_portfolio_provider_selects_only_exact_current_pages_root(self) -> None:
        self.assertEqual(_request_url(Provider.OWN_PORTFOLIO_HTML, None, None), PAGES_URL)
        _validate_url(PAGES_URL)
        with self.assertRaises(DataUnavailable):
            _validate_url(VERCEL_URL)

    def test_pages_source_refuses_lookalike_hosts_subpaths_queries_and_userinfo(self) -> None:
        rejected = (
            "https://cayleb-james2008.github.io.evil.invalid/agentic-resume/",
            "https://cayleb-james2008.github.io/agentic-resume/extra",
            "https://cayleb-james2008.github.io/agentic-resume/?page=2",
            "https://cayleb-james2008.github.io/agentic-resume/#section",
            "https://user@cayleb-james2008.github.io/agentic-resume/",
            "http://cayleb-james2008.github.io/agentic-resume/",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(DataUnavailable):
                _validate_url(url)

    def test_pages_read_emits_new_stable_identity_and_bounded_projection(self) -> None:
        body = (
            b"<html><head><title>Current portfolio</title>"
            b"<meta name='description' content='A factual portfolio summary'>"
            b"<script>not returned</script></head><body><nav><p>not returned</p></nav>"
            b"<h1>Selected work</h1><p>Public page text.</p></body></html>"
        )
        transport = StubTransport(_HTTPResponse(
            200,
            {"Content-Type": "text/html; charset=utf-8", "Last-Modified": LAST_MODIFIED},
            body,
        ))
        result = _fetch_with_transport(
            Provider.OWN_PORTFOLIO_HTML,
            task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
            owner=None,
            repo=None,
            timeout=5.0,
            transport=transport,
            _clock=lambda: RETRIEVED_AT,
        )
        self.assertEqual(result.status, "VERIFIED_SOURCE")
        self.assertEqual(result.request_url, PAGES_URL)
        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.source_id, PAGES_SOURCE_ID)
        self.assertEqual(record.source_url, PAGES_URL)
        self.assertEqual(record.as_of, "2026-09-25T14:50:52Z")
        self.assertEqual(record.retrieved_at_utc, RETRIEVED_AT)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0][0], PAGES_URL)
        self.assertEqual(record.data["headings"], ["Selected work"])
        self.assertNotIn("not returned", repr(record.data))

    def test_bounded_h4_fixture_counts_the_ten_project_headings(self) -> None:
        transport = StubTransport(_HTTPResponse(
            200,
            {"Content-Type": "text/html; charset=utf-8", "Last-Modified": LAST_MODIFIED},
            BOUNDED_H4_FIXTURE,
        ))
        result = _fetch_with_transport(
            Provider.OWN_PORTFOLIO_HTML,
            task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
            owner=None,
            repo=None,
            timeout=5.0,
            transport=transport,
            _clock=lambda: RETRIEVED_AT,
        )
        headings = result.records[0].data["headings"]
        self.assertEqual(headings, H4_ROSTER)
        with patch("apps.searchlift.flow.fetch_live", return_value=result):
            report = run_live()["result"]["name_coverage"]
        self.assertEqual(report["count"], "10/10")
        self.assertEqual(set(report["names_observed"]), set(H4_ROSTER))

    def test_suite_h4_projection_prioritizes_real_page_shape_within_heading_budget(self) -> None:
        earlier = "".join(
            f"<h{index % 3 + 1}>Earlier heading {index}</h{index % 3 + 1}>"
            for index in range(15)
        )
        groups = (H4_ROSTER[:4], H4_ROSTER[4:8], H4_ROSTER[8:])
        suite_groups = "".join(
            '<section class="suite-index__group"><h3>Workflow group</h3><ol>'
            + "".join(
                f'<li><h4><a href="/{name.casefold()}">{name}</a></h4></li>'
                for name in group
            )
            + "</ol></section>"
            for group in groups
        )
        html = (
            "<html><head><title>Current portfolio</title></head><body><main>"
            + earlier + '<section id="suite">' + suite_groups
            + "</section></main></body></html>"
        )
        parser = PortfolioHTMLParser()
        parser.feed(html)

        self.assertEqual(len(parser.headings), 20)
        self.assertEqual(parser.headings[:10], H4_ROSTER)
        self.assertEqual(parser.headings[10:], [f"Earlier heading {i}" for i in range(10)])
        self.assertIsNone(parser.section_error)
        result = _fetch_pages_html(html.encode("utf-8"))
        with patch("apps.searchlift.flow.fetch_live", return_value=result):
            coverage = run_live()["result"]["name_coverage"]
        self.assertEqual(coverage["count"], "10/10")
        self.assertEqual(coverage["verdict"], "PASS")

    def test_malformed_suite_boundaries_cannot_produce_a_ten_of_ten_pass(self) -> None:
        names = "".join(f"<h4>{name}</h4>" for name in H4_ROSTER)
        malformed_pages = {
            "unclosed suite": (
                f"<html><head><title>Current portfolio</title></head><body>"
                f"<section id='suite'>{names}<h4>Outside after missing close</h4>"
                "</body></html>"
            ),
            "duplicate suite id": (
                f"<html><head><title>Current portfolio</title></head><body>"
                f"<section id='suite'>{names}</section>"
                f"<section id='suite'>{names}</section></body></html>"
            ),
            "extra section end": (
                f"<html><head><title>Current portfolio</title></head><body>"
                f"<section id='suite'>{names}</section></section>{names}"
                "</body></html>"
            ),
            "unclosed nested section": (
                f"<html><head><title>Current portfolio</title></head><body>"
                f"<section id='suite'><section>{names}</section></body></html>"
            ),
            "section closes during an open suite h4": (
                f"<html><head><title>Current portfolio</title></head><body>"
                '<section id="suite"><h4>LedgerBridge</section><h4>MarketBrief</h4>'
                "</body></html>"
            ),
            "nested section starts during an open suite h4": (
                f"<html><head><title>Current portfolio</title></head><body>"
                '<section id="suite"><h4>LedgerBridge<section></h4></section>'
                + "".join(f"<h4>{name}</h4>" for name in H4_ROSTER[1:])
                + "</section></body></html>"
            ),
            "self-closing suite": (
                f"<html><head><title>Current portfolio</title></head><body>"
                f"<section id='suite'/>{names}</body></html>"
            ),
        }

        for label, html in malformed_pages.items():
            with self.subTest(boundary=label):
                result = _fetch_pages_html(html.encode("utf-8"))
                self.assertEqual(result.status, "UNVERIFIED")
                self.assertEqual(result.records, ())
                self.assertIn("section", result.reason.lower())
                with patch("apps.searchlift.flow.fetch_live", return_value=result):
                    receipt = run_live()
                self.assertEqual(receipt["status"], "UNVERIFIED")
                self.assertIn("section", receipt["result"]["reason"].lower())
                self.assertNotIn("name_coverage", receipt["result"])
                self.assertNotIn("10/10", repr(receipt))

    def test_closing_suite_section_clears_open_h4_capture(self) -> None:
        parser = PortfolioHTMLParser()
        parser.feed('<section id="suite"><h4>LedgerBridge</section>')

        self.assertIsNone(parser._capture_tag)
        self.assertEqual(parser._capture, [])
        self.assertIn("open suite h4", parser.section_error or "")

        parser.feed("<h4>MarketBrief</h4>")
        self.assertEqual(parser._page_headings, ["MarketBrief"])
        self.assertEqual(parser._suite_headings, [])

    def test_nested_section_start_clears_open_suite_h4_capture(self) -> None:
        parser = PortfolioHTMLParser()
        parser.feed('<section id="suite"><h4>LedgerBridge<section>')

        self.assertIsNone(parser._capture_tag)
        self.assertEqual(parser._capture, [])
        self.assertIn("open suite h4", parser.section_error or "")

        parser.feed("</h4></section>")
        self.assertEqual(parser._suite_headings, [])

    def test_h4_headings_keep_twenty_item_and_one_thousand_character_caps(self) -> None:
        parser = PortfolioHTMLParser()
        parser.feed(
            "<html><body>" + "".join(f"<h4>{'x' * 1001}</h4>" for _ in range(21))
            + "</body></html>"
        )
        self.assertEqual(len(parser.headings), 20)
        self.assertEqual(parser.headings, ["x" * 1000] * 20)

    def test_suite_h4_and_extra_paragraphs_stay_inside_existing_caps(self) -> None:
        earlier = "".join(f"<h2>Earlier {index}</h2>" for index in range(15))
        suite_h4s = "".join(f"<h4>Suite {index}</h4>" for index in range(21))
        paragraphs = "".join(f"<p>Paragraph {index}</p>" for index in range(31))
        parser = PortfolioHTMLParser()
        parser.feed(
            "<html><body>" + earlier + '<section id="suite">' + suite_h4s
            + "</section>" + paragraphs + "</body></html>"
        )

        self.assertEqual(parser.headings, [
            *(f"Suite {index}" for index in range(10)),
            *(f"Earlier {index}" for index in range(10)),
        ])
        self.assertNotIn("Suite 20", parser.headings)
        self.assertEqual(parser.paragraphs, [f"Paragraph {index}" for index in range(30)])

    def test_later_h4_names_without_suite_section_do_not_bypass_heading_budget(self) -> None:
        earlier = "".join(f"<h2>Earlier {index}</h2>" for index in range(20))
        later_names = "".join(f"<h4>{name}</h4>" for name in H4_ROSTER)
        body = (
            '<html><head><title>Current portfolio</title></head><body><main>'
            + earlier + '<div id="suite">' + later_names + "</div></main></body></html>"
        ).encode("utf-8")
        transport = StubTransport(_HTTPResponse(
            200,
            {"Content-Type": "text/html; charset=utf-8", "Last-Modified": LAST_MODIFIED},
            body,
        ))
        result = _fetch_with_transport(
            Provider.OWN_PORTFOLIO_HTML,
            task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
            owner=None,
            repo=None,
            timeout=5.0,
            transport=transport,
            _clock=lambda: RETRIEVED_AT,
        )

        self.assertEqual(result.records[0].data["headings"], [
            f"Earlier {index}" for index in range(20)
        ])
        with patch("apps.searchlift.flow.fetch_live", return_value=result):
            coverage = run_live()["result"]["name_coverage"]
        self.assertEqual(coverage["count"], "0/10")
        self.assertEqual(coverage["verdict"], "REFUTED")

    def test_hostile_h4_markup_and_skipped_regions_do_not_leak(self) -> None:
        parser = PortfolioHTMLParser()
        parser.feed(
            '<html><body><section id="suite">'
            '<h4 data-secret="H4_ATTRIBUTE_CANARY">Safe '
            '<script>H4_SCRIPT_CANARY</script>'
            '<a href="https://hostile.invalid/H4_LINK_CANARY">name</a></h4>'
            '<nav><section><h4>H4_NAV_CANARY</h4></section></nav>'
            '<style>H4_STYLE_CANARY</style></section><h4>Visible</h4></body></html>'
        )
        projected = repr(parser.headings)
        self.assertEqual(parser.headings, ["Safe name", "Visible"])
        for canary in (
            "H4_ATTRIBUTE_CANARY", "H4_SCRIPT_CANARY", "hostile.invalid",
            "H4_LINK_CANARY", "H4_NAV_CANARY", "H4_STYLE_CANARY",
        ):
            self.assertNotIn(canary, projected)

    def test_pages_redirect_is_refused_without_following_another_location(self) -> None:
        transport = StubTransport(_HTTPResponse(
            302,
            {"Location": "https://evil.invalid/collect", "Content-Type": "text/html"},
            b"",
        ))
        with self.assertRaisesRegex(DataUnavailable, "HTTP 302"):
            _fetch_with_transport(
                Provider.OWN_PORTFOLIO_HTML,
                task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
                owner=None,
                repo=None,
                timeout=5.0,
                transport=transport,
                _clock=lambda: RETRIEVED_AT,
            )
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0][0], PAGES_URL)

    def test_missing_malformed_and_stale_pages_dates_fail_closed(self) -> None:
        body = b"<html><head><title>Current portfolio</title></head><body><h1>Work</h1></body></html>"
        for headers, expected in (
            ({"Content-Type": "text/html"}, "UNVERIFIED"),
            ({"Content-Type": "text/html", "Last-Modified": "not-a-date"}, "DATA_UNAVAILABLE"),
            ({"Content-Type": "text/html", "Last-Modified": "Tue, 01 Jan 2001 00:00:00 GMT"}, "UNVERIFIED"),
        ):
            with self.subTest(headers=headers):
                transport = StubTransport(_HTTPResponse(200, headers, body))
                try:
                    result = _fetch_with_transport(
                        Provider.OWN_PORTFOLIO_HTML,
                        task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
                        owner=None,
                        repo=None,
                        timeout=5.0,
                        transport=transport,
                        _clock=lambda: RETRIEVED_AT,
                    )
                except DataUnavailable as error:
                    self.assertEqual(error.status, expected)
                else:
                    self.assertEqual(result.status, expected)
                    self.assertEqual(result.records, ())

    def test_partial_name_count_is_refuted_and_names_projection_limits(self) -> None:
        text = "LedgerBridge MarketBrief ChainWatch BacktestGuard ReplyCraft HandoffHub SentinelDesk SearchLift"
        with patch("apps.searchlift.flow.fetch_live", return_value=_portfolio_result(text)):
            receipt = run_live()

        self.assertEqual(receipt["status"], "VERIFIED_SOURCE")
        report = receipt["result"]["name_coverage"]
        self.assertEqual(report["count"], "8/10")
        self.assertEqual(report["verdict"], "REFUTED")
        self.assertEqual(report["names_observed"], [
            "LedgerBridge", "MarketBrief", "ChainWatch", "BacktestGuard",
            "ReplyCraft", "HandoffHub", "SentinelDesk", "SearchLift",
        ])
        self.assertEqual(report["fields_checked"], [
            "title", "meta description", "heading text", "paragraph text",
        ])
        self.assertEqual(report["limits"], {
            "maximum_headings": 20,
            "maximum_paragraphs": 30,
            "maximum_characters_per_captured_item": 1000,
        })
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertIn("bounded", serialized.lower())
        self.assertNotIn(text, serialized)

    def test_workflow_count_is_distinct_and_does_not_accept_substring_lookalikes(self) -> None:
        metrics = _portfolio_metrics({
            "title": "LedgerBridge LedgerBridge",
            "description": "ChainWatcher SearchLifting",
            "headings": [],
            "paragraphs": [],
        })
        self.assertEqual(metrics["approved_workflow_mentions"], 1)


if __name__ == "__main__":
    unittest.main()
