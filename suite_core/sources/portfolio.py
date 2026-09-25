"""Bounded visible-text projection for the exact owned portfolio page."""

from __future__ import annotations

from datetime import timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

from . import core

MAX_PROJECTED_HEADINGS = 20
MAX_PROJECTED_PARAGRAPHS = 30
MAX_PROJECTED_TEXT_CHARS = 1000
MAX_PRIORITY_SUITE_HEADINGS = MAX_PROJECTED_HEADINGS // 2
HEADING_TAGS = {"h1", "h2", "h3", "h4"}


class PortfolioHTMLParser(HTMLParser):
    """Extract bounded visible text only; never return markup or link targets."""

    _SKIP = {"script", "style", "noscript", "svg", "nav", "footer"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self._suite_headings: list[str] = []
        self._page_headings: list[str] = []
        self.paragraphs: list[str] = []
        self._section_stack: list[bool] = []
        self._suite_id_count = 0
        self._suite_section_count = 0
        self._suite_section_closed = False
        self._section_error: str | None = None
        self._capture_tag: str | None = None
        self._capture: list[str] = []
        self._capture_is_suite_h4 = False
        self._skip_depth = 0
        self._in_head = False

    @property
    def section_error(self) -> str | None:
        if self._section_error:
            return self._section_error
        if self._section_stack:
            return "portfolio section nesting is unclosed; suite heading priority is unverified"
        if self._suite_section_count and not self._suite_section_closed:
            return "portfolio suite section is unclosed; suite heading priority is unverified"
        return None

    @property
    def _suite_boundary_is_valid(self) -> bool:
        return (
            self._suite_id_count == 1
            and self._suite_section_count == 1
            and self._suite_section_closed
            and self.section_error is None
        )

    @property
    def headings(self) -> list[str]:
        """Prioritize suite h4 text, then fill the unchanged heading budget."""
        suite_headings = self._suite_headings if self._suite_boundary_is_valid else []
        remaining = MAX_PROJECTED_HEADINGS - len(suite_headings)
        return suite_headings + self._page_headings[:remaining]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "section" and self._capture_tag == "h4" and self._capture_is_suite_h4:
            self._section_error = (
                "portfolio section started during an open suite h4; "
                "suite heading priority is unverified"
            )
            self._capture_tag = None
            self._capture = []
            self._capture_is_suite_h4 = False
        attributes = dict(attrs)
        if attributes.get("id") == "suite":
            self._suite_id_count += 1
            if self._suite_id_count > 1:
                self._section_error = (
                    'portfolio suite section id="suite" is duplicated; '
                    "suite heading priority is unverified"
                )
        if tag == "section":
            is_suite = attributes.get("id") == "suite"
            if is_suite:
                self._suite_section_count += 1
            self._section_stack.append(is_suite or any(self._section_stack))
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "head":
            self._in_head = True
            return
        if (tag == "meta" and self._in_head
                and attributes.get("name", "").lower() == "description"):
            value = attributes.get("content")
            if value:
                self.description = value.strip()[:MAX_PROJECTED_TEXT_CHARS]
        elif (self._capture_tag is None
              and (tag in HEADING_TAGS or tag == "p"
                   or tag == "title" and self._in_head)):
            self._capture_tag = tag
            self._capture = []
            self._capture_is_suite_h4 = (
                tag == "h4"
                and bool(self._section_stack and self._section_stack[-1])
            )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "section":
            self._section_error = (
                "portfolio section uses a malformed self-closing tag; "
                "suite heading priority is unverified"
            )
        super().handle_startendtag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "section":
            if self._capture_tag == "h4" and self._capture_is_suite_h4:
                self._section_error = (
                    "portfolio section closed during an open suite h4; "
                    "suite heading priority is unverified"
                )
                self._capture_tag = None
                self._capture = []
                self._capture_is_suite_h4 = False
            if self._section_stack:
                was_in_suite = self._section_stack.pop()
                if was_in_suite and not any(self._section_stack):
                    self._suite_section_closed = True
            else:
                self._section_error = (
                    "portfolio section end tag has no matching open section; "
                    "suite heading priority is unverified"
                )
        if self._skip_depth:
            if tag in self._SKIP:
                self._skip_depth -= 1
            return
        if tag == "head":
            self._in_head = False
            return
        if tag != self._capture_tag:
            return
        text = " ".join("".join(self._capture).split())[:MAX_PROJECTED_TEXT_CHARS]
        if text and tag == "title":
            self.title = text
        elif text and tag in HEADING_TAGS:
            if self._capture_is_suite_h4:
                if len(self._suite_headings) < MAX_PRIORITY_SUITE_HEADINGS:
                    self._suite_headings.append(text)
            elif len(self._page_headings) < MAX_PROJECTED_HEADINGS:
                self._page_headings.append(text)
        elif text and tag == "p" and len(self.paragraphs) < MAX_PROJECTED_PARAGRAPHS:
            self.paragraphs.append(text)
        self._capture_tag = None
        self._capture = []
        self._capture_is_suite_h4 = False

    def handle_data(self, data: str) -> None:
        if self._capture_tag is not None and not self._skip_depth:
            self._capture.append(data)


def parse(body, source_url, response, response_hash, retrieved_at, task_fit):
    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise core.DataUnavailable("portfolio response is not valid UTF-8 HTML") from error
    parser = PortfolioHTMLParser()
    parser.feed(html)
    if parser.section_error:
        raise core.UnverifiedSource(parser.section_error)
    if not parser.title or not (parser.headings or parser.paragraphs):
        raise core.DataUnavailable("portfolio HTML is missing safe visible content")
    modified = core._header(response.headers, "Last-Modified")
    if modified is None:
        raise core.UnverifiedSource("portfolio response has no source-provided Last-Modified value")
    try:
        modified_at = parsedate_to_datetime(modified)
    except (TypeError, ValueError, OverflowError) as error:
        raise core.DataUnavailable("portfolio Last-Modified header is invalid") from error
    if modified_at.tzinfo is None:
        raise core.DataUnavailable("portfolio Last-Modified header has no timezone")
    as_of = modified_at.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    core._check_timestamp_freshness(
        as_of, retrieved_at,
        core._SOURCE_MAX_AGE_DAYS[core.Provider.OWN_PORTFOLIO_HTML],
        "portfolio Last-Modified",
    )
    return (core._record(
        core.Provider.OWN_PORTFOLIO_HTML,
        "cayleb-james2008.github.io:/agentic-resume/", source_url, response,
        response_hash, retrieved_at, core._TERMS[core.Provider.OWN_PORTFOLIO_HTML],
        task_fit, as_of, "second",
        {
            "title": parser.title,
            "description": parser.description,
            "headings": parser.headings,
            "paragraphs": parser.paragraphs,
        },
    ),)
