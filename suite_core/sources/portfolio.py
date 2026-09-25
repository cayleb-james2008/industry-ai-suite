"""Bounded visible-text projection for the exact owned portfolio page."""

from __future__ import annotations

from datetime import timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

from . import core


class PortfolioHTMLParser(HTMLParser):
    """Extract bounded visible text only; never return markup or link targets."""

    _SKIP = {"script", "style", "noscript", "svg", "nav", "footer"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self.headings: list[str] = []
        self.paragraphs: list[str] = []
        self._capture_tag: str | None = None
        self._capture: list[str] = []
        self._skip_depth = 0
        self._in_head = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "head":
            self._in_head = True
            return
        attributes = dict(attrs)
        if (tag == "meta" and self._in_head
                and attributes.get("name", "").lower() == "description"):
            value = attributes.get("content")
            if value:
                self.description = value.strip()[:1000]
        elif (self._capture_tag is None
              and (tag in {"h1", "h2", "h3", "p"}
                   or tag == "title" and self._in_head)):
            self._capture_tag = tag
            self._capture = []

    def handle_endtag(self, tag: str) -> None:
        if self._skip_depth:
            if tag in self._SKIP:
                self._skip_depth -= 1
            return
        if tag == "head":
            self._in_head = False
            return
        if tag != self._capture_tag:
            return
        text = " ".join("".join(self._capture).split())[:1000]
        if text and tag == "title":
            self.title = text
        elif text and tag in {"h1", "h2", "h3"} and len(self.headings) < 20:
            self.headings.append(text)
        elif text and tag == "p" and len(self.paragraphs) < 30:
            self.paragraphs.append(text)
        self._capture_tag = None
        self._capture = []

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
        "agentic-resume-nine.vercel.app:/", source_url, response,
        response_hash, retrieved_at, core._TERMS[core.Provider.OWN_PORTFOLIO_HTML],
        task_fit, as_of, "second",
        {
            "title": parser.title,
            "description": parser.description,
            "headings": parser.headings,
            "paragraphs": parser.paragraphs,
        },
    ),)
