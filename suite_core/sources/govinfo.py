"""Identity-bound direct GovInfo text for Federal Register OPM records."""

from __future__ import annotations

import hashlib
import re
from datetime import date
from html.parser import HTMLParser

from ..privacy import redact
from . import core

TERMS_URL = "https://www.govinfo.gov/about/policies#copyright"


class _GovInfoParser(HTMLParser):
    """Collect bounded visible paragraphs and stable printed section labels."""

    _SKIP = {"script", "style", "noscript", "svg", "nav", "footer"}
    _SECTION = re.compile(r"^(DATES|ADDRESSES|SUMMARY|SUPPLEMENTARY INFORMATION):\s*(.*)$", re.I)

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.paragraphs: list[str] = []
        self.sections: dict[str, list[str]] = {}
        self._skip_depth = 0
        self._capture_tag: str | None = None
        self._capture: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in {"p", "h1", "h2", "h3", "h4", "pre"} and self._capture_tag is None:
            self._capture_tag = tag
            self._capture = []

    def handle_endtag(self, tag: str) -> None:
        if self._skip_depth:
            if tag in self._SKIP:
                self._skip_depth -= 1
            return
        if tag != self._capture_tag:
            return
        raw = "".join(self._capture)
        blocks = re.split(r"\n\s*\n", raw) if tag == "pre" else [raw]
        for block in blocks:
            text = " ".join(block.split())[:1200]
            if not text:
                continue
            self.paragraphs.append(text)
            match = self._SECTION.match(text)
            if match:
                section = match.group(1).upper()
                body = match.group(2).strip()
                if body:
                    self.sections.setdefault(section, []).append(body[:1200])
        self._capture_tag = None
        self._capture = []

    def handle_data(self, data: str) -> None:
        if self._capture_tag is not None and not self._skip_depth:
            self._capture.append(data)


def _safe_text(value: str) -> str | None:
    without_links = re.sub(r"https?://\S+", "", value).strip()
    if not without_links or re.fullmatch(r"\[\[Page\s+\d+\]\]", without_links):
        return None
    return without_links if str(redact(without_links)) == without_links else None


def document_url(metadata: core.SourceRecord) -> str:
    if type(metadata) is not core.SourceRecord or not isinstance(metadata.data, core.Mapping):
        raise core.UnverifiedSource("GovInfo text requires an admitted OPM metadata record")
    doc_id = metadata.source_id
    published = core._as_date(metadata.as_of)
    data = metadata.data
    try:
        source = core.urllib.parse.urlsplit(metadata.source_url)
        source_port = source.port
    except (TypeError, ValueError):
        source = None
        source_port = -1
    source_path = re.fullmatch(
        r"/documents/(\d{4})/(\d{2})/(\d{2})/(\d{4}-\d{4,6})(?:/[^/?#]+)?",
        source.path if source else "",
    )
    if (metadata.provider != core.Provider.FEDERAL_REGISTER_OPM.value
            or metadata.task_fit != core.TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
            or metadata.response_status != 200 or metadata.read_only is not True
            or metadata.as_of_precision != "day"
            or metadata.terms_url != core._TERMS[core.Provider.FEDERAL_REGISTER_OPM]
            or not isinstance(doc_id, str) or not re.fullmatch(r"\d{4}-\d{4,6}", doc_id)
            or not isinstance(metadata.response_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata.response_sha256)
            or source is None or source.scheme != "https"
            or source.hostname != "www.federalregister.gov"
            or source.username or source.password or source_port is not None
            or source.query or source.fragment or source_path is None
            or source_path.group(4) != doc_id
            or "-".join(source_path.group(index) for index in (1, 2, 3)) != published
            or data.get("document_number") != doc_id
            or data.get("publication_date") != published
            or data.get("agency") != "OFFICE OF PERSONNEL MANAGEMENT"
            or data.get("type") not in {"Rule", "Proposed Rule"}
            or not isinstance(data.get("title"), str) or not data.get("title")):
        raise core.UnverifiedSource("GovInfo text requires a matching OPM Rule/Proposed Rule record")
    return f"https://www.govinfo.gov/content/pkg/FR-{published}/html/{doc_id}.htm"


def fetch(metadata: core.SourceRecord, *, timeout: float = 5.0, transport=None,
          _clock=None) -> core.SourceRecord:
    """Fetch only the exact GovInfo granule matching validated FR metadata."""
    url = document_url(metadata)
    core._validate_url(url)
    seconds = core._validate_timeout(timeout)
    if transport is None:
        transport = core._UrllibTransport()
    try:
        response = transport.get(url, timeout=seconds, max_bytes=core.MAX_RESPONSE_BYTES)
    except (core.DataUnavailable, TimeoutError, OSError, core.urllib.error.URLError) as error:
        raise core.DataUnavailable("direct GovInfo document request failed") from error
    if response.status != 200:
        raise core.DataUnavailable(f"direct GovInfo document text returned HTTP {response.status}")
    if len(response.body) > core.MAX_RESPONSE_BYTES:
        raise core.DataUnavailable("GovInfo document exceeded the response byte limit")
    content_type = (core._header(response.headers, "content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != "text/html":
        raise core.DataUnavailable("GovInfo document response is not HTML")
    try:
        html = response.body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise core.DataUnavailable("GovInfo document text is not UTF-8") from error
    published = date.fromisoformat(metadata.as_of)
    date_text = f"{published.strftime('%B')} {published.day}, {published.year}"
    if (not re.search(rf"FR\s+Doc\s+No:\s*{re.escape(metadata.source_id)}\b", html, re.I)
            or date_text not in html
            or str(metadata.data["title"]) not in html):
        raise core.DataUnavailable("GovInfo document number, title, or issue date does not match the metadata record")
    parser = _GovInfoParser()
    try:
        parser.feed(html)
    except ValueError as error:
        raise core.DataUnavailable("GovInfo document HTML could not be parsed") from error
    safe_blocks = [
        text for raw in parser.paragraphs
        if (text := _safe_text(raw)) is not None
    ]
    safe_sections = {}
    for section, contents in parser.sections.items():
        safe = [text for raw in contents if (text := _safe_text(raw)) is not None][:4]
        if safe:
            safe_sections[section] = safe
    preferred = [
        text for section in ("SUMMARY", "DATES", "ADDRESSES")
        for text in safe_sections.get(section, [])
    ]
    safe_paragraphs = list(dict.fromkeys([*preferred, *safe_blocks]))[:8]
    if not safe_paragraphs:
        raise core.UnverifiedSource("GovInfo document has no safe, usable text paragraphs")
    clock = _clock or core._retrieved_at
    retrieved_at = clock()
    core._check_day_freshness(
        date.fromisoformat(metadata.as_of), retrieved_at, 90,
        "GovInfo OPM publication_date",
    )
    digest = hashlib.sha256(response.body).hexdigest()
    return core.SourceRecord(
        provider=metadata.provider,
        source_id=metadata.source_id,
        source_url=url,
        response_status=response.status,
        response_sha256=digest,
        request_body_sha256=None,
        as_of=metadata.as_of,
        as_of_precision="day",
        retrieved_at_utc=retrieved_at,
        terms_url=TERMS_URL,
        read_only=True,
        task_fit="public_opm_policy_text",
        data={
            "title": metadata.data["title"],
            "type": metadata.data["type"],
            "document_text": safe_paragraphs,
            "sections": safe_sections,
            "metadata_response_sha256": metadata.response_sha256,
            "metadata_source_url": metadata.source_url,
            "federal_register_terms_url": metadata.terms_url,
        },
    )
