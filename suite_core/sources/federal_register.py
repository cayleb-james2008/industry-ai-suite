"""Federal Register OPM metadata identity and safe projection rules."""

from __future__ import annotations

import hashlib
import re
from datetime import date

from . import core

_OPM_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:[NSEW]\. ?)?(?:[\w.'’-]+\s+){0,4}"
    r"(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|"
    r"drive|dr\.?|lane|ln\.?|court|ct\.?|way|place|pl\.?|"
    r"terrace|ter\.?|parkway|pkwy\.?|circle|cir\.?)\b",
    re.IGNORECASE,
)
_OPM_NAMED_PERSON = re.compile(
    r"\b(?:name\s*[:=]|applicant|employee|petitioner|individual|person|"
    r"for|to|mr\.?|mrs\.?|ms\.?|miss|dr\.?)\s+"
    r"[A-Z][A-Za-z'’.-]+(?:\s+[A-Z][A-Za-z'’.-]+){1,2}\b"
)
_DOCUMENT_NUMBER = re.compile(r"\d{4}-\d{4,6}\Z")
_DOCUMENT_PATH = re.compile(
    r"/documents/(\d{4})/(\d{2})/(\d{2})/(\d{4}-\d{4,6})(?:/[^/]+)?\Z"
)


def _title_contains_personal_data(title: str) -> bool:
    return bool(_OPM_STREET_ADDRESS.search(title) or _OPM_NAMED_PERSON.search(title))


def canonical_document_url(source_url: object, document_number: object, publication_date: object) -> str:
    """Validate a Federal Register document identity and discard metadata path slugs."""
    if (not isinstance(source_url, str)
            or not isinstance(document_number, str) or not _DOCUMENT_NUMBER.fullmatch(document_number)
            or not isinstance(publication_date, str)):
        raise core.DataUnavailable("Federal Register URL identity does not match its document fields")
    try:
        published = date.fromisoformat(publication_date)
    except ValueError as error:
        raise core.DataUnavailable("Federal Register URL identity does not match its document fields") from error
    if published.isoformat() != publication_date:
        raise core.DataUnavailable("Federal Register URL identity does not match its document fields")
    try:
        page = core.urllib.parse.urlsplit(source_url)
    except (TypeError, ValueError):
        page = None
    path = _DOCUMENT_PATH.fullmatch(page.path if page else "")
    if (page is None or page.scheme != "https"
            or page.netloc != "www.federalregister.gov"
            or "?" in source_url or "#" in source_url or path is None):
        raise core.DataUnavailable("Federal Register document URL is outside the official document path")
    path_date = "-".join(path.group(index) for index in (1, 2, 3))
    if path.group(4) != document_number or path_date != publication_date:
        raise core.DataUnavailable("Federal Register URL identity does not match its document fields")
    return (
        f"https://www.federalregister.gov/documents/"
        f"{publication_date.replace('-', '/')}/{document_number}"
    )


def parse(payload, source_url, response, response_hash, retrieved_at, task_fit):
    result = core._mapping(payload, "Federal Register")
    documents = core._list(result.get("results"), "Federal Register results")
    core._check_record_count(core.Provider.FEDERAL_REGISTER_OPM, len(documents))
    records = []
    for item in documents:
        row = core._mapping(item, "Federal Register document")
        document_number = row.get("document_number")
        publication_date = core._as_date(row.get("publication_date"))
        agencies = core._list(row.get("agencies"), "Federal Register agencies")
        opm = any(
            isinstance(agency, core.Mapping)
            and agency.get("id") == core._FEDERAL_REGISTER_AGENCY_ID
            and agency.get("raw_name") == "OFFICE OF PERSONNEL MANAGEMENT"
            for agency in agencies
        )
        title, kind, html_url = row.get("title"), row.get("type"), row.get("html_url")
        if (not opm or not isinstance(document_number, str)
                or not re.fullmatch(r"\d{4}-\d{4,6}", document_number)
                or not isinstance(title, str) or not isinstance(kind, str)
                or not isinstance(html_url, str)):
            raise core.DataUnavailable("Federal Register OPM document schema mismatch")
        canonical_url = canonical_document_url(html_url, document_number, publication_date)
        safe_title = None if _title_contains_personal_data(title) else title[:1000]
        data = {
            "document_number": document_number,
            "publication_date": publication_date,
            "type": kind[:100],
            "agency": "OFFICE OF PERSONNEL MANAGEMENT",
        }
        if safe_title is not None:
            data["title"] = safe_title
        record = core._record(
            core.Provider.FEDERAL_REGISTER_OPM, document_number, canonical_url,
            response, response_hash, retrieved_at,
            core._TERMS[core.Provider.FEDERAL_REGISTER_OPM], task_fit,
            publication_date, "day", data,
        )
        public_identity = dict(record.data)
        public_identity.update(
            document_number=document_number,
            publication_date=publication_date,
            html_url=canonical_url,
        )
        records.append(core.replace(record, data=public_identity))
    if not records:
        raise core.DataUnavailable("Federal Register returned no OPM documents")
    newest_publication = max(core.date.fromisoformat(record.as_of) for record in records)
    core._check_day_freshness(
        newest_publication, retrieved_at,
        core._SOURCE_MAX_AGE_DAYS[core.Provider.FEDERAL_REGISTER_OPM],
        "newest Federal Register OPM publication_date",
    )
    return tuple(records)


def fetch_text(metadata, *, timeout: float = 5.0, transport=None, _clock=None):
    """Preserve the legacy exact-record request, always with redirects refused."""
    if type(metadata) is not core.SourceRecord or not isinstance(metadata.data, core.Mapping):
        raise core.UnverifiedSource("Federal Register text requires an admitted OPM metadata record")
    data = metadata.data
    doc_id, published, url = metadata.source_id, metadata.as_of, metadata.source_url
    try:
        path = core.urllib.parse.urlsplit(url)
    except (TypeError, ValueError):
        path = None
    match = re.fullmatch(
        r"/documents/(\d{4})/(\d{2})/(\d{2})/(\d{4}-\d{4,6})(?:/[^/?#]+)?",
        path.path if path else "",
    )
    if (metadata.provider != core.Provider.FEDERAL_REGISTER_OPM.value
            or metadata.task_fit != core.TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
            or metadata.read_only is not True or metadata.response_status != 200
            or metadata.terms_url != core._TERMS[core.Provider.FEDERAL_REGISTER_OPM]
            or metadata.as_of_precision != "day"
            or data.get("agency") != "OFFICE OF PERSONNEL MANAGEMENT"
            or data.get("document_number") != doc_id
            or data.get("publication_date") != published
            or data.get("type") not in {"Rule", "Proposed Rule"}
            or not isinstance(data.get("title"), str) or not data.get("title")
            or path is None or match is None
            or path.scheme != "https" or path.netloc != "www.federalregister.gov"
            or path.query or path.fragment or match.group(4) != doc_id
            or "-".join(match.group(index) for index in (1, 2, 3)) != published):
        raise core.UnverifiedSource("Federal Register text requires a matching OPM rule record")
    core._validate_url(url)
    if transport is None:
        transport = core._UrllibTransport()
    try:
        response = transport.get(
            url, timeout=core._validate_timeout(timeout), max_bytes=core.MAX_RESPONSE_BYTES,
        )
    except (core.DataUnavailable, TimeoutError, OSError, core.urllib.error.URLError) as error:
        raise core.DataUnavailable("Federal Register document text request failed") from error
    if response.status != 200:
        raise core.DataUnavailable(f"Federal Register document text returned HTTP {response.status}")
    if len(response.body) > core.MAX_RESPONSE_BYTES:
        raise core.DataUnavailable("Federal Register document text exceeded its size limit")
    content_type = (core._header(response.headers, "content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != "text/html":
        raise core.DataUnavailable("Federal Register document text is not HTML")
    try:
        from .portfolio import PortfolioHTMLParser

        parser = PortfolioHTMLParser()
        parser.feed(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise core.DataUnavailable("Federal Register document text is invalid UTF-8 HTML") from error
    paragraphs = [
        text for raw in parser.paragraphs
        if (text := str(core.redact(raw))) == raw
    ][:8]
    if not parser.title or not paragraphs:
        raise core.UnverifiedSource("Federal Register rule page has no safe, usable text paragraphs")
    clock = _clock or core._retrieved_at
    retrieved_at = clock()
    core._check_day_freshness(
        date.fromisoformat(published), retrieved_at, 90,
        "Federal Register OPM rule publication_date",
    )
    return core.SourceRecord(
        provider=metadata.provider, source_id=doc_id, source_url=url,
        response_status=response.status,
        response_sha256=hashlib.sha256(response.body).hexdigest(),
        request_body_sha256=None, as_of=published, as_of_precision="day",
        retrieved_at_utc=retrieved_at, terms_url=metadata.terms_url,
        read_only=True, task_fit="public_opm_policy_text",
        data={
            "title": data["title"], "type": data["type"],
            "document_text": paragraphs,
            "metadata_response_sha256": metadata.response_sha256,
        },
    )
