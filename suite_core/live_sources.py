"""Fail-closed, read-only adapters for a small allowlist of public sources.

`fetch_live` always uses the real HTTPS transport. Tests may exercise the
private parser boundary with explicitly adversarial stub transports; callers
cannot supply URLs, HTTP methods, headers, or a transport.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from html.parser import HTMLParser
from typing import Protocol

from .privacy import redact

MAX_RESPONSE_BYTES = 2_000_000
MAX_TIMEOUT_SECONDS = 8.0
_GITHUB_API = "https://api.github.com"
_PORTFOLIO_URL = "https://agentic-resume-nine.vercel.app/"
_WORLD_BANK_TERMS_URL = "https://data.worldbank.org/indicator/NY.GDP.MKTP.CD"
_FEDERAL_REGISTER_AGENCY_ID = 406
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


class Provider(str, Enum):
    TREASURY_DTS = "treasury_dts"
    CISA_KEV = "cisa_kev"
    WORLD_BANK_USA_GDP = "world_bank_usa_gdp"
    OWN_PORTFOLIO_HTML = "own_portfolio_html"
    FEDERAL_REGISTER_OPM = "federal_register_opm"
    GITHUB_REPOSITORY = "github_repository"
    GITHUB_README = "github_readme"
    GITHUB_ADVISORIES = "github_advisories"


class TaskFit(str, Enum):
    PUBLIC_TREASURY_CASH = "public_treasury_cash_reporting"
    PUBLIC_KEV_CONTEXT = "public_kev_vulnerability_context"
    PUBLIC_US_GDP = "public_us_annual_gdp"
    OWN_PORTFOLIO_CONTENT = "own_public_portfolio_content"
    PUBLIC_OPM_POLICY_DOCUMENTS = "public_opm_policy_documents"
    PUBLIC_REPOSITORY_METADATA = "public_repository_metadata"
    PUBLIC_REPOSITORY_README = "public_repository_readme_review"
    PUBLIC_REPOSITORY_ADVISORIES = "public_repository_advisory_context"


_RECORD_COUNT_BOUNDS = {
    Provider.TREASURY_DTS: (1, 100),
    Provider.CISA_KEV: (1721, 5000),
    Provider.WORLD_BANK_USA_GDP: (1, 100),
    Provider.OWN_PORTFOLIO_HTML: (1, 1),
    Provider.FEDERAL_REGISTER_OPM: (1, 100),
    Provider.GITHUB_REPOSITORY: (1, 1),
}

_SOURCE_MAX_AGE_DAYS = {
    Provider.TREASURY_DTS: 14,
    Provider.CISA_KEV: 60,
    Provider.OWN_PORTFOLIO_HTML: 30,
    Provider.FEDERAL_REGISTER_OPM: 90,
    Provider.GITHUB_REPOSITORY: 365,
}
_GDP_STALE_YEAR_LAG = 2
_SOURCE_CLOCK_SKEW = timedelta(minutes=5)


_FIT_BY_PROVIDER = {
    Provider.TREASURY_DTS: TaskFit.PUBLIC_TREASURY_CASH,
    Provider.CISA_KEV: TaskFit.PUBLIC_KEV_CONTEXT,
    Provider.WORLD_BANK_USA_GDP: TaskFit.PUBLIC_US_GDP,
    Provider.OWN_PORTFOLIO_HTML: TaskFit.OWN_PORTFOLIO_CONTENT,
    Provider.FEDERAL_REGISTER_OPM: TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
    Provider.GITHUB_REPOSITORY: TaskFit.PUBLIC_REPOSITORY_METADATA,
    Provider.GITHUB_README: TaskFit.PUBLIC_REPOSITORY_README,
    Provider.GITHUB_ADVISORIES: TaskFit.PUBLIC_REPOSITORY_ADVISORIES,
}


class LiveSourceError(RuntimeError):
    """Base class for source errors with a stable machine-readable status."""

    status = "UNVERIFIED"


class DataUnavailable(LiveSourceError):
    """The live endpoint failed, exceeded bounds, or returned an invalid schema."""

    status = "DATA_UNAVAILABLE"


class UnverifiedSource(LiveSourceError):
    """The response exists but terms, as-of data, or fit are not established."""

    status = "UNVERIFIED"


@dataclass(frozen=True)
class SourceRecord:
    provider: str
    source_id: str
    source_url: str
    response_status: int
    response_sha256: str
    request_body_sha256: str | None
    as_of: str
    as_of_precision: str
    retrieved_at_utc: str
    terms_url: str
    read_only: bool
    task_fit: str
    data: Mapping[str, object]


@dataclass(frozen=True)
class SourceResult:
    provider: str
    status: str
    request_url: str
    response_status: int
    response_sha256: str
    request_body_sha256: str | None
    retrieved_at_utc: str
    task_fit: str
    records: tuple[SourceRecord, ...]
    reason: str | None = None
    read_only: bool = True


@dataclass(frozen=True)
class _HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class _Transport(Protocol):
    def get(self, url: str, *, timeout: float, max_bytes: int) -> _HTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _UrllibTransport:
    """Real HTTPS GET transport with proxies and redirects disabled."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def get(self, url: str, *, timeout: float, max_bytes: int) -> _HTTPResponse:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/html;q=0.9",
                "User-Agent": "industry-ai-suite-read-only/1.0",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                length = response.headers.get("Content-Length")
                if length:
                    try:
                        declared_length = int(length)
                    except ValueError as error:
                        raise DataUnavailable("source returned an invalid content length") from error
                    if declared_length < 0:
                        raise DataUnavailable("source returned an invalid content length")
                    if declared_length > max_bytes:
                        raise DataUnavailable("source response exceeds the byte limit")
                body = response.read(max_bytes + 1)
                return _HTTPResponse(response.status, dict(response.headers.items()), body)
        except urllib.error.HTTPError as error:
            return _HTTPResponse(error.code, dict(error.headers.items()), b"")


_ALLOWED_PATHS = {
    "api.fiscaldata.treasury.gov": re.compile(
        r"^/services/api/fiscal_service/v1/accounting/dts/deposits_withdrawals_operating_cash$"
    ),
    "www.cisa.gov": re.compile(
        r"^/sites/default/files/feeds/known_exploited_vulnerabilities\.json$"
    ),
    "api.worldbank.org": re.compile(r"^/v2/country/USA/indicator/NY\.GDP\.MKTP\.CD$"),
    "data.worldbank.org": re.compile(r"^/indicator/NY\.GDP\.MKTP\.CD$"),
    "agentic-resume-nine.vercel.app": re.compile(r"^/$"),
    "www.federalregister.gov": re.compile(r"^/api/v1/documents\.json$"),
    "api.github.com": re.compile(
        r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/readme|/security/advisories)?$"
    ),
}

_TERMS = {
    Provider.TREASURY_DTS: "https://fiscaldata.treasury.gov/api-documentation/",
    Provider.CISA_KEV: "https://creativecommons.org/publicdomain/zero/1.0/",
    Provider.WORLD_BANK_USA_GDP: _WORLD_BANK_TERMS_URL,
    Provider.OWN_PORTFOLIO_HTML: "https://api.github.com/licenses/mit",
    Provider.FEDERAL_REGISTER_OPM: "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site",
}


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a finite number greater than 0 and at most 8 seconds")
    try:
        seconds = float(timeout)
    except OverflowError as error:
        raise ValueError("timeout must be a finite number greater than 0 and at most 8 seconds") from error
    if not math.isfinite(seconds) or not 0 < seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError("timeout must be a finite number greater than 0 and at most 8 seconds")
    return seconds


def _github_path(provider: Provider, owner: str, repo: str) -> str:
    segment = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
    if (not isinstance(owner, str) or not isinstance(repo, str)
            or not segment.fullmatch(owner) or not segment.fullmatch(repo)
            or owner in {".", ".."} or repo in {".", ".."}):
        raise UnverifiedSource("GitHub owner/repository is not a single safe path segment")
    suffix = {
        Provider.GITHUB_REPOSITORY: "",
        Provider.GITHUB_README: "/readme",
        Provider.GITHUB_ADVISORIES: "/security/advisories",
    }[provider]
    return f"/repos/{owner}/{repo}{suffix}"


def _request_url(provider: Provider, owner: str | None, repo: str | None) -> str:
    if provider is Provider.TREASURY_DTS:
        base = "https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/dts/deposits_withdrawals_operating_cash"
        query = urllib.parse.urlencode([("page[size]", "10"), ("sort", "-record_date")])
        return f"{base}?{query}"
    if provider is Provider.CISA_KEV:
        return "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    if provider is Provider.WORLD_BANK_USA_GDP:
        return "https://api.worldbank.org/v2/country/USA/indicator/NY.GDP.MKTP.CD?format=json&per_page=15"
    if provider is Provider.OWN_PORTFOLIO_HTML:
        return _PORTFOLIO_URL
    if provider is Provider.FEDERAL_REGISTER_OPM:
        query = urllib.parse.urlencode([
            ("conditions[agency_ids][]", str(_FEDERAL_REGISTER_AGENCY_ID)),
            ("per_page", "10"),
            ("order", "newest"),
        ])
        return f"https://www.federalregister.gov/api/v1/documents.json?{query}"
    if owner is None or repo is None:
        raise UnverifiedSource("GitHub providers require explicit owner and repository")
    path = _github_path(provider, owner, repo)
    query = "?per_page=5" if provider is Provider.GITHUB_ADVISORIES else ""
    return f"{_GITHUB_API}{path}{query}"


def _validate_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    allowed = _ALLOWED_PATHS.get(parsed.hostname or "")
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port
            or parsed.fragment or allowed is None or not allowed.fullmatch(parsed.path)):
        raise DataUnavailable("request URL is outside the fixed HTTPS host/path allowlist")


def _as_date(value: object) -> str:
    if not isinstance(value, str):
        raise UnverifiedSource("source did not provide an as-of date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise DataUnavailable("source date does not match the provider schema") from error
    if parsed.isoformat() != value:
        raise DataUnavailable("source date does not match the provider schema")
    return value


def _as_year(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}", value):
        if value is None:
            raise UnverifiedSource("source did not provide an as-of year")
        raise DataUnavailable("source year does not match the provider schema")
    return value


def _check_record_count(provider: Provider, count: int) -> None:
    bounds = _RECORD_COUNT_BOUNDS.get(provider)
    if bounds is None:
        return
    minimum, maximum = bounds
    if not minimum <= count <= maximum:
        raise DataUnavailable("source record count is outside the provider bound")


def _validate_record_set(
    provider: Provider, records: tuple[SourceRecord, ...]
) -> tuple[SourceRecord, ...]:
    _check_record_count(provider, len(records))
    source_ids = [record.source_id for record in records]
    if len(source_ids) != len(set(source_ids)):
        raise DataUnavailable("source returned duplicate stable record identifiers")
    return records


def _world_bank_license_is_cc_by_4(body: bytes) -> bool:
    try:
        page = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    license_block = re.search(
        r"<div\b(?=[^>]*\bclass=['\"][^'\"]*\blicense\b[^'\"]*['\"])[^>]*>(.*?)</div>",
        page,
        re.IGNORECASE | re.DOTALL,
    )
    if not license_block:
        return False
    text = html_lib.unescape(re.sub(r"<[^>]*>", " ", license_block.group(1)))
    return re.search(r"\bLicense\s*:\s*CC BY-4\.0\b", text, re.IGNORECASE) is not None


def _opm_title_contains_personal_data(title: str) -> bool:
    return bool(_OPM_STREET_ADDRESS.search(title) or _OPM_NAMED_PERSON.search(title))


def _as_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise UnverifiedSource("source did not provide an as-of timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DataUnavailable("source timestamp does not match the provider schema") from error
    if parsed.tzinfo is None:
        raise DataUnavailable("source timestamp has no timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _retrieval_time(retrieved_at: str) -> datetime:
    return datetime.fromisoformat(retrieved_at.replace("Z", "+00:00")).astimezone(timezone.utc)


def _check_day_freshness(
    source_as_of: date, retrieved_at: str, max_age_days: int, source_field: str
) -> None:
    today = _retrieval_time(retrieved_at).date()
    if source_as_of > today:
        raise DataUnavailable(f"{source_field} is later than the current UTC date")
    if (today - source_as_of).days > max_age_days:
        raise UnverifiedSource(f"{source_field} is older than {max_age_days} days")


def _check_timestamp_freshness(
    source_as_of: str, retrieved_at: str, max_age_days: int, source_field: str
) -> None:
    as_of = datetime.fromisoformat(source_as_of.replace("Z", "+00:00")).astimezone(timezone.utc)
    age = _retrieval_time(retrieved_at) - as_of
    if age < -_SOURCE_CLOCK_SKEW:
        raise DataUnavailable(f"{source_field} is later than the allowed clock skew")
    if age > timedelta(days=max_age_days):
        raise UnverifiedSource(f"{source_field} is older than {max_age_days} days")


def _check_gdp_freshness(years: list[int], retrieved_at: str) -> None:
    current_year = _retrieval_time(retrieved_at).year
    newest_year = max(years)
    if newest_year > current_year:
        raise DataUnavailable("newest World Bank GDP year is later than the current UTC year")
    if newest_year <= current_year - _GDP_STALE_YEAR_LAG:
        raise UnverifiedSource(
            "newest World Bank GDP year is at least two years behind the current UTC year"
        )


def _retrieved_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DataUnavailable(f"{label} response schema mismatch")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise DataUnavailable(f"{label} response schema mismatch")
    return value


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


class _PortfolioHTMLParser(HTMLParser):
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


def _parse_portfolio(
    body: bytes,
    source_url: str,
    response: _HTTPResponse,
    response_hash: str,
    retrieved_at: str,
    task_fit: TaskFit,
) -> tuple[SourceRecord, ...]:
    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DataUnavailable("portfolio response is not valid UTF-8 HTML") from error
    parser = _PortfolioHTMLParser()
    parser.feed(html)
    if not parser.title or not (parser.headings or parser.paragraphs):
        raise DataUnavailable("portfolio HTML is missing safe visible content")
    modified = _header(response.headers, "Last-Modified")
    if modified is None:
        raise UnverifiedSource("portfolio response has no source-provided Last-Modified value")
    try:
        modified_at = parsedate_to_datetime(modified)
    except (TypeError, ValueError, OverflowError) as error:
        raise DataUnavailable("portfolio Last-Modified header is invalid") from error
    if modified_at.tzinfo is None:
        raise DataUnavailable("portfolio Last-Modified header has no timezone")
    modified_at = modified_at.astimezone(timezone.utc)
    as_of = modified_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    _check_timestamp_freshness(
        as_of,
        retrieved_at,
        _SOURCE_MAX_AGE_DAYS[Provider.OWN_PORTFOLIO_HTML],
        "portfolio Last-Modified",
    )
    return (_record(
        Provider.OWN_PORTFOLIO_HTML,
        "agentic-resume-nine.vercel.app:/",
        source_url,
        response,
        response_hash,
        retrieved_at,
        _TERMS[Provider.OWN_PORTFOLIO_HTML],
        task_fit,
        as_of,
        "second",
        {
            "title": parser.title,
            "description": parser.description,
            "headings": parser.headings,
            "paragraphs": parser.paragraphs,
        },
    ),)


def _parse_federal_register(
    payload: object,
    source_url: str,
    response: _HTTPResponse,
    response_hash: str,
    retrieved_at: str,
    task_fit: TaskFit,
) -> tuple[SourceRecord, ...]:
    result = _mapping(payload, "Federal Register")
    documents = _list(result.get("results"), "Federal Register results")
    _check_record_count(Provider.FEDERAL_REGISTER_OPM, len(documents))
    records: list[SourceRecord] = []
    for item in documents:
        row = _mapping(item, "Federal Register document")
        document_number = row.get("document_number")
        publication_date = _as_date(row.get("publication_date"))
        agencies = _list(row.get("agencies"), "Federal Register agencies")
        opm = any(
            isinstance(agency, Mapping)
            and agency.get("id") == _FEDERAL_REGISTER_AGENCY_ID
            and agency.get("raw_name") == "OFFICE OF PERSONNEL MANAGEMENT"
            for agency in agencies
        )
        title, kind, html_url = row.get("title"), row.get("type"), row.get("html_url")
        if (not opm or not isinstance(document_number, str)
                or not re.fullmatch(r"\d{4}-\d{4,6}", document_number)
                or not isinstance(title, str) or not isinstance(kind, str)
                or not isinstance(html_url, str)):
            raise DataUnavailable("Federal Register OPM document schema mismatch")
        page = urllib.parse.urlsplit(html_url)
        try:
            page_port = page.port
        except ValueError:
            page_port = -1
        path = re.fullmatch(
            r"/documents/(\d{4})/(\d{2})/(\d{2})/(\d{4}-\d{4,6})(?:/[^/]+)?",
            page.path,
        )
        if (page.scheme != "https" or page.hostname != "www.federalregister.gov"
                or page.username or page.password or page_port is not None
                or page.query or page.fragment
                or path is None):
            raise DataUnavailable("Federal Register document URL is outside the official document path")
        path_date = "-".join(path.group(index) for index in (1, 2, 3))
        if path.group(4) != document_number or path_date != publication_date:
            raise DataUnavailable("Federal Register URL identity does not match its document fields")
        safe_title = None if _opm_title_contains_personal_data(title) else title[:1000]
        data = {
            "document_number": document_number,
            "publication_date": publication_date,
            "type": kind[:100],
            "html_url": html_url,
            "agency": "OFFICE OF PERSONNEL MANAGEMENT",
        }
        if safe_title is not None:
            data["title"] = safe_title
        record = _record(
            Provider.FEDERAL_REGISTER_OPM,
            document_number,
            html_url,
            response,
            response_hash,
            retrieved_at,
            _TERMS[Provider.FEDERAL_REGISTER_OPM],
            task_fit,
            publication_date,
            "day",
            data,
        )
        public_identity = dict(record.data)
        public_identity.update(
            document_number=document_number,
            publication_date=publication_date,
        )
        records.append(replace(record, data=public_identity))
    if not records:
        raise DataUnavailable("Federal Register returned no OPM documents")
    newest_publication = max(date.fromisoformat(record.as_of) for record in records)
    _check_day_freshness(
        newest_publication,
        retrieved_at,
        _SOURCE_MAX_AGE_DAYS[Provider.FEDERAL_REGISTER_OPM],
        "newest Federal Register OPM publication_date",
    )
    return tuple(records)


def _record(
    provider: Provider,
    source_id: object,
    source_url: str,
    response: _HTTPResponse,
    response_hash: str,
    retrieved_at: str,
    terms_url: str | None,
    task_fit: TaskFit,
    as_of: str,
    precision: str,
    data: Mapping[str, object],
) -> SourceRecord:
    if not isinstance(source_id, (str, int)) or not str(source_id).strip():
        raise DataUnavailable("source record has no stable identifier")
    if not terms_url:
        raise UnverifiedSource("source terms/license URL is missing")
    return SourceRecord(
        provider=provider.value,
        source_id=str(source_id),
        source_url=source_url,
        response_status=response.status,
        response_sha256=response_hash,
        request_body_sha256=None,
        as_of=as_of,
        as_of_precision=precision,
        retrieved_at_utc=retrieved_at,
        terms_url=terms_url,
        read_only=True,
        task_fit=task_fit.value,
        data=redact(data),  # type: ignore[arg-type]
    )


def _parse(
    provider: Provider,
    body: bytes,
    source_url: str,
    response: _HTTPResponse,
    response_hash: str,
    retrieved_at: str,
    task_fit: TaskFit,
    owner: str | None = None,
    repo: str | None = None,
) -> tuple[SourceRecord, ...]:
    if provider is Provider.OWN_PORTFOLIO_HTML:
        return _parse_portfolio(body, source_url, response, response_hash, retrieved_at, task_fit)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DataUnavailable("source response is not valid UTF-8 JSON") from error

    records: list[SourceRecord] = []
    if provider is Provider.TREASURY_DTS:
        data = _list(_mapping(payload, "Treasury").get("data"), "Treasury data")
        _check_record_count(provider, len(data))
        terms = _TERMS[provider]
        for row_value in data:
            row = _mapping(row_value, "Treasury record")
            record_date = _as_date(row.get("record_date"))
            table = row.get("table_nbr")
            line = row.get("src_line_nbr", row.get("source_line_nbr", row.get("line_nbr")))
            if table is None or line is None:
                raise DataUnavailable("Treasury record is missing its stable row identity")
            records.append(_record(
                provider, f"{record_date}:{table}:{line}", source_url, response,
                response_hash, retrieved_at, terms, task_fit, record_date, "day", row,
            ))
        newest_date = max(date.fromisoformat(record.as_of) for record in records)
        _check_day_freshness(
            newest_date,
            retrieved_at,
            _SOURCE_MAX_AGE_DAYS[provider],
            "newest Treasury record_date",
        )
    elif provider is Provider.CISA_KEV:
        catalog = _mapping(payload, "CISA KEV")
        vulnerabilities = _list(catalog.get("vulnerabilities"), "CISA vulnerabilities")
        _check_record_count(provider, len(vulnerabilities))
        for item in vulnerabilities:
            row = _mapping(item, "CISA vulnerability")
            cve = row.get("cveID")
            date_added = _as_date(row.get("dateAdded"))
            due_date = _as_date(row.get("dueDate"))
            if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,8}", cve):
                raise DataUnavailable("CISA record is missing a valid CVE identifier")
            record = _record(
                provider, cve, source_url, response, response_hash, retrieved_at,
                _TERMS[provider], task_fit, date_added, "day", row,
            )
            projected_data = dict(record.data)
            projected_data.update(dateAdded=date_added, dueDate=due_date)
            records.append(replace(record, data=projected_data))
        newest_added = max(date.fromisoformat(record.as_of) for record in records)
        _check_day_freshness(
            newest_added,
            retrieved_at,
            _SOURCE_MAX_AGE_DAYS[provider],
            "newest CISA dateAdded",
        )
    elif provider is Provider.WORLD_BANK_USA_GDP:
        if not isinstance(payload, list) or len(payload) != 2:
            raise DataUnavailable("World Bank response schema mismatch")
        observations = _list(payload[1], "World Bank observations")
        _check_record_count(provider, len(observations))
        for item in observations:
            row = _mapping(item, "World Bank observation")
            country = _mapping(row.get("country"), "World Bank country")
            indicator = _mapping(row.get("indicator"), "World Bank indicator")
            if row.get("countryiso3code") != "USA" or indicator.get("id") != "NY.GDP.MKTP.CD":
                raise DataUnavailable("World Bank observation is not the requested USA GDP indicator")
            year = _as_year(row.get("date"))
            records.append(_record(
                provider, f"USA:NY.GDP.MKTP.CD:{year}", source_url, response,
                response_hash, retrieved_at, _TERMS[provider], task_fit, year,
                "year", row,
            ))
        _check_gdp_freshness(
            [int(record.as_of) for record in records], retrieved_at
        )
    elif provider is Provider.FEDERAL_REGISTER_OPM:
        return _parse_federal_register(
            payload, source_url, response, response_hash, retrieved_at, task_fit
        )
    elif provider is Provider.GITHUB_REPOSITORY:
        row = _mapping(payload, "GitHub repository")
        repo_id = row.get("id")
        full_name = row.get("full_name")
        if type(repo_id) is not int or not isinstance(full_name, str):
            raise DataUnavailable("GitHub repository identity schema mismatch")
        if (owner is None or repo is None
                or full_name.casefold() != f"{owner}/{repo}".casefold()):
            raise UnverifiedSource("GitHub repository identity does not match the requested object")
        updated_at = _as_timestamp(row.get("updated_at"))
        _check_timestamp_freshness(
            updated_at,
            retrieved_at,
            _SOURCE_MAX_AGE_DAYS[provider],
            "GitHub repository updated_at",
        )
        license_info = row.get("license")
        if not isinstance(license_info, Mapping):
            raise UnverifiedSource("GitHub repository has no verified content license")
        spdx = license_info.get("spdx_id")
        license_url = license_info.get("url")
        if (not isinstance(spdx, str) or spdx in {"NOASSERTION", "OTHER"}
                or not isinstance(license_url, str)):
            raise UnverifiedSource("GitHub repository license is missing or ambiguous")
        license_key = license_info.get("key")
        if license_key is not None and license_key != spdx.lower():
            raise UnverifiedSource("GitHub license key does not match its SPDX identifier")
        _validate_github_license_url(license_url, spdx)
        projection = {
            key: row.get(key)
            for key in ("id", "full_name", "html_url", "default_branch", "license")
            if key in row
        }
        records.append(_record(
            provider, repo_id, source_url, response, response_hash, retrieved_at,
            license_url, task_fit, updated_at, "second", projection,
        ))
    elif provider is Provider.GITHUB_README:
        readme = _mapping(payload, "GitHub README")
        if (not isinstance(readme.get("path"), str)
                or not isinstance(readme.get("sha"), str)
                or not isinstance(readme.get("encoding"), str)
                or not isinstance(readme.get("content"), str)):
            raise DataUnavailable("GitHub README response schema mismatch")
        # The README endpoint identifies a blob SHA but does not supply its
        # timestamp or a per-file license. Do not borrow repo-level timestamps.
        raise UnverifiedSource("GitHub README response has no file-specific as-of timestamp and license proof")
    elif provider is Provider.GITHUB_ADVISORIES:
        advisories = _list(payload, "GitHub advisories")
        for item in advisories:
            advisory = _mapping(item, "GitHub advisory")
            if not isinstance(advisory.get("ghsa_id"), str):
                raise DataUnavailable("GitHub advisory response schema mismatch")
            _as_timestamp(advisory.get("updated_at"))
        # Repository licenses do not automatically establish advisory-text rights.
        raise UnverifiedSource("GitHub advisory response has no verified content-use terms")

    if not records:
        raise DataUnavailable("source returned no records matching the fixed query")
    return tuple(records)


def _validate_github_license_url(url: str, spdx_id: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (parsed.scheme != "https" or parsed.hostname != "api.github.com"
            or port is not None
            or parsed.path != f"/licenses/{spdx_id.lower()}"
            or not re.fullmatch(r"[A-Za-z0-9.+-]+", spdx_id)
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise UnverifiedSource("GitHub license URL does not match its SPDX identifier")


def _unverified_result(
    provider: Provider,
    request_url: str,
    response_status: int,
    response_hash: str,
    task_fit: TaskFit,
    reason: str,
) -> SourceResult:
    return SourceResult(
        provider=provider.value,
        status="UNVERIFIED",
        request_url=request_url,
        response_status=response_status,
        response_sha256=response_hash,
        request_body_sha256=None,
        retrieved_at_utc=_retrieved_at(),
        task_fit=task_fit.value,
        records=(),
        reason=reason,
    )


def _fetch_with_transport(
    provider: Provider,
    *,
    task_fit: TaskFit | None,
    owner: str | None,
    repo: str | None,
    timeout: float,
    transport: _Transport,
) -> SourceResult:
    if not isinstance(provider, Provider):
        raise UnverifiedSource("provider must be one of the fixed Provider values")
    if task_fit is not _FIT_BY_PROVIDER[provider]:
        raise UnverifiedSource("task-fit is missing or does not match the fixed provider use")
    seconds = _validate_timeout(timeout)
    url = _request_url(provider, owner, repo)
    _validate_url(url)
    if provider is Provider.WORLD_BANK_USA_GDP:
        terms_url = _TERMS[provider]
        _validate_url(terms_url)
        try:
            terms_response = transport.get(
                terms_url, timeout=seconds, max_bytes=MAX_RESPONSE_BYTES
            )
        except (DataUnavailable, TimeoutError, OSError, urllib.error.URLError):
            return _unverified_result(
                provider, terms_url, 0, "", task_fit,
                "World Bank dataset-specific license page could not be fetched",
            )
        terms_hash = hashlib.sha256(terms_response.body).hexdigest()
        terms_type = next(
            (value for key, value in terms_response.headers.items()
             if key.lower() == "content-type"),
            "",
        ).split(";", 1)[0].strip().lower()
        if (terms_response.status != 200 or len(terms_response.body) > MAX_RESPONSE_BYTES
                or terms_type != "text/html"
                or not _world_bank_license_is_cc_by_4(terms_response.body)):
            return _unverified_result(
                provider, terms_url, terms_response.status, terms_hash, task_fit,
                "World Bank dataset-specific license was not verified as CC BY-4.0",
            )
    try:
        response = transport.get(url, timeout=seconds, max_bytes=MAX_RESPONSE_BYTES)
    except DataUnavailable:
        raise
    except (TimeoutError, OSError, urllib.error.URLError) as error:
        raise DataUnavailable("live source request timed out or could not be reached") from error
    if response.status != 200:
        raise DataUnavailable(f"live source returned HTTP {response.status}")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise DataUnavailable("source response exceeds the byte limit")
    content_type = next(
        (value for key, value in response.headers.items() if key.lower() == "content-type"),
        "",
    ).split(";", 1)[0].strip().lower()
    allowed_content_types = {"application/json", "application/vnd.github+json"}
    if provider is Provider.OWN_PORTFOLIO_HTML:
        allowed_content_types = {"text/html"}
    if content_type not in allowed_content_types:
        raise DataUnavailable("source content type does not match the provider schema")
    response_hash = hashlib.sha256(response.body).hexdigest()
    retrieved_at = _retrieved_at()
    try:
        records = _parse(
            provider, response.body, url, response, response_hash, retrieved_at,
            task_fit, owner, repo,
        )
        records = _validate_record_set(provider, records)
    except UnverifiedSource as error:
        return _unverified_result(
            provider, url, response.status, response_hash, task_fit, str(error)
        )
    return SourceResult(
        provider=provider.value,
        status="VERIFIED_SOURCE",
        request_url=url,
        response_status=response.status,
        response_sha256=response_hash,
        request_body_sha256=None,
        retrieved_at_utc=retrieved_at,
        task_fit=task_fit.value,
        records=records,
    )


def fetch_live(
    provider: Provider,
    *,
    task_fit: TaskFit | None,
    owner: str | None = None,
    repo: str | None = None,
    timeout: float = 5.0,
) -> SourceResult:
    """Fetch live records from a fixed official HTTPS endpoint; never caches/falls back.

    `task_fit` is a narrow source-use declaration, not proof the caller's whole
    workflow is suitable. Downstream workflow evidence remains mandatory.
    """
    return _fetch_with_transport(
        provider,
        task_fit=task_fit,
        owner=owner,
        repo=repo,
        timeout=timeout,
        transport=_UrllibTransport(),
    )
