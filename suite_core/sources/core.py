"""Fail-closed, read-only adapters for a small allowlist of public sources.

`fetch_live` always uses the real HTTPS transport. Tests may exercise the
private parser boundary with explicitly adversarial stub transports; callers
cannot supply URLs, HTTP methods, headers, or a transport.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

from ..privacy import redact

MAX_RESPONSE_BYTES = 2_000_000
MAX_TIMEOUT_SECONDS = 8.0
_GITHUB_API = "https://api.github.com"
_PORTFOLIO_URL = "https://agentic-resume-nine.vercel.app/"
_WORLD_BANK_TERMS_URL = "https://data.worldbank.org/indicator/NY.GDP.MKTP.CD"
_FEDERAL_REGISTER_AGENCY_ID = 406
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
    "www.federalregister.gov": re.compile(
        r"^/api/v1/documents\.json$|^/documents/\d{4}/\d{2}/\d{2}/\d{4}-\d{4,6}(?:/[^/?#]+)?$"
    ),
    "www.govinfo.gov": re.compile(
        r"^/content/pkg/FR-\d{4}-\d{2}-\d{2}/html/\d{4}-\d{4,6}\.htm$"
    ),
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
        from .portfolio import parse

        return parse(body, source_url, response, response_hash, retrieved_at, task_fit)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DataUnavailable("source response is not valid UTF-8 JSON") from error
    if provider is Provider.TREASURY_DTS:
        from .treasury import parse
    elif provider is Provider.CISA_KEV:
        from .cisa import parse
    elif provider is Provider.WORLD_BANK_USA_GDP:
        from .world_bank import parse
    elif provider is Provider.FEDERAL_REGISTER_OPM:
        from .federal_register import parse
    elif provider in {Provider.GITHUB_REPOSITORY, Provider.GITHUB_README, Provider.GITHUB_ADVISORIES}:
        from .github import parse

        return parse(
            provider, payload, source_url, response, response_hash,
            retrieved_at, task_fit, owner, repo,
        )
    else:
        raise DataUnavailable("provider has no source-family parser")
    return parse(payload, source_url, response, response_hash, retrieved_at, task_fit)


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
    *,
    _clock=None,
) -> SourceResult:
    return SourceResult(
        provider=provider.value,
        status="UNVERIFIED",
        request_url=request_url,
        response_status=response_status,
        response_sha256=response_hash,
        request_body_sha256=None,
        retrieved_at_utc=(_clock or _retrieved_at)(),
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
    _clock=None,
) -> SourceResult:
    if not isinstance(provider, Provider):
        raise UnverifiedSource("provider must be one of the fixed Provider values")
    if task_fit is not _FIT_BY_PROVIDER[provider]:
        raise UnverifiedSource("task-fit is missing or does not match the fixed provider use")
    seconds = _validate_timeout(timeout)
    clock = _clock or _retrieved_at
    url = _request_url(provider, owner, repo)
    _validate_url(url)
    if provider is Provider.WORLD_BANK_USA_GDP:
        terms_url = _TERMS[provider]
        _validate_url(terms_url)
        from .world_bank import license_is_cc_by_4

        try:
            terms_response = transport.get(
                terms_url, timeout=seconds, max_bytes=MAX_RESPONSE_BYTES
            )
        except (DataUnavailable, TimeoutError, OSError, urllib.error.URLError):
            return _unverified_result(
                provider, terms_url, 0, "", task_fit,
                "World Bank dataset-specific license page could not be fetched",
                _clock=clock,
            )
        terms_hash = hashlib.sha256(terms_response.body).hexdigest()
        terms_type = next(
            (value for key, value in terms_response.headers.items()
             if key.lower() == "content-type"),
            "",
        ).split(";", 1)[0].strip().lower()
        if (terms_response.status != 200 or len(terms_response.body) > MAX_RESPONSE_BYTES
                or terms_type != "text/html"
                or not license_is_cc_by_4(terms_response.body)):
            return _unverified_result(
                provider, terms_url, terms_response.status, terms_hash, task_fit,
                "World Bank dataset-specific license was not verified as CC BY-4.0",
                _clock=clock,
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
    retrieved_at = clock()
    try:
        records = _parse(
            provider, response.body, url, response, response_hash, retrieved_at,
            task_fit, owner, repo,
        )
        records = _validate_record_set(provider, records)
    except UnverifiedSource as error:
        return _unverified_result(
            provider, url, response.status, response_hash, task_fit, str(error),
            _clock=clock,
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


def fetch_govinfo_opm_text(
    record: SourceRecord, *, timeout: float = 5.0, transport: _Transport | None = None,
    _clock=None,
) -> SourceRecord:
    from .govinfo import fetch

    return fetch(record, timeout=timeout, transport=transport, _clock=_clock)


def govinfo_opm_url(record: SourceRecord) -> str:
    from .govinfo import document_url

    return document_url(record)


def fetch_federal_register_opm_text(
    record: SourceRecord, *, timeout: float = 5.0, transport: _Transport | None = None,
    _clock=None,
) -> SourceRecord:
    """Compatibility API for a direct, no-redirect FederalRegister.gov read."""
    from .federal_register import fetch_text

    return fetch_text(record, timeout=timeout, transport=transport, _clock=_clock)
