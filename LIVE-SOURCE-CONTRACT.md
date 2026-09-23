> **Operator model:** plain English first; separate live source evidence from workflow-fit and licensing unknowns.

# Live source adapter contract

`suite_core.live_sources.fetch_live` is a no-key, standard-library-only, GET-only adapter. It takes a fixed `Provider` enum, not a caller URL. Only HTTPS URLs on fixed provider hosts and provider-specific paths are constructed. TLS verification stays enabled; redirects and environment proxies are disabled; each response is capped at 2,000,000 bytes and the timeout at 8 seconds. Provider row counts are independently bounded, and duplicate stable source IDs are rejected. There is no cache, retry, fixture, or synthetic fallback. The caller can declare one matching `TaskFit`; it cannot choose a URL, method, headers, or transport.

## P2–P5 import and call

```python
from suite_core import Provider, TaskFit, fetch_live

result = fetch_live(
    Provider.CISA_KEV,
    task_fit=TaskFit.PUBLIC_KEV_CONTEXT,
)
for record in result.records:
    print(record.source_id, record.as_of, record.retrieved_at_utc)
```

The additive P1b public sources use the same API:

```python
portfolio = fetch_live(
    Provider.OWN_PORTFOLIO_HTML,
    task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
)
opm_docs = fetch_live(
    Provider.FEDERAL_REGISTER_OPM,
    task_fit=TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
)
gdp_history = fetch_live(
    Provider.WORLD_BANK_USA_GDP,
    task_fit=TaskFit.PUBLIC_US_GDP,
)
```

GitHub routes require both path segments:

```python
result = fetch_live(
    Provider.GITHUB_REPOSITORY,
    owner="vercel",
    repo="next.js",
    task_fit=TaskFit.PUBLIC_REPOSITORY_METADATA,
)
```

`DataUnavailable` has `status == "DATA_UNAVAILABLE"` and covers HTTP 403/429, timeout, redirects, oversize bodies, invalid response/schema, inconsistent document identity, duplicate IDs, and provider row-count violations. `UnverifiedSource` has `status == "UNVERIFIED"` for a missing/mismatched task-fit declaration before a request. When a successful live response lacks terms/license or source as-of, `fetch_live` returns `SourceResult.status == "UNVERIFIED"`, a reason, exact response identity, and no consumable records. World Bank first fetches the fixed dataset indicator page below and checks its dataset-specific license; if that check fails, the unverified result identifies the terms request and returns no GDP records (an unavailable HTTP response is recorded as status `0` with an empty hash). Neither exceptions nor unverified results contain response body text. Callers must report those states and must not substitute fixtures, prior cache, or another source.

## Exported API

- `Provider`: `TREASURY_DTS`, `CISA_KEV`, `WORLD_BANK_USA_GDP`, `OWN_PORTFOLIO_HTML`, `FEDERAL_REGISTER_OPM`, `GITHUB_REPOSITORY`, `GITHUB_README`, `GITHUB_ADVISORIES`.
- `TaskFit`: the corresponding narrow public-scope declarations for cash reporting, KEV context, USA GDP, the exact owned portfolio page, OPM Federal Register document metadata, repository metadata, README review, and advisory context.
- `fetch_live(provider: Provider, *, task_fit: TaskFit | None, owner: str | None = None, repo: str | None = None, timeout: float = 5.0) -> SourceResult`.
- `SourceResult`: provider, status (`VERIFIED_SOURCE` or `UNVERIFIED`), exact request URL, HTTP status, SHA-256 of the exact raw response bytes, `request_body_sha256=None` for these GET-only calls, retrieval UTC, task-fit declaration, immutable record tuple, and an optional reason. An unverified response has no consumable records.
- `SourceRecord`: provider, stable `source_id`, exact source URL, response status, response SHA-256, `request_body_sha256=None`, source-provided `as_of` and precision, retrieval UTC, terms/license URL, `read_only=True`, task-fit declaration, and a PII-redacted field projection. The raw response body is never returned or written.
- `LiveSourceError`, `DataUnavailable`, `UnverifiedSource`: typed failure hierarchy.

Task-fit values are source-scope declarations only. They do not prove that a downstream workflow's job is suitable; that requires independent workflow evidence. All age checks use the genuine source-provided as-of value, with retrieval UTC used only as the clock reference. Missing as-of values return `UNVERIFIED` with no records; malformed timestamps are schema failures. The freshness limits below are **adapter product choices**, not provider guarantees, publication schedules, or claims that a source updates this often:

| Source field | Admission rule | Precision and future-date handling |
|---|---|---|
| Treasury DTS newest returned `record_date` | At most 14 days old | Day precision; a date after the current UTC date is `DATA_UNAVAILABLE`. |
| CISA newest `dateAdded` | At most 60 days old (existing gate) | Day precision; a date after the current UTC date is `DATA_UNAVAILABLE`. |
| Owned portfolio `Last-Modified` | At most 30 days old (existing gate) | Timestamp precision; up to 5 minutes ahead of retrieval UTC is tolerated for clock skew, beyond that is `DATA_UNAVAILABLE`. |
| Federal Register OPM newest `publication_date` | At most 90 days old | Day precision; a date after the current UTC date is `DATA_UNAVAILABLE`. |
| GitHub repository `updated_at` for a **current activity** scope | At most 365 days old | Timestamp precision; up to 5 minutes ahead of retrieval UTC is tolerated for clock skew, beyond that is `DATA_UNAVAILABLE`. This limit does not establish current code contents or activity on other repository objects. |
| World Bank USA GDP newest annual observation | `UNVERIFIED` when its year is less than or equal to current UTC year minus two | Year precision; a year later than the current UTC year is `DATA_UNAVAILABLE`. The check applies to the newest year only, so older annual records remain available for historical analysis when the newest year passes. |

A successful HTTP 200 with an over-age source as-of returns `UNVERIFIED` and no consumable records. No cache, fixture, retrieval-time substitute, or other source is used to fill the gap. Existing source IDs, terms, response-size, provider row-count, and duplicate-ID checks remain independent admission requirements.

## Provider admission and gaps

| Provider | Fixed live endpoint family | Terms reference in returned records | Admission status / limitation |
|---|---|---|---|
| U.S. Treasury FiscalData DTS | Official FiscalData API, DTS deposits/withdrawals operating cash | FiscalData API documentation, whose License and Authorization section says public data is free and may be copied, adapted, redistributed, or otherwise used without restriction | Public cash reporting only; not private company ledger data. The newest returned `record_date` must be at most 14 days old under this adapter's policy. P2 must preserve attribution/provenance and task fit. |
| CISA KEV | Official CISA JSON feed | CC0 1.0 | Admitted only as public vulnerability-catalog context; count must be 1,721–5,000 and newest `dateAdded` no older than 60 days; not organizational alerts or incident history. |
| World Bank USA GDP history (P1b/P1d) | Official Indicators API, USA / `NY.GDP.MKTP.CD`, fixed `per_page=15` | Dataset-specific official indicator page: `https://data.worldbank.org/indicator/NY.GDP.MKTP.CD`; each call must fetch the page over HTTPS and find the page's license-block text `License : CC BY-4.0` before GDP records are admitted | Admitted only as annual public macro context, not market prices or company research. Requests 15 actual years, with a 1–100 row ceiling. If the newest observation year is at least two years behind the current UTC year, return `UNVERIFIED` with no records; older years remain in a passing series for historical analysis. No years are padded or invented. If the fixed terms page is unavailable, oversized, not HTML, or does not affirm the exact dataset license, return `UNVERIFIED` with no GDP records. Macro history alone is not a backtest dataset or experiment record. |
| Owned agentic-resume portfolio HTML (P1b/P1d) | Exact `https://agentic-resume-nine.vercel.app/` root only | `https://api.github.com/licenses/mit`, independently checked against the public `cayleb-james2008/agentic-resume` repository's returned MIT license | Exactly one bounded visible-page record only. Requires the response's own valid `Last-Modified` no more than 30 days old; output contains title, meta description, headings, and paragraph text, never HTML, scripts, styles, or link targets. Does not admit arbitrary sites, referenced assets, or unverified portfolio claims. |
| Federal Register OPM documents (P1b/P1d) | Official `/api/v1/documents.json`, fixed agency ID 406, `per_page=10`, newest-first | Federal Register's About This Site notice: any person may reproduce material in regular or special editions under 1 CFR 2.6 | Up to 100 OPM metadata records only. The newest `publication_date` must be at most 90 days old under this adapter's policy. Every returned official document URL must encode the same `document_number` and `publication_date` as the record. A generic title heuristic omits titles with street addresses or context-marked personal names while preserving the document ID, type, and date. No private employee, personnel, or individual case claims. FederalRegister.gov labels its HTML service informational; consult official editions for legal research. |
| GitHub repository metadata | Official GitHub REST `/repos/{owner}/{repo}` | Repository's returned SPDX license API URL | Exactly one metadata record only. The returned `full_name` must match the requested owner/repository; the API license URL path slug must equal the declared SPDX identifier (and a returned key must agree). `updated_at` must be at most 365 days old for a current-activity scope under this adapter's policy. Any mismatch is `UNVERIFIED` with no records. Public metadata is not customer/CRM data. |
| GitHub README | Official GitHub REST `/repos/{owner}/{repo}/readme` | — | Deliberately `UNVERIFIED`: endpoint response lacks a file-specific timestamp and license proof. Do not use until both are established. |
| GitHub advisories | Official GitHub REST `/repos/{owner}/{repo}/security/advisories` | — | Deliberately `UNVERIFIED`: advisory text terms are not established by the repository license. Do not reuse advisory text without applicable terms. |

Provider record count bounds are: Treasury 1–100; CISA 1,721–5,000; World Bank 1–100; Federal Register OPM 1–100; owned portfolio exactly 1; and GitHub repository metadata exactly 1. Duplicate `source_id` values within a provider response are rejected before any records are returned. These count, identity, license, and privacy checks are independent of the freshness policy above and remain unchanged. The OPM title heuristic only omits the title field when it sees a plausible street address or context-marked personal name; it does not alter the shared `suite_core.privacy.redact` helper or the P1c CISA public-date projection.

The GitHub README and advisory paths are host/path-allowlisted for future evaluation, but return `UNVERIFIED` instead of records until the required source as-of and terms are established. GitHub rate limits remain provider-controlled; no retry is hidden. Repository content is user-authored and no general reuse license is inferred from public access.

USAspending award search and Blockscout instance APIs remain **UNVERIFIED and not exposed as providers**: current evidence did not establish all required read-only behavior, permitted use terms, and source-provided record as-of fields together. No request is made by this adapter for either candidate and no candidate records are returned. Do not infer their terms from a successful HTTP response. The exact allowed production sources added by P1b are only the three rows above; the suite remains incomplete until each workflow separately demonstrates task fit.

## Test boundary

`tests/test_live_sources.py` is labelled adversarial regression testing. Its synthetic records exist only inside stub transports in tests. Production `fetch_live` has no injectable transport, no fixture selection, no stale-cache path, and always performs a real HTTPS request.
