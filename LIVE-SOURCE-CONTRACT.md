> **Operator model:** plain English first; separate live source evidence from workflow-fit and licensing unknowns.

# Live source adapter contract

`suite_core.live_sources.fetch_live` is a no-key, standard-library-only, GET-only compatibility API. Its implementation is split by source family under `suite_core/sources/`: `core.py` owns the shared HTTP/allowlist boundary and family dispatch; `treasury.py`, `cisa.py`, `world_bank.py`, `portfolio.py`, `federal_register.py`, and `github.py` own their parser rules; `govinfo.py` owns the identity-bound GovInfo text request. `suite_core.live_sources` re-exports the existing public API. Only HTTPS URLs on exact hosts and fixed provider-specific paths are constructed. TLS verification stays enabled; redirects and environment proxies are disabled; each response is capped at 2,000,000 bytes and the timeout at 8 seconds. Provider row counts are independently bounded, and duplicate stable source IDs are rejected. There is no cache, retry, fixture, or synthetic fallback. The caller can declare one matching `TaskFit`; it cannot choose a URL, method, headers, or transport.

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
- `suite_core.live_sources.fetch_govinfo_opm_text(record, *, timeout=5.0) -> SourceRecord`: a narrow follow-up to one already-validated OPM metadata record. It accepts only `Rule`/`Proposed Rule` records with a safe title, constructs the direct GovInfo Federal Register issue/granule URL from the record's exact document number and publication date, and requests that one fixed-host/fixed-path URL through the shared no-redirect/no-proxy transport. The response must identify the same printed document number, title, and issue date. It returns at most eight safe visible paragraphs plus available stable section labels (`DATES`, `ADDRESSES`, and similar); paragraphs needing privacy redaction are omitted. The record preserves the metadata identity/hash, GovInfo text response hash/status/retrieval time, GovInfo reuse terms, and Federal Register reproduction terms. Task fit is `public_opm_policy_text`. It does not accept a caller-selected host/URL and returns no text from failed or mismatched responses.
- `suite_core.live_sources.fetch_federal_register_opm_text(record, *, timeout=5.0) -> SourceRecord` remains as a legacy direct FederalRegister.gov text adapter for callers that already depend on it. It keeps its exact-host/no-redirect behavior, returns `DATA_UNAVAILABLE` on the known challenge/redirect, and is not used by HandoffHub or OnboardPath in this round. Those workflows use the direct GovInfo helper above instead.
- `suite_core.live_sources.govinfo_opm_url(record) -> str` constructs the exact permitted GovInfo path for an admitted metadata record; the host/path is checked again before transport.
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
| Owned agentic-resume portfolio HTML (P1b/P1d) | Exact `https://cayleb-james2008.github.io/agentic-resume/` root only; stable source ID `cayleb-james2008.github.io:/agentic-resume/` | `https://api.github.com/licenses/mit`, inherited from the public `cayleb-james2008/agentic-resume` repository's independently checked MIT license | Exactly one bounded visible-page record only. Requires the response's own valid `Last-Modified` no more than 30 days old; output contains title, meta description, heading text, and paragraph text, never HTML, scripts, styles, or link targets. Does not admit the former Vercel host, arbitrary sites, queries, subpaths, referenced assets, or unverified portfolio claims. |
| Federal Register OPM documents (P1b/P1d) | Official `/api/v1/documents.json`, fixed agency ID 406, `per_page=10`, newest-first | Federal Register's About This Site notice: any person may reproduce material in regular or special editions under 1 CFR 2.6 | Up to 100 OPM metadata records only. The newest `publication_date` must be at most 90 days old under this adapter's policy. Every returned official document URL must encode the same `document_number` and `publication_date` as the record. The projected `source_url` and `data.html_url` are canonical links derived from the validated document number and date; returned URL slugs are discarded, and user-info, query, or fragment components are rejected. The raw API response hash and fixed API request URL preserve provenance. A generic title heuristic omits titles with street addresses or context-marked personal names while preserving the document ID, type, and date. No private employee, personnel, or individual case claims. FederalRegister.gov labels its HTML service informational; consult official editions for legal research. |
| Federal Register OPM rule text (bounded P1b-r2 follow-up) | Direct official GovInfo Federal Register granule `/content/pkg/FR-YYYY-MM-DD/html/{document_number}.htm`, constructed only from one admitted OPM metadata record; only `Rule` and `Proposed Rule` records qualify | [GovInfo Public Domain & Copyright Notice](https://www.govinfo.gov/about/policies#copyright) says U.S. government work is generally public domain and public documents can generally be reprinted, with a caveat for embedded third-party material. The Federal Register's [About This Site notice](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction under 1 CFR 2.6. | The helper uses the exact `www.govinfo.gov` host/path, no redirects/proxies, response-size/time caps, and checks the response's printed document number, title, and issue date against the metadata record. It returns at most eight paragraphs unchanged by PII/secret redaction and bounded section text for stable citations. No FederalRegister.gov challenge/interstitial is followed or bypassed. No employee records, private permissions, employer policy, legal advice, or person-specific handling is admitted. |
| Mempool public Bitcoin API candidate (not admitted) | Candidate read-only routes `/api/address/{address}` and `/api/address/{address}/txs` on `mempool.space`; excluded from the fixed production allowlist | [REST API documentation](https://mempool.space/docs/api/rest) documents address/transaction endpoints. The official `/terms-of-service` route returned only a JavaScript shell during the 2026-09-24 review, so the hosted API-use terms could not be freshly verified. | Not a provider and no app request is made. The My First Bitcoin page publicly discloses a donation address and links its transparency dashboard, but that does not establish Cayleb/company ownership. Do not consume records or claim company exposure until exact terms and address authority are established. |
| GitHub repository metadata | Official GitHub REST `/repos/{owner}/{repo}` | Repository's returned SPDX license API URL | Exactly one metadata record only. The returned `full_name` must match the requested owner/repository; the API license URL path slug must equal the declared SPDX identifier (and a returned key must agree). `updated_at` must be at most 365 days old for a current-activity scope under this adapter's policy. Any mismatch is `UNVERIFIED` with no records. Public metadata is not customer/CRM data. |
| GitHub README | Official GitHub REST `/repos/{owner}/{repo}/readme` | — | Deliberately `UNVERIFIED`: endpoint response lacks a file-specific timestamp and license proof. Do not use until both are established. |
| GitHub advisories | Official GitHub REST `/repos/{owner}/{repo}/security/advisories` | — | Deliberately `UNVERIFIED`: advisory text terms are not established by the repository license. Do not reuse advisory text without applicable terms. |

Provider record count bounds are: Treasury 1–100; CISA 1,721–5,000; World Bank 1–100; Federal Register OPM 1–100; owned portfolio exactly 1; and GitHub repository metadata exactly 1. Duplicate `source_id` values within a provider response are rejected before any records are returned. These count, identity, license, and privacy checks are independent of the freshness policy above and remain unchanged. The OPM title heuristic only omits the title field when it sees a plausible street address or context-marked personal name; it does not alter the shared `suite_core.privacy.redact` helper or the P1c CISA public-date projection.

The GitHub README and advisory paths are host/path-allowlisted for future evaluation, but return `UNVERIFIED` instead of records until the required source as-of and terms are established. GitHub rate limits remain provider-controlled; no retry is hidden. Repository content is user-authored and no general reuse license is inferred from public access.

USAspending, Blockscout, and the Mempool public API candidate remain **UNVERIFIED and are not exposed as providers**. For Mempool, direct candidate API requests responded, but the exact hosted API terms were not readable; successful responses do not establish permission. No ChainWatch app request is made and no candidate record is consumed. The direct GovInfo OPM text helper is a bounded follow-up to an admitted metadata record, not a general-purpose URL fetcher. The suite remains incomplete until each workflow separately demonstrates task fit.

## Test boundary

`tests/test_live_sources.py` is labelled adversarial regression testing. Its synthetic records exist only inside stub transports in tests. Production `fetch_live` has no injectable transport, no fixture selection, no stale-cache path, and always performs a real HTTPS request.
