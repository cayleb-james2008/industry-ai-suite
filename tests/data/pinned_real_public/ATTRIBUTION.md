> **Operator model:** plain English first; distinguish offline regression data from fresh live source results.

# Pinned real-public source projections

**OFFLINE ADVERSARIAL REGRESSION ONLY. NEVER used by `run_live()` or the production runner.**

These small, hash-pinned projections let `tests/test_ten_live_contract.py` replay source shapes without making network calls. They are test inputs, not fresh source checks, showcase data, business evidence, or fallback/cache data. `run_live()` remains a live source path; an added regression guards that the production runner never opens `tests/data/` and emits empty, honest failures when the network is blocked.

Original capture receipts are held privately by the project owner. This public attribution records source-level provenance without publishing local receipt paths.

Only fields required by the existing live-path and adversarial tests are retained. Public display text that P8b/P8c intentionally removed (including OPM titles, GDP country display values, and CISA vendor/product labels) is absent. Name/address probes are inserted in memory by the unchanged PII assertions' test setup; no raw personal/private run evidence is copied here. Treasury category/amount fields, World Bank numeric GDP values, stable record IDs, source dates, retrieval times, source response hashes, exact request URLs, read-only indicators, and terms references are source-derived values—not synthetic business records.

## Provenance and attribution

| Snapshot | Public source and record identity | Source as-of / retrieval UTC | Source response SHA-256 | Terms and attribution | Limits |
|---|---|---|---|---|---|
| `treasury_dts.json` | [Treasury FiscalData DTS request](https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/dts/deposits_withdrawals_operating_cash?page%5Bsize%5D=10&sort=-record_date); record ID `2026-09-21:II:1` | As of `2026-09-21` (day); retrieved `2026-09-23T16:21:57Z` | `bde7791b9c12c297dd1c05af620f3618951e5c02b8d20e66a087bb0768f059af` | [FiscalData API documentation](https://fiscaldata.treasury.gov/api-documentation/). Fiscal Service public data may be copied, adapted, and redistributed without restriction. | U.S. federal cash data, not a private company ledger; one source row is retained. |
| `world_bank_usa_gdp.json` | [World Bank API request](https://api.worldbank.org/v2/country/USA/indicator/NY.GDP.MKTP.CD?format=json&per_page=15); IDs `USA:NY.GDP.MKTP.CD:2011`, `USA:NY.GDP.MKTP.CD:2012`, `USA:NY.GDP.MKTP.CD:2013`, `USA:NY.GDP.MKTP.CD:2014`, `USA:NY.GDP.MKTP.CD:2015`, `USA:NY.GDP.MKTP.CD:2016`, `USA:NY.GDP.MKTP.CD:2017`, `USA:NY.GDP.MKTP.CD:2018`, `USA:NY.GDP.MKTP.CD:2019`, `USA:NY.GDP.MKTP.CD:2020`, `USA:NY.GDP.MKTP.CD:2021`, `USA:NY.GDP.MKTP.CD:2022`, `USA:NY.GDP.MKTP.CD:2023`, `USA:NY.GDP.MKTP.CD:2024`, `USA:NY.GDP.MKTP.CD:2025` | Each record is as of its year (2011–2025); retrieved `2026-09-23T18:51:34Z` | `2e54d1e502eae38a14474323ff0a3353c2f5d711c00009c41f4d752f99fedce3` | **World Bank, GDP (current US$), United States, indicator `NY.GDP.MKTP.CD`; CC BY-4.0.** The [dataset-specific indicator page](https://data.worldbank.org/indicator/NY.GDP.MKTP.CD) states `License : CC BY-4.0`; its terms-page response SHA-256 is `199180b076a7633eb3588d632efc0dc0be7e71ed57705936e488daf22abffe7a`. | Annual public U.S. GDP observations support macroeconomic context only, not company or securities research or an external backtest dataset. |
| `cisa_kev.json` | [CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); record ID `CVE-2021-27101`, `dateAdded` `2021-11-03`, due date `2021-11-17` | As of `2021-11-03` (day); retrieved `2026-09-23T16:21:57Z` | `e4988831e6d3c9036dc4279cdb7f5e369dadf1b245c7136aa719fca169b894fd` | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/); attribute CISA KEV. | Public vulnerability context, not an organization's alert or asset data. This historical row is stale for current admission rules and exists only for offline boundary tests; it is never a production fallback. |
| `github_pytest.json` | [GitHub repository metadata request](https://api.github.com/repos/pytest-dev/pytest); `pytest-dev/pytest`, repository ID `37489525` | Repository `updated_at` as of `2026-09-23T11:49:07Z` (second); retrieved `2026-09-23T18:51:35Z` | `728f1aebde3532e2fd95771fcaf353c92329faea68d9451424373e1d291ce146` | Response SPDX label `MIT`; [GitHub MIT license metadata](https://api.github.com/licenses/mit). | Public repository metadata only. No README, issue, advisory, customer, CRM, lead, or contact text is copied or implied. |
| `opm_public_records.json` | [Federal Register OPM metadata request](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest); document ID `2026-19222`; [document record](https://www.federalregister.gov/documents/2026/09/18/2026-19222/employment-in-the-excepted-service) | Published as of `2026-09-18` (day); retrieved `2026-09-23T18:51:34Z` | `e48bfc08f7e03a06a7feba8fe2d23becd18152a18da6e4735473243ce3e62b3f` | [Federal Register About This Site](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction of Federal Register edition material under 1 CFR 2.6. | Public document identity/date/type metadata only; no employee record, private workplace knowledge, or internal HR policy. |
| `own_portfolio.json` | [Prior owned portfolio page](https://agentic-resume-nine.vercel.app/); source ID `agentic-resume-nine.vercel.app:/` | `Last-Modified` as of `2026-09-22T12:49:24Z` (second); retrieved `2026-09-23T18:51:35Z` | `d2351ebc6ced387c9e2ec85894ec7b8947174d2fe613a582e5a05e049138e8f5` | Terms reference: [GitHub MIT license metadata](https://api.github.com/licenses/mit), for the owned `agentic-resume` repository. | HTML body is absent; this is a prior page revision, not a current site claim or usable SearchLift content. |

## Projection byte hashes

The following projection SHA-256 values pin the exact six public JSON test files. The same six values are enforced by `SNAPSHOT_SHA256` in `tests/test_ten_live_contract.py`; they are distinct from the upstream response hashes above.

| Snapshot | New SHA-256 |
|---|---|
| `treasury_dts.json` | `84be02ba4a1425a679dbe717379af3f2f0cc70a2f8bc1ac238dbaa0a72b427b6` |
| `world_bank_usa_gdp.json` | `01b64fd374495a1074ebc01b9d0d97ff08627f0d0116cb8e60d311d7f5018b66` |
| `cisa_kev.json` | `2a75b9acbbe0458a88b6ffdf41f77d9cde2123d4eeefdf1c525b9df1408ed4b5` |
| `github_pytest.json` | `8314b777e4bb801e798b1a8418c6251359ae5dc1d0e5b009b939328e1e2ba631` |
| `opm_public_records.json` | `e1cfaec43d5809292793074be7e51f27b5339a2dbfda01ad24e3308734a1fe46` |
| `own_portfolio.json` | `03f536c35ad0ac0ff0aa98bf40120d65cde1eef106762654672b447132e5e342` |
