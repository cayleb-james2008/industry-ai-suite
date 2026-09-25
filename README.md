> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# Industry AI Suite — ten workflow packages on a shared secure foundation

**Status: ten approved workflow apps in development; overall suite WIP / INCOMPLETE.** The ten concepts are approved project direction. Some apps expose bounded, real public-data slices, while missing private sources and other full-job requirements remain `UNVERIFIED`. Approval of the concepts is not evidence that the apps are AI-complete, shipped, deployed, used by customers, or commercially validated. Do not describe these packages as shipped or claim business results.

## The ten packages

| Package | Demonstration focus |
|---|---|
| **LedgerBridge** | Finance staff account for public Treasury rows once, explain exceptions, and route review; company books remain unverified. |
| **MarketBrief** | Analysts review cited U.S. GDP macro risk and a next step; no securities research or order/trade path. |
| **ChainWatch** | A candidate public-address watch, currently blocked because exact public API terms were not verifiable; no company exposure is claimed. |
| **BacktestGuard** | Quant research integrity and leakage checks |
| **ReplyCraft** | A cited public-policy sample draft for human review; customer support remains unverified without consent-authorized case/policy. |
| **HandoffHub** | Direct official GovInfo OPM text handoff; workplace knowledge, permissions, and a real owner remain unverified. |
| **SentinelDesk** | CISA KEV public-threat triage with a CVE-cited local review candidate; organization alerts/assets remain unverified |
| **SearchLift** | Read-only review of selected live public-site content |
| **PipelineRelay** | Public repository research handoff; no CRM, lead, consent, or outreach claim |
| **OnboardPath** | Direct official GovInfo OPM text review; employee-specific service and employer policy remain unverified. |

Every production command uses its live path; `run_demo()` and synthetic fixtures are reserved for explicitly labelled adversarial regression tests. A missing source or authorization is reported as `DATA_UNAVAILABLE` or `UNVERIFIED` with its reason and no fixture, cache, stale, or substitute records. Passing tests and a successful source response do not prove a complete business workflow or live AI.

## First run: all ten workflows

From this directory, run:

```sh
python3 scripts/run_all.py
python3 -m suite_core doctor
```

This calls each app's `run_live()` path and makes only the app's admitted, read-only requests; it never calls `run_demo()` and does not substitute fixtures or cached results. Expect read-only HTTPS GETs to public sources such as Treasury, World Bank, CISA, Federal Register metadata, matching GovInfo document text, GitHub repository metadata, and the selected public portfolio page. ChainWatch deliberately makes no request while its public API terms remain unverified. It does not start an AI server, send messages, publish content, trade, sign, or make account changes.

The command writes exactly ten per-app receipts to a temporary directory and exits **1** while the suite is incomplete; an all-`UNVERIFIED` run is never a success. The plain-English headline says `Suite status: INCOMPLETE`, while the separate workflow counts describe only each app receipt (for example, `UNVERIFIED=10`). The final `JSON summary:` line repeats this distinction in machine-readable form with `suite_status`, `job_status_counts`, and each app's `job_statuses`; `INCOMPLETE` is not a per-job counter. Receipts distinguish the app-reported source state (`VERIFIED_SOURCE`, `DATA_UNAVAILABLE`, or `UNVERIFIED`) from the full workflow state. A public source may return usable records and support a narrow task slice, but private finance, CRM, customer-support, employee, internal-knowledge, organization-alert, independent-AI, and other missing evidence keeps the affected full job `UNVERIFIED`. Receipts retain the source/provider URL, stable IDs, source as-of, retrieval UTC, terms, task result, uncertainty, and human handoff when the app returns them. `HTTP 200` verifies a response, not workflow completion, revenue, customers, or business impact. To keep receipts in a chosen local directory, add `--out-dir ./run-output`.

## Public read-only source slices and terms

These links identify narrow read-only inputs used by selected app paths. They do not provide private company, customer, employee, or organization records, and they do not prove that a full workflow is complete. Source status is separate from full-job status.

| App(s) | Read-only source slice | Exact source link | Terms and attribution | What it does not establish |
|---|---|---|---|---|
| LedgerBridge | U.S. Treasury FiscalData Daily Treasury Statement deposits/withdrawals; the workflow accounts for each returned row once and routes one-sided activity for review. | [Treasury DTS API request](https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/dts/deposits_withdrawals_operating_cash?page%5Bsize%5D=10&sort=-record_date) | [FiscalData API documentation](https://fiscaldata.treasury.gov/api-documentation/); attribute U.S. Treasury FiscalData. Its public-data license and authorization terms permit reuse of the public data. | A company's private ledger, bank statement, or month-end close.
| MarketBrief; BacktestGuard | World Bank USA annual GDP indicator `NY.GDP.MKTP.CD`; MarketBrief provides a dated macro brief and analyst next step, while BacktestGuard uses the 2011–2025 records only for a **limited** observation-year split, not a completed backtest. | [World Bank Indicators API request](https://api.worldbank.org/v2/country/USA/indicator/NY.GDP.MKTP.CD?format=json&per_page=15) | [Dataset-specific indicator page](https://data.worldbank.org/indicator/NY.GDP.MKTP.CD), checked for the exact `CC BY-4.0` license label. Attribute the World Bank and indicator. | Company/securities research, an external experiment record, or a completed backtest.
| SentinelDesk | CISA Known Exploited Vulnerabilities catalog | [Official CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/); attribute CISA KEV. | An organization's internal alerts, assets, or incident history.
| ChainWatch (candidate only; not admitted) | Mempool REST address and transaction endpoints; direct HTTP 200 responses were observed during review, but source terms could not be read from its JavaScript-shell terms route, so ChainWatch makes no request. | [Mempool REST API documentation](https://mempool.space/docs/api/rest); [terms route](https://mempool.space/terms-of-service). | Terms remain `UNVERIFIED`; a successful response does not establish permitted use. The separately verified [My First Bitcoin donation page](https://donate.myfirstbitcoin.org/) publishes a public nonprofit address and links a transparency dashboard. | Cayleb/company address, permission to monitor a company, or a verified terms grant for the hosted API.
| HandoffHub; OnboardPath; ReplyCraft public-policy sample | Federal Register OPM metadata plus a direct identity-matched GovInfo Federal Register document. Current live source record: document `2026-19222`, published `2026-09-18`. | [Federal Register API request](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest); [GovInfo text for `2026-19222`](https://www.govinfo.gov/content/pkg/FR-2026-09-18/html/2026-19222.htm). | [GovInfo Public Domain & Copyright Notice](https://www.govinfo.gov/about/policies#copyright) says U.S.-government works are generally public domain and public documents can generally be reprinted, while warning that embedded third-party content may have separate rights. The [Federal Register notice](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction under 1 CFR 2.6. | Private workplace knowledge, employee records, permissions, approved employer HR/support policy, or employee-specific guidance.
| PipelineRelay | Public metadata for `pytest-dev/pytest` repository | [GitHub repository metadata API](https://api.github.com/repos/pytest-dev/pytest) | The response identifies the repository's MIT license; [GitHub MIT license metadata](https://api.github.com/licenses/mit). The app reads repository metadata only, not README or issue text. | CRM/account data, a sales lead, customer identity, consent, or permission to contact anyone.
| SearchLift | One bounded read of the selected owned public page, `https://agentic-resume-nine.vercel.app/`; fresh retrieval `2026-09-24T10:17:49Z` (HTTP 200), source `Last-Modified` `2026-09-22T12:49:24Z`, ID `agentic-resume-nine.vercel.app:/`, response SHA-256 `d2351ebc6ced387c9e2ec85894ec7b8947174d2fe613a582e5a05e049138e8f5`. The read found 0/10 approved workflow names in the bounded visible-text projection. | Terms reference: [GitHub MIT license metadata](https://api.github.com/licenses/mit) for the owned `agentic-resume` repository. | A site update since 2026-09-22, whole-site coverage, analytics, traffic, search rankings, or search performance.

ChainWatch has no admitted chain source: the Mempool REST endpoints were reachable during review, but the exact public API terms could not be verified. The My First Bitcoin donation address is owner-published for nonprofit transparency, not an authorized Cayleb/company watch address. ReplyCraft's reusable GovInfo OPM text supports only a labelled public-policy sample; there is no consent-authorized customer case or approved internal support policy. Private inputs still needed include company ledger/bank records; a terms-verified chain source and authorized company address; real backtest experiments; customer cases and approved policy; permission-scoped internal knowledge and owners; CRM/account records and consent; employee/onboarding records and internal HR policy; and organization alerts/assets. Those gaps keep affected full jobs `UNVERIFIED` / `WIP · INCOMPLETE`.

The free AI setup is a local OpenAI-compatible server, such as `llama-server` or Ollama, with a model already present on the machine. The suite does not start or stop that server. When a local route is configured, use a numeric loopback address (`127.0.0.1` or `[::1]`); the `localhost` hostname is intentionally refused:

```sh
python3 scripts/run_all.py --ai-url http://127.0.0.1:PORT/v1 --out-dir ./run-output
```

Replace `PORT` with the port of a local OpenAI-compatible service. This loopback route requires no API key. The runner only probes and uses it when explicitly supplied. A reachable route or app-reported response remains **AI CANDIDATE (unwitnessed)**; neither proves a suitable model response was executed. No app or runner can mark a call `VERIFIED`. The separate `scripts/verify_witness.py` can verify one transport exchange against the proxy's keyed log, late reveal, and app-reported call record; it does not upgrade the runner's receipt or certify the task answer.

### AI provider tracing is available; verification remains independent

The optional `suite_core.OpenAICompatibleClient` supports OpenAI-compatible routes and writes an append-only, redacted **app-reported** transport trace with provider-returned response identity, model, usage, creation time, provider host, and request/response hashes. The free local loopback route is the recommended default and needs no API key. Credentialed hosted routes are disabled by default and refused before a network request. A user deploying their own hosted integration must explicitly set `SUITE_AI_ALLOW_HOSTED=true` and list both the exact hostname in `SUITE_AI_ALLOWED_HOSTS` and the exact model ID in `SUITE_AI_ALLOWED_MODELS`; this is a bring-your-own-service route, is not free, and may incur charges. That opt-in is off in this run: no hosted provider was contacted. Use `python3 scripts/run_all.py --ai-configured` only after configuring the intended route; `python3 -m suite_core doctor` reports readiness without revealing a credential. A provider response that reports non-zero model price or request cost is refused, and the route is stopped; missing price information is not proof that hosted use is free. With no configured route, the app keeps its deterministic non-AI slice and says `AI: unavailable (UNVERIFIED)`.

OpenCode Zen's free chat-completion endpoint returned HTTP 403 to a non-OpenCode client with the message that the free tier is only available from within OpenCode. It is not a suite route; the suite does not read OpenCode's credential store, and clients must not spoof an OpenCode identity. Use a local server for a free route, or bring your own OpenAI-compatible endpoint and key.

A local app receipt or app-selected trace file cannot certify itself. The runner always records app-reported calls as **AI CANDIDATE (unwitnessed)** and includes the provider ID and exact transport hashes needed by the verifier. After the proxy stops, a separate invocation of `scripts/verify_witness.py` checks the revealed HMAC key, full line chain, final pinned head, and one-to-one match. A `VERIFIED` result covers only that provider transport exchange, not task quality or workflow completion; the suite remains **INCOMPLETE**. Grounding continues to require citations for admitted evidence IDs, and rejected text is never replaced with a template labeled AI. Provider setup, the witness route, environment variables, safe secret storage, host allowlists, and trace details are documented once in [`SECURITY.md`](SECURITY.md).

## Individual demonstrations and tests

Run an app's live path with `python3 -m apps.<package>`, replacing `<package>` with one of the ten package names below in lowercase. Fixture/demo paths are regression-test tools, not production or showcase commands. Run package tests with the listed commands.

| Package slug | Live command | Test command |
|---|---|---|
| `ledgerbridge` | `python3 -m apps.ledgerbridge` | `python3 -m unittest discover -s apps/ledgerbridge -p 'test*.py' -v` |
| `marketbrief` | `python3 -m apps.marketbrief` | `python3 -m unittest discover -s apps/marketbrief -p 'test*.py' -v` |
| `chainwatch` | `python3 -m apps.chainwatch` | `python3 -m unittest discover -s apps/chainwatch -p 'test*.py' -v` |
| `backtestguard` | `python3 -m apps.backtestguard` | `python3 -m unittest discover -s apps/backtestguard -p 'test*.py' -v` |
| `replycraft` | `python3 -m apps.replycraft` | `python3 -m unittest discover -s apps/replycraft/tests -p 'test*.py' -v` |
| `handoffhub` | `python3 -m apps.handoffhub` | `python3 -m unittest discover -s apps/handoffhub/tests -p 'test*.py' -v` |
| `sentineldesk` | `python3 -m apps.sentineldesk` | `python3 -m unittest discover -s apps/sentineldesk/tests -p 'test*.py' -v` |
| `searchlift` | `python3 -m apps.searchlift` | `python3 -m unittest discover -s apps/searchlift/tests -p 'test*.py' -v` |
| `pipelinerelay` | `python3 -m apps.pipelinerelay` | `python3 -m unittest discover -s apps/pipelinerelay/tests -p 'test*.py' -v` |
| `onboardpath` | `python3 -m apps.onboardpath` | `python3 -m unittest discover -s apps/onboardpath/tests -p 'test*.py' -v` |

Shared integration and security checks:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Run the full root and ten-app pytest suite from the repository root with:

```sh
python3 -m pytest -q -p no:cacheprovider
```

The repository's `pytest.ini` selects importlib mode by default so same-named app test modules are collected without renaming or excluding tests. `tests/test_pytest_discovery.py` checks that root tests and all ten app suites are discovered.

## Shared security foundation and human controls

The reusable `suite_core` provides expiring signed identity claims, explicit tenant/role/evidence allowlists, fixture validation and path confinement, minimized audit records and personal-data redaction, evidence-bound output checks, one-use approval tokens tied to exact scope, a provider-traceable OpenAI-compatible client, and a simulated-only action sink. Fixtures are used only by explicitly labelled adversarial regression tests. Tests exercise forged or out-of-scope access, cross-tenant denial, prompt-injection attempts, replayed approvals, and sensitive-data handling. These controls reduce risk in the local workflows; they do not make them autonomous or deployment-ready.

Consequential actions stay with a responsible human. There is no real sending, publishing, account change, money movement, signing, or trading. No real customers, revenue, trading results, deployment, adoption, or commercial outcomes are claimed. SearchLift reads only its selected live public page; it does not publish.

The source-tree package uses Python's standard library only. See [`CONTRACT.md`](CONTRACT.md) for the shared-core boundary and [`SECURITY.md`](SECURITY.md) for the single source of truth on configuration and security limits.

## License status

There is currently no `LICENSE` file in this repository. Do not assume this README grants permission to reuse the suite code. The source links above have their own terms; those terms do not license this repository.
