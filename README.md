> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# Industry AI Suite — ten workflow packages on a shared secure foundation

**Status: ten approved workflow apps in development; overall suite WIP / INCOMPLETE.** The ten concepts are approved project direction. Some apps expose bounded, real public-data slices, while missing private sources and other full-job requirements remain `UNVERIFIED`. Approval of the concepts is not evidence that the apps are AI-complete, shipped, deployed, used by customers, or commercially validated. Do not describe these packages as shipped or claim business results.

## The ten packages

| Package | Demonstration focus |
|---|---|
| **LedgerBridge** | Finance close and reconciliation |
| **MarketBrief** | Public-market research and risk briefing; no order/trade path |
| **ChainWatch** | Watch-only crypto treasury and exposure monitoring |
| **BacktestGuard** | Quant research integrity and leakage checks |
| **ReplyCraft** | Policy-grounded customer-support response drafts |
| **HandoffHub** | Employee knowledge access and cross-team handoffs |
| **SentinelDesk** | Security-operations triage and human response guidance |
| **SearchLift** | Read-only review of selected live public-site content |
| **PipelineRelay** | Consented sales-account summary and human handoff |
| **OnboardPath** | HR onboarding and employee-service guidance |

Every production command uses its live path; `run_demo()` and synthetic fixtures are reserved for explicitly labelled adversarial regression tests. A missing source or authorization is reported as `DATA_UNAVAILABLE` or `UNVERIFIED` with its reason and no fixture, cache, stale, or substitute records. Passing tests and a successful source response do not prove a complete business workflow or live AI.

## First run: all ten workflows

From this directory, run:

```sh
python3 scripts/run_all.py
```

This calls each app's `run_live()` path and makes only the app's admitted, read-only requests; it never calls `run_demo()` and does not substitute fixtures or cached results. Expect read-only HTTPS GETs to public sources such as Treasury, World Bank, CISA, Federal Register, GitHub repository metadata, and the selected public portfolio page. Some verticals deliberately make no request when no authorized source exists. It does not start an AI server, send messages, publish content, trade, sign, or make account changes.

The command writes exactly ten per-app receipts to a temporary directory and exits **1** while the suite is incomplete; an all-`UNVERIFIED` run is never a success. The plain-English headline says `Suite status: INCOMPLETE`, while the separate workflow counts describe only each app receipt (for example, `UNVERIFIED=10`). The final `JSON summary:` line repeats this distinction in machine-readable form with `suite_status`, `job_status_counts`, and each app's `job_statuses`; `INCOMPLETE` is not a per-job counter. Receipts distinguish the app-reported source state (`VERIFIED_SOURCE`, `DATA_UNAVAILABLE`, or `UNVERIFIED`) from the full workflow state. A public source may return usable records and support a narrow task slice, but private finance, CRM, customer-support, employee, internal-knowledge, organization-alert, independent-AI, and other missing evidence keeps the affected full job `UNVERIFIED`. Receipts retain the source/provider URL, stable IDs, source as-of, retrieval UTC, terms, task result, uncertainty, and human handoff when the app returns them. `HTTP 200` verifies a response, not workflow completion, revenue, customers, or business impact. To keep receipts in a chosen local directory, add `--out-dir ./run-output`.

## Public read-only source slices and terms

These links identify narrow read-only inputs used by selected app paths. They do not provide private company, customer, employee, or organization records, and they do not prove that a full workflow is complete. Source status is separate from full-job status.

| App(s) | Read-only source slice | Exact source link | Terms and attribution | What it does not establish |
|---|---|---|---|---|
| LedgerBridge | U.S. Treasury FiscalData Daily Treasury Statement deposits/withdrawals rows | [Treasury DTS API request](https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/dts/deposits_withdrawals_operating_cash?page%5Bsize%5D=10&sort=-record_date) | [FiscalData API documentation](https://fiscaldata.treasury.gov/api-documentation/); attribute U.S. Treasury FiscalData. Its public-data license and authorization terms permit reuse of the public data. | A company's private ledger, bank statement, or month-end close.
| MarketBrief; BacktestGuard | World Bank USA annual GDP indicator `NY.GDP.MKTP.CD` | [World Bank Indicators API request](https://api.worldbank.org/v2/country/USA/indicator/NY.GDP.MKTP.CD?format=json&per_page=15) | [Dataset-specific indicator page](https://data.worldbank.org/indicator/NY.GDP.MKTP.CD), checked for the exact `CC BY-4.0` license label. Attribute the World Bank and indicator. | Company/securities research or an external backtest dataset and experiment log.
| SentinelDesk | CISA Known Exploited Vulnerabilities catalog | [Official CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/); attribute CISA KEV. | An organization's internal alerts, assets, or incident history.
| HandoffHub; OnboardPath | Federal Register metadata for Office of Personnel Management documents (agency ID 406) | [Federal Register API request](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest) | [Federal Register “About This Site”](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction of Federal Register edition material under 1 CFR 2.6. This adapter reads document metadata only; verify official editions for legal research. | Private workplace knowledge, employee records, permissions, or internal HR policy.
| PipelineRelay | Public metadata for `pytest-dev/pytest` repository | [GitHub repository metadata API](https://api.github.com/repos/pytest-dev/pytest) | The response identifies the repository's MIT license; [GitHub MIT license metadata](https://api.github.com/licenses/mit). The app reads repository metadata only, not README or issue text. | CRM/account data, a sales lead, customer identity, consent, or permission to contact anyone.
| SearchLift | A bounded selected-public-page reader | No current page URL is presented as verified: the earlier page capture is stale and is not current evidence. | No current source-terms claim is made for that stale capture. | Current site content, analytics, traffic, rankings, or a complete site review.

ChainWatch has no admitted chain source or authorized company address and makes no request. ReplyCraft has no consent-authorized customer case or approved internal support policy. The private inputs still needed across the suite include company ledger/bank records; an authorized chain address and permitted source; real backtest experiments; customer cases and approved policy; permission-scoped internal knowledge and owners; CRM/account records and consent; employee/onboarding records and internal HR policy; and organization alerts/assets. Those gaps keep affected full jobs `UNVERIFIED` / `WIP · INCOMPLETE`.

The runner accepts an optional literal-loopback OpenAI-compatible endpoint, for example:

```sh
python3 scripts/run_all.py --ai-url http://127.0.0.1:PORT/v1 --out-dir ./run-output
```

Replace `PORT` with the port of a local OpenAI-compatible service. The runner only probes and uses that loopback route when explicitly supplied. A reachable route or app-reported response is only an **AI CANDIDATE**; neither proves a suitable model response was executed. No app can mark the runner `VERIFIED AI` or `COMPLETE` by setting its own receipt fields.

### Independent AI verification is not implemented

The app cannot certify itself, and a standalone JSON file—even one copied from a fabricated app receipt—cannot certify it either. The runner has no metadata-file acceptance option and does not issue an AI-completion status. A future verification route would need an independently authenticated observer on a separate trust boundary, with its trust secret inaccessible to the app process, and evidence from the raw request/response transport. No such observer or live model execution is claimed here. Until that boundary exists, receipts stay **INCOMPLETE**; app-reported AI evidence remains an **AI CANDIDATE** only.

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

## Shared security foundation and human controls

The reusable `suite_core` provides expiring signed identity claims, explicit tenant/role/evidence allowlists, fixture validation and path confinement, minimized audit records and personal-data redaction, evidence-bound output checks, approval tokens tied to exact scope, and a simulated-only action sink. Fixtures are used only by explicitly labelled adversarial regression tests. Tests exercise forged or out-of-scope access, cross-tenant denial, prompt-injection attempts, and sensitive-data handling. These controls reduce risk in the local workflows; they do not make them autonomous or deployment-ready.

Consequential actions stay with a responsible human. There is no real sending, publishing, account change, money movement, signing, or trading. No real customers, revenue, trading results, deployment, adoption, or commercial outcomes are claimed. SearchLift reads only its selected live public page; it does not publish.

The source-tree package uses Python's standard library only. See [`CONTRACT.md`](CONTRACT.md) for the shared-core boundary, usage notes, and limitations.

## License status

There is currently no `LICENSE` file in this repository. Do not assume this README grants permission to reuse the suite code. The source links above have their own terms; those terms do not license this repository.
