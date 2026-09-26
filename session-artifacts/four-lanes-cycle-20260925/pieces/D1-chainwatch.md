# D1 — ChainWatch source admission (BLOCKED)

> **Final lead disposition:** Do not implement this proposed integration. R1 returned `UNVERIFIED` for the current API-docs route; the blind text critic endorsed the no-use branch; the numeric critic returned fail. The lead withdrew the initial tentative admission because the current exact API-use/endpoint basis was not sufficiently verified. `evidence/mempool-source-review.md` contains the full record. This piece is typed `BLOCKED_EXTERNAL_DEPENDENCY`; the normal app remains no-request and `UNVERIFIED`. The single prior GET is a response observation, not permission.

The remainder of this file preserves the bounded candidate design for traceability only. It is **not authorized to execute** in this run: no worker should modify the listed source files or issue another Mempool request.

## Outcome

Turn the current no-source ChainWatch readiness screen into a distinct normal user workflow that retrieves and summarizes only the most recent confirmed transactions for the publicly disclosed My First Bitcoin donation address, with a cited human handoff. This is a nonprofit transparency example, not Cayleb/company exposure.

## Scope and dependencies

- **Write only:** `apps/chainwatch/**`; `suite_core/sources/core.py`; new `suite_core/sources/mempool.py`; `suite_core/live_sources.py`; `tests/test_live_sources.py`; `tests/test_ten_live_contract.py`; root `LIVE-SOURCE-CONTRACT.md`; root `README.md`.
- **Read-only:** all other files and all files in `agentic-resume`; the supplied run `SPEC.md`, `bar.md`, `plan.md`, R1 research brief, and baseline evidence.
- **Dependencies:** Python 3.14 standard library; R1 must be GREEN before any source implementation or API request. The documented endpoint is a GET of `/api/address/{address}/txs/chain` with at most the first 25 confirmed transactions; the API documentation warns that repeated excess requests can trigger HTTP 429 and a service ban.

## Do

1. Read the worker role contract, sealed bar and the full thermo review checklist; run scoped OV recall and inspect the run mailbox.
2. Use the existing `suite_core.fetch_live` shared boundary. Add one exact-host, exact-path, HTTPS, redirect-disabled, proxy-disabled, bounded GET provider for the verified public address history. Validate a safe address path segment, JSON content type, response-size and row-count ceilings, unique stable transaction IDs, confirmed status, integer block height/time, and source-provided timestamps. No arbitrary URL, caller transport, retry, cache, fallback, or extra endpoint.
3. Admit only the fixed owner-published public donation address for the sample path. Do not query a company address or accept caller-supplied addresses this cycle. Do not request pending mempool transactions, balance/UTXOs, wallet info, node credentials, or transaction broadcasts.
4. Return a bounded list of transaction IDs, source block times/heights, exact response provenance/hash, and a human next step. Do not infer transaction owner, company exposure, recipient identity, or financial meaning; do not represent a latest-transaction time as a current balance snapshot.
5. Preserve the fixture-only EVM demo and its tenant/canary tests unchanged. Update app/root README and source contract to name the public sample and its limits.

## Verify / preserve / DoD

- Add adversarial tests for unsafe address/path input, redirects/proxies, response cap/schema, unconfirmed or missing block-time rows, duplicate txids, and the 25-record cap. Do not weaken old tests.
- Run ChainWatch tests plus `tests/test_live_sources.py`, relevant full integration tests, `--help`, and the default user CLI once (one API GET only). The lead will rerun fresh normal CLI and root tests independently.
- Worker writes a thermo self-review receipt citing all eight hold-backs; blind text critic and scoring critic review only the output. No AI call, signing, transfer, payment, push, PR, or deployment.
- **DoD:** normal command produces a real shared-adapter receipt for the publicly listed donation address; output uses source block time, stable txids, response SHA, terms URL, and read-only status; a human handoff and “not company data” limit are explicit; full company monitoring remains WIP/UNVERIFIED; tests and thermo review pass; no prohibited side effect.

R1 returned UNVERIFIED for a fresh rendered API-docs page, but the lead's source-admission memo `evidence/mempool-source-review.md` records a narrower decision: one fixed confirmed-history GET is admitted under the current ToS, the earlier official endpoint documentation, the exact live response, and the owner-published nonprofit transparency target. Do not expand beyond the memo's path, address, one-request budget, or local-only reporting. If an implementation needs any broader Mempool permission, a second endpoint, retry/polling, another address, pending transaction data, a balance, or redistribution, stop before that use and record a typed `BLOCKED_EXTERNAL_DEPENDENCY` bailout. Do not choose another address or infer permission.
