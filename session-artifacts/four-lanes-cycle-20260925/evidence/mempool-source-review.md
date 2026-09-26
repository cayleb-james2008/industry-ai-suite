# ChainWatch source-admission evidence — four-lanes-cycle-20260925

## Researcher return

`gauntlet_researcher` returned **UNVERIFIED / BLOCKED**. The Mempool ToS page was readable, but the current Agent Reach/Jina API-documentation refresh returned a cached empty page, so the researcher would not newly attest the precise confirmed-history endpoint. The researcher did verify the public nonprofit target basis and did not make an API/data request.

The lead preserves that limitation. No broad data-reuse or redistribution license is inferred. The endpoint cannot be generalized to another address or used for pending mempool data, balances, company monitoring, or alerts.

## Primary source records

### Mempool Terms of Service

- Official URL: `https://mempool.space/terms-of-service`
- Agent Reach/Jina read: 2026-09-26T02:07:31Z–02:07:32Z; page publication date shown: 2026-09-10; captured Jina Markdown SHA-256 `a5d983706b9b9aea64a917629dea1f2efe9ce7a63f069818a01b979fcc96ebef`.
- Exact relevant text: “their associated API services … collectively, the ‘Website’” and “By accessing this Website, you agree to the following Terms of Service.” The page disclaims data accuracy and service availability. The page does **not** state a separate data-reuse, redistribution, or commercial license.
- Scope: this establishes that the ToS covers associated API services. It is not a broad content license or accuracy guarantee.

### Mempool API documentation

- Official URL: `https://mempool.space/docs/api/rest`.
- A full Agent Reach/Jina capture during the run displayed a published time of 2026-09-10T17:58:30Z and documented `GET /api/address/{address}/txs/chain` as confirmed transaction history, 25 transactions per page. It also said: “we enforce rate limits”; excess returns HTTP 429, and repeated excess can lead to a ban.
- The current recheck at 2026-09-26T02:07:31Z–02:07:34Z returned only an empty cached snapshot (capture SHA-256 `c725578193804f4567716ae102c033fa50d0dd02439bcabe54f68b00381f366d`, 103 characters). The latest rendered docs text could not be re-confirmed. This is recorded as a documentation freshness limitation, not silently treated as a new source grant.
- The exact route is also named in the intake-pinned `LIVE-SOURCE-CONTRACT.md` candidate description (hash `e13e70d8c8045107e75548193d5f240b2b8f97cb51ea2047fff1fe512e98df1d`), which explicitly left Mempool **not admitted** until terms could be read.

### My First Bitcoin owner-published target

- Official URL: `https://donate.myfirstbitcoin.org/`.
- Agent Reach/Jina read: 2026-09-26T02:07:32Z; capture SHA-256 `dec32eeef9d971f9e7447c57dc019db265b6e2d2d01fed6565ed0ae9fd71a275`.
- The page labels its on-chain donation address as its Bitcoin address and says donations are watched on its public dashboard: “Don’t trust us — verify. Watch every sat on our public impact dashboard.”
- This proves the address is owner-published for a public nonprofit transparency example. It is not cryptographic proof of control, is not a Cayleb/company address, and does not establish any company exposure.

## Live endpoint observation already performed by the lead

- One GET only, after the lead read the current ToS, the public target page, the exact prior endpoint contract, and the prior official docs capture.
- URL: `https://mempool.space/api/address/{owner-published-address}/txs/chain` (exact target is the address published on the above donation page).
- HTTP **200**, `application/json`, 3,014 bytes, retrieved 2026-09-26T02:11:10Z. Exact response SHA-256: `21217bee579eff3403cecccacb813142c7a35a6301c027e137edbc208d273c60`.
- The response contained **2** records; both had `status.confirmed == true` and source-provided integer `block_time`. Newest source block time: `1790003229`; oldest returned: `1788962371`.
- This response proves that this exact endpoint produced this exact public response. HTTP 200 is not itself the ToS basis. No retry, polling, pagination, address summary, pending transaction, balance/UTXO, accelerator, or payment endpoint was called.

## Lead disposition — final

**Final decision: UNVERIFIED/BLOCKED for ChainWatch use; no-use path.** The lead initially considered a narrowly bounded read after finding the current ToS covers associated API services, but the independent researcher and blind text critic exposed the remaining gap: the latest official REST-documentation refresh was a cached empty page, the ToS contains no explicit authorization for this automated history request, and the current endpoint/rate-limit details could not be freshly confirmed. The scoring critic also returned a fail. The lead withdraws the tentative admission; ToS scope and owner-published target alone do not satisfy the bar's exact source-terms/task-fit/authorization check.

The one test GET recorded above remains a response observation only. It does not establish permission and will not be integrated, polled, replayed, redistributed, or treated as company exposure. ChainWatch's normal app command will continue making no Mempool request and remain Source/Full job `UNVERIFIED` until exact current API terms and endpoint documentation are verified. The public donation address is an owner-published nonprofit transparency example, not a Cayleb/company address.

The selected-code fallback is recorded in `evidence/baseline-assessment.md`: deepen the next weakest eligible public-data slice, OnboardPath, alongside PipelineRelay and BacktestGuard. This is not a fourth deepening piece and does not alter ChainWatch's negative result. No user input is needed this cycle.
