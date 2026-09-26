# R1 — Mempool source terms and public target evidence

## Outcome

Return an independent evidence brief deciding whether the read-only Mempool confirmed-address-history endpoint can support a single public transparency sample for ChainWatch, using only the owner-published My First Bitcoin donation address. The target is not Cayleb's or a company address.

## Scope

- Read-only official pages: `https://mempool.space/terms-of-service`, `https://mempool.space/docs/api/rest`, and `https://donate.myfirstbitcoin.org/`.
- No source code, tests, README/site, PDF, or external run-index edits. Do not call any Mempool `/api/address/...` endpoint, any API endpoint, a payment route, or any accelerator service during this research piece. No contact, donation, sign-in, credential, or account action.
- The lead may materialize the researcher's returned brief at `session-artifacts/four-lanes-cycle-20260925/evidence/mempool-source-review.md` after handover.

## Do

1. Run scoped OpenViking recall for `mempool public API terms bitcoin address` as `gauntlet_researcher`, read the top relevant prior item(s), and report exact hits/token count or the exact access blocker.
2. Read the three official pages through Agent Reach's permitted web reader. Capture retrieval UTC, source page publication/update time where available, exact route, relevant quotation, and a capture hash if the tool provides one.
3. Determine whether the current Mempool terms expressly include associated API services and whether a single, low-frequency GET of the documented confirmed-transaction history fits their stated conditions. Separate permission to access the endpoint from any absent content/data reuse license; do not infer a broad reuse grant.
4. Verify rate-limit guidance and the endpoint's documented record/page ceiling. Confirm the My First Bitcoin page itself labels the address as its on-chain donation address and invites public transparency review. Do not infer Cayleb/company ownership.
5. Return `GREEN` only if the stated terms and target authority support one bounded read-only request with no redistributive claim; otherwise return `UNVERIFIED/BLOCKED` and state the exact missing term/authority. Recommend a no-use path if ambiguous.

## Context and preserve

- The existing `LIVE-SOURCE-CONTRACT.md` records Mempool as not admitted because its prior terms route appeared as a JavaScript shell. This research must decide on current primary-source evidence and must preserve that historical record.
- Baseline user run `evidence/run-all/chainwatch.json` made no chain API request, has no source records, and reports `UNVERIFIED`. The lead separately made exactly one read-only API GET only after reading the current terms and the owner-published public address; raw response receipt is recorded in `evidence/baseline-assessment.md`. Do not repeat that API call in R1.
- No company address, private wallet, balance, company exposure, transaction attribution, customer, or performance result may be inferred.

## Verify / return / DoD

- **Verify:** official URLs and text are visible; retrieval time and freshness are explicit; API request is not made; findings distinguish source-access terms from data-license/redistribution rights.
- **Return:** compact claim/verdict/source/freshness table, key quotations, and a plain-English conclusion; include OV recall, prior-work acknowledgement, and verified `ov write --wait` + `ov read` + scoped `ov find` memory receipt.
- **DoD:** a reusable source-admission decision with exact terms, exact endpoint family/rate-limit caveat, exact target-authority evidence, and either a bounded one-GET GREEN finding or an honest BLOCKED/UNVERIFIED decision. No project files written by the researcher.
