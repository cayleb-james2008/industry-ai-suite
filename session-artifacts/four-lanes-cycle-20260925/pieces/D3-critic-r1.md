# D3 Round 1 — blind text critic

- Contract verdict: **FAIL**.
- D3 piece bar verdict: **FAIL**.
- Lane-wide bar verdict: **FAIL / not established**.
- D3-specific defect count: **1**.
- Reviewer model: `openai/gpt-6-luna`; worker same-family identity is not independently evidenced, so G-INDEPENDENCE remains unresolved.

## Single biggest gap

No inspectable lead-run receipt for the non-default cutoff was included in the permitted output. The incumbent baseline `evidence/run-all/backtestguard.json:39-66` records only the default cutoff 2020. The alternative-cutoff unit test uses `_adversarial_stub_transport` (`apps/backtestguard/test_backtestguard.py:158-160`), and the worker thermo receipt `pieces/D3-thermo-self-review.md:16` summarizes a live run but contains no captured output. The D3 contract requires the lead to repeat and record live commands (`pieces/D3-backtestguard.md:22`); Lane 2 Check 8 requires fresh lead-run evidence (`bar.md:85-88`).

## Code inspection notes

- Valid custom-cutoff partitioning is present at `apps/backtestguard/flow.py:241-267`; disjointness and limits are covered in `test_backtestguard.py:158-181`.
- Missing/out-of-range years fail closed with `DATA_UNAVAILABLE`, no default split, and no substitute at `flow.py:246-267`; tests cover out-of-range and missing-observation cases at `test_backtestguard.py:183-223`.
- The default 2020 split is preserved at `flow.py:241-245` and is present in the baseline receipt.
- Source IDs/hash/terms/as-of are output in `flow.py:274-315,343-348`; the supplied baseline receipt lacks the current license-page evidence required by Lane 2 Check 4.
- The public chronology result, no external experiment, no target/return, no source-release timestamp, full-job `UNVERIFIED`, and no trade path remain explicit (`flow.py:287-312,349-352`; `README.md:5-7`). AI remains fallback/unverified.
- No additional code-structure hold-back was confirmed by this scoped review; the worker's thermo receipt names all eight hold-backs.

## OV recall — outside the verdict

The required Gauntlet recall was denied; scoped `ov find` fallback returned ten URIs, read the closest available critic precedent, and found no BacktestGuard D3-specific hit. Token count unavailable. No verdict was persisted to OV.
