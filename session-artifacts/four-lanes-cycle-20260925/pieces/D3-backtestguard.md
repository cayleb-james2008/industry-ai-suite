# D3 — BacktestGuard configurable public chronology preflight

## Outcome

Allow a reviewer to choose a decision cutoff within the actual World Bank observation years and receive a reproducible train/holdout chronology and future-year leakage warning. This is a public-data preflight, not an external experiment or completed backtest.

## Scope and dependencies

- **Write only:** `apps/backtestguard/flow.py`, `apps/backtestguard/__main__.py`, `apps/backtestguard/test_backtestguard.py`, and `apps/backtestguard/README.md`.
- **Read-only:** shared source adapter/contracts, every other app, and all `agentic-resume` files.
- **Dependencies:** existing World Bank USA GDP source adapter and verified dataset-specific CC BY-4.0 terms; Python 3.14 standard library. No new source, experiment file, market-price feed, or external model.

## Do

1. Read the worker role contract, bar, BacktestGuard README, source contract, and V1 receipt; run scoped OV recall and read the mailbox.
2. Add an optional `--cutoff-year` argument to the ordinary CLI. Preserve the current default. Require the requested cutoff to be an actual observation year and to leave non-empty chronological training and holdout partitions; reject invalid cutoffs without substituting dates/data.
3. Keep existing 15 real GDP observations, source IDs, terms, source hashes, missing experiment record, missing target/return definition, source-release timing limits, future-year leakage probe, and human handoff visible. The result must not claim economic validity or trading performance.
4. Preserve all current fixture-only regression tests and guard behavior; add tests for a valid alternative cutoff, invalid/out-of-range/missing cutoffs, disjointness, chronology, and preserved unverified experiment status.

## Verify / preserve / DoD

- Run the app tests, both default and non-default `--cutoff-year` normal commands, invalid-input cases, and `--help`; the lead independently repeats the live commands and inspects the output.
- Worker writes a thermo self-review receipt; paired blind text and scoring critics review code and output.
- **DoD:** user-selected valid cutoffs create reproducible train/holdout output from real shared-adapter records; invalid cutoffs fail closed; the output remains explicitly `LIMITED`/`UNVERIFIED`, not a backtest; tests and thermo review pass; no trade or promotion path is added.
