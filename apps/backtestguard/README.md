> **Operator model:** plain English first; technical details only where they verify the workflow.

# BacktestGuard

The normal command `python3 -m apps.backtestguard` fetches 15 actual World Bank U.S. GDP observations and checks an observation-year train/holdout split for future-year leakage. Run `python3 -m apps.backtestguard --help` for help and `python3 -m unittest discover -s apps/backtestguard -p 'test_*.py' -v` for the app checks.

This is a data-provenance/time-order analysis, not a market-return backtest or a real external experiment log. The year-ordered control is valid only for observation-year chronology; release timing, a target/return definition, and an experiment record are absent, so the full research-integrity job stays `UNVERIFIED`. It has no broker, order, strategy execution, promotion, or publication adapter. A source failure returns `DATA_UNAVAILABLE` without fixture fallback. Synthetic tenant CSVs remain only for labelled `run_demo()` adversarial regression tests; they are not used by the normal CLI.
