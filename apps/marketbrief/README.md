> **Operator model:** plain English first; technical details only where they verify the workflow.

# MarketBrief

The normal command `python3 -m apps.marketbrief` fetches 15 actual annual U.S. GDP observations from the World Bank fixed, read-only API and cites each source ID and year. Use `python3 -m apps.marketbrief --help` for help and `python3 -m unittest discover -s apps/marketbrief -p 'test_*.py' -v` for checks.

This is a public macro slice, not full company research, a securities feed, or evidence of a trading edge; no stock-price, order, or trading capability exists, and the full MarketBrief job stays `UNVERIFIED`. Dataset-specific license overrides and source publication timing are not established by this path. A source failure returns `DATA_UNAVAILABLE` without fixture fallback. Synthetic tenant CSVs remain only for labelled `run_demo()` adversarial regression tests; they are not used by the normal CLI.
