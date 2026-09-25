> **Operator model:** plain English first; technical details only where they verify the workflow.

# MarketBrief

Market analysts use MarketBrief to turn sourced evidence into a dated macro-risk brief and a concrete next step. Its supported live slice uses actual World Bank U.S. annual nominal GDP observations only; it is not securities or company research.

Run `python3 -m apps.marketbrief` to fetch and cite 15 actual annual observations and summarize the latest nominal change for analyst review. `python3 -m apps.marketbrief --ai-configured` optionally requests a grounded summary through the configured shared provider client; its result remains `AI CANDIDATE (unwitnessed)` until separately verified. Use `--help` for options and `python3 -m unittest discover -s apps/marketbrief -p 'test_*.py' -v` for checks.

GDP history is public macro context, not full company research, a securities feed, or evidence of a trading edge; no stock-price, order, or trading capability exists, and the full MarketBrief job stays `UNVERIFIED`. The adapter checks the dataset-specific World Bank license page at request time; publication timing and any license override beyond the observed page remain unverified. A source failure returns `DATA_UNAVAILABLE` without fixture fallback. Synthetic tenant CSVs remain only for labelled `run_demo()` adversarial regression tests; they are not used by the normal CLI.
