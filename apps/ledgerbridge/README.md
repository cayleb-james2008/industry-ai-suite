> **Operator model:** plain English first; technical details only where they verify the workflow.

# LedgerBridge

Finance staff use LedgerBridge to account for cash/ledger rows exactly once, explain exceptions, and route unresolved items to a reviewer. The supported live slice applies that workflow to actual public U.S. Treasury DTS operating-cash rows only; it is not a company ledger or bank close.

Run `python3 -m apps.ledgerbridge` to fetch the live public rows, reconcile them by source date and category, and route single-sided activity to human review. `python3 -m apps.ledgerbridge --ai-configured` optionally requests a grounded summary through the configured shared provider client; its result remains `AI CANDIDATE (unwitnessed)` until separately verified. Inspect options with `--help`; run checks with `python3 -m unittest discover -s apps/ledgerbridge -p 'test_*.py' -v`.

This public cash feed is not a company's private ledger, bank statement, or month-end reconciliation; the full private-finance job stays `UNVERIFIED` until authorized company records are available. The live path never falls back to fixtures and cannot post entries. Checked-in synthetic tenant fixtures remain only for labelled `run_demo()` adversarial regression tests; they are not used by the normal CLI.
