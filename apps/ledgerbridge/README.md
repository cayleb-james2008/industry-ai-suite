> **Operator model:** plain English first; technical details only where they verify the workflow.

# LedgerBridge

The normal command `python3 -m apps.ledgerbridge` fetches actual public U.S. Treasury DTS operating-cash rows through the fixed, read-only P1 source adapter. It reconciles each returned category/row once and routes single-sided public activity for human review. Inspect command help with `python3 -m apps.ledgerbridge --help`; run checks with `python3 -m unittest discover -s apps/ledgerbridge -p 'test_*.py' -v`.

This public cash feed is not a company's private ledger, bank statement, or month-end reconciliation; the full private-finance job stays `UNVERIFIED` until an authorized ledger is provided. The live path never falls back to fixtures and cannot post entries. Checked-in synthetic tenant fixtures remain only for labelled `run_demo()` adversarial regression tests; they are not used by the normal CLI.
