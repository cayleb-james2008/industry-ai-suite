> **Operator model:** plain English first; technical details only where they verify the workflow.

# ChainWatch

The normal command `python3 -m apps.chainwatch` reports live readiness. It currently returns `UNVERIFIED`: Blockscout terms are not admitted and no authorized company watch address is configured. No chain request is made, and no synthetic exposure is returned. Run `python3 -m apps.chainwatch demo` only for the explicit fixture-only regression demo. Run `python3 -m unittest discover -s apps/chainwatch -p 'test_*.py' -v` for checks.

The fixture demo validates watch-only anomaly calculations, but it is not a live-chain monitor or company exposure evidence. There is no signing key, wallet, transfer, or transaction capability. Live use remains blocked until a specific free read-only source has independently verified terms and an authorized public watch address is provided. No AI is invoked by the live availability check.
