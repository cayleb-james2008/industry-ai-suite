> **Operator model:** plain English first; technical details only where they verify the workflow.

# ChainWatch

The normal command `python3 -m apps.chainwatch` reports live readiness. It currently returns `UNVERIFIED`: the reviewed Mempool address/transaction REST endpoints serve Bitcoin, while the local ChainWatch observation schema expects EVM addresses. Both candidate endpoints returned HTTP 200 during review, but the hosted terms route returned only a JavaScript shell and the terms could not be verified. The app therefore makes no chain request and admits no transactions.

My First Bitcoin's official donation page publishes its public Bitcoin address and links its transparency dashboard. That is a public nonprofit donation address, not a Cayleb/company address and not cryptographic proof of ownership. Company exposure remains `UNVERIFIED`. The fixture demo validates watch-only calculations but is not live-chain evidence. There is no signing key, wallet, transfer, or transaction capability. Run `python3 -m apps.chainwatch demo` only for the explicitly labelled fixture regression demo; the live check does not invoke AI.
