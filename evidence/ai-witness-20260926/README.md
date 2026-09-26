# Local model evidence — 26 September 2026

This bundle records six actual calls to a loopback llama.cpp server running a local 27B model. A separately started proxy wrote an HMAC chained log before disclosing its random session key. `verification.json` shows that all six app reported request and response hashes, returned IDs, model names, timestamps, and usage records match the proxy's completed HTTP exchanges. The disclosed key in `reveal.json` is a witness session key, **not** a model or account credential.

Five calls produced app accepted sentences with allowed inline evidence citations. Those sentences, their source IDs, and narrow human source review notes appear in `manifest.json`. The first OnboardPath call failed the citation validator because a privacy filter treated the public document number inside the citation token as a phone number. Its corrected sixth call passed without weakening that filter. The failed call remains in the log.

Recheck the transport evidence from the repository root:

```bash
python3 scripts/verify_witness.py \
  --witness-log evidence/ai-witness-20260926/witness.jsonl \
  --reveal evidence/ai-witness-20260926/reveal.json \
  --app-calls evidence/ai-witness-20260926/app-calls.json
```

**Scope:** The witness verifies transport identity and exact exchange hashes. The app validator checks citation syntax against an allowlist. The human review notes check these five public source statements. None of these checks verifies a private company workflow, current data freshness, general model accuracy, or permission to act on a customer, account, asset, or employee. All ten full jobs remain unverified. No external message, trade, transfer, containment, or employee decision occurred.
