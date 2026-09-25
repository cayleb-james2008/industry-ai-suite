> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# ReplyCraft

ReplyCraft's normal command first runs a clearly labelled public-policy sample using OPM Federal Register document `2026-19222` through the matching official GovInfo text endpoint. It cites the safe returned `DATES` section and returns a deterministic draft for human review only. The page's `SUMMARY` and `ADDRESSES` text is omitted when shared privacy screening would need to alter it. This is not a customer case or company policy: customer support remains `UNVERIFIED` until an actual consent-authorized case and approved internal policy are supplied. No message is sent and no account is changed.

From the repository root:

```sh
python3 -m apps.replycraft
python3 -m unittest discover -s apps/replycraft/tests -v
```

To use a future authorized import, place a UTF-8 JSON bundle and its consent manifest under `~/.local/share/industry-ai-suite/replycraft/imports/`, then run `python3 -m apps.replycraft --case-import <bundle.json> --consent-manifest <bundle.consent.json>`. The bundle contains only `case` (`source_id`, `as_of`, `issue`, `product`, `unresolved`, `days_since_purchase`) and `approved_policy` (`source_id`, `as_of`, `policy_id`, `product`, `days_limit`, `response_rule`, `escalation_queue`). The manifest must bind the bundle SHA-256, both source IDs/as-of values, terms reference, purpose, explicit customer consent, and policy-owner approval. Paths cannot escape the import directory; files are limited to 64 KB. Manifest assertions still require independent confirmation, so the whole workflow remains `UNVERIFIED` until that evidence exists. The public sample has a human-review-only handoff and no message-send capability.

The public sample reuses OPM document `2026-19222` only as reusable public text under GovInfo's Public Domain & Copyright notice, subject to its warning about embedded third-party content and the Federal Register reproduction notice. Its sample question is not a customer case, and the answer does not claim to be the organization's support policy. A real case with explicit customer consent and an approved internal support policy are still required; even with an import, consent and policy-owner assertions need independent confirmation before the full workflow could be verified.

`run_demo()` and checked-in synthetic cases/policies are fixture-only adversarial regression material; the normal CLI never calls them or falls back to them.
