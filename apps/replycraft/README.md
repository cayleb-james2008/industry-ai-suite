> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# ReplyCraft

ReplyCraft's normal command is live-only. With no authorized inputs it returns `UNVERIFIED`: no consent-authorized real customer case or approved internal support policy is supplied. Public GitHub issues are not customer cases. No message is sent and no account is changed.

From the repository root:

```sh
python3 -m apps.replycraft
python3 -m unittest discover -s apps/replycraft/tests -v
```

To use a future authorized import, place a UTF-8 JSON bundle and its consent manifest under `~/.local/share/industry-ai-suite/replycraft/imports/`, then run `python3 -m apps.replycraft --case-import <bundle.json> --consent-manifest <bundle.consent.json>`. The bundle contains only `case` (`source_id`, `as_of`, `issue`, `product`, `unresolved`, `days_since_purchase`) and `approved_policy` (`source_id`, `as_of`, `policy_id`, `product`, `days_limit`, `response_rule`, `escalation_queue`). The manifest must bind the bundle SHA-256, both source IDs/as-of values, terms reference, purpose, explicit customer consent, and policy-owner approval. Paths cannot escape the import directory; files are limited to 64 KB. Manifest assertions still require independent confirmation, so the whole workflow remains `UNVERIFIED` until that evidence exists. No send capability is present.

No public issue or repository feed is admitted as a customer case. A real case with explicit customer consent and an approved internal support policy are still required; there is no public-source terms claim for this workflow. Even with an import, the consent and policy-owner assertions require independent confirmation before the full workflow could be verified.

`run_demo()` and checked-in synthetic cases/policies are fixture-only adversarial regression material; the normal CLI never calls them or falls back to them.
