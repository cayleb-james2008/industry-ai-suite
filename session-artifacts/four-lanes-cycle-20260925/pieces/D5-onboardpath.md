# D5 — OnboardPath public OPM document navigator

## Outcome

Turn the current “latest safe text excerpt with no answer” path into a distinct public OPM document-review workflow with optional document selection. The no-argument normal command preserves its existing behavior and selects the first eligible Rule/Proposed Rule from the fresh, admitted metadata list. A reviewer may instead supply one exact document number from that list and receive identity-matched GovInfo text with bounded section labels/citations and an explicit human handoff. This is not employee-specific guidance or employer policy.

## Scope and dependencies

- **Write only:** `apps/onboardpath/flow.py`, `apps/onboardpath/__main__.py`, `apps/onboardpath/tests/test_flow.py`, `apps/onboardpath/README.md`, and the run-artifact receipt `session-artifacts/four-lanes-cycle-20260925/pieces/D5-thermo-self-review.md`.
- **Read-only:** all shared adapters/contracts, all other apps/tests, and every `agentic-resume` file.
- **Dependencies:** existing Federal Register OPM metadata and direct identity-matched GovInfo helper; existing reuse/PII rules. No new provider, URL fetcher, private record source, or policy inference.

## Do

1. Read the worker role, sealed bar, app README, source contract and fresh OnboardPath receipt; run scoped OV recall and read the mailbox.
2. Preserve default no-argument selection of the first eligible current `Rule`/`Proposed Rule`. Add optional `--document-number`; when supplied it must safely select exactly one such record in the fresh metadata response. Never construct a caller URL or fetch outside the exact shared GovInfo path. A malformed value or supplied number that is not present returns a clear `UNVERIFIED`/no-record handoff without a GovInfo request, fixture, cache, or substitute text. A missing optional flag is not a missing user selection; it means use the preserved default.
3. Preserve the fixed no-answer status for employee-specific requests. Make the narrow public document review meaningful by exposing only safe returned sections (for example `DATES`, if present), each bound to the exact metadata record, Federal Register metadata response status/hash, GovInfo text response status/hash, publication date, retrieval time, terms URLs, and stable evidence IDs.
4. State that this is public-document navigation for human review, not HR policy, legal advice, employee evidence, employee guidance, hiring/disciplinary decision, or evidence of employer permission. Keep `employee_records_loaded=false`, no send/action, and the full job `UNVERIFIED`.
5. Preserve the role/tenant/canary and PII-suppression tests; add coverage for selecting a doc from the current list, no match, unsafe ID, GovInfo identity mismatch, section/citation bounds, no fixture fallback, and explicit private-input limits.

## Verify / preserve / DoD

- Run OnboardPath tests, `--help`, default and `--document-number 2026-19222` normal commands, and negative no-match input; lead independently runs the same live source path and inspects the selected section and response hashes.
- Worker writes its thermo self-review receipt to the exact writable run-artifact path named above; paired blind text and scoring critics review output/code.
- **DoD:** the preserved no-argument workflow and an explicit selected-document workflow both use live metadata; a supplied admitted document returns identity-matched, section-cited public text through shared adapters with a clear human next step; malformed/no-match selection fails closed; tests and thermo review pass; employee-specific/full job stays WIP/UNVERIFIED.
