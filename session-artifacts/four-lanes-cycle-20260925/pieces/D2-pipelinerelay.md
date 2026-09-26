# D2 — PipelineRelay public repository research handoff

## Outcome

Make the public repository research slice a real user-selectable workflow through the existing shared GitHub metadata adapter: an operator can name an owner/repository and receive a source-bound identity/license/update-age handoff. It must not manufacture a sales lead or imply CRM, account, consent, or outreach evidence.

## Scope and dependencies

- **Write only:** `apps/pipelinerelay/flow.py`, `apps/pipelinerelay/__main__.py`, `apps/pipelinerelay/tests/test_flow.py`, and `apps/pipelinerelay/README.md`.
- **Read-only:** all other suite files (including shared adapter and source contracts) and all `agentic-resume` files.
- **Dependencies:** Python 3.14 standard library; already-admitted `Provider.GITHUB_REPOSITORY` and `TaskFit.PUBLIC_REPOSITORY_METADATA`; exact GitHub metadata source and returned SPDX license URL. Do not add another endpoint or read README/issues/advisory text.

## Do

1. Read the worker role contract, bar, PipelineRelay README, shared source contract, and V1 baseline receipts; run scoped OV recall and read the mailbox.
2. Add validated `--owner` and `--repo` input with the existing `pytest-dev/pytest` as the no-argument default. Refuse partial, malformed, traversal, query, or URL input before a request; pass the two safe segments to `fetch_live`.
3. Keep the human output limited to the selected public repository identity, returned license identifier/terms URL, default branch, and source-provided update time/age. Source update age is an observation, not proof of current code or activity. Return an explicit public-research review handoff.
4. Make no customer/account/lead/consent/outreach claim and never issue a message. Do not fetch repository README, issues, contacts, or security advisory text.
5. Preserve the demo fixtures and all existing test assertions; add coverage for default input, valid custom repo, malformed and partial inputs, identity/license mismatch, and no network on invalid input.

## Verify / preserve / DoD

- Run the app tests, normal default command, one safe custom repository command through the shared adapter, and `--help`; the lead independently repeats the live command.
- Worker writes a thermo self-review receipt; paired blind text and scoring critics review the code/output.
- **DoD:** both default and custom paths return exact source/terms/provenance receipts and a meaningful research handoff; invalid input fails before network; all account/consent/outreach limits stay explicit; tests and thermo review pass; full sales workflow remains WIP/UNVERIFIED.
