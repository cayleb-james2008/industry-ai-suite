---
id: SPEC-lane2-portfolio
companions: ["baseline-and-proof.md"]
sources:
  - "/home/cayleb/Work/session-artifacts/four-lanes-cycle-20260925/briefs/lane2-portfolio.md"
  - "/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/spec/SPEC.md"
  - "/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/lead/AI-EXECUTION-VERIFICATION-20260924.md"
---

> Canonical Lane 2 contract. This SPEC and its `companions:` are the complete, preservation-validated contract for this run's Lane 2 work. `sources:` are traceability only.

# Lane 2 — Portfolio and Industry AI Suite

## Why
Portfolio visitors and suite reviewers need accurate evidence of what each user workflow actually does; without fresh user-run evidence, incomplete jobs, fallback behavior, or public-data slices could be mistaken for full private-business workflows. This cycle therefore establishes current app status, improves only evidence-selected weak slices, and aligns local portfolio claims to what is proven.

## Capabilities
- **CAP-1**
  - **intent:** The lead can run and assess all ten app journeys as a user to establish an evidence-backed readiness status for each.
  - **success:** `python3 scripts/run_all.py` and `python3 -m suite_core doctor` are run, and each of the ten apps has a recorded outcome for setup, workflow, output-quality review, source/data claim, and AI label. A full job remains `WIP`/`INCOMPLETE`/`UNVERIFIED` unless independently proven.
- **CAP-2**
  - **intent:** The lead can correct observed journey breakages and focus improvement on the three weakest app slices revealed by fresh user-run evidence.
  - **success:** Only breakages found during fresh runs are fixed; only after those runs, three slices are selected and each demonstrates a distinct end-to-end workflow, meaningful output, and a real integration path through shared source adapters. None depends on missing private data, and scope does not widen beyond honest working journeys. Any unsupported full job remains visibly unverified.
- **CAP-3**
  - **intent:** Portfolio and résumé claims can be reconciled with current evidence and corrected locally where they do not match.
  - **success:** The live site's project claims and résumé page/PDF source, if they need matching changes, are compared with verified app outcomes for over- and underclaims; exact local corrections are made only where needed, and changed routes pass local build and route checks. Remote content remains unchanged this cycle.
- **CAP-4**
  - **intent:** The operator can review Lane 2 changes, evidence, and remaining gaps without confusing partial results for completion.
  - **success:** `/home/cayleb/Work/session-artifacts/four-lanes-cycle-20260925/lane-reports/lane2-portfolio.md` lists changes, a verified/WIP status line for each app, exit codes and receipts, current state, and a copyable one-command verify recipe; it asks Cayleb for no more than one exact item.

## Constraints
- Keep all ten full app jobs `WIP`/`INCOMPLETE` and `UNVERIFIED` unless independently proven with evidence for the current revision; a public-data slice or passing test alone does not prove the full job.
- Never infer company, customer, employee, or other private data from public sources. Verify source terms before use; `HTTP 200` proves only that a response was returned.
- Never invent customers, results, AI completions, or private company data; preserve honest `UNVERIFIED` labels.
- Do not use fixtures or cache as live data. Unsupported source, workflow, output-quality, or AI claims remain unverified or unavailable rather than being filled with substitutes.
- AI transport is `VERIFIED` only under the existing independent witness protocol, and transport verification does not prove task quality. Keep deterministic fallback labeled as fallback; historical AI evidence is limited to four named apps and is not current or general proof (`baseline-and-proof.md`).
- Select the three deeper slices only from the lead's fresh user-run evidence; do not require missing private data or bypass shared source adapters.
- Fix only breakages actually found in user journeys; do not widen scope beyond making those journeys honest and working.
- Keep Lane 2 implementation changes inside `/home/cayleb/Work/projects/industry-ai-suite` and `/home/cayleb/Work/projects/agentic-resume`; the live Pages site stays exactly as it is this cycle.
- Preserve existing project work and checks. The pre-existing portfolio `.gitignore` change and untracked `resume/__pycache__/` remain untouched (`baseline-and-proof.md`).
- Local commits are allowed if needed; no push, pull request, deployment, or publication is allowed this cycle.

## Non-goals
- Do not label all ten full app jobs complete or AI-quality-verified based on HTTP responses, public-data proxies, fixtures/cache, transport evidence, or fallback output.
- Do not deepen all ten apps, infer private facts from public records, invent unverified source terms, or select a slice that needs absent private data or bypasses shared adapters.
- Do not push, open a pull request, deploy, or publish any repository or site content this cycle.

## Success signal
The ten app journeys each have a fresh evidence-backed status line, the three deeper slices are selected only after those runs and satisfy their evidence boundaries, and any changed local portfolio routes match verified claims and pass local checks. The lane report exposes receipts and gaps; unsupported full jobs remain `WIP`/`INCOMPLETE`/`UNVERIFIED`, and no remote change occurs.

## Assumptions
- The supplied HEADs and document hashes are intake pins, not proof that later bytes remain unchanged; readiness decisions use fresh evidence for the revision being assessed.
- The affected readers are people inspecting the portfolio and the operator reviewing suite readiness; the brief names no narrower audience.

## Open Questions
- Which three app slices are weakest? **Default:** select them only from the lead's fresh user-run evidence; do not preselect or deepen an unsupported private-data-dependent slice.
- Which portfolio claims need correction? **Default:** compare current claims against verified outcomes, make only exact local corrections, validate changed routes locally, and leave remote content untouched.
- Which exact sources and current terms support each user-run slice? **Default:** verify exact source terms before use; if terms, task fit, or authority are not established, do not consume the source and leave the corresponding claim unverified.
- What output-quality threshold applies where an app-specific rule is not stated in the brief? **Default:** use existing project contracts/checks where present; invent no threshold and keep the result unverified when evidence is insufficient.
