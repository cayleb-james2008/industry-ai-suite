# Quality Bar: Lane 2 — Portfolio + Industry AI Suite

> **Operator model:** plain English first; technical details only where they verify the work.

## 1. Goal (one sentence)

Establish fresh, receipt-backed readiness for all ten app journeys, deepen only three slices selected from those runs, and align local portfolio claims to current evidence without turning a public-data slice, test, HTTP response, fallback, or witnessed transport into a full-job claim.

## 2. Reference Anchor

The standard is the existing suite and portfolio truth boundary, not an imagined implementation plan:

- The suite `README.md` defines the ten normal live app paths, per-app public-data limits, setup commands, receipt contents, source-vs-full-job distinction, and the rule that a successful test or source response does not prove a complete workflow or live AI.
- The ten existing app READMEs (LedgerBridge, MarketBrief, ChainWatch, BacktestGuard, ReplyCraft, HandoffHub, SentinelDesk, SearchLift, PipelineRelay, and OnboardPath) define the task-specific expected output, evidence/hand-off, permitted public slice, and known private-input or source-term boundary for each app.
- `CONTRACT.md` anchors authorization, tenant/evidence boundaries, grounded output, human review, simulated-only actions, and the distinction between shared-core behavior and proof of an app job. Its own citations do not prove factual correctness.
- `LIVE-SOURCE-CONTRACT.md` anchors exact provider/path, task-fit, terms, source identity, freshness, provenance, and no-cache/no-fixture live-source behavior. Task fit and HTTP status alone do not prove downstream workflow fit.
- The `agentic-resume/README.md` anchors the portfolio's current WIP / INCOMPLETE / UNVERIFIED statements and identifies the local résumé source and current Pages destination. Local bytes do not prove which revision the live site serves.
- The sealed Lane 2 SPEC requires fresh evidence for the revision assessed. Intake pins and historical receipts in `baseline-and-proof.md` are not fresh verification of later bytes.

Accordingly, ten green commands, a passing test suite, HTTP 200, an AI transport witness, or a public-data slice is never sufficient by itself. Lead-run evidence must expose the actual per-app output and its limits, and every status claim must match that evidence. No app slice is preselected by this bar.

## 3. Frozen Non-Negotiables

1. **Truth and privacy.** Never infer company, customer, employee, or other private data from public sources; never invent customers, results, AI completions, or private data. Unsupported evidence stays explicitly `UNVERIFIED`, `DATA_UNAVAILABLE`, `WIP`, or `INCOMPLETE` as applicable. A public slice does not silently become a full job.
2. **Source admission and honest fallbacks.** Verify exact source terms and task fit before use; record source identity and freshness; do not use fixtures, cache, stale results, substitutes, or unverified terms as live data. A response status proves only that a response was returned. Deterministic fallback stays labeled as fallback. AI transport and task quality remain separate claims.
3. **Preservation and no publication.** Preserve the intake working-tree state, including the pre-existing portfolio `.gitignore` change and untracked `resume/__pycache__/`. No push, pull request, deployment, publication, or remote content change is allowed this cycle.
4. **Forced delegation.** Every implementation piece is owned by a delegated `gauntlet_worker`; every verdict uses delegated blind `gauntlet_critic_text` and `gauntlet_critic_scoring`; any research brief uses a delegated `gauntlet_researcher`. The lead does not build a piece in place of its worker. Record owners and returned evidence.
5. **OpenViking memory.** The lead and every delegated session perform scoped `ov find -n 10 --uri=viking://user/default/memories` plus `ov read` at start and verified `ov write --wait` plus `ov read` read-back at end. Bare `ov add-memory` is not durability evidence. This bar author's own recall limitation and fallback are recorded in the return, not treated as a lead implementation verdict.
6. **Lifecycle gates.** Seal this bar before decomposition and revalidate its hash at close-out (`G-FROZEN-OBJECTIVE`). Use per-piece writable scopes and scope diffs (`G-SCOPE`), fixed budgets (`G-BUDGET`), per-round preservation checks (`G-PRESERVE`), same-check-set acceptance (`G-ACCEPT`), logged critic identity (`G-META`), intake evidence (`G-INTAKE`), and a verified DoD or evidenced typed bail-out (`G-BAIL`). Missing gate evidence is not a pass.
7. **Independent standard and critics.** Section 5 is authored before the lead's decomposition; the lead may tighten only through a recorded amendment and reseal, never loosen. Pair independent text and scoring critics from a different model family than the worker (`G-INDEPENDENCE`); critics judge the output against this frozen bar, not the worker's explanation.

## 4. Bounded Writable Scope (G-SCOPE)

- **This bar-author task may write:** only `/home/cayleb/Work/projects/industry-ai-suite/session-artifacts/four-lanes-cycle-20260925/bar.md`.
- **Read-only for this task:** all suite and portfolio source, tests, READMEs, contracts, site files, the external report destination, all other run artifacts/indexes, and all pre-existing working-tree changes. This task does not edit or create any of them.
- **Lane implementation boundary after the bar is sealed:** work may be scoped only to the two repository roots named by the SPEC, plus its exact external report destination. The lead must define exact per-piece writable globs and snapshot/rollback points before any edit; this bar does not assign pieces or pre-authorize paths. All other paths, including remote Pages content and external run indexes, remain read-only.
- **Rollback/preservation point:** use the actual pre-round snapshot and the intake state recorded in `baseline-and-proof.md`; its pinned HEADs do not establish later working-tree identity. Never overwrite or clean the pre-existing portfolio `.gitignore` change or untracked `resume/__pycache__/`.

## 5. Acceptance Checks (deterministic yes/no)

Every check below is all-or-nothing and must be judged from fresh lead-run evidence for the exact code/tree revision assessed. Each check quotes its sealed SPEC source. A missing receipt, stale evidence, uninspected output, or unproved claim is **NO**, not an implied pass.

### D1 — Fresh end-to-end evidence for all ten apps (30 points)

1. **Fresh suite run and revision-bound receipts — YES/NO (CAP-1).**
   - **SPEC trace — CAP-1 success:** “`python3 scripts/run_all.py` and `python3 -m suite_core doctor` are run, and each of the ten apps has a recorded outcome for setup, workflow, output-quality review, source/data claim, and AI label.”
   - **YES only if:** the lead runs both exact commands against the assessed current tree and records each command, UTC start/end, exit code, assessed repository identity (HEAD plus any working-tree changes relevant to the run), and an exact path and SHA-256 for each resulting receipt/log. The evidence must identify which bytes were assessed; historical receipts or intake hashes do not substitute.
   - **NO if:** either command is absent, any receipt is from another revision or an earlier run, receipt identity/hash is missing, or the aggregate command result is used without the individual app receipts. Exit code `1` is not itself a failure if it truthfully reports the suite's incomplete state; it must be recorded and interpreted honestly.

2. **Ten complete per-app outcome records — YES/NO (CAP-1).**
   - **SPEC trace — CAP-1 success:** “`python3 scripts/run_all.py` and `python3 -m suite_core doctor` are run, and each of the ten apps has a recorded outcome for setup, workflow, output-quality review, source/data claim, and AI label.”
   - **YES only if:** the fresh evidence has exactly one identifiable outcome row for each of LedgerBridge, MarketBrief, ChainWatch, BacktestGuard, ReplyCraft, HandoffHub, SentinelDesk, SearchLift, PipelineRelay, and OnboardPath; every row states setup, actual normal user workflow, output-quality review, source/data claim, AI label, and receipt reference; and setup is valid for all ten normal entrypoints. An unavailable or unverified external source may produce an honest blocked status after valid setup and normal-path execution; it is not called a successful workflow.
   - **NO if:** an app or field is missing, setup for any normal entrypoint is invalid/unproved, the row is only a test status or aggregate count, a demo/fixture is passed off as the normal user path, or a blocker is hidden instead of recorded. A blocked row without evidence of valid setup and attempted normal path is not complete.

3. **Meaningful output-quality review for each journey — YES/NO (CAP-1).**
   - **SPEC trace — CAP-1 success:** “`python3 scripts/run_all.py` and `python3 -m suite_core doctor` are run, and each of the ten apps has a recorded outcome for setup, workflow, output-quality review, source/data claim, and AI label.”
   - **YES only if:** for each app, the lead inspects the actual fresh output (or the actual failure/status output when no result is available), records the app-README/contract criterion applied, points to observed output fields/evidence/citations and uncertainty/human hand-off, and gives an explicit quality disposition. Use existing app-specific expectations; where no threshold is stated or evidence is insufficient, state `UNVERIFIED` rather than inventing a threshold. Sensitive values may be redacted while retaining a verifiable receipt/hash and relevant field evidence.
   - **NO if:** tests or HTTP status are offered instead of output inspection; the claimed result is not tied to visible output/evidence; any app lacks a review/disposition; or missing quality evidence is silently treated as good quality.

### D2 — Source, authorization, AI, and whole-job truth (25 points)

4. **Exact source terms, authority, and data-scope truth — YES/NO (Constraints).**
   - **SPEC trace — Constraint:** “Never infer company, customer, employee, or other private data from public sources. Verify source terms before use; `HTTP 200` proves only that a response was returned.”
   - **SPEC trace — Constraint:** “Do not use fixtures or cache as live data. Unsupported source, workflow, output-quality, or AI claims remain unverified or unavailable rather than being filled with substitutes.”
   - **YES only if:** for every source-backed claim across the ten app outcomes, the lead records the exact source/provider and request URL, current source terms/license evidence, task fit and authorization basis, stable source/document identity, source-provided as-of value, retrieval UTC, response status and exact response hash, and the output claim supported by that record. For private inputs, record the actual authorization/consent and input identity. If exact terms or authority are not established, no source request/use/claim is made and the affected item is explicitly `UNVERIFIED` or `DATA_UNAVAILABLE` with the exact reason.
   - **NO if:** any source is admitted on HTTP 200 alone, terms are inferred from another source, terms or authorization are absent, a public record is described as private/company/customer/employee data, source identity/freshness/provenance is missing, or fixtures/cache/stale records/substitutes are presented as live evidence.

5. **Per-app AI and fallback labels match the evidence — YES/NO (Constraint).**
   - **SPEC trace — Constraint:** “AI transport is `VERIFIED` only under the existing independent witness protocol, and transport verification does not prove task quality. Keep deterministic fallback labeled as fallback; historical AI evidence is limited to four named apps and is not current or general proof (`baseline-and-proof.md`).”
   - **YES only if:** each app's AI state is explicitly one of the evidence-supported states (no AI claim/role, unavailable or unverified, unwitnessed candidate, or witnessed transport); any `VERIFIED` transport claim is bound to the exact current app call and independent witness-verifier receipt; the label is limited to that exchange; the actual model output is separately reviewed for task quality; and every deterministic fallback is plainly labeled as non-AI/fallback. Prior witness receipts are marked historical and never reused as current/general proof.
   - **NO if:** a configured/reachable route, `/models` probe, app trace, provider response, witness alone, test double, deterministic fallback, or historical four-app record is represented as current verified AI task quality or as general proof; or any app's AI/fallback label is missing or misleading.

6. **No unsupported full-job promotion — YES/NO; TRIPWIRE (Constraint).**
   - **SPEC trace — Constraint:** “Keep all ten full app jobs `WIP`/`INCOMPLETE` and `UNVERIFIED` unless independently proven with evidence for the current revision; a public-data slice or passing test alone does not prove the full job.”
   - **YES only if:** all ten full-job statuses remain `WIP`/`INCOMPLETE` and `UNVERIFIED`, unless a specific full job is independently proven against its entire current-revision job scope with exact evidence, including every necessary authorized input. The evidence ledger distinguishes a limited public slice from the full job.
   - **NO if:** any unsupported full job is upgraded, or a test, HTTP response, public-data slice, shared-core check, AI transport, or fallback is used as its full-job proof. This is an immediate tripwire failure regardless of points elsewhere.

### D3 — Exactly three evidence-selected, truthful deep slices (20 points)

7. **Selection follows the fresh ten-app runs — YES/NO (CAP-2).**
   - **SPEC trace — CAP-2 success:** “Only after those runs, three slices are selected and each demonstrates a distinct end-to-end workflow, meaningful output, and a real integration path through shared source adapters. None depends on missing private data, and scope does not widen beyond honest working journeys.”
   - **YES only if:** after Checks 1–3 are evidenced, exactly three slices are named and each selection is linked to the specific fresh per-app evidence showing its weakness/blocker; the record shows why these three are the evidence-selected weak slices relative to the ten observed outcomes. This bar neither names nor ranks the three.
   - **NO if:** any slice is selected before fresh user-run evidence, a candidate is preselected from this bar or historical evidence, the lead cannot tie each selection to its current receipt, or more/fewer than three are deepened.

8. **Each selected slice is a distinct live end-to-end integration — YES/NO (CAP-2).**
   - **SPEC trace — CAP-2 success:** “Only after those runs, three slices are selected and each demonstrates a distinct end-to-end workflow, meaningful output, and a real integration path through shared source adapters. None depends on missing private data, and scope does not widen beyond honest working journeys. Any unsupported full job remains visibly unverified.”
   - **YES only if:** for each of the three slices, fresh lead-run evidence follows the normal user path from setup/input through a real shared-source-adapter integration to a task-specific, inspected output and honest hand-off/uncertainty. Each path is distinct, has an admissible source/task fit and exact source receipt where a source is used, and demonstrates meaningful output under the existing app README/contract. A blocked/unavailable source is reported as blocked, not replaced.
   - **NO if:** a slice is only code, a test, a mock, a fixture, a cache, a UI stub, or an HTTP response; there is no real adapter path or meaningful inspected output; or the three are not distinct end-to-end user workflows.

9. **Deepening fixes only observed breakages and does not widen claims — YES/NO (CAP-2 / Constraint).**
   - **SPEC trace — CAP-2 success:** “Only breakages found during fresh runs are fixed”.
   - **SPEC trace — Constraint:** “Fix only breakages actually found in user journeys; do not widen scope beyond making those journeys honest and working.”
   - **YES only if:** every implementation change is mapped to a reproducible breakage or evidence-backed weakness from the fresh runs, and the final receipt rechecks that affected path. Each public slice keeps explicit limits; any unsupported full job remains visibly unverified.
   - **NO if:** work introduces unrelated scope, is justified only by convenience or an old observation, does not address a reproduced user-journey issue, or presents deeper public-slice functionality as proof of missing private workflow requirements.

### D4 — Live/local portfolio claim alignment (15 points)

10. **Live portfolio claims and résumé source reconciled to verified outcomes — YES/NO (CAP-3).**
    - **SPEC trace — CAP-3 success:** “The live site's project claims and résumé page/PDF source, if they need matching changes, are compared with verified app outcomes for over- and underclaims; exact local corrections are made only where needed, and changed routes pass local build and route checks. Remote content remains unchanged this cycle.”
    - **YES only if:** the lead captures fresh, exact live Pages evidence for every relevant Lane 2 project claim (URL/route, retrieval UTC, response identity/hash or equivalent exact capture receipt), reads the local résumé page/PDF source and other relevant local claims, and records a claim-by-claim comparison against the verified app outcomes. The record identifies overclaims, underclaims, and claims that already match; an unreachable or unidentifiable live route is explicitly unverified, not presumed to match.
    - **NO if:** only local source or an old screenshot is compared, any relevant live project claim is omitted, the live evidence is not tied to exact routes/current retrieval, or claims are accepted because they appear in a README rather than because current evidence supports them.

11. **Only necessary local corrections; changed routes build and check locally — YES/NO (CAP-3).**
    - **SPEC trace — CAP-3 success:** “The live site's project claims and résumé page/PDF source, if they need matching changes, are compared with verified app outcomes for over- and underclaims; exact local corrections are made only where needed, and changed routes pass local build and route checks. Remote content remains unchanged this cycle.”
    - **YES only if:** every evidenced mismatch receives only the exact local correction needed, and each changed route passes a local build plus a local route/content check with command, exit code, route, and receipt recorded. If no correction is needed, the claim-by-claim comparison must show why and no unnecessary edit is made. Live remote bytes remain unchanged.
    - **NO if:** a correction is broader than the evidenced mismatch, any changed route lacks both build and route evidence, a failed check is hidden, no-change is asserted without a complete comparison, or remote content changes.

### D5 — Handoff, preservation, and publication boundary (10 points)

12. **Exact report contains a usable evidence handoff — YES/NO (CAP-4).**
    - **SPEC trace — CAP-4 success:** “`/home/cayleb/Work/session-artifacts/four-lanes-cycle-20260925/lane-reports/lane2-portfolio.md` lists changes, a verified/WIP status line for each app, exit codes and receipts, current state, and a copyable one-command verify recipe; it asks Cayleb for no more than one exact item.”
    - **YES only if:** that exact report exists and contains every listed item, all ten per-app status lines, exact receipt paths/hashes, the actual command exit codes, current state and remaining gaps, one copyable verification command, and zero or one exact operator request.
    - **NO if:** the report is absent/written elsewhere, any app/status/receipt/code/current-state item is absent, the recipe is not copyable, or it requests more than one exact item. This criterion specifies the required destination; this bar-author task does not write it.

13. **Intake work and dirty state preserved — YES/NO (Constraint).**
    - **SPEC trace — Constraint:** “Preserve existing project work and checks. The pre-existing portfolio `.gitignore` change and untracked `resume/__pycache__/` remain untouched (`baseline-and-proof.md`).”
    - **YES only if:** before/after evidence confirms the pre-existing `.gitignore` change and untracked `resume/__pycache__/` are byte/state-identical to intake, and no unrelated existing work/check is overwritten or cleaned.
    - **NO if:** either named dirty-state item is altered, removed, or replaced, or existing project work/checks are discarded. This is a tripwire failure.

14. **No push, PR, deployment, or publication — YES/NO; TRIPWIRE (Constraint).**
    - **SPEC trace — Constraint:** “Local commits are allowed if needed; no push, pull request, deployment, or publication is allowed this cycle.”
    - **YES only if:** all evidence and corrections remain local and the live Pages content is unchanged for the cycle.
    - **NO if:** any push, pull request, deployment, publication, or remote content change occurs. This is an immediate tripwire failure regardless of points elsewhere.

### Scoring and verdict rule

- The five dimension weights are **D1 30 + D2 25 + D3 20 + D4 15 + D5 10 = 100**.
- A dimension earns its full weight only when **every** check in that dimension is YES; otherwise it earns zero. There is no pro-rating, rounding up, or compensating a failed dimension with command volume.
- Overall `PASS` requires **100/100**, every check YES, every applicable tripwire clear, and the Section 3 delegation, OV-memory, lifecycle, and independence gates evidenced. Missing evidence is `UNVERIFIED`/NO, never a pass. Any failed check or tripwire is `FAIL` unless the precise negative branch below applies.
- A partial score, a blocked app, or fewer than three qualifying slices is never reported as `PASS`. `REFUTED` is a distinct measured negative result, not a quality pass or proof of completion.

## 6. Negative Branch (source-terms / private-input refutation)

If exact source terms, task fit, permission, consent, an accountable owner, or required private inputs cannot be established, stop before consuming or claiming that source/input. Preserve the exact evidence of the blocker: source/terms URL, retrieval UTC, HTTP/status and response identity/hash (or the exact reason there is no admissible response), the missing authorization/private-input item, the app/workflow affected, and the resulting no-use decision. Label the source/workflow `UNVERIFIED` or `DATA_UNAVAILABLE` as evidenced; keep the full job `WIP`/`INCOMPLETE`/`UNVERIFIED`. Do not infer private facts, switch to an unapproved source, use a fixture/cache/stale substitute, or describe a public slice as the private job.

**SPEC trace — Constraint:** “Never infer company, customer, employee, or other private data from public sources. Verify source terms before use; `HTTP 200` proves only that a response was returned.”

That specific source/slice hypothesis may be recorded as **REFUTED (negative eligibility result)** only when the lead has measured the exact terms/authorization/private-input blocker and shown that no safe admissible path exists under this contract. This does **not** satisfy a missing required slice or turn a partial run into `PASS`. The overall lane may be `REFUTED` only when fresh evidence shows the required outcome itself cannot be achieved without violating the frozen constraints; otherwise the overall verdict is `FAIL` or `UNVERIFIED` with the exact open criterion. No negative branch licenses a workaround or remote publication.
