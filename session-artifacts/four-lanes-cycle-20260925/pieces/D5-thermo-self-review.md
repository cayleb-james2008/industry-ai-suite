# D5 OnboardPath — thermo-nuclear self-review

Date: 2026-09-26 (UTC). Scope: `apps/onboardpath/**` source/CLI/tests/app README plus this exact receipt. Technical choice: standard-library `argparse` and the existing shared, free/local Federal Register/GovInfo adapters; no package install, new provider, credential, fixture, cache, or general URL fetcher. CLI-Anything was considered and is not applicable: this is a bounded extension of the app's existing normal CLI, not a request to build a separate software harness.

## Round 1 result and verification (historical)

- Pre-edit SHA-256 snapshot: `apps/onboardpath/flow.py` `bf74fd447b0bf9c108aab9580f25cfd56e455ca19cfba6ceac3b9ca9db8475a2`; `apps/onboardpath/__main__.py` `b7e4db8611e064702f9f7747efb55a994054558e560f65dfb4e975f34efdf635`; `apps/onboardpath/tests/test_flow.py` `6ce6f104be67404bfc4450779ca3f23300b89a39222ac80bd9d0a1b85ff216a1`; `apps/onboardpath/README.md` `6976ddc1ccc4ce03fba6d756fde1b7fbf3c50881ef53d9c26d254c2cd0eb5cb3`. The exact thermo receipt did not exist at snapshot time.
- **Build:** optional `--document-number` selects exactly one eligible Rule/Proposed Rule from the fresh shared metadata response. Malformed values stop before metadata; valid nonmatches return a no-document `UNVERIFIED` handoff before GovInfo. Selected sections are bounded and privacy-checked, with `document-number#SECTION` citations and metadata/text IDs, hashes, publication/retrieval dates, and terms. The selected flow retains `answer: null`, `employee_records_loaded: false`, `side_effect_count: 0`, and full-job `UNVERIFIED`; no HR-policy/legal/hiring decision or action claim is added.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/onboardpath/tests -p 'test*.py' -v` — **exit 0**, 19/19 tests passed. Includes selection, malformed/no-match-before-text-fetch, identity mismatch, section/citation bounds, PII rejection, no-fixture behavior, legacy role/tenant/canary checks, and prior regressions.
- `python3 -m apps.onboardpath --help` — **exit 0**.
- `python3 -m py_compile apps/onboardpath/flow.py apps/onboardpath/tests/test_flow.py` — **exit 0**.
- `git diff --check` — **exit 0**.
- Live normal CLI checks, output captured in memory and summarized here; no separate stdout JSON was written because no such output path is in D5's writable scope:
  - `python3 -m apps.onboardpath` — **exit 0**; stdout SHA-256 `47421084712cd45967724f88c4f84e259324da86f72c8bc31b27fad56b9dc3ca`; status `UNVERIFIED`, public text review only, selected `2026-19222`, metadata SHA-256 `e48bfc08f7e03a06a7feba8fe2d23becd18152a18da6e4735473243ce3e62b3f`, text SHA-256 `8527d1bdac9d64e22c1ae8d9d04d7d2517e26c0aeedbcece9ca2ffb10848934b`, retrieval `2026-09-26T04:58:23Z`, citation `opm-text-2026-19222#DATES`.
  - `python3 -m apps.onboardpath --document-number 2026-19222` — **exit 0**; stdout SHA-256 `8baf207fcd4315381e558912ba6b4302817fda8d14a53c957cd5205dfda73198`; selected `2026-19222`, metadata SHA-256 `e48bfc08f7e03a06a7feba8fe2d23becd18152a18da6e4735473243ce3e62b3f`, text SHA-256 `aa9532cbca4ee921125a40b54a6f4622ead6d6f86230c985de94580dfb689d25`, metadata/text retrieval `2026-09-26T04:58:32Z`, terms `https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site` and `https://www.govinfo.gov/about/policies#copyright`; section `DATES`: “Comments must be received on or before November 17, 2026.”, citation `opm-text-2026-19222#DATES`. Answer null, no employee records, no side effect.
  - `python3 -m apps.onboardpath --document-number 2026-99999` — **exit 0**; stdout SHA-256 `b7be45a36c3b5b031d7680e4672ed5f98fa00de0aecddd7425f201afb68e0624`; ten current metadata records returned, no selected document, `PUBLIC_OPM_DOCUMENT_NOT_FOUND` / `UNVERIFIED`, `policy_text_failure: null`, explicit handoff says no GovInfo text was requested. Mocked test independently confirms the GovInfo helper was not called.
- This receipt is the only newly written run-artifact path. Earlier verified source-run receipt `session-artifacts/four-lanes-cycle-20260925/evidence/run-all/onboardpath.json` (SHA-256 `22876154ab31320741b9b3d4a6ead516872295a12bf14977d42aafb4bfa37f7f`) and earlier normal CLI receipt `session-artifacts/four-lanes-cycle-20260925/evidence/app-cli/onboardpath.json` (SHA-256 `0d4d1259c8a5c0bba86bc2cd44d9fa049495308694de56ecf32485363875f0b1`) remain unchanged historical baseline evidence; lead-owned fresh receipt paths require independent reruns.

## Round 1 thermo-nuclear hold-back review

Reviewed the D5 diff against `/home/cayleb/.skill-library/active/thermo-nuclear-code-quality-review/SKILL.md` and `gauntlet-rlm/references/thermo-review.md`.

1. **Structural regression — PASS:** normal default still uses the first eligible current Rule/Proposed Rule; requested selection is constrained to validated metadata and leaves employee-specific answer/status boundaries intact.
2. **Missed simpler shape — PASS:** matching and safe section projection are narrow helpers; the repeated privacy/length rule is one `_safe_public_text` predicate. URL creation remains in the canonical GovInfo helper rather than reimplemented.
3. **1,000-line push — PASS:** `flow.py` remains below 1,000 lines (about 500); no changed file crosses the threshold.
4. **Spaghetti branching — PASS:** selection failure is represented explicitly and the GovInfo call only occurs after a unique admitted match; branches remain local to the OPM flow.
5. **Hacky/magic behavior — PASS:** the ASCII document-number pattern, allowed section labels, and content bounds are explicit constants; no caller-controlled URL or fallback path exists.
6. **Wrapper/cast churn — PASS:** no casts or pass-through wrappers added; `_safe_public_text` is reused for two real text boundaries.
7. **Wrong-layer logic — PASS:** selection/response projection stays in OnboardPath; shared adapters/contracts remain untouched.
8. **Duplicated helper — PASS:** uses existing `redact`, `govinfo_opm_url`, and identity-matched `fetch_govinfo_opm_text`; no parallel URL/network helper introduced.

**Self-check verdict: PASS** — no hold-back remains without justification.

## Round 1 prior work and memory

- **P-PRIOR-WORK:** builds on the verified baseline receipts and finding that the app had a real terms-admitted metadata/GovInfo path but returned `answer: null`; those prior bytes remain preserved. This change supersedes only the baseline's implicit latest-rule-only selection/output projection; it does not supersede the historical baseline receipts or claim a full employee-service job.
- **P-OV-MEMORY:** required `gauntlet.py recall` returned `estimated_tokens=404` (cap 1,500) and hits `viking://user/default/memories/events/D5-onboardpath-2026-09-26.md` and `viking://user/default/memories/events/frontend-p6-r2-20260920.md`; the top hit was read. The first records the authorized prior bail before any source edit and the two baseline receipt hashes above.
- Mailbox read confirmed the lead corrected the sole path contradiction and kept the same D5 budgets; no new blocker or widened cap was announced.

Round 1 verdict: **done** — scoped implementation and D5 DoD verified; full app job remains `UNVERIFIED`.

## Round 2 — critic-directed metadata response-status repair

- **Scope:** Only `apps/onboardpath/flow.py`, `apps/onboardpath/tests/test_flow.py`, and this receipt. The metadata/GovInfo source path and all employee/AI/action boundaries are unchanged. No network request was made; unit-test records remain synthetic tests, not current-source evidence.
- **Pre-edit SHA-256 snapshot:** `flow.py` `fea375048b2fc2aea34a407d6ad818266b3ba212ef2b67ffbeb18b1bb90748dd`; `test_flow.py` `8de2f36011f13f1e3fca74a8a948ccb8e5841b2290922c05794709efbb4b9004`; this receipt `00fafa45c2235ef6065778e57293a3387dba2b242b5ea6ac3b2dceedf5a310cf`.
- **Repair:** `_public_document` now requires the record's exact metadata `response_status` to be HTTP 200 and exposes it as `response_status` alongside `response_sha256`. A successfully selected document also exposes the same value as `metadata_response_status`. Tests assert both projections and reject a non-200 metadata record. No source adapter or fetch behavior changed.
- **Verify:** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/onboardpath/tests -p 'test*.py' -v` — exit 0, 19/19 tests passed; `PYTHONPYCACHEPREFIX=/tmp/opencode/onboardpath-round2-pycache python3 -m py_compile apps/onboardpath/flow.py apps/onboardpath/tests/test_flow.py` — exit 0; `git diff --check` — exit 0.

### Round 2 thermo-nuclear hold-back review

Reviewed the Round 2 diff against `/home/cayleb/.skill-library/active/thermo-nuclear-code-quality-review/SKILL.md` and `gauntlet-rlm/references/thermo-review.md`.

1. **Structural regression — PASS:** adding the record response status preserves the existing admitted-source path and only strengthens projection validation; no employee/AI/action boundary changes.
2. **Missed simpler shape — PASS:** direct field projection is the smallest change that closes the receipt omission; no helper or source-path change is warranted.
3. **1,000-line push — PASS:** `flow.py` and `test_flow.py` remain below 1,000 lines.
4. **Spaghetti branching — PASS:** one existing metadata validation guard now includes the record status; the selected receipt adds one direct field, with no new flow branch.
5. **Hacky/magic behavior — PASS:** `200` is the already-required HTTP success status, now enforced at the record projection boundary; the literal is explicit and no hidden behavior is introduced.
6. **Wrapper/cast churn — PASS:** no wrapper, cast, or optionality was added.
7. **Wrong-layer logic — PASS:** response validation/projection remains in the OnboardPath public-document boundary; shared source adapters remain untouched.
8. **Duplicated helper — PASS:** uses the existing `SourceRecord.response_status`; no new helper or duplicated extraction logic.

**Round 2 self-check verdict: PASS** — no hold-back remains without justification.

- **P-PRIOR-WORK:** builds on the Round 1 verified implementation snapshot above and its receipt; supersedes only the missing Federal Register metadata response-status evidence, not any source-path behavior or earlier historical receipts.
- **P-OV-MEMORY:** required recall returned `estimated_tokens=660` (cap 1,500), hits `viking://user/default/memories/events/D5-onboardpath-2026-09-26.md` and `viking://user/default/memories/events/piece-4-floor-counter-20260913.md`; both were read. Supplemental scoped `ov find` returned 10 hits and ranked the D5 memory at #5. Mailbox read included the Round 1 critic finding (bar check 4: metadata response status + hash) and confirmed the prior claims were released.

Round 2 verdict: **done** — exact metadata HTTP status and response hash are present in the public/selected receipts, all 19 tests and required checks pass, and full employee service remains `UNVERIFIED`.
