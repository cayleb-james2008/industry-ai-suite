# D5 Round 2 — blind text critic

- Contract verdict: **FAIL**.
- D5 piece bar verdict: **FAIL**.
- Lane-wide bar verdict: **FAIL / not established**.
- D5-specific defect count: **1**.
- Reviewer model: `openai/gpt-6-luna`; worker same-family identity is not independently evidenced.

## Single biggest gap

The reviewed D5 contract said the `--document-number` argument was optional but also said “Missing/non-matching document numbers return a clear `UNVERIFIED`/no-record handoff.” The code preserved the no-argument behavior and selected the first eligible metadata record (`apps/onboardpath/flow.py:285-293,344-346`), then requested its GovInfo text (`flow.py:357-365`). This conflicts with the literal missing-number condition in the reviewed D5 contract and makes the acceptance boundary ambiguous. The baseline user path is the documented no-argument CLI (`apps/onboardpath/README.md:12`); the contract should state whether it preserves that path.

Bar link: D3 check 8 requires a meaningful normal user path and honest handoff (`bar.md:85-88`). This is a D5 contract ambiguity, not evidence of private-data or AI leakage. The lead later clarified that omission of the optional flag preserves the verified default, while malformed/supplied nonmatching values fail closed; that clarification is outside this Round 2 verdict.

## Other output observations

- Lead receipts show `2026-19222` selected by default and explicitly, with section citation, source hashes/terms, `answer:null`, no employee records, no AI call, and zero side effects.
- Malformed and nonmatching document numbers fail closed; the current `2026-18944` and `2026-18828` GovInfo identity mismatches return `DATA_UNAVAILABLE` with no selected text.
- The metadata HTTP status omission from Round 1 has been fixed: the selected document exposes `metadata_response_status: 200` and response hash.
- No other D5-specific structural defect was identified. Lane-wide D1/D2/D3/D4/D5 acceptance remains incomplete.

## OV recall — outside verdict

The Gauntlet recall call was blocked; scoped `ov find`/`ov read` read `events/D5-round2-2026-09-26.md` and `events/D5-onboardpath-2026-09-26.md`. Token count unavailable; no verdict write.
