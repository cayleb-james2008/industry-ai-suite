# D5 OnboardPath — independent lead verification

**Lead verification window:** 2026-09-26T05:05:49Z–05:07:43Z. These receipts were produced by the lead after D5 implementation; they are distinct from the worker's stdout hashes.

## Executed commands and receipts

| Command | Exit | Exact receipt SHA-256 |
|---|---:|---|
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/onboardpath/tests -p 'test*.py' -v` | 0 | `tests.txt` `59eaac585e08e38556ce9276b5c8b0e2f8b8e999554d07d420b90fc04e5bbe47` — 19/19, `OK` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --help` | 0 | Help sent to `/dev/null`; no source request. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath` | 0 | `default.json` `1a8835e970ff6934d9dc9587a2e2b43b9854e68e0377dfb32148e6b6ff432e91` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --document-number 2026-19222` | 0 | `selected-2026-19222.json` `216dc6428a5c3b6910f530fbbcc9c324ab45779dce2733f7c465f4838821338e` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --document-number 2026-99999` | 0 | `unmatched-2026-99999.json` `124056e0dc29774157c0452f34c2a8ff60f2cb23c385f419bd45d67211605721` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --document-number bad/path` | 0 | `malformed.json` `8b330715116b198523047a7fa479e2e55add2d56a4ed36edee81bd42a406c4c4` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --document-number 2026-18944` | 0 | `selected-2026-18944.json` `44358d064de0d0994227743c768a3bf0808fdc137ee844635f29e3cac2d55c45` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.onboardpath --document-number 2026-18828` | 0 | `selected-2026-18828.json` `7bd55356c31380987e853796c74fa0fe585e145063dc1d1ee0329dce0c61dfa0` |

All files are under `session-artifacts/four-lanes-cycle-20260925/evidence/d5-lead/`.

## Fresh source-backed outputs and negative paths

- Default and explicit `--document-number 2026-19222` both returned `UNVERIFIED` full-job status, `VERIFIED_SOURCE` metadata and GovInfo text, selected document `2026-19222`, one safe `DATES` section, and citation `opm-text-2026-19222#DATES` (“Comments must be received on or before November 17, 2026.”). The explicit selection response includes exact metadata hash `e48bfc08f7e03a06a7feba8fe2d23becd18152a18da6e4735473243ce3e62b3f`, GovInfo text hash `f2930e743bc4e93b1d7c22bc36e8f2114269fbb57f587b944cdf25a817eb2790`, GovInfo retrieval time `2026-09-26T04:58:32Z`, and GovInfo copyright notice URL. `answer` is null, employee records are not loaded, AI is not invoked, and side effects are zero.
- `2026-99999` returned `PUBLIC_OPM_DOCUMENT_NOT_FOUND` / `UNVERIFIED`, with ten live metadata records and no selected document; no GovInfo text request or fixture fallback occurred. `bad/path` returned the same no-document/UNVERIFIED class before even the metadata request; the output contains no request URL.
- Two other currently listed OPM records, `2026-18944` and `2026-18828`, were deliberately checked through the ordinary selected-document command. Their metadata records were returned, but the shared GovInfo helper refused the identity/title/date mismatch as `DATA_UNAVAILABLE`; no text or substitute was surfaced. This negative source mismatch is preserved as evidence, not described as a working result.
- Across all outputs `answer` remains null, no employee record is loaded, no decision or action occurs, and the full employee-service job remains `UNVERIFIED`. This is a selectable public-document research/review handoff only; no employer policy, legal advice, hiring/disciplinary guidance, or employee permission is inferred.

## Round 2 status-projection fix — fresh lead rerun

After the D5 critic found that the Federal Register metadata HTTP status was checked but not exposed in the output, the worker added `metadata_response_status` and a regression assertion. The lead independently reran tests and the default/explicit-selection paths at 2026-09-26T05:29:21Z:

| Command | Exit | Receipt SHA-256 |
|---|---:|---|
| OnboardPath app tests | 0 | `d5-lead-r2/tests.txt` `aaa0a814d2e357d7a195b80a5931e578183ee59b25659c7c4b23451690f83603` — 19/19 |
| `python3 -m apps.onboardpath --help` | 0 | no source request |
| `python3 -m apps.onboardpath` | 0 | `d5-lead-r2/default.json` `e3ca1840d4892d2b7a6383abb9c3ce750dbd6c2ca133d9e40805336740a01ed9` |
| `python3 -m apps.onboardpath --document-number 2026-19222` | 0 | `d5-lead-r2/selected-2026-19222.json` `a2e1d3748666ffc68aab024ecb3433a99df6a0f1bec751841ea8ca056d8c7c30` |

Both fresh selected outputs now expose Federal Register metadata `response_status: 200` plus metadata response SHA `e48bfc08f7e03a06a7feba8fe2d23becd18152a18da6e4735473243ce3e62b3f`; both expose GovInfo `response_status: 200`, exact GovInfo response hash, source terms, retrieval time, and `opm-text-2026-19222#DATES`. `answer` remains null, no employee record loads, AI is not invoked, side effects are zero, and full job status remains `UNVERIFIED`.
