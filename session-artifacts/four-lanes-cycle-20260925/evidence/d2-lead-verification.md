# D2 PipelineRelay — independent lead verification

**Lead verification window:** 2026-09-26T03:34:30Z–03:34:31Z. This is the lead's own run after the worker's D2 output, not the worker's pasted test claim.

## Executed commands

| Command | Exit | Exact receipt |
|---|---:|---|
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/pipelinerelay/tests -p 'test*.py' -v` | 0 | `tests.txt` SHA-256 `4d60008ada3ffbf85a722fb1c2254897c39e98251a8415c093c5c779c773fa76` — 16 tests, `OK` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.pipelinerelay --help` | 0 | Help output intentionally sent to `/dev/null`; normal-path JSON receipts follow. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.pipelinerelay` | 0 | `default.json` SHA-256 `866cd72b7d6ab7e077b70e9cf3419ad244a7a0565a4f0ee6a7d134cace362b3b` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.pipelinerelay --owner pallets --repo flask` | 0 | `custom-pallets-flask.json` SHA-256 `1b5f1e2f173c3fba8507bb6fea4ae1ef8bc04fdb68b55d6dd8f0d6d9486c1990` |

All output files are in `session-artifacts/four-lanes-cycle-20260925/evidence/d2-lead/`.

## Observed results

- Default path used the shared GitHub metadata adapter at `https://api.github.com/repos/pytest-dev/pytest`, HTTP 200, stable ID `37489525`, MIT, exact terms metadata URL `https://api.github.com/licenses/mit`; response SHA-256 `dbf34608dc706b2b5d093c5c732b69a311b64b6fa0e842b27d1809263018f4f8`. Source `updated_at` is `2026-09-25T23:52:27Z`; retrieved `2026-09-26T03:34:30Z`. Output reports the elapsed age as an observation and explicitly says it does not prove current code/activity.
- Custom path used the shared adapter at `https://api.github.com/repos/pallets/flask`, HTTP 200, stable ID `596892`, BSD-3-Clause, exact terms metadata URL `https://api.github.com/licenses/bsd-3-clause`; response SHA-256 `0f9bced7279ffeb0d8350bffc4f33a15a83ec351abaa365a55d340a0725c0702`. Source `updated_at` is `2026-09-26T02:34:19Z`; retrieved `2026-09-26T03:34:31Z`.
- Both outputs are `PUBLIC_REPOSITORY_RESEARCH_ONLY`, `VERIFIED_SOURCE`, read-only, and have zero side effects. Both leave CRM/account/customer/lead/consent/outreach context `UNVERIFIED`; neither makes an AI claim beyond `NON-AI / DETERMINISTIC FALLBACK`.
- The second query exercises a real caller-selected owner/repo path; it is not a new customer or a sales lead. No README, issue, advisory, or contact content was requested.

## Current license-term corroboration

At 2026-09-26T03:53:20Z, a separate read-only request to each exact GitHub license metadata URL returned HTTP 200:

- MIT `https://api.github.com/licenses/mit`: response SHA-256 `15b2a5994e7c6e3db7437919f9374593dfc8c0e79eae0f4645e1286d2487deb4`; API identified `MIT`, with commercial use, modification, distribution, and private-use permissions conditioned on retaining copyright/license notices.
- BSD-3-Clause `https://api.github.com/licenses/bsd-3-clause`: response SHA-256 `27b66d435b9e5e154a815addcdef42069e52fa9c4a17deed8f3730b8217a48a0`; API identified `BSD-3-Clause`, with commercial use, modification, distribution, and private-use permissions conditioned on retaining notices; the third clause forbids using the copyright holder/contributors' names to endorse derived products without permission.

These are the exact source metadata license records returned for the selected repositories. They do not establish reuse rights for README/issues/advisories or create CRM/consent evidence.

The full sales-account job remains `WIP · INCOMPLETE · UNVERIFIED`.
