> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# SearchLift

A marketer reviews selected live public content, prioritizes evidence-backed search/usability improvements, and prepares drafts. This limited slice reads the selected public page and hands source-linked findings to the portfolio content owner for human review.

SearchLift's normal command fetches the exact owned public portfolio root through `suite_core.fetch_live` and analyzes only the returned title, meta description, headings, and paragraphs. Findings are structural and source-linked; traffic, rankings, link targets, images, and analytics are not inferred. Results never echo page copy, and all changes remain drafts for human review.

The fresh live read captured for this slice returned the exact selected URL `https://agentic-resume-nine.vercel.app/` with HTTP 200 at `2026-09-24T10:17:49Z`. Its source-provided `Last-Modified` is `2026-09-22T12:49:24Z` (second precision); this source as-of value is distinct from the retrieval time. The bounded visible-text projection had response SHA-256 `d2351ebc6ced387c9e2ec85894ec7b8947174d2fe613a582e5a05e049138e8f5`; the output linked its one P1 stale-roster finding to that hash and returned source ID `agentic-resume-nine.vercel.app:/`. The result makes no ranking, traffic, analytics, or full-site claim; raw page text is not stored.

From the repository root, run `python3 -m apps.searchlift` (or `python3 -m apps.searchlift live`) for the live source path. Source failures return `DATA_UNAVAILABLE` or `UNVERIFIED`; there is no fixture or snapshot fallback. The pinned sanitized real-source snapshot under `tests/` is for offline regression tests only. Run `python3 -m apps.searchlift demo` only for the explicit fixture-only regression demo; it never substitutes for the live path.

The suite entry point is `python3 scripts/run_all.py --out-dir <directory>` from the repository root. It emits one JSON receipt per catalog workflow and remains `INCOMPLETE` until all ten include verified local AI completion evidence.

The tenant-B fixture includes an isolation canary and hostile prompt-like text for boundary tests. It is not included in tenant-A results. If the bounded live text lacks the full approved suite roster, SearchLift reports that content issue generically without repeating legacy project names. This is not a search-rank guarantee or measured business outcome, and no content is edited or published. There is no honest AI role in this narrow structural review: deterministic checks and source-bound draft guidance are safer and sufficient; SearchLift makes no AI claim.

Run the app tests from the repository root: `python3 -m unittest discover -s apps/searchlift/tests -v`.
