> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# SearchLift

SearchLift's normal command fetches the exact owned public portfolio root through `suite_core.fetch_live` and analyzes only the returned title, meta description, headings, and paragraphs. Findings are structural and source-linked; traffic, rankings, link targets, images, and analytics are not inferred. Results never echo page copy, and all changes remain drafts for human review.

From the repository root, run `python3 -m apps.searchlift` (or `python3 -m apps.searchlift live`) for the live source path. Source failures return `DATA_UNAVAILABLE` or `UNVERIFIED`; there is no fixture or snapshot fallback. The pinned sanitized real-source snapshot under `tests/` is for offline regression tests only. Run `python3 -m apps.searchlift demo` only for the explicit fixture-only regression demo; it never substitutes for the live path.

The suite entry point is `python3 scripts/run_all.py --out-dir <directory>` from the repository root. It emits one JSON receipt per catalog workflow and remains `INCOMPLETE` until all ten include verified local AI completion evidence.

The tenant-B fixture includes an isolation canary and hostile prompt-like text for boundary tests. It is not included in tenant-A results. If the bounded live text lacks the full approved suite roster, SearchLift reports that content issue generically without repeating legacy project names. This is not a search-rank guarantee or measured business outcome, and no content is edited or published.

Run the app tests from the repository root: `python3 -m unittest discover -s apps/searchlift/tests -v`.
