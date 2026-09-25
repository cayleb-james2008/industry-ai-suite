> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# SearchLift

A marketer reviews one selected live public page, records source-linked structural findings, and prepares drafts for the portfolio content owner to review.

SearchLift's normal command fetches only `https://cayleb-james2008.github.io/agentic-resume/` through `suite_core.fetch_live` and analyzes the returned title, meta description, heading text, and paragraph text. The report binds findings to the response hash and separately records retrieval time and source-provided `Last-Modified`; it reports the distinct workflow-name count out of ten and the parser limits. It does not establish unseen page content, rankings, traffic, analytics, or AI completion. Results never echo page copy, and all changes remain drafts for human review.

The prior Vercel response (`agentic-resume-nine.vercel.app:/`, SHA-256 `d2351ebc6ced387c9e2ec85894ec7b8947174d2fe613a582e5a05e049138e8f5`) is historical offline test data only. It is not a live fallback or evidence about the current Pages response.

The fresh 2026-09-25 read-only Pages observation is recorded at `session-artifacts/searchlift-current-pages-20260925/pieces/P2/P2-live-observation.md`: HTTP 200 retrieved `2026-09-25T17:52:01Z`, source `Last-Modified` `2026-09-25T14:50:52Z`, response SHA-256 `b4ed4de9f785a5059acde72c7660d6c20351d8409915c6323a252836b3001c88`. It reports **PASS, 10/10** distinct approved names in the bounded projection, with the 20-heading and 30-paragraph caps reached and at most 1,000 characters per captured item. Omitted or truncated text and other routes were not assessed. The earlier P1 observation and historical Vercel fixture remain unchanged records.

From the repository root, run `python3 -m apps.searchlift` (or `python3 -m apps.searchlift live`) for the live source path. Source failures return `DATA_UNAVAILABLE` or `UNVERIFIED`; there is no fixture or snapshot fallback. The pinned sanitized real-source snapshot under `tests/` is for offline regression tests only. Run `python3 -m apps.searchlift demo` only for the explicit fixture-only regression demo; it never substitutes for the live path.

The suite entry point is `python3 scripts/run_all.py --out-dir <directory>` from the repository root. It emits one JSON receipt per catalog workflow and remains `INCOMPLETE` until all ten include verified local AI completion evidence.

The tenant-B fixture includes an isolation canary and hostile prompt-like text for boundary tests. It is not included in tenant-A results. If the bounded live text lacks the full approved suite roster, SearchLift reports that content issue generically without repeating legacy project names. This is not a search-rank guarantee or measured business outcome, and no content is edited or published. There is no honest AI role in this narrow structural review: deterministic checks and source-bound draft guidance are safer and sufficient; SearchLift makes no AI claim.

Run the app tests from the repository root: `python3 -m unittest discover -s apps/searchlift/tests -v`.
