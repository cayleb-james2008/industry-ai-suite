> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# OnboardPath

**Business need:** Help a human reviewer navigate public OPM documents that may inform an onboarding review; this app does not provide employee-specific guidance. **Last recorded live result:** Federal Register OPM metadata for document `2026-19222` (published 2026-09-18) and its matching official GovInfo text both returned HTTP 200 during review. The text is a public-document excerpt only; employee-specific service, applicable employer policy, and permission-scoped employee records remain `UNVERIFIED`.

The read-only workflow queries the [Federal Register OPM metadata API](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest), filtered to agency ID 406 and the ten newest records. By default it reviews the first eligible Rule or Proposed Rule; `--document-number` selects exactly one eligible record already present in that fresh response. Malformed or nonmatching numbers stop before any GovInfo text request. It fetches only the exact GovInfo Federal Register issue/granule path matching the selected record and publication date; safe returned section text (up to eight excerpts, with stable `document-id#SECTION` citations) and the metadata/text hashes, dates, retrieval times, and terms are included in the review. GovInfo's [reuse notice](https://www.govinfo.gov/about/policies#copyright) warns that embedded third-party content may have separate rights. The Federal Register HTML service is informational, not legal authority; consult official editions for legal research.

From the repository root:

```sh
python3 -m apps.onboardpath
python3 -m apps.onboardpath --document-number 2026-19222
python3 -m unittest discover -s apps/onboardpath/tests -v
```

The metadata and document-text requests are read-only and have no fixture fallback: 403, 429, redirects, timeouts, or schema/provenance failures report `DATA_UNAVAILABLE` for the affected source. A selection that is malformed or absent from the current Rule/Proposed Rule metadata returns a no-document/`UNVERIFIED` handoff without requesting GovInfo text. `run_demo()` and checked-in request/policy fixtures are regression-test-only. Any optional AI candidate is unwitnessed and is not employee guidance. Authorized employee/onboarding records and applicable approved employer policy remain missing, so the full job stays `UNVERIFIED`; public text is not HR policy, legal advice, employee evidence, hiring/disciplinary guidance, permission proof, or an action.
