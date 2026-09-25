> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# OnboardPath

**Business need:** Employees and HR staff find policy-grounded onboarding/service guidance and coordinate next steps. **Current live result:** Federal Register OPM metadata for document `2026-19222` (published 2026-09-18) and its matching official GovInfo text both returned HTTP 200 during review. The text is a public-document excerpt only; employee-specific service, applicable employer policy, and permission-scoped employee records remain `UNVERIFIED`.

The read-only workflow queries the [Federal Register OPM metadata API](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest), filtered to agency ID 406 and the ten newest records. It fetches only the exact GovInfo Federal Register issue/granule path matching the record number and publication date; up to eight paragraphs that need no further PII redaction are admitted. The source contract records GovInfo's [reuse notice](https://www.govinfo.gov/about/policies#copyright) and the Federal Register's [reproduction notice](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site); GovInfo warns that embedded third-party content may have separate rights. The Federal Register HTML service is informational, not legal authority; consult official editions for legal research.

From the repository root:

```sh
python3 -m apps.onboardpath
python3 -m unittest discover -s apps/onboardpath/tests -v
```

The metadata and document-text requests are read-only and have no fixture fallback: 403, 429, redirects, timeouts, or schema/provenance failures report `DATA_UNAVAILABLE` for the affected source. `run_demo()` and checked-in request/policy fixtures are regression-test-only. If a safe public text page is returned directly, the shared `LocalOpenAIClient` or `OpenAICompatibleClient` may summarize only that text with its document ID; the result remains `AI CANDIDATE (unwitnessed)` until a separate witness check and is never an employee policy answer. Authorized employee/onboarding records and applicable approved employer policy remain missing, so the full job is `UNVERIFIED`.
