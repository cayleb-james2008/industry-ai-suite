> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# HandoffHub

HandoffHub's normal command discovers public Office of Personnel Management (OPM) documents from live Federal Register metadata. It returns only document title, document number, publication date, and source provenance. It does not generate a policy answer or claim internal knowledge, employee permissions, or private records. The full staff handoff remains `UNVERIFIED` until authorized internal knowledge and owner records are supplied.

The read-only request is [the Federal Register OPM metadata API](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest), filtered to agency ID 406 and the ten newest records. The official [About This Site notice](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction of material in Federal Register editions under 1 CFR 2.6. This app reads metadata, not full policy text; the Federal Register HTML service is informational, so use official editions for legal research.

From the repository root:

```sh
python3 -m apps.handoffhub
python3 -m unittest discover -s apps/handoffhub/tests -v
```

The public metadata request is read-only and has no fixture fallback: 403, 429, timeout, or schema failure returns `DATA_UNAVAILABLE`. `run_demo()` and checked-in synthetic guide/owner fixtures are regression-test-only. An optional `LocalOpenAIClient` supplied through `run_live(ai_client=...)` may summarize admitted public metadata with source citations only; this is not an AI-complete claim and cannot answer policy questions. Authorized permission-scoped internal knowledge and owner records are still missing, so the full job remains `UNVERIFIED`.
