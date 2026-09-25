> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# HandoffHub

HandoffHub requests current public Office of Personnel Management (OPM) metadata, then fetches the matching document directly from the official GovInfo Federal Register edition URL. The live source review returned HTTP 200 for metadata document `2026-19222` (published 2026-09-18) and HTTP 200 for the matching GovInfo HTML text. The FederalRegister.gov challenge route is not followed or bypassed; the shared transport still refuses redirects. GovInfo reuse terms are recorded with the source receipt. This narrow public-text handoff is not internal knowledge, an employer-approved policy, proof of workplace permissions, or evidence of a real owner; the full staff job remains `UNVERIFIED`.

The read-only discovery request is [the Federal Register OPM metadata API](https://www.federalregister.gov/api/v1/documents.json?conditions%5Bagency_ids%5D%5B%5D=406&per_page=10&order=newest), filtered to agency ID 406 and the ten newest records. Text is fetched only from the fixed GovInfo URL whose issue date and document number match the admitted metadata. The adapter refuses redirects, cache, and fixture fallback; paragraphs that need PII redaction are omitted. [GovInfo's reuse notice](https://www.govinfo.gov/about/policies#copyright) describes U.S. government work as generally public domain while warning that embedded third-party material is not thereby licensed. The [Federal Register reproduction notice](https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/about-this-site) describes reproduction under 1 CFR 2.6. Consult the official edition for legal research.

From the repository root:

```sh
python3 -m apps.handoffhub
python3 -m unittest discover -s apps/handoffhub/tests -v
```

Both public GET requests are read-only and have no fixture fallback: 403, 429, timeout, redirects, invalid HTML/schema, mismatched document identity, or an unsafe text projection yields a source-status label without substitute records. The live path uses a deterministic text excerpt only when text is available; AI is not used. `run_demo()` and checked-in synthetic guide/owner fixtures are regression-test-only. The paired forbidden-document request is denied and audited before that document's contents are loaded; this does not prove real workplace permissions. Authorized permission-scoped internal knowledge and a real owner remain missing, so the full job stays `UNVERIFIED`.
