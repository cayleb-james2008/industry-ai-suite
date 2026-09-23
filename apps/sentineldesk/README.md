> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# SentinelDesk

SentinelDesk's normal command requests the official CISA Known Exploited Vulnerabilities (KEV) catalog. The CISA response currently returns actual source records, but the shared privacy projection redacts `dueDate`; the app therefore returns `UNVERIFIED` source provenance without a prioritized queue. Once that projection is repaired, the implemented queue groups actual catalog records by vendor/product and orders them by actual due date, date added, vendor, product, and CVE identifier. It does not create or infer a CVSS score or severity.

From the repository root, run `python3 -m apps.sentineldesk`. The current JSON receipt includes the actual CISA source URL, stable CVE IDs/as-of dates, retrieval time, terms, response hash, task fit, the projection blocker, and zero side effects. When the adapter supplies all required fields, an optional `LocalOpenAIClient` receives only admitted CISA records and must cite their CVE IDs; app-reported model output remains unverified without an independent observer.

**Important limit:** CISA KEV is public vulnerability-catalog context, not an organization's own alerts, incidents, or affected assets. R09 and the full security-operations workflow remain `UNVERIFIED` without an authorized alert source and asset inventory. The human must check affected products and versions against approved internal sources. Containment and account changes are not available.

Current adapter blocker: the shared source projection returns actual CISA `dateAdded` as the source as-of value, but redacts `dueDate`; SentinelDesk therefore records source provenance and returns `UNVERIFIED` rather than ranking with an invented deadline. The shared adapter/privacy projection is outside this piece's writable scope.

`run_demo()` and the checked-in tenant fixtures are retained for fixture regression tests only. The normal CLI does not select them and does not fall back to them if CISA is unavailable.

The fixture tests continue to check historical incident correlation, tenant isolation, canary/PII protections, and the simulated-only containment gate. No real containment or account change is executed by the live path.

The shared ten-workflow runner is outside this piece's write scope and still needs a separately scoped integration update before it can select this live path by default.

Run the app tests from the repository root: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/sentineldesk/tests -v`.
