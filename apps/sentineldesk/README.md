> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# SentinelDesk

SentinelDesk requests the official CISA Known Exploited Vulnerabilities (KEV) catalog and prioritizes real records by actual due date, date added, and CVE ID. It groups records into vendor/product review queues using opaque labels, returns a bounded 25-record queue plus the full-feed response hash, and does not create or infer CVSS scores, severity, or organizational exposure.

From the repository root, run `python3 -m apps.sentineldesk`. The JSON receipt includes the actual CISA request/source URLs, stable CVE IDs and source dates, retrieval time, terms, response hash, task fit, human handoff, and zero side effects. An optional grounded local review can be routed through a piece-owned loopback witness proxy with `python3 -m apps.sentineldesk --ai-url http://127.0.0.1:PORT/v1`; the fixed model is `industry-suite-local`, the app writes its private transport trace to `SUITE_AI_TRACE_PATH`, and every material statement must cite the selected CVE ID. Until the lead verifies the matching proxy witness, the app labels the result `AI CANDIDATE (unwitnessed)`; a witness alone does not certify answer quality.

**Important limit:** CISA KEV is public vulnerability-catalog context, not an organization's own alerts, incidents, or affected assets. The full security-operations workflow remains `UNVERIFIED` without an authorized alert source and asset inventory. A human must check affected products and versions against approved internal sources. Containment and account changes are not available.

If CISA returns an invalid, unavailable, or privacy-redacted due date, the app reports `DATA_UNAVAILABLE` or `UNVERIFIED` and does not invent a ranking deadline or use a fixture/cache fallback.

`run_demo()` and the checked-in tenant fixtures are retained for fixture regression tests only. The normal CLI does not select them and does not fall back to them if CISA is unavailable.

The fixture tests continue to check historical incident correlation, tenant isolation, canary/PII protections, and the simulated-only containment gate. No real containment or account change is executed by the live path.

The shared ten-workflow runner is outside this piece's write scope and still needs a separately scoped integration update before it can select this live path by default.

Run the app tests from the repository root: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/sentineldesk/tests -v`.
