> **Operator model:** plain English first. This is an input guide, not a claim of enterprise deployment.

# Organization review inputs

The local workbench now has a working import and review path for each product. Choose a product, select **Organization bundle · local only**, and click **Load safe example** to inspect its exact JSON fields. Those examples are invented engineering checks. The workbench processes a permitted, de-identified export in memory and returns a bounded receipt. It does not connect to an employer, verify the person using it, authenticate a tenant, or prove that an imported record is complete or genuine. All ten full organization jobs remain **UNVERIFIED**.

Use one envelope around the product's `data` object:

```json
{
  "tenant_id": "opaque-organization-code",
  "source_ref": "opaque-export-reference",
  "as_of": "2026-09-26",
  "reviewer": "opaque-reviewer-code",
  "provenance_kind": "operator_asserted",
  "authorized": true,
  "data": { }
}
```

`operator_asserted` and `authorized: true` record the importer's assertion, not an access decision by an identity system. For an invented example use `provenance_kind: "synthetic"` and `authorized: false`. The request limit is 128 KB; the normalized bundle limit is 120 KB. Each list holds at most 200 records, except knowledge and HR lists at 50 and HTML pages at 20. No credentials or direct personal identifiers belong in an import. The browser holds the pasted data until it is replaced or closed. The server does not write the input to disk or a remote service; choosing **Download receipt** saves the minimized output on your computer. Inspect it before sharing.

| Product | Minimum permitted input for a meaningful local review | What it returns | What remains needed to verify the full job |
|---|---|---|---|
| LedgerBridge | One close period; de-identified ledger and bank rows with unique row IDs, reconciliation reference, side, amount in cents, and owner code. | Accounted rows, variance and missing-side exceptions, owner queue. | Finance-controlled ledger and bank exports, completeness check, assigned reviewers, approval and posting audit. |
| MarketBrief | Research question; dated, licensed company or market report extracts with unique IDs, instrument, metric, numeric value, unit, claim, and owner code. | Current, stale, and future-dated cited claims. | Original reports and license rights, release timing, analyst access, independent risk judgment. |
| ChainWatch | Watch-only EVM address observations with unique event IDs, chain, measured and baseline rates, sample hours, owner code, and threshold. | Rate alerts and sample-window uncertainty; addresses are masked in output. | Verified address ownership, permitted chain source and sampling history, treasury escalation process. Never provide keys. |
| BacktestGuard | Experiment IDs, dataset IDs and SHA-256 hashes, feature cutoffs, decision and label dates, source-release dates, holdout-reuse flags, and metrics. | Per-experiment leakage and holdout gate; blocked experiments. | Dataset lineage, original experiment logs, target and selection history, independent research approval. |
| ReplyCraft | De-identified support case, matching consent record, and approved product policy with policy owner and escalation queue. | Policy-cited draft or escalation, with no send action. | Actual current consent, policy approval, authorized agent access, customer-safe final review and separate send approval. |
| HandoffHub | Staff question, knowledge documents with asserted role grants, and team owner map; include only documents the importer may inspect. | One relevant cited excerpt and next-owner handoff, or an explicit unanswered result. | Authenticated requester, current document permissions, controlled knowledge repository, real owner acceptance. |
| SentinelDesk | De-identified alerts with IDs, timestamps, source, asset ID, severity, signal and CVE; matching asset inventory with product, version, owner; separately sourced public threat records with CVE, product/version labels, date and HTTPS source. An empty threat list is allowed and marked unavailable. | Correlated incident timeline and asset context; imported CVE/product/version label comparison; applicability remains unverified. | Authorized security-tool and inventory access, authentic alert evidence, current public threat source and vulnerability match, responder decision. |
| SearchLift | One to twenty permitted relative-path HTML pages; no remote URL is fetched. | Page-hash-linked title, description, heading, image, link, and thin-content issues. | Site-owner rights, whole-site context, editorial review, separate publication decision; rankings and traffic require measurement. |
| PipelineRelay | De-identified account context with evidence and owner IDs, priority and renewal window; matching dated consent evidence. | Cited account handoff with no outreach. | Authenticated CRM access, current account/consent policy, owner confirmation and separate contact approval. |
| OnboardPath | De-identified request with opaque employee reference, role, topic and start date; matching approved HR policy, role grants, owner and checklist. | Policy-cited answer and checklist with HR handoff; no employment decision. | Authenticated employee/HR access, authoritative current policy, personnel context and human service review. |

An omitted, malformed, duplicate, or unsafe field is rejected; a missing match or asserted role/consent denial returns no task result. These checks operate on submitted records only. A passing check is not proof of organizational authority. The import path makes no model request, and every receipt says `AI: NOT RUN`. The existing five independently witnessed local model samples concern earlier bounded public-data journeys.
