"""Invented examples for local engineering review; never enterprise evidence."""

from __future__ import annotations


def _bundle(slug: str, data: dict[str, object]) -> dict[str, object]:
    return {
        "tenant_id": "synthetic-org",
        "source_ref": f"synthetic-{slug}-001",
        "as_of": "2026-09-26",
        "reviewer": "synthetic-reviewer",
        "provenance_kind": "synthetic",
        "authorized": False,
        "data": data,
    }


EXAMPLES = {
    "ledgerbridge": _bundle("ledgerbridge", {
        "close_period": "2026-09",
        "rows": [
            {"row_id": "L-001", "reference": "INV-001", "side": "ledger", "amount_cents": 2500, "owner": "finance-review"},
            {"row_id": "B-001", "reference": "INV-001", "side": "bank", "amount_cents": 2400, "owner": "finance-review"},
        ],
    }),
    "marketbrief": _bundle("marketbrief", {
        "question": "What do these dated sample reports say about the stated market risk?",
        "max_age_days": 7,
        "reports": [
            {"report_id": "MB-001", "published_on": "2026-09-24", "instrument": "SYNCO", "metric": "revenue_change", "value": 2.5, "unit": "percent", "claim": "The invented sample report records a positive change.", "owner": "research-review"},
            {"report_id": "MB-002", "published_on": "2026-09-10", "instrument": "SYNCO", "metric": "cost_change", "value": 4.0, "unit": "percent", "claim": "The invented cost observation is older than the review window.", "owner": "research-review"},
        ],
    }),
    "chainwatch": _bundle("chainwatch", {
        "threshold": 3,
        "observations": [
            {"event_id": "CW-001", "chain": "ethereum", "address": "0x" + "a" * 40, "rate_units_per_hour": 8, "baseline_units_per_hour": 2, "sample_hours": 12, "owner": "treasury-review"},
        ],
    }),
    "backtestguard": _bundle("backtestguard", {
        "experiments": [
            {"experiment_id": "BG-001", "dataset_id": "sample-dataset-a", "dataset_sha256": "a" * 64, "feature_cutoff": "2025-01-01", "decision_date": "2025-01-02", "label_available_at": "2025-01-03", "source_release_at": "2025-01-01", "holdout_reused": False, "metric": 0.52},
            {"experiment_id": "BG-002", "dataset_id": "sample-dataset-b", "dataset_sha256": "b" * 64, "feature_cutoff": "2025-01-01", "decision_date": "2025-01-02", "label_available_at": "2025-01-03", "source_release_at": "2025-01-04", "holdout_reused": False, "metric": 0.68},
        ],
    }),
    "replycraft": _bundle("replycraft", {
        "consent": {"case_id": "RC-001", "consent_record_id": "RC-CONSENT-001", "status": "authorized"},
        "case": {"case_id": "RC-001", "issue": "The sample product arrived late and needs a policy check.", "product": "sample-product", "unresolved": True, "days_since_purchase": 12},
        "policy": {"policy_id": "RC-POLICY-001", "product": "sample-product", "days_limit": 10, "response_rule": "Escalate delayed delivery for specialist review.", "escalation_queue": "support-specialist", "approved_by": "synthetic-policy-owner"},
    }),
    "handoffhub": _bundle("handoffhub", {
        "question": "Where should this sample invoice mismatch go?",
        "requester_role": "staff",
        "documents": [{"doc_id": "HH-DOC-001", "title": "Sample finance handoff", "body": "Send an invoice mismatch to the finance review queue with its reference and source ID.", "team": "finance", "allowed_roles": ["staff"]}],
        "owners": [{"evidence_id": "HH-OWNER-001", "team": "finance", "owner_id": "finance-review", "next_action": "Check both sides and assign a close owner."}],
    }),
    "sentineldesk": _bundle("sentineldesk", {
        "alerts": [
            {"alert_id": "SD-001", "occurred_at": "2026-09-26T10:00:00Z", "source": "sample-siem", "asset_id": "asset-001", "signal": "Sample suspicious process", "severity": "high", "details": "Invented test alert with no real host data.", "cve_id": "CVE-2026-9999"},
            {"alert_id": "SD-002", "occurred_at": "2026-09-26T10:07:00Z", "source": "sample-siem", "asset_id": "asset-001", "signal": "Sample follow-up event", "severity": "medium", "details": "Invented follow-up signal.", "cve_id": "CVE-2026-9999"},
        ],
        "assets": [{"asset_id": "asset-001", "product": "Sample server", "version": "1.0", "owner_id": "security-on-call"}],
        "threat_context": [{"evidence_id": "SD-THREAT-001", "cve_id": "CVE-2026-9999", "product": "Sample server", "version": "1.0", "published_on": "2026-09-25", "source_url": "https://example.invalid/synthetic-threat"}],
    }),
    "searchlift": _bundle("searchlift", {
        "pages": [{"path": "index.html", "html": "<!doctype html><html lang='en'><head><title>Sample portfolio page</title><meta name='description' content='An invented local page for testing a bounded offline review of titles, headings, links, images, and written content before a human publishes any change.'></head><body><h1>Sample portfolio page</h1><p>This invented page contains enough text to exercise a local structural review. It is not a live customer site or a measured search result.</p><img src='sample.png'><a href='missing.html'>Read the absent page</a></body></html>"}],
    }),
    "pipelinerelay": _bundle("pipelinerelay", {
        "consent": {"evidence_id": "PR-CONSENT-001", "account_id": "account-001", "status": "authorized", "as_of": "2026-09-25"},
        "account": {"evidence_id": "PR-ACCOUNT-001", "account_id": "account-001", "priority": "medium", "renewal_window": "next quarter", "approved_context": "The invented account requested a review of its next renewal window.", "owner_id": "account-owner"},
    }),
    "onboardpath": _bundle("onboardpath", {
        "request": {"request_id": "OP-REQ-001", "employee_ref": "employee-opaque-001", "question": "Which sample onboarding steps are next?", "requested_role": "new_hire", "topic": "start-checklist", "start_date": "2026-10-01"},
        "policies": [{"policy_id": "OP-POLICY-001", "topic": "start-checklist", "answer": "Confirm identity and schedule a welcome review with HR.", "checklist": "Confirm identity;Review schedule;Ask HR about missing items", "owner_id": "hr-onboarding", "allowed_roles": ["new_hire"], "approved_as_of": "2026-09-25"}],
    }),
}
