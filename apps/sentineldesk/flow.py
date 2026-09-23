"""Fixture-only alert regressions and live CISA KEV public-context review."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessPolicy,
    ApprovalAuthority,
    AuditLog,
    Authenticator,
    DataUnavailable,
    FixtureAdapter,
    FixtureSchema,
    HMACTokenCodec,
    LocalOpenAIClient,
    Principal, PromptInjectionError, PromptSentinel,
    Provider,
    SecurityCore,
    SimulatedSink,
    SourceRecord,
    SourceResult,
    TaskFit,
    UnverifiedSource,
    fetch_live,
    redact,
)
APP_DIR = Path(__file__).resolve().parent
FIXTURE_ROOT = APP_DIR / "fixtures"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ACTION_TRIAGE = "triage_alerts"
ACTION_SIMULATE_CONTAINMENT = "simulate_containment"
TENANT_EVIDENCE = {
    TENANT_A: ("SD-A-001", "SD-A-002", "SD-A-003", "SD-A-004"),
    TENANT_B: ("SD-B-001",),
}
PROTECTED_CANARIES = ("SENTINEL_TENANT_B_ONLY_CANARY_4F7A",)
ALERT_SCHEMA = FixtureSchema({
    "alert_id": str,
    "occurred_at": str,
    "source": str,
    "asset_id": str,
    "signal": str,
    "severity": str,
    "details": str,
})
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CISA_TERMS_URL = "https://creativecommons.org/publicdomain/zero/1.0/"


def _new_security(audit_path: Path) -> tuple[SecurityCore, Authenticator]:
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            TENANT_A: {
                "analyst": TENANT_EVIDENCE[TENANT_A],
                "incident_commander": TENANT_EVIDENCE[TENANT_A],
            },
            TENANT_B: {
                "analyst": TENANT_EVIDENCE[TENANT_B],
                "incident_commander": TENANT_EVIDENCE[TENANT_B],
            },
        },
        {"analyst": {ACTION_TRIAGE}, "incident_commander": {"approve"}},
    )
    return SecurityCore(auth, policy, AuditLog(audit_path)), auth


def _authorized_alerts(
    core: SecurityCore, token: str, *, tenant_id: str, fixture_root: Path = FIXTURE_ROOT
) -> tuple[tuple[dict[str, object], ...], dict[str, object]]:
    evidence_ids = TENANT_EVIDENCE.get(tenant_id, ())
    principal = core.authorize(
        token, tenant_id=tenant_id, action=ACTION_TRIAGE, evidence_ids=evidence_ids
    )
    fixture = FixtureAdapter(fixture_root, principal.tenant_id).load("alerts.json", ALERT_SCHEMA)
    actual_ids = tuple(str(row["alert_id"]) for row in fixture.rows)
    if set(actual_ids) != set(evidence_ids) or len(actual_ids) != len(evidence_ids):
        raise ValueError("security fixture evidence does not match its tenant allowlist")
    return fixture.rows, fixture.provenance


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("alert timestamp must be text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("alert timestamps must include a timezone")
    return parsed


def correlate_alerts(rows: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    """Group alerts by asset when adjacent observations are no more than 15 minutes apart."""
    by_asset: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row.get("severity") not in SEVERITY_RANK:
            raise ValueError("alert severity is outside the supported scale")
        by_asset[str(row["asset_id"])].append(row)

    incidents: list[dict[str, object]] = []
    for asset_id, asset_rows in by_asset.items():
        ordered = sorted(asset_rows, key=lambda row: (_time(row["occurred_at"]), str(row["alert_id"])))
        groups: list[list[dict[str, object]]] = []
        for row in ordered:
            if not groups or (_time(row["occurred_at"]) - _time(groups[-1][-1]["occurred_at"])).total_seconds() > 900:
                groups.append([row])
            else:
                groups[-1].append(row)
        for group in groups:
            evidence_ids = [str(row["alert_id"]) for row in group]
            severity = max((str(row["severity"]) for row in group), key=SEVERITY_RANK.__getitem__)
            first = str(group[0]["alert_id"])
            incident_id = "SD-INC-" + hashlib.sha256(f"{asset_id}:{first}".encode()).hexdigest()[:10]
            incidents.append({
                "incident_id": incident_id,
                "asset_id": asset_id,
                "severity": severity,
                "evidence_ids": evidence_ids,
                "timeline": [
                    {
                        "occurred_at": row["occurred_at"],
                        "alert_id": row["alert_id"],
                        "source": row["source"],
                        "signal": row["signal"],
                        "severity": row["severity"],
                        "details": redact(row["details"]),
                    }
                    for row in group
                ],
                "correlation": "same asset; adjacent alerts within a 15-minute window",
            })
    return sorted(incidents, key=lambda incident: (incident["timeline"][0]["occurred_at"], incident["incident_id"]))


def _model_review(
    ai_client: object | None,
    incidents: list[dict[str, object]],
    evidence_ids: tuple[str, ...],
) -> tuple[str, str, bool, dict[str, object] | None]:
    source_text = json.dumps(incidents, sort_keys=True, ensure_ascii=True)
    prompt = (
        "Review this synthetic security incident summary. Keep severity and evidence unchanged; "
        "state uncertainty and recommend a human next step. Cite supplied IDs inline as "
        "[evidence:ID]. Never contain a host or change an account.\n"
        f"Allowed evidence: {', '.join(evidence_ids)}\nIncidents: {source_text}"
    )
    ai = complete_grounded(
        ai_client, prompt,
        system="You are a local triage assistant. Use only supplied evidence; do not execute actions.",
        evidence_ids=evidence_ids, protected_canaries=PROTECTED_CANARIES,
    )
    return (
        str(ai["ai_output"] or ai["ai_handoff"] or ""),
        str(ai["ai_status"]),
        bool(ai["ai_invoked"]),
        ai["ai_evidence"] if isinstance(ai["ai_evidence"], dict) else None,
    )


def create_containment_gate(
    audit: AuditLog, approval_security: SecurityCore
) -> tuple[ApprovalAuthority, SimulatedSink]:
    """Create a simulated-only gate using the app's trusted approval identity boundary."""
    authority = ApprovalAuthority(
        HMACTokenCodec(secrets.token_bytes(32)), approver_roles={"incident_commander"},
        security_core=approval_security,
    )
    sink = SimulatedSink(authority, audit, allowed_actions={ACTION_SIMULATE_CONTAINMENT})
    return authority, sink


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """Run a tenant-A-only triage demo; it never requests containment or changes accounts."""
    with TemporaryDirectory(prefix="sentineldesk-demo-") as runtime:
        core, auth = _new_security(Path(runtime) / "audit.jsonl")
        actor = Principal(TENANT_A, "secops-analyst", "analyst")
        token = auth.issue(actor, expires_at=int(time.time()) + 120)
        rows, provenance = _authorized_alerts(core, token, tenant_id=TENANT_A)

    for row in rows:
        PromptSentinel().check(str(row["details"]), protected_canaries=PROTECTED_CANARIES)
    incidents = correlate_alerts(rows)
    evidence_ids = tuple(str(row["alert_id"]) for row in rows)
    review, ai_status, ai_invoked, ai_evidence = _model_review(ai_client, incidents, evidence_ids)
    highest = max((str(item["severity"]) for item in incidents), key=SEVERITY_RANK.__getitem__)
    evidence = [
        {
            "evidence_id": row["alert_id"],
            "source_id": provenance["source_id"],
            "source_hash": provenance["sha256"],
            "record": redact(row),
        }
        for row in rows
    ]
    return {
        "app": "SentinelDesk",
        "tenant_id": TENANT_A,
        "result": {
            "incident_count": len(incidents),
            "alert_count": len(rows),
            "incidents": incidents,
            "review_summary": review,
        },
        "evidence": evidence,
        "source_hash": provenance["sha256"],
        "risk": {
            "level": highest,
            "explanation": "Severity is the highest supplied alert rating; alerts are grouped by asset and 15-minute proximity.",
            "uncertainty": "Synthetic fixture only; alert signatures and timestamps are not independently validated. No containment or account change was performed.",
        },
        "handoff": {
            "owner": "security-operations-on-call",
            "next_action": "Review the preserved timeline and confirm the asset and alert context before deciding on containment.",
            "approval_required_for": ["containment", "account_change"],
        },
        "ai_status": ai_status,
        "ai_invoked": ai_invoked,
        "ai_evidence": ai_evidence,
        "side_effect_count": 0,
        "adapter": "tenant-confined FixtureAdapter + local correlation + optional verified loopback LocalOpenAIClient + approval-gated simulated-only sink",
    }


def _live_failure(
    status: str, reason: str, source: SourceResult | None = None,
) -> dict[str, object]:
    source_receipt: dict[str, object] = {"provider": Provider.CISA_KEV.value}
    if source is not None:
        source_receipt.update({
            "request_url": source.request_url,
            "response_status": source.response_status,
            "response_sha256": source.response_sha256,
            "request_body_sha256": source.request_body_sha256,
            "retrieved_at_utc": source.retrieved_at_utc,
            "read_only": source.read_only,
            "task_fit": source.task_fit,
            "record_count": len(source.records),
        })
        if source.records:
            source_receipt["terms_url"] = source.records[0].terms_url
    evidence = []
    if status == "UNVERIFIED" and source is not None:
        evidence = [
            {
                "source_id": record.source_id,
                "source_url": record.source_url,
                "as_of": record.as_of,
                "as_of_precision": record.as_of_precision,
                "retrieved_at_utc": record.retrieved_at_utc,
                "terms_url": record.terms_url,
                "response_status": record.response_status,
                "response_sha256": record.response_sha256,
                "read_only": record.read_only,
                "task_fit": record.task_fit,
            }
            for record in source.records
        ]
    return {
        "app": "SentinelDesk",
        "status": status,
        "workflow_status": "UNVERIFIED — no authorized organizational alert or asset source",
        "result": None,
        "source": source_receipt,
        "evidence": evidence,
        "risk": {
            "statement": "No organizational exposure or alert conclusion is available.",
            "uncertainty": reason,
        },
        "handoff": {
            "owner": "security-defender-review",
            "next_action": "Retry the admitted public source later, then compare its records with an authorized asset and alert source.",
            "containment_or_account_change": "not available",
        },
        "ai_status": "NOT RUN — no verified source records",
        "ai_invoked": False,
        "ai_evidence": None,
        "ai_verification_status": "UNVERIFIED — no independent AI observer",
        "side_effect_count": 0,
        "adapter": "suite_core.fetch_live; no fixture or cached fallback",
    }


def _cisa_finding(record: SourceRecord) -> dict[str, object]:
    data = record.data
    cve = record.source_id
    if (
        record.provider != Provider.CISA_KEV.value
        or record.task_fit != TaskFit.PUBLIC_KEV_CONTEXT.value
        or record.as_of_precision != "day"
        or not record.read_only
        or record.terms_url != CISA_TERMS_URL
        or not re.fullmatch(r"CVE-\d{4}-\d{4,8}", cve)
    ):
        raise DataUnavailable("CISA record provenance or identity schema mismatch")
    try:
        added = date.fromisoformat(record.as_of)
        if added.isoformat() != record.as_of:
            raise ValueError
    except ValueError as error:
        raise DataUnavailable("CISA record as-of date is invalid") from error

    vendor = data.get("vendorProject")
    product = data.get("product")
    if vendor is not None and not isinstance(vendor, str):
        raise DataUnavailable("CISA vendor field schema mismatch")
    if product is not None and not isinstance(product, str):
        raise DataUnavailable("CISA product field schema mismatch")
    for label in (vendor, product):
        if label is not None:
            PromptSentinel().check(label, protected_canaries=PROTECTED_CANARIES)
    due_value = data.get("dueDate")
    due_date: str | None = None
    if due_value == "[REDACTED]":
        raise UnverifiedSource(
            "shared source privacy projection redacted CISA dueDate; due-date prioritization needs an upstream projection repair"
        )
    if due_value not in (None, ""):
        if not isinstance(due_value, str):
            raise DataUnavailable("CISA due date schema mismatch")
        try:
            parsed_due = date.fromisoformat(due_value)
            if parsed_due.isoformat() != due_value:
                raise ValueError
            due_date = due_value
        except ValueError as error:
            raise DataUnavailable("CISA due date is invalid") from error
    return {
        "source_id": cve,
        "date_added": record.as_of,
        "due_date": due_date,
        "vendor_project": vendor,
        "product": product,
    }


def _opaque_source_group_id(kind: str, source_ids: list[str]) -> str:
    """Build a stable public handle from CVE IDs, never from source label text."""
    digest = hashlib.sha256("\0".join(sorted(source_ids)).encode("utf-8")).hexdigest()
    return f"{kind}-{digest}"


def _priority_key(finding: dict[str, object]) -> tuple[bool, str, str, str]:
    due_date = finding["due_date"]
    return (
        due_date is None,
        str(due_date or ""),
        str(finding["date_added"]),
        str(finding["source_id"]),
    )


def _live_review(
    ai_client: LocalOpenAIClient | None, findings: list[dict[str, object]],
) -> tuple[str, str, bool, dict[str, object] | None]:
    candidates = findings[:12]
    evidence_ids = tuple(str(item["source_id"]) for item in candidates)
    prompt = (
        "Review only these real CISA KEV catalog records. Explain the source-backed public "
        "vulnerability context and identify what a human defender should verify next. Do not "
        "infer this organization's alerts, affected assets, exposure, severity, CVSS, or need "
        "for containment. Cite each material statement using [evidence:CVE-ID].\n"
        f"Records: {json.dumps(candidates, sort_keys=True)}"
    )
    ai = complete_grounded(
        ai_client, prompt,
        system="You are a public-vulnerability-context assistant. Do not execute actions.",
        evidence_ids=evidence_ids,
    )
    return (
        str(ai["ai_output"] or ai["ai_handoff"] or ""),
        str(ai["ai_status"]),
        bool(ai["ai_invoked"]),
        ai["ai_evidence"] if isinstance(ai["ai_evidence"], dict) else None,
    )


def run_live(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Use the live CISA KEV catalog as public context, never as org alerts."""
    try:
        source = fetch_live(
            Provider.CISA_KEV,
            task_fit=TaskFit.PUBLIC_KEV_CONTEXT,
        )
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error))
    except UnverifiedSource as error:
        return _live_failure("UNVERIFIED", str(error))

    if source.status != "VERIFIED_SOURCE":
        return _live_failure(source.status, source.reason or "CISA source is not verified", source)
    if not source.records:
        return _live_failure("UNVERIFIED", "CISA returned no consumable vulnerability records", source)
    try:
        findings = sorted((_cisa_finding(record) for record in source.records), key=_priority_key)
    except PromptInjectionError:
        return _live_failure("UNVERIFIED", "CISA source text was rejected by the app safety boundary.", source)
    except (DataUnavailable, UnverifiedSource) as error:
        return _live_failure(error.status, str(error), source)

    vendor_rows: dict[str | None, list[dict[str, object]]] = defaultdict(list)
    product_rows: dict[tuple[str | None, str | None], list[dict[str, object]]] = defaultdict(list)
    for finding in findings:
        vendor = finding["vendor_project"]
        product = finding["product"]
        vendor_rows[vendor].append(finding)
        product_rows[(vendor, product)].append(finding)
    vendor_ids = {
        vendor: _opaque_source_group_id(
            "vendor", [str(row["source_id"]) for row in rows]
        )
        for vendor, rows in vendor_rows.items() if vendor is not None
    }
    product_ids = {
        key: _opaque_source_group_id(
            "product", [str(row["source_id"]) for row in rows]
        )
        for key, rows in product_rows.items()
    }

    # This label-minimized shape is shared by output and the model prompt.
    def public_finding(finding: dict[str, object]) -> dict[str, object]:
        vendor, product = finding["vendor_project"], finding["product"]
        return {
            "source_id": finding["source_id"],
            "date_added": finding["date_added"],
            "due_date": finding["due_date"],
            "vendor_project_id": vendor_ids.get(vendor),
            "product_id": product_ids[(vendor, product)],
        }

    public_findings = [public_finding(finding) for finding in findings]
    safe_by_source_id = {str(item["source_id"]): item for item in public_findings}
    ordered_groups = []
    for (vendor, product), rows in product_rows.items():
        source_ids = [str(row["source_id"]) for row in rows]
        ordered_groups.append((rows[0], {
            "vendor_project_id": vendor_ids.get(vendor),
            "product_id": product_ids[(vendor, product)],
            "record_count": len(rows),
            "source_ids": source_ids,
            "priority_examples": [safe_by_source_id[source_id] for source_id in source_ids[:3]],
        }))
    ordered_groups.sort(key=lambda item: _priority_key(item[0]))
    groups = [group for _, group in ordered_groups]
    records = source.records
    first = records[0]
    review, ai_status, ai_invoked, ai_evidence = _live_review(ai_client, public_findings)
    return {
        "app": "SentinelDesk",
        "status": "VERIFIED_SOURCE",
        "workflow_status": "UNVERIFIED — no authorized organizational alert or asset source",
        "result": {
            "catalog_record_count": len(findings),
            "product_group_count": len(groups),
            "priority_method": "earliest actual dueDate first; then actual dateAdded and CVE ID; records without dueDate sort after dated records",
            "review_queue": public_findings[:25],
            "review_queue_truncated": len(findings) > 25,
            "product_groups": groups,
            "human_review_summary": review,
        },
        "source": {
            "provider": source.provider,
            "request_url": source.request_url,
            "source_url": first.source_url,
            "response_status": source.response_status,
            "response_sha256": source.response_sha256,
            "request_body_sha256": source.request_body_sha256,
            "retrieved_at_utc": source.retrieved_at_utc,
            "terms_url": first.terms_url,
            "read_only": source.read_only,
            "task_fit": source.task_fit,
            "task_fit_note": "Public CISA vulnerability-catalog context only; not an organization's alert, incident, or asset source.",
        },
        "evidence": [
            {
                "source_id": item.source_id,
                "source_url": item.source_url,
                "as_of": item.as_of,
                "as_of_precision": item.as_of_precision,
                "retrieved_at_utc": item.retrieved_at_utc,
                "terms_url": item.terms_url,
                "response_status": item.response_status,
                "response_sha256": item.response_sha256,
                "read_only": item.read_only,
                "task_fit": item.task_fit,
            }
            for item in records
        ],
        "risk": {
            "statement": "KEV membership is public vulnerability context; no CVSS score, severity rating, or organizational exposure is inferred.",
            "uncertainty": "No authorized organization alert feed or asset inventory was queried; a defender must verify affected products and versions against approved internal sources.",
        },
        "handoff": {
            "owner": "security-defender-review",
            "next_action": "Compare cited CVEs with an authorized asset inventory and alert source, then validate product/version applicability before deciding on a response.",
            "containment_or_account_change": "not available",
        },
        "ai_status": ai_status,
        "ai_invoked": ai_invoked,
        "ai_evidence": ai_evidence,
        "ai_verification_status": "UNVERIFIED — app-reported AI execution is not independent evidence",
        "side_effect_count": 0,
        "adapter": "suite_core.fetch_live(Provider.CISA_KEV); no fixture or cached fallback",
    }
