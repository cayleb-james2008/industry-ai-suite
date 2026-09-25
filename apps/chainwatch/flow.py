"""Validate watch-only chain/address observations and flag rate anomalies."""

from __future__ import annotations

import json
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessPolicy, AuditLog, Authenticator, FixtureAdapter, FixtureData,
    FixtureSchema, HMACTokenCodec, LocalOpenAIClient, Principal, PromptSentinel,
    SecurityCore,
)

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = FixtureSchema({"event_id": str, "chain": str, "address": str,
                        "rate_units_per_hour": float, "baseline_units_per_hour": float,
                        "sample_hours": float, "owner": str})
ALPHA_IDS = ("CW-A-001", "CW-A-002")
BETA_IDS = ("CW-B-CANARY",)
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_CHAINS = {"base", "ethereum"}


@dataclass(frozen=True)
class _Context:
    authenticator: Authenticator
    core: SecurityCore
    audit: AuditLog
    token: str
    fixture: FixtureData


def _context(runtime: Path, tenant_id: str = "tenant-alpha", role: str = "analyst") -> _Context:
    audit = AuditLog(runtime / "audit.jsonl")
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {"tenant-alpha": {"analyst": ALPHA_IDS}, "tenant-beta": {"analyst": BETA_IDS}},
        {"analyst": {"read"}},
    )
    core = SecurityCore(auth, policy, audit)
    actor = Principal(tenant_id, "treasury-demo-a" if tenant_id == "tenant-alpha" else "treasury-demo-b", role)
    token = auth.issue(actor, expires_at=int(time.time()) + 60)
    evidence = ALPHA_IDS if tenant_id == "tenant-alpha" else BETA_IDS
    core.authorize(token, tenant_id=tenant_id, action="read", evidence_ids=evidence)
    fixture = FixtureAdapter(FIXTURES, tenant_id).load("observations.json", SCHEMA)
    return _Context(auth, core, audit, token, fixture)


def detect_anomalies(rows: tuple[dict[str, object], ...], *, threshold: float = 3.0) -> dict[str, object]:
    """Flag rates at least three times baseline after validating chain and EVM address."""
    if threshold <= 1:
        raise ValueError("anomaly threshold must exceed 1")
    events = []
    alerts = []
    seen: set[str] = set()
    sentinel = PromptSentinel()
    for row in rows:
        event_id, chain, address = row["event_id"], row["chain"], row["address"]
        rate, baseline, sample_hours = (row["rate_units_per_hour"],
                                        row["baseline_units_per_hour"], row["sample_hours"])
        owner = row["owner"]
        if (not isinstance(event_id, str) or event_id in seen or chain not in _CHAINS
                or not isinstance(address, str) or not _ADDRESS.fullmatch(address)
                or type(rate) not in {float, int} or type(baseline) not in {float, int}
                or type(sample_hours) not in {float, int} or baseline <= 0 or rate < 0
                or sample_hours <= 0 or not isinstance(owner, str) or not owner):
            raise ValueError("invalid watch-only chain observation")
        sentinel.check(owner, protected_canaries=BETA_IDS)
        seen.add(event_id)
        ratio = float(rate) / float(baseline)
        anomaly = ratio >= threshold
        uncertainty = "low" if sample_hours >= 24 else "medium" if sample_hours >= 6 else "high"
        event = {"event_id": event_id, "chain": chain, "address": address,
                 "rate_units_per_hour": rate, "baseline_units_per_hour": baseline,
                 "rate_to_baseline": round(ratio, 3), "sample_hours": sample_hours,
                 "uncertainty": uncertainty, "anomaly": anomaly, "owner": owner}
        events.append(event)
        if anomaly:
            alerts.append({"event_id": event_id, "owner": owner, "reason": "rate exceeds configured baseline threshold",
                           "rate_to_baseline": round(ratio, 3), "uncertainty": uncertainty})
    return {"observations": events, "alerts": alerts, "threshold_multiple": threshold}


def _ai_summary(ai_client: object, result: dict[str, object], evidence_ids: tuple[str, ...]) -> dict[str, object]:
    prompt = ("Summarize these synthetic watch-only rate alerts for treasury review. "
              "Cite every claim as [evidence:ID], state sample uncertainty, and never request keys or transfers. "
              "Observations: " + json.dumps(result, sort_keys=True))
    ai = complete_grounded(
        ai_client, prompt,
        system="Use only authorized evidence; state uncertainty; watch-only, no keys or transfers.",
        evidence_ids=evidence_ids, protected_canaries=BETA_IDS,
    )
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return ai


def run_live(ai_client: object | None = None) -> dict[str, object]:
    """Fail closed: candidate API terms are not admitted; no chain call is made."""
    return {
        "project": "ChainWatch",
        "status": "UNVERIFIED",
        "source_status": "UNVERIFIED — Mempool API terms could not be read and admitted",
        "reason": "Mempool REST endpoints were reachable, but its terms route returned only a JavaScript shell; no chain source is admitted. The published My First Bitcoin donation address is not an authorized Cayleb/company address.",
        "task_result": None,
        "evidence_ids": [],
        "source_records": [],
        "uncertainty": "Source-owner terms remain unverified; the app makes no chain request. Public organization context does not establish Cayleb/company ownership or exposure.",
        "risk": "No chain exposure, anomaly, or company treasury claim is reported.",
        "human_handoff": {
            "owner": "treasury-operator",
            "next_action": "Make the exact public API terms readable and verify any company watch address before enabling live monitoring.",
        },
        "ai_status": "NOT RUN / NO ADMITTED SOURCE",
        "ai_invoked": False,
        "ai_evidence": None,
        "side_effect_count": 0,
        "integration_adapter": "Source unavailable; no chain request, signing, or transfer capability",
        "capabilities": ["read_only_source_unavailable"],
    }


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """Run a local watch-only JSON demo with zero signing or transfer capability."""
    with tempfile.TemporaryDirectory(prefix="chainwatch-") as runtime:
        context = _context(Path(runtime))
        result = detect_anomalies(context.fixture.rows)
        evidence_ids = tuple(str(row["event_id"]) for row in context.fixture.rows)
        ai = _ai_summary(ai_client, result, evidence_ids)
        audit_receipts = list(context.audit.records())
        return {
            "project": "ChainWatch",
            "tenant_id": str(context.fixture.provenance["tenant_id"]),
            "task_result": result,
            "evidence_ids": list(evidence_ids),
            "source_hashes": {f"{context.fixture.provenance['tenant_id']}/{context.fixture.provenance['source_id']}": context.fixture.provenance["sha256"]},
            "uncertainty": "Rate thresholds are fixture-configured; short observation windows increase uncertainty.",
            "risk": "Alerts are watch-only; chain sampling, attribution, and address ownership are not independently verified.",
            "human_handoff": {"owner": "treasury-monitoring", "next_action": "Verify the address and source window, then decide whether to escalate."},
            **ai,
            "side_effect_count": 0,
            "integration_adapter": "suite_core.FixtureAdapter (tenant-scoped local JSON; read-only)",
            "audit_events": len(audit_receipts),
            "audit_receipts": audit_receipts,
            "capabilities": ["fixture_read", "watch_only_alert"],
        }
