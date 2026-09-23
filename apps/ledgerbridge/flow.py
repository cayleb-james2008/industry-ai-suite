"""Reconcile public Treasury cash rows; keep fixture reconciliation test-only."""

from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessPolicy, AuditLog, Authenticator, DataUnavailable, FixtureAdapter,
    FixtureData, FixtureSchema, HMACTokenCodec, LocalOpenAIClient, Principal,
    PromptInjectionError, PromptSentinel, Provider, SecurityCore, SourceRecord,
    SourceResult, TaskFit, UnverifiedSource, fetch_live,
)
from suite_core.privacy import project_source_metadata

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = FixtureSchema({"row_id": str, "reference": str, "side": str,
                        "amount_cents": int, "owner": str})
ALPHA_IDS = ("LB-A-001", "LB-A-002", "LB-A-003", "LB-A-004", "LB-A-005", "LB-A-006", "LB-A-007")
BETA_IDS = ("LB-B-CANARY",)


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
    actor_id = "finance-demo-a" if tenant_id == "tenant-alpha" else "finance-demo-b"
    actor = Principal(tenant_id, actor_id, role)
    token = auth.issue(actor, expires_at=int(time.time()) + 60)
    allowed = ALPHA_IDS if tenant_id == "tenant-alpha" else BETA_IDS
    core.authorize(token, tenant_id=tenant_id, action="read", evidence_ids=allowed)
    fixture = FixtureAdapter(FIXTURES, tenant_id).load("ledger.json", SCHEMA)
    return _Context(auth, core, audit, token, fixture)


def reconcile(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    """Classify each row once; duplicates, missing sides, and amount differences remain explicit."""
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    seen: set[str] = set()
    sentinel = PromptSentinel()
    for row in rows:
        row_id, reference, side = row["row_id"], row["reference"], row["side"]
        amount, owner = row["amount_cents"], row["owner"]
        if (not isinstance(row_id, str) or row_id in seen or not isinstance(reference, str)
                or not reference or side not in {"ledger", "bank"} or type(amount) is not int
                or amount < 0 or not isinstance(owner, str) or not owner):
            raise ValueError("invalid or duplicate reconciliation row")
        sentinel.check(owner, protected_canaries=BETA_IDS)
        seen.add(row_id)
        grouped[reference].append(row)

    reconciled = []
    owner_queue = []
    for reference, group in sorted(grouped.items()):
        ledger = [row for row in group if row["side"] == "ledger"]
        bank = [row for row in group if row["side"] == "bank"]
        reasons = []
        if len(ledger) > 1 or len(bank) > 1:
            reasons.append("duplicate")
        if not ledger or not bank:
            reasons.append("missing-side")
        variance = None
        if not reasons and ledger[0]["amount_cents"] != bank[0]["amount_cents"]:
            reasons.append("variance")
            variance = bank[0]["amount_cents"] - ledger[0]["amount_cents"]
        status = "matched" if not reasons else "+".join(reasons)
        reconciled.extend({"row_id": row["row_id"], "reference": reference, "status": status}
                          for row in group)
        if reasons:
            owner_queue.append({"reference": reference,
                                "owners": sorted({str(row["owner"]) for row in group}),
                                "reasons": reasons, "variance_cents": variance})
    return {
        "input_row_count": len(rows),
        "accounted_row_count": len(reconciled),
        "accounted_row_ids": [item["row_id"] for item in reconciled],
        "reconciled_rows": reconciled,
        "owner_queue": owner_queue,
    }


def _ai_summary(ai_client: object, result: dict[str, object], evidence_ids: tuple[str, ...]) -> dict[str, object]:
    prompt = ("Summarize these synthetic reconciliation exceptions for a finance reviewer. "
              "Use only the listed evidence and cite every claim as [evidence:ID]. "
              "Do not suggest or perform posting. Data: " + json.dumps(result, sort_keys=True))
    ai = complete_grounded(
        ai_client, prompt, system="Use only supplied evidence; state uncertainty; no ledger posting.",
        evidence_ids=evidence_ids, protected_canaries=BETA_IDS,
    )
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return ai


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """ADVERSARIAL REGRESSION TEST ONLY: read local fixture data; never posts."""
    with tempfile.TemporaryDirectory(prefix="ledgerbridge-") as runtime:
        context = _context(Path(runtime))
        result = reconcile(context.fixture.rows)
        evidence_ids = tuple(str(row["row_id"]) for row in context.fixture.rows)
        _ai = _ai_summary(ai_client, result, evidence_ids)
        audit_receipts = list(context.audit.records())
        return {
            "project": "LedgerBridge",
            "tenant_id": str(context.fixture.provenance["tenant_id"]),
            "task_result": result,
            "evidence_ids": list(evidence_ids),
            "source_hashes": {f"{context.fixture.provenance['tenant_id']}/{context.fixture.provenance['source_id']}": context.fixture.provenance["sha256"]},
            "uncertainty": "Exact fixture arithmetic only; no external ledger was queried.",
            "risk": "Duplicate and unmatched items require human review; this workflow cannot post entries.",
            "human_handoff": {"owner": "finance-close-review", "next_action": "Review each queued exception against approved records."},
            **_ai,
            "side_effect_count": 0,
            "integration_adapter": "suite_core.FixtureAdapter (tenant-scoped local JSON; read-only)",
            "audit_events": len(audit_receipts),
            "audit_receipts": audit_receipts,
        }


def _reconcile_public_cash(records: tuple[SourceRecord, ...]) -> dict[str, object]:
    """Account for each returned Treasury row once without calling it a company ledger."""
    groups: dict[tuple[str, str], list[tuple[str, Decimal, str]]] = defaultdict(list)
    seen: set[str] = set()
    sentinel = PromptSentinel()
    for record in records:
        data = record.data
        source_id = record.source_id
        category = data.get("transaction_catg")
        transaction_type = data.get("transaction_type")
        amount_value = data.get("transaction_today_amt")
        if (not isinstance(source_id, str) or source_id in seen
                or not isinstance(record.as_of, str) or not record.as_of
                or not isinstance(category, str) or not category.strip()
                or not isinstance(transaction_type, str)
                or transaction_type not in {"Deposits", "Withdrawals"}
                or amount_value is None):
            raise DataUnavailable("Treasury cash row schema mismatch")
        try:
            amount = Decimal(str(amount_value))
        except (InvalidOperation, ValueError):
            raise DataUnavailable("Treasury cash amount schema mismatch") from None
        if not amount.is_finite():
            raise DataUnavailable("Treasury cash amount schema mismatch")
        sentinel.check(json.dumps(data, sort_keys=True), protected_canaries=BETA_IDS)
        seen.add(source_id)
        groups[(record.as_of, category)].append((transaction_type, amount, source_id))

    if not groups:
        raise DataUnavailable("Treasury returned no consumable cash rows")
    # Derive the public grouping handle from stable source IDs, never category text.
    category_ids = {
        key: "category-" + hashlib.sha256(
            "\0".join(sorted(source_id for _, _, source_id in group)).encode("utf-8")
        ).hexdigest()
        for key, group in groups.items()
    }
    rows = [{
        "source_id": record.source_id,
        "as_of": record.as_of,
        "as_of_precision": record.as_of_precision,
        "category_id": category_ids[(record.as_of, record.data["transaction_catg"])],
        "transaction_type": record.data["transaction_type"],
        "amount_usd": format(Decimal(str(record.data["transaction_today_amt"])), "f"),
        "citation": f"[evidence:{record.source_id}]",
    } for record in records]

    categories = []
    exceptions = []
    ordered_groups = sorted(groups.items(), key=lambda item: (item[0][0], category_ids[item[0]]))
    for (as_of, category), group in ordered_groups:
        sides = {side for side, _, _ in group}
        deposits = sum((amount for side, amount, _ in group if side == "Deposits"), Decimal(0))
        withdrawals = sum((amount for side, amount, _ in group if side == "Withdrawals"), Decimal(0))
        source_ids = [source_id for _, _, source_id in group]
        category_id = category_ids[(as_of, category)]
        review_required = sides != {"Deposits", "Withdrawals"}
        categories.append({
            "as_of": as_of,
            "category_id": category_id,
            "source_ids": source_ids,
            "deposit_total_usd": format(deposits, "f"),
            "withdrawal_total_usd": format(withdrawals, "f"),
            "net_public_cash_flow_usd": format(deposits - withdrawals, "f"),
            "status": "REVIEW_REQUIRED_SINGLE_SIDED_PUBLIC_ACTIVITY" if review_required else "BOTH_PUBLIC_FLOW_TYPES_PRESENT",
        })
        if review_required:
            exceptions.append({
                "as_of": as_of,
                "category_id": category_id,
                "source_ids": source_ids,
                "exception": "single-sided-public-activity",
                "interpretation": "The bounded response has no opposite flow type for this category; this is a review cue, not proof of an accounting error.",
            })
    if len(seen) != len(records) or len(rows) != len(records):
        raise DataUnavailable("Treasury cash rows could not be accounted for exactly once")
    return {
        "scope": "public Treasury DTS operating-cash rows only; not a company ledger",
        "input_row_count": len(records),
        "accounted_row_count": len(rows),
        "accounted_source_ids": [row["source_id"] for row in rows],
        "rows": rows,
        "categories": categories,
        "exceptions_for_human_review": exceptions,
    }


def _live_failure(status: str, reason: str, source_metadata: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "project": "LedgerBridge",
        "data_status": status,
        "source_status": status,
        "source_metadata": source_metadata,
        "task_result": None,
        "job_verdict": "UNVERIFIED",
        "uncertainty": f"{reason} No fixture, cached, or substitute records were used.",
        "risk": "This public-source path cannot reconcile an organization's private books or post a ledger entry.",
        "human_handoff": {"owner": "public-treasury-cash-reviewer", "owner_type": "role, not an assigned person", "next_action": "Check the same public Treasury source and review its permitted records; provide an authorized company ledger separately for the private close task."},
        "ai_status": f"NOT RUN / {status}",
        "ai_invoked": False,
        "ai_completion_verdict": "UNVERIFIED",
        "ai_output": None,
        "ai_handoff": "No live source records were available for a grounded summary.",
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.TREASURY_DTS (fixed read-only GET)",
    }


def run_live(ai_client: object | None = None) -> dict[str, object]:
    """Fetch and review actual public Treasury cash rows with no fixture fallback."""
    try:
        source = fetch_live(Provider.TREASURY_DTS, task_fit=TaskFit.PUBLIC_TREASURY_CASH)
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error))
    except UnverifiedSource as error:
        return _live_failure("UNVERIFIED", str(error))
    if not isinstance(source.status, str) or source.status not in {"VERIFIED_SOURCE", "UNVERIFIED"}:
        return _live_failure("DATA_UNAVAILABLE", "Treasury adapter returned an invalid source status.")
    if source.status != "VERIFIED_SOURCE" or not source.records:
        return _live_failure(
            source.status, source.reason or "No consumable live Treasury rows were returned.",
            project_source_metadata(asdict(source)),
        )
    if (source.provider != Provider.TREASURY_DTS.value
            or source.task_fit != TaskFit.PUBLIC_TREASURY_CASH.value
            or not source.read_only or source.request_body_sha256 is not None):
        return _live_failure("UNVERIFIED", "Treasury response did not meet the admitted read-only source contract.")
    try:
        task_result = _reconcile_public_cash(source.records)
    except PromptInjectionError:
        return _live_failure(
            "UNVERIFIED", "A source row was rejected by the existing prompt/canary boundary.",
            project_source_metadata(asdict(source)),
        )
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error), project_source_metadata(asdict(source)))
    except (AttributeError, KeyError, TypeError, ValueError):
        return _live_failure(
            "DATA_UNAVAILABLE", "Treasury returned an invalid cash-row schema.",
            project_source_metadata(asdict(source)),
        )

    evidence_ids = tuple(record.source_id for record in source.records)
    ai = complete_grounded(
        ai_client,
        "Summarize this public Treasury cash-category review using only the cited live rows. State that it is not a company ledger and give no posting instructions. Data: " + json.dumps(task_result, sort_keys=True),
        system="Use only the cited public Treasury rows, state limits, and never post or order a transaction.",
        evidence_ids=evidence_ids,
        protected_canaries=BETA_IDS,
    )
    if ai["ai_status"] == "AI / LOCAL":
        ai["ai_status"] = "AI / LOCAL (APP-REPORTED; INDEPENDENT VERIFICATION REQUIRED)"
    ai["ai_completion_verdict"] = "UNVERIFIED"
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return {
        "project": "LedgerBridge",
        "data_status": "AVAILABLE",
        "source_status": source.status,
        "source_metadata": project_source_metadata(asdict(source)),
        "source_ids": list(evidence_ids),
        "task_result": task_result,
        "job_verdict": "UNVERIFIED",
        "uncertainty": "This reconciles only the bounded Treasury DTS public operating-cash rows returned for the source date. It has no company ledger, bank counterpart, expected balance, or authority to identify an organizational variance.",
        "risk": "Single-sided categories are human-review cues, not demonstrated errors. Public federal cash records are not private business books.",
        "human_handoff": {
            "owner": "public-treasury-cash-reviewer",
            "owner_type": "role, not an assigned person",
            "next_action": "Review each cited category and row at its official source URL; obtain an authorized company ledger and bank statement before any private month-end reconciliation.",
            "source_records": [
                {"source_id": record.source_id, "source_url": record.source_url}
                for record in source.records
            ],
        },
        **ai,
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.TREASURY_DTS (fixed read-only GET)",
    }
