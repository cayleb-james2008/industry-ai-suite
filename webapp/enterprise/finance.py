"""In-memory finance, market, watch-only, and research-integrity imports."""

from __future__ import annotations

import math
import re
from datetime import date

from apps.backtestguard.flow import check_experiments
from apps.chainwatch.flow import detect_anomalies
from apps.ledgerbridge.flow import reconcile
from apps.marketbrief.flow import compose_brief
from suite_core import redact

from .common import (
    ImportContext, exact_object, identifier, iso_date, nonnegative_int,
    receipt, rows, safe_text, text, unique_ids,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _number(value: object, label: str, *, positive: bool = False, nonnegative: bool = False) -> int | float:
    if type(value) not in (int, float) or abs(value) > 10**12 or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number within the supported range.")
    if positive and value <= 0:
        raise ValueError(f"{label} must be positive.")
    if nonnegative and value < 0:
        raise ValueError(f"{label} must be a finite nonnegative number.")
    return value


def review_ledger(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"close_period", "rows"}, "LedgerBridge data")
    period = text(data["close_period"], "Close period", maximum=7)
    if not re.fullmatch(r"\d{4}-\d{2}", period) or not 1 <= int(period[-2:]) <= 12:
        raise ValueError("Close period must be YYYY-MM.")
    submitted = rows(data["rows"], {"row_id", "reference", "side", "amount_cents", "owner"}, "Ledger and bank rows")
    unique_ids(submitted, "row_id", "Row ID")
    for row in submitted:
        identifier(row["reference"], "Reconciliation reference")
        identifier(row["owner"], "Owner code")
        if row["side"] not in {"ledger", "bank"}:
            raise ValueError("Each reconciliation side must be ledger or bank.")
        nonnegative_int(row["amount_cents"], "Amount in cents")
    result = reconcile(submitted)
    result["close_period"] = period
    queue = result["owner_queue"]
    summary = {
        "title": "Close exceptions for a finance reviewer",
        "metrics": [{"label": "Rows accounted", "value": result["accounted_row_count"]}, {"label": "Exceptions", "value": len(queue)}],
        "findings": [f"{item['reference']}: {', '.join(item['reasons'])}; variance {item['variance_cents'] if item['variance_cents'] is not None else 'not calculated'} cents." for item in queue[:20]] or ["All supplied pairs match; source completeness still needs confirmation."],
    }
    return receipt("LedgerBridge", context, redact(result), evidence_ids=[str(row["row_id"]) for row in submitted], summary=summary,
                   next_action="Confirm the period and both source exports; assign every exception before any approved ledger posting.")


def review_market(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"question", "max_age_days", "reports"}, "MarketBrief data")
    question = safe_text(data["question"], "Research question", maximum=500)
    limit = nonnegative_int(data["max_age_days"], "Freshness limit")
    if limit > 3650:
        raise ValueError("Freshness limit exceeds ten years.")
    reports = rows(data["reports"], {"report_id", "published_on", "instrument", "metric", "value", "unit", "claim", "owner"}, "Research reports")
    unique_ids(reports, "report_id", "Report ID")
    for row in reports:
        iso_date(row["published_on"], "Report publication date")
        identifier(row["instrument"], "Instrument code")
        identifier(row["owner"], "Report owner code")
        text(row["metric"], "Metric", maximum=120)
        text(row["unit"], "Unit", maximum=40)
        _number(row["value"], "Report value")
        text(row["claim"], "Research claim", maximum=1000)
    result = compose_brief(reports, as_of=context.as_of, max_age_days=limit)
    instrument_by_report = {str(row["report_id"]): str(row["instrument"]) for row in reports}
    for claim in result["claims"]:
        claim["instrument"] = instrument_by_report[str(claim["report_id"])]
    result["question"] = question
    result = redact(result)
    counts = {state: sum(claim["freshness"] == state for claim in result["claims"]) for state in ("current", "stale", "future-dated")}
    summary = {
        "title": "Sourced research claims for analyst review",
        "metrics": [{"label": "Reports", "value": len(reports)}, {"label": "Stale", "value": counts["stale"]}, {"label": "Future dated", "value": counts["future-dated"]}],
        "findings": [f"{claim['report_id']}: {claim['freshness']} as of {context.as_of} [evidence:{claim['report_id']}]." for claim in result["claims"][:20]],
    }
    return receipt("MarketBrief", context, result, evidence_ids=[str(row["report_id"]) for row in reports], summary=summary,
                   next_action="Check each source license, release time, and claim against the original report; write the final risk judgment without an order or trade action.")


def review_chain(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"observations", "threshold"}, "ChainWatch data")
    threshold = _number(data["threshold"], "Alert multiple", positive=True)
    if not 1 < threshold <= 100:
        raise ValueError("Alert multiple must be greater than one and no more than 100.")
    observations = rows(data["observations"], {"event_id", "chain", "address", "rate_units_per_hour", "baseline_units_per_hour", "sample_hours", "owner"}, "Watch-only observations")
    unique_ids(observations, "event_id", "Event ID")
    for row in observations:
        identifier(row["owner"], "Watch owner code")
        rate = _number(row["rate_units_per_hour"], "Observed rate", nonnegative=True)
        baseline = _number(row["baseline_units_per_hour"], "Baseline rate", positive=True)
        _number(row["sample_hours"], "Sample hours", positive=True)
        ratio = rate / baseline
        if not math.isfinite(ratio) or ratio > 10**12:
            raise ValueError("Observed-to-baseline ratio exceeds the supported range.")
    result = detect_anomalies(observations, threshold=float(threshold))
    for item in result["observations"]:
        address = str(item["address"])
        item["address"] = address[:4] + "…" + address[-6:]
    summary = {
        "title": "Watch-only exposure review",
        "metrics": [{"label": "Observations", "value": len(observations)}, {"label": "Alerts", "value": len(result["alerts"])}, {"label": "Threshold", "value": str(threshold) + "×"}],
        "findings": [f"{alert['event_id']}: {alert['rate_to_baseline']}× the supplied baseline; {alert['uncertainty']} window confidence." for alert in result["alerts"][:20]] or ["No supplied observation crossed the threshold; confirm source coverage and baseline quality."],
    }
    return receipt("ChainWatch", context, result, evidence_ids=[str(row["event_id"]) for row in observations], summary=summary,
                   next_action="Verify address ownership, chain provider terms, sampling window, and each alert before a human escalation; no signing or transfer is available.")


def review_backtest(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"experiments"}, "BacktestGuard data")
    fields = {"experiment_id", "dataset_id", "dataset_sha256", "feature_cutoff", "decision_date", "label_available_at", "source_release_at", "holdout_reused", "metric"}
    experiments = rows(data["experiments"], fields, "Experiment records")
    unique_ids(experiments, "experiment_id", "Experiment ID")
    for row in experiments:
        identifier(row["dataset_id"], "Dataset ID")
        if not isinstance(row["dataset_sha256"], str) or not _SHA256.fullmatch(row["dataset_sha256"]):
            raise ValueError("Dataset SHA-256 must be a 64-character lowercase hash.")
        for key in ("feature_cutoff", "decision_date", "label_available_at", "source_release_at"):
            iso_date(row[key], key)
        if type(row["holdout_reused"]) is not bool:
            raise ValueError("Holdout reuse must be true or false.")
        _number(row["metric"], "Experiment metric")
    result = check_experiments(experiments)
    for evaluated, source in zip(result["experiments"], experiments, strict=True):
        if date.fromisoformat(source["source_release_at"]) > date.fromisoformat(source["decision_date"]):
            evaluated["leakage_reasons"].append("source_release_after_decision")
            evaluated["status"] = "BLOCKED"
            evaluated["promotion_status"] = "blocked"
        evaluated["dataset_sha256"] = source["dataset_sha256"]
        evaluated["source_release_at"] = source["source_release_at"]
    result["blocked_experiment_ids"] = [item["experiment_id"] for item in result["experiments"] if item["status"] == "BLOCKED"]
    result["clean_control_passed"] = any(item["status"] == "PASS" for item in result["experiments"])
    summary = {
        "title": "Experiment integrity gate",
        "metrics": [{"label": "Experiments", "value": len(experiments)}, {"label": "Blocked", "value": len(result["blocked_experiment_ids"])}],
        "findings": [f"{item['experiment_id']}: {'blocked — ' + ', '.join(item['leakage_reasons']) if item['leakage_reasons'] else 'eligible for human review only'}." for item in result["experiments"][:20]],
    }
    return receipt("BacktestGuard", context, result, evidence_ids=[str(row["experiment_id"]) for row in experiments], summary=summary,
                   next_action="Inspect dataset hashes, release timestamps, target definition, selection history, and blocked reasons before any result is shared; no strategy execution is available.")
