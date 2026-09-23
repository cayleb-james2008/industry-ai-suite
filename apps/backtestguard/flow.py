"""Check historical observation-year ordering without claiming a market backtest."""

from __future__ import annotations

import json
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessPolicy, AuditLog, Authenticator, DataUnavailable, FixtureAdapter,
    FixtureData, FixtureSchema, HMACTokenCodec, LocalOpenAIClient, Principal,
    PromptInjectionError, PromptSentinel, Provider, SecurityCore, SourceRecord,
    TaskFit, UnverifiedSource, fetch_live,
)
from suite_core.privacy import project_source_metadata

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = FixtureSchema({"experiment_id": str, "dataset_id": str, "feature_cutoff": str,
                        "decision_date": str, "label_available_at": str,
                        "holdout_reused": bool, "metric": float})
ALPHA_IDS = ("BG-A-001", "BG-A-002", "BG-A-003")
BETA_IDS = ("BG-B-CANARY",)


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
    actor = Principal(tenant_id, "quant-demo-a" if tenant_id == "tenant-alpha" else "quant-demo-b", role)
    token = auth.issue(actor, expires_at=int(time.time()) + 60)
    evidence = ALPHA_IDS if tenant_id == "tenant-alpha" else BETA_IDS
    core.authorize(token, tenant_id=tenant_id, action="read", evidence_ids=evidence)
    fixture = FixtureAdapter(FIXTURES, tenant_id).load("experiments.csv", SCHEMA)
    return _Context(auth, core, audit, token, fixture)


def check_experiments(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    """Pass a clean chronology control; block lookahead and reused-holdout results."""
    evaluations = []
    seen: set[str] = set()
    sentinel = PromptSentinel()
    for row in rows:
        experiment_id, dataset_id = row["experiment_id"], row["dataset_id"]
        if (not isinstance(experiment_id, str) or experiment_id in seen
                or not isinstance(dataset_id, str) or not dataset_id):
            raise ValueError("invalid or duplicate experiment identity")
        sentinel.check(dataset_id, protected_canaries=BETA_IDS)
        seen.add(experiment_id)
        cutoff = date.fromisoformat(str(row["feature_cutoff"]))
        decision = date.fromisoformat(str(row["decision_date"]))
        label_at = date.fromisoformat(str(row["label_available_at"]))
        reasons = []
        if cutoff > decision:
            reasons.append("lookahead_feature_cutoff_after_decision")
        if label_at <= decision:
            reasons.append("label_timestamp_not_after_decision")
        if row["holdout_reused"] is True:
            reasons.append("holdout_reused_for_training_or_selection")
        if type(row["holdout_reused"]) is not bool:
            raise ValueError("holdout reuse flag must be boolean")
        blocked = bool(reasons)
        evaluations.append({
            "experiment_id": experiment_id,
            "dataset_id": dataset_id,
            "metric": row["metric"],
            "status": "BLOCKED" if blocked else "PASS",
            "leakage_reasons": reasons,
            "promotion_status": "blocked" if blocked else "eligible_for_human_review",
        })
    return {
        "experiments": evaluations,
        "clean_control_passed": any(item["status"] == "PASS" for item in evaluations),
        "blocked_experiment_ids": [item["experiment_id"] for item in evaluations if item["status"] == "BLOCKED"],
    }


def _ai_summary(ai_client: object, result: dict[str, object], evidence_ids: tuple[str, ...]) -> dict[str, object]:
    prompt = ("Explain these synthetic backtest integrity findings to a quant reviewer. "
              "Cite each claim as [evidence:ID]. State limits and never execute, publish, or promote results. "
              "Findings: " + json.dumps(result, sort_keys=True))
    ai = complete_grounded(
        ai_client, prompt,
        system="Use only authorized evidence, state uncertainty, and never promote a result.",
        evidence_ids=evidence_ids, protected_canaries=BETA_IDS,
    )
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return ai


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """ADVERSARIAL REGRESSION TEST ONLY: inspect local experiment fixtures."""
    with tempfile.TemporaryDirectory(prefix="backtestguard-") as runtime:
        context = _context(Path(runtime))
        result = check_experiments(context.fixture.rows)
        evidence_ids = tuple(str(row["experiment_id"]) for row in context.fixture.rows)
        ai = _ai_summary(ai_client, result, evidence_ids)
        audit_receipts = list(context.audit.records())
        return {
            "project": "BacktestGuard",
            "tenant_id": str(context.fixture.provenance["tenant_id"]),
            "task_result": result,
            "evidence_ids": list(evidence_ids),
            "source_hashes": {f"{context.fixture.provenance['tenant_id']}/{context.fixture.provenance['source_id']}": context.fixture.provenance["sha256"]},
            "uncertainty": "The chronology and holdout checks cover only recorded fixture metadata; they do not detect every form of leakage or overfitting.",
            "risk": "A PASS means eligible for human review only; a BLOCKED experiment cannot be promoted by this app.",
            "human_handoff": {"owner": "quant-research-review", "next_action": "Inspect blocked leakage reasons and dataset lineage before any result is shared."},
            **ai,
            "side_effect_count": 0,
            "integration_adapter": "suite_core.FixtureAdapter (tenant-scoped local CSV; read-only)",
            "audit_events": len(audit_receipts),
            "audit_receipts": audit_receipts,
            "capabilities": ["fixture_read", "integrity_check", "human_review_only"],
        }


def _live_failure(status: str, reason: str, source_metadata: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "project": "BacktestGuard",
        "data_status": status,
        "source_status": status,
        "source_metadata": source_metadata,
        "task_result": None,
        "job_verdict": "UNVERIFIED",
        "uncertainty": f"{reason} No fixture, cached, or substitute records were used.",
        "risk": "This path is not a market-return backtest, has no external experiment log, and cannot approve or execute a strategy.",
        "human_handoff": {"owner": "quant-research-reviewer", "owner_type": "role, not an assigned person", "next_action": "Check the same public World Bank source and provide a real, provenance-linked experiment record for review."},
        "ai_status": f"NOT RUN / {status}",
        "ai_invoked": False,
        "ai_completion_verdict": "UNVERIFIED",
        "ai_output": None,
        "ai_handoff": "No live source records were available for a grounded summary.",
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.WORLD_BANK_USA_GDP (fixed read-only GET)",
    }


def run_live(ai_client: object | None = None) -> dict[str, object]:
    """Audit chronological splits over actual USA GDP history; never use experiment fixtures."""
    try:
        source = fetch_live(Provider.WORLD_BANK_USA_GDP, task_fit=TaskFit.PUBLIC_US_GDP)
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error))
    except UnverifiedSource as error:
        return _live_failure("UNVERIFIED", str(error))
    if not isinstance(source.status, str) or source.status not in {"VERIFIED_SOURCE", "UNVERIFIED"}:
        return _live_failure("DATA_UNAVAILABLE", "World Bank adapter returned an invalid source status.")
    if source.status != "VERIFIED_SOURCE" or not source.records:
        return _live_failure(
            source.status, source.reason or "No consumable live GDP observations were returned.",
            project_source_metadata(asdict(source)),
        )
    if (source.provider != Provider.WORLD_BANK_USA_GDP.value
            or source.task_fit != TaskFit.PUBLIC_US_GDP.value
            or not source.read_only or source.request_body_sha256 is not None):
        return _live_failure("UNVERIFIED", "World Bank response did not meet the admitted read-only source contract.")

    values_by_year: dict[int, tuple[SourceRecord, Decimal]] = {}
    try:
        for record in source.records:
            used_data = {
                key: record.data.get(key)
                for key in ("countryiso3code", "date", "value")
            }
            PromptSentinel().check(json.dumps(used_data, sort_keys=True), protected_canaries=BETA_IDS)
            year = int(record.as_of)
            raw_value = record.data.get("value")
            value = Decimal(str(raw_value))
            if (record.provider != Provider.WORLD_BANK_USA_GDP.value
                    or record.task_fit != TaskFit.PUBLIC_US_GDP.value
                    or not record.read_only or record.request_body_sha256 is not None
                    or record.as_of_precision != "year"
                    or record.source_id != f"USA:NY.GDP.MKTP.CD:{year}"
                    or record.data.get("countryiso3code") != "USA"
                    or record.data.get("date") != str(year)
                    or not value.is_finite() or year in values_by_year):
                raise DataUnavailable("World Bank USA GDP observation schema mismatch")
            values_by_year[year] = (record, value)
        if len(values_by_year) != 15:
            raise DataUnavailable("World Bank response did not contain exactly 15 USA GDP annual records")
    except PromptInjectionError:
        return _live_failure("UNVERIFIED", "A source record was rejected by the existing prompt/canary boundary.")
    except (AttributeError, DataUnavailable, InvalidOperation, KeyError, ValueError, TypeError):
        return _live_failure("DATA_UNAVAILABLE", "World Bank returned an invalid or incomplete GDP record set.")

    years = sorted(values_by_year)
    cutoff_year = years[(len(years) * 2 // 3) - 1]
    training_years = [year for year in years if year <= cutoff_year]
    holdout_years = [year for year in years if year > cutoff_year]
    control_valid = bool(
        training_years and holdout_years
        and set(training_years).isdisjoint(holdout_years)
        and max(training_years) <= cutoff_year < min(holdout_years)
    )
    observations = [
        {
            "observation_year": year,
            "source_id": values_by_year[year][0].source_id,
            "as_of": values_by_year[year][0].as_of,
            "as_of_precision": values_by_year[year][0].as_of_precision,
            "retrieved_at_utc": values_by_year[year][0].retrieved_at_utc,
            "terms_url": values_by_year[year][0].terms_url,
            "gdp_current_usd": format(values_by_year[year][1], "f"),
        }
        for year in years
    ]
    future_years = [year for year in years if year > cutoff_year]
    analysis = {
        "label": "PUBLIC GDP CHRONOLOGY / PROVENANCE CHECK — not a market-return backtest",
        "experiment_record_status": "UNVERIFIED — no external experiment log or experiment owner record was supplied",
        "experiment_parameters": {
            "source_series": "World Bank USA NY.GDP.MKTP.CD (GDP current US$)",
            "observation_years": [years[0], years[-1]],
            "decision_cutoff_year": cutoff_year,
            "training_years": training_years,
            "holdout_years": holdout_years,
            "split_rule": "train on observation years at or before cutoff; hold out later observation years",
            "label_or_return_definition": "none supplied",
            "publication_availability_rule": "not established; source observation year is not a release timestamp",
        },
        "valid_chronological_control": {
            "passes_observation_year_order_only": control_valid,
            "training_years_disjoint_from_holdout": set(training_years).isdisjoint(holdout_years),
            "training_does_not_exceed_cutoff": max(training_years) <= cutoff_year,
            "holdout_starts_after_cutoff": min(holdout_years) > cutoff_year,
            "meaning": "A structurally valid year-ordered control, not evidence of a real or economically valid experiment.",
        },
        "future_observation_leakage_probe": {
            "future_years": future_years,
            "would_leak_if_used_before_cutoff": bool(future_years),
            "reason": "GDP observations after the decision cutoff would be future information if included in training or selection before that cutoff.",
            "observed_in_this_control": False,
        },
        "record_count": len(observations),
        "observations": observations,
    }
    evidence_ids = tuple(values_by_year[year][0].source_id for year in years)
    ai = complete_grounded(
        ai_client,
        "Explain this actual World Bank GDP observation-year split and future-data leakage probe using only the cited records. Do not describe it as a market-return backtest or external experiment. Data: " + json.dumps(analysis, sort_keys=True),
        system="Use only cited records, distinguish chronology from a real experiment, and never promote or execute a strategy.",
        evidence_ids=evidence_ids,
        protected_canaries=BETA_IDS,
    )
    if ai["ai_status"] == "AI / LOCAL":
        ai["ai_status"] = "AI / LOCAL (APP-REPORTED; INDEPENDENT VERIFICATION REQUIRED)"
    ai["ai_completion_verdict"] = "UNVERIFIED"
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return {
        "project": "BacktestGuard",
        "data_status": "AVAILABLE",
        "source_status": source.status,
        "source_metadata": project_source_metadata(
            asdict(source), record_data_fields=("countryiso3code", "date", "value"),
        ),
        "source_ids": list(evidence_ids),
        "task_result": analysis,
        "job_verdict": "UNVERIFIED",
        "uncertainty": "This is an integrity analysis of actual annual GDP observation years, not investment returns or a real external experiment log. Source release/availability timestamps, a target label, experiment provenance, and an accountable experiment owner are absent; nominal GDP values are not market performance.",
        "risk": "A valid year ordering alone does not establish a valid experiment, prevent every leakage class, or support trading. No order, strategy execution, or promotion is possible.",
        "human_handoff": {"owner": "quant-research-reviewer", "owner_type": "role, not an assigned person", "next_action": "Review the cutoff and holdout years, verify source release timing, and attach the actual experiment record before deciding whether any leakage conclusion applies."},
        **ai,
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.WORLD_BANK_USA_GDP (fixed read-only GET)",
    }
