"""Build a public macro brief; keep fixture-based reports test-only."""

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
SCHEMA = FixtureSchema({"report_id": str, "published_on": str, "instrument": str,
                        "metric": str, "value": float, "unit": str, "claim": str, "owner": str})
ALPHA_IDS = ("MB-A-001", "MB-A-002", "MB-A-003")
BETA_IDS = ("MB-B-CANARY",)


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
    actor = Principal(tenant_id, "market-demo-a" if tenant_id == "tenant-alpha" else "market-demo-b", role)
    token = auth.issue(actor, expires_at=int(time.time()) + 60)
    evidence = ALPHA_IDS if tenant_id == "tenant-alpha" else BETA_IDS
    core.authorize(token, tenant_id=tenant_id, action="read", evidence_ids=evidence)
    fixture = FixtureAdapter(FIXTURES, tenant_id).load("reports.csv", SCHEMA)
    return _Context(auth, core, audit, token, fixture)


def compose_brief(rows: tuple[dict[str, object], ...], *, as_of: str = "2026-09-22",
                 max_age_days: int = 7) -> dict[str, object]:
    """Cite every supplied report and mark stale/future-dated source material."""
    cutoff = date.fromisoformat(as_of)
    if max_age_days < 0:
        raise ValueError("staleness limit must be non-negative")
    claims = []
    seen: set[str] = set()
    for row in rows:
        report_id = row["report_id"]
        published = date.fromisoformat(str(row["published_on"]))
        claim = row["claim"]
        if not isinstance(report_id, str) or report_id in seen or not isinstance(claim, str):
            raise ValueError("invalid or duplicate market report")
        PromptSentinel().check(claim)
        seen.add(report_id)
        age_days = (cutoff - published).days
        status = "future-dated" if age_days < 0 else "stale" if age_days > max_age_days else "current"
        claims.append({
            "report_id": report_id,
            "claim": claim,
            "metric": row["metric"],
            "value": row["value"],
            "unit": row["unit"],
            "published_on": published.isoformat(),
            "age_days": age_days,
            "freshness": status,
            "citation": f"[evidence:{report_id}]",
        })
    return {"as_of": cutoff.isoformat(), "stale_after_days": max_age_days, "claims": claims}


def _ai_summary(ai_client: object, result: dict[str, object], evidence_ids: tuple[str, ...]) -> dict[str, object]:
    prompt = ("Draft a concise analyst briefing from these supplied, cited reports only. "
              "Mention stale/future sources and uncertainty. Do not give orders. "
              "Cite every claim as [evidence:ID]. Reports: " + json.dumps(result, sort_keys=True))
    ai = complete_grounded(
        ai_client, prompt,
        system="Use only authorized evidence, cite it, state uncertainty, and give no trading orders.",
        evidence_ids=evidence_ids, protected_canaries=BETA_IDS,
    )
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return ai


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """ADVERSARIAL REGRESSION TEST ONLY: read fixture reports, never place orders."""
    with tempfile.TemporaryDirectory(prefix="marketbrief-") as runtime:
        context = _context(Path(runtime))
        brief = compose_brief(context.fixture.rows)
        evidence_ids = tuple(str(row["report_id"]) for row in context.fixture.rows)
        ai = _ai_summary(ai_client, brief, evidence_ids)
        audit_receipts = list(context.audit.records())
        return {
            "project": "MarketBrief",
            "tenant_id": str(context.fixture.provenance["tenant_id"]),
            "task_result": brief,
            "evidence_ids": list(evidence_ids),
            "source_hashes": {f"{context.fixture.provenance['tenant_id']}/{context.fixture.provenance['source_id']}": context.fixture.provenance["sha256"]},
            "uncertainty": "Source freshness is measured only against the supplied as-of date; no independent source validation occurred.",
            "risk": "Stale and future-dated reports are flagged; the data is synthetic and cannot support a trade.",
            "human_handoff": {"owner": "market-risk-analyst", "next_action": "Review citations, source freshness, and uncertainty before using the brief."},
            **ai,
            "side_effect_count": 0,
            "integration_adapter": "suite_core.FixtureAdapter (tenant-scoped local CSV; read-only)",
            "audit_events": len(audit_receipts),
            "audit_receipts": audit_receipts,
            "capabilities": ["fixture_read", "dated_brief"],
        }


def _live_failure(status: str, reason: str, source_metadata: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "project": "MarketBrief",
        "data_status": status,
        "source_status": status,
        "source_metadata": source_metadata,
        "task_result": None,
        "job_verdict": "UNVERIFIED",
        "uncertainty": f"{reason} No fixture, cached, or substitute records were used.",
        "risk": "No stock-price, company-specific, valuation, or trading-edge evidence is available from this public GDP slice.",
        "human_handoff": {"owner": "macro-research-analyst", "owner_type": "role, not an assigned person", "next_action": "Check the same public World Bank source and obtain separate company and market evidence before making a research decision."},
        "ai_status": f"NOT RUN / {status}",
        "ai_invoked": False,
        "ai_completion_verdict": "UNVERIFIED",
        "ai_output": None,
        "ai_handoff": "No live source records were available for a grounded summary.",
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.WORLD_BANK_USA_GDP (fixed read-only GET)",
    }


def run_live(ai_client: object | None = None) -> dict[str, object]:
    """Fetch actual World Bank USA GDP observations; never substitute fixtures."""
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

    ordered = [values_by_year[year] for year in sorted(values_by_year)]
    observations = [
        {
            "year": int(record.as_of),
            "source_id": record.source_id,
            "as_of": record.as_of,
            "as_of_precision": record.as_of_precision,
            "retrieved_at_utc": record.retrieved_at_utc,
            "terms_url": record.terms_url,
            "gdp_current_usd": format(value, "f"),
            "citation": f"[evidence:{record.source_id}]",
        }
        for record, value in ordered
    ]
    prior_year, prior_value = int(ordered[-2][0].as_of), ordered[-2][1]
    latest_year, latest_value = int(ordered[-1][0].as_of), ordered[-1][1]
    if prior_value == 0:
        return _live_failure("DATA_UNAVAILABLE", "World Bank returned a zero prior-year GDP value; nominal growth cannot be computed.")
    change = latest_value - prior_value
    growth_percent = (change / prior_value * Decimal(100)).quantize(Decimal("0.01"))
    brief = {
        "label": "PUBLIC_MACRO_SLICE — not full company or securities research",
        "indicator": "NY.GDP.MKTP.CD — GDP (current US$)",
        "record_count": len(observations),
        "annual_observations": observations,
        "latest_nominal_change": {
            "from_year": prior_year,
            "to_year": latest_year,
            "change_current_usd": format(change, "f"),
            "change_percent": format(growth_percent, "f"),
            "citations": [f"[evidence:{ordered[-2][0].source_id}]", f"[evidence:{ordered[-1][0].source_id}]"],
        },
    }
    evidence_ids = tuple(record.source_id for record, _ in ordered)
    ai = complete_grounded(
        ai_client,
        "Draft a short public macro context note using only these cited World Bank GDP records. State nominal-dollar limits, and do not infer stock prices or a trading edge. Data: " + json.dumps(brief, sort_keys=True),
        system="Use only the cited GDP observations; state uncertainty and do not recommend a trade.",
        evidence_ids=evidence_ids,
        protected_canaries=BETA_IDS,
    )
    if ai["ai_status"] == "AI / LOCAL":
        ai["ai_status"] = "AI / LOCAL (APP-REPORTED; INDEPENDENT VERIFICATION REQUIRED)"
    ai["ai_completion_verdict"] = "UNVERIFIED"
    ai["ai_summary"] = ai["ai_output"] or ai["ai_handoff"]
    return {
        "project": "MarketBrief",
        "data_status": "AVAILABLE",
        "source_status": source.status,
        "source_metadata": project_source_metadata(
            asdict(source), record_data_fields=("countryiso3code", "date", "value"),
        ),
        "source_ids": list(evidence_ids),
        "task_result": brief,
        "job_verdict": "UNVERIFIED",
        "uncertainty": "This 15-year nominal GDP series is broad U.S. macro context only. It is not inflation-adjusted, does not include company evidence or security prices, and the source as-of year does not establish publication availability. The World Bank license page is cited; a dataset-specific license override was not independently checked here.",
        "risk": "Do not infer a stock price, investment performance, or trading edge from GDP levels or nominal growth.",
        "human_handoff": {"owner": "macro-research-analyst", "owner_type": "role, not an assigned person", "next_action": "Review each cited source year and add independently sourced company, valuation, and market evidence before presenting full company research."},
        **ai,
        "side_effect_count": 0,
        "integration_adapter": "suite_core.fetch_live / Provider.WORLD_BANK_USA_GDP (fixed read-only GET)",
    }
