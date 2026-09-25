"""Live public repository research and fixture-only consent-gated regression demo."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessDenied, AccessPolicy, AuditLog, Authenticator, DataUnavailable,
    FixtureAdapter, FixtureSchema, HMACTokenCodec, LocalOpenAIClient,
    Principal, PromptSentinel, Provider, SecurityCore, SourceRecord, SourceResult,
    TaskFit, UnverifiedSource, fetch_live, redact,
)

PROJECT = "PipelineRelay"
ACTION = "prepare_consent_gated_handoff"
ROLE = "sales_agent"
CONSENT_EVIDENCE = "consent-record-309"
ACCOUNT_EVIDENCE = "account-context-309"
NO_CONSENT_EVIDENCE = "consent-record-310"
TENANT_B_CANARY = "TENANT_B_PIPELINE_CANARY_48AC"
FIXTURES = Path(__file__).parent / "fixtures"
PUBLIC_RESEARCH_OWNER = "pytest-dev"
PUBLIC_RESEARCH_REPO = "pytest"


def _security_stack(runtime: Path) -> tuple[Authenticator, SecurityCore, Principal, AuditLog]:
    audit = AuditLog(runtime / "audit.jsonl")
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            "tenant-alpha": {ROLE: {CONSENT_EVIDENCE, ACCOUNT_EVIDENCE, NO_CONSENT_EVIDENCE}},
            "tenant-beta": {ROLE: {"consent-record-b09", "account-context-b09"}},
        },
        {ROLE: {ACTION}},
    )
    return auth, SecurityCore(auth, policy, audit), Principal("tenant-alpha", "seller-309", ROLE), audit


def run_demo(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Prepare a human follow-up from consented synthetic fields; never contact anyone."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")

    with TemporaryDirectory(prefix="pipelinerelay-demo-") as temp:
        auth, core, actor, audit = _security_stack(Path(temp))
        token = auth.issue(actor, expires_at=int(time.time()) + 60)
        adapter = FixtureAdapter(FIXTURES, actor.tenant_id)
        core.authorize(token, tenant_id=actor.tenant_id, action=ACTION, evidence_ids=(CONSENT_EVIDENCE,))
        consent_data = adapter.load("consent.json", FixtureSchema({
            "account_id": str, "consent": bool, "evidence_id": str,
        }))
        consent = next(row for row in consent_data.rows if row["evidence_id"] == CONSENT_EVIDENCE)
        if consent["consent"] is not True:
            raise AccessDenied("request denied")

        core.authorize(
            token, tenant_id=actor.tenant_id, action=ACTION,
            evidence_ids=(CONSENT_EVIDENCE, ACCOUNT_EVIDENCE),
        )
        context_data = adapter.load("account-context.csv", FixtureSchema({
            "evidence_id": str, "account_id": str, "priority": str,
            "renewal_window": str, "approved_context": str, "contact_email": str,
        }))
        account = next(row for row in context_data.rows if row["evidence_id"] == ACCOUNT_EVIDENCE)
        if consent["account_id"] != account["account_id"]:
            raise AccessDenied("request denied")
        PromptSentinel().check(str(account["approved_context"]), protected_canaries=(TENANT_B_CANARY,))
        safe_context = str(redact(account["approved_context"]))

        # The separate consent file contains only the gate; no account context is loaded for this denial.
        core.authorize(
            token, tenant_id=actor.tenant_id, action=ACTION, evidence_ids=(NO_CONSENT_EVIDENCE,),
        )
        denied_data = adapter.load("no-consent.json", FixtureSchema({
            "account_id": str, "consent": bool, "evidence_id": str,
        }))
        denied_consent = next(row for row in denied_data.rows if row["evidence_id"] == NO_CONSENT_EVIDENCE)
        no_consent_denied = denied_consent["consent"] is False

        source_ids = (CONSENT_EVIDENCE, ACCOUNT_EVIDENCE)
        prompt = (
            f"Summarize only this consent-approved synthetic context: {safe_context}. "
            f"Use the renewal window {account['renewal_window']}; cite "
            f"[evidence:{ACCOUNT_EVIDENCE}] and [evidence:{CONSENT_EVIDENCE}]. "
            "Prepare a handoff for a person; do not contact the account."
        )
        ai = complete_grounded(
            ai_client, prompt,
            system="Draft a human-only follow-up handoff from authorized evidence.",
            evidence_ids=source_ids, protected_canaries=(TENANT_B_CANARY,),
        )

        consent_source = f"tenant-alpha/{consent_data.provenance['source_id']}"
        account_source = f"tenant-alpha/{context_data.provenance['source_id']}"
        denied_source = f"tenant-alpha/{denied_data.provenance['source_id']}"
        return {
            "project": PROJECT,
            "task_result": {
                "status": "READY_FOR_HUMAN_REVIEW", "account_id": str(account["account_id"]),
                "approved_context": safe_context,
                "renewal_window": str(account["renewal_window"]),
                "citations": [CONSENT_EVIDENCE, ACCOUNT_EVIDENCE],
                "consent_verified": True, "outreach_sent": False,
            },
            "evidence": [
                {"id": CONSENT_EVIDENCE, "source": consent_source, "sha256": consent_data.provenance["sha256"]},
                {"id": ACCOUNT_EVIDENCE, "source": account_source, "sha256": context_data.provenance["sha256"]},
                {"id": NO_CONSENT_EVIDENCE, "source": denied_source, "sha256": denied_data.provenance["sha256"],
                 "purpose": "negative consent-gate check"},
            ],
            "source_hashes": {
                consent_source: consent_data.provenance["sha256"],
                account_source: context_data.provenance["sha256"],
                denied_source: denied_data.provenance["sha256"],
            },
            "uncertainty": ["Consent and account details are synthetic and may be stale; a human must verify current scope."]
            + (["A local model request failed or its output was rejected; no validated AI completion is evidence. A timeout may leave server-side execution uncertain."] if ai["ai_failure"] else []),
            "risk": ["Consent is mandatory; the workflow has no outreach operation and does not infer permission to contact."],
            "handoff": {"owner": "sales-operations-queue", "next_action": "Review approved context and decide whether any human follow-up is appropriate."},
            "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"], "ai_output": ai["ai_output"],
            "ai_failure": ai["ai_failure"], "ai_handoff": ai["ai_handoff"],
            "ai_evidence": ai["ai_evidence"],
            "side_effect_count": 0,
            "integration_adapter": {
                "type": "FixtureAdapter", "mode": "consent-gated human handoff only",
                "network_enabled": False, "outreach_capability": "none",
            },
            "negative_checks": {"no_consent_denied": no_consent_denied, "preapproval_outreach": 0},
            "audit_event_count": len(audit.records()),
        }


def _live_failure(
    status: str, reason: str, source: SourceResult | None = None,
) -> dict[str, object]:
    source_receipt: dict[str, object] = {"provider": Provider.GITHUB_REPOSITORY.value}
    if source is not None:
        source_receipt.update({
            "request_url": source.request_url,
            "response_status": source.response_status,
            "response_sha256": source.response_sha256,
            "request_body_sha256": source.request_body_sha256,
            "retrieved_at_utc": source.retrieved_at_utc,
            "read_only": source.read_only,
            "task_fit": source.task_fit,
        })
    return {
        "project": PROJECT,
        "status": status,
        "workflow_status": "UNVERIFIED — no authorized CRM/account/consent source",
        "task_result": None,
        "source": source_receipt,
        "evidence": [],
        "uncertainty": [reason],
        "risk": ["Public repository metadata is not a private sales account, lead, CRM record, or consent evidence."],
        "handoff": {
            "owner": "public-repository-research-review",
            "next_action": "Verify the public repository facts at the cited source; do not treat them as a sales lead or initiate contact.",
        },
        "ai_status": "NOT RUN — no verified source record",
        "ai_invoked": False,
        "ai_evidence": None,
        "ai_verification_status": "UNVERIFIED — no independent AI observer",
        "side_effect_count": 0,
        "integration_adapter": {
            "type": "suite_core.fetch_live",
            "mode": "fixed public repository metadata only; no fixture or cached fallback",
            "network_enabled": True,
            "outreach_capability": "none",
        },
    }


def _repository_metadata(record: SourceRecord, request_url: str) -> dict[str, str]:
    data = record.data
    expected_name = f"{PUBLIC_RESEARCH_OWNER}/{PUBLIC_RESEARCH_REPO}"
    expected_url = f"https://api.github.com/repos/{expected_name}"
    # The shared privacy projection redacts `full_name`; exact request and record URLs bind the selected repo.
    if (
        record.provider != Provider.GITHUB_REPOSITORY.value
        or record.task_fit != TaskFit.PUBLIC_REPOSITORY_METADATA.value
        or record.as_of_precision != "second"
        or not record.read_only
        or request_url != expected_url
        or record.source_url != expected_url
        or not re.fullmatch(r"\d+", record.source_id)
        or data.get("id") != int(record.source_id)
    ):
        raise DataUnavailable("GitHub repository identity or provenance schema mismatch")
    updated = record.as_of
    try:
        parsed_updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        if parsed_updated.tzinfo is None:
            raise ValueError
    except (AttributeError, ValueError) as error:
        raise DataUnavailable("GitHub repository update timestamp is invalid") from error

    license_info = data.get("license")
    if not isinstance(license_info, Mapping):
        raise UnverifiedSource("selected GitHub repository has no verified license")
    spdx = license_info.get("spdx_id")
    license_url = license_info.get("url")
    if spdx != "MIT" or not isinstance(license_url, str) or license_url != record.terms_url:
        raise UnverifiedSource("selected GitHub repository lacks the expected MIT terms reference")
    html_url = data.get("html_url")
    branch = data.get("default_branch")
    if (
        not isinstance(html_url, str)
        or html_url != f"https://github.com/{expected_name}"
        or not isinstance(branch, str)
        or not branch
    ):
        raise DataUnavailable("GitHub repository metadata schema mismatch")
    return {
        "repository_id": record.source_id,
        "full_name": expected_name,
        "html_url": html_url,
        "default_branch": branch,
        "license_spdx_id": spdx,
    }


def _public_research_checks(record: SourceRecord, evidence_id: str) -> list[dict[str, object]]:
    updated_at = datetime.fromisoformat(record.as_of.replace("Z", "+00:00"))
    retrieved_at = datetime.fromisoformat(record.retrieved_at_utc.replace("Z", "+00:00"))
    age_days = max(0, (retrieved_at.astimezone(timezone.utc) - updated_at.astimezone(timezone.utc)).days)
    return [
        {"check": "repository_identity", "status": "PASS", "evidence_ids": [evidence_id]},
        {"check": "reported_license", "status": "PASS", "value": "MIT", "evidence_ids": [evidence_id]},
        {
            "check": "source_update_age", "status": "OBSERVED", "days": age_days,
            "as_of": record.as_of, "precision": record.as_of_precision,
            "note": "This is the repository metadata timestamp, not proof of current activity.",
            "evidence_ids": [evidence_id],
        },
        {
            "check": "sales_account_and_consent", "status": "UNVERIFIED",
            "note": "Public repository metadata is not CRM, account, lead, customer, or consent evidence.",
        },
    ]


def run_live(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Prepare a deterministic public-repository research handoff, not a sales lead."""
    try:
        source = fetch_live(
            Provider.GITHUB_REPOSITORY,
            owner=PUBLIC_RESEARCH_OWNER,
            repo=PUBLIC_RESEARCH_REPO,
            task_fit=TaskFit.PUBLIC_REPOSITORY_METADATA,
        )
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error))
    except UnverifiedSource as error:
        return _live_failure("UNVERIFIED", str(error))

    if source.status != "VERIFIED_SOURCE":
        return _live_failure(source.status, source.reason or "GitHub metadata is not verified", source)
    if len(source.records) != 1:
        return _live_failure("DATA_UNAVAILABLE", "GitHub metadata response did not identify exactly one repository", source)
    record = source.records[0]
    try:
        metadata = _repository_metadata(record, source.request_url)
    except (DataUnavailable, UnverifiedSource) as error:
        return _live_failure(error.status, str(error), source)

    evidence_id = f"github-repo-{record.source_id}"
    return {
        "project": PROJECT,
        "status": "VERIFIED_SOURCE",
        "workflow_status": "UNVERIFIED — public GitHub metadata does not establish authorized CRM/account context or consent",
        "task_result": {
            "status": "PUBLIC_REPOSITORY_RESEARCH_ONLY",
            "summary": (
                f"GitHub identifies {metadata['full_name']} as a public repository on "
                f"branch {metadata['default_branch']} with an MIT license."
            ),
            "metadata": metadata,
            "citations": [evidence_id],
            "review_checks": _public_research_checks(record, evidence_id),
            "human_verification_task": (
                "A human reviewer must confirm the repository identity, license, and metadata update date, then decide whether it is relevant to an explicitly authorized public-research question; do not create a lead or initiate contact."
            ),
        },
        "source": {
            "provider": source.provider,
            "request_url": source.request_url,
            "response_status": source.response_status,
            "response_sha256": source.response_sha256,
            "request_body_sha256": source.request_body_sha256,
            "retrieved_at_utc": source.retrieved_at_utc,
            "terms_url": record.terms_url,
            "read_only": source.read_only,
            "task_fit": source.task_fit,
            "task_fit_note": "Permitted public repository metadata only; not a CRM, sales-lead, consent, or customer data source.",
        },
        "evidence": [{
            "evidence_id": evidence_id,
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
        }],
        "uncertainty": [
            "A public repository is not a private customer or sales account; no CRM records, account consent, user-authored issue text, or contact details were requested.",
            "Repository metadata does not establish current code contents or recent work beyond its returned timestamp.",
        ],
        "risk": ["Do not infer buyer intent, account need, relationship, consent, or outreach permission from public repository metadata."],
        "handoff": {
            "owner": "public-repository-research-review",
            "next_action": "Verify the repository identity/license and assess relevance only within a separately authorized public-research task.",
        },
        "ai_status": "NON-AI / DETERMINISTIC FALLBACK",
        "ai_invoked": False,
        "ai_output": None,
        "ai_handoff": "A human reviewer can inspect the cited public metadata; no model-generated sales inference is appropriate for this slice.",
        "ai_evidence": None,
        "ai_verification_status": "NON-AI — public repository metadata only; no honest AI role",
        "side_effect_count": 0,
        "integration_adapter": {
            "type": "suite_core.fetch_live",
            "mode": "fixed public GitHub repository metadata plus deterministic identity/license/age checks; no fixture or cached fallback",
            "network_enabled": True,
            "outreach_capability": "none",
        },
    }


def main() -> int:
    result = run_live()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED_SOURCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
