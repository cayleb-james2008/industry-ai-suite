"""Live public repository research and fixture-only consent-gated regression demo."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

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
_GITHUB_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SPDX_IDENTIFIER = re.compile(r"^[A-Za-z0-9.+-]+$")


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
    status: str, reason: str, source: SourceResult | None = None, *,
    network_attempted: bool = False,
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
            "mode": "selected public GitHub repository metadata only; no fixture or cached fallback",
            "network_enabled": True,
            "network_attempted": network_attempted,
            "outreach_capability": "none",
        },
    }


def _safe_repository_input(owner: object, repo: object) -> bool:
    return all(
        isinstance(segment, str)
        and _GITHUB_SEGMENT.fullmatch(segment) is not None
        and segment not in {".", ".."}
        for segment in (owner, repo)
    )


def _repository_metadata(
    record: SourceRecord, request_url: str, owner: str, repo: str,
) -> dict[str, object]:
    data = record.data
    expected_name = f"{owner}/{repo}"
    expected_url = f"https://api.github.com/repos/{expected_name}"
    # The shared adapter checks the raw full_name against the requested path before
    # redacting it; html_url retains returned casing for the handoff.
    html_url = data.get("html_url")
    try:
        parsed_html_url = urlsplit(html_url) if isinstance(html_url, str) else None
    except ValueError as error:
        raise DataUnavailable("GitHub repository page URL is malformed") from error
    returned_path = parsed_html_url.path.removeprefix("/") if parsed_html_url else ""
    if (
        record.provider != Provider.GITHUB_REPOSITORY.value
        or record.task_fit != TaskFit.PUBLIC_REPOSITORY_METADATA.value
        or record.as_of_precision != "second"
        or not record.read_only
        or request_url != expected_url
        or record.source_url != expected_url
        or not isinstance(record.source_id, str)
        or re.fullmatch(r"\d+", record.source_id) is None
        or data.get("id") != int(record.source_id)
        or parsed_html_url is None
        or parsed_html_url.scheme != "https"
        or parsed_html_url.hostname != "github.com"
        or parsed_html_url.netloc != "github.com"
        or parsed_html_url.query
        or parsed_html_url.fragment
        or returned_path.casefold() != expected_name.casefold()
    ):
        raise DataUnavailable("GitHub repository identity or provenance schema mismatch")
    updated = record.as_of
    try:
        parsed_updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        if parsed_updated.tzinfo is None:
            raise ValueError
        parsed_retrieved = datetime.fromisoformat(record.retrieved_at_utc.replace("Z", "+00:00"))
        if parsed_retrieved.tzinfo is None:
            raise ValueError
    except (AttributeError, ValueError) as error:
        raise DataUnavailable("GitHub repository update timestamp is invalid") from error

    license_info = data.get("license")
    if not isinstance(license_info, Mapping):
        raise UnverifiedSource("selected GitHub repository has no verified license")
    spdx = license_info.get("spdx_id")
    license_url = license_info.get("url")
    if (
        not isinstance(spdx, str)
        or spdx in {"", "NOASSERTION", "OTHER"}
        or _SPDX_IDENTIFIER.fullmatch(spdx) is None
    ):
        raise UnverifiedSource("selected GitHub repository license is missing or ambiguous")
    expected_terms_url = f"https://api.github.com/licenses/{spdx.lower()}"
    if (
        not isinstance(license_url, str)
        or license_url != expected_terms_url
        or record.terms_url != expected_terms_url
    ):
        raise UnverifiedSource("GitHub SPDX identifier and exact returned terms URL do not match")
    branch = data.get("default_branch")
    if (
        not isinstance(branch, str)
        or not branch
    ):
        raise DataUnavailable("GitHub repository metadata schema mismatch")
    age_seconds = int((
        parsed_retrieved.astimezone(timezone.utc)
        - parsed_updated.astimezone(timezone.utc)
    ).total_seconds())
    return {
        "repository_id": record.source_id,
        "full_name": returned_path,
        "html_url": html_url,
        "default_branch": branch,
        "license_spdx_id": spdx,
        "license_terms_url": record.terms_url,
        "updated_at": record.as_of,
        "updated_age_seconds": age_seconds,
        "updated_age_days": round(age_seconds / 86400, 6),
    }


def _public_research_checks(
    metadata: Mapping[str, object], evidence_id: str,
) -> list[dict[str, object]]:
    return [
        {"check": "repository_identity", "status": "PASS", "evidence_ids": [evidence_id]},
        {
            "check": "reported_license", "status": "PASS",
            "spdx_id": metadata["license_spdx_id"],
            "terms_url": metadata["license_terms_url"],
            "evidence_ids": [evidence_id],
        },
        {
            "check": "source_update_age", "status": "OBSERVED",
            "age_seconds": metadata["updated_age_seconds"],
            "age_days": metadata["updated_age_days"],
            "as_of": metadata["updated_at"],
            "precision": "second",
            "note": "This source-provided metadata timestamp is an observation, not proof of current code contents or activity.",
            "evidence_ids": [evidence_id],
        },
        {
            "check": "sales_account_and_consent", "status": "UNVERIFIED",
            "note": "Public repository metadata is not CRM, account, lead, customer, or consent evidence.",
        },
    ]


def run_live(
    ai_client: LocalOpenAIClient | None = None, *,
    owner: str | None = None, repo: str | None = None,
) -> dict[str, object]:
    """Prepare a public-repository metadata handoff, never a sales lead."""
    if owner is None and repo is None:
        owner, repo = PUBLIC_RESEARCH_OWNER, PUBLIC_RESEARCH_REPO
    if not _safe_repository_input(owner, repo):
        return _live_failure(
            "UNVERIFIED",
            "Provide both --owner and --repo as single safe GitHub path segments; no request was made.",
        )

    try:
        source = fetch_live(
            Provider.GITHUB_REPOSITORY,
            owner=owner,
            repo=repo,
            task_fit=TaskFit.PUBLIC_REPOSITORY_METADATA,
        )
    except DataUnavailable as error:
        return _live_failure("DATA_UNAVAILABLE", str(error), network_attempted=True)
    except UnverifiedSource as error:
        return _live_failure("UNVERIFIED", str(error), network_attempted=True)

    if source.status != "VERIFIED_SOURCE":
        return _live_failure(
            source.status, source.reason or "GitHub metadata is not verified", source,
            network_attempted=True,
        )
    if len(source.records) != 1:
        return _live_failure(
            "DATA_UNAVAILABLE", "GitHub metadata response did not identify exactly one repository",
            source, network_attempted=True,
        )
    record = source.records[0]
    try:
        if (
            source.provider != Provider.GITHUB_REPOSITORY.value
            or source.task_fit != TaskFit.PUBLIC_REPOSITORY_METADATA.value
            or not source.read_only
            or source.response_status != 200
            or source.response_sha256 != record.response_sha256
            or source.response_status != record.response_status
            or source.retrieved_at_utc != record.retrieved_at_utc
            or source.request_body_sha256 != record.request_body_sha256
        ):
            raise DataUnavailable("GitHub repository response identity or provenance mismatch")
        metadata = _repository_metadata(record, source.request_url, owner, repo)
    except (DataUnavailable, UnverifiedSource) as error:
        return _live_failure(error.status, str(error), source, network_attempted=True)

    evidence_id = f"github-repo-{record.source_id}"
    return {
        "project": PROJECT,
        "status": "VERIFIED_SOURCE",
        "workflow_status": "UNVERIFIED — public GitHub metadata does not establish authorized CRM/account context or consent",
        "task_result": {
            "status": "PUBLIC_REPOSITORY_RESEARCH_ONLY",
            "summary": (
                f"GitHub identifies {metadata['full_name']} (repository ID {metadata['repository_id']}) "
                f"as a public repository on branch {metadata['default_branch']}; its metadata reports "
                f"{metadata['license_spdx_id']} and updated_at {metadata['updated_at']} "
                f"(observed age at retrieval: {metadata['updated_age_seconds']} seconds)."
            ),
            "metadata": metadata,
            "citations": [evidence_id],
            "review_checks": _public_research_checks(metadata, evidence_id),
            "human_verification_task": (
                "Review the selected repository identity, default branch, source updated_at, and its exact returned SPDX terms URL; decide whether those public metadata facts fit an explicitly authorized research question. The update timestamp is not proof of current activity. Do not treat this as a lead, CRM/account evidence, consent, or permission to contact anyone."
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
            "next_action": (
                f"Review the exact returned license terms at {metadata['license_terms_url']}, "
                "confirm the repository metadata is relevant to an explicitly authorized public-research "
                "question, and keep the timestamp limitation visible; do not create a lead or initiate contact."
            ),
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
            "mode": "selected public GitHub repository metadata plus deterministic identity/license/age checks; no fixture or cached fallback",
            "network_enabled": True,
            "network_attempted": True,
            "outreach_capability": "none",
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a public GitHub repository metadata research handoff. "
            "Defaults to pytest-dev/pytest when neither selection flag is supplied."
        )
    )
    parser.add_argument("--owner", help="GitHub owner path segment (supply together with --repo)")
    parser.add_argument("--repo", help="GitHub repository path segment (supply together with --owner)")
    args = parser.parse_args(argv)
    result = run_live(owner=args.owner, repo=args.repo)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED_SOURCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
