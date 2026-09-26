"""Synthetic role-scoped demo and public OPM review; no live personnel-data access."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import time
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessDenied, AccessPolicy, Authenticator, AuditLog, DataUnavailable,
    FixtureAdapter, FixtureSchema, HMACTokenCodec, LiveSourceError,
    LocalOpenAIClient, OpenAICompatibleClient, Principal, PromptSentinel, Provider, SecurityCore,
    SourceRecord, TaskFit, fetch_live, redact,
)
# Keep the legacy symbol importable for older integration harnesses; the live
# workflow deliberately uses the direct GovInfo helper below.
from suite_core.live_sources import (
    fetch_federal_register_opm_text, fetch_govinfo_opm_text, govinfo_opm_url,
)
from suite_core.sources.federal_register import canonical_document_url

PROJECT = "OnboardPath"
ACTION = "answer_onboarding_policy"
ROLE = "new_hire"
REQUEST_EVIDENCE = "onboarding-request-410"
POLICY_EVIDENCE = "onboarding-policy-410"
FORBIDDEN_PERSONNEL = "personnel-record-private-410"
TENANT_B_CANARY = "TENANT_B_ONBOARDPATH_CANARY_6E15"
FIXTURES = Path(__file__).parent / "fixtures"
_PUBLIC_OPM_TYPES = frozenset({"Rule", "Proposed Rule", "Notice", "Presidential Document", "Correction"})
_RULE_TYPES = frozenset({"Rule", "Proposed Rule"})
_GOVINFO_SECTION_LABELS = ("SUMMARY", "DATES", "ADDRESSES", "SUPPLEMENTARY INFORMATION")
_DOCUMENT_NUMBER = re.compile(r"[0-9]{4}-[0-9]{4,6}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EXPOSED_SECTION_TEXTS = 8


def _security_stack(runtime: Path) -> tuple[Authenticator, SecurityCore, Principal, AuditLog]:
    audit = AuditLog(runtime / "audit.jsonl")
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            "tenant-alpha": {ROLE: {REQUEST_EVIDENCE, POLICY_EVIDENCE}},
            "tenant-beta": {ROLE: {"onboarding-request-b10", "onboarding-policy-b10"}},
        },
        {ROLE: {ACTION}},
    )
    return auth, SecurityCore(auth, policy, audit), Principal("tenant-alpha", "new-hire-410", ROLE), audit


def run_demo(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Fixture-only adversarial regression path; normal CLI execution uses run_live."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")

    with TemporaryDirectory(prefix="onboardpath-demo-") as temp:
        auth, core, actor, audit = _security_stack(Path(temp))
        token = auth.issue(actor, expires_at=int(time.time()) + 60)
        evidence_ids = (REQUEST_EVIDENCE, POLICY_EVIDENCE)
        principal = core.authorize(
            token, tenant_id=actor.tenant_id, action=ACTION, evidence_ids=evidence_ids,
        )
        adapter = FixtureAdapter(FIXTURES, principal.tenant_id)
        request_data = adapter.load("request.json", FixtureSchema({
            "request_id": str, "question": str, "requested_role": str, "evidence_id": str,
        }))
        policy_data = adapter.load("policies.csv", FixtureSchema({
            "evidence_id": str, "topic": str, "answer": str, "checklist": str, "owner": str,
        }))
        request = next(row for row in request_data.rows if row["evidence_id"] == REQUEST_EVIDENCE)
        policy = next(row for row in policy_data.rows if row["evidence_id"] == POLICY_EVIDENCE)
        if request["requested_role"] != ROLE:
            raise AccessDenied("request denied")
        PromptSentinel().check(str(request["question"]), protected_canaries=(TENANT_B_CANARY,))
        PromptSentinel().check(str(policy["answer"]), protected_canaries=(TENANT_B_CANARY,))
        safe_question = str(redact(request["question"]))
        safe_answer = str(redact(policy["answer"]))

        checklist = [
            str(redact(item.strip()))
            for item in str(policy["checklist"]).split(";") if item.strip()
        ]
        answer = f"{safe_answer} [evidence:{POLICY_EVIDENCE}]"
        prompt = (
            f"Answer this new-hire policy question: {safe_question} Use only '{safe_answer}' "
            f"and cite [evidence:{POLICY_EVIDENCE}]. Do not make a hiring or discipline decision."
        )
        ai = complete_grounded(
            ai_client, prompt,
            system="Provide policy guidance only; no employee or hiring decisions.",
            evidence_ids=evidence_ids, protected_canaries=(TENANT_B_CANARY,),
        )

        try:
            core.authorize(
                token, tenant_id=actor.tenant_id, action=ACTION,
                evidence_ids=(FORBIDDEN_PERSONNEL,),
            )
            forbidden_check = {"status": "UNEXPECTEDLY_ALLOWED", "answer": None}
        except AccessDenied:
            forbidden_check = {"status": "DENIED", "answer": "Access denied."}

        request_source = f"tenant-alpha/{request_data.provenance['source_id']}"
        policy_source = f"tenant-alpha/{policy_data.provenance['source_id']}"
        return {
            "project": PROJECT,
            "task_result": {
                "requested_role": ROLE, "answer": answer, "checklist": checklist,
                "policy_id": POLICY_EVIDENCE, "employment_decision": "NONE",
                "personnel_record_loaded": False,
            },
            "evidence": [
                {"id": REQUEST_EVIDENCE, "source": request_source, "sha256": request_data.provenance["sha256"]},
                {"id": POLICY_EVIDENCE, "source": policy_source, "sha256": policy_data.provenance["sha256"]},
            ],
            "source_hashes": {
                request_source: request_data.provenance["sha256"],
                policy_source: policy_data.provenance["sha256"],
            },
            "uncertainty": ["This answer reflects only the synthetic onboarding policy; local benefits and timing must be confirmed by HR."]
            + (["A local model request failed or its output was rejected; no validated AI completion is evidence. A timeout may leave server-side execution uncertain."] if ai["ai_failure"] else []),
            "risk": ["The workflow has no personnel-record access and makes no hiring or disciplinary decision."],
            "handoff": {"owner": str(policy["owner"]), "next_action": "Confirm the checklist and local start-date details with the onboarding coordinator."},
            "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"], "ai_output": ai["ai_output"],
            "ai_failure": ai["ai_failure"], "ai_handoff": ai["ai_handoff"],
            "ai_evidence": ai["ai_evidence"],
            "side_effect_count": 0,
            "integration_adapter": {
                "type": "FixtureAdapter", "mode": "role-scoped policy lookup and onboarding checklist",
                "network_enabled": False, "personnel_decision_capability": False,
            },
            "negative_checks": {"forbidden_personnel_denied": forbidden_check},
            "audit_event_count": len(audit.records()),
        }


def _public_document(record: SourceRecord) -> dict[str, object]:
    data = record.data
    document_number = record.source_id
    publication_date = record.as_of
    if (record.provider != Provider.FEDERAL_REGISTER_OPM.value
            or record.task_fit != TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
            or record.read_only is not True
            or not isinstance(record.terms_url, str) or not record.terms_url
            or not isinstance(record.retrieved_at_utc, str)
            or record.response_status != 200
            or not isinstance(record.response_sha256, str) or _SHA256.fullmatch(record.response_sha256) is None
            or not isinstance(document_number, str) or not isinstance(publication_date, str)
            or not isinstance(record.source_url, str)):
        raise DataUnavailable("Federal Register OPM metadata failed application validation")
    canonical_url = canonical_document_url(record.source_url, document_number, publication_date)
    document = {
        "document_number": document_number,
        "publication_date": publication_date,
        "source_id": record.source_id,
        "source_url": canonical_url,
        "as_of": record.as_of,
        "as_of_precision": record.as_of_precision,
        "retrieved_at_utc": record.retrieved_at_utc,
        "terms": record.terms_url,
        "read_only": record.read_only,
        "response_status": record.response_status,
        "response_sha256": record.response_sha256,
    }
    document_type = data.get("type")
    if isinstance(document_type, str) and document_type in _PUBLIC_OPM_TYPES:
        document["document_type"] = document_type
    return document


def _live_status(
    status: str, reason: str, missing: list[str], request_url: str | None = None,
) -> dict[str, object]:
    return {
        "project": PROJECT, "status": status, "source_status": status,
        "provider": Provider.FEDERAL_REGISTER_OPM.value, "request_url": request_url,
        "task_result": {"status": status, "documents": [], "answer": None, "employee_records_loaded": False},
        "evidence": [], "missing_sources": missing, "uncertainty": [reason],
        "handoff": {
            "owner": "unassigned HR/onboarding reviewer",
            "next_action": "Connect authorized employee records and applicable approved internal HR policy; review public documents directly.",
        },
        "ai_status": "NOT REQUESTED", "ai_invoked": False,
        "ai_output": None, "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {
            "type": "suite_core.fetch_live", "provider": Provider.FEDERAL_REGISTER_OPM.value,
            "read_only": True, "personnel_decision_capability": False,
        },
    }


def _safe_public_text(value: object, maximum_length: int) -> bool:
    return (
        isinstance(value, str) and bool(value.strip()) and len(value) <= maximum_length
        and str(redact(value)) == value
    )


def _safe_policy_text(metadata: SourceRecord, text_source: SourceRecord) -> list[str]:
    data = text_source.data
    paragraphs = data.get("document_text") if isinstance(data, Mapping) else None
    sections = data.get("sections") if isinstance(data, Mapping) else None
    if (
        text_source.provider != Provider.FEDERAL_REGISTER_OPM.value
        or text_source.source_id != metadata.source_id
        or text_source.source_url != govinfo_opm_url(metadata)
        or text_source.response_status != 200
        or not isinstance(text_source.response_sha256, str)
        or _SHA256.fullmatch(text_source.response_sha256) is None
        or text_source.as_of != metadata.as_of
        or text_source.as_of_precision != "day"
        or not isinstance(text_source.retrieved_at_utc, str)
        or not text_source.retrieved_at_utc.endswith("Z")
        or text_source.terms_url != "https://www.govinfo.gov/about/policies#copyright"
        or text_source.read_only is not True
        or text_source.task_fit != "public_opm_policy_text"
        or not isinstance(paragraphs, list)
        or not paragraphs
        or len(paragraphs) > 8
        or any(not _safe_public_text(paragraph, 1000) for paragraph in paragraphs)
        or data.get("title") != metadata.data.get("title")
        or data.get("type") != metadata.data.get("type")
        or data.get("metadata_response_sha256") != metadata.response_sha256
        or data.get("metadata_source_url") != metadata.source_url
        or data.get("federal_register_terms_url") != metadata.terms_url
        or not isinstance(sections, Mapping)
    ):
        raise DataUnavailable("GovInfo OPM text failed identity, terms, or safe-text checks")
    return paragraphs


def _safe_section_reviews(metadata: SourceRecord, text_source: SourceRecord) -> list[dict[str, str]]:
    """Project only bounded, privacy-safe section text with stable citations."""
    raw_sections = text_source.data["sections"]
    if (
        len(raw_sections) > len(_GOVINFO_SECTION_LABELS)
        or any(label not in _GOVINFO_SECTION_LABELS for label in raw_sections)
    ):
        raise DataUnavailable("GovInfo OPM text returned too many section labels")

    reviews: list[dict[str, str]] = []
    for label in _GOVINFO_SECTION_LABELS:
        if label not in raw_sections:
            continue
        texts = raw_sections[label]
        if not isinstance(texts, list) or len(texts) > 4:
            raise DataUnavailable("GovInfo OPM section text exceeded its safe bounds")
        for text in texts:
            if not _safe_public_text(text, 1200):
                raise DataUnavailable("GovInfo OPM section text failed privacy or length checks")
            if len(reviews) < _MAX_EXPOSED_SECTION_TEXTS:
                reviews.append({
                    "label": label,
                    "text": text,
                    "citation": f"opm-text-{metadata.source_id}#{label}",
                })
    return reviews


def _no_document_status(reason: str, missing: list[str]) -> dict[str, object]:
    result = _live_status("UNVERIFIED", reason, missing)
    result["policy_text_status"] = "UNVERIFIED"
    result["policy_text_failure"] = None
    result["task_result"]["status"] = "PUBLIC_OPM_DOCUMENT_NOT_FOUND"
    result["task_result"]["limitation"] = (
        "No public OPM document was selected; this workflow cannot provide employer policy, legal advice, "
        "employee evidence, or permission proof."
    )
    result["handoff"] = {
        "owner": "public-opm-policy-review-queue",
        "next_action": (
            "Choose a Rule or Proposed Rule document number from the current OPM metadata list; "
            "no GovInfo text request was made. Connect authorized employee records and applicable employer policy "
            "before answering a person."
        ),
    }
    return result


def _matching_rule_records(records: tuple[SourceRecord, ...], document_number: str | None) -> list[SourceRecord]:
    return [
        record for record in records
        if record.data.get("type") in _RULE_TYPES
        and record.data.get("document_number") == record.source_id
        and isinstance(record.data.get("title"), str)
        and (document_number is None or record.source_id == document_number)
    ]


def run_live(
    ai_client: LocalOpenAIClient | OpenAICompatibleClient | None = None,
    document_number: str | None = None,
) -> dict[str, object]:
    """Review one admitted public OPM rule; employee records and employer policy stay unverified."""
    if ai_client is not None and type(ai_client) not in (LocalOpenAIClient, OpenAICompatibleClient):
        raise TypeError("ai_client must be a suite_core OpenAI-compatible client")
    missing = [
        "consent-authorized employee/onboarding records with requester-specific access",
        "approved internal HR policy text applicable to the employee's request",
    ]
    if document_number is not None and (
        not isinstance(document_number, str) or _DOCUMENT_NUMBER.fullmatch(document_number) is None
    ):
        return _no_document_status(
            "The requested document number is malformed; use a Federal Register number in YYYY-NNNN.. format. "
            "No metadata or GovInfo text request was made.",
            missing,
        )
    try:
        source = fetch_live(
            Provider.FEDERAL_REGISTER_OPM,
            task_fit=TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        )
    except LiveSourceError as error:
        return _live_status(
            error.status,
            "The live OPM metadata request failed; no fixture or cached response was substituted.",
            missing,
        )
    if source.status != "VERIFIED_SOURCE" or not source.records:
        return _live_status(
            "UNVERIFIED", source.reason or "The public source did not establish usable OPM metadata.",
            missing, source.request_url,
        )
    try:
        if (source.provider != Provider.FEDERAL_REGISTER_OPM.value
                or source.task_fit != TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
                or source.read_only is not True or source.response_status != 200
                or not isinstance(source.response_sha256, str)
                or _SHA256.fullmatch(source.response_sha256) is None):
            raise DataUnavailable("Federal Register OPM response failed application validation")
        documents = [_public_document(record) for record in source.records]
    except DataUnavailable:
        return _live_status(
            "DATA_UNAVAILABLE",
            "The live OPM metadata failed application schema/provenance checks; no fixture fallback was used.",
            missing, source.request_url,
        )
    matching_records = _matching_rule_records(source.records, document_number)
    selection_failure = document_number is not None and len(matching_records) != 1
    metadata_record = matching_records[0] if matching_records and not selection_failure else None
    text_record: SourceRecord | None = None
    text_paragraphs: list[str] = []
    section_reviews: list[dict[str, str]] = []
    policy_text_status = "UNVERIFIED"
    policy_text_reason = (
        f"No unique Rule or Proposed Rule with document number {document_number} was present in the fresh OPM metadata response; "
        "no GovInfo text request was made."
        if selection_failure else "No recent OPM Rule or Proposed Rule with a safe title was returned."
    )
    text_request_attempted = False
    if metadata_record is not None:
        try:
            text_request_attempted = True
            text_record = fetch_govinfo_opm_text(metadata_record)
            text_paragraphs = _safe_policy_text(metadata_record, text_record)
            section_reviews = _safe_section_reviews(metadata_record, text_record)
            policy_text_status = "VERIFIED_SOURCE"
            policy_text_reason = ""
        except LiveSourceError as error:
            text_record = None
            policy_text_status = error.status
            policy_text_reason = f"The direct GovInfo text request failed ({error.status}: {error}); no Federal Register redirect, fixture, or cache was used."

    ai: dict[str, object] = {
        "ai_status": "NON-AI / DETERMINISTIC FALLBACK",
        "ai_invoked": False, "ai_output": None, "ai_evidence": None,
        "ai_failure": None, "ai_handoff": "Review the cited public source directly; employee-specific guidance is not available.",
    }
    selected_document = None
    text_evidence = None
    text_evidence_id = None
    if metadata_record is not None and text_record is not None:
        text_evidence_id = f"opm-text-{metadata_record.source_id}"
        excerpt_source = " ".join(text_paragraphs)
        excerpt = excerpt_source[:1200]
        selected_document = {
            "document_number": metadata_record.source_id,
            "source_id": metadata_record.source_id,
            "document_type": metadata_record.data["type"],
            "publication_date": metadata_record.as_of,
            "metadata_response_status": metadata_record.response_status,
            "metadata_response_sha256": metadata_record.response_sha256,
            "metadata_retrieved_at_utc": metadata_record.retrieved_at_utc,
            "federal_register_terms_url": metadata_record.terms_url,
            "text_response_sha256": text_record.response_sha256,
            "text_retrieved_at_utc": text_record.retrieved_at_utc,
            "text_terms_url": text_record.terms_url,
            "text_excerpt": excerpt,
            "excerpt_truncated": len(excerpt_source) > len(excerpt),
            "sections": section_reviews,
            "citations": [text_evidence_id],
        }
        text_evidence = {
            "evidence_id": text_evidence_id,
            "source_id": text_record.source_id,
            "source_url": text_record.source_url,
            "as_of": text_record.as_of,
            "as_of_precision": text_record.as_of_precision,
            "retrieved_at_utc": text_record.retrieved_at_utc,
            "terms_url": text_record.terms_url,
            "federal_register_terms_url": text_record.data["federal_register_terms_url"],
            "response_status": text_record.response_status,
            "response_sha256": text_record.response_sha256,
            "metadata_response_sha256": text_record.data["metadata_response_sha256"],
            "read_only": text_record.read_only,
            "task_fit": text_record.task_fit,
        }
        ai = complete_grounded(
            ai_client,
            f"Summarize only the public Federal Register OPM {metadata_record.data['type']} text below for a human reviewer. "
            f"Cite [evidence:{text_evidence_id}]. Do not answer an employee-specific question, claim this is an employer's policy, "
            f"or make an eligibility, hiring, or disciplinary decision. Text: {excerpt}",
            system="Write one short, cautious observation about the cited federal document only; no legal advice or employee decision.",
            evidence_ids=(text_evidence_id,),
        )

    all_evidence = [*documents]
    if text_evidence is not None:
        all_evidence.append(text_evidence)
    return {
        "project": PROJECT,
        "status": "UNVERIFIED",
        "source_status": source.status,
        "policy_text_status": policy_text_status,
        "policy_text_failure": ({
            "request_url": govinfo_opm_url(metadata_record),
            "source_id": metadata_record.source_id,
            "status": policy_text_status,
            "reason": policy_text_reason,
        } if text_request_attempted and metadata_record is not None and text_record is None else None),
        "provider": source.provider,
        "request_url": source.request_url,
        "task_result": {
            "status": (
                "PUBLIC_OPM_POLICY_TEXT_REVIEW_ONLY" if text_record else
                "PUBLIC_OPM_DOCUMENT_NOT_FOUND" if selection_failure else
                "PUBLIC_OPM_METADATA_DISCOVERY_ONLY"
            ),
            "documents": documents, "selected_document": selected_document, "answer": None,
            "limitation": "Federal Register text is a public-document review aid, not employer policy, legal advice, employee evidence, or permission proof.",
            "employee_records_loaded": False,
        },
        "evidence": all_evidence,
        "missing_sources": missing,
        "uncertainty": [
            "No authorized employee records or applicable employer HR policy are available; employee-specific service remains UNVERIFIED.",
            "Federal Register HTML is informational; verify legal questions against official editions.",
            *([policy_text_reason] if policy_text_reason else []),
        ],
        "risk": ["No employee access, employer policy answer, eligibility, hiring, or disciplinary decision is inferred from public text."],
        "handoff": {
            "owner": "public-opm-policy-review-queue",
            "next_action": (
                "Choose a Rule or Proposed Rule document number from the current OPM metadata list; no GovInfo text was requested. "
                "Connect authorized employee records and applicable employer policy before answering a person."
                if selection_failure else
                "A human reviewer should inspect the cited federal document; connect authorized employee records and applicable employer policy before answering a person."
            ),
        },
        "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"],
        "ai_output": ai["ai_output"], "ai_failure": ai["ai_failure"],
        "ai_handoff": ai["ai_handoff"], "ai_evidence": ai["ai_evidence"],
        "ai_verification_status": "AI CANDIDATE (unwitnessed)" if ai["ai_invoked"] else (
            "NON-AI / DETERMINISTIC FALLBACK" if text_record else "UNVERIFIED — no admitted public rule text"
        ),
        "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {
            "type": "suite_core.fetch_live + suite_core.live_sources.fetch_govinfo_opm_text",
            "provider": source.provider,
            "mode": "live OPM metadata plus one safe, identity-matched Rule/Proposed Rule text page; no fixture or cache fallback",
            "read_only": True, "personnel_decision_capability": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review a public OPM Rule or Proposed Rule; employee-specific guidance stays unverified."
    )
    parser.add_argument(
        "--document-number",
        help="Select one Rule or Proposed Rule already present in the fresh OPM metadata response.",
    )
    arguments = parser.parse_args(argv)
    print(json.dumps(run_live(document_number=arguments.document_number), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
