"""Role-scoped onboarding guidance; no personnel decisions or record access."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessDenied, AccessPolicy, Authenticator, AuditLog, DataUnavailable,
    FixtureAdapter, FixtureSchema, HMACTokenCodec, LiveSourceError,
    LocalOpenAIClient, Principal, PromptSentinel, Provider, SecurityCore,
    SourceRecord, TaskFit, fetch_live, redact,
)

PROJECT = "OnboardPath"
ACTION = "answer_onboarding_policy"
ROLE = "new_hire"
REQUEST_EVIDENCE = "onboarding-request-410"
POLICY_EVIDENCE = "onboarding-policy-410"
FORBIDDEN_PERSONNEL = "personnel-record-private-410"
TENANT_B_CANARY = "TENANT_B_ONBOARDPATH_CANARY_6E15"
FIXTURES = Path(__file__).parent / "fixtures"
_PUBLIC_OPM_TYPES = frozenset({"Rule", "Proposed Rule", "Notice", "Presidential Document", "Correction"})


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
            or not isinstance(document_number, str) or not isinstance(publication_date, str)
            or not isinstance(record.source_url, str)
            or not record.source_url.startswith("https://www.federalregister.gov/documents/")):
        raise DataUnavailable("Federal Register OPM metadata failed application validation")
    document = {
        "document_number": document_number,
        "publication_date": publication_date,
        "source_id": record.source_id,
        "source_url": record.source_url,
        "as_of": record.as_of,
        "as_of_precision": record.as_of_precision,
        "retrieved_at_utc": record.retrieved_at_utc,
        "terms": record.terms_url,
        "read_only": record.read_only,
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


def run_live(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Discover public OPM documents; employee records and applicable HR policy stay unverified."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")
    missing = [
        "consent-authorized employee/onboarding records with requester-specific access",
        "approved internal HR policy text applicable to the employee's request",
    ]
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
                or len(source.response_sha256) != 64):
            raise DataUnavailable("Federal Register OPM response failed application validation")
        documents = [_public_document(record) for record in source.records]
    except DataUnavailable:
        return _live_status(
            "DATA_UNAVAILABLE",
            "The live OPM metadata failed application schema/provenance checks; no fixture fallback was used.",
            missing, source.request_url,
        )
    ai: dict[str, object] = {"ai_status": "NOT REQUESTED", "ai_invoked": False, "ai_output": None, "ai_evidence": None}
    if ai_client is not None:
        citations = tuple(document["source_id"] for document in documents)
        metadata = "\n".join(
            f"{document.get('document_type', 'Public document')} — {document['document_number']} — {document['publication_date']} [evidence:{document['source_id']}]"
            for document in documents
        )
        ai = complete_grounded(
            ai_client,
            "Summarize public document-discovery metadata only. Do not state or infer policy rules, employee permissions, eligibility, or onboarding requirements.\n" + metadata,
            system="Summarize public document types and publication dates only; do not answer an employee policy question.",
            evidence_ids=citations,
        )
    return {
        "project": PROJECT,
        "status": "UNVERIFIED",
        "source_status": source.status,
        "provider": source.provider,
        "request_url": source.request_url,
        "task_result": {
            "status": "UNVERIFIED", "documents": documents, "answer": None,
            "limitation": "OPM metadata supports public-document discovery only; it is not applicable policy text or employee/permission evidence.",
            "employee_records_loaded": False,
        },
        "evidence": documents,
        "missing_sources": missing,
        "uncertainty": ["Public document metadata was retrieved, but no authorized employee records or applicable internal policy content are available."],
        "risk": ["No policy answer, employee access, private permission, or personnel decision is inferred from metadata."],
        "handoff": {"owner": "unassigned HR/onboarding reviewer", "next_action": "A human HR/onboarding reviewer must connect authorized employee records and applicable internal policy before answering."},
        "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"],
        "ai_output": ai["ai_output"], "ai_evidence": ai["ai_evidence"],
        "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {"type": "suite_core.fetch_live", "provider": source.provider, "mode": "public OPM metadata discovery only", "read_only": True, "personnel_decision_capability": False},
    }


def main() -> int:
    print(json.dumps(run_live(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
