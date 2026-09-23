"""Permission-scoped document Q&A with source citations and traceable handoffs."""

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

PROJECT = "HandoffHub"
ACTION = "answer_handoff_question"
ROLE = "knowledge_worker"
DOC_EVIDENCE = "handoff-guide-206"
OWNER_EVIDENCE = "handoff-owner-map-206"
FORBIDDEN_DOC = "restricted-personnel-206"
TENANT_B_CANARY = "TENANT_B_HANDOFF_CANARY_7B20"
FIXTURES = Path(__file__).parent / "fixtures"
_PUBLIC_OPM_TYPES = frozenset({"Rule", "Proposed Rule", "Notice", "Presidential Document", "Correction"})


def _security_stack(runtime: Path) -> tuple[Authenticator, SecurityCore, Principal, AuditLog]:
    audit = AuditLog(runtime / "audit.jsonl")
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            "tenant-alpha": {ROLE: {DOC_EVIDENCE, OWNER_EVIDENCE}},
            "tenant-beta": {ROLE: {"handoff-guide-b06", "handoff-owner-map-b06"}},
        },
        {ROLE: {ACTION}},
    )
    return auth, SecurityCore(auth, policy, audit), Principal("tenant-alpha", "staff-206", ROLE), audit


def run_demo(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Fixture-only adversarial regression path; normal CLI execution uses run_live."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")

    with TemporaryDirectory(prefix="handoffhub-demo-") as temp:
        auth, core, actor, audit = _security_stack(Path(temp))
        token = auth.issue(actor, expires_at=int(time.time()) + 60)
        evidence_ids = (DOC_EVIDENCE, OWNER_EVIDENCE)
        principal = core.authorize(
            token, tenant_id=actor.tenant_id, action=ACTION, evidence_ids=evidence_ids,
        )
        adapter = FixtureAdapter(FIXTURES, principal.tenant_id)
        documents = adapter.load("knowledge.json", FixtureSchema({
            "doc_id": str, "title": str, "body": str, "team": str,
        }))
        owners = adapter.load("owners.csv", FixtureSchema({
            "evidence_id": str, "team": str, "owner": str, "next_action": str,
        }))
        doc = next(row for row in documents.rows if row["doc_id"] == DOC_EVIDENCE)
        owner = next(row for row in owners.rows if row["team"] == doc["team"])
        PromptSentinel().check(str(doc["body"]), protected_canaries=(TENANT_B_CANARY,))
        PromptSentinel().check(str(owner["next_action"]), protected_canaries=(TENANT_B_CANARY,))
        safe_body = str(redact(doc["body"]))
        safe_next_action = str(redact(owner["next_action"]))

        answer = (
            f"{safe_body} [evidence:{DOC_EVIDENCE}] The responsible owner is "
            f"{owner['owner']} [evidence:{OWNER_EVIDENCE}]."
        )
        prompt = (
            f"Answer a staff question using only '{safe_body}' and this handoff owner "
            f"'{owner['owner']}'. Cite [evidence:{DOC_EVIDENCE}] and "
            f"[evidence:{OWNER_EVIDENCE}]. Do not infer access to other documents."
        )
        ai = complete_grounded(
            ai_client, prompt,
            system="Answer only from allowed documents and cite supplied sources.",
            evidence_ids=evidence_ids, protected_canaries=(TENANT_B_CANARY,),
        )

        try:
            core.authorize(
                token, tenant_id=actor.tenant_id, action=ACTION, evidence_ids=(FORBIDDEN_DOC,),
            )
            forbidden_check = {"status": "UNEXPECTEDLY_ALLOWED", "answer": None}
        except AccessDenied:
            forbidden_check = {"status": "DENIED", "answer": "Access denied."}

        doc_source = f"tenant-alpha/{documents.provenance['source_id']}"
        owner_source = f"tenant-alpha/{owners.provenance['source_id']}"
        return {
            "project": PROJECT,
            "task_result": {
                "question": "Where do invoice mismatches go, and who owns the next review?",
                "answer": str(answer), "document_id": DOC_EVIDENCE,
                "citations": [DOC_EVIDENCE, OWNER_EVIDENCE],
                "handoff_owner": str(owner["owner"]), "next_action": safe_next_action,
            },
            "evidence": [
                {"id": DOC_EVIDENCE, "source": doc_source, "sha256": documents.provenance["sha256"]},
                {"id": OWNER_EVIDENCE, "source": owner_source, "sha256": owners.provenance["sha256"]},
            ],
            "source_hashes": {
                doc_source: documents.provenance["sha256"], owner_source: owners.provenance["sha256"],
            },
            "uncertainty": ["The answer reflects only the synthetic guide and owner map; document freshness is not inferred."]
            + (["A local model request failed or its output was rejected; no validated AI completion is evidence. A timeout may leave server-side execution uncertain."] if ai["ai_failure"] else []),
            "risk": ["Document access is decided before file contents are loaded; denial text is generic."],
            "handoff": {"owner": str(owner["owner"]), "next_action": safe_next_action,
                        "source_id": OWNER_EVIDENCE},
            "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"], "ai_output": ai["ai_output"],
            "ai_failure": ai["ai_failure"], "ai_handoff": ai["ai_handoff"],
            "ai_evidence": ai["ai_evidence"],
            "side_effect_count": 0,
            "integration_adapter": {
                "type": "FixtureAdapter", "mode": "read-only tenant-scoped Q&A and handoff draft",
                "network_enabled": False, "external_write_capability": False,
            },
            "negative_checks": {"forbidden_document_denied": forbidden_check},
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
        "task_result": {"status": status, "documents": [], "answer": None},
        "evidence": [], "missing_sources": missing, "uncertainty": [reason],
        "handoff": {
            "owner": "unassigned human knowledge owner",
            "next_action": "Connect authorized internal knowledge and ownership records; review public documents directly.",
        },
        "ai_status": "NOT REQUESTED", "ai_invoked": False,
        "ai_output": None, "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {
            "type": "suite_core.fetch_live", "provider": Provider.FEDERAL_REGISTER_OPM.value,
            "read_only": True, "external_write_capability": False,
        },
    }


def run_live(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Discover public OPM documents; internal knowledge and permissions stay unverified."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")
    missing = [
        "authorized, permission-scoped internal knowledge records for the staff task",
        "verified internal owner and next-action records; public OPM metadata does not identify these",
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
            "Summarize public document-discovery metadata only. Do not state or infer policy rules, permissions, eligibility, or staff ownership.\n" + metadata,
            system="Summarize public document types and publication dates only; do not answer a policy question.",
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
            "limitation": "OPM metadata supports public-document discovery only; it is not policy text or internal permission evidence.",
        },
        "evidence": documents,
        "missing_sources": missing,
        "uncertainty": ["Public document metadata was retrieved, but no internal knowledge content or permission-scoped handoff records are available."],
        "risk": ["No policy answer, employee access, private permission, or internal owner is inferred from metadata."],
        "handoff": {"owner": "unassigned human knowledge owner", "next_action": "A human knowledge owner must connect permission-scoped internal records and review any public document directly."},
        "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"],
        "ai_output": ai["ai_output"], "ai_evidence": ai["ai_evidence"],
        "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {"type": "suite_core.fetch_live", "provider": source.provider, "mode": "public OPM metadata discovery only", "read_only": True, "external_write_capability": False},
    }


def main() -> int:
    print(json.dumps(run_live(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
