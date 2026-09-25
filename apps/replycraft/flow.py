"""Policy-grounded support reply drafting with a strict human-send boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessDenied, AccessPolicy, ApprovalAuthority, AuditLog, Authenticator,
    DataUnavailable, LiveSourceError, Provider, SourceRecord, TaskFit,
    FixtureAdapter, FixtureSchema, HMACTokenCodec, LocalOpenAIClient,
    Principal, PromptInjectionError, PromptSentinel, SecurityCore, SimulatedSink,
    fetch_live, redact,
)
from suite_core.live_sources import fetch_govinfo_opm_text, govinfo_opm_url
from suite_core.sources.federal_register import canonical_document_url

PROJECT = "ReplyCraft"
ACTION = "draft_support_reply"
ROLE = "support_agent"
CASE_EVIDENCE = "support-case-104"
POLICY_EVIDENCE = "support-policy-104"
TENANT_B_CANARY = "TENANT_B_REPLYCRAFT_CANARY_91D4"
PUBLIC_POLICY_QUESTION = (
    "SAMPLE QUESTION — By what date must the public submit comments on this OPM proposal?"
)
_CUSTOMER_SUPPORT_GAPS = (
    "consent-authorized customer support case",
    "approved internal support policy",
)
FIXTURES = Path(__file__).parent / "fixtures"
IMPORT_ROOT = Path.home() / ".local/share/industry-ai-suite/replycraft/imports"
IMPORT_MAX_BYTES = 64_000
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _security_stack(runtime: Path) -> tuple[Authenticator, SecurityCore, Principal, AuditLog]:
    audit = AuditLog(runtime / "audit.jsonl")
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            "tenant-alpha": {ROLE: {CASE_EVIDENCE, POLICY_EVIDENCE}},
            "tenant-beta": {ROLE: {"support-case-b04", "support-policy-b04"}},
        },
        {ROLE: {ACTION}},
    )
    return auth, SecurityCore(auth, policy, audit), Principal("tenant-alpha", "agent-104", ROLE), audit


def run_demo(ai_client: LocalOpenAIClient | None = None) -> dict[str, object]:
    """Fixture-only adversarial regression path; normal CLI execution uses run_live."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")

    with TemporaryDirectory(prefix="replycraft-demo-") as temp:
        auth, core, actor, audit = _security_stack(Path(temp))
        token = auth.issue(actor, expires_at=int(time.time()) + 60)
        authorized = core.authorize(
            token, tenant_id=actor.tenant_id, action=ACTION,
            evidence_ids=(CASE_EVIDENCE, POLICY_EVIDENCE),
        )
        adapter = FixtureAdapter(FIXTURES, authorized.tenant_id)
        case_data = adapter.load("cases.json", FixtureSchema({
            "case_id": str, "issue": str, "customer_email": str,
            "unresolved": bool, "days_since_purchase": int, "product": str,
        }))
        policy_data = adapter.load("policies.csv", FixtureSchema({
            "evidence_id": str, "product": str, "days_limit": int,
            "response_rule": str, "escalation_queue": str,
        }))
        case = next(row for row in case_data.rows if row["case_id"] == CASE_EVIDENCE)
        policy = next(row for row in policy_data.rows if row["evidence_id"] == POLICY_EVIDENCE)
        if case["product"] != policy["product"]:
            raise AccessDenied("request denied")
        PromptSentinel().check(str(case["issue"]), protected_canaries=(TENANT_B_CANARY,))
        PromptSentinel().check(str(policy["response_rule"]), protected_canaries=(TENANT_B_CANARY,))
        safe_issue = str(redact(case["issue"]))
        safe_policy = str(redact(policy["response_rule"]))

        unresolved = bool(case["unresolved"]) or int(case["days_since_purchase"]) > int(policy["days_limit"])
        if unresolved:
            draft = (
                "I’m sorry this has taken extra effort. The approved policy says this case needs "
                f"a specialist review [evidence:{POLICY_EVIDENCE}]. I’m preparing it for that team; "
                "no refund or account change has been made."
            )
            outcome = "ESCALATE"
            queue = str(policy["escalation_queue"])
        else:
            draft = (
                "Thanks for explaining the issue. I’ll follow the approved support policy and "
                f"share the next step for your case [evidence:{POLICY_EVIDENCE}]."
            )
            outcome = "DRAFT_FOR_AGENT_REVIEW"
            queue = "support-agent-review"

        prompt = (
            f"Draft an empathetic, concise response to this synthetic issue: {safe_issue} "
            f"Use only the approved rule '{safe_policy}' and cite "
            f"[evidence:{POLICY_EVIDENCE}]. Do not claim an action was completed."
        )
        ai = complete_grounded(
            ai_client, prompt,
            system="Write a draft only. Use supplied policy evidence and cite it exactly.",
            evidence_ids=(CASE_EVIDENCE, POLICY_EVIDENCE),
            protected_canaries=(TENANT_B_CANARY,),
        )

        approval = ApprovalAuthority(HMACTokenCodec(secrets.token_bytes(32)), approver_roles={"support_approver"})
        sink = SimulatedSink(approval, audit, allowed_actions={"send_reply"})
        case_source = f"tenant-alpha/{case_data.provenance['source_id']}"
        policy_source = f"tenant-alpha/{policy_data.provenance['source_id']}"
        result = {
            "project": PROJECT,
            "task_result": {
                "case_id": str(case["case_id"]), "decision": outcome,
                "draft": str(redact(draft)), "queue": queue,
                "customer_email_used": False, "human_approval_required_before_send": True,
                "send_attempted": False,
            },
            "evidence": [
                {"id": CASE_EVIDENCE, "source": case_source, "sha256": case_data.provenance["sha256"]},
                {"id": POLICY_EVIDENCE, "source": policy_source, "sha256": policy_data.provenance["sha256"]},
            ],
            "source_hashes": {
                case_source: case_data.provenance["sha256"],
                policy_source: policy_data.provenance["sha256"],
            },
            "uncertainty": ["The synthetic case lacks enough approved evidence for an automatic resolution."]
            + (["A local model request failed or its output was rejected; no validated AI completion is evidence. A timeout may leave server-side execution uncertain."] if ai["ai_failure"] else []),
            "risk": ["A draft is not a refund decision; a support specialist must review it."],
            "handoff": {"owner": queue, "next_action": "Review the cited case and approve or revise the draft."},
            "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"], "ai_output": ai["ai_output"],
            "ai_failure": ai["ai_failure"], "ai_handoff": ai["ai_handoff"],
            "ai_evidence": ai["ai_evidence"],
            "side_effect_count": len(sink.receipts),
            "integration_adapter": {
                "type": "FixtureAdapter + SimulatedSink", "mode": "synthetic, draft-only",
                "network_enabled": False, "send_capability": "simulated only; unused",
            },
            "negative_checks": {"unresolved_case_escalated": unresolved, "preapproval_sends": 0},
            "audit_event_count": len(audit.records()),
        }
        return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_import(path: str | Path) -> tuple[dict[str, object], bytes]:
    root = IMPORT_ROOT.resolve(strict=True)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=True)
    if (not resolved.is_relative_to(root) or candidate.is_symlink()
            or resolved.suffix.lower() != ".json"):
        raise ValueError("import path is outside the configured JSON import directory")
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("import is not a regular file")
        content = os.read(descriptor, IMPORT_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > IMPORT_MAX_BYTES:
        raise ValueError("import exceeds the 64 KB limit")
    value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(value) is not dict:
        raise ValueError("import root must be a JSON object")
    return value, content


def _valid_as_of(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        if len(value) == 10:
            return date.fromisoformat(value).isoformat() == value
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def _valid_utc(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() == datetime.now(timezone.utc).utcoffset()
    except ValueError:
        return False


def _import_status(status: str, reason: str, missing_sources: list[str]) -> dict[str, object]:
    return {
        "project": PROJECT,
        "status": status,
        "task_result": {"status": status, "draft": None, "send_attempted": False},
        "evidence": [],
        "missing_sources": missing_sources,
        "uncertainty": [reason],
        "handoff": {
            "owner": "unassigned support-policy reviewer",
            "next_action": "Provide the named authorized case, approved policy, and matching consent manifest for human review.",
        },
        "ai_status": "NOT REQUESTED",
        "ai_invoked": False,
        "ai_output": None,
        "ai_completion_claim": False,
        "side_effect_count": 0,
        "integration_adapter": {
            "type": "constrained local JSON import",
            "mode": "read-only, consent-gated draft only",
            "read_only": True,
            "send_capability": False,
        },
    }


def _public_document(record: SourceRecord) -> dict[str, object]:
    if (record.provider != Provider.FEDERAL_REGISTER_OPM.value
            or record.task_fit != TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
            or record.read_only is not True):
        raise DataUnavailable("Federal Register OPM metadata failed application validation")
    return {
        "source_id": record.source_id,
        "source_url": canonical_document_url(record.source_url, record.source_id, record.as_of),
        "as_of": record.as_of,
        "as_of_precision": record.as_of_precision,
        "retrieved_at_utc": record.retrieved_at_utc,
        "terms_url": record.terms_url,
        "response_status": record.response_status,
        "response_sha256": record.response_sha256,
        "task_fit": record.task_fit,
        "read_only": record.read_only,
    }


def _public_policy_unavailable(
    status: str,
    reason: str,
    *,
    request_url: str | None = None,
    metadata: SourceRecord | None = None,
) -> dict[str, object]:
    evidence = []
    if metadata is not None:
        try:
            evidence.append(_public_document(metadata))
        except DataUnavailable:
            pass
    return {
        "project": PROJECT,
        "status": status,
        "source_status": status,
        "workflow_status": "UNVERIFIED — public-policy sample only; customer support is not established",
        "request_url": request_url,
        "task_result": {
            "status": status,
            "question": PUBLIC_POLICY_QUESTION,
            "draft": None,
            "send_attempted": False,
        },
        "evidence": evidence,
        "missing_sources": [*_CUSTOMER_SUPPORT_GAPS,
            "reusable, identity-matched public policy text with a safe DATES section",
        ],
        "uncertainty": [reason],
        "handoff": {
            "owner": "public-policy-review-queue (role placeholder)",
            "next_action": "A human reviewer must inspect the official source; no customer response is available.",
        },
        "ai_status": "NOT USED — no AI claim",
        "ai_invoked": False,
        "ai_output": None,
        "ai_completion_claim": False,
        "side_effect_count": 0,
        "send_attempted": False,
        "integration_adapter": {
            "type": "suite_core.fetch_live + fetch_govinfo_opm_text",
            "read_only": True,
            "send_capability": False,
        },
    }


def run_public_policy() -> dict[str, object]:
    """Return a public-policy sample only; it is never a customer case or send."""
    try:
        source = fetch_live(
            Provider.FEDERAL_REGISTER_OPM,
            task_fit=TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS,
        )
    except LiveSourceError as error:
        return _public_policy_unavailable(
            error.status,
            "The live Federal Register OPM metadata request failed; no fixture or cache was used.",
        )
    if source.status != "VERIFIED_SOURCE" or not source.records:
        return _public_policy_unavailable(
            "UNVERIFIED",
            source.reason or "The live OPM source did not return admitted metadata.",
            request_url=source.request_url,
        )
    if (source.provider != Provider.FEDERAL_REGISTER_OPM.value
            or source.task_fit != TaskFit.PUBLIC_OPM_POLICY_DOCUMENTS.value
            or source.read_only is not True or source.response_status != 200
            or len(source.response_sha256) != 64):
        return _public_policy_unavailable(
            "DATA_UNAVAILABLE", "The live OPM metadata failed application provenance checks.",
            request_url=source.request_url,
        )
    metadata = next((
        item for item in source.records
        if item.data.get("type") in {"Rule", "Proposed Rule"}
        and isinstance(item.data.get("title"), str)
    ), None)
    if metadata is None:
        return _public_policy_unavailable(
            "UNVERIFIED", "No safe OPM Rule or Proposed Rule was returned for the public sample.",
            request_url=source.request_url,
        )
    try:
        public_document = _public_document(metadata)
    except DataUnavailable:
        return _public_policy_unavailable(
            "DATA_UNAVAILABLE", "The live OPM metadata failed document identity validation.",
            request_url=source.request_url,
        )

    request_url: str | None = None
    try:
        request_url = govinfo_opm_url(metadata)
        text = fetch_govinfo_opm_text(metadata)
    except LiveSourceError as error:
        return _public_policy_unavailable(
            error.status,
            f"The direct official GovInfo text request failed ({error.status}); no redirect or fallback was used.",
            request_url=request_url, metadata=metadata,
        )
    sections = text.data.get("sections") if isinstance(text.data, Mapping) else None
    required_sections = {"DATES"}
    if (
        text.provider != metadata.provider or text.source_id != metadata.source_id
        or text.source_url != request_url or text.response_status != 200
        or text.as_of != metadata.as_of or text.as_of_precision != "day"
        or text.terms_url != "https://www.govinfo.gov/about/policies#copyright"
        or text.read_only is not True or text.task_fit != "public_opm_policy_text"
        or not text.retrieved_at_utc.endswith("Z")
        or text.data.get("metadata_source_url") != metadata.source_url
        or text.data.get("metadata_response_sha256") != metadata.response_sha256
        or text.data.get("federal_register_terms_url") != metadata.terms_url
        or not isinstance(sections, Mapping) or not required_sections.issubset(sections)
        or any(not isinstance(sections[name], list) or not sections[name] for name in required_sections)
    ):
        return _public_policy_unavailable(
            "DATA_UNAVAILABLE", "GovInfo text did not pass identity, reuse-terms, or section checks.",
            request_url=request_url, metadata=metadata,
        )

    dates_text = " ".join(str(item) for item in sections["DATES"])
    citations = [f"{metadata.source_id}#DATES"]
    draft = f"Public-policy sample only: {dates_text} [evidence:{citations[0]}]"
    evidence = [public_document, {
        "source_id": text.source_id,
        "source_url": text.source_url,
        "as_of": text.as_of,
        "as_of_precision": text.as_of_precision,
        "retrieved_at_utc": text.retrieved_at_utc,
        "terms_url": text.terms_url,
        "response_status": text.response_status,
        "response_sha256": text.response_sha256,
        "task_fit": text.task_fit,
        "read_only": text.read_only,
    }]
    return {
        "project": PROJECT,
        "status": "VERIFIED_SOURCE",
        "source_status": "VERIFIED_SOURCE",
        "policy_text_status": "VERIFIED_SOURCE",
        "workflow_status": "UNVERIFIED — public-policy sample only; customer support remains unverified",
        "request_url": source.request_url,
        "task_result": {
            "status": "PUBLIC_POLICY_QA_SAMPLE",
            "question": PUBLIC_POLICY_QUESTION,
            "document_id": metadata.source_id,
            "draft": draft,
            "citations": citations,
            "sample_only": True,
            "customer_case": False,
            "human_approval_required_before_use": True,
            "send_attempted": False,
        },
        "evidence": evidence,
        "missing_sources": list(_CUSTOMER_SUPPORT_GAPS),
        "uncertainty": [
            "This is a sample about a public OPM proposal, not an individual customer or a company policy.",
            "The Federal Register HTML source is informational; consult the official GovInfo edition for legal research.",
        ],
        "risk": ["No customer communication or account action is authorized or attempted."],
        "handoff": {
            "owner": "public-policy-review-queue (role placeholder; no individual owner verified)",
            "next_action": "A human reviewer must approve or revise this sample before any separate use; no send endpoint is enabled.",
        },
        "ai_status": "NON-AI / DETERMINISTIC PUBLIC-POLICY SAMPLE",
        "ai_invoked": False,
        "ai_output": None,
        "ai_completion_claim": False,
        "side_effect_count": 0,
        "send_attempted": False,
        "approval_endpoint": "human-review-only; no message-send capability",
        "integration_adapter": {
            "type": "suite_core.fetch_live + fetch_govinfo_opm_text",
            "read_only": True,
            "send_capability": False,
        },
    }


def run_live(
    ai_client: LocalOpenAIClient | None = None,
    *,
    import_path: str | Path | None = None,
    consent_manifest_path: str | Path | None = None,
) -> dict[str, object]:
    """Use only an explicitly consented local case/policy import; never fixtures or sends."""
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        raise TypeError("ai_client must be a real LocalOpenAIClient instance")
    if import_path is None:
        return run_public_policy()
    if consent_manifest_path is None:
        consent_manifest_path = Path(import_path).with_suffix(".consent.json")
    try:
        bundle, bundle_bytes = _read_import(import_path)
        manifest, _ = _read_import(consent_manifest_path)
        if set(bundle) != {"case", "approved_policy"}:
            raise ValueError("import bundle must contain only case and approved_policy")
        case, policy = bundle["case"], bundle["approved_policy"]
        if type(case) is not dict or type(policy) is not dict:
            raise ValueError("case and approved_policy must be JSON objects")
        case_keys = {"source_id", "as_of", "issue", "product", "unresolved", "days_since_purchase"}
        policy_keys = {"source_id", "as_of", "policy_id", "product", "days_limit", "response_rule", "escalation_queue"}
        if set(case) != case_keys or set(policy) != policy_keys:
            raise ValueError("case or approved_policy does not match the minimal import schema")
        if (not all(isinstance(case[key], str) and case[key] for key in ("source_id", "issue", "product"))
                or not _SAFE_ID.fullmatch(case["source_id"])
                or not _valid_as_of(case["as_of"])
                or type(case["unresolved"]) is not bool
                or type(case["days_since_purchase"]) is not int
                or case["days_since_purchase"] < 0
                or len(case["issue"]) > 4000):
            raise ValueError("case fields do not match the minimal import schema")
        if (not all(isinstance(policy[key], str) and policy[key] for key in ("source_id", "policy_id", "product", "response_rule", "escalation_queue"))
                or not _SAFE_ID.fullmatch(policy["source_id"])
                or not _SAFE_ID.fullmatch(policy["policy_id"])
                or not _valid_as_of(policy["as_of"])
                or type(policy["days_limit"]) is not int
                or policy["days_limit"] < 0
                or len(policy["response_rule"]) > 2000):
            raise ValueError("approved_policy fields do not match the minimal import schema")
        manifest_keys = {
            "version", "bundle_sha256", "case_source_id", "case_as_of",
            "policy_source_id", "policy_as_of", "terms_reference", "purpose",
            "consent", "policy_approval",
        }
        if set(manifest) != manifest_keys:
            raise ValueError("consent manifest does not match its schema")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _import_status(
            "DATA_UNAVAILABLE",
            "The consent-gated import was rejected for path, size, encoding, JSON, or schema validation; no fixture was substituted.",
            ["valid local case/policy bundle and consent manifest inside the configured import directory"],
        )

    digest = hashlib.sha256(bundle_bytes).hexdigest()
    consent = manifest.get("consent")
    approval = manifest.get("policy_approval")
    if type(consent) is not dict or type(approval) is not dict:
        return _import_status(
            "UNVERIFIED", "The import manifest does not prove both customer consent and policy approval.",
            ["explicit customer consent record", "approved internal policy-owner record"],
        )
    consent_ok = (
        set(consent) == {"status", "record_id", "authorized_by", "authorized_at_utc"}
        and consent.get("status") == "authorized"
        and all(isinstance(consent.get(key), str) and consent[key] for key in ("record_id", "authorized_by"))
        and _valid_utc(consent.get("authorized_at_utc"))
    )
    approval_ok = (
        set(approval) == {"status", "record_id", "approved_by", "approved_at_utc"}
        and approval.get("status") == "approved"
        and all(isinstance(approval.get(key), str) and approval[key] for key in ("record_id", "approved_by"))
        and _valid_utc(approval.get("approved_at_utc"))
    )
    provenance_ok = (
        manifest.get("version") == 1
        and manifest.get("bundle_sha256") == digest
        and manifest.get("case_source_id") == case["source_id"]
        and manifest.get("case_as_of") == case["as_of"]
        and manifest.get("policy_source_id") == policy["source_id"]
        and manifest.get("policy_as_of") == policy["as_of"]
        and isinstance(manifest.get("terms_reference"), str)
        and bool(manifest["terms_reference"].strip())
        and manifest.get("purpose") == "support_reply_draft"
    )
    if not consent_ok or not approval_ok or not provenance_ok or case["product"] != policy["product"]:
        return _import_status(
            "UNVERIFIED",
            "The local manifest does not match the case and approved policy or does not assert the required consent and approval.",
            ["independently confirmed consent and policy approval bound to matching source IDs, as-of values, and import hash"],
        )

    try:
        PromptSentinel().check(case["issue"])
        PromptSentinel().check(policy["response_rule"])
    except PromptInjectionError:
        return _import_status(
            "UNVERIFIED", "Imported text failed the untrusted-content safety check; no draft was created.",
            ["safe authorized case and approved policy content"],
        )

    case_id = case["source_id"]
    policy_id = policy["policy_id"]
    safe_issue = str(redact(case["issue"]))
    safe_rule = str(redact(policy["response_rule"]))
    unresolved = case["unresolved"] or case["days_since_purchase"] > policy["days_limit"]
    queue = policy["escalation_queue"] if unresolved else "unassigned support-agent reviewer"
    draft = (
        f"A support specialist will review this case under the approved policy [evidence:{policy_id}]. "
        "No refund or account change has been made."
    )
    ai = complete_grounded(
        ai_client,
        f"Draft a short response for an authorized support case. Use only the redacted issue '{safe_issue}' and approved rule '{safe_rule}'. Cite [evidence:{case_id}] and [evidence:{policy_id}]. Do not claim an action was completed.",
        system="Write a draft for human review only. Never send a message or claim an account action.",
        evidence_ids=(case_id, policy_id),
    )
    if ai["ai_output"]:
        draft = str(ai["ai_output"])
    retrieved = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    source_records = [
        {
            "source_id": item["source_id"], "as_of": item["as_of"],
            "as_of_precision": "day" if len(item["as_of"]) == 10 else "timestamp",
            "retrieved_at_utc": retrieved, "terms": manifest["terms_reference"],
            "read_only": True, "sha256": digest,
        }
        for item in (case, policy)
    ]
    return {
        "project": PROJECT,
        "status": "UNVERIFIED",
        "task_result": {
            "status": "UNVERIFIED", "case_source_id": case_id,
            "decision": "ESCALATE" if unresolved else "DRAFT_FOR_AGENT_REVIEW",
            "draft": str(redact(draft)), "queue": queue,
            "human_approval_required_before_send": True, "send_attempted": False,
        },
        "evidence": source_records,
        "missing_sources": ["independent confirmation of the manifest's consent and policy-approval authority"],
        "uncertainty": ["Consent and policy approval are manifest assertions and have not been independently verified."],
        "risk": ["No customer message is sent; a support agent must approve any later action."],
        "handoff": {"owner": queue, "next_action": "Review the cited case and approved policy; revise the draft before any separately approved send."},
        "ai_status": ai["ai_status"], "ai_invoked": ai["ai_invoked"],
        "ai_output": ai["ai_output"], "ai_evidence": ai["ai_evidence"],
        "ai_completion_claim": False, "side_effect_count": 0,
        "integration_adapter": {
            "type": "constrained local JSON import", "mode": "read-only, consent-gated draft only",
            "read_only": True, "send_capability": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ReplyCraft against an explicitly authorized local import.")
    parser.add_argument("--case-import", help="JSON case/policy bundle inside the configured private import directory")
    parser.add_argument("--consent-manifest", help="matching consent/approval manifest JSON inside the same import directory")
    args = parser.parse_args()
    print(json.dumps(run_live(import_path=args.case_import, consent_manifest_path=args.consent_manifest), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
