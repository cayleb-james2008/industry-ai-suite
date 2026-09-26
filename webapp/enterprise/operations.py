"""Consent, permission, and policy-bound local review paths."""

from __future__ import annotations

import hashlib
import re
from datetime import date

from .common import (
    ImportContext, exact_object, identifier, iso_date, nonnegative_int,
    receipt, rows, safe_text, text, unique_ids,
)


def review_reply(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"case", "policy", "consent"}, "ReplyCraft data")
    consent = exact_object(data["consent"], {"case_id", "consent_record_id", "status"}, "Consent record")
    if consent["status"] != "authorized":
        raise ValueError("A consent record marked authorized is required before a case is reviewed.")
    case = exact_object(data["case"], {"case_id", "issue", "product", "unresolved", "days_since_purchase"}, "Support case")
    policy = exact_object(data["policy"], {"policy_id", "product", "days_limit", "response_rule", "escalation_queue", "approved_by"}, "Approved policy")
    case_id = identifier(case["case_id"], "Case ID")
    policy_id = identifier(policy["policy_id"], "Policy ID")
    consent_id = identifier(consent["consent_record_id"], "Consent record ID")
    if consent["case_id"] != case_id or case["product"] != policy["product"]:
        raise ValueError("Consent, case, and policy identifiers do not match.")
    identifier(case["product"], "Product code")
    identifier(policy["approved_by"], "Policy approver code")
    queue = identifier(policy["escalation_queue"], "Escalation queue")
    safe_issue = safe_text(case["issue"], "Case issue", maximum=1000)
    safe_rule = safe_text(policy["response_rule"], "Approved rule", maximum=1000)
    if type(case["unresolved"]) is not bool:
        raise ValueError("Unresolved must be true or false.")
    days = nonnegative_int(case["days_since_purchase"], "Days since purchase")
    limit = nonnegative_int(policy["days_limit"], "Policy day limit")
    escalate = case["unresolved"] or days > limit
    draft = (
        f"Thank you for explaining the issue. The approved rule says: {safe_rule} "
        f"[evidence:{policy_id}]. This case needs review by {queue}; no refund or account change has been made."
        if escalate else
        f"Thank you for explaining the issue. Based on the approved rule, {safe_rule} "
        f"[evidence:{policy_id}]. A support agent will confirm the next step before anything is sent."
    )
    result = {
        "case_id": case_id,
        "issue_for_reviewer": safe_issue,
        "decision": "ESCALATE" if escalate else "DRAFT_FOR_AGENT_REVIEW",
        "draft": draft,
        "queue": queue if escalate else "support-agent-review",
        "citations": [case_id, policy_id, consent_id],
        "dedicated_contact_fields_accepted": False,
        "send_attempted": False,
    }
    summary = {
        "title": "Policy-grounded support draft",
        "metrics": [{"label": "Decision", "value": result["decision"]}, {"label": "Send attempted", "value": "No"}],
        "findings": [f"Consent assertion {consent_id} matches case {case_id}; independent consent verification remains open.", f"Policy {policy_id} was supplied for product {case['product']} and needs owner confirmation."],
        "draft": draft,
    }
    return receipt("ReplyCraft", context, result, evidence_ids=[case_id, policy_id, consent_id], summary=summary,
                   next_action="A support owner must verify consent and policy approval, edit the draft, and decide separately whether any message may be sent.")


def review_handoff(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"question", "requester_role", "documents", "owners"}, "HandoffHub data")
    role = identifier(data["requester_role"], "Requester role")
    documents = rows(data["documents"], {"doc_id", "title", "body", "team", "allowed_roles"}, "Knowledge documents", maximum=50)
    unique_ids(documents, "doc_id", "Document ID")
    owners = rows(data["owners"], {"evidence_id", "team", "owner_id", "next_action"}, "Owner map", maximum=50)
    unique_ids(owners, "evidence_id", "Owner evidence ID")
    owner_by_team = {}
    for item in owners:
        team_id = identifier(item["team"], "Owner team")
        identifier(item["owner_id"], "Owner code")
        text(item["next_action"], "Owner next action", maximum=300)
        if team_id in owner_by_team:
            raise ValueError("Multiple owners for one team need an explicit owner selection.")
        owner_by_team[team_id] = item
    question = safe_text(data["question"], "Staff question", maximum=500)
    stopwords = {"a", "an", "and", "are", "do", "document", "for", "from", "guidance", "help", "how", "i", "in", "is", "it", "me", "my", "of", "on", "or", "policy", "sample", "should", "the", "this", "to", "what", "where", "which", "who", "with"}
    terms = {word for word in re.findall(r"[a-z0-9]{3,}", question.lower()) if word not in stopwords}
    if not terms:
        raise ValueError("Ask a more specific knowledge question.")
    allowed = []
    for item in documents:
        identifier(item["team"], "Document team")
        if not isinstance(item["title"], str) or not 1 <= len(item["title"]) <= 160:
            raise ValueError("Document title must contain 1 to 160 characters.")
        if not isinstance(item["body"], str) or not 1 <= len(item["body"]) <= 2000:
            raise ValueError("Document body must contain 1 to 2000 characters.")
        grants = item["allowed_roles"]
        if not isinstance(grants, list) or not grants or any(not isinstance(grant, str) for grant in grants):
            raise ValueError("Document role grants are invalid.")
        grant_ids = [identifier(grant, "Document role grant") for grant in grants]
        if role in grant_ids:
            allowed.append(item)
    if not allowed:
        raise ValueError("Access denied for the supplied knowledge documents.")
    scored = []
    for item in allowed:
        title = safe_text(item["title"], "Document title", maximum=160)
        body = safe_text(item["body"], "Knowledge body", maximum=2000)
        title_terms = set(re.findall(r"[a-z0-9]{3,}", title.lower()))
        body_terms = set(re.findall(r"[a-z0-9]{3,}", body.lower()))
        score = 3 * len(terms & title_terms) + len(terms & body_terms)
        scored.append((score, item, title, body))
    scored.sort(key=lambda entry: entry[0], reverse=True)
    if not scored or scored[0][0] == 0 or (len(scored) > 1 and scored[0][0] == scored[1][0]):
        result = {"question": question, "decision": "UNANSWERED", "answer": None, "citations": [], "nonselected_documents_quoted": False,
                  "role_check": "IMPORTED GRANT ONLY / REQUESTER IDENTITY UNVERIFIED"}
        summary = {"title": "Permission-scoped knowledge handoff", "metrics": [{"label": "Answer", "value": "Needs human owner"}],
                   "findings": ["No single relevant, role-permitted document supported an answer to the supplied question. No document text was returned."]}
        return receipt("HandoffHub", context, result, evidence_ids=[], summary=summary,
                       next_action="An authenticated knowledge owner must locate a relevant permitted document and assign a handoff; do not answer from an unrelated source.")
    _, selected, title, body = scored[0]
    target = identifier(selected["doc_id"], "Document ID")
    team = identifier(selected["team"], "Document team")
    owner = owner_by_team.get(team)
    if owner is None:
        raise ValueError("No owner exists for the matched document team.")
    owner_id = identifier(owner["owner_id"], "Owner code")
    owner_evidence = identifier(owner["evidence_id"], "Owner evidence ID")
    next_step = safe_text(owner["next_action"], "Owner next action", maximum=300)
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", body) if part.strip()]
    ranked = sorted(sentences, key=lambda sentence: len(terms & set(re.findall(r"[a-z0-9]{3,}", sentence.lower()))), reverse=True)
    excerpt = ranked[0][:500]
    result = {
        "question": question,
        "decision": "MATCHED_EXCERPT_FOR_REVIEW",
        "document_id": target,
        "document_title": title,
        "answer": f"{excerpt} [evidence:{target}]",
        "handoff_owner": owner_id,
        "next_action": next_step,
        "citations": [target, owner_evidence],
        "nonselected_documents_quoted": False,
        "role_check": "IMPORTED GRANT ONLY / REQUESTER IDENTITY UNVERIFIED",
    }
    summary = {
        "title": "Permission-scoped knowledge handoff",
        "metrics": [{"label": "Allowed document", "value": target}, {"label": "Owner", "value": owner_id}],
        "findings": [f"Document {target} matched the question among {len(allowed)} role-permitted imports; source access was asserted by the import and needs identity-system verification.", f"Next action: {next_step} [evidence:{owner_evidence}]."],
    }
    return receipt("HandoffHub", context, result, evidence_ids=[target, owner_evidence], summary=summary,
                   next_action="Verify staff identity, current document permissions, and owner assignment before sending a workplace handoff.")


def review_pipeline(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"consent", "account"}, "PipelineRelay data")
    consent = exact_object(data["consent"], {"evidence_id", "account_id", "status", "as_of"}, "Account consent")
    if consent["status"] != "authorized":
        raise ValueError("An authorized consent record is required before account context is reviewed.")
    consent_id = identifier(consent["evidence_id"], "Consent evidence ID")
    account_id = identifier(consent["account_id"], "Account ID")
    if date.fromisoformat(iso_date(consent["as_of"], "Consent as-of")) > date.fromisoformat(context.as_of):
        raise ValueError("Consent as-of cannot be later than the source as-of date.")
    account = exact_object(data["account"], {"evidence_id", "account_id", "priority", "renewal_window", "approved_context", "owner_id"}, "Account context")
    if account["account_id"] != account_id:
        raise ValueError("Consent and account IDs do not match.")
    account_evidence = identifier(account["evidence_id"], "Account evidence ID")
    owner = identifier(account["owner_id"], "Account owner code")
    priority = identifier(account["priority"], "Priority")
    window = safe_text(account["renewal_window"], "Renewal window", maximum=120)
    approved_context = safe_text(account["approved_context"], "Approved context", maximum=1000)
    result = {
        "account_id": account_id,
        "priority": priority,
        "renewal_window": window,
        "approved_context": approved_context,
        "citations": [consent_id, account_evidence],
        "consent_verified": False,
        "outreach_sent": False,
    }
    summary = {
        "title": "Consent-gated account handoff",
        "metrics": [{"label": "Account", "value": account_id}, {"label": "Outreach", "value": "None"}],
        "findings": [f"Consent record {consent_id} and account record {account_evidence} align; their organizational authority is still unverified.", f"Owner {owner} should review the {window} window before deciding on contact."],
        "draft": f"Human handoff for {account_id}: {approved_context} [evidence:{account_evidence}]. Consent assertion: [evidence:{consent_id}]. No outreach occurred.",
    }
    return receipt("PipelineRelay", context, result, evidence_ids=[consent_id, account_evidence], summary=summary,
                   next_action="The account owner must verify CRM access, current consent and contact policy before approving any separate outreach.")


def review_onboard(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"request", "policies"}, "OnboardPath data")
    request = exact_object(data["request"], {"request_id", "employee_ref", "question", "requested_role", "topic", "start_date"}, "Onboarding request")
    request_id = identifier(request["request_id"], "Request ID")
    employee_ref = identifier(request["employee_ref"], "Employee reference")
    role = identifier(request["requested_role"], "Requested role")
    topic = identifier(request["topic"], "Policy topic")
    iso_date(request["start_date"], "Start date")
    policies = rows(data["policies"], {"policy_id", "topic", "answer", "checklist", "owner_id", "allowed_roles", "approved_as_of"}, "HR policies", maximum=50)
    unique_ids(policies, "policy_id", "Policy ID")
    for item in policies:
        identifier(item["topic"], "Policy topic")
        identifier(item["owner_id"], "HR owner code")
        iso_date(item["approved_as_of"], "Policy approval date")
        grants = item["allowed_roles"]
        if not isinstance(grants, list) or not grants or any(not isinstance(value, str) for value in grants):
            raise ValueError("HR policy role grants are invalid.")
        for grant in grants:
            identifier(grant, "HR policy role grant")
        if not isinstance(item["answer"], str) or not 1 <= len(item["answer"]) <= 1500:
            raise ValueError("HR policy answer must contain 1 to 1500 characters.")
        if not isinstance(item["checklist"], str) or not 1 <= len(item["checklist"]) <= 1000:
            raise ValueError("HR policy checklist must contain 1 to 1000 characters.")
    topic_matches = [item for item in policies if item["topic"] == topic]
    if not topic_matches:
        raise ValueError("No approved policy was supplied for the requested topic.")
    eligible = []
    for item in topic_matches:
        roles = item["allowed_roles"]
        if not isinstance(roles, list) or not all(isinstance(value, str) for value in roles):
            raise ValueError("HR policy role grants are invalid.")
        if role in roles:
            approved = iso_date(item["approved_as_of"], "Policy approval date")
            if date.fromisoformat(approved) <= date.fromisoformat(context.as_of):
                eligible.append((approved, item))
    if not eligible:
        raise ValueError("Access denied for the requested HR policy.")
    eligible.sort(key=lambda value: value[0], reverse=True)
    if len(eligible) > 1 and eligible[0][0] == eligible[1][0]:
        raise ValueError("Multiple equally current HR policies need owner selection.")
    policy = eligible[0][1]
    policy_id = identifier(policy["policy_id"], "Policy ID")
    owner = identifier(policy["owner_id"], "HR owner code")
    if date.fromisoformat(iso_date(policy["approved_as_of"], "Policy approval date")) > date.fromisoformat(context.as_of):
        raise ValueError("Policy approval date cannot be later than the source as-of date.")
    safe_text(request["question"], "Employee question", maximum=500)
    answer = safe_text(policy["answer"], "Policy answer", maximum=1500)
    checklist_text = text(policy["checklist"], "Policy checklist", maximum=1000)
    checklist = [safe_text(item.strip(), "Checklist item", maximum=200) for item in checklist_text.split(";") if item.strip()]
    if not checklist or len(checklist) > 20:
        raise ValueError("Policy checklist must have 1 to 20 items.")
    result = {
        "request_id": request_id,
        "employee_reference_hash": hashlib.sha256(employee_ref.encode()).hexdigest()[:12],
        "requested_role": role,
        "topic": topic,
        "answer": f"{answer} [evidence:{policy_id}]",
        "checklist": checklist,
        "policy_id": policy_id,
        "owner_id": owner,
        "employment_decision": "NONE",
        "personnel_record_loaded": False,
    }
    summary = {
        "title": "Role-scoped onboarding guidance",
        "metrics": [{"label": "Policy", "value": policy_id}, {"label": "Checklist items", "value": len(checklist)}],
        "findings": [f"Request {request_id} matched policy {policy_id} for role {role}; identity and policy authority remain unverified.", f"HR owner {owner} must confirm the individual start-date details before an answer is used."],
    }
    return receipt("OnboardPath", context, result, evidence_ids=[request_id, policy_id], summary=summary,
                   next_action="An authenticated HR reviewer must confirm employee access, current policy, start-date details, and the checklist before answering a person.")
