"""Shared validation and honest receipt shape for local organization imports."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from suite_core import PromptInjectionError, PromptSentinel, redact
from suite_core.privacy import contains_likely_personal_data


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
_COMMON = {"tenant_id", "source_ref", "as_of", "reviewer", "provenance_kind", "authorized", "data"}
_SENTINEL = PromptSentinel()


@dataclass(frozen=True)
class ImportContext:
    tenant_id: str
    source_ref: str
    as_of: str
    reviewer: str
    provenance_kind: str
    data: dict[str, object]
    input_sha256: str


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly: {', '.join(sorted(fields))}.")
    return value


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_likely_personal_data(value):
        raise ValueError(f"{label} must be a short opaque identifier.")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON number: {value}.")


def strict_json_loads(value: str | bytes) -> object:
    return json.loads(value, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)


def text(value: Any, label: str, *, maximum: int = 1000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must contain 1 to {maximum} characters.")
    try:
        _SENTINEL.check(value)
    except PromptInjectionError as error:
        raise ValueError(f"{label} contains unsafe instruction-like text.") from error
    return value.strip()


def safe_text(value: Any, label: str, *, maximum: int = 1000) -> str:
    return str(redact(text(value, label, maximum=maximum)))


def iso_date(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO date.")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO date.") from error
    if parsed.isoformat() != value:
        raise ValueError(f"{label} must be an ISO date.")
    return value


def iso_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a time with timezone.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be a time with timezone.") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must be a time with timezone.")
    return value


def nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 10**12:
        raise ValueError(f"{label} must be a nonnegative whole number within the supported range.")
    return value


def rows(value: Any, fields: set[str], label: str, *, maximum: int = 200) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} must contain 1 to {maximum} records.")
    return tuple(exact_object(item, fields, f"{label} record") for item in value)


def unique_ids(records: tuple[dict[str, object], ...], field: str, label: str) -> list[str]:
    ids = [identifier(row[field], label) for row in records]
    if len(set(ids)) != len(ids):
        raise ValueError(f"{label} values must be unique.")
    return ids


def validate_bundle(bundle: Any) -> ImportContext:
    value = exact_object(bundle, _COMMON, "Organization bundle")
    tenant_id = identifier(value["tenant_id"], "Organization code")
    source_ref = identifier(value["source_ref"], "Source reference")
    reviewer = identifier(value["reviewer"], "Reviewer code")
    as_of = iso_date(value["as_of"], "Source as-of")
    kind = value["provenance_kind"]
    if kind == "synthetic":
        if value["authorized"] is not False:
            raise ValueError("A synthetic example must not claim organizational authorization.")
    elif kind == "operator_asserted":
        if value["authorized"] is not True:
            raise ValueError("Confirm authorization for real organization input.")
    else:
        raise ValueError("Provenance kind must be synthetic or operator_asserted.")
    data = value["data"]
    if not isinstance(data, dict):
        raise ValueError("Workflow data must be an object.")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise ValueError("Organization bundle contains unsupported values.") from error
    if len(encoded) > 120 * 1024:
        raise ValueError("Organization bundle exceeds the 120 KB processing limit.")
    return ImportContext(tenant_id, source_ref, as_of, reviewer, kind, data, hashlib.sha256(encoded).hexdigest())


def receipt(
    slug: str,
    context: ImportContext,
    result: dict[str, object],
    *,
    evidence_ids: list[str],
    summary: dict[str, object],
    next_action: str,
) -> dict[str, object]:
    if context.provenance_kind == "synthetic":
        source_status = "SYNTHETIC / ENGINEERING ONLY"
        qualifier = "The safe example is invented and proves engineering behavior only."
    else:
        source_status = "USER_SUPPLIED / AUTHORIZATION UNVERIFIED"
        qualifier = "The local operator asserted source ownership and permission; these were not independently confirmed."
    return {
        "project": slug,
        "status": "UNVERIFIED",
        "source_status": source_status,
        "workflow_status": "LOCAL REVIEW ONLY / ENTERPRISE UNVERIFIED",
        "input_mode": "enterprise",
        "task_result": result,
        "review_summary": summary,
        "evidence_ids": evidence_ids,
        "source_metadata": {
            "tenant_id": context.tenant_id,
            "source_ref": context.source_ref,
            "as_of": context.as_of,
            "provenance_kind": context.provenance_kind,
            "authorization_verdict": "UNVERIFIED",
            "input_sha256": context.input_sha256,
        },
        "input_sha256": context.input_sha256,
        "uncertainty": qualifier + " Only the submitted records were evaluated; their completeness, accuracy, and organizational scope remain unverified.",
        "human_handoff": {"owner": context.reviewer, "owner_type": "operator-supplied code, not an authenticated identity", "next_action": next_action},
        "ai_status": "NOT RUN / NO MODEL CLAIM",
        "ai_invoked": False,
        "side_effect_count": 0,
        "integration_adapter": "in-memory bounded local import; no external action or server-side input persistence",
    }
