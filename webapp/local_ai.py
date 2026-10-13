"""Optional loopback-only, evidence-cited summaries for local workbench imports."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable

from suite_core import (
    GroundedOutputValidator,
    LocalOpenAIClient,
    ModelUnavailable,
    PromptSentinel,
    UnsafeModelOutput,
    redact,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CITATION = re.compile(r"\[evidence:([A-Za-z0-9_.:-]{1,128})\]")
_DEFAULT_ROUTE = "http://127.0.0.1:52652/v1"
_SYSTEM = """You are a local review assistant. Use only the minimized processor findings provided. Return a short draft for a human reviewer: summarize the bounded result and identify one useful check. Do not claim source ownership, permission, freshness, completeness, enterprise verification, or authority. Do not invent facts or actions. Cite every factual sentence with an exact supplied ID in the form [evidence:ID]. If the supplied findings do not support a useful answer, say so and cite the relevant supplied ID. The answer remains an unverified candidate for human review."""


def _ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        return ()
    ids = tuple(item for item in value if isinstance(item, str) and _ID.fullmatch(item))
    return ids if len(ids) == len(value) and len(set(ids)) == len(ids) else ()


def _prompt(receipt: dict[str, object], evidence_ids: tuple[str, ...]) -> str:
    summary = receipt.get("review_summary")
    if not isinstance(summary, dict):
        raise ValueError("No bounded review summary is available.")
    title = summary.get("title")
    findings = summary.get("findings")
    if not isinstance(title, str) or not isinstance(findings, list):
        raise ValueError("No bounded review summary is available.")
    sentinel = PromptSentinel()
    clean_title = str(redact(title))[:200]
    sentinel.check(clean_title)
    clean_findings = []
    for finding in findings[:20]:
        if not isinstance(finding, str):
            continue
        clean = str(redact(finding))[:800]
        sentinel.check(clean)
        clean_findings.append(clean)
    if not clean_findings:
        raise ValueError("The processor produced no citeable findings.")
    packet = {
        "workflow": str(receipt.get("project", "")),
        "source_status": str(receipt.get("source_status", "UNVERIFIED")),
        "review_title": clean_title,
        "findings": clean_findings,
        "evidence_ids": list(evidence_ids),
    }
    return json.dumps(packet, ensure_ascii=False, separators=(",", ":"))


def apply_local_ai(
    receipt: dict[str, object],
    *,
    requested: bool,
    client_factory: Callable[..., LocalOpenAIClient] = LocalOpenAIClient,
) -> dict[str, object]:
    """Add a citation-checked local candidate; never falls back to generated text."""
    result = dict(receipt)
    result.update({
        "local_processing_status": "PARTIAL",
        "local_processing_reason": "The deterministic review is ready; optional local model drafting was not requested.",
        "human_review_status": "PENDING",
        "local_ai_output": None,
        "local_ai_evidence_ids": [],
        "local_ai_model": None,
        "ai_status": "NOT RUN / OPTIONAL LOCAL MODEL NOT REQUESTED",
        "ai_invoked": False,
    })
    if not requested:
        return result

    result["local_processing_status"] = "BLOCKED"
    result["local_processing_reason"] = "No local model answer was accepted; the deterministic review remains available."
    result["ai_status"] = "BLOCKED / LOCAL MODEL NOT AVAILABLE"
    evidence_ids = _ids(receipt.get("evidence_ids"))
    if not evidence_ids:
        result["local_processing_reason"] = "No valid evidence IDs were available for a grounded local answer."
        result["ai_status"] = "BLOCKED / NO CITEABLE EVIDENCE"
        return result

    try:
        prompt = _prompt(receipt, evidence_ids)
        route = os.environ.get("SUITE_AI_LOCAL_BASE_URL", _DEFAULT_ROUTE)
        client = client_factory(route, timeout=30, max_tokens=128, max_prompt_chars=50_000)
        status = client.probe(timeout=3)
    except (ModelUnavailable, ValueError):
        result["ai_status"] = "BLOCKED / LOCAL ROUTE OR PROMPT REJECTED"
        result["local_processing_reason"] = "The configured route was not admitted as loopback-only or the minimized findings were not safe to send; the deterministic review remains available."
        return result
    if not status.available:
        reason = status.reason or "no local model is advertised"
        result["local_processing_reason"] = f"The loopback model is unavailable ({reason}); the deterministic review remains available."
        return result

    selected_model = os.environ.get("SUITE_AI_LOCAL_MODEL", "").strip()
    if selected_model:
        if selected_model not in status.models:
            result["ai_status"] = "BLOCKED / PINNED LOCAL MODEL NOT AVAILABLE"
            result["local_processing_reason"] = "The selected local model is not advertised by the loopback model server."
            return result
    elif len(status.models) == 1:
        selected_model = status.models[0]
    else:
        result["ai_status"] = "BLOCKED / PIN A LOCAL MODEL"
        result["local_processing_reason"] = "More than one local model is available. Set SUITE_AI_LOCAL_MODEL to pin the intended model."
        return result

    try:
        model_result = client.complete(
            prompt,
            system=_SYSTEM,
            model=selected_model,
            max_tokens=128,
        )
    except (ModelUnavailable, ValueError):
        result["local_processing_reason"] = "The loopback model could not return a usable draft; the deterministic review remains available."
        return result
    result["ai_invoked"] = True
    text = str(redact(model_result.text))
    citations = tuple(_CITATION.findall(text))
    try:
        grounded = GroundedOutputValidator().validate(
            text,
            cited_evidence=citations,
            allowed_evidence=evidence_ids,
        )
    except UnsafeModelOutput:
        result["ai_status"] = "BLOCKED / LOCAL MODEL OUTPUT REJECTED"
        result["local_processing_reason"] = "The local model draft failed the exact evidence-ID check; the deterministic review remains available."
        return result

    result.update({
        "local_processing_status": "COMPLETE",
        "local_processing_reason": "A loopback model returned a draft that passed the exact evidence-ID check; source and workflow status remain unverified.",
        "local_ai_output": grounded.text,
        "local_ai_evidence_ids": list(grounded.evidence_ids),
        "local_ai_model": selected_model,
        "ai_status": "LOCAL MODEL CANDIDATE / CITATION CHECK PASSED",
    })
    return result
