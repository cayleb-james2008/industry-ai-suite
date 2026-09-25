"""Shared, fail-closed citation validation and provenance for real local completions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection

from suite_core import (
    GroundedOutputValidator,
    LocalOpenAIClient,
    ModelResult,
    ModelUnavailable,
    NonAIFallback,
    OpenAICompatibleClient,
    PromptInjectionError,
    PromptSentinel,
    UnsafeModelOutput,
    redact,
)

_CITATION = re.compile(r"\[evidence:([A-Za-z0-9_.:-]{1,128})\]")
MODEL_TIMEOUT_SECONDS = 150
MODEL_MAX_TOKENS = 256


def build_grounded_prompt(prompt: str, evidence_ids: Collection[str]) -> str:
    """Add an explicit citation allowlist and compact final-answer contract."""
    allowed = tuple(evidence_ids)
    if not prompt.strip() or not allowed or not all(allowed):
        raise ValueError("a prompt and non-empty allowed evidence IDs are required")
    return (
        f"{prompt.rstrip()}\nAllowed evidence IDs: {', '.join(allowed)}. "
        "Final only: one short sentence with exact [evidence:ID]."
    )


def complete_grounded(
    ai_client: object | None,
    prompt: str,
    *,
    system: str,
    evidence_ids: Collection[str],
    protected_canaries: Collection[str] = (),
) -> dict[str, object]:
    """Return a real, cited completion or an explicit deterministic handoff.

    The app result is always app-reported. Provider transport hashes bind the
    request bytes and raw response bytes; response text is redacted before it is
    included in this receipt.
    """
    evidence = tuple(evidence_ids)
    fallback = NonAIFallback().result(reason="no local model client was supplied", evidence_ids=evidence)
    if ai_client is None:
        return {
            "ai_status": fallback.status,
            "ai_availability": "AI: unavailable (UNVERIFIED)",
            "ai_invoked": False,
            "ai_output": None,
            "ai_failure": None,
            "ai_handoff": fallback.text,
            "ai_evidence": None,
        }
    if type(ai_client) not in (LocalOpenAIClient, OpenAICompatibleClient):
        raise TypeError("ai_client must be a suite_core OpenAI-compatible client")

    prompt = str(redact(build_grounded_prompt(prompt, evidence)))
    system = str(redact(f"{system.rstrip()} Final only, no reasoning."))
    completion: ModelResult | None = None
    proof: dict[str, object] | None = None
    invoked = False
    try:
        PromptSentinel().check(prompt, protected_canaries=protected_canaries)
        if type(ai_client) is OpenAICompatibleClient:
            completion = ai_client.complete(
                prompt, system=system, timeout=MODEL_TIMEOUT_SECONDS, max_tokens=MODEL_MAX_TOKENS,
                trace_context={
                    "task": "produce a cited response from the supplied evidence",
                    "evidence_ids": list(evidence),
                    "human_handoff": "human review required; no automatic side effect",
                },
            )
        else:
            completion = ai_client.complete(
                prompt, system=system, timeout=MODEL_TIMEOUT_SECONDS, max_tokens=MODEL_MAX_TOKENS,
            )
        invoked = type(completion) is ModelResult
        if not invoked:
            raise UnsafeModelOutput("local model result refused")

        response_text = str(redact(completion.text))
        citations = tuple(sorted(set(_CITATION.findall(response_text))))
        receipt_response = response_text
        for canary in protected_canaries:
            if canary:
                receipt_response = receipt_response.replace(canary, "[REDACTED]")
        request = redact({"system": system, "prompt": prompt})
        request_bytes = json.dumps(
            {
                "model": completion.model,
                "messages": [
                    {"role": "system", "content": request["system"]},
                    {"role": "user", "content": request["prompt"]},
                ],
                "temperature": 0,
                "max_tokens": MODEL_MAX_TOKENS,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        proof = {
            "trace_provenance": "app-reported",
            "route": completion.route,
            "model": completion.model,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "response_sha256": hashlib.sha256(receipt_response.encode("utf-8")).hexdigest(),
            "response": receipt_response,
            "evidence_ids": list(citations),
            "grounded": False,
        }
        if completion.provider_id is not None:
            proof.update({
                "provider_id": completion.provider_id,
                "provider_host": completion.provider_host,
                "created": completion.created,
                "usage": redact(completion.usage),
                "provider_request_sha256": completion.request_sha256,
                "provider_response_sha256": completion.response_sha256,
            })
        if (completion.status not in {"AI / LOCAL", "AI / PROVIDER"}
                or not completion.route or not completion.model):
            raise UnsafeModelOutput("provider completion identity refused")
        grounded = GroundedOutputValidator().validate(
            response_text,
            cited_evidence=citations,
            allowed_evidence=evidence,
            protected_canaries=protected_canaries,
        )
        proof.update(
            response=grounded.text,
            response_sha256=hashlib.sha256(grounded.text.encode("utf-8")).hexdigest(),
            evidence_ids=list(grounded.evidence_ids),
            grounded=True,
        )
        return {
            "ai_status": completion.status,
            "ai_availability": "configured; provider completion returned",
            "ai_invoked": True,
            "ai_output": grounded.text,
            "ai_failure": None,
            "ai_handoff": None,
            "ai_evidence": proof,
            "ai_evidence_provenance": "app-reported",
        }
    except (ModelUnavailable, PromptInjectionError, UnsafeModelOutput, ValueError) as exc:
        reason = f"local completion unavailable or rejected ({type(exc).__name__})"
        fallback = NonAIFallback().result(reason=reason, evidence_ids=evidence)
        return {
            "ai_status": fallback.status,
            "ai_availability": "AI: unavailable (UNVERIFIED)",
            "ai_invoked": invoked,
            "ai_output": None,
            "ai_failure": reason,
            "ai_handoff": str(redact(
                "No validated local AI answer is available. Do not use unvalidated model text; "
                f"review approved evidence manually: {', '.join(evidence) if evidence else 'none supplied'}."
            )),
            "ai_evidence": proof,
            "ai_evidence_provenance": "app-reported" if proof is not None else None,
        }
