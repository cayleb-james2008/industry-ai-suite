"""Untrusted-document sentinel and evidence-bound, PII-minimized output validation."""

import re
from collections.abc import Collection
from dataclasses import dataclass

from .privacy import redact
from .security import _valid_id, _valid_ids

_INJECTION = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"(?:reveal|exfiltrate|print|show|dump)\s+(?:the\s+)?(?:secret|system prompt|api key|canary)|"
    r"(?:repeat|reproduce|quote|copy|print|show).{0,80}(?:verbatim|word[- ]for[- ]word|exactly).{0,80}"
    r"(?:system (?:message|prompt|instructions?))|"
    r"(?:repeat|reproduce|quote|copy|print|show).{0,80}(?:system (?:message|prompt|instructions?)).{0,80}"
    r"(?:verbatim|word[- ]for[- ]word|exactly)|"
    r"(?:other|another)\s+tenant|"
    r"(?:retrieve|show|read|export|dump|reveal|fetch).{0,80}\btenant[- ]?[a-z0-9]+\b|"
    r"bypass\s+(?:the\s+)?(?:policy|safety)|override\s+(?:the\s+)?(?:policy|instructions)|"
    r"\bcanary\b",
    re.IGNORECASE,
)
_CITATION = re.compile(r"\[evidence:([A-Za-z0-9_.:-]{1,128})\]")


class PromptInjectionError(ValueError):
    """Untrusted material contains an instruction or protected canary attempt."""


class UnsafeModelOutput(ValueError):
    """Model output is ungrounded, cross-tenant, or contains protected content."""


class PromptSentinel:
    """Reject suspicious source text before including it in any model prompt."""

    def check(self, untrusted_text: str, *, protected_canaries: Collection[str] = ()) -> None:
        if not isinstance(untrusted_text, str) or len(untrusted_text) > 100_000:
            raise PromptInjectionError("untrusted source refused")
        if _INJECTION.search(untrusted_text) or any(
            canary and canary in untrusted_text for canary in protected_canaries
        ):
            raise PromptInjectionError("untrusted source refused")


@dataclass(frozen=True)
class GroundedOutput:
    text: str
    evidence_ids: tuple[str, ...]


class GroundedOutputValidator:
    """Require explicit citations that exactly match the caller's authorized evidence set."""

    def validate(
        self,
        text: str,
        *,
        cited_evidence: Collection[str],
        allowed_evidence: Collection[str],
        protected_canaries: Collection[str] = (),
    ) -> GroundedOutput:
        if not isinstance(text, str) or not text.strip() or len(text) > 20_000:
            raise UnsafeModelOutput("model output refused")
        if not _valid_ids(cited_evidence) or not _valid_ids(allowed_evidence):
            raise UnsafeModelOutput("model output refused")
        cited = set(cited_evidence)
        allowed = set(allowed_evidence)
        inline = set(_CITATION.findall(text))
        if (not cited or len(cited) != len(cited_evidence)
                or not all(_valid_id(item) for item in cited)
                or not cited.issubset(allowed) or inline != cited
                or any(canary and canary in text for canary in protected_canaries)):
            raise UnsafeModelOutput("model output refused")
        return GroundedOutput(text=str(redact(text)), evidence_ids=tuple(sorted(cited)))
