"""Bounded, in-memory organization-input reviews for the local workbench.

The import path intentionally does not certify source ownership or a complete
enterprise job.  It never substitutes checked-in fixtures for supplied data.
"""

from __future__ import annotations

from typing import Any

from .common import ImportContext, validate_bundle
from .finance import review_backtest, review_chain, review_ledger, review_market
from .operations import review_handoff, review_onboard, review_pipeline, review_reply
from .security_site import review_search, review_sentinel


REVIEWS = {
    "ledgerbridge": review_ledger,
    "marketbrief": review_market,
    "chainwatch": review_chain,
    "backtestguard": review_backtest,
    "replycraft": review_reply,
    "handoffhub": review_handoff,
    "sentineldesk": review_sentinel,
    "searchlift": review_search,
    "pipelinerelay": review_pipeline,
    "onboardpath": review_onboard,
}


def run(slug: str, bundle: Any) -> dict[str, object]:
    if slug not in REVIEWS:
        raise ValueError("Unknown workflow.")
    context = validate_bundle(bundle)
    return REVIEWS[slug](context)
