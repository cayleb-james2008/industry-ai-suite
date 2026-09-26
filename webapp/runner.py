"""Small input boundary between the workbench and the existing live workflows."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from apps.backtestguard.flow import run_live as backtestguard
from apps.chainwatch.flow import detect_anomalies
from apps.handoffhub.flow import run_live as handoffhub
from apps.ledgerbridge.flow import reconcile, run_live as ledgerbridge
from apps.marketbrief.flow import run_live as marketbrief
from apps.onboardpath.flow import run_live as onboardpath
from apps.pipelinerelay.flow import run_live as pipelinerelay
from apps.replycraft.flow import run_live as replycraft
from apps.searchlift.flow import run_live as searchlift
from apps.sentineldesk.flow import run_live as sentineldesk

SLUGS = (
    "ledgerbridge", "marketbrief", "chainwatch", "backtestguard",
    "replycraft", "handoffhub", "sentineldesk", "searchlift",
    "pipelinerelay", "onboardpath",
)


def _user_rows(value: Any, *, limit: int = 200) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(f"Provide between 1 and {limit} observation rows.")
    if any(not isinstance(row, dict) for row in value):
        raise ValueError("Every observation must be an object.")
    return tuple(value)


def _user_receipt(slug: str, rows: tuple[dict[str, object], ...], result: dict[str, object]) -> dict[str, object]:
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "project": "LedgerBridge" if slug == "ledgerbridge" else "ChainWatch",
        "status": "USER_SUPPLIED_REVIEW",
        "source_status": "USER_SUPPLIED / OWNERSHIP UNVERIFIED",
        "workflow_status": "LOCAL REVIEW ONLY",
        "task_result": result,
        "evidence_ids": [str(row["row_id" if slug == "ledgerbridge" else "event_id"]) for row in rows],
        "input_sha256": digest,
        "uncertainty": "Input ownership, completeness, and accuracy are asserted by the person supplying the rows and have not been independently verified.",
        "human_handoff": {"owner": "local reviewer", "next_action": "Check source records and each exception before any external action."},
        "ai_status": "NON-AI / DETERMINISTIC REVIEW",
        "ai_invoked": False,
        "side_effect_count": 0,
        "integration_adapter": "in-memory user input; no file, account, or network write",
    }


def run(slug: str, payload: dict[str, Any]) -> dict[str, object]:
    """Run one bounded journey; user data remains in memory for this request only."""
    if slug not in SLUGS:
        raise ValueError("Unknown workflow.")
    if not isinstance(payload, dict):
        raise ValueError("Request must be a JSON object.")
    mode = payload.get("mode", "public")
    if mode not in {"public", "user"}:
        raise ValueError("Choose a supported input mode.")

    if slug == "ledgerbridge":
        if mode == "public":
            return ledgerbridge()
        rows = _user_rows(payload.get("rows"))
        if any(set(row) != {"row_id", "reference", "side", "amount_cents", "owner"} for row in rows):
            raise ValueError("Ledger rows need row_id, reference, side, amount_cents, and owner only.")
        return _user_receipt(slug, rows, reconcile(rows))

    if slug == "chainwatch":
        if mode != "user":
            return {
                "project": "ChainWatch", "status": "UNVERIFIED",
                "source_status": "UNVERIFIED — public chain API not admitted",
                "task_result": None,
                "uncertainty": "Use authorized, user-supplied observations for a local watch-only review. The app does not fetch a chain API.",
                "ai_status": "NOT RUN", "side_effect_count": 0,
            }
        if payload.get("authorized") is not True:
            raise ValueError("Confirm you are authorized to review these observations.")
        rows = _user_rows(payload.get("rows"))
        expected = {"event_id", "chain", "address", "rate_units_per_hour", "baseline_units_per_hour", "sample_hours", "owner"}
        if any(set(row) != expected for row in rows):
            raise ValueError("Each watch row must contain only the seven listed observation fields.")
        threshold = payload.get("threshold", 3)
        if type(threshold) not in {int, float} or not 1 < threshold <= 100:
            raise ValueError("Threshold must be greater than 1 and no more than 100.")
        return _user_receipt(slug, rows, detect_anomalies(rows, threshold=float(threshold)))

    if mode != "public":
        raise ValueError("This workflow uses its cited public source.")
    if slug == "marketbrief":
        return marketbrief()
    if slug == "backtestguard":
        year = payload.get("cutoff_year")
        if year in (None, ""):
            return backtestguard()
        if type(year) is not int or not 1900 <= year <= 2100:
            raise ValueError("Enter a four-digit cutoff year.")
        return backtestguard(cutoff_year=year)
    if slug == "replycraft":
        return replycraft()
    if slug == "handoffhub":
        return handoffhub()
    if slug == "sentineldesk":
        return sentineldesk()
    if slug == "searchlift":
        return searchlift()
    if slug == "pipelinerelay":
        owner = payload.get("owner", "pytest-dev")
        repo = payload.get("repo", "pytest")
        if not isinstance(owner, str) or not isinstance(repo, str):
            raise ValueError("Enter a GitHub owner and repository name.")
        return pipelinerelay(owner=owner, repo=repo)
    if slug == "onboardpath":
        number = payload.get("document_number") or None
        if number is not None and not isinstance(number, str):
            raise ValueError("Enter a Federal Register document number.")
        return onboardpath(document_number=number)
    raise AssertionError("Unreachable workflow route")
