"""Run all ten source-tree workflows and write one truthful receipt per app."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from suite_core import LocalOpenAIClient

APP_SLUGS = (
    "ledgerbridge",
    "marketbrief",
    "chainwatch",
    "backtestguard",
    "replycraft",
    "handoffhub",
    "sentineldesk",
    "searchlift",
    "pipelinerelay",
    "onboardpath",
)
ROOT = Path(__file__).resolve().parents[1]


def _source_hash(receipt: dict[str, Any]) -> str | None:
    direct = receipt.get("source_hash")
    if isinstance(direct, str):
        return direct
    hashes = receipt.get("source_hashes")
    if not isinstance(hashes, dict) or not hashes:
        return None
    values = list(hashes.values())
    if not all(
        isinstance(value, str) and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
        for value in values
    ):
        return None
    if len(values) == 1:
        return values[0]
    canonical = json.dumps(hashes, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Map the P2/P3/P4 app-specific names onto the suite receipt contract."""
    normalized = dict(receipt)
    normalized["result"] = receipt.get("result", receipt.get("task_result"))
    evidence = receipt.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        evidence = receipt.get("evidence_ids")
    normalized["evidence"] = evidence if isinstance(evidence, list) else []
    normalized["source_hash"] = _source_hash(receipt)
    normalized["handoff"] = receipt.get("handoff", receipt.get("human_handoff"))
    normalized["adapter"] = receipt.get("adapter", receipt.get("integration_adapter"))
    return normalized


def _reported_source_status(receipt: dict[str, Any]) -> str:
    for key in ("source_status", "data_status", "status"):
        value = receipt.get(key)
        if isinstance(value, str):
            for status in ("DATA_UNAVAILABLE", "UNVERIFIED", "VERIFIED_SOURCE", "AVAILABLE"):
                if value == status or value.startswith(f"{status} —"):
                    return status
    return "UNVERIFIED"


def _workflow_reason(receipt: dict[str, Any]) -> str:
    for key in ("reason", "uncertainty", "workflow_status"):
        value = receipt.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list):
            messages = [item.strip() for item in value if isinstance(item, str) and item.strip()]
            if messages:
                return "; ".join(messages)
    missing = receipt.get("missing_sources")
    if isinstance(missing, list):
        sources = [item.strip() for item in missing if isinstance(item, str) and item.strip()]
        if sources:
            return "Missing required real or authorized sources: " + "; ".join(sources)
    return "The complete task and independently verified AI contribution remain unverified."


def _failure_receipt(slug: str, status: str, reason: str) -> dict[str, Any]:
    return {
        "app_slug": slug,
        "status": status,
        "source_status": status,
        "workflow_status": status,
        "workflow_reason": reason,
        "reason": reason,
        "error": reason,
        "result": None,
        "evidence": [],
        "source_hash": None,
        "risk": {"status": "unverified"},
        "handoff": {
            "owner": "suite-maintainer",
            "next_action": "Resolve the named live-source or workflow blocker; no fixture, cache, or substitute was used.",
        },
        "ai_status": "UNVERIFIED",
        "ai_verification_status": "UNVERIFIED",
        "ai_invoked": False,
        "ai_evidence": None,
        "side_effect_count": 0,
        "adapter": None,
    }


def _exception_status(error: Exception) -> str:
    status = getattr(error, "status", None)
    if status in {"DATA_UNAVAILABLE", "UNVERIFIED"}:
        return status
    if isinstance(error, TimeoutError):
        return "DATA_UNAVAILABLE"
    return "UNVERIFIED"


def _run_one(
    slug: str,
    ai_client: LocalOpenAIClient | None = None,
) -> dict[str, Any]:
    module_name = f"apps.{slug}.flow"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name in {f"apps.{slug}", module_name, "apps"}:
            return _failure_receipt(
                slug, "MISSING",
                f"Missing live workflow module: {module_name}; no demo or fixture fallback was attempted.",
            )
        return _failure_receipt(slug, "UNVERIFIED", f"Import failed: {type(exc).__name__}: {exc}")
    except Exception as exc:
        return _failure_receipt(slug, "UNVERIFIED", f"Import failed: {type(exc).__name__}: {exc}")

    try:
        run_live = getattr(module, "run_live", None)
        if not callable(run_live):
            return _failure_receipt(
                slug, "UNVERIFIED",
                f"Live workflow unavailable: {module_name}.run_live is missing or not callable; no demo or fixture fallback was attempted.",
            )
        value = run_live(ai_client=ai_client)
        if not isinstance(value, dict):
            return _failure_receipt(
                slug, "UNVERIFIED",
                f"Live workflow returned {type(value).__name__}, not a JSON object; no fallback was attempted.",
            )
        receipt = _normalize_receipt(value)
        receipt["app_slug"] = slug
        json.dumps(receipt, sort_keys=True)
        receipt.setdefault("ai_status", "UNVERIFIED")
        reported_ai_verification = receipt.get("ai_verification_status")
        if reported_ai_verification is not None:
            receipt["app_reported_ai_verification_status"] = reported_ai_verification
        is_ai_candidate = (
            isinstance(receipt.get("ai_status"), str)
            and receipt["ai_status"].startswith("AI / LOCAL")
        ) or (
            receipt.get("ai_invoked") is True
            or receipt.get("ai_evidence") is not None
        )
        is_fallback = receipt.get("ai_status") == "NON-AI / DETERMINISTIC FALLBACK"
        source_status = _reported_source_status(value)
        app_status = value.get("status")
        workflow_status = "DATA_UNAVAILABLE" if source_status == "DATA_UNAVAILABLE" else "UNVERIFIED"
        receipt["app_reported_status"] = app_status
        receipt["source_status"] = source_status
        receipt["workflow_status"] = workflow_status
        receipt["workflow_reason"] = _workflow_reason(value)
        receipt["status"] = workflow_status
        if is_ai_candidate:
            receipt["ai_verification_status"] = "AI CANDIDATE"
            receipt["ai_verification_basis"] = (
                "App-reported AI fields are a candidate only. No independently authenticated raw-transport "
                "observer exists, so this runner cannot verify model execution."
            )
        elif is_fallback:
            receipt["ai_verification_status"] = "NON-AI / DETERMINISTIC FALLBACK"
            receipt["ai_verification_basis"] = (
                "The app reports a deterministic fallback; this is not evidence of AI execution."
            )
        else:
            receipt["ai_verification_status"] = "UNVERIFIED"
            receipt["ai_verification_basis"] = (
                "No independently authenticated raw-transport observer exists; AI execution "
                "remains unverified."
            )
        return receipt
    except Exception as exc:
        return _failure_receipt(
            slug,
            _exception_status(exc),
            f"Live workflow failed: {type(exc).__name__}: {exc}; no demo or fixture fallback was attempted.",
        )


def _probe_model(ai_url: str | None) -> tuple[LocalOpenAIClient | None, dict[str, Any]]:
    if ai_url is None:
        return None, {"available": False, "reason": "no --ai-url supplied", "route": None, "models": []}
    from apps._ai_receipts import MODEL_MAX_TOKENS, MODEL_TIMEOUT_SECONDS
    from suite_core import LocalOpenAIClient

    try:
        client = LocalOpenAIClient(
            ai_url, timeout=MODEL_TIMEOUT_SECONDS, max_tokens=MODEL_MAX_TOKENS,
        )
    except (TypeError, ValueError) as exc:
        return None, {"available": False, "reason": f"route refused ({type(exc).__name__})", "route": ai_url, "models": []}
    status = client.probe(timeout=2)
    return (client if status.available else None), {
        "available": status.available,
        "reason": status.reason,
        "route": status.route,
        "models": list(status.models),
    }


def run_suite(
    out_dir: Path | None = None,
    ai_url: str | None = None,
) -> tuple[int, Path, list[dict[str, Any]]]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    if out_dir is None:
        destination = Path(tempfile.mkdtemp(prefix="industry-ai-suite-receipts-"))
    else:
        destination = out_dir.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)

    client, route_probe = _probe_model(ai_url)
    receipts = [_run_one(slug, client) for slug in APP_SLUGS]
    for receipt in receipts:
        receipt["model_route_probe"] = route_probe
        target = destination / f"{receipt['app_slug']}.json"
        target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    missing = [str(receipt["app_slug"]) for receipt in receipts if receipt.get("status") == "MISSING"]
    job_status_counts = {
        status: sum(receipt.get("status") == status for receipt in receipts)
        for status in ("UNVERIFIED", "DATA_UNAVAILABLE", "MISSING")
    }
    job_statuses = [
        {"app_slug": receipt["app_slug"], "status": receipt.get("status", "UNVERIFIED")}
        for receipt in receipts
    ]
    candidates = sum(receipt.get("ai_verification_status") == "AI CANDIDATE" for receipt in receipts)
    summary = {
        "suite_status": "INCOMPLETE",
        "job_count": len(receipts),
        "job_status_counts": job_status_counts,
        "job_statuses": job_statuses,
        "ai_candidates_pending_independent_verification": candidates,
    }
    print("Suite status: INCOMPLETE — full workflow completion and independent AI verification are not established.")
    print("Workflow job statuses: " + ", ".join(
        f"{status}={count}" for status, count in job_status_counts.items()
    ))
    if missing:
        print("Missing live workflow modules: " + ", ".join(missing))
    print(f"JSON receipts emitted: {len(receipts)}")
    print(f"AI candidates pending independent verification: {candidates}")
    print(f"Receipt directory: {destination}")
    print("JSON summary: " + json.dumps(summary, sort_keys=True))
    return 1, destination, receipts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all ten live industry AI workflows without fixture fallback.")
    parser.add_argument("--out-dir", type=Path, help="caller-owned directory for exactly ten app receipts")
    parser.add_argument("--ai-url", help="optional literal-loopback OpenAI-compatible route to probe and use")
    args = parser.parse_args(argv)
    try:
        code, _, _ = run_suite(args.out_dir, args.ai_url)
    except ValueError as exc:
        parser.error(str(exc))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
