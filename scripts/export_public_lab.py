"""Publishable, bounded replay of ten *recorded* workbench journeys.

This does not run a source request or claim a current workflow. The caller
supplies fresh run_all.py receipts and chooses an output directory.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from webapp.runner import SLUGS, run  # noqa: E402

STATIC = ROOT / "webapp" / "static"


def _result(slug: str, value: dict[str, object]) -> dict[str, object] | None:
    result = value.get("task_result") or value.get("result")
    if not isinstance(result, dict):
        return None
    if slug == "sentineldesk":
        return {key: result.get(key) for key in ("catalog_record_count", "product_group_count", "priority_method", "human_review_summary")} | {
            "review_queue": (result.get("review_queue") or [])[:20]
        }
    if slug == "handoffhub":
        return {key: result.get(key) for key in ("answer", "citations", "document_id", "limitation", "status")}
    if slug == "onboardpath":
        selected = result.get("selected_document")
        return {
            "status": result.get("status"), "selected_document": selected,
            "employee_records_loaded": result.get("employee_records_loaded"),
            "limitation": result.get("limitation"),
        }
    return result


def _source_fields(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    keys = ("request_url", "source_url", "source_id", "evidence_id", "as_of", "retrieved_at_utc", "terms_url", "response_sha256")
    return {key: value[key] for key in keys if key in value and isinstance(value[key], (str, int))}


def _receipt(
    slug: str, source: dict[str, object], exported_at: str,
    ai_proof: dict[str, object] | None = None,
) -> dict[str, object]:
    if source.get("app_slug") != slug:
        raise ValueError(f"Receipt identity mismatch: {slug}")
    evidence = source.get("evidence")
    public_evidence = [_source_fields(x) for x in evidence if isinstance(x, dict)] if isinstance(evidence, list) else []
    if slug in {"onboardpath", "handoffhub", "replycraft"}:
        public_evidence.sort(key=lambda item: 0 if str(item.get("evidence_id", "")).startswith("opm-text-") else 1)
    public = {
        "project": source.get("project"), "app_slug": slug,
        "status": source.get("status"), "source_status": source.get("source_status"),
        "workflow_status": source.get("workflow_status"),
        "policy_text_status": source.get("policy_text_status"),
        "task_result": _result(slug, source),
        "uncertainty": source.get("uncertainty"), "ai_status": source.get("ai_status"),
        "handoff": source.get("handoff"), "source_hash": source.get("source_hash"),
        "source_metadata": _source_fields(source.get("source_metadata")),
        "source": _source_fields(source.get("source")),
        "request_url": source.get("request_url") if isinstance(source.get("request_url"), str) else None,
        "evidence": public_evidence,
        "recorded_at_utc": exported_at,
        "preview_limit": "Dated public-source snapshot. Re-run the local workbench for fresh data; no private enterprise workflow or AI verification is implied.",
    }
    if ai_proof is not None:
        app_proof = source.get("ai_evidence")
        if (not isinstance(app_proof, dict) or app_proof.get("grounded") is not True
                or app_proof.get("provider_id") != ai_proof.get("provider_id")
                or app_proof.get("provider_request_sha256") != ai_proof.get("request_sha256")
                or app_proof.get("provider_response_sha256") != ai_proof.get("response_sha256")
                or (source.get("ai_output") or app_proof.get("response")) != ai_proof.get("cited_output")):
            raise ValueError(f"AI proof does not match the app receipt: {slug}")
        public.update({
            "ai_status": "WITNESSED LOCAL MODEL / CITED OUTPUT",
            "ai_output": ai_proof["cited_output"],
            "ai_proof": {
                "model": ai_proof["model"],
                "provider_id": ai_proof["provider_id"],
                "evidence_ids": ai_proof["evidence_ids"],
                "review_note": ai_proof["review_note"],
                "proof_url": "https://github.com/cayleb-james2008/industry-ai-suite/tree/main/evidence/ai-witness-20260926",
            },
        })
    return public


def _chain_example(exported_at: str) -> dict[str, object]:
    rows = [
        {"event_id": "EXAMPLE-1", "chain": "ethereum", "address": "0x" + "1" * 40,
         "rate_units_per_hour": 8, "baseline_units_per_hour": 2, "sample_hours": 12, "owner": "example-only"},
        {"event_id": "EXAMPLE-2", "chain": "base", "address": "0x" + "2" * 40,
         "rate_units_per_hour": 1, "baseline_units_per_hour": 2, "sample_hours": 24, "owner": "example-only"},
    ]
    value = run("chainwatch", {"mode": "user", "authorized": True, "rows": rows})
    value.update({
        "app_slug": "chainwatch", "source_status": "EXAMPLE INPUT / NO LIVE CHAIN",
        "workflow_status": "LOCAL CALCULATION EXAMPLE ONLY",
        "uncertainty": "These two observations and addresses are invented to demonstrate the calculation. They are not chain records, ownership evidence, company exposure, or a live API result.",
        "recorded_at_utc": exported_at,
        "preview_limit": "Synthetic calculation example; the hosted Mempool API remains unadmitted. The local workbench accepts authorized user-supplied observations.",
    })
    return value


def export(receipts_dir: Path, output_dir: Path, ai_proof_path: Path | None = None) -> None:
    if not receipts_dir.is_dir():
        raise ValueError("Receipt directory does not exist.")
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "receipts"
    target.mkdir(exist_ok=True)
    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    proofs = json.loads(ai_proof_path.read_text(encoding="utf-8")) if ai_proof_path else {}
    if not isinstance(proofs, dict) or not set(proofs).issubset(SLUGS):
        raise ValueError("AI proof manifest must map known workflow slugs.")
    for slug in SLUGS:
        if slug == "chainwatch":
            public = _chain_example(exported_at)
        else:
            path = receipts_dir / f"{slug}.json"
            source = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(source, dict):
                raise ValueError(f"Invalid receipt: {slug}")
            public = _receipt(slug, source, exported_at, proofs.get(slug))
        (target / f"{slug}.json").write_text(json.dumps(public, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    html = html.replace('<html lang="en">', '<html lang="en" data-mode="recorded">')
    html = html.replace('  <meta name="workbench-token" content="__WORKBENCH_TOKEN__">\n', '')
    html = html.replace('href="/styles.css"', 'href="styles.css"').replace('href="/dark.css', 'href="dark.css').replace('src="/app.js', 'src="app.js')
    html = html.replace('Industry AI Suite — workbench', 'Industry AI Suite — recorded journeys')
    html = html.replace('WORKBENCH / 01', 'RECORDED JOURNEYS / 01')
    html = html.replace('LOCAL · READ ONLY', 'RECORDED · READ ONLY')
    html = html.replace('RECORDED · READ ONLY</div>', 'RECORDED · READ ONLY <a class="return-link" href="../index.html">Portfolio ↗</a></div>')
    html = html.replace('Run a cited public source or bring your own permitted, de-identified input. Inspect the result, then make the human decision.', 'Explore ten dated product results. Each one shows its source, its actual output, and the decision left with a person.')
    html = html.replace('No account, private feed, message, trade, or publication is connected. Inputs stay in this local process and are not saved.', 'Recorded public results only. ChainWatch uses a clearly invented example. For fresh data and permitted, de-identified input, run the local workbench from the public repository.')
    html = html.replace('Fresh public requests may take a few seconds. Nothing is sent to a customer or account.', 'These files are dated snapshots. Opening them makes no new source request or external change.')
    html = html.replace('Turn on JavaScript to use the local workbench. The Python command-line workflows remain available.', 'Turn on JavaScript to explore the recorded results.')
    (output_dir / "index.html").write_text(html, encoding="utf-8")
    shutil.copy2(STATIC / "styles.css", output_dir / "styles.css")
    shutil.copy2(STATIC / "dark.css", output_dir / "dark.css")
    shutil.copy2(STATIC / "app.js", output_dir / "app.js")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--ai-proof-manifest", type=Path)
    args = parser.parse_args()
    export(args.receipts_dir, args.out_dir, args.ai_proof_manifest)


if __name__ == "__main__":
    main()
