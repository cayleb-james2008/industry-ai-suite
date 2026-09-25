"""Source-tree CLI for a safe local core demo, verification, and contract display."""

import argparse
import json
import secrets
import tempfile
import time
from pathlib import Path
from typing import Sequence

from . import (
    AccessPolicy, ApprovalAuthority, AuditLog, Authenticator, FixtureAdapter,
    FixtureSchema, GroundedOutputValidator, HMACTokenCodec, LocalOpenAIClient,
    NonAIFallback, Principal, PromptSentinel, SecurityCore, ai_configuration_status,
)

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA = FixtureSchema({"case_id": str, "summary": str, "evidence_id": str, "email": str})


def _run_demo() -> dict[str, object]:
    fixture = FixtureAdapter(_ROOT / "suite_core" / "fixtures", "tenant-alpha").load("demo.json", _SCHEMA)
    key = secrets.token_bytes(32)
    auth = Authenticator(HMACTokenCodec(key))
    user = Principal("tenant-alpha", "demo-user", "analyst")
    with tempfile.TemporaryDirectory(prefix="suite-core-") as temp_dir:
        audit = AuditLog(Path(temp_dir) / "audit.jsonl")
        policy = AccessPolicy(
            {"tenant-alpha": {"analyst": {"demo-policy-001"}, "approver": {"demo-policy-001"}}},
            {"analyst": {"read", "draft"}, "approver": {"read", "approve"}},
        )
        core = SecurityCore(auth, policy, audit)
        token = auth.issue(user, expires_at=int(time.time()) + 60)
        core.authorize(token, tenant_id=user.tenant_id, action="draft", evidence_ids=("demo-policy-001",))
        for row in fixture.rows:
            PromptSentinel().check(str(row["summary"]))
        result = GroundedOutputValidator().validate(
            "Manual review is needed [evidence:demo-policy-001].",
            cited_evidence=("demo-policy-001",), allowed_evidence=("demo-policy-001",),
        )
        model_status = LocalOpenAIClient().probe()
        fallback = NonAIFallback().result(
            reason="no model invocation is part of the deterministic core demo",
            evidence_ids=result.evidence_ids,
        )
        output = {
            "result": "PASS: safe core demo",
            "ai_invoked": False,
            "demo_mode": fallback.status,
            "model_route_probe": {
                "available": model_status.available, "route": model_status.route,
                "models": model_status.models, "reason": model_status.reason,
                "invoked": False,
            },
            "fixture": {"rows": len(fixture.rows), "provenance": fixture.provenance},
            "grounded_handoff": {"text": result.text, "evidence_ids": result.evidence_ids},
            "audit_receipts": audit.records(),
        }
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m suite_core",
        description="Safe source-tree demo and checks for the shared Industry AI Suite core.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="run a no-hidden-state, NON-AI safe fixture demo")
    commands.add_parser("check", help="run the same core safety smoke checks and local model probe")
    commands.add_parser("contract", help="print the app integration contract")
    commands.add_parser("doctor", help="report AI route readiness without exposing credentials")
    args = parser.parse_args(argv)
    if args.command == "contract":
        print((_ROOT / "CONTRACT.md").read_text(encoding="utf-8"), end="")
        return 0
    if args.command == "doctor":
        status = ai_configuration_status()
        print(json.dumps({"ai": status, "non_ai_workflow": "available"}, indent=2, sort_keys=True))
        return 0
    result = _run_demo()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
