"""Separate verifier for late-revealed, keyed witness logs and app call records."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

if __package__:
    from .witness_protocol import MAX_LOG_BYTES, numeric_usage, provider_metadata, verify_log
else:
    from witness_protocol import MAX_LOG_BYTES, numeric_usage, provider_metadata, verify_log

_MAX_INPUT_BYTES = 20_000_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _read_private(path: Path, limit: int = _MAX_INPUT_BYTES) -> bytes:
    descriptor = os.open(path.expanduser(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError("verifier inputs must be private user-owned regular files")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            value = source.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > limit:
        raise ValueError("verifier input exceeds the size limit")
    return value


def _parse_reveal(raw: bytes) -> tuple[bytes, str]:
    try:
        reveal = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("witness reveal is invalid") from None
    if not isinstance(reveal, Mapping) or reveal.get("event") != "witness-reveal":
        raise ValueError("witness reveal is invalid")
    if reveal.get("key_disclosure") != "session HMAC key; not a provider credential":
        raise ValueError("witness key disclosure label is missing")
    key_hex = reveal.get("hmac_key_hex_not_a_credential")
    head = reveal.get("final_chain_head_sha256")
    if (not isinstance(key_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", key_hex)
            or not isinstance(head, str) or not _SHA256.fullmatch(head)):
        raise ValueError("witness reveal fields are invalid")
    return bytes.fromhex(key_hex), head


def _call_matches(call: object, entries: Sequence[Mapping[str, object]], used: set[int]) -> int | None:
    if not isinstance(call, Mapping) or call.get("trace_provenance") != "app-reported":
        return None
    provider_id = call.get("provider_id")
    model = call.get("model")
    request_hash = call.get("provider_request_sha256")
    response_hash = call.get("provider_response_sha256")
    host = call.get("provider_host")
    created = call.get("created")
    usage = call.get("usage")
    if (not isinstance(provider_id, str) or not provider_id
            or not isinstance(model, str) or not model
            or provider_metadata("provider_id", provider_id) != {"provider_id": provider_id}
            or provider_metadata("model", model) != {"model": model}
            or not isinstance(request_hash, str) or not _SHA256.fullmatch(request_hash)
            or not isinstance(response_hash, str) or not _SHA256.fullmatch(response_hash)
            or not isinstance(host, str) or type(created) is not int
            or not isinstance(usage, Mapping) or numeric_usage(usage) != usage):
        return None
    for index, entry in enumerate(entries):
        if index in used:
            continue
        if (entry.get("method") == "POST" and entry.get("http_status") == 200
                and entry.get("response_complete") is True
                and entry.get("provider_id") == provider_id
                and entry.get("model") == model
                and entry.get("upstream_host") == host
                and entry.get("created") == created and entry.get("usage") == usage
                and entry.get("request_sha256") == request_hash
                and entry.get("response_sha256") == response_hash):
            return index
    return None


def verify_calls(witness_raw: bytes, reveal_raw: bytes, app_calls: object) -> dict[str, object]:
    """Return independent transport verdicts without changing app-owned receipts."""
    if not isinstance(app_calls, list):
        raise ValueError("app calls must be a JSON array of app-reported call records")
    if len(witness_raw) > MAX_LOG_BYTES:
        raise ValueError("witness log exceeds the size limit")
    key, expected_head = _parse_reveal(reveal_raw)
    try:
        entries = verify_log(witness_raw, key, expected_head)
    except ValueError as exc:
        return {
            "witness_integrity": "UNVERIFIED",
            "witness_reason": str(exc),
            "call_results": [
                {"call_index": index, "status": "UNVERIFIED", "reason": "witness chain is not intact"}
                for index, _ in enumerate(app_calls)
            ],
        }

    used: set[int] = set()
    results = []
    for index, call in enumerate(app_calls):
        match = _call_matches(call, entries, used)
        if match is None:
            results.append({
                "call_index": index,
                "status": "UNVERIFIED",
                "reason": "no intact witness entry matches the app-reported ID and exact transport hashes",
            })
            continue
        used.add(match)
        entry = entries[match]
        results.append({
            "call_index": index,
            "status": "VERIFIED",
            "scope": "provider transport exchange only; task quality and app grounding remain app-reported",
            "provider_id": entry["provider_id"],
            "model": entry["model"],
            "provider_host": entry["upstream_host"],
            "at_utc": entry["at_utc"],
            "request_sha256": entry["request_sha256"],
            "response_sha256": entry["response_sha256"],
            "http_status": entry["http_status"],
        })
    return {
        "witness_integrity": "VERIFIED",
        "final_chain_head_sha256": expected_head,
        "call_results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify app-reported calls against a late-revealed HMAC witness chain."
    )
    parser.add_argument("--witness-log", required=True, type=Path)
    parser.add_argument("--reveal", required=True, type=Path,
                        help="proxy stdout reveal JSON; its HMAC key is not a provider credential")
    parser.add_argument("--app-calls", required=True, type=Path,
                        help="private JSON array of app-reported call records")
    args = parser.parse_args(argv)
    try:
        result = verify_calls(
            _read_private(args.witness_log, MAX_LOG_BYTES),
            _read_private(args.reveal),
            json.loads(_read_private(args.app_calls)),
        )
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        result = {
            "witness_integrity": "UNVERIFIED",
            "witness_reason": "a private verifier input could not be read or parsed safely",
            "call_results": [],
        }
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["witness_integrity"] == "VERIFIED" and all(
        call["status"] == "VERIFIED" for call in result["call_results"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
