"""Shared HMAC and chain rules for the proxy and its separate verifier."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"[A-Za-z0-9._:/-]{1,256}\Z")
_PROVIDER_IDS = re.compile(
    r"(?:chatcmpl-|cmpl-|resp_|response_|msg_|completion-)[A-Za-z0-9_-]{1,128}\Z"
)
_CREDENTIAL_SHAPES = re.compile(
    r"(?i)(?:\bsk-|\bghp_|\bgithub_pat_|\bxox|\bAKIA[0-9A-Z]{16}\b|\bbearer\b)"
)
_JWT = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\Z")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,}")
GENESIS_CHAIN_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_LOG_BYTES = 16_000_000


def canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _secret_shaped(value: str) -> bool:
    if _CREDENTIAL_SHAPES.search(value) or _JWT.fullmatch(value):
        return True
    if _PROVIDER_IDS.fullmatch(value):
        return False
    return any(len(run) >= 32 and _entropy(run) >= 3.5 for run in _LONG_TOKEN.findall(value))


def provider_metadata(field: str, value: object) -> dict[str, object]:
    """Keep short ordinary identities; replace suspicious identities with a hash."""
    if field not in {"provider_id", "model"}:
        raise ValueError("unsupported provider metadata field")
    if value is None:
        return {field: None}
    if isinstance(value, str) and _SAFE_ID.fullmatch(value) and not _secret_shaped(value):
        return {field: value}
    raw = value.encode("utf-8") if isinstance(value, str) else json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=lambda _: None,
    ).encode("utf-8")
    return {
        field: None,
        f"{field}_sha256": hashlib.sha256(raw).hexdigest(),
        f"{field}_redacted": True,
    }


def numeric_usage(value: object, *, _depth: int = 0) -> object:
    """Retain only bounded numeric usage fields, never arbitrary provider text."""
    if _depth > 8:
        return None
    if isinstance(value, Mapping):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key):
                continue
            number = numeric_usage(item, _depth=_depth + 1)
            if number is not None:
                cleaned[key] = number
        return cleaned
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return value
    return None


def signed_record(key: bytes, record: Mapping[str, object], previous_line_sha256: str) -> dict[str, object]:
    if not isinstance(key, bytes) or len(key) != 32 or not _SHA256.fullmatch(previous_line_sha256):
        raise ValueError("invalid witness signing state")
    signed = dict(record)
    signed["previous_line_sha256"] = previous_line_sha256
    signed["hmac"] = hmac.new(key, canonical_json(signed), hashlib.sha256).hexdigest()
    return signed


def encoded_line(record: Mapping[str, object]) -> bytes:
    return canonical_json(record) + b"\n"


def line_sha256(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _valid_safe_metadata(record: Mapping[str, object], field: str) -> bool:
    value = record.get(field)
    redacted = record.get(f"{field}_redacted")
    digest = record.get(f"{field}_sha256")
    if value is None:
        return (redacted is None and digest is None) or (
            redacted is True and isinstance(digest, str) and _SHA256.fullmatch(digest) is not None
        )
    return (
        isinstance(value, str)
        and provider_metadata(field, value) == {field: value}
        and redacted is None and digest is None
    )


def _valid_usage(value: object) -> bool:
    if value is None:
        return True
    return isinstance(value, Mapping) and numeric_usage(value) == value


def validate_entry(entry: object) -> dict[str, object]:
    if not isinstance(entry, dict) or entry.get("schema_version") != 1:
        raise ValueError("witness log contains an unsupported line")
    required = {
        "schema_version", "at_utc", "upstream_host", "method", "request_path",
        "request_sha256", "response_sha256", "http_status", "response_complete",
        "provider_id", "model", "created", "usage", "previous_line_sha256", "hmac",
    }
    optional = {
        "provider_id_sha256", "provider_id_redacted", "model_sha256", "model_redacted",
    }
    if not required.issubset(entry) or set(entry) - required - optional:
        raise ValueError("witness line fields are invalid")
    if (not isinstance(entry.get("at_utc"), str) or not entry["at_utc"].endswith("Z")
            or not isinstance(entry.get("upstream_host"), str)
            or not re.fullmatch(r"[a-z0-9.-]{1,253}", entry["upstream_host"])):
        raise ValueError("witness line time or host is invalid")
    route = (entry.get("method"), entry.get("request_path"))
    if not isinstance(entry.get("request_path"), str) or not (
        route[0] == "GET" and route[1].endswith("/models")
        or route[0] == "POST" and route[1].endswith("/chat/completions")
    ):
        raise ValueError("witness line route is invalid")
    if (not isinstance(entry.get("request_sha256"), str) or not _SHA256.fullmatch(entry["request_sha256"])
            or not isinstance(entry.get("response_sha256"), str) or not _SHA256.fullmatch(entry["response_sha256"])
            or type(entry.get("http_status")) is not int or not 100 <= entry["http_status"] <= 599
            or type(entry.get("response_complete")) is not bool
            or (entry.get("created") is not None and type(entry.get("created")) is not int)
            or not _valid_usage(entry.get("usage"))
            or not _valid_safe_metadata(entry, "provider_id")
            or not _valid_safe_metadata(entry, "model")):
        raise ValueError("witness line fields are invalid")
    for field in ("previous_line_sha256", "hmac"):
        if not isinstance(entry.get(field), str) or not _SHA256.fullmatch(entry[field]):
            raise ValueError("witness line integrity fields are invalid")
    return entry


def verify_log(raw: bytes, key: bytes, expected_head: str) -> tuple[dict[str, object], ...]:
    """Verify canonical bytes, each keyed entry, the full chain, and its pinned head."""
    if len(raw) > MAX_LOG_BYTES or not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("witness log or reveal is invalid")
    if not _SHA256.fullmatch(expected_head):
        raise ValueError("revealed chain head is invalid")
    entries: list[dict[str, object]] = []
    previous = GENESIS_CHAIN_SHA256
    lines = raw.splitlines(keepends=True)
    if any(not line.endswith(b"\n") for line in lines):
        raise ValueError("witness log has an incomplete final line")
    for line in lines:
        try:
            parsed = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("witness log contains an invalid line") from None
        entry = validate_entry(parsed)
        if canonical_json(entry) + b"\n" != line or entry["previous_line_sha256"] != previous:
            raise ValueError("witness chain integrity check failed")
        unsigned = {name: value for name, value in entry.items() if name != "hmac"}
        expected_hmac = hmac.new(key, canonical_json(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(entry["hmac"], expected_hmac):
            raise ValueError("witness HMAC verification failed")
        entries.append(entry)
        previous = line_sha256(line)
    if previous != expected_head:
        raise ValueError("witness final chain head does not match the reveal")
    return tuple(entries)
