"""Small signed-token codec. Keys are injected at runtime and never logged."""

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping


class TokenError(ValueError):
    """A signed token is malformed, forged, or has invalid claims."""


class HMACTokenCodec:
    """Sign JSON claims with HMAC-SHA256; require a caller-supplied 256-bit key."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise TokenError("HMAC key must contain at least 32 bytes")
        self._key = key

    def sign(self, claims: Mapping[str, object]) -> str:
        if not isinstance(claims, Mapping):
            raise TokenError("claims must be a mapping")
        try:
            payload = json.dumps(
                claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TokenError("claims are not valid JSON") from exc
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        signature = hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        signature_text = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        return f"{encoded}.{signature_text}"

    def verify(self, token: str) -> dict[str, object]:
        if not isinstance(token, str) or len(token) > 8192:
            raise TokenError("invalid signed token")
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise TokenError("invalid signed token")
        parts = token.split(".")
        if len(parts) != 2:
            raise TokenError("invalid signed token")
        encoded, supplied_signature = parts
        expected = base64.urlsafe_b64encode(
            hmac.new(self._key, encoded.encode("ascii", "strict"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, supplied_signature):
            raise TokenError("invalid signed token")
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = base64.b64decode(padded, altchars=b"-_", validate=True)
            claims = json.loads(payload)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenError("invalid signed token") from exc
        if not isinstance(claims, dict):
            raise TokenError("invalid signed token")
        return claims
