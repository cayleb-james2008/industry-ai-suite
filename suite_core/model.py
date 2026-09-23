"""OpenAI-compatible localhost-only model client and honest deterministic fallback."""

import ipaddress
import json
import math
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic

from .privacy import redact

_DEFAULT_TIMEOUT = 2.0
_MAX_TIMEOUT = 180.0
_DEFAULT_MAX_TOKENS = 96
_MAX_TOKENS = 256
_DEFAULT_MAX_PROMPT_CHARS = 12_000
_MAX_PROMPT_CHARS = 50_000
_PROBE_TIMEOUT = 2.0


def _validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timeout must be a finite number greater than 0 and at most 180 seconds")
    try:
        seconds = float(value)
    except OverflowError as exc:
        raise ValueError("timeout must be a finite number greater than 0 and at most 180 seconds") from exc
    if not math.isfinite(seconds) or not 0 < seconds <= _MAX_TIMEOUT:
        raise ValueError("timeout must be a finite number greater than 0 and at most 180 seconds")
    return seconds


def _validate_max_tokens(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_TOKENS:
        raise ValueError("max_tokens must be an integer from 1 through 256")
    return value


def _validate_prompt_limit(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_PROMPT_CHARS:
        raise ValueError("max_prompt_chars must be an integer from 1 through 50000")
    return value


class ModelUnavailable(RuntimeError):
    """No verified local OpenAI-compatible endpoint is available."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class ModelStatus:
    available: bool
    route: str
    models: tuple[str, ...] = ()
    reason: str | None = None


@dataclass(frozen=True)
class ModelResult:
    status: str
    route: str | None
    model: str | None
    text: str

    def as_dict(self) -> dict[str, object]:
        return {"status": self.status, "route": self.route, "model": self.model,
                "text": redact(self.text)}


class LocalOpenAIClient:
    """Loopback-only OpenAI-compatible client with bounded time, output, and input."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:52652/v1",
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        max_prompt_chars: int = _DEFAULT_MAX_PROMPT_CHARS,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("model host must be a literal loopback IP") from exc
        if (parsed.scheme != "http" or not address.is_loopback or parsed.port is None
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("model route must be plain HTTP on a literal loopback address")
        self.timeout = _validate_timeout(timeout)
        self.max_tokens = _validate_max_tokens(max_tokens)
        self.max_prompt_chars = _validate_prompt_limit(max_prompt_chars)
        self.base_url = base_url.rstrip("/")
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler(),
        )

    def probe(self, *, timeout: float | None = None) -> ModelStatus:
        route = self.base_url
        request_timeout = self.timeout if timeout is None else _validate_timeout(timeout)
        request = urllib.request.Request(f"{route}/models", headers={"Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=request_timeout) as response:
                body = json.loads(response.read(1_000_001))
            if not isinstance(body, Mapping) or not isinstance(body.get("data"), list):
                return ModelStatus(False, route, reason="unexpected /models response")
            models = tuple(
                item["id"] for item in body["data"]
                if isinstance(item, Mapping) and isinstance(item.get("id"), str) and item["id"]
            )
            if not models:
                return ModelStatus(False, route, reason="no local models advertised")
            return ModelStatus(True, route, models)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                return ModelStatus(False, route, reason="redirect refused")
            return ModelStatus(False, route, reason=f"HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            reason = "connection refused" if isinstance(getattr(exc, "reason", None), ConnectionRefusedError) else type(exc).__name__
            return ModelStatus(False, route, reason=reason)

    def complete(
        self,
        prompt: str,
        *,
        system: str,
        model: str | None = None,
        timeout: float | None = None,
        max_tokens: int | None = None,
    ) -> ModelResult:
        request_timeout = self.timeout if timeout is None else _validate_timeout(timeout)
        output_tokens = self.max_tokens if max_tokens is None else _validate_max_tokens(max_tokens)
        if not isinstance(prompt, str) or not isinstance(system, str):
            raise ValueError("prompt and system must be strings")
        if len(prompt) > self.max_prompt_chars or len(system) > self.max_prompt_chars:
            raise ValueError(f"prompt and system text must each be at most {self.max_prompt_chars} characters")

        deadline = monotonic() + request_timeout
        status = self.probe(timeout=min(request_timeout, _PROBE_TIMEOUT))
        if not status.available:
            raise ModelUnavailable(f"localhost model route unavailable: {status.reason}")
        selected = model or status.models[0]
        if selected not in status.models:
            raise ModelUnavailable("requested model is not advertised by the local route")
        payload = json.dumps({
            "model": selected,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": output_tokens,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST",
        )
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ModelUnavailable("local model request deadline expired before completion")
        try:
            with self._opener.open(request, timeout=remaining) as response:
                result = json.loads(response.read(2_000_001))
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ModelUnavailable("local model request redirected; redirects are refused") from None
            raise ModelUnavailable("local model request failed") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ModelUnavailable("local model request failed") from exc
        try:
            text = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelUnavailable("local model returned an unexpected response") from exc
        if not isinstance(text, str):
            raise ModelUnavailable("local model returned an unexpected response")
        return ModelResult(status="AI / LOCAL", route=self.base_url, model=selected, text=str(redact(text)))


class NonAIFallback:
    """A transparent manual handoff; never generates or labels text as AI."""

    def result(self, *, reason: str, evidence_ids: tuple[str, ...] = ()) -> ModelResult:
        return ModelResult(
            status="NON-AI / DETERMINISTIC FALLBACK", route=None, model=None,
            text=str(redact(
                f"Local AI was not invoked ({reason}). Review approved evidence manually: "
                f"{', '.join(evidence_ids) if evidence_ids else 'none supplied'}."
            )),
        )
