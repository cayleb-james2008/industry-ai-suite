"""OpenAI-compatible model routes, trace capture, and honest deterministic fallback."""

import hashlib
import ipaddress
import json
import math
import os
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from time import monotonic

from .privacy import redact

_DEFAULT_TIMEOUT = 2.0
_MAX_TIMEOUT = 180.0
_DEFAULT_MAX_TOKENS = 96
_MAX_TOKENS = 256
_DEFAULT_MAX_PROMPT_CHARS = 12_000
_MAX_PROMPT_CHARS = 50_000
_PROBE_TIMEOUT = 2.0
_MAX_RESPONSE_BYTES = 2_000_000
_MAX_SECRET_BYTES = 16_384
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_PRICE_MARKERS = ("price", "pricing", "cost")
_PRICE_UNIT_LABELS = frozenset({
    "usd", "usd/token", "usd per token", "usd/1k tokens", "usd per 1k tokens",
    "usd/1000 tokens", "usd per 1000 tokens",
})
_PRICE_LABELS = {
    "currency": frozenset({"$", "usd"}),
    "unit": _PRICE_UNIT_LABELS,
    "units": _PRICE_UNIT_LABELS,
}


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
    """No safely configured OpenAI-compatible endpoint is available."""


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
    provider_id: str | None = None
    usage: Mapping[str, object] | None = None
    created: int | None = None
    provider_host: str | None = None
    request_sha256: str | None = None
    response_sha256: str | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "status": self.status, "route": self.route, "model": self.model,
            "text": redact(self.text),
        }
        for key in ("provider_id", "usage", "created", "provider_host",
                    "request_sha256", "response_sha256"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value if key == "provider_host" else redact(value)
        return result


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
        self.base_url = _admit_ai_route(
            base_url, None, _LOOPBACK_HOSTS,
            allow_hosted=False, allowed_models=(),
        )[0]
        self.timeout = _validate_timeout(timeout)
        self.max_tokens = _validate_max_tokens(max_tokens)
        self.max_prompt_chars = _validate_prompt_limit(max_prompt_chars)
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
                exc.close()
                return ModelStatus(False, route, reason="redirect refused")
            exc.close()
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
                exc.close()
                raise ModelUnavailable("local model request redirected; redirects are refused") from None
            exc.close()
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


def _private_file_bytes(path: str | Path, *, limit: int = _MAX_SECRET_BYTES) -> bytes:
    file_path = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(file_path, flags)
    except OSError:
        raise ModelUnavailable("configured secret file is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ModelUnavailable("secret file must be a user-owned regular file with private permissions")
        with os.fdopen(descriptor, "rb") as secret_file:
            descriptor = -1
            content = secret_file.read(limit + 1)
    except ModelUnavailable:
        raise
    except OSError:
        raise ModelUnavailable("configured secret file is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > limit:
        raise ModelUnavailable("configured secret file exceeds the size limit")
    return content


def _secret_value(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_SECRET_BYTES:
        raise ModelUnavailable("provider credential is missing or invalid")
    secret = value.strip()
    if "\n" in secret or "\r" in secret:
        raise ModelUnavailable("provider credential is malformed")
    return secret


def _read_secret_file(path: str | Path) -> str:
    try:
        value = _private_file_bytes(path).decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ModelUnavailable("configured secret file is not valid UTF-8") from None
    return _secret_value(value)


def _normal_host_allowlist(hosts: Collection[str]) -> frozenset[str]:
    if isinstance(hosts, (str, bytes)) or not hosts:
        raise ValueError("an explicit host allowlist is required")
    normalized: set[str] = set()
    for host in hosts:
        if (not isinstance(host, str) or not host or host != host.strip()
                or "*" in host or "/" in host):
            raise ValueError("host allowlist entries must be exact hostnames or loopback IPs")
        candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        candidate = candidate.rstrip(".").lower()
        if ":" in candidate and candidate != "::1":
            raise ValueError("host allowlist entries must be exact hostnames or loopback IPs")
        try:
            candidate = ipaddress.ip_address(candidate).compressed
        except ValueError:
            pass
        normalized.add(candidate)
    return frozenset(normalized)


def _normal_model_allowlist(models: Collection[str]) -> frozenset[str]:
    if isinstance(models, (str, bytes)) or not models:
        raise ValueError("an explicit model allowlist is required for hosted AI routes")
    normalized: set[str] = set()
    for model in models:
        if (not isinstance(model, str) or not model or model != model.strip()
                or len(model) > 256 or "*" in model or "," in model
                or any(ord(character) < 32 for character in model)):
            raise ValueError("model allowlist entries must be exact model IDs")
        normalized.add(model)
    return frozenset(normalized)


def _admit_ai_route(
    base_url: str,
    model: str | None,
    allowed_hosts: Collection[str],
    *,
    allow_hosted: bool,
    allowed_models: Collection[str],
) -> tuple[str, str, bool, frozenset[str], frozenset[str]]:
    if type(allow_hosted) is not bool:
        raise ValueError("hosted route opt-in must be a boolean")
    hosts = _normal_host_allowlist(allowed_hosts)
    if not isinstance(base_url, str):
        raise ValueError("AI base URL must be a string")
    try:
        if (not base_url or base_url != base_url.strip() or "\\" in base_url
                or "?" in base_url or "#" in base_url
                or any(character.isspace() or ord(character) < 32 for character in base_url)):
            raise ValueError("AI route URL is malformed")
        parsed = urllib.parse.urlsplit(base_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("AI route URL or port is invalid") from exc
    if host is None:
        raise ValueError("AI route host is required")
    host = host.rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    loopback = host in _LOOPBACK_HOSTS
    safe_path = parsed.path.startswith("/") and all(
        part not in {".", ".."} for part in parsed.path.split("/")
    )
    if (host not in hosts or not safe_path or "@" in parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or not parsed.path.rstrip("/")):
        raise ValueError("AI route is outside its exact host/path allowlist")
    if loopback:
        if parsed.scheme != "http" or port is None or not 0 < port < 65536:
            raise ValueError("AI routes must use HTTPS or an explicit-port HTTP loopback alias")
    elif parsed.scheme != "https" or port not in (None, 443):
        raise ValueError("AI routes must use HTTPS or an explicit-port HTTP loopback alias")
    models: frozenset[str] = frozenset()
    if not loopback:
        if not isinstance(model, str) or not model.strip() or len(model) > 256:
            raise ValueError("an explicit provider model is required")
        if allow_hosted is not True:
            raise ValueError("hosted AI routes are disabled; explicit opt-in is required")
        models = _normal_model_allowlist(allowed_models)
        if model not in models:
            raise ValueError("hosted model is outside its exact model allowlist")
    elif model is not None and (not isinstance(model, str) or not model.strip() or len(model) > 256):
        raise ValueError("an explicit provider model is required")
    return base_url.rstrip("/"), host, loopback, hosts, models


def _price_information(value: object) -> tuple[bool, list[Decimal], bool]:
    has_price_field = False
    amounts: list[Decimal] = []
    invalid_amount = False

    def collect_prices(item: object, *, price_field: bool = False) -> None:
        nonlocal has_price_field, invalid_amount
        if isinstance(item, Mapping):
            if price_field and not item:
                invalid_amount = True
            for key, child in item.items():
                key_name = str(key).lower()
                if price_field and key_name in _PRICE_LABELS:
                    label = child.lower().strip() if isinstance(child, str) else ""
                    invalid_amount |= label not in _PRICE_LABELS[key_name]
                    continue
                is_price_field = any(
                    marker in key_name for marker in _PRICE_MARKERS
                )
                has_price_field |= is_price_field
                collect_prices(child, price_field=price_field or is_price_field)
        elif isinstance(item, (list, tuple)):
            if price_field and not item:
                invalid_amount = True
            for child in item:
                collect_prices(child, price_field=price_field)
        elif price_field:
            try:
                amounts.append(Decimal(str(item)))
            except (InvalidOperation, ValueError):
                invalid_amount = True

    collect_prices(value)
    return has_price_field, amounts, invalid_amount


def _reported_nonzero_price(value: object) -> bool:
    has_price_field, amounts, invalid_amount = _price_information(value)
    return has_price_field and (
        invalid_amount or not amounts
        or any(not amount.is_finite() or amount < 0 or amount != 0 for amount in amounts)
    )


def _trace_path() -> Path:
    configured = os.environ.get("SUITE_AI_TRACE_PATH")
    return (Path(configured).expanduser() if configured
            else Path.home() / ".local/state/industry-ai-suite/ai-traces.jsonl")


class OpenAICompatibleClient:
    """Bounded OpenAI-compatible route with exact-host egress and provider trace."""

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        allowed_hosts: Collection[str],
        trace_path: str | Path,
        allow_hosted: bool = False,
        allowed_models: Collection[str] = (),
        _credential: str | None = None,
        provider: str = "openai-compatible",
        timeout: float = 60.0,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        max_prompt_chars: int = _DEFAULT_MAX_PROMPT_CHARS,
    ) -> None:
        (self.base_url, self.host, self.is_loopback, self.allowed_hosts,
         self._allowed_models) = _admit_ai_route(
            base_url, model, allowed_hosts,
            allow_hosted=allow_hosted, allowed_models=allowed_models,
        )
        if self.base_url.startswith("https://") and not _credential:
            raise ValueError("hosted OpenAI-compatible routes require a runtime credential")
        if _credential is not None:
            _credential = _secret_value(_credential)
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider label is required")
        self.model = model.strip()
        self.provider = provider.strip()
        self.provider_host = self.host
        self._api_key = _credential
        self.trace_path = Path(trace_path).expanduser()
        self.timeout = _validate_timeout(timeout)
        self.max_tokens = _validate_max_tokens(max_tokens)
        self.max_prompt_chars = _validate_prompt_limit(max_prompt_chars)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler(),
        )
        self._cost_reported = False
        self._cost_lock = threading.Lock()

    @classmethod
    def from_environment(cls) -> "OpenAICompatibleClient":
        provider = os.environ.get("SUITE_AI_PROVIDER", "openai-compatible")
        model = os.environ.get("SUITE_AI_MODEL", "").strip()
        if not model:
            raise ModelUnavailable("SUITE_AI_MODEL is not configured")
        if provider != "openai-compatible":
            raise ModelUnavailable("SUITE_AI_PROVIDER is not supported")
        base_url = os.environ.get("SUITE_AI_BASE_URL", "").strip()
        if not base_url:
            raise ModelUnavailable("SUITE_AI_BASE_URL is not configured")
        allowed_hosts = tuple(
            host.strip() for host in os.environ.get("SUITE_AI_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        )
        if not allowed_hosts:
            raise ModelUnavailable("SUITE_AI_ALLOWED_HOSTS is not configured")
        hosted_flag = os.environ.get("SUITE_AI_ALLOW_HOSTED", "")
        if hosted_flag not in ("", "false", "true"):
            raise ModelUnavailable("SUITE_AI_ALLOW_HOSTED must be exactly true or false")
        allow_hosted = hosted_flag == "true"
        allowed_models = tuple(
            model_id.strip() for model_id in os.environ.get("SUITE_AI_ALLOWED_MODELS", "").split(",")
            if model_id.strip()
        )
        try:
            _admit_ai_route(
                base_url, model, allowed_hosts,
                allow_hosted=allow_hosted, allowed_models=allowed_models,
            )
        except ValueError as exc:
            raise ModelUnavailable(str(exc)) from None
        environment_key = os.environ.get("SUITE_AI_API_KEY")
        secret_file = os.environ.get("SUITE_AI_API_KEY_FILE")
        if environment_key and secret_file:
            raise ModelUnavailable("configure exactly one provider credential source")
        api_key = _secret_value(environment_key) if environment_key else (
            _read_secret_file(secret_file) if secret_file else None
        )
        return cls(
            base_url, model=model, allowed_hosts=allowed_hosts, trace_path=_trace_path(),
            allow_hosted=allow_hosted, allowed_models=allowed_models,
            _credential=api_key, provider=provider,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "industry-ai-suite/1.0"}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _get_json(self, route: str, timeout: float) -> object:
        request = urllib.request.Request(route, headers=self._headers(), method="GET")
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ModelUnavailable("provider response exceeds the byte limit")
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            reason = "redirect refused" if 300 <= exc.code < 400 else f"HTTP {exc.code}"
            exc.close()
            raise ModelUnavailable(f"provider model request failed: {reason}") from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            raise ModelUnavailable("provider model request failed") from None

    def probe(self, *, timeout: float | None = None) -> ModelStatus:
        route = f"{self.base_url}/models"
        try:
            seconds = self.timeout if timeout is None else _validate_timeout(timeout)
            with self._cost_lock:
                if self._cost_reported:
                    return ModelStatus(False, self.base_url, reason="provider reported non-zero cost; route stopped")
            result = self._get_json(route, seconds)
            rows = result.get("data") if isinstance(result, Mapping) else None
            if not isinstance(rows, list):
                return ModelStatus(False, self.base_url, reason="unexpected /models response")
            selected = next((row for row in rows if isinstance(row, Mapping) and row.get("id") == self.model), None)
            if selected is None:
                return ModelStatus(False, self.base_url, reason="configured model is not advertised")
            if _reported_nonzero_price(selected):
                with self._cost_lock:
                    self._cost_reported = True
                return ModelStatus(False, self.base_url, reason="provider reports non-zero model price")
            models = tuple(
                row["id"] for row in rows
                if isinstance(row, Mapping) and isinstance(row.get("id"), str) and row["id"]
            )
            return ModelStatus(bool(models), self.base_url, models,
                               None if models else "no models advertised")
        except (ValueError, ModelUnavailable) as exc:
            return ModelStatus(False, self.base_url, reason=str(exc))

    def complete(
        self,
        prompt: str,
        *,
        system: str,
        timeout: float | None = None,
        max_tokens: int | None = None,
        trace_context: Mapping[str, object] | None = None,
    ) -> ModelResult:
        request_timeout = self.timeout if timeout is None else _validate_timeout(timeout)
        output_tokens = self.max_tokens if max_tokens is None else _validate_max_tokens(max_tokens)
        if not isinstance(prompt, str) or not isinstance(system, str):
            raise ValueError("prompt and system must be strings")
        if len(prompt) > self.max_prompt_chars or len(system) > self.max_prompt_chars:
            raise ValueError(f"prompt and system text must each be at most {self.max_prompt_chars} characters")
        status = self.probe(timeout=min(request_timeout, _PROBE_TIMEOUT))
        if not status.available:
            raise ModelUnavailable(f"configured provider route unavailable: {status.reason}")

        safe_prompt = str(redact(prompt))
        safe_system = str(redact(system))
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": safe_system}, {"role": "user", "content": safe_prompt}],
            "temperature": 0,
            "max_tokens": output_tokens,
        }
        request_bytes = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=request_bytes,
            headers={**self._headers(), "Content-Type": "application/json"}, method="POST",
        )
        deadline = monotonic() + request_timeout
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ModelUnavailable("provider request deadline expired")
        try:
            with self._opener.open(request, timeout=remaining) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ModelUnavailable("provider response exceeds the byte limit")
                result = json.loads(body)
        except urllib.error.HTTPError as exc:
            reason = "redirect refused" if 300 <= exc.code < 400 else "HTTP request failed"
            exc.close()
            raise ModelUnavailable(f"provider completion {reason}") from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            raise ModelUnavailable("provider completion request failed") from None
        try:
            provider_id = result["id"]
            returned_model = result["model"]
            created = result["created"]
            usage = result["usage"]
            text = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ModelUnavailable("provider returned incomplete completion identity") from None
        if (not isinstance(provider_id, str) or not provider_id or not isinstance(returned_model, str)
                or not returned_model or type(created) is not int or not isinstance(usage, Mapping)
                or not isinstance(text, str)):
            raise ModelUnavailable("provider returned incomplete completion identity")
        if not self.is_loopback and returned_model not in self._allowed_models:
            raise ModelUnavailable("provider returned a model outside its exact model allowlist")
        safe_text = str(redact(text))
        safe_result = redact(result)
        response_sha256 = hashlib.sha256(body).hexdigest()
        trace = {
            "trace_provenance": "app-reported",
            "at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "provider": self.provider,
            "provider_host": self.host,
            "provider_id": provider_id,
            "model": returned_model,
            "created": created,
            "usage": redact(usage),
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
            "request": payload,
            "response": safe_result,
            "context": redact(dict(trace_context or {})),
        }
        _append_provider_trace(self.trace_path, trace)
        if _reported_nonzero_price(usage):
            with self._cost_lock:
                self._cost_reported = True
            raise ModelUnavailable("provider reported non-zero request cost; route stopped")
        return ModelResult(
            status="AI / PROVIDER", route=self.base_url, model=returned_model,
            text=safe_text, provider_id=provider_id, usage=redact(usage), created=created,
            provider_host=self.host, request_sha256=request_sha256,
            response_sha256=response_sha256,
        )


def _append_provider_trace(path: Path, record: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise ModelUnavailable("provider trace could not be opened safely") from None
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ModelUnavailable("provider trace must be a private user-owned regular file")
        safe_record = redact(record)
        if isinstance(safe_record, dict):
            safe_record["provider_host"] = record["provider_host"]
        encoded = (json.dumps(safe_record, sort_keys=True, separators=(",", ":"), default=str) + "\n").encode("utf-8")
        written = 0
        while written < len(encoded):
            amount = os.write(descriptor, encoded[written:])
            if amount <= 0:
                raise OSError("provider trace append made no progress")
            written += amount
    except OSError:
        raise ModelUnavailable("provider trace could not be appended safely") from None
    finally:
        os.close(descriptor)


def configured_ai_client() -> OpenAICompatibleClient:
    """Build the explicit environment-selected provider without printing secrets."""
    return OpenAICompatibleClient.from_environment()


def ai_configuration_status() -> dict[str, object]:
    """Return safe readiness facts only; credentials and their values never escape."""
    try:
        client = configured_ai_client()
    except (ModelUnavailable, ValueError) as exc:
        return {
            "ready": False,
            "status": "AI: unavailable (UNVERIFIED)",
            "reason": str(exc),
        }
    return {
        "ready": True,
        "status": "configured; route not probed",
        "provider": client.provider,
        "host": client.provider_host,
        "model": client.model,
        "trace_configured": True,
    }


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
