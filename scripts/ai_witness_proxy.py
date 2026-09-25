"""Loopback-only forwarder with a late-revealed HMAC witness chain."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import select
import secrets
import signal
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if __package__:
    from .witness_protocol import (
        GENESIS_CHAIN_SHA256, encoded_line, line_sha256, numeric_usage, provider_metadata, signed_record,
    )
else:
    from witness_protocol import (
        GENESIS_CHAIN_SHA256, encoded_line, line_sha256, numeric_usage, provider_metadata, signed_record,
    )

_MAX_BODY_BYTES = 2_000_000
_MAX_LOG_BYTES = 16_000_000


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str,
    ) -> None:
        return None


def _allowed_hosts(values: Sequence[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not values:
        raise ValueError("supply at least one exact upstream host")
    hosts = set()
    for value in values:
        if (not isinstance(value, str) or not value or value != value.strip()
                or any(char in value for char in "*/:@?#")):
            raise ValueError("upstream hosts must be exact names or literal IP addresses")
        hosts.add(value.rstrip(".").lower())
    return frozenset(hosts)


def _validate_upstream(base_url: str, hosts: frozenset[str]) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(base_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("upstream URL is invalid") from None
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    path = parsed.path.rstrip("/")
    if (host not in hosts or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not path.startswith("/") or any(part in {".", ".."} for part in path.split("/"))):
        raise ValueError("upstream must use an exact allowlisted host and a safe base path")
    if parsed.scheme == "https" and port in (None, 443):
        pass
    elif parsed.scheme == "http" and loopback and port is not None and 0 < port < 65536:
        pass
    else:
        raise ValueError("upstream must use HTTPS or an explicit literal-loopback HTTP port")
    return base_url.rstrip("/"), host, path


def _private_file(path: Path, flags: int, mode: int = 0o600) -> int:
    descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077):
        os.close(descriptor)
        raise OSError("witness log must be a private user-owned regular file")
    return descriptor


def _create_private_log(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = _private_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.close(descriptor)


def _provider_fields(body: bytes) -> dict[str, object]:
    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        response = None
    if not isinstance(response, Mapping):
        response = {}
    return {
        **provider_metadata("provider_id", response.get("id")),
        **provider_metadata("model", response.get("model")),
        "created": response.get("created") if type(response.get("created")) is int else None,
        "usage": numeric_usage(response.get("usage")),
    }


class WitnessProxyServer(ThreadingHTTPServer):
    """One-upstream observer; a random key remains private until shutdown."""

    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(
        self,
        upstream: str,
        *,
        allowed_hosts: Sequence[str],
        witness_log: str | Path,
        port: int = 0,
    ) -> None:
        hosts = _allowed_hosts(allowed_hosts)
        self.upstream, self.upstream_host, self.upstream_path = _validate_upstream(upstream, hosts)
        self.witness_log = Path(witness_log).expanduser()
        self._hmac_key = secrets.token_bytes(32)
        self._chain_head = GENESIS_CHAIN_SHA256
        self._state_lock = threading.Lock()
        self._accepting = True
        self._revealed = False
        _create_private_log(self.witness_log)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler(),
        )
        super().__init__(("127.0.0.1", port), _WitnessProxyHandler)

    def accepts_requests(self) -> bool:
        with self._state_lock:
            return self._accepting and not self._revealed

    def append_exchange(self, record: dict[str, object]) -> None:
        with self._state_lock:
            if self._revealed:
                raise OSError("witness session has been revealed")
            signed = signed_record(self._hmac_key, record, self._chain_head)
            encoded = encoded_line(signed)
            descriptor = _private_file(self.witness_log, os.O_WRONLY | os.O_APPEND)
            try:
                if os.fstat(descriptor).st_size + len(encoded) > _MAX_LOG_BYTES:
                    raise OSError("witness log exceeds the size limit")
                written = 0
                while written < len(encoded):
                    count = os.write(descriptor, encoded[written:])
                    if count <= 0:
                        raise OSError("witness log append made no progress")
                    written += count
            finally:
                os.close(descriptor)
            self._chain_head = line_sha256(encoded)

    def reveal_and_close(self) -> None:
        """Stop admission, drain handlers, and reveal the HMAC key exactly once."""
        with self._state_lock:
            if self._revealed:
                return
            self._accepting = False
        self.shutdown()
        self.server_close()
        with self._state_lock:
            if self._revealed:
                return
            self._revealed = True
            reveal = {
                "event": "witness-reveal",
                "key_disclosure": "session HMAC key; not a provider credential",
                "hmac_key_hex_not_a_credential": self._hmac_key.hex(),
                "final_chain_head_sha256": self._chain_head,
            }
        print(json.dumps(reveal, sort_keys=True), file=sys.stdout, flush=True)


class _WitnessProxyHandler(BaseHTTPRequestHandler):
    server: WitnessProxyServer
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def _forward(self) -> None:
        if not self.server.accepts_requests():
            self.send_error(503, "witness session is closing")
            return
        parsed = urllib.parse.urlsplit(self.path)
        suffixes = {
            ("GET", f"{self.server.upstream_path}/models"): "/models",
            ("POST", f"{self.server.upstream_path}/chat/completions"): "/chat/completions",
        }
        suffix = suffixes.get((self.command, parsed.path))
        if suffix is None or parsed.query or parsed.fragment or self.headers.get("Transfer-Encoding"):
            self.send_error(404, "unsupported proxy request")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if length < 0 or length > _MAX_BODY_BYTES or (self.command == "GET" and length):
            self.send_error(413, "request body exceeds the limit")
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.send_error(400, "incomplete request body")
            return

        headers = {"Accept": self.headers.get("Accept", "application/json"),
                   "User-Agent": "industry-ai-witness/1.0"}
        if self.command == "POST":
            headers["Content-Type"] = self.headers.get("Content-Type", "application/json")
        authorization = self.headers.get("Authorization")
        if authorization:
            headers["Authorization"] = authorization
        request = urllib.request.Request(
            f"{self.server.upstream}{suffix}",
            data=body if self.command == "POST" else None,
            headers=headers,
            method=self.command,
        )
        try:
            with self.server.opener.open(request, timeout=180) as response:
                status = response.status
                response_body = response.read(_MAX_BODY_BYTES + 1)
                content_type = response.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as response:
            status = response.code
            response_body = response.read(_MAX_BODY_BYTES + 1)
            content_type = response.headers.get("Content-Type", "application/json")
            response.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            self.send_error(502, "upstream unavailable")
            return

        complete = len(response_body) <= _MAX_BODY_BYTES
        observed_body = response_body[:_MAX_BODY_BYTES]
        record: dict[str, object] = {
            "schema_version": 1,
            "at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "upstream_host": self.server.upstream_host,
            "method": self.command,
            "request_path": parsed.path,
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "response_sha256": hashlib.sha256(observed_body).hexdigest(),
            "http_status": status,
            "response_complete": complete,
            **_provider_fields(observed_body),
        }
        try:
            self.server.append_exchange(record)
        except OSError:
            self.send_error(503, "witness log unavailable; response withheld")
            return

        if not complete or 300 <= status < 400:
            response_body = b'{"error":"response refused by witness proxy"}'
            status = 502
            content_type = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        try:
            self.wfile.write(response_body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forward one API route and late-reveal its HMAC witness key.")
    parser.add_argument("--upstream", required=True, help="one upstream OpenAI-compatible base URL")
    parser.add_argument("--allow-host", action="append", required=True,
                        help="exact upstream host allowlist entry (repeat to declare exact names)")
    parser.add_argument("--witness-log", required=True, type=Path,
                        help="new private log path selected by the verifier")
    parser.add_argument("--port", type=int, default=0, help="loopback listening port (0 selects a free port)")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be from 0 through 65535")
    try:
        server = WitnessProxyServer(
            args.upstream, allowed_hosts=args.allow_host,
            witness_log=args.witness_log, port=args.port,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    stop_requested = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_requested.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    serve_thread = threading.Thread(target=server.serve_forever, name="witness-proxy", daemon=False)
    serve_thread.start()
    print(
        f"Witness proxy listening at http://127.0.0.1:{server.server_port}{server.upstream_path} "
        f"for upstream host {server.upstream_host}; type reveal to stop and disclose the witness key.",
        flush=True,
    )
    try:
        while not stop_requested.is_set():
            ready, _, _ = select.select([sys.stdin], [], [], 0.2)
            if ready:
                command = sys.stdin.readline()
                if command == "" or command.strip() == "reveal":
                    stop_requested.set()
                elif command.strip():
                    print("Only the reveal command is accepted.", flush=True)
    finally:
        server.reveal_and_close()
        serve_thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
