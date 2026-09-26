"""Serve the Industry AI Suite workbench on loopback only.

Run: python3 -m webapp.server --port 18340
"""

from __future__ import annotations

import argparse
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .runner import SLUGS, run

STATIC = Path(__file__).with_name("static")
MAX_BODY = 128 * 1024
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/dark.css": ("dark.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class WorkbenchHandler(BaseHTTPRequestHandler):
    server: "WorkbenchServer"

    def log_message(self, format: str, *args: object) -> None:
        # Paths and user input never enter a persistent access log.
        pass

    def _headers(self, code: int, content_type: str, length: int) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _send(self, code: int, data: bytes, content_type: str) -> None:
        self._headers(code, content_type, len(data))
        self.wfile.write(data)

    def _json(self, code: int, data: dict[str, object]) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False, default=str).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._json(200, {"status": "ready", "workflows": list(SLUGS)})
            return
        asset = ASSETS.get(path)
        if asset is None:
            self._json(404, {"error": "Route not found."})
            return
        data = (STATIC / asset[0]).read_bytes()
        if path == "/":
            data = data.replace(b"__WORKBENCH_TOKEN__", self.server.token.encode())
        self._send(200, data, asset[1])

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if not path.startswith("/api/run/") or path.rsplit("/", 1)[-1] not in SLUGS:
            self._json(404, {"error": "Route not found."})
            return
        origin = self.headers.get("Origin")
        allowed = {f"http://127.0.0.1:{self.server.server_port}"}
        if origin not in allowed or self.headers.get("X-Workbench-Token") != self.server.token:
            self._json(403, {"error": "Open the local workbench page before running a workflow."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._json(415, {"error": "Send JSON input."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            self._json(413, {"error": "Input is empty or exceeds 128 KB."})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = run(path.rsplit("/", 1)[-1], payload)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)[:300]})
            return
        except Exception:
            self._json(502, {"error": "The source or workflow failed. Check the input and try again; no saved result was substituted."})
            return
        self._json(200, result)


class WorkbenchServer(ThreadingHTTPServer):
    def __init__(self, port: int) -> None:
        super().__init__(("127.0.0.1", port), WorkbenchHandler)
        self.token = secrets.token_urlsafe(32)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local read-only suite workbench")
    parser.add_argument("--port", type=int, default=18340)
    args = parser.parse_args()
    with WorkbenchServer(args.port) as server:
        print(f"Industry AI Suite workbench: http://127.0.0.1:{server.server_port}/", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
