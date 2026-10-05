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

from suite_core import LiveSourceError
from .runner import SLUGS, run
from .enterprise.common import strict_json_loads
from .enterprise.examples import EXAMPLES

STATIC = Path(__file__).with_name("static")
MAX_BODY = 128 * 1024
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/dark.css": ("dark.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/result-intro.js": ("result-intro.js", "text/javascript; charset=utf-8"),
}


def _source_status_presentation(receipt: dict[str, object]) -> dict[str, str] | None:
    """Explain live-source status without upgrading the full workflow verdict."""
    status = ""
    for key in ("source_status", "data_status", "status"):
        value = receipt.get(key)
        if isinstance(value, str):
            status = value
            break
    if status.startswith("DATA_UNAVAILABLE"):
        return {
            "label": "DATA UNAVAILABLE", "tone": "warn",
            "explanation": (
                "The live source did not return usable records for this run. "
                "No fixture, cache, or substitute was used; retry the same source later. "
                "The full workflow remains unverified."
            ),
        }
    if status.startswith("UNVERIFIED"):
        return {
            "label": "SOURCE UNVERIFIED", "tone": "warn",
            "explanation": (
                "Source provenance, terms, freshness, task fit, or authority could not be established. "
                "No records are treated as verified, and no substitute was used."
            ),
        }
    if status.startswith("VERIFIED_SOURCE"):
        return {
            "label": "DATED PUBLIC SOURCE", "tone": "good",
            "explanation": (
                "The named public source passed its checks for this run. "
                "This does not verify the complete organization workflow or authorize an action."
            ),
        }
    return None


def _source_failure(slug: str, status: str) -> dict[str, object]:
    if status == "DATA_UNAVAILABLE":
        uncertainty = (
            "The live source did not return usable records for this run. "
            "No fixture, cache, or substitute was used."
        )
        next_action = "Retry the same public source later; do not use a stale or substitute result."
        ai_status = "NOT RUN / DATA UNAVAILABLE"
    else:
        status = "UNVERIFIED"
        uncertainty = (
            "Source provenance, terms, freshness, task fit, or authority could not be established. "
            "No records are treated as verified, and no substitute was used."
        )
        next_action = "Check the named source and its terms or authority before using any records."
        ai_status = "NOT RUN / UNVERIFIED SOURCE"
    receipt: dict[str, object] = {
        "app_slug": slug,
        "status": status,
        "source_status": status,
        "workflow_status": "UNVERIFIED",
        "task_result": None,
        "evidence": [],
        "uncertainty": uncertainty,
        "human_handoff": {"owner": "source reviewer", "next_action": next_action},
        "ai_status": ai_status,
        "ai_invoked": False,
        "side_effect_count": 0,
    }
    receipt["workbench_status"] = _source_status_presentation(receipt)
    return receipt


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
        self._send(code, json.dumps(data, ensure_ascii=False, allow_nan=False).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._json(200, {"status": "ready", "workflows": list(SLUGS)})
            return
        if path.startswith("/api/example/"):
            slug = path.rsplit("/", 1)[-1]
            if slug not in SLUGS:
                self._json(404, {"error": "Example not found."})
            else:
                self._json(200, {"bundle": EXAMPLES[slug], "notice": "SYNTHETIC EXAMPLE — engineering only; not a real organization source."})
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
            payload = strict_json_loads(self.rfile.read(length))
            result = run(path.rsplit("/", 1)[-1], payload)
        except LiveSourceError as exc:
            self._json(200, _source_failure(path.rsplit("/", 1)[-1], exc.status))
            return
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)[:300]})
            return
        except Exception:
            self._json(502, {"error": "The source or workflow failed. Check the input and try again; no saved result was substituted."})
            return
        if isinstance(result, dict) and "workbench_status" not in result:
            presentation = _source_status_presentation(result)
            if presentation is not None:
                result = {**result, "workbench_status": presentation}
        try:
            self._json(200, result)
        except (TypeError, ValueError):
            self._json(502, {"error": "The workflow produced an unsupported result; no receipt was returned."})


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
