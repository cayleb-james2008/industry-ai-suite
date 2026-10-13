"""Serve the Industry AI Suite workbench on loopback only.

Run: python3 -m webapp.server --port 18340
"""

from __future__ import annotations

import argparse
import json
import secrets
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from suite_core import LiveSourceError, LocalOpenAIClient
from .runner import SLUGS, run
from .enterprise.common import strict_json_loads
from .enterprise.examples import EXAMPLES
from .local_ai import apply_local_ai
from .receipt_store import LocalReceiptStore

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

    def _authorized(self) -> bool:
        origin = self.headers.get("Origin")
        allowed = {f"http://127.0.0.1:{self.server.server_port}"}
        return origin in allowed and self.headers.get("X-Workbench-Token") == self.server.token

    def _post_json(self) -> dict[str, object] | None:
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._json(415, {"error": "Send JSON input."})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            self._json(413, {"error": "Input is empty or exceeds 128 KB."})
            return None
        try:
            payload = strict_json_loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)[:300]})
            return None
        if not isinstance(payload, dict):
            self._json(400, {"error": "Request must be a JSON object."})
            return None
        return payload

    def _receipt_route(self, path: str) -> bool:
        if not path.startswith("/api/receipts/"):
            return False
        if not self._authorized():
            self._json(403, {"error": "Open the local workbench page before accessing saved receipts."})
            return True
        payload = self._post_json()
        if payload is None:
            return True
        try:
            if path == "/api/receipts/list" and payload == {}:
                self._json(200, {"receipts": self.server.receipt_store.list()})
                return True
            parts = path.strip("/").split("/")
            if (len(parts) == 4 and parts[:2] == ["api", "receipts"]
                    and parts[3] == "review" and set(payload) == {"status"}):
                record = self.server.receipt_store.review(parts[2], payload["status"])
                self._json(200, {"receipt": record})
                return True
            if (len(parts) == 4 and parts[:2] == ["api", "receipts"]
                    and parts[3] == "delete" and payload == {}):
                self.server.receipt_store.delete(parts[2])
                self._json(200, {"deleted": True})
                return True
        except KeyError:
            self._json(404, {"error": "Saved receipt not found."})
            return True
        except ValueError:
            self._json(400, {"error": "Unsupported receipt action."})
            return True
        except OSError:
            self._json(503, {"error": "Local receipt history is unavailable; no submitted input was saved."})
            return True
        self._json(404, {"error": "Receipt route not found."})
        return True

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path.startswith("/api/receipts/"):
            if not self._authorized():
                self._json(403, {"error": "Open the local workbench page before accessing saved receipts."})
            else:
                self._json(405, {"error": "Use the local workbench receipt action."})
            return
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
        if self._receipt_route(path):
            return
        if not path.startswith("/api/run/") or path.rsplit("/", 1)[-1] not in SLUGS:
            self._json(404, {"error": "Route not found."})
            return
        if not self._authorized():
            self._json(403, {"error": "Open the local workbench page before running a workflow."})
            return
        payload = self._post_json()
        if payload is None:
            return
        try:
            slug = path.rsplit("/", 1)[-1]
            local_ai_requested = False
            if payload.get("mode", "public") == "enterprise":
                local_ai_requested = payload.pop("local_ai", False)
                if type(local_ai_requested) is not bool:
                    raise ValueError("Local model selection must be true or false.")
            elif "local_ai" in payload:
                raise ValueError("Local model drafting is available only for organization imports.")
            result = run(slug, payload)
        except LiveSourceError as exc:
            self._json(200, _source_failure(path.rsplit("/", 1)[-1], exc.status))
            return
        except (ValueError, KeyError, TypeError) as exc:
            self._json(400, {"error": str(exc)[:300]})
            return
        except Exception:
            self._json(502, {"error": "The source or workflow failed. Check the input and try again; no saved result was substituted."})
            return
        if isinstance(result, dict) and "workbench_status" not in result:
            presentation = _source_status_presentation(result)
            if presentation is not None:
                result = {**result, "workbench_status": presentation}
        if result.get("input_mode") == "enterprise":
            result = apply_local_ai(
                result,
                requested=local_ai_requested,
                client_factory=self.server.local_model_factory,
            )
            try:
                saved = self.server.receipt_store.save(result)
            except (OSError, TypeError, ValueError):
                self._json(503, {"error": "The minimized local receipt could not be saved. The submitted input was not stored."})
                return
            result["receipt_id"] = saved["receipt_id"]
            result["minimized_receipt"] = saved
        try:
            self._json(200, result)
        except (TypeError, ValueError):
            self._json(502, {"error": "The workflow produced an unsupported result; no receipt was returned."})


class WorkbenchServer(ThreadingHTTPServer):
    def __init__(
        self,
        port: int,
        *,
        receipt_store: LocalReceiptStore | None = None,
        local_model_factory: Callable[..., LocalOpenAIClient] = LocalOpenAIClient,
    ) -> None:
        super().__init__(("127.0.0.1", port), WorkbenchHandler)
        self.token = secrets.token_urlsafe(32)
        self.receipt_store = receipt_store or LocalReceiptStore()
        self.local_model_factory = local_model_factory


def main() -> None:
    parser = argparse.ArgumentParser(description="Local read-only suite workbench")
    parser.add_argument("--port", type=int, default=18340)
    args = parser.parse_args()
    with WorkbenchServer(args.port) as server:
        print(f"Industry AI Suite workbench: http://127.0.0.1:{server.server_port}/", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
