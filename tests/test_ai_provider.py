from __future__ import annotations

import json
import io
import hashlib
import os
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apps._ai_receipts import complete_grounded
from scripts.ai_witness_proxy import WitnessProxyServer
from scripts.verify_witness import main as verify_witness_main, verify_calls
from scripts.witness_protocol import (
    GENESIS_CHAIN_SHA256,
    encoded_line,
    line_sha256,
    provider_metadata,
    signed_record,
)
from suite_core import LocalOpenAIClient, ModelUnavailable, OpenAICompatibleClient, ai_configuration_status
from suite_core.model import _reported_nonzero_price
from scripts.run_all import APP_SLUGS, run_suite


class _ProviderHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, status: int, value: object) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        self.server.calls.append(("GET", self.path, self.headers.get("User-Agent"), None))
        if self.path != "/v1/models":
            self.send_error(404)
            return
        if self.server.redirect_models:
            self.send_response(307)
            self.send_header("Location", self.server.redirect_target)
            self.end_headers()
            return
        self._send_json(200, {"data": self.server.models})

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.calls.append((
            "POST", self.path, self.headers.get("User-Agent"), self.headers.get("Authorization"),
        ))
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        self.server.payloads.append(json.loads(body))
        self._send_json(200, self.server.completion)


class _CountingTransport:
    def __init__(self) -> None:
        self.invocations: list[object] = []

    def open(self, request: object, timeout: float):
        self.invocations.append(request)
        raise AssertionError("fake transport must not be invoked by route-admission tests")


class _JSONResponse:
    def __init__(self, value: object) -> None:
        self.body = json.dumps(value).encode("utf-8")

    def __enter__(self) -> _JSONResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]


class _PriceRefusalTransport:
    def __init__(self, price: object) -> None:
        self.price = price
        self.requests: list[object] = []

    def open(self, request: object, timeout: float):
        self.requests.append(request)
        if request.get_method() != "GET":
            raise AssertionError("price refusal must prevent a completion POST")
        return _JSONResponse({"data": [{"id": "fixture-model", "pricing": self.price}]})


@contextmanager
def _provider_route(*, price: object = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    server.models = [{"id": "fixture-model", **({"pricing": price} if price is not None else {})}]
    server.completion = {
        "id": "completion-verified-test",
        "object": "chat.completion",
        "created": 1_790_000_000,
        "model": "fixture-model-returned",
        "choices": [{"index": 0, "message": {
            "role": "assistant",
            "content": "Avery Morgan recommends analyst review [evidence:WB:GDP:2024].",
        }, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 9, "total_tokens": 29},
    }
    server.calls = []
    server.payloads = []
    server.redirect_models = False
    server.redirect_target = "https://example.invalid/collect"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    route = f"http://127.0.0.1:{server.server_port}/v1"
    try:
        yield route, server
    finally:
        port = server.server_port
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        with socket.socket() as probe:
            probe.settimeout(0.2)
            closed = probe.connect_ex(("127.0.0.1", port)) != 0
        if not closed:
            raise AssertionError("owned provider test port remained open")


@contextmanager
def _witness_proxy(upstream: str, witness_log: Path):
    proxy = WitnessProxyServer(
        upstream, allowed_hosts=("127.0.0.1",), witness_log=witness_log,
    )
    thread = threading.Thread(target=proxy.serve_forever, daemon=False)
    thread.start()
    port = proxy.server_port
    try:
        yield proxy, f"http://127.0.0.1:{port}/v1"
    finally:
        with redirect_stdout(io.StringIO()):
            proxy.reveal_and_close()
        thread.join(timeout=2)
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise AssertionError("owned witness proxy port remained open")


def _reveal(proxy: WitnessProxyServer) -> bytes:
    output = io.StringIO()
    with redirect_stdout(output):
        proxy.reveal_and_close()
    line = output.getvalue().strip()
    if not line:
        raise AssertionError("proxy did not print its late reveal")
    return line.encode("utf-8")


class OpenAICompatibleClientTests(unittest.TestCase):
    def _client(self, route: str, trace: Path, **overrides: object) -> OpenAICompatibleClient:
        env = {
            "SUITE_AI_PROVIDER": "openai-compatible",
            "SUITE_AI_BASE_URL": route,
            "SUITE_AI_ALLOWED_HOSTS": "127.0.0.1",
            "SUITE_AI_MODEL": "fixture-model",
            "SUITE_AI_API_KEY": "runtime-only-test-value",
            "SUITE_AI_TRACE_PATH": str(trace),
        }
        with patch.dict(os.environ, env, clear=True):
            return OpenAICompatibleClient.from_environment()

    def test_provider_identity_trace_redaction_and_grounded_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (route, server):
            trace = Path(directory) / "provider-traces.jsonl"
            client = self._client(route, trace)
            result = complete_grounded(
                client,
                "Summarize GDP source WB:GDP:2024. Contact Avery Morgan at person@example.invalid.",
                system="Use only the cited record; the API key is not source data.",
                evidence_ids=("WB:GDP:2024",),
            )

            self.assertEqual(result["ai_status"], "AI / PROVIDER")
            self.assertTrue(result["ai_invoked"])
            self.assertEqual(result["ai_output"], "[REDACTED] recommends analyst review [evidence:WB:GDP:2024].")
            proof = result["ai_evidence"]
            self.assertEqual(proof["provider_id"], "completion-verified-test")
            self.assertEqual(proof["model"], "fixture-model-returned")
            self.assertEqual(proof["provider_host"], "127.0.0.1")
            self.assertEqual(proof["usage"]["total_tokens"], 29)
            self.assertTrue(proof["grounded"])
            self.assertEqual(len(server.payloads), 1)
            self.assertEqual(server.payloads[0]["model"], "fixture-model")
            request_text = json.dumps(server.payloads[0])
            self.assertNotIn("person@example.invalid", request_text)
            self.assertNotIn("Avery Morgan", request_text)
            self.assertTrue(all(call[2] == "industry-ai-suite/1.0" for call in server.calls))
            self.assertEqual(server.calls[-1][3], "Bearer runtime-only-test-value")

            trace_text = trace.read_text(encoding="utf-8")
            entry = json.loads(trace_text)
            self.assertEqual(entry["provider_id"], "completion-verified-test")
            self.assertEqual(entry["model"], "fixture-model-returned")
            self.assertEqual(entry["created"], 1_790_000_000)
            self.assertEqual(entry["provider_host"], "127.0.0.1")
            self.assertEqual(entry["context"]["evidence_ids"], ["WB:GDP:2024"])
            self.assertIn("request_sha256", entry)
            self.assertIn("response_sha256", entry)
            self.assertNotIn("person@example.invalid", trace_text)
            self.assertNotIn("Avery Morgan", trace_text)
            self.assertNotIn("runtime-only-test-value", trace_text)
            self.assertNotIn("test-secret-header-value", trace_text)
            self.assertEqual(trace.stat().st_mode & 0o077, 0)
            self.assertEqual(entry["trace_provenance"], "app-reported")

    def test_witness_proxy_matches_exact_call_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, provider):
            root = Path(directory)
            witness_log = root / "verifier-witness.jsonl"
            app_trace = root / "app-reported-trace.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model", allowed_hosts=("127.0.0.1",),
                    trace_path=app_trace, _credential="proxy-secret-test-value",
                )
                call = complete_grounded(
                    client, "Summarize source WB:GDP:2024", system="Cite only the supplied record.",
                    evidence_ids=("WB:GDP:2024",),
                )
                self.assertEqual(call["ai_status"], "AI / PROVIDER")
                proof = call["ai_evidence"]
                self.assertEqual(proof["trace_provenance"], "app-reported")
                self.assertEqual(provider.calls[-1][3], "Bearer proxy-secret-test-value")

                witness_text = witness_log.read_text(encoding="utf-8")
                self.assertNotIn("proxy-secret-test-value", witness_text)
                self.assertNotIn("Avery Morgan recommends", witness_text)
                self.assertNotIn("Summarize source", witness_text)
                self.assertEqual(witness_log.stat().st_mode & 0o077, 0)
                reveal = _reveal(proxy)
                result = verify_calls(witness_log.read_bytes(), reveal, [proof])
                self.assertEqual(result["witness_integrity"], "VERIFIED")
                self.assertEqual(result["call_results"][0]["status"], "VERIFIED")
                self.assertIn("transport exchange only", result["call_results"][0]["scope"])
                self.assertNotIn("proxy-secret-test-value", reveal.decode("utf-8"))

                reveal_file = root / "reveal.json"
                calls_file = root / "app-calls.json"
                reveal_file.write_bytes(reveal + b"\n")
                calls_file.write_text(json.dumps([proof]), encoding="utf-8")
                reveal_file.chmod(0o600)
                calls_file.chmod(0o600)
                with redirect_stdout(io.StringIO()) as cli_output:
                    exit_code = verify_witness_main([
                        "--witness-log", str(witness_log), "--reveal", str(reveal_file),
                        "--app-calls", str(calls_file),
                    ])
                self.assertEqual(exit_code, 0)
                cli_result = json.loads(cli_output.getvalue())
                self.assertEqual(cli_result["call_results"][0]["status"], "VERIFIED")

                forged = dict(proof, provider_id="forged-provider-id")
                rejected = verify_calls(witness_log.read_bytes(), reveal, [forged])
                self.assertEqual(rejected["call_results"][0]["status"], "UNVERIFIED")

                tampered = [json.loads(line) for line in witness_text.splitlines()]
                tampered[-1]["response_sha256"] = "f" * 64
                bad_log = ("".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
                                  for item in tampered)).encode("utf-8")
                bad_result = verify_calls(bad_log, reveal, [proof])
                self.assertEqual(bad_result["witness_integrity"], "UNVERIFIED")
                self.assertEqual(bad_result["call_results"][0]["status"], "UNVERIFIED")
                self.assertIn("HMAC", bad_result["witness_reason"])

    def test_witness_rejects_a_during_session_forgery_without_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, _):
            root = Path(directory)
            witness_log = root / "witness.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model", allowed_hosts=("127.0.0.1",),
                    trace_path=root / "app-trace.jsonl",
                )
                result = complete_grounded(
                    client, "Summarize WB:GDP:2024", system="Cite the record.",
                    evidence_ids=("WB:GDP:2024",),
                )
                lines = witness_log.read_bytes().splitlines(keepends=True)
                last = json.loads(lines[-1])
                forged = dict(last)
                forged["provider_id"] = "same-user-forgery"
                forged["previous_line_sha256"] = line_sha256(lines[-1])
                forged["hmac"] = "0" * 64
                with witness_log.open("ab") as output:
                    output.write(encoded_line(forged))
                reveal = _reveal(proxy)
                verdict = verify_calls(witness_log.read_bytes(), reveal, [result["ai_evidence"]])
                self.assertEqual(verdict["witness_integrity"], "UNVERIFIED")
                self.assertIn("HMAC", verdict["witness_reason"])

    def test_witness_chain_detects_deleted_and_reordered_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, _):
            root = Path(directory)
            witness_log = root / "witness.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model", allowed_hosts=("127.0.0.1",),
                    trace_path=root / "app-trace.jsonl",
                )
                call = complete_grounded(
                    client, "Summarize WB:GDP:2024", system="Cite the record.",
                    evidence_ids=("WB:GDP:2024",),
                )
                reveal = _reveal(proxy)
                lines = witness_log.read_bytes().splitlines(keepends=True)
                self.assertEqual(len(lines), 2)
                for damaged in (lines[1:], list(reversed(lines))):
                    result = verify_calls(b"".join(damaged), reveal, [call["ai_evidence"]])
                    self.assertEqual(result["witness_integrity"], "UNVERIFIED")
                    self.assertEqual(result["call_results"][0]["status"], "UNVERIFIED")

    def test_witness_chain_rejects_valid_line_appended_after_reveal(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, _):
            root = Path(directory)
            witness_log = root / "witness.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model", allowed_hosts=("127.0.0.1",),
                    trace_path=root / "app-trace.jsonl",
                )
                call = complete_grounded(
                    client, "Summarize WB:GDP:2024", system="Cite the record.",
                    evidence_ids=("WB:GDP:2024",),
                )
                reveal = _reveal(proxy)
                reveal_value = json.loads(reveal)
                key = bytes.fromhex(reveal_value["hmac_key_hex_not_a_credential"])
                previous = line_sha256(witness_log.read_bytes().splitlines(keepends=True)[-1])
                appended = signed_record(key, {
                    "schema_version": 1,
                    "at_utc": "2026-09-24T00:00:00Z",
                    "upstream_host": "127.0.0.1",
                    "method": "GET",
                    "request_path": "/v1/models",
                    "request_sha256": hashlib.sha256(b"").hexdigest(),
                    "response_sha256": "a" * 64,
                    "http_status": 200,
                    "response_complete": True,
                    "provider_id": None,
                    "model": None,
                    "created": None,
                    "usage": None,
                }, previous)
                with witness_log.open("ab") as output:
                    output.write(encoded_line(appended))
                verdict = verify_calls(witness_log.read_bytes(), reveal, [call["ai_evidence"]])
                self.assertEqual(verdict["witness_integrity"], "UNVERIFIED")
                self.assertIn("final chain head", verdict["witness_reason"])

    def test_credential_shaped_witness_metadata_is_hashed_and_unverifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, provider):
            root = Path(directory)
            provider.completion["id"] = "sk-AAAAAAAAAAAAAAAA"
            provider.completion["model"] = "model_0123456789abcdefghijklmnopqrstuv"
            witness_log = root / "witness.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model", allowed_hosts=("127.0.0.1",),
                    trace_path=root / "app-trace.jsonl",
                )
                call = complete_grounded(
                    client, "Summarize WB:GDP:2024", system="Cite the record.",
                    evidence_ids=("WB:GDP:2024",),
                )
                reveal = _reveal(proxy)
                completion = json.loads(witness_log.read_text(encoding="utf-8").splitlines()[-1])
                self.assertIsNone(completion["provider_id"])
                self.assertTrue(completion["provider_id_redacted"])
                self.assertEqual(completion["provider_id_sha256"], hashlib.sha256(
                    b"sk-AAAAAAAAAAAAAAAA"
                ).hexdigest())
                self.assertIsNone(completion["model"])
                self.assertTrue(completion["model_redacted"])
                self.assertNotIn("sk-AAAAAAAAAAAAAAAA", witness_log.read_text(encoding="utf-8"))
                verdict = verify_calls(witness_log.read_bytes(), reveal, [call["ai_evidence"]])
                self.assertEqual(verdict["call_results"][0]["status"], "UNVERIFIED")

        for secret in (
            "sk-AAAAAAAAAAAAAAAA", "ghp_1234567890abcdefgh", "github_pat_1234567890abcdefgh",
            "xoxb-1234567890abcdefgh", "AKIA1234567890ABCD12", "Bearer abcdefghijk",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl1234",
            "0123456789abcdefghijklmnopqrstuv",
        ):
            self.assertTrue(provider_metadata("model", secret)["model_redacted"])

    def test_witness_proxy_refuses_unlisted_upstream_and_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "exact allowlisted host"):
                WitnessProxyServer(
                    "https://unlisted.example/v1", allowed_hosts=("listed.example",),
                    witness_log=Path(directory) / "witness.jsonl",
                )

        with tempfile.TemporaryDirectory() as directory, _provider_route() as (upstream, provider):
            provider.redirect_models = True
            witness_log = Path(directory) / "redirect-witness.jsonl"
            with _witness_proxy(upstream, witness_log) as (proxy, proxy_url):
                client = OpenAICompatibleClient(
                    proxy_url, model="fixture-model",
                    allowed_hosts=("127.0.0.1",), trace_path=Path(directory) / "app-trace.jsonl",
                )
                status = client.probe()
                self.assertFalse(status.available)
                self.assertEqual(provider.calls, [("GET", "/v1/models", "industry-ai-witness/1.0", None)])
                entries = [json.loads(line) for line in witness_log.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(entries[0]["http_status"], 307)
                self.assertTrue(entries[0]["response_complete"])

    def test_runner_never_verifies_a_provider_call_or_imports_the_verifier(self) -> None:
        evidence = {
            "trace_provenance": "app-reported",
            "provider_id": "completion-app-reported",
            "model": "fixture-free",
            "provider_host": "127.0.0.1",
            "created": 1_790_000_000,
            "usage": {"total_tokens": 7},
            "provider_request_sha256": "a" * 64,
            "provider_response_sha256": "b" * 64,
            "grounded": True,
        }
        fake_flow = SimpleNamespace(run_live=lambda ai_client=None: {
            "status": "VERIFIED_SOURCE",
            "ai_status": "AI / PROVIDER",
            "ai_invoked": True,
            "ai_evidence": evidence,
            "ai_verification_status": "AI VERIFIED",
        })
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("scripts.run_all.importlib.import_module", return_value=fake_flow),
                redirect_stdout(io.StringIO()),
            ):
                _, _, receipts = run_suite(Path(directory) / "receipts")

        self.assertEqual(len(receipts), len(APP_SLUGS))
        self.assertTrue(all(
            receipt["ai_verification_status"] == "AI CANDIDATE (unwitnessed)"
            for receipt in receipts
        ))
        self.assertTrue(all(receipt["app_reported_ai_verification_claim_ignored"] for receipt in receipts))
        self.assertEqual(receipts[0]["ai_evidence"]["provider_request_sha256"], "a" * 64)
        self.assertEqual(receipts[0]["ai_evidence"]["provider_response_sha256"], "b" * 64)
        self.assertNotIn("verify_witness", Path("scripts/run_all.py").read_text(encoding="utf-8"))

    def test_grounded_reject_is_retained_as_rejected_not_replaced_by_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (route, server):
            server.completion["choices"][0]["message"]["content"] = "Unsupported claim without a citation."
            client = self._client(route, Path(directory) / "trace.jsonl")
            result = complete_grounded(
                client, "Summarize WB:GDP:2024", system="Cite evidence.",
                evidence_ids=("WB:GDP:2024",),
            )
            self.assertEqual(result["ai_status"], "NON-AI / DETERMINISTIC FALLBACK")
            self.assertTrue(result["ai_invoked"])
            self.assertIsNone(result["ai_output"])
            self.assertFalse(result["ai_evidence"]["grounded"])
            self.assertIn("UnsafeModelOutput", result["ai_failure"])
            self.assertEqual(len(server.calls), 2)

    def test_redirects_are_refused_and_no_second_host_receives_a_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (route, server):
            server.redirect_models = True
            client = self._client(route, Path(directory) / "trace.jsonl")
            status = client.probe()
            self.assertFalse(status.available)
            self.assertIn("redirect refused", status.reason)
            self.assertEqual([call[:2] for call in server.calls], [("GET", "/v1/models")])

    def test_reported_nonzero_model_price_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route(price={"input": "0.001"}) as (route, server):
            client = self._client(route, Path(directory) / "trace.jsonl")
            status = client.probe()
            self.assertFalse(status.available)
            self.assertEqual(status.reason, "provider reports non-zero model price")
            self.assertFalse(client.probe().available)
            self.assertEqual(len(server.calls), 1)

    def test_malformed_price_metadata_is_untrusted_but_explicit_recognized_zero_passes(self) -> None:
        for price in (
            {"pricing": {"input": "$0.001"}},
            {"pricing": {"input": "free-ish"}},
            {"pricing": {"input": "NaN"}},
            {"pricing": {"input": float("nan")}},
            {"pricing": {"input": -0.001}},
            {"pricing": {"input": 0, "currency": "BTC"}},
            {"pricing": {"input": 0, "unit": "unknown-unit"}},
            {"pricing": {}},
        ):
            with self.subTest(price=price):
                self.assertTrue(_reported_nonzero_price(price))

        self.assertFalse(_reported_nonzero_price({"pricing": {"input": 0}}))
        self.assertFalse(_reported_nonzero_price({
            "pricing": {"input": "0", "output": 0, "currency": "USD"},
        }))

    def test_price_refusal_uses_fake_transport_and_never_posts_completion(self) -> None:
        transport = _PriceRefusalTransport({"input": "$0.001"})
        with tempfile.TemporaryDirectory() as directory, patch(
            "suite_core.model.urllib.request.build_opener", return_value=transport,
        ):
            client = OpenAICompatibleClient(
                "http://127.0.0.1:8123/v1", model="fixture-model",
                allowed_hosts=("127.0.0.1",), trace_path=Path(directory) / "trace.jsonl",
            )
            status = client.probe()
            self.assertFalse(status.available)
            self.assertIn("non-zero model price", status.reason)
            with self.assertRaisesRegex(ModelUnavailable, "route stopped|non-zero model price"):
                client.complete("test prompt", system="test system")

        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0].get_method(), "GET")

    def test_shared_route_admission_accepts_only_numeric_loopback_addresses(self) -> None:
        for url_host, allowlisted_host, canonical_host in (
            ("127.0.0.1", "127.0.0.1", "127.0.0.1"),
            ("[::1]", "[::1]", "::1"),
        ):
            with self.subTest(url_host=url_host), tempfile.TemporaryDirectory() as directory:
                transport = _CountingTransport()
                route = f"http://{url_host}:8123/v1"
                with patch("suite_core.model.urllib.request.build_opener", return_value=transport):
                    client = OpenAICompatibleClient(
                        route, model="local-model", allowed_hosts=(allowlisted_host,),
                        trace_path=Path(directory) / "trace.jsonl",
                    )
                    local_client = LocalOpenAIClient(route)
                self.assertTrue(client.is_loopback)
                self.assertEqual(client.host, canonical_host)
                self.assertEqual(local_client.base_url, route)
                self.assertEqual(transport.invocations, [])

    def test_localhost_hostname_is_refused_before_transport(self) -> None:
        route = "http://localhost:8123/v1"
        with tempfile.TemporaryDirectory() as directory:
            transport = _CountingTransport()
            with patch(
                "suite_core.model.urllib.request.build_opener", return_value=transport,
            ) as make_opener:
                with self.assertRaises(ValueError):
                    OpenAICompatibleClient(
                        route, model="local-model", allowed_hosts=("localhost",),
                        trace_path=Path(directory) / "trace.jsonl",
                    )
                with self.assertRaises(ValueError):
                    LocalOpenAIClient(route)
            make_opener.assert_not_called()
            self.assertEqual(transport.invocations, [])

    def test_lookalike_userinfo_and_malformed_routes_are_refused_before_opener(self) -> None:
        for route, hosts in (
            ("http://localhost.evil:8123/v1", ("localhost.evil",)),
            ("http://127.0.0.1.evil:8123/v1", ("127.0.0.1.evil",)),
            ("http://user@127.0.0.1:8123/v1", ("127.0.0.1",)),
            ("http://[::1/v1", ("::1",)),
        ):
            with self.subTest(route=route), tempfile.TemporaryDirectory() as directory:
                transport = _CountingTransport()
                with patch(
                    "suite_core.model.urllib.request.build_opener", return_value=transport,
                ) as make_opener:
                    with self.assertRaises(ValueError):
                        OpenAICompatibleClient(
                            route, model="local-model", allowed_hosts=hosts,
                            trace_path=Path(directory) / "trace.jsonl",
                        )
                make_opener.assert_not_called()
                self.assertEqual(transport.invocations, [])

    def test_reported_nonzero_completion_cost_refuses_result_and_stops_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _provider_route() as (route, server):
            server.completion["usage"] = {
                "prompt_tokens": 20, "completion_tokens": 9, "total_tokens": 29,
                "cost": {"input": 0, "output": "0.001"},
            }
            trace = Path(directory) / "trace.jsonl"
            client = self._client(route, trace)

            with self.assertRaisesRegex(ModelUnavailable, "non-zero request cost"):
                client.complete("Summarize WB:GDP:2024", system="Use only cited evidence.")

            status = client.probe()
            self.assertFalse(status.available)
            self.assertEqual(status.reason, "provider reported non-zero cost; route stopped")
            self.assertEqual([call[0] for call in server.calls], ["GET", "POST"])
            self.assertEqual(json.loads(trace.read_text(encoding="utf-8"))["usage"]["cost"]["output"], "0.001")

    def test_exact_host_allowlist_and_transport_scheme_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            for route, hosts in (
                ("https://unlisted.example/v1", ("opencode.ai",)),
                ("http://example.invalid:8080/v1", ("example.invalid",)),
                ("https://user:pass@opencode.ai/v1", ("opencode.ai",)),
                ("https://opencode.ai/v1?next=https://example.invalid", ("opencode.ai",)),
            ):
                with self.subTest(route=route), self.assertRaises(ValueError):
                    OpenAICompatibleClient(
                        route, model="selected", allowed_hosts=hosts,
                        trace_path=trace,
                    )

    def test_credentialed_hosted_route_is_denied_before_fake_transport_by_default(self) -> None:
        transport = _CountingTransport()
        env = {
            "SUITE_AI_PROVIDER": "openai-compatible",
            "SUITE_AI_BASE_URL": "https://api.example.invalid/v1",
            "SUITE_AI_ALLOWED_HOSTS": "api.example.invalid",
            "SUITE_AI_MODEL": "selected-model",
            "SUITE_AI_API_KEY": "runtime-only-test-value",
            "SUITE_AI_TRACE_PATH": "/tmp/unused-provider-trace.jsonl",
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "suite_core.model.urllib.request.build_opener", return_value=transport,
        ) as make_opener:
            with self.assertRaisesRegex(ModelUnavailable, "hosted AI routes are disabled"):
                OpenAICompatibleClient.from_environment()
            with self.assertRaisesRegex(ValueError, "hosted AI routes are disabled"):
                OpenAICompatibleClient(
                    env["SUITE_AI_BASE_URL"], model=env["SUITE_AI_MODEL"],
                    allowed_hosts=("api.example.invalid",), trace_path=env["SUITE_AI_TRACE_PATH"],
                    _credential=env["SUITE_AI_API_KEY"],
                )
        make_opener.assert_not_called()
        self.assertEqual(transport.invocations, [])

    def test_hosted_opt_in_requires_exact_host_and_model_and_never_calls_transport(self) -> None:
        transport = _CountingTransport()
        env = {
            "SUITE_AI_PROVIDER": "openai-compatible",
            "SUITE_AI_BASE_URL": "https://api.example.invalid/v1",
            "SUITE_AI_ALLOWED_HOSTS": "api.example.invalid",
            "SUITE_AI_ALLOWED_MODELS": "selected-model",
            "SUITE_AI_ALLOW_HOSTED": "true",
            "SUITE_AI_MODEL": "selected-model",
            "SUITE_AI_API_KEY": "runtime-only-test-value",
            "SUITE_AI_TRACE_PATH": "/tmp/unused-provider-trace.jsonl",
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "suite_core.model.urllib.request.build_opener", return_value=transport,
        ):
            client = OpenAICompatibleClient.from_environment()
        self.assertEqual(client.host, "api.example.invalid")
        self.assertEqual(client.model, "selected-model")
        self.assertFalse(client.is_loopback)
        self.assertEqual(transport.invocations, [])

        for override, message in (
            ({"SUITE_AI_ALLOWED_HOSTS": "different.example.invalid"}, "exact host/path allowlist"),
            ({"SUITE_AI_ALLOWED_HOSTS": "*.example.invalid"}, "exact hostnames"),
            ({"SUITE_AI_ALLOWED_MODELS": ""}, "explicit model allowlist"),
            ({"SUITE_AI_ALLOWED_MODELS": "other-model"}, "exact model allowlist"),
            ({"SUITE_AI_ALLOWED_MODELS": "*"}, "exact model IDs"),
            ({"SUITE_AI_ALLOW_HOSTED": "yes"}, "exactly true or false"),
        ):
            with self.subTest(override=override), patch.dict(os.environ, {**env, **override}, clear=True):
                with self.assertRaisesRegex(ModelUnavailable, message):
                    OpenAICompatibleClient.from_environment()
        self.assertEqual(transport.invocations, [])

    def test_local_openai_compatible_route_remains_free_default_without_hosted_opt_in(self) -> None:
        with patch.dict(os.environ, {
            "SUITE_AI_PROVIDER": "openai-compatible",
            "SUITE_AI_BASE_URL": "http://127.0.0.1:52652/v1",
            "SUITE_AI_ALLOWED_HOSTS": "127.0.0.1",
            "SUITE_AI_MODEL": "local-model",
        }, clear=True):
            client = OpenAICompatibleClient.from_environment()
        self.assertTrue(client.is_loopback)
        self.assertIsNone(client._api_key)
        self.assertEqual(client.model, "local-model")

    def test_secret_files_require_private_regular_file_and_doctor_never_exposes_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_file = root / "provider-secret.txt"
            secret_file.write_text("runtime-only-test-value\n", encoding="utf-8")
            secret_file.chmod(0o600)
            env = {
                "SUITE_AI_PROVIDER": "openai-compatible",
                "SUITE_AI_BASE_URL": "https://api.example.invalid/v1",
                "SUITE_AI_ALLOWED_HOSTS": "api.example.invalid",
                "SUITE_AI_ALLOWED_MODELS": "example-free",
                "SUITE_AI_ALLOW_HOSTED": "true",
                "SUITE_AI_MODEL": "example-free",
                "SUITE_AI_API_KEY_FILE": str(secret_file),
                "SUITE_AI_TRACE_PATH": str(root / "trace.jsonl"),
            }
            with patch.dict(os.environ, env, clear=True):
                client = OpenAICompatibleClient.from_environment()
                status = ai_configuration_status()
                self.assertTrue(status["ready"])
                self.assertEqual(status["host"], "api.example.invalid")
                self.assertNotIn("runtime-only-test-value", json.dumps(status))
                secret_file.chmod(0o640)
                with self.assertRaises(ModelUnavailable) as denied:
                    OpenAICompatibleClient.from_environment()
                self.assertNotIn("runtime-only-test-value", str(denied.exception))

    def test_opencode_provider_id_is_not_supported(self) -> None:
        with patch.dict(os.environ, {
            "SUITE_AI_PROVIDER": "opencode-zen",
            "SUITE_AI_MODEL": "mimo-v2.6-flash-free",
        }, clear=True):
            with self.assertRaisesRegex(ModelUnavailable, "SUITE_AI_PROVIDER is not supported"):
                OpenAICompatibleClient.from_environment()

    def test_no_provider_configuration_reports_unavailable_without_a_secret(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            status = ai_configuration_status()
        fallback = complete_grounded(
            None, "Summarize record WB:GDP:2024", system="Cite the record.",
            evidence_ids=("WB:GDP:2024",),
        )
        self.assertFalse(status["ready"])
        self.assertEqual(status["status"], "AI: unavailable (UNVERIFIED)")
        self.assertNotIn("key", json.dumps(status).lower())
        self.assertEqual(fallback["ai_availability"], "AI: unavailable (UNVERIFIED)")
        self.assertEqual(fallback["ai_status"], "NON-AI / DETERMINISTIC FALLBACK")
        self.assertFalse(fallback["ai_invoked"])

    def test_configured_runner_without_a_route_keeps_every_app_on_non_ai_path(self) -> None:
        def import_workflow(_: str) -> SimpleNamespace:
            return SimpleNamespace(run_live=lambda ai_client=None: {
                "status": "UNVERIFIED",
                "ai_status": "NON-AI / DETERMINISTIC FALLBACK",
                "ai_availability": "AI: unavailable (UNVERIFIED)",
                "ai_invoked": False,
                "ai_evidence": None,
                "side_effect_count": 0,
            })

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            with patch("scripts.run_all.importlib.import_module", side_effect=import_workflow):
                with redirect_stdout(io.StringIO()):
                    code, _, receipts = run_suite(Path(directory) / "receipts", ai_configured=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(receipts), len(APP_SLUGS))
        self.assertTrue(all(item["ai_verification_status"] == "NON-AI / DETERMINISTIC FALLBACK"
                            for item in receipts))
        self.assertTrue(all(item["ai_availability"] == "AI: unavailable (UNVERIFIED)"
                            for item in receipts))
        self.assertTrue(all(item["model_route_probe"]["available"] is False for item in receipts))


if __name__ == "__main__":
    unittest.main()
