"""Local-only model, minimized receipt persistence, and human review contract."""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from webapp.enterprise.examples import EXAMPLES
from webapp.local_ai import apply_local_ai
from webapp.receipt_store import LocalReceiptStore
from webapp.runner import run
from webapp.server import WorkbenchServer


def _post(base: str, path: str, body: object, *, origin: str | None, token: str | None):
    headers = {"Content-Type": "application/json"}
    if origin is not None:
        headers["Origin"] = origin
    if token is not None:
        headers["X-Workbench-Token"] = token
    request = Request(base + path, data=json.dumps(body).encode(), method="POST", headers=headers)
    with urlopen(request, timeout=3) as response:
        return json.load(response)


def _http_error(base: str, path: str, body: object, *, origin: str | None, token: str | None) -> int:
    try:
        _post(base, path, body, origin=origin, token=token)
    except HTTPError as error:
        error.close()
        return error.code
    raise AssertionError("request unexpectedly succeeded")


class _FakeLocalClient:
    def __init__(self, prompts: list[str], *, available: bool = True, models: tuple[str, ...] = ("local-test-model",)):
        self.prompts = prompts
        self.available = available
        self.models = models
        self.completions = 0

    def probe(self, *, timeout: float | None = None):
        return SimpleNamespace(
            available=self.available,
            models=self.models,
            reason="connection refused" if not self.available else None,
        )

    def complete(self, prompt: str, *, system: str, model: str, max_tokens: int):
        self.prompts.append(prompt)
        self.completions += 1
        packet = json.loads(prompt)
        return SimpleNamespace(text=f"The bounded review is ready for human inspection [evidence:{packet['evidence_ids'][0]}].")


def test_local_ai_uses_only_minimized_findings_and_preserves_unverified_source_status(monkeypatch) -> None:
    monkeypatch.setenv("SUITE_AI_LOCAL_BASE_URL", "http://127.0.0.1:52652/v1")
    monkeypatch.setenv("SUITE_AI_LOCAL_MODEL", "")
    for slug, bundle in EXAMPLES.items():
        receipt = run(slug, {"mode": "enterprise", "bundle": copy.deepcopy(bundle)})
        receipt["task_result"]["raw_bundle_canary"] = "RAW_PRIVATE_BUNDLE_MARKER"
        prompts: list[str] = []
        clients: list[_FakeLocalClient] = []

        def factory(*_args, **_kwargs):
            client = _FakeLocalClient(prompts)
            clients.append(client)
            return client

        result = apply_local_ai(receipt, requested=True, client_factory=factory)
        assert result["local_processing_status"] == "COMPLETE", slug
        assert result["human_review_status"] == "PENDING", slug
        assert result["ai_invoked"] is True, slug
        assert result["local_ai_model"] == "local-test-model", slug
        assert result["source_status"] == receipt["source_status"] == "SYNTHETIC / ENGINEERING ONLY", slug
        assert result["workflow_status"] == receipt["workflow_status"], slug
        assert len(prompts) == 1 and len(clients) == 1, slug
        assert "RAW_PRIVATE_BUNDLE_MARKER" not in prompts[0], slug
        assert "task_result" not in prompts[0], slug
        assert result["local_ai_evidence_ids"], slug


def test_unavailable_local_model_blocks_without_fallback_or_fake_answer(monkeypatch) -> None:
    monkeypatch.setenv("SUITE_AI_LOCAL_BASE_URL", "http://127.0.0.1:52652/v1")
    monkeypatch.setenv("SUITE_AI_LOCAL_MODEL", "")
    receipt = run("ledgerbridge", {"mode": "enterprise", "bundle": copy.deepcopy(EXAMPLES["ledgerbridge"])})
    prompts: list[str] = []
    clients: list[_FakeLocalClient] = []

    def factory(*_args, **_kwargs):
        client = _FakeLocalClient(prompts, available=False)
        clients.append(client)
        return client

    result = apply_local_ai(receipt, requested=True, client_factory=factory)
    assert result["local_processing_status"] == "BLOCKED"
    assert "unavailable" in result["local_processing_reason"]
    assert result["local_ai_output"] is None
    assert result["ai_invoked"] is False
    assert clients[0].completions == 0
    assert result["source_status"] == receipt["source_status"]
    assert result["workflow_status"] == receipt["workflow_status"]


def test_multiple_models_require_an_explicit_local_pin(monkeypatch) -> None:
    monkeypatch.setenv("SUITE_AI_LOCAL_BASE_URL", "http://127.0.0.1:52652/v1")
    monkeypatch.setenv("SUITE_AI_LOCAL_MODEL", "")
    receipt = run("ledgerbridge", {"mode": "enterprise", "bundle": copy.deepcopy(EXAMPLES["ledgerbridge"])})
    prompts: list[str] = []
    clients: list[_FakeLocalClient] = []

    def factory(*_args, **_kwargs):
        client = _FakeLocalClient(prompts, models=("one", "two"))
        clients.append(client)
        return client

    result = apply_local_ai(receipt, requested=True, client_factory=factory)
    assert result["local_processing_status"] == "BLOCKED"
    assert result["ai_status"] == "BLOCKED / PIN A LOCAL MODEL"
    assert clients[0].completions == 0


def test_non_loopback_model_route_is_rejected_without_network_access(monkeypatch) -> None:
    monkeypatch.setenv("SUITE_AI_LOCAL_BASE_URL", "https://example.com/v1")
    receipt = run("ledgerbridge", {"mode": "enterprise", "bundle": copy.deepcopy(EXAMPLES["ledgerbridge"])})
    result = apply_local_ai(receipt, requested=True)
    assert result["local_processing_status"] == "BLOCKED"
    assert result["ai_status"] == "BLOCKED / LOCAL ROUTE OR PROMPT REJECTED"
    assert result["local_ai_output"] is None


def _sample_receipt() -> dict[str, object]:
    return {
        "project": "ledgerbridge",
        "status": "UNVERIFIED",
        "source_status": "USER_SUPPLIED / AUTHORIZATION UNVERIFIED",
        "workflow_status": "LOCAL REVIEW ONLY / ENTERPRISE UNVERIFIED",
        "local_processing_status": "PARTIAL",
        "human_review_status": "PENDING",
        "local_processing_reason": "Optional model was not requested.",
        "ai_status": "NOT RUN",
        "ai_invoked": False,
        "review_summary": {"title": "Safe bounded summary", "findings": ["One exception [evidence:row-1]."], "metrics": []},
        "source_metadata": {"source_ref": "operator-file-1", "tenant_id": "org-code-1", "input_sha256": "a" * 64},
        "evidence_ids": ["row-1"],
        "task_result": {"raw_canary": "DO_NOT_PERSIST_RAW_BUNDLE"},
        "uncertainty": "Source remains unverified.",
        "human_handoff": {"owner": "reviewer-1", "owner_type": "operator code", "next_action": "Check the original source."},
        "side_effect_count": 0,
    }


def test_store_minimizes_data_persists_review_and_keeps_private_permissions(tmp_path) -> None:
    store = LocalReceiptStore(tmp_path / "history")
    saved = store.save(_sample_receipt())
    assert saved["human_review_status"] == "PENDING"
    assert saved["human_handoff"]["next_action"] == "Check the original source."
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert store.directory.stat().st_mode & 0o777 == 0o700
    persisted = store.path.read_text()
    assert "DO_NOT_PERSIST_RAW_BUNDLE" not in persisted
    assert "task_result" not in persisted

    reviewed = store.review(saved["receipt_id"], "REVIEWED")
    assert reviewed["human_review_status"] == "REVIEWED"
    assert LocalReceiptStore(store.directory).list()[0]["human_review_status"] == "REVIEWED"
    requested = store.review(saved["receipt_id"], "CHANGES_REQUESTED")
    assert requested["human_review_status"] == "CHANGES_REQUESTED"
    store.delete(saved["receipt_id"])
    assert store.list() == []


def test_failed_atomic_review_write_preserves_previous_history(tmp_path) -> None:
    store = LocalReceiptStore(tmp_path / "history")
    saved = store.save(_sample_receipt())
    original = store.path.read_bytes()
    with patch("webapp.receipt_store.os.replace", side_effect=OSError("test-only replace failure")):
        with pytest.raises(OSError):
            store.review(saved["receipt_id"], "REVIEWED")
    assert store.path.read_bytes() == original
    assert store.list()[0]["human_review_status"] == "PENDING"
    assert not list(store.directory.glob(".receipts-*.tmp"))


def test_all_receipt_reads_and_mutations_require_local_origin_and_page_token(tmp_path) -> None:
    store = LocalReceiptStore(tmp_path / "history")
    server = WorkbenchServer(0, receipt_store=store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        created = _post(
            base,
            "/api/run/ledgerbridge",
            {"mode": "enterprise", "bundle": copy.deepcopy(EXAMPLES["ledgerbridge"])},
            origin=base,
            token=server.token,
        )
        receipt_id = created["receipt_id"]
        for path, body in (
            ("/api/receipts/list", {}),
            (f"/api/receipts/{receipt_id}/review", {"status": "REVIEWED"}),
            (f"/api/receipts/{receipt_id}/delete", {}),
        ):
            assert _http_error(base, path, body, origin="https://example.com", token=server.token) == 403
            assert _http_error(base, path, body, origin=base, token="wrong") == 403
            assert _http_error(base, path, body, origin=None, token=server.token) == 403

        assert _http_error(base, "/api/receipts/list", {}, origin=None, token=server.token) == 403
        get_request = Request(base + "/api/receipts/list", method="GET")
        with pytest.raises(HTTPError) as denied_get:
            urlopen(get_request, timeout=3)
        assert denied_get.value.code == 403
        denied_get.value.close()
        assert _post(base, "/api/receipts/list", {}, origin=base, token=server.token)["receipts"][0]["receipt_id"] == receipt_id
        _post(base, f"/api/receipts/{receipt_id}/review", {"status": "REVIEWED"}, origin=base, token=server.token)
        assert LocalReceiptStore(store.directory).list()[0]["human_review_status"] == "REVIEWED"
        assert _post(base, f"/api/receipts/{receipt_id}/delete", {}, origin=base, token=server.token)["deleted"] is True
        assert _post(base, "/api/receipts/list", {}, origin=base, token=server.token)["receipts"] == []
        assert _http_error(base, f"/api/receipts/{receipt_id}/review", {"status": ["REVIEWED"]}, origin=base, token=server.token) == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
