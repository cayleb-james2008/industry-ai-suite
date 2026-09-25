"""ADVERSARIAL REGRESSION ONLY: exercise all ten real run_live paths via runner."""

from __future__ import annotations

import builtins
import copy
import hashlib
import importlib
import io
import json
import os
import re
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import suite_core.live_sources as live_sources
from scripts import run_all
from suite_core import DataUnavailable, LocalOpenAIClient, SourceRecord, SourceResult


APP_SLUGS = run_all.APP_SLUGS
PINNED_REAL_PUBLIC = Path(__file__).resolve().parent / "data" / "pinned_real_public"
SNAPSHOT_FOR_APP = {
    "ledgerbridge": "treasury_dts.json",
    "marketbrief": "world_bank_usa_gdp.json",
    "backtestguard": "world_bank_usa_gdp.json",
    "sentineldesk": "cisa_kev.json",
    "searchlift": "own_portfolio.json",
    "pipelinerelay": "github_pytest.json",
    "handoffhub": "opm_public_records.json",
    "onboardpath": "opm_public_records.json",
    "replycraft": "replycraft_public_policy.json",
}
SNAPSHOT_SHA256 = {
    "treasury_dts.json": "84be02ba4a1425a679dbe717379af3f2f0cc70a2f8bc1ac238dbaa0a72b427b6",
    "world_bank_usa_gdp.json": "01b64fd374495a1074ebc01b9d0d97ff08627f0d0116cb8e60d311d7f5018b66",
    "cisa_kev.json": "2a75b9acbbe0458a88b6ffdf41f77d9cde2123d4eeefdf1c525b9df1408ed4b5",
    "github_pytest.json": "8314b777e4bb801e798b1a8418c6251359ae5dc1d0e5b009b939328e1e2ba631",
    "opm_public_records.json": "e1cfaec43d5809292793074be7e51f27b5339a2dbfda01ad24e3308734a1fe46",
    "own_portfolio.json": "03f536c35ad0ac0ff0aa98bf40120d65cde1eef106762654672b447132e5e342",
    "replycraft_public_policy.json": "c9f85b20a1494f36baed85803ed3783622631037b58156c930ed58cf06abb680",
}
ADAPTER_APPS = frozenset(SNAPSHOT_FOR_APP)
NO_ADMITTED_SOURCE_APPS = frozenset({"chainwatch"})
PII_NAME = "Avery Morgan"
PII_ADDRESS = "19 Example Road"
PII_TEXT = f"{PII_NAME}, {PII_ADDRESS}"
_NONEMPTY_RECORD_LISTS = (
    "records", "source_records", "source_ids", "evidence", "rows", "observations",
    "documents", "issues", "review_queue",
)
_COUNT_FIELDS = ("record_count", "accounted_row_count", "pages_reviewed", "issue_count")


@pytest.fixture(autouse=True)
def _block_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep this module offline even if an app bypasses its patched adapter symbol."""

    def deny_transport(self: object, url: str, *, timeout: float, max_bytes: int) -> object:
        raise AssertionError(f"unexpected live HTTP request from adversarial test: {url}")

    monkeypatch.setattr(live_sources._UrllibTransport, "get", deny_transport)


@pytest.fixture
def model_call_guard(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def deny_model(self: object, *args: object, **kwargs: object) -> object:
        calls.append("LocalOpenAIClient.complete")
        raise AssertionError("live-path contract attempted a model call")

    monkeypatch.setattr(LocalOpenAIClient, "complete", deny_model)
    return calls


def _captured_receipt(slug: str) -> dict[str, Any]:
    filename = SNAPSHOT_FOR_APP[slug]
    path = PINNED_REAL_PUBLIC / filename
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SNAPSHOT_SHA256[filename], (
        f"{filename}: pinned public snapshot changed; do not silently refresh test provenance"
    )
    return json.loads(raw)


def _source_from_metadata(snapshot: dict[str, Any]) -> SourceResult:
    source = snapshot["source"]
    records = tuple(
        SourceRecord(
            provider=source["provider"],
            source_id=item["source_id"],
            source_url=item.get("source_url", source["request_url"]),
            response_status=source["response_status"],
            response_sha256=source["response_sha256"],
            request_body_sha256=source["request_body_sha256"],
            as_of=item["as_of"],
            as_of_precision=item["as_of_precision"],
            retrieved_at_utc=source["retrieved_at_utc"],
            terms_url=source["terms_url"],
            read_only=source["read_only"],
            task_fit=source["task_fit"],
            data=item["data"],
        )
        for item in snapshot["records"]
    )
    return SourceResult(
        provider=source["provider"],
        status=source["status"],
        request_url=source["request_url"],
        response_status=source["response_status"],
        response_sha256=source["response_sha256"],
        request_body_sha256=source["request_body_sha256"],
        retrieved_at_utc=source["retrieved_at_utc"],
        task_fit=source["task_fit"],
        records=records,
        read_only=source["read_only"],
    )


def _replycraft_text() -> SourceRecord:
    text = _captured_receipt("replycraft")["text"]
    return SourceRecord(
        provider=text["provider"],
        source_id=text["source_id"],
        source_url=text["source_url"],
        response_status=text["response_status"],
        response_sha256=text["response_sha256"],
        request_body_sha256=text["request_body_sha256"],
        as_of=text["as_of"],
        as_of_precision=text["as_of_precision"],
        retrieved_at_utc=text["retrieved_at_utc"],
        terms_url=text["terms_url"],
        read_only=text["read_only"],
        task_fit=text["task_fit"],
        data=text["data"],
    )


def _opm_source(receipt: dict[str, Any]) -> SourceResult:
    evidence = receipt["evidence"]
    records = tuple(
        SourceRecord(
            provider=receipt["provider"],
            source_id=item["source_id"],
            source_url=item["source_url"],
            # P1b's captured Federal Register smoke recorded HTTP 200; P6's
            # per-record receipt projection omits this response-level field.
            response_status=item.get("response_status", 200),
            response_sha256=item["response_sha256"],
            request_body_sha256=None,
            as_of=item["as_of"],
            as_of_precision=item["as_of_precision"],
            retrieved_at_utc=item["retrieved_at_utc"],
            terms_url=item["terms"],
            read_only=item["read_only"],
            task_fit="public_opm_policy_documents",
            # Public titles are intentionally absent from the sanitized snapshot.
            data={"document_number": item["source_id"], "type": item.get("document_type")},
        )
        for item in evidence
    )
    first = evidence[0]
    return SourceResult(
        provider=receipt["provider"],
        status="VERIFIED_SOURCE",
        request_url=receipt["request_url"],
        response_status=first.get("response_status", 200),
        response_sha256=first["response_sha256"],
        request_body_sha256=None,
        retrieved_at_utc=first["retrieved_at_utc"],
        task_fit="public_opm_policy_documents",
        records=records,
        read_only=True,
    )


def _cisa_source(receipt: dict[str, Any]) -> SourceResult:
    evidence = receipt["evidence"]
    by_id = {item["source_id"]: item for item in evidence}
    example = receipt["example"]
    item = by_id[example["source_id"]]
    record = SourceRecord(
        provider=item["provider"] if "provider" in item else "cisa_kev",
        source_id=item["source_id"],
        source_url=item["source_url"],
        response_status=item["response_status"],
        response_sha256=item["response_sha256"],
        request_body_sha256=None,
        as_of=example["date_added"],
        as_of_precision=item["as_of_precision"],
        retrieved_at_utc=item["retrieved_at_utc"],
        terms_url=item["terms_url"],
        read_only=item["read_only"],
        task_fit=item["task_fit"],
        data={
            "dateAdded": example["date_added"],
            "dueDate": example["due_date"],
        },
    )
    return SourceResult(
        provider=record.provider,
        status="VERIFIED_SOURCE",
        request_url=item["source_url"],
        response_status=record.response_status,
        response_sha256=record.response_sha256,
        request_body_sha256=None,
        retrieved_at_utc=record.retrieved_at_utc,
        task_fit=record.task_fit,
        records=(record,),
        read_only=True,
    )


def _github_source(receipt: dict[str, Any]) -> SourceResult:
    evidence = receipt["evidence"][0]
    metadata = receipt["task_result"]["metadata"]
    record = SourceRecord(
        provider=receipt["source"]["provider"],
        source_id=evidence["source_id"],
        source_url=evidence["source_url"],
        response_status=evidence["response_status"],
        response_sha256=evidence["response_sha256"],
        request_body_sha256=None,
        as_of=evidence["as_of"],
        as_of_precision=evidence["as_of_precision"],
        retrieved_at_utc=evidence["retrieved_at_utc"],
        terms_url=evidence["terms_url"],
        read_only=evidence["read_only"],
        task_fit=evidence["task_fit"],
        data={
            "id": int(metadata["repository_id"]),
            "html_url": metadata["html_url"],
            "default_branch": metadata["default_branch"],
            "license": {"spdx_id": metadata["license_spdx_id"], "url": evidence["terms_url"]},
        },
    )
    return SourceResult(
        provider=record.provider,
        status="VERIFIED_SOURCE",
        request_url=receipt["source"]["request_url"],
        response_status=record.response_status,
        response_sha256=record.response_sha256,
        request_body_sha256=None,
        retrieved_at_utc=record.retrieved_at_utc,
        task_fit=record.task_fit,
        records=(record,),
        read_only=True,
    )


def _pinned_source(slug: str) -> SourceResult:
    """Replay captured real response-schema records; this is never a production path."""
    receipt = _captured_receipt(slug)
    if slug in {"ledgerbridge", "marketbrief", "backtestguard"}:
        return _source_from_metadata(receipt)
    if slug in {"handoffhub", "onboardpath"}:
        return _opm_source(receipt)
    if slug == "replycraft":
        return _source_from_metadata(receipt)
    if slug == "sentineldesk":
        return _cisa_source(receipt)
    if slug == "pipelinerelay":
        return _github_source(receipt)
    if slug == "searchlift":
        source = receipt["source"]
        # The pinned snapshot intentionally omits raw HTML text. It cannot stand in for a live record.
        return SourceResult(
            provider=source["provider"],
            status="UNVERIFIED",
            request_url=source["source_url"],
            response_status=source["response_status"],
            response_sha256=source["response_sha256"],
            request_body_sha256=source["request_body_sha256"],
            retrieved_at_utc=source["retrieved_at_utc"],
            task_fit=source["task_fit"],
            records=(),
            reason="Captured metrics omit raw response fields; offline snapshot is not a live fallback.",
            read_only=source["read_only"],
        )
    raise AssertionError(f"{slug} has no admitted captured source")


def _with_pii_probe(source: SourceResult, field_path: tuple[str, ...]) -> SourceResult:
    assert source.records, "PII probe requires a captured source record"
    records = list(source.records)
    record = records[0]
    data = copy.deepcopy(dict(record.data))
    container: dict[str, Any] = data
    for part in field_path[:-1]:
        child = container.get(part)
        if not isinstance(child, dict):
            child = {}
            container[part] = child
        container = child
    container[field_path[-1]] = PII_TEXT
    records[0] = replace(record, data=data)
    return replace(source, records=tuple(records))


def _is_test_snapshot_path(file: object, root: Path) -> bool:
    if not isinstance(file, (str, bytes, os.PathLike)):
        return False
    try:
        candidate = Path(os.fsdecode(file)).resolve()
    except (OSError, RuntimeError, TypeError):
        return False
    return candidate == root or root in candidate.parents


def _guard_test_snapshot_reads(
    monkeypatch: pytest.MonkeyPatch, attempted: list[str],
) -> None:
    root = PINNED_REAL_PUBLIC.parent.resolve()

    def reject(file: object) -> None:
        if _is_test_snapshot_path(file, root):
            attempted.append(os.fsdecode(file))
            raise AssertionError("production runner attempted to open adversarial test data")

    original_builtin_open = builtins.open

    def guarded_builtin_open(file: object, *args: object, **kwargs: object) -> Any:
        reject(file)
        return original_builtin_open(file, *args, **kwargs)

    original_io_open = io.open

    def guarded_io_open(file: object, *args: object, **kwargs: object) -> Any:
        reject(file)
        return original_io_open(file, *args, **kwargs)

    original_os_open = os.open

    def guarded_os_open(file: object, *args: object, **kwargs: object) -> int:
        reject(file)
        return original_os_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_builtin_open)
    monkeypatch.setattr(io, "open", guarded_io_open)
    monkeypatch.setattr(os, "open", guarded_os_open)


def _capture_prompts(monkeypatch: pytest.MonkeyPatch, module: object) -> list[str]:
    prompts: list[str] = []
    original = getattr(module, "complete_grounded", None)
    if callable(original):
        def capture(ai_client: object, prompt: str, *args: object, **kwargs: object) -> dict[str, object]:
            prompts.append(str(prompt))
            return original(ai_client, prompt, *args, **kwargs)

        monkeypatch.setattr(module, "complete_grounded", capture)
    return prompts


def _provenance_records(value: object) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if (
            all(isinstance(value.get(key), str) and value[key] for key in ("source_id", "as_of", "retrieved_at_utc"))
            and (isinstance(value.get("terms_url"), str) or isinstance(value.get("terms"), str))
            and value.get("read_only") is True
        ):
            records.append(value)
        for child in value.values():
            records.extend(_provenance_records(child))
    elif isinstance(value, list):
        for child in value:
            records.extend(_provenance_records(child))
    return records


def _assert_honest_failure(receipt: dict[str, Any]) -> None:
    assert receipt["status"] in {"DATA_UNAVAILABLE", "UNVERIFIED"}
    assert receipt["workflow_status"] in {"DATA_UNAVAILABLE", "UNVERIFIED"}
    assert receipt["evidence"] == []
    assert receipt["source_hash"] is None
    assert receipt["side_effect_count"] == 0
    assert receipt["ai_invoked"] is False
    assert receipt.get("ai_evidence") is None
    result = receipt.get("result")
    if result is not None:
        assert isinstance(result, dict)
        assert result.get("status") in {None, "UNVERIFIED", "DATA_UNAVAILABLE"}
        assert all(not result.get(key) for key in _NONEMPTY_RECORD_LISTS)
        assert all(result.get(key, 0) == 0 for key in _COUNT_FIELDS)
    rendered = json.dumps(receipt, sort_keys=True, default=str)
    assert "CANARY" not in rendered.upper()
    assert not re.search(r"tenant-(?:alpha|beta)/", rendered)
    assert '"fixture": true' not in rendered.lower()


def test_runner_cli_calls_each_real_run_live_with_pinned_public_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    model_call_guard: list[str],
) -> None:
    """The normal runner route uses real apps, never demos; all jobs remain UNVERIFIED."""
    called_live: list[str] = []
    called_adapters: dict[str, int] = {}
    called_text_adapters: list[str] = []

    for slug in APP_SLUGS:
        module = importlib.import_module(f"apps.{slug}.flow")
        actual_run_live = module.run_live

        def record_live(*args: object, _slug: str = slug, _run: Any = actual_run_live, **kwargs: object) -> dict[str, Any]:
            called_live.append(_slug)
            return _run(*args, **kwargs)

        monkeypatch.setattr(module, "run_live", record_live)
        if slug not in NO_ADMITTED_SOURCE_APPS:
            def captured_adapter(*args: object, _slug: str = slug, **kwargs: object) -> SourceResult:
                called_adapters[_slug] = called_adapters.get(_slug, 0) + 1
                return _pinned_source(_slug)

            monkeypatch.setattr(module, "fetch_live", captured_adapter)
        if slug == "replycraft":
            def captured_policy_text(record: SourceRecord) -> SourceRecord:
                called_text_adapters.append(record.source_id)
                return _replycraft_text()

            monkeypatch.setattr(module, "fetch_govinfo_opm_text", captured_policy_text)

    output_dir = tmp_path / "runner-receipts"
    exit_code = run_all.main(["--out-dir", str(output_dir)])
    printed = capsys.readouterr().out

    assert exit_code == 1
    assert "INCOMPLETE" in printed
    assert "JSON receipts emitted: 10" in printed
    assert called_live == list(APP_SLUGS)
    assert called_adapters == {slug: 1 for slug in APP_SLUGS if slug not in NO_ADMITTED_SOURCE_APPS}
    assert called_text_adapters == ["2026-19222"]
    assert model_call_guard == []

    receipts = {
        slug: json.loads((output_dir / f"{slug}.json").read_text(encoding="utf-8"))
        for slug in APP_SLUGS
    }
    assert set(receipts) == set(APP_SLUGS)
    for slug, receipt in receipts.items():
        assert receipt["status"] == "UNVERIFIED", f"{slug}: no private data or independent AI proof"
        assert receipt["workflow_status"] == "UNVERIFIED"
        assert receipt["side_effect_count"] == 0
        assert receipt["ai_invoked"] is False
        assert receipt["ai_verification_status"] != "VERIFIED AI"
        handoff = receipt.get("handoff")
        assert isinstance(handoff, dict) and handoff.get("owner") and handoff.get("next_action"), slug
        assert "CANARY" not in json.dumps(receipt, sort_keys=True).upper()

    replycraft = receipts["replycraft"]
    assert replycraft["source_status"] == "VERIFIED_SOURCE"
    assert replycraft["workflow_status"] == "UNVERIFIED"
    assert replycraft["result"]["sample_only"] is True
    assert replycraft["result"]["customer_case"] is False
    assert replycraft["result"]["citations"] == ["2026-19222#DATES"]
    assert replycraft["send_attempted"] is False

    for slug in ADAPTER_APPS - {"searchlift"}:
        receipt = receipts[slug]
        expected = {record.source_id for record in _pinned_source(slug).records}
        surfaced = {record["source_id"] for record in _provenance_records(receipt)}
        assert expected and expected <= surfaced, f"{slug}: captured IDs lost on the runner path"
        provenance = _provenance_records(receipt)
        assert provenance, f"{slug}: source ID/as-of/retrieval/terms projection missing"
        for record in provenance:
            assert record["as_of"]
            retrieved = datetime.fromisoformat(record["retrieved_at_utc"].replace("Z", "+00:00"))
            assert retrieved.utcoffset() == timedelta(0)
            assert (record.get("terms_url") or record.get("terms")).startswith("https://")
            assert record["read_only"] is True

    for slug in NO_ADMITTED_SOURCE_APPS | {"searchlift"}:
        _assert_honest_failure(receipts[slug])


def test_production_runner_never_reads_test_snapshots_or_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    model_call_guard: list[str],
) -> None:
    """ADVERSARIAL REGRESSION ONLY: live failure stays empty without test data."""
    attempted: list[str] = []
    _guard_test_snapshot_reads(monkeypatch, attempted)

    output_dir = tmp_path / "runner-receipts"
    exit_code = run_all.main(["--out-dir", str(output_dir)])
    printed = capsys.readouterr().out
    receipts = {
        slug: json.loads((output_dir / f"{slug}.json").read_text(encoding="utf-8"))
        for slug in APP_SLUGS
    }

    assert attempted == []
    assert exit_code == 1
    assert "Suite status: INCOMPLETE" in printed
    assert set(receipts) == set(APP_SLUGS)
    for receipt in receipts.values():
        _assert_honest_failure(receipt)
    assert model_call_guard == []


@pytest.mark.parametrize("slug", APP_SLUGS, ids=APP_SLUGS)
@pytest.mark.parametrize(
    ("failure_case", "message"),
    (("HTTP403", "HTTP 403 denied"), ("HTTP429", "HTTP 429 rate limited"), ("timeout", "source timeout")),
    ids=("http-403", "http-429", "timeout"),
)
def test_adversarial_live_adapter_failures_never_fall_back(
    slug: str,
    failure_case: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    model_call_guard: list[str],
) -> None:
    """Typed adapter denials/timeouts stay empty; no-adapter apps stay UNVERIFIED."""
    module = importlib.import_module(f"apps.{slug}.flow")
    adapter_calls: list[str] = []

    def fail_at_adapter(*args: object, **kwargs: object) -> SourceResult:
        adapter_calls.append(failure_case)
        raise DataUnavailable(f"ADVERSARIAL REGRESSION ONLY: {message}")

    monkeypatch.setattr(module, "fetch_live", fail_at_adapter, raising=False)
    receipt = run_all._run_one(slug)

    if slug in NO_ADMITTED_SOURCE_APPS:
        assert adapter_calls == []
        assert receipt["status"] == "UNVERIFIED"
    else:
        assert adapter_calls == [failure_case]
        assert receipt["status"] == "DATA_UNAVAILABLE"
    _assert_honest_failure(receipt)
    assert model_call_guard == []


@pytest.mark.parametrize(
    ("slug", "field_path"),
    (
        ("ledgerbridge", ("transaction_catg",)),
        ("marketbrief", ("country", "value")),
        ("backtestguard", ("country", "value")),
        ("handoffhub", ("title",)),
        ("onboardpath", ("title",)),
        ("sentineldesk", ("product",)),
        ("pipelinerelay", ("description",)),
    ),
    ids=("ledger-category", "market-country", "backtest-country", "handoff-title", "onboard-title", "cisa-product", "github-description"),
)
def test_adversarial_live_free_text_pii_is_not_exposed_or_prompted(
    slug: str,
    field_path: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    model_call_guard: list[str],
) -> None:
    """ADVERSARIAL REGRESSION ONLY: name/address probes must be minimized at live boundaries."""
    module = importlib.import_module(f"apps.{slug}.flow")
    captured_prompts = _capture_prompts(monkeypatch, module)
    probed_source = _with_pii_probe(_pinned_source(slug), field_path)
    adapter_calls: list[int] = []

    def return_probed_record(*args: object, **kwargs: object) -> SourceResult:
        adapter_calls.append(1)
        return probed_source

    monkeypatch.setattr(module, "fetch_live", return_probed_record)
    receipt = run_all._run_one(slug)
    exposed = json.dumps(receipt, sort_keys=True, default=str) + "\n".join(captured_prompts)

    assert adapter_calls == [1]
    assert PII_NAME not in exposed
    assert PII_ADDRESS not in exposed
    assert "CANARY" not in exposed.upper()
    assert receipt["side_effect_count"] == 0
    assert receipt["ai_invoked"] is False
    assert model_call_guard == []
