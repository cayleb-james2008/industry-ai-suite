"""Private, minimized workbench receipt history with atomic file replacement."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from suite_core import redact
from suite_core.privacy import project_source_metadata

_RECEIPT_ID = re.compile(r"[0-9a-f]{32}\Z")
_EVIDENCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_HISTORY_BYTES = 16 * 1024 * 1024
_MAX_RECORDS = 1000
_REVIEW_STATUSES = {"REVIEWED", "CHANGES_REQUESTED"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"title": "Local organization review", "findings": [], "metrics": []}
    title = value.get("title")
    findings = value.get("findings")
    metrics = value.get("metrics")
    return {
        "title": str(redact(title))[:200] if isinstance(title, str) else "Local organization review",
        "findings": [str(redact(item))[:800] for item in findings[:20] if isinstance(item, str)]
        if isinstance(findings, list) else [],
        "metrics": [
            {"label": str(redact(item["label"]))[:80], "value": redact(item["value"])}
            for item in metrics[:12]
            if isinstance(item, dict) and isinstance(item.get("label"), str)
            and isinstance(item.get("value"), (str, int, float, bool))
        ] if isinstance(metrics, list) else [],
    }


def minimized_receipt(receipt: dict[str, object], receipt_id: str | None = None) -> dict[str, object]:
    """Keep provenance and review output; omit submitted bundles and task records."""
    summary = _safe_summary(receipt.get("review_summary"))
    source_metadata = receipt.get("source_metadata")
    safe_source = project_source_metadata(source_metadata) if isinstance(source_metadata, dict) else {}
    evidence = receipt.get("evidence_ids")
    evidence_ids = [item for item in evidence if isinstance(item, str) and _EVIDENCE_ID.fullmatch(item)][:200] if isinstance(evidence, list) else []
    answer = receipt.get("local_ai_output")
    answer_ids = receipt.get("local_ai_evidence_ids")
    valid_answer_ids = [item for item in answer_ids if isinstance(item, str) and _EVIDENCE_ID.fullmatch(item)][:200] if isinstance(answer_ids, list) else []
    handoff = receipt.get("human_handoff")
    safe_handoff = {
        key: str(redact(handoff[key]))[:500]
        for key in ("owner", "owner_type", "next_action")
        if isinstance(handoff, dict) and isinstance(handoff.get(key), str)
    }
    record: dict[str, object] = {
        "receipt_id": receipt_id or secrets.token_hex(16),
        "created_at_utc": _utc_now(),
        "project": str(receipt.get("project", ""))[:40],
        "input_mode": "enterprise",
        "status": str(receipt.get("status", "UNVERIFIED")),
        "source_status": str(receipt.get("source_status", "UNVERIFIED")),
        "workflow_status": str(receipt.get("workflow_status", "LOCAL REVIEW ONLY / ENTERPRISE UNVERIFIED")),
        "local_processing_status": str(receipt.get("local_processing_status", "PARTIAL")),
        "local_processing_reason": str(redact(receipt.get("local_processing_reason", "")))[:500],
        "human_review_status": "PENDING",
        "ai_status": str(receipt.get("ai_status", "NOT RUN"))[:120],
        "ai_invoked": receipt.get("ai_invoked") is True,
        "local_ai_output": str(redact(answer))[:4000] if isinstance(answer, str) else None,
        "local_ai_evidence_ids": valid_answer_ids,
        "local_ai_model": str(redact(receipt.get("local_ai_model")))[:256] if isinstance(receipt.get("local_ai_model"), str) else None,
        "review_summary": summary,
        "source_metadata": safe_source,
        "evidence_ids": evidence_ids,
        "uncertainty": str(redact(receipt.get("uncertainty", "")))[:1000],
        "human_handoff": safe_handoff,
        "side_effect_count": receipt.get("side_effect_count") if type(receipt.get("side_effect_count")) is int else 0,
    }
    return record


class LocalReceiptStore:
    """One private JSON history file; a failed write leaves the previous file intact."""

    def __init__(self, directory: str | Path | None = None) -> None:
        if directory is None:
            state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
            directory = state_home / "industry-ai-suite" / "workbench"
        self.directory = Path(directory)
        self.path = self.directory / "receipts.json"
        self._lock = threading.RLock()

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = self.directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise OSError("local receipt directory must be private and user-owned")

    def _read(self) -> list[dict[str, object]]:
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return []
        except OSError as error:
            raise OSError("local receipt history could not be opened safely") from error
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or metadata.st_size > _MAX_HISTORY_BYTES):
                raise OSError("local receipt history is not a private user-owned file")
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                raw = source.read(_MAX_HISTORY_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > _MAX_HISTORY_BYTES:
            raise OSError("local receipt history exceeds its size limit")
        try:
            records = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as error:
            raise OSError("local receipt history is malformed; no record was changed") from error
        if not isinstance(records, list) or len(records) > _MAX_RECORDS or any(not isinstance(item, dict) for item in records):
            raise OSError("local receipt history has an unsupported format")
        return records

    def _write(self, records: list[dict[str, object]]) -> None:
        encoded = (json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        if len(encoded) > _MAX_HISTORY_BYTES:
            raise OSError("local receipt history has reached its size limit; delete an older receipt first")
        descriptor = -1
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=".receipts-", suffix=".tmp", dir=self.directory)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                descriptor = -1
                target.write(encoded)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            temporary = None
            directory_fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            self._ensure_directory()
            return list(reversed(self._read()))

    def save(self, receipt: dict[str, object]) -> dict[str, object]:
        with self._lock:
            self._ensure_directory()
            records = self._read()
            if len(records) >= _MAX_RECORDS:
                raise OSError("local receipt history is full; delete an older receipt first")
            record = minimized_receipt(receipt)
            records.append(record)
            self._write(records)
            return record

    def review(self, receipt_id: str, status: str) -> dict[str, object]:
        if (not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id)
                or not isinstance(status, str) or status not in _REVIEW_STATUSES):
            raise ValueError("unsupported review update")
        with self._lock:
            self._ensure_directory()
            records = self._read()
            for record in records:
                if record.get("receipt_id") == receipt_id:
                    record["human_review_status"] = status
                    record["reviewed_at_utc"] = _utc_now()
                    self._write(records)
                    return record
            raise KeyError("receipt not found")

    def delete(self, receipt_id: str) -> None:
        if not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
            raise ValueError("unsupported receipt ID")
        with self._lock:
            self._ensure_directory()
            records = self._read()
            remaining = [record for record in records if record.get("receipt_id") != receipt_id]
            if len(remaining) == len(records):
                raise KeyError("receipt not found")
            self._write(remaining)
