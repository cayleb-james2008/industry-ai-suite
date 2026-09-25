"""Compatibility facade for the source-family package.

Keep this path stable for existing applications and tests. HTTP and parsing
implementation lives under ``suite_core.sources``.
"""

from __future__ import annotations

from .sources import core as _core
from .sources.core import (
    MAX_RESPONSE_BYTES,
    MAX_TIMEOUT_SECONDS,
    DataUnavailable,
    LiveSourceError,
    Provider,
    SourceRecord,
    SourceResult,
    TaskFit,
    UnverifiedSource,
    _HTTPResponse,
    _UrllibTransport,
    govinfo_opm_url,
)


def _retrieved_at() -> str:
    """Compatibility clock hook used by existing deterministic source tests."""
    return _core._retrieved_at()


def _fetch_with_transport(
    provider: Provider,
    *,
    task_fit: TaskFit | None,
    owner: str | None,
    repo: str | None,
    timeout: float,
    transport: _core._Transport,
) -> SourceResult:
    return _core._fetch_with_transport(
        provider,
        task_fit=task_fit,
        owner=owner,
        repo=repo,
        timeout=timeout,
        transport=transport,
        _clock=_retrieved_at,
    )


def fetch_live(
    provider: Provider,
    *,
    task_fit: TaskFit | None,
    owner: str | None = None,
    repo: str | None = None,
    timeout: float = 5.0,
) -> SourceResult:
    """Use the preserved no-redirect transport through the old import path."""
    return _core._fetch_with_transport(
        provider,
        task_fit=task_fit,
        owner=owner,
        repo=repo,
        timeout=timeout,
        transport=_UrllibTransport(),
        _clock=_retrieved_at,
    )


def fetch_govinfo_opm_text(record: SourceRecord, *, timeout: float = 5.0) -> SourceRecord:
    return _core.fetch_govinfo_opm_text(
        record, timeout=timeout, transport=_UrllibTransport(), _clock=_retrieved_at
    )


def fetch_federal_register_opm_text(record: SourceRecord, *, timeout: float = 5.0) -> SourceRecord:
    """Compatibility spelling for a direct no-redirect Federal Register read."""
    return _core.fetch_federal_register_opm_text(
        record, timeout=timeout, transport=_UrllibTransport(), _clock=_retrieved_at
    )


__all__ = [
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "DataUnavailable",
    "LiveSourceError",
    "Provider",
    "SourceRecord",
    "SourceResult",
    "TaskFit",
    "UnverifiedSource",
    "fetch_live",
    "fetch_federal_register_opm_text",
    "fetch_govinfo_opm_text",
    "govinfo_opm_url",
]
