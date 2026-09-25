"""Bounded source-family parsers and the shared read-only HTTP boundary."""

from .core import (
    MAX_RESPONSE_BYTES,
    MAX_TIMEOUT_SECONDS,
    DataUnavailable,
    LiveSourceError,
    Provider,
    SourceRecord,
    SourceResult,
    TaskFit,
    UnverifiedSource,
    fetch_live,
    fetch_federal_register_opm_text,
    fetch_govinfo_opm_text,
    govinfo_opm_url,
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
