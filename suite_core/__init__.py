"""Shared security and integration primitives for the Industry AI Suite."""

from .approval import ApprovalAuthority, ApprovalError, SimulatedSink
from .audit import AuditLog
from .fixtures import FixtureAdapter, FixtureData, FixtureError, FixtureSchema
from .live_sources import (
    DataUnavailable,
    LiveSourceError,
    Provider,
    SourceRecord,
    SourceResult,
    TaskFit,
    UnverifiedSource,
    fetch_live,
)
from .grounding import (
    GroundedOutput,
    GroundedOutputValidator,
    PromptInjectionError,
    PromptSentinel,
    UnsafeModelOutput,
)
from .model import LocalOpenAIClient, ModelResult, ModelStatus, ModelUnavailable, NonAIFallback
from .privacy import redact
from .security import AccessDenied, AccessPolicy, Authenticator, Principal, SecurityCore
from .tokens import HMACTokenCodec, TokenError

__all__ = [
    "AccessDenied",
    "AccessPolicy",
    "ApprovalAuthority",
    "ApprovalError",
    "AuditLog",
    "Authenticator",
    "FixtureAdapter",
    "FixtureData",
    "FixtureError",
    "FixtureSchema",
    "DataUnavailable",
    "GroundedOutput",
    "GroundedOutputValidator",
    "HMACTokenCodec",
    "LocalOpenAIClient",
    "LiveSourceError",
    "ModelResult",
    "ModelStatus",
    "ModelUnavailable",
    "NonAIFallback",
    "Principal",
    "PromptInjectionError",
    "PromptSentinel",
    "Provider",
    "SecurityCore",
    "SimulatedSink",
    "SourceRecord",
    "SourceResult",
    "TaskFit",
    "TokenError",
    "UnverifiedSource",
    "UnsafeModelOutput",
    "fetch_live",
    "redact",
]
