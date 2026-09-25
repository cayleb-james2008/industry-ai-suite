"""Explicit human approval tokens and an in-memory sink with no external side effects."""

import hashlib
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass

from .audit import AuditLog
from .security import AccessDenied, Principal, SecurityCore, _valid_id, _valid_ids
from .tokens import HMACTokenCodec, TokenError


class ApprovalError(ValueError):
    """Approval is absent, invalid, expired, or outside its exact scope."""


class ApprovalAuthority:
    """Mint exact-scope tokens from an authenticated approver allowed to approve."""

    def __init__(
        self,
        codec: HMACTokenCodec,
        approver_roles: Collection[str] = ("approver",),
        *,
        security_core: SecurityCore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._codec = codec
        self._security_core = security_core
        self._clock = time.time if clock is None else clock
        self._approver_roles = frozenset(approver_roles)
        self._consumed_tokens: dict[str, int] = {}
        self._consumed_lock = threading.Lock()
        if not _valid_ids(approver_roles) or not self._approver_roles:
            raise ValueError("explicit approver roles are required")

    def issue(
        self,
        approver_token: str,
        *,
        tenant_id: str,
        requester_actor: str,
        action: str,
        evidence_ids: Collection[str],
        expires_at: int,
        confirmed: bool,
    ) -> str:
        if self._security_core is None:
            raise ApprovalError("approval denied")
        if (confirmed is not True or not _valid_ids(evidence_ids) or not evidence_ids
                or not all(_valid_id(value) for value in (tenant_id, requester_actor, action, *evidence_ids))
                or type(expires_at) is not int or expires_at <= int(self._clock())
                or len(set(evidence_ids)) != len(evidence_ids)):
            self._record_denial(tenant_id, action)
            raise ApprovalError("approval denied")
        try:
            approver = self._security_core.authorize(
                approver_token, tenant_id=tenant_id, action="approve", evidence_ids=evidence_ids,
            )
        except AccessDenied:
            raise ApprovalError("approval denied") from None
        if approver.actor_id == requester_actor or approver.role not in self._approver_roles:
            self._record_denial(tenant_id, action)
            raise ApprovalError("approval denied")
        return self._codec.sign(
            {"kind": "human-approval-v1", "tenant": tenant_id,
             "approver": approver.actor_id, "role": approver.role,
             "requester": requester_actor, "action": action,
             "evidence": sorted(evidence_ids), "exp": expires_at}
        )

    def verify(
        self,
        token: str,
        *,
        tenant_id: str,
        requester_actor: str,
        action: str,
        evidence_ids: Collection[str],
    ) -> Principal:
        try:
            claims = self._codec.verify(token)
        except TokenError as exc:
            raise ApprovalError("approval denied") from exc
        if not _valid_ids(evidence_ids) or not evidence_ids:
            raise ApprovalError("approval denied")
        current_time = int(self._clock())
        expected_evidence = sorted(evidence_ids)
        if (set(claims) != {"kind", "tenant", "approver", "role", "requester", "action", "evidence", "exp"}
                or claims.get("kind") != "human-approval-v1"
                or claims.get("tenant") != tenant_id
                or claims.get("requester") != requester_actor
                or claims.get("action") != action
                or claims.get("evidence") != expected_evidence
                or claims.get("role") not in self._approver_roles
                or type(claims.get("exp")) is not int
                or claims["exp"] <= current_time
                or not _valid_id(claims.get("approver"))
                or claims.get("approver") == requester_actor):
            raise ApprovalError("approval denied")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._consumed_lock:
            self._consumed_tokens = {
                digest: expiry for digest, expiry in self._consumed_tokens.items()
                if expiry > current_time
            }
            if token_hash in self._consumed_tokens:
                raise ApprovalError("approval denied")
            self._consumed_tokens[token_hash] = claims["exp"]
        return Principal(tenant_id=tenant_id, actor_id=claims["approver"], role=claims["role"])

    def _record_denial(self, tenant_id: str, action: str) -> None:
        if self._security_core is None:
            return
        self._security_core.audit.record(
            actor_id="unknown", tenant_id=tenant_id, role="unknown", action=action,
            evidence_ids=(), approval=False, outcome="denied",
        )


@dataclass(frozen=True)
class SimulatedReceipt:
    tenant_id: str
    requester: str
    approved_by: str
    action: str
    evidence_ids: tuple[str, ...]
    status: str = "SIMULATED ONLY"


class SimulatedSink:
    """Records approved intent in memory; it has no network, file, or external adapter."""

    def __init__(self, authority: ApprovalAuthority, audit: AuditLog,
                 allowed_actions: Collection[str]) -> None:
        self._authority = authority
        self._audit = audit
        self._allowed_actions = frozenset(allowed_actions)
        self._receipts: list[SimulatedReceipt] = []
        if not _valid_ids(allowed_actions) or not self._allowed_actions:
            raise ValueError("simulated sink actions must be explicit safe IDs")

    @property
    def receipts(self) -> tuple[SimulatedReceipt, ...]:
        return tuple(self._receipts)

    def execute(self, requester: Principal, *, action: str, evidence_ids: Collection[str],
                approval_token: str | None) -> SimulatedReceipt:
        if action not in self._allowed_actions or not approval_token:
            self._record_denial(requester, action)
            raise ApprovalError("approval denied")
        try:
            approver = self._authority.verify(
                approval_token, tenant_id=requester.tenant_id, requester_actor=requester.actor_id,
                action=action, evidence_ids=evidence_ids,
            )
        except ApprovalError:
            self._record_denial(requester, action)
            raise ApprovalError("approval denied") from None
        receipt = SimulatedReceipt(
            tenant_id=requester.tenant_id, requester=requester.actor_id,
            approved_by=approver.actor_id, action=action, evidence_ids=tuple(sorted(evidence_ids)),
        )
        self._audit.record(
            actor_id=requester.actor_id, tenant_id=requester.tenant_id, role=requester.role,
            action=action, evidence_ids=evidence_ids, approval=True,
            approved_by=approver.actor_id, outcome="simulated",
        )
        self._receipts.append(receipt)
        return receipt

    def _record_denial(self, requester: Principal, action: str) -> None:
        self._audit.record(
            actor_id=requester.actor_id, tenant_id=requester.tenant_id, role=requester.role,
            action=action, evidence_ids=(), approval=False, outcome="denied",
        )
