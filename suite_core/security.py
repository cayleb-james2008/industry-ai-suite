"""Expiry-checked authentication and tenant/role/evidence authorization."""

import re
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass

from .audit import AuditLog
from .tokens import HMACTokenCodec, TokenError

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _valid_ids(values: object) -> bool:
    return (isinstance(values, Collection) and not isinstance(values, (str, bytes))
            and all(_valid_id(value) for value in values))


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    role: str


class AccessDenied(ValueError):
    """Authentication or authorization failed; message intentionally reveals no detail."""


class Authenticator:
    """Issue and verify short-lived tenant-scoped role claims."""

    def __init__(self, codec: HMACTokenCodec) -> None:
        self._codec = codec

    def issue(self, principal: Principal, *, expires_at: int) -> str:
        if not all(_valid_id(value) for value in (principal.tenant_id, principal.actor_id, principal.role)):
            raise TokenError("principal identifiers must be opaque safe IDs")
        if type(expires_at) is not int:
            raise TokenError("expiry must be an integer timestamp")
        return self._codec.sign(
            {"v": 1, "tenant": principal.tenant_id, "actor": principal.actor_id,
             "role": principal.role, "exp": expires_at}
        )

    def verify(self, token: str, *, now: int | None = None) -> Principal:
        claims = self._codec.verify(token)
        if set(claims) != {"v", "tenant", "actor", "role", "exp"}:
            raise TokenError("invalid signed token")
        if claims["v"] != 1 or type(claims["exp"]) is not int:
            raise TokenError("invalid signed token")
        if claims["exp"] <= (int(time.time()) if now is None else now):
            raise TokenError("expired signed token")
        tenant, actor, role = claims["tenant"], claims["actor"], claims["role"]
        if not all(_valid_id(value) for value in (tenant, actor, role)):
            raise TokenError("invalid signed token")
        return Principal(tenant_id=tenant, actor_id=actor, role=role)


class AccessPolicy:
    """Explicit per-tenant role/evidence allowlists plus per-role action allowlists."""

    def __init__(
        self,
        tenant_role_evidence: Mapping[str, Mapping[str, Collection[str]]],
        role_actions: Mapping[str, Collection[str]],
    ) -> None:
        self._tenant_role_evidence: dict[str, dict[str, frozenset[str]]] = {}
        for tenant, roles in tenant_role_evidence.items():
            if not _valid_id(tenant):
                raise ValueError("tenant IDs must be opaque safe IDs")
            self._tenant_role_evidence[tenant] = {}
            for role, evidence in roles.items():
                if not _valid_id(role) or not _valid_ids(evidence):
                    raise ValueError("role and evidence IDs must be opaque safe IDs")
                self._tenant_role_evidence[tenant][role] = frozenset(evidence)
        self._role_actions: dict[str, frozenset[str]] = {}
        for role, actions in role_actions.items():
            if not _valid_id(role) or not _valid_ids(actions) or not actions:
                raise ValueError("roles and allowed actions must be explicit safe IDs")
            self._role_actions[role] = frozenset(actions)

    def check(self, principal: Principal, action: str, evidence_ids: Collection[str]) -> None:
        roles = self._tenant_role_evidence.get(principal.tenant_id, {})
        allowlisted = roles.get(principal.role)
        if allowlisted is None or action not in self._role_actions.get(principal.role, frozenset()):
            raise AccessDenied("request denied")
        if not _valid_ids(evidence_ids):
            raise AccessDenied("request denied")
        requested = set(evidence_ids)
        if len(requested) != len(evidence_ids) or not all(_valid_id(item) for item in requested):
            raise AccessDenied("request denied")
        if not requested.issubset(allowlisted):
            raise AccessDenied("request denied")


class SecurityCore:
    """Authorize before work; denied requests produce a minimal denial receipt."""

    def __init__(self, authenticator: Authenticator, policy: AccessPolicy, audit: AuditLog) -> None:
        self.authenticator = authenticator
        self.policy = policy
        self.audit = audit

    def authorize(
        self, token: str, *, tenant_id: str, action: str, evidence_ids: Collection[str] = ()
    ) -> Principal:
        principal: Principal | None = None
        try:
            principal = self.authenticator.verify(token)
            if principal.tenant_id != tenant_id:
                raise AccessDenied("request denied")
            self.policy.check(principal, action, evidence_ids)
        except (TokenError, AccessDenied):
            self.audit.record(
                actor_id=principal.actor_id if principal else "unknown",
                tenant_id=tenant_id,
                role=principal.role if principal else "unknown",
                action=action,
                evidence_ids=(),
                approval=False,
                outcome="denied",
            )
            raise AccessDenied("request denied") from None
        self.audit.record(
            actor_id=principal.actor_id,
            tenant_id=principal.tenant_id,
            role=principal.role,
            action=action,
            evidence_ids=evidence_ids,
            approval=False,
            outcome="allowed",
        )
        return principal
