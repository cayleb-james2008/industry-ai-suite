"""Append-only, minimal JSONL audit receipts; arbitrary inputs and credentials are excluded."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterable

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
_PHONE_ID = re.compile(r"^\+?\d[\d .()-]{7,}\d$")


def _identifier(value: str | None) -> str:
    return value if (isinstance(value, str) and _SAFE_ID.fullmatch(value)
                     and "@" not in value and not _PHONE_ID.fullmatch(value)) else "redacted"


class AuditLog:
    """Append only fixed-field receipts. A failed write fails the protected operation closed."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(
        self,
        *,
        actor_id: str | None,
        tenant_id: str | None,
        role: str | None,
        action: str,
        evidence_ids: Iterable[str] = (),
        approval: bool = False,
        approved_by: str | None = None,
        outcome: str,
    ) -> dict[str, object]:
        if outcome not in {"allowed", "denied", "simulated"} or type(approval) is not bool:
            raise ValueError("invalid audit outcome")
        ids = (sorted({_identifier(item) for item in evidence_ids})
               if not isinstance(evidence_ids, (str, bytes)) else ["redacted"])
        event: dict[str, object] = {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "actor": _identifier(actor_id),
            "tenant": _identifier(tenant_id),
            "role": _identifier(role),
            "action": _identifier(action),
            "evidence": ids,
            "approval": approval,
            "approved_by": _identifier(approved_by) if approved_by else None,
            "outcome": outcome,
        }
        encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OSError("incomplete audit append")
        finally:
            os.close(descriptor)
        return event

    def records(self) -> tuple[dict[str, object], ...]:
        if not self.path.exists():
            return ()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        records = tuple(json.loads(line) for line in lines if line)
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("audit log contains an invalid record")
        return records
