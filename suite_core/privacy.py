"""PII and credential minimization for values crossing ordinary log/output paths."""

import re
from collections.abc import Mapping

_SENSITIVE_KEYS = {
    "email", "phone", "mobile", "ssn", "socialsecurity", "password", "secret", "token",
    "credential", "apikey", "address", "dateofbirth", "dob", "name", "fullname",
    "personname", "accountnumber", "ipaddress", "birthdate", "nationalid",
}
_KEY_PARTS = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|[^A-Za-z0-9]+")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\w)\+?\d[\d .()-]{7,}\d(?!\w)")
_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z0-9.'-]+\s+){0,4}"
    r"(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct|way)\b",
    re.IGNORECASE,
)


def _is_sensitive_key(key: object) -> bool:
    text = str(key)
    normalized = re.sub(r"[^a-z0-9]", "", text.lower())
    parts = (re.sub(r"[^a-z0-9]", "", part.lower()) for part in _KEY_PARTS.split(text))
    return normalized in _SENSITIVE_KEYS or any(part in _SENSITIVE_KEYS for part in parts)


def redact(value: object) -> object:
    """Return a new, recursively redacted value without mutating caller data."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _PHONE.sub("[REDACTED]", _EMAIL.sub("[REDACTED]", value))
    return value


def contains_likely_personal_data(value: str) -> bool:
    """Flag contact details and numbered street addresses in free-text source labels.

    This is a narrow fail-closed heuristic, not named-entity recognition: it does
    not reliably identify a person's name when the name appears without contact
    or address context. Callers should minimize fields they do not need rather
    than treating this check as proof that arbitrary prose is safe.
    """
    return bool(_EMAIL.search(value) or _PHONE.search(value) or _STREET_ADDRESS.search(value))


def project_source_metadata(
    metadata: Mapping[str, object], *, record_data_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    """Keep source provenance while dropping unapproved free-text record data.

    An empty allowlist removes record ``data`` entirely. A non-empty allowlist
    copies only those fields; callers still must validate that the retained
    values match their expected types and meaning. This projection is not PII
    detection and does not inspect URLs or other provenance values.
    """
    projected = {key: value for key, value in metadata.items() if key != "reason"}
    records = projected.get("records")
    if not isinstance(records, (list, tuple)):
        return projected

    safe_records = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        safe_record = dict(record)
        data = safe_record.get("data")
        if record_data_fields:
            safe_record["data"] = {
                key: data[key]
                for key in record_data_fields
                if isinstance(data, Mapping) and key in data
            }
        else:
            safe_record.pop("data", None)
        safe_records.append(safe_record)
    projected["records"] = safe_records
    return projected
