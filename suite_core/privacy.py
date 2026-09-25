"""PII and credential minimization for values crossing ordinary log/output paths."""

import re
from collections.abc import Mapping

_SENSITIVE_KEYS = {
    "email", "phone", "mobile", "ssn", "socialsecurity", "password", "secret", "token",
    "credential", "apikey", "key", "authorization", "auth", "cookie", "setcookie",
    "address", "dateofbirth", "dob", "name", "fullname", "personname", "accountnumber",
    "acctnumber", "routingnumber", "creditcard", "cardnumber", "iban", "ipaddress",
    "birthdate", "nationalid",
}
_KEY_PARTS = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|[^A-Za-z0-9]+")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<!CVE-)(?<!\w)\+?\d[\d .()-]{7,}\d(?!\w)", re.IGNORECASE)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_ACCOUNT_NUMBER = re.compile(
    r"\b(?:account|acct|routing|iban|card)\s*(?:number|no\.?|#)\s*[:=]?\s*"
    r"[A-Z0-9][A-Z0-9 -]{4,32}[A-Z0-9]\b",
    re.IGNORECASE,
)
_SECRET_QUERY = re.compile(
    r"([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|token|secret|password|code)=)"
    r"[^&#\s]+",
    re.IGNORECASE,
)
_SECRET_FRAGMENT = re.compile(
    r"(#(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|token|secret|password|code)=)"
    r"[^&#\s]+",
    re.IGNORECASE,
)
_URL_USERINFO = re.compile(
    r"(\b[A-Za-z][A-Za-z0-9+.-]*://)[^/@\s:]+:[^/@\s]*@",
    re.IGNORECASE,
)
_SECRET_HEADER = re.compile(
    r"\b(?:authorization|proxy-authorization|x-api-key|api[-_]?key|x-auth-token|"
    r"access[-_]?token|refresh[-_]?token)\s*:\s*(?:bearer\s+)?[^\r\n,;]+",
    re.IGNORECASE,
)
_BEARER_TOKEN = re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}={0,2}", re.IGNORECASE)
_SERVICE_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_PERSON_NAME = re.compile(
    r"\b[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?\s+"
    r"[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?"
    r"(?:\s+[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?)?\b"
)
_LABELED_PERSON_NAME = re.compile(
    r"\b(?:name|customer|client|employee|contact|person|applicant|owner|author|reviewer)"
    r"(?:\s*[:=]\s*|\s+)([A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?"
    r"(?:\s+[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?){1,2})\b",
    re.IGNORECASE,
)
_SAFE_PROPER_NAMES = {
    "arista velocloud", "arista velocloud orchestrator", "cisa known exploited vulnerabilities", "excepted service",
    "example vendor", "federal register", "federal register opm", "office of personnel management",
    "open source", "proposed rule", "united states", "windows server", "world bank",
    "world bank usa",
}
_PERSON_BEARING_FIELDS = {
    "person", "personname", "fullname", "firstname", "lastname", "givenname", "familyname",
    "customer", "customername", "client", "clientname", "employee", "employeename",
    "contact", "contactname", "applicant", "applicantname", "author", "authorname",
    "reviewer", "reviewername", "recipient", "recipientname",
}
_PROVENANCE_LABEL_FIELDS = {
    "provider", "source", "sourcelabel", "sourcename", "sourcetitle", "publisher",
    "publishername", "organization", "organizationname", "agency", "agencyname",
}
_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z0-9.'-]+\s+){0,4}"
    r"(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct|way)\b",
    re.IGNORECASE,
)


def _normalized_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _is_sensitive_key(key: object) -> bool:
    text = str(key)
    normalized = _normalized_key(text)
    parts = (re.sub(r"[^a-z0-9]", "", part.lower()) for part in _KEY_PARTS.split(text))
    return normalized in _SENSITIVE_KEYS or any(part in _SENSITIVE_KEYS for part in parts)


def _is_likely_person_name(value: str) -> bool:
    return " ".join(value.casefold().split()) not in _SAFE_PROPER_NAMES


def _has_phone(value: str) -> bool:
    return any(not _ISO_DATE.fullmatch(match.group(0)) for match in _PHONE.finditer(value))


def redact(value: object) -> object:
    """Return a new, recursively redacted value without mutating caller data."""
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]" if _is_sensitive_key(key)
                or (_normalized_key(key) in _PERSON_BEARING_FIELDS and isinstance(item, str))
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(value: str) -> str:
    value = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = _SECRET_HEADER.sub("[REDACTED]", value)
    value = _SECRET_QUERY.sub(r"\1[REDACTED]", value)
    value = _SECRET_FRAGMENT.sub(r"\1[REDACTED]", value)
    value = _BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    value = _SERVICE_TOKEN.sub("[REDACTED]", value)
    value = _ACCOUNT_NUMBER.sub("[REDACTED]", value)
    value = _EMAIL.sub("[REDACTED]", value)
    value = _PHONE.sub(
        lambda match: match.group(0) if _ISO_DATE.fullmatch(match.group(0)) else "[REDACTED]",
        value,
    )
    value = _STREET_ADDRESS.sub("[REDACTED]", value)
    value = _PERSON_NAME.sub(
        lambda match: "[REDACTED]" if _is_likely_person_name(match.group(0)) else match.group(0),
        value,
    )
    return _LABELED_PERSON_NAME.sub(
        lambda match: match.group(0).replace(match.group(1), "[REDACTED]"), value,
    )


def contains_likely_personal_data(value: str) -> bool:
    """Flag recognizable PII patterns in free-text source labels.

    This conservative heuristic is not named-entity recognition. It flags
    likely title-case human names, explicitly labeled names, contact/credential
    patterns, account numbers, and numbered street addresses; applications must
    still minimize source fields instead of treating a clean result as proof
    that prose is safe.
    """
    name_match = any(_is_likely_person_name(match.group(0)) for match in _PERSON_NAME.finditer(value))
    return bool(
        name_match or _EMAIL.search(value) or _has_phone(value)
        or _ACCOUNT_NUMBER.search(value) or _STREET_ADDRESS.search(value)
        or _SECRET_QUERY.search(value) or _SECRET_FRAGMENT.search(value)
        or _URL_USERINFO.search(value) or _SECRET_HEADER.search(value)
        or _BEARER_TOKEN.search(value) or _SERVICE_TOKEN.search(value)
        or _LABELED_PERSON_NAME.search(value)
    )


def project_source_metadata(
    metadata: Mapping[str, object], *, record_data_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    """Keep source provenance while dropping unapproved free-text record data.

    An empty allowlist removes record ``data`` entirely. A non-empty allowlist
    copies only those fields. Declared ID/hash fields and source-label fields
    retain their exact scalar values; other values follow the ordinary redaction
    policy, including URL credentials and person-bearing field roles.
    """
    def project_field(key: object, value: object) -> object:
        normalized = _normalized_key(key)
        if normalized in _PROVENANCE_LABEL_FIELDS and isinstance(value, str):
            return value
        if (_is_sensitive_key(key) and normalized not in _PROVENANCE_LABEL_FIELDS):
            return "[REDACTED]"
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            if normalized.endswith("id") or normalized in {"sha", "sha256", "commitsha", "hash"}:
                return value
        return redact(value)

    projected: dict[str, object] = {}
    for key, value in metadata.items():
        if key == "reason":
            continue
        if key != "records" or not isinstance(value, (list, tuple)):
            projected[str(key)] = project_field(key, value)
            continue

        safe_records = []
        for record in value:
            if not isinstance(record, Mapping):
                continue
            safe_record: dict[str, object] = {}
            for field, item in record.items():
                if field == "data":
                    if record_data_fields and isinstance(item, Mapping):
                        safe_record["data"] = {
                            name: project_field(name, item[name])
                            for name in record_data_fields if name in item
                        }
                else:
                    safe_record[str(field)] = project_field(field, item)
            safe_records.append(safe_record)
        projected["records"] = safe_records
    return projected
