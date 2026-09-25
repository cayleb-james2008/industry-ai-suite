"""CISA KEV catalog schema, identity, date, and projection checks."""

from __future__ import annotations

from datetime import date

from . import core


def parse(payload, source_url, response, response_hash, retrieved_at, task_fit):
    catalog = core._mapping(payload, "CISA KEV")
    vulnerabilities = core._list(catalog.get("vulnerabilities"), "CISA vulnerabilities")
    core._check_record_count(core.Provider.CISA_KEV, len(vulnerabilities))
    records = []
    for item in vulnerabilities:
        row = core._mapping(item, "CISA vulnerability")
        cve = row.get("cveID")
        date_added = core._as_date(row.get("dateAdded"))
        due_date = core._as_date(row.get("dueDate"))
        if not isinstance(cve, str) or not core.re.fullmatch(r"CVE-\d{4}-\d{4,8}", cve):
            raise core.DataUnavailable("CISA record is missing a valid CVE identifier")
        record = core._record(
            core.Provider.CISA_KEV, cve, source_url, response, response_hash,
            retrieved_at, core._TERMS[core.Provider.CISA_KEV], task_fit,
            date_added, "day", row,
        )
        projected_data = dict(record.data)
        projected_data.update(dateAdded=date_added, dueDate=due_date)
        records.append(core.replace(record, data=projected_data))
    newest_added = max(date.fromisoformat(record.as_of) for record in records)
    core._check_day_freshness(
        newest_added, retrieved_at,
        core._SOURCE_MAX_AGE_DAYS[core.Provider.CISA_KEV],
        "newest CISA dateAdded",
    )
    return tuple(records)
