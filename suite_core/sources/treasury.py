"""U.S. Treasury FiscalData DTS row validation and projection."""

from __future__ import annotations

from datetime import date
from . import core


def parse(payload, source_url, response, response_hash, retrieved_at, task_fit):
    data = core._list(core._mapping(payload, "Treasury").get("data"), "Treasury data")
    core._check_record_count(core.Provider.TREASURY_DTS, len(data))
    terms = core._TERMS[core.Provider.TREASURY_DTS]
    records = []
    for row_value in data:
        row = core._mapping(row_value, "Treasury record")
        record_date = core._as_date(row.get("record_date"))
        table = row.get("table_nbr")
        line = row.get("src_line_nbr", row.get("source_line_nbr", row.get("line_nbr")))
        if table is None or line is None:
            raise core.DataUnavailable("Treasury record is missing its stable row identity")
        records.append(core._record(
            core.Provider.TREASURY_DTS, f"{record_date}:{table}:{line}", source_url,
            response, response_hash, retrieved_at, terms, task_fit,
            record_date, "day", row,
        ))
    newest_date = max(date.fromisoformat(record.as_of) for record in records)
    core._check_day_freshness(
        newest_date, retrieved_at,
        core._SOURCE_MAX_AGE_DAYS[core.Provider.TREASURY_DTS],
        "newest Treasury record_date",
    )
    return tuple(records)
