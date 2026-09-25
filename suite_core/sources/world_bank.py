"""World Bank USA GDP observations and dataset-specific reuse-term check."""

from __future__ import annotations

import html as html_lib
import re

from . import core


def license_is_cc_by_4(body: bytes) -> bool:
    try:
        page = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    license_block = re.search(
        r"<div\b(?=[^>]*\bclass=['\"][^'\"]*\blicense\b[^'\"]*['\"])[^>]*>(.*?)</div>",
        page,
        re.IGNORECASE | re.DOTALL,
    )
    if not license_block:
        return False
    text = html_lib.unescape(re.sub(r"<[^>]*>", " ", license_block.group(1)))
    return re.search(r"\bLicense\s*:\s*CC BY-4\.0\b", text, re.IGNORECASE) is not None


def parse(payload, source_url, response, response_hash, retrieved_at, task_fit):
    if not isinstance(payload, list) or len(payload) != 2:
        raise core.DataUnavailable("World Bank response schema mismatch")
    observations = core._list(payload[1], "World Bank observations")
    core._check_record_count(core.Provider.WORLD_BANK_USA_GDP, len(observations))
    records = []
    for item in observations:
        row = core._mapping(item, "World Bank observation")
        core._mapping(row.get("country"), "World Bank country")
        indicator = core._mapping(row.get("indicator"), "World Bank indicator")
        if row.get("countryiso3code") != "USA" or indicator.get("id") != "NY.GDP.MKTP.CD":
            raise core.DataUnavailable("World Bank observation is not the requested USA GDP indicator")
        year = core._as_year(row.get("date"))
        records.append(core._record(
            core.Provider.WORLD_BANK_USA_GDP,
            f"USA:NY.GDP.MKTP.CD:{year}", source_url, response,
            response_hash, retrieved_at, core._TERMS[core.Provider.WORLD_BANK_USA_GDP],
            task_fit, year, "year", row,
        ))
    core._check_gdp_freshness([int(record.as_of) for record in records], retrieved_at)
    return tuple(records)
