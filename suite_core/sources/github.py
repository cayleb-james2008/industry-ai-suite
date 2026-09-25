"""GitHub repository metadata and deliberately refused text/advisory routes."""

from __future__ import annotations

from collections.abc import Mapping

from . import core


def parse(provider, payload, source_url, response, response_hash, retrieved_at,
          task_fit, owner, repo):
    records = []
    if provider is core.Provider.GITHUB_REPOSITORY:
        row = core._mapping(payload, "GitHub repository")
        repo_id = row.get("id")
        full_name = row.get("full_name")
        if type(repo_id) is not int or not isinstance(full_name, str):
            raise core.DataUnavailable("GitHub repository identity schema mismatch")
        if (owner is None or repo is None
                or full_name.casefold() != f"{owner}/{repo}".casefold()):
            raise core.UnverifiedSource("GitHub repository identity does not match the requested object")
        updated_at = core._as_timestamp(row.get("updated_at"))
        core._check_timestamp_freshness(
            updated_at, retrieved_at,
            core._SOURCE_MAX_AGE_DAYS[provider], "GitHub repository updated_at",
        )
        license_info = row.get("license")
        if not isinstance(license_info, Mapping):
            raise core.UnverifiedSource("GitHub repository has no verified content license")
        spdx = license_info.get("spdx_id")
        license_url = license_info.get("url")
        if (not isinstance(spdx, str) or spdx in {"NOASSERTION", "OTHER"}
                or not isinstance(license_url, str)):
            raise core.UnverifiedSource("GitHub repository license is missing or ambiguous")
        license_key = license_info.get("key")
        if license_key is not None and license_key != spdx.lower():
            raise core.UnverifiedSource("GitHub license key does not match its SPDX identifier")
        core._validate_github_license_url(license_url, spdx)
        projection = {
            key: row.get(key)
            for key in ("id", "full_name", "html_url", "default_branch", "license")
            if key in row
        }
        records.append(core._record(
            provider, repo_id, source_url, response, response_hash, retrieved_at,
            license_url, task_fit, updated_at, "second", projection,
        ))
    elif provider is core.Provider.GITHUB_README:
        readme = core._mapping(payload, "GitHub README")
        if (not isinstance(readme.get("path"), str)
                or not isinstance(readme.get("sha"), str)
                or not isinstance(readme.get("encoding"), str)
                or not isinstance(readme.get("content"), str)):
            raise core.DataUnavailable("GitHub README response schema mismatch")
        raise core.UnverifiedSource("GitHub README response has no file-specific as-of timestamp and license proof")
    elif provider is core.Provider.GITHUB_ADVISORIES:
        advisories = core._list(payload, "GitHub advisories")
        for item in advisories:
            advisory = core._mapping(item, "GitHub advisory")
            if not isinstance(advisory.get("ghsa_id"), str):
                raise core.DataUnavailable("GitHub advisory response schema mismatch")
            core._as_timestamp(advisory.get("updated_at"))
        raise core.UnverifiedSource("GitHub advisory response has no verified content-use terms")
    return tuple(records)
