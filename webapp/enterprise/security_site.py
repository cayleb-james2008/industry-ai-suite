"""Security alert and offline uploaded-HTML review paths."""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import Counter
from datetime import date
from urllib.parse import urlsplit

from apps.searchlift.flow import PRIORITY_RANK, _PageFacts, _issue
from apps.sentineldesk.flow import SEVERITY_RANK, correlate_alerts
from suite_core import redact

from .common import (
    ImportContext, exact_object, identifier, iso_date, iso_timestamp, receipt, rows,
    safe_text, text, unique_ids,
)


_CVE = re.compile(r"CVE-\d{4}-\d{4,7}\Z")


def review_sentinel(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"alerts", "assets", "threat_context"}, "SentinelDesk data")
    alerts = rows(data["alerts"], {"alert_id", "occurred_at", "source", "asset_id", "signal", "severity", "details", "cve_id"}, "Security alerts")
    assets = rows(data["assets"], {"asset_id", "product", "version", "owner_id"}, "Asset inventory")
    threat_raw = data["threat_context"]
    if not isinstance(threat_raw, list) or len(threat_raw) > 200:
        raise ValueError("Public threat context must contain 0 to 200 records.")
    threats = tuple(exact_object(row, {"evidence_id", "cve_id", "product", "version", "published_on", "source_url"}, "Threat-context record") for row in threat_raw)
    unique_ids(threats, "evidence_id", "Threat evidence ID")
    by_cve: dict[str, list[dict[str, str]]] = {}
    for row in threats:
        cve = row["cve_id"]
        if not isinstance(cve, str) or not _CVE.fullmatch(cve):
            raise ValueError("Threat context needs a valid CVE identifier.")
        url = row["source_url"]
        if not isinstance(url, str) or len(url) > 500:
            raise ValueError("Threat source URL must be a short HTTPS URL.")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Threat source URL must be HTTPS without credentials, query, or fragment.")
        published = iso_date(row["published_on"], "Threat publication date")
        if date.fromisoformat(published) > date.fromisoformat(context.as_of):
            raise ValueError("Threat publication date cannot be later than the source as-of date.")
        by_cve.setdefault(cve, []).append({
            "evidence_id": identifier(row["evidence_id"], "Threat evidence ID"),
            "cve_id": cve,
            "product": text(row["product"], "Threat product", maximum=120),
            "version": text(row["version"], "Threat version", maximum=80),
            "published_on": published,
            "source_url": safe_text(url, "Threat source URL", maximum=500),
        })
    unique_ids(alerts, "alert_id", "Alert ID")
    unique_ids(assets, "asset_id", "Asset ID")
    by_asset = {}
    for asset in assets:
        asset_id = identifier(asset["asset_id"], "Asset ID")
        by_asset[asset_id] = {
            "asset_id": asset_id,
            "product": text(asset["product"], "Asset product", maximum=120),
            "version": text(asset["version"], "Asset version", maximum=80),
            "owner_id": identifier(asset["owner_id"], "Asset owner code"),
        }
    for alert in alerts:
        identifier(alert["asset_id"], "Alert asset ID")
        iso_timestamp(alert["occurred_at"], "Alert time")
        identifier(alert["source"], "Alert source code")
        safe_text(alert["signal"], "Alert signal", maximum=160)
        safe_text(alert["details"], "Alert details", maximum=1000)
        if alert["severity"] not in SEVERITY_RANK:
            raise ValueError("Alert severity is outside the supported scale.")
        if not isinstance(alert["cve_id"], str) or not _CVE.fullmatch(alert["cve_id"]):
            raise ValueError("Alert CVE must have a valid CVE identifier.")
        if alert["asset_id"] not in by_asset:
            raise ValueError("Every alert needs a matching asset-inventory record.")
    incidents = correlate_alerts(alerts)
    for incident in incidents:
        incident["asset_context"] = by_asset[incident["asset_id"]]
        incident["cve_ids"] = sorted({str(row["cve_id"]) for row in alerts if row["asset_id"] == incident["asset_id"] and row["alert_id"] in incident["evidence_ids"]})
        matches = [item for cve in incident["cve_ids"] for item in by_cve.get(cve, [])]
        product_matches = [item for item in matches if item["product"].casefold() == by_asset[incident["asset_id"]]["product"].casefold()]
        version_matches = [item for item in product_matches if item["version"].casefold() == by_asset[incident["asset_id"]]["version"].casefold()]
        incident["public_threat_comparison"] = {
            "status": "NO SUPPLIED CONTEXT" if not threats else "NO CVE MATCH" if not matches else "CVE MATCH / PRODUCT MISMATCH" if not product_matches else "CVE AND PRODUCT MATCH / VERSION MISMATCH" if not version_matches else "CVE, PRODUCT AND VERSION LABEL MATCH / APPLICABILITY UNVERIFIED",
            "matched_evidence": matches,
        }
        incident["applicability_verdict"] = "UNVERIFIED — product and version require responder confirmation"
    incidents = redact(incidents)
    highest = max((item["severity"] for item in incidents), key=SEVERITY_RANK.__getitem__)
    result = {"alert_count": len(alerts), "asset_count": len(assets), "threat_context_count": len(threats), "threat_context_status": "IMPORTED / SOURCE UNVERIFIED" if threats else "UNAVAILABLE / NONE SUPPLIED", "incident_count": len(incidents), "incidents": incidents, "highest_supplied_severity": highest, "containment_attempted": False}
    summary = {
        "title": "Alert-to-asset triage",
        "metrics": [{"label": "Alerts", "value": len(alerts)}, {"label": "Incidents", "value": len(incidents)}, {"label": "Threat records", "value": len(threats)}],
        "findings": [f"{item['incident_id']}: {item['severity']} supplied severity on asset {item['asset_id']}; {', '.join(item['cve_ids'])}; {item['public_threat_comparison']['status']}." for item in incidents[:20]],
    }
    return receipt("SentinelDesk", context, result, evidence_ids=[str(row["alert_id"]) for row in alerts] + [str(row["evidence_id"]) for row in threats], summary=summary,
                   next_action="A responder must verify alert authenticity, imported public-threat source and applicability, affected product/version, and current asset owner before any containment decision.")


def _page_path(value: object) -> str:
    path = text(value, "HTML page path", maximum=160)
    if path.startswith("/") or "\\" in path or not path.endswith(".html") or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("HTML page paths must be relative .html paths without traversal.")
    return path


def _html_facts(path: str, html: str, known_paths: set[str]) -> dict[str, object]:
    parser = _PageFacts()
    parser.feed(html)
    title = " ".join(parser.title_parts).strip()
    if title:
        safe_text(title, "Page title", maximum=300)
    description = (parser.description or "").strip()
    if description:
        safe_text(description, "Page description", maximum=500)
    outside_root = []
    unprovided = []
    for href in parser.links:
        split = urlsplit(href)
        if split.scheme or split.netloc or not split.path or split.path.startswith("/"):
            continue
        if split.path.endswith(".html"):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), split.path))
            if target == ".." or target.startswith("../"):
                outside_root.append(href)
            elif target not in known_paths:
                unprovided.append(href)
    return {
        "path": path,
        "source_hash": hashlib.sha256(html.encode()).hexdigest(),
        "title": title,
        "description": description,
        "lang": (parser.lang or "").strip(),
        "h1_count": parser.h1_count,
        "missing_alt": parser.missing_alt,
        "outside_root_links": outside_root,
        "unprovided_links": unprovided,
        "word_count": sum(len(part.split()) for part in parser.visible_text),
    }


def review_search(context: ImportContext) -> dict[str, object]:
    data = exact_object(context.data, {"pages"}, "SearchLift data")
    pages = rows(data["pages"], {"path", "html"}, "Uploaded HTML pages", maximum=20)
    paths = [_page_path(page["path"]) for page in pages]
    if len(set(paths)) != len(paths):
        raise ValueError("Uploaded HTML page paths must be unique.")
    for page in pages:
        if not isinstance(page["html"], str) or not 1 <= len(page["html"]) <= 20000:
            raise ValueError("Each HTML page must contain 1 to 20000 characters.")
    facts = [_html_facts(path, page["html"], set(paths)) for path, page in zip(paths, pages, strict=True)]
    issues = []
    for page in facts:
        title = str(page["title"])
        description = str(page["description"])
        if not 15 <= len(title) <= 60:
            issues.append(_issue(page, "SEO_TITLE", {"characters": len(title), "title": title or "missing"}))
        if not 70 <= len(description) <= 160:
            issues.append(_issue(page, "SEO_DESCRIPTION", {"characters": len(description)}))
        if page["missing_alt"]:
            issues.append(_issue(page, "IMAGE_ALT", {"images_missing_alt": page["missing_alt"]}))
        if page["h1_count"] != 1:
            issues.append(_issue(page, "CONTENT_H1", {"h1_count": page["h1_count"]}))
        if not page["lang"]:
            issues.append(_issue(page, "DOCUMENT_LANGUAGE", {"lang": "missing"}))
        if page["outside_root_links"]:
            issue = _issue(page, "LOCAL_LINK", {"links": page["outside_root_links"]})
            issue["finding"] = "A relative link resolves outside the supplied site root."
            issues.append(issue)
        if page["unprovided_links"]:
            issue = _issue(page, "LOCAL_LINK", {"links": page["unprovided_links"]})
            issue.update({
                "issue_id": "SL-" + hashlib.sha256(f"{page['path']}:LOCAL_LINK_UNSUPPLIED".encode()).hexdigest()[:12],
                "rule_id": "LOCAL_LINK_UNSUPPLIED",
                "priority": "P3",
                "finding": "A linked page was not included in this import; its existence is unverified.",
                "improvement_draft": "Supply the linked page or inspect it separately before calling the link broken.",
            })
            issues.append(issue)
        if page["word_count"] < 40:
            issues.append(_issue(page, "THIN_CONTENT", {"visible_words": page["word_count"]}))
    issues.sort(key=lambda item: (PRIORITY_RANK[str(item["priority"])], str(item["issue_id"])))
    priorities = Counter(str(issue["priority"]) for issue in issues)
    result = {
        "pages_reviewed": len(facts),
        "issue_count": len(issues),
        "priority_counts": {key: priorities.get(key, 0) for key in ("P1", "P2", "P3")},
        "issues": issues,
        "page_sources": [{"path": str(redact(page["path"])), "source_hash": page["source_hash"]} for page in facts],
        "coverage_limit": "Only supplied HTML was inspected offline; unprovided linked pages, remote assets, analytics, rankings, and real-user behavior were not verified.",
        "publication_attempted": False,
    }
    summary = {
        "title": "Offline website improvement review",
        "metrics": [{"label": "Pages", "value": len(facts)}, {"label": "Issues", "value": len(issues)}],
        "findings": [f"{item['page']}: {item['rule_id']} — {item['finding']} [evidence:{item['evidence_id']}]." for item in issues[:20]] or ["No issue was found in the uploaded HTML checks; search outcomes are unmeasured."],
    }
    return receipt("SearchLift", context, result, evidence_ids=["SL-SRC-" + hashlib.sha256(path.encode()).hexdigest()[:10] for path in paths], summary=summary,
                   next_action="The site owner must inspect each source file, choose edits, and separately approve any publication; rankings and traffic remain unmeasured.")
