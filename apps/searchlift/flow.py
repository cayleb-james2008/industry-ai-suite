"""Inspect tenant-scoped local HTML and draft deterministic SEO/usability fixes offline."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import Counter
from collections.abc import Mapping
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from apps._ai_receipts import complete_grounded

from suite_core import (
    AccessPolicy,
    AuditLog,
    Authenticator,
    HMACTokenCodec,
    LiveSourceError,
    LocalOpenAIClient,
    NonAIFallback,
    Principal,
    PromptInjectionError,
    PromptSentinel,
    Provider,
    SecurityCore,
    TaskFit,
    fetch_live,
    redact,
)

APP_DIR = Path(__file__).resolve().parent
FIXTURE_ROOT = APP_DIR / "fixtures"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ACTION_ANALYZE = "analyze_local_site"
TENANT_EVIDENCE = {
    TENANT_A: ("SL-A-HOME", "SL-A-SERVICES"),
    TENANT_B: ("SL-B-HOME",),
}
PROTECTED_CANARIES = ("SEARCHLIFT_TENANT_B_CANARY_85C2",)
PORTFOLIO_URL = "https://agentic-resume-nine.vercel.app/"
PORTFOLIO_SOURCE_ID = "agentic-resume-nine.vercel.app:/"
PORTFOLIO_TERMS_URL = "https://api.github.com/licenses/mit"
APPROVED_WORKFLOWS = (
    "LedgerBridge", "MarketBrief", "ChainWatch", "BacktestGuard", "ReplyCraft",
    "HandoffHub", "PipelineRelay", "OnboardPath", "SentinelDesk", "SearchLift",
)
PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2}
RULES = {
    "SEO_TITLE": ("P1", "Page title is missing or outside the recommended 15–60 character range."),
    "SEO_DESCRIPTION": ("P1", "Search description is missing or outside the 70–160 character working range."),
    "IMAGE_ALT": ("P1", "One or more images have no useful alternative text."),
    "CONTENT_H1": ("P2", "The page should have exactly one clear primary heading."),
    "DOCUMENT_LANGUAGE": ("P2", "The HTML document should declare its language."),
    "CONTENT_HEADINGS": ("P2", "No section headings were returned in the bounded visible-text sample."),
    "STALE_ROSTER": (
        "P1",
        "The captured public page does not include all currently approved suite workflows; its roster is stale for this suite.",
    ),
    "LOCAL_LINK": ("P2", "One or more local links point outside the site folder or to a missing file."),
    "THIN_CONTENT": ("P3", "The page has fewer than 40 visible words; confirm whether visitors have enough useful detail."),
}
DRAFTS = {
    "SEO_TITLE": "Write a specific page title of about 15–60 characters that describes this page accurately.",
    "SEO_DESCRIPTION": "Draft a clear, factual search description of about 70–160 characters; do not add unsupported claims.",
    "IMAGE_ALT": "Add concise, context-appropriate alternative text to each informative image; use empty alt only for decorative images.",
    "CONTENT_H1": "Use one descriptive primary heading that tells visitors what this page helps them do.",
    "DOCUMENT_LANGUAGE": "Add the correct language code to the opening html element so assistive tools can pronounce the page appropriately.",
    "CONTENT_HEADINGS": "Review the live page structure and add clear section headings where useful.",
    "STALE_ROSTER": "Review the approved portfolio content and update the roster only after its evidence and safety checks pass.",
    "LOCAL_LINK": "Check each flagged local link and point it to an existing page inside this site folder.",
    "THIN_CONTENT": "Add useful, verified details that answer a visitor's likely question; avoid filler or unsupported promises.",
}


class _PageFacts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.description: str | None = None
        self.lang: str | None = None
        self.h1_count = 0
        self.missing_alt = 0
        self.h2_count = 0
        self.links: list[str] = []
        self.visible_text: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html":
            self.lang = values.get("lang")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and values.get("name", "").lower() == "description":
            self.description = values.get("content") or ""
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "h2":
            self.h2_count += 1
        elif tag == "img" and not (values.get("alt") or "").strip():
            self.missing_alt += 1
        elif tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if cleaned:
            self.visible_text.append(cleaned)
            if self._in_title:
                self.title_parts.append(cleaned)


def _new_security(audit_path: Path) -> tuple[SecurityCore, Authenticator]:
    auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    policy = AccessPolicy(
        {
            TENANT_A: {"marketer": TENANT_EVIDENCE[TENANT_A]},
            TENANT_B: {"marketer": TENANT_EVIDENCE[TENANT_B]},
        },
        {"marketer": {ACTION_ANALYZE}},
    )
    return SecurityCore(auth, policy, AuditLog(audit_path)), auth


def _authorized_site(
    core: SecurityCore,
    token: str,
    *,
    tenant_id: str,
    fixture_root: Path = FIXTURE_ROOT,
) -> Path:
    evidence_ids = TENANT_EVIDENCE.get(tenant_id, ())
    principal = core.authorize(
        token, tenant_id=tenant_id, action=ACTION_ANALYZE, evidence_ids=evidence_ids
    )
    root = fixture_root.resolve(strict=True)
    tenant_dir = root / principal.tenant_id
    if tenant_dir.is_symlink():
        raise ValueError("tenant website fixture must not be a symlink")
    site_root = (tenant_dir / "site").resolve(strict=True)
    if not site_root.is_dir() or not site_root.is_relative_to(root):
        raise ValueError("website fixture escaped its tenant root")
    return site_root


def _local_target_exists(site_root: Path, page: Path, href: str) -> bool | None:
    parts = urlsplit(href)
    if parts.scheme or parts.netloc or href.startswith(("mailto:", "tel:")):
        return None
    if not parts.path:
        return True
    target = (page.parent / parts.path).resolve(strict=False)
    if not target.is_relative_to(site_root):
        return False
    if target.is_dir():
        target = target / "index.html"
    return target.is_file()


def _page_facts(site_root: Path) -> list[dict[str, object]]:
    pages: list[dict[str, object]] = []
    sentinel = PromptSentinel()
    for candidate in sorted(site_root.rglob("*.html"), key=lambda path: path.relative_to(site_root).as_posix()):
        if candidate.is_symlink():
            raise ValueError("website pages must not be symlinks")
        page = candidate.resolve(strict=True)
        if not page.is_file() or not page.is_relative_to(site_root):
            raise ValueError("website page escaped the local site folder")
        raw = page.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        parser = _PageFacts()
        parser.feed(text)
        title = " ".join(parser.title_parts).strip()
        sentinel.check(title, protected_canaries=PROTECTED_CANARIES)
        relative = page.relative_to(site_root).as_posix()
        broken_links = [
            href for href in parser.links if _local_target_exists(site_root, page, href) is False
        ]
        pages.append({
            "path": relative,
            "source_hash": hashlib.sha256(raw).hexdigest(),
            "title": title,
            "description": (parser.description or "").strip(),
            "lang": (parser.lang or "").strip(),
            "h1_count": parser.h1_count,
            "missing_alt": parser.missing_alt,
            "broken_links": broken_links,
            "word_count": sum(len(part.split()) for part in parser.visible_text),
        })
    if not pages:
        raise ValueError("website folder contains no local .html pages")
    return pages


def _issue(page: dict[str, object], rule_id: str, observed: object) -> dict[str, object]:
    priority, finding = RULES[rule_id]
    page_path = str(page["path"])
    stable = hashlib.sha256(f"{page_path}:{rule_id}".encode("utf-8")).hexdigest()[:12]
    receipt = {
        "issue_id": f"SL-{stable}",
        "rule_id": rule_id,
        "priority": priority,
        "page": str(redact(page_path)),
        "finding": finding,
        "observed": redact(observed),
        "evidence_id": "SL-SRC-" + hashlib.sha256(page_path.encode("utf-8")).hexdigest()[:10],
        "source_hash": page["source_hash"],
        "improvement_draft": DRAFTS[rule_id],
    }
    return receipt


def analyze_site(site_root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return deterministically ordered, source-bound issues and local page evidence."""
    pages = _page_facts(site_root)
    issues: list[dict[str, object]] = []
    for page in pages:
        title = str(page["title"])
        description = str(page["description"])
        if not 15 <= len(title) <= 60:
            issues.append(_issue(page, "SEO_TITLE", {"characters": len(title), "title": title or "missing"}))
        if not 70 <= len(description) <= 160:
            issues.append(_issue(page, "SEO_DESCRIPTION", {"characters": len(description), "description": description or "missing"}))
        if int(page["missing_alt"]):
            issues.append(_issue(page, "IMAGE_ALT", {"images_missing_alt": page["missing_alt"]}))
        if int(page["h1_count"]) != 1:
            issues.append(_issue(page, "CONTENT_H1", {"h1_count": page["h1_count"]}))
        if not page["lang"]:
            issues.append(_issue(page, "DOCUMENT_LANGUAGE", {"lang": "missing"}))
        if page["broken_links"]:
            issues.append(_issue(page, "LOCAL_LINK", {"links": page["broken_links"]}))
        if int(page["word_count"]) < 40:
            issues.append(_issue(page, "THIN_CONTENT", {"visible_words": page["word_count"]}))
    issues.sort(key=lambda item: (PRIORITY_RANK[str(item["priority"])], str(item["issue_id"])))
    evidence = [
        {
            "evidence_id": "SL-SRC-" + hashlib.sha256(str(page["path"]).encode("utf-8")).hexdigest()[:10],
            "source_id": str(redact(str(page["path"]))),
            "source_hash": str(page["source_hash"]),
            "facts": {
                "title": redact(page["title"]),
                "description_characters": len(str(page["description"])),
                "h1_count": page["h1_count"],
                "images_missing_alt": page["missing_alt"],
                "broken_links": redact(page["broken_links"]),
                "visible_words": page["word_count"],
            },
        }
        for page in pages
    ]
    return issues, evidence


def _portfolio_metrics(data: Mapping[str, object]) -> dict[str, int]:
    if not isinstance(data, Mapping):
        raise ValueError("bounded portfolio content has an invalid structure")
    title = data.get("title")
    description = data.get("description")
    headings = data.get("headings")
    paragraphs = data.get("paragraphs")
    if (
        not isinstance(title, str)
        or (description is not None and not isinstance(description, str))
        or not isinstance(headings, list)
        or any(not isinstance(item, str) for item in headings)
        or not isinstance(paragraphs, list)
        or any(not isinstance(item, str) for item in paragraphs)
    ):
        raise ValueError("bounded portfolio content has an invalid structure")

    description = description or ""
    visible_fields = (title, description, *headings, *paragraphs)
    sentinel = PromptSentinel()
    for field in visible_fields:
        sentinel.check(field, protected_canaries=PROTECTED_CANARIES)
    searchable_text = "\n".join(visible_fields).casefold()
    return {
        "title_characters": len(title),
        "description_characters": len(description),
        "heading_count": len(headings),
        "paragraph_count": len(paragraphs),
        "visible_words": sum(len(part.split()) for part in (*headings, *paragraphs)),
        "approved_workflow_mentions": sum(
            workflow.casefold() in searchable_text for workflow in APPROVED_WORKFLOWS
        ),
    }


def _portfolio_issue(
    source: Mapping[str, object], rule_id: str, observed: Mapping[str, int]
) -> dict[str, object]:
    priority, finding = RULES[rule_id]
    draft = DRAFTS[rule_id]
    source_id = str(source["source_id"])
    issue_hash = hashlib.sha256(f"{source_id}:{rule_id}".encode("utf-8")).hexdigest()[:12]
    evidence_id = "SL-SRC-" + hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:10]
    return {
        "issue_id": f"SL-{issue_hash}",
        "rule_id": rule_id,
        "priority": priority,
        "finding": finding,
        "observed": dict(observed),
        "evidence_id": evidence_id,
        "source_hash": source["response_sha256"],
        "improvement_draft": draft,
    }


def _analyze_portfolio_metrics(
    metrics: Mapping[str, object], source: Mapping[str, object]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    counts: dict[str, int] = {}
    for name in (
        "title_characters", "description_characters", "heading_count", "paragraph_count",
        "visible_words", "approved_workflow_mentions",
    ):
        value = metrics.get(name)
        if type(value) is not int or value < 0:
            raise ValueError("portfolio snapshot metrics are invalid")
        counts[name] = value

    checks = (
        (not 15 <= counts["title_characters"] <= 60, "SEO_TITLE", {"characters": counts["title_characters"]}),
        (not 70 <= counts["description_characters"] <= 160, "SEO_DESCRIPTION", {"characters": counts["description_characters"]}),
        (counts["heading_count"] == 0, "CONTENT_HEADINGS", {"headings": counts["heading_count"]}),
        (counts["approved_workflow_mentions"] < len(APPROVED_WORKFLOWS), "STALE_ROSTER", {
            "approved_workflow_mentions": counts["approved_workflow_mentions"],
            "approved_workflows_expected": len(APPROVED_WORKFLOWS),
        }),
        (counts["visible_words"] < 40, "THIN_CONTENT", {"visible_words": counts["visible_words"]}),
    )
    issues = [
        _portfolio_issue(source, rule_id, observed)
        for should_report, rule_id, observed in checks
        if should_report
    ]
    issues.sort(key=lambda item: (PRIORITY_RANK[str(item["priority"])], str(item["issue_id"])))
    evidence_id = "SL-SRC-" + hashlib.sha256(str(source["source_id"]).encode("utf-8")).hexdigest()[:10]
    evidence = [{
        "evidence_id": evidence_id,
        "provider": source["provider"],
        "source_id": source["source_id"],
        "source_url": source["source_url"],
        "response_status": source["response_status"],
        "source_hash": source["response_sha256"],
        "request_body_sha256": source["request_body_sha256"],
        "source_as_of": source["as_of"],
        "as_of_precision": source["as_of_precision"],
        "retrieved_at_utc": source["retrieved_at_utc"],
        "terms_url": source["terms_url"],
        "read_only": source["read_only"],
        "task_fit": source["task_fit"],
        "facts": {**counts, "approved_workflows_expected": len(APPROVED_WORKFLOWS)},
    }]
    return issues, evidence


def _unavailable_live(status: str, reason: str) -> dict[str, object]:
    return {
        "app": "SearchLift",
        "status": status,
        "source": None,
        "result": {
            "pages_reviewed": 0,
            "issue_count": 0,
            "issues": [],
            "draft_notice": "No source-backed draft was produced; no snapshot or fixture was substituted.",
            "reason": reason,
        },
        "evidence": [],
        "risk": {
            "level": "UNVERIFIED",
            "explanation": "No live portfolio record was admitted for this run.",
            "uncertainty": "The public source, content, and any SEO or usability findings are unavailable for this run.",
        },
        "handoff": {
            "owner": "portfolio-content-owner",
            "next_action": "Review the source status and rerun only after the live source is available and verified.",
        },
        "ai_status": "NOT RUN / NO ADMITTED SOURCE",
        "ai_invoked": False,
        "ai_evidence": None,
        "side_effect_count": 0,
        "adapter": "suite_core.fetch_live; no fixture or snapshot fallback",
    }


def run_live(ai_client: object | None = None) -> dict[str, object]:
    """Structurally review the live response; the optional AI client is not invoked."""
    # This slice is a deterministic structural review. A model client cannot add source
    # provenance or turn the result into an AI-completion claim.
    try:
        result = fetch_live(
            Provider.OWN_PORTFOLIO_HTML,
            task_fit=TaskFit.OWN_PORTFOLIO_CONTENT,
        )
    except LiveSourceError as error:
        return _unavailable_live(error.status, "The fixed public-source request was not admitted.")

    if result.status != "VERIFIED_SOURCE":
        return _unavailable_live(result.status, result.reason or "Live source provenance is incomplete.")
    if (
        result.provider != Provider.OWN_PORTFOLIO_HTML.value
        or result.request_url != PORTFOLIO_URL
        or result.task_fit != TaskFit.OWN_PORTFOLIO_CONTENT.value
        or result.response_status != 200
        or result.request_body_sha256 is not None
        or not result.read_only
        or len(result.records) != 1
    ):
        return _unavailable_live("UNVERIFIED", "The live response did not match the admitted portfolio contract.")

    record = result.records[0]
    if (
        record.provider != result.provider
        or record.source_id != PORTFOLIO_SOURCE_ID
        or record.source_url != result.request_url
        or record.response_status != result.response_status
        or record.response_sha256 != result.response_sha256
        or record.request_body_sha256 is not None
        or record.as_of_precision != "second"
        or not record.as_of
        or not record.retrieved_at_utc
        or record.terms_url != PORTFOLIO_TERMS_URL
        or record.task_fit != result.task_fit
        or not record.read_only
    ):
        return _unavailable_live("UNVERIFIED", "The live record is missing required source provenance.")

    try:
        metrics = _portfolio_metrics(record.data)
    except PromptInjectionError:
        return _unavailable_live("UNVERIFIED", "The bounded source text failed the existing input safety screen.")
    except (TypeError, ValueError):
        return _unavailable_live("DATA_UNAVAILABLE", "The bounded source text did not match its admitted structure.")

    source = {
        "provider": record.provider,
        "source_id": record.source_id,
        "source_url": record.source_url,
        "response_status": record.response_status,
        "response_sha256": record.response_sha256,
        "request_body_sha256": record.request_body_sha256,
        "as_of": record.as_of,
        "as_of_precision": record.as_of_precision,
        "retrieved_at_utc": record.retrieved_at_utc,
        "terms_url": record.terms_url,
        "read_only": record.read_only,
        "task_fit": record.task_fit,
    }
    issues, evidence = _analyze_portfolio_metrics(metrics, source)
    priorities = Counter(str(issue["priority"]) for issue in issues)
    return {
        "app": "SearchLift",
        "status": "VERIFIED_SOURCE",
        "source": source,
        "result": {
            "pages_reviewed": 1,
            "issue_count": len(issues),
            "priority_counts": {key: priorities.get(key, 0) for key in ("P1", "P2", "P3")},
            "issues": issues,
            "draft_notice": "Drafts are suggestions for human review; no file was edited or published.",
        },
        "evidence": evidence,
        "risk": {
            "level": "MEDIUM" if issues else "LOW",
            "explanation": "Findings are structural checks against bounded returned text, not a search-ranking prediction.",
            "uncertainty": "Only the returned title, meta description, headings, and paragraphs were inspected. Traffic, rankings, links, images, analytics, and real-user outcomes were not measured.",
        },
        "handoff": {
            "owner": "portfolio-content-owner",
            "next_action": "Review the source-linked findings and drafts; any content change requires a separate human publishing decision.",
        },
        "ai_status": "NOT RUN / DETERMINISTIC STRUCTURAL REVIEW",
        "ai_invoked": False,
        "ai_evidence": None,
        "side_effect_count": 0,
        "adapter": "suite_core.fetch_live (fixed portfolio GET, bounded visible text, read-only)",
    }


def _combined_source_hash(evidence: list[dict[str, object]]) -> str:
    sources = [(item["source_id"], item["source_hash"]) for item in evidence]
    stable_bytes = json.dumps(sources, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(stable_bytes).hexdigest()


def run_demo(ai_client: object | None = None) -> dict[str, object]:
    """Analyze only tenant A's checked-in website, with no network or publishing path."""
    with TemporaryDirectory(prefix="searchlift-demo-") as runtime:
        core, auth = _new_security(Path(runtime) / "audit.jsonl")
        actor = Principal(TENANT_A, "site-reviewer", "marketer")
        token = auth.issue(actor, expires_at=int(time.time()) + 120)
        site_root = _authorized_site(core, token, tenant_id=TENANT_A)
        issues, evidence = analyze_site(site_root)

    evidence_ids = tuple(str(item["evidence_id"]) for item in evidence)
    prompt = (
        "Summarize these deterministic local-site findings for a marketer. Cite every claim as "
        "[evidence:ID], prioritize only listed issues, and do not publish or make unsupported claims. "
        "Issues: " + json.dumps([
            {key: issue[key] for key in ("issue_id", "rule_id", "priority", "evidence_id", "finding", "observed")}
            for issue in issues
        ], sort_keys=True)
    )
    if ai_client is not None and type(ai_client) is not LocalOpenAIClient:
        fallback = NonAIFallback().result(
            reason="offline-only policy refused the supplied model adapter without probing it",
            evidence_ids=evidence_ids,
        )
        ai = {
            "ai_status": fallback.status, "ai_invoked": False, "ai_output": None,
            "ai_failure": None, "ai_handoff": fallback.text, "ai_evidence": None,
        }
    else:
        ai = complete_grounded(
            ai_client, prompt,
            system="Use only the deterministic local-site issues, cite evidence, and never publish.",
            evidence_ids=evidence_ids, protected_canaries=PROTECTED_CANARIES,
        )
    ai_summary = ai["ai_output"] or ai["ai_handoff"]
    priorities = Counter(str(issue["priority"]) for issue in issues)
    receipt = {
        "app": "SearchLift",
        "tenant_id": TENANT_A,
        "result": {
            "pages_reviewed": len(evidence),
            "issue_count": len(issues),
            "priority_counts": {key: priorities.get(key, 0) for key in ("P1", "P2", "P3")},
            "issues": issues,
            "draft_notice": "Drafts are suggestions for human review; no file was edited or published.",
            "ai_note": ai_summary,
        },
        "evidence": evidence,
        "source_hash": _combined_source_hash(evidence),
        "risk": {
            "level": "MEDIUM" if issues else "LOW",
            "explanation": "Findings use only deterministic local HTML checks; this is not a search-ranking prediction.",
            "uncertainty": "Only checked-in synthetic pages were inspected; search engine behavior, remote assets, and real-user usability were not measured.",
        },
        "handoff": {
            "owner": "website-content-owner",
            "next_action": "Review the prioritized evidence and adapt approved drafts to the real site before any separate publishing decision.",
        },
        "ai_status": ai["ai_status"],
        "ai_invoked": ai["ai_invoked"],
        "ai_evidence": ai["ai_evidence"],
        "ai_failure": ai["ai_failure"],
        "side_effect_count": 0,
        "adapter": "offline local HTMLParser adapter; no HTTP, paid service, file mutation, or publishing operation",
    }
    return receipt
