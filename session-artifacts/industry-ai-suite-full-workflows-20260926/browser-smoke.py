"""Run the ten invented organization journeys in a real local Chromium page."""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:18340/"
SLUGS = (
    "ledgerbridge", "marketbrief", "chainwatch", "backtestguard", "replycraft",
    "handoffhub", "sentineldesk", "searchlift", "pipelinerelay", "onboardpath",
)
DETAIL = {
    "ledgerbridge": "owners finance-review",
    "marketbrief": "invented sample report",
    "chainwatch": "CW-001 · ALERT",
    "backtestguard": "source released",
    "replycraft": "Case RC-001",
    "handoffhub": "Send an invoice mismatch",
    "sentineldesk": "Public-context import SD-THREAT-001",
    "searchlift": "Draft for editor",
    "pipelinerelay": "Account account-001",
    "onboardpath": "Confirm identity",
}


def main() -> None:
    errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, executable_path="/usr/bin/chromium",
            args=["--disable-gpu", "--no-sandbox"],
        )
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(URL, wait_until="networkidle")
        page.screenshot(path=str(ROOT / "workbench-before.png"), full_page=True)
        for slug in SLUGS:
            page.locator(f'.nav-item[data-slug="{slug}"]').click()
            page.locator("#input-route").select_option("enterprise")
            assert page.locator(".enterprise-fields").is_visible(), slug
            assert "de-identified" in page.locator("#input-help").inner_text() or slug in {"chainwatch", "backtestguard", "sentineldesk", "searchlift"}, slug
            page.get_by_role("button", name="Load safe example").click()
            page.locator("#enterprise-json").evaluate("element => new Promise(resolve => { const tick = () => element.value.includes('synthetic-org') ? resolve() : setTimeout(tick, 20); tick(); })")
            page.locator("#run-button").click()
            page.locator("#result-state").get_by_text("SYNTHETIC EXAMPLE", exact=True).wait_for(timeout=10000)
            content = page.locator("#result-content").inner_text()
            assert "ENTERPRISE UNVERIFIED" in content and "AI: NOT RUN" in content, slug
            assert "Local organization bundle only" in content, slug
            assert DETAIL[slug] in content, slug
            print(f"PASS {slug}: browser import, distinct result, source boundary")
            if slug == "replycraft":
                page.screenshot(path=str(ROOT / "workbench-replycraft-result.png"), full_page=True)

        page.locator('.nav-item[data-slug="replycraft"]').click()
        page.locator("#input-route").select_option("enterprise")
        page.get_by_role("button", name="Load safe example").click()
        page.locator("#enterprise-json").evaluate("element => new Promise(resolve => { const tick = () => element.value.includes('synthetic-org') ? resolve() : setTimeout(tick, 20); tick(); })")
        bundle = json.loads(page.locator("#enterprise-json").input_value())
        bundle["data"]["consent"]["status"] = "denied"
        page.locator("#enterprise-json").fill(json.dumps(bundle))
        page.locator("#run-button").click()
        page.locator("#result-state").get_by_text("NEEDS ATTENTION", exact=True).wait_for(timeout=10000)
        assert not page.locator("#result-actions").is_visible()
        assert "consent" in page.locator("#result-content").inner_text().lower()
        print("PASS replycraft: denied consent returns no task result")

        page.locator("#enterprise-json").fill('{"tenant_id":"one","tenant_id":"two"}')
        page.locator("#run-button").click()
        page.locator("#result-state").get_by_text("NEEDS ATTENTION", exact=True).wait_for(timeout=10000)
        assert "Duplicate JSON fields" in page.locator("#result-content").inner_text()
        print("PASS browser: duplicate organization field rejected by server")

        file_button = page.get_by_role("button", name="Choose local JSON file")
        file_button.focus()
        assert file_button.evaluate("element => document.activeElement === element")
        page.set_viewport_size({"width": 390, "height": 844})
        page.screenshot(path=str(ROOT / "workbench-mobile.png"), full_page=True)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        print("PASS mobile: file button focusable; no horizontal overflow at 390px")
        browser.close()
    if errors:
        raise AssertionError(f"Browser errors: {errors}")


if __name__ == "__main__":
    main()
