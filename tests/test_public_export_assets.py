"""The recorded export must carry every script it references."""
import json
from html.parser import HTMLParser
from urllib.parse import urlsplit

from scripts import export_public_lab as exporter


class StaticAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script" and attributes.get("src"):
            self.paths.append(attributes["src"])
        elif tag == "link" and attributes.get("rel") == "stylesheet":
            self.paths.append(attributes["href"])


def test_recorded_export_is_self_contained_under_a_site_subdirectory(tmp_path, monkeypatch):
    receipts = tmp_path / "input"
    receipts.mkdir()
    (receipts / "ledgerbridge.json").write_text(json.dumps({
        "app_slug": "ledgerbridge", "status": "UNVERIFIED",
        "source_status": "DATA_UNAVAILABLE", "workflow_status": "UNVERIFIED",
        "uncertainty": "Synthetic regression fixture; no external request made.",
        "handoff": {"next_action": "Review the source before retrying."},
        "task_result": None, "evidence": [],
    }), encoding="utf-8")
    monkeypatch.setattr(exporter, "SLUGS", ["ledgerbridge"])
    output = tmp_path / "site" / "lab"
    exporter.export(receipts, output)
    html = (output / "index.html").read_text(encoding="utf-8")
    assets = StaticAssets()
    assets.feed(html)
    paths = [urlsplit(item).path for item in assets.paths]
    assert "result-intro.js" in paths, "helper must resolve relative to /site/lab/, not domain root"
    assert paths.index("result-intro.js") < paths.index("app.js"), "load helper before its consumer"
    for name in paths:
        assert not name.startswith("/"), f"root-absolute asset breaks subdirectory hosting: {name}"
        assert (output / name).is_file(), f"export omitted referenced asset: {name}"
        assert (output / name).read_bytes() == (exporter.STATIC / name).read_bytes()
    assert 'data-mode="recorded"' in html
    assert "__WORKBENCH_TOKEN__" not in html
