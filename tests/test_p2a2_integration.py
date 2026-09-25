"""P2a2 integration checks using separately pinned real-source projections."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.backtestguard.flow import run_live as run_backtestguard_live
from apps.searchlift.flow import _analyze_portfolio_metrics
from suite_core import Provider, SourceRecord, SourceResult, TaskFit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PINNED_GDP = PROJECT_ROOT / "tests/data/pinned_real_public/world_bank_usa_gdp.json"
SEARCHLIFT_SNAPSHOT = PROJECT_ROOT / "apps/searchlift/tests/real_portfolio_snapshot.json"


def _recorded_gdp_source() -> SourceResult:
    capture = json.loads(PINNED_GDP.read_text(encoding="utf-8"))
    source = capture["source"]
    records = tuple(
        SourceRecord(
            provider=source["provider"],
            source_id=row["source_id"],
            source_url=source["request_url"],
            response_status=source["response_status"],
            response_sha256=source["response_sha256"],
            request_body_sha256=source["request_body_sha256"],
            as_of=row["as_of"],
            as_of_precision=row["as_of_precision"],
            retrieved_at_utc=source["retrieved_at_utc"],
            terms_url=source["terms_url"],
            read_only=source["read_only"],
            task_fit=source["task_fit"],
            data=row["data"],
        )
        for row in capture["records"]
    )
    return SourceResult(
        provider=source["provider"],
        status=source["status"],
        request_url=source["request_url"],
        response_status=source["response_status"],
        response_sha256=source["response_sha256"],
        request_body_sha256=source["request_body_sha256"],
        retrieved_at_utc=source["retrieved_at_utc"],
        task_fit=source["task_fit"],
        records=records,
        read_only=source["read_only"],
    )


class P2a2IntegrationTests(unittest.TestCase):
    def test_backtestguard_maps_pinned_real_gdp_rows_to_limited_review(self) -> None:
        recorded = _recorded_gdp_source()
        with patch(
            "apps.backtestguard.flow.fetch_live", return_value=recorded
        ) as fetch:
            receipt = run_backtestguard_live()

        fetch.assert_called_once_with(
            Provider.WORLD_BANK_USA_GDP, task_fit=TaskFit.PUBLIC_US_GDP
        )
        analysis = receipt["task_result"]
        self.assertEqual(receipt["data_status"], "AVAILABLE")
        self.assertEqual(receipt["job_verdict"], "UNVERIFIED")
        self.assertEqual(receipt["source_metadata"]["response_sha256"], recorded.response_sha256)
        self.assertEqual(analysis["record_count"], 15)
        self.assertIn("LIMITED", analysis["label"])
        self.assertIn("not a completed backtest", analysis["label"])
        self.assertEqual(analysis["experiment_parameters"]["decision_cutoff_year"], 2020)
        self.assertEqual(analysis["experiment_parameters"]["training_years"], list(range(2011, 2021)))
        self.assertEqual(analysis["experiment_parameters"]["holdout_years"], list(range(2021, 2026)))
        self.assertTrue(analysis["valid_chronological_control"]["passes_observation_year_order_only"])
        self.assertTrue(analysis["future_observation_leakage_probe"]["would_leak_if_used_before_cutoff"])
        self.assertFalse(analysis["future_observation_leakage_probe"]["observed_in_this_control"])
        self.assertEqual(receipt["human_handoff"]["owner"], "quant-research-reviewer")
        self.assertEqual(receipt["side_effect_count"], 0)

    def test_searchlift_pinned_fresh_read_maps_metrics_to_one_cited_draft(self) -> None:
        capture = json.loads(SEARCHLIFT_SNAPSHOT.read_text(encoding="utf-8"))
        source = capture["source"]
        issues, evidence = _analyze_portfolio_metrics(capture["content_metrics"], source)

        self.assertEqual(source["source_id"], "agentic-resume-nine.vercel.app:/")
        self.assertEqual(source["source_url"], "https://agentic-resume-nine.vercel.app/")
        self.assertEqual(source["response_status"], 200)
        self.assertEqual(source["as_of"], "2026-09-22T12:49:24Z")
        self.assertEqual(source["retrieved_at_utc"], "2026-09-24T09:53:27Z")
        self.assertEqual(source["response_sha256"], "d2351ebc6ced387c9e2ec85894ec7b8947174d2fe613a582e5a05e049138e8f5")
        self.assertEqual(source["terms_url"], "https://api.github.com/licenses/mit")
        self.assertEqual([item["rule_id"] for item in issues], ["STALE_ROSTER"])
        self.assertEqual(issues[0]["observed"], {
            "approved_workflow_mentions": 0,
            "approved_workflows_expected": 10,
        })
        self.assertEqual(issues[0]["evidence_id"], evidence[0]["evidence_id"])
        self.assertEqual(issues[0]["source_hash"], source["response_sha256"])
        self.assertTrue(issues[0]["improvement_draft"])


if __name__ == "__main__":
    unittest.main()
