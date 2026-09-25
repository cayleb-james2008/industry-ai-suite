import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COLLECTION_ROOTS = (
    "tests/",
    "apps/ledgerbridge/",
    "apps/marketbrief/",
    "apps/chainwatch/",
    "apps/backtestguard/",
    "apps/replycraft/",
    "apps/handoffhub/",
    "apps/sentineldesk/",
    "apps/searchlift/",
    "apps/pipelinerelay/",
    "apps/onboardpath/",
)


def test_default_pytest_collects_root_and_all_app_suites():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    collected_items = [line for line in result.stdout.splitlines() if "::" in line]
    missing_roots = [
        root
        for root in EXPECTED_COLLECTION_ROOTS
        if not any(item.startswith(root) for item in collected_items)
    ]
    assert not missing_roots, f"pytest did not collect suite roots: {missing_roots}"
