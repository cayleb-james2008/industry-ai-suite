import shutil
import subprocess
from pathlib import Path

import pytest


def test_browser_result_intro_copy_contract():
    repo = Path(__file__).resolve().parents[1]
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the browser copy helper")
    result = subprocess.run(
        [node, "--test", "tests/result-intro.test.cjs"],
        cwd=repo,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
