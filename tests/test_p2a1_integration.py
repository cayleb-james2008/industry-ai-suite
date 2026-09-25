"""P2a1 CLI integration checks; no source or model network calls are made."""

from __future__ import annotations

import importlib
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


APP_MODULES = (
    "apps.ledgerbridge.__main__",
    "apps.marketbrief.__main__",
)


class P2a1CliIntegrationTests(unittest.TestCase):
    def test_default_cli_keeps_ai_off_and_runs_the_live_path(self) -> None:
        for module_name in APP_MODULES:
            with self.subTest(module=module_name):
                entry = importlib.import_module(module_name)
                printed = io.StringIO()
                with patch.object(entry, "run_live", return_value={"status": "UNVERIFIED"}) as run_live, \
                        patch.object(entry, "configured_ai_client") as configured_client, \
                        patch.object(sys, "argv", [module_name]), \
                        redirect_stdout(printed):
                    entry.main()

                run_live.assert_called_once_with(ai_client=None)
                configured_client.assert_not_called()
                self.assertEqual(json.loads(printed.getvalue()), {"status": "UNVERIFIED"})

    def test_configured_cli_passes_the_shared_client_without_certifying_it(self) -> None:
        for module_name in APP_MODULES:
            with self.subTest(module=module_name):
                entry = importlib.import_module(module_name)
                client = object()
                printed = io.StringIO()
                with patch.object(entry, "run_live", return_value={"ai_status": "AI CANDIDATE"}) as run_live, \
                        patch.object(entry, "configured_ai_client", return_value=client) as configured_client, \
                        patch.object(sys, "argv", [module_name, "--ai-configured"]), \
                        redirect_stdout(printed):
                    entry.main()

                configured_client.assert_called_once_with()
                run_live.assert_called_once_with(ai_client=client)
                self.assertEqual(json.loads(printed.getvalue()), {"ai_status": "AI CANDIDATE"})


if __name__ == "__main__":
    unittest.main()
