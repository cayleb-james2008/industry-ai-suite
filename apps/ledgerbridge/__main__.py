"""LedgerBridge read-only live Treasury command."""

import argparse
import json

from suite_core import configured_ai_client

from .flow import run_live


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and review public Treasury DTS cash rows; never posts a ledger entry.")
    parser.add_argument(
        "--ai-configured", action="store_true",
        help="request an optional grounded summary from the configured provider; output remains unverified",
    )
    args = parser.parse_args()
    ai_client = configured_ai_client() if args.ai_configured else None
    print(json.dumps(run_live(ai_client=ai_client), sort_keys=True))


if __name__ == "__main__":
    main()
