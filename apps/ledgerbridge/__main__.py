"""LedgerBridge read-only live Treasury command."""

import argparse
import json

from .flow import run_live


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and review public Treasury DTS cash rows; never posts a ledger entry.")
    parser.parse_args()
    print(json.dumps(run_live(), sort_keys=True))


if __name__ == "__main__":
    main()
