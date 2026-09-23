"""Command-line entry point for live SearchLift, with an explicit fixture demo."""

import argparse
import json

from .flow import run_demo, run_live


def main() -> int:
    parser = argparse.ArgumentParser(description="Review the live portfolio, or explicitly run the fixture-only demo.")
    parser.add_argument("command", nargs="?", choices=("live", "demo"), default="live")
    args = parser.parse_args()
    receipt = run_demo() if args.command == "demo" else run_live()
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
