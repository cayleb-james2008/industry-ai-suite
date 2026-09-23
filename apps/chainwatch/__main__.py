"""ChainWatch live availability check, with an explicit fixture-only demo."""

import argparse
import json

from .flow import run_demo, run_live


def main() -> int:
    parser = argparse.ArgumentParser(description="Check live ChainWatch readiness, or explicitly run the fixture demo.")
    parser.add_argument("command", nargs="?", choices=("live", "demo"), default="live")
    args = parser.parse_args()
    receipt = run_demo() if args.command == "demo" else run_live()
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
