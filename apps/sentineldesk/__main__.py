"""Command-line entry point for the live SentinelDesk public-context review."""

import argparse
import json

from .flow import run_live


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Review the live CISA KEV catalog as public context, not organization alerts."
    )
    parser.parse_args()
    result = run_live()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED_SOURCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
