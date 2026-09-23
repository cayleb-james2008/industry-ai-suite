"""MarketBrief read-only public macro command."""

import argparse
import json

from .flow import run_live


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch a cited World Bank USA GDP macro slice; no quote or order capability.")
    parser.parse_args()
    print(json.dumps(run_live(), sort_keys=True))


if __name__ == "__main__":
    main()
