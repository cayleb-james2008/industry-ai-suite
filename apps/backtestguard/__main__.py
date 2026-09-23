"""BacktestGuard read-only GDP chronology command."""

import argparse
import json

from .flow import run_live


def main() -> None:
    parser = argparse.ArgumentParser(description="Check a World Bank GDP time split; no market-return backtest or execution.")
    parser.parse_args()
    print(json.dumps(run_live(), sort_keys=True))


if __name__ == "__main__":
    main()
