"""BacktestGuard read-only GDP chronology command."""

import argparse
import json

from .flow import run_live


def main() -> None:
    parser = argparse.ArgumentParser(description="Check a World Bank GDP time split; no market-return backtest or execution.")
    parser.add_argument(
        "--cutoff-year",
        type=int,
        help="Actual World Bank observation year for the split (default keeps the existing 2011–2020 / 2021–2025 split).",
    )
    args = parser.parse_args()
    result = run_live(cutoff_year=args.cutoff_year)
    print(json.dumps(result, sort_keys=True))
    if args.cutoff_year is not None and result["data_status"] != "AVAILABLE":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
