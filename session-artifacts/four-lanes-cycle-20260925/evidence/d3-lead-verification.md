# D3 BacktestGuard — independent lead verification

**Lead verification window:** 2026-09-26T04:17:11Z–04:17:13Z. These are fresh lead-run receipts, separate from the worker's test/live claims.

## Commands and receipts

| Command | Exit | Receipt SHA-256 |
|---|---:|---|
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/backtestguard -p 'test_*.py' -v` | 0 | `tests.txt` — `d31fa6dc82c7fcda3510d05820c7ccebad2b822732b0f7723664eec15a7c417b` (15 tests, OK) |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.backtestguard --help` | 0 | Help output sent to `/dev/null`; no source request. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.backtestguard` | 0 | `default.json` — `32f31879bae2ffa1895373376f037ec59efdf8aad69e907707497b9f00536000` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.backtestguard --cutoff-year 2018` | 0 | `cutoff-2018.json` — `1e771f532c81986b538fb97a8bcac3d88b2dc3112e73bb20626cf0376ed41061` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m apps.backtestguard --cutoff-year 2026` | 2 | `invalid-2026.json` — `7652f52eda635eb19a838cad955529eba2f7febc8b3d1d9ec0d7254c827aa560` |

All receipts are under `session-artifacts/four-lanes-cycle-20260925/evidence/d3-lead/`.

## Observed live output

- The default run returned 15 World Bank USA GDP observations, source response SHA-256 `2e54d1e502eae38a14474323ff0a3353c2f5d711c00009c41f4d752f99fedce3`, source IDs 2011–2025, source-provided as-of years, exact terms URL, and retrieval time `2026-09-26T04:17:12Z`. It preserved the default 2011–2020 training / 2021–2025 holdout split.
- `--cutoff-year 2018` returned the same 15 source observations and response SHA, with training 2011–2018 and holdout 2019–2025; the output retained the future-year leakage warning.
- `--cutoff-year 2026` returned `DATA_UNAVAILABLE`, `cutoff_status=INVALID`, and `requested_cutoff_year=2026`; the JSON said no default or substitute was used. The CLI exited 2 as documented by the new path.
- Current exact dataset-license check is in `evidence/baseline-assessment.md`: World Bank indicator page HTTP 200, response SHA-256 `d76cf419c87b033290a9c8bc2e89fbd84d40dc0dc95237a880f28ca833b5bf12`, and the suite's exact `CC BY-4.0` predicate returned true.
- Every valid output remains `LIMITED PUBLIC GDP CHRONOLOGY / PROVENANCE CHECK — not a completed backtest`; the external experiment record, target/return, and source release time remain `UNVERIFIED`. AI is not invoked (`NON-AI / DETERMINISTIC FALLBACK`); no orders, trades, strategy promotion, or side effects are possible.
