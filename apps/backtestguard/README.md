> **Operator model:** plain English first; technical details only where they verify the workflow.

# BacktestGuard

Quant researchers detect leakage, overfitting, or unsupported conclusions before sharing an experiment. This limited real-data chronology slice checks an observation-year split and routes the findings to a quant research reviewer; it does not evaluate a supplied experiment record.

The normal command `python3 -m apps.backtestguard` reads 15 actual World Bank U.S. GDP observations and checks chronology, disjoint train/holdout years, and a future-observation leakage probe. Its result is explicitly labelled `LIMITED` and not a completed backtest; release timing, a target/return definition, and an external experiment record are absent, so the full research-integrity job remains `UNVERIFIED`. It has no broker, order, strategy execution, promotion, or publication adapter. A source failure returns `DATA_UNAVAILABLE` without fixture fallback. Synthetic tenant CSVs remain only for labelled `run_demo()` adversarial regression tests and are not used by the normal command.

When the suite runner is explicitly invoked with `--ai-configured`, a task-limited model may provide one evidence-cited explanation for the human reviewer; it cannot establish experiment validity or change the `UNVERIFIED` job verdict. Its result is `AI CANDIDATE (unwitnessed)` until the independent witness is verified. Without that optional route the workflow remains deterministic. Run `python3 -m apps.backtestguard --help` for command options and `python3 -m unittest discover -s apps/backtestguard -p 'test_*.py' -v` for the app checks.
