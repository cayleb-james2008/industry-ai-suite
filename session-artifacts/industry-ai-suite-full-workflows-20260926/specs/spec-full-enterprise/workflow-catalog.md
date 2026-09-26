> **Operator model:** the reader is a non-technical goal-bringer; plain English, no unexplained jargon, no technical questions; professional output in an operator-accessible voice.

# Product jobs and missing enterprise evidence

| Product | End-to-end job to implement locally | Enterprise evidence that cannot be assumed |
|---|---|---|
| LedgerBridge | Load ledger and bank rows, reconcile by reference, account for every row, queue unmatched and variance items for a finance reviewer. | Authorized ledger, bank statement, close period, reconciliation owner, posting policy. |
| MarketBrief | Load dated, licensed company/market research claims, flag stale/future observations, prepare a cited risk brief for analyst review. | Licensed source rights, chosen security/company scope, analyst mandate, source release timing. |
| ChainWatch | Load owned watch-only observations and baselines, validate addresses, flag unusual exposure, prepare an alert for treasury review. | Address ownership, approved chain-data provider and terms, baseline authority, alert recipient. |
| BacktestGuard | Load experiment metadata and dataset lineage, block lookahead/holdout misuse, present clean and blocked results for researcher review. | Actual experiment artifacts, target/return definition, source release times, researcher/approver. |
| ReplyCraft | Load consent-authorized case and approved support policy, draft a cited reply or escalation, leave sending to a human. | Customer consent, case record, policy-owner approval, support identity, send authority. |
| HandoffHub | Search only permissioned knowledge and an owner map, answer with citations and route a handoff to an authorized owner. | Organization document ACLs, current owner map, staff identity, handoff destination. |
| SentinelDesk | Load alerts and asset context, group incidents, compare relevant public threat context, prepare a responder handoff. | SIEM/alert authority, asset inventory and versions, on-call roster, containment policy. |
| SearchLift | Audit local owned HTML offline, prioritize traceable content/UX issues, prepare review drafts without publishing. | Site ownership and approved content goals; rankings/traffic impact need analytics and time. |
| PipelineRelay | Load consent-gated account context, summarize only approved facts, route a human sales handoff without outreach. | CRM/account authority, consent record, account owner, outreach policy. |
| OnboardPath | Load a permissioned employee request and approved HR policy, return a cited checklist and human HR handoff. | Employee access grant, employer policy, start-date/role context, HR owner and decision limits. |

The existing public-source slices may accompany these journeys as context but never replace the enterprise inputs in this table. Safe test fixtures prove engineering behavior only.
