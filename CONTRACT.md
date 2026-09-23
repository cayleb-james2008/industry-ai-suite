> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# Shared core import and safety contract (P1)

This source-tree package is shared infrastructure for LedgerBridge, MarketBrief, ChainWatch, BacktestGuard, ReplyCraft, HandoffHub, SentinelDesk, SearchLift, PipelineRelay, and OnboardPath. It does not implement any of those jobs. Each app owns its task-specific policy, evidence rules, normal/denial fixtures, result, uncertainty, and human handoff. The core is not proof that any app is complete.

## Clean first run

Requires Python 3.14 and its standard library; no package installation or `.env` file is used.

```sh
python3 -m suite_core --help
python3 -m suite_core demo
python3 -m suite_core check
python3 -m unittest discover -s tests -p 'test_core*.py' -v
```

`demo`/`check` build fresh process-local demo keys, store audit data in a temporary directory, and remove it on exit. No credentials, database, or persistent state are required. `contract` prints this document. A clean source checkout is the supported import surface: start Python from the repository root so `suite_core` is on `sys.path`.

## Public exports

Import from `suite_core`: `HMACTokenCodec`, `Authenticator`, `Principal`, `AccessPolicy`, `SecurityCore`, `AuditLog`, `FixtureSchema`, `FixtureAdapter`, `FixtureData`, `redact`, `ApprovalAuthority`, `SimulatedSink`, `PromptSentinel`, `GroundedOutputValidator`, `LocalOpenAIClient`, `NonAIFallback`, and their documented error/result types.

## App worker pattern

The example below is runnable at the repository root. The random keys are deliberately demo-only; production must inject two separate 32-byte-or-longer secrets from the app's approved runtime secret provider. Do not commit secrets, write them to fixtures, or copy `.env` files. A service must retain its injected keys across restarts using its external secret provider; generating a new key on each production start invalidates existing tokens.

```python
from pathlib import Path
import secrets
import time
from tempfile import TemporaryDirectory

from suite_core import (
    AccessPolicy, AuditLog, Authenticator, FixtureAdapter, FixtureSchema,
    HMACTokenCodec, Principal, SecurityCore,
)

root = Path("suite_core/fixtures")
auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))  # demo only
policy = AccessPolicy(
    {"tenant-alpha": {"analyst": {"demo-policy-001"}}},
    {"analyst": {"read", "draft"}},
)
actor = Principal("tenant-alpha", "demo-user", "analyst")
token = auth.issue(actor, expires_at=int(time.time()) + 60)
with TemporaryDirectory(prefix="suite-core-contract-") as runtime:
    audit = AuditLog(Path(runtime) / "audit.jsonl")
    core = SecurityCore(auth, policy, audit)
    principal = core.authorize(
        token, tenant_id=actor.tenant_id, action="read", evidence_ids=("demo-policy-001",)
    )
    fixture = FixtureAdapter(root, principal.tenant_id).load(
        "demo.json",
        FixtureSchema({"case_id": str, "summary": str, "evidence_id": str, "email": str}),
    )
    print(fixture.provenance)
```

The demo fixture tenant is `tenant-alpha`; replace its path and schema with each app's checked-in synthetic fixtures. In production, route actor identity and token issuance through the owning app's trusted identity boundary rather than exposing an arbitrary-token minting function to ordinary callers.

### Required per-request order

1. Verify the HMAC token and its integer expiry. `SecurityCore.authorize` checks exact tenant, the tenant's allowed role, the role's allowed action, and every requested evidence ID. Any failure raises a generic `AccessDenied`, records a denial without requested evidence, and returns no protected data. Keep the action/evidence allowlists explicit; do not use wildcard grants.
2. Load only a tenant-partitioned fixture: `FixtureAdapter(base_dir, principal.tenant_id)` reads from `<base_dir>/<tenant_id>/`. It accepts JSON or CSV only, rejects absolute paths, `..`, symlink escapes, duplicate JSON keys/CSV columns, schema mismatch, and empty fixture sets. The receipt includes tenant, relative source ID, format, schema, and SHA-256 of the exact input bytes. JSON's `declared` provenance is untrusted metadata, not a verified claim.
3. Before putting any untrusted text into a model prompt, run `PromptSentinel().check(text, protected_canaries=...)`. It fails closed on common instruction-override, secret-exfiltration, cross-tenant, or canary signals; a regression test also covers paraphrased requests to reproduce a system message verbatim. This lexical sentinel is a safety layer, not a complete prompt-injection detector and cannot be treated as covering every attack.
4. Validate model output with `GroundedOutputValidator().validate(text, cited_evidence=..., allowed_evidence=..., protected_canaries=...)`. Every output must contain inline `[evidence:ID]` citations that exactly match the explicit citation list; IDs must be in this request's allowlist. Cross-tenant IDs, citation mismatch, or canary output raises `UnsafeModelOutput`. The output is redacted before it is returned. This proves bounded citations, not factual correctness.
5. For consequential work, call only the in-process `SimulatedSink`. `ApprovalAuthority` accepts a signed approver authentication token and a trusted `SecurityCore`; that core must authorize the explicit `approve` action for the exact tenant and evidence. A caller-created `Principal`, a forged/expired/wrong-tenant token, a role without `approve`, or the requester approving their own action is denied and audited. `confirmed=True` is still required, but is not identity proof and is insufficient by itself. The resulting approval token binds tenant, requester, approver role, action, evidence, and expiry. The sink verifies the exact scope and appends a `SIMULATED ONLY` receipt in memory plus an audit event. It has no network or external side-effect adapter. Replacing it with a live integration is outside this contract and requires a separately reviewed piece.

### Approval example

This block is independently runnable. The synthetic `Authenticator` below represents an app-owned trusted identity boundary; ordinary request handlers must not be allowed to issue arbitrary approver tokens or construct the approval authority.

```python
from pathlib import Path
import secrets
import tempfile
import time

from suite_core import (
    AccessPolicy, ApprovalAuthority, AuditLog, Authenticator, HMACTokenCodec,
    Principal, SecurityCore, SimulatedSink,
)

with tempfile.TemporaryDirectory(prefix="suite-core-approval-") as runtime:
    audit = AuditLog(Path(runtime) / "audit.jsonl")
    requester = Principal("tenant-alpha", "demo-user", "analyst")
    approver = Principal("tenant-alpha", "human-reviewer", "approver")
    approver_auth = Authenticator(HMACTokenCodec(secrets.token_bytes(32)))
    approver_policy = AccessPolicy(
        {"tenant-alpha": {"approver": {"demo-policy-001"}}},
        {"approver": {"approve"}},
    )
    approval_security = SecurityCore(approver_auth, approver_policy, audit)
    approvals = ApprovalAuthority(
        HMACTokenCodec(secrets.token_bytes(32)), approver_roles={"approver"},
        security_core=approval_security,
    )
    approver_auth_token = approver_auth.issue(approver, expires_at=int(time.time()) + 60)
    approval_token = approvals.issue(
        approver_auth_token, tenant_id=requester.tenant_id,
        requester_actor=requester.actor_id, action="send_reply",
        evidence_ids=("demo-policy-001",), expires_at=int(time.time()) + 60, confirmed=True,
    )
    sink = SimulatedSink(approvals, audit, allowed_actions={"send_reply"})
    receipt = sink.execute(
        requester, action="send_reply", evidence_ids=("demo-policy-001",),
        approval_token=approval_token,
    )
    assert receipt.status == "SIMULATED ONLY"
```

Only call `issue(... confirmed=True)` after both the trusted security core accepts the signed approver token for `approve` and the UI/service boundary receives explicit human confirmation. The trusted identity service—not the requesting worker—must issue the signed approver token after authenticating the human. Never let the requesting worker approve its own action. A missing, expired, forged, wrong-role, cross-tenant, wrong-evidence, self-approval, or wrong-action token is refused before the sink records anything, and denial is audited without evidence contents.

## Audit and personal-data handling

`AuditLog` is an append-only JSONL writer with fixed fields: UTC time, actor, tenant, role, action, allowlisted evidence IDs, approval boolean, approving actor, and outcome. It does not accept arbitrary payloads or credentials. Write failures raise; the protected operation must stop. Call `redact(value)` before ordinary outputs/logging: sensitive named fields (including compound names such as `customer_name`, `first_name`, `street_address`, and `api_secret`) and recognizable emails/phone numbers are replaced. This is minimization, not a substitute for app-specific data classification; apps should avoid collecting unnecessary personal data in the first place. Use opaque identifiers for actors, tenants, actions, and evidence.

The audit path is caller-owned runtime state, not a fixture input. Select a private, persistent location in the host app. The CLI intentionally uses temporary state only. Neither tokens nor HMAC keys are written to audit records.

## Model route and truthful fallback

`LocalOpenAIClient` defaults to `http://127.0.0.1:52652/v1`, accepts only a literal loopback IP over plain HTTP, disables proxy use, probes `/models`, and then can make OpenAI-compatible `/chat/completions` calls. It never contacts hosted endpoints or handles API credentials. Probe with `client.probe()` at runtime; `complete()` probes again before invocation. The constructor defaults are `timeout=2.0` seconds, `max_tokens=96`, and `max_prompt_chars=12000`; prompt and system text are each capped. `max_prompt_chars` may be configured only up to 50,000, output tokens only from 1 through 256, and a completion deadline only above 0 and up to 180 seconds. The complete-call deadline includes the short (at most 2-second) `/models` preflight and the completion request.

Apps can keep the accidental-call default short, then opt in per request:

```python
client = LocalOpenAIClient()
prompt = "Draft a careful reply to synthetic case demo-001 using [evidence:policy-001]."
system_instruction = "Use only supplied authorized evidence; cite it and state uncertainty."
result = client.complete(
    prompt,
    system=system_instruction,
    timeout=90,
    max_tokens=96,
)
```

`timeout` and `max_tokens` can also be set as constructor defaults: `LocalOpenAIClient(timeout=90, max_tokens=96)`. Per-call values override those defaults and are revalidated. Rejecting an oversized or invalid prompt/limit happens before any HTTP request. A successful `/models` probe alone is not a model invocation; only a successful `/chat/completions` response is labelled `AI / LOCAL`. Even then, pass output through `GroundedOutputValidator` before exposing it. The owned loopback fake used in P1 tests verifies only the HTTP wire payload and deadline behavior; it is not model or AI evidence.

`NonAIFallback().result(reason=..., evidence_ids=...)` returns `NON-AI / DETERMINISTIC FALLBACK` and a manual evidence handoff. It does not simulate or generate an AI answer. When no model is reachable, keep this status and do not count the app as AI-backed. The original P1 probe on 2026-09-22 found `127.0.0.1:52652` closed (`connect_ex=111`, connection refused); the lead now reports `/v1/models` HTTP 200. This refinement did not independently probe or invoke the lead-owned endpoint, and no model completion is claimed.

**AI proof limitation:** a `LocalOpenAIClient` object and its self-reported route/model/response hashes do not independently prove that a real model produced the response. Those fields can be fabricated; no cryptographic model provenance or attestation is supplied here. Only a lead-owned live model observation can certify AI completeness. Local self-claims alone must remain **INCOMPLETE**. The current suite aggregator only checks receipt fields and hashes, so it cannot enforce that rule; changing its certification boundary is outside this P1-security-r2 write scope. Keep the suite **INCOMPLETE** until the lead records live observation and the aggregator is tightened in a separately scoped change.

## Per-app test pattern

Each of the ten apps should add its own `tests/test_core_<app>.py` or app-local tests. Use safe synthetic fixtures and the same API, then assert all of the following for that workflow:

- task-specific expected result, exact input/evidence provenance, uncertainty/risk, and named human handoff;
- normal path, meaningful denial/exception path, tenant-A/B canary refusal, role/action denial, forged signature, and expired token;
- fixture schema/provenance, traversal and symlink confinement, and a PII-redacted exposed result/log;
- hostile untrusted-document canary refusal and evidence/citation validation;
- zero sink receipts and zero external calls before approval, then exactly one `SIMULATED ONLY` receipt after a scoped approval;
- model status, actual invocation evidence if available, and honest fallback label otherwise. Never substitute a mock model response for an AI receipt.

Run the shared regression command after app additions:

```sh
python3 -m unittest discover -s tests -p 'test_core*.py' -v
```

## Limits and not-yet-verified work

- P1 is a shared core only. No app package, business workflow, production deployment, customer, or measured business outcome is claimed.
- The checked-in demo is deliberately deterministic and **not AI**. A real completion, exact model identity/version, and AI quality remain unverified by this piece and must be evidenced by the lead.
- HMAC provides authenticity/integrity, not encryption, key rotation, revocation, or identity proof by itself. The host must securely issue and retain keys and authenticate the human approver through the trusted identity boundary; possession of a locally constructible `Principal` is not authentication.
- `AccessPolicy` is in-process; each app must load trusted policy, enforce authorization before data access, and avoid sharing mutable policy from untrusted callers.
- The prompt sentinel uses lexical patterns and cannot guarantee detection of every prompt-injection attack. Evidence/citation checks do not establish factual truth. Apps still need app-specific adversarial tests and human review.
- The audit file is append-only through this API, not a tamper-proof external ledger. Protect its filesystem and back it up under the app's retention policy.
- The simulated sink can never send messages, post marketing, trade, move money, contain threats, or call any external side effect. No live side-effect adapter is supplied.
- Source-tree imports from the repo root are the supported setup; no wheel/install flow is included, to keep the runtime and test path standard-library-only.

## CLI-Anything applicability

The target is a new plain-Python library/CLI, not an existing external application with a real backend or an installed CLI-Anything harness. `cli-anything` was not discoverable in the current environment. The method is therefore **NOT APPLICABLE for P1**; the suite supplies its own deterministic `python3 -m suite_core` commands and makes no CLI-Anything installation/runtime claim.
