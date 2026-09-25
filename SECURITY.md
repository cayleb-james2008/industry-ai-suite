> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# Shared security and AI setup

This file is the single configuration reference for `suite_core` credentials, provider routes, trace files, and the shared redaction model. The ten workflows remain **WIP / INCOMPLETE**; configuration or a successful API response does not establish a complete job or independently verified AI.

## Allow and deny model for sensitive data

`suite_core.redact(value)` recursively copies mappings and sequences without changing caller-owned objects. It replaces values for sensitive field names, including compound and camel-case variants such as `customer_email`, `api_key`, `authorization`, `accessToken`, `account_number`, and `firstName`. Free-text values in person-bearing fields (for example `author`, `reviewer`, `customer_name`, `contact_name`, `first_name`, and `full_name`) are masked wholesale; that rule does not depend on knowing the person's name. Other free text screens email addresses, recognizable phone numbers, labeled account/routing/card numbers, numbered street addresses, authorization/header values, credential query or URL-fragment parameters, URL user-info, bearer values, common service-token shapes, and capitalized word-pairs that look like names.

The name detector is intentionally conservative: it may redact ordinary proper nouns. An explicit allowlist retains known organization and provenance labels, including “World Bank,” “United States,” “Federal Register,” “Proposed Rule,” and “Arista VeloCloud Orchestrator.” `project_source_metadata` also retains declared identifier fields (for example `source_id`, `record_id`, CVE IDs, and commit SHAs) and source-label fields exactly, while applying ordinary person/credential redaction to other values and allowlisted free-text record fields. Opaque evidence IDs, dates, ordinary measurements, and uncredentialed source links remain available unless they match a deny pattern.

This is minimization, not complete personal-data discovery. Capitalized-bigram detection can miss all-capital names, other writing systems, unusual formats, or a name that matches an explicitly allowlisted organization label. Minimize inputs before calling the helper, keep source-specific field allowlists, and do not treat an unchanged string as proof that it contains no personal data.

## Authenticated approvals and effects

Approval identity comes only from an expiring signed authentication token verified by the trusted `SecurityCore`, with explicit `approve` permission for the exact tenant and evidence scope. The public `ApprovalAuthority.verify` API has no caller-settable clock; a clock can be injected only when constructing an authority for deterministic tests. A caller-created `Principal`, a forged or expired token, a wrong role/scope, self-approval, or a missing human confirmation is denied. The signed approval token binds the approver, requester, tenant, action, evidence, and expiry. Each token can be consumed only once by the same in-memory `ApprovalAuthority`; a second use is denied and audited without protected evidence.

The provided `SimulatedSink` is in-memory and has no network or external-effect adapter. Its one-use replay set is process-local, not a durable cross-restart ledger. Any real consequential effect would require separately reviewed, durable replay storage and a new scoped security review; it is not part of this suite.

Audit events use fixed fields and do not contain tokens, keys, arbitrary request text, or protected evidence from denied requests. Keep audit paths in private runtime state, not in fixture directories or source control.

## Network boundary

Public source adapters construct fixed HTTPS requests for their admitted providers, disable environment proxies, and refuse redirects. The OpenAI-compatible client separately requires an exact host allowlist for each configured route, disables proxies and redirects, caps request time and response size, and sends hosted credentials only in the authorization header. Plain HTTP is allowed only on an explicit port for numeric loopback IPs `127.0.0.1` and `[::1]`; the `localhost` hostname and lookalike names are refused. Wildcard host entries are refused.

## AI provider settings

The default workflow remains non-AI. With no provider configured, app output keeps its deterministic handoff and reports `AI: unavailable (UNVERIFIED)`. Use `python3 -m suite_core doctor` to check whether configuration is present; it does not make a network request and never prints a secret.

The optional configured runner is explicit:

```sh
python3 scripts/run_all.py --ai-configured --out-dir ./run-output
```

The command uses the settings below only when that flag is supplied. Every app-reported call remains `AI CANDIDATE (unwitnessed)` in the app and runner; only the separate `scripts/verify_witness.py` can return a transport-only verdict.

### Free local OpenAI-compatible server (recommended)

Use a locally installed server such as `llama-server` or Ollama with a model already present on the machine. The suite never starts or stops the model server. A numeric loopback IP needs no API key; list the same numeric IP used in the URL. The `localhost` hostname is not admitted:

```sh
export SUITE_AI_PROVIDER=openai-compatible
export SUITE_AI_BASE_URL=http://127.0.0.1:8080/v1
export SUITE_AI_ALLOWED_HOSTS=127.0.0.1
export SUITE_AI_MODEL=the-model-id-advertised-by-the-local-server
export SUITE_AI_TRACE_PATH=./private-runtime/ai-traces.jsonl
python3 -m suite_core doctor
python3 scripts/run_all.py --ai-configured --out-dir ./run-output
```

The client checks that the selected model is advertised before making a completion request. It refuses a model catalog entry or completion usage report with non-zero price/cost, then stops using that route for the rest of the client session.

### Bring your own hosted OpenAI-compatible endpoint and key

Hosted OpenAI-compatible endpoints are disabled by default, even when a URL and credential are configured. The client refuses a non-loopback route before opening a connection unless the separate `SUITE_AI_ALLOW_HOSTED=true` opt-in is present. A user deploying their own external integration may opt in, but must provide an exact hostname allowlist and an exact model allowlist; the selected model must match `SUITE_AI_ALLOWED_MODELS`. This is not a free route and may incur provider charges. Never put the credential in a command, example, fixture, trace, receipt, or repository file. Use a secret manager, an injected environment variable, or a private key file. This run leaves the opt-in OFF and makes no hosted calls.

```sh
export SUITE_AI_PROVIDER=openai-compatible
export SUITE_AI_BASE_URL=https://api.example.invalid/v1
export SUITE_AI_ALLOWED_HOSTS=api.example.invalid
export SUITE_AI_ALLOWED_MODELS=your-provider-model-id
export SUITE_AI_ALLOW_HOSTED=true
export SUITE_AI_MODEL=your-provider-model-id
export SUITE_AI_API_KEY_FILE=/run/secrets/industry-ai-suite-key
export SUITE_AI_TRACE_PATH=./private-runtime/ai-traces.jsonl
python3 -m suite_core doctor
python3 scripts/run_all.py --ai-configured --out-dir ./run-output
```

The `.invalid` host is a non-routable example; replace it with the provider's documented values. A secret file must be a regular file owned by the current user with no group/world permissions (for example, mode `0600`). Alternatively, an already-injected `SUITE_AI_API_KEY` environment value may be used; do not set both key sources. The client refuses missing or unsafe secret files without displaying their contents. It refuses non-zero model prices and non-zero request costs reported by a provider, but absence of a price report is not proof that a hosted route is free.

OpenCode Zen free chat-completion requests from a non-OpenCode client received HTTP 403: the response stated that the free tier can only be used from within OpenCode. The suite does not read the OpenCode credential store, and users must not spoof an OpenCode client identity. Use the free local route above, or bring your own authorized OpenAI-compatible endpoint and credential.

### Environment variables

| Variable | Purpose |
|---|---|
| `SUITE_AI_PROVIDER` | `openai-compatible`; unset configuration is unavailable. |
| `SUITE_AI_BASE_URL` | OpenAI-compatible API base path, such as a provider's `/v1` endpoint. |
| `SUITE_AI_ALLOWED_HOSTS` | Comma-separated exact hostnames or loopback IPs; wildcards are rejected. |
| `SUITE_AI_ALLOW_HOSTED` | Hosted-route opt-in; only the exact value `true` enables non-loopback routes. Unset or `false` keeps hosted routes disabled. |
| `SUITE_AI_ALLOWED_MODELS` | Comma-separated exact model IDs allowed only for an explicitly opted-in hosted route. |
| `SUITE_AI_MODEL` | Exact model ID advertised by the provider. |
| `SUITE_AI_API_KEY` | Runtime-injected secret value; never store it in repository files. |
| `SUITE_AI_API_KEY_FILE` | Alternative private secret-file path; file must be owned by the current user and mode `0600`-equivalent. |
| `SUITE_AI_TRACE_PATH` | Optional app-reported append-only JSONL trace path; default is `~/.local/state/industry-ai-suite/ai-traces.jsonl`. Never independent verification. |

Exactly one API-key source may be configured. A local loopback server may omit both credential variables and does not need the hosted opt-in or hosted model allowlist. `python3 -m suite_core doctor` reports route configuration readiness only; it does not prove provider availability, model quality, zero price, or AI completion. The model-catalog price check blocks completion for a model that reports a non-zero price; it cannot establish that a hosted provider is free when price data is absent.

### Independent local witness route

For a narrow transport observation, the verifier starts the separate standard-library witness process in front of one configured OpenAI-compatible upstream. The proxy binds only to `127.0.0.1`, accepts only `/models` and `/chat/completions`, uses an exact upstream host allowlist, disables proxy environment settings, and refuses redirects. It forwards request/response bodies but its private JSONL witness log contains only hashes, UTC time, upstream host, HTTP status, and provider-returned `id`, `model`, `usage`, and `created`; it never writes request or response bodies or Authorization headers. Provider IDs and model names must pass conservative character/length checks and credential-shape detection (`sk-`, GitHub and Slack tokens, `AKIA`, bearer text, JWTs, and high-entropy runs). Rejected metadata is stored only as SHA-256 plus a redaction flag.

At startup, the proxy generates a random per-session HMAC-SHA256 key and keeps it only in memory. Each canonical JSON record is HMACed and includes the SHA-256 of the preceding exact JSONL line. The verifier cannot learn the key while requests are served. On `SIGTERM`, `SIGINT`, stdin `reveal`, or stdin close, the proxy stops accepting new requests, drains active requests, closes its socket, then writes the key and final chain head to its own stdout. The key is explicitly labeled as a session HMAC key, not a provider credential. Use a fresh private witness-log path for each session; a pre-existing log is refused. An app sharing the process user cannot forge an entry during the session without the in-memory key.

Example for a local model server listening on port `8080` (run the proxy in a separate process; use a new private path each time):

```sh
python3 scripts/ai_witness_proxy.py \
  --upstream http://127.0.0.1:8080/v1 --allow-host 127.0.0.1 \
  --port 0 --witness-log "$HOME/.local/state/industry-ai-suite/ai-witness-session.jsonl"
```

Set the suite's normal OpenAI-compatible settings to use the proxy's announced loopback port; the runner still emits only app-reported candidates:

```sh
export SUITE_AI_PROVIDER=openai-compatible
export SUITE_AI_BASE_URL=http://127.0.0.1:PORT/v1
export SUITE_AI_ALLOWED_HOSTS=127.0.0.1
export SUITE_AI_MODEL=the-model-id-advertised-by-the-local-server
export SUITE_AI_TRACE_PATH="$HOME/.local/state/industry-ai-suite/app-reported-traces.jsonl"
python3 scripts/run_all.py --ai-configured --out-dir "$HOME/.local/state/industry-ai-suite/run-output"
```

After the call, stop the proxy with `SIGTERM` or type `reveal` in its own stdin. Save the single JSON reveal line from proxy stdout to a private file. Put only app-reported call records into a private JSON array, then run:

```sh
python3 scripts/verify_witness.py \
  --witness-log "$HOME/.local/state/industry-ai-suite/ai-witness-session.jsonl" \
  --reveal "$HOME/.local/state/industry-ai-suite/witness-reveal.json" \
  --app-calls "$HOME/.local/state/industry-ai-suite/app-calls.json"
```

The verifier is separate and is not imported by app code, `suite_core`, or `scripts/run_all.py`. It returns `VERIFIED` only when every HMAC and previous-line link is valid, the last line hash matches the head printed at reveal, and one unused, complete HTTP 200 entry matches the app-reported provider ID, model, host, usage, creation time, and exact request/response hashes. The runner never reads the witness log or labels anything `VERIFIED`; it continues to report `AI CANDIDATE (unwitnessed)` with the match hashes. Even a verifier `VERIFIED` result covers transport only—not model quality, grounding, or workflow completion. The suite remains `INCOMPLETE` without the remaining lead evidence.

## Provider trace and limits

For every successful call through `OpenAICompatibleClient`, the core writes an append-only JSONL trace outside the app's decision fields with `trace_provenance: app-reported`. It records provider-returned response ID, model, usage, creation time, provider host, UTC time, exact request/response transport SHA-256 values, and redacted request/response content. A caller may include evidence IDs and a human-handoff note in the trace context. The trace is opened without following symlinks, owned by the current user, and private to that user. API authorization headers and credential values are never included.

The app trace is evidence for a lead to inspect, not independent proof or a cryptographic provider attestation. App receipts and app-selected trace paths are never sufficient to mark a call verified; the runner always leaves it as `AI CANDIDATE (unwitnessed)`. Only the separate verifier reads the HMAC witness chain and returns a transport-only verdict. `GroundedOutputValidator` still rejects missing, mismatched, or unauthorized citations. Rejected model text stays rejected and is not replaced with templated text labeled AI.
