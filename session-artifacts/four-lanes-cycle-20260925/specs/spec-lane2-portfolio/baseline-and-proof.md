# Lane 2 intake baseline and prior proof

This companion carries the pinned starting state and limits on prior verification. Hashes are recorded at intake or verified for the named prior artifacts; they do not prove that later working-tree bytes are unchanged.

## Current intake pins

| Item | Intake identity | Boundary |
|---|---|---|
| `industry-ai-suite` | HEAD `1122d8a615b70a7225ac0993577817c1d05c91a6` | Fresh results must be tied to the revision actually assessed. |
| Suite `README.md` | SHA-256 `9a6802a7eb58f8f708d1b965af1f0fef20a3af87dc76ead6ac0414888d367732` | Intake reference only. |
| Suite `CONTRACT.md` | SHA-256 `d07e17ebd148a426e7b75a2baa54de521d06208077640789eb2988fbfab83175` | Existing contract governs source/job claims; verify relevant terms before use. |
| Suite `LIVE-SOURCE-CONTRACT.md` | SHA-256 `e13e70d8c8045107e75548193d5f240b2b8f97cb51ea2047fff1fe512e98df1d` | Existing live-source rules remain binding. |
| `agentic-resume` portfolio | HEAD `2571fb04be6931223068456384f97c71b8aba9aa` | Preserve the pre-existing `.gitignore` change and untracked `resume/__pycache__/`; do not alter either. |

## Prior verified artifacts and scope

| Artifact | Path and SHA-256 | What carries forward | What it does not prove / supersession |
|---|---|---|---|
| Prior portfolio-suite kernel | `/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/spec/SPEC.md` — `d120816b6c377723238f6187b6c9f818426022268d1a0c0e2f80ad4815a49105` | A broader 15-capability suite/portfolio contract; its historical validation record is the prior `.memlog.md` below. | This Lane 2 SPEC supersedes its broader scope only for the current run, including the stricter no-publication boundary. It does not invalidate prior evidence or source contracts. |
| Prior kernel validation log | `/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/spec/.memlog.md` — `b690452c4e585b375f03b6929825f779ed658ea8f18518ec569112051e6863e` | Records Pass 1, Pass 2, and `spec_check` exit 0 for that prior kernel. | Historical record only; this run did not rerun those prior checks or treat them as current product verification. |
| Prior adopted-work companion | `/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/spec/adopted-prior-work.md` — `b02e88551190a7e7231784bda15b34556f4e57b849d02ae64fca16a1397d8cfe` | Its recorded source, privacy, and verification boundaries inform this contract. | Broader prior scope is not a new Lane 2 authorization. |
| Independent AI execution verification | `/home/cayleb/Work/session-artifacts/portfolio-suite-finish-20260923/lead/AI-EXECUTION-VERIFICATION-20260924.md` — `7c585bdd13bd6184a807107e0eedd8af160046ccc7f5f8c7bc851b95d48e65ad` | Lead-witnessed transport calls for LedgerBridge, MarketBrief, BacktestGuard, and SentinelDesk. | Historical calls only; no general/current transport proof, no proof for the other six apps, and no claim about task quality. |

## Carry-forward boundaries

- The full jobs for all ten apps remain `WIP`/`INCOMPLETE`/`UNVERIFIED` unless fresh independent evidence proves otherwise.
- Public records do not establish private company data; source terms must be verified before use; an HTTP response alone is not a valid-data or workflow proof.
- Fixtures/cache are not live data. Existing independent AI witness verification proves transport only, not task quality. Deterministic fallback remains labeled fallback.
- The three deep slices are selected after fresh user-run evidence and must use shared source adapters without requiring unavailable private data.
- No push, pull request, deployment, or publication is authorized this cycle.
