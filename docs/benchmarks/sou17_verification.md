# SOU-17 independent failure, overlap and replay verification

This procedure extends the initial [Task 3 resilience suite](task3_resilience.md)
for [SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior),
[roadmap R06, bounded P01–P02](../ROADMAP.md). It uses existing production code and
safe local fixtures. Owner: konung3; PR review coordinator: Nari_Ab.

**Final runtime acceptance is pending SOU-15.** On preparation base
`fdf4bf716a87b88f17a6241e710bb447885fb8df`, adapter tests import
`soup_wall_adapter::runner::{run_enforcement_pipeline, evaluate_baseline_policy}`.
Native/MCP tests launch the actual `agentfw` gateway and native admission service,
but that production path does not yet call the shared adapter runner. Passing the
two surfaces separately does not establish the integrated milestone. No test-local
classifier or policy pipeline is substituted for the missing integration.

## Reproduce and retain raw evidence

Use the Rust/native compiler/Python prerequisites in [DEVELOPMENT](../DEVELOPMENT.md).
Tests bind loopback listeners and start a synthetic Python MCP server; they need no
external model, model credentials, production data or paid access. Cache dependencies
with `cargo fetch --locked` before adding `--offline`.

From a clean checkout of the exact revision under review:

```sh
python3 scripts/verify-sou17.py --expected-commit "$(git rev-parse HEAD)" --offline
```

For preparation with uncommitted changes, explicitly add `--allow-dirty`; that run
records the patch and file hashes and cannot count as final candidate acceptance.
Use `--out target/sou17-verification` to select the evidence parent directory.
The command builds and enumerates the adapter `resilience_tests`, native
`native_endpoint`, and actual MCP `mcp_admission` targets. It runs each discovered
test individually, rejects empty/misfiltered runs, bounds each test to 60 seconds,
and retains failures, timeouts and skips instead of counting them as passes.

Each run writes JSON and Markdown summaries, original test output, exact source
revision and dirty state, source/lockfile/policy/test hashes, toolchain/host identity,
binary hashes and emitted `SOU17_EVIDENCE` records. Registry and policy definitions
remain in the fixture source; emitted records identify actual fixture hashes where
provided. The launcher reuses the existing Docker baseline's report/process helpers;
it does not define another internal event contract or execution policy.

The existing native macOS CI job runs this command pinned to `GITHUB_SHA` and
retains its raw logs/JSON/Markdown in `task3-native-macos-resilience` for 14 days.
A workflow definition is not evidence of a passed platform check.

The shared Docker procedure remains `python3 scripts/test-environment.py` in
[DEVELOPMENT](../DEVELOPMENT.md#shared-local-agentmcp-test-environment). Docker on
macOS exercises Linux; retain a native run separately. On macOS, use a canonical
`TMPDIR` if the native boundary rejects the `/var` symlink.

## Required observations

| Case | Witness and expected outcome |
| --- | --- |
| Malformed JSON, missing fields, invalid scores including NaN/infinities | Shared runner refuses; zero executor entries and no filesystem marker |
| Unknown/read+unknown, mixed read+delete/send/permissions | Imported policy keeps Ask/Deny blocked before executor entry |
| Overlapping Read, Write, Unknown and a hard-risk label, with uncertainty 1.0 | Deny survives all tested label positions/directions; 24 independent zero-effect checks |
| Useful benign call | Original arguments/IDs reach the real fixture once and its correlated result reaches the client |
| Allowed executor returns an error after an effect | Effect count stays one; original correlated error is inspected and returned when admitted |
| Replay with the same ID but changed tool/arguments | First call executes once; second call is refused without a new effect |
| Unsupported two-call batch | Gateway refuses the batch; neither call reaches the fixture |
| Second call while a first result is pending | First effect remains; second call is refused; pending protected result is not released |
| Unsupported cancellation before a call | Session closes before any tool effect |
| Cancellation after an effect while result is gated | Session closes with one recorded effect and no original result released |
| Two sessions on the same real daemon | A denied call in one session does not interrupt a permitted call in its peer; equal native IDs are session-scoped |
| Fresh daemon restart with an old result pending | Old completion is withheld; a new gateway/session can perform a useful call using the same native ID |
| Startup/post-manifest outage and admission timeout | No executor effect; gateway refuses/terminates |
| Result-stage outage | One effect already happened; original result bytes are withheld |

The MCP executor witness is the independent server ledger containing original
synthetic JSON-RPC calls. The release witness is actual gateway stdout; a filesystem
marker proves when a result has been prepared but remains gated. Refusal/error text
may reach the client without the original protected result. An error, EOF, or a
self-reported `executed: false` alone is never evidence that nothing ran. Withholding
a result cannot undo the tool's side effect.

Cancellation is currently an unsupported notification and terminates the transport.
These cases do **not** establish cancellation of an admission already in flight:
the present relay awaits admission before reading another client frame. Define and
verify that boundary on the integrated SOU-15 candidate before claiming cancellation
support. Existing pipelined/concurrent checks test explicit refusal, not support for
parallel calls. Batch support is also refused.

## Local validation — 2026-10-09

Preparation on macOS arm64, Rust 1.99.0, Python 3.14.3, default Cargo features,
locked offline dependencies, dev/test debug information disabled and incremental
compilation disabled:

| Contributor check | Outcome |
| --- | --- |
| Shared adapter resilience target | 19 passed; no failures/ignored cases |
| Actual MCP target | 25 passed; no failures/ignored cases |
| Native HTTP endpoint target | 28 passed; no failures/ignored cases |
| Workspace Rust tests | 857 passed, 0 failed, 5 ignored |
| Formatting and workspace/all-target Clippy with warnings denied | Passed |
| Python script tests | 150 run: 145 passed, 5 Windows-specific skips |
| Python benchmark tests | 44 run: 28 passed, 16 individual skips; two additional class-level skips |
| Documentation checker | 49 Markdown files, 249 local links, 0 errors |

The five ignored Rust checks need a live model, disposable Redis/PostgreSQL or real
OIDC/SAML configuration. Benchmark skips require explicitly selected AgentDojo or
native Agent environments; two class-level skip records are outside Python's
`Ran 44 tests` count. No unavailable environment is counted as successful acceptance.
The exact-source launcher and CI artifacts identify the tested revision and retain
individual raw outcomes; these preparation counts do not close the integration gate.

## Metrics and remaining runtime acceptance

The report records raw test outcomes and fixture elapsed time, including subprocess
startup, deliberate waits and cleanup. This is not classifier latency or enforcement
overhead; do not subtract unrelated test durations as a performance estimate.
Classification accuracy, uncertainty calibration and a held-out false-block rate are
not measured here. The positive controls check useful calls and session isolation;
their regression pass count is not a general false-interruption rate.

SOU-15 must supply one integrated exact commit, its stable interface and classifier,
registry/schema/resource/policy revisions and configuration. Then run the same suites
through that production boundary, including invalid classifier outputs, trusted
hard-Deny versus weaker classification, Unknown/Ask, model-service failure, session
isolation, replay/restart and both execution/release witnesses. Record any unsupported
mapping, failure or skip explicitly. Unagreed or unmet accepted performance/error
limits keep SOU-17 open; the local regression launcher cannot approve acceptance.

The October 12 candidate is due at 15:00; run immediately, report blocking failures
by 18:00, and finish verification by 23:59 as specified in the Linear task. Any code
change after a run requires the affected checks again on the new revision.

## Code scanning triage — 2026-10-09

Authorized GitHub access showed **6 open Critical alerts and 74 closed alerts** for
`is:open branch:main`. Each open alert lists only `main` among affected branches.
Other unscanned branches are not certified. The current alert snippets and the Rust
configuration's last scan both identify exact main commit
`fdf4bf716a87b88f17a6241e710bb447885fb8df`, scanned October 8.

[CodeQL Rust configuration](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/2b7122206b8ac86cd7b88fd927bd502861908b2a6bfb3dfdcf2968009cb71086)
reported working as expected: CodeQL 2.27.1, `/language:rust`, rust-queries 0.1.43,
rust-all 0.2.22 and threat-models 1.0.58. Default setup also shows Python and Actions
at that commit, with push and pull-request scan events targeting main. This does not
verify required-check/ruleset enforcement; [SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status)
owns that configuration acceptance. No scan settings were changed or duplicated.

All six findings use `rust/hard-coded-cryptographic-value`:

| Alert | Location | Assessment and rationale |
| --- | --- | --- |
| [85](https://github.com/SoupTeam/soup-wall/security/code-scanning/85) | `provider_baseline.rs:165` | False-positive recommendation: PBKDF2 known-answer input; fixed expected bytes/FIPS rejection |
| [86](https://github.com/SoupTeam/soup-wall/security/code-scanning/86) | `provider_baseline.rs:193` | False-positive recommendation: compliant PBKDF2 known-answer parameters and fixed expected bytes |
| [87](https://github.com/SoupTeam/soup-wall/security/code-scanning/87) | `provider_baseline.rs:524` | False-positive recommendation: negative test asserts unsupported algorithm before parsing |
| [88](https://github.com/SoupTeam/soup-wall/security/code-scanning/88) | `provider_baseline.rs:549` | False-positive recommendation: FIPS negative test rejects SHA-1 PBKDF2 |
| [89](https://github.com/SoupTeam/soup-wall/security/code-scanning/89) | `provider_parity.rs:502` | False-positive recommendation: fixed PBKDF2 provider-parity expected output and FIPS rejection |
| [90](https://github.com/SoupTeam/soup-wall/security/code-scanning/90) | `provider_parity.rs:532` | False-positive recommendation: compliant fixed PBKDF2 parity inputs/expected output |

Both files are under `vendor/kryptering/tests/`, explicit Cargo integration-test
targets separate from the `src/lib.rs` production library. The application workspace
excludes the vendored crate as a member, although production uses its library as a
dependency. Source searches found no production inclusion of these test files;
release packaging ships application binaries and the vendored licence. Fixed
cryptographic test vectors are intentional inputs, with no evidence of a deployed
credential at these locations. Randomizing them to silence CodeQL would weaken the
known-answer checks.

[Machine-readable inventory and source links](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-09.json)
record each URL/rule/severity/path/commit/hash and assessment. **All six alerts remain
open.** No dismissal, code fix or remediation issue was made: the inspected findings
do not establish a production defect. Nari coordinates review; MakazhanAlpamys is the
proposed affected-code reviewer based on the vendored provider's introduction, not a
verified CODEOWNERS assignment. Record reviewer-supported disposition and any actual
dismissal rationale, then refresh scan evidence on the final candidate. A working scan
with open recommendations is not a clean scan, and static analysis does not establish
tool-call enforcement effectiveness.
