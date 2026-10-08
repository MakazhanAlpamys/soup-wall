# Task 3 resilience: reproduction and local evidence

This suite covers malformed events, unfamiliar tools, invalid classifier outputs and
admission-daemon failures. It checks execution witnesses as well as reported decisions.
It is a deterministic resilience regression suite, not a load test or a measurement of
classifier effectiveness on unseen real-world traffic.

## Reproduce

Use the prerequisites in the [development guide](../DEVELOPMENT.md): Rust stable,
a native compiler and Python 3.10 or newer on `PATH`. The MCP target launches a local
Python subprocess and binds loopback sockets. Fixtures use temporary directories and
synthetic data; no external model, credentials, paid API or external MCP server is needed.
Cargo may download dependencies on the first build; `--locked` preserves the lockfile.

From the repository root, run both targets in one command:

```sh
cargo test --locked -p soup-wall-adapter -p agentfw --test resilience_tests --test mcp_admission
```

Expected result at this revision: **18 adapter tests and 18 MCP tests pass**, with no
ignored or filtered cases. The three new daemon-failure tests extend 15 existing MCP
checks. The adapter suite contains 18 new test functions, several with input tables.
The timeout case deliberately exercises the production five-second HTTP timeout.

For a focused reproduction of daemon failures (four cases, including the existing
startup-outage case):

```sh
cargo test --locked -p agentfw --test mcp_admission native_mcp_daemon_ -- --nocapture
```

For malformed JSON, unknown tools and invalid classification results:

```sh
cargo test --locked -p soup-wall-adapter --test resilience_tests -- --nocapture
```

On macOS, if a wider workspace check rejects a temporary path through `/var`, create
`target/task3-resilience/tmp` and set `TMPDIR` to its canonical absolute path before
running checks. The dedicated macOS CI job does this automatically.

## Scenario matrix and execution evidence

| Boundary | Inputs or fault | Required observation |
| --- | --- | --- |
| Event parser | Empty/truncated/non-JSON input, scalars, arrays, missing or wrongly typed fields, duplicate tool name | `Deny`, no panic, `executed: false`, nonempty refusal, zero executor entries and no file marker |
| Event validation | Empty identifiers, unsupported contract version, null arguments | `Deny`, no executor entry or file marker |
| Classification data | Invalid category/type, missing score, non-finite or out-of-range scores | `Deny`, no executor entry or file marker |
| Unknown or uncertain action | Unfamiliar tool, empty/Unknown categories, uncertainty at or above 0.8 | `Ask`, `executed: false`, zero executor entries and no file marker |
| Mixed actions | Read with Unknown, Delete, SendData or ChangePermissions | Read never weakens Ask/Deny; no execution |
| Untrusted description | Delete tool claims it is safe and asks to ignore policy | `Deny`, no execution |
| Positive control | Allowed Read with nested arguments and Unicode | Exactly one executor entry and file marker; original arguments and identifiers preserved |
| Executor error | Allowed executor creates a marker and then returns an error | Effect remains witnessed, `executed: true`, error reported |
| Startup outage | Admission daemon unavailable before server startup | MCP server never starts (existing test) |
| Post-manifest outage | Shut down the daemon and its pooled connections after successful setup | Existing server receives no tool call; host sees EOF and gateway fails |
| Admission timeout | Real daemon accepts the call request but delays its response | Exactly one call-admission request observed; production timeout closes gateway, no tool call in server ledger |
| Result-stage outage | Allow and execute a call, stop daemon, release the prepared server result | Exact original call appears once in ledger; result witness exists, host receives no result and gateway fails |

The adapter witness combines `MockExecutor::count()`, recorded events and an independent
temporary filesystem marker. The real MCP fixture records the original JSON-RPC call
line at the server and checks host stdout. Its gated result has a bounded wait so a
failed assertion does not leave a fixture waiting indefinitely.

The result-stage test intentionally has **one executed call**. Blocking delivery of an
unverified result does not undo an effect that already occurred. This differs from
pre-execution refusal, which requires zero actual tool calls.

## Local validation evidence — 2026-10-08

Tested against prerequisite PR #33 at `1eb07fed7a4d08c3c0995eda00731b67d546e51d`
plus this contribution's tests and CI configuration. Platform: macOS 26.3.1, arm64;
Rust 1.99.0; Python 3.14.3. Debug profiles used `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_INCREMENTAL=0` to reduce local disk use.
The dependency cache allowed adding `--offline` to the locked Cargo commands.

| Check | Observed result |
| --- | --- |
| Focused command above | 36 passed, 0 failed, 0 ignored |
| `cargo test --locked --workspace` | 847 passed, 0 failed, 5 ignored |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed |
| Python `scripts/tests` discovery | 124 discovered: 119 passed, 5 skipped |
| Python `scripts/benchmarks` discovery | 44 tests run: 28 passed, 16 skipped; 2 additional class-level skips |
| `python3 scripts/check_docs.py` | Passed |

The five ignored Rust checks require a live local model, disposable Redis,
disposable PostgreSQL, an operator-selected OIDC issuer and real SAML metadata.
The five Python script skips require native Windows launcher, ACL or DPAPI behavior.
Benchmark skips require an explicitly selected pinned AgentDojo checkout/runtime or
disposable native Agent: 16 individual tests and two whole test classes were skipped.
Python reports 18 skip records in total; the two class-level records are not included
in its `Ran 44 tests` count. No skipped environment was silently treated as accepted.

Ignored and skipped tests are not counted as successful executions. Repository-wide
validation commands and platform-dependent checks are listed in
[CONTRIBUTING.md](../../CONTRIBUTING.md#before-opening-a-pull-request).

The existing Linux workspace CI picks up both test targets. The new
`Native macOS admission resilience` job runs them natively on `macos-15` and retains
`environment.log`, `adapter-resilience.log` and `mcp-admission.log` as the
`task3-native-macos-resilience` artifact for 14 days. A workflow definition is not a
passed platform result: use the check results attached to the tested commit as evidence.

## Scope and integration limits

- The public `ToolCallEvent` runner tests and native MCP admission tests exercise two
  boundaries. They do not prove that an agreed real harness uses the shared runner
  end to end; that adapter/classifier integration belongs to Task 2.
- `Ask` stays blocked in headless execution. This suite does not add an approval path
  or a strict-policy switch to the public runner.
- Invalid classifier data is covered with local values. A real model-service crash or
  model timeout needs the eventual Task 1 service interface and Task 2 integration.
- Daemon faults are controlled local unavailability and response delay, not an OS crash,
  soak test, or proof against all resource-exhaustion failures.
- The suite does not estimate classifier accuracy, false-block rates or end-to-end
  latency overhead. Use a labelled corpus, explicit treatment of benign `Ask`, and
  repeated measurements against a control path for those evaluations.
- This contribution is stacked on PR #33. Merge that prerequisite first, refresh the
  branch against `main`, then rerun the combined checks before merging this PR.
- PR #35 already supplies the shared Docker launcher. After these branches converge,
  add `("soup-wall-adapter", "resilience_tests")` to its suite list. Its existing
  `agentfw/mcp_admission` target will discover the new daemon scenarios automatically.
