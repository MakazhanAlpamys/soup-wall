# Task 3 Quality Evaluation and Enforcement Benchmark

This document records the scoped runner regressions and historical in-memory
microbenchmark for Task 3 test support. It does not report real Team 1 classifier
quality, shared native integration, or production protection rates.

## In-crate test interface

The runner uses the scoped `sw-tool-event/0.1` test interface defined in
`crates/adapter/src/tool_call.rs`. Its [documented boundaries](../specs/shared_event_contract.md)
remain distinct from the shared runtime classifier contract:

- **Event Identity**: `call_id`, `session_id`, `tool_name`, `raw_arguments`.
- **Classification Categories**: `read`, `write`, `delete`, `send_data`, `change_permissions`, `unknown`.
- **Classification Score Bounds**: `confidence` in `[0.0, 1.0]`, `uncertainty` in `[0.0, 1.0]`, non-NaN.
- **Verification Receipt**: `call_id`, `session_id`, `verdict` (`allow`, `ask`, `deny`), `executed` (boolean), `refusal_message`, and `latency_ms`.

## Tested validation and dispatch behavior

The hardcoded fixture policy in `crates/adapter/src/runner.rs` has the following
regressions. Valid fixture classifications and independent witnesses are used;
the demo classifier does not attest tool effects or replace active Agent policy:

1. **Non-Weakening Precedence**:
   - `Delete`, `SendData`, and `ChangePermissions` take strict precedence over `Read`. Even if a multi-action tool contains both `Read` and `ChangePermissions`, the verdict evaluates strictly to `Verdict::Deny`.
   - `Write` operations strictly require operator confirmation (`Verdict::Ask`), and adding `Read` to a classification (`[Read, Write]`) does not downgrade or release the write requirement.
2. **Unfamiliar Tool Interception**:
   - An `Unknown` label or `uncertainty >= 0.8` requires Ask unless a stronger dangerous-action restriction requires Deny. Neither decision automatically dispatches the executor.
3. **Execution Isolation**:
   - On `Verdict::Deny` or `Verdict::Ask`, the tool executor is never invoked (guaranteed 0 physical calls).
4. **Fail-Closed Validation**:
   - Null arguments fail validation (`null_arguments`).
   - Declared schemas (`tool_schema`) are checked against the [supported schema subset](../specs/shared_event_contract.md#supported-tool-schemas): missing required fields, type mismatches, disallowed additional properties, malformed definitions and unsupported constraints evaluate to fail-closed `Verdict::Deny`.
   - Out-of-bounds or NaN confidence scores evaluate to fail-closed `Verdict::Deny`.
   - Empty or malformed JSON payloads evaluate to fail-closed `Verdict::Deny` (`executed: false`).
5. **Runtime Error Differentiation**:
   - If an allowed executor call returns an error, `executed: true` records dispatch alongside the error string. Completed effects and result release require separate witnesses; this receipt does not attest them.

## In-Memory Runner Microbenchmark

The historical figures below were recorded by the author at `41609bf`, before later classifier fixes. They are not measurements of the final integrated candidate; rerun the benchmark on the exact candidate before quoting current performance.

They represent an in-memory microbenchmark of `run_enforcement_pipeline` and `execute_raw_json` using `MockExecutor`. They evaluate policy evaluation and dispatch overhead without network transport (MCP transport or daemon boundaries):

- **Platform**: Apple Silicon (macOS arm64), Rust 1.99.0
- **Build Profile**: Debug (`[unoptimized + debuginfo]`)
- **Reproduction Command**: `cargo test -p soup-wall-adapter --test latency_bench -- --nocapture`
- **Timing Resolution**: Wall-clock duration truncated to integer microseconds (`as_micros()`).

| Scenario | Invocations | Throughput | Mean Latency | p50 Latency | p95 Latency | p99 Latency |
|---|---|---|---|---|---|---|
| **Benign Allowed Call** | 1,000 | ~392,000 ops/sec | 1.19 µs | 1 µs | 2 µs | 2 µs |
| **Blocked Egress / Denial** | 1,000 | ~413,000 ops/sec | 1.07 µs | 1 µs | 2 µs | 2 µs |
| **Raw JSON Parse + Policy** | 1,000 | ~208,000 ops/sec | 4.07 µs | 4 µs | 4 µs | 5 µs |

In local runs, observed p99 latencies for the pure in-memory pipeline remained under 10 µs across 1,000 samples.

## Test Matrix Summary

The updated test matrix has 60 cases in `soup-wall-adapter`. Independent pinned
Rust 1.98/Linux AMD64 verification of the updated #33/#37 integration tree passed
all 60, and all 18 real MCP admission tests, without failures or ignores:

- 23 unit tests in `crates/adapter/src/lib.rs`, `tool_call.rs`, and `runner.rs`.
- 5 public-runner integration test cases in `crates/adapter/tests/enforcement_pipeline.rs`.
- 1 latency and throughput microbenchmark in `crates/adapter/tests/latency_bench.rs`.
- 13 schema enforcement regression tests in `crates/adapter/tests/schema_validation.rs`, with independent executor counters and temporary file witnesses.

- 18 resilience regression tests in `crates/adapter/tests/resilience_tests.rs`.

The [resilience reproduction and evidence report](task3_resilience.md) also covers
real MCP daemon outages, admission timeouts and result withholding.