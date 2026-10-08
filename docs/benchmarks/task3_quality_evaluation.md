# Task 3 Quality Evaluation and Enforcement Benchmark

This document reports the quality evaluation, security guarantees, and empirical latency
benchmarks for the Task 3 test environment in `soup-wall-adapter`.

## Shared Event Contract Specification

The enforcement pipeline is anchored on the shared wire contract `sw-tool-event/0.1` defined in
`crates/adapter/src/tool_call.rs`:

- **Event Identity**: `call_id`, `session_id`, `tool_name`, `raw_arguments`.
- **Classification Categories**: `read`, `write`, `delete`, `send_data`, `change_permissions`, `unknown`.
- **Classification Score Bounds**: `confidence` in `[0.0, 1.0]`, `uncertainty` in `[0.0, 1.0]`, non-NaN.
- **Verification Receipt**: `call_id`, `session_id`, `verdict` (`allow`, `ask`, `deny`), `executed` (boolean), `refusal_message`, and `latency_ms`.

## Security Guarantees & Policy Evaluation

The baseline enforcement pipeline (`crates/adapter/src/runner.rs`) guarantees strict fail-closed
and non-weakening behavior:

1. **Non-Weakening Precedence**:
   - `Delete`, `SendData`, and `ChangePermissions` take strict precedence over `Read`. Even if a multi-action tool contains both `Read` and `ChangePermissions`, the verdict evaluates strictly to `Verdict::Deny`.
   - `Write` operations strictly require operator confirmation (`Verdict::Ask`), and adding `Read` to a classification (`[Read, Write]`) does not downgrade or release the write requirement.
2. **Unfamiliar Tool Interception**:
   - Any tool classified as `Unknown` or having `uncertainty >= 0.8` evaluates to `Verdict::Ask` (manual operator confirmation required). It never automatically executes.
3. **Execution Isolation**:
   - On `Verdict::Deny` or `Verdict::Ask`, the tool executor is never invoked (guaranteed 0 physical calls).
4. **Fail-Closed Validation**:
   - Null arguments fail validation (`null_arguments`).
   - Declared schemas (`tool_schema`) are checked against the [supported schema subset](../specs/shared_event_contract.md#supported-tool-schemas): missing required fields, type mismatches, disallowed additional properties, malformed definitions and unsupported constraints evaluate to fail-closed `Verdict::Deny`.
   - Out-of-bounds or NaN confidence scores evaluate to fail-closed `Verdict::Deny`.
   - Empty or malformed JSON payloads evaluate to fail-closed `Verdict::Deny` (`executed: false`).
5. **Runtime Error Differentiation**:
   - If an allowed call fails during physical host execution, `executed: true` is preserved alongside the runtime error string, differentiating host runtime errors from firewall interception.

## In-Memory Runner Microbenchmark

The figures below represent an in-memory microbenchmark of `run_enforcement_pipeline` and `execute_raw_json` using `MockExecutor`. They evaluate policy evaluation and dispatch overhead without network transport (MCP transport or daemon boundaries):

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

All 40 test cases pass in `soup-wall-adapter`:

- 22 unit tests in `crates/adapter/src/lib.rs`, `tool_call.rs`, and `runner.rs`.
- 4 demonstration integration test cases in `crates/adapter/tests/enforcement_pipeline.rs`.
- 1 latency and throughput microbenchmark in `crates/adapter/tests/latency_bench.rs`.

- 13 schema enforcement regression tests in `crates/adapter/tests/schema_validation.rs`, with independent executor counters and temporary file witnesses.
