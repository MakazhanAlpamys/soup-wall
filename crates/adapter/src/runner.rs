// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Reusable enforcement pipeline runner and mock executor interfaces for Task 3 testing.
//!
//! Provides the canonical `run_enforcement_pipeline` execution flow, policy evaluation,
//! and fail-closed handling for malformed or interrupted payloads.

use crate::{ToolActionCategory, ToolCallEvent, ToolClassification, Verdict, VerificationReceipt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Interface for executing authorized tool calls on the host/runtime.
pub trait ToolExecutor: Send + Sync {
    /// Execute the tool call and return the raw output or an execution error.
    fn execute(&self, event: &ToolCallEvent) -> Result<serde_json::Value, String>;
}

/// In-memory mock executor tracking invocations for verification and stress tests.
#[derive(Debug, Default)]
pub struct MockExecutor {
    call_count: Arc<AtomicUsize>,
}

impl MockExecutor {
    /// Create a new mock executor with zero initial calls.
    pub fn new() -> Self {
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Number of times `execute` was actually invoked.
    pub fn count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Reset the invocation counter.
    pub fn reset(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }
}

impl ToolExecutor for MockExecutor {
    fn execute(&self, _event: &ToolCallEvent) -> Result<serde_json::Value, String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({ "status": "mock_executed" }))
    }
}

/// Baseline policy evaluation mapping tool classification to enforcement verdicts.
pub fn evaluate_baseline_policy(classification: &ToolClassification) -> (Verdict, Option<String>) {
    if classification
        .categories
        .contains(&ToolActionCategory::Delete)
    {
        (
            Verdict::Deny,
            Some("Destructive delete is forbidden by security policy".into()),
        )
    } else if classification
        .categories
        .contains(&ToolActionCategory::SendData)
    {
        (
            Verdict::Deny,
            Some("Unapproved data exfiltration / egress is blocked".into()),
        )
    } else if classification
        .categories
        .contains(&ToolActionCategory::Read)
        && classification.uncertainty < 0.8
    {
        (Verdict::Allow, None)
    } else {
        // High uncertainty or unfamiliar tools require explicit operator approval
        (
            Verdict::Ask,
            Some("Unfamiliar tool action requires explicit operator approval".into()),
        )
    }
}

/// Baseline tool classifier used when an external model is not yet connected.
pub fn baseline_classify(event: &ToolCallEvent) -> ToolClassification {
    let name = event.tool_name.to_lowercase();
    let args_str = event.raw_arguments.to_string().to_lowercase();

    if name.contains("read") || name.contains("cat") {
        ToolClassification {
            categories: vec![ToolActionCategory::Read],
            confidence: 0.95,
            uncertainty: 0.05,
            reason: Some("File read operation detected".into()),
        }
    } else if name.contains("curl")
        || args_str.contains("https://")
        || args_str.contains("leak")
        || args_str.contains("attacker")
    {
        ToolClassification {
            categories: vec![ToolActionCategory::SendData],
            confidence: 0.98,
            uncertainty: 0.02,
            reason: Some("Network egress detected".into()),
        }
    } else if name.contains("rm") || name.contains("delete") {
        ToolClassification {
            categories: vec![ToolActionCategory::Delete],
            confidence: 0.99,
            uncertainty: 0.01,
            reason: Some("Destructive delete detected".into()),
        }
    } else {
        // Unfamiliar tool
        ToolClassification {
            categories: vec![],
            confidence: 0.40,
            uncertainty: 0.85,
            reason: Some("Unfamiliar tool action".into()),
        }
    }
}

/// Executes the full enforcement pipeline:
/// Classification -> Policy Evaluation -> Conditional Execution -> Verification Receipt.
pub fn run_enforcement_pipeline<E: ToolExecutor>(
    event: &mut ToolCallEvent,
    executor: &E,
) -> VerificationReceipt {
    let start = Instant::now();

    // 1. Validate incoming event schema
    if let Err(validation_err) = event.validate() {
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        return VerificationReceipt {
            call_id: event.call_id.clone(),
            session_id: event.session_id.clone(),
            verdict: Verdict::Deny,
            executed: false,
            refusal_message: Some(format!("Event validation failed: {validation_err}")),
            latency_ms,
        };
    }

    // 2. Classify tool call if not already classified
    let classification = match &event.classification {
        Some(c) => c.clone(),
        None => {
            let c = baseline_classify(event);
            event.classification = Some(c.clone());
            c
        }
    };

    // 3. Evaluate Policy
    let (verdict, refusal_message) = evaluate_baseline_policy(&classification);

    // 4. Enforce Decision
    let executed = if verdict == Verdict::Allow {
        executor.execute(event).is_ok()
    } else {
        // Deny or Ask: Execution is strictly prevented
        false
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    VerificationReceipt {
        call_id: event.call_id.clone(),
        session_id: event.session_id.clone(),
        verdict,
        executed,
        refusal_message,
        latency_ms,
    }
}

/// Ingests a raw JSON string, validating and running it with strict fail-closed handling.
///
/// If parsing fails or the payload is malformed, execution is strictly denied (`executed = false`).
pub fn execute_raw_json<E: ToolExecutor>(raw_json: &str, executor: &E) -> VerificationReceipt {
    let start = Instant::now();
    match serde_json::from_str::<ToolCallEvent>(raw_json) {
        Ok(mut event) => run_enforcement_pipeline(&mut event, executor),
        Err(err) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            VerificationReceipt {
                call_id: "unknown".into(),
                session_id: "unknown".into(),
                verdict: Verdict::Deny,
                executed: false,
                refusal_message: Some(format!(
                    "Malformed JSON payload rejected (fail-closed): {err}"
                )),
                latency_ms,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_json_fails_closed_and_never_executes() {
        let executor = MockExecutor::new();
        let malformed_payload = r#"{"call_id": "bad", "tool_name": 12345}"#; // invalid types

        let receipt = execute_raw_json(malformed_payload, &executor);

        assert_eq!(receipt.verdict, Verdict::Deny);
        assert!(!receipt.executed, "Malformed JSON must NEVER execute");
        assert_eq!(
            executor.count(),
            0,
            "Executor must not be touched on malformed JSON"
        );
        assert!(receipt.refusal_message.unwrap().contains("fail-closed"));
    }

    #[test]
    fn test_empty_json_fails_closed() {
        let executor = MockExecutor::new();
        let receipt = execute_raw_json("", &executor);

        assert_eq!(receipt.verdict, Verdict::Deny);
        assert!(!receipt.executed);
        assert_eq!(executor.count(), 0);
    }
}
