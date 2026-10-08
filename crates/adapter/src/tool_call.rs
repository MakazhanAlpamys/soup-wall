// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Shared Tool Call and Classification Event Contract.
//!
//! Implements the shared event contract between Adapter (Task 2),
//! Tool Classifier (Task 1), and Quality Evaluation / Test Environment (Task 3).

use crate::Verdict;
use serde::{Deserialize, Serialize};

/// Contract version for tool call events.
pub const TOOL_CONTRACT_VERSION: &str = "sw-tool-event/0.1";

/// Action categories for tool classification per Task 1 specification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ToolActionCategory {
    Read,
    Write,
    Delete,
    SendData,
    ChangePermissions,
    Unknown,
}

/// Structured classification output produced by Task 1 classifier (Rule-based or Jev/ML).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ToolClassification {
    /// Categorized action types (supports tools with multiple action types).
    pub categories: Vec<ToolActionCategory>,
    /// Prediction confidence score in range [0.0, 1.0].
    pub confidence: f32,
    /// Model / heuristic uncertainty score in range [0.0, 1.0].
    pub uncertainty: f32,
    /// Optional rationale or attribution explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ToolClassification {
    /// Helper to construct an unknown classification with maximum uncertainty.
    pub fn unknown(reason: Option<String>) -> Self {
        Self {
            categories: vec![ToolActionCategory::Unknown],
            confidence: 0.0,
            uncertainty: 1.0,
            reason,
        }
    }

    /// Check if the classification contains high-risk actions (delete, change permissions, or send data).
    pub fn is_high_risk(&self) -> bool {
        self.categories.iter().any(|c| {
            matches!(
                c,
                ToolActionCategory::Delete
                    | ToolActionCategory::ChangePermissions
                    | ToolActionCategory::SendData
            )
        })
    }

    /// Validate confidence and uncertainty score bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.confidence < 0.0 || self.confidence > 1.0 || self.confidence.is_nan() {
            return Err("invalid_confidence");
        }
        if self.uncertainty < 0.0 || self.uncertainty > 1.0 || self.uncertainty.is_nan() {
            return Err("invalid_uncertainty");
        }
        Ok(())
    }
}

/// Normalized internal tool call event emitted by Adapter (Task 2)
/// and consumed by Classifier (Task 1), Policy Engine, and Verification (Task 3).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ToolCallEvent {
    /// Contract version identifier (must be `sw-tool-event/0.1`).
    pub contract_version: String,
    /// Unique identifier of the tool call (preserves native harness call identifier).
    pub call_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Tool name declared by the harness / model (e.g. `bash`, `read_file`, `http_post`).
    pub tool_name: String,
    /// Raw unparsed or JSON arguments passed by the model.
    pub raw_arguments: serde_json::Value,
    /// Tool description provided by the manifest (treated as UNTRUSTED data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_description: Option<String>,
    /// Optional tool schema declared in manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_schema: Option<serde_json::Value>,
    /// Classification result attached after Task 1 classifier evaluates the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<ToolClassification>,
}

impl ToolCallEvent {
    /// Create a new incoming tool call event before classification.
    pub fn new(
        call_id: impl Into<String>,
        session_id: impl Into<String>,
        tool_name: impl Into<String>,
        raw_arguments: serde_json::Value,
    ) -> Self {
        Self {
            contract_version: TOOL_CONTRACT_VERSION.into(),
            call_id: call_id.into(),
            session_id: session_id.into(),
            tool_name: tool_name.into(),
            raw_arguments,
            tool_description: None,
            tool_schema: None,
            classification: None,
        }
    }

    /// Validate required identifiers, contract version, and declared tool schema.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.contract_version != TOOL_CONTRACT_VERSION {
            return Err("unsupported_contract_version");
        }
        if self.call_id.is_empty() {
            return Err("empty_call_id");
        }
        if self.session_id.is_empty() {
            return Err("empty_session_id");
        }
        if self.tool_name.is_empty() {
            return Err("empty_tool_name");
        }
        if self.raw_arguments.is_null() {
            return Err("null_arguments");
        }
        if let Some(schema) = &self.tool_schema {
            validate_json_schema(&self.raw_arguments, schema)?;
        }
        Ok(())
    }
}

/// Validate a JSON value against a basic JSON Schema specification.
pub fn validate_json_schema(
    val: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), &'static str> {
    let schema_obj = match schema.as_object() {
        Some(obj) => obj,
        None => return Ok(()),
    };

    // 1. Type validation
    if let Some(expected_type) = schema_obj.get("type").and_then(|t| t.as_str()) {
        match expected_type {
            "object" if !val.is_object() => return Err("schema_type_mismatch_expected_object"),
            "array" if !val.is_array() => return Err("schema_type_mismatch_expected_array"),
            "string" if !val.is_string() => return Err("schema_type_mismatch_expected_string"),
            "number" | "integer" if !val.is_number() => {
                return Err("schema_type_mismatch_expected_number")
            }
            "boolean" if !val.is_boolean() => return Err("schema_type_mismatch_expected_boolean"),
            "null" if !val.is_null() => return Err("schema_type_mismatch_expected_null"),
            _ => {}
        }
    }

    // 2. Object validation
    if let Some(obj) = val.as_object() {
        if let Some(required) = schema_obj.get("required").and_then(|r| r.as_array()) {
            for req in required {
                if let Some(field) = req.as_str() {
                    if !obj.contains_key(field) {
                        return Err("schema_missing_required_property");
                    }
                }
            }
        }

        let properties = schema_obj.get("properties").and_then(|p| p.as_object());
        let additional_allowed = schema_obj
            .get("additionalProperties")
            .and_then(|a| a.as_bool())
            .unwrap_or(true);

        for (k, v) in obj {
            if let Some(props) = properties {
                if let Some(prop_schema) = props.get(k) {
                    validate_json_schema(v, prop_schema)?;
                    continue;
                }
            }
            if !additional_allowed {
                return Err("schema_additional_properties_forbidden");
            }
        }
    }

    // 3. Array items validation
    if let Some(arr) = val.as_array() {
        if let Some(items_schema) = schema_obj.get("items") {
            for item in arr {
                validate_json_schema(item, items_schema)?;
            }
        }
    }

    Ok(())
}

/// Final receipt verifying physical execution and enforcement outcome (Task 3).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VerificationReceipt {
    pub call_id: String,
    pub session_id: String,
    pub verdict: Verdict,
    /// Whether the tool was physically executed by the runtime.
    pub executed: bool,
    /// Refusal message returned to the caller if denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_message: Option<String>,
    /// Pipeline latency measured in milliseconds.
    pub latency_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_call_event_serializes_and_deserializes() {
        let mut event = ToolCallEvent::new(
            "call-42",
            "sess-1",
            "file_reader",
            json!({"path": "/etc/passwd"}),
        );
        event.tool_description = Some("Reads arbitrary files from disk".into());
        event.classification = Some(ToolClassification {
            categories: vec![ToolActionCategory::Read],
            confidence: 0.95,
            uncertainty: 0.05,
            reason: Some("Argument targets a path with read intent".into()),
        });

        let json_str = serde_json::to_string_pretty(&event).unwrap();
        let parsed: ToolCallEvent = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.call_id, "call-42");
        assert_eq!(parsed.tool_name, "file_reader");
        assert_eq!(parsed.raw_arguments["path"], "/etc/passwd");
        assert!(parsed.validate().is_ok());

        let classification = parsed.classification.unwrap();
        assert_eq!(classification.categories, vec![ToolActionCategory::Read]);
        assert_eq!(classification.confidence, 0.95);
        assert_eq!(classification.uncertainty, 0.05);
    }

    #[test]
    fn high_risk_action_detection() {
        let safe = ToolClassification {
            categories: vec![ToolActionCategory::Read],
            confidence: 0.9,
            uncertainty: 0.1,
            reason: None,
        };
        assert!(!safe.is_high_risk());

        let dangerous = ToolClassification {
            categories: vec![ToolActionCategory::Read, ToolActionCategory::SendData],
            confidence: 0.85,
            uncertainty: 0.15,
            reason: Some("Exfiltrates data over network".into()),
        };
        assert!(dangerous.is_high_risk());
    }

    #[test]
    fn validation_rejects_empty_identifiers() {
        let mut event = ToolCallEvent::new("", "sess-1", "bash", json!({}));
        assert_eq!(event.validate(), Err("empty_call_id"));

        event.call_id = "call-1".into();
        event.tool_name = "".into();
        assert_eq!(event.validate(), Err("empty_tool_name"));
    }
}
