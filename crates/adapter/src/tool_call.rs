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

/// Validate a value against the adapter's bounded JSON Schema subset.
///
/// Supports boolean schemas, types (including unions), properties, required,
/// additionalProperties and items. Unsupported constraints and malformed schema
/// definitions are rejected before checking the value. No references are resolved.
pub fn validate_json_schema(
    val: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), &'static str> {
    validate_schema_definition(schema, 0)?;
    validate_schema_value(val, schema)
}

const MAX_SCHEMA_DEPTH: usize = 64;

fn validate_schema_definition(
    schema: &serde_json::Value,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err("schema_depth_limit_exceeded");
    }
    if schema.is_boolean() {
        return Ok(());
    }
    let object = schema.as_object().ok_or("schema_invalid_definition")?;
    for keyword in object.keys() {
        if !matches!(
            keyword.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "items"
                | "$schema"
                | "$id"
                | "$comment"
                | "title"
                | "description"
                | "default"
                | "examples"
                | "readOnly"
                | "writeOnly"
                | "deprecated"
        ) {
            return Err("schema_unsupported_keyword");
        }
    }
    if let Some(dialect) = object.get("$schema") {
        if dialect.as_str() != Some("https://json-schema.org/draft/2020-12/schema") {
            return Err("schema_unsupported_dialect");
        }
    }
    for keyword in ["$id", "$comment", "title", "description"] {
        if object.get(keyword).is_some_and(|value| !value.is_string()) {
            return Err("schema_invalid_annotation");
        }
    }
    for keyword in ["readOnly", "writeOnly", "deprecated"] {
        if object.get(keyword).is_some_and(|value| !value.is_boolean()) {
            return Err("schema_invalid_annotation");
        }
    }
    if object
        .get("examples")
        .is_some_and(|value| !value.is_array())
    {
        return Err("schema_invalid_annotation");
    }
    if let Some(types) = object.get("type") {
        if let Some(name) = types.as_str() {
            validate_schema_type_name(name)?;
        } else {
            let names = types.as_array().ok_or("schema_invalid_type")?;
            if names.is_empty() {
                return Err("schema_invalid_type");
            }
            for (index, name) in names.iter().enumerate() {
                validate_schema_type_name(name.as_str().ok_or("schema_invalid_type")?)?;
                if names[..index].contains(name) {
                    return Err("schema_invalid_type");
                }
            }
        }
    }
    if let Some(required) = object.get("required") {
        let fields = required.as_array().ok_or("schema_invalid_required")?;
        for (index, field) in fields.iter().enumerate() {
            if !field.is_string() || fields[..index].contains(field) {
                return Err("schema_invalid_required");
            }
        }
    }
    if let Some(properties) = object.get("properties") {
        for property in properties
            .as_object()
            .ok_or("schema_invalid_properties")?
            .values()
        {
            validate_schema_definition(property, depth + 1)?;
        }
    }
    for keyword in ["additionalProperties", "items"] {
        if let Some(subschema) = object.get(keyword) {
            validate_schema_definition(subschema, depth + 1)?;
        }
    }
    Ok(())
}

fn validate_schema_type_name(name: &str) -> Result<(), &'static str> {
    if matches!(
        name,
        "object" | "array" | "string" | "number" | "integer" | "boolean" | "null"
    ) {
        Ok(())
    } else {
        Err("schema_unsupported_type")
    }
}

fn validate_schema_type(val: &serde_json::Value, name: &str) -> Result<(), &'static str> {
    match name {
        "object" if !val.is_object() => Err("schema_type_mismatch_expected_object"),
        "array" if !val.is_array() => Err("schema_type_mismatch_expected_array"),
        "string" if !val.is_string() => Err("schema_type_mismatch_expected_string"),
        "number" if !val.is_number() => Err("schema_type_mismatch_expected_number"),
        "integer"
            if !(val.is_i64()
                || val.is_u64()
                || val
                    .as_f64()
                    .is_some_and(|number| number.is_finite() && number.fract() == 0.0)) =>
        {
            Err("schema_type_mismatch_expected_integer")
        }
        "boolean" if !val.is_boolean() => Err("schema_type_mismatch_expected_boolean"),
        "null" if !val.is_null() => Err("schema_type_mismatch_expected_null"),
        _ => Ok(()),
    }
}

fn validate_schema_value(
    val: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), &'static str> {
    match schema.as_bool() {
        Some(true) => return Ok(()),
        Some(false) => return Err("schema_false"),
        None => {}
    }
    let object = schema.as_object().ok_or("schema_invalid_definition")?;
    if let Some(types) = object.get("type") {
        if let Some(name) = types.as_str() {
            validate_schema_type(val, name)?;
        } else {
            let names = types.as_array().ok_or("schema_invalid_type")?;
            if !names.iter().any(|name| {
                name.as_str()
                    .is_some_and(|name| validate_schema_type(val, name).is_ok())
            }) {
                return Err("schema_type_mismatch");
            }
        }
    }
    if let Some(values) = val.as_object() {
        if let Some(required) = object.get("required").and_then(|value| value.as_array()) {
            for field in required {
                let field = field.as_str().ok_or("schema_invalid_required")?;
                if !values.contains_key(field) {
                    return Err("schema_missing_required_property");
                }
            }
        }
        let properties = object.get("properties").and_then(|value| value.as_object());
        for (name, value) in values {
            if let Some(property) = properties.and_then(|properties| properties.get(name)) {
                validate_schema_value(value, property)?;
            } else if let Some(additional) = object.get("additionalProperties") {
                validate_schema_value(value, additional)?;
            }
        }
    }
    if let Some(values) = val.as_array() {
        if let Some(items) = object.get("items") {
            for value in values {
                validate_schema_value(value, items)?;
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
