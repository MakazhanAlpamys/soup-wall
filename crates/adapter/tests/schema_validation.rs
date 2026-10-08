// SPDX-License-Identifier: Apache-2.0
//! Regression checks at the public runner boundary, with independent disk effects.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde_json::{json, Value};
use soup_wall_adapter::{
    run_enforcement_pipeline, MockExecutor, ToolCallEvent, ToolExecutor, Verdict,
};

struct MarkerExecutor {
    calls: MockExecutor,
    marker: PathBuf,
}

impl ToolExecutor for MarkerExecutor {
    fn execute(&self, event: &ToolCallEvent) -> Result<Value, String> {
        let result = self.calls.execute(event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.marker)
            .map_err(|err| err.to_string())?;
        let record = json!({
            "call_id": event.call_id,
            "session_id": event.session_id,
            "raw_arguments": event.raw_arguments
        });
        writeln!(file, "{record}").map_err(|err| err.to_string())?;
        Ok(result)
    }
}

fn check(schema: Value, arguments: Value, expected: Verdict) {
    let dir = tempfile::tempdir().unwrap();
    let executor = MarkerExecutor {
        calls: MockExecutor::new(),
        marker: dir.path().join("executed.jsonl"),
    };
    let mut event = ToolCallEvent::new(
        "native-call-42",
        "native-session-7",
        "read_file",
        arguments.clone(),
    );
    event.tool_schema = Some(schema.clone());

    let receipt = run_enforcement_pipeline(&mut event, &executor);
    assert_eq!(
        receipt.verdict, expected,
        "schema={schema}, args={arguments}"
    );
    assert_eq!(receipt.call_id, "native-call-42");
    assert_eq!(receipt.session_id, "native-session-7");
    let entries: Vec<Value> = fs::read_to_string(&executor.marker)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    match expected {
        Verdict::Deny => {
            assert!(!receipt.executed);
            assert!(receipt.refusal_message.is_some());
            assert_eq!(
                executor.calls.count(),
                0,
                "no dispatch on invalid schema/input"
            );
            assert!(!executor.marker.exists(), "no physical effect on denial");
            assert!(entries.is_empty());
        }
        Verdict::Allow => {
            assert!(receipt.executed);
            assert!(receipt.refusal_message.is_none());
            assert_eq!(executor.calls.count(), 1);
            assert_eq!(entries.len(), 1, "exactly one physical execution");
            assert_eq!(entries[0]["call_id"], "native-call-42");
            assert_eq!(entries[0]["session_id"], "native-session-7");
            assert_eq!(entries[0]["raw_arguments"], arguments);
        }
        Verdict::Ask => panic!("schema fixtures should resolve to Allow or Deny"),
    }
}

#[test]
fn integer_schema_rejects_fractional_and_nonnumeric_arguments() {
    for arguments in [json!(1.5), json!(-1.5), json!("1"), json!(true)] {
        check(json!({"type": "integer"}), arguments, Verdict::Deny);
    }
}

#[test]
fn integer_schema_accepts_integral_float_and_large_unsigned_representations() {
    for arguments in [
        json!(1),
        json!(1.0),
        json!(-1.0),
        json!(0),
        json!(i64::MIN),
        json!(u64::MAX),
    ] {
        check(json!({"type": "integer"}), arguments, Verdict::Allow);
    }
}

#[test]
fn false_schemas_block_root_property_and_array_item_execution() {
    for (schema, arguments) in [
        (json!(false), json!({})),
        (
            json!({"type": "object", "properties": {"value": false}}),
            json!({"value": "present"}),
        ),
        (json!({"type": "array", "items": false}), json!(["present"])),
    ] {
        check(schema, arguments, Verdict::Deny);
    }
}

#[test]
fn true_schemas_allow_root_property_and_array_item_controls() {
    for (schema, arguments) in [
        (json!(true), json!({"path": "note.txt"})),
        (json!({}), json!({})),
        (
            json!({"type": "object", "properties": {"value": true}}),
            json!({"value": null}),
        ),
        (
            json!({"type": "array", "items": true}),
            json!([1, "text", null]),
        ),
        (json!({"type": "array", "items": false}), json!([])),
        (
            json!({"type": "object", "properties": {"absent": false}}),
            json!({}),
        ),
    ] {
        check(schema, arguments, Verdict::Allow);
    }
}

#[test]
fn type_unions_validate_supported_alternatives_including_nested_null() {
    let union = json!({"type": ["object", "array"]});
    for arguments in [json!({}), json!([])] {
        check(union.clone(), arguments, Verdict::Allow);
    }
    for arguments in [json!(42), json!(false)] {
        check(union.clone(), arguments, Verdict::Deny);
    }
    let nullable = json!({"type": "object", "properties": {"value": {"type": ["string", "null"]}}});
    for arguments in [json!({"value": null}), json!({"value": "text"})] {
        check(nullable.clone(), arguments, Verdict::Allow);
    }
    check(nullable, json!({"value": 42}), Verdict::Deny);
}

#[test]
fn additional_properties_validate_boolean_and_schema_constraints() {
    let schema = json!({
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "additionalProperties": {"type": "integer"}
    });
    check(
        schema.clone(),
        json!({"path": "note.txt", "version": 2}),
        Verdict::Allow,
    );
    check(
        schema,
        json!({"path": "note.txt", "version": 2.5}),
        Verdict::Deny,
    );
    check(
        json!({"additionalProperties": false}),
        json!({"extra": 1}),
        Verdict::Deny,
    );
    check(
        json!({"additionalProperties": true}),
        json!({"extra": 1}),
        Verdict::Allow,
    );
}

#[test]
fn nested_object_and_array_validation_prevents_invalid_execution() {
    let schema = json!({
        "type": "object",
        "properties": {"rows": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": false
            }
        }},
        "required": ["rows"],
        "additionalProperties": false
    });
    check(
        schema.clone(),
        json!({"rows": [{"name": "widget"}]}),
        Verdict::Allow,
    );
    for arguments in [
        json!({}),
        json!({"rows": [{}]}),
        json!({"rows": [{"name": 7}]}),
        json!({"rows": [{"name": "widget", "extra": true}]}),
    ] {
        check(schema.clone(), arguments, Verdict::Deny);
    }
}

#[test]
fn malformed_root_schema_values_fail_closed() {
    for schema in [Value::Null, json!(42), json!("object"), json!([])] {
        check(schema, json!({}), Verdict::Deny);
    }
}

#[test]
fn malformed_definitions_are_rejected_even_without_corresponding_values() {
    for schema in [
        json!({"type": "not-a-json-type"}),
        json!({"type": 7}),
        json!({"type": []}),
        json!({"type": ["object", 7]}),
        json!({"required": "path"}),
        json!({"required": ["path", 7]}),
        json!({"properties": []}),
        json!({"description": 7}),
        json!({"examples": {}}),
        json!({"readOnly": "yes"}),
        json!({"$schema": "https://json-schema.org/draft-07/schema"}),
        json!({"properties": {"absent": null}}),
        json!({"properties": {"absent": {"type": "not-a-json-type"}}}),
        json!({"properties": {"absent": {"required": 7}}}),
        json!({"additionalProperties": 7}),
        json!({"additionalProperties": {"type": "not-a-json-type"}}),
    ] {
        check(schema, json!({}), Verdict::Deny);
    }
    for schema in [
        json!({"type": "array", "items": null}),
        json!({"type": "array", "items": [{"type": "string"}]}),
        json!({"type": "array", "items": {"type": "not-a-json-type"}}),
    ] {
        check(schema, json!([]), Verdict::Deny);
    }
}

#[test]
fn unsupported_restricting_keywords_cannot_be_silently_ignored() {
    for (schema, arguments) in [
        (json!({"enum": ["permitted"]}), json!("different")),
        (json!({"const": "permitted"}), json!("different")),
        (json!({"allOf": [{"type": "string"}]}), json!({})),
        (json!({"oneOf": [{"type": "string"}]}), json!({})),
        (json!({"not": {}}), json!({})),
        (json!({"type": "string", "minLength": 4}), json!("x")),
        (
            json!({"type": "string", "pattern": "^safe$"}),
            json!("different"),
        ),
        (
            json!({"properties": {"absent": {"minLength": 4}}}),
            json!({}),
        ),
        (json!({"items": {"minLength": 4}}), json!([])),
    ] {
        check(schema, arguments, Verdict::Deny);
    }
}

#[test]
fn supported_annotations_do_not_change_arguments_or_execution() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:fixture:read",
        "$comment": "Harmless fixture annotation",
        "title": "Read fixture",
        "description": "Read a local fixture",
        "default": {"path": "unused.txt"},
        "examples": [{"path": "example.txt"}],
        "readOnly": true,
        "writeOnly": false,
        "deprecated": false,
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": false
    });
    check(schema, json!({"path": "original.txt"}), Verdict::Allow);
}

#[test]
fn duplicate_type_and_required_entries_are_invalid_definitions() {
    for schema in [
        json!({"type": ["object", "object"]}),
        json!({"required": ["path", "path"]}),
    ] {
        check(schema, json!({"path": "present.txt"}), Verdict::Deny);
    }
}

#[test]
fn schema_depth_is_bounded_even_for_absent_optional_properties() {
    for (depth, verdict) in [(64, Verdict::Allow), (65, Verdict::Deny)] {
        let mut schema = json!(true);
        for _ in 0..depth {
            schema = json!({"properties": {"absent": schema}});
        }
        check(schema, json!({}), verdict);
    }
}
