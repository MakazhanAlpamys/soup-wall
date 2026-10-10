// SPDX-License-Identifier: Apache-2.0
//! SOU-11 reusable input-profile checks; no real host configuration is read.

use agentfw::mcp::input::{inspect_host_config, InputSchema, MAX_DEPTH, MAX_ITEMS};
use serde_json::{json, Value};

fn nested_schema() -> Value {
    serde_json::from_str(include_str!("fixtures/mcp_inputs/nested_schema.json")).unwrap()
}

#[test]
fn nested_values_and_optional_fields_preserve_original_arguments() {
    let original = json!({"query":{"names":["alpha","beta"],"limit":2,"enabled":true},"weight":0.5,"unused":null});
    let args = original.clone();
    InputSchema::read(&nested_schema())
        .unwrap()
        .validate(&args)
        .unwrap();
    assert_eq!(original, args);
    assert!(
        args.get("note").is_none(),
        "defaults must never be injected"
    );
}

#[test]
fn missing_wrong_type_and_unknown_nested_fields_are_refused() {
    let schema = InputSchema::read(&nested_schema()).unwrap();
    for args in [
        Value::Null,
        json!({}),
        json!({"query":null}),
        json!({"query":{"names":[],"limit":"2"}}),
        json!({"query":{"names":[false],"limit":2}}),
        json!({"query":{"names":[],"limit":2,"extra":"x"}}),
        json!({"query":{"names":[],"limit":2},"extra":true}),
    ] {
        assert!(schema.validate(&args).is_err(), "accepted {args}");
    }
}

#[test]
fn unsupported_schema_features_are_not_silently_ignored() {
    for keyword in [
        "$ref", "allOf", "anyOf", "oneOf", "pattern", "format", "minimum", "enum", "$schema",
    ] {
        let mut schema = nested_schema();
        schema[keyword] = json!("unsupported");
        assert!(InputSchema::read(&schema).is_err(), "accepted {keyword}");
    }
    let mut schema = nested_schema();
    schema["additionalProperties"] = json!(true);
    assert!(InputSchema::read(&schema).is_err());
    schema = nested_schema();
    schema["required"] = json!(["query", "query"]);
    assert!(InputSchema::read(&schema).is_err());
    schema["required"] = json!(["missing"]);
    assert!(InputSchema::read(&schema).is_err());
}

#[test]
fn oversized_nested_inputs_and_deep_schemas_are_refused() {
    let schema = InputSchema::read(&nested_schema()).unwrap();
    assert!(schema
        .validate(&json!({"query":{"names":vec!["a"; MAX_ITEMS + 1],"limit":1}}))
        .is_err());
    assert!(schema
        .validate(&json!({"query":{"names":["a".repeat(16 * 1024 + 1)],"limit":1}}))
        .is_err());
    let mut child = json!({"type":"string"});
    for _ in 0..MAX_DEPTH + 2 {
        child = json!({"type":"object","properties":{"child":child},"required":["child"],"additionalProperties":false});
    }
    assert!(InputSchema::read(&child).is_err());
}

#[test]
fn config_inspection_only_reports_redacted_inventory() {
    let config = json!({"mcpServers":{
        "local":{"command":"NEVER_EXECUTE_THIS","args":["secret-argument"],"env":{"TOKEN":"secret-env"}},
        "remote":{"type":"http","url":"https://secret.example.invalid","headers":{"Authorization":"secret-header"}}
    }});
    let summary = inspect_host_config(&serde_json::to_vec(&config).unwrap()).unwrap();
    let output = serde_json::to_string(&summary).unwrap();
    for secret in [
        "NEVER_EXECUTE",
        "secret-argument",
        "secret-env",
        "secret.example",
        "secret-header",
    ] {
        assert!(!output.contains(secret));
    }
    assert!(
        summary
            .iter()
            .find(|s| s.name == "local")
            .unwrap()
            .supported
    );
    assert!(
        !summary
            .iter()
            .find(|s| s.name == "remote")
            .unwrap()
            .supported
    );
    assert!(summary.iter().all(|s| s.requires_explicit_selection));
}

#[test]
fn invalid_config_has_no_payload_in_errors() {
    for config in [
        b"{\"secret-value\"".as_slice(),
        br#"{"mcpServers":{"a":{},"a":{}}}"#,
        b"{}",
        b"null",
    ] {
        let error = inspect_host_config(config).unwrap_err().to_string();
        assert!(!error.contains("secret-value"));
    }
    assert!(inspect_host_config(&vec![b' '; 1024 * 1024 + 1]).is_err());
}

#[test]
fn config_cli_does_not_start_a_discovered_command_or_connect_to_remote() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("must-not-exist");
    let path = dir.path().join("synthetic-host.json");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let python = if cfg!(windows) { "python" } else { "python3" };
    let config = json!({"mcpServers": {
        "local":{"command":python,"args":["-c","import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",marker],"env":{"TOKEN":"synthetic-secret"}},
        "remote":{"url":format!("http://{}/must-not-connect",listener.local_addr().unwrap())}
    }});
    std::fs::write(&path, config.to_string()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("mcp-inspect-config")
        .arg("--path")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!marker.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary.as_array().unwrap().len(), 2);
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("synthetic-secret"));
    assert!(output.stderr.is_empty());
}
