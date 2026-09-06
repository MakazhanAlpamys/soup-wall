// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Minimal, tolerant JSON-RPC 2.0 recognition for MCP over newline-delimited stdio.
//! We do not implement JSON-RPC; we only need to spot the `tools/list` response so we
//! can extract the manifest. Anything unrecognized is treated as opaque bytes.

use llm_firewall_agent::ToolDecl;

/// If `line` is a JSON-RPC response whose `result.tools` is an array, return the
/// declared tools. Returns `None` for anything else — a request, a different
/// response, or unparseable bytes. Tolerant by design: a malformed line is never an
/// error, just "not a manifest", so the relay forwards it untouched.
pub fn manifest_from_line(line: &str) -> Option<Vec<ToolDecl>> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let arr = v.get("result")?.get("tools")?.as_array()?;
    let mut tools = Vec::with_capacity(arr.len());
    for t in arr {
        let name = t.get("name")?.as_str()?.to_string();
        let description = t
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let schema = t
            .get("inputSchema")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        tools.push(ToolDecl {
            name,
            description,
            schema,
        });
    }
    Some(tools)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_tool_manifest_from_a_tools_list_response() {
        let line = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
            {"name":"create_issue","description":"Open an issue","inputSchema":{"type":"object"}},
            {"name":"list_repos","description":"List repos"}
        ]}}"#;
        let tools = manifest_from_line(line).expect("should parse a manifest");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "create_issue");
        assert_eq!(tools[0].description, "Open an issue");
        assert_eq!(tools[0].schema, serde_json::json!({"type": "object"}));
        assert_eq!(
            tools[1].schema,
            serde_json::Value::Null,
            "missing schema -> null"
        );
    }

    #[test]
    fn a_non_tools_list_message_yields_none() {
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hi"}]}}"#,
            "not json at all",
            "",
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":"not-an-array"}}"#,
        ] {
            assert!(
                manifest_from_line(line).is_none(),
                "{line:?} must not yield a manifest"
            );
        }
    }
}
