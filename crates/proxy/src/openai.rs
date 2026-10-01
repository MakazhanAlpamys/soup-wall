// SPDX-License-Identifier: Apache-2.0

//! Minimal OpenAI chat-completions request model (enough to inspect + re-forward).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: String,
    /// `None` for assistant tool-call messages, which carry `tool_calls` instead of
    /// text. A `role:"tool"` result message carries its output here as a string.
    #[serde(default)]
    pub content: Option<String>,
    /// Preserve `tool_calls` / `tool_call_id` / `name` so re-forwarding is faithful
    /// and the agent collector can read the tool blocks.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    /// Preserve unknown fields (temperature, tools, …) so we forward faithfully.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_preserves_extra_fields() {
        let raw =
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.7}"#;
        let req: ChatRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.messages.len(), 1);
        assert!(!req.stream);
        // temperature preserved in `rest`
        assert!(req.rest.contains_key("temperature"));
        // re-serialize keeps it
        let out = serde_json::to_string(&req).unwrap();
        assert!(out.contains("temperature"));
    }

    #[test]
    fn a_tool_call_conversation_deserializes() {
        // Assistant with null content + tool_calls, then a tool result — must parse.
        let raw = r#"{
            "model":"gpt-4","messages":[
                {"role":"user","content":"list my repos"},
                {"role":"assistant","content":null,"tool_calls":[
                    {"id":"c1","type":"function","function":{"name":"list_repos","arguments":"{}"}}]},
                {"role":"tool","tool_call_id":"c1","content":"repo-a\nrepo-b"}
            ]}"#;
        let req: ChatRequest = serde_json::from_str(raw).expect("tool conversations must parse");
        assert_eq!(req.messages.len(), 3);
        assert_eq!(
            req.messages[1].content, None,
            "assistant tool-call content is null"
        );
        assert!(
            req.messages[1].rest.contains_key("tool_calls"),
            "tool_calls preserved in rest"
        );
        assert_eq!(req.messages[2].role, "tool");
        assert_eq!(req.messages[2].content.as_deref(), Some("repo-a\nrepo-b"));
    }
}
