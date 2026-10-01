// SPDX-License-Identifier: Apache-2.0

//! Minimal Anthropic Messages API request model (`POST /v1/messages`).
//!
//! Anthropic's schema differs from OpenAI's: `system` is a top-level field (a string
//! or an array of text blocks), and each message's `content` is either a plain string
//! or an array of typed blocks (`{"type":"text","text":...}`, plus image/tool blocks).
//! We keep `content`/`system` as raw JSON so unknown block types forward faithfully and
//! we only touch the `text` we need to inspect.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicMessage {
    pub role: String,
    /// String or array of content blocks.
    pub content: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicRequest {
    pub model: String,
    /// Optional system prompt: a string or an array of text blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<Value>,
    pub messages: Vec<AnthropicMessage>,
    #[serde(default)]
    pub stream: bool,
    /// Preserve unknown fields (max_tokens, temperature, tools, …) so we forward faithfully.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_block_content_and_preserves_extras() {
        let raw = r#"{
            "model":"claude-3-5-sonnet",
            "max_tokens":1024,
            "system":"you are helpful",
            "messages":[
                {"role":"user","content":"hello"},
                {"role":"user","content":[{"type":"text","text":"and again"}]}
            ]
        }"#;
        let req: AnthropicRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.model, "claude-3-5-sonnet");
        assert_eq!(req.messages.len(), 2);
        assert!(!req.stream);
        // max_tokens preserved in `rest`, and survives re-serialization.
        assert!(req.rest.contains_key("max_tokens"));
        let out = serde_json::to_string(&req).unwrap();
        assert!(out.contains("max_tokens"));
        assert!(out.contains("you are helpful"));
    }
}
