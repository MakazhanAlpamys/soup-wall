// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The hook wire contract. Deliberately tolerant: unknown event names and extra
//! fields must degrade, never error — a version skew between Claude Code and this
//! daemon would otherwise break every tool call in every session.

use serde::Deserialize;

/// Which hook fired. `Other` is the forward-compatibility fallback — an event this
/// build does not know about is inert, never an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum HookEvent {
    PreToolUse,
    PostToolUse,
    SubagentStop,
    SessionStart,
    SessionEnd,
    #[serde(other)]
    Other,
}

impl HookEvent {
    /// Stable snake_case name for the audit log. Deliberately explicit rather than
    /// derived from `Debug`: the audit log is a forensic record and its schema must
    /// not change silently when a Rust variant is renamed.
    pub fn as_str(self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "pre_tool_use",
            HookEvent::PostToolUse => "post_tool_use",
            HookEvent::SubagentStop => "subagent_stop",
            HookEvent::SessionStart => "session_start",
            HookEvent::SessionEnd => "session_end",
            HookEvent::Other => "unknown",
        }
    }
}

/// One hook invocation. Field names follow Claude Code's documented contract;
/// everything except `session_id` is optional so a partial or future payload
/// still parses.
#[derive(Debug, Clone, Deserialize)]
pub struct HookPayload {
    pub session_id: String,
    #[serde(rename = "hook_event_name")]
    pub event: HookEvent,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: serde_json::Value,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
}

impl HookPayload {
    /// Flatten `tool_response` to text. It may be a bare string, `{ "text": … }`,
    /// or an arbitrary structure — in the last case fall back to its JSON form so
    /// detectors still see the content.
    pub fn response_text(&self) -> String {
        match &self.tool_response {
            serde_json::Value::Null => String::new(),
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Object(o) => match o.get("text") {
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => self.tool_response.to_string(),
            },
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRE: &str = r#"{
      "session_id": "abc123",
      "transcript_path": "/home/u/.claude/projects/x/transcript.jsonl",
      "cwd": "/home/u/my-project",
      "permission_mode": "default",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": { "command": "npm test", "timeout": 120000 },
      "tool_use_id": "toolu_01ABC"
    }"#;

    const POST: &str = r#"{
      "session_id": "abc123",
      "cwd": "/home/u/my-project",
      "hook_event_name": "PostToolUse",
      "tool_name": "WebFetch",
      "tool_input": { "url": "https://example.com/x" },
      "tool_use_id": "toolu_01ABC",
      "tool_response": { "type": "text", "text": "hello" }
    }"#;

    const SUBAGENT: &str = r#"{
      "session_id": "abc123",
      "cwd": "/home/u/p",
      "hook_event_name": "SubagentStop",
      "agent_id": "a1",
      "agent_type": "Explore",
      "last_assistant_message": "I found three files."
    }"#;

    #[test]
    fn parses_pre_tool_use() {
        let h: HookPayload = serde_json::from_str(PRE).unwrap();
        assert_eq!(h.session_id, "abc123");
        assert_eq!(h.cwd.as_deref(), Some("/home/u/my-project"));
        assert_eq!(h.event, HookEvent::PreToolUse);
        assert_eq!(h.tool_name.as_deref(), Some("Bash"));
        assert_eq!(h.tool_input["command"], "npm test");
    }

    #[test]
    fn parses_post_tool_use_with_a_structured_response() {
        let h: HookPayload = serde_json::from_str(POST).unwrap();
        assert_eq!(h.event, HookEvent::PostToolUse);
        assert_eq!(h.response_text(), "hello");
    }

    #[test]
    fn parses_subagent_stop() {
        let h: HookPayload = serde_json::from_str(SUBAGENT).unwrap();
        assert_eq!(h.event, HookEvent::SubagentStop);
        assert_eq!(h.agent_type.as_deref(), Some("Explore"));
        assert_eq!(
            h.last_assistant_message.as_deref(),
            Some("I found three files.")
        );
    }

    #[test]
    fn an_unknown_event_name_parses_as_other_rather_than_erroring() {
        let j = r#"{"session_id":"s","hook_event_name":"SomeFutureEvent"}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        assert_eq!(h.event, HookEvent::Other);
    }

    #[test]
    fn unexpected_extra_fields_are_ignored() {
        let j = r#"{"session_id":"s","hook_event_name":"PreToolUse","brand_new_field":42}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        assert_eq!(h.event, HookEvent::PreToolUse);
    }

    #[test]
    fn a_missing_session_id_is_an_error() {
        // Everything is keyed by session. Without it we cannot isolate taint state,
        // and silently bucketing into one shared session would leak taint ACROSS
        // sessions — worse than refusing.
        let j = r#"{"hook_event_name":"PreToolUse"}"#;
        assert!(serde_json::from_str::<HookPayload>(j).is_err());
    }

    #[test]
    fn a_plain_string_tool_response_is_read_as_text() {
        let j =
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_response":"raw output"}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        assert_eq!(h.response_text(), "raw output");
    }

    #[test]
    fn an_absent_tool_response_yields_empty_text() {
        let j = r#"{"session_id":"s","hook_event_name":"PostToolUse"}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        assert_eq!(h.response_text(), "");
    }

    #[test]
    fn an_empty_session_id_still_parses_but_is_not_a_valid_session() {
        // The plan requires only that `session_id` be *present*, not non-empty.
        // Recorded here rather than silently "fixed": an empty session id is not
        // rejected by this type. Anything that would key taint state by session
        // must treat "" as invalid before trusting it, or sessions would collapse
        // into a single shared taint bucket.
        let j = r#"{"session_id":"","hook_event_name":"PreToolUse"}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        assert_eq!(h.session_id, "");
    }

    #[test]
    fn as_str_is_pinned_and_snake_case_for_every_variant() {
        // This is the on-disk audit schema. A future rename of the Rust variant
        // must not silently change it, so pin each mapping explicitly here.
        assert_eq!(HookEvent::PreToolUse.as_str(), "pre_tool_use");
        assert_eq!(HookEvent::PostToolUse.as_str(), "post_tool_use");
        assert_eq!(HookEvent::SubagentStop.as_str(), "subagent_stop");
        assert_eq!(HookEvent::SessionStart.as_str(), "session_start");
        assert_eq!(HookEvent::SessionEnd.as_str(), "session_end");
        assert_eq!(HookEvent::Other.as_str(), "unknown");
    }

    #[test]
    fn an_array_shaped_tool_response_stringifies_to_useful_text() {
        let j = r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_response":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}"#;
        let h: HookPayload = serde_json::from_str(j).unwrap();
        let t = h.response_text();
        assert!(t.contains('a') && t.contains('b'), "got {t:?}");
    }
}
