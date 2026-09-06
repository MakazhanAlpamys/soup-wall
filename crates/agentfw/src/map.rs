// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Hook payload -> `AgentEvent`. The daemon supplies the clock and the sequence
//! number; `llm-firewall-agent` has neither by design.

use llm_firewall_agent::{AgentEvent, EventKind};

use crate::hook::{HookEvent, HookPayload};
use crate::provenance;

/// Truncate on a UTF-8 boundary at or below `max` bytes. Returns whether anything
/// was removed, so the audit log can record it — a line claiming nothing was
/// truncated when content was cut would mislead any later analysis of a missed
/// detection.
fn truncate(mut s: String, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    (s, true)
}

/// A mapped event plus whether its content had to be truncated.
pub struct Mapped {
    pub event: AgentEvent,
    pub truncated: bool,
}

/// Map one hook payload to an `AgentEvent`. `None` means "nothing to inspect" —
/// an event kind this build does not handle.
pub fn to_event(p: &HookPayload, seq: u64, at_ms: u64, max_bytes: usize) -> Option<Mapped> {
    // Everything is keyed by session. An empty id would bucket unrelated sessions
    // into one shared taint pool — a cross-session leak, and worse than declining
    // to inspect. serde requires the field to be present but not to be non-empty.
    if p.session_id.is_empty() {
        return None;
    }

    let mut truncated = false;
    let kind = match p.event {
        HookEvent::PreToolUse => EventKind::ToolCall {
            tool: p.tool_name.clone().unwrap_or_default(),
            args: p.tool_input.clone(),
        },
        HookEvent::PostToolUse => {
            let tool = p.tool_name.clone().unwrap_or_default();
            let source = provenance::decide(&tool, &p.tool_input, p.cwd.as_deref());
            let (content, cut) = truncate(p.response_text(), max_bytes);
            truncated = cut;
            EventKind::ToolResult {
                content,
                source,
                tool,
            }
        }
        HookEvent::SubagentStop => {
            let (content, cut) = truncate(
                p.last_assistant_message.clone().unwrap_or_default(),
                max_bytes,
            );
            truncated = cut;
            EventKind::SubagentReport {
                name: p.agent_type.clone().unwrap_or_else(|| "subagent".into()),
                content,
            }
        }
        HookEvent::SessionStart => EventKind::SessionStart,
        HookEvent::SessionEnd => EventKind::SessionEnd,
        HookEvent::Other => return None,
    };

    Some(Mapped {
        event: AgentEvent {
            session: p.session_id.clone(),
            agent: "main".into(),
            parent: None,
            seq,
            at_ms,
            kind,
        },
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::HookPayload;
    use llm_firewall_agent::{EventKind, Provenance};

    fn payload(j: &str) -> HookPayload {
        serde_json::from_str(j).unwrap()
    }

    #[test]
    fn pre_tool_use_becomes_a_tool_call() {
        let p = payload(
            r#"{"session_id":"s1","hook_event_name":"PreToolUse",
                            "tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        );
        let m = to_event(&p, 7, 1_753_000_000_000, 262_144).unwrap();
        let ev = m.event;
        assert_eq!(ev.session, "s1");
        assert_eq!(ev.seq, 7);
        assert_eq!(ev.at_ms, 1_753_000_000_000);
        assert!(!m.truncated);
        match ev.kind {
            EventKind::ToolCall { tool, args } => {
                assert_eq!(tool, "Bash");
                assert_eq!(args["command"], "ls");
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn post_tool_use_becomes_a_tool_result_with_provenance() {
        let p = payload(
            r#"{"session_id":"s1","cwd":"/proj","hook_event_name":"PostToolUse",
                            "tool_name":"WebFetch","tool_input":{"url":"https://evil.com/a"},
                            "tool_response":"page text"}"#,
        );
        let m = to_event(&p, 1, 0, 262_144).unwrap();
        assert!(!m.truncated);
        match m.event.kind {
            EventKind::ToolResult {
                content, source, ..
            } => {
                assert_eq!(content, "page text");
                assert_eq!(
                    source,
                    Provenance::Network {
                        host: "evil.com".into()
                    }
                );
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[test]
    fn subagent_stop_becomes_a_subagent_report() {
        let p = payload(
            r#"{"session_id":"s1","hook_event_name":"SubagentStop",
                            "agent_type":"Explore","last_assistant_message":"done"}"#,
        );
        let m = to_event(&p, 1, 0, 262_144).unwrap();
        assert!(!m.truncated);
        match m.event.kind {
            EventKind::SubagentReport { name, content } => {
                assert_eq!(name, "Explore");
                assert_eq!(content, "done");
            }
            other => panic!("expected SubagentReport, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_events_map_across() {
        let s = payload(r#"{"session_id":"s","hook_event_name":"SessionStart"}"#);
        assert!(matches!(
            to_event(&s, 1, 0, 100).unwrap().event.kind,
            EventKind::SessionStart
        ));
        let e = payload(r#"{"session_id":"s","hook_event_name":"SessionEnd"}"#);
        assert!(matches!(
            to_event(&e, 1, 0, 100).unwrap().event.kind,
            EventKind::SessionEnd
        ));
    }

    #[test]
    fn an_unknown_event_maps_to_none_so_the_daemon_can_skip_it() {
        let p = payload(r#"{"session_id":"s","hook_event_name":"FutureThing"}"#);
        assert!(to_event(&p, 1, 0, 100).is_none());
    }

    #[test]
    fn an_empty_session_id_maps_to_none_rather_than_a_shared_bucket() {
        // Found in Task 4: `session_id` is required to be PRESENT but serde does not
        // require it to be non-empty. Everything — taint, sequence numbers, session
        // isolation — is keyed by it, so an empty id would collapse unrelated
        // sessions into one shared taint pool. That is exactly the cross-session
        // leak the required-field rule exists to prevent, so refuse to inspect.
        let p = payload(r#"{"session_id":"","hook_event_name":"PreToolUse","tool_name":"Bash"}"#);
        assert!(to_event(&p, 1, 0, 100).is_none());
    }

    #[test]
    fn oversized_content_is_truncated_at_the_cap() {
        // Measured: record() on 10 MB costs 532 ms, far past the hook budget.
        let big = "x".repeat(5000);
        let p = payload(&format!(
            r#"{{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":"{big}"}}"#
        ));
        let m = to_event(&p, 1, 0, 1000).unwrap();
        assert!(m.truncated);
        match m.event.kind {
            EventKind::ToolResult { content, .. } => assert_eq!(content.len(), 1000),
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[test]
    fn small_content_is_not_reported_as_truncated() {
        let p = payload(
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_response":"short"}"#,
        );
        let m = to_event(&p, 1, 0, 1000).unwrap();
        assert!(!m.truncated);
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        // A naive byte slice would panic mid-codepoint.
        let p = payload(
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_response":"ααααα"}"#,
        );
        let m = to_event(&p, 1, 0, 5).unwrap();
        assert!(m.truncated);
        match m.event.kind {
            EventKind::ToolResult { content, .. } => assert!(content.len() <= 5),
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[test]
    fn truncation_handles_a_four_byte_character_at_the_cut_point() {
        // A 4-byte emoji straddling the cut boundary must not panic and must not
        // produce invalid UTF-8.
        let s = "ab\u{1F600}cd".to_string(); // 😀 is 4 bytes, at byte offset 2..6
        for max in [0usize, 1, 2, 3, 4, 5, 6, s.len()] {
            let (out, cut) = truncate(s.clone(), max);
            assert!(out.len() <= max);
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
            assert_eq!(cut, max < s.len());
        }
    }

    #[test]
    fn truncation_at_max_zero_one_and_full_length_never_panics() {
        let s = "αβγ".to_string();
        assert_eq!(truncate(s.clone(), 0), (String::new(), true));
        assert_eq!(truncate(s.clone(), 1), (String::new(), true)); // 'α' is 2 bytes; boundary walks back to 0
        assert_eq!(truncate(s.clone(), s.len()), (s.clone(), false));
    }
}
