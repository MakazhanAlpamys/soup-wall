// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The wire schema every collector produces. One shape for hooks, API traffic, and MCP.

use serde::{Deserialize, Serialize};

/// Stable id for one Claude Code session or one API conversation.
pub type SessionId = String;
/// `"main"` or a subagent name, e.g. `"osint-agent"`.
pub type AgentId = String;

/// How far content is trusted, derived from where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Third-party content. Never an instruction.
    Untrusted,
    /// Local, but not typed by the human.
    Semi,
    /// The human said it.
    Trusted,
}

/// Where a piece of content entered the session from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum Provenance {
    UserPrompt,
    LocalProject,
    LocalSystem,
    Network { host: String },
    McpServer { name: String },
    Subagent { name: String },
}

impl Provenance {
    pub fn trust(&self) -> Trust {
        match self {
            Provenance::UserPrompt => Trust::Trusted,
            Provenance::LocalProject | Provenance::LocalSystem => Trust::Semi,
            Provenance::Network { .. }
            | Provenance::McpServer { .. }
            | Provenance::Subagent { .. } => Trust::Untrusted,
        }
    }

    /// The origin discriminant on its own: `user`, `project`, `system`,
    /// `network`, `mcp`, `subagent`.
    ///
    /// Exists so a consumer can group or filter by origin without re-parsing
    /// [`label`](Self::label). A machine field and a human string are different
    /// jobs, and deriving the first from the second makes every reader
    /// re-implement a split this crate already knows how to do.
    pub fn kind(&self) -> &'static str {
        match self {
            Provenance::UserPrompt => "user",
            Provenance::LocalProject => "project",
            Provenance::LocalSystem => "system",
            Provenance::Network { .. } => "network",
            Provenance::McpServer { .. } => "mcp",
            Provenance::Subagent { .. } => "subagent",
        }
    }

    /// The specific host, server, or subagent this content came from.
    ///
    /// `None` for origins that have no name of their own — a user prompt is not
    /// a named source, and reporting an empty string there would invite readers
    /// to treat "" as a source identity.
    pub fn source_name(&self) -> Option<&str> {
        match self {
            Provenance::UserPrompt | Provenance::LocalProject | Provenance::LocalSystem => None,
            Provenance::Network { host } => Some(host),
            Provenance::McpServer { name } | Provenance::Subagent { name } => Some(name),
        }
    }

    /// Short label used in policy conditions and operator messages.
    pub fn label(&self) -> String {
        match self {
            Provenance::UserPrompt => "user".into(),
            Provenance::LocalProject => "project".into(),
            Provenance::LocalSystem => "system".into(),
            Provenance::Network { host } => format!("network:{host}"),
            Provenance::McpServer { name } => format!("mcp:{name}"),
            Provenance::Subagent { name } => format!("subagent:{name}"),
        }
    }
}

/// One tool declared by an MCP server at handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDecl {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The tool's JSON input schema, verbatim from the MCP `tools/list` response.
    /// Part of the pinned manifest: a rug-pull that widens a tool's parameters
    /// changes this even when the name and description are untouched.
    #[serde(default)]
    pub schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A tool is about to run. This is the blockable moment.
    ToolCall {
        tool: String,
        args: serde_json::Value,
    },
    /// A tool returned; this content is about to re-enter the model's context.
    ToolResult {
        tool: String,
        content: String,
        source: Provenance,
    },
    SubagentSpawn {
        name: String,
        instructions: String,
        #[serde(default)]
        granted_tools: Vec<String>,
    },
    SubagentReport {
        name: String,
        content: String,
    },
    ManifestSeen {
        server: String,
        tools: Vec<ToolDecl>,
    },
    SessionStart,
    SessionEnd,
    /// An event kind this build does not recognize — emitted by a newer collector
    /// talking to an older daemon. Deliberately inert: it projects no facets and
    /// contributes no signals, so an unknown event degrades to "no opinion" rather
    /// than a parse failure that would break the agent loop.
    #[serde(other)]
    Unknown,
}

/// One observation from any collector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    pub session: SessionId,
    pub agent: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<AgentId>,
    pub seq: u64,
    /// Milliseconds since the Unix epoch. Supplied by the collector; this crate has no clock.
    pub at_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every origin must report a discriminant and, where it has one, a name --
    /// without a consumer having to split `label()`.
    #[test]
    fn every_origin_exposes_its_kind_and_name_separately() {
        let cases: Vec<(Provenance, &str, Option<&str>)> = vec![
            (Provenance::UserPrompt, "user", None),
            (Provenance::LocalProject, "project", None),
            (Provenance::LocalSystem, "system", None),
            (
                Provenance::Network {
                    host: "evil.example.com".into(),
                },
                "network",
                Some("evil.example.com"),
            ),
            (
                Provenance::McpServer {
                    name: "docs".into(),
                },
                "mcp",
                Some("docs"),
            ),
            (
                Provenance::Subagent {
                    name: "worker".into(),
                },
                "subagent",
                Some("worker"),
            ),
        ];
        for (provenance, kind, name) in cases {
            assert_eq!(provenance.kind(), kind, "kind for {provenance:?}");
            assert_eq!(provenance.source_name(), name, "name for {provenance:?}");
        }
    }

    /// A bracketed IPv6 literal is a legitimate egress host. Its colons are the
    /// reason a machine field must not be recovered by splitting the human
    /// label: the structured accessor returns the host whole.
    #[test]
    fn an_ipv6_host_survives_as_one_value() {
        let provenance = Provenance::Network {
            host: "[2001:db8::1]".into(),
        };
        assert_eq!(provenance.kind(), "network");
        assert_eq!(provenance.source_name(), Some("[2001:db8::1]"));
        assert_eq!(provenance.label(), "network:[2001:db8::1]");
    }

    /// The security-relevant classification must be reachable from the origin
    /// alone, so an audit record can carry it instead of making a reader derive
    /// it from this crate's source.
    #[test]
    fn trust_is_derivable_from_the_origin_for_every_variant() {
        assert_eq!(Provenance::UserPrompt.trust(), Trust::Trusted);
        assert_eq!(Provenance::LocalProject.trust(), Trust::Semi);
        assert_eq!(Provenance::LocalSystem.trust(), Trust::Semi);
        for untrusted in [
            Provenance::Network { host: "h".into() },
            Provenance::McpServer { name: "m".into() },
            Provenance::Subagent { name: "s".into() },
        ] {
            assert_eq!(
                untrusted.trust(),
                Trust::Untrusted,
                "third-party content is never trusted: {untrusted:?}"
            );
        }
    }

    #[test]
    fn provenance_trust_levels() {
        assert_eq!(Provenance::UserPrompt.trust(), Trust::Trusted);
        assert_eq!(Provenance::LocalProject.trust(), Trust::Semi);
        assert_eq!(Provenance::LocalSystem.trust(), Trust::Semi);
        assert_eq!(
            Provenance::Network {
                host: "evil.com".into()
            }
            .trust(),
            Trust::Untrusted
        );
        assert_eq!(
            Provenance::McpServer {
                name: "shodan".into()
            }
            .trust(),
            Trust::Untrusted
        );
        assert_eq!(
            Provenance::Subagent {
                name: "osint-agent".into()
            }
            .trust(),
            Trust::Untrusted
        );
    }

    /// `EventKind::Unknown` is deliberately excluded from this list. It is not a
    /// wire variant a collector ever deliberately emits — it is the fallback a
    /// *receiver* falls into when it sees a `"kind"` tag it doesn't recognize
    /// (added by `#[serde(other)]`, which affects deserialization only). Empirically,
    /// `Unknown` *does* still serialize (as `derive(Serialize)` treats it like any
    /// other unit variant, tagged `"unknown"` under `rename_all = "snake_case"`) and
    /// even round-trips correctly here, because the literal string `"unknown"` isn't
    /// one of the other six explicit tags and so falls back into `Unknown` again on
    /// the way in. That's incidental, not a schema guarantee — a future variant
    /// literally named `Unknown`/`unknown` would break it silently. See
    /// `unknown_kind_falls_back_instead_of_erroring` for the behavior this schema
    /// actually depends on: an *unrecognized* tag (e.g. `"bogus"`) parses to `Unknown`
    /// instead of erroring.
    fn all_known_kinds() -> Vec<EventKind> {
        vec![
            EventKind::ToolCall {
                tool: "Bash".into(),
                args: serde_json::json!({ "command": "ls -la" }),
            },
            EventKind::ToolResult {
                tool: "WebFetch".into(),
                content: "<html>evil</html>".into(),
                source: Provenance::Network {
                    host: "evil.com".into(),
                },
            },
            EventKind::SubagentSpawn {
                name: "osint-agent".into(),
                instructions: "recon example.com".into(),
                granted_tools: vec!["WebFetch".into()],
            },
            EventKind::SubagentReport {
                name: "osint-agent".into(),
                content: "found nothing".into(),
            },
            EventKind::ManifestSeen {
                server: "shodan".into(),
                tools: vec![ToolDecl {
                    name: "shodan_search".into(),
                    description: "search shodan".into(),
                    schema: serde_json::Value::Null,
                }],
            },
            EventKind::SessionStart,
            EventKind::SessionEnd,
        ]
    }

    #[test]
    fn event_round_trips_through_json() {
        for (i, kind) in all_known_kinds().into_iter().enumerate() {
            let parent = if i % 2 == 0 {
                None
            } else {
                Some("main".to_string())
            };
            let ev = AgentEvent {
                session: "s1".into(),
                agent: "main".into(),
                parent,
                seq: u64::MAX,
                at_ms: u64::MAX,
                kind,
            };
            let json = serde_json::to_string(&ev).unwrap();
            let back: AgentEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ev, "round trip mismatch for {json}");
        }
    }

    #[test]
    fn subagent_spawn_defaults_granted_tools_when_omitted() {
        let json = r#"{
            "session": "s1",
            "agent": "main",
            "seq": 1,
            "at_ms": 1,
            "kind": "subagent_spawn",
            "name": "osint-agent",
            "instructions": "recon example.com"
        }"#;
        let ev: AgentEvent = serde_json::from_str(json).unwrap();
        match ev.kind {
            EventKind::SubagentSpawn { granted_tools, .. } => {
                assert!(granted_tools.is_empty());
            }
            other => panic!("expected SubagentSpawn, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_falls_back_instead_of_erroring() {
        let json = r#"{
            "session": "s1",
            "agent": "main",
            "seq": 1,
            "at_ms": 1,
            "kind": "bogus"
        }"#;
        let ev: AgentEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.kind, EventKind::Unknown);
    }

    #[test]
    fn a_manifest_seen_event_round_trips_with_tool_schemas() {
        let ev = AgentEvent {
            session: "s1".into(),
            agent: "main".into(),
            parent: None,
            seq: 1,
            at_ms: 0,
            kind: EventKind::ManifestSeen {
                server: "github".into(),
                tools: vec![ToolDecl {
                    name: "create_issue".into(),
                    description: "Open an issue".into(),
                    schema: serde_json::json!({"type": "object"}),
                }],
            },
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: AgentEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn a_tool_decl_without_a_schema_defaults_to_null() {
        let t: ToolDecl = serde_json::from_str(r#"{"name":"x","description":"y"}"#).unwrap();
        assert_eq!(t.schema, serde_json::Value::Null);
    }

    #[test]
    fn event_kind_tag_is_snake_case() {
        let ev = EventKind::SubagentSpawn {
            name: "osint-agent".into(),
            instructions: "recon example.com".into(),
            granted_tools: vec!["WebFetch".into()],
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"subagent_spawn""#), "got {json}");
    }
}
