// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Provider-neutral capability authorization for model-emitted tool calls.
//!
//! Detection asks whether content looks risky. Capability authorization asks
//! whether a tool call is allowed to exist at all, based on explicit operator
//! grants. It is deliberately shadow-first so an operator can measure impact
//! before turning enforcement on.

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::agent_scan::ToolCall;
use crate::events::{EventDirection, EventKind, SecurityEvent};

/// Explicit grants for tools and network destinations.
///
/// An empty `allowed_tools` list means that tool names are unrestricted. An
/// empty `allowed_hosts` list means that no explicitly detected network host is
/// allowed once this policy is enabled. This makes enabling enforcement
/// conservative for egress while keeping tool-only deployments convenient.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapabilityPolicy {
    /// Evaluate the policy and emit audit warnings. Off by default.
    pub enabled: bool,
    /// Refuse violating responses instead of only auditing them.
    pub enforce: bool,
    /// Exact tool names allowed to be emitted. Empty means any tool name.
    pub allowed_tools: Vec<String>,
    /// Domains/IPs allowed as tool-call network destinations. Subdomains are
    /// accepted using the agent layer's boundary-safe matcher.
    pub allowed_hosts: Vec<String>,
    /// Normalized path prefixes allowed in structured tool arguments. Empty
    /// means no filesystem scope is applied.
    pub allowed_path_prefixes: Vec<String>,
    /// Additional structured argument names which should be interpreted as
    /// filesystem paths for this deployment's tool schemas. Built-in common
    /// names are always recognized; this is for domain-specific names such as
    /// `artifact_location`.
    pub extra_path_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub tool: String,
    pub reason: String,
}

/// Check all provider-neutral output tool calls against the explicit grants.
pub fn violations(policy: &CapabilityPolicy, events: &[SecurityEvent]) -> Vec<Violation> {
    let calls = events
        .iter()
        .filter_map(|event| match (&event.direction, &event.kind) {
            (EventDirection::Output, EventKind::ToolCall { name, args, .. }) => Some(ToolCall {
                name: name.clone(),
                args: args.clone(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    violations_for_calls(policy, &calls)
}

/// Check already-extracted tool calls. Streaming adapters use this form when
/// a complete provider event has arrived but the full response is not present.
pub fn violations_for_calls(policy: &CapabilityPolicy, calls: &[ToolCall]) -> Vec<Violation> {
    if !policy.enabled {
        return Vec::new();
    }

    let mut out = Vec::new();
    for call in calls {
        if !policy.allowed_tools.is_empty()
            && !policy.allowed_tools.iter().any(|name| name == &call.name)
        {
            out.push(Violation {
                tool: call.name.clone(),
                reason: format!("tool '{}' is not in the capability allowlist", call.name),
            });
        }

        let denied_hosts = soup_wall_agent::hosts(&call.args)
            .into_iter()
            .filter(|host| !soup_wall_agent::is_allowed(host, &policy.allowed_hosts))
            .collect::<Vec<_>>();
        if !denied_hosts.is_empty() {
            out.push(Violation {
                tool: call.name.clone(),
                reason: format!(
                    "tool '{}' reaches non-allowlisted host(s): {}",
                    call.name,
                    denied_hosts.join(", ")
                ),
            });
        }

        if !policy.allowed_path_prefixes.is_empty() {
            for candidate in extract_path_candidates(&call.args, &policy.extra_path_keys) {
                let allowed = !candidate.traversal
                    && policy
                        .allowed_path_prefixes
                        .iter()
                        .any(|prefix| path_is_within(&candidate.value, prefix));
                if !allowed {
                    out.push(Violation {
                        tool: call.name.clone(),
                        reason: format!(
                            "tool '{}' references a path outside the filesystem scope: {}",
                            call.name, candidate.value
                        ),
                    });
                }
            }
        }
    }
    out
}

const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "directory",
    "directories",
    "dir",
    "dirs",
    "cwd",
    "workdir",
    "working_directory",
    "filename",
    "file_path",
    "directory_path",
    "target",
    "target_path",
    "destination_path",
    "input_path",
    "output_path",
    "input_file",
    "output_file",
    "root",
    "root_dir",
    "workspace",
    "workspace_path",
    "repo_path",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathCandidate {
    value: String,
    traversal: bool,
}

fn extract_path_candidates(
    value: &serde_json::Value,
    extra_path_keys: &[String],
) -> Vec<PathCandidate> {
    fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) if !text.trim().is_empty() => out.push(text.clone()),
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_strings(item, out);
                }
            }
            _ => {}
        }
    }

    fn walk(value: &serde_json::Value, extra_path_keys: &[String], out: &mut Vec<String>) {
        let serde_json::Value::Object(object) = value else {
            if let serde_json::Value::Array(items) = value {
                for item in items {
                    walk(item, extra_path_keys, out);
                }
            }
            return;
        };
        for (key, child) in object {
            let normalized_key = key.to_ascii_lowercase();
            if PATH_KEYS.contains(&normalized_key.as_str())
                || extra_path_keys
                    .iter()
                    .any(|extra| extra.eq_ignore_ascii_case(key))
            {
                collect_strings(child, out);
            }
            walk(child, extra_path_keys, out);
        }
    }

    let mut raw = Vec::new();
    walk(value, extra_path_keys, &mut raw);
    let mut unique = BTreeSet::new();
    raw.into_iter()
        .filter_map(|text| {
            let (value, traversal) = normalize_path(&text)?;
            unique.insert((value, traversal));
            Some(())
        })
        .for_each(drop);
    unique
        .into_iter()
        .map(|(value, traversal)| PathCandidate { value, traversal })
        .collect()
}

fn normalize_path(raw: &str) -> Option<(String, bool)> {
    let mut text = raw.trim().trim_matches(['"', '\'']).replace('\\', "/");
    if let Some(rest) = text.strip_prefix("file://") {
        text = rest.to_string();
    }
    if text.is_empty() {
        return None;
    }
    let absolute = text.starts_with('/');
    let mut traversal = false;
    let mut parts = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                traversal = true;
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    let mut normalized = parts.join("/");
    if absolute {
        normalized.insert(0, '/');
    }
    (!normalized.is_empty()).then_some((normalized, traversal))
}

fn path_is_within(path: &str, prefix: &str) -> bool {
    let Some((path, path_traversal)) = normalize_path(path) else {
        return false;
    };
    let Some((prefix, prefix_traversal)) = normalize_path(prefix) else {
        return false;
    };
    if path_traversal || prefix_traversal {
        return false;
    }
    if prefix == "/" {
        return path.starts_with('/');
    }
    let case_insensitive = path.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        || prefix.as_bytes().get(1).is_some_and(|byte| *byte == b':');
    let (path, prefix) = if case_insensitive {
        (path.to_ascii_lowercase(), prefix.to_ascii_lowercase())
    } else {
        (path, prefix)
    };
    path == prefix
        || path
            .strip_prefix(&prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            name: name.into(),
            args,
        }
    }

    #[test]
    fn disabled_policy_is_a_no_op() {
        let policy = CapabilityPolicy {
            allowed_tools: vec!["Read".into()],
            allowed_hosts: vec!["example.com".into()],
            ..CapabilityPolicy::default()
        };
        assert!(violations_for_calls(
            &policy,
            &[call("Bash", serde_json::json!({"url":"https://evil.com"}))]
        )
        .is_empty());
    }

    #[test]
    fn tool_allowlist_is_exact_and_shadow_safe() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_tools: vec!["Read".into()],
            ..CapabilityPolicy::default()
        };
        let violations = violations_for_calls(&policy, &[call("Bash", serde_json::json!({}))]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].reason.contains("allowlist"));
    }

    #[test]
    fn host_allowlist_accepts_subdomains_and_rejects_lookalikes() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_hosts: vec!["example.com".into()],
            ..CapabilityPolicy::default()
        };
        assert!(violations_for_calls(
            &policy,
            &[call(
                "Fetch",
                serde_json::json!({"url":"https://api.example.com/x"})
            )]
        )
        .is_empty());
        assert_eq!(
            violations_for_calls(
                &policy,
                &[call(
                    "Fetch",
                    serde_json::json!({"url":"https://example.com.evil/x"})
                )]
            )
            .len(),
            1
        );
    }

    #[test]
    fn empty_host_grant_denies_detected_network_destinations() {
        let policy = CapabilityPolicy {
            enabled: true,
            ..CapabilityPolicy::default()
        };
        assert_eq!(
            violations_for_calls(
                &policy,
                &[call(
                    "Fetch",
                    serde_json::json!({"url":"http://localhost:3000"})
                )]
            )
            .len(),
            1
        );
    }

    #[test]
    fn input_tool_results_are_not_capability_checked() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_tools: vec!["Read".into()],
            ..CapabilityPolicy::default()
        };
        let events = vec![SecurityEvent {
            provider: crate::events::Provider::OpenAiChat,
            direction: EventDirection::Input,
            kind: EventKind::ToolResult {
                call_id: Some("c1".into()),
                content: "https://evil.com".into(),
            },
        }];
        assert!(violations(&policy, &events).is_empty());
    }

    #[test]
    fn filesystem_scope_is_boundary_safe_and_rejects_traversal() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_path_prefixes: vec!["C:/workspace/project".into()],
            ..CapabilityPolicy::default()
        };
        assert!(violations_for_calls(
            &policy,
            &[call(
                "Read",
                serde_json::json!({"file_path":"c:\\workspace\\project\\src\\main.rs"})
            )]
        )
        .is_empty());
        let sibling = violations_for_calls(
            &policy,
            &[call(
                "Read",
                serde_json::json!({"file_path":"C:/workspace/project-old/secret.txt"}),
            )],
        );
        assert_eq!(sibling.len(), 1);
        let traversal = violations_for_calls(
            &policy,
            &[call(
                "Read",
                serde_json::json!({"path":"C:/workspace/project/../secrets.txt"}),
            )],
        );
        assert_eq!(traversal.len(), 1);
    }

    #[test]
    fn filesystem_scope_covers_common_and_deployment_specific_argument_names() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_path_prefixes: vec!["/srv/workspace".into()],
            extra_path_keys: vec!["artifact_location".into()],
            ..CapabilityPolicy::default()
        };
        assert!(violations_for_calls(
            &policy,
            &[call(
                "Write",
                serde_json::json!({
                    "output_path": "/srv/workspace/result.json",
                    "artifact_location": "/srv/workspace/artifact.bin"
                })
            )]
        )
        .is_empty());
        assert_eq!(
            violations_for_calls(
                &policy,
                &[call(
                    "Write",
                    serde_json::json!({"artifact_location": "/etc/shadow"})
                )]
            )
            .len(),
            1
        );
    }

    #[test]
    fn filesystem_root_scope_allows_absolute_paths() {
        let policy = CapabilityPolicy {
            enabled: true,
            allowed_path_prefixes: vec!["/".into()],
            ..CapabilityPolicy::default()
        };
        assert!(violations_for_calls(
            &policy,
            &[call(
                "Read",
                serde_json::json!({"path": "/var/data/item.txt"})
            )]
        )
        .is_empty());
    }
}
