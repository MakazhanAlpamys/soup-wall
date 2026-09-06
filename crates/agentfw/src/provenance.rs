// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Decide where a tool result came from. Every taint verdict downstream depends on
//! this being right, and it is the one judgment the phase-08 library could not make
//! for itself.

use std::path::{Component, Path, PathBuf};

use llm_firewall_agent::Provenance;

/// Tools that retrieve third-party content over the network.
const NETWORK_TOOLS: &[&str] = &["WebFetch", "WebSearch"];
/// Tools whose primary argument is a filesystem path.
const PATH_TOOLS: &[&str] = &["Read", "Grep", "Glob", "NotebookRead"];

/// Where did this tool's output come from?
///
/// Conservative on ambiguity: an unrecognized tool is `LocalSystem` (semi-trusted),
/// never `Untrusted`. Marking everything unknown untrusted would flood the taint set
/// and make the firewall prompt constantly.
pub fn decide(tool: &str, args: &serde_json::Value, cwd: Option<&str>) -> Provenance {
    if let Some(server) = tool
        .strip_prefix("mcp__")
        .and_then(|r| r.split("__").next())
    {
        if !server.is_empty() {
            return Provenance::McpServer {
                name: server.to_string(),
            };
        }
        // A bare `mcp__` carries no server identity; fall through to the
        // conservative default rather than inventing an empty-named server.
    }

    if NETWORK_TOOLS.contains(&tool) {
        let host = args
            .get("url")
            .and_then(|v| v.as_str())
            .and_then(host_of)
            .unwrap_or_else(|| "unknown".to_string());
        return Provenance::Network { host };
    }

    if PATH_TOOLS.contains(&tool) {
        let path = args
            .get("file_path")
            .or_else(|| args.get("path"))
            .or_else(|| args.get("notebook_path"))
            .and_then(|v| v.as_str());
        if let (Some(p), Some(root)) = (path, cwd) {
            // Hooks may pass a relative path. `Path::starts_with` compares component
            // sequences, so a relative path never starts with an absolute root and
            // an ordinary in-project file would be mislabelled LocalSystem. Resolve
            // it against cwd first — lexically, no filesystem access, since this runs
            // on the synchronous hook path.
            let joined = if Path::new(p).is_absolute() {
                PathBuf::from(p)
            } else {
                Path::new(root).join(p)
            };
            return if is_inside(&joined.to_string_lossy(), root) {
                Provenance::LocalProject
            } else {
                Provenance::LocalSystem
            };
        }
    }

    Provenance::LocalSystem
}

/// Host of a URL, without a scheme parser dependency.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = hostport.split(':').next()?;
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// True when `path` resolves inside `root`. Lexical only — no filesystem access, so
/// it stays fast on the hook path — but `..` components are resolved so a traversal
/// cannot masquerade as being inside the project, and comparison is component-wise
/// so `/proj-secrets` does not count as inside `/proj`.
fn is_inside(path: &str, root: &str) -> bool {
    let norm = |p: &str| -> PathBuf {
        let mut out = PathBuf::new();
        for c in Path::new(p).components() {
            match c {
                Component::ParentDir => {
                    out.pop();
                }
                Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        out
    };
    norm(path).starts_with(norm(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use llm_firewall_agent::{Provenance, Trust};

    fn args(v: serde_json::Value) -> serde_json::Value {
        v
    }

    #[test]
    fn web_fetch_is_network_with_the_host() {
        let p = decide(
            "WebFetch",
            &args(serde_json::json!({"url":"https://evil.com/x"})),
            Some("/proj"),
        );
        assert_eq!(
            p,
            Provenance::Network {
                host: "evil.com".into()
            }
        );
        assert_eq!(p.trust(), Trust::Untrusted);
    }

    #[test]
    fn web_fetch_without_a_parsable_url_is_still_network() {
        let p = decide("WebFetch", &args(serde_json::json!({})), Some("/proj"));
        assert!(matches!(p, Provenance::Network { .. }), "got {p:?}");
        assert_eq!(p.trust(), Trust::Untrusted);
    }

    #[test]
    fn mcp_tools_carry_their_server_name() {
        let p = decide(
            "mcp__shodan__search",
            &args(serde_json::json!({})),
            Some("/proj"),
        );
        assert_eq!(
            p,
            Provenance::McpServer {
                name: "shodan".into()
            }
        );
    }

    #[test]
    fn a_read_inside_the_project_is_local_project() {
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"/proj/src/main.rs"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalProject);
        assert_eq!(p.trust(), Trust::Semi);
    }

    #[test]
    fn a_read_outside_the_project_is_local_system() {
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"/etc/hosts"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalSystem);
    }

    #[test]
    fn a_traversal_path_is_not_treated_as_inside_the_project() {
        // `/proj/../etc/passwd` starts with `/proj` as a string but is not inside it.
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"/proj/../etc/passwd"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalSystem);
    }

    #[test]
    fn a_sibling_directory_sharing_a_prefix_is_outside() {
        // `/project-secrets` must not count as inside `/proj`.
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"/proj-secrets/k"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalSystem);
    }

    #[test]
    fn bash_and_unknown_tools_are_local_system_not_untrusted() {
        // Conservative but NOT untrusted: marking every unknown tool untrusted would
        // flood the taint set and reproduce the prompt-fatigue failure phase 08 spent
        // its measurement effort avoiding.
        assert_eq!(
            decide("Bash", &args(serde_json::json!({})), Some("/p")),
            Provenance::LocalSystem
        );
        assert_eq!(
            decide("SomeNewTool", &args(serde_json::json!({})), Some("/p")),
            Provenance::LocalSystem
        );
        assert_eq!(
            decide("Bash", &args(serde_json::json!({})), Some("/p")).trust(),
            Trust::Semi
        );
    }

    #[test]
    fn no_tool_result_is_ever_marked_user_prompt() {
        // UserPrompt erases taint. No tool result is ever what the human typed.
        for tool in ["Read", "Bash", "WebFetch", "mcp__x__y", "Weird"] {
            let p = decide(tool, &args(serde_json::json!({})), Some("/p"));
            assert_ne!(p, Provenance::UserPrompt, "{tool} must never be UserPrompt");
        }
    }

    // --- Hazard verification: is_inside path logic (lexical, `..` resolution) ---

    #[test]
    fn root_itself_is_inside_root() {
        assert!(is_inside("/proj", "/proj"));
    }

    #[test]
    fn relative_path_against_absolute_root_does_not_match_is_inside_directly() {
        // `is_inside` itself is purely lexical: `Path::starts_with` compares
        // component sequences, and a relative path never starts with an absolute
        // one. This is exactly why `decide` joins a relative path onto `cwd` before
        // calling `is_inside` — see `a_relative_path_in_project_is_local_project`.
        assert!(!is_inside("src/main.rs", "/proj"));
    }

    #[test]
    fn a_relative_path_in_project_is_local_project() {
        // Hooks may hand a relative `file_path`. Previously this fell through to
        // LocalSystem, mislabelling an ordinary in-project read in the audit log
        // (the phase-10 tuning corpus / phase-12 benchmark). `decide` now resolves
        // the relative path against `cwd` before the containment check.
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"src/main.rs"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalProject);
    }

    #[test]
    fn a_relative_traversal_path_is_still_outside_the_project() {
        // `../etc/passwd` joined onto `/proj` resolves to `/etc/passwd`, which is
        // not inside `/proj`. Joining onto cwd must not accidentally legitimize a
        // traversal.
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"../etc/passwd"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalSystem);
    }

    #[test]
    fn trailing_slashes_do_not_change_the_result() {
        assert!(is_inside("/proj/src/main.rs", "/proj/"));
        assert!(is_inside("/proj/src/main.rs/", "/proj"));
    }

    // --- Hazard verification: host_of hand-rolled URL parsing ---

    #[test]
    fn host_of_handles_userinfo_port_case_and_missing_scheme() {
        assert_eq!(host_of("https://evil.com/x").as_deref(), Some("evil.com"));
        assert_eq!(
            host_of("https://user:pass@evil.com/x").as_deref(),
            Some("evil.com")
        );
        assert_eq!(
            host_of("http://evil.com:8080/x").as_deref(),
            Some("evil.com")
        );
        assert_eq!(
            host_of("HTTPS://EVIL.COM/x").as_deref(),
            Some("evil.com"),
            "host must be lowercased"
        );
        assert_eq!(host_of("evil.com/x"), None, "no scheme => no host");
        assert_eq!(host_of(""), None);
    }

    // --- Hazard verification: MCP name parsing edge cases ---

    #[test]
    fn mcp_name_parsing_edge_cases() {
        // Nothing after `mcp__`: an empty server name is meaningless in an audit
        // line and would group unrelated servers together in later per-server
        // logic, so this falls back to the conservative default instead.
        let p = decide("mcp__", &args(serde_json::json!({})), Some("/p"));
        assert_eq!(p, Provenance::LocalSystem);

        // Only one `__`-delimited part after the prefix: whole remainder is taken
        // as the server name (no tool segment to split off).
        let p = decide(
            "mcp__only_one_part",
            &args(serde_json::json!({})),
            Some("/p"),
        );
        assert_eq!(
            p,
            Provenance::McpServer {
                name: "only_one_part".into()
            }
        );

        // A server name itself containing an underscore, followed by `__tool`:
        // `split("__").next()` takes everything up to the FIRST `__`, so the
        // server name here is `my_server`, not `my`.
        let p = decide(
            "mcp__my_server__tool",
            &args(serde_json::json!({})),
            Some("/p"),
        );
        assert_eq!(
            p,
            Provenance::McpServer {
                name: "my_server".into()
            }
        );
    }

    // --- Hazard verification: decide ignores cwd being None ---

    #[test]
    fn a_path_tool_with_no_cwd_falls_through_to_local_system() {
        let p = decide(
            "Read",
            &args(serde_json::json!({"file_path":"/proj/src/main.rs"})),
            None,
        );
        assert_eq!(p, Provenance::LocalSystem);
    }

    // --- Hazard verification: notebook_path argument key ---

    #[test]
    fn notebook_read_uses_the_notebook_path_key() {
        let p = decide(
            "NotebookRead",
            &args(serde_json::json!({"notebook_path":"notebooks/analysis.ipynb"})),
            Some("/proj"),
        );
        assert_eq!(p, Provenance::LocalProject);
    }
}
