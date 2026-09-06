// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The transparent stdio relay: spawn the real MCP server, pump JSON-RPC both ways,
//! tee the handshake to the daemon, and — only when enforcing — withhold a manifest
//! the daemon rejected by returning a JSON-RPC error to the client.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::mcp::jsonrpc::manifest_from_line;

/// What the daemon said about a handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
    /// Daemon unreachable or unparsable — fail open.
    Unavailable,
}

/// Whether the proxy should replace a `tools/list` result with an error. Only when the
/// daemon is enforcing AND the verdict is not allow. Everything else passes through —
/// including every `Unavailable`, so a down daemon never breaks a session.
pub fn should_withhold(verdict: &Verdict, enforce: bool) -> bool {
    enforce && matches!(verdict, Verdict::Ask | Verdict::Deny)
}

/// Runtime config for one proxied server.
pub struct ProxyCfg {
    pub server_id: String,
    /// Daemon `/mcp` URL, e.g. `http://127.0.0.1:8787/mcp`.
    pub daemon_url: String,
    pub token: String,
    /// The real server command and its args.
    pub command: String,
    pub args: Vec<String>,
}

/// POST a handshake to the daemon and map its reply to a Verdict. Any failure ->
/// `Unavailable` (fail open).
async fn ask_daemon(
    client: &reqwest::Client,
    cfg: &ProxyCfg,
    tools_json: &serde_json::Value,
) -> (Verdict, bool) {
    let body = serde_json::json!({ "server": cfg.server_id, "tools": tools_json });
    let resp = client
        .post(&cfg.daemon_url)
        .bearer_auth(&cfg.token)
        .json(&body)
        .send()
        .await;
    let v = match resp {
        Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
        _ => None,
    };
    match v {
        Some(j) => {
            let enforce = j["enforce"].as_bool().unwrap_or(false);
            let verdict = match j["verdict"].as_str() {
                Some("allow") => Verdict::Allow,
                Some("ask") => Verdict::Ask,
                Some("deny") => Verdict::Deny,
                _ => Verdict::Unavailable,
            };
            (verdict, enforce)
        }
        None => (Verdict::Unavailable, false),
    }
}

/// Run the proxy until the child exits. Relays stdin->child and child->stdout line by
/// line; when a child line is a `tools/list` result, asks the daemon and (if enforcing
/// and rejected) replaces it with a JSON-RPC error carrying the same id.
pub async fn run(cfg: ProxyCfg) -> anyhow::Result<()> {
    let mut child = Command::new(&cfg.command)
        .args(&cfg.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");
    let client = reqwest::Client::new();

    // client stdin -> child stdin (verbatim).
    let up = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if child_stdin.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if child_stdin.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = child_stdin.flush().await;
        }
    });

    // child stdout -> client stdout, teeing the manifest.
    let down = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut forward = line.clone();
            if let Some(tools) = manifest_from_line(&line) {
                let tools_json = serde_json::to_value(&tools).unwrap_or(serde_json::Value::Null);
                let (verdict, enforce) = ask_daemon(&client, &cfg, &tools_json).await;
                if should_withhold(&verdict, enforce) {
                    let id = serde_json::from_str::<serde_json::Value>(&line)
                        .ok()
                        .and_then(|v| v.get("id").cloned())
                        .unwrap_or(serde_json::Value::Null);
                    forward = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32000, "message":
                            "agentfw withheld this MCP server's tool manifest (drift/shadow/poisoning). Review the audit log." }
                    })
                    .to_string();
                }
            }
            if out.write_all(forward.as_bytes()).await.is_err() {
                break;
            }
            if out.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = out.flush().await;
        }
    });

    let _ = child.wait().await;
    up.abort();
    down.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withholds_only_when_enforcing_and_not_allowed() {
        assert!(should_withhold(&Verdict::Deny, true));
        assert!(should_withhold(&Verdict::Ask, true));
        assert!(!should_withhold(&Verdict::Allow, true));
        assert!(!should_withhold(&Verdict::Unavailable, true), "fail open");
        assert!(
            !should_withhold(&Verdict::Deny, false),
            "shadow never withholds"
        );
    }
}
