// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentfw::audit::AuditSink;
use agentfw::handlers::{AppState, Sessions};
use agentfw::sandbox::{
    GuardedFileDeleteSpec, GuardedFileRenameSpec, GuardedFileWriteSpec, GuardedNetworkFetchSpec,
    NetworkPolicy, SandboxSpec,
};
use agentfw::{app, Config};
use clap::{Parser, Subcommand};
use llm_firewall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};

#[derive(Parser)]
#[command(name = "agentfw", about = "Agent firewall daemon and tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon.
    Serve,
    /// Summarize an audit log: what would this policy have done?
    Replay {
        /// Path to the audit log (defaults to ~/.agentfw/audit.jsonl).
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Print the settings.json hook block and setup instructions.
    Install,
    /// Check that the daemon is up, and report its enforcement posture.
    ///
    /// Exits non-zero when it is not. The Claude Code hook fails open, so a
    /// stopped daemon is otherwise invisible: tool calls simply proceed after
    /// the hook timeout. Run this before a session, or from a wrapper script.
    Preflight {
        /// Also fail when the daemon is running but still in shadow mode.
        #[arg(long)]
        require_enforce: bool,
        /// Seconds to wait for the health endpoint.
        #[arg(long, default_value_t = 2)]
        timeout_seconds: u64,
    },
    /// Approve one exact tool call that policy would otherwise only ask about.
    ///
    /// The approval is signed, expires, is single-use, and is bound to the exact
    /// arguments given here -- approving `rm -rf ./build` does not authorize
    /// `rm -rf /`.
    ///
    /// It withdraws this firewall's objection to one `ask`. It does not override
    /// your own Claude Code permission rules, and a policy `deny` stays denied.
    Approve {
        /// Session the call belongs to, as reported in the ask.
        #[arg(long)]
        session: String,
        /// Tool name, e.g. `Bash`.
        #[arg(long)]
        tool: String,
        /// The tool's exact arguments as JSON, matching the pending call.
        #[arg(long)]
        args: String,
        /// Minutes the approval stays usable.
        #[arg(long, default_value_t = 5)]
        ttl_minutes: u64,
    },
    /// Proxy an MCP server, pinning its tool manifest at handshake.
    Mcp {
        /// Stable identity for this server (keys its pin + audit). Defaults to a
        /// hash of the command.
        #[arg(long)]
        id: Option<String>,
        /// The real server command and its args, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Run one high-risk command inside the Linux bubblewrap sandbox.
    Sandbox {
        /// Writable directory exposed as `/workspace`.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Kill the command after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum bytes retained from each output stream.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_output_bytes: usize,
        /// The command and args, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect a Bash command and execute it only after an explicit allow
    /// inside the Linux bubblewrap sandbox.
    GuardedShell {
        /// Stable session identifier used by taint tracking and policy.
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        /// Agent identifier used by the policy event.
        #[arg(long, default_value = "root")]
        agent: String,
        /// Monotonic event sequence supplied by the caller.
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Writable directory exposed as `/workspace`.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Kill the command after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum bytes retained from each output stream.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_output_bytes: usize,
        /// The Bash command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect a typed file write and apply it only inside the workspace.
    GuardedWrite {
        /// Stable session identifier used by taint tracking and policy.
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        /// Agent identifier used by the policy event.
        #[arg(long, default_value = "root")]
        agent: String,
        /// Monotonic event sequence supplied by the caller.
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Writable workspace that contains the target file.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Relative (or workspace-contained absolute) target path.
        #[arg(long)]
        path: PathBuf,
        /// UTF-8 content to write. The value is never included in the result.
        #[arg(long)]
        content: String,
    },
    /// Inspect a typed file deletion and apply it only inside the workspace.
    GuardedDelete {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        path: PathBuf,
    },
    /// Inspect a typed file rename and apply it only inside the workspace.
    GuardedRename {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
    },
    /// Inspect a typed WebFetch and retrieve it only through an egress proxy.
    GuardedFetch {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// HTTPS URL to retrieve (HTTP is accepted only for loopback tests).
        #[arg(long)]
        url: String,
        /// Deployment-owned HTTPS egress proxy (loopback HTTP is test-only).
        #[arg(long)]
        proxy_url: String,
        /// Kill the request after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum UTF-8 response bytes returned to the agent.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_response_bytes: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve => {
            tracing_subscriber::fmt().json().init();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve())
        }
        Cmd::Replay { log } => {
            let home = Config::home()?;
            let path = log.unwrap_or_else(|| home.join("audit.jsonl"));
            let body = std::fs::read_to_string(&path)?;
            print!("{}", agentfw::replay::summarize(&body).render());
            Ok(())
        }
        Cmd::Install => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            agentfw::token::load_or_create(&home.join("token"))?;
            println!(
                "{}",
                agentfw::install::instructions(cfg.port, &home.join("token"))
            );
            Ok(())
        }
        Cmd::Preflight {
            require_enforce,
            timeout_seconds,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let probe = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(probe_health(&cfg.bind, cfg.port, timeout_seconds));
            let report = agentfw::preflight::evaluate(&probe);
            println!("{}", report.render(require_enforce));
            std::process::exit(report.exit_code(require_enforce));
        }
        Cmd::Approve {
            session,
            tool,
            args,
            ttl_minutes,
        } => {
            let parsed: serde_json::Value = serde_json::from_str(&args)
                .map_err(|e| anyhow::anyhow!("--args must be JSON: {e}"))?;
            let home = Config::home()?;
            let token = agentfw::token::load_or_create(&home.join("token"))?;
            let action = agentfw::grant::ActionRef {
                session,
                tool: tool.clone(),
                args_fingerprint: agentfw::grant::action_fingerprint(&tool, &parsed),
            };
            let nonce = agentfw::token::generate();
            let grant = agentfw::grant::mint(
                &agentfw::grant::derive_key(&token),
                &action,
                now_ms(),
                ttl_minutes.saturating_mul(60_000),
                nonce,
            );
            let store = agentfw::grant::GrantStore::new(&home.join("grants"));
            let path = store.write(&grant)?;
            println!(
                "Approved {tool} for {} minute(s). Single use, bound to these exact arguments.
                 Revoke before it is used by deleting:
  {}",
                ttl_minutes,
                path.display()
            );
            Ok(())
        }
        Cmd::Mcp { id, command } => {
            let (cmd, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no server command given after --"))?;
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let token = agentfw::token::load_or_create(&home.join("token"))?;
            let server_id = id.unwrap_or_else(|| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(command.join(" ").as_bytes());
                format!("srv-{:x}", h.finalize()).chars().take(12).collect()
            });
            let proxy_cfg = agentfw::mcp::proxy::ProxyCfg {
                server_id,
                daemon_url: format!("http://{}:{}/mcp", cfg.bind, cfg.port),
                token,
                command: cmd.clone(),
                args: args.to_vec(),
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(agentfw::mcp::proxy::run(proxy_cfg))
        }
        Cmd::Sandbox {
            workspace,
            timeout_seconds,
            max_output_bytes,
            command,
        } => {
            let (program, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no command given after --"))?;
            let spec = SandboxSpec {
                program: program.clone(),
                args: args.to_vec(),
                workspace,
                network: NetworkPolicy::Deny,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run(spec).await?;
                    println!("{}", serde_json::to_string(&result)?);
                    if result.timed_out || result.status != Some(0) {
                        anyhow::bail!("sandboxed command failed or timed out");
                    }
                    Ok(())
                })
        }
        Cmd::GuardedShell {
            session,
            agent,
            seq,
            workspace,
            timeout_seconds,
            max_output_bytes,
            command,
        } => {
            let command = command.join(" ");
            if command.is_empty() {
                anyhow::bail!("no command given after --");
            }
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_shell(
                        &mut firewall,
                        agentfw::sandbox::GuardedShellSpec {
                            session,
                            agent,
                            seq,
                            command,
                            workspace,
                            network: agentfw::sandbox::NetworkPolicy::Deny,
                            timeout: Duration::from_secs(timeout_seconds),
                            max_output_bytes,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    if result.execution.timed_out || result.execution.status != Some(0) {
                        anyhow::bail!("guarded sandbox command failed or timed out");
                    }
                    Ok(())
                })
        }
        Cmd::GuardedWrite {
            session,
            agent,
            seq,
            workspace,
            path,
            content,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_write(
                        &mut firewall,
                        GuardedFileWriteSpec {
                            session,
                            agent,
                            seq,
                            path,
                            content,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedDelete {
            session,
            agent,
            seq,
            workspace,
            path,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_delete(
                        &mut firewall,
                        GuardedFileDeleteSpec {
                            session,
                            agent,
                            seq,
                            path,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedRename {
            session,
            agent,
            seq,
            workspace,
            from,
            to,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_rename(
                        &mut firewall,
                        GuardedFileRenameSpec {
                            session,
                            agent,
                            seq,
                            from,
                            to,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedFetch {
            session,
            agent,
            seq,
            url,
            proxy_url,
            timeout_seconds,
            max_response_bytes,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_network_fetch(
                        &mut firewall,
                        GuardedNetworkFetchSpec {
                            session,
                            agent,
                            seq,
                            url,
                            proxy_url,
                            timeout: Duration::from_secs(timeout_seconds),
                            max_response_bytes,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
    }
}

/// Probe the daemon's unauthenticated loopback health endpoint. Every failure mode
/// collapses to  with the transport detail, which is what the
/// operator needs: the distinction between refused, reset and timed out does not
/// change the action (start the daemon).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

async fn probe_health(bind: &str, port: u16, timeout_seconds: u64) -> agentfw::preflight::Probe {
    let url = format!("http://{bind}:{port}/health");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            return agentfw::preflight::Probe::Unreachable {
                detail: e.to_string(),
            }
        }
    };
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            agentfw::preflight::Probe::Answered { status, body }
        }
        Err(e) => agentfw::preflight::Probe::Unreachable {
            detail: e.to_string(),
        },
    }
}

async fn serve() -> anyhow::Result<()> {
    let home = Config::home()?;
    let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
        Ok(s) => Config::from_yaml(&s)?,
        Err(_) => Config::default(),
    };

    let firewall = match &cfg.policy {
        Some(p) => AgentFirewall::new(
            AgentPolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
            DEFAULT_TAINT_CAP,
        ),
        None => AgentFirewall::with_default_policy(),
    };

    let token = agentfw::token::load_or_create(&home.join("token"))?;
    let audit_path = cfg
        .audit
        .clone()
        .unwrap_or_else(|| home.join("audit.jsonl"));
    let state: agentfw::Shared = Arc::new(AppState {
        firewall: Mutex::new(firewall),
        sessions: Sessions::default(),
        audit: AuditSink::open(&audit_path)?,
        spans: agentfw::spans::SpanCache::new(64, cfg.judge.max_span_bytes),
        judge: agentfw::judge::Judge::new(cfg.judge.clone()),
        manifests: agentfw::mcp::store::ManifestStore::new(&home.join("manifests")),
        tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
        grants: agentfw::grant::GrantStore::new(&home.join("grants")),
        grant_ledger: agentfw::grant::GrantLedger::open(&home.join("grants-spent.json")),
        grant_key: agentfw::grant::derive_key(&token),
        config: cfg.clone(),
        token,
    });

    let addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        addr = %addr,
        enforce = cfg.enforce,
        "agentfw listening ({})",
        if cfg.enforce { "ENFORCING" } else { "shadow mode" }
    );
    axum::serve(listener, app(state)).await?;
    Ok(())
}
