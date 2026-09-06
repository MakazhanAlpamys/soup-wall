// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Daemon configuration: `~/.agentfw/config.yaml` with safe defaults.

use std::path::PathBuf;

use serde::Deserialize;

fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8787
}
fn default_max_record_bytes() -> usize {
    262_144
}
fn default_timeout_ms() -> u64 {
    100
}
fn default_max_body_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_judge_url() -> String {
    "http://localhost:1234/v1/chat/completions".into()
}
fn default_judge_model() -> String {
    "local-model".into()
}
fn default_judge_timeout() -> u64 {
    3000
}
fn default_max_span() -> usize {
    4096
}

/// Optional local-model escalation tier. Off unless a model is actually available.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeCfg {
    #[serde(default)]
    pub enabled: bool,
    /// Any OpenAI-compatible chat-completions endpoint. Must be loopback.
    #[serde(default = "default_judge_url")]
    pub url: String,
    #[serde(default = "default_judge_model")]
    pub model: String,
    #[serde(default = "default_judge_timeout")]
    pub timeout_ms: u64,
    /// Cap on the tainted span sent for judging. Prefill dominates latency on a
    /// local model, so this is the main lever on how long a judgement takes.
    #[serde(default = "default_max_span")]
    pub max_span_bytes: usize,
}

impl Default for JudgeCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_judge_url(),
            model: default_judge_model(),
            timeout_ms: default_judge_timeout(),
            max_span_bytes: default_max_span(),
        }
    }
}

/// Extract the host component (no port, no brackets) from a `scheme://...` URL,
/// without pulling in a URL-parsing dependency for one check. Anchors on the
/// authority component rather than matching a raw string prefix: a prefix check
/// against `"http://localhost"` would also match `http://localhost.evil.com`,
/// where `localhost.evil.com` is an attacker-controlled DNS name that merely
/// starts with the string "localhost".
fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Drop userinfo (`user:pass@host`) if present.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:1234`.
        return rest.split(']').next();
    }
    // Strip a trailing `:port` — only if what follows the last colon is all digits,
    // so a bare IPv6 literal without brackets (which we don't accept anyway) isn't
    // mistaken for host:port.
    match authority.rfind(':') {
        Some(idx)
            if !authority[idx + 1..].is_empty()
                && authority[idx + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(&authority[..idx])
        }
        _ => Some(authority),
    }
}

/// Whether a `judge.url` points at this machine only. Exact match on the extracted
/// host — never a prefix check, which lookalike hostnames like
/// `localhost.evil.com` or `127.0.0.1.evil.com` would defeat.
fn is_loopback_url(url: &str) -> bool {
    match url_host(url) {
        Some(host) => matches!(
            host.to_ascii_lowercase().as_str(),
            "localhost" | "127.0.0.1" | "::1"
        ),
        None => false,
    }
}

/// Daemon configuration. Every field has a safe default, so an absent config file
/// is equivalent to an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Loopback only. A non-loopback value is rejected at parse time.
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// `false` = shadow mode: verdicts are computed and logged but never enforced.
    #[serde(default)]
    pub enforce: bool,
    #[serde(default)]
    pub policy: Option<PathBuf>,
    #[serde(default)]
    pub audit: Option<PathBuf>,
    /// Persist the complete body of hook events unknown to this build.
    /// Disabled by default because future event shapes may contain credentials,
    /// prompts, file contents, or other sensitive material.
    #[serde(default)]
    pub capture_unknown_raw: bool,
    /// Cap on content handed to the taint recorder. Measured: 10 MB costs 532 ms,
    /// far past the budget for a synchronous hook. 256 KB costs roughly 13 ms.
    #[serde(default = "default_max_record_bytes")]
    pub max_record_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub deterministic_timeout_ms: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Optional local-model escalation tier. Off by default.
    #[serde(default)]
    pub judge: JudgeCfg,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            enforce: false,
            policy: None,
            audit: None,
            capture_unknown_raw: false,
            max_record_bytes: default_max_record_bytes(),
            deterministic_timeout_ms: default_timeout_ms(),
            max_body_bytes: default_max_body_bytes(),
            judge: JudgeCfg::default(),
        }
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let c: Config = serde_yaml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    /// Reject anything that would expose the daemon beyond this machine.
    fn validate(&self) -> anyhow::Result<()> {
        let ok = self.bind == "127.0.0.1" || self.bind == "::1" || self.bind == "localhost";
        anyhow::ensure!(
            ok,
            "bind must be a loopback address (127.0.0.1, ::1, localhost); got {:?}. \
             The daemon holds session data and taint state and must never be reachable off-host.",
            self.bind
        );
        // Only enforced when the judge is actually enabled: a disabled judge with a
        // silly timeout or a non-loopback URL sitting in a config file must not
        // stop the daemon from booting. Most installs will never turn this on.
        if self.judge.enabled {
            anyhow::ensure!(
                self.judge.timeout_ms <= 4000,
                "judge.timeout_ms must be <= 4000: the Claude Code hook timeout is 5s, and a judge \
                 allowed to outlast it would make the hook itself time out. Got {}",
                self.judge.timeout_ms
            );
            anyhow::ensure!(
                is_loopback_url(&self.judge.url),
                "judge.url must be a loopback address; got {:?}. The judge prompt contains tool \
                 arguments and untrusted fetched content — sending that off-host would make this \
                 firewall an exfiltration channel.",
                self.judge.url
            );
        }
        Ok(())
    }

    /// `~/.agentfw`, created if absent.
    pub fn home() -> anyhow::Result<PathBuf> {
        let home = platform_home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
        let dir = home.join(".agentfw");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

fn platform_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert_eq!(c.bind, "127.0.0.1", "must never bind a public interface");
        assert_eq!(c.port, 8787);
        assert!(
            !c.enforce,
            "shadow mode is the default; enforcement is opt-in"
        );
        assert_eq!(c.max_record_bytes, 262_144);
        assert_eq!(c.deterministic_timeout_ms, 100);
        assert!(
            !c.capture_unknown_raw,
            "raw unknown events may contain secrets and must be opt-in"
        );
    }

    #[test]
    fn parses_a_partial_file_and_keeps_defaults() {
        let c = Config::from_yaml("enforce: true\nport: 9001\n").unwrap();
        assert!(c.enforce);
        assert_eq!(c.port, 9001);
        assert_eq!(c.bind, "127.0.0.1");
        assert_eq!(c.max_record_bytes, 262_144);
        assert!(!c.capture_unknown_raw);
    }

    #[test]
    fn raw_unknown_capture_requires_explicit_opt_in() {
        let c = Config::from_yaml("capture_unknown_raw: true\n").unwrap();
        assert!(c.capture_unknown_raw);
    }

    #[test]
    fn an_empty_file_is_all_defaults() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_non_loopback_bind_is_rejected() {
        // Binding a public interface would expose session data and let any host
        // poison taint state. This must be impossible via config.
        let err = Config::from_yaml("bind: 0.0.0.0\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("loopback"), "got: {err}");
    }

    // --- phase 10: judge configuration ---

    #[test]
    fn the_judge_is_disabled_by_default() {
        let c = Config::default();
        assert!(
            !c.judge.enabled,
            "a local model is optional; the tool must work without one"
        );
        assert_eq!(c.judge.timeout_ms, 3000);
        assert_eq!(c.judge.max_span_bytes, 4096);
        assert!(c.judge.url.contains("/v1/chat/completions"));
    }

    #[test]
    fn a_config_without_a_judge_block_still_parses() {
        // A phase-09 config must keep working untouched.
        let c = Config::from_yaml("enforce: true\n").unwrap();
        assert!(!c.judge.enabled);
    }

    #[test]
    fn an_empty_file_still_equals_default_with_judge_added() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_judge_timeout_that_would_outlast_the_hook_is_rejected() {
        // The Claude Code hook timeout is 5s. A judge allowed to run longer would
        // make the hook itself time out, which is a worse failure than no judge.
        let err = Config::from_yaml("judge:\n  enabled: true\n  timeout_ms: 9000\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("timeout"), "got: {err}");
    }

    #[test]
    fn a_disabled_judge_with_an_oversized_timeout_does_not_block_boot() {
        // Most installs have no local model. A silly timeout on a disabled judge
        // must not stop the daemon from starting.
        let c = Config::from_yaml("judge:\n  enabled: false\n  timeout_ms: 999999\n").unwrap();
        assert!(!c.judge.enabled);
        assert_eq!(c.judge.timeout_ms, 999_999);
    }

    #[test]
    fn a_judge_url_must_be_loopback_when_enabled() {
        // The prompt contains tainted content and tool arguments. Sending that to a
        // remote endpoint would be an exfiltration channel opened by the firewall.
        let err = Config::from_yaml(
            "judge:\n  enabled: true\n  url: https://api.example.com/v1/chat/completions\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("loopback"), "got: {err}");
    }

    #[test]
    fn a_lookalike_loopback_hostname_is_not_fooled_by_a_prefix_check() {
        // "http://localhost.evil.com" starts with "http://localhost" but resolves
        // to an attacker-controlled domain. A naive `starts_with` check would let
        // this through and turn the judge into an exfiltration channel.
        for url in [
            "http://localhost.evil.com/v1/chat/completions",
            "http://127.0.0.1.evil.com/v1/chat/completions",
        ] {
            let err = Config::from_yaml(&format!("judge:\n  enabled: true\n  url: {url}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("loopback"),
                "lookalike host {url:?} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn loopback_urls_with_ports_and_ipv6_are_accepted() {
        for url in [
            "http://localhost:1234/v1/chat/completions",
            "http://127.0.0.1:1234/v1/chat/completions",
            "http://[::1]:1234/v1/chat/completions",
        ] {
            let c = Config::from_yaml(&format!("judge:\n  enabled: true\n  url: {url}\n"))
                .unwrap_or_else(|e| panic!("expected {url:?} to be accepted, got: {e}"));
            assert!(c.judge.enabled);
        }
    }

    #[test]
    fn an_unknown_key_inside_the_judge_block_is_rejected() {
        let err = Config::from_yaml("judge:\n  enabled: true\n  bogus: 1\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bogus") || err.contains("unknown field"),
            "got: {err}"
        );
    }
}
