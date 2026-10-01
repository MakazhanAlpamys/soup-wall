// SPDX-License-Identifier: Apache-2.0

//! Proxy configuration: `firewall.yaml` with env-var overrides.

use serde::Deserialize;
use soup_wall_core::Normalizer;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailClosed,
    FailOpen,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default = "default_openai")]
    pub openai_base: String,
    /// Base URL for the native Anthropic Messages API (`/v1/messages`).
    #[serde(default = "default_anthropic")]
    pub anthropic_base: String,
}

/// Obfuscation/evasion normalization pre-pass config (all default on except base64).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizeCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strip_zero_width: bool,
    #[serde(default = "default_true")]
    pub fold_homoglyphs: bool,
    #[serde(default)]
    pub decode_encoded: bool,
}

impl Default for NormalizeCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            strip_zero_width: true,
            fold_homoglyphs: true,
            decode_encoded: false,
        }
    }
}

/// Agent-layer inspection of tool blocks in proxied traffic. Off by default, and
/// shadow-first (`enforce` off) when enabled — verdicts are audited but not applied.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInspection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub enforce: bool,
}

impl NormalizeCfg {
    /// Build a `Normalizer` when enabled; `None` disables the pre-pass entirely.
    pub fn to_normalizer(&self) -> Option<Normalizer> {
        self.enabled.then_some(Normalizer {
            strip_zero_width: self.strip_zero_width,
            fold_homoglyphs: self.fold_homoglyphs,
            decode_encoded: self.decode_encoded,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default)]
    pub policy_file: Option<String>,
    #[serde(default = "default_fail")]
    pub fail_mode: FailMode,
    #[serde(default = "default_window")]
    pub stream_window: usize,
    /// Maximum JSON request size accepted by the proxy before parsing it.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum JSON response size accepted from a non-streaming upstream.
    #[serde(default = "default_max_upstream_body_bytes")]
    pub max_upstream_body_bytes: usize,
    /// Deadline for non-streaming upstream headers and JSON body reads.
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    /// Maximum idle gap between chunks in a streaming upstream response.
    #[serde(default = "default_stream_idle_timeout_ms")]
    pub stream_idle_timeout_ms: u64,
    /// Maximum number of upstream chunks buffered while a downstream client is slow.
    #[serde(default = "default_stream_buffer_chunks")]
    pub stream_buffer_chunks: usize,
    /// Largest individual upstream streaming chunk accepted by the proxy.
    #[serde(default = "default_max_stream_chunk_bytes")]
    pub max_stream_chunk_bytes: usize,
    #[serde(default)]
    pub normalize: NormalizeCfg,
    #[serde(default)]
    pub agent_inspection: AgentInspection,
    #[serde(default)]
    pub proxy_auth: ProxyAuth,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub spend_limit: SpendLimit,
    #[serde(default)]
    pub tenant_store: TenantStoreConfig,
    #[serde(default)]
    pub redis_limits: RedisLimitsConfig,
    #[serde(default)]
    pub capability_policy: crate::capability::CapabilityPolicy,
    #[serde(default)]
    pub output_moderation: OutputModeration,
}

/// What to do when a model reply is judged harmful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModerationAction {
    /// Forward the response, but record the verdict + categories in the audit log.
    Flag,
    /// Refuse the response with a safe message; the client never sees the harmful text.
    Block,
}

fn default_mod_threshold() -> f32 {
    0.8
}
fn default_mod_model() -> String {
    "models/moderation".into()
}
fn default_refusal() -> String {
    "This response was withheld by the output content policy.".into()
}

/// Model-agnostic output content moderation: restrict harmful model replies regardless
/// of backend. Off by default, and `flag`-first (audit without refusing) when enabled.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct OutputModeration {
    /// Run the harmful-content classifier on model replies. Off by default.
    pub enabled: bool,
    /// What to do on a harmful reply. `flag` (default) audits; `block` refuses.
    pub action: ModerationAction,
    /// Classifier score at/above which a category counts as harmful.
    pub threshold: f32,
    /// Directory of the moderation model.
    pub model_path: String,
    /// Restrict to these harm categories (empty = every category the model emits).
    pub categories: Vec<String>,
    /// Refusal message returned to the client when `action: block`.
    pub refusal_message: String,
}

impl Default for OutputModeration {
    fn default() -> Self {
        Self {
            enabled: false,
            action: ModerationAction::Flag,
            threshold: default_mod_threshold(),
            model_path: default_mod_model(),
            categories: Vec::new(),
            refusal_message: default_refusal(),
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:8080".into()
}
fn default_openai() -> String {
    "https://api.openai.com".into()
}
fn default_anthropic() -> String {
    "https://api.anthropic.com".into()
}
fn default_fail() -> FailMode {
    FailMode::FailClosed
}
fn default_window() -> usize {
    64
}

/// Authentication required from callers before this proxy will forward any
/// model request. The secret itself is read only from an environment variable.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyAuth {
    /// Require `X-LLM-Firewall-Token: Bearer <token>` on every API route.
    pub enabled: bool,
    /// Environment variable that carries the bearer token; never put its value
    /// in `firewall.yaml`.
    pub token_env: String,
}

fn default_proxy_auth_token_env() -> String {
    "LLM_FW_PROXY_AUTH_TOKEN".into()
}

impl Default for ProxyAuth {
    fn default() -> Self {
        Self {
            enabled: false,
            token_env: default_proxy_auth_token_env(),
        }
    }
}

/// In-memory request limiter at the proxy boundary. It is intentionally off by
/// default so local development retains its current behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimit {
    /// Enable a fixed-window request limit before a request body is parsed.
    pub enabled: bool,
    /// Requests allowed from one client during a window.
    pub requests_per_window: u32,
    /// Fixed-window duration in seconds.
    pub window_seconds: u64,
    /// Hard bound on client identities retained in memory.
    pub max_tracked_clients: usize,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_window: 60,
            window_seconds: 60,
            max_tracked_clients: 10_000,
        }
    }
}

/// Operator-supplied per-model prices. All values are USD micros per one
/// million tokens (1 USD = 1,000,000 USD micros); no provider price is baked
/// into the binary because provider pricing changes.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub input_usd_micros_per_million: u64,
    pub output_usd_micros_per_million: u64,
}

/// Process-local spend guard. It reserves a conservative amount before an
/// upstream call, then settles it using the provider's reported token usage.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpendLimit {
    pub enabled: bool,
    pub window_seconds: u64,
    pub max_usd_micros: u64,
    pub reserve_usd_micros_per_request: u64,
    pub max_tracked_clients: usize,
    pub model_prices: BTreeMap<String, ModelPrice>,
}

impl Default for SpendLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            window_seconds: 86_400,
            max_usd_micros: 0,
            reserve_usd_micros_per_request: 0,
            max_tracked_clients: 10_000,
            model_prices: BTreeMap::new(),
        }
    }
}

/// Optional tenant control plane. When enabled, client requests authenticate
/// with tenant tokens issued through the local admin API instead of one shared
/// `proxy_auth` secret.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TenantStoreConfig {
    pub enabled: bool,
    /// Selects the local SQLite store or the shared PostgreSQL control plane.
    pub backend: TenantStoreBackend,
    /// Local SQLite database path, used only when `backend: sqlite`.
    pub database_path: String,
    /// Environment variable holding the PostgreSQL connection string when
    /// `backend: postgres`. Its value may contain a credential and never
    /// belongs in YAML.
    pub postgres_url_env: String,
    /// Environment variable holding an optional path to a PEM bundle of
    /// additional PostgreSQL CA certificates. The bundle is loaded in
    /// addition to the Mozilla roots and is never stored in YAML.
    pub postgres_ca_cert_file_env: String,
    /// Bound each PostgreSQL control-plane command so database trouble does
    /// not hold caller authentication or admin requests indefinitely.
    pub postgres_command_timeout_ms: u64,
    /// Maximum number of PostgreSQL connections held by one firewall replica.
    pub postgres_pool_max_size: usize,
    /// Maximum time a request can wait for a PostgreSQL pool connection.
    pub postgres_pool_wait_timeout_ms: u64,
    /// Environment variable containing the credential for `/admin/v1/*`.
    pub admin_token_env: String,
    /// Retention target for privacy-safe tenant audit rows. Concurrent replicas
    /// may briefly exceed it while writes are in flight, but pruning is
    /// non-blocking and converges without a global table lock.
    pub audit_max_rows: usize,
    /// Bounded audit queue size. A full queue drops only audit metadata and is
    /// surfaced by `/readyz`; authentication and model traffic stay protected.
    pub audit_queue_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStoreBackend {
    Sqlite,
    Postgres,
}

fn default_tenant_database_path() -> String {
    "data/llm-firewall.sqlite".into()
}

fn default_tenant_postgres_url_env() -> String {
    "LLM_FW_POSTGRES_URL".into()
}

fn default_tenant_postgres_ca_cert_file_env() -> String {
    "LLM_FW_POSTGRES_CA_CERT_FILE".into()
}

fn default_tenant_postgres_command_timeout_ms() -> u64 {
    1_000
}

fn default_tenant_postgres_pool_max_size() -> usize {
    16
}

fn default_tenant_postgres_pool_wait_timeout_ms() -> u64 {
    1_000
}

fn default_tenant_audit_queue_capacity() -> usize {
    10_000
}

fn default_admin_token_env() -> String {
    "LLM_FW_ADMIN_TOKEN".into()
}

impl Default for TenantStoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: TenantStoreBackend::Sqlite,
            database_path: default_tenant_database_path(),
            postgres_url_env: default_tenant_postgres_url_env(),
            postgres_ca_cert_file_env: default_tenant_postgres_ca_cert_file_env(),
            postgres_command_timeout_ms: default_tenant_postgres_command_timeout_ms(),
            postgres_pool_max_size: default_tenant_postgres_pool_max_size(),
            postgres_pool_wait_timeout_ms: default_tenant_postgres_pool_wait_timeout_ms(),
            admin_token_env: default_admin_token_env(),
            audit_max_rows: 100_000,
            audit_queue_capacity: default_tenant_audit_queue_capacity(),
        }
    }
}

/// Optional Redis backend for rate and spend counters. Tenant identities,
/// policies, and audit history remain in the control plane; only volatile
/// fixed-window enforcement state is stored in Redis.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedisLimitsConfig {
    /// Switch from process-local counters to Redis-backed shared counters.
    pub enabled: bool,
    /// Environment variable holding the `redis://` or `rediss://` connection
    /// URL. The URL may include a credential, so it never belongs in YAML.
    pub url_env: String,
    /// Namespace for firewall keys. It is validated to safe Redis-key ASCII.
    pub key_prefix: String,
    /// Bound an unavailable Redis command rather than holding proxy requests
    /// indefinitely.
    pub command_timeout_ms: u64,
    /// Whether a Redis outage blocks protected traffic or lets it through.
    pub fail_mode: FailMode,
}

fn default_redis_url_env() -> String {
    "LLM_FW_REDIS_URL".into()
}

fn default_redis_key_prefix() -> String {
    "llm-firewall:v1".into()
}

fn default_redis_command_timeout_ms() -> u64 {
    250
}

impl Default for RedisLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url_env: default_redis_url_env(),
            key_prefix: default_redis_key_prefix(),
            command_timeout_ms: default_redis_command_timeout_ms(),
            fail_mode: FailMode::FailClosed,
        }
    }
}
fn default_max_body_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_max_upstream_body_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_upstream_timeout_ms() -> u64 {
    120_000
}
fn default_stream_idle_timeout_ms() -> u64 {
    30_000
}
fn default_stream_buffer_chunks() -> usize {
    8
}
fn default_max_stream_chunk_bytes() -> usize {
    1024 * 1024
}
fn default_true() -> bool {
    true
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            openai_base: default_openai(),
            anthropic_base: default_anthropic(),
        }
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = serde_yaml::from_str(s)?;
        cfg.apply_env()?;
        Ok(cfg)
    }

    /// Env overrides win over the file (12-factor).
    fn apply_env(&mut self) -> anyhow::Result<()> {
        if let Ok(v) = std::env::var("LLM_FW_BIND") {
            self.bind = v;
        }
        if let Ok(v) = std::env::var("LLM_FW_OPENAI_BASE") {
            self.upstream.openai_base = v;
        }
        if let Ok(v) = std::env::var("LLM_FW_ANTHROPIC_BASE") {
            self.upstream.anthropic_base = v;
        }
        if let Ok(v) = std::env::var("LLM_FW_PROXY_AUTH_ENABLED") {
            self.proxy_auth.enabled = v.parse().map_err(|_| {
                anyhow::anyhow!("LLM_FW_PROXY_AUTH_ENABLED must be 'true' or 'false', got '{v}'")
            })?;
        }
        Ok(())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms.max(1))
    }

    pub fn stream_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.stream_idle_timeout_ms.max(1))
    }

    pub fn max_upstream_body_bytes(&self) -> usize {
        self.max_upstream_body_bytes.max(1)
    }

    /// Keep the producer queue bounded even when a config sets zero.
    pub fn stream_buffer_capacity(&self) -> usize {
        self.stream_buffer_chunks.clamp(1, 64)
    }

    pub fn max_stream_chunk_bytes(&self) -> usize {
        self.max_stream_chunk_bytes.max(1)
    }

    pub fn rate_limit_window(&self) -> Duration {
        Duration::from_secs(self.rate_limit.window_seconds.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert_eq!(c.bind, "127.0.0.1:8080");
        assert_eq!(c.fail_mode, FailMode::FailClosed);
        assert_eq!(c.stream_window, 64);
        assert_eq!(c.max_body_bytes, 4 * 1024 * 1024);
        assert_eq!(c.max_upstream_body_bytes, 8 * 1024 * 1024);
        assert_eq!(c.upstream_timeout_ms, 120_000);
        assert_eq!(c.stream_idle_timeout_ms, 30_000);
        assert_eq!(c.stream_buffer_chunks, 8);
        assert_eq!(c.max_stream_chunk_bytes, 1024 * 1024);
        assert!(!c.rate_limit.enabled);
        assert_eq!(c.rate_limit.requests_per_window, 60);
        assert_eq!(c.rate_limit.window_seconds, 60);
        assert_eq!(c.rate_limit.max_tracked_clients, 10_000);
        assert!(!c.spend_limit.enabled);
        assert!(c.spend_limit.model_prices.is_empty());
        assert!(!c.tenant_store.enabled);
        assert_eq!(c.tenant_store.backend, TenantStoreBackend::Sqlite);
        assert_eq!(c.tenant_store.database_path, "data/llm-firewall.sqlite");
        assert_eq!(c.tenant_store.postgres_url_env, "LLM_FW_POSTGRES_URL");
        assert_eq!(
            c.tenant_store.postgres_ca_cert_file_env,
            "LLM_FW_POSTGRES_CA_CERT_FILE"
        );
        assert_eq!(c.tenant_store.postgres_command_timeout_ms, 1_000);
        assert_eq!(c.tenant_store.postgres_pool_max_size, 16);
        assert_eq!(c.tenant_store.postgres_pool_wait_timeout_ms, 1_000);
        assert_eq!(c.tenant_store.admin_token_env, "LLM_FW_ADMIN_TOKEN");
        assert_eq!(c.tenant_store.audit_max_rows, 100_000);
        assert_eq!(c.tenant_store.audit_queue_capacity, 10_000);
        assert!(!c.redis_limits.enabled);
        assert_eq!(c.redis_limits.url_env, "LLM_FW_REDIS_URL");
        assert_eq!(c.redis_limits.key_prefix, "llm-firewall:v1");
        assert_eq!(c.redis_limits.command_timeout_ms, 250);
        assert_eq!(c.redis_limits.fail_mode, FailMode::FailClosed);
    }

    #[test]
    fn output_moderation_is_off_and_flag_first_by_default() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(!c.output_moderation.enabled, "opt-in");
        assert_eq!(
            c.output_moderation.action,
            ModerationAction::Flag,
            "flag-first"
        );
    }

    #[test]
    fn parses_boundary_limits_and_clamps_zero_durations() {
        let c = Config::from_yaml(
            "upstream: {}\nmax_body_bytes: 8192\nupstream_timeout_ms: 0\nstream_idle_timeout_ms: 7\n",
        )
        .unwrap();
        assert_eq!(c.max_body_bytes, 8192);
        assert_eq!(c.upstream_timeout(), Duration::from_millis(1));
        assert_eq!(c.stream_idle_timeout(), Duration::from_millis(7));
    }

    #[test]
    fn stream_buffer_capacity_clamps_zero() {
        let c = Config::from_yaml(
            "upstream: {}\nstream_buffer_chunks: 0\nmax_upstream_body_bytes: 0\nmax_stream_chunk_bytes: 0",
        )
        .unwrap();
        assert_eq!(c.stream_buffer_capacity(), 1);
        assert_eq!(c.max_upstream_body_bytes(), 1);
        assert_eq!(c.max_stream_chunk_bytes(), 1);
    }

    #[test]
    fn stream_buffer_capacity_has_a_safe_upper_bound() {
        let c = Config::from_yaml("upstream: {}\nstream_buffer_chunks: 1000").unwrap();
        assert_eq!(c.stream_buffer_capacity(), 64);
    }

    #[test]
    fn config_rejects_unknown_security_fields() {
        let err = Config::from_yaml(
            "upstream: {}\ncapability_policy:\n  enabled: true\n  enfore: true\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("enfore"));
    }

    #[test]
    fn output_moderation_parses_block_action() {
        let c = Config::from_yaml(
            "upstream: {}\noutput_moderation:\n  enabled: true\n  action: block\n  threshold: 0.9\n",
        )
        .unwrap();
        assert!(c.output_moderation.enabled);
        assert_eq!(c.output_moderation.action, ModerationAction::Block);
        assert!((c.output_moderation.threshold - 0.9).abs() < 1e-6);
    }

    #[test]
    fn agent_inspection_is_off_by_default() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(!c.agent_inspection.enabled, "must be opt-in");
        assert!(!c.agent_inspection.enforce, "shadow-first");
    }

    #[test]
    fn proxy_auth_is_off_by_default_and_uses_a_secret_env_var() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(
            !c.proxy_auth.enabled,
            "local development remains frictionless"
        );
        assert_eq!(c.proxy_auth.token_env, "LLM_FW_PROXY_AUTH_TOKEN");
    }

    #[test]
    fn rate_limit_is_opt_in_and_clamps_a_zero_window() {
        let c = Config::from_yaml(
            "upstream: {}\nrate_limit:\n  enabled: true\n  requests_per_window: 3\n  window_seconds: 0\n  max_tracked_clients: 9\n",
        )
        .unwrap();
        assert!(c.rate_limit.enabled);
        assert_eq!(c.rate_limit.requests_per_window, 3);
        assert_eq!(c.rate_limit_window(), Duration::from_secs(1));
        assert_eq!(c.rate_limit.max_tracked_clients, 9);
    }

    #[test]
    fn spend_limit_parses_operator_supplied_prices() {
        let c = Config::from_yaml(
            "upstream: {}\nspend_limit:\n  enabled: true\n  max_usd_micros: 1000000\n  reserve_usd_micros_per_request: 10000\n  model_prices:\n    gpt-test:\n      input_usd_micros_per_million: 100000\n      output_usd_micros_per_million: 200000\n",
        )
        .unwrap();
        let price = c.spend_limit.model_prices.get("gpt-test").unwrap();
        assert_eq!(price.input_usd_micros_per_million, 100_000);
        assert_eq!(price.output_usd_micros_per_million, 200_000);
    }

    #[test]
    fn tenant_store_is_opt_in_and_uses_env_for_admin_secret() {
        let c = Config::from_yaml(
            "upstream: {}\ntenant_store:\n  enabled: true\n  backend: postgres\n  postgres_url_env: MY_POSTGRES_URL\n  postgres_ca_cert_file_env: MY_POSTGRES_CA_CERT_FILE\n  postgres_command_timeout_ms: 333\n  postgres_pool_max_size: 7\n  postgres_pool_wait_timeout_ms: 444\n  admin_token_env: MY_ADMIN_TOKEN\n  audit_max_rows: 44\n  audit_queue_capacity: 55\n",
        )
        .unwrap();
        assert!(c.tenant_store.enabled);
        assert_eq!(c.tenant_store.backend, TenantStoreBackend::Postgres);
        assert_eq!(c.tenant_store.postgres_url_env, "MY_POSTGRES_URL");
        assert_eq!(
            c.tenant_store.postgres_ca_cert_file_env,
            "MY_POSTGRES_CA_CERT_FILE"
        );
        assert_eq!(c.tenant_store.postgres_command_timeout_ms, 333);
        assert_eq!(c.tenant_store.postgres_pool_max_size, 7);
        assert_eq!(c.tenant_store.postgres_pool_wait_timeout_ms, 444);
        assert_eq!(c.tenant_store.admin_token_env, "MY_ADMIN_TOKEN");
        assert_eq!(c.tenant_store.audit_max_rows, 44);
        assert_eq!(c.tenant_store.audit_queue_capacity, 55);
    }

    #[test]
    fn redis_limits_are_opt_in_and_keep_the_url_in_an_environment_variable() {
        let c = Config::from_yaml(
            "upstream: {}\nredis_limits:\n  enabled: true\n  url_env: REDIS_URL\n  key_prefix: tenant-fw\n  command_timeout_ms: 500\n  fail_mode: fail_open\n",
        )
        .unwrap();
        assert!(c.redis_limits.enabled);
        assert_eq!(c.redis_limits.url_env, "REDIS_URL");
        assert_eq!(c.redis_limits.key_prefix, "tenant-fw");
        assert_eq!(c.redis_limits.command_timeout_ms, 500);
        assert_eq!(c.redis_limits.fail_mode, FailMode::FailOpen);
    }

    #[test]
    fn capability_policy_is_off_and_shadow_first_by_default() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(!c.capability_policy.enabled, "must be opt-in");
        assert!(!c.capability_policy.enforce, "shadow-first");
    }

    #[test]
    fn upstream_defaults() {
        // Checked via Default (not env-influenced) to avoid racing the env-override tests.
        let u = Upstream::default();
        assert_eq!(u.openai_base, "https://api.openai.com");
        assert_eq!(u.anthropic_base, "https://api.anthropic.com");
    }

    #[test]
    fn anthropic_env_override_wins() {
        std::env::set_var("LLM_FW_ANTHROPIC_BASE", "http://localhost:8888");
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert_eq!(c.upstream.anthropic_base, "http://localhost:8888");
        std::env::remove_var("LLM_FW_ANTHROPIC_BASE");
    }

    #[test]
    fn env_override_wins() {
        std::env::set_var("LLM_FW_OPENAI_BASE", "http://localhost:9999");
        let c = Config::from_yaml("upstream: { openai_base: https://api.openai.com }").unwrap();
        assert_eq!(c.upstream.openai_base, "http://localhost:9999");
        std::env::remove_var("LLM_FW_OPENAI_BASE");
    }
}
