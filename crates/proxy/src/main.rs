// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use llm_firewall::config::{Config, TenantStoreBackend};
use llm_firewall::handlers::{AppState, Shared};
use llm_firewall::oidc::OidcStateCipher;
use llm_firewall::saml_auth::SamlRuntimeConfig;
use llm_firewall::{app, build_firewall};

fn is_loopback_bind(bind: &str) -> bool {
    bind.parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback())
}

/// Return whether the PostgreSQL connection must use TLS for this deployment.
///
/// The only plaintext exception on a network-exposed bind is the private
/// `postgres` service name from `deploy/docker-compose.production.yaml`; it is
/// not published outside the Compose network. Loopback development binds may
/// also use a local plaintext database. URL and deployment validation run
/// before this helper is used, so a malformed URL fails closed in the strict
/// (`true`) branch.
fn postgres_tls_required(bind: &str, connection_url: &str) -> bool {
    if is_loopback_bind(bind) {
        return false;
    }
    reqwest::Url::parse(connection_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host != "postgres"))
        .unwrap_or(true)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn select_openai_key(preferred: Option<String>, conventional: Option<String>) -> Option<String> {
    preferred
        .filter(|value| !value.trim().is_empty())
        .or_else(|| conventional.filter(|value| !value.trim().is_empty()))
}

fn validate_runtime_security(
    bind: &str,
    caller_auth_enabled: bool,
    shared_proxy_auth_enabled: bool,
    proxy_auth_token: Option<&str>,
    has_server_side_openai_key: bool,
) -> anyhow::Result<()> {
    if shared_proxy_auth_enabled && proxy_auth_token.is_none() {
        anyhow::bail!(
            "proxy_auth is enabled but its token environment variable is empty or absent"
        );
    }
    if !is_loopback_bind(bind) && !caller_auth_enabled {
        anyhow::bail!("a non-loopback bind requires proxy_auth.enabled or tenant_store.enabled");
    }
    if has_server_side_openai_key && !is_loopback_bind(bind) {
        anyhow::bail!(
            "server-side OpenAI key fallback requires a literal loopback bind (for example \
             127.0.0.1:8080); use caller Authorization or put authenticated TLS reverse proxy \
             in front of a network-exposed firewall"
        );
    }
    Ok(())
}

fn validate_tenant_store(
    cfg: &Config,
    admin_token: Option<&str>,
    postgres_url: Option<&str>,
    require_admin_token: bool,
) -> anyhow::Result<()> {
    let tenant_store = &cfg.tenant_store;
    if !tenant_store.enabled {
        return Ok(());
    }
    if cfg.proxy_auth.enabled {
        anyhow::bail!(
            "tenant_store and proxy_auth cannot both be enabled; use tenant tokens instead of a shared proxy token"
        );
    }
    if tenant_store.backend == TenantStoreBackend::Sqlite
        && tenant_store.database_path.trim().is_empty()
    {
        anyhow::bail!("tenant_store.database_path cannot be empty when backend is sqlite");
    }
    if tenant_store.backend == TenantStoreBackend::Postgres {
        if tenant_store.postgres_url_env.trim().is_empty() {
            anyhow::bail!("tenant_store.postgres_url_env cannot be empty when backend is postgres");
        }
        if postgres_url.is_none() {
            anyhow::bail!(
                "tenant_store is configured for PostgreSQL but its connection URL environment variable is empty or absent"
            );
        }
        if tenant_store.postgres_command_timeout_ms == 0 {
            anyhow::bail!("tenant_store.postgres_command_timeout_ms must be greater than zero");
        }
        if tenant_store.postgres_pool_max_size == 0 {
            anyhow::bail!("tenant_store.postgres_pool_max_size must be greater than zero");
        }
        if tenant_store.postgres_pool_wait_timeout_ms == 0 {
            anyhow::bail!("tenant_store.postgres_pool_wait_timeout_ms must be greater than zero");
        }
    }
    if tenant_store.audit_max_rows == 0 {
        anyhow::bail!("tenant_store.audit_max_rows must be greater than zero");
    }
    if tenant_store.audit_queue_capacity == 0 {
        anyhow::bail!("tenant_store.audit_queue_capacity must be greater than zero");
    }
    if require_admin_token && admin_token.is_none() {
        anyhow::bail!(
            "tenant_store is enabled but its admin token environment variable is empty or absent"
        );
    }
    Ok(())
}

fn validate_spend_limit(cfg: &Config) -> anyhow::Result<()> {
    let spend = &cfg.spend_limit;
    if !spend.enabled {
        return Ok(());
    }
    if spend.max_usd_micros == 0 || spend.reserve_usd_micros_per_request == 0 {
        anyhow::bail!(
            "spend_limit requires nonzero max_usd_micros and reserve_usd_micros_per_request"
        );
    }
    if spend.reserve_usd_micros_per_request > spend.max_usd_micros {
        anyhow::bail!("spend_limit reserve_usd_micros_per_request cannot exceed max_usd_micros");
    }
    if spend.model_prices.is_empty() {
        anyhow::bail!("spend_limit requires at least one model_prices entry");
    }
    Ok(())
}

fn validate_postgres_ca_cert_file(
    cfg: &Config,
    postgres_ca_cert_file: Option<&str>,
) -> anyhow::Result<()> {
    if cfg.tenant_store.enabled && cfg.tenant_store.backend == TenantStoreBackend::Postgres {
        if let Some(path) = postgres_ca_cert_file {
            if !Path::new(path).is_file() {
                anyhow::bail!(
                    "LLM_FW_POSTGRES_CA_CERT_FILE must point to a readable PEM certificate file"
                );
            }
        }
    }
    Ok(())
}

fn validate_redis_limits(cfg: &Config, redis_url: Option<&str>) -> anyhow::Result<()> {
    let redis_limits = &cfg.redis_limits;
    if !redis_limits.enabled {
        return Ok(());
    }
    if redis_limits.url_env.trim().is_empty() {
        anyhow::bail!("redis_limits.url_env cannot be empty");
    }
    if redis_url.is_none() {
        anyhow::bail!(
            "redis_limits is enabled but its Redis URL environment variable is empty or absent"
        );
    }
    if redis_limits.key_prefix.is_empty()
        || !redis_limits
            .key_prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
    {
        anyhow::bail!(
            "redis_limits.key_prefix must contain only ASCII letters, digits, ':', '_' or '-'"
        );
    }
    Ok(())
}

/// Validate deployment-only transport requirements without opening a network
/// connection. A loopback development deployment may use plaintext local
/// PostgreSQL/Redis. The bundled Compose service names (`postgres` and `redis`)
/// are also allowed because those services have no published ports; every other
/// backend on a network-exposed bind must use encryption.
fn validate_production_transports(
    cfg: &Config,
    postgres_url: Option<&str>,
    redis_url: Option<&str>,
) -> anyhow::Result<()> {
    if is_loopback_bind(&cfg.bind) {
        return Ok(());
    }

    if cfg.tenant_store.enabled && cfg.tenant_store.backend == TenantStoreBackend::Postgres {
        let url = postgres_url.ok_or_else(|| {
            anyhow::anyhow!("network-exposed PostgreSQL deployment requires its URL")
        })?;
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| anyhow::anyhow!("LLM_FW_POSTGRES_URL is not a valid URL"))?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") {
            anyhow::bail!("LLM_FW_POSTGRES_URL must use the postgres:// or postgresql:// scheme");
        }
        let sslmode = parsed
            .query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case("sslmode"))
            .map(|(_, value)| value.to_ascii_lowercase());
        let local_compose_backend = matches!(parsed.host_str(), Some("postgres"));
        if !local_compose_backend && !matches!(sslmode.as_deref(), Some("require")) {
            anyhow::bail!("network-exposed PostgreSQL requires sslmode=require");
        }
    }

    if cfg.redis_limits.enabled {
        let url = redis_url
            .ok_or_else(|| anyhow::anyhow!("network-exposed Redis deployment requires its URL"))?;
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| anyhow::anyhow!("LLM_FW_REDIS_URL is not a valid URL"))?;
        let local_compose_backend = matches!(parsed.host_str(), Some("redis"));
        if !local_compose_backend && parsed.scheme() != "rediss" {
            anyhow::bail!("network-exposed Redis requires a rediss:// TLS URL");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    // Local development convenience only. dotenvy does not override variables
    // already supplied by the operating system or production secret manager.
    if std::path::Path::new(".env").exists() {
        dotenvy::dotenv().context("failed to load .env")?;
    }

    let command = std::env::args().nth(1);
    if let Some(command) = command.as_deref() {
        if !matches!(command, "migrate" | "preflight") {
            anyhow::bail!("unknown command `{command}`; supported commands: migrate, preflight");
        }
    }

    let cfg = Config::from_yaml(&std::fs::read_to_string("firewall.yaml")?)?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()?;
    let openai_api_key = select_openai_key(
        nonempty_env("LLM_FW_OPENAI_API_KEY"),
        nonempty_env("OPENAI_API_KEY"),
    );
    let proxy_auth_token = cfg
        .proxy_auth
        .enabled
        .then(|| nonempty_env(&cfg.proxy_auth.token_env))
        .flatten();
    let admin_token = cfg
        .tenant_store
        .enabled
        .then(|| nonempty_env(&cfg.tenant_store.admin_token_env))
        .flatten();
    let webhook_signing_key = nonempty_env("LLM_FW_WEBHOOK_SIGNING_KEY");
    let redis_url = cfg
        .redis_limits
        .enabled
        .then(|| nonempty_env(&cfg.redis_limits.url_env))
        .flatten();
    let postgres_url = (cfg.tenant_store.enabled
        && cfg.tenant_store.backend == TenantStoreBackend::Postgres)
        .then(|| nonempty_env(&cfg.tenant_store.postgres_url_env))
        .flatten();
    let postgres_ca_cert_file = (cfg.tenant_store.enabled
        && cfg.tenant_store.backend == TenantStoreBackend::Postgres)
        .then(|| nonempty_env(&cfg.tenant_store.postgres_ca_cert_file_env))
        .flatten();
    if command.as_deref() == Some("migrate") {
        validate_tenant_store(&cfg, None, postgres_url.as_deref(), false)?;
        validate_postgres_ca_cert_file(&cfg, postgres_ca_cert_file.as_deref())?;
        if cfg.tenant_store.backend != TenantStoreBackend::Postgres {
            anyhow::bail!("`llm-firewall migrate` requires tenant_store.backend: postgres");
        }
        llm_firewall::tenant_store::TenantStore::migrate_postgres_with_ca_and_tls(
            postgres_url
                .as_deref()
                .expect("validated PostgreSQL tenant-store URL"),
            cfg.tenant_store.audit_max_rows,
            Duration::from_millis(cfg.tenant_store.postgres_command_timeout_ms),
            cfg.tenant_store.postgres_pool_max_size,
            Duration::from_millis(cfg.tenant_store.postgres_pool_wait_timeout_ms),
            postgres_ca_cert_file.as_deref(),
            postgres_tls_required(
                &cfg.bind,
                postgres_url
                    .as_deref()
                    .expect("validated PostgreSQL tenant-store URL"),
            ),
        )
        .await?;
        tracing::info!("PostgreSQL control-plane migrations are current");
        return Ok(());
    }

    if command.as_deref() == Some("preflight") {
        validate_spend_limit(&cfg)?;
        validate_tenant_store(&cfg, admin_token.as_deref(), postgres_url.as_deref(), true)?;
        validate_postgres_ca_cert_file(&cfg, postgres_ca_cert_file.as_deref())?;
        validate_redis_limits(&cfg, redis_url.as_deref())?;
        validate_production_transports(&cfg, postgres_url.as_deref(), redis_url.as_deref())?;
        if let Some(encoded_key) = nonempty_env("LLM_FW_OIDC_STATE_KEY") {
            OidcStateCipher::from_base64url_key(&encoded_key)?;
        }
        if cfg.tenant_store.enabled {
            SamlRuntimeConfig::from_env()?;
        }
        validate_runtime_security(
            &cfg.bind,
            cfg.proxy_auth.enabled || cfg.tenant_store.enabled,
            cfg.proxy_auth.enabled,
            proxy_auth_token.as_deref(),
            openai_api_key.is_some(),
        )?;
        // Build the policy as part of the preflight, but do not open databases,
        // Redis, or an HTTP listener. This catches malformed policy files and
        // unsafe production transport settings before a rollout.
        build_firewall(&cfg)?;
        println!("Soup Wall Gateway preflight passed (no external connections made)");
        return Ok(());
    }

    let oidc_state_cipher = cfg
        .tenant_store
        .enabled
        .then(|| nonempty_env("LLM_FW_OIDC_STATE_KEY"))
        .flatten()
        .map(|encoded_key| OidcStateCipher::from_base64url_key(&encoded_key))
        .transpose()?;
    let saml = if cfg.tenant_store.enabled {
        SamlRuntimeConfig::from_env()?
    } else {
        None
    };
    validate_spend_limit(&cfg)?;
    let firewall = build_firewall(&cfg)?;
    validate_tenant_store(&cfg, admin_token.as_deref(), postgres_url.as_deref(), true)?;
    validate_postgres_ca_cert_file(&cfg, postgres_ca_cert_file.as_deref())?;
    validate_redis_limits(&cfg, redis_url.as_deref())?;
    validate_production_transports(&cfg, postgres_url.as_deref(), redis_url.as_deref())?;
    let tenant_store = if !cfg.tenant_store.enabled {
        None
    } else {
        let store = match cfg.tenant_store.backend {
            TenantStoreBackend::Sqlite => {
                llm_firewall::tenant_store::TenantStore::open_with_audit_capacity(
                    &cfg.tenant_store.database_path,
                    cfg.tenant_store.audit_max_rows,
                )?
            }
            TenantStoreBackend::Postgres => {
                llm_firewall::tenant_store::TenantStore::open_postgres_with_ca_and_tls(
                    postgres_url
                        .as_deref()
                        .expect("validated PostgreSQL tenant-store URL"),
                    cfg.tenant_store.audit_max_rows,
                    Duration::from_millis(cfg.tenant_store.postgres_command_timeout_ms),
                    cfg.tenant_store.postgres_pool_max_size,
                    Duration::from_millis(cfg.tenant_store.postgres_pool_wait_timeout_ms),
                    postgres_ca_cert_file.as_deref(),
                    postgres_tls_required(
                        &cfg.bind,
                        postgres_url
                            .as_deref()
                            .expect("validated PostgreSQL tenant-store URL"),
                    ),
                )
                .await?
            }
        };
        let store = store.with_audit_dispatcher(cfg.tenant_store.audit_queue_capacity);
        let store = match webhook_signing_key.as_deref() {
            Some(encoded_key) => store.with_webhook_signing_key_base64url(encoded_key)?,
            None => store,
        };
        let webhook_worker = store.clone();
        if webhook_signing_key.is_some() {
            tokio::spawn(async move {
                webhook_worker.run_webhook_delivery_loop().await;
            });
        }
        Some(store)
    };
    let redis_limits = match redis_url {
        Some(url) => Some(
            llm_firewall::redis_limits::RedisLimits::connect(&url, &cfg.redis_limits)
                .await
                .context("failed to connect the Redis limits backend")?,
        ),
        None => None,
    };
    validate_runtime_security(
        &cfg.bind,
        cfg.proxy_auth.enabled || tenant_store.is_some(),
        cfg.proxy_auth.enabled,
        proxy_auth_token.as_deref(),
        openai_api_key.is_some(),
    )?;
    let state: Shared = Arc::new(AppState {
        firewall,
        http,
        config: cfg.clone(),
        openai_api_key,
        proxy_auth_token,
        tenant_store,
        admin_token,
        oidc_state_cipher,
        saml,
        rate_limiter: std::sync::Mutex::new(llm_firewall::rate_limit::RateLimiter::new(
            cfg.rate_limit.clone(),
        )),
        spend_ledger: std::sync::Mutex::new(llm_firewall::spend_limit::SpendLedger::new(
            cfg.spend_limit.clone(),
        )),
        redis_limits,
        agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(cfg.output_moderation.clone()),
    });

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("Soup Wall Gateway listening on {}", cfg.bind);
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        is_loopback_bind, postgres_tls_required, select_openai_key, validate_postgres_ca_cert_file,
        validate_production_transports, validate_redis_limits, validate_runtime_security,
        validate_spend_limit, validate_tenant_store,
    };
    use llm_firewall::config::{
        Config, ModelPrice, RedisLimitsConfig, SpendLimit, TenantStoreBackend, TenantStoreConfig,
    };
    use std::collections::BTreeMap;

    #[test]
    fn server_side_key_fallback_requires_a_literal_loopback_bind() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("localhost:8080"));
    }

    #[test]
    fn postgres_tls_exception_matches_only_loopback_or_compose_service() {
        assert!(!postgres_tls_required(
            "127.0.0.1:8080",
            "postgresql://fw:secret@db/firewall?sslmode=disable"
        ));
        assert!(!postgres_tls_required(
            "0.0.0.0:8080",
            "postgresql://fw:secret@postgres/firewall?sslmode=disable"
        ));
        assert!(postgres_tls_required(
            "0.0.0.0:8080",
            "postgresql://fw:secret@db/firewall?sslmode=disable"
        ));
        assert!(postgres_tls_required("0.0.0.0:8080", "not-a-url"));
    }

    #[test]
    fn empty_preferred_key_falls_back_to_conventional_openai_key() {
        assert_eq!(
            select_openai_key(Some(" ".into()), Some("sk-secondary".into())),
            Some("sk-secondary".into())
        );
        assert_eq!(
            select_openai_key(Some("sk-preferred".into()), Some("sk-secondary".into())),
            Some("sk-preferred".into())
        );
    }

    #[test]
    fn public_bind_requires_a_configured_proxy_token() {
        assert!(validate_runtime_security("0.0.0.0:8080", false, false, None, false).is_err());
        assert!(validate_runtime_security("0.0.0.0:8080", true, true, None, false).is_err());
        assert!(
            validate_runtime_security("0.0.0.0:8080", true, true, Some("token"), false).is_ok()
        );
        assert!(validate_runtime_security("127.0.0.1:8080", false, false, None, false).is_ok());
    }

    #[test]
    fn enabled_spend_limit_requires_a_real_budget_reservation_and_price_table() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.spend_limit.enabled = true;
        assert!(validate_spend_limit(&cfg).is_err());
        cfg.spend_limit = SpendLimit {
            enabled: true,
            window_seconds: 60,
            max_usd_micros: 10,
            reserve_usd_micros_per_request: 4,
            max_tracked_clients: 1,
            model_prices: BTreeMap::from([(
                "gpt-test".into(),
                ModelPrice {
                    input_usd_micros_per_million: 1,
                    output_usd_micros_per_million: 1,
                },
            )]),
        };
        assert!(validate_spend_limit(&cfg).is_ok());
    }

    #[test]
    fn tenant_store_requires_a_separate_admin_secret_and_no_shared_proxy_token() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.tenant_store = TenantStoreConfig {
            enabled: true,
            backend: TenantStoreBackend::Sqlite,
            database_path: "runtime/tenants.sqlite".into(),
            postgres_url_env: "LLM_FW_POSTGRES_URL".into(),
            postgres_ca_cert_file_env: "LLM_FW_POSTGRES_CA_CERT_FILE".into(),
            postgres_command_timeout_ms: 1_000,
            postgres_pool_max_size: 16,
            postgres_pool_wait_timeout_ms: 1_000,
            admin_token_env: "LLM_FW_ADMIN_TOKEN".into(),
            audit_max_rows: 100,
            audit_queue_capacity: 100,
        };
        assert!(validate_tenant_store(&cfg, None, None, true).is_err());
        assert!(validate_tenant_store(&cfg, Some("admin"), None, true).is_ok());
        cfg.proxy_auth.enabled = true;
        assert!(validate_tenant_store(&cfg, Some("admin"), None, true).is_err());
        cfg.proxy_auth.enabled = false;
        cfg.tenant_store.backend = TenantStoreBackend::Postgres;
        assert!(validate_tenant_store(&cfg, Some("admin"), None, true).is_err());
        assert!(validate_tenant_store(
            &cfg,
            Some("admin"),
            Some("postgresql://firewall:secret@db.example/firewall?sslmode=require"),
            true,
        )
        .is_ok());
        cfg.tenant_store.postgres_command_timeout_ms = 0;
        assert!(validate_tenant_store(
            &cfg,
            Some("admin"),
            Some("postgresql://firewall:secret@db.example/firewall?sslmode=require"),
            true,
        )
        .is_err());
    }

    #[test]
    fn postgres_ca_file_validation_rejects_missing_paths() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.tenant_store.enabled = true;
        cfg.tenant_store.backend = TenantStoreBackend::Postgres;
        assert!(validate_postgres_ca_cert_file(&cfg, None).is_ok());
        assert!(validate_postgres_ca_cert_file(
            &cfg,
            Some("runtime/does-not-exist/postgres-ca.pem")
        )
        .is_err());
    }

    #[test]
    fn redis_limits_require_a_secret_url_and_safe_key_prefix() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.redis_limits = RedisLimitsConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(validate_redis_limits(&cfg, None).is_err());
        assert!(validate_redis_limits(&cfg, Some("redis://127.0.0.1")).is_ok());
        cfg.redis_limits.key_prefix = "unsafe prefix".into();
        assert!(validate_redis_limits(&cfg, Some("redis://127.0.0.1")).is_err());
    }

    #[test]
    fn public_deployment_requires_tls_for_postgres_and_redis() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.bind = "0.0.0.0:8080".into();
        cfg.tenant_store.enabled = true;
        cfg.tenant_store.backend = TenantStoreBackend::Postgres;
        cfg.redis_limits.enabled = true;

        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://fw:secret@db/firewall?sslmode=disable"),
            Some("redis://cache:6379"),
        )
        .is_err());
        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://fw:secret@db/firewall?sslmode=require"),
            Some("rediss://cache:6379"),
        )
        .is_ok());
        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://fw:secret@db/firewall?sslmode=verify-full"),
            Some("rediss://cache:6379"),
        )
        .is_err());
        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://fw:secret@postgres/firewall?sslmode=disable"),
            Some("redis://redis:6379"),
        )
        .is_ok());
    }

    #[test]
    fn loopback_deployment_may_use_local_backend_urls() {
        let mut cfg = llm_firewall::test_config("http://127.0.0.1:1".into());
        cfg.tenant_store.enabled = true;
        cfg.tenant_store.backend = TenantStoreBackend::Postgres;
        cfg.redis_limits.enabled = true;
        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://fw:secret@127.0.0.1/firewall?sslmode=disable"),
            Some("redis://127.0.0.1:6379"),
        )
        .is_ok());
    }

    #[test]
    fn production_template_uses_tenant_auth_without_a_shared_proxy_secret() {
        let cfg: Config =
            serde_yaml::from_str(include_str!("../../../deploy/production.firewall.yaml"))
                .expect("production template must parse");
        assert!(cfg.tenant_store.enabled);
        assert_eq!(cfg.tenant_store.backend, TenantStoreBackend::Postgres);
        assert!(!cfg.proxy_auth.enabled);
        assert!(validate_tenant_store(
            &cfg,
            Some("admin-test-token"),
            Some("postgresql://firewall:secret@postgres/firewall?sslmode=disable"),
            true,
        )
        .is_ok());
        assert!(
            validate_runtime_security(&cfg.bind, true, cfg.proxy_auth.enabled, None, false,)
                .is_ok()
        );
        assert!(validate_production_transports(
            &cfg,
            Some("postgresql://firewall:secret@postgres/firewall?sslmode=disable"),
            Some("redis://:secret@redis:6379"),
        )
        .is_ok());
    }
}
