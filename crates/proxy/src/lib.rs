// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Soup Wall Gateway — library surface (also used by integration tests).

pub mod admin;
pub mod admin_ui;
pub mod agent_scan;
pub mod anthropic;
pub mod audit;
pub mod auth;
pub mod capability;
pub mod config;
pub mod control_plane;
pub mod customer_ui;
pub mod events;
pub mod handlers;
pub mod invitation_ui;
pub mod moderation;
pub mod oidc;
pub mod oidc_auth;
pub mod oidc_token;
pub mod openai;
pub mod pipeline;
pub mod rate_limit;
pub mod redis_limits;
pub mod responses;
pub mod saml_auth;
pub mod scim;
pub mod spend_limit;
pub mod tenant_store;
pub mod usage;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use soup_wall_core::{
    Firewall, InjectionDetector, ModerationDetector, OutputDetector, PiiDetector, PolicySet,
    SecretDetector,
};

pub use config::{Config, FailMode};
pub use handlers::{
    chat_completions, healthz, messages, metrics, readyz, responses, AppState, Shared,
};

/// Build the `Firewall` (detectors + policy) from config.
pub fn build_firewall(cfg: &Config) -> anyhow::Result<Firewall> {
    let policy = match &cfg.policy_file {
        Some(p) => PolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
        None => PolicySet::from_yaml("default: allow")?,
    };
    let mut fw = Firewall::new(
        vec![
            Box::new(InjectionDetector::new()),
            Box::new(SecretDetector::new()),
            Box::new(PiiDetector::new()),
            Box::new(OutputDetector::new()),
            // Inert without the `ml` feature + a fetched model (same as injection ML).
            Box::new(ModerationDetector::new()),
        ],
        policy,
    );
    if let Some(n) = cfg.normalize.to_normalizer() {
        fw = fw.with_normalizer(n);
    }
    Ok(fw)
}

/// The axum router.
pub fn app(state: Shared) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    let probes = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/readyz", get(readyz));
    let api = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_proxy_token,
        ));
    let oidc_login_enabled = state.tenant_store.is_some() && state.oidc_state_cipher.is_some();
    let saml_login_enabled =
        state.tenant_store.is_some() && state.oidc_state_cipher.is_some() && state.saml.is_some();
    let router = if state.tenant_store.is_some() {
        // The static console itself contains no data or credentials, so it can
        // be loaded by a browser before that browser can attach the custom
        // admin header. Every data-changing request remains on the separately
        // authenticated /admin/v1 API below.
        let dashboard = Router::new().route("/admin", get(admin_ui::dashboard));
        let scim_api = Router::new()
            .route(
                "/scim/v2/ServiceProviderConfig",
                get(scim::service_provider_config),
            )
            .route(
                "/scim/v2/Users",
                get(scim::list_users).post(scim::create_user),
            )
            .route(
                "/scim/v2/Users/:user_id",
                get(scim::get_user)
                    .patch(scim::patch_user)
                    .delete(scim::delete_user),
            )
            .route(
                "/scim/v2/Groups",
                get(scim::list_groups).post(scim::create_group),
            )
            .route(
                "/scim/v2/Groups/:group_id",
                get(scim::get_group)
                    .patch(scim::patch_group)
                    .delete(scim::delete_group),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                scim::require_scim_token,
            ));
        let admin = Router::new()
            .route("/admin/v1/whoami", get(admin::whoami))
            .route(
                "/admin/v1/organizations",
                post(admin::create_organization).get(admin::list_organizations),
            )
            .route(
                "/admin/v1/organizations/:organization_id",
                axum::routing::patch(admin::set_organization_state),
            )
            .route(
                "/admin/v1/organizations/:organization_id/tenants",
                post(admin::create_organization_tenant),
            )
            .route(
                "/admin/v1/organizations/:organization_id/workspaces",
                get(admin::list_organization_workspaces),
            )
            .route(
                "/admin/v1/organizations/:organization_id/onboarding",
                get(admin::get_organization_onboarding),
            )
            .route(
                "/admin/v1/organizations/:organization_id/scim-tokens",
                post(admin::issue_scim_token).get(admin::list_scim_tokens),
            )
            .route(
                "/admin/v1/organizations/:organization_id/oidc",
                axum::routing::get(admin::get_organization_oidc_connection)
                    .put(admin::set_organization_oidc_connection)
                    .delete(admin::delete_organization_oidc_connection),
            )
            .route(
                "/admin/v1/organizations/:organization_id/saml",
                axum::routing::get(admin::get_organization_saml_connection)
                    .put(admin::set_organization_saml_connection)
                    .delete(admin::delete_organization_saml_connection),
            )
            .route(
                "/admin/v1/tenants",
                post(admin::create_tenant).get(admin::list_tenants),
            )
            .route(
                "/admin/v1/tenants/:tenant_id",
                axum::routing::patch(admin::set_tenant_state).delete(admin::delete_tenant),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/tokens",
                post(admin::issue_token).get(admin::list_tokens),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/limits",
                axum::routing::get(admin::get_limits).put(admin::set_limits),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/model-policy",
                axum::routing::get(admin::get_model_policy).put(admin::set_model_policy),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions",
                get(admin::list_policy_versions).post(admin::create_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id",
                get(admin::get_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id/export",
                get(admin::export_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id/simulate",
                post(admin::simulate_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id/approve",
                post(admin::approve_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id/activate",
                post(admin::activate_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-versions/:version_id/rollback",
                post(admin::rollback_policy_version),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/policy-deployments",
                get(admin::list_policy_deployments),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/security-events",
                get(admin::list_security_events),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/webhook-destinations",
                get(admin::list_webhook_destinations).post(admin::create_webhook_destination),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/webhook-destinations/:destination_id/deactivate",
                post(admin::deactivate_webhook_destination),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/webhook-deliveries",
                get(admin::list_webhook_deliveries),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/audit",
                axum::routing::get(admin::list_audit),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/usage/reconciliation",
                get(admin::list_usage_reconciliation_runs).post(admin::import_usage_reconciliation),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/usage/reconciliation/:run_id",
                get(admin::list_usage_reconciliation_observations),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/usage/retention/policy",
                get(admin::get_usage_retention_policy).put(admin::set_usage_retention_policy),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/usage/retention/runs",
                get(admin::list_usage_retention_runs).post(admin::run_usage_retention),
            )
            .route(
                "/admin/v1/tenants/:tenant_id/usage/quota",
                get(admin::get_usage_quota_status).put(admin::set_usage_quota_policy),
            )
            .route(
                "/admin/v1/tokens/:token_id/revoke",
                post(admin::revoke_token),
            )
            .route(
                "/admin/v1/scim-tokens/:token_id/revoke",
                post(admin::revoke_scim_token),
            )
            .route(
                "/admin/v1/admins",
                post(admin::create_admin).get(admin::list_admins),
            )
            .route(
                "/admin/v1/admins/:admin_id/revoke",
                post(admin::revoke_admin),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                admin::require_admin_token,
            ));
        probes
            .merge(api)
            .merge(admin)
            .merge(dashboard)
            .merge(scim_api)
    } else {
        probes.merge(api)
    };
    let router = if oidc_login_enabled {
        router
            .route("/auth/oidc/start", get(oidc_auth::start_login))
            .route(
                "/auth/oidc/invitation/start",
                post(oidc_auth::start_invitation_login),
            )
            .route("/auth/oidc/callback", get(oidc_auth::callback))
            .route("/auth/logout", post(oidc_auth::logout))
            .route("/auth/session/rotate", post(oidc_auth::rotate_session))
            .route("/auth/session/refresh", post(oidc_auth::rotate_session))
            .route("/customer", get(customer_ui::dashboard))
            .route("/customer/invitation", get(invitation_ui::accept))
            .route("/customer/v1/session", get(oidc_auth::customer_session))
            .route("/customer/v1/csrf", get(oidc_auth::customer_csrf))
            .route(
                "/customer/v1/service-accounts",
                get(oidc_auth::customer_service_accounts)
                    .post(oidc_auth::create_customer_service_account),
            )
            .route(
                "/customer/v1/service-accounts/:account_id/revoke",
                post(oidc_auth::revoke_customer_service_account),
            )
            .route(
                "/customer/v1/audit",
                get(oidc_auth::customer_workspace_audit),
            )
            .route(
                "/customer/v1/proxy-audit",
                get(oidc_auth::customer_workspace_proxy_audit),
            )
            .route(
                "/customer/v1/usage",
                get(oidc_auth::customer_workspace_usage),
            )
            .route(
                "/customer/v1/billing/invoice-preview",
                get(oidc_auth::customer_workspace_invoice_preview),
            )
            .route(
                "/customer/v1/usage/export.csv",
                get(oidc_auth::export_customer_workspace_usage),
            )
            .route(
                "/customer/v1/usage/reconciliation",
                get(oidc_auth::customer_workspace_usage_reconciliation_runs),
            )
            .route(
                "/customer/v1/usage/reconciliation/:run_id",
                get(oidc_auth::customer_workspace_usage_reconciliation_observations),
            )
            .route(
                "/customer/v1/usage/retention",
                get(oidc_auth::customer_workspace_usage_retention)
                    .put(oidc_auth::set_customer_workspace_usage_retention),
            )
            .route(
                "/customer/v1/usage/quota",
                get(oidc_auth::customer_workspace_usage_quota)
                    .put(oidc_auth::set_customer_workspace_usage_quota),
            )
            .route(
                "/customer/v1/members",
                get(oidc_auth::customer_workspace_members)
                    .post(oidc_auth::assign_customer_workspace_scim_user)
                    .patch(oidc_auth::update_customer_workspace_membership),
            )
            .route(
                "/customer/v1/invitations",
                get(oidc_auth::customer_workspace_invitations)
                    .post(oidc_auth::create_customer_workspace_invitation),
            )
            .route(
                "/customer/v1/invitations/:invitation_id/revoke",
                post(oidc_auth::revoke_customer_workspace_invitation),
            )
            .route(
                "/customer/v1/invitations/:invitation_id/resend",
                post(oidc_auth::resend_customer_workspace_invitation),
            )
            .route(
                "/customer/v1/scim-users",
                get(oidc_auth::customer_workspace_scim_users),
            )
            .route(
                "/customer/v1/scim-groups",
                get(oidc_auth::customer_workspace_scim_groups),
            )
            .route(
                "/customer/v1/group-mappings",
                get(oidc_auth::customer_workspace_scim_group_mappings)
                    .post(oidc_auth::create_customer_workspace_scim_group_mapping),
            )
            .route(
                "/customer/v1/group-mappings/:group_id",
                delete(oidc_auth::delete_customer_workspace_scim_group_mapping),
            )
            .route(
                "/customer/v1/controls",
                get(oidc_auth::customer_workspace_controls),
            )
            .route(
                "/customer/v1/model-policy",
                put(oidc_auth::set_customer_workspace_model_policy),
            )
            .route(
                "/customer/v1/limits",
                put(oidc_auth::set_customer_workspace_limits),
            )
            .route(
                "/customer/v1/webhook-destinations",
                get(oidc_auth::customer_webhook_destinations)
                    .post(oidc_auth::create_customer_webhook_destination),
            )
            .route(
                "/customer/v1/webhook-destinations/:destination_id/deactivate",
                post(oidc_auth::deactivate_customer_webhook_destination),
            )
            .route(
                "/customer/v1/webhook-deliveries",
                get(oidc_auth::customer_webhook_deliveries),
            )
    } else {
        router
    };
    let router = if saml_login_enabled {
        router
            .route("/auth/saml/start", get(saml_auth::start_login))
            .route(
                "/auth/saml/invitation/start",
                post(saml_auth::start_invitation_login),
            )
            .route("/auth/saml/acs", post(saml_auth::acs))
    } else {
        router
    };
    router
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

/// Test helper: a `Config` pointing upstream at `base`, fail_closed, no policy file.
pub fn test_config(base: String) -> Config {
    Config {
        bind: "127.0.0.1:0".into(),
        upstream: config::Upstream {
            openai_base: base.clone(),
            anthropic_base: base,
        },
        policy_file: None,
        fail_mode: FailMode::FailClosed,
        stream_window: 64,
        max_body_bytes: 4 * 1024 * 1024,
        max_upstream_body_bytes: 8 * 1024 * 1024,
        upstream_timeout_ms: 120_000,
        stream_idle_timeout_ms: 30_000,
        stream_buffer_chunks: 8,
        max_stream_chunk_bytes: 1024 * 1024,
        normalize: config::NormalizeCfg::default(),
        agent_inspection: config::AgentInspection::default(),
        proxy_auth: config::ProxyAuth::default(),
        rate_limit: config::RateLimit::default(),
        spend_limit: config::SpendLimit::default(),
        tenant_store: config::TenantStoreConfig::default(),
        redis_limits: config::RedisLimitsConfig::default(),
        capability_policy: capability::CapabilityPolicy::default(),
        output_moderation: config::OutputModeration::default(),
    }
}
