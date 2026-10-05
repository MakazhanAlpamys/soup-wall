// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL implementation of the tenant control plane.
//!
//! The production constructor requires `sslmode=require`. It keeps only a
//! client handle in memory: tenants, hashed tokens, policies, and audit events
//! live in PostgreSQL and are therefore shared by every proxy instance.

use std::future::Future;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use tokio::time::timeout;
use tokio_postgres::config::SslMode;
use tokio_postgres::Row;
use tokio_postgres_rustls::MakeRustlsConnect;

use super::{
    canonical_policy_document, canonical_security_event_payload, evaluate_policy_simulation,
    evaluate_usage_reconciliation, generate_admin_token, generate_oidc_browser_session_token,
    generate_scim_token, generate_token, now_unix, oidc_browser_session_hash, random_id,
    scim_token_hash, token_hash, usage_retention_cutoff, validate_label, validate_limits,
    validate_oidc_browser_session_expiry, validate_policy_document, validate_scim_token_expiry,
    validate_usage_event, validate_usage_quota_policy, validate_usage_range,
    validate_usage_reconciliation_import, validate_usage_retention_policy, validate_usage_text,
    AdminIdentity, AdminRole, BrowserSessionFederation, ControlPlaneAdmin, DailyUsageAggregate,
    IssuedAdminToken, IssuedOidcBrowserSession, IssuedScimToken, IssuedToken,
    IssuedWorkspaceInvitation, IssuedWorkspaceServiceAccount, ModelUsageAggregate, NewUsageEvent,
    NewUsageReconciliationImport, OidcBrowserSession, Organization, OrganizationOidcConnection,
    OrganizationSamlConnection, PendingWebhookDelivery, PolicyDeploymentAction,
    PolicySimulationCase, SamlAuthorizationPending, ScimGroup, ScimGroupMemberChange,
    ScimGroupPage, ScimGroupUpdate, ScimIdentity, ScimToken, ScimUser, ScimUserPage,
    ScimUserUpdate, Tenant, TenantAccess, TenantAuditEvent, TenantIdentity, TenantLimits,
    TenantModelPolicy, TenantPolicyDeployment, TenantPolicyDocument, TenantPolicySimulation,
    TenantPolicyVersion, TenantRateLimit, TenantSecurityEvent, TenantSpendLimit, TenantToken,
    UsageEvent, UsageEventPage, UsageQuotaPolicy, UsageReconciliationCandidate,
    UsageReconciliationObservation, UsageReconciliationReadiness, UsageReconciliationRun,
    UsageReconciliationStatus, UsageReport, UsageRetentionPolicy, UsageRetentionRun, UsageTotals,
    VerifiedWorkspaceAccess, WebhookAttemptResult, WebhookDelivery, WebhookDeliveryStatus,
    WebhookDestination, Workspace, WorkspaceAdminAuditEvent, WorkspaceExternalIdentity,
    WorkspaceInvitation, WorkspaceMember, WorkspaceMembership, WorkspacePermission,
    WorkspacePrincipal, WorkspaceRole, WorkspaceScimGroup, WorkspaceScimGroupMapping,
    WorkspaceScimUser, WorkspaceServiceAccount, BOOTSTRAP_ORGANIZATION_ID,
};

#[derive(Clone)]
pub(super) struct PostgresTenantStore {
    pool: Pool,
    audit_max_rows: i64,
    command_timeout: Duration,
    pool_wait_timeout: Duration,
}

impl PostgresTenantStore {
    fn tls_config(ca_cert_file: Option<&str>) -> anyhow::Result<rustls::ClientConfig> {
        let mut root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca_cert_file.filter(|path| !path.trim().is_empty()) {
            let path = Path::new(path);
            let certificates = CertificateDer::pem_file_iter(path).with_context(|| {
                format!(
                    "failed to open PostgreSQL CA certificate file {}",
                    path.display()
                )
            })?;
            let mut loaded = 0_usize;
            for certificate in certificates {
                let certificate = certificate.with_context(|| {
                    format!(
                        "failed to parse PostgreSQL CA certificate file {}",
                        path.display()
                    )
                })?;
                root_store.add(certificate).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to add PostgreSQL CA certificate from {}: {error}",
                        path.display()
                    )
                })?;
                loaded += 1;
            }
            if loaded == 0 {
                bail!(
                    "PostgreSQL CA certificate file {} contains no CERTIFICATE blocks",
                    path.display()
                );
            }
        }
        Ok(rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }

    pub(super) async fn open(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        require_tls: bool,
        ca_cert_file: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut config = tokio_postgres::Config::from_str(connection_url)
            .map_err(|_| anyhow::anyhow!("invalid PostgreSQL tenant-store URL"))?;
        if require_tls && !matches!(config.get_ssl_mode(), SslMode::Require) {
            bail!("PostgreSQL tenant-store URL must set sslmode=require");
        }
        config.application_name("llm-firewall-control-plane");
        config.connect_timeout(command_timeout);

        let tls_config = Self::tls_config(ca_cert_file)?;
        let tls = MakeRustlsConnect::new(tls_config);
        let manager = Manager::from_config(
            config,
            tls,
            ManagerConfig {
                // Verify an idle connection before reusing it. Dead connections
                // are discarded and the pool establishes a replacement.
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_max_size.max(1))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| anyhow::anyhow!("failed to build PostgreSQL tenant-store pool"))?;

        let store = Self {
            pool,
            audit_max_rows: i64::try_from(audit_max_rows.max(1))
                .context("tenant audit row cap exceeds PostgreSQL integer range")?,
            command_timeout,
            pool_wait_timeout,
        };
        store.health_check().await?;
        store.ensure_schema_current().await?;
        Ok(store)
    }

    pub(super) async fn migrate(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        require_tls: bool,
        ca_cert_file: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut config = tokio_postgres::Config::from_str(connection_url)
            .map_err(|_| anyhow::anyhow!("invalid PostgreSQL tenant-store URL"))?;
        if require_tls && !matches!(config.get_ssl_mode(), SslMode::Require) {
            bail!("PostgreSQL tenant-store URL must set sslmode=require");
        }
        config.application_name("llm-firewall-control-plane-migrate");
        config.connect_timeout(command_timeout);
        let tls_config = Self::tls_config(ca_cert_file)?;
        let manager = Manager::from_config(
            config,
            MakeRustlsConnect::new(tls_config),
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let store = Self {
            pool: Pool::builder(manager)
                .max_size(pool_max_size.max(1))
                .runtime(Runtime::Tokio1)
                .build()
                .map_err(|_| anyhow::anyhow!("failed to build PostgreSQL migration pool"))?,
            audit_max_rows: i64::try_from(audit_max_rows.max(1))
                .context("tenant audit row cap exceeds PostgreSQL integer range")?,
            command_timeout,
            pool_wait_timeout,
        };
        store.run_migrations().await
    }

    async fn run_migrations(&self) -> anyhow::Result<()> {
        const BASE_VERSION: i64 = 1;
        const ADMIN_ROLES_VERSION: i64 = 2;
        const WORKSPACE_RBAC_VERSION: i64 = 3;
        const EXTERNAL_IDENTITY_VERSION: i64 = 4;
        const ORGANIZATION_OIDC_VERSION: i64 = 5;
        const OIDC_AUTHORIZATION_STATE_VERSION: i64 = 6;
        const OIDC_BROWSER_SESSION_VERSION: i64 = 7;
        const SCIM_TOKENS_VERSION: i64 = 8;
        const SCIM_USERS_VERSION: i64 = 9;
        const SCIM_GROUPS_VERSION: i64 = 10;
        const SCIM_GROUP_MAPPINGS_VERSION: i64 = 11;
        const USAGE_EVENTS_VERSION: i64 = 12;
        const USAGE_REPORTING_VERSION: i64 = 13;
        const USAGE_RECONCILIATION_VERSION: i64 = 14;
        const USAGE_RETENTION_VERSION: i64 = 15;
        const USAGE_QUOTAS_VERSION: i64 = 16;
        const POLICY_DELIVERY_VERSION: i64 = 17;
        const SECURITY_EVENTS_VERSION: i64 = 18;
        const WEBHOOKS_VERSION: i64 = 19;
        const SERVICE_ACCOUNTS_VERSION: i64 = 20;
        const ORGANIZATION_SAML_VERSION: i64 = 21;
        const SAML_AUTHORIZATION_STATE_VERSION: i64 = 22;
        const BROWSER_SESSION_FEDERATION_VERSION: i64 = 23;
        const WORKSPACE_INVITATIONS_VERSION: i64 = 24;
        const SAML_INVITATION_STATE_VERSION: i64 = 25;
        let client = self.checkout().await?;
        self.bounded(client.batch_execute(
            "
            CREATE TABLE IF NOT EXISTS llm_firewall_schema_migrations (
                version BIGINT PRIMARY KEY NOT NULL,
                applied_at_unix BIGINT NOT NULL
            );
            ",
        ))
        .await
        .context("failed to initialise PostgreSQL migration metadata")?;
        let already_applied = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&BASE_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL migration metadata")?
            .is_some();
        if !already_applied {
            self.bounded(client.batch_execute(
            "
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL UNIQUE,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at_unix BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenant_tokens (
                id TEXT PRIMARY KEY NOT NULL,
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                token_hash BYTEA NOT NULL UNIQUE,
                label TEXT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at_unix BIGINT NOT NULL,
                revoked_at_unix BIGINT
            );

            CREATE INDEX IF NOT EXISTS tenant_tokens_active_hash
                ON tenant_tokens(token_hash) WHERE active = TRUE;

            CREATE TABLE IF NOT EXISTS tenant_limits (
                tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                rate_limit_requests_per_window BIGINT,
                rate_limit_window_seconds BIGINT,
                spend_limit_window_seconds BIGINT,
                spend_limit_max_usd_micros BIGINT,
                spend_limit_reserve_usd_micros_per_request BIGINT,
                updated_at_unix BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenant_model_policies (
                tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                allowed_models_json TEXT NOT NULL,
                updated_at_unix BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenant_audit (
                id BIGSERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                created_at_unix BIGINT NOT NULL,
                path TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                latency_ms BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS tenant_audit_tenant_created
                ON tenant_audit(tenant_id, id DESC);

            CREATE OR REPLACE FUNCTION llm_firewall_append_tenant_audit(
                p_tenant_id TEXT,
                p_created_at_unix BIGINT,
                p_path TEXT,
                p_outcome TEXT,
                p_status_code INTEGER,
                p_latency_ms BIGINT,
                p_audit_max_rows BIGINT
            ) RETURNS VOID
            LANGUAGE plpgsql
            AS $$
            BEGIN
                INSERT INTO tenant_audit
                    (tenant_id, created_at_unix, path, outcome, status_code, latency_ms)
                VALUES
                    (p_tenant_id, p_created_at_unix, p_path, p_outcome, p_status_code, p_latency_ms);
                -- Only one concurrent writer prunes at a time. Other writes
                -- never wait for a table-wide lock; retention converges after
                -- in-flight events finish.
                IF pg_try_advisory_xact_lock(841_337_611) THEN
                    DELETE FROM tenant_audit
                    WHERE id IN (
                        SELECT id FROM tenant_audit
                        ORDER BY id DESC
                        OFFSET p_audit_max_rows
                    );
                END IF;
            END;
            $$;
            ",
            ))
            .await
            .context("failed to migrate PostgreSQL tenant store")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
             VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&BASE_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL migration")?;
        }

        let admins_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&ADMIN_ROLES_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL migration metadata")?
            .is_some();
        if !admins_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS control_plane_admins (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    token_hash BYTEA NOT NULL UNIQUE,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'operator', 'viewer')),
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    revoked_at_unix BIGINT
                );

                CREATE INDEX IF NOT EXISTS control_plane_admins_active_hash
                    ON control_plane_admins(token_hash) WHERE active = TRUE;
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL admin roles")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&ADMIN_ROLES_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL admin-role migration")?;
        }

        let workspace_rbac_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&WORKSPACE_RBAC_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL workspace-RBAC migration metadata")?
            .is_some();
        if !workspace_rbac_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(organization_id, name)
                );

                CREATE INDEX IF NOT EXISTS workspaces_organization_created
                    ON workspaces(organization_id, created_at_unix, id);

                CREATE TABLE IF NOT EXISTS workspace_principals (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workspace_memberships (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'analyst', 'developer')),
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(workspace_id, principal_id)
                );

                CREATE INDEX IF NOT EXISTS workspace_memberships_principal_active
                    ON workspace_memberships(principal_id, workspace_id) WHERE active = TRUE;

                CREATE TABLE IF NOT EXISTS workspace_admin_audit (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS workspace_admin_audit_workspace_created
                    ON workspace_admin_audit(workspace_id, id DESC);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL workspace RBAC")?;
            let bootstrap_created_at = now_unix();
            self.bounded(client.execute(
                "INSERT INTO organizations (id, name, active, created_at_unix)
                 VALUES ($1, $2, TRUE, $3) ON CONFLICT (id) DO NOTHING",
                &[
                    &BOOTSTRAP_ORGANIZATION_ID,
                    &"Bootstrap organization",
                    &bootstrap_created_at,
                ],
            ))
            .await
            .context("failed to create PostgreSQL bootstrap organization")?;
            self.bounded(client.execute(
                "INSERT INTO workspaces
                    (id, organization_id, tenant_id, name, active, created_at_unix)
                 SELECT 'workspace_' || id, $1, id, name, active, created_at_unix
                 FROM tenants
                 ON CONFLICT (tenant_id) DO NOTHING",
                &[&BOOTSTRAP_ORGANIZATION_ID],
            ))
            .await
            .context("failed to backfill PostgreSQL tenant workspaces")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&WORKSPACE_RBAC_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL workspace-RBAC migration")?;
        }

        let external_identities_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&EXTERNAL_IDENTITY_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL external-identity migration metadata")?
            .is_some();
        if !external_identities_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS workspace_external_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    principal_id TEXT NOT NULL REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(issuer, subject),
                    UNIQUE(principal_id, issuer)
                );

                CREATE INDEX IF NOT EXISTS workspace_external_identities_principal
                    ON workspace_external_identities(principal_id);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL external identities")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&EXTERNAL_IDENTITY_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL external-identity migration")?;
        }

        let organization_oidc_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&ORGANIZATION_OIDC_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL OIDC migration metadata")?
            .is_some();
        if !organization_oidc_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS organization_oidc_connections (
                    organization_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    issuer TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL
                );
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL organization OIDC connections")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&ORGANIZATION_OIDC_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL organization OIDC migration")?;
        }

        let oidc_authorization_states_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&OIDC_AUTHORIZATION_STATE_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL OIDC authorization-state migration metadata")?
            .is_some();
        if !oidc_authorization_states_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS oidc_authorization_states (
                    state_hash BYTEA PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    expires_at_unix BIGINT NOT NULL,
                    consumed_at_unix BIGINT,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS oidc_authorization_states_expiry
                    ON oidc_authorization_states(expires_at_unix);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL OIDC authorization states")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&OIDC_AUTHORIZATION_STATE_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL OIDC authorization-state migration")?;
        }

        let oidc_browser_sessions_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&OIDC_BROWSER_SESSION_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL OIDC browser-session migration metadata")?
            .is_some();
        if !oidc_browser_sessions_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS oidc_browser_sessions (
                    session_hash BYTEA PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    expires_at_unix BIGINT NOT NULL,
                    revoked_at_unix BIGINT,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS oidc_browser_sessions_expiry
                    ON oidc_browser_sessions(expires_at_unix);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL OIDC browser sessions")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&OIDC_BROWSER_SESSION_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL OIDC browser-session migration")?;
        }
        let scim_tokens_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SCIM_TOKENS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SCIM-token migration metadata")?
            .is_some();
        if !scim_tokens_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS scim_tokens (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    token_hash BYTEA NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    expires_at_unix BIGINT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    revoked_at_unix BIGINT
                );

                CREATE INDEX IF NOT EXISTS scim_tokens_active_hash
                    ON scim_tokens(token_hash) WHERE active = TRUE;

                CREATE INDEX IF NOT EXISTS scim_tokens_organization_created
                    ON scim_tokens(organization_id, created_at_unix, id);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL SCIM tokens")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SCIM_TOKENS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SCIM-token migration")?;
        }
        let scim_users_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SCIM_USERS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SCIM-user migration metadata")?
            .is_some();
        if !scim_users_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS scim_users (
                    id TEXT PRIMARY KEY NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    external_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    UNIQUE(organization_id, external_id),
                    UNIQUE(organization_id, user_name)
                );

                CREATE INDEX IF NOT EXISTS scim_users_organization_active
                    ON scim_users(organization_id, active, id);

                CREATE TABLE IF NOT EXISTS scim_audit (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    scim_token_id TEXT REFERENCES scim_tokens(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS scim_audit_organization_created
                    ON scim_audit(organization_id, id DESC);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL SCIM users")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SCIM_USERS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SCIM-user migration")?;
        }
        let scim_groups_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SCIM_GROUPS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SCIM-group migration metadata")?
            .is_some();
        if !scim_groups_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS scim_groups (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    external_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    UNIQUE(organization_id, external_id)
                );

                CREATE INDEX IF NOT EXISTS scim_groups_organization_active
                    ON scim_groups(organization_id, active, id);

                CREATE TABLE IF NOT EXISTS scim_group_members (
                    group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(group_id, principal_id)
                );

                CREATE INDEX IF NOT EXISTS scim_group_members_principal
                    ON scim_group_members(principal_id, group_id);

                CREATE TABLE IF NOT EXISTS scim_group_audit (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    scim_token_id TEXT REFERENCES scim_tokens(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_group_id TEXT NOT NULL,
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS scim_group_audit_organization_created
                    ON scim_group_audit(organization_id, id DESC);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL SCIM groups")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SCIM_GROUPS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SCIM-group migration")?;
        }
        let scim_group_mappings_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SCIM_GROUP_MAPPINGS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SCIM-group-mapping migration metadata")?
            .is_some();
        if !scim_group_mappings_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS workspace_scim_group_mappings (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    PRIMARY KEY(workspace_id, group_id)
                );

                CREATE INDEX IF NOT EXISTS workspace_scim_group_mappings_group
                    ON workspace_scim_group_mappings(group_id, workspace_id);

                CREATE TABLE IF NOT EXISTS workspace_scim_group_mapping_audit (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    group_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('group_mapping.create', 'group_mapping.delete')),
                    created_at_unix BIGINT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS workspace_scim_group_mapping_audit_workspace_created
                    ON workspace_scim_group_mapping_audit(workspace_id, id DESC);
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL SCIM group mappings")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SCIM_GROUP_MAPPINGS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SCIM-group-mapping migration")?;
        }
        let usage_events_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&USAGE_EVENTS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL usage-event migration metadata")?
            .is_some();
        if !usage_events_migrated {
            self.bounded(client.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS usage_events (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_id TEXT NOT NULL,
                    provider_response_id TEXT,
                    provider TEXT NOT NULL CHECK(provider IN ('openai', 'anthropic')),
                    path TEXT NOT NULL,
                    requested_model TEXT NOT NULL,
                    provider_model TEXT,
                    input_tokens BIGINT,
                    output_tokens BIGINT,
                    token_status TEXT NOT NULL CHECK(token_status IN ('actual', 'missing')),
                    pricing_status TEXT NOT NULL CHECK(pricing_status IN ('priced', 'unpriced')),
                    model_price_version TEXT,
                    input_usd_micros_per_million BIGINT,
                    output_usd_micros_per_million BIGINT,
                    cost_usd_micros BIGINT,
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(tenant_id, request_id),
                    CHECK(input_tokens IS NULL OR input_tokens >= 0),
                    CHECK(output_tokens IS NULL OR output_tokens >= 0),
                    CHECK(input_usd_micros_per_million IS NULL OR input_usd_micros_per_million >= 0),
                    CHECK(output_usd_micros_per_million IS NULL OR output_usd_micros_per_million >= 0),
                    CHECK(cost_usd_micros IS NULL OR cost_usd_micros >= 0),
                    CHECK(
                        (token_status = 'actual' AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL)
                        OR
                        (token_status = 'missing' AND input_tokens IS NULL AND output_tokens IS NULL)
                    ),
                    CHECK(
                        (model_price_version IS NULL
                         AND input_usd_micros_per_million IS NULL
                         AND output_usd_micros_per_million IS NULL)
                        OR
                        (model_price_version IS NOT NULL
                         AND input_usd_micros_per_million IS NOT NULL
                         AND output_usd_micros_per_million IS NOT NULL)
                    ),
                    CHECK(
                        (pricing_status = 'priced' AND token_status = 'actual'
                         AND model_price_version IS NOT NULL AND cost_usd_micros IS NOT NULL)
                        OR
                        (pricing_status = 'unpriced' AND cost_usd_micros IS NULL)
                    )
                );

                CREATE INDEX IF NOT EXISTS usage_events_tenant_created
                    ON usage_events(tenant_id, created_at_unix DESC, id DESC);

                CREATE INDEX IF NOT EXISTS usage_events_provider_response
                    ON usage_events(provider, provider_response_id)
                    WHERE provider_response_id IS NOT NULL;
                ",
            ))
            .await
            .context("failed to migrate PostgreSQL usage events")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&USAGE_EVENTS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL usage-event migration")?;
        }
        let usage_reporting_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&USAGE_REPORTING_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL usage-reporting migration metadata")?
            .is_some();
        if !usage_reporting_migrated {
            self.bounded(client.batch_execute(
                "CREATE INDEX IF NOT EXISTS usage_events_tenant_provider_response
                    ON usage_events(tenant_id, provider, provider_response_id)
                    WHERE provider_response_id IS NOT NULL;",
            ))
            .await
            .context("failed to migrate PostgreSQL usage-reporting indexes")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&USAGE_REPORTING_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL usage-reporting migration")?;
        }
        let usage_reconciliation_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&USAGE_RECONCILIATION_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL usage-reconciliation migration metadata")?
            .is_some();
        if !usage_reconciliation_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS usage_reconciliation_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    source TEXT NOT NULL,
                    statement_id TEXT NOT NULL,
                    statement_hash BYTEA NOT NULL,
                    actor_admin_id TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK(record_count > 0),
                    matched_count INTEGER NOT NULL CHECK(matched_count >= 0),
                    mismatched_count INTEGER NOT NULL CHECK(mismatched_count >= 0),
                    orphan_count INTEGER NOT NULL CHECK(orphan_count >= 0),
                    ambiguous_count INTEGER NOT NULL CHECK(ambiguous_count >= 0),
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(tenant_id, source, statement_id),
                    CHECK(record_count = matched_count + mismatched_count + orphan_count + ambiguous_count)
                );

                CREATE INDEX IF NOT EXISTS usage_reconciliation_runs_tenant_created
                    ON usage_reconciliation_runs(tenant_id, created_at_unix DESC, id DESC);

                CREATE TABLE IF NOT EXISTS usage_reconciliation_observations (
                    id BIGSERIAL PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES usage_reconciliation_runs(id) ON DELETE RESTRICT,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    source_record_id TEXT NOT NULL,
                    usage_event_id BIGINT REFERENCES usage_events(id) ON DELETE RESTRICT,
                    provider TEXT NOT NULL CHECK(provider IN ('openai', 'anthropic')),
                    provider_response_id TEXT NOT NULL,
                    input_tokens BIGINT,
                    output_tokens BIGINT,
                    cost_usd_micros BIGINT,
                    status TEXT NOT NULL CHECK(status IN ('matched', 'mismatched', 'orphan', 'ambiguous')),
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(run_id, source_record_id),
                    CHECK((input_tokens IS NULL) = (output_tokens IS NULL)),
                    CHECK(input_tokens IS NOT NULL OR cost_usd_micros IS NOT NULL),
                    CHECK(input_tokens IS NULL OR input_tokens >= 0),
                    CHECK(output_tokens IS NULL OR output_tokens >= 0),
                    CHECK(cost_usd_micros IS NULL OR cost_usd_micros >= 0),
                    CHECK(
                        (status IN ('matched', 'mismatched') AND usage_event_id IS NOT NULL)
                        OR
                        (status IN ('orphan', 'ambiguous') AND usage_event_id IS NULL)
                    )
                );

                CREATE INDEX IF NOT EXISTS usage_reconciliation_observations_run
                    ON usage_reconciliation_observations(run_id, id ASC);",
            ))
            .await
            .context("failed to migrate PostgreSQL usage reconciliation")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&USAGE_RECONCILIATION_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL usage-reconciliation migration")?;
        }
        let usage_retention_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&USAGE_RETENTION_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL usage-retention migration metadata")?
            .is_some();
        if !usage_retention_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS usage_retention_policies (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),
                    updated_by TEXT NOT NULL,
                    updated_at_unix BIGINT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS usage_retention_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    actor_admin_id TEXT NOT NULL,
                    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),
                    cutoff_unix BIGINT NOT NULL,
                    executed BOOLEAN NOT NULL,
                    eligible_event_count BIGINT NOT NULL CHECK(eligible_event_count >= 0),
                    protected_reconciliation_event_count BIGINT NOT NULL
                        CHECK(protected_reconciliation_event_count >= 0),
                    eligible_input_tokens BIGINT NOT NULL CHECK(eligible_input_tokens >= 0),
                    eligible_output_tokens BIGINT NOT NULL CHECK(eligible_output_tokens >= 0),
                    eligible_cost_usd_micros BIGINT NOT NULL CHECK(eligible_cost_usd_micros >= 0),
                    deleted_event_count BIGINT NOT NULL CHECK(deleted_event_count >= 0),
                    created_at_unix BIGINT NOT NULL,
                    CHECK((executed = FALSE AND deleted_event_count = 0)
                          OR (executed = TRUE AND deleted_event_count = eligible_event_count))
                );

                CREATE INDEX IF NOT EXISTS usage_retention_runs_tenant_created
                    ON usage_retention_runs(tenant_id, created_at_unix DESC, id DESC);",
            ))
            .await
            .context("failed to migrate PostgreSQL usage retention")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&USAGE_RETENTION_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL usage-retention migration")?;
        }
        let usage_quotas_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&USAGE_QUOTAS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL usage-quota migration metadata")?
            .is_some();
        if !usage_quotas_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS usage_quota_policies (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_limit BIGINT CHECK(request_limit IS NULL OR request_limit > 0),
                    token_limit BIGINT CHECK(token_limit IS NULL OR token_limit > 0),
                    cost_usd_micros_limit BIGINT
                        CHECK(cost_usd_micros_limit IS NULL OR cost_usd_micros_limit > 0),
                    alert_threshold_basis_points INTEGER NOT NULL
                        CHECK(alert_threshold_basis_points BETWEEN 1 AND 10000),
                    updated_by TEXT NOT NULL,
                    updated_at_unix BIGINT NOT NULL,
                    CHECK(request_limit IS NOT NULL OR token_limit IS NOT NULL
                          OR cost_usd_micros_limit IS NOT NULL)
                );",
            ))
            .await
            .context("failed to migrate PostgreSQL usage quotas")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&USAGE_QUOTAS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL usage-quota migration")?;
        }
        let policy_delivery_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&POLICY_DELIVERY_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL policy-delivery migration metadata")?
            .is_some();
        if !policy_delivery_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS tenant_policy_versions (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence BIGINT NOT NULL CHECK(sequence > 0),
                    document_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
                    created_by TEXT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(tenant_id, sequence)
                 );
                 CREATE INDEX IF NOT EXISTS tenant_policy_versions_tenant_sequence
                    ON tenant_policy_versions(tenant_id, sequence DESC);
                 CREATE TABLE IF NOT EXISTS tenant_policy_approvals (
                    version_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    approved_by TEXT NOT NULL,
                    approved_at_unix BIGINT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS tenant_policy_state (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    active_version_id TEXT NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    updated_at_unix BIGINT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS tenant_policy_deployments (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence BIGINT NOT NULL CHECK(sequence > 0),
                    version_id TEXT NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    previous_version_id TEXT
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    action TEXT NOT NULL CHECK(action IN ('activate', 'rollback')),
                    actor_id TEXT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(tenant_id, sequence)
                 );
                 CREATE INDEX IF NOT EXISTS tenant_policy_deployments_tenant_sequence
                    ON tenant_policy_deployments(tenant_id, sequence DESC);
                 CREATE OR REPLACE FUNCTION llm_firewall_reject_immutable_policy_change()
                 RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN
                    RAISE EXCEPTION 'tenant policy history is immutable';
                 END;
                 $$;
                 DO $$ BEGIN
                    CREATE TRIGGER tenant_policy_versions_immutable
                    BEFORE UPDATE OR DELETE ON tenant_policy_versions
                    FOR EACH ROW EXECUTE FUNCTION llm_firewall_reject_immutable_policy_change();
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$;
                 DO $$ BEGIN
                    CREATE TRIGGER tenant_policy_approvals_immutable
                    BEFORE UPDATE OR DELETE ON tenant_policy_approvals
                    FOR EACH ROW EXECUTE FUNCTION llm_firewall_reject_immutable_policy_change();
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$;
                 DO $$ BEGIN
                    CREATE TRIGGER tenant_policy_deployments_immutable
                    BEFORE UPDATE OR DELETE ON tenant_policy_deployments
                    FOR EACH ROW EXECUTE FUNCTION llm_firewall_reject_immutable_policy_change();
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
            ))
            .await
            .context("failed to migrate PostgreSQL policy delivery")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&POLICY_DELIVERY_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL policy-delivery migration")?;
        }
        let security_events_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SECURITY_EVENTS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL security-events migration metadata")?
            .is_some();
        if !security_events_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS tenant_security_events (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence BIGINT NOT NULL CHECK(sequence > 0),
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
                    occurred_at_unix BIGINT NOT NULL,
                    UNIQUE(tenant_id, sequence)
                 );
                 CREATE INDEX IF NOT EXISTS tenant_security_events_tenant_sequence
                    ON tenant_security_events(tenant_id, sequence);
                 CREATE OR REPLACE FUNCTION llm_firewall_reject_security_event_change()
                 RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN
                    RAISE EXCEPTION 'tenant security events are immutable';
                 END;
                 $$;
                 DO $$ BEGIN
                    CREATE TRIGGER tenant_security_events_immutable
                    BEFORE UPDATE OR DELETE ON tenant_security_events
                    FOR EACH ROW EXECUTE FUNCTION llm_firewall_reject_security_event_change();
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
            ))
            .await
            .context("failed to migrate PostgreSQL security events")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SECURITY_EVENTS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL security-events migration")?;
        }
        let webhooks_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&WEBHOOKS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL webhook migration metadata")?
            .is_some();
        if !webhooks_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS tenant_webhook_destinations (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    url TEXT NOT NULL,
                    event_types_json TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS tenant_webhook_destinations_tenant_active
                    ON tenant_webhook_destinations(tenant_id, active, id);
                 CREATE TABLE IF NOT EXISTS tenant_webhook_deliveries (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    event_id TEXT NOT NULL REFERENCES tenant_security_events(id) ON DELETE RESTRICT,
                    destination_id TEXT NOT NULL REFERENCES tenant_webhook_destinations(id) ON DELETE RESTRICT,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'in_flight', 'delivered', 'dead')),
                    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    next_attempt_at_unix BIGINT NOT NULL,
                    locked_until_unix BIGINT,
                    delivered_at_unix BIGINT,
                    last_http_status INTEGER,
                    last_error TEXT,
                    created_at_unix BIGINT NOT NULL,
                    UNIQUE(event_id, destination_id)
                 );
                 CREATE INDEX IF NOT EXISTS tenant_webhook_deliveries_due
                    ON tenant_webhook_deliveries(tenant_id, status, next_attempt_at_unix);",
            ))
            .await
            .context("failed to migrate PostgreSQL webhook delivery")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&WEBHOOKS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL webhook migration")?;
        }
        let service_accounts_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SERVICE_ACCOUNTS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL service-account migration metadata")?
            .is_some();
        if !service_accounts_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS workspace_service_accounts (
                    id TEXT PRIMARY KEY NOT NULL,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    created_by_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE RESTRICT,
                    token_hash BYTEA NOT NULL UNIQUE,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    expires_at_unix BIGINT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    revoked_at_unix BIGINT
                 );
                 CREATE INDEX IF NOT EXISTS workspace_service_accounts_active_hash
                    ON workspace_service_accounts(token_hash) WHERE active = TRUE;
                 CREATE INDEX IF NOT EXISTS workspace_service_accounts_workspace_created
                    ON workspace_service_accounts(workspace_id, created_at_unix, id);",
            ))
            .await
            .context("failed to migrate PostgreSQL workspace service accounts")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SERVICE_ACCOUNTS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL service-account migration")?;
        }
        let organization_saml_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&ORGANIZATION_SAML_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SAML migration metadata")?
            .is_some();
        if !organization_saml_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS organization_saml_connections (
                    organization_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    entity_id TEXT NOT NULL,
                    metadata_xml TEXT NOT NULL,
                    metadata_signing_cert_pem TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at_unix BIGINT NOT NULL,
                    updated_at_unix BIGINT NOT NULL
                );",
            ))
            .await
            .context("failed to migrate PostgreSQL organization SAML connections")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&ORGANIZATION_SAML_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SAML migration")?;
        }
        let saml_authorization_states_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SAML_AUTHORIZATION_STATE_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SAML authorization-state migration metadata")?
            .is_some();
        if !saml_authorization_states_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS saml_authorization_states (
                    state_hash BYTEA PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL
                        REFERENCES workspaces(id) ON DELETE CASCADE,
                    request_id TEXT NOT NULL,
                    idp_entity_id TEXT NOT NULL,
                    expected_binding TEXT NOT NULL,
                    request_binding TEXT NOT NULL,
                    acs_url TEXT NOT NULL,
                    acs_binding TEXT NOT NULL,
                    expires_at_unix BIGINT NOT NULL,
                    consumed_at_unix BIGINT,
                    created_at_unix BIGINT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS saml_authorization_states_expiry
                    ON saml_authorization_states(expires_at_unix);",
            ))
            .await
            .context("failed to migrate PostgreSQL SAML authorization states")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SAML_AUTHORIZATION_STATE_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SAML authorization-state migration")?;
        }
        let browser_session_federation_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&BROWSER_SESSION_FEDERATION_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL browser-session federation migration metadata")?
            .is_some();
        if !browser_session_federation_migrated {
            self.bounded(client.batch_execute(
                "ALTER TABLE oidc_browser_sessions
                 ADD COLUMN IF NOT EXISTS federation_kind TEXT NOT NULL DEFAULT 'oidc'
                 CHECK(federation_kind IN ('oidc', 'saml'));",
            ))
            .await
            .context("failed to migrate PostgreSQL browser-session federation kind")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&BROWSER_SESSION_FEDERATION_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL browser-session federation migration")?;
        }
        let workspace_invitations_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&WORKSPACE_INVITATIONS_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL workspace-invitation migration metadata")?
            .is_some();
        if !workspace_invitations_migrated {
            self.bounded(client.batch_execute(
                "CREATE TABLE IF NOT EXISTS workspace_invitations (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    token_hash BYTEA NOT NULL UNIQUE,
                    recipient_label TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'analyst', 'developer')),
                    created_by_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE RESTRICT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    expires_at_unix BIGINT NOT NULL,
                    created_at_unix BIGINT NOT NULL,
                    revoked_at_unix BIGINT,
                    accepted_by_principal_id TEXT
                        REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    accepted_at_unix BIGINT,
                    CHECK((accepted_at_unix IS NULL AND accepted_by_principal_id IS NULL)
                          OR (accepted_at_unix IS NOT NULL
                              AND accepted_by_principal_id IS NOT NULL))
                 );
                 CREATE INDEX IF NOT EXISTS workspace_invitations_active_hash
                    ON workspace_invitations(token_hash) WHERE active = TRUE;
                 CREATE INDEX IF NOT EXISTS workspace_invitations_workspace_created
                    ON workspace_invitations(workspace_id, created_at_unix DESC, id DESC);",
            ))
            .await
            .context("failed to migrate PostgreSQL workspace invitations")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&WORKSPACE_INVITATIONS_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL workspace-invitation migration")?;
        }
        let saml_invitation_state_migrated = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&SAML_INVITATION_STATE_VERSION],
            ))
            .await
            .context("failed to read PostgreSQL SAML invitation-state migration metadata")?
            .is_some();
        if !saml_invitation_state_migrated {
            self.bounded(client.batch_execute(
                "ALTER TABLE saml_authorization_states
                 ADD COLUMN IF NOT EXISTS invitation_id TEXT
                 REFERENCES workspace_invitations(id) ON DELETE CASCADE;",
            ))
            .await
            .context("failed to migrate PostgreSQL SAML invitation state")?;
            self.bounded(client.execute(
                "INSERT INTO llm_firewall_schema_migrations (version, applied_at_unix)
                 VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                &[&SAML_INVITATION_STATE_VERSION, &now_unix()],
            ))
            .await
            .context("failed to record PostgreSQL SAML invitation-state migration")?;
        }
        Ok(())
    }

    async fn ensure_schema_current(&self) -> anyhow::Result<()> {
        const VERSION: i64 = 25;
        let client = self.checkout().await?;
        let applied = self
            .bounded(client.query_opt(
                "SELECT version FROM llm_firewall_schema_migrations WHERE version = $1",
                &[&VERSION],
            ))
            .await;
        if applied.ok().flatten().is_none() {
            bail!(
                "PostgreSQL control-plane schema is absent or outdated; run `llm-firewall migrate` with the migration database role"
            );
        }
        Ok(())
    }

    pub(super) async fn health_check(&self) -> anyhow::Result<()> {
        let client = self.checkout().await?;
        self.bounded(client.simple_query("SELECT 1"))
            .await
            .context("PostgreSQL tenant-store health check failed")?;
        Ok(())
    }

    pub(super) async fn create_tenant(&self, name: &str) -> anyhow::Result<Tenant> {
        self.create_tenant_in_organization(BOOTSTRAP_ORGANIZATION_ID, name)
            .await
    }

    pub(super) async fn create_tenant_in_organization(
        &self,
        organization_id: &str,
        name: &str,
    ) -> anyhow::Result<Tenant> {
        let tenant = Tenant {
            id: random_id("tenant"),
            name: validate_label(name, "tenant name", 128)?,
            active: true,
            created_at_unix: now_unix(),
        };
        let workspace_id = format!("workspace_{}", tenant.id);
        let client = self.checkout().await?;
        let created = self
            .bounded(client.execute(
                "WITH active_organization AS (
                    SELECT id FROM organizations WHERE id = $1 AND active = TRUE
                 ), inserted_tenant AS (
                    INSERT INTO tenants (id, name, active, created_at_unix)
                    SELECT $2, $3, TRUE, $4 FROM active_organization
                    RETURNING id, name, created_at_unix
                 )
                 INSERT INTO workspaces
                    (id, organization_id, tenant_id, name, active, created_at_unix)
                 SELECT $5, $1, id, name, TRUE, created_at_unix FROM inserted_tenant",
                &[
                    &organization_id,
                    &tenant.id,
                    &tenant.name,
                    &tenant.created_at_unix,
                    &workspace_id,
                ],
            ))
            .await
            .context("failed to create tenant workspace")?;
        if created != 1 {
            bail!("organization not found or inactive");
        }
        Ok(tenant)
    }

    pub(super) async fn create_organization(&self, name: &str) -> anyhow::Result<Organization> {
        let organization = Organization {
            id: random_id("org"),
            name: validate_label(name, "organization name", 128)?,
            active: true,
            created_at_unix: now_unix(),
        };
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO organizations (id, name, active, created_at_unix)
             VALUES ($1, $2, TRUE, $3)",
            &[
                &organization.id,
                &organization.name,
                &organization.created_at_unix,
            ],
        ))
        .await
        .context("failed to create organization")?;
        Ok(organization)
    }

    pub(super) async fn list_organizations(&self) -> anyhow::Result<Vec<Organization>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, name, active, created_at_unix
                 FROM organizations ORDER BY created_at_unix ASC, id ASC",
                &[],
            ))
            .await
            .context("failed to query organizations")?;
        rows.into_iter().map(organization_from_row).collect()
    }

    pub(super) async fn issue_scim_token(
        &self,
        organization_id: &str,
        label: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedScimToken> {
        validate_scim_token_expiry(expires_at_unix)?;
        let credential = ScimToken {
            id: random_id("scim"),
            organization_id: organization_id.to_owned(),
            label: validate_label(label, "SCIM token label", 128)?,
            active: true,
            expires_at_unix,
            created_at_unix: now_unix(),
            revoked_at_unix: None,
        };
        let token = generate_scim_token();
        let token_hash = scim_token_hash(&token)?;
        let client = self.checkout().await?;
        let inserted = self
            .bounded(client.execute(
                "INSERT INTO scim_tokens
                    (id, organization_id, token_hash, label, active, expires_at_unix,
                     created_at_unix, revoked_at_unix)
                 SELECT $1, organizations.id, $3, $4, TRUE, $5, $6, NULL
                 FROM organizations
                 WHERE organizations.id = $2 AND organizations.active = TRUE",
                &[
                    &credential.id,
                    &credential.organization_id,
                    &token_hash,
                    &credential.label,
                    &credential.expires_at_unix,
                    &credential.created_at_unix,
                ],
            ))
            .await
            .context("failed to issue SCIM token")?;
        if inserted != 1 {
            bail!("organization not found or inactive");
        }
        Ok(IssuedScimToken { credential, token })
    }

    pub(super) async fn list_scim_tokens(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Vec<ScimToken>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, organization_id, label, active, expires_at_unix, created_at_unix,
                        revoked_at_unix
                 FROM scim_tokens
                 WHERE organization_id = $1
                 ORDER BY created_at_unix DESC, id DESC",
                &[&organization_id],
            ))
            .await
            .context("failed to query SCIM token list")?;
        rows.into_iter().map(scim_token_from_row).collect()
    }

    pub(super) async fn revoke_scim_token(&self, token_id: &str) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE scim_tokens
                 SET active = FALSE, revoked_at_unix = $1
                 WHERE id = $2 AND active = TRUE",
                &[&now_unix(), &token_id],
            ))
            .await
            .context("failed to revoke SCIM token")?;
        Ok(changed == 1)
    }

    pub(super) async fn authenticate_scim_bearer(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<ScimIdentity>> {
        let Some(token) = presented_header.and_then(|value| value.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        let Ok(token_hash) = scim_token_hash(token) else {
            return Ok(None);
        };
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT scim_tokens.organization_id, scim_tokens.id
                 FROM scim_tokens
                 JOIN organizations ON organizations.id = scim_tokens.organization_id
                 WHERE scim_tokens.token_hash = $1
                   AND scim_tokens.active = TRUE
                   AND scim_tokens.expires_at_unix >= $2
                   AND organizations.active = TRUE",
                &[&token_hash, &now],
            ))
            .await
            .context("failed to authenticate SCIM token")?;
        Ok(row.map(|row| ScimIdentity {
            organization_id: row.get(0),
            token_id: row.get(1),
        }))
    }

    pub(super) async fn create_scim_user(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        user_name: &str,
        display_name: &str,
        active: bool,
    ) -> anyhow::Result<ScimUser> {
        let (external_id, user_name, display_name) =
            super::validate_scim_user_fields(external_id, user_name, display_name)?;
        let now = now_unix();
        let user_id = random_id("principal");
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH active_organization AS MATERIALIZED (
                    SELECT id FROM organizations WHERE id = $1 AND active = TRUE
                 ), inserted_principal AS (
                    INSERT INTO workspace_principals (id, name, active, created_at_unix)
                    SELECT $2, $5, TRUE, $6 FROM active_organization
                    RETURNING id
                 ), saved_user AS (
                    INSERT INTO scim_users
                        (id, organization_id, external_id, user_name, display_name, active,
                         created_at_unix, updated_at_unix)
                    SELECT inserted_principal.id, active_organization.id, $3, $4, $5, $7, $6, $6
                    FROM inserted_principal
                    CROSS JOIN active_organization
                    RETURNING id, organization_id, external_id, user_name, display_name, active,
                              created_at_unix, updated_at_unix
                 ), audited AS (
                    INSERT INTO scim_audit
                        (organization_id, scim_token_id, action, target_principal_id, created_at_unix)
                    SELECT organization_id, $8, 'user.create', id, $6 FROM saved_user
                 )
                 SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM saved_user",
                &[
                    &identity.organization_id,
                    &user_id,
                    &external_id,
                    &user_name,
                    &display_name,
                    &now,
                    &active,
                    &identity.token_id,
                ],
            ))
            .await
            .context("failed to create SCIM user")?
            .ok_or_else(|| anyhow::anyhow!("SCIM organization not found or inactive"))?;
        scim_user_from_row(row)
    }

    pub(super) async fn list_scim_users(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimUserPage> {
        super::validate_scim_page(start_index, count)?;
        let offset = i64::try_from(start_index - 1)
            .context("SCIM start index exceeds PostgreSQL integer range")?;
        let limit =
            i64::try_from(count).context("SCIM page size exceeds PostgreSQL integer range")?;
        let client = self.checkout().await?;
        let total_results: i64 = self
            .bounded(client.query_one(
                "SELECT COUNT(*) FROM scim_users WHERE organization_id = $1",
                &[&identity.organization_id],
            ))
            .await
            .context("failed to count SCIM users")?
            .get(0);
        let rows = self
            .bounded(client.query(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = $1
                 ORDER BY id ASC
                 LIMIT $2 OFFSET $3",
                &[&identity.organization_id, &limit, &offset],
            ))
            .await
            .context("failed to query SCIM users")?;
        let resources = rows
            .into_iter()
            .map(scim_user_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(ScimUserPage {
            total_results: u64::try_from(total_results)
                .context("stored SCIM user count cannot be negative")?,
            start_index,
            items_per_page: resources.len(),
            resources,
        })
    }

    pub(super) async fn scim_user_by_id(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
    ) -> anyhow::Result<Option<ScimUser>> {
        let user_id = super::validate_scim_user_id(user_id)?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = $1 AND id = $2",
                &[&identity.organization_id, &user_id],
            ))
            .await
            .context("failed to load SCIM user")?;
        row.map(scim_user_from_row).transpose()
    }

    pub(super) async fn update_scim_user(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
        update: ScimUserUpdate,
    ) -> anyhow::Result<Option<ScimUser>> {
        let user_id = super::validate_scim_user_id(user_id)?;
        let update = super::validate_scim_user_update(update)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH saved_user AS (
                    UPDATE scim_users
                    SET user_name = COALESCE($3, user_name),
                        display_name = COALESCE($4, display_name),
                        active = COALESCE($5, active),
                        updated_at_unix = $6
                    WHERE organization_id = $1 AND id = $2
                    RETURNING id, organization_id, external_id, user_name, display_name, active,
                              created_at_unix, updated_at_unix
                 ), updated_principal AS (
                    UPDATE workspace_principals
                    SET name = saved_user.display_name
                    FROM saved_user
                    WHERE workspace_principals.id = saved_user.id
                 ), suspended_memberships AS (
                    UPDATE workspace_memberships
                    SET active = FALSE, updated_at_unix = $6
                    FROM saved_user, workspaces
                    WHERE saved_user.active = FALSE
                      AND workspace_memberships.principal_id = saved_user.id
                      AND workspaces.id = workspace_memberships.workspace_id
                      AND workspaces.organization_id = saved_user.organization_id
                 ), audited AS (
                    INSERT INTO scim_audit
                        (organization_id, scim_token_id, action, target_principal_id, created_at_unix)
                    SELECT organization_id, $7,
                           CASE WHEN active = FALSE THEN 'user.deactivate' ELSE 'user.update' END,
                           id, $6
                    FROM saved_user
                 )
                 SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM saved_user",
                &[
                    &identity.organization_id,
                    &user_id,
                    &update.user_name,
                    &update.display_name,
                    &update.active,
                    &now,
                    &identity.token_id,
                ],
            ))
            .await
            .context("failed to update SCIM user")?;
        row.map(scim_user_from_row).transpose()
    }

    pub(super) async fn create_scim_group(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        display_name: &str,
        member_ids: Vec<String>,
    ) -> anyhow::Result<ScimGroup> {
        let (external_id, display_name) =
            super::validate_scim_group_fields(external_id, display_name)?;
        let member_ids = super::validate_scim_group_member_ids(member_ids)?;
        let members_json =
            serde_json::to_string(&member_ids).context("failed to encode SCIM group members")?;
        let now = now_unix();
        let group_id = random_id("scim_group");
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH active_organization AS MATERIALIZED (
                    SELECT id FROM organizations WHERE id = $1 AND active = TRUE
                 ), requested_members AS MATERIALIZED (
                    SELECT value AS id FROM jsonb_array_elements_text(($6::text)::jsonb)
                 ), valid_members AS MATERIALIZED (
                    SELECT scim_users.id
                    FROM scim_users
                    JOIN requested_members ON requested_members.id = scim_users.id
                    WHERE scim_users.organization_id = $1 AND scim_users.active = TRUE
                 ), valid_request AS MATERIALIZED (
                    SELECT active_organization.id
                    FROM active_organization
                    WHERE (SELECT COUNT(*) FROM requested_members) =
                          (SELECT COUNT(*) FROM valid_members)
                 ), saved_group AS (
                    INSERT INTO scim_groups
                        (id, organization_id, external_id, display_name, active,
                         created_at_unix, updated_at_unix)
                    SELECT $2, id, $3, $4, TRUE, $5, $5 FROM valid_request
                    RETURNING id, organization_id, external_id, display_name, active,
                              created_at_unix, updated_at_unix
                 ), added_members AS (
                    INSERT INTO scim_group_members (group_id, principal_id, created_at_unix)
                    SELECT saved_group.id, valid_members.id, $5
                    FROM saved_group
                    CROSS JOIN valid_members
                 ), audited AS (
                    INSERT INTO scim_group_audit
                        (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                    SELECT organization_id, $7, 'group.create', id, $5 FROM saved_group
                 )
                 SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM saved_group",
                &[
                    &identity.organization_id,
                    &group_id,
                    &external_id,
                    &display_name,
                    &now,
                    &members_json,
                    &identity.token_id,
                ],
            ))
            .await
            .context("failed to create SCIM group")?
            .ok_or_else(|| {
                anyhow::anyhow!("SCIM group organization is unavailable or members are invalid")
            })?;
        let mut group = scim_group_from_row(row)?;
        group.member_ids = self.scim_group_members(&client, &group.id).await?;
        Ok(group)
    }

    pub(super) async fn list_scim_groups(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimGroupPage> {
        super::validate_scim_page(start_index, count)?;
        let offset = i64::try_from(start_index - 1)
            .context("SCIM start index exceeds PostgreSQL integer range")?;
        let limit =
            i64::try_from(count).context("SCIM page size exceeds PostgreSQL integer range")?;
        let client = self.checkout().await?;
        let total_results: i64 = self
            .bounded(client.query_one(
                "SELECT COUNT(*) FROM scim_groups WHERE organization_id = $1 AND active = TRUE",
                &[&identity.organization_id],
            ))
            .await
            .context("failed to count SCIM groups")?
            .get(0);
        let rows = self
            .bounded(client.query(
                "SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_groups
                 WHERE organization_id = $1 AND active = TRUE
                 ORDER BY id ASC
                 LIMIT $2 OFFSET $3",
                &[&identity.organization_id, &limit, &offset],
            ))
            .await
            .context("failed to query SCIM groups")?;
        let mut resources = rows
            .into_iter()
            .map(scim_group_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        for group in &mut resources {
            group.member_ids = self.scim_group_members(&client, &group.id).await?;
        }
        Ok(ScimGroupPage {
            total_results: u64::try_from(total_results)
                .context("stored SCIM group count cannot be negative")?,
            start_index,
            items_per_page: resources.len(),
            resources,
        })
    }

    pub(super) async fn scim_group_by_id(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<Option<ScimGroup>> {
        let group_id = super::validate_scim_group_id(group_id)?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_groups
                 WHERE organization_id = $1 AND id = $2 AND active = TRUE",
                &[&identity.organization_id, &group_id],
            ))
            .await
            .context("failed to load SCIM group")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut group = scim_group_from_row(row)?;
        group.member_ids = self.scim_group_members(&client, &group.id).await?;
        Ok(Some(group))
    }

    pub(super) async fn update_scim_group(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
        update: ScimGroupUpdate,
    ) -> anyhow::Result<Option<ScimGroup>> {
        let group_id = super::validate_scim_group_id(group_id)?;
        let update = super::validate_scim_group_update(update)?;
        let (mutation, member_ids) = match update.member_change {
            Some(ScimGroupMemberChange::Replace(member_ids)) => ("replace", member_ids),
            Some(ScimGroupMemberChange::Add(member_ids)) => ("add", member_ids),
            Some(ScimGroupMemberChange::Remove(member_ids)) => ("remove", member_ids),
            None => ("none", Vec::new()),
        };
        let members_json = serde_json::to_string(&member_ids)
            .context("failed to encode SCIM group member update")?;
        let action = match mutation {
            "replace" => "group.members.replace",
            "add" => "group.members.add",
            "remove" => "group.members.remove",
            _ => "group.update",
        };
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH requested_members AS MATERIALIZED (
                    SELECT value AS id FROM jsonb_array_elements_text(($5::text)::jsonb)
                 ), valid_members AS MATERIALIZED (
                    SELECT scim_users.id
                    FROM scim_users
                    JOIN requested_members ON requested_members.id = scim_users.id
                    WHERE scim_users.organization_id = $1 AND scim_users.active = TRUE
                 ), valid_request AS MATERIALIZED (
                    SELECT 1
                    WHERE $6 IN ('remove', 'none')
                       OR (SELECT COUNT(*) FROM requested_members) =
                          (SELECT COUNT(*) FROM valid_members)
                 ), saved_group AS (
                    UPDATE scim_groups
                    SET display_name = COALESCE($3, display_name), updated_at_unix = $4
                    WHERE organization_id = $1 AND id = $2 AND active = TRUE
                      AND EXISTS (SELECT 1 FROM valid_request)
                    RETURNING id, organization_id, external_id, display_name, active,
                              created_at_unix, updated_at_unix
                 ), replaced_members AS (
                    DELETE FROM scim_group_members
                    USING saved_group
                    WHERE $6 = 'replace' AND scim_group_members.group_id = saved_group.id
                 ), removed_members AS (
                    DELETE FROM scim_group_members
                    USING saved_group, requested_members
                    WHERE $6 = 'remove'
                      AND scim_group_members.group_id = saved_group.id
                      AND scim_group_members.principal_id = requested_members.id
                 ), added_members AS (
                    INSERT INTO scim_group_members (group_id, principal_id, created_at_unix)
                    SELECT saved_group.id, valid_members.id, $4
                    FROM saved_group
                    CROSS JOIN valid_members
                    WHERE $6 IN ('replace', 'add')
                    ON CONFLICT (group_id, principal_id) DO NOTHING
                 ), audited AS (
                    INSERT INTO scim_group_audit
                        (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                    SELECT organization_id, $7, $8, id, $4 FROM saved_group
                 )
                 SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM saved_group",
                &[
                    &identity.organization_id,
                    &group_id,
                    &update.display_name,
                    &now,
                    &members_json,
                    &mutation,
                    &identity.token_id,
                    &action,
                ],
            ))
            .await
            .context("failed to update SCIM group")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut group = scim_group_from_row(row)?;
        group.member_ids = self.scim_group_members(&client, &group.id).await?;
        Ok(Some(group))
    }

    pub(super) async fn delete_scim_group(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = super::validate_scim_group_id(group_id)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let deleted = self
            .bounded(client.query_opt(
                "WITH existing_group AS MATERIALIZED (
                    SELECT id, organization_id FROM scim_groups
                    WHERE organization_id = $1 AND id = $2 AND active = TRUE
                 ), audited AS (
                    INSERT INTO scim_group_audit
                        (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                    SELECT organization_id, $3, 'group.delete', id, $4 FROM existing_group
                 ), removed AS (
                    DELETE FROM scim_groups
                    USING existing_group
                    WHERE scim_groups.id = existing_group.id
                 )
                 SELECT id FROM existing_group",
                &[
                    &identity.organization_id,
                    &group_id,
                    &identity.token_id,
                    &now,
                ],
            ))
            .await
            .context("failed to delete SCIM group")?;
        Ok(deleted.is_some())
    }

    async fn scim_group_members(
        &self,
        client: &deadpool_postgres::Client,
        group_id: &str,
    ) -> anyhow::Result<Vec<String>> {
        let rows = self
            .bounded(client.query(
                "SELECT principal_id FROM scim_group_members
                 WHERE group_id = $1 ORDER BY principal_id ASC",
                &[&group_id],
            ))
            .await
            .context("failed to query SCIM group members")?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    pub(super) async fn set_organization_oidc_connection(
        &self,
        organization_id: &str,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationOidcConnection> {
        let issuer = super::validate_oidc_https_uri(issuer, "OIDC issuer")?;
        let client_id =
            super::validate_external_identity_component(client_id, "OIDC client id", 512)?;
        let redirect_uri = super::validate_oidc_https_uri(redirect_uri, "OIDC redirect URI")?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH active_organization AS (
                    SELECT id FROM organizations WHERE id = $1 AND active = TRUE
                 ), saved AS (
                    INSERT INTO organization_oidc_connections
                        (organization_id, issuer, client_id, redirect_uri, active,
                         created_at_unix, updated_at_unix)
                    SELECT id, $2, $3, $4, $5, $6, $6 FROM active_organization
                    ON CONFLICT (organization_id) DO UPDATE SET
                        issuer = excluded.issuer,
                        client_id = excluded.client_id,
                        redirect_uri = excluded.redirect_uri,
                        active = excluded.active,
                        updated_at_unix = excluded.updated_at_unix
                    RETURNING organization_id, issuer, client_id, redirect_uri, active,
                              created_at_unix, updated_at_unix
                 )
                 SELECT organization_id, issuer, client_id, redirect_uri, active,
                        created_at_unix, updated_at_unix FROM saved",
                &[
                    &organization_id,
                    &issuer,
                    &client_id,
                    &redirect_uri,
                    &active,
                    &now,
                ],
            ))
            .await
            .context("failed to save PostgreSQL organization OIDC connection")?
            .ok_or_else(|| anyhow::anyhow!("organization not found or inactive"))?;
        organization_oidc_connection_from_row(row)
    }

    pub(super) async fn organization_oidc_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationOidcConnection>> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT organization_id, issuer, client_id, redirect_uri, active,
                        created_at_unix, updated_at_unix
                 FROM organization_oidc_connections WHERE organization_id = $1",
                &[&organization_id],
            ))
            .await
            .context("failed to load PostgreSQL organization OIDC connection")?;
        row.map(organization_oidc_connection_from_row).transpose()
    }

    pub(super) async fn delete_organization_oidc_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let deleted = self
            .bounded(client.execute(
                "DELETE FROM organization_oidc_connections WHERE organization_id = $1",
                &[&organization_id],
            ))
            .await
            .context("failed to delete PostgreSQL organization OIDC connection")?;
        Ok(deleted == 1)
    }

    pub(super) async fn set_organization_saml_connection(
        &self,
        organization_id: &str,
        entity_id: &str,
        metadata_xml: &str,
        metadata_signing_cert_pem: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationSamlConnection> {
        let entity_id = super::validate_saml_entity_id(entity_id)?;
        let metadata_xml = super::validate_saml_metadata(metadata_xml)?;
        let metadata_signing_cert_pem =
            super::validate_saml_certificate(metadata_signing_cert_pem)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH active_organization AS (
                    SELECT id FROM organizations WHERE id = $1 AND active = TRUE
                 ), saved AS (
                    INSERT INTO organization_saml_connections
                        (organization_id, entity_id, metadata_xml,
                         metadata_signing_cert_pem, active, created_at_unix, updated_at_unix)
                    SELECT id, $2, $3, $4, $5, $6, $6 FROM active_organization
                    ON CONFLICT (organization_id) DO UPDATE SET
                        entity_id = excluded.entity_id,
                        metadata_xml = excluded.metadata_xml,
                        metadata_signing_cert_pem = excluded.metadata_signing_cert_pem,
                        active = excluded.active,
                        updated_at_unix = excluded.updated_at_unix
                    RETURNING organization_id, entity_id, metadata_xml,
                              metadata_signing_cert_pem, active,
                              created_at_unix, updated_at_unix
                 )
                 SELECT organization_id, entity_id, metadata_xml,
                        metadata_signing_cert_pem, active,
                        created_at_unix, updated_at_unix FROM saved",
                &[
                    &organization_id,
                    &entity_id,
                    &metadata_xml,
                    &metadata_signing_cert_pem,
                    &active,
                    &now,
                ],
            ))
            .await
            .context("failed to save PostgreSQL organization SAML connection")?
            .ok_or_else(|| anyhow::anyhow!("organization not found or inactive"))?;
        organization_saml_connection_from_row(row)
    }

    pub(super) async fn organization_saml_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationSamlConnection>> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT organization_id, entity_id, metadata_xml,
                        metadata_signing_cert_pem, active, created_at_unix, updated_at_unix
                 FROM organization_saml_connections WHERE organization_id = $1",
                &[&organization_id],
            ))
            .await
            .context("failed to load PostgreSQL organization SAML connection")?;
        row.map(organization_saml_connection_from_row).transpose()
    }

    pub(super) async fn delete_organization_saml_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let deleted = self
            .bounded(client.execute(
                "DELETE FROM organization_saml_connections WHERE organization_id = $1",
                &[&organization_id],
            ))
            .await
            .context("failed to delete PostgreSQL organization SAML connection")?;
        Ok(deleted == 1)
    }

    pub(super) async fn reserve_oidc_authorization_state(
        &self,
        state: &str,
        organization_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        super::validate_oidc_authorization_state_expiry(expires_at_unix)?;
        let state_hash = super::oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "WITH expired AS (
                SELECT state_hash FROM oidc_authorization_states
                WHERE expires_at_unix < $1
                ORDER BY expires_at_unix ASC LIMIT 100
             )
             DELETE FROM oidc_authorization_states
             USING expired
             WHERE oidc_authorization_states.state_hash = expired.state_hash",
            &[&now],
        ))
        .await
        .context("failed to prune expired PostgreSQL OIDC authorization states")?;
        let inserted = self
            .bounded(client.execute(
                "INSERT INTO oidc_authorization_states
                    (state_hash, organization_id, expires_at_unix, consumed_at_unix, created_at_unix)
                 SELECT $1, organizations.id, $3, NULL, $4
                 FROM organizations
                 JOIN organization_oidc_connections
                   ON organization_oidc_connections.organization_id = organizations.id
                 WHERE organizations.id = $2
                   AND organizations.active = TRUE
                   AND organization_oidc_connections.active = TRUE",
                &[&state_hash, &organization_id, &expires_at_unix, &now],
            ))
            .await
            .context("failed to reserve PostgreSQL OIDC authorization state")?;
        if inserted != 1 {
            bail!("organization not found, inactive, or has no active OIDC connection");
        }
        Ok(())
    }

    pub(super) async fn consume_oidc_authorization_state(
        &self,
        state: &str,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        let state_hash = super::oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let consumed = self
            .bounded(client.execute(
                "UPDATE oidc_authorization_states
                 SET consumed_at_unix = $3
                 WHERE state_hash = $1
                   AND organization_id = $2
                   AND consumed_at_unix IS NULL
                   AND expires_at_unix >= $3",
                &[&state_hash, &organization_id, &now],
            ))
            .await
            .context("failed to consume PostgreSQL OIDC authorization state")?;
        Ok(consumed == 1)
    }

    pub(super) async fn reserve_saml_authorization_state(
        &self,
        state: &str,
        pending: &SamlAuthorizationPending,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        super::validate_oidc_authorization_state_expiry(expires_at_unix)?;
        let state_hash = super::oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "WITH expired AS (
                SELECT state_hash FROM saml_authorization_states
                WHERE expires_at_unix < $1 ORDER BY expires_at_unix ASC LIMIT 100
             )
             DELETE FROM saml_authorization_states
             USING expired WHERE saml_authorization_states.state_hash = expired.state_hash",
            &[&now],
        ))
        .await
        .context("failed to prune expired PostgreSQL SAML authorization states")?;
        let inserted = self
            .bounded(client.execute(
                "INSERT INTO saml_authorization_states
                    (state_hash, organization_id, workspace_id, invitation_id, request_id, idp_entity_id,
                     expected_binding, request_binding, acs_url, acs_binding,
                     expires_at_unix, consumed_at_unix, created_at_unix)
                 SELECT $1, organizations.id, workspaces.id, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12
                 FROM organizations
                 JOIN workspaces ON workspaces.organization_id = organizations.id
                 JOIN organization_saml_connections
                   ON organization_saml_connections.organization_id = organizations.id
                 WHERE organizations.id = $2 AND workspaces.id = $3
                   AND organizations.active = TRUE AND workspaces.active = TRUE
                   AND organization_saml_connections.active = TRUE",
                &[
                    &state_hash,
                    &pending.organization_id,
                    &pending.workspace_id,
                    &pending.invitation_id,
                    &pending.request_id,
                    &pending.idp_entity_id,
                    &pending.expected_binding,
                    &pending.request_binding,
                    &pending.acs_url,
                    &pending.acs_binding,
                    &expires_at_unix,
                    &now,
                ],
            ))
            .await
            .context("failed to reserve PostgreSQL SAML authorization state")?;
        if inserted != 1 {
            bail!("organization or workspace is inactive, or SAML is not configured");
        }
        Ok(())
    }

    pub(super) async fn consume_saml_authorization_state(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<SamlAuthorizationPending>> {
        let state_hash = super::oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "UPDATE saml_authorization_states
                 SET consumed_at_unix = $2
                 WHERE state_hash = $1 AND consumed_at_unix IS NULL AND expires_at_unix >= $2
                RETURNING organization_id, workspace_id, invitation_id, request_id, idp_entity_id,
                           expected_binding, request_binding, acs_url, acs_binding",
                &[&state_hash, &now],
            ))
            .await
            .context("failed to consume PostgreSQL SAML authorization state")?;
        row.map(|row| {
            Ok(SamlAuthorizationPending {
                organization_id: row.get(0),
                workspace_id: row.get(1),
                invitation_id: row.get(2),
                request_id: row.get(3),
                idp_entity_id: row.get(4),
                expected_binding: row.get(5),
                request_binding: row.get(6),
                acs_url: row.get(7),
                acs_binding: row.get(8),
            })
        })
        .transpose()
    }

    pub(super) async fn issue_oidc_browser_session(
        &self,
        access: &VerifiedWorkspaceAccess,
        federation: BrowserSessionFederation,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedOidcBrowserSession> {
        validate_oidc_browser_session_expiry(expires_at_unix)?;
        let issued = IssuedOidcBrowserSession {
            token: generate_oidc_browser_session_token(),
            expires_at_unix,
        };
        let session_hash = oidc_browser_session_hash(&issued.token)?;
        let now = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "WITH obsolete AS (
                SELECT session_hash FROM oidc_browser_sessions
                WHERE expires_at_unix < $1 OR revoked_at_unix IS NOT NULL
                ORDER BY expires_at_unix ASC LIMIT 100
             )
             DELETE FROM oidc_browser_sessions
             USING obsolete
             WHERE oidc_browser_sessions.session_hash = obsolete.session_hash",
            &[&now],
        ))
        .await
        .context("failed to prune expired PostgreSQL OIDC browser sessions")?;
        let inserted = self
            .bounded(client.execute(
                "INSERT INTO oidc_browser_sessions
                    (session_hash, organization_id, workspace_id, principal_id, federation_kind,
                     expires_at_unix, revoked_at_unix, created_at_unix)
                 SELECT $1, organizations.id, workspaces.id, workspace_principals.id,
                        $5, $6, NULL, $7
                 FROM organizations
                 JOIN workspaces ON workspaces.organization_id = organizations.id
                 JOIN workspace_principals ON workspace_principals.id = $4
                 WHERE organizations.id = $2
                   AND workspaces.id = $3
                   AND organizations.active = TRUE
                   AND workspaces.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND (
                     ($5 = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = TRUE
                     )) OR ($5 = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = TRUE
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = TRUE
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = TRUE
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = TRUE
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                &[
                    &session_hash,
                    &access.organization_id,
                    &access.workspace_id,
                    &access.principal_id,
                    &federation.as_storage(),
                    &expires_at_unix,
                    &now,
                ],
            ))
            .await
            .context("failed to create PostgreSQL OIDC browser session")?;
        if inserted != 1 {
            bail!("verified OIDC identity no longer has active workspace access");
        }
        Ok(issued)
    }

    pub(super) async fn rotate_oidc_browser_session(
        &self,
        token: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<Option<IssuedOidcBrowserSession>> {
        validate_oidc_browser_session_expiry(expires_at_unix)?;
        let old_hash = oidc_browser_session_hash(token)?;
        let issued = IssuedOidcBrowserSession {
            token: generate_oidc_browser_session_token(),
            expires_at_unix,
        };
        let new_hash = oidc_browser_session_hash(&issued.token)?;
        let now = now_unix();
        let mut client = self.checkout().await?;
        let transaction = client
            .transaction()
            .await
            .context("failed to begin PostgreSQL OIDC session rotation")?;
        let current = self
            .bounded(transaction.query_opt(
                "SELECT organizations.id, workspaces.id, workspace_principals.id,
                        oidc_browser_sessions.federation_kind,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = TRUE),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = TRUE
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = TRUE
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        )
                 FROM oidc_browser_sessions
                 JOIN organizations ON organizations.id = oidc_browser_sessions.organization_id
                 JOIN workspaces ON workspaces.id = oidc_browser_sessions.workspace_id
                  AND workspaces.organization_id = organizations.id
                 JOIN workspace_principals
                   ON workspace_principals.id = oidc_browser_sessions.principal_id
                 WHERE oidc_browser_sessions.session_hash = $1
                   AND oidc_browser_sessions.expires_at_unix >= $2
                   AND oidc_browser_sessions.revoked_at_unix IS NULL
                   AND organizations.active = TRUE
                   AND workspaces.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND (
                     (oidc_browser_sessions.federation_kind = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = TRUE
                     )) OR (oidc_browser_sessions.federation_kind = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = TRUE
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = TRUE
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = TRUE
                       JOIN scim_group_members
                         ON scim_group_members.group_id = workspace_scim_group_mappings.group_id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = TRUE
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                &[&old_hash, &now],
            ))
            .await
            .context("failed to authenticate PostgreSQL OIDC session for rotation")?;
        let Some(current) = current else {
            transaction
                .commit()
                .await
                .context("failed to finish empty PostgreSQL OIDC session rotation")?;
            return Ok(None);
        };
        let access = VerifiedWorkspaceAccess {
            organization_id: current.get(0),
            workspace_id: current.get(1),
            principal_id: current.get(2),
            role: WorkspaceRole::from_storage(&current.get::<_, String>(4))?,
        };
        let federation = BrowserSessionFederation::from_storage(&current.get::<_, String>(3))?;
        let revoked = self
            .bounded(transaction.execute(
                "UPDATE oidc_browser_sessions SET revoked_at_unix = $2
                 WHERE session_hash = $1 AND revoked_at_unix IS NULL
                   AND expires_at_unix >= $3",
                &[&old_hash, &now, &now],
            ))
            .await
            .context("failed to revoke old PostgreSQL OIDC browser session")?;
        if revoked != 1 {
            transaction
                .commit()
                .await
                .context("failed to finish concurrent PostgreSQL OIDC session rotation")?;
            return Ok(None);
        }
        self.bounded(transaction.execute(
            "INSERT INTO oidc_browser_sessions
                (session_hash, organization_id, workspace_id, principal_id, federation_kind,
                 expires_at_unix, revoked_at_unix, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)",
            &[
                &new_hash,
                &access.organization_id,
                &access.workspace_id,
                &access.principal_id,
                &federation.as_storage(),
                &expires_at_unix,
                &now,
            ],
        ))
        .await
        .context("failed to issue replacement PostgreSQL OIDC browser session")?;
        transaction
            .commit()
            .await
            .context("failed to commit PostgreSQL OIDC session rotation")?;
        Ok(Some(issued))
    }

    pub(super) async fn authenticate_oidc_browser_session(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<OidcBrowserSession>> {
        let session_hash = oidc_browser_session_hash(token)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT organizations.id, workspaces.id, workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = TRUE),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = TRUE
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = TRUE
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        ), oidc_browser_sessions.expires_at_unix
                 FROM oidc_browser_sessions
                 JOIN organizations ON organizations.id = oidc_browser_sessions.organization_id
                 JOIN workspaces ON workspaces.id = oidc_browser_sessions.workspace_id
                  AND workspaces.organization_id = organizations.id
                 JOIN workspace_principals
                   ON workspace_principals.id = oidc_browser_sessions.principal_id
                 WHERE oidc_browser_sessions.session_hash = $1
                   AND oidc_browser_sessions.expires_at_unix >= $2
                   AND oidc_browser_sessions.revoked_at_unix IS NULL
                   AND organizations.active = TRUE
                   AND workspaces.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND (
                     (oidc_browser_sessions.federation_kind = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = TRUE
                     )) OR (oidc_browser_sessions.federation_kind = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = TRUE
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = TRUE
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = TRUE
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = TRUE
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                &[&session_hash, &now],
            ))
            .await
            .context("failed to authenticate PostgreSQL OIDC browser session")?;
        row.map(|row| {
            Ok(OidcBrowserSession {
                access: VerifiedWorkspaceAccess {
                    organization_id: row.get(0),
                    workspace_id: row.get(1),
                    principal_id: row.get(2),
                    role: WorkspaceRole::from_storage(&row.get::<_, String>(3))?,
                },
                expires_at_unix: row.get(4),
            })
        })
        .transpose()
    }

    pub(super) async fn revoke_oidc_browser_session(&self, token: &str) -> anyhow::Result<bool> {
        let session_hash = oidc_browser_session_hash(token)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let revoked = self
            .bounded(client.execute(
                "UPDATE oidc_browser_sessions
                 SET revoked_at_unix = $2
                 WHERE session_hash = $1 AND revoked_at_unix IS NULL",
                &[&session_hash, &now],
            ))
            .await
            .context("failed to revoke PostgreSQL OIDC browser session")?;
        Ok(revoked == 1)
    }

    pub(super) async fn list_workspace_service_accounts(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceServiceAccount>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT a.id, a.workspace_id, a.name, a.created_by_principal_id,
                        a.active, a.expires_at_unix, a.created_at_unix, a.revoked_at_unix
                 FROM workspace_service_accounts a
                 JOIN workspaces w ON w.id = a.workspace_id
                 JOIN organizations o ON o.id = w.organization_id
                 JOIN tenants t ON t.id = w.tenant_id
                 JOIN workspace_principals actor ON actor.id = $2
                 JOIN workspace_memberships membership
                   ON membership.workspace_id = w.id
                  AND membership.principal_id = actor.id
                  AND membership.active = TRUE
                 WHERE a.workspace_id = $1 AND w.active = TRUE
                   AND o.active = TRUE AND t.active = TRUE AND actor.active = TRUE
                   AND (membership.role IN ('owner', 'admin')
                        OR a.created_by_principal_id = $2)
                 ORDER BY a.created_at_unix ASC, a.id ASC",
                &[&workspace_id, &actor_principal_id],
            ))
            .await
            .context("failed to list PostgreSQL workspace service accounts")?;
        rows.into_iter().map(service_account_from_row).collect()
    }

    pub(super) async fn create_workspace_service_account(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        name: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceServiceAccount> {
        super::validate_service_account_expiry(expires_at_unix)?;
        let account = WorkspaceServiceAccount {
            id: random_id("service_account"),
            workspace_id: workspace_id.to_owned(),
            name: validate_label(name, "service account name", 128)?,
            created_by_principal_id: actor_principal_id.to_owned(),
            active: true,
            expires_at_unix,
            created_at_unix: now_unix(),
            revoked_at_unix: None,
        };
        let token = format!("llmfw_sa_{}", super::random_base64url(32));
        let token_hash = token_hash(&token);
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH authorized AS (
                    SELECT w.organization_id, m.role
                    FROM workspaces w
                    JOIN organizations o ON o.id = w.organization_id
                    JOIN tenants t ON t.id = w.tenant_id
                    JOIN workspace_principals p ON p.id = $2
                    JOIN workspace_memberships m
                      ON m.workspace_id = w.id AND m.principal_id = p.id
                    WHERE w.id = $1 AND w.active = TRUE AND o.active = TRUE
                      AND t.active = TRUE AND p.active = TRUE AND m.active = TRUE
                      AND m.role IN ('owner', 'admin', 'developer')
                 ), inserted AS (
                    INSERT INTO workspace_service_accounts
                        (id, workspace_id, name, created_by_principal_id, token_hash,
                         active, expires_at_unix, created_at_unix, revoked_at_unix)
                    SELECT $3, $1, $4, $2, $5, TRUE, $6, $7, NULL
                    FROM authorized
                    RETURNING id, workspace_id, name, created_by_principal_id,
                              active, expires_at_unix, created_at_unix, revoked_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, 'service_account.create', $2, $7
                    FROM authorized CROSS JOIN inserted
                 )
                 SELECT id, workspace_id, name, created_by_principal_id,
                        active, expires_at_unix, created_at_unix, revoked_at_unix
                 FROM inserted",
                &[
                    &workspace_id,
                    &actor_principal_id,
                    &account.id,
                    &account.name,
                    &token_hash,
                    &account.expires_at_unix,
                    &account.created_at_unix,
                ],
            ))
            .await
            .context("failed to create PostgreSQL workspace service account")?;
        let account_row =
            row.ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        Ok(IssuedWorkspaceServiceAccount {
            account: service_account_from_row(account_row)?,
            token,
        })
    }

    pub(super) async fn revoke_workspace_service_account(
        &self,
        workspace_id: &str,
        account_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.query_one(
                "WITH authorized AS (
                    SELECT w.organization_id, m.role
                    FROM workspaces w
                    JOIN organizations o ON o.id = w.organization_id
                    JOIN tenants t ON t.id = w.tenant_id
                    JOIN workspace_principals p ON p.id = $3
                    JOIN workspace_memberships m
                      ON m.workspace_id = w.id AND m.principal_id = p.id
                    WHERE w.id = $1 AND w.active = TRUE AND o.active = TRUE
                      AND t.active = TRUE AND p.active = TRUE AND m.active = TRUE
                 ), changed AS (
                    UPDATE workspace_service_accounts a
                    SET active = FALSE, revoked_at_unix = $4
                    FROM authorized
                    WHERE a.id = $2 AND a.workspace_id = $1 AND a.active = TRUE
                      AND (authorized.role IN ('owner', 'admin')
                           OR (authorized.role = 'developer'
                               AND a.created_by_principal_id = $3))
                    RETURNING a.created_by_principal_id
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT authorized.organization_id, $1, $3, 'service_account.revoke',
                           changed.created_by_principal_id, $4
                    FROM authorized CROSS JOIN changed
                 )
                 SELECT COUNT(*) FROM changed",
                &[&workspace_id, &account_id, &actor_principal_id, &now],
            ))
            .await
            .context("failed to revoke PostgreSQL workspace service account")?
            .get::<_, i64>(0);
        Ok(changed == 1)
    }

    pub(super) async fn set_organization_active(
        &self,
        organization_id: &str,
        active: bool,
    ) -> anyhow::Result<bool> {
        if organization_id == BOOTSTRAP_ORGANIZATION_ID && !active {
            bail!("the bootstrap organization cannot be suspended");
        }
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE organizations SET active = $1 WHERE id = $2",
                &[&active, &organization_id],
            ))
            .await
            .context("failed to update organization state")?;
        Ok(changed == 1)
    }

    pub(super) async fn list_organization_workspaces(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Vec<Workspace>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, organization_id, tenant_id, name, active, created_at_unix
                 FROM workspaces
                 WHERE organization_id = $1
                 ORDER BY created_at_unix ASC, id ASC",
                &[&organization_id],
            ))
            .await
            .context("failed to query organization workspaces")?;
        rows.into_iter().map(workspace_from_row).collect()
    }

    pub(super) async fn active_workspace_in_organization(
        &self,
        organization_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let found = self
            .bounded(client.query_opt(
                "SELECT 1
                 FROM workspaces
                 INNER JOIN organizations ON organizations.id = workspaces.organization_id
                 WHERE workspaces.id = $1
                   AND workspaces.organization_id = $2
                   AND workspaces.active = TRUE
                   AND organizations.active = TRUE",
                &[&workspace_id, &organization_id],
            ))
            .await
            .context("failed to verify workspace organization")?;
        Ok(found.is_some())
    }

    pub(super) async fn list_tenants(&self) -> anyhow::Result<Vec<Tenant>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, name, active, created_at_unix
                 FROM tenants ORDER BY created_at_unix ASC, id ASC",
                &[],
            ))
            .await
            .context("failed to query tenants")?;
        rows.iter().map(tenant_from_row).collect()
    }

    pub(super) async fn workspace_for_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<Workspace>> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT id, organization_id, tenant_id, name, active, created_at_unix
                 FROM workspaces WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load tenant workspace")?;
        row.map(workspace_from_row).transpose()
    }

    pub(super) async fn active_workspace_by_id(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Option<Workspace>> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT workspaces.id, workspaces.organization_id, workspaces.tenant_id,
                        workspaces.name, workspaces.active, workspaces.created_at_unix
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 WHERE workspaces.id = $1
                   AND workspaces.active = TRUE
                   AND organizations.active = TRUE
                   AND tenants.active = TRUE",
                &[&workspace_id],
            ))
            .await
            .context("failed to load active workspace")?;
        row.map(workspace_from_row).transpose()
    }

    pub(super) async fn create_workspace_principal(
        &self,
        name: &str,
    ) -> anyhow::Result<WorkspacePrincipal> {
        let principal = WorkspacePrincipal {
            id: random_id("principal"),
            name: validate_label(name, "principal name", 128)?,
            active: true,
            created_at_unix: now_unix(),
        };
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO workspace_principals (id, name, active, created_at_unix)
             VALUES ($1, $2, TRUE, $3)",
            &[&principal.id, &principal.name, &principal.created_at_unix],
        ))
        .await
        .context("failed to create workspace principal")?;
        Ok(principal)
    }

    pub(super) async fn link_workspace_external_identity(
        &self,
        principal_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<WorkspaceExternalIdentity> {
        let identity = WorkspaceExternalIdentity {
            issuer: super::validate_external_identity_component(issuer, "identity issuer", 2_048)?,
            subject: super::validate_external_identity_component(subject, "identity subject", 255)?,
            principal_id: principal_id.to_owned(),
            created_at_unix: now_unix(),
        };
        let client = self.checkout().await?;
        let linked = self
            .bounded(client.execute(
                "INSERT INTO workspace_external_identities
                    (issuer, subject, principal_id, created_at_unix)
                 SELECT $1, $2, id, $3 FROM workspace_principals
                 WHERE id = $4 AND active = TRUE",
                &[
                    &identity.issuer,
                    &identity.subject,
                    &identity.created_at_unix,
                    &principal_id,
                ],
            ))
            .await
            .context("failed to link workspace external identity")?;
        if linked != 1 {
            bail!("workspace principal not found or inactive");
        }
        Ok(identity)
    }

    pub(super) async fn workspace_principal_for_external_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<WorkspacePrincipal>> {
        let issuer = super::validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject =
            super::validate_external_identity_component(subject, "identity subject", 255)?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT workspace_principals.id, workspace_principals.name,
                        workspace_principals.active, workspace_principals.created_at_unix
                 FROM workspace_external_identities
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_external_identities.principal_id
                 WHERE workspace_external_identities.issuer = $1
                   AND workspace_external_identities.subject = $2
                   AND workspace_principals.active = TRUE",
                &[&issuer, &subject],
            ))
            .await
            .context("failed to look up workspace external identity")?;
        row.map(workspace_principal_from_row).transpose()
    }

    pub(super) async fn verified_identity_workspace_access(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = super::validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject =
            super::validate_external_identity_component(subject, "identity subject", 255)?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = TRUE),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = TRUE
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = TRUE
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        )
                 FROM organization_oidc_connections
                 JOIN organizations
                   ON organizations.id = organization_oidc_connections.organization_id
                 JOIN workspaces
                   ON workspaces.organization_id = organizations.id
                 JOIN workspace_external_identities
                   ON workspace_external_identities.issuer = organization_oidc_connections.issuer
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_external_identities.principal_id
                 WHERE organization_oidc_connections.organization_id = $1
                   AND workspaces.id = $2
                   AND organization_oidc_connections.issuer = $3
                   AND workspace_external_identities.subject = $4
                   AND organization_oidc_connections.active = TRUE
                   AND organizations.active = TRUE
                   AND workspaces.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = TRUE
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = TRUE
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = TRUE
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                &[&organization_id, &workspace_id, &issuer, &subject],
            ))
            .await
            .context("failed to authorize verified OIDC identity for workspace")?;
        row.map(|row| {
            Ok(VerifiedWorkspaceAccess {
                organization_id: organization_id.to_owned(),
                workspace_id: workspace_id.to_owned(),
                principal_id: row.get(0),
                role: WorkspaceRole::from_storage(&row.get::<_, String>(1))?,
            })
        })
        .transpose()
    }

    pub(super) async fn verified_saml_identity_workspace_access(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = super::validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject =
            super::validate_external_identity_component(subject, "identity subject", 255)?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = TRUE),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = TRUE
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = TRUE
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        )
                 FROM organization_saml_connections
                 JOIN organizations
                   ON organizations.id = organization_saml_connections.organization_id
                 JOIN workspaces
                   ON workspaces.organization_id = organizations.id
                 JOIN workspace_external_identities
                   ON workspace_external_identities.issuer = organization_saml_connections.entity_id
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_external_identities.principal_id
                 WHERE organization_saml_connections.organization_id = $1
                   AND workspaces.id = $2
                   AND organization_saml_connections.entity_id = $3
                   AND workspace_external_identities.subject = $4
                   AND organization_saml_connections.active = TRUE
                   AND organizations.active = TRUE
                   AND workspaces.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = TRUE
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = TRUE
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = TRUE
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                &[&organization_id, &workspace_id, &issuer, &subject],
            ))
            .await
            .context("failed to authorize verified SAML identity for workspace")?;
        row.map(|row| {
            Ok(VerifiedWorkspaceAccess {
                organization_id: organization_id.to_owned(),
                workspace_id: workspace_id.to_owned(),
                principal_id: row.get(0),
                role: WorkspaceRole::from_storage(&row.get::<_, String>(1))?,
            })
        })
        .transpose()
    }

    pub(super) async fn set_workspace_membership(
        &self,
        workspace_id: &str,
        principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        let client = self.checkout().await?;
        let now = now_unix();
        let row = self
            .bounded(client.query_opt(
                "WITH valid_workspace AS (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND organizations.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND (scim_users.id IS NULL OR
                           (scim_users.organization_id = workspaces.organization_id
                            AND scim_users.active = TRUE))
                 ), saved_membership AS (
                    INSERT INTO workspace_memberships
                        (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
                    SELECT $1, $2, $3, TRUE, $4, $4 FROM valid_workspace
                    ON CONFLICT (workspace_id, principal_id) DO UPDATE SET
                        role = excluded.role,
                        active = TRUE,
                        updated_at_unix = excluded.updated_at_unix
                    RETURNING workspace_id, principal_id, role, active, created_at_unix,
                              updated_at_unix
                 ), workspace_audit AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, NULL, 'membership.upsert', $2, $4
                    FROM valid_workspace
                 )
                 SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM saved_membership",
                &[&workspace_id, &principal_id, &role.storage_value(), &now],
            ))
            .await
            .context("failed to save workspace membership and audit event")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot assign membership: workspace, organization, or principal is inactive or not found"
                )
            })?;
        workspace_membership_from_row(row)
    }

    pub(super) async fn list_workspace_members(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceMember>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT workspace_memberships.workspace_id, workspace_memberships.principal_id,
                        workspace_principals.name, workspace_memberships.role,
                        workspace_memberships.active, workspace_memberships.created_at_unix,
                        workspace_memberships.updated_at_unix
                 FROM workspace_memberships
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_memberships.principal_id
                 WHERE workspace_memberships.workspace_id = $1
                 ORDER BY workspace_memberships.active DESC, workspace_principals.name ASC,
                          workspace_memberships.principal_id ASC",
                &[&workspace_id],
            ))
            .await
            .context("failed to query workspace members")?;
        rows.into_iter().map(workspace_member_from_row).collect()
    }

    pub(super) async fn create_workspace_invitation_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        recipient_label: &str,
        role: WorkspaceRole,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceInvitation> {
        super::validate_workspace_invitation_expiry(expires_at_unix)?;
        let token = super::generate_workspace_invitation_token();
        let token_hash = super::workspace_invitation_token_hash(&token)?;
        let invitation_id = random_id("invitation");
        let recipient_label = validate_label(recipient_label, "invitation recipient label", 128)?;
        let created_at_unix = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE AND tenants.active = TRUE
                      AND workspaces.active = TRUE AND workspace_principals.active = TRUE
                 ), inserted AS (
                    INSERT INTO workspace_invitations
                        (id, organization_id, workspace_id, token_hash, recipient_label, role,
                         created_by_principal_id, active, expires_at_unix, created_at_unix,
                         revoked_at_unix, accepted_by_principal_id, accepted_at_unix)
                    SELECT $3, organization_id, $1, $4, $5, $6, $2, TRUE, $7, $8,
                           NULL, NULL, NULL
                    FROM authorized
                    RETURNING id, organization_id, workspace_id, recipient_label, role,
                              created_by_principal_id, active, expires_at_unix, created_at_unix,
                              revoked_at_unix, accepted_by_principal_id, accepted_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, 'invitation.create', NULL, $8
                    FROM inserted
                 )
                 SELECT id, organization_id, workspace_id, recipient_label, role,
                        created_by_principal_id, active, expires_at_unix, created_at_unix,
                        revoked_at_unix, accepted_by_principal_id, accepted_at_unix
                 FROM inserted",
                &[
                    &workspace_id,
                    &actor_principal_id,
                    &invitation_id,
                    &token_hash,
                    &recipient_label,
                    &role.storage_value(),
                    &expires_at_unix,
                    &created_at_unix,
                ],
            ))
            .await
            .context("failed to create PostgreSQL workspace invitation")?
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        Ok(IssuedWorkspaceInvitation {
            invitation: workspace_invitation_from_row(row)?,
            token,
        })
    }

    pub(super) async fn list_workspace_invitations_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceInvitation>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT invitations.id, invitations.organization_id,
                        invitations.workspace_id, invitations.recipient_label,
                        invitations.role, invitations.created_by_principal_id,
                        invitations.active, invitations.expires_at_unix,
                        invitations.created_at_unix, invitations.revoked_at_unix,
                        invitations.accepted_by_principal_id, invitations.accepted_at_unix
                 FROM workspace_invitations AS invitations
                 WHERE invitations.workspace_id = $1
                   AND EXISTS (
                       SELECT 1 FROM workspaces
                       JOIN organizations ON organizations.id = workspaces.organization_id
                       JOIN tenants ON tenants.id = workspaces.tenant_id
                       JOIN workspace_principals ON workspace_principals.id = $2
                       JOIN workspace_memberships
                         ON workspace_memberships.workspace_id = workspaces.id
                        AND workspace_memberships.principal_id = workspace_principals.id
                       WHERE workspaces.id = invitations.workspace_id
                         AND workspace_memberships.role = 'owner'
                         AND workspace_memberships.active = TRUE
                         AND organizations.active = TRUE AND tenants.active = TRUE
                         AND workspaces.active = TRUE AND workspace_principals.active = TRUE
                   )
                 ORDER BY invitations.created_at_unix DESC, invitations.id DESC",
                &[&workspace_id, &actor_principal_id],
            ))
            .await
            .context("failed to list PostgreSQL workspace invitations")?;
        rows.into_iter()
            .map(workspace_invitation_from_row)
            .collect()
    }

    pub(super) async fn revoke_workspace_invitation_as_owner(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_one(
                "WITH authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $3
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE AND tenants.active = TRUE
                      AND workspaces.active = TRUE AND workspace_principals.active = TRUE
                 ), changed AS (
                    UPDATE workspace_invitations AS invitations
                    SET active = FALSE, revoked_at_unix = $4
                    FROM authorized
                    WHERE invitations.id = $2 AND invitations.workspace_id = $1
                      AND invitations.active = TRUE
                      AND invitations.accepted_at_unix IS NULL
                    RETURNING invitations.id, authorized.organization_id
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $3, 'invitation.revoke', NULL, $4
                    FROM changed
                 )
                 SELECT EXISTS(SELECT 1 FROM changed)",
                &[&workspace_id, &invitation_id, &actor_principal_id, &now],
            ))
            .await
            .context("failed to revoke PostgreSQL workspace invitation")?;
        Ok(row.get(0))
    }

    pub(super) async fn workspace_invitation_for_federation_token(
        &self,
        token: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<WorkspaceInvitation>> {
        let token_hash = super::workspace_invitation_token_hash(token)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT invitations.id, invitations.organization_id,
                        invitations.workspace_id, invitations.recipient_label,
                        invitations.role, invitations.created_by_principal_id,
                        invitations.active, invitations.expires_at_unix,
                        invitations.created_at_unix, invitations.revoked_at_unix,
                        invitations.accepted_by_principal_id, invitations.accepted_at_unix
                 FROM workspace_invitations AS invitations
                 JOIN organizations ON organizations.id = invitations.organization_id
                 JOIN workspaces
                   ON workspaces.id = invitations.workspace_id
                  AND workspaces.organization_id = invitations.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 LEFT JOIN organization_oidc_connections AS oidc_connections
                   ON oidc_connections.organization_id = organizations.id
                  AND oidc_connections.active = TRUE
                 LEFT JOIN organization_saml_connections AS saml_connections
                   ON saml_connections.organization_id = organizations.id
                  AND saml_connections.active = TRUE
                 WHERE invitations.token_hash = $1 AND invitations.active = TRUE
                   AND invitations.revoked_at_unix IS NULL
                   AND invitations.accepted_at_unix IS NULL
                   AND invitations.expires_at_unix >= $2
                   AND organizations.active = TRUE AND workspaces.active = TRUE
                   AND tenants.active = TRUE
                   AND (($3 = 'oidc' AND oidc_connections.organization_id IS NOT NULL)
                        OR ($3 = 'saml' AND saml_connections.organization_id IS NOT NULL))",
                &[&token_hash, &now, &federation.as_storage()],
            ))
            .await
            .context("failed to resolve PostgreSQL workspace invitation")?;
        row.map(workspace_invitation_from_row).transpose()
    }

    pub(super) async fn accept_workspace_invitation(
        &self,
        invitation_id: &str,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = super::validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject =
            super::validate_external_identity_component(subject, "identity subject", 255)?;
        let now = now_unix();
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL workspace invitation acceptance")?;
        let invitation = self
            .bounded(transaction.query_opt(
                "SELECT invitations.id, invitations.organization_id,
                        invitations.workspace_id, invitations.recipient_label,
                        invitations.role, invitations.created_by_principal_id,
                        invitations.active, invitations.expires_at_unix,
                        invitations.created_at_unix, invitations.revoked_at_unix,
                        invitations.accepted_by_principal_id, invitations.accepted_at_unix
                 FROM workspace_invitations AS invitations
                 JOIN organizations ON organizations.id = invitations.organization_id
                 JOIN workspaces
                   ON workspaces.id = invitations.workspace_id
                  AND workspaces.organization_id = invitations.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 LEFT JOIN organization_oidc_connections AS oidc_connections
                   ON oidc_connections.organization_id = organizations.id
                  AND oidc_connections.issuer = $5
                 LEFT JOIN organization_saml_connections AS saml_connections
                   ON saml_connections.organization_id = organizations.id
                  AND saml_connections.entity_id = $5
                 WHERE invitations.id = $1
                   AND invitations.organization_id = $2
                   AND invitations.workspace_id = $3
                   AND (($4 = 'oidc' AND oidc_connections.organization_id IS NOT NULL)
                        OR ($4 = 'saml' AND saml_connections.organization_id IS NOT NULL))
                   AND invitations.active = TRUE
                   AND invitations.revoked_at_unix IS NULL
                   AND invitations.accepted_at_unix IS NULL
                   AND invitations.expires_at_unix >= $6
                   AND organizations.active = TRUE AND workspaces.active = TRUE
                   AND tenants.active = TRUE
                   AND (($4 = 'oidc' AND oidc_connections.active = TRUE)
                        OR ($4 = 'saml' AND saml_connections.active = TRUE))
                 FOR UPDATE OF invitations",
                &[
                    &invitation_id,
                    &organization_id,
                    &workspace_id,
                    &federation.as_storage(),
                    &issuer,
                    &now,
                ],
            ))
            .await
            .context("failed to load PostgreSQL invitation for acceptance")?
            .map(workspace_invitation_from_row)
            .transpose()?;
        let Some(invitation) = invitation else {
            self.bounded(transaction.commit())
                .await
                .context("failed to commit unavailable invitation lookup")?;
            return Ok(None);
        };
        self.bounded(transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))",
            &[&issuer, &subject],
        ))
        .await
        .context("failed to lock PostgreSQL invitation identity")?;
        let existing_principal = self
            .bounded(transaction.query_opt(
                "SELECT principals.id, principals.active,
                        CASE WHEN scim_users.id IS NULL THEN TRUE
                             WHEN scim_users.organization_id = $3 AND scim_users.active = TRUE
                             THEN TRUE ELSE FALSE END
                 FROM workspace_external_identities AS identities
                 JOIN workspace_principals AS principals
                   ON principals.id = identities.principal_id
                 LEFT JOIN scim_users ON scim_users.id = principals.id
                 WHERE identities.issuer = $1 AND identities.subject = $2",
                &[&issuer, &subject, &invitation.organization_id],
            ))
            .await
            .context("failed to resolve PostgreSQL invitation federated identity")?;
        let principal_id = match existing_principal {
            Some(row) if !row.get::<_, bool>(1) || !row.get::<_, bool>(2) => {
                self.bounded(transaction.commit())
                    .await
                    .context("failed to commit unavailable invitation identity lookup")?;
                return Ok(None);
            }
            Some(row) => row.get::<_, String>(0),
            None => {
                let principal_id = random_id("principal");
                self.bounded(transaction.execute(
                    "INSERT INTO workspace_principals (id, name, active, created_at_unix)
                     VALUES ($1, $2, TRUE, $3)",
                    &[&principal_id, &invitation.recipient_label, &now],
                ))
                .await
                .context("failed to create PostgreSQL invited principal")?;
                self.bounded(transaction.execute(
                    "INSERT INTO workspace_external_identities
                        (issuer, subject, principal_id, created_at_unix)
                     VALUES ($1, $2, $3, $4)",
                    &[&issuer, &subject, &principal_id, &now],
                ))
                .await
                .context("failed to bind PostgreSQL invited federated identity")?;
                principal_id
            }
        };
        let membership_exists = self
            .bounded(transaction.query_opt(
                "SELECT 1 FROM workspace_memberships
                 WHERE workspace_id = $1 AND principal_id = $2",
                &[&invitation.workspace_id, &principal_id],
            ))
            .await
            .context("failed to check PostgreSQL invited membership")?
            .is_some();
        if membership_exists {
            self.bounded(transaction.commit())
                .await
                .context("failed to commit existing invitation membership lookup")?;
            return Ok(None);
        }
        self.bounded(transaction.execute(
            "INSERT INTO workspace_memberships
                (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
             VALUES ($1, $2, $3, TRUE, $4, $4)",
            &[
                &invitation.workspace_id,
                &principal_id,
                &invitation.role.storage_value(),
                &now,
            ],
        ))
        .await
        .context("failed to create PostgreSQL invited membership")?;
        let consumed = self
            .bounded(transaction.execute(
                "UPDATE workspace_invitations
                 SET active = FALSE, accepted_by_principal_id = $2, accepted_at_unix = $3
                 WHERE id = $1 AND active = TRUE AND accepted_at_unix IS NULL
                   AND expires_at_unix >= $3",
                &[&invitation.id, &principal_id, &now],
            ))
            .await
            .context("failed to consume PostgreSQL workspace invitation")?;
        if consumed != 1 {
            self.bounded(transaction.rollback())
                .await
                .context("failed to roll back raced workspace invitation")?;
            return Ok(None);
        }
        self.bounded(transaction.execute(
            "INSERT INTO workspace_admin_audit
                (organization_id, workspace_id, actor_principal_id, action,
                 target_principal_id, created_at_unix)
             VALUES ($1, $2, $3, 'invitation.accept', $3, $4)",
            &[
                &invitation.organization_id,
                &invitation.workspace_id,
                &principal_id,
                &now,
            ],
        ))
        .await
        .context("failed to audit PostgreSQL invitation acceptance")?;
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL invitation acceptance")?;
        Ok(Some(VerifiedWorkspaceAccess {
            organization_id: invitation.organization_id,
            workspace_id: invitation.workspace_id,
            principal_id,
            role: invitation.role,
        }))
    }

    pub(super) async fn list_workspace_scim_users_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimUser>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT scim_users.id, scim_users.display_name
                 FROM scim_users
                 WHERE scim_users.organization_id = (
                     SELECT workspaces.organization_id
                     FROM workspaces
                     JOIN organizations ON organizations.id = workspaces.organization_id
                     JOIN tenants ON tenants.id = workspaces.tenant_id
                     JOIN workspace_principals
                       ON workspace_principals.id = $2
                     JOIN workspace_memberships
                       ON workspace_memberships.workspace_id = workspaces.id
                      AND workspace_memberships.principal_id = workspace_principals.id
                     WHERE workspaces.id = $1
                       AND workspace_memberships.role = 'owner'
                       AND workspace_memberships.active = TRUE
                       AND organizations.active = TRUE
                       AND tenants.active = TRUE
                       AND workspaces.active = TRUE
                       AND workspace_principals.active = TRUE
                 )
                   AND scim_users.active = TRUE
                 ORDER BY scim_users.display_name ASC, scim_users.id ASC",
                &[&workspace_id, &actor_principal_id],
            ))
            .await
            .context("failed to query workspace SCIM directory")?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceScimUser {
                principal_id: row.get(0),
                display_name: row.get(1),
            })
            .collect())
    }

    pub(super) async fn assign_scim_user_to_workspace_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH workspace_lock AS MATERIALIZED (
                    SELECT pg_advisory_xact_lock(hashtextextended($1, 0))
                 ), authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals
                      ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    CROSS JOIN workspace_lock
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                 ), target AS MATERIALIZED (
                    SELECT scim_users.id
                    FROM scim_users
                    JOIN workspace_principals ON workspace_principals.id = scim_users.id
                    JOIN authorized ON authorized.organization_id = scim_users.organization_id
                    WHERE scim_users.id = $3
                      AND scim_users.active = TRUE
                      AND workspace_principals.active = TRUE
                 ), saved AS (
                    INSERT INTO workspace_memberships
                        (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
                    SELECT $1, target.id, $4, TRUE, $5, $5 FROM target
                    ON CONFLICT (workspace_id, principal_id) DO UPDATE SET
                        role = excluded.role,
                        active = TRUE,
                        updated_at_unix = excluded.updated_at_unix
                    RETURNING workspace_id, principal_id, role, active, created_at_unix,
                              updated_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT authorized.organization_id, $1, $2, 'membership.assign_scim', $3, $5
                    FROM authorized
                    CROSS JOIN saved
                 )
                 SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM saved",
                &[
                    &workspace_id,
                    &actor_principal_id,
                    &target_principal_id,
                    &role.storage_value(),
                    &now,
                ],
            ))
            .await
            .context("failed to save SCIM workspace assignment")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "customer workspace action is not permitted or SCIM user is unavailable"
                )
            })?;
        workspace_membership_from_row(row)
    }

    pub(super) async fn list_workspace_scim_groups_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroup>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT scim_groups.id, scim_groups.display_name
                 FROM scim_groups
                 WHERE scim_groups.organization_id = (
                     SELECT workspaces.organization_id
                     FROM workspaces
                     JOIN organizations ON organizations.id = workspaces.organization_id
                     JOIN tenants ON tenants.id = workspaces.tenant_id
                     JOIN workspace_principals ON workspace_principals.id = $2
                     JOIN workspace_memberships
                       ON workspace_memberships.workspace_id = workspaces.id
                      AND workspace_memberships.principal_id = workspace_principals.id
                     WHERE workspaces.id = $1
                       AND workspace_memberships.role = 'owner'
                       AND workspace_memberships.active = TRUE
                       AND organizations.active = TRUE
                       AND tenants.active = TRUE
                       AND workspaces.active = TRUE
                       AND workspace_principals.active = TRUE
                 ) AND scim_groups.active = TRUE
                 ORDER BY scim_groups.display_name ASC, scim_groups.id ASC",
                &[&workspace_id, &actor_principal_id],
            ))
            .await
            .context("failed to query workspace SCIM group directory")?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceScimGroup {
                group_id: row.get(0),
                display_name: row.get(1),
            })
            .collect())
    }

    pub(super) async fn list_workspace_scim_group_mappings_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroupMapping>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT mappings.workspace_id, mappings.group_id, scim_groups.display_name,
                        mappings.created_at_unix, mappings.updated_at_unix
                 FROM workspace_scim_group_mappings AS mappings
                 JOIN scim_groups ON scim_groups.id = mappings.group_id
                 WHERE mappings.workspace_id = $1
                   AND EXISTS (
                       SELECT 1 FROM workspaces
                       JOIN organizations ON organizations.id = workspaces.organization_id
                       JOIN tenants ON tenants.id = workspaces.tenant_id
                       JOIN workspace_principals ON workspace_principals.id = $2
                       JOIN workspace_memberships
                         ON workspace_memberships.workspace_id = workspaces.id
                        AND workspace_memberships.principal_id = workspace_principals.id
                       WHERE workspaces.id = mappings.workspace_id
                         AND workspace_memberships.role = 'owner'
                         AND workspace_memberships.active = TRUE
                         AND organizations.active = TRUE
                         AND tenants.active = TRUE
                         AND workspaces.active = TRUE
                         AND workspace_principals.active = TRUE
                   )
                 ORDER BY scim_groups.display_name ASC, mappings.group_id ASC",
                &[&workspace_id, &actor_principal_id],
            ))
            .await
            .context("failed to query workspace SCIM group mappings")?;
        Ok(rows
            .into_iter()
            .map(|row| WorkspaceScimGroupMapping {
                workspace_id: row.get(0),
                group_id: row.get(1),
                group_display_name: row.get(2),
                role: WorkspaceRole::Analyst,
                created_at_unix: row.get(3),
                updated_at_unix: row.get(4),
            })
            .collect())
    }

    pub(super) async fn create_workspace_scim_group_mapping_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = super::validate_scim_group_id(group_id)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_one(
                "WITH workspace_lock AS MATERIALIZED (
                    SELECT pg_advisory_xact_lock(hashtextextended($1, 0))
                 ), authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    CROSS JOIN workspace_lock
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                 ), valid_group AS MATERIALIZED (
                    SELECT scim_groups.id, authorized.organization_id
                    FROM scim_groups
                    JOIN authorized ON authorized.organization_id = scim_groups.organization_id
                    WHERE scim_groups.id = $3 AND scim_groups.active = TRUE
                 ), inserted AS (
                    INSERT INTO workspace_scim_group_mappings
                        (workspace_id, group_id, created_at_unix, updated_at_unix)
                    SELECT $1, id, $4, $4 FROM valid_group
                    ON CONFLICT(workspace_id, group_id) DO NOTHING
                    RETURNING group_id
                 ), audited AS (
                    INSERT INTO workspace_scim_group_mapping_audit
                        (organization_id, workspace_id, actor_principal_id, group_id, action,
                         created_at_unix)
                    SELECT valid_group.organization_id, $1, $2, inserted.group_id,
                           'group_mapping.create', $4
                    FROM valid_group CROSS JOIN inserted
                 )
                 SELECT EXISTS(SELECT 1 FROM valid_group)",
                &[&workspace_id, &actor_principal_id, &group_id, &now],
            ))
            .await
            .context("failed to create SCIM group mapping")?;
        Ok(row.get(0))
    }

    pub(super) async fn delete_workspace_scim_group_mapping_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = super::validate_scim_group_id(group_id)?;
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_one(
                "WITH workspace_lock AS MATERIALIZED (
                    SELECT pg_advisory_xact_lock(hashtextextended($1, 0))
                 ), authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    CROSS JOIN workspace_lock
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                 ), deleted AS (
                    DELETE FROM workspace_scim_group_mappings
                    USING authorized, scim_groups
                    WHERE workspace_scim_group_mappings.workspace_id = $1
                      AND workspace_scim_group_mappings.group_id = $3
                      AND scim_groups.id = workspace_scim_group_mappings.group_id
                      AND scim_groups.organization_id = authorized.organization_id
                    RETURNING workspace_scim_group_mappings.group_id, authorized.organization_id
                 ), audited AS (
                    INSERT INTO workspace_scim_group_mapping_audit
                        (organization_id, workspace_id, actor_principal_id, group_id, action,
                         created_at_unix)
                    SELECT organization_id, $1, $2, group_id, 'group_mapping.delete', $4
                    FROM deleted
                 )
                 SELECT EXISTS(SELECT 1 FROM deleted)",
                &[&workspace_id, &actor_principal_id, &group_id, &now],
            ))
            .await
            .context("failed to delete SCIM group mapping")?;
        Ok(row.get(0))
    }

    pub(super) async fn update_workspace_membership_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
        active: bool,
    ) -> anyhow::Result<WorkspaceMembership> {
        let now = now_unix();
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH workspace_lock AS MATERIALIZED (
                    SELECT pg_advisory_xact_lock(hashtextextended($1, 0))
                 ), authorized AS MATERIALIZED (
                    SELECT workspaces.organization_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals
                      ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    CROSS JOIN workspace_lock
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspaces.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                 ), target AS MATERIALIZED (
                    SELECT workspace_memberships.workspace_id, workspace_memberships.principal_id,
                           workspace_memberships.role AS previous_role,
                           workspace_memberships.active AS previous_active
                    FROM workspace_memberships
                    JOIN workspace_principals
                      ON workspace_principals.id = workspace_memberships.principal_id
                    LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                    JOIN authorized ON TRUE
                    WHERE workspace_memberships.workspace_id = $1
                      AND workspace_memberships.principal_id = $3
                      AND workspace_principals.active = TRUE
                      AND (scim_users.id IS NULL OR
                           (scim_users.organization_id = authorized.organization_id
                            AND scim_users.active = TRUE))
                 ), allowed_target AS (
                    SELECT * FROM target
                    WHERE NOT (
                        previous_active = TRUE
                        AND previous_role = 'owner'
                        AND ($5 = FALSE OR $4 <> 'owner')
                        AND (SELECT COUNT(*) FROM workspace_memberships
                             WHERE workspace_id = $1
                               AND active = TRUE
                               AND role = 'owner') <= 1
                    )
                 ), saved AS (
                    UPDATE workspace_memberships
                    SET role = $4, active = $5, updated_at_unix = $6
                    FROM allowed_target
                    WHERE workspace_memberships.workspace_id = allowed_target.workspace_id
                      AND workspace_memberships.principal_id = allowed_target.principal_id
                    RETURNING workspace_memberships.workspace_id, workspace_memberships.principal_id,
                              workspace_memberships.role, workspace_memberships.active,
                              workspace_memberships.created_at_unix,
                              workspace_memberships.updated_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT authorized.organization_id, $1, $2, 'membership.update', $3, $6
                    FROM authorized
                    CROSS JOIN saved
                 )
                 SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM saved",
                &[
                    &workspace_id,
                    &actor_principal_id,
                    &target_principal_id,
                    &role.storage_value(),
                    &active,
                    &now,
                ],
            ))
            .await
            .context("failed to save customer workspace membership")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "customer workspace action is not permitted, target is unavailable, or it would remove the last owner"
                )
            })?;
        workspace_membership_from_row(row)
    }

    pub(super) async fn workspace_permits(
        &self,
        principal_id: &str,
        workspace_id: &str,
        permission: WorkspacePermission,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT role FROM (
                    SELECT workspace_memberships.role AS role
                    FROM workspace_memberships
                    JOIN workspaces ON workspaces.id = workspace_memberships.workspace_id
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN workspace_principals
                      ON workspace_principals.id = workspace_memberships.principal_id
                    LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                    WHERE workspace_memberships.workspace_id = $1
                      AND workspace_memberships.principal_id = $2
                      AND workspace_memberships.active = TRUE
                      AND organizations.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND (scim_users.id IS NULL OR
                           (scim_users.organization_id = organizations.id
                            AND scim_users.active = TRUE))
                    UNION
                    SELECT 'analyst' AS role
                    FROM workspace_scim_group_mappings
                    JOIN workspaces ON workspaces.id = workspace_scim_group_mappings.workspace_id
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN scim_groups
                      ON scim_groups.id = workspace_scim_group_mappings.group_id
                     AND scim_groups.organization_id = organizations.id
                    JOIN scim_group_members
                      ON scim_group_members.group_id = scim_groups.id
                     AND scim_group_members.principal_id = workspace_principals.id
                    JOIN scim_users
                      ON scim_users.id = workspace_principals.id
                     AND scim_users.organization_id = organizations.id
                    WHERE workspace_scim_group_mappings.workspace_id = $1
                      AND organizations.active = TRUE
                      AND workspaces.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND scim_groups.active = TRUE
                      AND scim_users.active = TRUE
                 )",
                &[&workspace_id, &principal_id],
            ))
            .await
            .context("failed to authorize workspace action")?;
        rows.into_iter()
            .map(|row| WorkspaceRole::from_storage(&row.get::<_, String>(0)))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(|roles| roles.into_iter().any(|role| role.permits(permission)))
    }

    pub(super) async fn list_workspace_admin_audit(
        &self,
        workspace_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WorkspaceAdminAuditEvent>> {
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded workspace audit limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, organization_id, workspace_id, actor_principal_id, action,
                        target_principal_id, created_at_unix
                 FROM workspace_admin_audit
                 WHERE workspace_id = $1
                 ORDER BY id DESC LIMIT $2",
                &[&workspace_id, &limit],
            ))
            .await
            .context("failed to query workspace admin audit events")?;
        rows.into_iter()
            .map(workspace_admin_audit_from_row)
            .collect()
    }

    pub(super) async fn set_tenant_active(
        &self,
        tenant_id: &str,
        active: bool,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE tenants SET active = $1 WHERE id = $2",
                &[&active, &tenant_id],
            ))
            .await
            .context("failed to update tenant state")?;
        Ok(changed == 1)
    }

    pub(super) async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute("DELETE FROM tenants WHERE id = $1", &[&tenant_id]))
            .await
            .context("failed to delete tenant")?;
        Ok(changed == 1)
    }

    pub(super) async fn create_admin(
        &self,
        name: &str,
        role: AdminRole,
    ) -> anyhow::Result<IssuedAdminToken> {
        let admin = ControlPlaneAdmin {
            id: random_id("admin"),
            name: validate_label(name, "admin name", 128)?,
            role,
            active: true,
            created_at_unix: now_unix(),
        };
        let token = generate_admin_token();
        let token_hash = token_hash(&token);
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO control_plane_admins
                (id, name, token_hash, role, active, created_at_unix)
             VALUES ($1, $2, $3, $4, TRUE, $5)",
            &[
                &admin.id,
                &admin.name,
                &token_hash,
                &admin.role.storage_value(),
                &admin.created_at_unix,
            ],
        ))
        .await
        .context("failed to create control-plane admin")?;
        Ok(IssuedAdminToken { admin, token })
    }

    pub(super) async fn list_admins(&self) -> anyhow::Result<Vec<ControlPlaneAdmin>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, name, role, active, created_at_unix
                 FROM control_plane_admins ORDER BY created_at_unix ASC, id ASC",
                &[],
            ))
            .await
            .context("failed to query control-plane admins")?;
        rows.iter().map(control_plane_admin_from_row).collect()
    }

    pub(super) async fn revoke_admin(&self, admin_id: &str) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE control_plane_admins
                 SET active = FALSE, revoked_at_unix = $1
                 WHERE id = $2 AND active = TRUE",
                &[&now_unix(), &admin_id],
            ))
            .await
            .context("failed to revoke control-plane admin")?;
        Ok(changed == 1)
    }

    pub(super) async fn authenticate_admin_bearer(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<AdminIdentity>> {
        let Some(token) = presented_header.and_then(|value| value.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        if token.is_empty() {
            return Ok(None);
        }
        let token_hash = token_hash(token);
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT id, name, role FROM control_plane_admins
                 WHERE token_hash = $1 AND active = TRUE",
                &[&token_hash],
            ))
            .await
            .context("failed to authenticate control-plane admin")?;
        row.map(admin_identity_from_row).transpose()
    }

    pub(super) async fn issue_token(
        &self,
        tenant_id: &str,
        label: &str,
    ) -> anyhow::Result<IssuedToken> {
        let client = self.checkout().await?;
        let active = self
            .bounded(client.query_opt("SELECT active FROM tenants WHERE id = $1", &[&tenant_id]))
            .await
            .context("failed to look up tenant")?;
        match active.map(|row| row.get::<_, bool>(0)) {
            Some(true) => {}
            Some(false) => bail!("cannot issue a token for an inactive tenant"),
            None => bail!("tenant not found"),
        }

        let issued = IssuedToken {
            id: random_id("token"),
            tenant_id: tenant_id.to_owned(),
            label: validate_label(label, "token label", 128)?,
            token: generate_token(),
            created_at_unix: now_unix(),
        };
        let token_hash = token_hash(&issued.token);
        self.bounded(client.execute(
            "INSERT INTO tenant_tokens
                (id, tenant_id, token_hash, label, active, created_at_unix)
             VALUES ($1, $2, $3, $4, TRUE, $5)",
            &[
                &issued.id,
                &issued.tenant_id,
                &token_hash,
                &issued.label,
                &issued.created_at_unix,
            ],
        ))
        .await
        .context("failed to issue tenant token")?;
        Ok(issued)
    }

    pub(super) async fn revoke_token(&self, token_id: &str) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE tenant_tokens
                 SET active = FALSE, revoked_at_unix = $1
                 WHERE id = $2 AND active = TRUE",
                &[&now_unix(), &token_id],
            ))
            .await
            .context("failed to revoke tenant token")?;
        Ok(changed == 1)
    }

    pub(super) async fn list_tokens(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToken>> {
        self.require_tenant(tenant_id).await?;
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, label, active, created_at_unix, revoked_at_unix
                 FROM tenant_tokens WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id DESC",
                &[&tenant_id],
            ))
            .await
            .context("failed to query tenant token inventory")?;
        rows.iter().map(tenant_token_from_row).collect()
    }

    pub(super) async fn limits_for(&self, tenant_id: &str) -> anyhow::Result<TenantLimits> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT rate_limit_requests_per_window,
                        rate_limit_window_seconds,
                        spend_limit_window_seconds,
                        spend_limit_max_usd_micros,
                        spend_limit_reserve_usd_micros_per_request
                 FROM tenant_limits WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load tenant limits")?;
        row.map(limits_from_row)
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    pub(super) async fn set_limits(
        &self,
        tenant_id: &str,
        limits: TenantLimits,
    ) -> anyhow::Result<()> {
        validate_limits(&limits)?;
        self.require_tenant(tenant_id).await?;
        let rate_requests = limits
            .rate_limit
            .as_ref()
            .map(|rate| i64::from(rate.requests_per_window));
        let rate_window = limits
            .rate_limit
            .as_ref()
            .map(|rate| postgres_integer(rate.window_seconds, "tenant rate window"))
            .transpose()?;
        let spend_window = limits
            .spend_limit
            .as_ref()
            .map(|spend| postgres_integer(spend.window_seconds, "tenant spend window"))
            .transpose()?;
        let spend_max = limits
            .spend_limit
            .as_ref()
            .map(|spend| postgres_integer(spend.max_usd_micros, "tenant spend budget"))
            .transpose()?;
        let spend_reserve = limits
            .spend_limit
            .as_ref()
            .map(|spend| {
                postgres_integer(
                    spend.reserve_usd_micros_per_request,
                    "tenant spend reservation",
                )
            })
            .transpose()?;
        let updated_at = now_unix();
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO tenant_limits (
                tenant_id,
                rate_limit_requests_per_window,
                rate_limit_window_seconds,
                spend_limit_window_seconds,
                spend_limit_max_usd_micros,
                spend_limit_reserve_usd_micros_per_request,
                updated_at_unix
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(tenant_id) DO UPDATE SET
                rate_limit_requests_per_window = excluded.rate_limit_requests_per_window,
                rate_limit_window_seconds = excluded.rate_limit_window_seconds,
                spend_limit_window_seconds = excluded.spend_limit_window_seconds,
                spend_limit_max_usd_micros = excluded.spend_limit_max_usd_micros,
                spend_limit_reserve_usd_micros_per_request = excluded.spend_limit_reserve_usd_micros_per_request,
                updated_at_unix = excluded.updated_at_unix",
            &[
                &tenant_id,
                &rate_requests,
                &rate_window,
                &spend_window,
                &spend_max,
                &spend_reserve,
                &updated_at,
            ],
        ))
        .await
        .context("failed to save tenant limits")?;
        Ok(())
    }

    pub(super) async fn set_workspace_limits(
        &self,
        workspace_id: &str,
        principal_id: &str,
        limits: TenantLimits,
    ) -> anyhow::Result<()> {
        validate_limits(&limits)?;
        let rate_requests = limits
            .rate_limit
            .as_ref()
            .map(|rate| i64::from(rate.requests_per_window));
        let rate_window = limits
            .rate_limit
            .as_ref()
            .map(|rate| postgres_integer(rate.window_seconds, "customer rate window"))
            .transpose()?;
        let spend_window = limits
            .spend_limit
            .as_ref()
            .map(|spend| postgres_integer(spend.window_seconds, "customer spend window"))
            .transpose()?;
        let spend_max = limits
            .spend_limit
            .as_ref()
            .map(|spend| postgres_integer(spend.max_usd_micros, "customer spend budget"))
            .transpose()?;
        let spend_reserve = limits
            .spend_limit
            .as_ref()
            .map(|spend| {
                postgres_integer(
                    spend.reserve_usd_micros_per_request,
                    "customer spend reservation",
                )
            })
            .transpose()?;
        let now = now_unix();
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "WITH authorized AS (
                    SELECT workspaces.organization_id, workspaces.tenant_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role IN ('owner', 'admin')
                      AND workspaces.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                 ), saved AS (
                    INSERT INTO tenant_limits (
                        tenant_id, rate_limit_requests_per_window, rate_limit_window_seconds,
                        spend_limit_window_seconds, spend_limit_max_usd_micros,
                        spend_limit_reserve_usd_micros_per_request, updated_at_unix
                    ) SELECT tenant_id, $3, $4, $5, $6, $7, $8 FROM authorized
                    ON CONFLICT(tenant_id) DO UPDATE SET
                        rate_limit_requests_per_window = excluded.rate_limit_requests_per_window,
                        rate_limit_window_seconds = excluded.rate_limit_window_seconds,
                        spend_limit_window_seconds = excluded.spend_limit_window_seconds,
                        spend_limit_max_usd_micros = excluded.spend_limit_max_usd_micros,
                        spend_limit_reserve_usd_micros_per_request = excluded.spend_limit_reserve_usd_micros_per_request,
                        updated_at_unix = excluded.updated_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, 'limits.set', NULL, $8 FROM authorized
                 )
                 SELECT 1 FROM authorized",
                &[
                    &workspace_id,
                    &principal_id,
                    &rate_requests,
                    &rate_window,
                    &spend_window,
                    &spend_max,
                    &spend_reserve,
                    &now,
                ],
            ))
            .await
            .context("failed to save customer limits")?;
        if changed != 1 {
            bail!("customer workspace action is not permitted");
        }
        Ok(())
    }

    pub(super) async fn create_policy_version(
        &self,
        tenant_id: &str,
        actor_id: &str,
        document: TenantPolicyDocument,
    ) -> anyhow::Result<TenantPolicyVersion> {
        validate_usage_text(actor_id, "policy actor ID", 256)?;
        let (document_json, content_sha256) = canonical_policy_document(&document)?;
        let id = random_id("policy");
        let created_at_unix = now_unix();
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL policy-version transaction")?;
        let tenant_exists = self
            .bounded(transaction.query_opt(
                "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
                &[&tenant_id],
            ))
            .await
            .context("failed to lock PostgreSQL tenant for policy version")?
            .is_some();
        if !tenant_exists {
            bail!("tenant not found");
        }
        let sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_versions WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL policy sequence")?;
        let sequence_db: i64 = sequence_row.get(0);
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_versions
                (id, tenant_id, sequence, document_json, content_sha256,
                 created_by, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &id,
                &tenant_id,
                &sequence_db,
                &document_json,
                &content_sha256,
                &actor_id,
                &created_at_unix,
            ],
        ))
        .await
        .context("failed to append PostgreSQL tenant policy version")?;
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL policy version")?;
        Ok(TenantPolicyVersion {
            id,
            tenant_id: tenant_id.to_owned(),
            sequence: nonnegative_postgres_integer(sequence_db, "policy sequence")?,
            document,
            content_sha256,
            created_by: actor_id.to_owned(),
            created_at_unix,
            approved_by: None,
            approved_at_unix: None,
            active: false,
        })
    }

    pub(super) async fn list_policy_versions(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyVersion>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded policy-version limit fits PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT versions.id, versions.tenant_id, versions.sequence,
                        versions.document_json, versions.content_sha256,
                        versions.created_by, versions.created_at_unix,
                        approvals.approved_by, approvals.approved_at_unix,
                        (state.active_version_id = versions.id)
                 FROM tenant_policy_versions AS versions
                 LEFT JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 LEFT JOIN tenant_policy_state AS state
                   ON state.tenant_id = versions.tenant_id
                 WHERE versions.tenant_id = $1
                 ORDER BY versions.sequence DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL policy versions")?;
        rows.iter().map(policy_version_from_row).collect()
    }

    pub(super) async fn policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
    ) -> anyhow::Result<Option<TenantPolicyVersion>> {
        let client = self.checkout().await?;
        self.bounded(client.query_opt(
            "SELECT versions.id, versions.tenant_id, versions.sequence,
                    versions.document_json, versions.content_sha256,
                    versions.created_by, versions.created_at_unix,
                    approvals.approved_by, approvals.approved_at_unix,
                    (state.active_version_id = versions.id)
             FROM tenant_policy_versions AS versions
             LEFT JOIN tenant_policy_approvals AS approvals
               ON approvals.version_id = versions.id
             LEFT JOIN tenant_policy_state AS state
               ON state.tenant_id = versions.tenant_id
             WHERE versions.tenant_id = $1 AND versions.id = $2",
            &[&tenant_id, &version_id],
        ))
        .await
        .context("failed to load PostgreSQL policy version")?
        .as_ref()
        .map(policy_version_from_row)
        .transpose()
    }

    pub(super) async fn approve_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<TenantPolicyVersion> {
        validate_usage_text(actor_id, "policy approver ID", 256)?;
        let now = now_unix();
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL policy approval")?;
        let row = self
            .bounded(transaction.query_opt(
                "SELECT approvals.approved_by
                 FROM tenant_policy_versions AS versions
                 LEFT JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 WHERE versions.tenant_id = $1 AND versions.id = $2
                 FOR UPDATE OF versions",
                &[&tenant_id, &version_id],
            ))
            .await
            .context("failed to load PostgreSQL policy approval")?
            .ok_or_else(|| anyhow::anyhow!("policy version not found"))?;
        let existing: Option<String> = row.get(0);
        match existing {
            Some(existing) if existing != actor_id => {
                bail!("policy version was already approved by another actor")
            }
            Some(_) => {}
            None => {
                self.bounded(transaction.execute(
                    "INSERT INTO tenant_policy_approvals
                        (version_id, approved_by, approved_at_unix)
                     VALUES ($1, $2, $3)",
                    &[&version_id, &actor_id, &now],
                ))
                .await
                .context("failed to approve PostgreSQL policy version")?;
            }
        }
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL policy approval")?;
        drop(client);
        self.policy_version(tenant_id, version_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("policy version not found after approval"))
    }

    pub(super) async fn deploy_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
        action: PolicyDeploymentAction,
    ) -> anyhow::Result<TenantPolicyDeployment> {
        validate_usage_text(actor_id, "policy deployment actor ID", 256)?;
        let now = now_unix();
        let deployment_id = random_id("policy_deployment");
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL policy deployment")?;
        self.bounded(transaction.query_one(
            "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
            &[&tenant_id],
        ))
        .await
        .context("failed to lock PostgreSQL tenant for policy deployment")?;
        let version_row = self
            .bounded(transaction.query_opt(
                "SELECT versions.document_json
                 FROM tenant_policy_versions AS versions
                 JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 WHERE versions.tenant_id = $1 AND versions.id = $2",
                &[&tenant_id, &version_id],
            ))
            .await
            .context("failed to load approved PostgreSQL policy version")?
            .ok_or_else(|| anyhow::anyhow!("approved policy version not found"))?;
        let document: TenantPolicyDocument = serde_json::from_str(&version_row.get::<_, String>(0))
            .context("stored tenant policy version is invalid")?;
        validate_policy_document(&document)?;
        let previous_version_id = self
            .bounded(transaction.query_opt(
                "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load active PostgreSQL policy version")?
            .map(|row| row.get::<_, String>(0));
        if previous_version_id.as_deref() == Some(version_id) {
            bail!("policy version is already active");
        }
        if action == PolicyDeploymentAction::Rollback {
            let was_deployed = self
                .bounded(transaction.query_opt(
                    "SELECT 1 FROM tenant_policy_deployments
                     WHERE tenant_id = $1 AND version_id = $2 LIMIT 1",
                    &[&tenant_id, &version_id],
                ))
                .await
                .context("failed to verify PostgreSQL rollback target")?
                .is_some();
            if !was_deployed {
                bail!("rollback target has never been deployed");
            }
        }
        match &document.model_policy {
            Some(policy) => {
                let encoded = serde_json::to_string(policy)
                    .context("failed to encode active model policy")?;
                self.bounded(transaction.execute(
                    "INSERT INTO tenant_model_policies
                        (tenant_id, allowed_models_json, updated_at_unix)
                     VALUES ($1, $2, $3)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        allowed_models_json = excluded.allowed_models_json,
                        updated_at_unix = excluded.updated_at_unix",
                    &[&tenant_id, &encoded, &now],
                ))
                .await
                .context("failed to materialize PostgreSQL active model policy")?;
            }
            None => {
                self.bounded(transaction.execute(
                    "DELETE FROM tenant_model_policies WHERE tenant_id = $1",
                    &[&tenant_id],
                ))
                .await
                .context("failed to clear PostgreSQL active model policy")?;
            }
        }
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_state (tenant_id, active_version_id, updated_at_unix)
             VALUES ($1, $2, $3)
             ON CONFLICT(tenant_id) DO UPDATE SET
                active_version_id = excluded.active_version_id,
                updated_at_unix = excluded.updated_at_unix",
            &[&tenant_id, &version_id, &now],
        ))
        .await
        .context("failed to update PostgreSQL active policy version")?;
        let deployment_sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_deployments WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL policy deployment sequence")?;
        let deployment_sequence: i64 = deployment_sequence_row.get(0);
        let deployment = TenantPolicyDeployment {
            id: deployment_id,
            tenant_id: tenant_id.to_owned(),
            sequence: nonnegative_postgres_integer(
                deployment_sequence,
                "policy deployment sequence",
            )?,
            version_id: version_id.to_owned(),
            previous_version_id,
            action,
            actor_id: actor_id.to_owned(),
            created_at_unix: now,
        };
        let action_value = action.storage_value();
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_deployments
                (id, tenant_id, sequence, version_id, previous_version_id, action,
                 actor_id, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &deployment.id,
                &tenant_id,
                &deployment_sequence,
                &deployment.version_id,
                &deployment.previous_version_id,
                &action_value,
                &deployment.actor_id,
                &deployment.created_at_unix,
            ],
        ))
        .await
        .context("failed to append PostgreSQL policy deployment")?;
        let event_id = random_id("security_event");
        let (event_json, event_sha256) = canonical_security_event_payload(
            "policy.deployed",
            &super::policy_deployment_security_payload(&deployment),
        )?;
        let event_sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_security_events WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL security event sequence")?;
        let event_sequence: i64 = event_sequence_row.get(0);
        self.bounded(transaction.execute(
            "INSERT INTO tenant_security_events
                (id, tenant_id, sequence, event_type, payload_json,
                 content_sha256, occurred_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &event_id,
                &tenant_id,
                &event_sequence,
                &"policy.deployed",
                &event_json,
                &event_sha256,
                &now,
            ],
        ))
        .await
        .context("failed to append PostgreSQL policy security event")?;
        let destinations = self
            .bounded(transaction.query(
                "SELECT id, event_types_json FROM tenant_webhook_destinations
                 WHERE tenant_id = $1 AND active = TRUE",
                &[&tenant_id],
            ))
            .await
            .context("failed to list PostgreSQL webhook destinations for delivery")?;
        for destination_row in destinations {
            let destination_id: String = destination_row.get(0);
            let event_types: Vec<String> =
                serde_json::from_str(&destination_row.get::<_, String>(1))
                    .context("stored PostgreSQL webhook subscriptions are invalid")?;
            if !event_types
                .iter()
                .any(|event_type| event_type == "policy.deployed")
            {
                continue;
            }
            self.bounded(transaction.execute(
                "INSERT INTO tenant_webhook_deliveries
                    (id, tenant_id, event_id, destination_id, status,
                     attempt_count, next_attempt_at_unix, created_at_unix)
                 VALUES ($1, $2, $3, $4, 'pending', 0, $5, $5)
                 ON CONFLICT(event_id, destination_id) DO NOTHING",
                &[
                    &random_id("webhook_delivery"),
                    &tenant_id,
                    &event_id,
                    &destination_id,
                    &now,
                ],
            ))
            .await
            .context("failed to enqueue PostgreSQL webhook delivery")?;
        }
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL policy deployment")?;
        Ok(deployment)
    }

    pub(super) async fn list_policy_deployments(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyDeployment>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded policy-deployment limit fits PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, sequence, version_id, previous_version_id, action,
                        actor_id, created_at_unix
                 FROM tenant_policy_deployments
                 WHERE tenant_id = $1
                 ORDER BY sequence DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL policy deployments")?;
        rows.iter().map(policy_deployment_from_row).collect()
    }

    pub(super) async fn list_security_events(
        &self,
        tenant_id: &str,
        after_sequence: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantSecurityEvent>> {
        let after_sequence = i64::try_from(after_sequence)
            .context("security-event cursor exceeds PostgreSQL integer range")?;
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded security-event limit fits PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, sequence, event_type, payload_json,
                        content_sha256, occurred_at_unix
                 FROM tenant_security_events
                 WHERE tenant_id = $1 AND sequence > $2
                 ORDER BY sequence ASC LIMIT $3",
                &[&tenant_id, &after_sequence, &limit],
            ))
            .await
            .context("failed to query PostgreSQL security events")?;
        rows.iter().map(security_event_from_row).collect()
    }

    pub(super) async fn create_webhook_destination(
        &self,
        tenant_id: &str,
        url: &str,
        event_types: &[String],
    ) -> anyhow::Result<WebhookDestination> {
        let destination = WebhookDestination {
            id: random_id("webhook"),
            tenant_id: tenant_id.to_owned(),
            url: url.to_owned(),
            event_types: event_types.to_vec(),
            active: true,
            created_at_unix: now_unix(),
            updated_at_unix: now_unix(),
        };
        let event_types_json = serde_json::to_string(&destination.event_types)
            .context("failed to encode webhook event subscriptions")?;
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "INSERT INTO tenant_webhook_destinations
                (id, tenant_id, url, event_types_json, active, created_at_unix, updated_at_unix)
             VALUES ($1, $2, $3, $4, TRUE, $5, $5)",
            &[
                &destination.id,
                &destination.tenant_id,
                &destination.url,
                &event_types_json,
                &destination.created_at_unix,
            ],
        ))
        .await
        .context("failed to create PostgreSQL webhook destination")?;
        Ok(destination)
    }

    pub(super) async fn create_workspace_webhook_destination(
        &self,
        workspace_id: &str,
        principal_id: &str,
        url: &str,
        event_types: &[String],
    ) -> anyhow::Result<WebhookDestination> {
        let id = random_id("webhook");
        let now = now_unix();
        let event_types_json = serde_json::to_string(event_types)
            .context("failed to encode webhook event subscriptions")?;
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH authorized AS (
                    SELECT workspaces.organization_id, workspaces.tenant_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspaces.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                      AND workspace_memberships.role = 'owner'
                 ), inserted AS (
                    INSERT INTO tenant_webhook_destinations
                        (id, tenant_id, url, event_types_json, active,
                         created_at_unix, updated_at_unix)
                    SELECT $3, tenant_id, $4, $5, TRUE, $6, $6
                    FROM authorized
                    RETURNING id, tenant_id, url, event_types_json, active,
                              created_at_unix, updated_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, 'webhook_destination.create', NULL, $6
                    FROM authorized CROSS JOIN inserted
                 )
                 SELECT id, tenant_id, url, event_types_json, active,
                        created_at_unix, updated_at_unix
                 FROM inserted",
                &[
                    &workspace_id,
                    &principal_id,
                    &id,
                    &url,
                    &event_types_json,
                    &now,
                ],
            ))
            .await
            .context("failed to create customer PostgreSQL webhook destination")?;
        let row =
            row.ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        webhook_destination_from_row(&row)
    }

    pub(super) async fn list_webhook_destinations(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<WebhookDestination>> {
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, url, event_types_json, active,
                        created_at_unix, updated_at_unix
                 FROM tenant_webhook_destinations
                 WHERE tenant_id = $1 ORDER BY id ASC",
                &[&tenant_id],
            ))
            .await
            .context("failed to query PostgreSQL webhook destinations")?;
        rows.iter().map(webhook_destination_from_row).collect()
    }

    pub(super) async fn deactivate_webhook_destination(
        &self,
        tenant_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "UPDATE tenant_webhook_destinations
                 SET active = FALSE, updated_at_unix = $3
                 WHERE tenant_id = $1 AND id = $2 AND active = TRUE",
                &[&tenant_id, &destination_id, &now_unix()],
            ))
            .await
            .context("failed to deactivate PostgreSQL webhook destination")?;
        Ok(changed != 0)
    }

    pub(super) async fn deactivate_workspace_webhook_destination(
        &self,
        workspace_id: &str,
        principal_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let client = self.checkout().await?;
        let changed = self
            .bounded(client.execute(
                "WITH authorized AS (
                    SELECT workspaces.organization_id, workspaces.tenant_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspaces.active = TRUE
                      AND organizations.active = TRUE
                      AND tenants.active = TRUE
                      AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                      AND workspace_memberships.role = 'owner'
                 ), changed AS (
                    UPDATE tenant_webhook_destinations
                    SET active = FALSE, updated_at_unix = $4
                    WHERE id = $3 AND active = TRUE
                      AND tenant_id IN (SELECT tenant_id FROM authorized)
                    RETURNING id
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, 'webhook_destination.deactivate', NULL, $4
                    FROM authorized CROSS JOIN changed
                 )
                 SELECT COUNT(*) FROM changed",
                &[&workspace_id, &principal_id, &destination_id, &now],
            ))
            .await
            .context("failed to deactivate customer PostgreSQL webhook destination")?;
        Ok(changed == 1)
    }

    pub(super) async fn list_webhook_deliveries(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WebhookDelivery>> {
        let limit = i64::try_from(limit.clamp(1, 500)).expect("bounded webhook limit fits i64");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, event_id, destination_id, status, attempt_count,
                        next_attempt_at_unix, locked_until_unix, delivered_at_unix,
                        last_http_status, last_error, created_at_unix
                 FROM tenant_webhook_deliveries
                 WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL webhook deliveries")?;
        rows.iter().map(webhook_delivery_from_row).collect()
    }

    pub(super) async fn claim_webhook_delivery(
        &self,
    ) -> anyhow::Result<Option<PendingWebhookDelivery>> {
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL webhook claim")?;
        let now = now_unix();
        let pending = self
            .bounded(transaction.query_opt(
                "SELECT d.id, d.tenant_id, d.event_id, d.destination_id, d.status,
                        d.attempt_count, d.next_attempt_at_unix, d.locked_until_unix,
                        d.delivered_at_unix, d.last_http_status, d.last_error, d.created_at_unix,
                        w.id, w.tenant_id, w.url, w.event_types_json, w.active,
                        w.created_at_unix, w.updated_at_unix,
                        e.id, e.tenant_id, e.sequence, e.event_type, e.payload_json,
                        e.content_sha256, e.occurred_at_unix
                 FROM tenant_webhook_deliveries d
                 JOIN tenant_webhook_destinations w ON w.id = d.destination_id
                 JOIN tenant_security_events e ON e.id = d.event_id
                 WHERE w.active = TRUE
                   AND ((d.status = 'pending' AND d.next_attempt_at_unix <= $1)
                     OR (d.status = 'in_flight' AND d.locked_until_unix <= $1))
                 ORDER BY d.next_attempt_at_unix ASC, d.id ASC
                 LIMIT 1 FOR UPDATE OF d SKIP LOCKED",
                &[&now],
            ))
            .await
            .context("failed to select PostgreSQL webhook delivery")?
            .map(|row| pending_webhook_from_pg_row(&row))
            .transpose()?;
        let Some(mut pending) = pending else {
            self.bounded(transaction.commit())
                .await
                .context("failed to commit empty PostgreSQL webhook claim")?;
            return Ok(None);
        };
        let locked_until = now.saturating_add(30);
        self.bounded(transaction.execute(
            "UPDATE tenant_webhook_deliveries
             SET status = 'in_flight', attempt_count = attempt_count + 1,
                 locked_until_unix = $2
             WHERE id = $1",
            &[&pending.delivery.id, &locked_until],
        ))
        .await
        .context("failed to lock PostgreSQL webhook delivery")?;
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL webhook claim")?;
        pending.delivery.status = WebhookDeliveryStatus::InFlight;
        pending.delivery.attempt_count = pending.delivery.attempt_count.saturating_add(1);
        pending.delivery.locked_until_unix = Some(locked_until);
        Ok(Some(pending))
    }

    pub(super) async fn finish_webhook_delivery(
        &self,
        delivery_id: &str,
        result: WebhookAttemptResult,
    ) -> anyhow::Result<()> {
        let client = self.checkout().await?;
        let attempts = self
            .bounded(client.query_opt(
                "SELECT attempt_count FROM tenant_webhook_deliveries WHERE id = $1",
                &[&delivery_id],
            ))
            .await
            .context("failed to load PostgreSQL webhook attempt count")?
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0);
        let now = now_unix();
        let status = if result.error.is_none() {
            WebhookDeliveryStatus::Delivered
        } else if attempts >= 8 {
            WebhookDeliveryStatus::Dead
        } else {
            WebhookDeliveryStatus::Pending
        };
        let next_attempt = if matches!(status, WebhookDeliveryStatus::Pending) {
            now.saturating_add(5_i64.saturating_mul(1_i64 << attempts.clamp(0, 10)))
        } else {
            now
        };
        let error = result
            .error
            .map(|value| value.chars().take(512).collect::<String>());
        let status_value = status.storage_value();
        self.bounded(client.execute(
            "UPDATE tenant_webhook_deliveries
             SET status = $2, next_attempt_at_unix = $3, locked_until_unix = NULL,
                 delivered_at_unix = CASE WHEN $2 = 'delivered' THEN $4 ELSE delivered_at_unix END,
                 last_http_status = $5, last_error = $6
             WHERE id = $1",
            &[
                &delivery_id,
                &status_value,
                &next_attempt,
                &now,
                &result.http_status.map(i32::from),
                &error,
            ],
        ))
        .await
        .context("failed to update PostgreSQL webhook delivery")?;
        Ok(())
    }

    pub(super) async fn simulate_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        cases: Vec<PolicySimulationCase>,
    ) -> anyhow::Result<TenantPolicySimulation> {
        let candidate = self
            .policy_version(tenant_id, version_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("policy version not found"))?;
        let client = self.checkout().await?;
        let active_version_id = self
            .bounded(client.query_opt(
                "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load active PostgreSQL policy state")?
            .map(|row| row.get::<_, String>(0));
        drop(client);
        let active_document = match active_version_id.as_deref() {
            Some(active_id) => self
                .policy_version(tenant_id, active_id)
                .await?
                .map(|version| version.document),
            None => None,
        };
        let fallback_document = if active_document.is_none() {
            self.model_policy_for(tenant_id)
                .await?
                .map(|policy| TenantPolicyDocument::new(Some(policy)))
        } else {
            None
        };
        evaluate_policy_simulation(
            candidate.id,
            active_version_id,
            active_document.as_ref().or(fallback_document.as_ref()),
            &candidate.document,
            cases,
        )
    }

    pub(super) async fn model_policy_for(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<TenantModelPolicy>> {
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "SELECT allowed_models_json FROM tenant_model_policies WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load tenant model policy")?;
        row.map(|row| {
            serde_json::from_str::<TenantModelPolicy>(&row.get::<_, String>(0))
                .context("stored tenant model policy is invalid")
        })
        .transpose()
    }

    pub(super) async fn set_model_policy(
        &self,
        tenant_id: &str,
        policy: Option<TenantModelPolicy>,
    ) -> anyhow::Result<()> {
        const ACTOR_ID: &str = "internal_control_plane";
        let version = self
            .create_policy_version(tenant_id, ACTOR_ID, TenantPolicyDocument::new(policy))
            .await?;
        self.approve_policy_version(tenant_id, &version.id, ACTOR_ID)
            .await?;
        self.deploy_policy_version(
            tenant_id,
            &version.id,
            ACTOR_ID,
            PolicyDeploymentAction::Activate,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn set_workspace_model_policy(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<TenantModelPolicy>,
    ) -> anyhow::Result<()> {
        let document = TenantPolicyDocument::new(policy);
        let (document_json, content_sha256) = canonical_policy_document(&document)?;
        let encoded_policy = document
            .model_policy
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("failed to encode customer model policy")?;
        let audit_action = if document.model_policy.is_some() {
            "model_policy.set"
        } else {
            "model_policy.clear"
        };
        let now = now_unix();
        let version_id = random_id("policy");
        let deployment_id = random_id("policy_deployment");
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL customer policy transaction")?;
        let authorized = self
            .bounded(transaction.query_opt(
                "SELECT workspaces.organization_id, workspaces.tenant_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = $2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = $1
                   AND workspace_memberships.role = 'owner'
                   AND workspaces.active = TRUE
                   AND organizations.active = TRUE
                   AND tenants.active = TRUE
                   AND workspace_principals.active = TRUE
                   AND workspace_memberships.active = TRUE
                 FOR UPDATE OF tenants",
                &[&workspace_id, &principal_id],
            ))
            .await
            .context("failed to authorize PostgreSQL customer policy mutation")?
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        let organization_id: String = authorized.get(0);
        let tenant_id: String = authorized.get(1);
        let sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_versions WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL customer policy sequence")?;
        let sequence: i64 = sequence_row.get(0);
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_versions
                (id, tenant_id, sequence, document_json, content_sha256,
                 created_by, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &version_id,
                &tenant_id,
                &sequence,
                &document_json,
                &content_sha256,
                &principal_id,
                &now,
            ],
        ))
        .await
        .context("failed to append PostgreSQL customer policy version")?;
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_approvals
                (version_id, approved_by, approved_at_unix)
             VALUES ($1, $2, $3)",
            &[&version_id, &principal_id, &now],
        ))
        .await
        .context("failed to approve PostgreSQL customer policy version")?;
        let previous_version_id = self
            .bounded(transaction.query_opt(
                "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to load active PostgreSQL customer policy version")?
            .map(|row| row.get::<_, String>(0));
        match encoded_policy {
            Some(encoded) => {
                self.bounded(transaction.execute(
                    "INSERT INTO tenant_model_policies
                        (tenant_id, allowed_models_json, updated_at_unix)
                     VALUES ($1, $2, $3)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        allowed_models_json = excluded.allowed_models_json,
                        updated_at_unix = excluded.updated_at_unix",
                    &[&tenant_id, &encoded, &now],
                ))
                .await
                .context("failed to save PostgreSQL customer model policy")?;
            }
            None => {
                self.bounded(transaction.execute(
                    "DELETE FROM tenant_model_policies WHERE tenant_id = $1",
                    &[&tenant_id],
                ))
                .await
                .context("failed to clear PostgreSQL customer model policy")?;
            }
        }
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_state (tenant_id, active_version_id, updated_at_unix)
             VALUES ($1, $2, $3)
             ON CONFLICT(tenant_id) DO UPDATE SET
                active_version_id = excluded.active_version_id,
                updated_at_unix = excluded.updated_at_unix",
            &[&tenant_id, &version_id, &now],
        ))
        .await
        .context("failed to update active PostgreSQL customer policy version")?;
        let deployment_sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_deployments WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL customer policy deployment sequence")?;
        let deployment_sequence: i64 = deployment_sequence_row.get(0);
        let deployment = TenantPolicyDeployment {
            id: deployment_id,
            tenant_id: tenant_id.clone(),
            sequence: nonnegative_postgres_integer(
                deployment_sequence,
                "customer policy deployment sequence",
            )?,
            version_id: version_id.clone(),
            previous_version_id: previous_version_id.clone(),
            action: PolicyDeploymentAction::Activate,
            actor_id: principal_id.to_owned(),
            created_at_unix: now,
        };
        let deployment_action = PolicyDeploymentAction::Activate.storage_value();
        self.bounded(transaction.execute(
            "INSERT INTO tenant_policy_deployments
                (id, tenant_id, sequence, version_id, previous_version_id, action,
                 actor_id, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &deployment.id,
                &deployment.tenant_id,
                &deployment_sequence,
                &deployment.version_id,
                &deployment.previous_version_id,
                &deployment_action,
                &deployment.actor_id,
                &deployment.created_at_unix,
            ],
        ))
        .await
        .context("failed to append PostgreSQL customer policy deployment")?;
        let event_id = random_id("security_event");
        let (event_json, event_sha256) = canonical_security_event_payload(
            "policy.deployed",
            &super::policy_deployment_security_payload(&deployment),
        )?;
        let event_sequence_row = self
            .bounded(transaction.query_one(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_security_events WHERE tenant_id = $1",
                &[&deployment.tenant_id],
            ))
            .await
            .context("failed to allocate PostgreSQL customer security event sequence")?;
        let event_sequence: i64 = event_sequence_row.get(0);
        self.bounded(transaction.execute(
            "INSERT INTO tenant_security_events
                (id, tenant_id, sequence, event_type, payload_json,
                 content_sha256, occurred_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &event_id,
                &deployment.tenant_id,
                &event_sequence,
                &"policy.deployed",
                &event_json,
                &event_sha256,
                &now,
            ],
        ))
        .await
        .context("failed to append PostgreSQL customer policy security event")?;
        let destinations = self
            .bounded(transaction.query(
                "SELECT id, event_types_json FROM tenant_webhook_destinations
                 WHERE tenant_id = $1 AND active = TRUE",
                &[&tenant_id],
            ))
            .await
            .context("failed to list PostgreSQL webhook destinations for delivery")?;
        for destination_row in destinations {
            let destination_id: String = destination_row.get(0);
            let event_types: Vec<String> =
                serde_json::from_str(&destination_row.get::<_, String>(1))
                    .context("stored PostgreSQL webhook subscriptions are invalid")?;
            if !event_types
                .iter()
                .any(|event_type| event_type == "policy.deployed")
            {
                continue;
            }
            self.bounded(transaction.execute(
                "INSERT INTO tenant_webhook_deliveries
                    (id, tenant_id, event_id, destination_id, status,
                     attempt_count, next_attempt_at_unix, created_at_unix)
                 VALUES ($1, $2, $3, $4, 'pending', 0, $5, $5)
                 ON CONFLICT(event_id, destination_id) DO NOTHING",
                &[
                    &random_id("webhook_delivery"),
                    &tenant_id,
                    &event_id,
                    &destination_id,
                    &now,
                ],
            ))
            .await
            .context("failed to enqueue PostgreSQL webhook delivery")?;
        }
        self.bounded(transaction.execute(
            "INSERT INTO workspace_admin_audit
                (organization_id, workspace_id, actor_principal_id, action,
                 target_principal_id, created_at_unix)
             VALUES ($1, $2, $3, $4, NULL, $5)",
            &[
                &organization_id,
                &workspace_id,
                &principal_id,
                &audit_action,
                &now,
            ],
        ))
        .await
        .context("failed to append PostgreSQL customer policy audit event")?;
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL customer policy transaction")?;
        Ok(())
    }

    pub(super) async fn append_audit(
        &self,
        tenant_id: &str,
        path: &str,
        outcome: &str,
        status_code: u16,
        latency_ms: u64,
    ) -> anyhow::Result<()> {
        let created_at = now_unix();
        let status_code = i32::from(status_code);
        let latency_ms = postgres_integer(latency_ms, "tenant audit latency")?;
        let client = self.checkout().await?;
        self.bounded(client.execute(
            "SELECT llm_firewall_append_tenant_audit($1, $2, $3, $4, $5, $6, $7)",
            &[
                &tenant_id,
                &created_at,
                &path,
                &outcome,
                &status_code,
                &latency_ms,
                &self.audit_max_rows,
            ],
        ))
        .await
        .context("failed to append tenant audit event")?;
        Ok(())
    }

    pub(super) async fn list_audit(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantAuditEvent>> {
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded audit limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, created_at_unix, path, outcome, status_code, latency_ms
                 FROM tenant_audit WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query tenant audit history")?;
        rows.iter().map(audit_from_row).collect()
    }

    pub(super) async fn append_usage_event(&self, event: &NewUsageEvent) -> anyhow::Result<bool> {
        validate_usage_event(event)?;
        let input_tokens = optional_postgres_integer(event.input_tokens, "input token count")?;
        let output_tokens = optional_postgres_integer(event.output_tokens, "output token count")?;
        let input_price =
            optional_postgres_integer(event.input_usd_micros_per_million, "input model price")?;
        let output_price =
            optional_postgres_integer(event.output_usd_micros_per_million, "output model price")?;
        let cost = optional_postgres_integer(event.cost_usd_micros, "usage cost")?;
        let token_status = super::usage_token_status_storage_value(event.token_status);
        let pricing_status = super::usage_pricing_status_storage_value(event.pricing_status);
        let client = self.checkout().await?;
        let inserted = self
            .bounded(client.execute(
                "INSERT INTO usage_events
                    (tenant_id, request_id, provider_response_id, provider, path,
                     requested_model, provider_model,
                     input_tokens, output_tokens, token_status, pricing_status,
                     model_price_version, input_usd_micros_per_million,
                     output_usd_micros_per_million, cost_usd_micros, created_at_unix)
                 VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                 ON CONFLICT(tenant_id, request_id) DO NOTHING",
                &[
                    &event.tenant_id,
                    &event.request_id,
                    &event.provider_response_id,
                    &event.provider,
                    &event.path,
                    &event.requested_model,
                    &event.provider_model,
                    &input_tokens,
                    &output_tokens,
                    &token_status,
                    &pricing_status,
                    &event.model_price_version,
                    &input_price,
                    &output_price,
                    &cost,
                    &event.created_at_unix,
                ],
            ))
            .await
            .context("failed to append immutable usage event")?;
        Ok(inserted == 1)
    }

    pub(super) async fn list_usage_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageEvent>> {
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded usage-event limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, request_id, provider_response_id, provider, path,
                        requested_model,
                        provider_model, input_tokens, output_tokens, token_status,
                        pricing_status, model_price_version, input_usd_micros_per_million,
                        output_usd_micros_per_million, cost_usd_micros, created_at_unix
                 FROM usage_events WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query usage events")?;
        rows.iter().map(usage_event_from_row).collect()
    }

    pub(super) async fn usage_report(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
    ) -> anyhow::Result<UsageReport> {
        validate_usage_range(from_unix, until_unix)?;
        let client = self.checkout().await?;
        let totals_row = self
            .bounded(client.query_one(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0)::BIGINT,
                        COALESCE(SUM(output_tokens), 0)::BIGINT,
                        COALESCE(SUM(cost_usd_micros), 0)::BIGINT
                 FROM usage_events
                 WHERE tenant_id = $1 AND created_at_unix >= $2 AND created_at_unix < $3",
                &[&tenant_id, &from_unix, &until_unix],
            ))
            .await
            .context("failed to aggregate PostgreSQL usage totals")?;
        let totals = usage_totals_from_postgres_row(&totals_row, 0)?;

        let daily_rows = self
            .bounded(client.query(
                "SELECT (created_at_unix / 86400) * 86400 AS day_start_unix,
                        COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0)::BIGINT,
                        COALESCE(SUM(output_tokens), 0)::BIGINT,
                        COALESCE(SUM(cost_usd_micros), 0)::BIGINT
                 FROM usage_events
                 WHERE tenant_id = $1 AND created_at_unix >= $2 AND created_at_unix < $3
                 GROUP BY 1 ORDER BY 1 ASC",
                &[&tenant_id, &from_unix, &until_unix],
            ))
            .await
            .context("failed to aggregate PostgreSQL daily usage")?;
        let daily = daily_rows
            .iter()
            .map(|row| {
                Ok(DailyUsageAggregate {
                    day_start_unix: row.get(0),
                    totals: usage_totals_from_postgres_row(row, 1)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let model_rows = self
            .bounded(client.query(
                "SELECT provider, requested_model, COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0)::BIGINT,
                        COALESCE(SUM(output_tokens), 0)::BIGINT,
                        COALESCE(SUM(cost_usd_micros), 0)::BIGINT
                 FROM usage_events
                 WHERE tenant_id = $1 AND created_at_unix >= $2 AND created_at_unix < $3
                 GROUP BY provider, requested_model ORDER BY provider ASC, requested_model ASC",
                &[&tenant_id, &from_unix, &until_unix],
            ))
            .await
            .context("failed to aggregate PostgreSQL model usage")?;
        let models = model_rows
            .iter()
            .map(|row| {
                Ok(ModelUsageAggregate {
                    provider: row.get(0),
                    requested_model: row.get(1),
                    totals: usage_totals_from_postgres_row(row, 2)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let ready_row = self
            .bounded(client.query_one(
                "SELECT COUNT(*) FROM usage_events AS event
                 WHERE event.tenant_id = $1
                   AND event.created_at_unix >= $2 AND event.created_at_unix < $3
                   AND event.provider_response_id IS NOT NULL
                   AND event.token_status = 'actual' AND event.pricing_status = 'priced'
                   AND NOT EXISTS (
                     SELECT 1 FROM usage_events AS duplicate
                     WHERE duplicate.tenant_id = event.tenant_id
                       AND duplicate.provider = event.provider
                       AND duplicate.provider_response_id = event.provider_response_id
                       AND duplicate.id <> event.id
                   )",
                &[&tenant_id, &from_unix, &until_unix],
            ))
            .await
            .context("failed to aggregate PostgreSQL reconciliation-ready events")?;
        let ready_events = nonnegative_postgres_integer(ready_row.get(0), "ready event count")?;
        let duplicate_row = self
            .bounded(client.query_one(
                "SELECT COUNT(*), COALESCE(SUM(range_event_count), 0)::BIGINT
                 FROM (
                    SELECT event.provider, event.provider_response_id,
                           COUNT(*) AS range_event_count
                    FROM usage_events AS event
                    WHERE event.tenant_id = $1
                      AND event.created_at_unix >= $2 AND event.created_at_unix < $3
                      AND event.provider_response_id IS NOT NULL
                      AND EXISTS (
                        SELECT 1 FROM usage_events AS duplicate
                        WHERE duplicate.tenant_id = event.tenant_id
                          AND duplicate.provider = event.provider
                          AND duplicate.provider_response_id = event.provider_response_id
                          AND duplicate.id <> event.id
                      )
                    GROUP BY event.provider, event.provider_response_id
                 ) AS duplicate_provider_responses",
                &[&tenant_id, &from_unix, &until_unix],
            ))
            .await
            .context("failed to find duplicate PostgreSQL provider response IDs")?;
        let duplicate_groups =
            nonnegative_postgres_integer(duplicate_row.get(0), "duplicate response group count")?;
        let duplicate_events =
            nonnegative_postgres_integer(duplicate_row.get(1), "duplicate response event count")?;
        let reconciliation = UsageReconciliationReadiness {
            ready_events,
            review_required_events: totals
                .request_count
                .checked_sub(ready_events)
                .ok_or_else(|| anyhow::anyhow!("usage reconciliation counts are inconsistent"))?,
            missing_provider_response_id_events: totals
                .request_count
                .checked_sub(totals.provider_correlated_events)
                .ok_or_else(|| {
                    anyhow::anyhow!("usage provider correlation counts are inconsistent")
                })?,
            duplicate_provider_response_id_groups: duplicate_groups,
            duplicate_provider_response_id_events: duplicate_events,
        };

        Ok(UsageReport {
            from_unix,
            until_unix,
            totals,
            daily,
            models,
            reconciliation,
        })
    }

    pub(super) async fn list_usage_events_range(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
        after_id: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<UsageEventPage> {
        validate_usage_range(from_unix, until_unix)?;
        if after_id.is_some_and(|value| value < 0) {
            bail!("usage event cursor is invalid");
        }
        let limit = limit.clamp(1, 1_000);
        let query_limit = i64::try_from(limit + 1)
            .expect("bounded usage-event export limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, request_id, provider_response_id, provider, path,
                        requested_model, provider_model, input_tokens, output_tokens, token_status,
                        pricing_status, model_price_version, input_usd_micros_per_million,
                        output_usd_micros_per_million, cost_usd_micros, created_at_unix
                 FROM usage_events
                 WHERE tenant_id = $1 AND created_at_unix >= $2 AND created_at_unix < $3
                   AND id > COALESCE($4, 0)
                 ORDER BY id ASC LIMIT $5",
                &[&tenant_id, &from_unix, &until_unix, &after_id, &query_limit],
            ))
            .await
            .context("failed to query PostgreSQL usage-event export")?;
        let mut events = rows
            .iter()
            .map(usage_event_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let next_after_id = if events.len() > limit {
            events.pop();
            events.last().map(|event| event.id)
        } else {
            None
        };
        Ok(UsageEventPage {
            events,
            next_after_id,
        })
    }

    pub(super) async fn import_usage_reconciliation(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        import: &NewUsageReconciliationImport,
    ) -> anyhow::Result<UsageReconciliationRun> {
        validate_usage_text(tenant_id, "reconciliation tenant ID", 256)?;
        validate_usage_text(actor_admin_id, "reconciliation actor admin ID", 256)?;
        let statement_hash = validate_usage_reconciliation_import(import)?;
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL usage reconciliation transaction")?;
        let existing = self
            .bounded(transaction.query_opt(
                "SELECT id, tenant_id, source, statement_id, actor_admin_id, record_count,
                        matched_count, mismatched_count, orphan_count, ambiguous_count,
                        created_at_unix, statement_hash
                 FROM usage_reconciliation_runs
                 WHERE tenant_id = $1 AND source = $2 AND statement_id = $3",
                &[&tenant_id, &import.source, &import.statement_id],
            ))
            .await
            .context("failed to find existing PostgreSQL usage reconciliation run")?;
        if let Some(row) = existing {
            let run = usage_reconciliation_run_from_row(&row)?;
            let existing_hash: Vec<u8> = row.get(11);
            if existing_hash.as_slice() != statement_hash {
                bail!("reconciliation statement ID was already used with different content");
            }
            return Ok(run);
        }

        let mut evaluations = Vec::with_capacity(import.records.len());
        let mut matched_count = 0_u32;
        let mut mismatched_count = 0_u32;
        let mut orphan_count = 0_u32;
        let mut ambiguous_count = 0_u32;
        for record in &import.records {
            let rows = self
                .bounded(transaction.query(
                    "SELECT id, input_tokens, output_tokens, cost_usd_micros
                     FROM usage_events
                     WHERE tenant_id = $1 AND provider = $2 AND provider_response_id = $3
                     ORDER BY id ASC LIMIT 2",
                    &[&tenant_id, &record.provider, &record.provider_response_id],
                ))
                .await
                .context("failed to match PostgreSQL usage reconciliation record")?;
            let local = rows
                .iter()
                .map(|row| {
                    Ok(UsageReconciliationCandidate {
                        id: row.get(0),
                        input_tokens: optional_u64(row.get(1), "reconciliation input token count")?,
                        output_tokens: optional_u64(
                            row.get(2),
                            "reconciliation output token count",
                        )?,
                        cost_usd_micros: optional_u64(row.get(3), "reconciliation cost")?,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let (usage_event_id, status) = evaluate_usage_reconciliation(record, &local);
            match status {
                UsageReconciliationStatus::Matched => matched_count += 1,
                UsageReconciliationStatus::Mismatched => mismatched_count += 1,
                UsageReconciliationStatus::Orphan => orphan_count += 1,
                UsageReconciliationStatus::Ambiguous => ambiguous_count += 1,
            }
            evaluations.push((record, usage_event_id, status));
        }

        let run = UsageReconciliationRun {
            id: random_id("usage_reconciliation"),
            tenant_id: tenant_id.to_owned(),
            source: import.source.clone(),
            statement_id: import.statement_id.clone(),
            actor_admin_id: actor_admin_id.to_owned(),
            record_count: u32::try_from(import.records.len())
                .expect("bounded reconciliation record count fits u32"),
            matched_count,
            mismatched_count,
            orphan_count,
            ambiguous_count,
            created_at_unix: now_unix(),
        };
        let record_count = i32::try_from(run.record_count)
            .expect("bounded reconciliation record count fits PostgreSQL integer");
        let matched_count = i32::try_from(run.matched_count)
            .expect("bounded reconciliation matched count fits PostgreSQL integer");
        let mismatched_count = i32::try_from(run.mismatched_count)
            .expect("bounded reconciliation mismatched count fits PostgreSQL integer");
        let orphan_count = i32::try_from(run.orphan_count)
            .expect("bounded reconciliation orphan count fits PostgreSQL integer");
        let ambiguous_count = i32::try_from(run.ambiguous_count)
            .expect("bounded reconciliation ambiguous count fits PostgreSQL integer");
        let inserted = self
            .bounded(transaction.execute(
                "INSERT INTO usage_reconciliation_runs
                    (id, tenant_id, source, statement_id, statement_hash, actor_admin_id,
                     record_count, matched_count, mismatched_count, orphan_count, ambiguous_count,
                     created_at_unix)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 ON CONFLICT(tenant_id, source, statement_id) DO NOTHING",
                &[
                    &run.id,
                    &run.tenant_id,
                    &run.source,
                    &run.statement_id,
                    &&statement_hash[..],
                    &run.actor_admin_id,
                    &record_count,
                    &matched_count,
                    &mismatched_count,
                    &orphan_count,
                    &ambiguous_count,
                    &run.created_at_unix,
                ],
            ))
            .await
            .context("failed to append PostgreSQL usage reconciliation run")?;
        if inserted == 0 {
            let row = self
                .bounded(transaction.query_one(
                    "SELECT id, tenant_id, source, statement_id, actor_admin_id, record_count,
                            matched_count, mismatched_count, orphan_count, ambiguous_count,
                            created_at_unix, statement_hash
                     FROM usage_reconciliation_runs
                     WHERE tenant_id = $1 AND source = $2 AND statement_id = $3",
                    &[&tenant_id, &import.source, &import.statement_id],
                ))
                .await
                .context("failed to read concurrently imported reconciliation run")?;
            let existing_hash: Vec<u8> = row.get(11);
            if existing_hash.as_slice() != statement_hash {
                bail!("reconciliation statement ID was already used with different content");
            }
            return usage_reconciliation_run_from_row(&row);
        }

        for (record, usage_event_id, status) in evaluations {
            let input_tokens =
                optional_postgres_integer(record.input_tokens, "reconciliation input tokens")?;
            let output_tokens =
                optional_postgres_integer(record.output_tokens, "reconciliation output tokens")?;
            let cost = optional_postgres_integer(record.cost_usd_micros, "reconciliation cost")?;
            let status = status.storage_value();
            self.bounded(transaction.execute(
                "INSERT INTO usage_reconciliation_observations
                    (run_id, tenant_id, source_record_id, usage_event_id, provider,
                     provider_response_id, input_tokens, output_tokens, cost_usd_micros,
                     status, created_at_unix)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &run.id,
                    &tenant_id,
                    &record.source_record_id,
                    &usage_event_id,
                    &record.provider,
                    &record.provider_response_id,
                    &input_tokens,
                    &output_tokens,
                    &cost,
                    &status,
                    &run.created_at_unix,
                ],
            ))
            .await
            .context("failed to append PostgreSQL reconciliation observation")?;
        }
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL usage reconciliation import")?;
        Ok(run)
    }

    pub(super) async fn list_usage_reconciliation_runs(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationRun>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded reconciliation-run limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, source, statement_id, actor_admin_id, record_count,
                        matched_count, mismatched_count, orphan_count, ambiguous_count,
                        created_at_unix
                 FROM usage_reconciliation_runs
                 WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL usage reconciliation runs")?;
        rows.iter().map(usage_reconciliation_run_from_row).collect()
    }

    pub(super) async fn list_usage_reconciliation_observations(
        &self,
        tenant_id: &str,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationObservation>> {
        let limit = i64::try_from(limit.clamp(1, 1_000))
            .expect("bounded reconciliation-observation limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT observation.id, observation.run_id, observation.tenant_id,
                        observation.source_record_id, observation.usage_event_id,
                        observation.provider, observation.provider_response_id,
                        observation.input_tokens, observation.output_tokens,
                        observation.cost_usd_micros, observation.status,
                        observation.created_at_unix
                 FROM usage_reconciliation_observations AS observation
                 JOIN usage_reconciliation_runs AS run ON run.id = observation.run_id
                 WHERE observation.tenant_id = $1 AND observation.run_id = $2
                   AND run.tenant_id = $1
                 ORDER BY observation.id ASC LIMIT $3",
                &[&tenant_id, &run_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL reconciliation observations")?;
        rows.iter()
            .map(usage_reconciliation_observation_from_row)
            .collect()
    }

    pub(super) async fn usage_retention_policy(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageRetentionPolicy>> {
        let client = self.checkout().await?;
        self.bounded(client.query_opt(
            "SELECT retention_days FROM usage_retention_policies WHERE tenant_id = $1",
            &[&tenant_id],
        ))
        .await
        .context("failed to load PostgreSQL usage retention policy")?
        .map(|row| {
            Ok(UsageRetentionPolicy {
                retention_days: nonnegative_postgres_u32(row.get(0), "usage retention period")?,
            })
        })
        .transpose()
    }

    pub(super) async fn set_usage_retention_policy(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageRetentionPolicy>,
    ) -> anyhow::Result<()> {
        validate_usage_text(actor_id, "retention actor ID", 256)?;
        if let Some(policy) = &policy {
            validate_usage_retention_policy(policy)?;
        }
        self.require_tenant(tenant_id).await?;
        let client = self.checkout().await?;
        match policy {
            Some(policy) => {
                let retention_days = i32::try_from(policy.retention_days)
                    .expect("validated retention period fits PostgreSQL integer");
                let now = now_unix();
                self.bounded(client.execute(
                    "INSERT INTO usage_retention_policies
                        (tenant_id, retention_days, updated_by, updated_at_unix)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        retention_days = excluded.retention_days,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix",
                    &[&tenant_id, &retention_days, &actor_id, &now],
                ))
                .await
                .context("failed to save PostgreSQL usage retention policy")?;
            }
            None => {
                self.bounded(client.execute(
                    "DELETE FROM usage_retention_policies WHERE tenant_id = $1",
                    &[&tenant_id],
                ))
                .await
                .context("failed to clear PostgreSQL usage retention policy")?;
            }
        }
        Ok(())
    }

    pub(super) async fn set_workspace_usage_retention_policy(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<UsageRetentionPolicy>,
    ) -> anyhow::Result<()> {
        if let Some(policy) = &policy {
            validate_usage_retention_policy(policy)?;
        }
        let now = now_unix();
        let action = if policy.is_some() {
            "usage_retention_policy.set"
        } else {
            "usage_retention_policy.clear"
        };
        let client = self.checkout().await?;
        let changed = match policy {
            Some(policy) => {
                let retention_days = i32::try_from(policy.retention_days)
                    .expect("validated retention period fits PostgreSQL integer");
                self.bounded(client.execute(
                    "WITH authorized AS (
                        SELECT workspaces.organization_id, workspaces.tenant_id
                        FROM workspaces
                        JOIN organizations ON organizations.id = workspaces.organization_id
                        JOIN tenants ON tenants.id = workspaces.tenant_id
                        JOIN workspace_principals ON workspace_principals.id = $2
                        JOIN workspace_memberships
                          ON workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                        WHERE workspaces.id = $1
                          AND workspace_memberships.role = 'owner'
                          AND workspaces.active = TRUE AND organizations.active = TRUE
                          AND tenants.active = TRUE AND workspace_principals.active = TRUE
                          AND workspace_memberships.active = TRUE
                     ), saved AS (
                        INSERT INTO usage_retention_policies
                            (tenant_id, retention_days, updated_by, updated_at_unix)
                        SELECT tenant_id, $3, $2, $4 FROM authorized
                        ON CONFLICT(tenant_id) DO UPDATE SET
                            retention_days = excluded.retention_days,
                            updated_by = excluded.updated_by,
                            updated_at_unix = excluded.updated_at_unix
                     ), audited AS (
                        INSERT INTO workspace_admin_audit
                            (organization_id, workspace_id, actor_principal_id, action,
                             target_principal_id, created_at_unix)
                        SELECT organization_id, $1, $2, $5, NULL, $4 FROM authorized
                     )
                     SELECT 1 FROM authorized",
                    &[&workspace_id, &principal_id, &retention_days, &now, &action],
                ))
                .await
                .context("failed to save customer PostgreSQL usage retention policy")?
            }
            None => self
                .bounded(client.execute(
                    "WITH authorized AS (
                        SELECT workspaces.organization_id, workspaces.tenant_id
                        FROM workspaces
                        JOIN organizations ON organizations.id = workspaces.organization_id
                        JOIN tenants ON tenants.id = workspaces.tenant_id
                        JOIN workspace_principals ON workspace_principals.id = $2
                        JOIN workspace_memberships
                          ON workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                        WHERE workspaces.id = $1
                          AND workspace_memberships.role = 'owner'
                          AND workspaces.active = TRUE AND organizations.active = TRUE
                          AND tenants.active = TRUE AND workspace_principals.active = TRUE
                          AND workspace_memberships.active = TRUE
                     ), cleared AS (
                        DELETE FROM usage_retention_policies
                        WHERE tenant_id IN (SELECT tenant_id FROM authorized)
                     ), audited AS (
                        INSERT INTO workspace_admin_audit
                            (organization_id, workspace_id, actor_principal_id, action,
                             target_principal_id, created_at_unix)
                        SELECT organization_id, $1, $2, $3, NULL, $4 FROM authorized
                     )
                     SELECT 1 FROM authorized",
                    &[&workspace_id, &principal_id, &action, &now],
                ))
                .await
                .context("failed to clear customer PostgreSQL usage retention policy")?,
        };
        if changed != 1 {
            bail!("customer workspace action is not permitted");
        }
        Ok(())
    }

    pub(super) async fn run_usage_retention(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        execute: bool,
    ) -> anyhow::Result<UsageRetentionRun> {
        validate_usage_text(actor_admin_id, "retention actor ID", 256)?;
        let now = now_unix();
        let mut client = self.checkout().await?;
        let transaction = self
            .bounded(client.transaction())
            .await
            .context("failed to begin PostgreSQL usage retention transaction")?;
        let policy_row = self
            .bounded(transaction.query_opt(
                "SELECT retention_days FROM usage_retention_policies
                 WHERE tenant_id = $1 FOR UPDATE",
                &[&tenant_id],
            ))
            .await
            .context("failed to load PostgreSQL usage retention policy")?
            .ok_or_else(|| anyhow::anyhow!("usage retention policy is not configured"))?;
        let retention_days = nonnegative_postgres_u32(policy_row.get(0), "usage retention period")?;
        let policy_cutoff = usage_retention_cutoff(now, retention_days)?;
        let (current_month_start, _) = super::current_utc_month_range(now)?;
        let cutoff_unix = policy_cutoff.min(current_month_start);
        let aggregate = self
            .bounded(transaction.query_one(
                "SELECT COUNT(*)::BIGINT,
                        COALESCE(SUM(input_tokens), 0)::BIGINT,
                        COALESCE(SUM(output_tokens), 0)::BIGINT,
                        COALESCE(SUM(cost_usd_micros), 0)::BIGINT
                 FROM usage_events AS event
                 WHERE event.tenant_id = $1 AND event.created_at_unix < $2
                   AND NOT EXISTS (
                     SELECT 1 FROM usage_reconciliation_observations AS observation
                     WHERE observation.usage_event_id = event.id
                   )",
                &[&tenant_id, &cutoff_unix],
            ))
            .await
            .context("failed to inspect PostgreSQL usage retention eligibility")?;
        let eligible_event_count =
            nonnegative_postgres_integer(aggregate.get(0), "eligible usage event count")?;
        let eligible_input_tokens =
            nonnegative_postgres_integer(aggregate.get(1), "eligible input token count")?;
        let eligible_output_tokens =
            nonnegative_postgres_integer(aggregate.get(2), "eligible output token count")?;
        let eligible_cost_usd_micros =
            nonnegative_postgres_integer(aggregate.get(3), "eligible usage cost")?;
        let protected_row = self
            .bounded(transaction.query_one(
                "SELECT COUNT(*)::BIGINT FROM usage_events AS event
                 WHERE event.tenant_id = $1 AND event.created_at_unix < $2
                   AND EXISTS (
                     SELECT 1 FROM usage_reconciliation_observations AS observation
                     WHERE observation.usage_event_id = event.id
                   )",
                &[&tenant_id, &cutoff_unix],
            ))
            .await
            .context("failed to count PostgreSQL reconciliation-protected usage events")?;
        let protected_reconciliation_event_count =
            nonnegative_postgres_integer(protected_row.get(0), "protected usage event count")?;
        let deleted_event_count = if execute {
            self.bounded(transaction.execute(
                "DELETE FROM usage_events AS event
                 WHERE event.tenant_id = $1 AND event.created_at_unix < $2
                   AND NOT EXISTS (
                     SELECT 1 FROM usage_reconciliation_observations AS observation
                     WHERE observation.usage_event_id = event.id
                   )",
                &[&tenant_id, &cutoff_unix],
            ))
            .await
            .context("failed to purge eligible PostgreSQL usage events")?
        } else {
            0
        };
        if execute && deleted_event_count != eligible_event_count {
            bail!("usage retention deletion count changed unexpectedly");
        }
        let run = UsageRetentionRun {
            id: random_id("usage_retention"),
            tenant_id: tenant_id.to_owned(),
            actor_admin_id: actor_admin_id.to_owned(),
            retention_days,
            cutoff_unix,
            executed: execute,
            eligible_event_count,
            protected_reconciliation_event_count,
            eligible_input_tokens,
            eligible_output_tokens,
            eligible_cost_usd_micros,
            deleted_event_count,
            created_at_unix: now,
        };
        let retention_days_db = i32::try_from(retention_days)
            .expect("validated retention period fits PostgreSQL integer");
        let eligible_event_count_db =
            postgres_integer(eligible_event_count, "eligible event count")?;
        let protected_count_db = postgres_integer(
            protected_reconciliation_event_count,
            "protected event count",
        )?;
        let input_db = postgres_integer(eligible_input_tokens, "eligible input tokens")?;
        let output_db = postgres_integer(eligible_output_tokens, "eligible output tokens")?;
        let cost_db = postgres_integer(eligible_cost_usd_micros, "eligible usage cost")?;
        let deleted_db = postgres_integer(deleted_event_count, "deleted usage event count")?;
        self.bounded(transaction.execute(
            "INSERT INTO usage_retention_runs
                (id, tenant_id, actor_admin_id, retention_days, cutoff_unix, executed,
                 eligible_event_count, protected_reconciliation_event_count,
                 eligible_input_tokens, eligible_output_tokens, eligible_cost_usd_micros,
                 deleted_event_count, created_at_unix)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[
                &run.id,
                &run.tenant_id,
                &run.actor_admin_id,
                &retention_days_db,
                &run.cutoff_unix,
                &run.executed,
                &eligible_event_count_db,
                &protected_count_db,
                &input_db,
                &output_db,
                &cost_db,
                &deleted_db,
                &run.created_at_unix,
            ],
        ))
        .await
        .context("failed to append PostgreSQL usage retention run")?;
        self.bounded(transaction.commit())
            .await
            .context("failed to commit PostgreSQL usage retention run")?;
        Ok(run)
    }

    pub(super) async fn list_usage_retention_runs(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageRetentionRun>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded retention-run limit fits in a PostgreSQL integer");
        let client = self.checkout().await?;
        let rows = self
            .bounded(client.query(
                "SELECT id, tenant_id, actor_admin_id, retention_days, cutoff_unix, executed,
                        eligible_event_count, protected_reconciliation_event_count,
                        eligible_input_tokens, eligible_output_tokens, eligible_cost_usd_micros,
                        deleted_event_count, created_at_unix
                 FROM usage_retention_runs
                 WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id DESC LIMIT $2",
                &[&tenant_id, &limit],
            ))
            .await
            .context("failed to query PostgreSQL usage retention runs")?;
        rows.iter().map(usage_retention_run_from_row).collect()
    }

    pub(super) async fn usage_quota_policy(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageQuotaPolicy>> {
        let client = self.checkout().await?;
        self.bounded(client.query_opt(
            "SELECT request_limit, token_limit, cost_usd_micros_limit,
                    alert_threshold_basis_points
             FROM usage_quota_policies WHERE tenant_id = $1",
            &[&tenant_id],
        ))
        .await
        .context("failed to load PostgreSQL usage quota policy")?
        .map(|row| usage_quota_policy_from_row(&row))
        .transpose()
    }

    pub(super) async fn set_usage_quota_policy(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageQuotaPolicy>,
    ) -> anyhow::Result<()> {
        validate_usage_text(actor_id, "quota actor ID", 256)?;
        if let Some(policy) = &policy {
            validate_usage_quota_policy(policy)?;
        }
        self.require_tenant(tenant_id).await?;
        let client = self.checkout().await?;
        if let Some(policy) = policy {
            let request_limit = optional_postgres_integer(policy.request_limit, "request quota")?;
            let token_limit = optional_postgres_integer(policy.token_limit, "token quota")?;
            let cost_limit = optional_postgres_integer(policy.cost_usd_micros_limit, "cost quota")?;
            let threshold = i32::from(policy.alert_threshold_basis_points);
            let now = now_unix();
            self.bounded(client.execute(
                "INSERT INTO usage_quota_policies
                    (tenant_id, request_limit, token_limit, cost_usd_micros_limit,
                     alert_threshold_basis_points, updated_by, updated_at_unix)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                    request_limit = excluded.request_limit,
                    token_limit = excluded.token_limit,
                    cost_usd_micros_limit = excluded.cost_usd_micros_limit,
                    alert_threshold_basis_points = excluded.alert_threshold_basis_points,
                    updated_by = excluded.updated_by,
                    updated_at_unix = excluded.updated_at_unix",
                &[
                    &tenant_id,
                    &request_limit,
                    &token_limit,
                    &cost_limit,
                    &threshold,
                    &actor_id,
                    &now,
                ],
            ))
            .await
            .context("failed to save PostgreSQL usage quota policy")?;
        } else {
            self.bounded(client.execute(
                "DELETE FROM usage_quota_policies WHERE tenant_id = $1",
                &[&tenant_id],
            ))
            .await
            .context("failed to clear PostgreSQL usage quota policy")?;
        }
        Ok(())
    }

    pub(super) async fn set_workspace_usage_quota_policy(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<UsageQuotaPolicy>,
    ) -> anyhow::Result<()> {
        if let Some(policy) = &policy {
            validate_usage_quota_policy(policy)?;
        }
        let now = now_unix();
        let action = if policy.is_some() {
            "usage_quota_policy.set"
        } else {
            "usage_quota_policy.clear"
        };
        let client = self.checkout().await?;
        let changed = if let Some(policy) = policy {
            let request_limit = optional_postgres_integer(policy.request_limit, "request quota")?;
            let token_limit = optional_postgres_integer(policy.token_limit, "token quota")?;
            let cost_limit = optional_postgres_integer(policy.cost_usd_micros_limit, "cost quota")?;
            let threshold = i32::from(policy.alert_threshold_basis_points);
            self.bounded(client.execute(
                "WITH authorized AS (
                    SELECT workspaces.organization_id, workspaces.tenant_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspaces.active = TRUE AND organizations.active = TRUE
                      AND tenants.active = TRUE AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                 ), saved AS (
                    INSERT INTO usage_quota_policies
                        (tenant_id, request_limit, token_limit, cost_usd_micros_limit,
                         alert_threshold_basis_points, updated_by, updated_at_unix)
                    SELECT tenant_id, $3, $4, $5, $6, $2, $7 FROM authorized
                    ON CONFLICT(tenant_id) DO UPDATE SET
                        request_limit = excluded.request_limit,
                        token_limit = excluded.token_limit,
                        cost_usd_micros_limit = excluded.cost_usd_micros_limit,
                        alert_threshold_basis_points = excluded.alert_threshold_basis_points,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, $8, NULL, $7 FROM authorized
                 )
                 SELECT 1 FROM authorized",
                &[
                    &workspace_id,
                    &principal_id,
                    &request_limit,
                    &token_limit,
                    &cost_limit,
                    &threshold,
                    &now,
                    &action,
                ],
            ))
            .await
            .context("failed to save customer PostgreSQL usage quota policy")?
        } else {
            self.bounded(client.execute(
                "WITH authorized AS (
                    SELECT workspaces.organization_id, workspaces.tenant_id
                    FROM workspaces
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN tenants ON tenants.id = workspaces.tenant_id
                    JOIN workspace_principals ON workspace_principals.id = $2
                    JOIN workspace_memberships
                      ON workspace_memberships.workspace_id = workspaces.id
                     AND workspace_memberships.principal_id = workspace_principals.id
                    WHERE workspaces.id = $1
                      AND workspace_memberships.role = 'owner'
                      AND workspaces.active = TRUE AND organizations.active = TRUE
                      AND tenants.active = TRUE AND workspace_principals.active = TRUE
                      AND workspace_memberships.active = TRUE
                 ), cleared AS (
                    DELETE FROM usage_quota_policies
                    WHERE tenant_id IN (SELECT tenant_id FROM authorized)
                 ), audited AS (
                    INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                    SELECT organization_id, $1, $2, $3, NULL, $4 FROM authorized
                 )
                 SELECT 1 FROM authorized",
                &[&workspace_id, &principal_id, &action, &now],
            ))
            .await
            .context("failed to clear customer PostgreSQL usage quota policy")?
        };
        if changed != 1 {
            bail!("customer workspace action is not permitted");
        }
        Ok(())
    }

    /// Load identity, limits and the model policy from one PostgreSQL snapshot.
    /// This is the request-time tenant control-plane hot path.
    pub(super) async fn authenticate_access(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<TenantAccess>> {
        let Some(token) = presented_header.and_then(|value| value.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        if token.is_empty() {
            return Ok(None);
        }
        let token_hash = token_hash(token);
        let client = self.checkout().await?;
        let row = self
            .bounded(client.query_opt(
                "WITH credentials AS (
                    SELECT tenant_id
                    FROM tenant_tokens
                    WHERE token_hash = $1 AND active = TRUE
                    UNION ALL
                    SELECT w.tenant_id
                    FROM workspace_service_accounts a
                    JOIN workspaces w ON w.id = a.workspace_id
                    WHERE a.token_hash = $1 AND a.active = TRUE
                      AND a.expires_at_unix >= $2
                      AND w.active = TRUE
                    LIMIT 1
                 )
                 SELECT tenants.id, tenants.name,
                        tenant_limits.rate_limit_requests_per_window,
                        tenant_limits.rate_limit_window_seconds,
                        tenant_limits.spend_limit_window_seconds,
                        tenant_limits.spend_limit_max_usd_micros,
                        tenant_limits.spend_limit_reserve_usd_micros_per_request,
                        tenant_model_policies.allowed_models_json
                 FROM credentials
                 JOIN tenants ON tenants.id = credentials.tenant_id
                 LEFT JOIN tenant_limits ON tenant_limits.tenant_id = tenants.id
                 LEFT JOIN tenant_model_policies ON tenant_model_policies.tenant_id = tenants.id
                 WHERE tenants.active = TRUE",
                &[&token_hash, &now_unix()],
            ))
            .await
            .context("failed to authenticate tenant token")?;
        row.map(access_from_row).transpose()
    }

    pub(super) async fn authenticate_bearer(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<TenantIdentity>> {
        Ok(self
            .authenticate_access(presented_header)
            .await?
            .map(|access| access.identity))
    }

    async fn require_tenant(&self, tenant_id: &str) -> anyhow::Result<()> {
        let client = self.checkout().await?;
        let exists = self
            .bounded(client.query_opt("SELECT 1 FROM tenants WHERE id = $1", &[&tenant_id]))
            .await
            .context("failed to look up tenant")?
            .is_some();
        if !exists {
            bail!("tenant not found");
        }
        Ok(())
    }

    async fn checkout(&self) -> anyhow::Result<deadpool_postgres::Client> {
        timeout(self.pool_wait_timeout, self.pool.get())
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL tenant-store pool wait timed out"))?
            .map_err(|_| anyhow::anyhow!("PostgreSQL tenant-store pool is unavailable"))
    }

    async fn bounded<T>(
        &self,
        operation: impl Future<Output = Result<T, tokio_postgres::Error>>,
    ) -> anyhow::Result<T> {
        timeout(self.command_timeout, operation)
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL tenant-store command timed out"))?
            .map_err(|_| anyhow::anyhow!("PostgreSQL tenant-store command failed"))
    }
}

fn tenant_from_row(row: &Row) -> anyhow::Result<Tenant> {
    Ok(Tenant {
        id: row.get(0),
        name: row.get(1),
        active: row.get(2),
        created_at_unix: row.get(3),
    })
}

fn organization_from_row(row: Row) -> anyhow::Result<Organization> {
    Ok(Organization {
        id: row.get(0),
        name: row.get(1),
        active: row.get(2),
        created_at_unix: row.get(3),
    })
}

fn organization_oidc_connection_from_row(row: Row) -> anyhow::Result<OrganizationOidcConnection> {
    Ok(OrganizationOidcConnection {
        organization_id: row.get(0),
        issuer: row.get(1),
        client_id: row.get(2),
        redirect_uri: row.get(3),
        active: row.get(4),
        created_at_unix: row.get(5),
        updated_at_unix: row.get(6),
    })
}

fn organization_saml_connection_from_row(row: Row) -> anyhow::Result<OrganizationSamlConnection> {
    Ok(OrganizationSamlConnection {
        organization_id: row.get(0),
        entity_id: row.get(1),
        metadata_xml: row.get(2),
        metadata_signing_cert_pem: row.get(3),
        active: row.get(4),
        created_at_unix: row.get(5),
        updated_at_unix: row.get(6),
    })
}

fn workspace_from_row(row: Row) -> anyhow::Result<Workspace> {
    Ok(Workspace {
        id: row.get(0),
        organization_id: row.get(1),
        tenant_id: row.get(2),
        name: row.get(3),
        active: row.get(4),
        created_at_unix: row.get(5),
    })
}

fn workspace_principal_from_row(row: Row) -> anyhow::Result<WorkspacePrincipal> {
    Ok(WorkspacePrincipal {
        id: row.get(0),
        name: row.get(1),
        active: row.get(2),
        created_at_unix: row.get(3),
    })
}

fn workspace_membership_from_row(row: Row) -> anyhow::Result<WorkspaceMembership> {
    Ok(WorkspaceMembership {
        workspace_id: row.get(0),
        principal_id: row.get(1),
        role: WorkspaceRole::from_storage(&row.get::<_, String>(2))?,
        active: row.get(3),
        created_at_unix: row.get(4),
        updated_at_unix: row.get(5),
    })
}

fn workspace_member_from_row(row: Row) -> anyhow::Result<WorkspaceMember> {
    Ok(WorkspaceMember {
        workspace_id: row.get(0),
        principal_id: row.get(1),
        principal_name: row.get(2),
        role: WorkspaceRole::from_storage(&row.get::<_, String>(3))?,
        active: row.get(4),
        created_at_unix: row.get(5),
        updated_at_unix: row.get(6),
    })
}

fn workspace_invitation_from_row(row: Row) -> anyhow::Result<WorkspaceInvitation> {
    Ok(WorkspaceInvitation {
        id: row.get(0),
        organization_id: row.get(1),
        workspace_id: row.get(2),
        recipient_label: row.get(3),
        role: WorkspaceRole::from_storage(&row.get::<_, String>(4))?,
        created_by_principal_id: row.get(5),
        active: row.get(6),
        expires_at_unix: row.get(7),
        created_at_unix: row.get(8),
        revoked_at_unix: row.get(9),
        accepted_by_principal_id: row.get(10),
        accepted_at_unix: row.get(11),
    })
}

fn service_account_from_row(row: Row) -> anyhow::Result<WorkspaceServiceAccount> {
    Ok(WorkspaceServiceAccount {
        id: row.get(0),
        workspace_id: row.get(1),
        name: row.get(2),
        created_by_principal_id: row.get(3),
        active: row.get(4),
        expires_at_unix: row.get(5),
        created_at_unix: row.get(6),
        revoked_at_unix: row.get(7),
    })
}

fn workspace_admin_audit_from_row(row: Row) -> anyhow::Result<WorkspaceAdminAuditEvent> {
    Ok(WorkspaceAdminAuditEvent {
        id: row.get(0),
        organization_id: row.get(1),
        workspace_id: row.get(2),
        actor_principal_id: row.get(3),
        action: row.get(4),
        target_principal_id: row.get(5),
        created_at_unix: row.get(6),
    })
}

fn control_plane_admin_from_row(row: &Row) -> anyhow::Result<ControlPlaneAdmin> {
    Ok(ControlPlaneAdmin {
        id: row.get(0),
        name: row.get(1),
        role: AdminRole::from_storage(&row.get::<_, String>(2))?,
        active: row.get(3),
        created_at_unix: row.get(4),
    })
}

fn scim_token_from_row(row: Row) -> anyhow::Result<ScimToken> {
    Ok(ScimToken {
        id: row.get(0),
        organization_id: row.get(1),
        label: row.get(2),
        active: row.get(3),
        expires_at_unix: row.get(4),
        created_at_unix: row.get(5),
        revoked_at_unix: row.get(6),
    })
}

fn scim_user_from_row(row: Row) -> anyhow::Result<ScimUser> {
    Ok(ScimUser {
        id: row.get(0),
        organization_id: row.get(1),
        external_id: row.get(2),
        user_name: row.get(3),
        display_name: row.get(4),
        active: row.get(5),
        created_at_unix: row.get(6),
        updated_at_unix: row.get(7),
    })
}

fn scim_group_from_row(row: Row) -> anyhow::Result<ScimGroup> {
    Ok(ScimGroup {
        id: row.get(0),
        organization_id: row.get(1),
        external_id: row.get(2),
        display_name: row.get(3),
        active: row.get(4),
        created_at_unix: row.get(5),
        updated_at_unix: row.get(6),
        member_ids: Vec::new(),
    })
}

fn tenant_token_from_row(row: &Row) -> anyhow::Result<TenantToken> {
    Ok(TenantToken {
        id: row.get(0),
        tenant_id: row.get(1),
        label: row.get(2),
        active: row.get(3),
        created_at_unix: row.get(4),
        revoked_at_unix: row.get(5),
    })
}

fn admin_identity_from_row(row: Row) -> anyhow::Result<AdminIdentity> {
    Ok(AdminIdentity {
        admin_id: row.get(0),
        admin_name: row.get(1),
        role: AdminRole::from_storage(&row.get::<_, String>(2))?,
    })
}

fn limits_from_row(row: Row) -> anyhow::Result<TenantLimits> {
    limits_from_columns(&row, 0)
}

fn access_from_row(row: Row) -> anyhow::Result<TenantAccess> {
    let policy = row
        .get::<_, Option<String>>(7)
        .map(|encoded| {
            serde_json::from_str::<TenantModelPolicy>(&encoded)
                .context("stored tenant model policy is invalid")
        })
        .transpose()?;
    Ok(TenantAccess {
        identity: TenantIdentity {
            tenant_id: row.get(0),
            tenant_name: row.get(1),
        },
        limits: limits_from_columns(&row, 2)?,
        model_policy: policy,
    })
}

fn limits_from_columns(row: &Row, offset: usize) -> anyhow::Result<TenantLimits> {
    let rate_requests = optional_u32(
        row.get::<_, Option<i64>>(offset),
        "tenant rate request limit",
    )?;
    let rate_window = optional_u64(row.get::<_, Option<i64>>(offset + 1), "tenant rate window")?;
    let spend_window = optional_u64(row.get::<_, Option<i64>>(offset + 2), "tenant spend window")?;
    let spend_max = optional_u64(row.get::<_, Option<i64>>(offset + 3), "tenant spend budget")?;
    let spend_reserve = optional_u64(
        row.get::<_, Option<i64>>(offset + 4),
        "tenant spend reservation",
    )?;
    Ok(TenantLimits {
        rate_limit: rate_requests
            .zip(rate_window)
            .map(|(requests_per_window, window_seconds)| TenantRateLimit {
                requests_per_window,
                window_seconds,
            }),
        spend_limit: spend_window.zip(spend_max).zip(spend_reserve).map(
            |((window_seconds, max_usd_micros), reserve_usd_micros_per_request)| TenantSpendLimit {
                window_seconds,
                max_usd_micros,
                reserve_usd_micros_per_request,
            },
        ),
    })
}

fn audit_from_row(row: &Row) -> anyhow::Result<TenantAuditEvent> {
    Ok(TenantAuditEvent {
        id: row.get(0),
        tenant_id: row.get(1),
        created_at_unix: row.get(2),
        path: row.get(3),
        outcome: row.get(4),
        status_code: u16::try_from(row.get::<_, i32>(5))
            .context("stored tenant audit status is outside the HTTP range")?,
        latency_ms: u64::try_from(row.get::<_, i64>(6))
            .context("stored tenant audit latency is negative")?,
    })
}

fn usage_event_from_row(row: &Row) -> anyhow::Result<UsageEvent> {
    Ok(UsageEvent {
        id: row.get(0),
        tenant_id: row.get(1),
        request_id: row.get(2),
        provider_response_id: row.get(3),
        provider: row.get(4),
        path: row.get(5),
        requested_model: row.get(6),
        provider_model: row.get(7),
        input_tokens: optional_u64(row.get(8), "stored input token count")?,
        output_tokens: optional_u64(row.get(9), "stored output token count")?,
        token_status: super::usage_token_status_from_storage(&row.get::<_, String>(10))?,
        pricing_status: super::usage_pricing_status_from_storage(&row.get::<_, String>(11))?,
        model_price_version: row.get(12),
        input_usd_micros_per_million: optional_u64(row.get(13), "stored input model price")?,
        output_usd_micros_per_million: optional_u64(row.get(14), "stored output model price")?,
        cost_usd_micros: optional_u64(row.get(15), "stored usage cost")?,
        created_at_unix: row.get(16),
    })
}

fn usage_reconciliation_run_from_row(row: &Row) -> anyhow::Result<UsageReconciliationRun> {
    Ok(UsageReconciliationRun {
        id: row.get(0),
        tenant_id: row.get(1),
        source: row.get(2),
        statement_id: row.get(3),
        actor_admin_id: row.get(4),
        record_count: nonnegative_postgres_u32(row.get(5), "reconciliation record count")?,
        matched_count: nonnegative_postgres_u32(row.get(6), "reconciliation matched count")?,
        mismatched_count: nonnegative_postgres_u32(row.get(7), "reconciliation mismatched count")?,
        orphan_count: nonnegative_postgres_u32(row.get(8), "reconciliation orphan count")?,
        ambiguous_count: nonnegative_postgres_u32(row.get(9), "reconciliation ambiguous count")?,
        created_at_unix: row.get(10),
    })
}

fn usage_reconciliation_observation_from_row(
    row: &Row,
) -> anyhow::Result<UsageReconciliationObservation> {
    Ok(UsageReconciliationObservation {
        id: row.get(0),
        run_id: row.get(1),
        tenant_id: row.get(2),
        source_record_id: row.get(3),
        usage_event_id: row.get(4),
        provider: row.get(5),
        provider_response_id: row.get(6),
        input_tokens: optional_u64(row.get(7), "reconciliation input token count")?,
        output_tokens: optional_u64(row.get(8), "reconciliation output token count")?,
        cost_usd_micros: optional_u64(row.get(9), "reconciliation cost")?,
        status: UsageReconciliationStatus::from_storage(&row.get::<_, String>(10))?,
        created_at_unix: row.get(11),
    })
}

fn usage_retention_run_from_row(row: &Row) -> anyhow::Result<UsageRetentionRun> {
    Ok(UsageRetentionRun {
        id: row.get(0),
        tenant_id: row.get(1),
        actor_admin_id: row.get(2),
        retention_days: nonnegative_postgres_u32(row.get(3), "usage retention period")?,
        cutoff_unix: row.get(4),
        executed: row.get(5),
        eligible_event_count: nonnegative_postgres_integer(
            row.get(6),
            "eligible usage event count",
        )?,
        protected_reconciliation_event_count: nonnegative_postgres_integer(
            row.get(7),
            "protected usage event count",
        )?,
        eligible_input_tokens: nonnegative_postgres_integer(
            row.get(8),
            "eligible input token count",
        )?,
        eligible_output_tokens: nonnegative_postgres_integer(
            row.get(9),
            "eligible output token count",
        )?,
        eligible_cost_usd_micros: nonnegative_postgres_integer(row.get(10), "eligible usage cost")?,
        deleted_event_count: nonnegative_postgres_integer(
            row.get(11),
            "deleted usage event count",
        )?,
        created_at_unix: row.get(12),
    })
}

fn policy_version_from_row(row: &Row) -> anyhow::Result<TenantPolicyVersion> {
    let document = serde_json::from_str::<TenantPolicyDocument>(&row.get::<_, String>(3))
        .context("stored PostgreSQL tenant policy version is invalid")?;
    Ok(TenantPolicyVersion {
        id: row.get(0),
        tenant_id: row.get(1),
        sequence: nonnegative_postgres_integer(row.get(2), "policy sequence")?,
        document,
        content_sha256: row.get(4),
        created_by: row.get(5),
        created_at_unix: row.get(6),
        approved_by: row.get(7),
        approved_at_unix: row.get(8),
        active: row.get::<_, Option<bool>>(9).unwrap_or(false),
    })
}

fn policy_deployment_from_row(row: &Row) -> anyhow::Result<TenantPolicyDeployment> {
    Ok(TenantPolicyDeployment {
        id: row.get(0),
        tenant_id: row.get(1),
        sequence: nonnegative_postgres_integer(row.get(2), "policy deployment sequence")?,
        version_id: row.get(3),
        previous_version_id: row.get(4),
        action: PolicyDeploymentAction::from_storage(&row.get::<_, String>(5))?,
        actor_id: row.get(6),
        created_at_unix: row.get(7),
    })
}

fn security_event_from_row(row: &Row) -> anyhow::Result<TenantSecurityEvent> {
    let payload_json: String = row.get(4);
    let payload = serde_json::from_str(&payload_json)
        .context("stored PostgreSQL security event payload is invalid")?;
    Ok(TenantSecurityEvent {
        id: row.get(0),
        tenant_id: row.get(1),
        sequence: nonnegative_postgres_integer(row.get(2), "security event sequence")?,
        event_type: row.get(3),
        payload,
        content_sha256: row.get(5),
        occurred_at_unix: row.get(6),
    })
}

fn webhook_destination_from_row(row: &Row) -> anyhow::Result<WebhookDestination> {
    let event_types_json: String = row.get(3);
    Ok(WebhookDestination {
        id: row.get(0),
        tenant_id: row.get(1),
        url: row.get(2),
        event_types: serde_json::from_str(&event_types_json)
            .context("stored PostgreSQL webhook subscriptions are invalid")?,
        active: row.get(4),
        created_at_unix: row.get(5),
        updated_at_unix: row.get(6),
    })
}

fn webhook_delivery_from_row(row: &Row) -> anyhow::Result<WebhookDelivery> {
    Ok(WebhookDelivery {
        id: row.get(0),
        tenant_id: row.get(1),
        event_id: row.get(2),
        destination_id: row.get(3),
        status: WebhookDeliveryStatus::from_storage(&row.get::<_, String>(4))?,
        attempt_count: nonnegative_postgres_integer(row.get(5), "webhook attempt count")?
            .try_into()
            .context("webhook attempt count exceeds supported range")?,
        next_attempt_at_unix: row.get(6),
        locked_until_unix: row.get(7),
        delivered_at_unix: row.get(8),
        last_http_status: row
            .get::<_, Option<i32>>(9)
            .map(|value| u16::try_from(value).context("stored webhook HTTP status is invalid"))
            .transpose()?,
        last_error: row.get(10),
        created_at_unix: row.get(11),
    })
}

fn pending_webhook_from_pg_row(row: &Row) -> anyhow::Result<PendingWebhookDelivery> {
    let delivery = webhook_delivery_from_row(row)?;
    let destination = WebhookDestination {
        id: row.get(12),
        tenant_id: row.get(13),
        url: row.get(14),
        event_types: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(15))
            .context("stored PostgreSQL webhook subscriptions are invalid")?,
        active: row.get(16),
        created_at_unix: row.get(17),
        updated_at_unix: row.get(18),
    };
    let event_payload_json: String = row.get(23);
    let event = TenantSecurityEvent {
        id: row.get(19),
        tenant_id: row.get(20),
        sequence: nonnegative_postgres_integer(row.get(21), "security event sequence")?,
        event_type: row.get(22),
        payload: serde_json::from_str(&event_payload_json)
            .context("stored PostgreSQL security event payload is invalid")?,
        content_sha256: row.get(24),
        occurred_at_unix: row.get(25),
    };
    Ok(PendingWebhookDelivery {
        delivery,
        destination,
        event,
    })
}

fn usage_quota_policy_from_row(row: &Row) -> anyhow::Result<UsageQuotaPolicy> {
    Ok(UsageQuotaPolicy {
        request_limit: optional_u64(row.get(0), "request quota")?,
        token_limit: optional_u64(row.get(1), "token quota")?,
        cost_usd_micros_limit: optional_u64(row.get(2), "cost quota")?,
        alert_threshold_basis_points: u16::try_from(row.get::<_, i32>(3))
            .context("stored usage quota threshold is outside the supported range")?,
    })
}

fn postgres_integer(value: u64, field: &str) -> anyhow::Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds PostgreSQL integer range"))
}

fn optional_postgres_integer(value: Option<u64>, field: &str) -> anyhow::Result<Option<i64>> {
    value
        .map(|value| postgres_integer(value, field))
        .transpose()
}

fn optional_u64(value: Option<i64>, field: &str) -> anyhow::Result<Option<u64>> {
    value
        .map(|value| u64::try_from(value).with_context(|| format!("stored {field} is negative")))
        .transpose()
}

fn nonnegative_postgres_integer(value: i64, field: &str) -> anyhow::Result<u64> {
    u64::try_from(value).with_context(|| format!("stored {field} is negative"))
}

fn nonnegative_postgres_u32(value: i32, field: &str) -> anyhow::Result<u32> {
    u32::try_from(value).with_context(|| format!("stored {field} is negative"))
}

fn usage_totals_from_postgres_row(row: &Row, offset: usize) -> anyhow::Result<UsageTotals> {
    Ok(UsageTotals {
        request_count: nonnegative_postgres_integer(row.get(offset), "usage request count")?,
        actual_token_events: nonnegative_postgres_integer(
            row.get(offset + 1),
            "actual usage event count",
        )?,
        missing_token_events: nonnegative_postgres_integer(
            row.get(offset + 2),
            "missing usage event count",
        )?,
        priced_events: nonnegative_postgres_integer(
            row.get(offset + 3),
            "priced usage event count",
        )?,
        unpriced_events: nonnegative_postgres_integer(
            row.get(offset + 4),
            "unpriced usage event count",
        )?,
        provider_correlated_events: nonnegative_postgres_integer(
            row.get(offset + 5),
            "provider-correlated usage event count",
        )?,
        input_tokens: nonnegative_postgres_integer(row.get(offset + 6), "input token total")?,
        output_tokens: nonnegative_postgres_integer(row.get(offset + 7), "output token total")?,
        priced_cost_usd_micros: nonnegative_postgres_integer(
            row.get(offset + 8),
            "priced usage cost total",
        )?,
    })
}

fn optional_u32(value: Option<i64>, field: &str) -> anyhow::Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).with_context(|| format!("stored {field} is outside u32 range"))
        })
        .transpose()
}

#[cfg(test)]
impl PostgresTenantStore {
    pub(super) async fn open_for_test(
        connection_url: &str,
        audit_max_rows: usize,
    ) -> anyhow::Result<Self> {
        Self::migrate(
            connection_url,
            audit_max_rows,
            Duration::from_secs(5),
            4,
            Duration::from_secs(5),
            false,
            None,
        )
        .await?;
        Self::open(
            connection_url,
            audit_max_rows,
            Duration::from_secs(5),
            4,
            Duration::from_secs(5),
            false,
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tls_tests {
    use super::PostgresTenantStore;

    #[test]
    fn rejects_a_ca_file_without_certificate_blocks() {
        let path = std::env::temp_dir().join(format!(
            "llm-firewall-invalid-postgres-ca-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a certificate").expect("test CA fixture should be writable");
        let result = PostgresTenantStore::tls_config(path.to_str());
        std::fs::remove_file(&path).expect("test CA fixture should be removable");
        assert!(result.is_err(), "invalid CA bundles must fail closed");
    }
}
