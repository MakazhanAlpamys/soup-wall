// SPDX-License-Identifier: Apache-2.0

//! Browser entry point for organization-selected OIDC authorization-code login.
//!
//! This module starts an organization-selected OIDC login and completes it
//! only after a one-time state check, code exchange, JWKS-backed ID-token
//! verification, and workspace membership lookup.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    handlers::Shared,
    oidc::{random_urlsafe_value, OidcHttpClient, PkcePair, ValidatedEndpoints, CALLBACK_PATH},
    oidc_token::verify_id_token,
    tenant_store::{
        BrowserSessionFederation, IssuedWebhookDestination, IssuedWorkspaceInvitation,
        IssuedWorkspaceServiceAccount, OidcBrowserSession, OrganizationOidcConnection,
        TenantAuditEvent, TenantLimits, TenantModelPolicy, UsageEvent, UsageEventPage,
        UsagePricingStatus, UsageQuotaMetricStatus, UsageQuotaPolicy, UsageQuotaState,
        UsageQuotaStatus, UsageReconciliationObservation, UsageReconciliationRun,
        UsageReconciliationStatus, UsageReport, UsageRetentionPolicy, UsageRetentionRun,
        UsageTokenStatus, WebhookDelivery, WebhookDeliveryStatus, WebhookDestination, Workspace,
        WorkspaceInvitation, WorkspacePermission, WorkspaceRole, WorkspaceServiceAccount,
    },
};

const AUTHORIZATION_STATE_TTL_SECONDS: i64 = 10 * 60;
const BROWSER_SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;
const SESSION_COOKIE_NAME: &str = "__Host-llm-fw-session";
const CUSTOMER_CSRF_HEADER: &str = "x-llm-firewall-csrf-token";
const MAX_BROWSER_SESSION_TOKEN_BYTES: usize = 256;
const MAX_CUSTOMER_PRINCIPAL_ID_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartLoginQuery {
    pub organization_id: String,
    pub workspace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationStartForm {
    pub token: String,
}

/// Parameters returned by a standards-compliant OpenID Provider. Unknown
/// parameters are ignored because providers may include optional diagnostic
/// fields, but none of those browser-supplied values affect authorization.
#[derive(Deserialize)]
pub struct CallbackQuery {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

/// Bounded size for the current workspace's customer-administration history.
/// The handler obtains the workspace solely from the authenticated browser
/// session, never from a client-supplied path or query value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerAuditQuery {
    #[serde(default = "default_customer_audit_limit")]
    pub limit: usize,
}

/// Customer-safe view of proxy request outcomes. Internal tenant and row IDs
/// stay server-side; paths and timing are retained because they are useful for
/// operations without exposing prompts, responses, or credentials.
#[derive(Serialize)]
struct CustomerProxyAuditEvent {
    created_at_unix: i64,
    path: String,
    outcome: String,
    status_code: u16,
    latency_ms: u64,
}

impl From<TenantAuditEvent> for CustomerProxyAuditEvent {
    fn from(event: TenantAuditEvent) -> Self {
        Self {
            created_at_unix: event.created_at_unix,
            path: event.path,
            outcome: event.outcome,
            status_code: event.status_code,
            latency_ms: event.latency_ms,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerUsageQuery {
    pub from_unix: Option<i64>,
    pub until_unix: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerUsageExportQuery {
    pub from_unix: Option<i64>,
    pub until_unix: Option<i64>,
    pub after_id: Option<i64>,
    #[serde(default = "default_customer_usage_export_limit")]
    pub limit: usize,
}

#[derive(Serialize)]
struct CustomerUsageTotals {
    request_count: String,
    actual_token_events: String,
    missing_token_events: String,
    priced_events: String,
    unpriced_events: String,
    provider_correlated_events: String,
    input_tokens: String,
    output_tokens: String,
    priced_cost_usd_micros: String,
}

#[derive(Serialize)]
struct CustomerUsageDaily {
    day_start_unix: i64,
    totals: CustomerUsageTotals,
}

#[derive(Serialize)]
struct CustomerUsageModel {
    provider: String,
    requested_model: String,
    totals: CustomerUsageTotals,
}

#[derive(Serialize)]
struct CustomerUsageReconciliation {
    ready_events: String,
    review_required_events: String,
    missing_provider_response_id_events: String,
    duplicate_provider_response_id_groups: String,
    duplicate_provider_response_id_events: String,
}

#[derive(Serialize)]
struct CustomerUsageReport {
    from_unix: i64,
    until_unix: i64,
    totals: CustomerUsageTotals,
    daily: Vec<CustomerUsageDaily>,
    models: Vec<CustomerUsageModel>,
    reconciliation: CustomerUsageReconciliation,
}

/// A billing preview is deliberately read-only and never becomes an invoice.
/// It exposes only exact usage-ledger totals and marks missing evidence for review.
#[derive(Serialize)]
struct CustomerInvoicePreview {
    currency: &'static str,
    from_unix: i64,
    until_unix: i64,
    status: CustomerInvoicePreviewStatus,
    is_final: bool,
    totals: CustomerUsageTotals,
    line_items: Vec<CustomerInvoiceLineItem>,
    reconciliation: CustomerUsageReconciliation,
    notice: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CustomerInvoicePreviewStatus {
    Ready,
    ReviewRequired,
}

#[derive(Serialize)]
struct CustomerInvoiceLineItem {
    provider: String,
    requested_model: String,
    request_count: String,
    input_tokens: String,
    output_tokens: String,
    cost_usd_micros: String,
}

#[derive(Serialize)]
struct CustomerUsageReconciliationRun {
    id: String,
    source: String,
    statement_id: String,
    record_count: String,
    matched_count: String,
    mismatched_count: String,
    orphan_count: String,
    ambiguous_count: String,
    created_at_unix: i64,
}

#[derive(Serialize)]
struct CustomerUsageReconciliationObservation {
    source_record_id: String,
    provider: String,
    provider_response_id: String,
    input_tokens: Option<String>,
    output_tokens: Option<String>,
    cost_usd_micros: Option<String>,
    status: UsageReconciliationStatus,
    created_at_unix: i64,
}

#[derive(Serialize)]
struct CustomerUsageRetention {
    policy: Option<UsageRetentionPolicy>,
    runs: Vec<CustomerUsageRetentionRun>,
}

#[derive(Serialize)]
struct CustomerUsageRetentionRun {
    id: String,
    retention_days: u32,
    cutoff_unix: i64,
    executed: bool,
    eligible_event_count: String,
    protected_reconciliation_event_count: String,
    eligible_input_tokens: String,
    eligible_output_tokens: String,
    eligible_cost_usd_micros: String,
    deleted_event_count: String,
    created_at_unix: i64,
}

#[derive(Serialize)]
struct CustomerUsageQuotaPolicy {
    request_limit: Option<String>,
    token_limit: Option<String>,
    cost_usd_micros_limit: Option<String>,
    alert_threshold_basis_points: u16,
}

#[derive(Serialize)]
struct CustomerUsageQuotaMetricStatus {
    used: String,
    limit: String,
    state: UsageQuotaState,
}

#[derive(Serialize)]
struct CustomerUsageQuotaStatus {
    from_unix: i64,
    until_unix: i64,
    policy: CustomerUsageQuotaPolicy,
    requests: Option<CustomerUsageQuotaMetricStatus>,
    tokens: Option<CustomerUsageQuotaMetricStatus>,
    cost_usd_micros: Option<CustomerUsageQuotaMetricStatus>,
    missing_token_events: String,
    unpriced_events: String,
    attention_required: bool,
}

#[derive(Clone, Copy)]
enum CustomerUsageRangeError {
    Clock,
    Invalid,
}

/// Read-only controls intentionally exposed to an authorized administrator of
/// the browser session's current workspace. Credentials, internal tenant IDs,
/// counters, and operator defaults are not included.
#[derive(Serialize)]
struct CustomerWorkspaceControls {
    limits: CustomerTenantLimits,
    model_policy: Option<TenantModelPolicy>,
}

#[derive(Serialize)]
struct CustomerCsrfToken {
    token: String,
}

/// Customer-facing webhook configuration deliberately omits the internal
/// tenant identifier. The destination secret is returned only by the create
/// response and is never included in inventory responses.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerWebhookDestinationCreate {
    pub url: String,
    #[serde(default)]
    pub event_types: Vec<String>,
}

#[derive(Serialize)]
struct CustomerWebhookDestination {
    id: String,
    url: String,
    event_types: Vec<String>,
    active: bool,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<WebhookDestination> for CustomerWebhookDestination {
    fn from(destination: WebhookDestination) -> Self {
        Self {
            id: destination.id,
            url: destination.url,
            event_types: destination.event_types,
            active: destination.active,
            created_at_unix: destination.created_at_unix,
            updated_at_unix: destination.updated_at_unix,
        }
    }
}

#[derive(Serialize)]
struct IssuedCustomerWebhookDestination {
    destination: CustomerWebhookDestination,
    secret: String,
}

impl From<IssuedWebhookDestination> for IssuedCustomerWebhookDestination {
    fn from(issued: IssuedWebhookDestination) -> Self {
        Self {
            destination: issued.destination.into(),
            secret: issued.secret,
        }
    }
}

#[derive(Serialize)]
struct CustomerWebhookDelivery {
    id: String,
    event_id: String,
    destination_id: String,
    status: WebhookDeliveryStatus,
    attempt_count: u32,
    next_attempt_at_unix: i64,
    locked_until_unix: Option<i64>,
    delivered_at_unix: Option<i64>,
    last_http_status: Option<u16>,
    last_error: Option<String>,
    created_at_unix: i64,
}

impl From<WebhookDelivery> for CustomerWebhookDelivery {
    fn from(delivery: WebhookDelivery) -> Self {
        Self {
            id: delivery.id,
            event_id: delivery.event_id,
            destination_id: delivery.destination_id,
            status: delivery.status,
            attempt_count: delivery.attempt_count,
            next_attempt_at_unix: delivery.next_attempt_at_unix,
            locked_until_unix: delivery.locked_until_unix,
            delivered_at_unix: delivery.delivered_at_unix,
            last_http_status: delivery.last_http_status,
            last_error: delivery.last_error,
            created_at_unix: delivery.created_at_unix,
        }
    }
}

/// A customer owner may update an existing local membership only. Principal
/// creation and identity linking are deliberately not browser functions:
/// verified OIDC and future SCIM provisioning own that lifecycle.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerWorkspaceMembershipUpdate {
    pub principal_id: String,
    pub role: WorkspaceRole,
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerWorkspaceInvitationCreate {
    pub recipient_label: String,
    pub role: WorkspaceRole,
    pub expires_at_unix: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerWorkspaceInvitationResend {
    pub expires_at_unix: i64,
}

#[derive(Serialize)]
struct IssuedCustomerWorkspaceInvitation {
    invitation: WorkspaceInvitation,
    token: String,
    accept_path: String,
}

impl From<IssuedWorkspaceInvitation> for IssuedCustomerWorkspaceInvitation {
    fn from(issued: IssuedWorkspaceInvitation) -> Self {
        let accept_path = format!("/customer/invitation#{}", issued.token);
        Self {
            invitation: issued.invitation,
            token: issued.token,
            accept_path,
        }
    }
}

/// An owner may explicitly grant an already SCIM-provisioned directory user a
/// role. This request cannot create a local identity, invite an email address,
/// or select another organization: the store verifies the target's SCIM scope
/// in the same transaction as the membership and audit write.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerScimWorkspaceMembershipCreate {
    pub principal_id: String,
    pub role: WorkspaceRole,
}

/// An owner-approved SCIM group mapping has no caller-selectable role. The
/// server intentionally grants only the fixed analyst/read-only bundle.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerScimGroupMappingCreate {
    pub group_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerServiceAccountCreate {
    pub name: String,
    pub expires_at_unix: i64,
}

#[derive(Serialize)]
struct CustomerServiceAccount {
    id: String,
    name: String,
    created_by_principal_id: String,
    active: bool,
    expires_at_unix: String,
    created_at_unix: i64,
    revoked_at_unix: Option<i64>,
}

#[derive(Serialize)]
struct IssuedCustomerServiceAccount {
    account: CustomerServiceAccount,
    token: String,
}

impl From<WorkspaceServiceAccount> for CustomerServiceAccount {
    fn from(account: WorkspaceServiceAccount) -> Self {
        Self {
            id: account.id,
            name: account.name,
            created_by_principal_id: account.created_by_principal_id,
            active: account.active,
            expires_at_unix: account.expires_at_unix.to_string(),
            created_at_unix: account.created_at_unix,
            revoked_at_unix: account.revoked_at_unix,
        }
    }
}

impl From<IssuedWorkspaceServiceAccount> for IssuedCustomerServiceAccount {
    fn from(issued: IssuedWorkspaceServiceAccount) -> Self {
        Self {
            account: issued.account.into(),
            token: issued.token,
        }
    }
}

/// Browser-facing limits intentionally serialize every 64-bit numeric value
/// as decimal text. JavaScript cannot represent every `u64` exactly, and an
/// imprecise dashboard must never be mistaken for an exact financial control.
#[derive(Serialize)]
struct CustomerTenantLimits {
    rate_limit: Option<CustomerRateLimit>,
    spend_limit: Option<CustomerSpendLimit>,
}

#[derive(Serialize)]
struct CustomerRateLimit {
    requests_per_window: u32,
    window_seconds: String,
}

#[derive(Serialize)]
struct CustomerSpendLimit {
    window_seconds: String,
    max_usd_micros: String,
    reserve_usd_micros_per_request: String,
}

impl From<TenantLimits> for CustomerTenantLimits {
    fn from(limits: TenantLimits) -> Self {
        Self {
            rate_limit: limits.rate_limit.map(|rate| CustomerRateLimit {
                requests_per_window: rate.requests_per_window,
                window_seconds: rate.window_seconds.to_string(),
            }),
            spend_limit: limits.spend_limit.map(|spend| CustomerSpendLimit {
                window_seconds: spend.window_seconds.to_string(),
                max_usd_micros: spend.max_usd_micros.to_string(),
                reserve_usd_micros_per_request: spend.reserve_usd_micros_per_request.to_string(),
            }),
        }
    }
}

impl From<crate::tenant_store::UsageTotals> for CustomerUsageTotals {
    fn from(totals: crate::tenant_store::UsageTotals) -> Self {
        Self {
            request_count: totals.request_count.to_string(),
            actual_token_events: totals.actual_token_events.to_string(),
            missing_token_events: totals.missing_token_events.to_string(),
            priced_events: totals.priced_events.to_string(),
            unpriced_events: totals.unpriced_events.to_string(),
            provider_correlated_events: totals.provider_correlated_events.to_string(),
            input_tokens: totals.input_tokens.to_string(),
            output_tokens: totals.output_tokens.to_string(),
            priced_cost_usd_micros: totals.priced_cost_usd_micros.to_string(),
        }
    }
}

impl From<UsageReport> for CustomerUsageReport {
    fn from(report: UsageReport) -> Self {
        Self {
            from_unix: report.from_unix,
            until_unix: report.until_unix,
            totals: report.totals.into(),
            daily: report
                .daily
                .into_iter()
                .map(|day| CustomerUsageDaily {
                    day_start_unix: day.day_start_unix,
                    totals: day.totals.into(),
                })
                .collect(),
            models: report
                .models
                .into_iter()
                .map(|model| CustomerUsageModel {
                    provider: model.provider,
                    requested_model: model.requested_model,
                    totals: model.totals.into(),
                })
                .collect(),
            reconciliation: CustomerUsageReconciliation {
                ready_events: report.reconciliation.ready_events.to_string(),
                review_required_events: report.reconciliation.review_required_events.to_string(),
                missing_provider_response_id_events: report
                    .reconciliation
                    .missing_provider_response_id_events
                    .to_string(),
                duplicate_provider_response_id_groups: report
                    .reconciliation
                    .duplicate_provider_response_id_groups
                    .to_string(),
                duplicate_provider_response_id_events: report
                    .reconciliation
                    .duplicate_provider_response_id_events
                    .to_string(),
            },
        }
    }
}

impl From<UsageReport> for CustomerInvoicePreview {
    fn from(report: UsageReport) -> Self {
        let status = if report.totals.missing_token_events == 0
            && report.totals.unpriced_events == 0
            && report.reconciliation.review_required_events == 0
        {
            CustomerInvoicePreviewStatus::Ready
        } else {
            CustomerInvoicePreviewStatus::ReviewRequired
        };
        Self {
            currency: "USD",
            from_unix: report.from_unix,
            until_unix: report.until_unix,
            status,
            is_final: false,
            totals: report.totals.clone().into(),
            line_items: report
                .models
                .into_iter()
                .map(|model| CustomerInvoiceLineItem {
                    provider: model.provider,
                    requested_model: model.requested_model,
                    request_count: model.totals.request_count.to_string(),
                    input_tokens: model.totals.input_tokens.to_string(),
                    output_tokens: model.totals.output_tokens.to_string(),
                    cost_usd_micros: model.totals.priced_cost_usd_micros.to_string(),
                })
                .collect(),
            reconciliation: CustomerUsageReconciliation {
                ready_events: report.reconciliation.ready_events.to_string(),
                review_required_events: report.reconciliation.review_required_events.to_string(),
                missing_provider_response_id_events: report
                    .reconciliation
                    .missing_provider_response_id_events
                    .to_string(),
                duplicate_provider_response_id_groups: report
                    .reconciliation
                    .duplicate_provider_response_id_groups
                    .to_string(),
                duplicate_provider_response_id_events: report
                    .reconciliation
                    .duplicate_provider_response_id_events
                    .to_string(),
            },
            notice: "Preview only. Final invoices require provider reconciliation, tax/privacy review, and an explicit billing workflow.",
        }
    }
}

impl From<UsageReconciliationRun> for CustomerUsageReconciliationRun {
    fn from(run: UsageReconciliationRun) -> Self {
        Self {
            id: run.id,
            source: run.source,
            statement_id: run.statement_id,
            record_count: run.record_count.to_string(),
            matched_count: run.matched_count.to_string(),
            mismatched_count: run.mismatched_count.to_string(),
            orphan_count: run.orphan_count.to_string(),
            ambiguous_count: run.ambiguous_count.to_string(),
            created_at_unix: run.created_at_unix,
        }
    }
}

impl From<UsageReconciliationObservation> for CustomerUsageReconciliationObservation {
    fn from(observation: UsageReconciliationObservation) -> Self {
        Self {
            source_record_id: observation.source_record_id,
            provider: observation.provider,
            provider_response_id: observation.provider_response_id,
            input_tokens: observation.input_tokens.map(|value| value.to_string()),
            output_tokens: observation.output_tokens.map(|value| value.to_string()),
            cost_usd_micros: observation.cost_usd_micros.map(|value| value.to_string()),
            status: observation.status,
            created_at_unix: observation.created_at_unix,
        }
    }
}

impl From<UsageRetentionRun> for CustomerUsageRetentionRun {
    fn from(run: UsageRetentionRun) -> Self {
        Self {
            id: run.id,
            retention_days: run.retention_days,
            cutoff_unix: run.cutoff_unix,
            executed: run.executed,
            eligible_event_count: run.eligible_event_count.to_string(),
            protected_reconciliation_event_count: run
                .protected_reconciliation_event_count
                .to_string(),
            eligible_input_tokens: run.eligible_input_tokens.to_string(),
            eligible_output_tokens: run.eligible_output_tokens.to_string(),
            eligible_cost_usd_micros: run.eligible_cost_usd_micros.to_string(),
            deleted_event_count: run.deleted_event_count.to_string(),
            created_at_unix: run.created_at_unix,
        }
    }
}

impl From<UsageQuotaPolicy> for CustomerUsageQuotaPolicy {
    fn from(policy: UsageQuotaPolicy) -> Self {
        Self {
            request_limit: policy.request_limit.map(|value| value.to_string()),
            token_limit: policy.token_limit.map(|value| value.to_string()),
            cost_usd_micros_limit: policy.cost_usd_micros_limit.map(|value| value.to_string()),
            alert_threshold_basis_points: policy.alert_threshold_basis_points,
        }
    }
}

impl From<UsageQuotaMetricStatus> for CustomerUsageQuotaMetricStatus {
    fn from(metric: UsageQuotaMetricStatus) -> Self {
        Self {
            used: metric.used.to_string(),
            limit: metric.limit.to_string(),
            state: metric.state,
        }
    }
}

impl From<UsageQuotaStatus> for CustomerUsageQuotaStatus {
    fn from(status: UsageQuotaStatus) -> Self {
        Self {
            from_unix: status.from_unix,
            until_unix: status.until_unix,
            policy: status.policy.into(),
            requests: status.requests.map(Into::into),
            tokens: status.tokens.map(Into::into),
            cost_usd_micros: status.cost_usd_micros.map(Into::into),
            missing_token_events: status.missing_token_events.to_string(),
            unpriced_events: status.unpriced_events.to_string(),
            attention_required: status.attention_required,
        }
    }
}

fn default_customer_audit_limit() -> usize {
    100
}

fn default_customer_usage_export_limit() -> usize {
    1_000
}

/// Begin login for an explicitly selected organization workspace. A browser
/// never gets to select the issuer or redirect target: both come from the
/// owner-managed organization connection after discovery metadata validation.
pub async fn start_login(
    State(state): State<Shared>,
    Query(query): Query<StartLoginQuery>,
) -> Response {
    start_login_for_workspace(&state, &query.organization_id, &query.workspace_id, None).await
}

/// Begin OIDC enrollment from a raw invitation bearer posted by the
/// same-origin acceptance page. Resolution determines the organization and
/// workspace; no routing input is accepted from the browser.
pub async fn start_invitation_login(
    State(state): State<Shared>,
    Form(form): Form<InvitationStartForm>,
) -> Response {
    if form.token.len() > 256 || !form.token.starts_with("llmfw_invite_") {
        return login_unavailable();
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let invitation = match store
        .workspace_invitation_for_token_async(&form.token)
        .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => return login_unavailable(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to resolve workspace invitation");
            return control_plane_unavailable();
        }
    };
    start_login_for_workspace(
        &state,
        &invitation.organization_id,
        &invitation.workspace_id,
        Some(&invitation.id),
    )
    .await
}

async fn start_login_for_workspace(
    state: &Shared,
    organization_id: &str,
    workspace_id: &str,
    invitation_id: Option<&str>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };

    match store
        .active_workspace_in_organization_async(organization_id, workspace_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return login_unavailable(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to verify OIDC workspace");
            return control_plane_unavailable();
        }
    }

    let connection = match store
        .organization_oidc_connection_async(organization_id)
        .await
    {
        Ok(Some(connection)) => connection,
        Ok(None) => return login_unavailable(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OIDC connection");
            return control_plane_unavailable();
        }
    };
    if !connection.active || callback_path(&connection).is_err() {
        return login_unavailable();
    }

    let client = match OidcHttpClient::new() {
        Ok(client) => client,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create OIDC HTTP client");
            return control_plane_unavailable();
        }
    };
    let endpoints = match client.fetch_validated_discovery(&connection).await {
        Ok(endpoints) => endpoints,
        Err(error_value) => {
            tracing::warn!(error = %error_value, organization_id = %connection.organization_id, "OIDC discovery failed");
            return login_unavailable();
        }
    };

    let pkce = PkcePair::generate();
    let nonce = random_urlsafe_value(32);
    let expires_at_unix = match authorization_state_expiry() {
        Ok(expires_at_unix) => expires_at_unix,
        Err(error_value) => {
            tracing::error!(error = %error_value, "system clock cannot create OIDC state");
            return control_plane_unavailable();
        }
    };
    let state_value = match cipher.seal_authorization_state_with_invitation(
        &connection.organization_id,
        workspace_id,
        invitation_id,
        &pkce,
        &nonce,
        expires_at_unix,
    ) {
        Ok(state_value) => state_value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to encrypt OIDC state");
            return control_plane_unavailable();
        }
    };
    if let Err(error_value) = store
        .reserve_oidc_authorization_state_async(
            &state_value,
            &connection.organization_id,
            expires_at_unix,
        )
        .await
    {
        tracing::warn!(error = %error_value, organization_id = %connection.organization_id, "failed to reserve OIDC state");
        return control_plane_unavailable();
    }

    match authorization_url(&endpoints, &connection, &state_value, &pkce, &nonce) {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to build OIDC authorization redirect");
            control_plane_unavailable()
        }
    }
}

/// Finish an authorization-code flow. The state is authenticated and consumed
/// before any provider request, which makes it single-use even when a browser
/// retries a callback. A successful provider response still grants nothing
/// unless the verified `(issuer, subject)` has an active local membership in
/// the workspace sealed into state at login start.
pub async fn callback(State(state): State<Shared>, Query(query): Query<CallbackQuery>) -> Response {
    let client = match OidcHttpClient::new() {
        Ok(client) => client,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create OIDC HTTP client");
            return control_plane_unavailable();
        }
    };
    callback_with_client(state, query, client).await
}

async fn callback_with_client(
    state: Shared,
    query: CallbackQuery,
    client: OidcHttpClient,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(state_value) = query.state.as_deref() else {
        return login_failed();
    };
    let authorization_state = match cipher.open_authorization_state(state_value) {
        Ok(authorization_state) => authorization_state,
        Err(_) => return login_failed(),
    };
    let now = match now_unix() {
        Ok(now) => now,
        Err(error_value) => {
            tracing::error!(error = %error_value, "system clock cannot validate OIDC callback");
            return control_plane_unavailable();
        }
    };
    if authorization_state.expires_at_unix() < now {
        return login_failed();
    }
    match store
        .consume_oidc_authorization_state_async(state_value, authorization_state.organization_id())
        .await
    {
        Ok(true) => {}
        Ok(false) => return login_failed(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to consume OIDC callback state");
            return control_plane_unavailable();
        }
    }
    if query.error.is_some() {
        return login_failed();
    }
    let Some(code) = query.code.as_deref() else {
        return login_failed();
    };

    let connection = match store
        .organization_oidc_connection_async(authorization_state.organization_id())
        .await
    {
        Ok(Some(connection)) if connection.active && callback_path(&connection).is_ok() => {
            connection
        }
        Ok(_) => return login_failed(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load OIDC connection for callback");
            return control_plane_unavailable();
        }
    };
    let endpoints = match client.fetch_validated_discovery(&connection).await {
        Ok(endpoints) => endpoints,
        Err(error_value) => {
            tracing::warn!(error = %error_value, "OIDC callback discovery failed");
            return login_failed();
        }
    };
    let jwks = match client.fetch_jwks(&endpoints).await {
        Ok(jwks) => jwks,
        Err(error_value) => {
            tracing::warn!(error = %error_value, "OIDC callback JWKS fetch failed");
            return login_failed();
        }
    };
    let token_response = match client
        .exchange_authorization_code(
            &endpoints,
            &connection,
            code,
            authorization_state.code_verifier(),
        )
        .await
    {
        Ok(token_response) => token_response,
        Err(error_value) => {
            tracing::warn!(error = %error_value, "OIDC authorization-code exchange failed");
            return login_failed();
        }
    };
    let identity = match verify_id_token(
        token_response.id_token(),
        &jwks,
        &connection,
        authorization_state.nonce(),
    ) {
        Ok(identity) => identity,
        Err(error_value) => {
            tracing::warn!(error = %error_value, "OIDC ID token verification failed");
            return login_failed();
        }
    };
    let access_result = match authorization_state.invitation_id() {
        Some(invitation_id) => {
            store
                .accept_workspace_invitation_oidc_async(
                    invitation_id,
                    authorization_state.organization_id(),
                    authorization_state.workspace_id(),
                    &identity.issuer,
                    &identity.subject,
                )
                .await
        }
        None => {
            store
                .verified_identity_workspace_access_async(
                    authorization_state.organization_id(),
                    authorization_state.workspace_id(),
                    &identity.issuer,
                    &identity.subject,
                )
                .await
        }
    };
    let access = match access_result {
        Ok(Some(access)) => access,
        Ok(None) => return login_failed(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize verified OIDC identity");
            return control_plane_unavailable();
        }
    };
    if access.organization_id != authorization_state.organization_id()
        || access.workspace_id != authorization_state.workspace_id()
    {
        tracing::error!(
            state_organization_id = %authorization_state.organization_id(),
            state_workspace_id = %authorization_state.workspace_id(),
            access_organization_id = %access.organization_id,
            access_workspace_id = %access.workspace_id,
            "OIDC access scope did not match authenticated authorization state"
        );
        return login_failed();
    }
    let expires_at_unix = match browser_session_expiry() {
        Ok(expires_at_unix) => expires_at_unix,
        Err(error_value) => {
            tracing::error!(error = %error_value, "system clock cannot create OIDC session");
            return control_plane_unavailable();
        }
    };
    let session = match store
        .issue_oidc_browser_session_async(&access, BrowserSessionFederation::Oidc, expires_at_unix)
        .await
    {
        Ok(session) => session,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create OIDC browser session");
            return control_plane_unavailable();
        }
    };
    let cookie = match session_cookie(&session.token, BROWSER_SESSION_TTL_SECONDS) {
        Ok(cookie) => cookie,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create OIDC session cookie");
            return control_plane_unavailable();
        }
    };
    let mut response = Redirect::to("/customer").into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

/// Return the current customer session for a future dashboard or API client.
/// This endpoint deliberately exposes only local opaque IDs and the current
/// role, never an upstream ID token, access token, email address, or claim set.
pub async fn customer_session(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => customer_json(session),
        Ok(None) => customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session");
            control_plane_unavailable()
        }
    }
}

/// List workspace-scoped machine identities. The store applies the same RBAC
/// check again, so this endpoint remains safe even if the UI is bypassed.
pub async fn customer_service_accounts(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate service-account session");
            return control_plane_unavailable();
        }
    };
    match store
        .list_workspace_service_accounts_async(
            &session.access.workspace_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(accounts) => customer_json(
            accounts
                .into_iter()
                .map(CustomerServiceAccount::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list service accounts");
            control_plane_unavailable()
        }
    }
}

/// Create a machine identity for the current workspace member. The token is
/// returned in this response only; it cannot be recovered later.
pub async fn create_customer_service_account(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<CustomerServiceAccountCreate>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let Some(csrf) = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return customer_csrf_invalid();
    };
    if !cipher.verifies_browser_csrf_token(token, csrf) {
        return customer_csrf_invalid();
    }
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate service-account session");
            return control_plane_unavailable();
        }
    };
    match store
        .create_workspace_service_account_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &request.name,
            request.expires_at_unix,
        )
        .await
    {
        Ok(issued) => customer_json(IssuedCustomerServiceAccount::from(issued)),
        Err(error_value) if error_value.to_string().contains("not permitted") => {
            customer_forbidden()
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create service account");
            error(
                StatusCode::BAD_REQUEST,
                "service_account_invalid",
                "Service account could not be created",
            )
        }
    }
}

/// Revoke one machine identity in the current workspace. Owner/admin may
/// revoke any account; developer may revoke only an account they created.
pub async fn revoke_customer_service_account(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let Some(csrf) = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return customer_csrf_invalid();
    };
    if !cipher.verifies_browser_csrf_token(token, csrf) {
        return customer_csrf_invalid();
    }
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate service-account session");
            return control_plane_unavailable();
        }
    };
    match store
        .revoke_workspace_service_account_async(
            &session.access.workspace_id,
            &account_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(true) => customer_json(serde_json::json!({ "revoked": true })),
        Ok(false) => customer_forbidden(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke service account");
            control_plane_unavailable()
        }
    }
}

/// Issue a CSRF proof bound to the current opaque browser session. Future
/// state-changing customer endpoints require this value in a custom request
/// header, which cross-origin HTML forms cannot set.
pub async fn customer_csrf(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(_)) => customer_json(CustomerCsrfToken {
            token: cipher.browser_csrf_token(token),
        }),
        Ok(None) => customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for CSRF token");
            control_plane_unavailable()
        }
    }
}

/// List webhook destinations for the authenticated workspace. Read access is
/// shared with the audit view; the response removes the internal tenant ID and
/// never includes a destination secret.
pub async fn customer_webhook_destinations(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadAudit)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_webhook_destinations_async(&workspace.tenant_id)
        .await
    {
        Ok(destinations) => customer_json(
            destinations
                .into_iter()
                .map(CustomerWebhookDestination::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer webhook destinations");
            control_plane_unavailable()
        }
    }
}

/// Create a webhook destination for the current workspace. CSRF is checked at
/// the browser boundary and the store repeats an owner-only check atomically
/// with the destination insert and workspace audit event.
pub async fn create_customer_webhook_destination(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<CustomerWebhookDestinationCreate>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let Some(csrf) = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return customer_csrf_invalid();
    };
    if !cipher.verifies_browser_csrf_token(token, csrf) {
        return customer_csrf_invalid();
    }
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer webhook session");
            return control_plane_unavailable();
        }
    };
    match store
        .create_workspace_webhook_destination_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &request.url,
            &request.event_types,
        )
        .await
    {
        Ok(issued) => customer_json(IssuedCustomerWebhookDestination::from(issued)),
        Err(error_value) if error_value.to_string().contains("not permitted") => {
            customer_forbidden()
        }
        Err(error_value) if error_value.to_string().contains("not configured") => {
            tracing::error!(error = %error_value, "customer webhook signing key is not configured");
            control_plane_unavailable()
        }
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create customer webhook destination");
            error(
                StatusCode::BAD_REQUEST,
                "customer_webhook_destination_error",
                "The webhook destination could not be created",
            )
        }
    }
}

/// Deactivate a webhook destination owned by this workspace. Destination IDs
/// are accepted only as opaque selectors; the store binds them to the current
/// workspace and owner in the same write as the audit event.
pub async fn deactivate_customer_webhook_destination(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(destination_id): Path<String>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let Some(csrf) = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return customer_csrf_invalid();
    };
    if !cipher.verifies_browser_csrf_token(token, csrf) {
        return customer_csrf_invalid();
    }
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer webhook session");
            return control_plane_unavailable();
        }
    };
    match store
        .deactivate_workspace_webhook_destination_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &destination_id,
        )
        .await
    {
        Ok(true) => customer_json(serde_json::json!({ "deactivated": true })),
        Ok(false) => customer_forbidden(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to deactivate customer webhook destination");
            control_plane_unavailable()
        }
    }
}

/// Return bounded delivery status for the current workspace. Payload bodies
/// and signing material are never stored in or returned from this endpoint.
pub async fn customer_webhook_deliveries(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadAudit)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_webhook_deliveries_async(&workspace.tenant_id, query.limit)
        .await
    {
        Ok(deliveries) => customer_json(
            deliveries
                .into_iter()
                .map(CustomerWebhookDelivery::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer webhook deliveries");
            control_plane_unavailable()
        }
    }
}

/// Read the current workspace's customer-administration audit history.
///
/// The opaque browser session is resolved before both authorization and scope
/// selection. Consequently a browser cannot query another workspace by
/// changing a tenant/workspace identifier, and UI visibility is never an
/// authorization boundary.
pub async fn customer_workspace_audit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for workspace audit");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ReadAudit,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer workspace audit");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .list_workspace_admin_audit_async(&session.access.workspace_id, query.limit)
        .await
    {
        Ok(events) => customer_json(events),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer workspace audit");
            control_plane_unavailable()
        }
    }
}

/// Read recent proxy request outcomes for the authenticated workspace. The
/// tenant is resolved from the active workspace rather than a browser-supplied
/// identifier, and the response omits internal row/tenant IDs and all content.
pub async fn customer_workspace_proxy_audit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadAudit)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_audit_async(&workspace.tenant_id, query.limit)
        .await
    {
        Ok(events) => customer_json(
            events
                .into_iter()
                .map(CustomerProxyAuditEvent::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer proxy audit");
            control_plane_unavailable()
        }
    }
}

/// Return exact usage aggregates for the authenticated workspace. Every
/// 64-bit counter is encoded as decimal text for browser precision, and the
/// reconciliation section describes evidence quality rather than claiming an
/// external provider has confirmed the events.
pub async fn customer_workspace_usage(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerUsageQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let (from_unix, until_unix) = match customer_usage_range(query.from_unix, query.until_unix) {
        Ok(range) => range,
        Err(CustomerUsageRangeError::Clock) => return control_plane_unavailable(),
        Err(CustomerUsageRangeError::Invalid) => return customer_usage_range_invalid(),
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .usage_report_async(&workspace.tenant_id, from_unix, until_unix)
        .await
    {
        Ok(report) => customer_json(CustomerUsageReport::from(report)),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to aggregate customer workspace usage");
            control_plane_unavailable()
        }
    }
}

/// Return a read-only invoice preview from immutable, reconciliable usage
/// events. This endpoint never charges a customer, creates an invoice, or
/// calls a payment provider.
pub async fn customer_workspace_invoice_preview(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerUsageQuery>,
) -> Response {
    let (_, workspace) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageBilling,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let (from_unix, until_unix) = match customer_usage_range(query.from_unix, query.until_unix) {
        Ok(range) => range,
        Err(CustomerUsageRangeError::Clock) => return control_plane_unavailable(),
        Err(CustomerUsageRangeError::Invalid) => return customer_usage_range_invalid(),
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .usage_report_async(&workspace.tenant_id, from_unix, until_unix)
        .await
    {
        Ok(report) => customer_json(CustomerInvoicePreview::from(report)),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to build customer invoice preview");
            control_plane_unavailable()
        }
    }
}

/// Export a bounded, cursor-paginated page of privacy-safe ledger evidence.
/// The CSV contains no prompt, response body, credential, or customer email.
pub async fn export_customer_workspace_usage(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerUsageExportQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ExportUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let (from_unix, until_unix) = match customer_usage_range(query.from_unix, query.until_unix) {
        Ok(range) => range,
        Err(CustomerUsageRangeError::Clock) => return control_plane_unavailable(),
        Err(CustomerUsageRangeError::Invalid) => return customer_usage_range_invalid(),
    };
    if query.after_id.is_some_and(|value| value < 0) {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_usage_export_cursor_error",
            "Usage export cursor must be a non-negative event ID",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let page = match store
        .list_usage_events_range_async(
            &workspace.tenant_id,
            from_unix,
            until_unix,
            query.after_id,
            query.limit,
        )
        .await
    {
        Ok(page) => page,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to export customer workspace usage");
            return control_plane_unavailable();
        }
    };
    customer_usage_csv_response(page)
}

pub async fn customer_workspace_usage_reconciliation_runs(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_usage_reconciliation_runs_async(&workspace.tenant_id, query.limit)
        .await
    {
        Ok(runs) => customer_json(
            runs.into_iter()
                .map(CustomerUsageReconciliationRun::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer reconciliation runs");
            control_plane_unavailable()
        }
    }
}

pub async fn customer_workspace_usage_reconciliation_observations(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_usage_reconciliation_observations_async(&workspace.tenant_id, &run_id, query.limit)
        .await
    {
        Ok(observations) => customer_json(
            observations
                .into_iter()
                .map(CustomerUsageReconciliationObservation::from)
                .collect::<Vec<_>>(),
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer reconciliation observations");
            control_plane_unavailable()
        }
    }
}

/// Show the opt-in retention policy and immutable run history without
/// exposing platform administrator identities or an internal tenant ID.
pub async fn customer_workspace_usage_retention(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<CustomerAuditQuery>,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let policy = match store
        .usage_retention_policy_async(&workspace.tenant_id)
        .await
    {
        Ok(policy) => policy,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load customer usage retention policy");
            return control_plane_unavailable();
        }
    };
    match store
        .list_usage_retention_runs_async(&workspace.tenant_id, query.limit)
        .await
    {
        Ok(runs) => customer_json(CustomerUsageRetention {
            policy,
            runs: runs
                .into_iter()
                .map(CustomerUsageRetentionRun::from)
                .collect(),
        }),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer usage retention runs");
            control_plane_unavailable()
        }
    }
}

/// Owners may opt in to or disable a retention policy. This endpoint never
/// executes deletion; a separate platform-owner operation must do that after
/// inspecting a dry-run.
pub async fn set_customer_workspace_usage_retention(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(policy): Json<Option<UsageRetentionPolicy>>,
) -> Response {
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageBilling,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .set_workspace_usage_retention_policy_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            policy.clone(),
        )
        .await
    {
        Ok(()) => customer_json(policy),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save customer usage retention policy");
            error(
                StatusCode::BAD_REQUEST,
                "customer_usage_retention_policy_error",
                "The usage retention policy could not be saved",
            )
        }
    }
}

/// Return current UTC-month quota and in-app alert state. Missing provider
/// token or pricing evidence is never shown as a healthy exact total.
pub async fn customer_workspace_usage_quota(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let (_, workspace) =
        match customer_workspace_for_permission(&state, &headers, WorkspacePermission::ReadUsage)
            .await
        {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store.usage_quota_status_async(&workspace.tenant_id).await {
        Ok(status) => customer_json(status.map(CustomerUsageQuotaStatus::from)),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load customer usage quota status");
            control_plane_unavailable()
        }
    }
}

/// Customer owners may configure or clear monitoring thresholds. These
/// thresholds only produce dashboard alerts and never block traffic or bill.
pub async fn set_customer_workspace_usage_quota(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(policy): Json<Option<UsageQuotaPolicy>>,
) -> Response {
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageBilling,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .set_workspace_usage_quota_policy_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            policy.clone(),
        )
        .await
    {
        Ok(()) => customer_json(policy.map(CustomerUsageQuotaPolicy::from)),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save customer usage quota policy");
            error(
                StatusCode::BAD_REQUEST,
                "customer_usage_quota_policy_error",
                "The usage quota policy could not be saved",
            )
        }
    }
}

/// Return the current workspace's member directory to an owner. The workspace
/// is always derived from the opaque browser session; this endpoint never
/// accepts an organization or workspace identifier from the browser.
pub async fn customer_workspace_members(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for member list");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer member list");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .list_workspace_members_async(&session.access.workspace_id)
        .await
    {
        Ok(members) => customer_json(members),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer workspace members");
            control_plane_unavailable()
        }
    }
}

/// List invitation metadata for the current workspace. The raw token is never
/// part of this repeatable inventory.
pub async fn customer_workspace_invitations(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageMembership,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .list_workspace_invitations_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(invitations) => customer_json(invitations),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer workspace invitations");
            control_plane_unavailable()
        }
    }
}

/// Create one fixed-role, short-lived invitation. The raw bearer and fragment
/// acceptance path are returned only in this response.
pub async fn create_customer_workspace_invitation(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(create): Json<CustomerWorkspaceInvitationCreate>,
) -> Response {
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageMembership,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .create_workspace_invitation_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &create.recipient_label,
            create.role,
            create.expires_at_unix,
        )
        .await
    {
        Ok(issued) => customer_json(IssuedCustomerWorkspaceInvitation::from(issued)),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create customer workspace invitation");
            error(
                StatusCode::BAD_REQUEST,
                "customer_invitation_error",
                "The workspace invitation could not be created",
            )
        }
    }
}

/// Revoke an unconsumed invitation. Workspace and actor identity always come
/// from the authenticated browser session.
pub async fn revoke_customer_workspace_invitation(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(invitation_id): Path<String>,
) -> Response {
    if invitation_id.is_empty() || invitation_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_invitation_error",
            "The workspace invitation target is invalid",
        );
    }
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageMembership,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .revoke_workspace_invitation_as_owner_async(
            &session.access.workspace_id,
            &invitation_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "customer_invitation_error",
            "The active workspace invitation was not found",
        ),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to revoke customer workspace invitation");
            error(
                StatusCode::BAD_REQUEST,
                "customer_invitation_error",
                "The workspace invitation could not be revoked",
            )
        }
    }
}

/// Revoke an unconsumed invitation and issue a new bearer with the same label
/// and role. The raw replacement token is returned only in this response.
pub async fn resend_customer_workspace_invitation(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(invitation_id): Path<String>,
    Json(resend): Json<CustomerWorkspaceInvitationResend>,
) -> Response {
    if invitation_id.is_empty() || invitation_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_invitation_error",
            "The workspace invitation target is invalid",
        );
    }
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let (session, _) = match customer_workspace_for_permission(
        &state,
        &headers,
        WorkspacePermission::ManageMembership,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    match store
        .resend_workspace_invitation_as_owner_async(
            &session.access.workspace_id,
            &invitation_id,
            &session.access.principal_id,
            resend.expires_at_unix,
        )
        .await
    {
        Ok(Some(issued)) => customer_json(IssuedCustomerWorkspaceInvitation::from(issued)),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "customer_invitation_error",
            "The active workspace invitation was not found",
        ),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to resend customer workspace invitation");
            error(
                StatusCode::BAD_REQUEST,
                "customer_invitation_error",
                "The workspace invitation could not be resent",
            )
        }
    }
}

/// List only display-safe, active SCIM directory users that belong to the
/// current owner's organization. This does not reveal an IdP username, email,
/// external ID, or a user from another customer.
pub async fn customer_workspace_scim_users(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM directory");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM directory read");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .list_workspace_scim_users_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(users) => customer_json(users),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer SCIM directory");
            control_plane_unavailable()
        }
    }
}

/// List display-safe active SCIM groups in the current owner's organization.
/// A group has no authority until the owner explicitly creates a mapping.
pub async fn customer_workspace_scim_groups(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM groups");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM group read");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .list_workspace_scim_groups_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(groups) => customer_json(groups),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer SCIM groups");
            control_plane_unavailable()
        }
    }
}

/// List current explicit group-to-workspace grants. The request is owner-only
/// even though the resulting analyst permission is read-only.
pub async fn customer_workspace_scim_group_mappings(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM group mappings");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM mapping read");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .list_workspace_scim_group_mappings_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
        )
        .await
    {
        Ok(mappings) => customer_json(mappings),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list customer SCIM group mappings");
            control_plane_unavailable()
        }
    }
}

/// Create an explicit owner-approved analyst grant for one SCIM group. There
/// is no role field: IdP membership can never obtain a mutation-capable role.
pub async fn create_customer_workspace_scim_group_mapping(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(create): Json<CustomerScimGroupMappingCreate>,
) -> Response {
    if create.group_id.is_empty() || create.group_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_scim_group_mapping_error",
            "The SCIM group target is invalid",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM group mapping");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM group mapping");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .create_workspace_scim_group_mapping_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &create.group_id,
        )
        .await
    {
        Ok(created) => customer_json(serde_json::json!({ "created": created })),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create customer SCIM group mapping");
            error(
                StatusCode::BAD_REQUEST,
                "customer_scim_group_mapping_error",
                "The SCIM group could not be mapped to this workspace",
            )
        }
    }
}

/// Revoke an explicit group mapping. A browser path parameter identifies only
/// a group; workspace and actor are taken from the authenticated session.
pub async fn delete_customer_workspace_scim_group_mapping(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
) -> Response {
    if group_id.is_empty() || group_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_scim_group_mapping_error",
            "The SCIM group target is invalid",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM group unmapping");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM group unmapping");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .delete_workspace_scim_group_mapping_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &group_id,
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "customer_scim_group_mapping_error",
            "The SCIM group mapping was not found",
        ),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to delete customer SCIM group mapping");
            error(
                StatusCode::BAD_REQUEST,
                "customer_scim_group_mapping_error",
                "The SCIM group mapping could not be removed",
            )
        }
    }
}

/// Change a role or suspend/reactivate an existing member of the current
/// workspace. Only an active owner may use this endpoint; both CSRF and the
/// owner check are repeated in the state-changing transaction. The store also
/// refuses to remove or demote the final active owner.
pub async fn update_customer_workspace_membership(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(update): Json<CustomerWorkspaceMembershipUpdate>,
) -> Response {
    if update.principal_id.is_empty() || update.principal_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES
    {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_membership_error",
            "The membership target is invalid",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for membership mutation");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer membership mutation");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .update_workspace_membership_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &update.principal_id,
            update.role,
            update.active,
        )
        .await
    {
        Ok(membership) => customer_json(membership),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save customer workspace membership");
            error(
                StatusCode::BAD_REQUEST,
                "customer_membership_error",
                "The workspace membership could not be saved",
            )
        }
    }
}

/// Add or reactivate a role for one already SCIM-provisioned user. Browser
/// input provides only a local opaque principal ID and requested role; both
/// organization scope and owner authority are rechecked by the store before
/// it records the membership and actor-attributed audit event.
pub async fn assign_customer_workspace_scim_user(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(create): Json<CustomerScimWorkspaceMembershipCreate>,
) -> Response {
    if create.principal_id.is_empty() || create.principal_id.len() > MAX_CUSTOMER_PRINCIPAL_ID_BYTES
    {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_scim_membership_error",
            "The SCIM membership target is invalid",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer session for SCIM assignment");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageMembership,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer SCIM assignment");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .assign_scim_user_to_workspace_as_owner_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            &create.principal_id,
            create.role,
        )
        .await
    {
        Ok(membership) => customer_json(membership),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to assign SCIM user to customer workspace");
            error(
                StatusCode::BAD_REQUEST,
                "customer_scim_membership_error",
                "The SCIM user could not be assigned to this workspace",
            )
        }
    }
}

/// Return configuration controls for the authenticated session's workspace.
///
/// This is deliberately read-only in the first customer panel. It re-checks
/// `ManagePolicies`, obtains the active workspace-to-tenant relation from the
/// control plane, and verifies the session organization matches it before
/// loading any tenant-scoped record.
pub async fn customer_workspace_controls(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for controls");
            return control_plane_unavailable();
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManagePolicies,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer workspace controls");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    let workspace = match store
        .active_workspace_by_id_async(&session.access.workspace_id)
        .await
    {
        Ok(Some(workspace)) if workspace.organization_id == session.access.organization_id => {
            workspace
        }
        Ok(Some(_)) => {
            tracing::error!(workspace_id = %session.access.workspace_id, "workspace organization did not match authenticated customer session");
            return control_plane_unavailable();
        }
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to resolve customer workspace controls");
            return control_plane_unavailable();
        }
    };
    let limits = match store.limits_for_async(&workspace.tenant_id).await {
        Ok(limits) => limits,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load customer tenant limits");
            return control_plane_unavailable();
        }
    };
    match store.model_policy_for_async(&workspace.tenant_id).await {
        Ok(model_policy) => customer_json(CustomerWorkspaceControls {
            limits: limits.into(),
            model_policy,
        }),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load customer model policy");
            control_plane_unavailable()
        }
    }
}

/// Replace or clear the current workspace's exact model allowlist.
///
/// Only a locally authorized owner may perform the direct mutation. Admins can
/// prepare policy versions, but activation remains an owner approval boundary.
/// The session
/// bearer remains HttpOnly; JavaScript submits only its HMAC-bound CSRF proof.
/// The store performs a second role check and writes the policy change plus a
/// customer-administration audit event atomically.
pub async fn set_customer_workspace_model_policy(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(policy): Json<Option<TenantModelPolicy>>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for policy mutation");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ApprovePolicies,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer policy mutation");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .set_workspace_model_policy_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            policy.clone(),
        )
        .await
    {
        Ok(()) => customer_json(policy),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save customer model policy");
            error(
                StatusCode::BAD_REQUEST,
                "customer_model_policy_error",
                "The model policy could not be saved",
            )
        }
    }
}

/// Replace the current workspace's rate/spend admission limits. The customer
/// cannot supply a tenant or workspace identifier: scope and role come from
/// the active browser session, while the store repeats authorization inside
/// the atomic limits-plus-audit transaction.
pub async fn set_customer_workspace_limits(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(limits): Json<TenantLimits>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate OIDC browser session for limits mutation");
            return control_plane_unavailable();
        }
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            WorkspacePermission::ManageTenant,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer limits mutation");
            return control_plane_unavailable();
        }
    };
    if !permitted {
        return customer_forbidden();
    }
    match store
        .set_workspace_limits_async(
            &session.access.workspace_id,
            &session.access.principal_id,
            limits.clone(),
        )
        .await
    {
        Ok(()) => customer_json(CustomerTenantLimits::from(limits)),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save customer limits");
            error(
                StatusCode::BAD_REQUEST,
                "customer_limits_error",
                "The workspace limits could not be saved",
            )
        }
    }
}

/// Revoke the current opaque browser session and expire its cookie. Logout is
/// idempotent so a stale or already-expired cookie never reveals account state.
pub async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    if let Some(token) = session_cookie_token(&headers) {
        if let Err(error_value) = store.revoke_oidc_browser_session_async(token).await {
            tracing::error!(error = %error_value, "failed to revoke OIDC browser session");
            return control_plane_unavailable();
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, expired_session_cookie());
    response
}

/// Rotate the current browser session under a CSRF proof. Rotation is useful
/// after privilege changes or at a fixed session-age boundary: the old cookie
/// is invalidated atomically before the replacement is set.
pub async fn rotate_session(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(token) = session_cookie_token(&headers) else {
        return customer_unauthenticated();
    };
    let csrf = headers
        .get(CUSTOMER_CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| cipher.verifies_browser_csrf_token(token, csrf)) {
        return customer_csrf_invalid();
    }
    let expires_at_unix = match browser_session_expiry() {
        Ok(value) => value,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to calculate OIDC session expiry");
            return control_plane_unavailable();
        }
    };
    let rotated = match store
        .rotate_oidc_browser_session_async(token, expires_at_unix)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return customer_unauthenticated(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to rotate OIDC browser session");
            return control_plane_unavailable();
        }
    };
    let cookie = match session_cookie(&rotated.token, BROWSER_SESSION_TTL_SECONDS) {
        Ok(cookie) => cookie,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to create rotated OIDC session cookie");
            return control_plane_unavailable();
        }
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn authorization_state_expiry() -> anyhow::Result<i64> {
    Ok(now_unix()? + AUTHORIZATION_STATE_TTL_SECONDS)
}

fn browser_session_expiry() -> anyhow::Result<i64> {
    Ok(now_unix()? + BROWSER_SESSION_TTL_SECONDS)
}

fn now_unix() -> anyhow::Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(now).map_err(|_| anyhow::anyhow!("system clock is out of range"))
}

/// Browser login callbacks are handled only by this proxy's fixed endpoint.
/// This closes the open-redirect class even if an administrative configuration
/// was entered incorrectly.
fn callback_path(connection: &OrganizationOidcConnection) -> anyhow::Result<()> {
    let url = Url::parse(&connection.redirect_uri)?;
    if url.path() != CALLBACK_PATH {
        anyhow::bail!("OIDC redirect URI does not use the firewall callback path");
    }
    Ok(())
}

fn authorization_url(
    endpoints: &ValidatedEndpoints,
    connection: &OrganizationOidcConnection,
    state: &str,
    pkce: &PkcePair,
    nonce: &str,
) -> anyhow::Result<Url> {
    callback_path(connection)?;
    if state.is_empty() || nonce.is_empty() {
        anyhow::bail!("OIDC authorization state is invalid");
    }
    let mut url = endpoints.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &connection.client_id)
        .append_pair("redirect_uri", &connection.redirect_uri)
        .append_pair("scope", "openid")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", pkce.code_challenge())
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

pub(crate) fn session_cookie(token: &str, max_age_seconds: i64) -> anyhow::Result<HeaderValue> {
    if !is_valid_browser_session_token(token) || max_age_seconds <= 0 {
        anyhow::bail!("invalid OIDC browser session cookie");
    }
    HeaderValue::try_from(format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={max_age_seconds}; HttpOnly; Secure; SameSite=Lax"
    ))
    .map_err(|_| anyhow::anyhow!("invalid OIDC browser session cookie"))
}

fn expired_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-llm-fw-session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
    )
}

fn session_cookie_token(headers: &HeaderMap) -> Option<&str> {
    let mut session_token = None;
    for cookie in headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|header_value| header_value.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
    {
        let Some((name, token)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name != SESSION_COOKIE_NAME {
            continue;
        }
        if session_token.is_some() || !is_valid_browser_session_token(token) {
            return None;
        }
        session_token = Some(token);
    }
    session_token
}

fn is_valid_browser_session_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_BROWSER_SESSION_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

async fn customer_workspace_for_permission(
    state: &Shared,
    headers: &HeaderMap,
    permission: WorkspacePermission,
) -> Result<(OidcBrowserSession, Workspace), Box<Response>> {
    let Some(store) = state.tenant_store.as_ref() else {
        return Err(Box::new(unavailable()));
    };
    let Some(token) = session_cookie_token(headers) else {
        return Err(Box::new(customer_unauthenticated()));
    };
    let session = match store.authenticate_oidc_browser_session_async(token).await {
        Ok(Some(session)) => session,
        Ok(None) => return Err(Box::new(customer_unauthenticated())),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authenticate customer usage session");
            return Err(Box::new(control_plane_unavailable()));
        }
    };
    let permitted = match store
        .workspace_permits_async(
            &session.access.principal_id,
            &session.access.workspace_id,
            permission,
        )
        .await
    {
        Ok(permitted) => permitted,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to authorize customer usage request");
            return Err(Box::new(control_plane_unavailable()));
        }
    };
    if !permitted {
        return Err(Box::new(customer_forbidden()));
    }
    let workspace = match store
        .active_workspace_by_id_async(&session.access.workspace_id)
        .await
    {
        Ok(Some(workspace)) if workspace.organization_id == session.access.organization_id => {
            workspace
        }
        Ok(Some(_)) => {
            tracing::error!(workspace_id = %session.access.workspace_id, "workspace organization did not match customer usage session");
            return Err(Box::new(control_plane_unavailable()));
        }
        Ok(None) => return Err(Box::new(customer_unauthenticated())),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to resolve customer usage workspace");
            return Err(Box::new(control_plane_unavailable()));
        }
    };
    Ok((session, workspace))
}

fn customer_usage_range(
    from_unix: Option<i64>,
    until_unix: Option<i64>,
) -> Result<(i64, i64), CustomerUsageRangeError> {
    const DEFAULT_RANGE_SECONDS: i64 = 30 * 24 * 60 * 60;
    const MAX_RANGE_SECONDS: i64 = 366 * 24 * 60 * 60;
    let default_until = now_unix()
        .and_then(|now| {
            now.checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("system clock is out of range"))
        })
        .map_err(|_| CustomerUsageRangeError::Clock)?;
    let until_unix = until_unix.unwrap_or(default_until);
    let from_unix = from_unix.unwrap_or_else(|| until_unix.saturating_sub(DEFAULT_RANGE_SECONDS));
    if from_unix < 0 || until_unix <= from_unix || until_unix - from_unix > MAX_RANGE_SECONDS {
        return Err(CustomerUsageRangeError::Invalid);
    }
    Ok((from_unix, until_unix))
}

fn customer_usage_csv_response(page: UsageEventPage) -> Response {
    let mut csv = String::from(
        "event_id,request_id,provider_response_id,provider,path,requested_model,provider_model,input_tokens,output_tokens,token_status,pricing_status,model_price_version,input_usd_micros_per_million,output_usd_micros_per_million,cost_usd_micros,created_at_unix\r\n",
    );
    for event in &page.events {
        csv.push_str(&usage_event_csv_row(event));
        csv.push_str("\r\n");
    }
    let mut response = csv.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-disposition",
        HeaderValue::from_static("attachment; filename=soup-wall-usage.csv"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Some(next_after_id) = page.next_after_id {
        if let Ok(value) = HeaderValue::try_from(next_after_id.to_string()) {
            headers.insert("x-llm-firewall-next-after-id", value);
        }
    }
    response
}

fn usage_event_csv_row(event: &UsageEvent) -> String {
    [
        event.id.to_string(),
        csv_text(&event.request_id),
        csv_optional_text(event.provider_response_id.as_deref()),
        csv_text(&event.provider),
        csv_text(&event.path),
        csv_text(&event.requested_model),
        csv_optional_text(event.provider_model.as_deref()),
        csv_optional_integer(event.input_tokens),
        csv_optional_integer(event.output_tokens),
        match event.token_status {
            UsageTokenStatus::Actual => "actual".into(),
            UsageTokenStatus::Missing => "missing".into(),
        },
        match event.pricing_status {
            UsagePricingStatus::Priced => "priced".into(),
            UsagePricingStatus::Unpriced => "unpriced".into(),
        },
        csv_optional_text(event.model_price_version.as_deref()),
        csv_optional_integer(event.input_usd_micros_per_million),
        csv_optional_integer(event.output_usd_micros_per_million),
        csv_optional_integer(event.cost_usd_micros),
        event.created_at_unix.to_string(),
    ]
    .join(",")
}

fn csv_optional_integer(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn csv_optional_text(value: Option<&str>) -> String {
    value.map(csv_text).unwrap_or_default()
}

/// Escape RFC 4180 syntax and neutralize spreadsheet formula prefixes. Model
/// names and provider IDs are external strings even though they are bounded.
fn csv_text(value: &str) -> String {
    let formula_like = value
        .trim_start_matches(' ')
        .starts_with(['=', '+', '-', '@']);
    let safe = if formula_like {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if safe.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        safe
    }
}

fn unavailable() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "oidc_not_enabled",
        "OIDC browser login is not enabled",
    )
}

fn customer_usage_range_invalid() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "customer_usage_range_error",
        "Usage range must be a positive half-open interval of at most 366 days",
    )
}

fn login_unavailable() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "oidc_login_unavailable",
        "OIDC login is unavailable for this organization",
    )
}

fn login_failed() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "oidc_login_failed",
        "OIDC login could not be completed",
    )
}

fn customer_unauthenticated() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "customer_session_required",
        "A valid customer session is required",
    )
}

fn customer_forbidden() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "customer_permission_denied",
        "Your current workspace role cannot perform this action",
    )
}

fn customer_csrf_invalid() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "customer_csrf_invalid",
        "A valid CSRF proof is required",
    )
}

fn customer_json<T: Serialize>(payload: T) -> Response {
    let mut response = Json(payload).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn control_plane_unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "oidc_control_plane_unavailable",
        "OIDC login is temporarily unavailable",
    )
}

fn error(status: StatusCode, error_type: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        authorization_url, callback_path, callback_with_client, expired_session_cookie,
        session_cookie, session_cookie_token, CallbackQuery, CustomerInvoicePreview,
    };
    use crate::{
        handlers::AppState,
        oidc::{OidcHttpClient, OidcStateCipher, PkcePair, ValidatedEndpoints},
        tenant_store::{
            OrganizationOidcConnection, TenantStore, UsageReconciliationReadiness, UsageReport,
            UsageTotals, WorkspaceRole,
        },
        test_config,
    };
    use reqwest::Url;

    fn connection() -> OrganizationOidcConnection {
        OrganizationOidcConnection {
            organization_id: "org_acme".into(),
            issuer: "https://id.example.test/acme".into(),
            client_id: "firewall-console".into(),
            redirect_uri: "https://console.example.test/auth/oidc/callback".into(),
            active: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn endpoints() -> ValidatedEndpoints {
        ValidatedEndpoints {
            authorization_endpoint: Url::parse("https://id.example.test/authorize?tenant=acme")
                .unwrap(),
            token_endpoint: Url::parse("https://id.example.test/token").unwrap(),
            jwks_uri: Url::parse("https://id.example.test/keys").unwrap(),
        }
    }

    fn test_state(store: TenantStore, cipher: OidcStateCipher) -> Arc<AppState> {
        let config = test_config("http://127.0.0.1:1".into());
        Arc::new(AppState {
            firewall: Firewall::new(
                vec![Box::new(InjectionDetector::new())],
                PolicySet::from_yaml("default: allow").unwrap(),
            ),
            http: reqwest::Client::new(),
            openai_api_key: None,
            proxy_auth_token: None,
            tenant_store: Some(store),
            admin_token: None,
            oidc_state_cipher: Some(cipher),
            saml: None,
            rate_limiter: std::sync::Mutex::new(crate::rate_limit::RateLimiter::new(
                Default::default(),
            )),
            spend_ledger: std::sync::Mutex::new(crate::spend_limit::SpendLedger::new(
                Default::default(),
            )),
            redis_limits: None,
            agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
            moderation: crate::moderation::ModerationGate::new(Default::default()),
            config,
        })
    }

    #[test]
    fn authorization_redirect_uses_only_fixed_protocol_parameters() {
        let connection = connection();
        let pair = PkcePair::generate();
        let url =
            authorization_url(&endpoints(), &connection, "sealed-state", &pair, "nonce").unwrap();
        let values = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            values.get("tenant").map(|value| value.as_ref()),
            Some("acme")
        );
        assert_eq!(
            values.get("response_type").map(|value| value.as_ref()),
            Some("code")
        );
        assert_eq!(
            values.get("client_id").map(|value| value.as_ref()),
            Some("firewall-console")
        );
        assert_eq!(
            values.get("redirect_uri").map(|value| value.as_ref()),
            Some("https://console.example.test/auth/oidc/callback")
        );
        assert_eq!(
            values.get("scope").map(|value| value.as_ref()),
            Some("openid")
        );
        assert_eq!(
            values.get("state").map(|value| value.as_ref()),
            Some("sealed-state")
        );
        assert_eq!(
            values.get("nonce").map(|value| value.as_ref()),
            Some("nonce")
        );
        assert_eq!(
            values
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            values.get("code_challenge").map(|value| value.as_ref()),
            Some(pair.code_challenge())
        );
    }

    #[test]
    fn start_login_rejects_a_configuration_that_cannot_return_to_the_proxy() {
        let mut connection = connection();
        connection.redirect_uri = "https://console.example.test/welcome".into();
        assert!(callback_path(&connection).is_err());
        assert!(authorization_url(
            &endpoints(),
            &connection,
            "state",
            &PkcePair::generate(),
            "nonce"
        )
        .is_err());
    }

    #[test]
    fn invoice_preview_is_never_final_and_flags_incomplete_evidence() {
        let preview = CustomerInvoicePreview::from(UsageReport {
            from_unix: 10,
            until_unix: 20,
            totals: UsageTotals {
                request_count: 1,
                missing_token_events: 1,
                unpriced_events: 1,
                ..UsageTotals::default()
            },
            daily: Vec::new(),
            models: Vec::new(),
            reconciliation: UsageReconciliationReadiness {
                review_required_events: 1,
                ..UsageReconciliationReadiness::default()
            },
        });
        let json = serde_json::to_value(preview).unwrap();
        assert_eq!(json["status"], "review_required");
        assert_eq!(json["is_final"], false);
        assert_eq!(json["notice"], "Preview only. Final invoices require provider reconciliation, tax/privacy review, and an explicit billing workflow.");
    }

    #[tokio::test]
    async fn local_idp_callback_verifies_token_and_creates_single_use_browser_session() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store.create_organization("Local IdP organization").unwrap();
        let issuer = "https://id.local.test/acme";
        store
            .set_organization_oidc_connection(
                &organization.id,
                issuer,
                "firewall-console",
                "https://console.example.test/auth/oidc/callback",
                true,
            )
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "Local IdP tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let principal = store
            .create_workspace_principal("Local IdP customer")
            .unwrap();
        store
            .link_workspace_external_identity(&principal.id, issuer, "local-subject")
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Analyst)
            .unwrap();

        let cipher =
            OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([11_u8; 32])).unwrap();
        let pkce = PkcePair::generate();
        let nonce = "local-idp-nonce";
        let expires_at_unix = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
            + 600;
        let state_value = cipher
            .seal_authorization_state(
                &organization.id,
                &workspace.id,
                &pkce,
                nonce,
                expires_at_unix,
            )
            .unwrap();
        store
            .reserve_oidc_authorization_state(&state_value, &organization.id, expires_at_unix)
            .unwrap();

        let (id_token, jwks) = crate::oidc_token::tests::signed_local_id_token(
            issuer,
            "local-subject",
            "firewall-console",
            nonce,
        );
        let provider = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .expect(1)
            .mount(&provider)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=local-code"))
            .and(body_string_contains("client_id=firewall-console"))
            .and(body_string_contains(format!(
                "code_verifier={}",
                pkce.code_verifier()
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id_token": id_token })),
            )
            .expect(1)
            .mount(&provider)
            .await;
        let endpoints = ValidatedEndpoints {
            authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
                .unwrap(),
            token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
            jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
        };
        let client = OidcHttpClient::for_local_test_provider(endpoints).unwrap();
        let state = test_state(store, cipher);

        let response = callback_with_client(
            state.clone(),
            CallbackQuery {
                state: Some(state_value.clone()),
                code: Some("local-code".into()),
                error: None,
            },
            client.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/customer");
        let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("; HttpOnly"));
        assert!(set_cookie.contains("; Secure"));
        let session_token = set_cookie
            .strip_prefix("__Host-llm-fw-session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let session = state
            .tenant_store
            .as_ref()
            .unwrap()
            .authenticate_oidc_browser_session(session_token)
            .unwrap()
            .unwrap();
        assert_eq!(session.access.organization_id, organization.id);
        assert_eq!(session.access.workspace_id, workspace.id);
        assert_eq!(session.access.principal_id, principal.id);
        assert_eq!(session.access.role, WorkspaceRole::Analyst);

        let replay = callback_with_client(
            state,
            CallbackQuery {
                state: Some(state_value),
                code: Some("local-code".into()),
                error: None,
            },
            client,
        )
        .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn local_idp_callback_consumes_invitation_and_creates_membership() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("Local invitation organization")
            .unwrap();
        let issuer = "https://id.local.test/invitations";
        store
            .set_organization_oidc_connection(
                &organization.id,
                issuer,
                "firewall-console",
                "https://console.example.test/auth/oidc/callback",
                true,
            )
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "Local invitation tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store
            .create_workspace_principal("Local invitation owner")
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        let issued = store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &owner.id,
                "Invited developer",
                WorkspaceRole::Developer,
                super::now_unix().unwrap() + 600,
            )
            .unwrap();

        let cipher =
            OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([13_u8; 32])).unwrap();
        let pkce = PkcePair::generate();
        let nonce = "local-invitation-nonce";
        let expires_at_unix = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
            + 600;
        let state_value = cipher
            .seal_authorization_state_with_invitation(
                &organization.id,
                &workspace.id,
                Some(&issued.invitation.id),
                &pkce,
                nonce,
                expires_at_unix,
            )
            .unwrap();
        store
            .reserve_oidc_authorization_state(&state_value, &organization.id, expires_at_unix)
            .unwrap();

        let (id_token, jwks) = crate::oidc_token::tests::signed_local_id_token(
            issuer,
            "local-invitation-subject",
            "firewall-console",
            nonce,
        );
        let provider = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .expect(1)
            .mount(&provider)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=invitation-code"))
            .and(body_string_contains("client_id=firewall-console"))
            .and(body_string_contains(format!(
                "code_verifier={}",
                pkce.code_verifier()
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id_token": id_token })),
            )
            .expect(1)
            .mount(&provider)
            .await;
        let endpoints = ValidatedEndpoints {
            authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
                .unwrap(),
            token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
            jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
        };
        let client = OidcHttpClient::for_local_test_provider(endpoints).unwrap();
        let state = test_state(store, cipher);

        let response = callback_with_client(
            state.clone(),
            CallbackQuery {
                state: Some(state_value),
                code: Some("invitation-code".into()),
                error: None,
            },
            client,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        let session_token = set_cookie
            .strip_prefix("__Host-llm-fw-session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let session = state
            .tenant_store
            .as_ref()
            .unwrap()
            .authenticate_oidc_browser_session(session_token)
            .unwrap()
            .unwrap();
        assert_eq!(session.access.organization_id, organization.id);
        assert_eq!(session.access.workspace_id, workspace.id);
        assert_eq!(session.access.role, WorkspaceRole::Developer);
        assert_ne!(session.access.principal_id, owner.id);
        assert!(state
            .tenant_store
            .as_ref()
            .unwrap()
            .workspace_invitation_for_token(&issued.token)
            .unwrap()
            .is_none());
        let access = state
            .tenant_store
            .as_ref()
            .unwrap()
            .verified_identity_workspace_access(
                &organization.id,
                &workspace.id,
                issuer,
                "local-invitation-subject",
            )
            .unwrap()
            .unwrap();
        assert_eq!(access.principal_id, session.access.principal_id);
        assert_eq!(access.role, WorkspaceRole::Developer);
    }

    #[test]
    fn browser_session_cookie_is_host_scoped_and_not_accepted_from_another_name() {
        let cookie = session_cookie("opaque-session", 60).unwrap();
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("__Host-llm-fw-session=opaque-session; Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain="));

        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("other=opaque-session; __Host-llm-fw-session=accepted"),
        );
        assert_eq!(session_cookie_token(&headers), Some("accepted"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-llm-fw-session=duplicate"),
        );
        assert_eq!(session_cookie_token(&headers), None);
        let mut wrong_name = HeaderMap::new();
        wrong_name.append(
            header::COOKIE,
            HeaderValue::from_static("session=opaque-session"),
        );
        assert_eq!(session_cookie_token(&wrong_name), None);
        assert!(session_cookie("line\nbreak", 60).is_err());
        assert!(session_cookie("token;injection", 60).is_err());
        assert!(session_cookie("token", 0).is_err());
        assert!(expired_session_cookie()
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
    }
}
