// SPDX-License-Identifier: Apache-2.0

//! Tenant control plane for firewall tenants and client tokens.
//!
//! The database deliberately stores a one-way hash of each client token, never
//! the token itself. A raw token is returned only by [`TenantStore::issue_token`]
//! so an operator can give it to a tenant once.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use reqwest::{redirect::Policy, Client, Url};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

mod postgres;

use postgres::PostgresTenantStore;

const BOOTSTRAP_ORGANIZATION_ID: &str = "org_bootstrap";

#[derive(Clone)]
pub struct TenantStore {
    connection: Option<Arc<Mutex<Connection>>>,
    postgres: Option<PostgresTenantStore>,
    audit_max_rows: usize,
    audit_dispatcher: Option<TenantAuditDispatcher>,
    usage_failed_events: Arc<AtomicU64>,
    webhook_signing_key: Option<WebhookSigningKey>,
}

// Readiness counters moved to `crate::control_plane`: the data plane reports its
// own readiness and must be able to do so with no control plane compiled in.
// Re-exported because this module's consumers name them here.
pub use crate::control_plane::{TenantAuditQueueStatus, UsageLedgerStatus};

#[derive(Clone)]
struct TenantAuditDispatcher {
    sender: mpsc::Sender<TenantAuditWrite>,
    dropped_events: Arc<AtomicU64>,
    failed_events: Arc<AtomicU64>,
}

struct TenantAuditWrite {
    tenant_id: String,
    path: String,
    outcome: String,
    status_code: u16,
    latency_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantAuditQueueResult {
    Queued,
    Dropped,
    NotConfigured,
}

/// Safe identity attached to an authenticated proxy request. It intentionally
/// contains no credential material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantIdentity {
    pub tenant_id: String,
    pub tenant_name: String,
}

/// The authenticated tenant plus its current database-backed limits. This is
/// attached to the request after token authentication and has no raw token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantAccess {
    pub identity: TenantIdentity,
    pub limits: TenantLimits,
    pub model_policy: Option<TenantModelPolicy>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<TenantRateLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_limit: Option<TenantSpendLimit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRateLimit {
    pub requests_per_window: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSpendLimit {
    pub window_seconds: u64,
    pub max_usd_micros: u64,
    pub reserve_usd_micros_per_request: u64,
}

/// Exact tenant-scoped model allowlist. `None` means no tenant model policy is
/// configured; a present empty list deliberately denies every model until an
/// operator adds an approved identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantModelPolicy {
    pub allowed_models: Vec<String>,
}

impl TenantModelPolicy {
    pub fn permits(&self, model: &str) -> bool {
        self.allowed_models.iter().any(|allowed| allowed == model)
    }
}

pub const TENANT_POLICY_SCHEMA_VERSION: u16 = 1;

/// Extensible, canonical tenant policy document. Only fields enforced by the
/// current data plane belong here; future schema versions must be migrated
/// explicitly rather than silently reinterpreting an old version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPolicyDocument {
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_policy: Option<TenantModelPolicy>,
}

impl TenantPolicyDocument {
    pub fn new(model_policy: Option<TenantModelPolicy>) -> Self {
        Self {
            schema_version: TENANT_POLICY_SCHEMA_VERSION,
            model_policy,
        }
    }
}

/// Immutable policy version. Approval and deployment are separate append-only
/// records so the version body and its content hash never change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantPolicyVersion {
    pub id: String,
    pub tenant_id: String,
    pub sequence: u64,
    pub document: TenantPolicyDocument,
    pub content_sha256: String,
    pub created_by: String,
    pub created_at_unix: i64,
    pub approved_by: Option<String>,
    pub approved_at_unix: Option<i64>,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDeploymentAction {
    Activate,
    Rollback,
}

impl PolicyDeploymentAction {
    pub(crate) fn storage_value(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Rollback => "rollback",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "activate" => Ok(Self::Activate),
            "rollback" => Ok(Self::Rollback),
            _ => bail!("stored policy deployment action is invalid"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantPolicyDeployment {
    pub id: String,
    pub tenant_id: String,
    pub sequence: u64,
    pub version_id: String,
    pub previous_version_id: Option<String>,
    pub action: PolicyDeploymentAction,
    pub actor_id: String,
    pub created_at_unix: i64,
}

/// Immutable, cursor-addressable security event suitable for SIEM ingestion.
/// Payloads contain only control-plane metadata; prompts, responses, raw
/// credentials, and provider authorization headers are never included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantSecurityEvent {
    pub id: String,
    pub tenant_id: String,
    pub sequence: u64,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub content_sha256: String,
    pub occurred_at_unix: i64,
}

/// Tenant-scoped webhook destination. The URL and event allowlist are stored,
/// but the derived delivery secret is never persisted or returned on reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WebhookDestination {
    pub id: String,
    pub tenant_id: String,
    pub url: String,
    pub event_types: Vec<String>,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Returned exactly once when an owner creates a destination. The destination
/// secret is derived from the process signing key and destination ID; it is
/// intentionally absent from all inventory endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedWebhookDestination {
    #[serde(flatten)]
    pub destination: WebhookDestination,
    pub secret: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryStatus {
    Pending,
    InFlight,
    Delivered,
    Dead,
}

impl WebhookDeliveryStatus {
    fn storage_value(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InFlight => "in_flight",
            Self::Delivered => "delivered",
            Self::Dead => "dead",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "in_flight" => Ok(Self::InFlight),
            "delivered" => Ok(Self::Delivered),
            "dead" => Ok(Self::Dead),
            _ => bail!("stored webhook delivery status is invalid"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WebhookDelivery {
    pub id: String,
    pub tenant_id: String,
    pub event_id: String,
    pub destination_id: String,
    pub status: WebhookDeliveryStatus,
    pub attempt_count: u32,
    pub next_attempt_at_unix: i64,
    pub locked_until_unix: Option<i64>,
    pub delivered_at_unix: Option<i64>,
    pub last_http_status: Option<u16>,
    pub last_error: Option<String>,
    pub created_at_unix: i64,
}

#[derive(Clone)]
struct WebhookSigningKey(Arc<[u8]>);

impl WebhookSigningKey {
    fn from_base64url(encoded: &str) -> anyhow::Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .context("webhook signing key must be base64url")?;
        if bytes.len() != 32 {
            bail!("webhook signing key must decode to exactly 32 bytes");
        }
        Ok(Self(Arc::from(bytes)))
    }

    fn secret_for(&self, destination_id: &str) -> anyhow::Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .map_err(|_| anyhow::anyhow!("invalid webhook signing key"))?;
        mac.update(b"llm-firewall-webhook-secret-v1:");
        mac.update(destination_id.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn signature_for(&self, destination_id: &str, body: &[u8]) -> anyhow::Result<String> {
        let secret = self.secret_for(destination_id)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid derived webhook secret"))?;
        mac.update(body);
        Ok(format!(
            "sha256={}",
            hex_lower(mac.finalize().into_bytes().as_ref())
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationCase {
    pub requested_model: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicySimulationResult {
    pub requested_model: String,
    pub current_permitted: bool,
    pub candidate_permitted: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantPolicySimulation {
    pub version_id: String,
    pub active_version_id: Option<String>,
    pub changed_count: u64,
    pub results: Vec<PolicySimulationResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantAuditEvent {
    pub id: i64,
    pub tenant_id: String,
    pub created_at_unix: i64,
    pub path: String,
    pub outcome: String,
    pub status_code: u16,
    pub latency_ms: u64,
}

// `UsageTokenStatus`, `UsagePricingStatus` and `NewUsageEvent` now live in
// `crate::usage`, beside the code that builds them, so the event constructor no
// longer has to reach into the store that persists it. Re-exported here because
// every existing consumer names them through this module.
//
// Their storage encoding stays here: it is a property of this store, not of the
// event. They are free functions rather than inherent methods because an
// inherent `impl` must live in the same crate as its type, which would stop
// working the moment the control plane becomes a separate crate.
pub use crate::usage::{NewUsageEvent, UsagePricingStatus, UsageTokenStatus};

fn usage_token_status_storage_value(status: UsageTokenStatus) -> &'static str {
    match status {
        UsageTokenStatus::Actual => "actual",
        UsageTokenStatus::Missing => "missing",
    }
}

fn usage_token_status_from_storage(value: &str) -> anyhow::Result<UsageTokenStatus> {
    match value {
        "actual" => Ok(UsageTokenStatus::Actual),
        "missing" => Ok(UsageTokenStatus::Missing),
        _ => bail!("stored usage token status is invalid"),
    }
}

fn usage_pricing_status_storage_value(status: UsagePricingStatus) -> &'static str {
    match status {
        UsagePricingStatus::Priced => "priced",
        UsagePricingStatus::Unpriced => "unpriced",
    }
}

fn usage_pricing_status_from_storage(value: &str) -> anyhow::Result<UsagePricingStatus> {
    match value {
        "priced" => Ok(UsagePricingStatus::Priced),
        "unpriced" => Ok(UsagePricingStatus::Unpriced),
        _ => bail!("stored usage pricing status is invalid"),
    }
}

/// Immutable usage source of truth returned to reconciliation and future
/// customer views. Database IDs are monotonic only within one backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageEvent {
    pub id: i64,
    pub tenant_id: String,
    pub request_id: String,
    pub provider_response_id: Option<String>,
    pub provider: String,
    pub path: String,
    pub requested_model: String,
    pub provider_model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub token_status: UsageTokenStatus,
    pub pricing_status: UsagePricingStatus,
    pub model_price_version: Option<String>,
    pub input_usd_micros_per_million: Option<u64>,
    pub output_usd_micros_per_million: Option<u64>,
    pub cost_usd_micros: Option<u64>,
    pub created_at_unix: i64,
}

/// Exact totals over one bounded half-open UTC interval. Missing usage and
/// unpriced events remain separate counts instead of being folded into zero.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UsageTotals {
    pub request_count: u64,
    pub actual_token_events: u64,
    pub missing_token_events: u64,
    pub priced_events: u64,
    pub unpriced_events: u64,
    pub provider_correlated_events: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub priced_cost_usd_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DailyUsageAggregate {
    pub day_start_unix: i64,
    pub totals: UsageTotals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModelUsageAggregate {
    pub provider: String,
    pub requested_model: String,
    pub totals: UsageTotals,
}

/// Measures whether local events have enough evidence to be compared with a
/// provider statement. `ready_events` are candidates, not a claim that a
/// provider has already confirmed them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UsageReconciliationReadiness {
    pub ready_events: u64,
    pub review_required_events: u64,
    pub missing_provider_response_id_events: u64,
    pub duplicate_provider_response_id_groups: u64,
    pub duplicate_provider_response_id_events: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReport {
    pub from_unix: i64,
    pub until_unix: i64,
    pub totals: UsageTotals,
    pub daily: Vec<DailyUsageAggregate>,
    pub models: Vec<ModelUsageAggregate>,
    pub reconciliation: UsageReconciliationReadiness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageEventPage {
    pub events: Vec<UsageEvent>,
    pub next_after_id: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReconciliationStatus {
    Matched,
    Mismatched,
    Orphan,
    Ambiguous,
}

impl UsageReconciliationStatus {
    fn storage_value(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatched => "mismatched",
            Self::Orphan => "orphan",
            Self::Ambiguous => "ambiguous",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "matched" => Ok(Self::Matched),
            "mismatched" => Ok(Self::Mismatched),
            "orphan" => Ok(Self::Orphan),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => bail!("stored usage reconciliation status is invalid"),
        }
    }
}

/// One privacy-safe provider statement row. At least one exact token pair or
/// provider cost must be present; no prompt, response text, or credential is
/// accepted by this contract.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUsageReconciliationRecord {
    pub source_record_id: String,
    pub provider: String,
    pub provider_response_id: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd_micros: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUsageReconciliationImport {
    pub source: String,
    pub statement_id: String,
    pub records: Vec<NewUsageReconciliationRecord>,
}

/// Immutable summary of one imported provider statement. Counts are bounded
/// by the import limit and therefore fit safely in `u32`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReconciliationRun {
    pub id: String,
    pub tenant_id: String,
    pub source: String,
    pub statement_id: String,
    pub actor_admin_id: String,
    pub record_count: u32,
    pub matched_count: u32,
    pub mismatched_count: u32,
    pub orphan_count: u32,
    pub ambiguous_count: u32,
    pub created_at_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReconciliationObservation {
    pub id: i64,
    pub run_id: String,
    pub tenant_id: String,
    pub source_record_id: String,
    pub usage_event_id: Option<i64>,
    pub provider: String,
    pub provider_response_id: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd_micros: Option<u64>,
    pub status: UsageReconciliationStatus,
    pub created_at_unix: i64,
}

/// Opt-in minimum retention period for immutable usage evidence. Absence of a
/// policy means that nothing may be purged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageRetentionPolicy {
    pub retention_days: u32,
}

/// Immutable, privacy-safe evidence for one retention dry-run or execution.
/// Reconciliation-linked events are always protected and counted separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageRetentionRun {
    pub id: String,
    pub tenant_id: String,
    pub actor_admin_id: String,
    pub retention_days: u32,
    pub cutoff_unix: i64,
    pub executed: bool,
    pub eligible_event_count: u64,
    pub protected_reconciliation_event_count: u64,
    pub eligible_input_tokens: u64,
    pub eligible_output_tokens: u64,
    pub eligible_cost_usd_micros: u64,
    pub deleted_event_count: u64,
    pub created_at_unix: i64,
}

/// Customer-owned monitoring thresholds over the current UTC calendar month.
/// These never alter admission and are deliberately separate from invoices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageQuotaPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_micros_limit: Option<u64>,
    #[serde(default = "default_usage_quota_alert_threshold_basis_points")]
    pub alert_threshold_basis_points: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageQuotaState {
    Ok,
    Threshold,
    Exceeded,
    EvidenceIncomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageQuotaMetricStatus {
    pub used: u64,
    pub limit: u64,
    pub state: UsageQuotaState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageQuotaStatus {
    pub from_unix: i64,
    pub until_unix: i64,
    pub policy: UsageQuotaPolicy,
    pub requests: Option<UsageQuotaMetricStatus>,
    pub tokens: Option<UsageQuotaMetricStatus>,
    pub cost_usd_micros: Option<UsageQuotaMetricStatus>,
    pub missing_token_events: u64,
    pub unpriced_events: u64,
    pub attention_required: bool,
}

struct UsageReconciliationCandidate {
    id: i64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_usd_micros: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub created_at_unix: i64,
}

/// Customer billing and identity boundary. Platform control-plane
/// administrators are deliberately not organizations or members of one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub created_at_unix: i64,
}

/// Customer-facing wrapper around one existing tenant. Keeping a stable tenant
/// foreign key lets the organization migration preserve every proxy token,
/// policy, audit record, and rate/spend counter namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Workspace {
    pub id: String,
    pub organization_id: String,
    pub tenant_id: String,
    pub name: String,
    pub active: bool,
    pub created_at_unix: i64,
}

/// Customer roles are intentionally separate from [`AdminRole`]. An identity
/// with a workspace role never gains platform-control-plane authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Owner,
    Admin,
    Analyst,
    Developer,
}

/// Server-side authorization actions. A future browser/UI may hide controls,
/// but must call this authorization seam before it can make any change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspacePermission {
    ManageMembership,
    ManageIdentity,
    ManageTenant,
    ManageBilling,
    ManagePolicies,
    ApprovePolicies,
    ManageServiceTokens,
    ManageOwnServiceTokens,
    ReadAudit,
    ReadUsage,
    ExportUsage,
}

impl WorkspaceRole {
    pub fn permits(self, permission: WorkspacePermission) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => matches!(
                permission,
                WorkspacePermission::ManageTenant
                    | WorkspacePermission::ManagePolicies
                    | WorkspacePermission::ManageServiceTokens
                    | WorkspacePermission::ReadAudit
                    | WorkspacePermission::ReadUsage
                    | WorkspacePermission::ExportUsage
            ),
            Self::Analyst => matches!(
                permission,
                WorkspacePermission::ReadAudit
                    | WorkspacePermission::ReadUsage
                    | WorkspacePermission::ExportUsage
            ),
            Self::Developer => matches!(permission, WorkspacePermission::ManageOwnServiceTokens),
        }
    }

    fn storage_value(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Developer => "developer",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "analyst" => Ok(Self::Analyst),
            "developer" => Ok(Self::Developer),
            _ => bail!("stored workspace role is invalid"),
        }
    }
}

/// Human or service identity. OIDC issuer/subject mappings are exact opaque
/// bindings; invitation enrollment creates them only after token verification.
/// Email is never an identity key here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspacePrincipal {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub created_at_unix: i64,
}

/// Stable, opaque identity binding for an external IdP. Issuer and subject are
/// deliberately stored exactly as verified by a future OIDC implementation:
/// neither email addresses nor display names are identity keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceExternalIdentity {
    pub issuer: String,
    pub subject: String,
    pub principal_id: String,
    pub created_at_unix: i64,
}

/// Public configuration for an organization's future OIDC authorization-code
/// flow. Client secrets are intentionally absent: a future verifier must obtain
/// any confidential-client secret from a dedicated secret manager, never this
/// control-plane database or its JSON API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrganizationOidcConnection {
    pub organization_id: String,
    /// Exact HTTPS issuer expected in a verified `iss` claim.
    pub issuer: String,
    /// Public OIDC client identifier / expected audience.
    pub client_id: String,
    /// Exact HTTPS callback registered at the identity provider.
    pub redirect_uri: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Owner-managed SAML 2.0 identity-provider metadata. Metadata is retained so
/// the runtime can verify the exact signed document against the separately
/// pinned certificate before every login; it is never returned by the admin
/// API. No IdP claim is trusted for workspace roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationSamlConnection {
    pub organization_id: String,
    pub entity_id: String,
    pub metadata_xml: String,
    pub metadata_signing_cert_pem: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Durable, one-time SAML request correlation. It contains only protocol
/// identifiers, endpoint metadata, and an optional local invitation ID; the
/// browser-facing RelayState remains an authenticated opaque value and is
/// stored by hash in both backends. The raw invitation bearer is never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlAuthorizationPending {
    pub organization_id: String,
    pub workspace_id: String,
    /// Optional invitation accepted only after the SAML assertion is fully
    /// verified. The bearer itself is never persisted in this state.
    pub invitation_id: Option<String>,
    pub request_id: String,
    pub idp_entity_id: String,
    pub expected_binding: String,
    pub request_binding: String,
    pub acs_url: String,
    pub acs_binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceMembership {
    pub workspace_id: String,
    pub principal_id: String,
    pub role: WorkspaceRole,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// A workspace-scoped machine identity. The token is never stored or
/// serialized after issuance; only this metadata is safe to return repeatedly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceServiceAccount {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub created_by_principal_id: String,
    pub active: bool,
    pub expires_at_unix: i64,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
}

/// Returned exactly once when a service account is created. Store the token in
/// a secret manager; the control plane keeps only a one-way hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedWorkspaceServiceAccount {
    pub account: WorkspaceServiceAccount,
    pub token: String,
}

/// A customer-safe view of a workspace member. It contains the locally
/// managed display name, but deliberately no email address, IdP claims, or
/// external identity data. OIDC issuer/subject mappings remain server-side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceMember {
    pub workspace_id: String,
    pub principal_id: String,
    pub principal_name: String,
    pub role: WorkspaceRole,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// One owner-created OIDC enrollment grant. The raw bearer is absent from this
/// repeatable view and from every audit record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceInvitation {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub recipient_label: String,
    pub role: WorkspaceRole,
    pub created_by_principal_id: String,
    pub active: bool,
    pub expires_at_unix: i64,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    pub accepted_by_principal_id: Option<String>,
    pub accepted_at_unix: Option<i64>,
}

/// Returned once when an owner creates an invitation. The store persists only
/// a domain-separated hash of `token`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedWorkspaceInvitation {
    pub invitation: WorkspaceInvitation,
    pub token: String,
}

/// Customer authorization context derived from an already verified OIDC
/// `(issuer, subject)` pair. This is deliberately not proof of identity: the
/// OIDC verifier must validate the signed ID token before calling this lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedWorkspaceAccess {
    pub organization_id: String,
    pub workspace_id: String,
    pub principal_id: String,
    pub role: WorkspaceRole,
}

/// The independently configured federation that authenticated a browser
/// session. It is retained with the session so disabling one connection
/// invalidates only sessions created through that connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserSessionFederation {
    Oidc,
    Saml,
}

impl BrowserSessionFederation {
    fn as_storage(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "oidc" => Ok(Self::Oidc),
            "saml" => Ok(Self::Saml),
            _ => bail!("invalid browser session federation kind"),
        }
    }
}

impl VerifiedWorkspaceAccess {
    pub fn permits(&self, permission: WorkspacePermission) -> bool {
        self.role.permits(permission)
    }
}

/// A newly created opaque browser session. The raw `token` is returned only
/// to the callback handler so it can set an HttpOnly cookie; it is never
/// stored in plaintext or serialized into an API response.
pub struct IssuedOidcBrowserSession {
    pub token: String,
    pub expires_at_unix: i64,
}

/// A current customer browser identity. Its role is resolved afresh from the
/// active membership table, rather than trusting a claim embedded in a cookie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OidcBrowserSession {
    pub access: VerifiedWorkspaceAccess,
    pub expires_at_unix: i64,
}

/// Privacy-safe record of a customer-administration change. Platform operators
/// and future automated provisioning may have no workspace principal, so the
/// actor is nullable rather than inventing a customer identity for them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceAdminAuditEvent {
    pub id: i64,
    pub organization_id: String,
    pub workspace_id: String,
    pub actor_principal_id: Option<String>,
    pub action: String,
    pub target_principal_id: Option<String>,
    pub created_at_unix: i64,
}

/// Returned from the admin API exactly once. Do not log or persist this value
/// outside a secrets manager.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedToken {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub token: String,
    pub created_at_unix: i64,
}

/// A tenant credential inventory record. Unlike [`IssuedToken`], this is safe
/// to return repeatedly: it never contains a raw credential or its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantToken {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
}

/// Metadata for an organization-scoped SCIM bearer credential. This is safe
/// to list repeatedly: the raw bearer and its hash are never serialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScimToken {
    pub id: String,
    pub organization_id: String,
    pub label: String,
    pub active: bool,
    pub expires_at_unix: i64,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
}

/// Returned exactly once when a platform owner creates a SCIM integration
/// credential. Store the raw value in the IdP's secret manager; the control
/// plane stores only a domain-separated hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedScimToken {
    pub credential: ScimToken,
    pub token: String,
}

/// Organization scope authenticated from a valid SCIM bearer. It intentionally
/// carries no workspace or customer-browser privilege.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScimIdentity {
    pub organization_id: String,
    pub token_id: String,
}

/// A SCIM-provisioned person scoped to one customer organization. `external_id`
/// is an opaque IdP correlation value, not an authentication key; a SCIM user
/// receives no workspace membership or proxy credential at creation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScimUser {
    pub id: String,
    pub organization_id: String,
    pub external_id: String,
    pub user_name: String,
    pub display_name: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// A bounded SCIM list result. Pagination is performed in the control plane,
/// rather than loading an organization's full directory into the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScimUserPage {
    pub total_results: u64,
    pub start_index: usize,
    pub items_per_page: usize,
    pub resources: Vec<ScimUser>,
}

/// Supported SCIM user mutations. The stable `external_id` deliberately has
/// no update field: changing an IdP correlation key is a delete/re-provision
/// operation, not an implicit identity merge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScimUserUpdate {
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    pub active: Option<bool>,
}

/// A SCIM group scoped to one customer organization. Groups are directory
/// objects only at this stage: no workspace authorization is derived from
/// their existence or their member list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScimGroup {
    pub id: String,
    pub organization_id: String,
    pub external_id: String,
    pub display_name: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
    pub member_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScimGroupPage {
    pub total_results: u64,
    pub start_index: usize,
    pub items_per_page: usize,
    pub resources: Vec<ScimGroup>,
}

/// A bounded membership operation for a SCIM group. Each referenced member
/// must be an active SCIM user of the same organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScimGroupMemberChange {
    Replace(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScimGroupUpdate {
    pub display_name: Option<String>,
    pub member_change: Option<ScimGroupMemberChange>,
}

/// Customer-safe directory entry for an active SCIM user. It intentionally
/// excludes `userName` and `externalId`, which may contain IdP identifiers or
/// email addresses and are not needed to make an explicit workspace grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceScimUser {
    pub principal_id: String,
    pub display_name: String,
}

/// Customer-safe entry for an active SCIM directory group. Group external IDs
/// are deliberately not exposed to the browser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceScimGroup {
    pub group_id: String,
    pub display_name: String,
}

/// An owner-approved, read-only SCIM group grant. The initial mapping is
/// intentionally fixed to `analyst`: an IdP-managed group may never create an
/// owner/admin or mutation-capable workspace role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceScimGroupMapping {
    pub workspace_id: String,
    pub group_id: String,
    pub group_display_name: String,
    pub role: WorkspaceRole,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    Owner,
    Operator,
    Viewer,
}

impl AdminRole {
    pub fn permits(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Owner, _)
                | (Self::Operator, Self::Operator | Self::Viewer)
                | (Self::Viewer, Self::Viewer)
        )
    }

    fn storage_value(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    fn from_storage(value: &str) -> anyhow::Result<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            _ => bail!("stored admin role is invalid"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ControlPlaneAdmin {
    pub id: String,
    pub name: String,
    pub role: AdminRole,
    pub active: bool,
    pub created_at_unix: i64,
}

/// Returned only once when an operator creates an admin principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedAdminToken {
    pub admin: ControlPlaneAdmin,
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminIdentity {
    pub admin_id: String,
    pub admin_name: String,
    pub role: AdminRole,
}

impl TenantStore {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_audit_capacity(path, 100_000)
    }

    pub fn open_with_audit_capacity(
        path: impl AsRef<Path>,
        audit_max_rows: usize,
    ) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path != Path::new(":memory:") {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create tenant database directory {}",
                        parent.display()
                    )
                })?;
            }
        }

        let connection = Connection::open(path)
            .with_context(|| format!("failed to open tenant database {}", path.display()))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .context("failed to configure tenant database busy timeout")?;
        connection
            .execute_batch(
                "
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;

                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_tokens (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    token_hash BLOB NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER
                );

                CREATE INDEX IF NOT EXISTS tenant_tokens_active_hash
                    ON tenant_tokens(token_hash) WHERE active = 1;

                CREATE TABLE IF NOT EXISTS tenant_limits (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    rate_limit_requests_per_window INTEGER,
                    rate_limit_window_seconds INTEGER,
                    spend_limit_window_seconds INTEGER,
                    spend_limit_max_usd_micros INTEGER,
                    spend_limit_reserve_usd_micros_per_request INTEGER,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_model_policies (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    allowed_models_json TEXT NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_policy_versions (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    document_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
                    created_by TEXT NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    UNIQUE(tenant_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS tenant_policy_versions_tenant_sequence
                    ON tenant_policy_versions(tenant_id, sequence DESC);

                CREATE TABLE IF NOT EXISTS tenant_policy_approvals (
                    version_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    approved_by TEXT NOT NULL,
                    approved_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_policy_state (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    active_version_id TEXT NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_policy_deployments (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    version_id TEXT NOT NULL
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    previous_version_id TEXT
                        REFERENCES tenant_policy_versions(id) ON DELETE RESTRICT,
                    action TEXT NOT NULL CHECK(action IN ('activate', 'rollback')),
                    actor_id TEXT NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    UNIQUE(tenant_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS tenant_policy_deployments_tenant_sequence
                    ON tenant_policy_deployments(tenant_id, sequence DESC);

                CREATE TRIGGER IF NOT EXISTS tenant_policy_versions_no_update
                BEFORE UPDATE ON tenant_policy_versions
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_policy_versions_no_delete
                BEFORE DELETE ON tenant_policy_versions
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_policy_approvals_no_update
                BEFORE UPDATE ON tenant_policy_approvals
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy approvals are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_policy_approvals_no_delete
                BEFORE DELETE ON tenant_policy_approvals
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy approvals are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_policy_deployments_no_update
                BEFORE UPDATE ON tenant_policy_deployments
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy deployments are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_policy_deployments_no_delete
                BEFORE DELETE ON tenant_policy_deployments
                BEGIN
                    SELECT RAISE(ABORT, 'tenant policy deployments are immutable');
                END;

                CREATE TABLE IF NOT EXISTS tenant_security_events (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
                    occurred_at_unix INTEGER NOT NULL,
                    UNIQUE(tenant_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS tenant_security_events_tenant_sequence
                    ON tenant_security_events(tenant_id, sequence);

                CREATE TRIGGER IF NOT EXISTS tenant_security_events_no_update
                BEFORE UPDATE ON tenant_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'tenant security events are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS tenant_security_events_no_delete
                BEFORE DELETE ON tenant_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'tenant security events are immutable');
                END;

                CREATE TABLE IF NOT EXISTS tenant_webhook_destinations (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    url TEXT NOT NULL,
                    event_types_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS tenant_webhook_destinations_tenant_active
                    ON tenant_webhook_destinations(tenant_id, active, id);

                CREATE TABLE IF NOT EXISTS tenant_webhook_deliveries (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    event_id TEXT NOT NULL REFERENCES tenant_security_events(id) ON DELETE RESTRICT,
                    destination_id TEXT NOT NULL REFERENCES tenant_webhook_destinations(id) ON DELETE RESTRICT,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'in_flight', 'delivered', 'dead')),
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    next_attempt_at_unix INTEGER NOT NULL,
                    locked_until_unix INTEGER,
                    delivered_at_unix INTEGER,
                    last_http_status INTEGER,
                    last_error TEXT,
                    created_at_unix INTEGER NOT NULL,
                    UNIQUE(event_id, destination_id)
                );

                CREATE INDEX IF NOT EXISTS tenant_webhook_deliveries_due
                    ON tenant_webhook_deliveries(tenant_id, status, next_attempt_at_unix);

                CREATE TABLE IF NOT EXISTS tenant_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    created_at_unix INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS tenant_audit_tenant_created
                    ON tenant_audit(tenant_id, id DESC);

                CREATE TABLE IF NOT EXISTS usage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_id TEXT NOT NULL,
                    provider_response_id TEXT,
                    provider TEXT NOT NULL CHECK(provider IN ('openai', 'anthropic')),
                    path TEXT NOT NULL,
                    requested_model TEXT NOT NULL,
                    provider_model TEXT,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    token_status TEXT NOT NULL CHECK(token_status IN ('actual', 'missing')),
                    pricing_status TEXT NOT NULL CHECK(pricing_status IN ('priced', 'unpriced')),
                    model_price_version TEXT,
                    input_usd_micros_per_million INTEGER,
                    output_usd_micros_per_million INTEGER,
                    cost_usd_micros INTEGER,
                    created_at_unix INTEGER NOT NULL,
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

                CREATE INDEX IF NOT EXISTS usage_events_tenant_provider_response
                    ON usage_events(tenant_id, provider, provider_response_id)
                    WHERE provider_response_id IS NOT NULL;

                CREATE TABLE IF NOT EXISTS usage_reconciliation_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    source TEXT NOT NULL,
                    statement_id TEXT NOT NULL,
                    statement_hash BLOB NOT NULL,
                    actor_admin_id TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK(record_count > 0),
                    matched_count INTEGER NOT NULL CHECK(matched_count >= 0),
                    mismatched_count INTEGER NOT NULL CHECK(mismatched_count >= 0),
                    orphan_count INTEGER NOT NULL CHECK(orphan_count >= 0),
                    ambiguous_count INTEGER NOT NULL CHECK(ambiguous_count >= 0),
                    created_at_unix INTEGER NOT NULL,
                    UNIQUE(tenant_id, source, statement_id),
                    CHECK(record_count = matched_count + mismatched_count + orphan_count + ambiguous_count)
                );

                CREATE INDEX IF NOT EXISTS usage_reconciliation_runs_tenant_created
                    ON usage_reconciliation_runs(tenant_id, created_at_unix DESC, id DESC);

                CREATE TABLE IF NOT EXISTS usage_reconciliation_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES usage_reconciliation_runs(id) ON DELETE RESTRICT,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    source_record_id TEXT NOT NULL,
                    usage_event_id INTEGER REFERENCES usage_events(id) ON DELETE RESTRICT,
                    provider TEXT NOT NULL CHECK(provider IN ('openai', 'anthropic')),
                    provider_response_id TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cost_usd_micros INTEGER,
                    status TEXT NOT NULL CHECK(status IN ('matched', 'mismatched', 'orphan', 'ambiguous')),
                    created_at_unix INTEGER NOT NULL,
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
                    ON usage_reconciliation_observations(run_id, id ASC);

                CREATE TABLE IF NOT EXISTS usage_retention_policies (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),
                    updated_by TEXT NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS usage_retention_runs (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    actor_admin_id TEXT NOT NULL,
                    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),
                    cutoff_unix INTEGER NOT NULL,
                    executed INTEGER NOT NULL CHECK(executed IN (0, 1)),
                    eligible_event_count INTEGER NOT NULL CHECK(eligible_event_count >= 0),
                    protected_reconciliation_event_count INTEGER NOT NULL
                        CHECK(protected_reconciliation_event_count >= 0),
                    eligible_input_tokens INTEGER NOT NULL CHECK(eligible_input_tokens >= 0),
                    eligible_output_tokens INTEGER NOT NULL CHECK(eligible_output_tokens >= 0),
                    eligible_cost_usd_micros INTEGER NOT NULL CHECK(eligible_cost_usd_micros >= 0),
                    deleted_event_count INTEGER NOT NULL CHECK(deleted_event_count >= 0),
                    created_at_unix INTEGER NOT NULL,
                    CHECK((executed = 0 AND deleted_event_count = 0)
                          OR (executed = 1 AND deleted_event_count = eligible_event_count))
                );

                CREATE INDEX IF NOT EXISTS usage_retention_runs_tenant_created
                    ON usage_retention_runs(tenant_id, created_at_unix DESC, id DESC);

                CREATE TABLE IF NOT EXISTS usage_quota_policies (
                    tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_limit INTEGER CHECK(request_limit IS NULL OR request_limit > 0),
                    token_limit INTEGER CHECK(token_limit IS NULL OR token_limit > 0),
                    cost_usd_micros_limit INTEGER
                        CHECK(cost_usd_micros_limit IS NULL OR cost_usd_micros_limit > 0),
                    alert_threshold_basis_points INTEGER NOT NULL
                        CHECK(alert_threshold_basis_points BETWEEN 1 AND 10000),
                    updated_by TEXT NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    CHECK(request_limit IS NOT NULL OR token_limit IS NOT NULL
                          OR cost_usd_micros_limit IS NOT NULL)
                );

                CREATE TABLE IF NOT EXISTS control_plane_admins (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    token_hash BLOB NOT NULL UNIQUE,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'operator', 'viewer')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER
                );

                CREATE INDEX IF NOT EXISTS control_plane_admins_active_hash
                    ON control_plane_admins(token_hash) WHERE active = 1;

                CREATE TABLE IF NOT EXISTS scim_tokens (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    token_hash BLOB NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    expires_at_unix INTEGER NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER
                );

                CREATE INDEX IF NOT EXISTS scim_tokens_active_hash
                    ON scim_tokens(token_hash) WHERE active = 1;

                CREATE INDEX IF NOT EXISTS scim_tokens_organization_created
                    ON scim_tokens(organization_id, created_at_unix, id);

                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organization_oidc_connections (
                    organization_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    issuer TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organization_saml_connections (
                    organization_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    entity_id TEXT NOT NULL,
                    metadata_xml TEXT NOT NULL,
                    metadata_signing_cert_pem TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS oidc_authorization_states (
                    state_hash BLOB PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    expires_at_unix INTEGER NOT NULL,
                    consumed_at_unix INTEGER,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS oidc_authorization_states_expiry
                    ON oidc_authorization_states(expires_at_unix);

                CREATE TABLE IF NOT EXISTS saml_authorization_states (
                    state_hash BLOB PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL
                        REFERENCES workspaces(id) ON DELETE CASCADE,
                    invitation_id TEXT REFERENCES workspace_invitations(id) ON DELETE CASCADE,
                    request_id TEXT NOT NULL,
                    idp_entity_id TEXT NOT NULL,
                    expected_binding TEXT NOT NULL,
                    request_binding TEXT NOT NULL,
                    acs_url TEXT NOT NULL,
                    acs_binding TEXT NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    consumed_at_unix INTEGER,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS saml_authorization_states_expiry
                    ON saml_authorization_states(expires_at_unix);

                CREATE TABLE IF NOT EXISTS oidc_browser_sessions (
                    session_hash BLOB PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    federation_kind TEXT NOT NULL DEFAULT 'oidc'
                        CHECK(federation_kind IN ('oidc', 'saml')),
                    expires_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS oidc_browser_sessions_expiry
                    ON oidc_browser_sessions(expires_at_unix);

                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    UNIQUE(organization_id, name)
                );

                CREATE INDEX IF NOT EXISTS workspaces_organization_created
                    ON workspaces(organization_id, created_at_unix, id);

                CREATE TABLE IF NOT EXISTS workspace_principals (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workspace_external_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    principal_id TEXT NOT NULL REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(issuer, subject),
                    UNIQUE(principal_id, issuer)
                );

                CREATE INDEX IF NOT EXISTS workspace_external_identities_principal
                    ON workspace_external_identities(principal_id);

                CREATE TABLE IF NOT EXISTS workspace_memberships (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'analyst', 'developer')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(workspace_id, principal_id)
                );

                CREATE INDEX IF NOT EXISTS workspace_memberships_principal_active
                    ON workspace_memberships(principal_id, workspace_id) WHERE active = 1;

                CREATE TABLE IF NOT EXISTS workspace_invitations (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    token_hash BLOB NOT NULL UNIQUE,
                    recipient_label TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'analyst', 'developer')),
                    created_by_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE RESTRICT,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    expires_at_unix INTEGER NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER,
                    accepted_by_principal_id TEXT
                        REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    accepted_at_unix INTEGER,
                    CHECK((accepted_at_unix IS NULL AND accepted_by_principal_id IS NULL)
                          OR (accepted_at_unix IS NOT NULL
                              AND accepted_by_principal_id IS NOT NULL))
                );

                CREATE INDEX IF NOT EXISTS workspace_invitations_active_hash
                    ON workspace_invitations(token_hash) WHERE active = 1;
                CREATE INDEX IF NOT EXISTS workspace_invitations_workspace_created
                    ON workspace_invitations(workspace_id, created_at_unix DESC, id DESC);

                CREATE TABLE IF NOT EXISTS workspace_service_accounts (
                    id TEXT PRIMARY KEY NOT NULL,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    created_by_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE RESTRICT,
                    token_hash BLOB NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    expires_at_unix INTEGER NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    revoked_at_unix INTEGER
                );

                CREATE INDEX IF NOT EXISTS workspace_service_accounts_active_hash
                    ON workspace_service_accounts(token_hash) WHERE active = 1;
                CREATE INDEX IF NOT EXISTS workspace_service_accounts_workspace_created
                    ON workspace_service_accounts(workspace_id, created_at_unix, id);

                -- SCIM records deliberately bind an opaque IdP correlation
                -- value to a local principal without creating a membership,
                -- external OIDC identity, or credential. A later explicit
                -- workspace role assignment is the only access grant.
                CREATE TABLE IF NOT EXISTS scim_users (
                    id TEXT PRIMARY KEY NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    external_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    UNIQUE(organization_id, external_id),
                    UNIQUE(organization_id, user_name)
                );

                CREATE INDEX IF NOT EXISTS scim_users_organization_active
                    ON scim_users(organization_id, active, id);

                CREATE TABLE IF NOT EXISTS scim_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    scim_token_id TEXT REFERENCES scim_tokens(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS scim_audit_organization_created
                    ON scim_audit(organization_id, id DESC);

                CREATE TABLE IF NOT EXISTS scim_groups (
                    id TEXT PRIMARY KEY NOT NULL,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    external_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    UNIQUE(organization_id, external_id)
                );

                CREATE INDEX IF NOT EXISTS scim_groups_organization_active
                    ON scim_groups(organization_id, active, id);

                CREATE TABLE IF NOT EXISTS scim_group_members (
                    group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
                    principal_id TEXT NOT NULL
                        REFERENCES workspace_principals(id) ON DELETE CASCADE,
                    created_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(group_id, principal_id)
                );

                CREATE INDEX IF NOT EXISTS scim_group_members_principal
                    ON scim_group_members(principal_id, group_id);

                CREATE TABLE IF NOT EXISTS scim_group_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL
                        REFERENCES organizations(id) ON DELETE CASCADE,
                    scim_token_id TEXT REFERENCES scim_tokens(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_group_id TEXT NOT NULL,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS scim_group_audit_organization_created
                    ON scim_group_audit(organization_id, id DESC);

                -- A group never carries authority by itself. An active
                -- workspace owner must create this explicit mapping, which
                -- grants the fixed read-only analyst bundle at evaluation
                -- time. Removing a SCIM group member therefore revokes access
                -- without copying a group-derived membership into this table.
                CREATE TABLE IF NOT EXISTS workspace_scim_group_mappings (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(workspace_id, group_id)
                );

                CREATE INDEX IF NOT EXISTS workspace_scim_group_mappings_group
                    ON workspace_scim_group_mappings(group_id, workspace_id);

                CREATE TABLE IF NOT EXISTS workspace_scim_group_mapping_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    group_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('group_mapping.create', 'group_mapping.delete')),
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS workspace_scim_group_mapping_audit_workspace_created
                    ON workspace_scim_group_mapping_audit(workspace_id, id DESC);

                CREATE TABLE IF NOT EXISTS workspace_admin_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    target_principal_id TEXT REFERENCES workspace_principals(id) ON DELETE SET NULL,
                    created_at_unix INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS workspace_admin_audit_workspace_created
                    ON workspace_admin_audit(workspace_id, id DESC);
                ",
            )
            .context("failed to migrate tenant database")?;

        let browser_session_has_federation_kind = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('oidc_browser_sessions')
                    WHERE name = 'federation_kind'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to inspect SQLite browser-session schema")?
            != 0;
        if !browser_session_has_federation_kind {
            connection
                .execute_batch(
                    "ALTER TABLE oidc_browser_sessions
                     ADD COLUMN federation_kind TEXT NOT NULL DEFAULT 'oidc'
                     CHECK(federation_kind IN ('oidc', 'saml'));",
                )
                .context("failed to migrate SQLite browser-session federation kind")?;
        }

        let saml_state_has_invitation_id = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('saml_authorization_states')
                    WHERE name = 'invitation_id'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to inspect SQLite SAML authorization-state schema")?
            != 0;
        if !saml_state_has_invitation_id {
            connection
                .execute_batch(
                    "ALTER TABLE saml_authorization_states
                     ADD COLUMN invitation_id TEXT REFERENCES workspace_invitations(id) ON DELETE CASCADE;",
                )
                .context("failed to migrate SQLite SAML invitation state")?;
        }

        let bootstrap_created_at = now_unix();
        connection
            .execute(
                "INSERT OR IGNORE INTO organizations (id, name, active, created_at_unix)
                 VALUES (?1, ?2, 1, ?3)",
                params![
                    BOOTSTRAP_ORGANIZATION_ID,
                    "Bootstrap organization",
                    bootstrap_created_at
                ],
            )
            .context("failed to create SQLite bootstrap organization")?;
        connection
            .execute(
                "INSERT OR IGNORE INTO workspaces
                    (id, organization_id, tenant_id, name, active, created_at_unix)
                 SELECT 'workspace_' || id, ?1, id, name, active, created_at_unix
                 FROM tenants",
                [BOOTSTRAP_ORGANIZATION_ID],
            )
            .context("failed to backfill SQLite tenant workspaces")?;

        Ok(Self {
            connection: Some(Arc::new(Mutex::new(connection))),
            postgres: None,
            audit_max_rows: audit_max_rows.max(1),
            audit_dispatcher: None,
            usage_failed_events: Arc::new(AtomicU64::new(0)),
            webhook_signing_key: None,
        })
    }

    /// Open the shared PostgreSQL control plane. The connection URL is read
    /// from an environment variable by the caller and must require TLS.
    pub async fn open_postgres(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
    ) -> anyhow::Result<Self> {
        Self::open_postgres_with_ca(
            connection_url,
            audit_max_rows,
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            None,
        )
        .await
    }

    /// Open the shared PostgreSQL control plane with an optional additional
    /// PEM CA bundle for providers using a private certificate authority.
    pub async fn open_postgres_with_ca(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        ca_cert_file: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::open_postgres_with_ca_and_tls(
            connection_url,
            audit_max_rows,
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            ca_cert_file,
            true,
        )
        .await
    }

    /// Open the shared PostgreSQL control plane with an explicit TLS policy.
    ///
    /// `require_tls` may only be false for a loopback development deployment
    /// or the private `postgres` service in the bundled Compose template. The
    /// process entry point validates that boundary before calling this method;
    /// the strict `open_postgres_with_ca` API remains the safe default.
    pub async fn open_postgres_with_ca_and_tls(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        ca_cert_file: Option<&str>,
        require_tls: bool,
    ) -> anyhow::Result<Self> {
        let postgres = PostgresTenantStore::open(
            connection_url,
            audit_max_rows.max(1),
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            require_tls,
            ca_cert_file,
        )
        .await?;
        Ok(Self {
            connection: None,
            postgres: Some(postgres),
            audit_max_rows: audit_max_rows.max(1),
            audit_dispatcher: None,
            usage_failed_events: Arc::new(AtomicU64::new(0)),
            webhook_signing_key: None,
        })
    }

    /// Run PostgreSQL schema migrations using a separately privileged migration
    /// role. Normal proxy startup deliberately never performs DDL.
    pub async fn migrate_postgres(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
    ) -> anyhow::Result<()> {
        Self::migrate_postgres_with_ca(
            connection_url,
            audit_max_rows,
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            None,
        )
        .await
    }

    /// Run PostgreSQL migrations with an optional additional PEM CA bundle.
    pub async fn migrate_postgres_with_ca(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        ca_cert_file: Option<&str>,
    ) -> anyhow::Result<()> {
        Self::migrate_postgres_with_ca_and_tls(
            connection_url,
            audit_max_rows,
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            ca_cert_file,
            true,
        )
        .await
    }

    /// Run PostgreSQL migrations with an explicit TLS policy. The caller must
    /// restrict `require_tls = false` to loopback or the private Compose
    /// `postgres` service; `migrate_postgres_with_ca` stays strict by default.
    pub async fn migrate_postgres_with_ca_and_tls(
        connection_url: &str,
        audit_max_rows: usize,
        command_timeout: Duration,
        pool_max_size: usize,
        pool_wait_timeout: Duration,
        ca_cert_file: Option<&str>,
        require_tls: bool,
    ) -> anyhow::Result<()> {
        PostgresTenantStore::migrate(
            connection_url,
            audit_max_rows.max(1),
            command_timeout,
            pool_max_size,
            pool_wait_timeout,
            require_tls,
            ca_cert_file,
        )
        .await
    }

    /// Move persistence of low-sensitivity audit metadata off the proxy's
    /// request path. Queue pressure is visible through `/readyz`; model
    /// authentication and policy enforcement are never silently bypassed.
    pub fn with_audit_dispatcher(mut self, capacity: usize) -> Self {
        let writer = self.clone();
        let (sender, mut receiver) = mpsc::channel::<TenantAuditWrite>(capacity.max(1));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let failed_events = Arc::new(AtomicU64::new(0));
        let worker_failures = failed_events.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                if let Err(error_value) = writer
                    .append_audit_async(
                        &event.tenant_id,
                        &event.path,
                        &event.outcome,
                        event.status_code,
                        event.latency_ms,
                    )
                    .await
                {
                    worker_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(error = %error_value, "failed to persist queued tenant audit event");
                }
            }
        });
        self.audit_dispatcher = Some(TenantAuditDispatcher {
            sender,
            dropped_events,
            failed_events,
        });
        self
    }

    /// Queue an audit event without awaiting storage. Returns false when this
    /// store is not configured with an asynchronous dispatcher or when its
    /// bounded queue is full/closed.
    pub fn queue_audit(
        &self,
        tenant_id: &str,
        path: &str,
        outcome: &str,
        status_code: u16,
        latency_ms: u64,
    ) -> TenantAuditQueueResult {
        let Some(dispatcher) = &self.audit_dispatcher else {
            return TenantAuditQueueResult::NotConfigured;
        };
        let event = TenantAuditWrite {
            tenant_id: tenant_id.to_owned(),
            path: path.to_owned(),
            outcome: outcome.to_owned(),
            status_code,
            latency_ms,
        };
        if dispatcher.sender.try_send(event).is_ok() {
            TenantAuditQueueResult::Queued
        } else {
            dispatcher.dropped_events.fetch_add(1, Ordering::Relaxed);
            TenantAuditQueueResult::Dropped
        }
    }

    pub fn audit_queue_status(&self) -> TenantAuditQueueStatus {
        match &self.audit_dispatcher {
            Some(dispatcher) => TenantAuditQueueStatus {
                enabled: true,
                dropped_events: dispatcher.dropped_events.load(Ordering::Relaxed),
                failed_events: dispatcher.failed_events.load(Ordering::Relaxed),
            },
            None => TenantAuditQueueStatus {
                enabled: false,
                dropped_events: 0,
                failed_events: 0,
            },
        }
    }

    pub fn usage_ledger_status(&self) -> UsageLedgerStatus {
        UsageLedgerStatus {
            failed_events: self.usage_failed_events.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    async fn open_postgres_for_test(
        connection_url: &str,
        audit_max_rows: usize,
    ) -> anyhow::Result<Self> {
        let postgres = PostgresTenantStore::open_for_test(connection_url, audit_max_rows).await?;
        Ok(Self {
            connection: None,
            postgres: Some(postgres),
            audit_max_rows: audit_max_rows.max(1),
            audit_dispatcher: None,
            usage_failed_events: Arc::new(AtomicU64::new(0)),
            webhook_signing_key: None,
        })
    }

    /// Configure the process-wide webhook master key. It must be a base64url
    /// encoding of 32 random bytes, normally supplied by a secret manager.
    /// Destination secrets are derived deterministically and never stored.
    pub fn with_webhook_signing_key_base64url(mut self, encoded: &str) -> anyhow::Result<Self> {
        let key = WebhookSigningKey::from_base64url(encoded)?;
        self.webhook_signing_key = Some(key);
        Ok(self)
    }

    pub async fn create_webhook_destination_async(
        &self,
        tenant_id: &str,
        url: &str,
        event_types: &[String],
    ) -> anyhow::Result<IssuedWebhookDestination> {
        let key = self
            .webhook_signing_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("webhook signing key is not configured"))?;
        let url = validate_webhook_destination_url(url)?;
        let event_types = validate_webhook_event_types(event_types)?;
        let destination = match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_webhook_destination(tenant_id, &url, &event_types)
                    .await?
            }
            None => self.create_webhook_destination(tenant_id, &url, &event_types)?,
        };
        Ok(IssuedWebhookDestination {
            secret: key.secret_for(&destination.id)?,
            destination,
        })
    }

    /// Create a webhook destination from a customer workspace session. The
    /// backend performs the owner check and workspace-to-tenant resolution in
    /// the same transaction/query as the insert and audit event, so a browser
    /// can never select another tenant by supplying an ID.
    pub async fn create_workspace_webhook_destination_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        url: &str,
        event_types: &[String],
    ) -> anyhow::Result<IssuedWebhookDestination> {
        let key = self
            .webhook_signing_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("webhook signing key is not configured"))?;
        let url = validate_webhook_destination_url(url)?;
        let event_types = validate_webhook_event_types(event_types)?;
        let destination = match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_workspace_webhook_destination(
                        workspace_id,
                        principal_id,
                        &url,
                        &event_types,
                    )
                    .await?
            }
            None => self.create_workspace_webhook_destination(
                workspace_id,
                principal_id,
                &url,
                &event_types,
            )?,
        };
        Ok(IssuedWebhookDestination {
            secret: key.secret_for(&destination.id)?,
            destination,
        })
    }

    pub async fn list_webhook_destinations_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<WebhookDestination>> {
        match &self.postgres {
            Some(postgres) => postgres.list_webhook_destinations(tenant_id).await,
            None => self.list_webhook_destinations(tenant_id),
        }
    }

    pub async fn deactivate_webhook_destination_async(
        &self,
        tenant_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .deactivate_webhook_destination(tenant_id, destination_id)
                    .await
            }
            None => self.deactivate_webhook_destination(tenant_id, destination_id),
        }
    }

    /// Deactivate a customer webhook destination with an owner-only,
    /// workspace-scoped authorization check and an atomic audit event.
    pub async fn deactivate_workspace_webhook_destination_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .deactivate_workspace_webhook_destination(
                        workspace_id,
                        principal_id,
                        destination_id,
                    )
                    .await
            }
            None => self.deactivate_workspace_webhook_destination(
                workspace_id,
                principal_id,
                destination_id,
            ),
        }
    }

    pub async fn list_webhook_deliveries_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WebhookDelivery>> {
        match &self.postgres {
            Some(postgres) => postgres.list_webhook_deliveries(tenant_id, limit).await,
            None => self.list_webhook_deliveries(tenant_id, limit),
        }
    }

    /// Run one bounded delivery attempt. A caller may invoke this from a
    /// scheduler or the process worker; no prompts or model responses enter
    /// the webhook payload.
    pub async fn dispatch_webhooks_once(&self, client: &Client) -> anyhow::Result<bool> {
        let Some(key) = self.webhook_signing_key.as_ref() else {
            return Ok(false);
        };
        let pending = match &self.postgres {
            Some(postgres) => postgres.claim_webhook_delivery().await?,
            None => self.claim_webhook_delivery()?,
        };
        let Some(pending) = pending else {
            return Ok(false);
        };
        let result = deliver_webhook(client, key, &pending).await;
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .finish_webhook_delivery(&pending.delivery.id, result)
                    .await?
            }
            None => self.finish_webhook_delivery(&pending.delivery.id, result)?,
        }
        Ok(true)
    }

    pub async fn run_webhook_delivery_loop(self) {
        let client = match Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to build webhook delivery client");
                return;
            }
        };
        loop {
            match self.dispatch_webhooks_once(&client).await {
                Ok(true) => continue,
                Ok(false) => tokio::time::sleep(Duration::from_secs(2)).await,
                Err(error_value) => {
                    tracing::error!(error = %error_value, "webhook delivery worker failed");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    pub async fn create_tenant_async(&self, name: &str) -> anyhow::Result<Tenant> {
        match &self.postgres {
            Some(postgres) => postgres.create_tenant(name).await,
            None => self.create_tenant(name),
        }
    }

    pub async fn create_tenant_in_organization_async(
        &self,
        organization_id: &str,
        name: &str,
    ) -> anyhow::Result<Tenant> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_tenant_in_organization(organization_id, name)
                    .await
            }
            None => self.create_tenant_in_organization(organization_id, name),
        }
    }

    pub async fn list_tenants_async(&self) -> anyhow::Result<Vec<Tenant>> {
        match &self.postgres {
            Some(postgres) => postgres.list_tenants().await,
            None => self.list_tenants(),
        }
    }

    pub async fn create_organization_async(&self, name: &str) -> anyhow::Result<Organization> {
        match &self.postgres {
            Some(postgres) => postgres.create_organization(name).await,
            None => self.create_organization(name),
        }
    }

    pub async fn list_organizations_async(&self) -> anyhow::Result<Vec<Organization>> {
        match &self.postgres {
            Some(postgres) => postgres.list_organizations().await,
            None => self.list_organizations(),
        }
    }

    /// Issue an organization-scoped, expiring SCIM credential. The raw
    /// credential is returned once and never persisted in plaintext.
    pub async fn issue_scim_token_async(
        &self,
        organization_id: &str,
        label: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedScimToken> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .issue_scim_token(organization_id, label, expires_at_unix)
                    .await
            }
            None => self.issue_scim_token(organization_id, label, expires_at_unix),
        }
    }

    pub async fn list_scim_tokens_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Vec<ScimToken>> {
        match &self.postgres {
            Some(postgres) => postgres.list_scim_tokens(organization_id).await,
            None => self.list_scim_tokens(organization_id),
        }
    }

    pub async fn revoke_scim_token_async(&self, token_id: &str) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.revoke_scim_token(token_id).await,
            None => self.revoke_scim_token(token_id),
        }
    }

    /// Authenticate a SCIM bearer against its active organization scope. This
    /// is intentionally distinct from proxy, platform-admin, and browser
    /// credentials, so a credential from any other plane cannot cross-auth.
    pub async fn authenticate_scim_bearer_async(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<ScimIdentity>> {
        match &self.postgres {
            Some(postgres) => postgres.authenticate_scim_bearer(presented_header).await,
            None => self.authenticate_scim_bearer(presented_header),
        }
    }

    /// Provision a SCIM directory user under the authenticated credential's
    /// organization. This intentionally creates no workspace membership.
    pub async fn create_scim_user_async(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        user_name: &str,
        display_name: &str,
        active: bool,
    ) -> anyhow::Result<ScimUser> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_scim_user(identity, external_id, user_name, display_name, active)
                    .await
            }
            None => self.create_scim_user(identity, external_id, user_name, display_name, active),
        }
    }

    pub async fn list_scim_users_async(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimUserPage> {
        match &self.postgres {
            Some(postgres) => postgres.list_scim_users(identity, start_index, count).await,
            None => self.list_scim_users(identity, start_index, count),
        }
    }

    pub async fn scim_user_by_id_async(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
    ) -> anyhow::Result<Option<ScimUser>> {
        match &self.postgres {
            Some(postgres) => postgres.scim_user_by_id(identity, user_id).await,
            None => self.scim_user_by_id(identity, user_id),
        }
    }

    pub async fn update_scim_user_async(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
        update: ScimUserUpdate,
    ) -> anyhow::Result<Option<ScimUser>> {
        match &self.postgres {
            Some(postgres) => postgres.update_scim_user(identity, user_id, update).await,
            None => self.update_scim_user(identity, user_id, update),
        }
    }

    /// Create a directory-only SCIM group. Membership in this group is not a
    /// workspace role and cannot authorize a browser or proxy request.
    pub async fn create_scim_group_async(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        display_name: &str,
        member_ids: Vec<String>,
    ) -> anyhow::Result<ScimGroup> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_scim_group(identity, external_id, display_name, member_ids)
                    .await
            }
            None => self.create_scim_group(identity, external_id, display_name, member_ids),
        }
    }

    pub async fn list_scim_groups_async(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimGroupPage> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_scim_groups(identity, start_index, count)
                    .await
            }
            None => self.list_scim_groups(identity, start_index, count),
        }
    }

    pub async fn scim_group_by_id_async(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<Option<ScimGroup>> {
        match &self.postgres {
            Some(postgres) => postgres.scim_group_by_id(identity, group_id).await,
            None => self.scim_group_by_id(identity, group_id),
        }
    }

    pub async fn update_scim_group_async(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
        update: ScimGroupUpdate,
    ) -> anyhow::Result<Option<ScimGroup>> {
        match &self.postgres {
            Some(postgres) => postgres.update_scim_group(identity, group_id, update).await,
            None => self.update_scim_group(identity, group_id, update),
        }
    }

    pub async fn delete_scim_group_async(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.delete_scim_group(identity, group_id).await,
            None => self.delete_scim_group(identity, group_id),
        }
    }

    pub async fn set_organization_active_async(
        &self,
        organization_id: &str,
        active: bool,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_organization_active(organization_id, active)
                    .await
            }
            None => self.set_organization_active(organization_id, active),
        }
    }

    pub async fn list_organization_workspaces_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Vec<Workspace>> {
        match &self.postgres {
            Some(postgres) => postgres.list_organization_workspaces(organization_id).await,
            None => self.list_organization_workspaces(organization_id),
        }
    }

    /// Return whether an active workspace belongs to an active organization.
    /// This is intentionally an existence query instead of a workspace list,
    /// so an OIDC login start never enumerates tenant data from browser input.
    pub async fn active_workspace_in_organization_async(
        &self,
        organization_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .active_workspace_in_organization(organization_id, workspace_id)
                    .await
            }
            None => self.active_workspace_in_organization(organization_id, workspace_id),
        }
    }

    /// Save only public OIDC connection metadata. This does not authenticate a
    /// browser and cannot be used to manually bind an external subject.
    pub async fn set_organization_oidc_connection_async(
        &self,
        organization_id: &str,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationOidcConnection> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_organization_oidc_connection(
                        organization_id,
                        issuer,
                        client_id,
                        redirect_uri,
                        active,
                    )
                    .await
            }
            None => self.set_organization_oidc_connection(
                organization_id,
                issuer,
                client_id,
                redirect_uri,
                active,
            ),
        }
    }

    pub async fn organization_oidc_connection_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationOidcConnection>> {
        match &self.postgres {
            Some(postgres) => postgres.organization_oidc_connection(organization_id).await,
            None => self.organization_oidc_connection(organization_id),
        }
    }

    pub async fn delete_organization_oidc_connection_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .delete_organization_oidc_connection(organization_id)
                    .await
            }
            None => self.delete_organization_oidc_connection(organization_id),
        }
    }

    pub async fn set_organization_saml_connection_async(
        &self,
        organization_id: &str,
        entity_id: &str,
        metadata_xml: &str,
        metadata_signing_cert_pem: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationSamlConnection> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_organization_saml_connection(
                        organization_id,
                        entity_id,
                        metadata_xml,
                        metadata_signing_cert_pem,
                        active,
                    )
                    .await
            }
            None => self.set_organization_saml_connection(
                organization_id,
                entity_id,
                metadata_xml,
                metadata_signing_cert_pem,
                active,
            ),
        }
    }

    pub async fn organization_saml_connection_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationSamlConnection>> {
        match &self.postgres {
            Some(postgres) => postgres.organization_saml_connection(organization_id).await,
            None => self.organization_saml_connection(organization_id),
        }
    }

    pub async fn delete_organization_saml_connection_async(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .delete_organization_saml_connection(organization_id)
                    .await
            }
            None => self.delete_organization_saml_connection(organization_id),
        }
    }

    /// Reserve an opaque, single-use OIDC state for a short browser round trip.
    /// Only its domain-separated hash reaches durable storage; the raw state
    /// and future PKCE verifier are never written to the control-plane database.
    pub async fn reserve_oidc_authorization_state_async(
        &self,
        state: &str,
        organization_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .reserve_oidc_authorization_state(state, organization_id, expires_at_unix)
                    .await
            }
            None => self.reserve_oidc_authorization_state(state, organization_id, expires_at_unix),
        }
    }

    /// Atomically consume a previously reserved state. Replays, expired states,
    /// and a state for a different organization all return `false`.
    pub async fn consume_oidc_authorization_state_async(
        &self,
        state: &str,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .consume_oidc_authorization_state(state, organization_id)
                    .await
            }
            None => self.consume_oidc_authorization_state(state, organization_id),
        }
    }

    pub async fn reserve_saml_authorization_state_async(
        &self,
        state: &str,
        pending: &SamlAuthorizationPending,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .reserve_saml_authorization_state(state, pending, expires_at_unix)
                    .await
            }
            None => self.reserve_saml_authorization_state(state, pending, expires_at_unix),
        }
    }

    pub async fn consume_saml_authorization_state_async(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<SamlAuthorizationPending>> {
        match &self.postgres {
            Some(postgres) => postgres.consume_saml_authorization_state(state).await,
            None => self.consume_saml_authorization_state(state),
        }
    }

    pub async fn workspace_for_tenant_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<Workspace>> {
        match &self.postgres {
            Some(postgres) => postgres.workspace_for_tenant(tenant_id).await,
            None => self.workspace_for_tenant(tenant_id),
        }
    }

    /// Resolve an active workspace to its current tenant relationship. Browser
    /// handlers use this after authenticating a session rather than deriving a
    /// tenant ID from an opaque workspace ID convention.
    pub async fn active_workspace_by_id_async(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Option<Workspace>> {
        match &self.postgres {
            Some(postgres) => postgres.active_workspace_by_id(workspace_id).await,
            None => self.active_workspace_by_id(workspace_id),
        }
    }

    pub async fn create_workspace_principal_async(
        &self,
        name: &str,
    ) -> anyhow::Result<WorkspacePrincipal> {
        match &self.postgres {
            Some(postgres) => postgres.create_workspace_principal(name).await,
            None => self.create_workspace_principal(name),
        }
    }

    /// Record an IdP-issued subject only after the OIDC/JWKS verification path
    /// has authenticated it. This storage API never accepts an email address
    /// as a substitute for issuer + subject.
    pub async fn link_workspace_external_identity_async(
        &self,
        principal_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<WorkspaceExternalIdentity> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .link_workspace_external_identity(principal_id, issuer, subject)
                    .await
            }
            None => self.link_workspace_external_identity(principal_id, issuer, subject),
        }
    }

    pub async fn workspace_principal_for_external_identity_async(
        &self,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<WorkspacePrincipal>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .workspace_principal_for_external_identity(issuer, subject)
                    .await
            }
            None => self.workspace_principal_for_external_identity(issuer, subject),
        }
    }

    /// Resolve an identity only after its ID token has been cryptographically
    /// verified. The lookup joins the selected organization, its active OIDC
    /// connection, the exact issuer and subject, principal, workspace, and
    /// active membership so an IdP cannot grant access merely by authenticating
    /// a user.
    pub async fn verified_identity_workspace_access_async(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .verified_identity_workspace_access(
                        organization_id,
                        workspace_id,
                        issuer,
                        subject,
                    )
                    .await
            }
            None => self.verified_identity_workspace_access(
                organization_id,
                workspace_id,
                issuer,
                subject,
            ),
        }
    }

    /// Resolve a SAML identity only after the SAML response has been
    /// cryptographically verified. The lookup is deliberately bound to the
    /// active SAML connection's entity ID, rather than accepting another
    /// federation connection as authority for the same external identity.
    pub async fn verified_saml_identity_workspace_access_async(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .verified_saml_identity_workspace_access(
                        organization_id,
                        workspace_id,
                        issuer,
                        subject,
                    )
                    .await
            }
            None => self.verified_saml_identity_workspace_access(
                organization_id,
                workspace_id,
                issuer,
                subject,
            ),
        }
    }

    /// Create an opaque browser session only for a still-active, authorized
    /// customer identity. The session has no role claim: later authentication
    /// resolves membership again, so suspend/revoke changes take effect at
    /// the next request.
    pub async fn issue_oidc_browser_session_async(
        &self,
        access: &VerifiedWorkspaceAccess,
        federation: BrowserSessionFederation,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedOidcBrowserSession> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .issue_oidc_browser_session(access, federation, expires_at_unix)
                    .await
            }
            None => self.issue_oidc_browser_session(access, federation, expires_at_unix),
        }
    }

    /// Atomically rotate an opaque browser session. The old token is revoked
    /// in the same transaction that issues its replacement, so it can never
    /// remain usable after a successful rotation.
    pub async fn rotate_oidc_browser_session_async(
        &self,
        token: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<Option<IssuedOidcBrowserSession>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .rotate_oidc_browser_session(token, expires_at_unix)
                    .await
            }
            None => self.rotate_oidc_browser_session(token, expires_at_unix),
        }
    }

    /// Resolve a browser session against current active organization, OIDC
    /// connection, workspace, principal, and membership state.
    pub async fn authenticate_oidc_browser_session_async(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<OidcBrowserSession>> {
        match &self.postgres {
            Some(postgres) => postgres.authenticate_oidc_browser_session(token).await,
            None => self.authenticate_oidc_browser_session(token),
        }
    }

    /// Revoke one browser session by its opaque token. It is safe to call this
    /// for a missing or already revoked token.
    pub async fn revoke_oidc_browser_session_async(&self, token: &str) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.revoke_oidc_browser_session(token).await,
            None => self.revoke_oidc_browser_session(token),
        }
    }

    pub async fn set_workspace_membership_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_workspace_membership(workspace_id, principal_id, role)
                    .await
            }
            None => self.set_workspace_membership(workspace_id, principal_id, role),
        }
    }

    /// List members of one workspace. Customer HTTP handlers must authorize
    /// this with `ManageMembership` before exposing the result.
    pub async fn list_workspace_members_async(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceMember>> {
        match &self.postgres {
            Some(postgres) => postgres.list_workspace_members(workspace_id).await,
            None => self.list_workspace_members(workspace_id),
        }
    }

    /// Create one short-lived OIDC enrollment grant. Only an active workspace
    /// owner may issue it, and the raw bearer is returned exactly once.
    pub async fn create_workspace_invitation_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        recipient_label: &str,
        role: WorkspaceRole,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceInvitation> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_workspace_invitation_as_owner(
                        workspace_id,
                        actor_principal_id,
                        recipient_label,
                        role,
                        expires_at_unix,
                    )
                    .await
            }
            None => self.create_workspace_invitation_as_owner(
                workspace_id,
                actor_principal_id,
                recipient_label,
                role,
                expires_at_unix,
            ),
        }
    }

    /// List invitation metadata after repeating the active-owner check in the
    /// store. Raw invitation bearers are never recoverable from this view.
    pub async fn list_workspace_invitations_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceInvitation>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_invitations_as_owner(workspace_id, actor_principal_id)
                    .await
            }
            None => self.list_workspace_invitations_as_owner(workspace_id, actor_principal_id),
        }
    }

    /// Revoke one unconsumed invitation. Missing, expired, consumed, and
    /// already-revoked invitations all return `false` without disclosure.
    pub async fn revoke_workspace_invitation_as_owner_async(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .revoke_workspace_invitation_as_owner(
                        workspace_id,
                        invitation_id,
                        actor_principal_id,
                    )
                    .await
            }
            None => self.revoke_workspace_invitation_as_owner(
                workspace_id,
                invitation_id,
                actor_principal_id,
            ),
        }
    }

    /// Reissue one unconsumed invitation as a new bearer. The old grant is
    /// revoked before the replacement is created, so a failed replacement
    /// cannot leave the old URL usable. The list/revoke/create calls each
    /// repeat owner authorization in their backend transaction; a concurrent
    /// acceptance therefore wins over the resend and no new grant is issued.
    pub async fn resend_workspace_invitation_as_owner_async(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        actor_principal_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<Option<IssuedWorkspaceInvitation>> {
        validate_workspace_invitation_expiry(expires_at_unix)?;
        let invitation = self
            .list_workspace_invitations_as_owner_async(workspace_id, actor_principal_id)
            .await?
            .into_iter()
            .find(|invitation| {
                invitation.id == invitation_id
                    && invitation.active
                    && invitation.revoked_at_unix.is_none()
                    && invitation.accepted_at_unix.is_none()
            });
        let Some(invitation) = invitation else {
            return Ok(None);
        };
        if !self
            .revoke_workspace_invitation_as_owner_async(
                workspace_id,
                invitation_id,
                actor_principal_id,
            )
            .await?
        {
            return Ok(None);
        }
        self.create_workspace_invitation_as_owner_async(
            workspace_id,
            actor_principal_id,
            &invitation.recipient_label,
            invitation.role,
            expires_at_unix,
        )
        .await
        .map(Some)
    }

    /// Resolve a raw invitation for the OIDC login-start endpoint. This does
    /// not consume the grant; final acceptance happens only after ID-token
    /// verification in the callback.
    pub async fn workspace_invitation_for_token_async(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<WorkspaceInvitation>> {
        self.workspace_invitation_for_federation_token_async(token, BrowserSessionFederation::Oidc)
            .await
    }

    pub async fn workspace_invitation_for_federation_token_async(
        &self,
        token: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<WorkspaceInvitation>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .workspace_invitation_for_federation_token(token, federation)
                    .await
            }
            None => self.workspace_invitation_for_federation_token(token, federation),
        }
    }

    /// Atomically consume one invitation for an already verified OIDC
    /// identity. The invitation scope must match the authenticated OIDC state
    /// supplied by the caller. A new opaque principal and exact issuer/subject
    /// binding are created only inside this transaction when the identity is
    /// first seen.
    pub async fn accept_workspace_invitation_oidc_async(
        &self,
        invitation_id: &str,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        self.accept_workspace_invitation_async(
            invitation_id,
            organization_id,
            workspace_id,
            issuer,
            subject,
            BrowserSessionFederation::Oidc,
        )
        .await
    }

    pub async fn accept_workspace_invitation_async(
        &self,
        invitation_id: &str,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .accept_workspace_invitation(
                        invitation_id,
                        organization_id,
                        workspace_id,
                        issuer,
                        subject,
                        federation,
                    )
                    .await
            }
            None => self.accept_workspace_invitation_federated(
                invitation_id,
                organization_id,
                workspace_id,
                issuer,
                subject,
                federation,
            ),
        }
    }

    /// List machine identities visible to the caller. Owner/admin see all
    /// accounts; developers see only accounts they created.
    pub async fn list_workspace_service_accounts_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceServiceAccount>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_service_accounts(workspace_id, actor_principal_id)
                    .await
            }
            None => self.list_workspace_service_accounts(workspace_id, actor_principal_id),
        }
    }

    /// Issue one workspace-scoped machine credential. The raw value is
    /// returned once and is never persisted.
    pub async fn create_workspace_service_account_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        name: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceServiceAccount> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_workspace_service_account(
                        workspace_id,
                        actor_principal_id,
                        name,
                        expires_at_unix,
                    )
                    .await
            }
            None => self.create_workspace_service_account(
                workspace_id,
                actor_principal_id,
                name,
                expires_at_unix,
            ),
        }
    }

    /// Revoke a machine identity. Developers may revoke their own accounts;
    /// owner/admin can revoke any account in the workspace.
    pub async fn revoke_workspace_service_account_async(
        &self,
        workspace_id: &str,
        account_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .revoke_workspace_service_account(workspace_id, account_id, actor_principal_id)
                    .await
            }
            None => {
                self.revoke_workspace_service_account(workspace_id, account_id, actor_principal_id)
            }
        }
    }

    /// Return active SCIM users from the caller's workspace organization. This
    /// is owner-only both at the HTTP edge and inside the store; no IdP login
    /// identifier or opaque SCIM external ID is returned.
    pub async fn list_workspace_scim_users_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimUser>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_scim_users_as_owner(workspace_id, actor_principal_id)
                    .await
            }
            None => self.list_workspace_scim_users_as_owner(workspace_id, actor_principal_id),
        }
    }

    /// Explicitly grant an active SCIM-provisioned user a role in one
    /// workspace. This never accepts an arbitrary local principal: the target
    /// must belong to the same organization SCIM directory and the actor must
    /// be an active workspace owner at commit time.
    pub async fn assign_scim_user_to_workspace_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .assign_scim_user_to_workspace_as_owner(
                        workspace_id,
                        actor_principal_id,
                        target_principal_id,
                        role,
                    )
                    .await
            }
            None => self.assign_scim_user_to_workspace_as_owner(
                workspace_id,
                actor_principal_id,
                target_principal_id,
                role,
            ),
        }
    }

    /// List only active same-organization SCIM groups after checking that the
    /// caller is the active owner of this workspace.
    pub async fn list_workspace_scim_groups_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroup>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_scim_groups_as_owner(workspace_id, actor_principal_id)
                    .await
            }
            None => self.list_workspace_scim_groups_as_owner(workspace_id, actor_principal_id),
        }
    }

    /// List explicit, owner-approved SCIM group mappings for one workspace.
    pub async fn list_workspace_scim_group_mappings_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroupMapping>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_scim_group_mappings_as_owner(workspace_id, actor_principal_id)
                    .await
            }
            None => {
                self.list_workspace_scim_group_mappings_as_owner(workspace_id, actor_principal_id)
            }
        }
    }

    /// Approve one group as the fixed, read-only analyst grant for a
    /// workspace. The group must be active and owned by the same organization.
    pub async fn create_workspace_scim_group_mapping_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_workspace_scim_group_mapping_as_owner(
                        workspace_id,
                        actor_principal_id,
                        group_id,
                    )
                    .await
            }
            None => self.create_workspace_scim_group_mapping_as_owner(
                workspace_id,
                actor_principal_id,
                group_id,
            ),
        }
    }

    /// Revoke a previously owner-approved group grant. Removing a member from
    /// the SCIM group also revokes their access immediately without deleting
    /// this mapping.
    pub async fn delete_workspace_scim_group_mapping_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .delete_workspace_scim_group_mapping_as_owner(
                        workspace_id,
                        actor_principal_id,
                        group_id,
                    )
                    .await
            }
            None => self.delete_workspace_scim_group_mapping_as_owner(
                workspace_id,
                actor_principal_id,
                group_id,
            ),
        }
    }

    /// Customer-originated membership lifecycle update. Only an active owner
    /// may make the change; the store repeats that authorization and appends
    /// the actor-attributed audit event in the same transaction. It never
    /// creates a principal or membership: identity provisioning belongs to
    /// OIDC/SCIM, not to a browser-supplied email address.
    pub async fn update_workspace_membership_as_owner_async(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
        active: bool,
    ) -> anyhow::Result<WorkspaceMembership> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .update_workspace_membership_as_owner(
                        workspace_id,
                        actor_principal_id,
                        target_principal_id,
                        role,
                        active,
                    )
                    .await
            }
            None => self.update_workspace_membership_as_owner(
                workspace_id,
                actor_principal_id,
                target_principal_id,
                role,
                active,
            ),
        }
    }

    /// The first customer-RBAC authorization seam. No HTTP handler may rely on
    /// UI state: it must ask the store whether this principal can perform the
    /// requested action in this exact workspace.
    pub async fn workspace_permits_async(
        &self,
        principal_id: &str,
        workspace_id: &str,
        permission: WorkspacePermission,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .workspace_permits(principal_id, workspace_id, permission)
                    .await
            }
            None => self.workspace_permits(principal_id, workspace_id, permission),
        }
    }

    pub async fn list_workspace_admin_audit_async(
        &self,
        workspace_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WorkspaceAdminAuditEvent>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_workspace_admin_audit(workspace_id, limit)
                    .await
            }
            None => self.list_workspace_admin_audit(workspace_id, limit),
        }
    }

    pub async fn set_tenant_active_async(
        &self,
        tenant_id: &str,
        active: bool,
    ) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.set_tenant_active(tenant_id, active).await,
            None => self.set_tenant_active(tenant_id, active),
        }
    }

    pub async fn delete_tenant_async(&self, tenant_id: &str) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.delete_tenant(tenant_id).await,
            None => self.delete_tenant(tenant_id),
        }
    }

    pub async fn create_admin_async(
        &self,
        name: &str,
        role: AdminRole,
    ) -> anyhow::Result<IssuedAdminToken> {
        match &self.postgres {
            Some(postgres) => postgres.create_admin(name, role).await,
            None => self.create_admin(name, role),
        }
    }

    pub async fn list_admins_async(&self) -> anyhow::Result<Vec<ControlPlaneAdmin>> {
        match &self.postgres {
            Some(postgres) => postgres.list_admins().await,
            None => self.list_admins(),
        }
    }

    pub async fn revoke_admin_async(&self, admin_id: &str) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.revoke_admin(admin_id).await,
            None => self.revoke_admin(admin_id),
        }
    }

    pub async fn authenticate_admin_bearer_async(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<AdminIdentity>> {
        match &self.postgres {
            Some(postgres) => postgres.authenticate_admin_bearer(presented_header).await,
            None => self.authenticate_admin_bearer(presented_header),
        }
    }

    pub async fn issue_token_async(
        &self,
        tenant_id: &str,
        label: &str,
    ) -> anyhow::Result<IssuedToken> {
        match &self.postgres {
            Some(postgres) => postgres.issue_token(tenant_id, label).await,
            None => self.issue_token(tenant_id, label),
        }
    }

    pub async fn list_tokens_async(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToken>> {
        match &self.postgres {
            Some(postgres) => postgres.list_tokens(tenant_id).await,
            None => self.list_tokens(tenant_id),
        }
    }

    pub async fn revoke_token_async(&self, token_id: &str) -> anyhow::Result<bool> {
        match &self.postgres {
            Some(postgres) => postgres.revoke_token(token_id).await,
            None => self.revoke_token(token_id),
        }
    }

    pub async fn limits_for_async(&self, tenant_id: &str) -> anyhow::Result<TenantLimits> {
        match &self.postgres {
            Some(postgres) => postgres.limits_for(tenant_id).await,
            None => self.limits_for(tenant_id),
        }
    }

    pub async fn set_limits_async(
        &self,
        tenant_id: &str,
        limits: TenantLimits,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => postgres.set_limits(tenant_id, limits).await,
            None => self.set_limits(tenant_id, limits),
        }
    }

    /// Customer-originated admission-limit mutation. It resolves the tenant
    /// only through the active workspace, re-checks the role in storage, and
    /// appends a workspace audit event in the same transaction.
    pub async fn set_workspace_limits_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        limits: TenantLimits,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_workspace_limits(workspace_id, principal_id, limits)
                    .await
            }
            None => self.set_workspace_limits(workspace_id, principal_id, limits),
        }
    }

    pub async fn create_policy_version_async(
        &self,
        tenant_id: &str,
        actor_id: &str,
        document: TenantPolicyDocument,
    ) -> anyhow::Result<TenantPolicyVersion> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .create_policy_version(tenant_id, actor_id, document)
                    .await
            }
            None => self.create_policy_version(tenant_id, actor_id, document),
        }
    }

    pub async fn list_policy_versions_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyVersion>> {
        match &self.postgres {
            Some(postgres) => postgres.list_policy_versions(tenant_id, limit).await,
            None => self.list_policy_versions(tenant_id, limit),
        }
    }

    pub async fn policy_version_async(
        &self,
        tenant_id: &str,
        version_id: &str,
    ) -> anyhow::Result<Option<TenantPolicyVersion>> {
        match &self.postgres {
            Some(postgres) => postgres.policy_version(tenant_id, version_id).await,
            None => self.policy_version(tenant_id, version_id),
        }
    }

    pub async fn approve_policy_version_async(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<TenantPolicyVersion> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .approve_policy_version(tenant_id, version_id, actor_id)
                    .await
            }
            None => self.approve_policy_version(tenant_id, version_id, actor_id),
        }
    }

    pub async fn deploy_policy_version_async(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
        action: PolicyDeploymentAction,
    ) -> anyhow::Result<TenantPolicyDeployment> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .deploy_policy_version(tenant_id, version_id, actor_id, action)
                    .await
            }
            None => self.deploy_policy_version(tenant_id, version_id, actor_id, action),
        }
    }

    pub async fn list_policy_deployments_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyDeployment>> {
        match &self.postgres {
            Some(postgres) => postgres.list_policy_deployments(tenant_id, limit).await,
            None => self.list_policy_deployments(tenant_id, limit),
        }
    }

    /// Return immutable control-plane events in ascending cursor order for
    /// SIEM consumers. `after_sequence` is exclusive and scoped to a tenant.
    pub async fn list_security_events_async(
        &self,
        tenant_id: &str,
        after_sequence: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantSecurityEvent>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_security_events(tenant_id, after_sequence, limit)
                    .await
            }
            None => self.list_security_events(tenant_id, after_sequence, limit),
        }
    }

    pub async fn simulate_policy_version_async(
        &self,
        tenant_id: &str,
        version_id: &str,
        cases: Vec<PolicySimulationCase>,
    ) -> anyhow::Result<TenantPolicySimulation> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .simulate_policy_version(tenant_id, version_id, cases)
                    .await
            }
            None => self.simulate_policy_version(tenant_id, version_id, cases),
        }
    }

    pub async fn model_policy_for_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<TenantModelPolicy>> {
        match &self.postgres {
            Some(postgres) => postgres.model_policy_for(tenant_id).await,
            None => self.model_policy_for(tenant_id),
        }
    }

    pub async fn set_model_policy_async(
        &self,
        tenant_id: &str,
        policy: Option<TenantModelPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => postgres.set_model_policy(tenant_id, policy).await,
            None => self.set_model_policy(tenant_id, policy),
        }
    }

    /// Customer-originated policy mutation. The store, rather than a browser
    /// handler, re-checks the active workspace role and appends its audit event
    /// in the same transaction as the policy write.
    pub async fn set_workspace_model_policy_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<TenantModelPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_workspace_model_policy(workspace_id, principal_id, policy)
                    .await
            }
            None => self.set_workspace_model_policy(workspace_id, principal_id, policy),
        }
    }

    pub async fn append_audit_async(
        &self,
        tenant_id: &str,
        path: &str,
        outcome: &str,
        status_code: u16,
        latency_ms: u64,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .append_audit(tenant_id, path, outcome, status_code, latency_ms)
                    .await
            }
            None => self.append_audit(tenant_id, path, outcome, status_code, latency_ms),
        }
    }

    pub async fn list_audit_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantAuditEvent>> {
        match &self.postgres {
            Some(postgres) => postgres.list_audit(tenant_id, limit).await,
            None => self.list_audit(tenant_id, limit),
        }
    }

    /// Append exactly one terminal provider usage event. Repeating the same
    /// `(tenant_id, request_id)` is a successful no-op and returns `false`.
    pub async fn append_usage_event_async(&self, event: &NewUsageEvent) -> anyhow::Result<bool> {
        let result = match &self.postgres {
            Some(postgres) => postgres.append_usage_event(event).await,
            None => self.append_usage_event(event),
        };
        if result.is_err() {
            self.usage_failed_events.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn list_usage_events_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageEvent>> {
        match &self.postgres {
            Some(postgres) => postgres.list_usage_events(tenant_id, limit).await,
            None => self.list_usage_events(tenant_id, limit),
        }
    }

    pub async fn usage_report_async(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
    ) -> anyhow::Result<UsageReport> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .usage_report(tenant_id, from_unix, until_unix)
                    .await
            }
            None => self.usage_report(tenant_id, from_unix, until_unix),
        }
    }

    pub async fn list_usage_events_range_async(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
        after_id: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<UsageEventPage> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_usage_events_range(tenant_id, from_unix, until_unix, after_id, limit)
                    .await
            }
            None => self.list_usage_events_range(tenant_id, from_unix, until_unix, after_id, limit),
        }
    }

    pub async fn import_usage_reconciliation_async(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        import: &NewUsageReconciliationImport,
    ) -> anyhow::Result<UsageReconciliationRun> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .import_usage_reconciliation(tenant_id, actor_admin_id, import)
                    .await
            }
            None => self.import_usage_reconciliation(tenant_id, actor_admin_id, import),
        }
    }

    pub async fn list_usage_reconciliation_runs_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationRun>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_usage_reconciliation_runs(tenant_id, limit)
                    .await
            }
            None => self.list_usage_reconciliation_runs(tenant_id, limit),
        }
    }

    pub async fn list_usage_reconciliation_observations_async(
        &self,
        tenant_id: &str,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationObservation>> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .list_usage_reconciliation_observations(tenant_id, run_id, limit)
                    .await
            }
            None => self.list_usage_reconciliation_observations(tenant_id, run_id, limit),
        }
    }

    pub async fn usage_retention_policy_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageRetentionPolicy>> {
        match &self.postgres {
            Some(postgres) => postgres.usage_retention_policy(tenant_id).await,
            None => self.usage_retention_policy(tenant_id),
        }
    }

    pub async fn set_usage_retention_policy_async(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageRetentionPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_usage_retention_policy(tenant_id, actor_id, policy)
                    .await
            }
            None => self.set_usage_retention_policy(tenant_id, actor_id, policy),
        }
    }

    pub async fn set_workspace_usage_retention_policy_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<UsageRetentionPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_workspace_usage_retention_policy(workspace_id, principal_id, policy)
                    .await
            }
            None => self.set_workspace_usage_retention_policy(workspace_id, principal_id, policy),
        }
    }

    pub async fn run_usage_retention_async(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        execute: bool,
    ) -> anyhow::Result<UsageRetentionRun> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .run_usage_retention(tenant_id, actor_admin_id, execute)
                    .await
            }
            None => self.run_usage_retention(tenant_id, actor_admin_id, execute),
        }
    }

    pub async fn list_usage_retention_runs_async(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageRetentionRun>> {
        match &self.postgres {
            Some(postgres) => postgres.list_usage_retention_runs(tenant_id, limit).await,
            None => self.list_usage_retention_runs(tenant_id, limit),
        }
    }

    pub async fn usage_quota_policy_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageQuotaPolicy>> {
        match &self.postgres {
            Some(postgres) => postgres.usage_quota_policy(tenant_id).await,
            None => self.usage_quota_policy(tenant_id),
        }
    }

    pub async fn set_usage_quota_policy_async(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageQuotaPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_usage_quota_policy(tenant_id, actor_id, policy)
                    .await
            }
            None => self.set_usage_quota_policy(tenant_id, actor_id, policy),
        }
    }

    pub async fn set_workspace_usage_quota_policy_async(
        &self,
        workspace_id: &str,
        principal_id: &str,
        policy: Option<UsageQuotaPolicy>,
    ) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => {
                postgres
                    .set_workspace_usage_quota_policy(workspace_id, principal_id, policy)
                    .await
            }
            None => self.set_workspace_usage_quota_policy(workspace_id, principal_id, policy),
        }
    }

    pub async fn usage_quota_status_async(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageQuotaStatus>> {
        let Some(policy) = self.usage_quota_policy_async(tenant_id).await? else {
            return Ok(None);
        };
        let (from_unix, until_unix) = current_utc_month_range(now_unix())?;
        let report = self
            .usage_report_async(tenant_id, from_unix, until_unix)
            .await?;
        Ok(Some(evaluate_usage_quota(policy, &report)?))
    }

    pub async fn authenticate_bearer_async(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<TenantIdentity>> {
        match &self.postgres {
            Some(postgres) => postgres.authenticate_bearer(presented_header).await,
            None => self.authenticate_bearer(presented_header),
        }
    }

    /// Authenticate a tenant token and load its enforcement policy. PostgreSQL
    /// performs this in one query; SQLite keeps the same public semantics for
    /// local development.
    pub async fn authenticate_access_async(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<TenantAccess>> {
        match &self.postgres {
            Some(postgres) => postgres.authenticate_access(presented_header).await,
            None => {
                let Some(identity) = self.authenticate_bearer(presented_header)? else {
                    return Ok(None);
                };
                Ok(Some(TenantAccess {
                    limits: self.limits_for(&identity.tenant_id)?,
                    model_policy: self.model_policy_for(&identity.tenant_id)?,
                    identity,
                }))
            }
        }
    }

    /// Verify the shared control plane before serving a readiness probe.
    pub async fn health_check_async(&self) -> anyhow::Result<()> {
        match &self.postgres {
            Some(postgres) => postgres.health_check().await,
            None => self
                .connection()?
                .query_row("SELECT 1", [], |_| Ok(()))
                .context("SQLite tenant-store health check failed"),
        }
    }

    pub fn create_tenant(&self, name: &str) -> anyhow::Result<Tenant> {
        self.create_tenant_in_organization(BOOTSTRAP_ORGANIZATION_ID, name)
    }

    pub fn create_tenant_in_organization(
        &self,
        organization_id: &str,
        name: &str,
    ) -> anyhow::Result<Tenant> {
        let name = validate_label(name, "tenant name", 128)?;
        let tenant = Tenant {
            id: random_id("tenant"),
            name,
            active: true,
            created_at_unix: now_unix(),
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin tenant and workspace creation")?;
        let organization_active = transaction
            .query_row(
                "SELECT active FROM organizations WHERE id = ?1",
                [organization_id],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()
            .context("failed to load tenant organization")?;
        match organization_active {
            Some(true) => {}
            Some(false) => bail!("cannot create a tenant in an inactive organization"),
            None => bail!("organization not found"),
        }
        transaction
            .execute(
                "INSERT INTO tenants (id, name, active, created_at_unix) VALUES (?1, ?2, 1, ?3)",
                params![&tenant.id, &tenant.name, tenant.created_at_unix],
            )
            .context("failed to create tenant")?;
        transaction
            .execute(
                "INSERT INTO workspaces
                    (id, organization_id, tenant_id, name, active, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    workspace_id_for_tenant(&tenant.id),
                    organization_id,
                    &tenant.id,
                    &tenant.name,
                    tenant.created_at_unix,
                ],
            )
            .context("failed to create tenant workspace")?;
        transaction
            .commit()
            .context("failed to commit tenant and workspace creation")?;
        Ok(tenant)
    }

    pub fn create_organization(&self, name: &str) -> anyhow::Result<Organization> {
        let organization = Organization {
            id: random_id("org"),
            name: validate_label(name, "organization name", 128)?,
            active: true,
            created_at_unix: now_unix(),
        };
        self.connection()?
            .execute(
                "INSERT INTO organizations (id, name, active, created_at_unix)
                 VALUES (?1, ?2, 1, ?3)",
                params![
                    &organization.id,
                    &organization.name,
                    organization.created_at_unix,
                ],
            )
            .context("failed to create organization")?;
        Ok(organization)
    }

    pub fn list_organizations(&self) -> anyhow::Result<Vec<Organization>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, active, created_at_unix
                 FROM organizations ORDER BY created_at_unix ASC, id ASC",
            )
            .context("failed to prepare organization list")?;
        let organizations = statement
            .query_map([], organization_from_sqlite_row)
            .context("failed to query organizations")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read organizations")?;
        Ok(organizations)
    }

    pub fn issue_scim_token(
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
        let connection = self.connection()?;
        let inserted = connection
            .execute(
                "INSERT INTO scim_tokens
                    (id, organization_id, token_hash, label, active, expires_at_unix,
                     created_at_unix, revoked_at_unix)
                 SELECT ?1, organizations.id, ?3, ?4, 1, ?5, ?6, NULL
                 FROM organizations
                 WHERE organizations.id = ?2 AND organizations.active = 1",
                params![
                    &credential.id,
                    &credential.organization_id,
                    scim_token_hash(&token)?,
                    &credential.label,
                    credential.expires_at_unix,
                    credential.created_at_unix,
                ],
            )
            .context("failed to issue SCIM token")?;
        if inserted != 1 {
            bail!("organization not found or inactive");
        }
        Ok(IssuedScimToken { credential, token })
    }

    pub fn list_scim_tokens(&self, organization_id: &str) -> anyhow::Result<Vec<ScimToken>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, organization_id, label, active, expires_at_unix, created_at_unix,
                        revoked_at_unix
                 FROM scim_tokens
                 WHERE organization_id = ?1
                 ORDER BY created_at_unix DESC, id DESC",
            )
            .context("failed to prepare SCIM token list")?;
        let tokens = statement
            .query_map([organization_id], scim_token_from_sqlite_row)
            .context("failed to query SCIM token list")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read SCIM token list")?;
        Ok(tokens)
    }

    pub fn revoke_scim_token(&self, token_id: &str) -> anyhow::Result<bool> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE scim_tokens
                 SET active = 0, revoked_at_unix = ?1
                 WHERE id = ?2 AND active = 1",
                params![now_unix(), token_id],
            )
            .context("failed to revoke SCIM token")?;
        Ok(changed == 1)
    }

    pub fn authenticate_scim_bearer(
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
        self.connection()?
            .query_row(
                "SELECT scim_tokens.organization_id, scim_tokens.id
                 FROM scim_tokens
                 JOIN organizations ON organizations.id = scim_tokens.organization_id
                 WHERE scim_tokens.token_hash = ?1
                   AND scim_tokens.active = 1
                   AND scim_tokens.expires_at_unix >= ?2
                   AND organizations.active = 1",
                params![token_hash, now],
                |row| {
                    Ok(ScimIdentity {
                        organization_id: row.get(0)?,
                        token_id: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to authenticate SCIM token")
    }

    pub fn create_scim_user(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        user_name: &str,
        display_name: &str,
        active: bool,
    ) -> anyhow::Result<ScimUser> {
        let (external_id, user_name, display_name) =
            validate_scim_user_fields(external_id, user_name, display_name)?;
        let now = now_unix();
        let user = ScimUser {
            id: random_id("principal"),
            organization_id: identity.organization_id.clone(),
            external_id,
            user_name,
            display_name,
            active,
            created_at_unix: now,
            updated_at_unix: now,
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin SCIM user creation")?;
        let organization_active = transaction
            .query_row(
                "SELECT active FROM organizations WHERE id = ?1",
                [&identity.organization_id],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()
            .context("failed to load SCIM organization")?;
        match organization_active {
            Some(true) => {}
            Some(false) => bail!("SCIM organization is inactive"),
            None => bail!("SCIM organization not found"),
        }
        // Keep the shared principal technically active so an administrator can
        // assign it after a later SCIM reactivation. `scim_users.active` and
        // the membership predicates below remain the organization-specific
        // authorization boundary.
        transaction
            .execute(
                "INSERT INTO workspace_principals (id, name, active, created_at_unix)
                 VALUES (?1, ?2, 1, ?3)",
                params![&user.id, &user.display_name, user.created_at_unix],
            )
            .context("failed to create SCIM workspace principal")?;
        transaction
            .execute(
                "INSERT INTO scim_users
                    (id, organization_id, external_id, user_name, display_name, active,
                     created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![
                    &user.id,
                    &user.organization_id,
                    &user.external_id,
                    &user.user_name,
                    &user.display_name,
                    i64::from(user.active),
                    user.created_at_unix,
                ],
            )
            .context("failed to save SCIM user")?;
        transaction
            .execute(
                "INSERT INTO scim_audit
                    (organization_id, scim_token_id, action, target_principal_id, created_at_unix)
                 VALUES (?1, ?2, 'user.create', ?3, ?4)",
                params![
                    &user.organization_id,
                    &identity.token_id,
                    &user.id,
                    user.created_at_unix,
                ],
            )
            .context("failed to append SCIM user audit event")?;
        transaction
            .commit()
            .context("failed to commit SCIM user creation")?;
        Ok(user)
    }

    pub fn list_scim_users(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimUserPage> {
        validate_scim_page(start_index, count)?;
        let offset = i64::try_from(start_index - 1)
            .context("SCIM start index exceeds SQLite integer range")?;
        let limit = i64::try_from(count).context("SCIM page size exceeds SQLite integer range")?;
        let connection = self.connection()?;
        let total_results: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM scim_users WHERE organization_id = ?1",
                [&identity.organization_id],
                |row| row.get(0),
            )
            .context("failed to count SCIM users")?;
        let mut statement = connection
            .prepare(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = ?1
                 ORDER BY id ASC
                 LIMIT ?2 OFFSET ?3",
            )
            .context("failed to prepare SCIM user list")?;
        let resources = statement
            .query_map(
                params![&identity.organization_id, limit, offset],
                scim_user_from_sqlite_row,
            )
            .context("failed to query SCIM users")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read SCIM users")?;
        Ok(ScimUserPage {
            total_results: u64::try_from(total_results)
                .context("stored SCIM user count cannot be negative")?,
            start_index,
            items_per_page: resources.len(),
            resources,
        })
    }

    pub fn scim_user_by_id(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
    ) -> anyhow::Result<Option<ScimUser>> {
        let user_id = validate_scim_user_id(user_id)?;
        self.connection()?
            .query_row(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = ?1 AND id = ?2",
                params![&identity.organization_id, &user_id],
                scim_user_from_sqlite_row,
            )
            .optional()
            .context("failed to load SCIM user")
    }

    pub fn update_scim_user(
        &self,
        identity: &ScimIdentity,
        user_id: &str,
        update: ScimUserUpdate,
    ) -> anyhow::Result<Option<ScimUser>> {
        let user_id = validate_scim_user_id(user_id)?;
        let update = validate_scim_user_update(update)?;
        let now = now_unix();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin SCIM user update")?;
        let current = transaction
            .query_row(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = ?1 AND id = ?2",
                params![&identity.organization_id, &user_id],
                scim_user_from_sqlite_row,
            )
            .optional()
            .context("failed to load SCIM user for update")?;
        let Some(current) = current else {
            return Ok(None);
        };
        let next_user_name = update.user_name.unwrap_or(current.user_name);
        let next_display_name = update
            .display_name
            .unwrap_or_else(|| current.display_name.clone());
        let next_active = update.active.unwrap_or(current.active);
        transaction
            .execute(
                "UPDATE scim_users
                 SET user_name = ?1, display_name = ?2, active = ?3, updated_at_unix = ?4
                 WHERE id = ?5 AND organization_id = ?6",
                params![
                    &next_user_name,
                    &next_display_name,
                    i64::from(next_active),
                    now,
                    &user_id,
                    &identity.organization_id,
                ],
            )
            .context("failed to update SCIM user")?;
        transaction
            .execute(
                "UPDATE workspace_principals SET name = ?1 WHERE id = ?2",
                params![&next_display_name, &user_id],
            )
            .context("failed to update SCIM principal display name")?;
        if !next_active {
            // Deprovisioning is organization-scoped and immediate: existing
            // memberships are suspended atomically, and reactivation never
            // restores them. An owner must grant access again explicitly.
            transaction
                .execute(
                    "UPDATE workspace_memberships
                     SET active = 0, updated_at_unix = ?1
                     WHERE principal_id = ?2
                       AND workspace_id IN (
                           SELECT id FROM workspaces WHERE organization_id = ?3
                       )",
                    params![now, &user_id, &identity.organization_id],
                )
                .context("failed to suspend SCIM user workspace memberships")?;
        }
        let action = if current.active && !next_active {
            "user.deactivate"
        } else {
            "user.update"
        };
        transaction
            .execute(
                "INSERT INTO scim_audit
                    (organization_id, scim_token_id, action, target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &identity.organization_id,
                    &identity.token_id,
                    action,
                    &user_id,
                    now,
                ],
            )
            .context("failed to append SCIM user audit event")?;
        let updated = transaction
            .query_row(
                "SELECT id, organization_id, external_id, user_name, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_users
                 WHERE organization_id = ?1 AND id = ?2",
                params![&identity.organization_id, &user_id],
                scim_user_from_sqlite_row,
            )
            .context("failed to read updated SCIM user")?;
        transaction
            .commit()
            .context("failed to commit SCIM user update")?;
        Ok(Some(updated))
    }

    pub fn create_scim_group(
        &self,
        identity: &ScimIdentity,
        external_id: &str,
        display_name: &str,
        member_ids: Vec<String>,
    ) -> anyhow::Result<ScimGroup> {
        let (external_id, display_name) = validate_scim_group_fields(external_id, display_name)?;
        let member_ids = validate_scim_group_member_ids(member_ids)?;
        let now = now_unix();
        let group = ScimGroup {
            id: random_id("scim_group"),
            organization_id: identity.organization_id.clone(),
            external_id,
            display_name,
            active: true,
            created_at_unix: now,
            updated_at_unix: now,
            member_ids: Vec::new(),
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin SCIM group creation")?;
        let organization_active = transaction
            .query_row(
                "SELECT active FROM organizations WHERE id = ?1",
                [&identity.organization_id],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()
            .context("failed to load SCIM group organization")?;
        match organization_active {
            Some(true) => {}
            Some(false) => bail!("SCIM organization is inactive"),
            None => bail!("SCIM organization not found"),
        }
        require_active_scim_group_members_sqlite(
            &transaction,
            &identity.organization_id,
            &member_ids,
        )?;
        transaction
            .execute(
                "INSERT INTO scim_groups
                    (id, organization_id, external_id, display_name, active,
                     created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                params![
                    &group.id,
                    &group.organization_id,
                    &group.external_id,
                    &group.display_name,
                    group.created_at_unix,
                ],
            )
            .context("failed to save SCIM group")?;
        for principal_id in &member_ids {
            transaction
                .execute(
                    "INSERT INTO scim_group_members (group_id, principal_id, created_at_unix)
                     VALUES (?1, ?2, ?3)",
                    params![&group.id, principal_id, now],
                )
                .context("failed to add SCIM group member")?;
        }
        transaction
            .execute(
                "INSERT INTO scim_group_audit
                    (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                 VALUES (?1, ?2, 'group.create', ?3, ?4)",
                params![
                    &group.organization_id,
                    &identity.token_id,
                    &group.id,
                    group.created_at_unix,
                ],
            )
            .context("failed to append SCIM group audit event")?;
        let mut group = group;
        group.member_ids = scim_group_members_from_sqlite_connection(&transaction, &group.id)?;
        transaction
            .commit()
            .context("failed to commit SCIM group creation")?;
        Ok(group)
    }

    pub fn list_scim_groups(
        &self,
        identity: &ScimIdentity,
        start_index: usize,
        count: usize,
    ) -> anyhow::Result<ScimGroupPage> {
        validate_scim_page(start_index, count)?;
        let offset = i64::try_from(start_index - 1)
            .context("SCIM start index exceeds SQLite integer range")?;
        let limit = i64::try_from(count).context("SCIM page size exceeds SQLite integer range")?;
        let connection = self.connection()?;
        let total_results: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM scim_groups WHERE organization_id = ?1 AND active = 1",
                [&identity.organization_id],
                |row| row.get(0),
            )
            .context("failed to count SCIM groups")?;
        let mut statement = connection
            .prepare(
                "SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_groups
                 WHERE organization_id = ?1 AND active = 1
                 ORDER BY id ASC
                 LIMIT ?2 OFFSET ?3",
            )
            .context("failed to prepare SCIM group list")?;
        let mut resources = statement
            .query_map(
                params![&identity.organization_id, limit, offset],
                scim_group_from_sqlite_row,
            )
            .context("failed to query SCIM groups")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read SCIM groups")?;
        for group in &mut resources {
            group.member_ids = scim_group_members_from_sqlite_connection(&connection, &group.id)?;
        }
        Ok(ScimGroupPage {
            total_results: u64::try_from(total_results)
                .context("stored SCIM group count cannot be negative")?,
            start_index,
            items_per_page: resources.len(),
            resources,
        })
    }

    pub fn scim_group_by_id(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<Option<ScimGroup>> {
        let group_id = validate_scim_group_id(group_id)?;
        let connection = self.connection()?;
        let group = connection
            .query_row(
                "SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_groups
                 WHERE organization_id = ?1 AND id = ?2 AND active = 1",
                params![&identity.organization_id, &group_id],
                scim_group_from_sqlite_row,
            )
            .optional()
            .context("failed to load SCIM group")?;
        group
            .map(|mut group| {
                group.member_ids =
                    scim_group_members_from_sqlite_connection(&connection, &group.id)?;
                Ok(group)
            })
            .transpose()
    }

    pub fn update_scim_group(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
        update: ScimGroupUpdate,
    ) -> anyhow::Result<Option<ScimGroup>> {
        let group_id = validate_scim_group_id(group_id)?;
        let update = validate_scim_group_update(update)?;
        let now = now_unix();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin SCIM group update")?;
        let current = transaction
            .query_row(
                "SELECT id, organization_id, external_id, display_name, active,
                        created_at_unix, updated_at_unix
                 FROM scim_groups
                 WHERE organization_id = ?1 AND id = ?2 AND active = 1",
                params![&identity.organization_id, &group_id],
                scim_group_from_sqlite_row,
            )
            .optional()
            .context("failed to load SCIM group for update")?;
        let Some(current) = current else {
            return Ok(None);
        };
        let next_display_name = update.display_name.unwrap_or(current.display_name);
        let action = match &update.member_change {
            Some(ScimGroupMemberChange::Replace(_)) => "group.members.replace",
            Some(ScimGroupMemberChange::Add(_)) => "group.members.add",
            Some(ScimGroupMemberChange::Remove(_)) => "group.members.remove",
            None => "group.update",
        };
        if let Some(member_change) = &update.member_change {
            let member_ids = match member_change {
                ScimGroupMemberChange::Replace(member_ids)
                | ScimGroupMemberChange::Add(member_ids)
                | ScimGroupMemberChange::Remove(member_ids) => member_ids,
            };
            if !matches!(member_change, ScimGroupMemberChange::Remove(_)) {
                require_active_scim_group_members_sqlite(
                    &transaction,
                    &identity.organization_id,
                    member_ids,
                )?;
            }
            match member_change {
                ScimGroupMemberChange::Replace(_) => {
                    transaction
                        .execute(
                            "DELETE FROM scim_group_members WHERE group_id = ?1",
                            [&group_id],
                        )
                        .context("failed to replace SCIM group members")?;
                }
                ScimGroupMemberChange::Add(_) | ScimGroupMemberChange::Remove(_) => {}
            }
            if matches!(member_change, ScimGroupMemberChange::Remove(_)) {
                for principal_id in member_ids {
                    transaction
                        .execute(
                            "DELETE FROM scim_group_members WHERE group_id = ?1 AND principal_id = ?2",
                            params![&group_id, principal_id],
                        )
                        .context("failed to remove SCIM group member")?;
                }
            } else {
                for principal_id in member_ids {
                    transaction
                        .execute(
                            "INSERT OR IGNORE INTO scim_group_members
                                (group_id, principal_id, created_at_unix)
                             VALUES (?1, ?2, ?3)",
                            params![&group_id, principal_id, now],
                        )
                        .context("failed to add SCIM group member")?;
                }
            }
        }
        transaction
            .execute(
                "UPDATE scim_groups
                 SET display_name = ?1, updated_at_unix = ?2
                 WHERE id = ?3 AND organization_id = ?4 AND active = 1",
                params![
                    &next_display_name,
                    now,
                    &group_id,
                    &identity.organization_id,
                ],
            )
            .context("failed to update SCIM group")?;
        transaction
            .execute(
                "INSERT INTO scim_group_audit
                    (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &identity.organization_id,
                    &identity.token_id,
                    action,
                    &group_id,
                    now,
                ],
            )
            .context("failed to append SCIM group audit event")?;
        let mut updated = ScimGroup {
            display_name: next_display_name,
            updated_at_unix: now,
            ..current
        };
        updated.member_ids = scim_group_members_from_sqlite_connection(&transaction, &group_id)?;
        transaction
            .commit()
            .context("failed to commit SCIM group update")?;
        Ok(Some(updated))
    }

    pub fn delete_scim_group(
        &self,
        identity: &ScimIdentity,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = validate_scim_group_id(group_id)?;
        let now = now_unix();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin SCIM group deletion")?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM scim_groups
                 WHERE organization_id = ?1 AND id = ?2 AND active = 1",
                params![&identity.organization_id, &group_id],
                |_| Ok(()),
            )
            .optional()
            .context("failed to load SCIM group for deletion")?
            .is_some();
        if !exists {
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO scim_group_audit
                    (organization_id, scim_token_id, action, target_group_id, created_at_unix)
                 VALUES (?1, ?2, 'group.delete', ?3, ?4)",
                params![
                    &identity.organization_id,
                    &identity.token_id,
                    &group_id,
                    now
                ],
            )
            .context("failed to append SCIM group deletion audit event")?;
        transaction
            .execute("DELETE FROM scim_groups WHERE id = ?1", [&group_id])
            .context("failed to delete SCIM group")?;
        transaction
            .commit()
            .context("failed to commit SCIM group deletion")?;
        Ok(true)
    }

    pub fn set_organization_active(
        &self,
        organization_id: &str,
        active: bool,
    ) -> anyhow::Result<bool> {
        if organization_id == BOOTSTRAP_ORGANIZATION_ID && !active {
            bail!("the bootstrap organization cannot be suspended");
        }
        let changed = self
            .connection()?
            .execute(
                "UPDATE organizations SET active = ?1 WHERE id = ?2",
                params![i64::from(active), organization_id],
            )
            .context("failed to update organization state")?;
        Ok(changed == 1)
    }

    pub fn list_organization_workspaces(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Vec<Workspace>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, organization_id, tenant_id, name, active, created_at_unix
                 FROM workspaces
                 WHERE organization_id = ?1
                 ORDER BY created_at_unix ASC, id ASC",
            )
            .context("failed to prepare workspace list")?;
        let workspaces = statement
            .query_map([organization_id], workspace_from_sqlite_row)
            .context("failed to query organization workspaces")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read organization workspaces")?;
        Ok(workspaces)
    }

    /// Return whether an active workspace belongs to an active organization.
    /// Both identifiers are treated as opaque values from an authenticated
    /// control-plane request or encrypted OIDC state.
    pub fn active_workspace_in_organization(
        &self,
        organization_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<bool> {
        let found: Option<i64> = self
            .connection()?
            .query_row(
                "SELECT 1
                 FROM workspaces
                 INNER JOIN organizations ON organizations.id = workspaces.organization_id
                 WHERE workspaces.id = ?1
                   AND workspaces.organization_id = ?2
                   AND workspaces.active = 1
                   AND organizations.active = 1",
                params![workspace_id, organization_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to verify workspace organization")?;
        Ok(found.is_some())
    }

    pub fn list_tenants(&self) -> anyhow::Result<Vec<Tenant>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, active, created_at_unix
                 FROM tenants ORDER BY created_at_unix ASC, id ASC",
            )
            .context("failed to prepare tenant list")?;
        let tenants = statement
            .query_map([], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    active: row.get::<_, i64>(2)? != 0,
                    created_at_unix: row.get(3)?,
                })
            })
            .context("failed to query tenants")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read tenants")?;
        Ok(tenants)
    }

    pub fn workspace_for_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Workspace>> {
        self.connection()?
            .query_row(
                "SELECT id, organization_id, tenant_id, name, active, created_at_unix
                 FROM workspaces WHERE tenant_id = ?1",
                [tenant_id],
                workspace_from_sqlite_row,
            )
            .optional()
            .context("failed to load tenant workspace")
    }

    pub fn active_workspace_by_id(&self, workspace_id: &str) -> anyhow::Result<Option<Workspace>> {
        self.connection()?
            .query_row(
                "SELECT workspaces.id, workspaces.organization_id, workspaces.tenant_id,
                        workspaces.name, workspaces.active, workspaces.created_at_unix
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1",
                [workspace_id],
                workspace_from_sqlite_row,
            )
            .optional()
            .context("failed to load active workspace")
    }

    pub fn set_organization_oidc_connection(
        &self,
        organization_id: &str,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationOidcConnection> {
        let issuer = validate_oidc_https_uri(issuer, "OIDC issuer")?;
        let client_id = validate_external_identity_component(client_id, "OIDC client id", 512)?;
        let redirect_uri = validate_oidc_https_uri(redirect_uri, "OIDC redirect URI")?;
        let now = now_unix();
        {
            let connection = self.connection()?;
            let organization_active: Option<bool> = connection
                .query_row(
                    "SELECT active FROM organizations WHERE id = ?1",
                    [organization_id],
                    |row| Ok(row.get::<_, i64>(0)? != 0),
                )
                .optional()
                .context("failed to validate organization for OIDC connection")?;
            match organization_active {
                Some(true) => {}
                Some(false) => bail!("cannot configure OIDC for an inactive organization"),
                None => bail!("organization not found"),
            }
            connection
                .execute(
                    "INSERT INTO organization_oidc_connections
                        (organization_id, issuer, client_id, redirect_uri, active,
                         created_at_unix, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(organization_id) DO UPDATE SET
                        issuer = excluded.issuer,
                        client_id = excluded.client_id,
                        redirect_uri = excluded.redirect_uri,
                        active = excluded.active,
                        updated_at_unix = excluded.updated_at_unix",
                    params![
                        organization_id,
                        issuer,
                        client_id,
                        redirect_uri,
                        active as i64,
                        now
                    ],
                )
                .context("failed to save organization OIDC connection")?;
        }
        self.organization_oidc_connection(organization_id)?
            .ok_or_else(|| anyhow::anyhow!("OIDC connection disappeared after save"))
    }

    pub fn organization_oidc_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationOidcConnection>> {
        self.connection()?
            .query_row(
                "SELECT organization_id, issuer, client_id, redirect_uri, active,
                        created_at_unix, updated_at_unix
                 FROM organization_oidc_connections WHERE organization_id = ?1",
                [organization_id],
                organization_oidc_connection_from_sqlite_row,
            )
            .optional()
            .context("failed to load organization OIDC connection")
    }

    pub fn delete_organization_oidc_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .connection()?
            .execute(
                "DELETE FROM organization_oidc_connections WHERE organization_id = ?1",
                [organization_id],
            )
            .context("failed to delete organization OIDC connection")?
            == 1)
    }

    pub fn set_organization_saml_connection(
        &self,
        organization_id: &str,
        entity_id: &str,
        metadata_xml: &str,
        metadata_signing_cert_pem: &str,
        active: bool,
    ) -> anyhow::Result<OrganizationSamlConnection> {
        let entity_id = validate_saml_entity_id(entity_id)?;
        let metadata_xml = validate_saml_metadata(metadata_xml)?;
        let metadata_signing_cert_pem = validate_saml_certificate(metadata_signing_cert_pem)?;
        let now = now_unix();
        {
            let connection = self.connection()?;
            let organization_active: Option<bool> = connection
                .query_row(
                    "SELECT active FROM organizations WHERE id = ?1",
                    [organization_id],
                    |row| Ok(row.get::<_, i64>(0)? != 0),
                )
                .optional()
                .context("failed to validate organization for SAML connection")?;
            match organization_active {
                Some(true) => {}
                Some(false) => bail!("cannot configure SAML for an inactive organization"),
                None => bail!("organization not found"),
            }
            connection
                .execute(
                    "INSERT INTO organization_saml_connections
                        (organization_id, entity_id, metadata_xml,
                         metadata_signing_cert_pem, active, created_at_unix, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(organization_id) DO UPDATE SET
                        entity_id = excluded.entity_id,
                        metadata_xml = excluded.metadata_xml,
                        metadata_signing_cert_pem = excluded.metadata_signing_cert_pem,
                        active = excluded.active,
                        updated_at_unix = excluded.updated_at_unix",
                    params![
                        organization_id,
                        entity_id,
                        metadata_xml,
                        metadata_signing_cert_pem,
                        active as i64,
                        now
                    ],
                )
                .context("failed to save organization SAML connection")?;
        }
        self.organization_saml_connection(organization_id)?
            .ok_or_else(|| anyhow::anyhow!("SAML connection disappeared after save"))
    }

    pub fn organization_saml_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<Option<OrganizationSamlConnection>> {
        self.connection()?
            .query_row(
                "SELECT organization_id, entity_id, metadata_xml,
                        metadata_signing_cert_pem, active, created_at_unix, updated_at_unix
                 FROM organization_saml_connections WHERE organization_id = ?1",
                [organization_id],
                organization_saml_connection_from_sqlite_row,
            )
            .optional()
            .context("failed to load organization SAML connection")
    }

    pub fn delete_organization_saml_connection(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .connection()?
            .execute(
                "DELETE FROM organization_saml_connections WHERE organization_id = ?1",
                [organization_id],
            )
            .context("failed to delete organization SAML connection")?
            == 1)
    }

    pub fn reserve_oidc_authorization_state(
        &self,
        state: &str,
        organization_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        validate_oidc_authorization_state_expiry(expires_at_unix)?;
        let state_hash = oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let connection = self.connection()?;
        connection
            .execute(
                "DELETE FROM oidc_authorization_states
                 WHERE state_hash IN (
                     SELECT state_hash FROM oidc_authorization_states
                     WHERE expires_at_unix < ?1
                     ORDER BY expires_at_unix ASC LIMIT 100
                 )",
                [now],
            )
            .context("failed to prune expired OIDC authorization states")?;
        let inserted = connection
            .execute(
                "INSERT INTO oidc_authorization_states
                    (state_hash, organization_id, expires_at_unix, consumed_at_unix, created_at_unix)
                 SELECT ?1, organizations.id, ?3, NULL, ?4
                 FROM organizations
                 JOIN organization_oidc_connections
                   ON organization_oidc_connections.organization_id = organizations.id
                 WHERE organizations.id = ?2
                   AND organizations.active = 1
                   AND organization_oidc_connections.active = 1",
                params![state_hash, organization_id, expires_at_unix, now],
            )
            .context("failed to reserve OIDC authorization state")?;
        if inserted != 1 {
            bail!("organization not found, inactive, or has no active OIDC connection");
        }
        Ok(())
    }

    pub fn consume_oidc_authorization_state(
        &self,
        state: &str,
        organization_id: &str,
    ) -> anyhow::Result<bool> {
        let state_hash = oidc_authorization_state_hash(state)?;
        let now = now_unix();
        Ok(self
            .connection()?
            .execute(
                "UPDATE oidc_authorization_states
                 SET consumed_at_unix = ?3
                 WHERE state_hash = ?1
                   AND organization_id = ?2
                   AND consumed_at_unix IS NULL
                   AND expires_at_unix >= ?3",
                params![state_hash, organization_id, now],
            )
            .context("failed to consume OIDC authorization state")?
            == 1)
    }

    pub fn reserve_saml_authorization_state(
        &self,
        state: &str,
        pending: &SamlAuthorizationPending,
        expires_at_unix: i64,
    ) -> anyhow::Result<()> {
        validate_oidc_authorization_state_expiry(expires_at_unix)?;
        let state_hash = oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let connection = self.connection()?;
        connection
            .execute(
                "DELETE FROM saml_authorization_states
                 WHERE state_hash IN (
                     SELECT state_hash FROM saml_authorization_states
                     WHERE expires_at_unix < ?1
                     ORDER BY expires_at_unix ASC LIMIT 100
                 )",
                [now],
            )
            .context("failed to prune expired SAML authorization states")?;
        let inserted = connection
            .execute(
                "INSERT INTO saml_authorization_states
                    (state_hash, organization_id, workspace_id, invitation_id, request_id, idp_entity_id,
                     expected_binding, request_binding, acs_url, acs_binding,
                     expires_at_unix, consumed_at_unix, created_at_unix)
                 SELECT ?1, organizations.id, workspaces.id, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12
                 FROM organizations
                 JOIN workspaces ON workspaces.organization_id = organizations.id
                 JOIN organization_saml_connections
                   ON organization_saml_connections.organization_id = organizations.id
                 WHERE organizations.id = ?2
                   AND workspaces.id = ?3
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND organization_saml_connections.active = 1",
                params![
                    state_hash,
                    pending.organization_id,
                    pending.workspace_id,
                    pending.invitation_id,
                    pending.request_id,
                    pending.idp_entity_id,
                    pending.expected_binding,
                    pending.request_binding,
                    pending.acs_url,
                    pending.acs_binding,
                    expires_at_unix,
                    now,
                ],
            )
            .context("failed to reserve SAML authorization state")?;
        if inserted != 1 {
            bail!("organization or workspace is inactive, or SAML is not configured");
        }
        Ok(())
    }

    pub fn consume_saml_authorization_state(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<SamlAuthorizationPending>> {
        let state_hash = oidc_authorization_state_hash(state)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let pending = transaction
            .query_row(
                "SELECT organization_id, workspace_id, invitation_id, request_id, idp_entity_id,
                        expected_binding, request_binding, acs_url, acs_binding
                 FROM saml_authorization_states
                 WHERE state_hash = ?1 AND consumed_at_unix IS NULL AND expires_at_unix >= ?2",
                params![state_hash, now],
                |row| {
                    Ok(SamlAuthorizationPending {
                        organization_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        invitation_id: row.get(2)?,
                        request_id: row.get(3)?,
                        idp_entity_id: row.get(4)?,
                        expected_binding: row.get(5)?,
                        request_binding: row.get(6)?,
                        acs_url: row.get(7)?,
                        acs_binding: row.get(8)?,
                    })
                },
            )
            .optional()
            .context("failed to load SAML authorization state")?;
        if pending.is_some() {
            let consumed = transaction.execute(
                "UPDATE saml_authorization_states
                     SET consumed_at_unix = ?2
                     WHERE state_hash = ?1 AND consumed_at_unix IS NULL
                       AND expires_at_unix >= ?2",
                params![state_hash, now],
            )?;
            if consumed != 1 {
                transaction.rollback()?;
                return Ok(None);
            }
        }
        transaction.commit()?;
        Ok(pending)
    }

    pub fn create_workspace_principal(&self, name: &str) -> anyhow::Result<WorkspacePrincipal> {
        let principal = WorkspacePrincipal {
            id: random_id("principal"),
            name: validate_label(name, "principal name", 128)?,
            active: true,
            created_at_unix: now_unix(),
        };
        self.connection()?
            .execute(
                "INSERT INTO workspace_principals (id, name, active, created_at_unix)
                 VALUES (?1, ?2, 1, ?3)",
                params![&principal.id, &principal.name, principal.created_at_unix],
            )
            .context("failed to create workspace principal")?;
        Ok(principal)
    }

    pub fn link_workspace_external_identity(
        &self,
        principal_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<WorkspaceExternalIdentity> {
        let identity = WorkspaceExternalIdentity {
            issuer: validate_external_identity_component(issuer, "identity issuer", 2_048)?,
            subject: validate_external_identity_component(subject, "identity subject", 255)?,
            principal_id: principal_id.to_owned(),
            created_at_unix: now_unix(),
        };
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO workspace_external_identities
                    (issuer, subject, principal_id, created_at_unix)
                 SELECT ?1, ?2, id, ?3 FROM workspace_principals
                 WHERE id = ?4 AND active = 1",
                params![
                    &identity.issuer,
                    &identity.subject,
                    identity.created_at_unix,
                    principal_id,
                ],
            )
            .context("failed to link workspace external identity")?;
        if changed != 1 {
            bail!("workspace principal not found or inactive");
        }
        Ok(identity)
    }

    pub fn workspace_principal_for_external_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<WorkspacePrincipal>> {
        let issuer = validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject = validate_external_identity_component(subject, "identity subject", 255)?;
        self.connection()?
            .query_row(
                "SELECT workspace_principals.id, workspace_principals.name,
                        workspace_principals.active, workspace_principals.created_at_unix
                 FROM workspace_external_identities
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_external_identities.principal_id
                 WHERE workspace_external_identities.issuer = ?1
                   AND workspace_external_identities.subject = ?2
                   AND workspace_principals.active = 1",
                params![issuer, subject],
                workspace_principal_from_sqlite_row,
            )
            .optional()
            .context("failed to look up workspace external identity")
    }

    pub fn verified_identity_workspace_access(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject = validate_external_identity_component(subject, "identity subject", 255)?;
        self.connection()?
            .query_row(
                "SELECT workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = 1),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = 1
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = 1
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
                 WHERE organization_oidc_connections.organization_id = ?1
                   AND workspaces.id = ?2
                   AND organization_oidc_connections.issuer = ?3
                   AND workspace_external_identities.subject = ?4
                   AND organization_oidc_connections.active = 1
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = 1
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = 1
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = 1
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                params![organization_id, workspace_id, issuer, subject],
                |row| {
                    Ok(VerifiedWorkspaceAccess {
                        organization_id: organization_id.to_owned(),
                        workspace_id: workspace_id.to_owned(),
                        principal_id: row.get(0)?,
                        role: WorkspaceRole::from_storage(&row.get::<_, String>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .context("failed to authorize verified OIDC identity for workspace")
    }

    pub fn verified_saml_identity_workspace_access(
        &self,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject = validate_external_identity_component(subject, "identity subject", 255)?;
        self.connection()?
            .query_row(
                "SELECT workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = 1),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = 1
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = 1
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
                 WHERE organization_saml_connections.organization_id = ?1
                   AND workspaces.id = ?2
                   AND organization_saml_connections.entity_id = ?3
                   AND workspace_external_identities.subject = ?4
                   AND organization_saml_connections.active = 1
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = 1
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = 1
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = 1
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                params![organization_id, workspace_id, issuer, subject],
                |row| {
                    Ok(VerifiedWorkspaceAccess {
                        organization_id: organization_id.to_owned(),
                        workspace_id: workspace_id.to_owned(),
                        principal_id: row.get(0)?,
                        role: WorkspaceRole::from_storage(&row.get::<_, String>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .context("failed to authorize verified SAML identity for workspace")
    }

    /// Create a short-lived opaque browser session. The insert re-checks the
    /// complete current authorization seam in one statement to close the gap
    /// between ID-token verification and session creation.
    pub fn issue_oidc_browser_session(
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
        let connection = self.connection()?;
        connection
            .execute(
                "DELETE FROM oidc_browser_sessions
                 WHERE session_hash IN (
                     SELECT session_hash FROM oidc_browser_sessions
                     WHERE expires_at_unix < ?1 OR revoked_at_unix IS NOT NULL
                     ORDER BY expires_at_unix ASC LIMIT 100
                 )",
                [now],
            )
            .context("failed to prune expired OIDC browser sessions")?;
        let inserted = connection
            .execute(
                "INSERT INTO oidc_browser_sessions
                    (session_hash, organization_id, workspace_id, principal_id, federation_kind,
                     expires_at_unix, revoked_at_unix, created_at_unix)
                 SELECT ?1, organizations.id, workspaces.id, workspace_principals.id,
                        ?5, ?6, NULL, ?7
                 FROM organizations
                 JOIN workspaces ON workspaces.organization_id = organizations.id
                 JOIN workspace_principals ON workspace_principals.id = ?4
                 WHERE organizations.id = ?2
                   AND workspaces.id = ?3
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
                   AND (
                     (?5 = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = 1
                     )) OR (?5 = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = 1
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = 1
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = 1
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = 1
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                params![
                    session_hash,
                    &access.organization_id,
                    &access.workspace_id,
                    &access.principal_id,
                    federation.as_storage(),
                    expires_at_unix,
                    now,
                ],
            )
            .context("failed to create OIDC browser session")?;
        if inserted != 1 {
            bail!("verified OIDC identity no longer has active workspace access");
        }
        Ok(issued)
    }

    pub fn rotate_oidc_browser_session(
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin OIDC session rotation")?;
        let current = transaction
            .query_row(
                "SELECT organizations.id, workspaces.id, workspace_principals.id,
                        oidc_browser_sessions.federation_kind,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = 1),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = 1
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = 1
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        )
                 FROM oidc_browser_sessions
                 JOIN organizations ON organizations.id = oidc_browser_sessions.organization_id
                 JOIN workspaces ON workspaces.id = oidc_browser_sessions.workspace_id
                  AND workspaces.organization_id = organizations.id
                 JOIN workspace_principals
                   ON workspace_principals.id = oidc_browser_sessions.principal_id
                 WHERE oidc_browser_sessions.session_hash = ?1
                   AND oidc_browser_sessions.expires_at_unix >= ?2
                   AND oidc_browser_sessions.revoked_at_unix IS NULL
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
                   AND (
                     (oidc_browser_sessions.federation_kind = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = 1
                     )) OR (oidc_browser_sessions.federation_kind = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = 1
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = 1
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = 1
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = 1
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                params![old_hash, now],
                |row| {
                    Ok((
                        VerifiedWorkspaceAccess {
                            organization_id: row.get(0)?,
                            workspace_id: row.get(1)?,
                            principal_id: row.get(2)?,
                            role: WorkspaceRole::from_storage(&row.get::<_, String>(4)?)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        },
                        BrowserSessionFederation::from_storage(&row.get::<_, String>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authenticate OIDC session for rotation")?;
        let Some(current) = current else {
            transaction
                .commit()
                .context("failed to finish empty OIDC session rotation")?;
            return Ok(None);
        };
        let revoked = transaction
            .execute(
                "UPDATE oidc_browser_sessions SET revoked_at_unix = ?2
                 WHERE session_hash = ?1 AND revoked_at_unix IS NULL
                   AND expires_at_unix >= ?3",
                params![old_hash, now, now],
            )
            .context("failed to revoke old OIDC browser session")?;
        if revoked != 1 {
            transaction
                .commit()
                .context("failed to finish concurrent OIDC session rotation")?;
            return Ok(None);
        }
        transaction
            .execute(
                "INSERT INTO oidc_browser_sessions
                    (session_hash, organization_id, workspace_id, principal_id, federation_kind,
                     expires_at_unix, revoked_at_unix, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                params![
                    new_hash,
                    current.0.organization_id,
                    current.0.workspace_id,
                    current.0.principal_id,
                    current.1.as_storage(),
                    expires_at_unix,
                    now,
                ],
            )
            .context("failed to issue replacement OIDC browser session")?;
        transaction
            .commit()
            .context("failed to commit OIDC session rotation")?;
        Ok(Some(issued))
    }

    /// Authenticate an opaque cookie value without placing the raw value in a
    /// lookup key, audit record, or log. The current role is loaded from the
    /// active membership, which makes suspend and RBAC changes immediate.
    pub fn authenticate_oidc_browser_session(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<OidcBrowserSession>> {
        let session_hash = oidc_browser_session_hash(token)?;
        let now = now_unix();
        self.connection()?
            .query_row(
                "SELECT organizations.id, workspaces.id, workspace_principals.id,
                        COALESCE(
                            (SELECT workspace_memberships.role
                             FROM workspace_memberships
                             WHERE workspace_memberships.workspace_id = workspaces.id
                               AND workspace_memberships.principal_id = workspace_principals.id
                               AND workspace_memberships.active = 1),
                            (SELECT 'analyst'
                             FROM workspace_scim_group_mappings
                             JOIN scim_groups
                               ON scim_groups.id = workspace_scim_group_mappings.group_id
                              AND scim_groups.organization_id = organizations.id
                              AND scim_groups.active = 1
                             JOIN scim_group_members
                               ON scim_group_members.group_id = scim_groups.id
                              AND scim_group_members.principal_id = workspace_principals.id
                             JOIN scim_users
                               ON scim_users.id = workspace_principals.id
                              AND scim_users.organization_id = organizations.id
                              AND scim_users.active = 1
                             WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                             LIMIT 1)
                        ), oidc_browser_sessions.expires_at_unix
                 FROM oidc_browser_sessions
                 JOIN organizations ON organizations.id = oidc_browser_sessions.organization_id
                 JOIN workspaces ON workspaces.id = oidc_browser_sessions.workspace_id
                  AND workspaces.organization_id = organizations.id
                 JOIN workspace_principals
                   ON workspace_principals.id = oidc_browser_sessions.principal_id
                 WHERE oidc_browser_sessions.session_hash = ?1
                   AND oidc_browser_sessions.expires_at_unix >= ?2
                   AND oidc_browser_sessions.revoked_at_unix IS NULL
                   AND organizations.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
                   AND (
                     (oidc_browser_sessions.federation_kind = 'oidc' AND EXISTS (
                       SELECT 1 FROM organization_oidc_connections
                       WHERE organization_oidc_connections.organization_id = organizations.id
                         AND organization_oidc_connections.active = 1
                     )) OR (oidc_browser_sessions.federation_kind = 'saml' AND EXISTS (
                       SELECT 1 FROM organization_saml_connections
                       WHERE organization_saml_connections.organization_id = organizations.id
                         AND organization_saml_connections.active = 1
                     ))
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM workspace_memberships
                       WHERE workspace_memberships.workspace_id = workspaces.id
                         AND workspace_memberships.principal_id = workspace_principals.id
                         AND workspace_memberships.active = 1
                     ) OR EXISTS (
                       SELECT 1 FROM workspace_scim_group_mappings
                       JOIN scim_groups
                         ON scim_groups.id = workspace_scim_group_mappings.group_id
                        AND scim_groups.organization_id = organizations.id
                        AND scim_groups.active = 1
                       JOIN scim_group_members
                         ON scim_group_members.group_id = scim_groups.id
                        AND scim_group_members.principal_id = workspace_principals.id
                       JOIN scim_users
                         ON scim_users.id = workspace_principals.id
                        AND scim_users.organization_id = organizations.id
                        AND scim_users.active = 1
                       WHERE workspace_scim_group_mappings.workspace_id = workspaces.id
                     )
                   )",
                params![session_hash, now],
                |row| {
                    Ok(OidcBrowserSession {
                        access: VerifiedWorkspaceAccess {
                            organization_id: row.get(0)?,
                            workspace_id: row.get(1)?,
                            principal_id: row.get(2)?,
                            role: WorkspaceRole::from_storage(&row.get::<_, String>(3)?)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        },
                        expires_at_unix: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("failed to authenticate OIDC browser session")
    }

    pub fn revoke_oidc_browser_session(&self, token: &str) -> anyhow::Result<bool> {
        let session_hash = oidc_browser_session_hash(token)?;
        let revoked = self
            .connection()?
            .execute(
                "UPDATE oidc_browser_sessions
                 SET revoked_at_unix = ?2
                 WHERE session_hash = ?1 AND revoked_at_unix IS NULL",
                params![session_hash, now_unix()],
            )
            .context("failed to revoke OIDC browser session")?;
        Ok(revoked == 1)
    }

    pub fn list_workspace_service_accounts(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceServiceAccount>> {
        let connection = self.connection()?;
        let mut rows = connection
            .prepare(
                "SELECT workspace_service_accounts.id, workspace_service_accounts.workspace_id,
                        workspace_service_accounts.name,
                        workspace_service_accounts.created_by_principal_id,
                        workspace_service_accounts.active,
                        workspace_service_accounts.expires_at_unix,
                        workspace_service_accounts.created_at_unix,
                        workspace_service_accounts.revoked_at_unix
                 FROM workspace_service_accounts
                 JOIN workspaces ON workspaces.id = workspace_service_accounts.workspace_id
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals actor ON actor.id = ?2
                 JOIN workspace_memberships membership
                   ON membership.workspace_id = workspaces.id
                  AND membership.principal_id = actor.id
                  AND membership.active = 1
                 WHERE workspace_service_accounts.workspace_id = ?1
                   AND workspaces.active = 1 AND organizations.active = 1
                   AND tenants.active = 1 AND actor.active = 1
                   AND (membership.role IN ('owner', 'admin')
                        OR workspace_service_accounts.created_by_principal_id = ?2)
                 ORDER BY workspace_service_accounts.created_at_unix ASC,
                          workspace_service_accounts.id ASC",
            )
            .context("failed to prepare workspace service-account listing")?;
        let rows = rows
            .query_map([workspace_id, actor_principal_id], service_account_from_row)
            .context("failed to list workspace service accounts")?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn create_workspace_service_account(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        name: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceServiceAccount> {
        validate_service_account_expiry(expires_at_unix)?;
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
        let token = generate_service_account_token();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin service-account creation")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1 AND workspaces.active = 1
                   AND organizations.active = 1 AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, actor_principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize service-account creation")?
            .filter(|(_, role)| {
                role.permits(WorkspacePermission::ManageServiceTokens)
                    || role.permits(WorkspacePermission::ManageOwnServiceTokens)
            })
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        transaction
            .execute(
                "INSERT INTO workspace_service_accounts
                    (id, workspace_id, name, created_by_principal_id, token_hash,
                     active, expires_at_unix, created_at_unix, revoked_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL)",
                params![
                    &account.id,
                    &account.workspace_id,
                    &account.name,
                    &account.created_by_principal_id,
                    token_hash(&token),
                    account.expires_at_unix,
                    account.created_at_unix,
                ],
            )
            .context("failed to create workspace service account")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'service_account.create', ?3, ?4)",
                params![
                    &authorized.0,
                    workspace_id,
                    actor_principal_id,
                    account.created_at_unix
                ],
            )
            .context("failed to audit service-account creation")?;
        transaction
            .commit()
            .context("failed to commit service-account creation")?;
        Ok(IssuedWorkspaceServiceAccount { account, token })
    }

    pub fn revoke_workspace_service_account(
        &self,
        workspace_id: &str,
        account_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin service-account revocation")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1 AND workspaces.active = 1
                   AND organizations.active = 1 AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, actor_principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize service-account revocation")?;
        let Some((organization_id, role)) = authorized else {
            transaction.commit().ok();
            return Ok(false);
        };
        let creator = transaction
            .query_row(
                "SELECT created_by_principal_id FROM workspace_service_accounts
                 WHERE id = ?1 AND workspace_id = ?2 AND active = 1",
                params![account_id, workspace_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to load service account for revocation")?;
        let Some(creator) = creator else {
            transaction.commit().ok();
            return Ok(false);
        };
        let allowed = role.permits(WorkspacePermission::ManageServiceTokens)
            || (creator == actor_principal_id
                && role.permits(WorkspacePermission::ManageOwnServiceTokens));
        if !allowed {
            transaction.commit().ok();
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE workspace_service_accounts
                 SET active = 0, revoked_at_unix = ?3
                 WHERE id = ?1 AND workspace_id = ?2 AND active = 1",
            params![account_id, workspace_id, now],
        )?;
        if changed == 1 {
            transaction
                .execute(
                    "INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                     VALUES (?1, ?2, ?3, 'service_account.revoke', ?4, ?5)",
                    params![
                        organization_id,
                        workspace_id,
                        actor_principal_id,
                        creator,
                        now
                    ],
                )
                .context("failed to audit service-account revocation")?;
        }
        transaction
            .commit()
            .context("failed to commit service-account revocation")?;
        Ok(changed == 1)
    }

    pub fn set_workspace_membership(
        &self,
        workspace_id: &str,
        principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin workspace membership change")?;
        let active = transaction
            .query_row(
                "SELECT organizations.id, organizations.active, workspaces.active,
                        workspace_principals.active,
                        CASE WHEN scim_users.id IS NULL THEN 1
                             WHEN scim_users.organization_id = workspaces.organization_id
                                  AND scim_users.active = 1 THEN 1
                             ELSE 0 END
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                 WHERE workspaces.id = ?1",
                params![workspace_id, principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, i64>(3)? != 0,
                        row.get::<_, i64>(4)? != 0,
                    ))
                },
            )
            .optional()
            .context("failed to validate workspace membership")?;
        match active {
            Some((_, true, true, true, true)) => {}
            Some((_, false, _, _, _)) => {
                bail!("cannot assign a membership to an inactive organization")
            }
            Some((_, _, false, _, _)) => {
                bail!("cannot assign a membership to an inactive workspace")
            }
            Some((_, _, _, false, _)) => bail!("cannot assign an inactive principal"),
            Some((_, _, _, _, false)) => {
                bail!("cannot assign a membership to an inactive or cross-organization SCIM user")
            }
            None => bail!("workspace or principal not found"),
        }

        let organization_id = active
            .as_ref()
            .expect("active membership has an organization")
            .0
            .as_str();
        let now = now_unix();
        transaction
            .execute(
                "INSERT INTO workspace_memberships
                    (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)
                 ON CONFLICT(workspace_id, principal_id) DO UPDATE SET
                    role = excluded.role,
                    active = 1,
                    updated_at_unix = excluded.updated_at_unix",
                params![workspace_id, principal_id, role.storage_value(), now],
            )
            .context("failed to save workspace membership")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                params![
                    organization_id,
                    workspace_id,
                    "membership.upsert",
                    principal_id,
                    now,
                ],
            )
            .context("failed to append workspace membership audit event")?;
        let membership = transaction
            .query_row(
                "SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM workspace_memberships WHERE workspace_id = ?1 AND principal_id = ?2",
                params![workspace_id, principal_id],
                workspace_membership_from_sqlite_row,
            )
            .context("failed to read saved workspace membership")?;
        transaction
            .commit()
            .context("failed to commit workspace membership change")?;
        Ok(membership)
    }

    pub fn list_workspace_members(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceMember>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT workspace_memberships.workspace_id, workspace_memberships.principal_id,
                        workspace_principals.name, workspace_memberships.role,
                        workspace_memberships.active, workspace_memberships.created_at_unix,
                        workspace_memberships.updated_at_unix
                 FROM workspace_memberships
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_memberships.principal_id
                 WHERE workspace_memberships.workspace_id = ?1
                 ORDER BY workspace_memberships.active DESC, workspace_principals.name ASC,
                          workspace_memberships.principal_id ASC",
            )
            .context("failed to prepare workspace member list")?;
        let members = statement
            .query_map([workspace_id], workspace_member_from_sqlite_row)
            .context("failed to query workspace members")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace members")?;
        Ok(members)
    }

    pub fn create_workspace_invitation_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        recipient_label: &str,
        role: WorkspaceRole,
        expires_at_unix: i64,
    ) -> anyhow::Result<IssuedWorkspaceInvitation> {
        validate_workspace_invitation_expiry(expires_at_unix)?;
        let token = generate_workspace_invitation_token();
        let invitation = WorkspaceInvitation {
            id: random_id("invitation"),
            organization_id: String::new(),
            workspace_id: workspace_id.to_owned(),
            recipient_label: validate_label(recipient_label, "invitation recipient label", 128)?,
            role,
            created_by_principal_id: actor_principal_id.to_owned(),
            active: true,
            expires_at_unix,
            created_at_unix: now_unix(),
            revoked_at_unix: None,
            accepted_by_principal_id: None,
            accepted_at_unix: None,
        };
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin workspace invitation creation")?;
        let organization_id =
            authorized_workspace_owner_sqlite(&transaction, workspace_id, actor_principal_id)?;
        transaction
            .execute(
                "INSERT INTO workspace_invitations
                    (id, organization_id, workspace_id, token_hash, recipient_label, role,
                     created_by_principal_id, active, expires_at_unix, created_at_unix,
                     revoked_at_unix, accepted_by_principal_id, accepted_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, NULL, NULL, NULL)",
                params![
                    &invitation.id,
                    &organization_id,
                    workspace_id,
                    workspace_invitation_token_hash(&token)?,
                    &invitation.recipient_label,
                    role.storage_value(),
                    actor_principal_id,
                    expires_at_unix,
                    invitation.created_at_unix,
                ],
            )
            .context("failed to create workspace invitation")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'invitation.create', NULL, ?4)",
                params![
                    &organization_id,
                    workspace_id,
                    actor_principal_id,
                    invitation.created_at_unix,
                ],
            )
            .context("failed to audit workspace invitation creation")?;
        transaction
            .commit()
            .context("failed to commit workspace invitation creation")?;
        Ok(IssuedWorkspaceInvitation {
            invitation: WorkspaceInvitation {
                organization_id,
                ..invitation
            },
            token,
        })
    }

    pub fn list_workspace_invitations_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceInvitation>> {
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin workspace invitation listing")?;
        authorized_workspace_owner_sqlite(&transaction, workspace_id, actor_principal_id)?;
        let invitations = {
            let mut statement = transaction
                .prepare(
                    "SELECT id, organization_id, workspace_id, recipient_label, role,
                            created_by_principal_id, active, expires_at_unix, created_at_unix,
                            revoked_at_unix, accepted_by_principal_id, accepted_at_unix
                     FROM workspace_invitations
                     WHERE workspace_id = ?1
                     ORDER BY created_at_unix DESC, id DESC",
                )
                .context("failed to prepare workspace invitation listing")?;
            let invitations = statement
                .query_map([workspace_id], workspace_invitation_from_sqlite_row)
                .context("failed to query workspace invitations")?
                .collect::<Result<Vec<_>, _>>()
                .context("failed to read workspace invitations")?;
            invitations
        };
        transaction
            .commit()
            .context("failed to commit workspace invitation listing")?;
        Ok(invitations)
    }

    pub fn revoke_workspace_invitation_as_owner(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin workspace invitation revocation")?;
        let organization_id =
            authorized_workspace_owner_sqlite(&transaction, workspace_id, actor_principal_id)?;
        let changed = transaction
            .execute(
                "UPDATE workspace_invitations
                 SET active = 0, revoked_at_unix = ?3
                 WHERE id = ?1 AND workspace_id = ?2 AND active = 1
                   AND accepted_at_unix IS NULL",
                params![invitation_id, workspace_id, now],
            )
            .context("failed to revoke workspace invitation")?;
        if changed == 1 {
            transaction
                .execute(
                    "INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                     VALUES (?1, ?2, ?3, 'invitation.revoke', NULL, ?4)",
                    params![organization_id, workspace_id, actor_principal_id, now],
                )
                .context("failed to audit workspace invitation revocation")?;
        }
        transaction
            .commit()
            .context("failed to commit workspace invitation revocation")?;
        Ok(changed == 1)
    }

    pub fn workspace_invitation_for_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<WorkspaceInvitation>> {
        self.workspace_invitation_for_federation_token(token, BrowserSessionFederation::Oidc)
    }

    pub fn workspace_invitation_for_federation_token(
        &self,
        token: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<WorkspaceInvitation>> {
        let hash = workspace_invitation_token_hash(token)?;
        self.connection()?
            .query_row(
                "SELECT invitations.id, invitations.organization_id,
                        invitations.workspace_id, invitations.recipient_label,
                        invitations.role, invitations.created_by_principal_id,
                        invitations.active, invitations.expires_at_unix,
                        invitations.created_at_unix, invitations.revoked_at_unix,
                        invitations.accepted_by_principal_id, invitations.accepted_at_unix
                 FROM workspace_invitations AS invitations
                 JOIN organizations
                   ON organizations.id = invitations.organization_id
                 JOIN workspaces
                   ON workspaces.id = invitations.workspace_id
                  AND workspaces.organization_id = invitations.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 LEFT JOIN organization_oidc_connections AS oidc_connections
                   ON oidc_connections.organization_id = organizations.id
                  AND oidc_connections.active = 1
                 LEFT JOIN organization_saml_connections AS saml_connections
                   ON saml_connections.organization_id = organizations.id
                  AND saml_connections.active = 1
                 WHERE invitations.token_hash = ?1 AND invitations.active = 1
                   AND invitations.revoked_at_unix IS NULL
                   AND invitations.accepted_at_unix IS NULL
                   AND invitations.expires_at_unix >= ?2
                   AND organizations.active = 1 AND workspaces.active = 1
                   AND tenants.active = 1
                   AND ((?3 = 'oidc' AND oidc_connections.organization_id IS NOT NULL)
                        OR (?3 = 'saml' AND saml_connections.organization_id IS NOT NULL))",
                params![hash, now_unix(), federation.as_storage()],
                workspace_invitation_from_sqlite_row,
            )
            .optional()
            .context("failed to resolve workspace invitation")
    }

    pub fn accept_workspace_invitation_oidc(
        &self,
        invitation_id: &str,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        self.accept_workspace_invitation_federated(
            invitation_id,
            organization_id,
            workspace_id,
            issuer,
            subject,
            BrowserSessionFederation::Oidc,
        )
    }

    fn accept_workspace_invitation_federated(
        &self,
        invitation_id: &str,
        organization_id: &str,
        workspace_id: &str,
        issuer: &str,
        subject: &str,
        federation: BrowserSessionFederation,
    ) -> anyhow::Result<Option<VerifiedWorkspaceAccess>> {
        let issuer = validate_external_identity_component(issuer, "identity issuer", 2_048)?;
        let subject = validate_external_identity_component(subject, "identity subject", 255)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin workspace invitation acceptance")?;
        let invitation = transaction
            .query_row(
                "SELECT invitations.id, invitations.organization_id,
                        invitations.workspace_id, invitations.recipient_label,
                        invitations.role, invitations.created_by_principal_id,
                        invitations.active, invitations.expires_at_unix,
                        invitations.created_at_unix, invitations.revoked_at_unix,
                        invitations.accepted_by_principal_id, invitations.accepted_at_unix
                 FROM workspace_invitations AS invitations
                 JOIN organizations
                   ON organizations.id = invitations.organization_id
                 JOIN workspaces
                   ON workspaces.id = invitations.workspace_id
                  AND workspaces.organization_id = invitations.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 LEFT JOIN organization_oidc_connections AS oidc_connections
                   ON oidc_connections.organization_id = organizations.id
                  AND oidc_connections.issuer = ?5
                 LEFT JOIN organization_saml_connections AS saml_connections
                   ON saml_connections.organization_id = organizations.id
                  AND saml_connections.entity_id = ?5
                 WHERE invitations.id = ?1
                   AND invitations.organization_id = ?2
                   AND invitations.workspace_id = ?3
                   AND ((?4 = 'oidc' AND oidc_connections.organization_id IS NOT NULL)
                        OR (?4 = 'saml' AND saml_connections.organization_id IS NOT NULL))
                   AND invitations.active = 1
                   AND invitations.revoked_at_unix IS NULL
                   AND invitations.accepted_at_unix IS NULL
                   AND invitations.expires_at_unix >= ?6
                   AND organizations.active = 1 AND workspaces.active = 1
                   AND tenants.active = 1
                   AND ((?4 = 'oidc' AND oidc_connections.active = 1)
                        OR (?4 = 'saml' AND saml_connections.active = 1))",
                params![
                    invitation_id,
                    organization_id,
                    workspace_id,
                    federation.as_storage(),
                    &issuer,
                    now
                ],
                workspace_invitation_from_sqlite_row,
            )
            .optional()
            .context("failed to load workspace invitation for acceptance")?;
        let Some(invitation) = invitation else {
            transaction.commit().ok();
            return Ok(None);
        };

        let existing_principal = transaction
            .query_row(
                "SELECT principals.id, principals.active,
                        CASE WHEN scim_users.id IS NULL THEN 1
                             WHEN scim_users.organization_id = ?3 AND scim_users.active = 1
                             THEN 1 ELSE 0 END
                 FROM workspace_external_identities AS identities
                 JOIN workspace_principals AS principals
                   ON principals.id = identities.principal_id
                 LEFT JOIN scim_users ON scim_users.id = principals.id
                 WHERE identities.issuer = ?1 AND identities.subject = ?2",
                params![&issuer, &subject, &invitation.organization_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()
            .context("failed to resolve invitation federated identity")?;
        let principal_id = match existing_principal {
            Some((_, false, _)) | Some((_, _, false)) => {
                transaction.commit().ok();
                return Ok(None);
            }
            Some((principal_id, true, true)) => principal_id,
            None => {
                let principal_id = random_id("principal");
                transaction
                    .execute(
                        "INSERT INTO workspace_principals (id, name, active, created_at_unix)
                         VALUES (?1, ?2, 1, ?3)",
                        params![&principal_id, &invitation.recipient_label, now],
                    )
                    .context("failed to create invited workspace principal")?;
                transaction
                    .execute(
                        "INSERT INTO workspace_external_identities
                            (issuer, subject, principal_id, created_at_unix)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![&issuer, &subject, &principal_id, now],
                    )
                    .context("failed to bind invited federated identity")?;
                principal_id
            }
        };
        let membership_exists = transaction
            .query_row(
                "SELECT 1 FROM workspace_memberships
                 WHERE workspace_id = ?1 AND principal_id = ?2",
                params![&invitation.workspace_id, &principal_id],
                |_| Ok(()),
            )
            .optional()
            .context("failed to check invited workspace membership")?
            .is_some();
        if membership_exists {
            transaction.commit().ok();
            return Ok(None);
        }
        transaction
            .execute(
                "INSERT INTO workspace_memberships
                    (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)",
                params![
                    &invitation.workspace_id,
                    &principal_id,
                    invitation.role.storage_value(),
                    now,
                ],
            )
            .context("failed to create invited workspace membership")?;
        let consumed = transaction
            .execute(
                "UPDATE workspace_invitations
                 SET active = 0, accepted_by_principal_id = ?2, accepted_at_unix = ?3
                 WHERE id = ?1 AND active = 1 AND accepted_at_unix IS NULL
                   AND expires_at_unix >= ?3",
                params![&invitation.id, &principal_id, now],
            )
            .context("failed to consume workspace invitation")?;
        if consumed != 1 {
            transaction.rollback().ok();
            return Ok(None);
        }
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'invitation.accept', ?3, ?4)",
                params![
                    &invitation.organization_id,
                    &invitation.workspace_id,
                    &principal_id,
                    now,
                ],
            )
            .context("failed to audit workspace invitation acceptance")?;
        transaction
            .commit()
            .context("failed to commit workspace invitation acceptance")?;
        Ok(Some(VerifiedWorkspaceAccess {
            organization_id: invitation.organization_id,
            workspace_id: invitation.workspace_id,
            principal_id,
            role: invitation.role,
        }))
    }

    pub fn list_workspace_scim_users_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimUser>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT scim_users.id, scim_users.display_name
                 FROM scim_users
                 WHERE scim_users.organization_id = (
                     SELECT workspaces.organization_id
                     FROM workspaces
                     JOIN organizations ON organizations.id = workspaces.organization_id
                     JOIN tenants ON tenants.id = workspaces.tenant_id
                     JOIN workspace_principals
                       ON workspace_principals.id = ?2
                     JOIN workspace_memberships
                       ON workspace_memberships.workspace_id = workspaces.id
                      AND workspace_memberships.principal_id = workspace_principals.id
                     WHERE workspaces.id = ?1
                       AND workspace_memberships.role = 'owner'
                       AND workspace_memberships.active = 1
                       AND organizations.active = 1
                       AND tenants.active = 1
                       AND workspaces.active = 1
                       AND workspace_principals.active = 1
                 )
                   AND scim_users.active = 1
                 ORDER BY scim_users.display_name ASC, scim_users.id ASC",
            )
            .context("failed to prepare workspace SCIM directory list")?;
        let users = statement
            .query_map(params![workspace_id, actor_principal_id], |row| {
                Ok(WorkspaceScimUser {
                    principal_id: row.get(0)?,
                    display_name: row.get(1)?,
                })
            })
            .context("failed to query workspace SCIM directory")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace SCIM directory")?;
        Ok(users)
    }

    pub fn assign_scim_user_to_workspace_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin SCIM workspace assignment")?;
        let organization_id = transaction
            .query_row(
                "SELECT workspaces.organization_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals
                   ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspace_memberships.role = 'owner'
                   AND workspace_memberships.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1",
                params![workspace_id, actor_principal_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to authorize SCIM workspace assignment")?
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        let target_active = transaction
            .query_row(
                "SELECT 1 FROM scim_users
                 JOIN workspace_principals ON workspace_principals.id = scim_users.id
                 WHERE scim_users.id = ?1
                   AND scim_users.organization_id = ?2
                   AND scim_users.active = 1
                   AND workspace_principals.active = 1",
                params![target_principal_id, &organization_id],
                |_| Ok(()),
            )
            .optional()
            .context("failed to validate SCIM workspace assignment target")?
            .is_some();
        if !target_active {
            bail!("SCIM user is not active in this workspace organization");
        }
        transaction
            .execute(
                "INSERT INTO workspace_memberships
                    (workspace_id, principal_id, role, active, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)
                 ON CONFLICT(workspace_id, principal_id) DO UPDATE SET
                    role = excluded.role,
                    active = 1,
                    updated_at_unix = excluded.updated_at_unix",
                params![workspace_id, target_principal_id, role.storage_value(), now],
            )
            .context("failed to save SCIM workspace assignment")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'membership.assign_scim', ?4, ?5)",
                params![
                    &organization_id,
                    workspace_id,
                    actor_principal_id,
                    target_principal_id,
                    now,
                ],
            )
            .context("failed to append SCIM workspace assignment audit event")?;
        let membership = transaction
            .query_row(
                "SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM workspace_memberships WHERE workspace_id = ?1 AND principal_id = ?2",
                params![workspace_id, target_principal_id],
                workspace_membership_from_sqlite_row,
            )
            .context("failed to read SCIM workspace assignment")?;
        transaction
            .commit()
            .context("failed to commit SCIM workspace assignment")?;
        Ok(membership)
    }

    pub fn list_workspace_scim_groups_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroup>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT scim_groups.id, scim_groups.display_name
             FROM scim_groups
             WHERE scim_groups.organization_id = (
                 SELECT workspaces.organization_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspace_memberships.role = 'owner'
                   AND workspace_memberships.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspaces.active = 1
                   AND workspace_principals.active = 1
             ) AND scim_groups.active = 1
             ORDER BY scim_groups.display_name ASC, scim_groups.id ASC",
            )
            .context("failed to prepare workspace SCIM group directory list")?;
        let groups = statement
            .query_map(params![workspace_id, actor_principal_id], |row| {
                Ok(WorkspaceScimGroup {
                    group_id: row.get(0)?,
                    display_name: row.get(1)?,
                })
            })
            .context("failed to query workspace SCIM group directory")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace SCIM group directory")?;
        Ok(groups)
    }

    pub fn list_workspace_scim_group_mappings_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceScimGroupMapping>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT mappings.workspace_id, mappings.group_id, scim_groups.display_name,
                    mappings.created_at_unix, mappings.updated_at_unix
             FROM workspace_scim_group_mappings AS mappings
             JOIN scim_groups ON scim_groups.id = mappings.group_id
             WHERE mappings.workspace_id = ?1
               AND EXISTS (
                   SELECT 1 FROM workspaces
                   JOIN organizations ON organizations.id = workspaces.organization_id
                   JOIN tenants ON tenants.id = workspaces.tenant_id
                   JOIN workspace_principals ON workspace_principals.id = ?2
                   JOIN workspace_memberships
                     ON workspace_memberships.workspace_id = workspaces.id
                    AND workspace_memberships.principal_id = workspace_principals.id
                   WHERE workspaces.id = mappings.workspace_id
                     AND workspace_memberships.role = 'owner'
                     AND workspace_memberships.active = 1
                     AND organizations.active = 1
                     AND tenants.active = 1
                     AND workspaces.active = 1
                     AND workspace_principals.active = 1
               )
             ORDER BY scim_groups.display_name ASC, mappings.group_id ASC",
            )
            .context("failed to prepare workspace SCIM group mappings")?;
        let mappings = statement
            .query_map(params![workspace_id, actor_principal_id], |row| {
                Ok(WorkspaceScimGroupMapping {
                    workspace_id: row.get(0)?,
                    group_id: row.get(1)?,
                    group_display_name: row.get(2)?,
                    role: WorkspaceRole::Analyst,
                    created_at_unix: row.get(3)?,
                    updated_at_unix: row.get(4)?,
                })
            })
            .context("failed to query workspace SCIM group mappings")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace SCIM group mappings")?;
        Ok(mappings)
    }

    pub fn create_workspace_scim_group_mapping_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = validate_scim_group_id(group_id)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin SCIM group mapping transaction")?;
        let organization_id =
            authorized_workspace_owner_sqlite(&transaction, workspace_id, actor_principal_id)?;
        let valid_group = transaction
            .query_row(
                "SELECT 1 FROM scim_groups
                 WHERE id = ?1 AND organization_id = ?2 AND active = 1",
                params![&group_id, &organization_id],
                |_| Ok(()),
            )
            .optional()
            .context("failed to validate SCIM group mapping target")?
            .is_some();
        if !valid_group {
            bail!("SCIM group is not active in this workspace organization");
        }
        let created = transaction
            .execute(
                "INSERT INTO workspace_scim_group_mappings
                    (workspace_id, group_id, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(workspace_id, group_id) DO NOTHING",
                params![workspace_id, &group_id, now],
            )
            .context("failed to save SCIM group mapping")?
            == 1;
        if created {
            transaction
                .execute(
                    "INSERT INTO workspace_scim_group_mapping_audit
                    (organization_id, workspace_id, actor_principal_id, group_id, action,
                     created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 'group_mapping.create', ?5)",
                    params![
                        &organization_id,
                        workspace_id,
                        actor_principal_id,
                        &group_id,
                        now
                    ],
                )
                .context("failed to append SCIM group mapping audit event")?;
        }
        transaction
            .commit()
            .context("failed to commit SCIM group mapping transaction")?;
        Ok(created)
    }

    pub fn delete_workspace_scim_group_mapping_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        group_id: &str,
    ) -> anyhow::Result<bool> {
        let group_id = validate_scim_group_id(group_id)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin SCIM group unmapping transaction")?;
        let organization_id =
            authorized_workspace_owner_sqlite(&transaction, workspace_id, actor_principal_id)?;
        let deleted = transaction
            .execute(
                "DELETE FROM workspace_scim_group_mappings
                 WHERE workspace_id = ?1 AND group_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM scim_groups
                       WHERE scim_groups.id = ?2
                         AND scim_groups.organization_id = ?3
                   )",
                params![workspace_id, &group_id, &organization_id],
            )
            .context("failed to delete SCIM group mapping")?
            == 1;
        if deleted {
            transaction
                .execute(
                    "INSERT INTO workspace_scim_group_mapping_audit
                    (organization_id, workspace_id, actor_principal_id, group_id, action,
                     created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 'group_mapping.delete', ?5)",
                    params![
                        &organization_id,
                        workspace_id,
                        actor_principal_id,
                        &group_id,
                        now
                    ],
                )
                .context("failed to append SCIM group unmapping audit event")?;
        }
        transaction
            .commit()
            .context("failed to commit SCIM group unmapping transaction")?;
        Ok(deleted)
    }

    pub fn update_workspace_membership_as_owner(
        &self,
        workspace_id: &str,
        actor_principal_id: &str,
        target_principal_id: &str,
        role: WorkspaceRole,
        active: bool,
    ) -> anyhow::Result<WorkspaceMembership> {
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer membership transaction")?;
        let organization_id = transaction
            .query_row(
                "SELECT workspaces.organization_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals
                   ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspace_memberships.role = 'owner'
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, actor_principal_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to authorize customer membership mutation")?
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        let target = transaction
            .query_row(
                "SELECT workspace_memberships.role, workspace_memberships.active
                 FROM workspace_memberships
                 JOIN workspace_principals
                   ON workspace_principals.id = workspace_memberships.principal_id
                 JOIN workspaces ON workspaces.id = workspace_memberships.workspace_id
                 LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                 WHERE workspace_memberships.workspace_id = ?1
                   AND workspace_memberships.principal_id = ?2
                   AND workspace_principals.active = 1
                   AND (scim_users.id IS NULL OR
                        (scim_users.organization_id = workspaces.organization_id
                         AND scim_users.active = 1))",
                params![workspace_id, target_principal_id],
                |row| {
                    Ok((
                        WorkspaceRole::from_storage(&row.get::<_, String>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        row.get::<_, i64>(1)? != 0,
                    ))
                },
            )
            .optional()
            .context("failed to resolve customer membership target")?
            .ok_or_else(|| {
                anyhow::anyhow!("workspace membership target is not active or not found")
            })?;
        if target.0 == WorkspaceRole::Owner && target.1 && (!active || role != WorkspaceRole::Owner)
        {
            let owner_count = transaction
                .query_row(
                    "SELECT COUNT(*) FROM workspace_memberships
                     WHERE workspace_id = ?1 AND active = 1 AND role = 'owner'",
                    [workspace_id],
                    |row| row.get::<_, i64>(0),
                )
                .context("failed to count active workspace owners")?;
            if owner_count <= 1 {
                bail!("cannot remove or demote the last active workspace owner");
            }
        }
        let changed = transaction
            .execute(
                "UPDATE workspace_memberships
                 SET role = ?3, active = ?4, updated_at_unix = ?5
                 WHERE workspace_id = ?1 AND principal_id = ?2",
                params![
                    workspace_id,
                    target_principal_id,
                    role.storage_value(),
                    i64::from(active),
                    now,
                ],
            )
            .context("failed to save customer workspace membership")?;
        if changed != 1 {
            bail!("workspace membership target is not found");
        }
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'membership.update', ?4, ?5)",
                params![
                    organization_id,
                    workspace_id,
                    actor_principal_id,
                    target_principal_id,
                    now,
                ],
            )
            .context("failed to append customer membership audit event")?;
        let membership = transaction
            .query_row(
                "SELECT workspace_id, principal_id, role, active, created_at_unix, updated_at_unix
                 FROM workspace_memberships WHERE workspace_id = ?1 AND principal_id = ?2",
                params![workspace_id, target_principal_id],
                workspace_membership_from_sqlite_row,
            )
            .context("failed to read customer workspace membership")?;
        transaction
            .commit()
            .context("failed to commit customer membership transaction")?;
        Ok(membership)
    }

    pub fn workspace_permits(
        &self,
        principal_id: &str,
        workspace_id: &str,
        permission: WorkspacePermission,
    ) -> anyhow::Result<bool> {
        let roles = self
            .connection()?
            .prepare(
                "SELECT role FROM (
                    SELECT workspace_memberships.role AS role
                    FROM workspace_memberships
                    JOIN workspaces ON workspaces.id = workspace_memberships.workspace_id
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN workspace_principals
                      ON workspace_principals.id = workspace_memberships.principal_id
                    LEFT JOIN scim_users ON scim_users.id = workspace_principals.id
                    WHERE workspace_memberships.workspace_id = ?1
                      AND workspace_memberships.principal_id = ?2
                      AND workspace_memberships.active = 1
                      AND organizations.active = 1
                      AND workspaces.active = 1
                      AND workspace_principals.active = 1
                      AND (scim_users.id IS NULL OR
                           (scim_users.organization_id = organizations.id
                            AND scim_users.active = 1))
                    UNION
                    SELECT 'analyst' AS role
                    FROM workspace_scim_group_mappings
                    JOIN workspaces ON workspaces.id = workspace_scim_group_mappings.workspace_id
                    JOIN organizations ON organizations.id = workspaces.organization_id
                    JOIN workspace_principals ON workspace_principals.id = ?2
                    JOIN scim_groups
                      ON scim_groups.id = workspace_scim_group_mappings.group_id
                     AND scim_groups.organization_id = organizations.id
                    JOIN scim_group_members
                      ON scim_group_members.group_id = scim_groups.id
                     AND scim_group_members.principal_id = workspace_principals.id
                    JOIN scim_users
                      ON scim_users.id = workspace_principals.id
                     AND scim_users.organization_id = organizations.id
                    WHERE workspace_scim_group_mappings.workspace_id = ?1
                      AND organizations.active = 1
                      AND workspaces.active = 1
                      AND workspace_principals.active = 1
                      AND scim_groups.active = 1
                      AND scim_users.active = 1
                 )",
            )
            .context("failed to prepare workspace authorization")?
            .query_map(params![workspace_id, principal_id], |row| {
                row.get::<_, String>(0)
            })
            .context("failed to authorize workspace action")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace authorization")?;
        roles
            .into_iter()
            .map(|role| WorkspaceRole::from_storage(&role))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(|roles| roles.into_iter().any(|role| role.permits(permission)))
    }

    pub fn list_workspace_admin_audit(
        &self,
        workspace_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WorkspaceAdminAuditEvent>> {
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded workspace audit limit fits in SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, organization_id, workspace_id, actor_principal_id, action,
                        target_principal_id, created_at_unix
                 FROM workspace_admin_audit
                 WHERE workspace_id = ?1
                 ORDER BY id DESC LIMIT ?2",
            )
            .context("failed to prepare workspace admin audit list")?;
        let events = statement
            .query_map(
                params![workspace_id, limit],
                workspace_admin_audit_from_sqlite_row,
            )
            .context("failed to query workspace admin audit events")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read workspace admin audit events")?;
        Ok(events)
    }

    pub fn set_tenant_active(&self, tenant_id: &str, active: bool) -> anyhow::Result<bool> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE tenants SET active = ?1 WHERE id = ?2",
                params![i64::from(active), tenant_id],
            )
            .context("failed to update tenant state")?;
        Ok(changed == 1)
    }

    pub fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let changed = self
            .connection()?
            .execute("DELETE FROM tenants WHERE id = ?1", [tenant_id])
            .context("failed to delete tenant")?;
        Ok(changed == 1)
    }

    pub fn create_admin(&self, name: &str, role: AdminRole) -> anyhow::Result<IssuedAdminToken> {
        let admin = ControlPlaneAdmin {
            id: random_id("admin"),
            name: validate_label(name, "admin name", 128)?,
            role,
            active: true,
            created_at_unix: now_unix(),
        };
        let token = generate_admin_token();
        self.connection()?
            .execute(
                "INSERT INTO control_plane_admins
                    (id, name, token_hash, role, active, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    admin.id,
                    admin.name,
                    token_hash(&token),
                    admin.role.storage_value(),
                    admin.created_at_unix,
                ],
            )
            .context("failed to create control-plane admin")?;
        Ok(IssuedAdminToken { admin, token })
    }

    pub fn list_admins(&self) -> anyhow::Result<Vec<ControlPlaneAdmin>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, role, active, created_at_unix
                 FROM control_plane_admins ORDER BY created_at_unix ASC, id ASC",
            )
            .context("failed to prepare control-plane admin list")?;
        let admins = statement
            .query_map([], control_plane_admin_from_sqlite_row)
            .context("failed to query control-plane admins")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read control-plane admins")?;
        Ok(admins)
    }

    pub fn revoke_admin(&self, admin_id: &str) -> anyhow::Result<bool> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE control_plane_admins
                 SET active = 0, revoked_at_unix = ?1
                 WHERE id = ?2 AND active = 1",
                params![now_unix(), admin_id],
            )
            .context("failed to revoke control-plane admin")?;
        Ok(changed == 1)
    }

    pub fn authenticate_admin_bearer(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<AdminIdentity>> {
        let Some(token) = presented_header.and_then(|value| value.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        if token.is_empty() {
            return Ok(None);
        }
        self.connection()?
            .query_row(
                "SELECT id, name, role FROM control_plane_admins
                 WHERE token_hash = ?1 AND active = 1",
                [token_hash(token)],
                |row| {
                    Ok(AdminIdentity {
                        admin_id: row.get(0)?,
                        admin_name: row.get(1)?,
                        role: AdminRole::from_storage(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .context("failed to authenticate control-plane admin")
    }

    pub fn issue_token(&self, tenant_id: &str, label: &str) -> anyhow::Result<IssuedToken> {
        let label = validate_label(label, "token label", 128)?;
        let mut connection = self.connection()?;
        let tenant_active = connection
            .query_row(
                "SELECT active FROM tenants WHERE id = ?1",
                [tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .context("failed to look up tenant")?;
        match tenant_active {
            Some(1) => {}
            Some(_) => bail!("cannot issue a token for an inactive tenant"),
            None => bail!("tenant not found"),
        }

        let token = generate_token();
        let issued = IssuedToken {
            id: random_id("token"),
            tenant_id: tenant_id.to_owned(),
            label,
            token,
            created_at_unix: now_unix(),
        };
        let transaction = connection
            .transaction()
            .context("failed to begin token issuance")?;
        transaction
            .execute(
                "INSERT INTO tenant_tokens
                    (id, tenant_id, token_hash, label, active, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    issued.id,
                    issued.tenant_id,
                    token_hash(&issued.token),
                    issued.label,
                    issued.created_at_unix,
                ],
            )
            .context("failed to issue tenant token")?;
        transaction
            .commit()
            .context("failed to commit tenant token")?;
        Ok(issued)
    }

    pub fn revoke_token(&self, token_id: &str) -> anyhow::Result<bool> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE tenant_tokens
                 SET active = 0, revoked_at_unix = ?1
                 WHERE id = ?2 AND active = 1",
                params![now_unix(), token_id],
            )
            .context("failed to revoke tenant token")?;
        Ok(changed == 1)
    }

    pub fn list_tokens(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToken>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, label, active, created_at_unix, revoked_at_unix
                 FROM tenant_tokens WHERE tenant_id = ?1 ORDER BY created_at_unix DESC, id DESC",
            )
            .context("failed to prepare tenant token inventory query")?;
        let tokens = statement
            .query_map([tenant_id], tenant_token_from_sqlite_row)
            .context("failed to query tenant token inventory")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read tenant token inventory")?;
        Ok(tokens)
    }

    pub fn limits_for(&self, tenant_id: &str) -> anyhow::Result<TenantLimits> {
        self.connection()?
            .query_row(
                "SELECT rate_limit_requests_per_window,
                        rate_limit_window_seconds,
                        spend_limit_window_seconds,
                        spend_limit_max_usd_micros,
                        spend_limit_reserve_usd_micros_per_request
                 FROM tenant_limits WHERE tenant_id = ?1",
                [tenant_id],
                |row| {
                    let rate_requests = row.get::<_, Option<u32>>(0)?;
                    let rate_window = row.get::<_, Option<u64>>(1)?;
                    let spend_window = row.get::<_, Option<u64>>(2)?;
                    let spend_max = row.get::<_, Option<u64>>(3)?;
                    let spend_reserve = row.get::<_, Option<u64>>(4)?;
                    Ok(TenantLimits {
                        rate_limit: rate_requests.zip(rate_window).map(
                            |(requests_per_window, window_seconds)| TenantRateLimit {
                                requests_per_window,
                                window_seconds,
                            },
                        ),
                        spend_limit: spend_window.zip(spend_max).zip(spend_reserve).map(
                            |((window_seconds, max_usd_micros), reserve_usd_micros_per_request)| {
                                TenantSpendLimit {
                                    window_seconds,
                                    max_usd_micros,
                                    reserve_usd_micros_per_request,
                                }
                            },
                        ),
                    })
                },
            )
            .optional()
            .map(|limits| limits.unwrap_or_default())
            .context("failed to load tenant limits")
    }

    pub fn set_limits(&self, tenant_id: &str, limits: TenantLimits) -> anyhow::Result<()> {
        validate_limits(&limits)?;
        let connection = self.connection()?;
        let tenant_exists = connection
            .query_row("SELECT 1 FROM tenants WHERE id = ?1", [tenant_id], |_| {
                Ok(())
            })
            .optional()
            .context("failed to look up tenant for limits")?
            .is_some();
        if !tenant_exists {
            bail!("tenant not found");
        }
        connection
            .execute(
                "INSERT INTO tenant_limits (
                    tenant_id,
                    rate_limit_requests_per_window,
                    rate_limit_window_seconds,
                    spend_limit_window_seconds,
                    spend_limit_max_usd_micros,
                    spend_limit_reserve_usd_micros_per_request,
                    updated_at_unix
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                    rate_limit_requests_per_window = excluded.rate_limit_requests_per_window,
                    rate_limit_window_seconds = excluded.rate_limit_window_seconds,
                    spend_limit_window_seconds = excluded.spend_limit_window_seconds,
                    spend_limit_max_usd_micros = excluded.spend_limit_max_usd_micros,
                    spend_limit_reserve_usd_micros_per_request = excluded.spend_limit_reserve_usd_micros_per_request,
                    updated_at_unix = excluded.updated_at_unix",
                params![
                    tenant_id,
                    limits.rate_limit.as_ref().map(|rate| rate.requests_per_window),
                    limits.rate_limit.as_ref().map(|rate| rate.window_seconds),
                    limits.spend_limit.as_ref().map(|spend| spend.window_seconds),
                    limits.spend_limit.as_ref().map(|spend| spend.max_usd_micros),
                    limits
                        .spend_limit
                        .as_ref()
                        .map(|spend| spend.reserve_usd_micros_per_request),
                    now_unix(),
                ],
            )
            .context("failed to save tenant limits")?;
        Ok(())
    }

    pub fn set_workspace_limits(
        &self,
        workspace_id: &str,
        principal_id: &str,
        limits: TenantLimits,
    ) -> anyhow::Result<()> {
        validate_limits(&limits)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer limits transaction")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize customer limits mutation")?
            .filter(|(_, _, role)| role.permits(WorkspacePermission::ManageTenant))
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        transaction
            .execute(
                "INSERT INTO tenant_limits (
                    tenant_id, rate_limit_requests_per_window, rate_limit_window_seconds,
                    spend_limit_window_seconds, spend_limit_max_usd_micros,
                    spend_limit_reserve_usd_micros_per_request, updated_at_unix
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                    rate_limit_requests_per_window = excluded.rate_limit_requests_per_window,
                    rate_limit_window_seconds = excluded.rate_limit_window_seconds,
                    spend_limit_window_seconds = excluded.spend_limit_window_seconds,
                    spend_limit_max_usd_micros = excluded.spend_limit_max_usd_micros,
                    spend_limit_reserve_usd_micros_per_request = excluded.spend_limit_reserve_usd_micros_per_request,
                    updated_at_unix = excluded.updated_at_unix",
                params![
                    &authorized.1,
                    limits.rate_limit.as_ref().map(|rate| rate.requests_per_window),
                    limits.rate_limit.as_ref().map(|rate| rate.window_seconds),
                    limits.spend_limit.as_ref().map(|spend| spend.window_seconds),
                    limits.spend_limit.as_ref().map(|spend| spend.max_usd_micros),
                    limits.spend_limit.as_ref().map(|spend| spend.reserve_usd_micros_per_request),
                    now,
                ],
            )
            .context("failed to save customer limits")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'limits.set', NULL, ?4)",
                params![&authorized.0, workspace_id, principal_id, now],
            )
            .context("failed to append customer limits audit event")?;
        transaction
            .commit()
            .context("failed to commit customer limits transaction")?;
        Ok(())
    }

    pub fn create_policy_version(
        &self,
        tenant_id: &str,
        actor_id: &str,
        document: TenantPolicyDocument,
    ) -> anyhow::Result<TenantPolicyVersion> {
        validate_usage_text(actor_id, "policy actor ID", 256)?;
        let (document_json, content_sha256) = canonical_policy_document(&document)?;
        let id = random_id("policy");
        let created_at_unix = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin policy-version transaction")?;
        let tenant_exists = transaction
            .query_row("SELECT 1 FROM tenants WHERE id = ?1", [tenant_id], |_| {
                Ok(())
            })
            .optional()
            .context("failed to look up tenant for policy version")?
            .is_some();
        if !tenant_exists {
            bail!("tenant not found");
        }
        let next_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_versions WHERE tenant_id = ?1",
                [tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate policy sequence")?;
        transaction
            .execute(
                "INSERT INTO tenant_policy_versions
                    (id, tenant_id, sequence, document_json, content_sha256,
                     created_by, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &id,
                    tenant_id,
                    next_sequence,
                    &document_json,
                    &content_sha256,
                    actor_id,
                    created_at_unix,
                ],
            )
            .context("failed to append tenant policy version")?;
        transaction
            .commit()
            .context("failed to commit policy version")?;
        Ok(TenantPolicyVersion {
            id,
            tenant_id: tenant_id.to_owned(),
            sequence: u64::try_from(next_sequence).context("policy sequence is invalid")?,
            document,
            content_sha256,
            created_by: actor_id.to_owned(),
            created_at_unix,
            approved_by: None,
            approved_at_unix: None,
            active: false,
        })
    }

    pub fn list_policy_versions(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyVersion>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded policy-version limit fits SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT versions.id, versions.tenant_id, versions.sequence,
                        versions.document_json, versions.content_sha256,
                        versions.created_by, versions.created_at_unix,
                        approvals.approved_by, approvals.approved_at_unix,
                        CASE WHEN state.active_version_id = versions.id THEN 1 ELSE 0 END
                 FROM tenant_policy_versions AS versions
                 LEFT JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 LEFT JOIN tenant_policy_state AS state
                   ON state.tenant_id = versions.tenant_id
                 WHERE versions.tenant_id = ?1
                 ORDER BY versions.sequence DESC LIMIT ?2",
            )
            .context("failed to prepare policy-version query")?;
        let versions = statement
            .query_map(params![tenant_id, limit], policy_version_from_sqlite_row)
            .context("failed to query policy versions")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read policy versions")?;
        Ok(versions)
    }

    pub fn policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
    ) -> anyhow::Result<Option<TenantPolicyVersion>> {
        self.connection()?
            .query_row(
                "SELECT versions.id, versions.tenant_id, versions.sequence,
                        versions.document_json, versions.content_sha256,
                        versions.created_by, versions.created_at_unix,
                        approvals.approved_by, approvals.approved_at_unix,
                        CASE WHEN state.active_version_id = versions.id THEN 1 ELSE 0 END
                 FROM tenant_policy_versions AS versions
                 LEFT JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 LEFT JOIN tenant_policy_state AS state
                   ON state.tenant_id = versions.tenant_id
                 WHERE versions.tenant_id = ?1 AND versions.id = ?2",
                params![tenant_id, version_id],
                policy_version_from_sqlite_row,
            )
            .optional()
            .context("failed to load policy version")
    }

    pub fn approve_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<TenantPolicyVersion> {
        validate_usage_text(actor_id, "policy approver ID", 256)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin policy-approval transaction")?;
        let existing = transaction
            .query_row(
                "SELECT approvals.approved_by
                 FROM tenant_policy_versions AS versions
                 LEFT JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 WHERE versions.tenant_id = ?1 AND versions.id = ?2",
                params![tenant_id, version_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .context("failed to load policy approval")?
            .ok_or_else(|| anyhow::anyhow!("policy version not found"))?;
        match existing {
            Some(existing) if existing != actor_id => {
                bail!("policy version was already approved by another actor")
            }
            Some(_) => {}
            None => {
                transaction
                    .execute(
                        "INSERT INTO tenant_policy_approvals
                            (version_id, approved_by, approved_at_unix)
                         VALUES (?1, ?2, ?3)",
                        params![version_id, actor_id, now],
                    )
                    .context("failed to approve policy version")?;
            }
        }
        transaction
            .commit()
            .context("failed to commit policy approval")?;
        drop(connection);
        self.policy_version(tenant_id, version_id)?
            .ok_or_else(|| anyhow::anyhow!("policy version not found after approval"))
    }

    pub fn deploy_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        actor_id: &str,
        action: PolicyDeploymentAction,
    ) -> anyhow::Result<TenantPolicyDeployment> {
        validate_usage_text(actor_id, "policy deployment actor ID", 256)?;
        let now = now_unix();
        let deployment_id = random_id("policy_deployment");
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin policy deployment")?;
        let document_json = transaction
            .query_row(
                "SELECT versions.document_json
                 FROM tenant_policy_versions AS versions
                 JOIN tenant_policy_approvals AS approvals
                   ON approvals.version_id = versions.id
                 WHERE versions.tenant_id = ?1 AND versions.id = ?2",
                params![tenant_id, version_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to load approved policy version")?
            .ok_or_else(|| anyhow::anyhow!("approved policy version not found"))?;
        let document: TenantPolicyDocument = serde_json::from_str(&document_json)
            .context("stored tenant policy version is invalid")?;
        validate_policy_document(&document)?;
        let previous_version_id = transaction
            .query_row(
                "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = ?1",
                [tenant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to load active policy version")?;
        if previous_version_id.as_deref() == Some(version_id) {
            bail!("policy version is already active");
        }
        if action == PolicyDeploymentAction::Rollback {
            let was_deployed = transaction
                .query_row(
                    "SELECT 1 FROM tenant_policy_deployments
                     WHERE tenant_id = ?1 AND version_id = ?2 LIMIT 1",
                    params![tenant_id, version_id],
                    |_| Ok(()),
                )
                .optional()
                .context("failed to verify rollback target")?
                .is_some();
            if !was_deployed {
                bail!("rollback target has never been deployed");
            }
        }
        match &document.model_policy {
            Some(policy) => {
                let encoded = serde_json::to_string(policy)
                    .context("failed to encode active model policy")?;
                transaction
                    .execute(
                        "INSERT INTO tenant_model_policies
                            (tenant_id, allowed_models_json, updated_at_unix)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(tenant_id) DO UPDATE SET
                            allowed_models_json = excluded.allowed_models_json,
                            updated_at_unix = excluded.updated_at_unix",
                        params![tenant_id, encoded, now],
                    )
                    .context("failed to materialize active model policy")?;
            }
            None => {
                transaction
                    .execute(
                        "DELETE FROM tenant_model_policies WHERE tenant_id = ?1",
                        [tenant_id],
                    )
                    .context("failed to clear active model policy")?;
            }
        }
        transaction
            .execute(
                "INSERT INTO tenant_policy_state (tenant_id, active_version_id, updated_at_unix)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                    active_version_id = excluded.active_version_id,
                    updated_at_unix = excluded.updated_at_unix",
                params![tenant_id, version_id, now],
            )
            .context("failed to update active policy version")?;
        let deployment_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_deployments WHERE tenant_id = ?1",
                [tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate policy deployment sequence")?;
        let deployment = TenantPolicyDeployment {
            id: deployment_id,
            tenant_id: tenant_id.to_owned(),
            sequence: u64::try_from(deployment_sequence)
                .context("policy deployment sequence is invalid")?,
            version_id: version_id.to_owned(),
            previous_version_id,
            action,
            actor_id: actor_id.to_owned(),
            created_at_unix: now,
        };
        transaction
            .execute(
                "INSERT INTO tenant_policy_deployments
                    (id, tenant_id, sequence, version_id, previous_version_id, action,
                     actor_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    &deployment.id,
                    tenant_id,
                    deployment_sequence,
                    &deployment.version_id,
                    &deployment.previous_version_id,
                    deployment.action.storage_value(),
                    &deployment.actor_id,
                    deployment.created_at_unix,
                ],
            )
            .context("failed to append policy deployment")?;
        let (event_json, event_sha256) = canonical_security_event_payload(
            "policy.deployed",
            &policy_deployment_security_payload(&deployment),
        )?;
        let event_id = random_id("security_event");
        let event_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_security_events WHERE tenant_id = ?1",
                [tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate security event sequence")?;
        transaction
            .execute(
                "INSERT INTO tenant_security_events
                    (id, tenant_id, sequence, event_type, payload_json,
                     content_sha256, occurred_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &event_id,
                    tenant_id,
                    event_sequence,
                    "policy.deployed",
                    &event_json,
                    &event_sha256,
                    now,
                ],
            )
            .context("failed to append policy security event")?;
        let destinations = transaction
            .prepare(
                "SELECT id, event_types_json FROM tenant_webhook_destinations
                 WHERE tenant_id = ?1 AND active = 1",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([&deployment.tenant_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()
            })
            .context("failed to list webhook destinations for delivery")?;
        for (destination_id, event_types_json) in destinations {
            let event_types: Vec<String> = serde_json::from_str(&event_types_json)
                .context("stored webhook event subscriptions are invalid")?;
            if !event_types
                .iter()
                .any(|event_type| event_type == "policy.deployed")
            {
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO tenant_webhook_deliveries
                        (id, tenant_id, event_id, destination_id, status,
                         attempt_count, next_attempt_at_unix, created_at_unix)
                     VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5)
                     ON CONFLICT(event_id, destination_id) DO NOTHING",
                    params![
                        random_id("webhook_delivery"),
                        &deployment.tenant_id,
                        event_id,
                        destination_id,
                        now,
                    ],
                )
                .context("failed to enqueue webhook delivery")?;
        }
        transaction
            .commit()
            .context("failed to commit policy deployment")?;
        Ok(deployment)
    }

    pub fn list_policy_deployments(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantPolicyDeployment>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded policy-deployment limit fits SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, sequence, version_id, previous_version_id, action,
                        actor_id, created_at_unix
                 FROM tenant_policy_deployments
                 WHERE tenant_id = ?1
                 ORDER BY sequence DESC LIMIT ?2",
            )
            .context("failed to prepare policy-deployment query")?;
        let deployments = statement
            .query_map(params![tenant_id, limit], policy_deployment_from_sqlite_row)
            .context("failed to query policy deployments")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read policy deployments")?;
        Ok(deployments)
    }

    pub fn list_security_events(
        &self,
        tenant_id: &str,
        after_sequence: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantSecurityEvent>> {
        let after_sequence = i64::try_from(after_sequence)
            .context("security-event cursor exceeds SQLite integer range")?;
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded security-event limit fits SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, sequence, event_type, payload_json,
                        content_sha256, occurred_at_unix
                 FROM tenant_security_events
                 WHERE tenant_id = ?1 AND sequence > ?2
                 ORDER BY sequence ASC LIMIT ?3",
            )
            .context("failed to prepare security-event query")?;
        let events = statement
            .query_map(
                params![tenant_id, after_sequence, limit],
                security_event_from_sqlite_row,
            )
            .context("failed to query security events")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read security events")?;
        Ok(events)
    }

    fn create_webhook_destination(
        &self,
        tenant_id: &str,
        url: &str,
        event_types: &[String],
    ) -> anyhow::Result<WebhookDestination> {
        let id = random_id("webhook");
        let now = now_unix();
        let event_types_json = serde_json::to_string(event_types)
            .context("failed to encode webhook event subscriptions")?;
        self.connection()?
            .execute(
                "INSERT INTO tenant_webhook_destinations
                    (id, tenant_id, url, event_types_json, active, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                params![id, tenant_id, url, event_types_json, now],
            )
            .context("failed to create webhook destination")?;
        Ok(WebhookDestination {
            id,
            tenant_id: tenant_id.to_owned(),
            url: url.to_owned(),
            event_types: event_types.to_vec(),
            active: true,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    fn create_workspace_webhook_destination(
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
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer webhook destination transaction")?;
        let tenant_id = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1
                   AND workspace_memberships.role = 'owner'",
                params![workspace_id, principal_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .context("failed to authorize customer webhook destination")?
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        transaction
            .execute(
                "INSERT INTO tenant_webhook_destinations
                    (id, tenant_id, url, event_types_json, active, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                params![id, &tenant_id.1, url, event_types_json, now],
            )
            .context("failed to create customer webhook destination")?;
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, 'webhook_destination.create', NULL, ?4)",
                params![&tenant_id.0, workspace_id, principal_id, now],
            )
            .context("failed to audit customer webhook destination creation")?;
        transaction
            .commit()
            .context("failed to commit customer webhook destination")?;
        Ok(WebhookDestination {
            id,
            tenant_id: tenant_id.1,
            url: url.to_owned(),
            event_types: event_types.to_vec(),
            active: true,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    fn list_webhook_destinations(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<WebhookDestination>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, url, event_types_json, active,
                        created_at_unix, updated_at_unix
                 FROM tenant_webhook_destinations
                 WHERE tenant_id = ?1 ORDER BY id ASC",
            )
            .context("failed to prepare webhook destination query")?;
        let result = statement
            .query_map([tenant_id], webhook_destination_from_sqlite_row)
            .context("failed to query webhook destinations")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read webhook destinations");
        result
    }

    fn deactivate_webhook_destination(
        &self,
        tenant_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        let changed = self.connection()?.execute(
            "UPDATE tenant_webhook_destinations
                 SET active = 0, updated_at_unix = ?3
                 WHERE tenant_id = ?1 AND id = ?2 AND active = 1",
            params![tenant_id, destination_id, now_unix()],
        )?;
        Ok(changed != 0)
    }

    fn deactivate_workspace_webhook_destination(
        &self,
        workspace_id: &str,
        principal_id: &str,
        destination_id: &str,
    ) -> anyhow::Result<bool> {
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer webhook destination revocation")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1
                   AND workspace_memberships.role = 'owner'",
                params![workspace_id, principal_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .context("failed to authorize customer webhook destination revocation")?;
        let Some((organization_id, tenant_id)) = authorized else {
            transaction
                .commit()
                .context("failed to commit denied webhook destination revocation")?;
            return Ok(false);
        };
        let changed = transaction.execute(
            "UPDATE tenant_webhook_destinations
                 SET active = 0, updated_at_unix = ?3
                 WHERE tenant_id = ?1 AND id = ?2 AND active = 1",
            params![tenant_id, destination_id, now],
        )?;
        if changed == 1 {
            transaction
                .execute(
                    "INSERT INTO workspace_admin_audit
                        (organization_id, workspace_id, actor_principal_id, action,
                         target_principal_id, created_at_unix)
                     VALUES (?1, ?2, ?3, 'webhook_destination.deactivate', NULL, ?4)",
                    params![organization_id, workspace_id, principal_id, now],
                )
                .context("failed to audit customer webhook destination revocation")?;
        }
        transaction
            .commit()
            .context("failed to commit customer webhook destination revocation")?;
        Ok(changed != 0)
    }

    fn list_webhook_deliveries(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<WebhookDelivery>> {
        let limit = i64::try_from(limit.clamp(1, 500)).expect("bounded webhook limit fits i64");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, event_id, destination_id, status, attempt_count,
                        next_attempt_at_unix, locked_until_unix, delivered_at_unix,
                        last_http_status, last_error, created_at_unix
                 FROM tenant_webhook_deliveries
                 WHERE tenant_id = ?1 ORDER BY created_at_unix DESC, id DESC LIMIT ?2",
            )
            .context("failed to prepare webhook delivery query")?;
        let result = statement
            .query_map(params![tenant_id, limit], webhook_delivery_from_sqlite_row)
            .context("failed to query webhook deliveries")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read webhook deliveries");
        result
    }

    fn claim_webhook_delivery(&self) -> anyhow::Result<Option<PendingWebhookDelivery>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin webhook claim transaction")?;
        let now = now_unix();
        let pending = transaction
            .query_row(
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
                 WHERE w.active = 1
                   AND ((d.status = 'pending' AND d.next_attempt_at_unix <= ?1)
                     OR (d.status = 'in_flight' AND d.locked_until_unix <= ?1))
                 ORDER BY d.next_attempt_at_unix ASC, d.id ASC LIMIT 1",
                [now],
                pending_webhook_from_sqlite_row,
            )
            .optional()
            .context("failed to claim webhook delivery")?;
        let Some(mut pending) = pending else {
            transaction
                .commit()
                .context("failed to commit empty webhook claim")?;
            return Ok(None);
        };
        let locked_until = now.saturating_add(30);
        transaction
            .execute(
                "UPDATE tenant_webhook_deliveries
                 SET status = 'in_flight', attempt_count = attempt_count + 1,
                     locked_until_unix = ?2
                 WHERE id = ?1",
                params![pending.delivery.id, locked_until],
            )
            .context("failed to lock webhook delivery")?;
        transaction
            .commit()
            .context("failed to commit webhook claim")?;
        pending.delivery.status = WebhookDeliveryStatus::InFlight;
        pending.delivery.attempt_count = pending.delivery.attempt_count.saturating_add(1);
        pending.delivery.locked_until_unix = Some(locked_until);
        Ok(Some(pending))
    }

    fn finish_webhook_delivery(
        &self,
        delivery_id: &str,
        result: WebhookAttemptResult,
    ) -> anyhow::Result<()> {
        let connection = self.connection()?;
        let attempt_count: u32 = connection
            .query_row(
                "SELECT attempt_count FROM tenant_webhook_deliveries WHERE id = ?1",
                [delivery_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| u32::try_from(value).unwrap_or(u32::MAX))
            .unwrap_or(0);
        let now = now_unix();
        let status = if result.error.is_none() {
            WebhookDeliveryStatus::Delivered
        } else if attempt_count >= 8 {
            WebhookDeliveryStatus::Dead
        } else {
            WebhookDeliveryStatus::Pending
        };
        let next_attempt = if matches!(status, WebhookDeliveryStatus::Pending) {
            now.saturating_add(5_i64.saturating_mul(1_i64 << attempt_count.min(10)))
        } else {
            now
        };
        let error = result
            .error
            .map(|error| error.chars().take(512).collect::<String>());
        connection
            .execute(
                "UPDATE tenant_webhook_deliveries
                 SET status = ?2, next_attempt_at_unix = ?3, locked_until_unix = NULL,
                     delivered_at_unix = CASE WHEN ?2 = 'delivered' THEN ?4 ELSE delivered_at_unix END,
                     last_http_status = ?5, last_error = ?6
                 WHERE id = ?1",
                params![
                    delivery_id,
                    status.storage_value(),
                    next_attempt,
                    now,
                    result.http_status.map(i64::from),
                    error,
                ],
            )
            .context("failed to update webhook delivery result")?;
        Ok(())
    }

    pub fn simulate_policy_version(
        &self,
        tenant_id: &str,
        version_id: &str,
        cases: Vec<PolicySimulationCase>,
    ) -> anyhow::Result<TenantPolicySimulation> {
        let candidate = self
            .policy_version(tenant_id, version_id)?
            .ok_or_else(|| anyhow::anyhow!("policy version not found"))?;
        let active_version_id = {
            let connection = self.connection()?;
            connection
                .query_row(
                    "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = ?1",
                    [tenant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .context("failed to load active policy state")?
        };
        let active_document = active_version_id
            .as_deref()
            .map(|active_id| self.policy_version(tenant_id, active_id))
            .transpose()?
            .flatten()
            .map(|version| version.document);
        let fallback_document = if active_document.is_none() {
            self.model_policy_for(tenant_id)?
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

    pub fn model_policy_for(&self, tenant_id: &str) -> anyhow::Result<Option<TenantModelPolicy>> {
        self.connection()?
            .query_row(
                "SELECT allowed_models_json FROM tenant_model_policies WHERE tenant_id = ?1",
                [tenant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to load tenant model policy")?
            .map(|encoded| {
                serde_json::from_str::<TenantModelPolicy>(&encoded)
                    .context("stored tenant model policy is invalid")
            })
            .transpose()
    }

    /// Replace or clear the tenant's exact model allowlist. Passing `None`
    /// removes the policy and restores the operator-level model behaviour.
    pub fn set_model_policy(
        &self,
        tenant_id: &str,
        policy: Option<TenantModelPolicy>,
    ) -> anyhow::Result<()> {
        const ACTOR_ID: &str = "internal_control_plane";
        let version =
            self.create_policy_version(tenant_id, ACTOR_ID, TenantPolicyDocument::new(policy))?;
        self.approve_policy_version(tenant_id, &version.id, ACTOR_ID)?;
        self.deploy_policy_version(
            tenant_id,
            &version.id,
            ACTOR_ID,
            PolicyDeploymentAction::Activate,
        )?;
        Ok(())
    }

    pub fn set_workspace_model_policy(
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
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer model policy transaction")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                   AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize customer model policy mutation")?
            .filter(|(_, _, role)| role.permits(WorkspacePermission::ApprovePolicies))
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        let next_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_versions WHERE tenant_id = ?1",
                [&authorized.1],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate customer policy sequence")?;
        transaction
            .execute(
                "INSERT INTO tenant_policy_versions
                    (id, tenant_id, sequence, document_json, content_sha256,
                     created_by, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &version_id,
                    &authorized.1,
                    next_sequence,
                    &document_json,
                    &content_sha256,
                    principal_id,
                    now,
                ],
            )
            .context("failed to append customer policy version")?;
        transaction
            .execute(
                "INSERT INTO tenant_policy_approvals
                    (version_id, approved_by, approved_at_unix)
                 VALUES (?1, ?2, ?3)",
                params![&version_id, principal_id, now],
            )
            .context("failed to approve customer policy version")?;
        let previous_version_id = transaction
            .query_row(
                "SELECT active_version_id FROM tenant_policy_state WHERE tenant_id = ?1",
                [&authorized.1],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to load active customer policy version")?;
        if let Some(encoded) = encoded_policy {
            transaction
                .execute(
                    "INSERT INTO tenant_model_policies
                        (tenant_id, allowed_models_json, updated_at_unix)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        allowed_models_json = excluded.allowed_models_json,
                        updated_at_unix = excluded.updated_at_unix",
                    params![&authorized.1, encoded, now],
                )
                .context("failed to save customer model policy")?;
        } else {
            transaction
                .execute(
                    "DELETE FROM tenant_model_policies WHERE tenant_id = ?1",
                    [&authorized.1],
                )
                .context("failed to clear customer model policy")?;
        }
        transaction
            .execute(
                "INSERT INTO tenant_policy_state (tenant_id, active_version_id, updated_at_unix)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                    active_version_id = excluded.active_version_id,
                    updated_at_unix = excluded.updated_at_unix",
                params![&authorized.1, &version_id, now],
            )
            .context("failed to update active customer policy version")?;
        let deployment_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_policy_deployments WHERE tenant_id = ?1",
                [&authorized.1],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate customer policy deployment sequence")?;
        let deployment = TenantPolicyDeployment {
            id: deployment_id,
            tenant_id: authorized.1.clone(),
            sequence: u64::try_from(deployment_sequence)
                .context("customer policy deployment sequence is invalid")?,
            version_id: version_id.clone(),
            previous_version_id: previous_version_id.clone(),
            action: PolicyDeploymentAction::Activate,
            actor_id: principal_id.to_owned(),
            created_at_unix: now,
        };
        transaction
            .execute(
                "INSERT INTO tenant_policy_deployments
                    (id, tenant_id, sequence, version_id, previous_version_id, action,
                     actor_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'activate', ?6, ?7)",
                params![
                    &deployment.id,
                    &deployment.tenant_id,
                    deployment.sequence,
                    &deployment.version_id,
                    &deployment.previous_version_id,
                    &deployment.actor_id,
                    deployment.created_at_unix,
                ],
            )
            .context("failed to append customer policy deployment")?;
        let (event_json, event_sha256) = canonical_security_event_payload(
            "policy.deployed",
            &policy_deployment_security_payload(&deployment),
        )?;
        let event_id = random_id("security_event");
        let event_sequence = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1
                 FROM tenant_security_events WHERE tenant_id = ?1",
                [&deployment.tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .context("failed to allocate customer security event sequence")?;
        transaction
            .execute(
                "INSERT INTO tenant_security_events
                    (id, tenant_id, sequence, event_type, payload_json,
                     content_sha256, occurred_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &event_id,
                    &deployment.tenant_id,
                    event_sequence,
                    "policy.deployed",
                    &event_json,
                    &event_sha256,
                    now,
                ],
            )
            .context("failed to append customer policy security event")?;
        let destinations = transaction
            .prepare(
                "SELECT id, event_types_json FROM tenant_webhook_destinations
                 WHERE tenant_id = ?1 AND active = 1",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([&deployment.tenant_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()
            })
            .context("failed to list webhook destinations for delivery")?;
        for (destination_id, event_types_json) in destinations {
            let event_types: Vec<String> = serde_json::from_str(&event_types_json)
                .context("stored webhook event subscriptions are invalid")?;
            if !event_types
                .iter()
                .any(|event_type| event_type == "policy.deployed")
            {
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO tenant_webhook_deliveries
                        (id, tenant_id, event_id, destination_id, status,
                         attempt_count, next_attempt_at_unix, created_at_unix)
                     VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5)
                     ON CONFLICT(event_id, destination_id) DO NOTHING",
                    params![
                        random_id("webhook_delivery"),
                        &deployment.tenant_id,
                        event_id,
                        destination_id,
                        now,
                    ],
                )
                .context("failed to enqueue webhook delivery")?;
        }
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![&authorized.0, workspace_id, principal_id, audit_action, now],
            )
            .context("failed to append customer model policy audit event")?;
        transaction
            .commit()
            .context("failed to commit customer model policy transaction")?;
        Ok(())
    }

    /// Append privacy-safe request metadata. Prompt text, provider keys, model
    /// responses, and raw client tokens never enter this table.
    pub fn append_audit(
        &self,
        tenant_id: &str,
        path: &str,
        outcome: &str,
        status_code: u16,
        latency_ms: u64,
    ) -> anyhow::Result<()> {
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin tenant audit write")?;
        transaction
            .execute(
                "INSERT INTO tenant_audit
                    (tenant_id, created_at_unix, path, outcome, status_code, latency_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    tenant_id,
                    now_unix(),
                    path,
                    outcome,
                    status_code,
                    latency_ms
                ],
            )
            .context("failed to append tenant audit event")?;
        transaction
            .execute(
                "DELETE FROM tenant_audit
                 WHERE id <= COALESCE(
                    (SELECT id FROM tenant_audit ORDER BY id DESC LIMIT 1 OFFSET ?1),
                    -1
                 )",
                [self.audit_max_rows],
            )
            .context("failed to prune tenant audit history")?;
        transaction
            .commit()
            .context("failed to commit tenant audit event")?;
        Ok(())
    }

    pub fn list_audit(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TenantAuditEvent>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, created_at_unix, path, outcome, status_code, latency_ms
                 FROM tenant_audit WHERE tenant_id = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .context("failed to prepare tenant audit query")?;
        let events = statement
            .query_map(params![tenant_id, limit.clamp(1, 500)], |row| {
                Ok(TenantAuditEvent {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    created_at_unix: row.get(2)?,
                    path: row.get(3)?,
                    outcome: row.get(4)?,
                    status_code: row.get(5)?,
                    latency_ms: row.get(6)?,
                })
            })
            .context("failed to query tenant audit history")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read tenant audit history")?;
        Ok(events)
    }

    pub fn append_usage_event(&self, event: &NewUsageEvent) -> anyhow::Result<bool> {
        validate_usage_event(event)?;
        let input_tokens = optional_database_integer(event.input_tokens, "input token count")?;
        let output_tokens = optional_database_integer(event.output_tokens, "output token count")?;
        let input_price =
            optional_database_integer(event.input_usd_micros_per_million, "input model price")?;
        let output_price =
            optional_database_integer(event.output_usd_micros_per_million, "output model price")?;
        let cost = optional_database_integer(event.cost_usd_micros, "usage cost")?;
        let connection = self.connection()?;
        let inserted = connection
            .execute(
                "INSERT INTO usage_events
                    (tenant_id, request_id, provider_response_id, provider, path,
                     requested_model, provider_model,
                     input_tokens, output_tokens, token_status, pricing_status,
                     model_price_version, input_usd_micros_per_million,
                     output_usd_micros_per_million, cost_usd_micros, created_at_unix)
                 VALUES
                    (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(tenant_id, request_id) DO NOTHING",
                params![
                    &event.tenant_id,
                    &event.request_id,
                    &event.provider_response_id,
                    &event.provider,
                    &event.path,
                    &event.requested_model,
                    &event.provider_model,
                    input_tokens,
                    output_tokens,
                    usage_token_status_storage_value(event.token_status),
                    usage_pricing_status_storage_value(event.pricing_status),
                    &event.model_price_version,
                    input_price,
                    output_price,
                    cost,
                    event.created_at_unix,
                ],
            )
            .context("failed to append immutable usage event")?;
        Ok(inserted == 1)
    }

    pub fn list_usage_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageEvent>> {
        let limit = i64::try_from(limit.clamp(1, 500))
            .expect("bounded usage-event limit fits in a SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, request_id, provider_response_id, provider, path, requested_model,
                        provider_model, input_tokens, output_tokens, token_status,
                        pricing_status, model_price_version, input_usd_micros_per_million,
                        output_usd_micros_per_million, cost_usd_micros, created_at_unix
                 FROM usage_events WHERE tenant_id = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .context("failed to prepare usage-event query")?;
        let events = statement
            .query_map(params![tenant_id, limit], usage_event_from_sqlite_row)
            .context("failed to query usage events")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read usage events")?;
        Ok(events)
    }

    pub fn usage_report(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
    ) -> anyhow::Result<UsageReport> {
        validate_usage_text(tenant_id, "usage tenant ID", 256)?;
        validate_usage_range(from_unix, until_unix)?;
        let connection = self.connection()?;
        let totals = connection
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
                        COALESCE(SUM(cost_usd_micros), 0)
                 FROM usage_events
                 WHERE tenant_id = ?1 AND created_at_unix >= ?2 AND created_at_unix < ?3",
                params![tenant_id, from_unix, until_unix],
                |row| usage_totals_from_sqlite_row(row, 0),
            )
            .context("failed to aggregate usage totals")?;

        let mut daily_statement = connection
            .prepare(
                "SELECT (created_at_unix / 86400) * 86400 AS day_start_unix,
                        COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
                        COALESCE(SUM(cost_usd_micros), 0)
                 FROM usage_events
                 WHERE tenant_id = ?1 AND created_at_unix >= ?2 AND created_at_unix < ?3
                 GROUP BY day_start_unix ORDER BY day_start_unix ASC",
            )
            .context("failed to prepare daily usage aggregation")?;
        let daily = daily_statement
            .query_map(params![tenant_id, from_unix, until_unix], |row| {
                Ok(DailyUsageAggregate {
                    day_start_unix: row.get(0)?,
                    totals: usage_totals_from_sqlite_row(row, 1)?,
                })
            })
            .context("failed to aggregate daily usage")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read daily usage aggregation")?;

        let mut model_statement = connection
            .prepare(
                "SELECT provider, requested_model, COUNT(*),
                        COALESCE(SUM(CASE WHEN token_status = 'actual' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN token_status = 'missing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'priced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN pricing_status = 'unpriced' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN provider_response_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
                        COALESCE(SUM(cost_usd_micros), 0)
                 FROM usage_events
                 WHERE tenant_id = ?1 AND created_at_unix >= ?2 AND created_at_unix < ?3
                 GROUP BY provider, requested_model ORDER BY provider ASC, requested_model ASC",
            )
            .context("failed to prepare model usage aggregation")?;
        let models = model_statement
            .query_map(params![tenant_id, from_unix, until_unix], |row| {
                Ok(ModelUsageAggregate {
                    provider: row.get(0)?,
                    requested_model: row.get(1)?,
                    totals: usage_totals_from_sqlite_row(row, 2)?,
                })
            })
            .context("failed to aggregate model usage")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read model usage aggregation")?;

        let ready_events: u64 = nonnegative_sqlite_integer(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM usage_events AS event
                     WHERE event.tenant_id = ?1
                       AND event.created_at_unix >= ?2 AND event.created_at_unix < ?3
                       AND event.provider_response_id IS NOT NULL
                       AND event.token_status = 'actual' AND event.pricing_status = 'priced'
                       AND NOT EXISTS (
                         SELECT 1 FROM usage_events AS duplicate
                         WHERE duplicate.tenant_id = event.tenant_id
                           AND duplicate.provider = event.provider
                           AND duplicate.provider_response_id = event.provider_response_id
                           AND duplicate.id <> event.id
                       )",
                    params![tenant_id, from_unix, until_unix],
                    |row| row.get(0),
                )
                .context("failed to aggregate reconciliation-ready events")?,
        )?;
        let (duplicate_groups, duplicate_events) = connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(range_event_count), 0)
                 FROM (
                    SELECT event.provider, event.provider_response_id,
                           COUNT(*) AS range_event_count
                    FROM usage_events AS event
                    WHERE event.tenant_id = ?1
                      AND event.created_at_unix >= ?2 AND event.created_at_unix < ?3
                      AND event.provider_response_id IS NOT NULL
                      AND EXISTS (
                        SELECT 1 FROM usage_events AS duplicate
                        WHERE duplicate.tenant_id = event.tenant_id
                          AND duplicate.provider = event.provider
                          AND duplicate.provider_response_id = event.provider_response_id
                          AND duplicate.id <> event.id
                      )
                    GROUP BY event.provider, event.provider_response_id
                 )",
                params![tenant_id, from_unix, until_unix],
                |row| {
                    Ok((
                        nonnegative_sqlite_integer(row.get(0)?)?,
                        nonnegative_sqlite_integer(row.get(1)?)?,
                    ))
                },
            )
            .context("failed to find duplicate provider response IDs")?;
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

    pub fn list_usage_events_range(
        &self,
        tenant_id: &str,
        from_unix: i64,
        until_unix: i64,
        after_id: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<UsageEventPage> {
        validate_usage_text(tenant_id, "usage tenant ID", 256)?;
        validate_usage_range(from_unix, until_unix)?;
        if after_id.is_some_and(|value| value < 0) {
            bail!("usage event cursor is invalid");
        }
        let limit = limit.clamp(1, 1_000);
        let query_limit = i64::try_from(limit + 1)
            .expect("bounded usage-event export limit fits in a SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, request_id, provider_response_id, provider, path,
                        requested_model, provider_model, input_tokens, output_tokens, token_status,
                        pricing_status, model_price_version, input_usd_micros_per_million,
                        output_usd_micros_per_million, cost_usd_micros, created_at_unix
                 FROM usage_events
                 WHERE tenant_id = ?1 AND created_at_unix >= ?2 AND created_at_unix < ?3
                   AND id > COALESCE(?4, 0)
                 ORDER BY id ASC LIMIT ?5",
            )
            .context("failed to prepare usage-event export query")?;
        let mut events = statement
            .query_map(
                params![tenant_id, from_unix, until_unix, after_id, query_limit],
                usage_event_from_sqlite_row,
            )
            .context("failed to query usage-event export")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read usage-event export")?;
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

    pub fn import_usage_reconciliation(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        import: &NewUsageReconciliationImport,
    ) -> anyhow::Result<UsageReconciliationRun> {
        validate_usage_text(tenant_id, "reconciliation tenant ID", 256)?;
        validate_usage_text(actor_admin_id, "reconciliation actor admin ID", 256)?;
        let statement_hash = validate_usage_reconciliation_import(import)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .context("failed to begin usage reconciliation transaction")?;

        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, source, statement_id, actor_admin_id, record_count,
                        matched_count, mismatched_count, orphan_count, ambiguous_count,
                        created_at_unix, statement_hash
                 FROM usage_reconciliation_runs
                 WHERE tenant_id = ?1 AND source = ?2 AND statement_id = ?3",
                params![tenant_id, &import.source, &import.statement_id],
                |row| {
                    Ok((
                        usage_reconciliation_run_from_sqlite_row(row)?,
                        row.get::<_, Vec<u8>>(11)?,
                    ))
                },
            )
            .optional()
            .context("failed to find existing usage reconciliation run")?;
        if let Some((run, existing_hash)) = existing {
            if existing_hash.as_slice() != statement_hash {
                bail!("reconciliation statement ID was already used with different content");
            }
            return Ok(run);
        }

        let mut match_statement = transaction
            .prepare(
                "SELECT id, input_tokens, output_tokens, cost_usd_micros
                 FROM usage_events
                 WHERE tenant_id = ?1 AND provider = ?2 AND provider_response_id = ?3
                 ORDER BY id ASC LIMIT 2",
            )
            .context("failed to prepare usage reconciliation matching query")?;
        let mut evaluations = Vec::with_capacity(import.records.len());
        let mut matched_count = 0_u32;
        let mut mismatched_count = 0_u32;
        let mut orphan_count = 0_u32;
        let mut ambiguous_count = 0_u32;
        for record in &import.records {
            let local = match_statement
                .query_map(
                    params![tenant_id, &record.provider, &record.provider_response_id],
                    |row| {
                        Ok(UsageReconciliationCandidate {
                            id: row.get(0)?,
                            input_tokens: optional_u64_from_sqlite(row.get(1)?)?,
                            output_tokens: optional_u64_from_sqlite(row.get(2)?)?,
                            cost_usd_micros: optional_u64_from_sqlite(row.get(3)?)?,
                        })
                    },
                )
                .context("failed to match usage reconciliation record")?
                .collect::<Result<Vec<_>, _>>()
                .context("failed to read usage reconciliation candidates")?;
            let (usage_event_id, status) = evaluate_usage_reconciliation(record, &local);
            match status {
                UsageReconciliationStatus::Matched => matched_count += 1,
                UsageReconciliationStatus::Mismatched => mismatched_count += 1,
                UsageReconciliationStatus::Orphan => orphan_count += 1,
                UsageReconciliationStatus::Ambiguous => ambiguous_count += 1,
            }
            evaluations.push((record, usage_event_id, status));
        }
        drop(match_statement);

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
        transaction
            .execute(
                "INSERT INTO usage_reconciliation_runs
                    (id, tenant_id, source, statement_id, statement_hash, actor_admin_id,
                     record_count, matched_count, mismatched_count, orphan_count, ambiguous_count,
                     created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    &run.id,
                    &run.tenant_id,
                    &run.source,
                    &run.statement_id,
                    &statement_hash[..],
                    &run.actor_admin_id,
                    i64::from(run.record_count),
                    i64::from(run.matched_count),
                    i64::from(run.mismatched_count),
                    i64::from(run.orphan_count),
                    i64::from(run.ambiguous_count),
                    run.created_at_unix,
                ],
            )
            .context("failed to append usage reconciliation run")?;
        let mut insert_observation = transaction
            .prepare(
                "INSERT INTO usage_reconciliation_observations
                    (run_id, tenant_id, source_record_id, usage_event_id, provider,
                     provider_response_id, input_tokens, output_tokens, cost_usd_micros,
                     status, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .context("failed to prepare usage reconciliation observation insert")?;
        for (record, usage_event_id, status) in evaluations {
            insert_observation
                .execute(params![
                    &run.id,
                    tenant_id,
                    &record.source_record_id,
                    usage_event_id,
                    &record.provider,
                    &record.provider_response_id,
                    optional_database_integer(record.input_tokens, "reconciliation input tokens")?,
                    optional_database_integer(
                        record.output_tokens,
                        "reconciliation output tokens"
                    )?,
                    optional_database_integer(record.cost_usd_micros, "reconciliation cost")?,
                    status.storage_value(),
                    run.created_at_unix,
                ])
                .context("failed to append usage reconciliation observation")?;
        }
        drop(insert_observation);
        transaction
            .commit()
            .context("failed to commit usage reconciliation import")?;
        Ok(run)
    }

    pub fn list_usage_reconciliation_runs(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationRun>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded reconciliation-run limit fits in a SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, source, statement_id, actor_admin_id, record_count,
                        matched_count, mismatched_count, orphan_count, ambiguous_count,
                        created_at_unix
                 FROM usage_reconciliation_runs
                 WHERE tenant_id = ?1 ORDER BY created_at_unix DESC, id DESC LIMIT ?2",
            )
            .context("failed to prepare usage reconciliation run query")?;
        let runs = statement
            .query_map(
                params![tenant_id, limit],
                usage_reconciliation_run_from_sqlite_row,
            )
            .context("failed to query usage reconciliation runs")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read usage reconciliation runs")?;
        Ok(runs)
    }

    pub fn list_usage_reconciliation_observations(
        &self,
        tenant_id: &str,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageReconciliationObservation>> {
        let limit = i64::try_from(limit.clamp(1, 1_000))
            .expect("bounded reconciliation-observation limit fits in a SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT observation.id, observation.run_id, observation.tenant_id,
                        observation.source_record_id, observation.usage_event_id,
                        observation.provider, observation.provider_response_id,
                        observation.input_tokens, observation.output_tokens,
                        observation.cost_usd_micros, observation.status,
                        observation.created_at_unix
                 FROM usage_reconciliation_observations AS observation
                 JOIN usage_reconciliation_runs AS run ON run.id = observation.run_id
                 WHERE observation.tenant_id = ?1 AND observation.run_id = ?2
                   AND run.tenant_id = ?1
                 ORDER BY observation.id ASC LIMIT ?3",
            )
            .context("failed to prepare usage reconciliation observation query")?;
        let observations = statement
            .query_map(
                params![tenant_id, run_id, limit],
                usage_reconciliation_observation_from_sqlite_row,
            )
            .context("failed to query usage reconciliation observations")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read usage reconciliation observations")?;
        Ok(observations)
    }

    pub fn usage_retention_policy(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<UsageRetentionPolicy>> {
        self.connection()?
            .query_row(
                "SELECT retention_days FROM usage_retention_policies WHERE tenant_id = ?1",
                [tenant_id],
                |row| {
                    Ok(UsageRetentionPolicy {
                        retention_days: nonnegative_sqlite_u32(row.get(0)?)?,
                    })
                },
            )
            .optional()
            .context("failed to load usage retention policy")
    }

    pub fn set_usage_retention_policy(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageRetentionPolicy>,
    ) -> anyhow::Result<()> {
        validate_usage_text(actor_id, "retention actor ID", 256)?;
        if let Some(policy) = &policy {
            validate_usage_retention_policy(policy)?;
        }
        let connection = self.connection()?;
        let tenant_exists = connection
            .query_row("SELECT 1 FROM tenants WHERE id = ?1", [tenant_id], |_| {
                Ok(())
            })
            .optional()
            .context("failed to look up tenant for usage retention policy")?
            .is_some();
        if !tenant_exists {
            bail!("tenant not found");
        }
        match policy {
            Some(policy) => connection
                .execute(
                    "INSERT INTO usage_retention_policies
                        (tenant_id, retention_days, updated_by, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        retention_days = excluded.retention_days,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix",
                    params![tenant_id, policy.retention_days, actor_id, now_unix()],
                )
                .context("failed to save usage retention policy")?,
            None => connection
                .execute(
                    "DELETE FROM usage_retention_policies WHERE tenant_id = ?1",
                    [tenant_id],
                )
                .context("failed to clear usage retention policy")?,
        };
        Ok(())
    }

    pub fn set_workspace_usage_retention_policy(
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
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer usage retention transaction")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1 AND organizations.active = 1
                   AND tenants.active = 1 AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize customer usage retention mutation")?
            .filter(|(_, _, role)| role.permits(WorkspacePermission::ManageBilling))
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        if let Some(policy) = policy {
            transaction
                .execute(
                    "INSERT INTO usage_retention_policies
                        (tenant_id, retention_days, updated_by, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        retention_days = excluded.retention_days,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix",
                    params![&authorized.1, policy.retention_days, principal_id, now],
                )
                .context("failed to save customer usage retention policy")?;
        } else {
            transaction
                .execute(
                    "DELETE FROM usage_retention_policies WHERE tenant_id = ?1",
                    [&authorized.1],
                )
                .context("failed to clear customer usage retention policy")?;
        }
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![&authorized.0, workspace_id, principal_id, action, now],
            )
            .context("failed to append customer usage retention audit event")?;
        transaction
            .commit()
            .context("failed to commit customer usage retention transaction")?;
        Ok(())
    }

    pub fn run_usage_retention(
        &self,
        tenant_id: &str,
        actor_admin_id: &str,
        execute: bool,
    ) -> anyhow::Result<UsageRetentionRun> {
        validate_usage_text(actor_admin_id, "retention actor ID", 256)?;
        let now = now_unix();
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin usage retention transaction")?;
        let retention_days: u32 = transaction
            .query_row(
                "SELECT retention_days FROM usage_retention_policies WHERE tenant_id = ?1",
                [tenant_id],
                |row| nonnegative_sqlite_u32(row.get(0)?),
            )
            .optional()
            .context("failed to load usage retention policy")?
            .ok_or_else(|| anyhow::anyhow!("usage retention policy is not configured"))?;
        let policy_cutoff = usage_retention_cutoff(now, retention_days)?;
        let (current_month_start, _) = current_utc_month_range(now)?;
        let cutoff_unix = policy_cutoff.min(current_month_start);
        let aggregate = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(input_tokens), 0),
                        COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cost_usd_micros), 0)
                 FROM usage_events AS event
                 WHERE event.tenant_id = ?1 AND event.created_at_unix < ?2
                   AND NOT EXISTS (
                     SELECT 1 FROM usage_reconciliation_observations AS observation
                     WHERE observation.usage_event_id = event.id
                   )",
                params![tenant_id, cutoff_unix],
                |row| {
                    Ok((
                        nonnegative_sqlite_integer(row.get(0)?)?,
                        nonnegative_sqlite_integer(row.get(1)?)?,
                        nonnegative_sqlite_integer(row.get(2)?)?,
                        nonnegative_sqlite_integer(row.get(3)?)?,
                    ))
                },
            )
            .context("failed to inspect usage retention eligibility")?;
        let protected_reconciliation_event_count = nonnegative_sqlite_integer(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM usage_events AS event
                     WHERE event.tenant_id = ?1 AND event.created_at_unix < ?2
                       AND EXISTS (
                         SELECT 1 FROM usage_reconciliation_observations AS observation
                         WHERE observation.usage_event_id = event.id
                       )",
                    params![tenant_id, cutoff_unix],
                    |row| row.get(0),
                )
                .context("failed to count reconciliation-protected usage events")?,
        )?;
        let deleted_event_count = if execute {
            let deleted = transaction
                .execute(
                    "DELETE FROM usage_events AS event
                     WHERE event.tenant_id = ?1 AND event.created_at_unix < ?2
                       AND NOT EXISTS (
                         SELECT 1 FROM usage_reconciliation_observations AS observation
                         WHERE observation.usage_event_id = event.id
                       )",
                    params![tenant_id, cutoff_unix],
                )
                .context("failed to purge eligible usage events")?;
            u64::try_from(deleted).context("deleted usage-event count exceeds supported range")?
        } else {
            0
        };
        if execute && deleted_event_count != aggregate.0 {
            bail!("usage retention deletion count changed unexpectedly");
        }
        let run = UsageRetentionRun {
            id: random_id("usage_retention"),
            tenant_id: tenant_id.to_owned(),
            actor_admin_id: actor_admin_id.to_owned(),
            retention_days,
            cutoff_unix,
            executed: execute,
            eligible_event_count: aggregate.0,
            protected_reconciliation_event_count,
            eligible_input_tokens: aggregate.1,
            eligible_output_tokens: aggregate.2,
            eligible_cost_usd_micros: aggregate.3,
            deleted_event_count,
            created_at_unix: now,
        };
        transaction
            .execute(
                "INSERT INTO usage_retention_runs
                    (id, tenant_id, actor_admin_id, retention_days, cutoff_unix, executed,
                     eligible_event_count, protected_reconciliation_event_count,
                     eligible_input_tokens, eligible_output_tokens, eligible_cost_usd_micros,
                     deleted_event_count, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    &run.id,
                    &run.tenant_id,
                    &run.actor_admin_id,
                    run.retention_days,
                    run.cutoff_unix,
                    run.executed,
                    optional_database_integer(
                        Some(run.eligible_event_count),
                        "eligible event count"
                    )?,
                    optional_database_integer(
                        Some(run.protected_reconciliation_event_count),
                        "protected event count"
                    )?,
                    optional_database_integer(
                        Some(run.eligible_input_tokens),
                        "eligible input tokens"
                    )?,
                    optional_database_integer(
                        Some(run.eligible_output_tokens),
                        "eligible output tokens"
                    )?,
                    optional_database_integer(
                        Some(run.eligible_cost_usd_micros),
                        "eligible usage cost"
                    )?,
                    optional_database_integer(
                        Some(run.deleted_event_count),
                        "deleted event count"
                    )?,
                    run.created_at_unix,
                ],
            )
            .context("failed to append usage retention run")?;
        transaction
            .commit()
            .context("failed to commit usage retention run")?;
        Ok(run)
    }

    pub fn list_usage_retention_runs(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<UsageRetentionRun>> {
        let limit = i64::try_from(limit.clamp(1, 100))
            .expect("bounded retention-run limit fits in a SQLite integer");
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, tenant_id, actor_admin_id, retention_days, cutoff_unix, executed,
                        eligible_event_count, protected_reconciliation_event_count,
                        eligible_input_tokens, eligible_output_tokens, eligible_cost_usd_micros,
                        deleted_event_count, created_at_unix
                 FROM usage_retention_runs
                 WHERE tenant_id = ?1 ORDER BY created_at_unix DESC, id DESC LIMIT ?2",
            )
            .context("failed to prepare usage retention run query")?;
        let runs = statement
            .query_map(
                params![tenant_id, limit],
                usage_retention_run_from_sqlite_row,
            )
            .context("failed to query usage retention runs")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to read usage retention runs")?;
        Ok(runs)
    }

    pub fn usage_quota_policy(&self, tenant_id: &str) -> anyhow::Result<Option<UsageQuotaPolicy>> {
        self.connection()?
            .query_row(
                "SELECT request_limit, token_limit, cost_usd_micros_limit,
                        alert_threshold_basis_points
                 FROM usage_quota_policies WHERE tenant_id = ?1",
                [tenant_id],
                usage_quota_policy_from_sqlite_row,
            )
            .optional()
            .context("failed to load usage quota policy")
    }

    pub fn set_usage_quota_policy(
        &self,
        tenant_id: &str,
        actor_id: &str,
        policy: Option<UsageQuotaPolicy>,
    ) -> anyhow::Result<()> {
        validate_usage_text(actor_id, "quota actor ID", 256)?;
        if let Some(policy) = &policy {
            validate_usage_quota_policy(policy)?;
        }
        let connection = self.connection()?;
        let tenant_exists = connection
            .query_row("SELECT 1 FROM tenants WHERE id = ?1", [tenant_id], |_| {
                Ok(())
            })
            .optional()
            .context("failed to look up tenant for usage quota policy")?
            .is_some();
        if !tenant_exists {
            bail!("tenant not found");
        }
        if let Some(policy) = policy {
            connection
                .execute(
                    "INSERT INTO usage_quota_policies
                        (tenant_id, request_limit, token_limit, cost_usd_micros_limit,
                         alert_threshold_basis_points, updated_by, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        request_limit = excluded.request_limit,
                        token_limit = excluded.token_limit,
                        cost_usd_micros_limit = excluded.cost_usd_micros_limit,
                        alert_threshold_basis_points = excluded.alert_threshold_basis_points,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix",
                    params![
                        tenant_id,
                        optional_database_integer(policy.request_limit, "request quota")?,
                        optional_database_integer(policy.token_limit, "token quota")?,
                        optional_database_integer(policy.cost_usd_micros_limit, "cost quota")?,
                        policy.alert_threshold_basis_points,
                        actor_id,
                        now_unix(),
                    ],
                )
                .context("failed to save usage quota policy")?;
        } else {
            connection
                .execute(
                    "DELETE FROM usage_quota_policies WHERE tenant_id = ?1",
                    [tenant_id],
                )
                .context("failed to clear usage quota policy")?;
        }
        Ok(())
    }

    pub fn set_workspace_usage_quota_policy(
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
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .context("failed to begin customer usage quota transaction")?;
        let authorized = transaction
            .query_row(
                "SELECT workspaces.organization_id, workspaces.tenant_id, workspace_memberships.role
                 FROM workspaces
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN workspace_principals ON workspace_principals.id = ?2
                 JOIN workspace_memberships
                   ON workspace_memberships.workspace_id = workspaces.id
                  AND workspace_memberships.principal_id = workspace_principals.id
                 WHERE workspaces.id = ?1
                   AND workspaces.active = 1 AND organizations.active = 1
                   AND tenants.active = 1 AND workspace_principals.active = 1
                   AND workspace_memberships.active = 1",
                params![workspace_id, principal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        WorkspaceRole::from_storage(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .context("failed to authorize customer usage quota mutation")?
            .filter(|(_, _, role)| role.permits(WorkspacePermission::ManageBilling))
            .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))?;
        if let Some(policy) = policy {
            transaction
                .execute(
                    "INSERT INTO usage_quota_policies
                        (tenant_id, request_limit, token_limit, cost_usd_micros_limit,
                         alert_threshold_basis_points, updated_by, updated_at_unix)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(tenant_id) DO UPDATE SET
                        request_limit = excluded.request_limit,
                        token_limit = excluded.token_limit,
                        cost_usd_micros_limit = excluded.cost_usd_micros_limit,
                        alert_threshold_basis_points = excluded.alert_threshold_basis_points,
                        updated_by = excluded.updated_by,
                        updated_at_unix = excluded.updated_at_unix",
                    params![
                        &authorized.1,
                        optional_database_integer(policy.request_limit, "request quota")?,
                        optional_database_integer(policy.token_limit, "token quota")?,
                        optional_database_integer(policy.cost_usd_micros_limit, "cost quota")?,
                        policy.alert_threshold_basis_points,
                        principal_id,
                        now,
                    ],
                )
                .context("failed to save customer usage quota policy")?;
        } else {
            transaction
                .execute(
                    "DELETE FROM usage_quota_policies WHERE tenant_id = ?1",
                    [&authorized.1],
                )
                .context("failed to clear customer usage quota policy")?;
        }
        transaction
            .execute(
                "INSERT INTO workspace_admin_audit
                    (organization_id, workspace_id, actor_principal_id, action,
                     target_principal_id, created_at_unix)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![&authorized.0, workspace_id, principal_id, action, now],
            )
            .context("failed to append customer usage quota audit event")?;
        transaction
            .commit()
            .context("failed to commit customer usage quota transaction")?;
        Ok(())
    }

    /// Check a proxy request header against an active tenant token. The raw
    /// credential is hashed locally and never put into an audit/log field.
    pub fn authenticate_bearer(
        &self,
        presented_header: Option<&str>,
    ) -> anyhow::Result<Option<TenantIdentity>> {
        let Some(token) = presented_header.and_then(|value| value.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        if token.is_empty() {
            return Ok(None);
        }
        self.connection()?
            .query_row(
                "SELECT tenants.id, tenants.name
                 FROM tenant_tokens
                 JOIN tenants ON tenants.id = tenant_tokens.tenant_id
                 WHERE tenant_tokens.token_hash = ?1
                   AND tenant_tokens.active = 1
                   AND tenants.active = 1
                 UNION ALL
                 SELECT tenants.id, tenants.name
                 FROM workspace_service_accounts
                 JOIN workspaces ON workspaces.id = workspace_service_accounts.workspace_id
                 JOIN tenants ON tenants.id = workspaces.tenant_id
                 JOIN organizations ON organizations.id = workspaces.organization_id
                 WHERE workspace_service_accounts.token_hash = ?1
                   AND workspace_service_accounts.active = 1
                   AND workspace_service_accounts.expires_at_unix >= ?2
                   AND workspaces.active = 1
                   AND organizations.active = 1
                   AND tenants.active = 1
                 LIMIT 1",
                params![token_hash(token), now_unix()],
                |row| {
                    Ok(TenantIdentity {
                        tenant_id: row.get(0)?,
                        tenant_name: row.get(1)?,
                    })
                },
            )
            .optional()
            .context("failed to authenticate tenant token")
    }

    fn connection(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SQLite tenant store is not enabled"))?
            .lock()
            .map_err(|_| anyhow::anyhow!("tenant database mutex unavailable"))
    }
}

fn validate_usage_event(event: &NewUsageEvent) -> anyhow::Result<()> {
    validate_usage_text(&event.tenant_id, "usage tenant ID", 256)?;
    validate_usage_text(&event.request_id, "usage request ID", 256)?;
    if let Some(provider_response_id) = &event.provider_response_id {
        validate_usage_text(provider_response_id, "provider response ID", 256)?;
    }
    if !matches!(event.provider.as_str(), "openai" | "anthropic") {
        bail!("usage provider is unsupported");
    }
    validate_usage_text(&event.path, "usage request path", 128)?;
    validate_usage_text(&event.requested_model, "usage requested model", 256)?;
    if let Some(provider_model) = &event.provider_model {
        validate_usage_text(provider_model, "usage provider model", 256)?;
    }
    if event.created_at_unix < 0 {
        bail!("usage event timestamp is invalid");
    }

    let tokens_present = event.input_tokens.is_some() && event.output_tokens.is_some();
    if event.input_tokens.is_some() != event.output_tokens.is_some()
        || matches!(event.token_status, UsageTokenStatus::Actual) != tokens_present
    {
        bail!("usage token status does not match token evidence");
    }

    let prices_present = event.model_price_version.is_some()
        && event.input_usd_micros_per_million.is_some()
        && event.output_usd_micros_per_million.is_some();
    if event.model_price_version.is_some() != event.input_usd_micros_per_million.is_some()
        || event.model_price_version.is_some() != event.output_usd_micros_per_million.is_some()
    {
        bail!("usage model-price metadata is incomplete");
    }
    if let Some(version) = &event.model_price_version {
        validate_usage_text(version, "usage model-price version", 128)?;
    }
    let priced = matches!(event.pricing_status, UsagePricingStatus::Priced);
    if priced != (tokens_present && prices_present && event.cost_usd_micros.is_some())
        || (!priced && event.cost_usd_micros.is_some())
    {
        bail!("usage pricing status does not match pricing evidence");
    }

    optional_database_integer(event.input_tokens, "input token count")?;
    optional_database_integer(event.output_tokens, "output token count")?;
    optional_database_integer(event.input_usd_micros_per_million, "input model price")?;
    optional_database_integer(event.output_usd_micros_per_million, "output model price")?;
    optional_database_integer(event.cost_usd_micros, "usage cost")?;
    Ok(())
}

fn validate_usage_range(from_unix: i64, until_unix: i64) -> anyhow::Result<()> {
    const MAX_RANGE_SECONDS: i64 = 366 * 24 * 60 * 60;
    if from_unix < 0 || until_unix <= from_unix {
        bail!("usage time range is invalid");
    }
    if until_unix - from_unix > MAX_RANGE_SECONDS {
        bail!("usage time range cannot exceed 366 days");
    }
    Ok(())
}

fn validate_usage_retention_policy(policy: &UsageRetentionPolicy) -> anyhow::Result<()> {
    if !(30..=3_650).contains(&policy.retention_days) {
        bail!("usage retention must be between 30 and 3650 days");
    }
    Ok(())
}

fn usage_retention_cutoff(now: i64, retention_days: u32) -> anyhow::Result<i64> {
    validate_usage_retention_policy(&UsageRetentionPolicy { retention_days })?;
    now.checked_sub(i64::from(retention_days) * 86_400)
        .ok_or_else(|| anyhow::anyhow!("usage retention cutoff is outside the supported range"))
}

fn default_usage_quota_alert_threshold_basis_points() -> u16 {
    8_000
}

fn validate_usage_quota_policy(policy: &UsageQuotaPolicy) -> anyhow::Result<()> {
    if policy.request_limit.is_none()
        && policy.token_limit.is_none()
        && policy.cost_usd_micros_limit.is_none()
    {
        bail!("usage quota policy requires at least one limit");
    }
    if !(1..=10_000).contains(&policy.alert_threshold_basis_points) {
        bail!("usage quota alert threshold must be between 1 and 10000 basis points");
    }
    for (value, field) in [
        (policy.request_limit, "request quota"),
        (policy.token_limit, "token quota"),
        (policy.cost_usd_micros_limit, "cost quota"),
    ] {
        if value == Some(0) {
            bail!("{field} must be positive");
        }
        optional_database_integer(value, field)?;
    }
    Ok(())
}

fn evaluate_usage_quota(
    policy: UsageQuotaPolicy,
    report: &UsageReport,
) -> anyhow::Result<UsageQuotaStatus> {
    validate_usage_quota_policy(&policy)?;
    let threshold = policy.alert_threshold_basis_points;
    let requests = policy
        .request_limit
        .map(|limit| usage_quota_metric(report.totals.request_count, limit, threshold, true));
    let tokens_used = report
        .totals
        .input_tokens
        .checked_add(report.totals.output_tokens)
        .ok_or_else(|| anyhow::anyhow!("usage token total exceeds supported range"))?;
    let tokens = policy.token_limit.map(|limit| {
        usage_quota_metric(
            tokens_used,
            limit,
            threshold,
            report.totals.missing_token_events == 0,
        )
    });
    let cost_usd_micros = policy.cost_usd_micros_limit.map(|limit| {
        usage_quota_metric(
            report.totals.priced_cost_usd_micros,
            limit,
            threshold,
            report.totals.unpriced_events == 0,
        )
    });
    let attention_required = [&requests, &tokens, &cost_usd_micros]
        .into_iter()
        .flatten()
        .any(|metric| metric.state != UsageQuotaState::Ok);
    Ok(UsageQuotaStatus {
        from_unix: report.from_unix,
        until_unix: report.until_unix,
        policy,
        requests,
        tokens,
        cost_usd_micros,
        missing_token_events: report.totals.missing_token_events,
        unpriced_events: report.totals.unpriced_events,
        attention_required,
    })
}

fn usage_quota_metric(
    used: u64,
    limit: u64,
    threshold_basis_points: u16,
    evidence_complete: bool,
) -> UsageQuotaMetricStatus {
    let state = if used >= limit {
        UsageQuotaState::Exceeded
    } else if !evidence_complete {
        UsageQuotaState::EvidenceIncomplete
    } else if u128::from(used) * 10_000 >= u128::from(limit) * u128::from(threshold_basis_points) {
        UsageQuotaState::Threshold
    } else {
        UsageQuotaState::Ok
    };
    UsageQuotaMetricStatus { used, limit, state }
}

/// Return the current UTC calendar month as a half-open Unix interval without
/// depending on a locale or host timezone.
fn current_utc_month_range(now_unix: i64) -> anyhow::Result<(i64, i64)> {
    if now_unix < 0 {
        bail!("system clock is before the Unix epoch");
    }
    let days = now_unix / 86_400;
    let (year, month, _) = civil_from_days(days);
    let start_days = days_from_civil(year, month, 1);
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let next_days = days_from_civil(next_year, next_month, 1);
    Ok((
        start_days
            .checked_mul(86_400)
            .ok_or_else(|| anyhow::anyhow!("UTC month start exceeds supported range"))?,
        next_days
            .checked_mul(86_400)
            .ok_or_else(|| anyhow::anyhow!("UTC month end exceeds supported range"))?,
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn validate_usage_reconciliation_import(
    import: &NewUsageReconciliationImport,
) -> anyhow::Result<[u8; 32]> {
    validate_usage_text(&import.source, "reconciliation source", 128)?;
    validate_usage_text(&import.statement_id, "reconciliation statement ID", 256)?;
    if import.records.is_empty() || import.records.len() > 1_000 {
        bail!("reconciliation import must contain between 1 and 1000 records");
    }
    let mut seen = std::collections::HashSet::with_capacity(import.records.len());
    for record in &import.records {
        validate_usage_text(
            &record.source_record_id,
            "reconciliation source record ID",
            256,
        )?;
        if !seen.insert(record.source_record_id.as_str()) {
            bail!("reconciliation source record IDs must be unique");
        }
        if !matches!(record.provider.as_str(), "openai" | "anthropic") {
            bail!("reconciliation provider is unsupported");
        }
        validate_usage_text(
            &record.provider_response_id,
            "reconciliation provider response ID",
            256,
        )?;
        if record.input_tokens.is_some() != record.output_tokens.is_some() {
            bail!("reconciliation token evidence must contain both input and output counters");
        }
        if record.input_tokens.is_none() && record.cost_usd_micros.is_none() {
            bail!("reconciliation record requires token or cost evidence");
        }
        optional_database_integer(record.input_tokens, "reconciliation input token count")?;
        optional_database_integer(record.output_tokens, "reconciliation output token count")?;
        optional_database_integer(record.cost_usd_micros, "reconciliation cost")?;
    }

    let mut records = import.records.iter().collect::<Vec<_>>();
    records.sort_by(|left, right| left.source_record_id.cmp(&right.source_record_id));
    let mut hash = Sha256::new();
    hash.update(b"llm-firewall/usage-reconciliation/v1\0");
    hash_reconciliation_text(&mut hash, &import.source);
    hash_reconciliation_text(&mut hash, &import.statement_id);
    hash.update((records.len() as u64).to_be_bytes());
    for record in records {
        hash_reconciliation_text(&mut hash, &record.source_record_id);
        hash_reconciliation_text(&mut hash, &record.provider);
        hash_reconciliation_text(&mut hash, &record.provider_response_id);
        hash_reconciliation_optional_u64(&mut hash, record.input_tokens);
        hash_reconciliation_optional_u64(&mut hash, record.output_tokens);
        hash_reconciliation_optional_u64(&mut hash, record.cost_usd_micros);
    }
    Ok(hash.finalize().into())
}

fn hash_reconciliation_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn hash_reconciliation_optional_u64(hash: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
}

fn evaluate_usage_reconciliation(
    record: &NewUsageReconciliationRecord,
    local: &[UsageReconciliationCandidate],
) -> (Option<i64>, UsageReconciliationStatus) {
    let [local] = local else {
        return if local.is_empty() {
            (None, UsageReconciliationStatus::Orphan)
        } else {
            (None, UsageReconciliationStatus::Ambiguous)
        };
    };
    let tokens_match = match (record.input_tokens, record.output_tokens) {
        (Some(input), Some(output)) => {
            local.input_tokens == Some(input) && local.output_tokens == Some(output)
        }
        (None, None) => true,
        _ => false,
    };
    let cost_matches = record
        .cost_usd_micros
        .is_none_or(|cost| local.cost_usd_micros == Some(cost));
    (
        Some(local.id),
        if tokens_match && cost_matches {
            UsageReconciliationStatus::Matched
        } else {
            UsageReconciliationStatus::Mismatched
        },
    )
}

fn validate_usage_text(value: &str, field: &str, max_bytes: usize) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        bail!("{field} is invalid");
    }
    Ok(())
}

fn optional_database_integer(value: Option<u64>, field: &str) -> anyhow::Result<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value).with_context(|| format!("{field} exceeds database range"))
        })
        .transpose()
}

fn policy_version_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TenantPolicyVersion> {
    let encoded = row.get::<_, String>(3)?;
    let document =
        serde_json::from_str::<TenantPolicyDocument>(&encoded).map_err(|error_value| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error_value),
            )
        })?;
    Ok(TenantPolicyVersion {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        sequence: nonnegative_sqlite_integer(row.get(2)?)?,
        document,
        content_sha256: row.get(4)?,
        created_by: row.get(5)?,
        created_at_unix: row.get(6)?,
        approved_by: row.get(7)?,
        approved_at_unix: row.get(8)?,
        active: row.get::<_, i64>(9)? != 0,
    })
}

fn policy_deployment_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TenantPolicyDeployment> {
    Ok(TenantPolicyDeployment {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        sequence: nonnegative_sqlite_integer(row.get(2)?)?,
        version_id: row.get(3)?,
        previous_version_id: row.get(4)?,
        action: PolicyDeploymentAction::from_storage(&row.get::<_, String>(5)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        actor_id: row.get(6)?,
        created_at_unix: row.get(7)?,
    })
}

fn security_event_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TenantSecurityEvent> {
    let payload_json: String = row.get(4)?;
    let payload = serde_json::from_str(&payload_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(TenantSecurityEvent {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        sequence: nonnegative_sqlite_integer(row.get(2)?)?,
        event_type: row.get(3)?,
        payload,
        content_sha256: row.get(5)?,
        occurred_at_unix: row.get(6)?,
    })
}

fn webhook_destination_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WebhookDestination> {
    let event_types_json: String = row.get(3)?;
    let event_types = serde_json::from_str(&event_types_json).map_err(|error_value| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(error_value),
        )
    })?;
    Ok(WebhookDestination {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        url: row.get(2)?,
        event_types,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
        updated_at_unix: row.get(6)?,
    })
}

fn webhook_delivery_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebhookDelivery> {
    Ok(WebhookDelivery {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        event_id: row.get(2)?,
        destination_id: row.get(3)?,
        status: WebhookDeliveryStatus::from_storage(&row.get::<_, String>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        attempt_count: nonnegative_sqlite_u32(row.get(5)?)?,
        next_attempt_at_unix: row.get(6)?,
        locked_until_unix: row.get(7)?,
        delivered_at_unix: row.get(8)?,
        last_http_status: row
            .get::<_, Option<i64>>(9)?
            .map(|value| u16::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        last_error: row.get(10)?,
        created_at_unix: row.get(11)?,
    })
}

fn pending_webhook_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingWebhookDelivery> {
    let delivery = webhook_delivery_from_sqlite_row(row)?;
    let event_types_json: String = row.get(15)?;
    let event_types = serde_json::from_str(&event_types_json).map_err(|error_value| {
        rusqlite::Error::FromSqlConversionFailure(
            15,
            rusqlite::types::Type::Text,
            Box::new(error_value),
        )
    })?;
    let destination = WebhookDestination {
        id: row.get(12)?,
        tenant_id: row.get(13)?,
        url: row.get(14)?,
        event_types,
        active: row.get::<_, i64>(16)? != 0,
        created_at_unix: row.get(17)?,
        updated_at_unix: row.get(18)?,
    };
    let payload_json: String = row.get(23)?;
    let payload = serde_json::from_str(&payload_json).map_err(|error_value| {
        rusqlite::Error::FromSqlConversionFailure(
            23,
            rusqlite::types::Type::Text,
            Box::new(error_value),
        )
    })?;
    let event = TenantSecurityEvent {
        id: row.get(19)?,
        tenant_id: row.get(20)?,
        sequence: nonnegative_sqlite_integer(row.get(21)?)?,
        event_type: row.get(22)?,
        payload,
        content_sha256: row.get(24)?,
        occurred_at_unix: row.get(25)?,
    };
    Ok(PendingWebhookDelivery {
        delivery,
        destination,
        event,
    })
}

fn usage_event_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageEvent> {
    Ok(UsageEvent {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        request_id: row.get(2)?,
        provider_response_id: row.get(3)?,
        provider: row.get(4)?,
        path: row.get(5)?,
        requested_model: row.get(6)?,
        provider_model: row.get(7)?,
        input_tokens: optional_u64_from_sqlite(row.get(8)?)?,
        output_tokens: optional_u64_from_sqlite(row.get(9)?)?,
        token_status: usage_token_status_from_storage(&row.get::<_, String>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        pricing_status: usage_pricing_status_from_storage(&row.get::<_, String>(11)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        model_price_version: row.get(12)?,
        input_usd_micros_per_million: optional_u64_from_sqlite(row.get(13)?)?,
        output_usd_micros_per_million: optional_u64_from_sqlite(row.get(14)?)?,
        cost_usd_micros: optional_u64_from_sqlite(row.get(15)?)?,
        created_at_unix: row.get(16)?,
    })
}

fn usage_reconciliation_run_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UsageReconciliationRun> {
    Ok(UsageReconciliationRun {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        source: row.get(2)?,
        statement_id: row.get(3)?,
        actor_admin_id: row.get(4)?,
        record_count: nonnegative_sqlite_u32(row.get(5)?)?,
        matched_count: nonnegative_sqlite_u32(row.get(6)?)?,
        mismatched_count: nonnegative_sqlite_u32(row.get(7)?)?,
        orphan_count: nonnegative_sqlite_u32(row.get(8)?)?,
        ambiguous_count: nonnegative_sqlite_u32(row.get(9)?)?,
        created_at_unix: row.get(10)?,
    })
}

fn usage_reconciliation_observation_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UsageReconciliationObservation> {
    Ok(UsageReconciliationObservation {
        id: row.get(0)?,
        run_id: row.get(1)?,
        tenant_id: row.get(2)?,
        source_record_id: row.get(3)?,
        usage_event_id: row.get(4)?,
        provider: row.get(5)?,
        provider_response_id: row.get(6)?,
        input_tokens: optional_u64_from_sqlite(row.get(7)?)?,
        output_tokens: optional_u64_from_sqlite(row.get(8)?)?,
        cost_usd_micros: optional_u64_from_sqlite(row.get(9)?)?,
        status: UsageReconciliationStatus::from_storage(&row.get::<_, String>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        created_at_unix: row.get(11)?,
    })
}

fn usage_retention_run_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UsageRetentionRun> {
    Ok(UsageRetentionRun {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        actor_admin_id: row.get(2)?,
        retention_days: nonnegative_sqlite_u32(row.get(3)?)?,
        cutoff_unix: row.get(4)?,
        executed: row.get(5)?,
        eligible_event_count: nonnegative_sqlite_integer(row.get(6)?)?,
        protected_reconciliation_event_count: nonnegative_sqlite_integer(row.get(7)?)?,
        eligible_input_tokens: nonnegative_sqlite_integer(row.get(8)?)?,
        eligible_output_tokens: nonnegative_sqlite_integer(row.get(9)?)?,
        eligible_cost_usd_micros: nonnegative_sqlite_integer(row.get(10)?)?,
        deleted_event_count: nonnegative_sqlite_integer(row.get(11)?)?,
        created_at_unix: row.get(12)?,
    })
}

fn usage_quota_policy_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UsageQuotaPolicy> {
    Ok(UsageQuotaPolicy {
        request_limit: optional_u64_from_sqlite(row.get(0)?)?,
        token_limit: optional_u64_from_sqlite(row.get(1)?)?,
        cost_usd_micros_limit: optional_u64_from_sqlite(row.get(2)?)?,
        alert_threshold_basis_points: u16::try_from(row.get::<_, i64>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn optional_u64_from_sqlite(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

fn nonnegative_sqlite_integer(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn nonnegative_sqlite_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn usage_totals_from_sqlite_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<UsageTotals> {
    Ok(UsageTotals {
        request_count: nonnegative_sqlite_integer(row.get(offset)?)?,
        actual_token_events: nonnegative_sqlite_integer(row.get(offset + 1)?)?,
        missing_token_events: nonnegative_sqlite_integer(row.get(offset + 2)?)?,
        priced_events: nonnegative_sqlite_integer(row.get(offset + 3)?)?,
        unpriced_events: nonnegative_sqlite_integer(row.get(offset + 4)?)?,
        provider_correlated_events: nonnegative_sqlite_integer(row.get(offset + 5)?)?,
        input_tokens: nonnegative_sqlite_integer(row.get(offset + 6)?)?,
        output_tokens: nonnegative_sqlite_integer(row.get(offset + 7)?)?,
        priced_cost_usd_micros: nonnegative_sqlite_integer(row.get(offset + 8)?)?,
    })
}

fn validate_limits(limits: &TenantLimits) -> anyhow::Result<()> {
    if let Some(rate) = &limits.rate_limit {
        if rate.requests_per_window == 0 || rate.window_seconds == 0 {
            bail!("tenant rate limit requires nonzero requests_per_window and window_seconds");
        }
    }
    if let Some(spend) = &limits.spend_limit {
        if spend.window_seconds == 0
            || spend.max_usd_micros == 0
            || spend.reserve_usd_micros_per_request == 0
        {
            bail!("tenant spend limit requires nonzero window, budget, and reservation");
        }
        if spend.reserve_usd_micros_per_request > spend.max_usd_micros {
            bail!("tenant spend reservation cannot exceed the tenant budget");
        }
    }
    Ok(())
}

fn control_plane_admin_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ControlPlaneAdmin> {
    let role = AdminRole::from_storage(&row.get::<_, String>(2)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(ControlPlaneAdmin {
        id: row.get(0)?,
        name: row.get(1)?,
        role,
        active: row.get::<_, i64>(3)? != 0,
        created_at_unix: row.get(4)?,
    })
}

fn scim_token_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScimToken> {
    Ok(ScimToken {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        label: row.get(2)?,
        active: row.get::<_, i64>(3)? != 0,
        expires_at_unix: row.get(4)?,
        created_at_unix: row.get(5)?,
        revoked_at_unix: row.get(6)?,
    })
}

fn scim_user_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScimUser> {
    Ok(ScimUser {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        external_id: row.get(2)?,
        user_name: row.get(3)?,
        display_name: row.get(4)?,
        active: row.get::<_, i64>(5)? != 0,
        created_at_unix: row.get(6)?,
        updated_at_unix: row.get(7)?,
    })
}

fn scim_group_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScimGroup> {
    Ok(ScimGroup {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        external_id: row.get(2)?,
        display_name: row.get(3)?,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
        updated_at_unix: row.get(6)?,
        member_ids: Vec::new(),
    })
}

fn scim_group_members_from_sqlite_connection(
    connection: &Connection,
    group_id: &str,
) -> anyhow::Result<Vec<String>> {
    let mut statement = connection
        .prepare(
            "SELECT principal_id FROM scim_group_members
             WHERE group_id = ?1 ORDER BY principal_id ASC",
        )
        .context("failed to prepare SCIM group member list")?;
    let members = statement
        .query_map([group_id], |row| row.get(0))
        .context("failed to query SCIM group members")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read SCIM group members")?;
    Ok(members)
}

fn require_active_scim_group_members_sqlite(
    connection: &Connection,
    organization_id: &str,
    member_ids: &[String],
) -> anyhow::Result<()> {
    for principal_id in member_ids {
        let found = connection
            .query_row(
                "SELECT 1 FROM scim_users
                 WHERE id = ?1 AND organization_id = ?2 AND active = 1",
                params![principal_id, organization_id],
                |_| Ok(()),
            )
            .optional()
            .context("failed to validate SCIM group member")?
            .is_some();
        if !found {
            bail!("SCIM group member is not an active user of this organization");
        }
    }
    Ok(())
}

fn workspace_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Workspace> {
    Ok(Workspace {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        tenant_id: row.get(2)?,
        name: row.get(3)?,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
    })
}

fn organization_oidc_connection_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OrganizationOidcConnection> {
    Ok(OrganizationOidcConnection {
        organization_id: row.get(0)?,
        issuer: row.get(1)?,
        client_id: row.get(2)?,
        redirect_uri: row.get(3)?,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
        updated_at_unix: row.get(6)?,
    })
}

fn organization_saml_connection_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OrganizationSamlConnection> {
    Ok(OrganizationSamlConnection {
        organization_id: row.get(0)?,
        entity_id: row.get(1)?,
        metadata_xml: row.get(2)?,
        metadata_signing_cert_pem: row.get(3)?,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
        updated_at_unix: row.get(6)?,
    })
}

fn organization_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Organization> {
    Ok(Organization {
        id: row.get(0)?,
        name: row.get(1)?,
        active: row.get::<_, i64>(2)? != 0,
        created_at_unix: row.get(3)?,
    })
}

fn workspace_principal_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WorkspacePrincipal> {
    Ok(WorkspacePrincipal {
        id: row.get(0)?,
        name: row.get(1)?,
        active: row.get::<_, i64>(2)? != 0,
        created_at_unix: row.get(3)?,
    })
}

fn workspace_membership_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WorkspaceMembership> {
    let role = WorkspaceRole::from_storage(&row.get::<_, String>(2)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(WorkspaceMembership {
        workspace_id: row.get(0)?,
        principal_id: row.get(1)?,
        role,
        active: row.get::<_, i64>(3)? != 0,
        created_at_unix: row.get(4)?,
        updated_at_unix: row.get(5)?,
    })
}

/// Recheck the complete owner boundary inside a mutating SQLite transaction.
/// Returning the organization ID lets callers bind a SCIM group target to the
/// authorized workspace without trusting a browser-supplied organization.
fn authorized_workspace_owner_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    actor_principal_id: &str,
) -> anyhow::Result<String> {
    transaction
        .query_row(
            "SELECT workspaces.organization_id
             FROM workspaces
             JOIN organizations ON organizations.id = workspaces.organization_id
             JOIN tenants ON tenants.id = workspaces.tenant_id
             JOIN workspace_principals ON workspace_principals.id = ?2
             JOIN workspace_memberships
               ON workspace_memberships.workspace_id = workspaces.id
              AND workspace_memberships.principal_id = workspace_principals.id
             WHERE workspaces.id = ?1
               AND workspace_memberships.role = 'owner'
               AND workspace_memberships.active = 1
               AND organizations.active = 1
               AND tenants.active = 1
               AND workspaces.active = 1
               AND workspace_principals.active = 1",
            params![workspace_id, actor_principal_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .context("failed to authorize workspace owner action")?
        .ok_or_else(|| anyhow::anyhow!("customer workspace action is not permitted"))
}

fn workspace_member_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceMember> {
    let role = WorkspaceRole::from_storage(&row.get::<_, String>(3)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(WorkspaceMember {
        workspace_id: row.get(0)?,
        principal_id: row.get(1)?,
        principal_name: row.get(2)?,
        role,
        active: row.get::<_, i64>(4)? != 0,
        created_at_unix: row.get(5)?,
        updated_at_unix: row.get(6)?,
    })
}

fn workspace_invitation_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WorkspaceInvitation> {
    let role = WorkspaceRole::from_storage(&row.get::<_, String>(4)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(WorkspaceInvitation {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        workspace_id: row.get(2)?,
        recipient_label: row.get(3)?,
        role,
        created_by_principal_id: row.get(5)?,
        active: row.get::<_, i64>(6)? != 0,
        expires_at_unix: row.get(7)?,
        created_at_unix: row.get(8)?,
        revoked_at_unix: row.get(9)?,
        accepted_by_principal_id: row.get(10)?,
        accepted_at_unix: row.get(11)?,
    })
}

fn service_account_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceServiceAccount> {
    Ok(WorkspaceServiceAccount {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        name: row.get(2)?,
        created_by_principal_id: row.get(3)?,
        active: row.get::<_, i64>(4)? != 0,
        expires_at_unix: row.get(5)?,
        created_at_unix: row.get(6)?,
        revoked_at_unix: row.get(7)?,
    })
}

fn workspace_admin_audit_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WorkspaceAdminAuditEvent> {
    Ok(WorkspaceAdminAuditEvent {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        workspace_id: row.get(2)?,
        actor_principal_id: row.get(3)?,
        action: row.get(4)?,
        target_principal_id: row.get(5)?,
        created_at_unix: row.get(6)?,
    })
}

fn tenant_token_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TenantToken> {
    Ok(TenantToken {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        label: row.get(2)?,
        active: row.get::<_, i64>(3)? != 0,
        created_at_unix: row.get(4)?,
        revoked_at_unix: row.get(5)?,
    })
}

fn validate_model_policy(policy: &TenantModelPolicy) -> anyhow::Result<()> {
    if policy.allowed_models.len() > 100 {
        bail!("tenant model policy cannot contain more than 100 models");
    }
    let mut seen = std::collections::HashSet::new();
    for model in &policy.allowed_models {
        if model.is_empty() || model.len() > 200 || model.trim() != model {
            bail!("tenant model identifiers must be nonempty, trimmed, and at most 200 bytes");
        }
        if !seen.insert(model) {
            bail!("tenant model policy cannot contain duplicate models");
        }
    }
    Ok(())
}

fn validate_policy_document(document: &TenantPolicyDocument) -> anyhow::Result<()> {
    if document.schema_version != TENANT_POLICY_SCHEMA_VERSION {
        bail!(
            "unsupported tenant policy schema version {}; expected {}",
            document.schema_version,
            TENANT_POLICY_SCHEMA_VERSION
        );
    }
    if let Some(policy) = &document.model_policy {
        validate_model_policy(policy)?;
    }
    Ok(())
}

fn canonical_policy_document(document: &TenantPolicyDocument) -> anyhow::Result<(String, String)> {
    validate_policy_document(document)?;
    let encoded = serde_json::to_string(document).context("failed to encode tenant policy")?;
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-tenant-policy-v1:");
    hasher.update(encoded.as_bytes());
    let digest = hasher.finalize();
    let content_sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((encoded, content_sha256))
}

fn policy_deployment_security_payload(deployment: &TenantPolicyDeployment) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "event_type": "policy.deployed",
        "tenant_id": deployment.tenant_id,
        "deployment_id": deployment.id,
        "deployment_sequence": deployment.sequence,
        "version_id": deployment.version_id,
        "previous_version_id": deployment.previous_version_id,
        "action": deployment.action.storage_value(),
        "actor_id": deployment.actor_id,
        "created_at_unix": deployment.created_at_unix,
    })
}

fn canonical_security_event_payload(
    event_type: &str,
    payload: &serde_json::Value,
) -> anyhow::Result<(String, String)> {
    validate_usage_text(event_type, "security event type", 128)?;
    let encoded = serde_json::to_string(payload).context("failed to encode security event")?;
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-security-event-v1:");
    hasher.update(event_type.as_bytes());
    hasher.update(b":");
    hasher.update(encoded.as_bytes());
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((encoded, content_sha256))
}

fn validate_policy_simulation_cases(cases: &[PolicySimulationCase]) -> anyhow::Result<()> {
    const MAX_CASES: usize = 1_000;
    if cases.is_empty() || cases.len() > MAX_CASES {
        bail!("policy simulation requires between 1 and {MAX_CASES} cases");
    }
    for case in cases {
        validate_usage_text(&case.requested_model, "simulation model", 200)?;
        if case.requested_model.trim() != case.requested_model {
            bail!("simulation model identifiers must be trimmed");
        }
    }
    Ok(())
}

fn policy_document_permits(document: Option<&TenantPolicyDocument>, model: &str) -> bool {
    document
        .and_then(|document| document.model_policy.as_ref())
        .is_none_or(|policy| policy.permits(model))
}

fn evaluate_policy_simulation(
    version_id: String,
    active_version_id: Option<String>,
    current: Option<&TenantPolicyDocument>,
    candidate: &TenantPolicyDocument,
    cases: Vec<PolicySimulationCase>,
) -> anyhow::Result<TenantPolicySimulation> {
    validate_policy_simulation_cases(&cases)?;
    validate_policy_document(candidate)?;
    let results = cases
        .into_iter()
        .map(|case| {
            let current_permitted = policy_document_permits(current, case.requested_model.as_str());
            let candidate_permitted =
                policy_document_permits(Some(candidate), case.requested_model.as_str());
            PolicySimulationResult {
                requested_model: case.requested_model,
                current_permitted,
                candidate_permitted,
                changed: current_permitted != candidate_permitted,
            }
        })
        .collect::<Vec<_>>();
    let changed_count = u64::try_from(results.iter().filter(|result| result.changed).count())
        .expect("simulation case cap fits u64");
    Ok(TenantPolicySimulation {
        version_id,
        active_version_id,
        changed_count,
        results,
    })
}

fn validate_label(value: &str, field: &str, max_len: usize) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{field} cannot be empty");
    }
    if value.len() > max_len {
        bail!("{field} cannot exceed {max_len} bytes");
    }
    Ok(value.to_owned())
}

fn validate_external_identity_component(
    value: &str,
    field: &str,
    max_len: usize,
) -> anyhow::Result<String> {
    if value.is_empty() {
        bail!("{field} cannot be empty");
    }
    if value.len() > max_len {
        bail!("{field} cannot exceed {max_len} bytes");
    }
    if value.chars().any(char::is_control) {
        bail!("{field} cannot contain control characters");
    }
    Ok(value.to_owned())
}

fn validate_scim_user_fields(
    external_id: &str,
    user_name: &str,
    display_name: &str,
) -> anyhow::Result<(String, String, String)> {
    let external_id = validate_external_identity_component(external_id, "SCIM externalId", 512)?;
    let user_name = validate_scim_user_text(user_name, "SCIM userName", 320)?;
    let display_name = validate_scim_user_text(display_name, "SCIM displayName", 256)?;
    Ok((external_id, user_name, display_name))
}

fn validate_scim_user_text(value: &str, field: &str, max_len: usize) -> anyhow::Result<String> {
    let value = validate_external_identity_component(value, field, max_len)?;
    if value.trim() != value {
        bail!("{field} cannot start or end with whitespace");
    }
    Ok(value)
}

fn validate_scim_user_id(value: &str) -> anyhow::Result<String> {
    validate_external_identity_component(value, "SCIM user id", 256)
}

fn validate_scim_user_update(update: ScimUserUpdate) -> anyhow::Result<ScimUserUpdate> {
    if update.user_name.is_none() && update.display_name.is_none() && update.active.is_none() {
        bail!("SCIM user update must change at least one supported attribute");
    }
    Ok(ScimUserUpdate {
        user_name: update
            .user_name
            .as_deref()
            .map(|value| validate_scim_user_text(value, "SCIM userName", 320))
            .transpose()?,
        display_name: update
            .display_name
            .as_deref()
            .map(|value| validate_scim_user_text(value, "SCIM displayName", 256))
            .transpose()?,
        active: update.active,
    })
}

fn validate_scim_group_fields(
    external_id: &str,
    display_name: &str,
) -> anyhow::Result<(String, String)> {
    Ok((
        validate_external_identity_component(external_id, "SCIM group externalId", 512)?,
        validate_scim_user_text(display_name, "SCIM group displayName", 256)?,
    ))
}

fn validate_scim_group_id(value: &str) -> anyhow::Result<String> {
    validate_external_identity_component(value, "SCIM group id", 256)
}

fn validate_scim_group_member_ids(member_ids: Vec<String>) -> anyhow::Result<Vec<String>> {
    const MAX_MEMBERS: usize = 100;
    if member_ids.len() > MAX_MEMBERS {
        bail!("SCIM group cannot contain more than {MAX_MEMBERS} members per request");
    }
    let mut seen = std::collections::HashSet::new();
    member_ids
        .into_iter()
        .map(|member_id| {
            let member_id = validate_scim_user_id(&member_id)?;
            if !seen.insert(member_id.clone()) {
                bail!("SCIM group member IDs cannot be duplicated");
            }
            Ok(member_id)
        })
        .collect()
}

fn validate_scim_group_update(update: ScimGroupUpdate) -> anyhow::Result<ScimGroupUpdate> {
    if update.display_name.is_none() && update.member_change.is_none() {
        bail!("SCIM group update must change a supported attribute");
    }
    let member_change = update
        .member_change
        .map(|change| {
            Ok::<ScimGroupMemberChange, anyhow::Error>(match change {
                ScimGroupMemberChange::Replace(member_ids) => {
                    ScimGroupMemberChange::Replace(validate_scim_group_member_ids(member_ids)?)
                }
                ScimGroupMemberChange::Add(member_ids) => {
                    ScimGroupMemberChange::Add(validate_scim_group_member_ids(member_ids)?)
                }
                ScimGroupMemberChange::Remove(member_ids) => {
                    ScimGroupMemberChange::Remove(validate_scim_group_member_ids(member_ids)?)
                }
            })
        })
        .transpose()?;
    Ok(ScimGroupUpdate {
        display_name: update
            .display_name
            .as_deref()
            .map(|value| validate_scim_user_text(value, "SCIM group displayName", 256))
            .transpose()?,
        member_change,
    })
}

fn validate_scim_page(start_index: usize, count: usize) -> anyhow::Result<()> {
    const MAX_START_INDEX: usize = 1_000_000;
    const MAX_PAGE_SIZE: usize = 100;
    if start_index == 0 || start_index > MAX_START_INDEX {
        bail!("SCIM startIndex must be between 1 and {MAX_START_INDEX}");
    }
    if count > MAX_PAGE_SIZE {
        bail!("SCIM count cannot exceed {MAX_PAGE_SIZE}");
    }
    Ok(())
}

/// OIDC issuer and callback registration are security boundaries: require an
/// absolute HTTPS URI with no embedded credentials, query string, or fragment.
/// The input string is returned unchanged after validation because an OIDC
/// `iss` comparison must be exact; a future verifier must not silently
/// canonicalize it before comparing a signed claim.
fn validate_oidc_https_uri(value: &str, field: &str) -> anyhow::Result<String> {
    let value = validate_external_identity_component(value, field, 2_048)?;
    let uri = Url::parse(&value).map_err(|_| anyhow::anyhow!("{field} must be an absolute URI"))?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        bail!("{field} must be an HTTPS URI without embedded credentials, query, or fragment");
    }
    Ok(value)
}

fn validate_saml_entity_id(value: &str) -> anyhow::Result<String> {
    // EntityIDs may be HTTPS URLs or URNs, but must be stable, bounded and
    // free of control characters. The SAML parser performs the protocol-level
    // URI validation when the connection is used.
    validate_external_identity_component(value.trim(), "SAML IdP entity ID", 2_048)
}

fn validate_saml_metadata(value: &str) -> anyhow::Result<String> {
    const MAX_SAML_METADATA_BYTES: usize = 512 * 1024;
    let value = value.trim();
    if value.is_empty() {
        bail!("SAML metadata cannot be empty");
    }
    if value.len() > MAX_SAML_METADATA_BYTES {
        bail!("SAML metadata cannot exceed {MAX_SAML_METADATA_BYTES} bytes");
    }
    if value.contains("<!DOCTYPE") || value.contains("<!ENTITY") {
        bail!("SAML metadata cannot contain a DTD or external entity");
    }
    if !value.contains("EntityDescriptor") {
        bail!("SAML metadata must contain an EntityDescriptor");
    }
    Ok(value.to_owned())
}

fn validate_saml_certificate(value: &str) -> anyhow::Result<String> {
    const MAX_SAML_CERTIFICATE_BYTES: usize = 16 * 1024;
    let value = value.trim();
    if value.is_empty() {
        bail!("SAML metadata signing certificate cannot be empty");
    }
    if value.len() > MAX_SAML_CERTIFICATE_BYTES {
        bail!("SAML metadata signing certificate cannot exceed {MAX_SAML_CERTIFICATE_BYTES} bytes");
    }
    if !value.contains("-----BEGIN CERTIFICATE-----")
        || !value.contains("-----END CERTIFICATE-----")
    {
        bail!("SAML metadata signing certificate must be PEM encoded");
    }
    Ok(value.to_owned())
}

const WEBHOOK_POLICY_DEPLOYED_EVENT: &str = "policy.deployed";

fn validate_webhook_destination_url(value: &str) -> anyhow::Result<String> {
    let value = validate_oidc_https_uri(value, "webhook URL")?;
    let uri = Url::parse(&value).context("webhook URL is not a valid URI")?;
    let host = uri
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("webhook URL must contain a host"))?;
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.eq_ignore_ascii_case("metadata.google.internal")
        || host.eq_ignore_ascii_case("metadata.google.internal.")
        || host.parse::<IpAddr>().is_ok()
    {
        bail!("webhook URL must use an external DNS hostname, not a local or literal address");
    }
    Ok(value)
}

fn validate_webhook_event_types(event_types: &[String]) -> anyhow::Result<Vec<String>> {
    let values = if event_types.is_empty() {
        vec![WEBHOOK_POLICY_DEPLOYED_EVENT.to_owned()]
    } else {
        event_types.to_vec()
    };
    if values.len() > 16 {
        bail!("a webhook destination cannot subscribe to more than 16 event types");
    }
    let mut validated = Vec::with_capacity(values.len());
    for event_type in values {
        validate_usage_text(&event_type, "webhook event type", 128)?;
        if event_type != WEBHOOK_POLICY_DEPLOYED_EVENT {
            bail!("unsupported webhook event type");
        }
        if !validated.contains(&event_type) {
            validated.push(event_type);
        }
    }
    Ok(validated)
}

fn is_public_socket_address(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.octets().starts_with(&[100, 64])
                && !ip.octets().starts_with(&[192, 0, 0])
                && !ip.octets().starts_with(&[198, 18])
                && !ip.octets().starts_with(&[198, 19])
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
    }
}

async fn resolve_public_webhook_url(url: &str) -> anyhow::Result<(Url, Vec<SocketAddr>)> {
    let parsed = Url::parse(url).context("webhook URL is not a valid URI")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("webhook URL must contain a host"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .context("webhook host could not be resolved")?
        .filter(|address| is_public_socket_address(*address))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("webhook host resolved only to private or local addresses");
    }
    Ok((parsed, addresses))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct PendingWebhookDelivery {
    delivery: WebhookDelivery,
    destination: WebhookDestination,
    event: TenantSecurityEvent,
}

struct WebhookAttemptResult {
    http_status: Option<u16>,
    error: Option<String>,
}

async fn deliver_webhook(
    _base_client: &Client,
    key: &WebhookSigningKey,
    pending: &PendingWebhookDelivery,
) -> WebhookAttemptResult {
    let (url, addresses) = match resolve_public_webhook_url(&pending.destination.url).await {
        Ok(value) => value,
        Err(error_value) => {
            return WebhookAttemptResult {
                http_status: None,
                error: Some(error_value.to_string()),
            };
        }
    };
    let body_value = serde_json::json!({
        "schema_version": 1,
        "event_id": pending.event.id,
        "tenant_id": pending.event.tenant_id,
        "sequence": pending.event.sequence,
        "event_type": pending.event.event_type,
        "payload": pending.event.payload,
        "content_sha256": pending.event.content_sha256,
        "occurred_at_unix": pending.event.occurred_at_unix,
    });
    let body = match serde_json::to_vec(&body_value) {
        Ok(body) => body,
        Err(error_value) => {
            return WebhookAttemptResult {
                http_status: None,
                error: Some(format!("failed to encode webhook body: {error_value}")),
            };
        }
    };
    let signature = match key.signature_for(&pending.destination.id, &body) {
        Ok(signature) => signature,
        Err(error_value) => {
            return WebhookAttemptResult {
                http_status: None,
                error: Some(error_value.to_string()),
            };
        }
    };
    let host = url.host_str().expect("validated webhook URL has a host");
    let client = match Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
    {
        Ok(client) => client,
        Err(error_value) => {
            return WebhookAttemptResult {
                http_status: None,
                error: Some(format!("failed to build webhook client: {error_value}")),
            };
        }
    };
    let response = match client
        .post(url)
        .header("content-type", "application/json")
        .header("x-llm-firewall-event", pending.event.event_type.as_str())
        .header("x-llm-firewall-delivery", pending.delivery.id.as_str())
        .header("x-llm-firewall-signature", signature)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error_value) => {
            return WebhookAttemptResult {
                http_status: None,
                error: Some(format!("webhook request failed: {error_value}")),
            };
        }
    };
    let status = response.status();
    if status.is_success() {
        WebhookAttemptResult {
            http_status: Some(status.as_u16()),
            error: None,
        }
    } else {
        WebhookAttemptResult {
            http_status: Some(status.as_u16()),
            error: Some(format!(
                "webhook endpoint returned HTTP {}",
                status.as_u16()
            )),
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs() as i64
}

fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", random_base64url(16))
}

fn workspace_id_for_tenant(tenant_id: &str) -> String {
    format!("workspace_{tenant_id}")
}

fn generate_token() -> String {
    format!("llmfw_{}", random_base64url(32))
}

fn generate_admin_token() -> String {
    format!("llmfw_admin_{}", random_base64url(32))
}

fn generate_scim_token() -> String {
    format!("llmfw_scim_{}", random_base64url(32))
}

fn generate_service_account_token() -> String {
    format!("llmfw_sa_{}", random_base64url(32))
}

fn generate_workspace_invitation_token() -> String {
    format!("llmfw_invite_{}", random_base64url(32))
}

fn generate_oidc_browser_session_token() -> String {
    random_base64url(32)
}

fn random_base64url(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let value = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        output.push(TABLE[(value & 0x3f) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        0 => {}
        1 => {
            let value = u32::from(bytes[index]) << 16;
            output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let value = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
            output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
            output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        }
        _ => unreachable!("remainder is always below three"),
    }
    output
}

fn token_hash(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-tenant-token-v1:");
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn scim_token_hash(token: &str) -> anyhow::Result<Vec<u8>> {
    let token = validate_external_identity_component(token, "SCIM token", 256)?;
    if !token.starts_with("llmfw_scim_") {
        bail!("invalid SCIM token");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-scim-token-v1:");
    hasher.update(token.as_bytes());
    Ok(hasher.finalize().to_vec())
}

fn workspace_invitation_token_hash(token: &str) -> anyhow::Result<Vec<u8>> {
    let token = validate_external_identity_component(token, "workspace invitation token", 256)?;
    if !token.starts_with("llmfw_invite_") {
        bail!("invalid workspace invitation token");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-workspace-invitation-v1:");
    hasher.update(token.as_bytes());
    Ok(hasher.finalize().to_vec())
}

fn oidc_authorization_state_hash(state: &str) -> anyhow::Result<Vec<u8>> {
    let state = validate_external_identity_component(state, "OIDC state", 8_192)?;
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-oidc-authorization-state-v1:");
    hasher.update(state.as_bytes());
    Ok(hasher.finalize().to_vec())
}

fn oidc_browser_session_hash(token: &str) -> anyhow::Result<Vec<u8>> {
    let token = validate_external_identity_component(token, "OIDC browser session", 256)?;
    let mut hasher = Sha256::new();
    hasher.update(b"llm-firewall-oidc-browser-session-v1:");
    hasher.update(token.as_bytes());
    Ok(hasher.finalize().to_vec())
}

fn validate_service_account_expiry(expires_at_unix: i64) -> anyhow::Result<()> {
    const MAX_LIFETIME_SECONDS: i64 = 366 * 24 * 60 * 60;
    let now = now_unix();
    if expires_at_unix <= now || expires_at_unix > now + MAX_LIFETIME_SECONDS {
        bail!("service-account expiry must be in the next 366 days");
    }
    Ok(())
}

fn validate_workspace_invitation_expiry(expires_at_unix: i64) -> anyhow::Result<()> {
    const MAX_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
    let now = now_unix();
    if expires_at_unix <= now || expires_at_unix > now + MAX_LIFETIME_SECONDS {
        bail!("workspace invitation expiry must be in the next seven days");
    }
    Ok(())
}

fn validate_oidc_authorization_state_expiry(expires_at_unix: i64) -> anyhow::Result<()> {
    const MAX_LIFETIME_SECONDS: i64 = 600;
    let now = now_unix();
    if expires_at_unix <= now || expires_at_unix > now + MAX_LIFETIME_SECONDS {
        bail!(
            "OIDC authorization state expiry must be between one second and ten minutes from now"
        );
    }
    Ok(())
}

fn validate_oidc_browser_session_expiry(expires_at_unix: i64) -> anyhow::Result<()> {
    const MAX_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
    let now = now_unix();
    if expires_at_unix <= now || expires_at_unix > now + MAX_LIFETIME_SECONDS {
        bail!(
            "OIDC browser session expiry must be between one second and twenty-four hours from now"
        );
    }
    Ok(())
}

fn validate_scim_token_expiry(expires_at_unix: i64) -> anyhow::Result<()> {
    const MAX_LIFETIME_SECONDS: i64 = 365 * 24 * 60 * 60;
    let now = now_unix();
    if expires_at_unix <= now || expires_at_unix > now + MAX_LIFETIME_SECONDS {
        bail!("SCIM token expiry must be between one second and one year from now");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::{
        base64url, BrowserSessionFederation, NewUsageEvent, NewUsageReconciliationImport,
        NewUsageReconciliationRecord, PolicyDeploymentAction, PolicySimulationCase,
        SamlAuthorizationPending, TenantLimits, TenantModelPolicy, TenantPolicyDocument,
        TenantRateLimit, TenantSpendLimit, TenantStore, UsagePricingStatus, UsageQuotaPolicy,
        UsageQuotaState, UsageReconciliationStatus, UsageRetentionPolicy, UsageTokenStatus,
        WorkspacePermission, WorkspaceRole,
    };

    fn priced_usage_event(tenant_id: &str, request_id: &str) -> NewUsageEvent {
        NewUsageEvent {
            tenant_id: tenant_id.into(),
            request_id: request_id.into(),
            provider_response_id: Some("resp_test_one".into()),
            provider: "openai".into(),
            path: "/v1/responses".into(),
            requested_model: "gpt-test".into(),
            provider_model: Some("gpt-test-2026-08-01".into()),
            input_tokens: Some(3),
            output_tokens: Some(4),
            token_status: UsageTokenStatus::Actual,
            pricing_status: UsagePricingStatus::Priced,
            model_price_version: Some("sha256:test-price-version".into()),
            input_usd_micros_per_million: Some(1_000_000),
            output_usd_micros_per_million: Some(2_000_000),
            cost_usd_micros: Some(11),
            created_at_unix: super::now_unix(),
        }
    }

    #[tokio::test]
    async fn webhook_destinations_are_secret_once_and_deployments_enqueue_delivery() {
        let store = TenantStore::open(":memory:")
            .unwrap()
            .with_webhook_signing_key_base64url(&base64url(&[7; 32]))
            .unwrap();
        let tenant = store.create_tenant("Webhook tenant").unwrap();
        assert!(
            store
                .create_webhook_destination_async(
                    &tenant.id,
                    "https://hooks.example.test/events",
                    &[]
                )
                .await
                .unwrap()
                .secret
                .len()
                > 20
        );
        assert!(store
            .create_webhook_destination_async(&tenant.id, "https://localhost/events", &[])
            .await
            .is_err());
        let destinations = store
            .list_webhook_destinations_async(&tenant.id)
            .await
            .unwrap();
        assert_eq!(destinations.len(), 1);
        assert!(destinations[0].active);

        let version = store
            .create_policy_version(
                &tenant.id,
                "operator_one",
                TenantPolicyDocument::new(Some(TenantModelPolicy {
                    allowed_models: vec!["gpt-test".into()],
                })),
            )
            .unwrap();
        store
            .approve_policy_version(&tenant.id, &version.id, "owner_one")
            .unwrap();
        store
            .deploy_policy_version(
                &tenant.id,
                &version.id,
                "owner_one",
                PolicyDeploymentAction::Activate,
            )
            .unwrap();
        let deliveries = store
            .list_webhook_deliveries_async(&tenant.id, 100)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status.storage_value(), "pending");
        assert_eq!(deliveries[0].attempt_count, 0);
    }

    #[test]
    fn usage_events_are_idempotent_immutable_and_separate_from_spend_counters() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Usage tenant").unwrap();
        let event = priced_usage_event(&tenant.id, "req_usage_one");
        assert!(store.append_usage_event(&event).unwrap());

        let mut conflicting_retry = event.clone();
        conflicting_retry.cost_usd_micros = Some(999);
        assert!(!store.append_usage_event(&conflicting_retry).unwrap());

        let stored = store.list_usage_events(&tenant.id, 100).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].request_id, "req_usage_one");
        assert_eq!(stored[0].cost_usd_micros, Some(11));
        assert_eq!(
            stored[0].model_price_version.as_deref(),
            Some("sha256:test-price-version")
        );
    }

    #[test]
    fn usage_retention_requires_policy_and_protects_reconciled_evidence() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Retention tenant").unwrap();
        assert!(store
            .run_usage_retention(&tenant.id, "admin_owner", false)
            .is_err());
        assert!(store
            .set_usage_retention_policy(
                &tenant.id,
                "admin_owner",
                Some(UsageRetentionPolicy { retention_days: 29 }),
            )
            .is_err());
        store
            .set_usage_retention_policy(
                &tenant.id,
                "admin_owner",
                Some(UsageRetentionPolicy { retention_days: 30 }),
            )
            .unwrap();

        let old_timestamp = super::now_unix() - 31 * 86_400;
        let mut eligible = priced_usage_event(&tenant.id, "req_retention_eligible");
        eligible.provider_response_id = Some("resp_retention_eligible".into());
        eligible.created_at_unix = old_timestamp;
        store.append_usage_event(&eligible).unwrap();

        let mut protected = priced_usage_event(&tenant.id, "req_retention_protected");
        protected.provider_response_id = Some("resp_retention_protected".into());
        protected.created_at_unix = old_timestamp;
        store.append_usage_event(&protected).unwrap();

        let mut recent = priced_usage_event(&tenant.id, "req_retention_recent");
        recent.provider_response_id = Some("resp_retention_recent".into());
        store.append_usage_event(&recent).unwrap();

        store
            .import_usage_reconciliation(
                &tenant.id,
                "admin_owner",
                &NewUsageReconciliationImport {
                    source: "provider-statement".into(),
                    statement_id: "statement-retention".into(),
                    records: vec![NewUsageReconciliationRecord {
                        source_record_id: "line-protected".into(),
                        provider: "openai".into(),
                        provider_response_id: "resp_retention_protected".into(),
                        input_tokens: Some(3),
                        output_tokens: Some(4),
                        cost_usd_micros: Some(11),
                    }],
                },
            )
            .unwrap();

        let dry_run = store
            .run_usage_retention(&tenant.id, "admin_owner", false)
            .unwrap();
        assert!(!dry_run.executed);
        assert_eq!(dry_run.eligible_event_count, 1);
        assert_eq!(dry_run.protected_reconciliation_event_count, 1);
        assert_eq!(dry_run.deleted_event_count, 0);
        assert_eq!(store.list_usage_events(&tenant.id, 10).unwrap().len(), 3);

        let execution = store
            .run_usage_retention(&tenant.id, "admin_owner", true)
            .unwrap();
        assert!(execution.executed);
        assert_eq!(execution.eligible_event_count, 1);
        assert_eq!(execution.deleted_event_count, 1);
        let remaining = store.list_usage_events(&tenant.id, 10).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining
            .iter()
            .any(|event| event.request_id == "req_retention_protected"));
        assert!(remaining
            .iter()
            .any(|event| event.request_id == "req_retention_recent"));
        assert_eq!(
            store
                .list_usage_retention_runs(&tenant.id, 10)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn only_customer_owner_can_change_usage_retention_policy() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store.create_organization("Retention customer").unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "Retention workspace")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store.create_workspace_principal("Retention owner").unwrap();
        let admin = store.create_workspace_principal("Retention admin").unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &admin.id, WorkspaceRole::Admin)
            .unwrap();
        let policy = Some(UsageRetentionPolicy { retention_days: 90 });
        assert!(store
            .set_workspace_usage_retention_policy(&workspace.id, &admin.id, policy.clone())
            .is_err());
        store
            .set_workspace_usage_retention_policy(&workspace.id, &owner.id, policy.clone())
            .unwrap();
        assert_eq!(store.usage_retention_policy(&tenant.id).unwrap(), policy);
        let audit = store.list_workspace_admin_audit(&workspace.id, 10).unwrap();
        assert_eq!(audit[0].action, "usage_retention_policy.set");
        assert_eq!(
            audit[0].actor_principal_id.as_deref(),
            Some(owner.id.as_str())
        );
    }

    #[tokio::test]
    async fn utc_month_range_and_quota_alerts_are_exact_and_evidence_aware() {
        assert_eq!(super::current_utc_month_range(0).unwrap(), (0, 31 * 86_400));
        assert_eq!(
            super::current_utc_month_range(1_707_955_200).unwrap(),
            (1_706_745_600, 1_709_251_200)
        );

        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Quota tenant").unwrap();
        let policy = UsageQuotaPolicy {
            request_limit: Some(2),
            token_limit: Some(10),
            cost_usd_micros_limit: Some(20),
            alert_threshold_basis_points: 5_000,
        };
        store
            .set_usage_quota_policy(&tenant.id, "admin_owner", Some(policy.clone()))
            .unwrap();
        let mut actual = priced_usage_event(&tenant.id, "req_quota_actual");
        actual.provider_response_id = Some("resp_quota_actual".into());
        store.append_usage_event(&actual).unwrap();
        let status = store
            .usage_quota_status_async(&tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.policy, policy);
        assert_eq!(status.requests.unwrap().state, UsageQuotaState::Threshold);
        assert_eq!(status.tokens.unwrap().state, UsageQuotaState::Threshold);
        assert_eq!(
            status.cost_usd_micros.unwrap().state,
            UsageQuotaState::Threshold
        );
        assert!(status.attention_required);

        let mut missing = priced_usage_event(&tenant.id, "req_quota_missing");
        missing.provider_response_id = None;
        missing.input_tokens = None;
        missing.output_tokens = None;
        missing.token_status = UsageTokenStatus::Missing;
        missing.pricing_status = UsagePricingStatus::Unpriced;
        missing.cost_usd_micros = None;
        store.append_usage_event(&missing).unwrap();
        let status = store
            .usage_quota_status_async(&tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.requests.unwrap().state, UsageQuotaState::Exceeded);
        assert_eq!(
            status.tokens.unwrap().state,
            UsageQuotaState::EvidenceIncomplete
        );
        assert_eq!(
            status.cost_usd_micros.unwrap().state,
            UsageQuotaState::EvidenceIncomplete
        );
        assert_eq!(status.missing_token_events, 1);
        assert_eq!(status.unpriced_events, 1);
    }

    #[test]
    fn only_customer_owner_can_change_usage_quota_policy() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store.create_organization("Quota customer").unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "Quota workspace")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store.create_workspace_principal("Quota owner").unwrap();
        let admin = store.create_workspace_principal("Quota admin").unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &admin.id, WorkspaceRole::Admin)
            .unwrap();
        let policy = Some(UsageQuotaPolicy {
            request_limit: Some(1_000),
            token_limit: None,
            cost_usd_micros_limit: Some(50_000_000),
            alert_threshold_basis_points: 8_000,
        });
        assert!(store
            .set_workspace_usage_quota_policy(&workspace.id, &admin.id, policy.clone())
            .is_err());
        store
            .set_workspace_usage_quota_policy(&workspace.id, &owner.id, policy.clone())
            .unwrap();
        assert_eq!(store.usage_quota_policy(&tenant.id).unwrap(), policy);
        let audit = store.list_workspace_admin_audit(&workspace.id, 10).unwrap();
        assert_eq!(audit[0].action, "usage_quota_policy.set");
    }

    #[test]
    fn usage_reporting_preserves_quality_gaps_and_exports_with_a_cursor() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Reporting tenant").unwrap();

        let mut first = priced_usage_event(&tenant.id, "req_report_one");
        first.created_at_unix = 172_800;
        assert!(store.append_usage_event(&first).unwrap());

        let mut duplicate_provider_response = first.clone();
        duplicate_provider_response.request_id = "req_report_two".into();
        assert!(store
            .append_usage_event(&duplicate_provider_response)
            .unwrap());

        let mut missing = first.clone();
        missing.request_id = "req_report_three".into();
        missing.provider_response_id = None;
        missing.input_tokens = None;
        missing.output_tokens = None;
        missing.token_status = UsageTokenStatus::Missing;
        missing.pricing_status = UsagePricingStatus::Unpriced;
        missing.cost_usd_micros = None;
        assert!(store.append_usage_event(&missing).unwrap());

        let report = store.usage_report(&tenant.id, 86_400, 259_200).unwrap();
        assert_eq!(report.totals.request_count, 3);
        assert_eq!(report.totals.actual_token_events, 2);
        assert_eq!(report.totals.missing_token_events, 1);
        assert_eq!(report.totals.priced_events, 2);
        assert_eq!(report.totals.unpriced_events, 1);
        assert_eq!(report.totals.provider_correlated_events, 2);
        assert_eq!(report.totals.input_tokens, 6);
        assert_eq!(report.totals.output_tokens, 8);
        assert_eq!(report.totals.priced_cost_usd_micros, 22);
        assert_eq!(report.daily.len(), 1);
        assert_eq!(report.daily[0].day_start_unix, 172_800);
        assert_eq!(report.models.len(), 1);
        assert_eq!(report.reconciliation.ready_events, 0);
        assert_eq!(report.reconciliation.review_required_events, 3);
        assert_eq!(report.reconciliation.missing_provider_response_id_events, 1);
        assert_eq!(
            report.reconciliation.duplicate_provider_response_id_groups,
            1
        );
        assert_eq!(
            report.reconciliation.duplicate_provider_response_id_events,
            2
        );

        let first_page = store
            .list_usage_events_range(&tenant.id, 86_400, 259_200, None, 2)
            .unwrap();
        assert_eq!(first_page.events.len(), 2);
        let cursor = first_page.next_after_id.expect("a third event remains");
        let second_page = store
            .list_usage_events_range(&tenant.id, 86_400, 259_200, Some(cursor), 2)
            .unwrap();
        assert_eq!(second_page.events.len(), 1);
        assert!(second_page.next_after_id.is_none());
        assert_eq!(second_page.events[0].request_id, "req_report_three");
    }

    #[test]
    fn reconciliation_import_is_immutable_idempotent_and_classifies_every_record() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Reconciliation tenant").unwrap();
        let other_tenant = store.create_tenant("Other tenant").unwrap();

        let mut matched = priced_usage_event(&tenant.id, "req_reconcile_matched");
        matched.provider_response_id = Some("resp_matched".into());
        assert!(store.append_usage_event(&matched).unwrap());

        let mut mismatched = priced_usage_event(&tenant.id, "req_reconcile_mismatched");
        mismatched.provider_response_id = Some("resp_mismatched".into());
        assert!(store.append_usage_event(&mismatched).unwrap());

        let mut duplicate_one = priced_usage_event(&tenant.id, "req_reconcile_duplicate_one");
        duplicate_one.provider_response_id = Some("resp_duplicate".into());
        assert!(store.append_usage_event(&duplicate_one).unwrap());
        let mut duplicate_two = duplicate_one.clone();
        duplicate_two.request_id = "req_reconcile_duplicate_two".into();
        assert!(store.append_usage_event(&duplicate_two).unwrap());

        let import = NewUsageReconciliationImport {
            source: "provider-export".into(),
            statement_id: "statement-2026-08".into(),
            records: vec![
                NewUsageReconciliationRecord {
                    source_record_id: "record-matched".into(),
                    provider: "openai".into(),
                    provider_response_id: "resp_matched".into(),
                    input_tokens: Some(3),
                    output_tokens: Some(4),
                    cost_usd_micros: Some(11),
                },
                NewUsageReconciliationRecord {
                    source_record_id: "record-mismatched".into(),
                    provider: "openai".into(),
                    provider_response_id: "resp_mismatched".into(),
                    input_tokens: Some(30),
                    output_tokens: Some(40),
                    cost_usd_micros: Some(11),
                },
                NewUsageReconciliationRecord {
                    source_record_id: "record-ambiguous".into(),
                    provider: "openai".into(),
                    provider_response_id: "resp_duplicate".into(),
                    input_tokens: Some(3),
                    output_tokens: Some(4),
                    cost_usd_micros: None,
                },
                NewUsageReconciliationRecord {
                    source_record_id: "record-orphan".into(),
                    provider: "openai".into(),
                    provider_response_id: "resp_missing_locally".into(),
                    input_tokens: None,
                    output_tokens: None,
                    cost_usd_micros: Some(99),
                },
            ],
        };
        let run = store
            .import_usage_reconciliation(&tenant.id, "bootstrap_owner", &import)
            .unwrap();
        assert_eq!(run.record_count, 4);
        assert_eq!(run.matched_count, 1);
        assert_eq!(run.mismatched_count, 1);
        assert_eq!(run.orphan_count, 1);
        assert_eq!(run.ambiguous_count, 1);

        let mut reordered = import.clone();
        reordered.records.reverse();
        let replay = store
            .import_usage_reconciliation(&tenant.id, "another_operator", &reordered)
            .unwrap();
        assert_eq!(
            replay, run,
            "record ordering does not alter statement identity"
        );
        assert_eq!(
            store
                .list_usage_reconciliation_runs(&tenant.id, 10)
                .unwrap(),
            vec![run.clone()]
        );
        assert!(store
            .list_usage_reconciliation_runs(&other_tenant.id, 10)
            .unwrap()
            .is_empty());

        let observations = store
            .list_usage_reconciliation_observations(&tenant.id, &run.id, 10)
            .unwrap();
        assert_eq!(observations.len(), 4);
        assert!(observations.iter().any(|observation| {
            observation.status == UsageReconciliationStatus::Matched
                && observation.usage_event_id.is_some()
        }));
        assert!(observations.iter().any(|observation| {
            observation.status == UsageReconciliationStatus::Mismatched
                && observation.usage_event_id.is_some()
        }));
        assert!(observations.iter().any(|observation| {
            observation.status == UsageReconciliationStatus::Ambiguous
                && observation.usage_event_id.is_none()
        }));
        assert!(observations.iter().any(|observation| {
            observation.status == UsageReconciliationStatus::Orphan
                && observation.usage_event_id.is_none()
        }));

        let mut conflicting = import;
        conflicting.records[0].cost_usd_micros = Some(12);
        assert!(store
            .import_usage_reconciliation(&tenant.id, "bootstrap_owner", &conflicting)
            .is_err());
    }

    #[tokio::test]
    async fn failed_usage_write_stays_visible_to_readiness() {
        let store = TenantStore::open(":memory:").unwrap();
        let event = priced_usage_event("missing_tenant", "req_usage_failure");

        assert!(store.append_usage_event_async(&event).await.is_err());
        assert_eq!(store.usage_ledger_status().failed_events, 1);
    }

    #[test]
    fn issued_token_authenticates_then_revocation_takes_effect() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Acme").unwrap();
        let issued = store.issue_token(&tenant.id, "production").unwrap();
        let header = format!("Bearer {}", issued.token);

        assert_eq!(
            store.authenticate_bearer(Some(&header)).unwrap(),
            Some(super::TenantIdentity {
                tenant_id: tenant.id,
                tenant_name: "Acme".into(),
            })
        );
        assert!(store.revoke_token(&issued.id).unwrap());
        assert_eq!(store.authenticate_bearer(Some(&header)).unwrap(), None);
        assert!(!store.revoke_token(&issued.id).unwrap());
    }

    #[test]
    fn scim_tokens_are_organization_scoped_expiring_and_revocable() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store.create_organization("SCIM organization").unwrap();
        let issued = store
            .issue_scim_token(
                &organization.id,
                "identity-provider",
                super::now_unix() + 3_600,
            )
            .unwrap();
        assert!(issued.token.starts_with("llmfw_scim_"));
        let header = format!("Bearer {}", issued.token);
        assert_eq!(
            store.authenticate_scim_bearer(Some(&header)).unwrap(),
            Some(super::ScimIdentity {
                organization_id: organization.id.clone(),
                token_id: issued.credential.id.clone(),
            })
        );
        let inventory = store.list_scim_tokens(&organization.id).unwrap();
        assert_eq!(inventory, vec![issued.credential.clone()]);
        assert!(store
            .issue_scim_token(&organization.id, "expired", super::now_unix())
            .is_err());
        assert!(store.revoke_scim_token(&issued.credential.id).unwrap());
        assert_eq!(store.authenticate_scim_bearer(Some(&header)).unwrap(), None);
    }

    #[test]
    fn scim_users_start_without_workspace_access_and_deprovisioning_is_sticky() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("SCIM directory organization")
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "SCIM directory tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let credential = store
            .issue_scim_token(&organization.id, "directory", super::now_unix() + 3_600)
            .unwrap();
        let identity = store
            .authenticate_scim_bearer(Some(&format!("Bearer {}", credential.token)))
            .unwrap()
            .unwrap();
        let user = store
            .create_scim_user(
                &identity,
                "idp-opaque-user-1",
                "security.engineer@example.test",
                "Security Engineer",
                true,
            )
            .unwrap();
        assert_eq!(
            store.list_scim_users(&identity, 1, 100).unwrap().resources,
            vec![user.clone()]
        );
        assert!(!store
            .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
            .unwrap());

        // A role assignment is explicit and can only target the user's own
        // organization. The person never receives it from SCIM creation.
        store
            .set_workspace_membership(&workspace.id, &user.id, WorkspaceRole::Analyst)
            .unwrap();
        assert!(store
            .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
            .unwrap());
        let suspended = store
            .update_scim_user(
                &identity,
                &user.id,
                super::ScimUserUpdate {
                    active: Some(false),
                    ..super::ScimUserUpdate::default()
                },
            )
            .unwrap()
            .unwrap();
        assert!(!suspended.active);
        assert!(!store
            .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
            .unwrap());
        store
            .update_scim_user(
                &identity,
                &user.id,
                super::ScimUserUpdate {
                    active: Some(true),
                    ..super::ScimUserUpdate::default()
                },
            )
            .unwrap();
        assert!(
            !store
                .workspace_permits(&user.id, &workspace.id, WorkspacePermission::ReadUsage,)
                .unwrap(),
            "reactivation must not restore a prior workspace role"
        );

        let other_organization = store.create_organization("Other organization").unwrap();
        let other_tenant = store
            .create_tenant_in_organization(&other_organization.id, "Other tenant")
            .unwrap();
        let other_workspace = store
            .workspace_for_tenant(&other_tenant.id)
            .unwrap()
            .unwrap();
        assert!(store
            .set_workspace_membership(&other_workspace.id, &user.id, WorkspaceRole::Analyst)
            .is_err());
    }

    #[test]
    fn raw_token_is_not_a_database_lookup_key() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Acme").unwrap();
        let issued = store.issue_token(&tenant.id, "production").unwrap();
        assert!(issued.token.starts_with("llmfw_"));
        assert!(store
            .authenticate_bearer(Some("Bearer incorrect"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn issue_rejects_unknown_or_inactive_tenants() {
        let store = TenantStore::open(":memory:").unwrap();
        assert!(store.issue_token("missing", "production").is_err());
        assert!(store.create_tenant(" ").is_err());
    }

    #[test]
    fn tenant_limits_and_privacy_safe_audit_are_persisted() {
        let store = TenantStore::open_with_audit_capacity(":memory:", 2).unwrap();
        let tenant = store.create_tenant("Acme").unwrap();
        let limits = TenantLimits {
            rate_limit: Some(TenantRateLimit {
                requests_per_window: 7,
                window_seconds: 60,
            }),
            spend_limit: Some(TenantSpendLimit {
                window_seconds: 86_400,
                max_usd_micros: 1_000_000,
                reserve_usd_micros_per_request: 50_000,
            }),
        };
        store.set_limits(&tenant.id, limits.clone()).unwrap();
        assert_eq!(store.limits_for(&tenant.id).unwrap(), limits);

        store
            .append_audit(&tenant.id, "/v1/chat/completions", "completed", 200, 12)
            .unwrap();
        store
            .append_audit(&tenant.id, "/v1/responses", "rejected", 429, 1)
            .unwrap();
        store
            .append_audit(&tenant.id, "/v1/messages", "completed", 200, 8)
            .unwrap();
        let audit = store.list_audit(&tenant.id, 100).unwrap();
        assert_eq!(audit.len(), 2, "configured retention applies");
        assert_eq!(audit[0].path, "/v1/messages");
        assert_eq!(audit[1].outcome, "rejected");
    }

    #[test]
    fn tenant_model_policy_is_exact_persisted_and_can_be_cleared() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Acme").unwrap();
        let policy = TenantModelPolicy {
            allowed_models: vec!["gpt-5.6".into(), "gpt-5.6-mini".into()],
        };
        store
            .set_model_policy(&tenant.id, Some(policy.clone()))
            .unwrap();
        let loaded = store.model_policy_for(&tenant.id).unwrap().unwrap();
        assert_eq!(loaded, policy);
        assert!(loaded.permits("gpt-5.6"));
        assert!(!loaded.permits("gpt-5.6-preview"), "no prefix matching");
        store.set_model_policy(&tenant.id, None).unwrap();
        assert_eq!(store.model_policy_for(&tenant.id).unwrap(), None);
    }

    #[test]
    fn policy_versions_require_approval_simulate_exactly_and_rollback_immutably() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Versioned policy tenant").unwrap();
        let first = store
            .create_policy_version(
                &tenant.id,
                "policy_author",
                TenantPolicyDocument::new(Some(TenantModelPolicy {
                    allowed_models: vec!["gpt-safe".into()],
                })),
            )
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.content_sha256.len(), 64);
        let preview = store
            .simulate_policy_version(
                &tenant.id,
                &first.id,
                vec![
                    PolicySimulationCase {
                        requested_model: "gpt-safe".into(),
                    },
                    PolicySimulationCase {
                        requested_model: "gpt-other".into(),
                    },
                ],
            )
            .unwrap();
        assert_eq!(preview.changed_count, 1);
        assert!(preview.results[0].candidate_permitted);
        assert!(!preview.results[1].candidate_permitted);
        assert!(store
            .deploy_policy_version(
                &tenant.id,
                &first.id,
                "policy_owner",
                PolicyDeploymentAction::Activate,
            )
            .is_err());
        store
            .approve_policy_version(&tenant.id, &first.id, "policy_owner")
            .unwrap();
        store
            .deploy_policy_version(
                &tenant.id,
                &first.id,
                "policy_owner",
                PolicyDeploymentAction::Activate,
            )
            .unwrap();
        assert!(store
            .model_policy_for(&tenant.id)
            .unwrap()
            .unwrap()
            .permits("gpt-safe"));

        let second = store
            .create_policy_version(
                &tenant.id,
                "policy_author",
                TenantPolicyDocument::new(Some(TenantModelPolicy {
                    allowed_models: vec!["gpt-next".into()],
                })),
            )
            .unwrap();
        store
            .approve_policy_version(&tenant.id, &second.id, "policy_owner")
            .unwrap();
        store
            .deploy_policy_version(
                &tenant.id,
                &second.id,
                "policy_owner",
                PolicyDeploymentAction::Activate,
            )
            .unwrap();
        let rollback = store
            .deploy_policy_version(
                &tenant.id,
                &first.id,
                "policy_owner",
                PolicyDeploymentAction::Rollback,
            )
            .unwrap();
        assert_eq!(
            rollback.previous_version_id.as_deref(),
            Some(second.id.as_str())
        );
        assert_eq!(
            store.list_policy_deployments(&tenant.id, 10).unwrap()[0].action,
            PolicyDeploymentAction::Rollback
        );
        let security_events = store.list_security_events(&tenant.id, 0, 10).unwrap();
        assert_eq!(security_events.len(), 3);
        assert_eq!(security_events[0].sequence, 1);
        assert_eq!(security_events[2].payload["event_type"], "policy.deployed");
        assert_eq!(security_events[2].content_sha256.len(), 64);
        assert!(store
            .list_security_events(&tenant.id, security_events[0].sequence, 10)
            .unwrap()
            .iter()
            .all(|event| event.sequence > security_events[0].sequence));
        let exported = store
            .policy_version(&tenant.id, &first.id)
            .unwrap()
            .unwrap();
        assert!(exported.active);
        assert_eq!(exported.document, first.document);

        let connection = store.connection().unwrap();
        assert!(connection
            .execute(
                "UPDATE tenant_policy_versions SET content_sha256 = ?1 WHERE id = ?2",
                params!["0".repeat(64), &first.id],
            )
            .is_err());
    }

    #[test]
    fn workspace_rbac_is_scoped_to_the_tenant_workspace() {
        let store = TenantStore::open(":memory:").unwrap();
        let acme = store.create_tenant("Acme").unwrap();
        let beta = store.create_tenant("Beta").unwrap();
        let acme_workspace = store.workspace_for_tenant(&acme.id).unwrap().unwrap();
        let beta_workspace = store.workspace_for_tenant(&beta.id).unwrap().unwrap();
        assert_eq!(
            acme_workspace.organization_id,
            super::BOOTSTRAP_ORGANIZATION_ID
        );
        assert_eq!(acme_workspace.tenant_id, acme.id);

        let alice = store.create_workspace_principal("Alice").unwrap();
        store
            .set_workspace_membership(&acme_workspace.id, &alice.id, WorkspaceRole::Owner)
            .unwrap();
        assert!(store
            .workspace_permits(
                &alice.id,
                &acme_workspace.id,
                WorkspacePermission::ManagePolicies
            )
            .unwrap());
        assert!(!store
            .workspace_permits(
                &alice.id,
                &beta_workspace.id,
                WorkspacePermission::ReadAudit
            )
            .unwrap());

        store
            .set_workspace_membership(&acme_workspace.id, &alice.id, WorkspaceRole::Analyst)
            .unwrap();
        assert!(store
            .workspace_permits(
                &alice.id,
                &acme_workspace.id,
                WorkspacePermission::ReadAudit
            )
            .unwrap());
        assert!(!store
            .workspace_permits(
                &alice.id,
                &acme_workspace.id,
                WorkspacePermission::ManagePolicies
            )
            .unwrap());

        let audit = store
            .list_workspace_admin_audit(&acme_workspace.id, 10)
            .unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].action, "membership.upsert");
        assert_eq!(
            audit[0].target_principal_id.as_deref(),
            Some(alice.id.as_str())
        );
        assert_eq!(audit[1].organization_id, acme_workspace.organization_id);
        assert!(store
            .list_workspace_admin_audit(&beta_workspace.id, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn workspace_service_accounts_are_scoped_one_time_and_revocable() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Service account tenant").unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store.create_workspace_principal("Owner").unwrap();
        let developer = store.create_workspace_principal("Developer").unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &developer.id, WorkspaceRole::Developer)
            .unwrap();

        let issued = store
            .create_workspace_service_account(
                &workspace.id,
                &developer.id,
                "build-agent",
                super::now_unix() + 3_600,
            )
            .unwrap();
        assert!(issued.token.starts_with("llmfw_sa_"));
        let header = format!("Bearer {}", issued.token);
        assert_eq!(
            store.authenticate_bearer(Some(&header)).unwrap(),
            Some(super::TenantIdentity {
                tenant_id: tenant.id.clone(),
                tenant_name: tenant.name.clone(),
            })
        );
        assert_eq!(
            store
                .list_workspace_service_accounts(&workspace.id, &developer.id)
                .unwrap(),
            vec![issued.account.clone()]
        );
        assert_eq!(
            store
                .list_workspace_service_accounts(&workspace.id, &owner.id)
                .unwrap(),
            vec![issued.account.clone()]
        );
        assert!(store
            .revoke_workspace_service_account(&workspace.id, &issued.account.id, &developer.id)
            .unwrap());
        assert!(!store
            .revoke_workspace_service_account(&workspace.id, &issued.account.id, &owner.id)
            .unwrap());
        assert_eq!(store.authenticate_bearer(Some(&header)).unwrap(), None);
        assert!(!store
            .revoke_workspace_service_account(&workspace.id, &issued.account.id, &owner.id)
            .unwrap());
        assert!(store
            .create_workspace_service_account(
                &workspace.id,
                &developer.id,
                "expired",
                super::now_unix(),
            )
            .is_err());
    }

    #[test]
    fn workspace_invitations_are_hash_only_owner_scoped_and_single_use() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("Invitation organization")
            .unwrap();
        let issuer = "https://id.example.test/invitations";
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
            .create_tenant_in_organization(&organization.id, "Invitation tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store
            .create_workspace_principal("Invitation owner")
            .unwrap();
        let analyst = store
            .create_workspace_principal("Existing analyst")
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &analyst.id, WorkspaceRole::Analyst)
            .unwrap();

        assert!(store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &analyst.id,
                "Not allowed",
                WorkspaceRole::Developer,
                super::now_unix() + 3_600,
            )
            .is_err());
        let revoked = store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &owner.id,
                "Revoked recipient",
                WorkspaceRole::Analyst,
                super::now_unix() + 3_600,
            )
            .unwrap();
        assert!(store
            .revoke_workspace_invitation_as_owner(&workspace.id, &revoked.invitation.id, &owner.id,)
            .unwrap());
        assert!(store
            .workspace_invitation_for_token(&revoked.token)
            .unwrap()
            .is_none());

        let issued = store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &owner.id,
                "New developer",
                WorkspaceRole::Developer,
                super::now_unix() + 3_600,
            )
            .unwrap();
        assert!(issued.token.starts_with("llmfw_invite_"));
        let raw_token_count: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM workspace_invitations
                 WHERE token_hash = CAST(?1 AS BLOB)",
                [&issued.token],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_token_count, 0, "only an invitation hash is stored");
        assert_eq!(
            store
                .workspace_invitation_for_token(&issued.token)
                .unwrap()
                .map(|invitation| invitation.id),
            Some(issued.invitation.id.clone())
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resend_candidate = store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &owner.id,
                "Resend candidate",
                WorkspaceRole::Analyst,
                super::now_unix() + 3_600,
            )
            .unwrap();
        let resent = runtime
            .block_on(store.resend_workspace_invitation_as_owner_async(
                &workspace.id,
                &resend_candidate.invitation.id,
                &owner.id,
                super::now_unix() + 7_200,
            ))
            .unwrap()
            .expect("an active invitation can be resent");
        assert_ne!(
            resent.token, resend_candidate.token,
            "resend must mint a new bearer"
        );
        assert_eq!(
            resent.invitation.recipient_label,
            resend_candidate.invitation.recipient_label
        );
        assert_eq!(resent.invitation.role, resend_candidate.invitation.role);
        assert!(
            store
                .workspace_invitation_for_token(&resend_candidate.token)
                .unwrap()
                .is_none(),
            "the old bearer is revoked immediately"
        );
        assert_eq!(
            store
                .workspace_invitation_for_token(&resent.token)
                .unwrap()
                .map(|invitation| invitation.id),
            Some(resent.invitation.id.clone())
        );
        let resent_inventory = store
            .list_workspace_invitations_as_owner(&workspace.id, &owner.id)
            .unwrap();
        assert!(resent_inventory.iter().any(|invitation| {
            invitation.id == resend_candidate.invitation.id
                && !invitation.active
                && invitation.revoked_at_unix.is_some()
        }));

        let other_tenant = store
            .create_tenant_in_organization(&organization.id, "Invitation other tenant")
            .unwrap();
        let other_workspace = store
            .workspace_for_tenant(&other_tenant.id)
            .unwrap()
            .unwrap();
        assert!(store
            .accept_workspace_invitation_oidc(
                &issued.invitation.id,
                &organization.id,
                &other_workspace.id,
                issuer,
                "new-developer-subject",
            )
            .unwrap()
            .is_none());
        assert!(store
            .workspace_invitation_for_token(&issued.token)
            .unwrap()
            .is_some());

        let access = store
            .accept_workspace_invitation_oidc(
                &issued.invitation.id,
                &organization.id,
                &workspace.id,
                issuer,
                "new-developer-subject",
            )
            .unwrap()
            .expect("a verified new OIDC identity can consume the invitation once");
        assert_eq!(access.organization_id, organization.id);
        assert_eq!(access.workspace_id, workspace.id);
        assert_eq!(access.role, WorkspaceRole::Developer);
        assert_eq!(
            store
                .workspace_principal_for_external_identity(issuer, "new-developer-subject")
                .unwrap()
                .map(|principal| principal.id),
            Some(access.principal_id.clone())
        );
        assert!(store
            .verified_identity_workspace_access(
                &organization.id,
                &workspace.id,
                issuer,
                "new-developer-subject",
            )
            .unwrap()
            .is_some());
        assert!(store
            .accept_workspace_invitation_oidc(
                &issued.invitation.id,
                &organization.id,
                &workspace.id,
                issuer,
                "new-developer-subject",
            )
            .unwrap()
            .is_none());
        assert!(store
            .workspace_invitation_for_token(&issued.token)
            .unwrap()
            .is_none());
        let invitations = store
            .list_workspace_invitations_as_owner(&workspace.id, &owner.id)
            .unwrap();
        let accepted = invitations
            .iter()
            .find(|invitation| invitation.id == issued.invitation.id)
            .unwrap();
        assert!(!accepted.active);
        assert_eq!(
            accepted.accepted_by_principal_id.as_deref(),
            Some(access.principal_id.as_str())
        );
        assert!(accepted.accepted_at_unix.is_some());
        let audit = store.list_workspace_admin_audit(&workspace.id, 20).unwrap();
        assert!(audit
            .iter()
            .any(|event| event.action == "invitation.create"));
        assert!(audit
            .iter()
            .any(|event| event.action == "invitation.revoke"));
        assert!(audit
            .iter()
            .any(|event| event.action == "invitation.accept"));
    }

    #[test]
    fn saml_workspace_invitations_bind_only_after_verified_identity() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("SAML invitation organization")
            .unwrap();
        let issuer = "https://id.example.test/saml-invitations";
        store
            .set_organization_saml_connection(
                &organization.id,
                issuer,
                "<EntityDescriptor entityID=\"https://id.example.test/saml-invitations\"></EntityDescriptor>",
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                true,
            )
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "SAML invitation tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store.create_workspace_principal("SAML owner").unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        let issued = store
            .create_workspace_invitation_as_owner(
                &workspace.id,
                &owner.id,
                "SAML recipient",
                WorkspaceRole::Analyst,
                super::now_unix() + 3_600,
            )
            .unwrap();

        assert!(store
            .workspace_invitation_for_token(&issued.token)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .workspace_invitation_for_federation_token(
                    &issued.token,
                    BrowserSessionFederation::Saml,
                )
                .unwrap()
                .map(|invitation| invitation.id),
            Some(issued.invitation.id.clone())
        );
        let pending = SamlAuthorizationPending {
            organization_id: organization.id.clone(),
            workspace_id: workspace.id.clone(),
            invitation_id: Some(issued.invitation.id.clone()),
            request_id: "_saml_invitation_request".to_owned(),
            idp_entity_id: issuer.to_owned(),
            expected_binding: "post".to_owned(),
            request_binding: "redirect".to_owned(),
            acs_url: "https://console.example.test/auth/saml/acs".to_owned(),
            acs_binding: "post".to_owned(),
        };
        store
            .reserve_saml_authorization_state(
                "saml-invitation-state",
                &pending,
                super::now_unix() + 60,
            )
            .unwrap();
        assert_eq!(
            store
                .consume_saml_authorization_state("saml-invitation-state")
                .unwrap(),
            Some(pending)
        );
        let access = store
            .accept_workspace_invitation_federated(
                &issued.invitation.id,
                &organization.id,
                &workspace.id,
                issuer,
                "saml-recipient-1",
                BrowserSessionFederation::Saml,
            )
            .unwrap()
            .expect("verified SAML identity can consume the invitation");
        assert_eq!(access.role, WorkspaceRole::Analyst);
        assert!(store
            .accept_workspace_invitation_federated(
                &issued.invitation.id,
                &organization.id,
                &workspace.id,
                issuer,
                "saml-recipient-2",
                BrowserSessionFederation::Saml,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn workspace_owner_can_manage_existing_members_but_cannot_remove_last_owner() {
        let store = TenantStore::open(":memory:").unwrap();
        let tenant = store.create_tenant("Membership tenant").unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let owner = store.create_workspace_principal("Owner").unwrap();
        let member = store.create_workspace_principal("Member").unwrap();
        store
            .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &member.id, WorkspaceRole::Analyst)
            .unwrap();

        let members = store.list_workspace_members(&workspace.id).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].principal_name, "Member");
        assert_eq!(members[1].principal_name, "Owner");
        assert!(members.iter().all(|member| member.active));

        let updated = store
            .update_workspace_membership_as_owner(
                &workspace.id,
                &owner.id,
                &member.id,
                WorkspaceRole::Developer,
                false,
            )
            .unwrap();
        assert_eq!(updated.role, WorkspaceRole::Developer);
        assert!(!updated.active);
        assert!(store
            .update_workspace_membership_as_owner(
                &workspace.id,
                &owner.id,
                &owner.id,
                WorkspaceRole::Admin,
                true,
            )
            .is_err());
        assert!(store
            .workspace_permits(
                &owner.id,
                &workspace.id,
                WorkspacePermission::ManageMembership
            )
            .unwrap());
        let audit = store.list_workspace_admin_audit(&workspace.id, 1).unwrap();
        assert_eq!(audit[0].action, "membership.update");
        assert_eq!(
            audit[0].actor_principal_id.as_deref(),
            Some(owner.id.as_str())
        );
        assert_eq!(
            audit[0].target_principal_id.as_deref(),
            Some(member.id.as_str())
        );
    }

    #[test]
    fn organizations_isolate_workspaces_and_suspend_membership_changes() {
        let store = TenantStore::open(":memory:").unwrap();
        let acme = store.create_organization("Acme organization").unwrap();
        let beta = store.create_organization("Beta organization").unwrap();
        let acme_tenant = store
            .create_tenant_in_organization(&acme.id, "Acme production")
            .unwrap();
        let acme_workspace = store
            .workspace_for_tenant(&acme_tenant.id)
            .unwrap()
            .unwrap();
        assert_eq!(acme_workspace.organization_id, acme.id);
        assert!(store
            .list_organization_workspaces(&beta.id)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.list_organization_workspaces(&acme.id).unwrap(),
            vec![acme_workspace.clone()]
        );
        assert!(store
            .active_workspace_in_organization(&acme.id, &acme_workspace.id)
            .unwrap());
        assert!(!store
            .active_workspace_in_organization(&beta.id, &acme_workspace.id)
            .unwrap());

        assert!(store.set_organization_active(&acme.id, false).unwrap());
        assert!(!store
            .active_workspace_in_organization(&acme.id, &acme_workspace.id)
            .unwrap());
        assert!(store
            .create_tenant_in_organization(&acme.id, "must fail")
            .is_err());
        let principal = store.create_workspace_principal("Acme user").unwrap();
        assert!(store
            .set_workspace_membership(&acme_workspace.id, &principal.id, WorkspaceRole::Owner)
            .is_err());
        assert!(store
            .set_organization_active(super::BOOTSTRAP_ORGANIZATION_ID, false)
            .is_err());
    }

    #[test]
    fn opening_a_legacy_tenant_database_backfills_bootstrap_workspaces() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!(
            "llm-firewall-legacy-backfill-{}-{}.sqlite",
            std::process::id(),
            super::now_unix()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(
                "CREATE TABLE tenants (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                    created_at_unix INTEGER NOT NULL
                );
                INSERT INTO tenants (id, name, active, created_at_unix)
                VALUES ('tenant_legacy', 'Legacy tenant', 1, 1);",
            )?;
        }

        let store = TenantStore::open(&path)?;
        let workspace = store
            .workspace_for_tenant("tenant_legacy")?
            .ok_or_else(|| anyhow::anyhow!("legacy tenant workspace was not backfilled"))?;
        assert_eq!(workspace.id, "workspace_tenant_legacy");
        assert_eq!(workspace.organization_id, super::BOOTSTRAP_ORGANIZATION_ID);
        assert_eq!(workspace.tenant_id, "tenant_legacy");
        assert!(workspace.active);
        drop(store);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn organization_oidc_connections_are_https_only_and_require_an_active_organization() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store.create_organization("OIDC organization").unwrap();
        let saved = store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test/tenant-a",
                "firewall-control-plane",
                "https://console.example.test/auth/callback",
                true,
            )
            .unwrap();
        assert_eq!(saved.organization_id, organization.id);
        assert_eq!(saved.issuer, "https://id.example.test/tenant-a");
        assert!(saved.active);
        assert_eq!(
            store
                .organization_oidc_connection(&organization.id)
                .unwrap(),
            Some(saved.clone())
        );
        assert!(store
            .set_organization_oidc_connection(
                &organization.id,
                "http://id.example.test",
                "client",
                "https://console.example.test/auth/callback",
                true,
            )
            .is_err());
        assert!(store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test?unexpected=query",
                "client",
                "https://console.example.test/auth/callback",
                true,
            )
            .is_err());
        assert!(store
            .set_organization_active(&organization.id, false)
            .unwrap());
        assert!(store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test/tenant-a",
                "client",
                "https://console.example.test/auth/callback",
                true,
            )
            .is_err());
        assert!(store
            .delete_organization_oidc_connection(&organization.id)
            .unwrap());
        assert_eq!(
            store
                .organization_oidc_connection(&organization.id)
                .unwrap(),
            None
        );
    }

    #[test]
    fn oidc_authorization_states_are_hashed_short_lived_and_single_use() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("OIDC state organization")
            .unwrap();
        store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test/tenant-a",
                "firewall-control-plane",
                "https://console.example.test/auth/callback",
                true,
            )
            .unwrap();
        let state = "opaque-state-that-must-not-be-stored-raw";
        store
            .reserve_oidc_authorization_state(state, &organization.id, super::now_unix() + 60)
            .unwrap();
        let raw_state_count: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM oidc_authorization_states
                 WHERE CAST(state_hash AS TEXT) = ?1",
                [state],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            raw_state_count, 0,
            "only a domain-separated state hash is stored"
        );
        assert!(store
            .consume_oidc_authorization_state(state, &organization.id)
            .unwrap());
        assert!(!store
            .consume_oidc_authorization_state(state, &organization.id)
            .unwrap());
        assert!(store
            .reserve_oidc_authorization_state(
                "expired-state",
                &organization.id,
                super::now_unix() - 1,
            )
            .is_err());
    }

    #[test]
    fn saml_authorization_state_persists_pending_request_and_is_single_use() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("SAML state organization")
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "SAML state tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        store
            .set_organization_saml_connection(
                &organization.id,
                "https://id.example.test/saml",
                "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                true,
            )
            .unwrap();
        let pending = SamlAuthorizationPending {
            organization_id: organization.id.clone(),
            workspace_id: workspace.id.clone(),
            invitation_id: None,
            request_id: "_request-1".into(),
            idp_entity_id: "https://id.example.test/saml".into(),
            expected_binding: "post".into(),
            request_binding: "redirect".into(),
            acs_url: "https://console.example.test/auth/saml/acs".into(),
            acs_binding: "post".into(),
        };
        let state = "opaque-saml-state";
        store
            .reserve_saml_authorization_state(state, &pending, super::now_unix() + 60)
            .unwrap();
        let raw_state_count: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM saml_authorization_states
                 WHERE CAST(state_hash AS TEXT) = ?1",
                [state],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_state_count, 0);
        assert_eq!(
            store.consume_saml_authorization_state(state).unwrap(),
            Some(pending)
        );
        assert_eq!(store.consume_saml_authorization_state(state).unwrap(), None);
    }

    #[test]
    fn saml_identity_and_browser_session_require_the_active_saml_connection() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("SAML browser session organization")
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "SAML browser session tenant")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let issuer = "https://id.example.test/saml";
        store
            .set_organization_saml_connection(
                &organization.id,
                issuer,
                "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                true,
            )
            .unwrap();
        let principal = store.create_workspace_principal("SAML member").unwrap();
        store
            .link_workspace_external_identity(&principal.id, issuer, "member-123")
            .unwrap();
        store
            .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Admin)
            .unwrap();

        let access = store
            .verified_saml_identity_workspace_access(
                &organization.id,
                &workspace.id,
                issuer,
                "member-123",
            )
            .unwrap()
            .expect("active SAML identity has the explicit workspace membership");
        assert_eq!(access.role, WorkspaceRole::Admin);
        let session = store
            .issue_oidc_browser_session(
                &access,
                BrowserSessionFederation::Saml,
                super::now_unix() + 3_600,
            )
            .unwrap();
        assert!(store
            .authenticate_oidc_browser_session(&session.token)
            .unwrap()
            .is_some());

        store
            .set_organization_saml_connection(
                &organization.id,
                issuer,
                "<EntityDescriptor entityID=\"https://id.example.test/saml\"></EntityDescriptor>",
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .authenticate_oidc_browser_session(&session.token)
                .unwrap(),
            None,
            "disabling SAML invalidates sessions established by SAML without affecting OIDC policy"
        );
    }

    #[test]
    fn oidc_browser_sessions_are_hashed_revocable_and_recheck_rbac() {
        let store = TenantStore::open(":memory:").unwrap();
        let organization = store
            .create_organization("OIDC session organization")
            .unwrap();
        store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test/session",
                "firewall-control-plane",
                "https://console.example.test/auth/oidc/callback",
                true,
            )
            .unwrap();
        let tenant = store
            .create_tenant_in_organization(&organization.id, "Session production")
            .unwrap();
        let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
        let principal = store.create_workspace_principal("Session user").unwrap();
        store
            .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Developer)
            .unwrap();
        let access = super::VerifiedWorkspaceAccess {
            organization_id: organization.id.clone(),
            workspace_id: workspace.id.clone(),
            principal_id: principal.id.clone(),
            role: WorkspaceRole::Developer,
        };
        let issued = store
            .issue_oidc_browser_session(
                &access,
                BrowserSessionFederation::Oidc,
                super::now_unix() + 3_600,
            )
            .unwrap();
        let raw_token_count: i64 = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM oidc_browser_sessions
                 WHERE CAST(session_hash AS TEXT) = ?1",
                [&issued.token],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_token_count, 0, "only a session hash is stored");
        assert_eq!(
            store
                .authenticate_oidc_browser_session(&issued.token)
                .unwrap()
                .map(|session| session.access.role),
            Some(WorkspaceRole::Developer)
        );
        let rotated = store
            .rotate_oidc_browser_session(&issued.token, super::now_unix() + 3_600)
            .unwrap()
            .unwrap();
        assert!(store
            .authenticate_oidc_browser_session(&issued.token)
            .unwrap()
            .is_none());
        assert!(store
            .authenticate_oidc_browser_session(&rotated.token)
            .unwrap()
            .is_some());

        store
            .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Admin)
            .unwrap();
        assert_eq!(
            store
                .authenticate_oidc_browser_session(&rotated.token)
                .unwrap()
                .map(|session| session.access.role),
            Some(WorkspaceRole::Admin),
            "the cookie has no stale role claim"
        );
        assert!(store.revoke_oidc_browser_session(&rotated.token).unwrap());
        assert!(!store.revoke_oidc_browser_session(&rotated.token).unwrap());
        assert_eq!(
            store
                .authenticate_oidc_browser_session(&rotated.token)
                .unwrap(),
            None
        );

        let another = store
            .issue_oidc_browser_session(
                &access,
                BrowserSessionFederation::Oidc,
                super::now_unix() + 3_600,
            )
            .unwrap();
        store
            .set_organization_oidc_connection(
                &organization.id,
                "https://id.example.test/session",
                "firewall-control-plane",
                "https://console.example.test/auth/oidc/callback",
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .authenticate_oidc_browser_session(&another.token)
                .unwrap(),
            None,
            "disabling the OIDC connection invalidates existing browser sessions"
        );
    }

    #[test]
    fn external_identities_are_opaque_unique_and_ignore_inactive_principals() {
        let store = TenantStore::open(":memory:").unwrap();
        let alice = store.create_workspace_principal("Alice").unwrap();
        let binding = store
            .link_workspace_external_identity(
                &alice.id,
                "https://id.example.test/tenant-a",
                "00u-alice-opaque-subject",
            )
            .unwrap();
        assert_eq!(binding.principal_id, alice.id);
        assert_eq!(
            store
                .workspace_principal_for_external_identity(
                    "https://id.example.test/tenant-a",
                    "00u-alice-opaque-subject",
                )
                .unwrap(),
            Some(alice.clone())
        );
        let bob = store.create_workspace_principal("Bob").unwrap();
        assert!(store
            .link_workspace_external_identity(
                &bob.id,
                "https://id.example.test/tenant-a",
                "00u-alice-opaque-subject",
            )
            .is_err());
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE workspace_principals SET active = 0 WHERE id = ?1",
                [&alice.id],
            )
            .unwrap();
        assert_eq!(
            store
                .workspace_principal_for_external_identity(
                    "https://id.example.test/tenant-a",
                    "00u-alice-opaque-subject",
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn verified_oidc_identity_requires_the_selected_connection_and_membership() {
        let store = TenantStore::open(":memory:").unwrap();
        let acme = store.create_organization("Acme").unwrap();
        let beta = store.create_organization("Beta").unwrap();
        let issuer = "https://id.example.test/shared";
        for organization in [&acme, &beta] {
            store
                .set_organization_oidc_connection(
                    &organization.id,
                    issuer,
                    "firewall-console",
                    "https://console.example.test/auth/callback",
                    true,
                )
                .unwrap();
        }
        let acme_tenant = store
            .create_tenant_in_organization(&acme.id, "Acme production")
            .unwrap();
        let acme_workspace = store
            .workspace_for_tenant(&acme_tenant.id)
            .unwrap()
            .unwrap();
        let beta_tenant = store
            .create_tenant_in_organization(&beta.id, "Beta production")
            .unwrap();
        let beta_workspace = store
            .workspace_for_tenant(&beta_tenant.id)
            .unwrap()
            .unwrap();
        let principal = store.create_workspace_principal("Acme operator").unwrap();
        store
            .link_workspace_external_identity(&principal.id, issuer, "opaque-subject")
            .unwrap();
        store
            .set_workspace_membership(&acme_workspace.id, &principal.id, WorkspaceRole::Admin)
            .unwrap();

        let access = store
            .verified_identity_workspace_access(
                &acme.id,
                &acme_workspace.id,
                issuer,
                "opaque-subject",
            )
            .unwrap()
            .expect("the verified identity has an active Acme membership");
        assert_eq!(access.principal_id, principal.id);
        assert_eq!(access.role, WorkspaceRole::Admin);
        assert!(access.permits(WorkspacePermission::ManagePolicies));
        assert!(!access.permits(WorkspacePermission::ManageMembership));
        assert_eq!(
            store
                .verified_identity_workspace_access(
                    &beta.id,
                    &beta_workspace.id,
                    issuer,
                    "opaque-subject",
                )
                .unwrap(),
            None,
            "the same IdP subject must not cross organization/workspace boundaries"
        );

        store
            .set_organization_oidc_connection(
                &acme.id,
                issuer,
                "firewall-console",
                "https://console.example.test/auth/callback",
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .verified_identity_workspace_access(
                    &acme.id,
                    &acme_workspace.id,
                    issuer,
                    "opaque-subject",
                )
                .unwrap(),
            None,
            "disabling an OIDC connection immediately revokes its login path"
        );
    }

    #[tokio::test]
    #[ignore = "requires LLM_FW_TEST_POSTGRES_URL pointing at a disposable PostgreSQL instance"]
    async fn postgres_control_plane_persists_tenants_tokens_policies_and_audit() {
        let url = std::env::var("LLM_FW_TEST_POSTGRES_URL")
            .expect("PostgreSQL integration test URL must be configured");
        let store = TenantStore::open_postgres_for_test(&url, 2).await.unwrap();
        let tenant = store
            .create_tenant_async(&format!("PostgreSQL {}", super::random_id("test")))
            .await
            .unwrap();
        let issued = store
            .issue_token_async(&tenant.id, "production")
            .await
            .unwrap();
        let header = format!("Bearer {}", issued.token);
        assert_eq!(
            store
                .authenticate_bearer_async(Some(&header))
                .await
                .unwrap(),
            Some(super::TenantIdentity {
                tenant_id: tenant.id.clone(),
                tenant_name: tenant.name.clone(),
            })
        );

        let limits = TenantLimits {
            rate_limit: Some(TenantRateLimit {
                requests_per_window: 7,
                window_seconds: 60,
            }),
            spend_limit: Some(TenantSpendLimit {
                window_seconds: 86_400,
                max_usd_micros: 1_000_000,
                reserve_usd_micros_per_request: 50_000,
            }),
        };
        store
            .set_limits_async(&tenant.id, limits.clone())
            .await
            .unwrap();
        assert_eq!(store.limits_for_async(&tenant.id).await.unwrap(), limits);

        let policy = TenantModelPolicy {
            allowed_models: vec!["gpt-test".into()],
        };
        store
            .set_model_policy_async(&tenant.id, Some(policy.clone()))
            .await
            .unwrap();
        assert_eq!(
            store.model_policy_for_async(&tenant.id).await.unwrap(),
            Some(policy)
        );
        let access = store
            .authenticate_access_async(Some(&header))
            .await
            .unwrap()
            .expect("active PostgreSQL token authenticates");
        assert_eq!(access.identity.tenant_id, tenant.id);
        assert_eq!(access.limits, limits);
        assert!(access
            .model_policy
            .as_ref()
            .is_some_and(|policy| policy.permits("gpt-test")));

        let usage_request_id = super::random_id("req_postgres_usage");
        let usage = priced_usage_event(&tenant.id, &usage_request_id);
        assert!(store.append_usage_event_async(&usage).await.unwrap());
        assert!(!store.append_usage_event_async(&usage).await.unwrap());
        let stored_usage = store.list_usage_events_async(&tenant.id, 10).await.unwrap();
        assert!(
            stored_usage
                .iter()
                .any(|event| event.request_id == usage_request_id
                    && event.cost_usd_micros == Some(11))
        );

        let workspace = store
            .workspace_for_tenant_async(&tenant.id)
            .await
            .unwrap()
            .expect("a PostgreSQL tenant receives a workspace in the migration");
        let principal = store
            .create_workspace_principal_async("PostgreSQL owner")
            .await
            .unwrap();
        let external_identity = store
            .link_workspace_external_identity_async(
                &principal.id,
                "https://id.example.test/postgresql",
                &format!("postgres-subject-{}", super::random_id("test")),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .workspace_principal_for_external_identity_async(
                    &external_identity.issuer,
                    &external_identity.subject,
                )
                .await
                .unwrap(),
            Some(principal.clone())
        );
        store
            .set_workspace_membership_async(&workspace.id, &principal.id, WorkspaceRole::Owner)
            .await
            .unwrap();
        assert!(store
            .workspace_permits_async(
                &principal.id,
                &workspace.id,
                WorkspacePermission::ManageTenant
            )
            .await
            .unwrap());
        let workspace_audit = store
            .list_workspace_admin_audit_async(&workspace.id, 10)
            .await
            .unwrap();
        assert_eq!(workspace_audit.len(), 1);
        assert_eq!(workspace_audit[0].action, "membership.upsert");

        let managed_member = store
            .create_workspace_principal_async("PostgreSQL managed member")
            .await
            .unwrap();
        store
            .set_workspace_membership_async(
                &workspace.id,
                &managed_member.id,
                WorkspaceRole::Analyst,
            )
            .await
            .unwrap();
        let members = store
            .list_workspace_members_async(&workspace.id)
            .await
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(members
            .iter()
            .any(|member| member.principal_id == managed_member.id));
        let updated_member = store
            .update_workspace_membership_as_owner_async(
                &workspace.id,
                &principal.id,
                &managed_member.id,
                WorkspaceRole::Developer,
                false,
            )
            .await
            .unwrap();
        assert_eq!(updated_member.role, WorkspaceRole::Developer);
        assert!(!updated_member.active);
        assert!(store
            .update_workspace_membership_as_owner_async(
                &workspace.id,
                &principal.id,
                &principal.id,
                WorkspaceRole::Admin,
                true,
            )
            .await
            .is_err());
        let workspace_audit = store
            .list_workspace_admin_audit_async(&workspace.id, 1)
            .await
            .unwrap();
        assert_eq!(workspace_audit[0].action, "membership.update");
        assert_eq!(
            workspace_audit[0].actor_principal_id.as_deref(),
            Some(principal.id.as_str())
        );

        let customer_policy = TenantModelPolicy {
            allowed_models: vec!["gpt-customer-policy".into()],
        };
        store
            .set_workspace_model_policy_async(
                &workspace.id,
                &principal.id,
                Some(customer_policy.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            store.model_policy_for_async(&tenant.id).await.unwrap(),
            Some(customer_policy)
        );
        let policy_versions = store
            .list_policy_versions_async(&tenant.id, 10)
            .await
            .unwrap();
        assert!(policy_versions.iter().any(|version| {
            version.active
                && version.approved_by.as_deref() == Some(principal.id.as_str())
                && version.created_by == principal.id
        }));
        let workspace_audit = store
            .list_workspace_admin_audit_async(&workspace.id, 1)
            .await
            .unwrap();
        assert_eq!(workspace_audit[0].action, "model_policy.set");
        assert_eq!(
            workspace_audit[0].actor_principal_id,
            Some(principal.id.clone())
        );
        let customer_limits = TenantLimits {
            rate_limit: Some(TenantRateLimit {
                requests_per_window: 11,
                window_seconds: 90,
            }),
            spend_limit: Some(TenantSpendLimit {
                window_seconds: 3_600,
                max_usd_micros: 2_000_000,
                reserve_usd_micros_per_request: 50_000,
            }),
        };
        store
            .set_workspace_limits_async(&workspace.id, &principal.id, customer_limits.clone())
            .await
            .unwrap();
        assert_eq!(
            store.limits_for_async(&tenant.id).await.unwrap(),
            customer_limits
        );
        let workspace_audit = store
            .list_workspace_admin_audit_async(&workspace.id, 1)
            .await
            .unwrap();
        assert_eq!(workspace_audit[0].action, "limits.set");
        assert_eq!(
            workspace_audit[0].actor_principal_id,
            Some(principal.id.clone())
        );
        store
            .set_workspace_membership_async(&workspace.id, &principal.id, WorkspaceRole::Developer)
            .await
            .unwrap();
        assert!(store
            .set_workspace_model_policy_async(&workspace.id, &principal.id, None)
            .await
            .is_err());
        assert!(store
            .set_workspace_limits_async(&workspace.id, &principal.id, TenantLimits::default())
            .await
            .is_err());

        let organization = store
            .create_organization_async(&format!("PostgreSQL org {}", super::random_id("test")))
            .await
            .unwrap();
        let scim_credential = store
            .issue_scim_token_async(
                &organization.id,
                "PostgreSQL identity provider",
                super::now_unix() + 3_600,
            )
            .await
            .unwrap();
        let scim_header = format!("Bearer {}", scim_credential.token);
        let scim_identity = store
            .authenticate_scim_bearer_async(Some(&scim_header))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            scim_identity,
            super::ScimIdentity {
                organization_id: organization.id.clone(),
                token_id: scim_credential.credential.id.clone(),
            }
        );
        assert_eq!(
            store
                .list_scim_tokens_async(&organization.id)
                .await
                .unwrap(),
            vec![scim_credential.credential.clone()]
        );
        let scim_user = store
            .create_scim_user_async(
                &scim_identity,
                "postgres-idp-user",
                "postgres-user@example.test",
                "PostgreSQL SCIM user",
                true,
            )
            .await
            .unwrap();
        let scim_group = store
            .create_scim_group_async(
                &scim_identity,
                "postgres-idp-group",
                "PostgreSQL SCIM group",
                vec![scim_user.id.clone()],
            )
            .await
            .unwrap();
        assert_eq!(scim_group.member_ids, vec![scim_user.id.clone()]);
        let updated_group = store
            .update_scim_group_async(
                &scim_identity,
                &scim_group.id,
                super::ScimGroupUpdate {
                    member_change: Some(super::ScimGroupMemberChange::Remove(vec![scim_user
                        .id
                        .clone()])),
                    ..super::ScimGroupUpdate::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(updated_group.member_ids.is_empty());
        assert!(store
            .delete_scim_group_async(&scim_identity, &scim_group.id)
            .await
            .unwrap());
        assert!(store
            .revoke_scim_token_async(&scim_credential.credential.id)
            .await
            .unwrap());
        assert_eq!(
            store
                .authenticate_scim_bearer_async(Some(&scim_header))
                .await
                .unwrap(),
            None
        );
        let oidc_connection = store
            .set_organization_oidc_connection_async(
                &organization.id,
                "https://id.example.test/postgresql",
                "postgresql-firewall-console",
                "https://console.example.test/auth/callback",
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .organization_oidc_connection_async(&organization.id)
                .await
                .unwrap(),
            Some(oidc_connection)
        );
        let state = format!("postgres-state-{}", super::random_id("test"));
        store
            .reserve_oidc_authorization_state_async(
                &state,
                &organization.id,
                super::now_unix() + 60,
            )
            .await
            .unwrap();
        assert!(store
            .consume_oidc_authorization_state_async(&state, &organization.id)
            .await
            .unwrap());
        assert!(!store
            .consume_oidc_authorization_state_async(&state, &organization.id)
            .await
            .unwrap());
        let organization_tenant = store
            .create_tenant_in_organization_async(
                &organization.id,
                &format!("PostgreSQL org tenant {}", super::random_id("test")),
            )
            .await
            .unwrap();
        let organization_workspace = store
            .workspace_for_tenant_async(&organization_tenant.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(organization_workspace.organization_id, organization.id);
        store
            .set_workspace_membership_async(
                &organization_workspace.id,
                &principal.id,
                WorkspaceRole::Admin,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .verified_identity_workspace_access_async(
                    &organization.id,
                    &organization_workspace.id,
                    &external_identity.issuer,
                    &external_identity.subject,
                )
                .await
                .unwrap()
                .map(|access| access.role),
            Some(WorkspaceRole::Admin)
        );
        let invitation_owner = store
            .create_workspace_principal_async("PostgreSQL invitation owner")
            .await
            .unwrap();
        store
            .set_workspace_membership_async(
                &organization_workspace.id,
                &invitation_owner.id,
                WorkspaceRole::Owner,
            )
            .await
            .unwrap();
        let issued_invitation = store
            .create_workspace_invitation_as_owner_async(
                &organization_workspace.id,
                &invitation_owner.id,
                "PostgreSQL invited developer",
                WorkspaceRole::Developer,
                super::now_unix() + 600,
            )
            .await
            .unwrap();
        assert!(issued_invitation.token.starts_with("llmfw_invite_"));
        assert_eq!(
            store
                .list_workspace_invitations_as_owner_async(
                    &organization_workspace.id,
                    &invitation_owner.id,
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .workspace_invitation_for_token_async(&issued_invitation.token)
                .await
                .unwrap()
                .map(|invitation| invitation.id),
            Some(issued_invitation.invitation.id.clone())
        );
        assert!(store
            .accept_workspace_invitation_oidc_async(
                &issued_invitation.invitation.id,
                &organization.id,
                &workspace.id,
                &external_identity.issuer,
                "postgres-invited-subject",
            )
            .await
            .unwrap()
            .is_none());
        assert!(store
            .workspace_invitation_for_token_async(&issued_invitation.token)
            .await
            .unwrap()
            .is_some());
        let invited_access = store
            .accept_workspace_invitation_oidc_async(
                &issued_invitation.invitation.id,
                &organization.id,
                &organization_workspace.id,
                &external_identity.issuer,
                "postgres-invited-subject",
            )
            .await
            .unwrap()
            .expect("PostgreSQL invitation accepts a verified identity");
        assert_eq!(invited_access.role, WorkspaceRole::Developer);
        assert!(store
            .workspace_invitation_for_token_async(&issued_invitation.token)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .accept_workspace_invitation_oidc_async(
                &issued_invitation.invitation.id,
                &organization.id,
                &organization_workspace.id,
                &external_identity.issuer,
                "postgres-invited-subject",
            )
            .await
            .unwrap()
            .is_none());
        let verified_access = store
            .verified_identity_workspace_access_async(
                &organization.id,
                &organization_workspace.id,
                &external_identity.issuer,
                &external_identity.subject,
            )
            .await
            .unwrap()
            .expect("PostgreSQL verified identity receives a browser session");
        let browser_session = store
            .issue_oidc_browser_session_async(
                &verified_access,
                BrowserSessionFederation::Oidc,
                super::now_unix() + 3_600,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .authenticate_oidc_browser_session_async(&browser_session.token)
                .await
                .unwrap()
                .map(|session| session.access.role),
            Some(WorkspaceRole::Admin)
        );
        assert!(store
            .revoke_oidc_browser_session_async(&browser_session.token)
            .await
            .unwrap());
        assert_eq!(
            store
                .authenticate_oidc_browser_session_async(&browser_session.token)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .list_organization_workspaces_async(&organization.id)
                .await
                .unwrap(),
            vec![organization_workspace]
        );
        assert!(store
            .set_organization_active_async(&organization.id, false)
            .await
            .unwrap());
        assert!(store
            .create_tenant_in_organization_async(&organization.id, "must fail")
            .await
            .is_err());

        store
            .append_audit_async(&tenant.id, "/v1/chat/completions", "completed", 200, 12)
            .await
            .unwrap();
        store
            .append_audit_async(&tenant.id, "/v1/responses", "rejected", 429, 1)
            .await
            .unwrap();
        store
            .append_audit_async(&tenant.id, "/v1/messages", "completed", 200, 8)
            .await
            .unwrap();
        let audit = store.list_audit_async(&tenant.id, 100).await.unwrap();
        assert_eq!(audit.len(), 2, "configured retention applies");
        assert_eq!(audit[0].path, "/v1/messages");
        assert_eq!(audit[1].outcome, "rejected");

        assert!(store.revoke_token_async(&issued.id).await.unwrap());
        assert_eq!(
            store
                .authenticate_bearer_async(Some(&header))
                .await
                .unwrap(),
            None
        );
    }
}
