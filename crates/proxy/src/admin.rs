// SPDX-License-Identifier: Apache-2.0

//! Authenticated local control-plane endpoints for tenant management.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, ETAG};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::handlers::Shared;
use crate::tenant_store::{
    AdminIdentity, AdminRole, NewUsageReconciliationImport, PolicyDeploymentAction,
    PolicySimulationCase, TenantPolicyDocument, UsageQuotaPolicy, UsageRetentionPolicy,
};

pub const ADMIN_AUTH_HEADER: &str = "x-llm-firewall-admin-token";

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct SetOrganizationStateRequest {
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetOrganizationOidcConnectionRequest {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetOrganizationSamlConnectionRequest {
    pub entity_id: String,
    pub metadata_xml: String,
    pub metadata_signing_cert_pem: String,
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Safe SAML connection inventory. Metadata and certificates are write-only;
/// the fingerprint lets an operator confirm which pinned document is active
/// without reflecting trust material into an API response.
#[derive(Serialize)]
pub struct OrganizationSamlConnectionResponse {
    pub organization_id: String,
    pub entity_id: String,
    pub metadata_sha256: String,
    pub active: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Safe, aggregate onboarding status for an organization. This endpoint is
/// intentionally an operator checklist: it never returns credentials,
/// provider configuration, webhook URLs, or customer content.
#[derive(Serialize)]
pub struct OrganizationOnboardingResponse {
    pub organization_id: String,
    pub organization_active: bool,
    pub has_active_oidc: bool,
    pub has_active_saml: bool,
    pub active_scim_token_count: usize,
    pub workspaces: Vec<WorkspaceOnboardingStatus>,
    pub completed: bool,
    pub next_actions: Vec<String>,
}

#[derive(Serialize)]
pub struct WorkspaceOnboardingStatus {
    pub workspace_id: String,
    pub tenant_id: String,
    pub name: String,
    pub workspace_active: bool,
    pub tenant_active: bool,
    pub active_proxy_token_count: usize,
    pub active_webhook_count: usize,
}

#[derive(Deserialize)]
pub struct IssueTokenRequest {
    pub label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueScimTokenRequest {
    pub label: String,
    pub expires_at_unix: i64,
}

#[derive(Deserialize)]
pub struct SetTenantStateRequest {
    pub active: bool,
}

#[derive(Deserialize)]
pub struct CreateAdminRequest {
    pub name: String,
    pub role: AdminRole,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
}

#[derive(Deserialize)]
pub struct SecurityEventQuery {
    #[serde(default)]
    pub after_sequence: u64,
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunUsageRetentionRequest {
    #[serde(default)]
    pub execute: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePolicyVersionRequest {
    pub document: TenantPolicyDocument,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatePolicyVersionRequest {
    pub cases: Vec<PolicySimulationCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookDestinationRequest {
    pub url: String,
    #[serde(default)]
    pub event_types: Vec<String>,
}

fn default_audit_limit() -> usize {
    100
}

fn default_true() -> bool {
    true
}

/// Protect the control plane separately from model callers. An admin credential
/// must never be accepted on a proxied model route, and a tenant credential
/// must never be accepted here.
pub async fn require_admin_token(
    State(state): State<Shared>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(ADMIN_AUTH_HEADER)
        .and_then(|value| value.to_str().ok());
    let identity = if state
        .admin_token
        .as_deref()
        .is_some_and(|expected| bearer_matches(expected, presented))
    {
        Some(AdminIdentity {
            admin_id: "bootstrap_owner".into(),
            admin_name: "Bootstrap owner".into(),
            role: AdminRole::Owner,
        })
    } else if let Some(store) = &state.tenant_store {
        match store.authenticate_admin_bearer_async(presented).await {
            Ok(identity) => identity,
            Err(error_value) => {
                tracing::error!(error = %error_value, "control-plane admin authentication unavailable");
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "tenant_store_unavailable",
                    "tenant store temporarily unavailable",
                );
            }
        }
    } else {
        None
    };
    let Some(identity) = identity else {
        tracing::warn!(path = %request.uri().path(), "rejected unauthenticated admin request");
        return error(
            StatusCode::UNAUTHORIZED,
            "admin_authentication_error",
            "admin authentication required",
        );
    };
    let required = required_admin_role(request.method(), request.uri().path());
    if !identity.role.permits(required) {
        tracing::warn!(path = %request.uri().path(), role = ?identity.role, "rejected insufficient admin role");
        return error(
            StatusCode::FORBIDDEN,
            "admin_authorization_error",
            "admin role does not permit this operation",
        );
    }
    request.extensions_mut().insert(identity);
    next.run(request).await
}

fn required_admin_role(method: &axum::http::Method, path: &str) -> AdminRole {
    if path.contains("/scim-tokens")
        || (path.contains("/policy-versions/")
            && (path.ends_with("/approve")
                || path.ends_with("/activate")
                || path.ends_with("/rollback")))
        || (*method == axum::http::Method::PUT && path.ends_with("/model-policy"))
        || (*method != axum::http::Method::GET
            && (path.contains("/usage/retention") || path.contains("/usage/quota")))
        || (*method != axum::http::Method::GET
            && path.starts_with("/admin/v1/organizations/")
            && (path.ends_with("/oidc") || path.ends_with("/saml")))
        || (path.contains("/webhook-destinations") && *method != axum::http::Method::GET)
        || (path.contains("/webhook-deliveries") && *method != axum::http::Method::GET)
        || path.starts_with("/admin/v1/admins")
        || (*method == axum::http::Method::DELETE && path.starts_with("/admin/v1/tenants/"))
        || (*method == axum::http::Method::POST && path == "/admin/v1/organizations")
        || (*method == axum::http::Method::PATCH && path.starts_with("/admin/v1/organizations/"))
    {
        AdminRole::Owner
    } else if *method == axum::http::Method::GET {
        AdminRole::Viewer
    } else {
        AdminRole::Operator
    }
}

/// Create an expiring SCIM bearer credential for one organization. It is
/// returned once for placement in the IdP secret manager; inventory endpoints
/// deliberately never return the raw value or its hash.
pub async fn issue_scim_token(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
    Json(request): Json<IssueScimTokenRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .issue_scim_token_async(&organization_id, &request.label, request.expires_at_unix)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(credential) => (StatusCode::CREATED, Json(credential)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to issue SCIM token");
            error(
                StatusCode::BAD_REQUEST,
                "scim_token_issue_error",
                "SCIM token could not be issued",
            )
        }
    }
}

pub async fn list_scim_tokens(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_scim_tokens_async(&organization_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(tokens) => Json(tokens).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list SCIM tokens");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn revoke_scim_token(
    State(state): State<Shared>,
    Path(token_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.revoke_scim_token_async(&token_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "scim_token_not_found",
            "SCIM token not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke SCIM token");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Platform-owner provisioning only. It does not create a customer login or
/// customer-facing endpoint; customer OIDC enrollment is handled separately
/// through the owner-managed workspace membership and invitation flow.
pub async fn create_organization(
    State(state): State<Shared>,
    Json(request): Json<CreateOrganizationRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.create_organization_async(&request.name).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(organization) => (StatusCode::CREATED, Json(organization)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create organization");
            error(
                StatusCode::BAD_REQUEST,
                "organization_create_error",
                "organization could not be created",
            )
        }
    }
}

pub async fn list_organizations(State(state): State<Shared>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_organizations_async().await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(organizations) => Json(organizations).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list organizations");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn set_organization_state(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
    Json(request): Json<SetOrganizationStateRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_organization_active_async(&organization_id, request.active)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "organization_not_found",
            "organization not found",
        ),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to update organization state");
            error(
                StatusCode::BAD_REQUEST,
                "organization_state_error",
                "organization state could not be updated",
            )
        }
    }
}

pub async fn create_organization_tenant(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
    Json(request): Json<CreateTenantRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .create_tenant_in_organization_async(&organization_id, &request.name)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(tenant) => (StatusCode::CREATED, Json(tenant)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create organization tenant");
            error(
                StatusCode::BAD_REQUEST,
                "organization_tenant_create_error",
                "tenant could not be created in this organization",
            )
        }
    }
}

pub async fn list_organization_workspaces(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_organization_workspaces_async(&organization_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(workspaces) => Json(workspaces).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list organization workspaces");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Return a privacy-safe onboarding checklist for a hosted organization.
/// Every field is derived from control-plane metadata and the response never
/// exposes a raw token, secret, provider URL, webhook URL, or model traffic.
pub async fn get_organization_onboarding(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result: anyhow::Result<Option<OrganizationOnboardingResponse>> = async {
        let store = store(&state)?;
        let organization = store
            .list_organizations_async()
            .await?
            .into_iter()
            .find(|organization| organization.id == organization_id);
        let Some(organization) = organization else {
            return Ok(None);
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let has_active_oidc = store
            .organization_oidc_connection_async(&organization_id)
            .await?
            .is_some_and(|connection| connection.active);
        let has_active_saml = store
            .organization_saml_connection_async(&organization_id)
            .await?
            .is_some_and(|connection| connection.active);
        let active_scim_token_count = store
            .list_scim_tokens_async(&organization_id)
            .await?
            .into_iter()
            .filter(|token| token.active && token.expires_at_unix > now_unix)
            .count();
        let tenant_active_by_id: HashMap<_, _> = store
            .list_tenants_async()
            .await?
            .into_iter()
            .map(|tenant| (tenant.id, tenant.active))
            .collect();

        let mut workspaces = Vec::new();
        for workspace in store
            .list_organization_workspaces_async(&organization_id)
            .await?
        {
            let active_proxy_token_count = store
                .list_tokens_async(&workspace.tenant_id)
                .await?
                .into_iter()
                .filter(|token| token.active)
                .count();
            let active_webhook_count = store
                .list_webhook_destinations_async(&workspace.tenant_id)
                .await?
                .into_iter()
                .filter(|destination| destination.active)
                .count();
            workspaces.push(WorkspaceOnboardingStatus {
                workspace_id: workspace.id,
                tenant_id: workspace.tenant_id.clone(),
                name: workspace.name,
                workspace_active: workspace.active,
                tenant_active: tenant_active_by_id
                    .get(&workspace.tenant_id)
                    .copied()
                    .unwrap_or(false),
                active_proxy_token_count,
                active_webhook_count,
            });
        }

        let mut next_actions = Vec::new();
        if !organization.active {
            next_actions.push("activate_organization".to_owned());
        }
        if !has_active_oidc && !has_active_saml {
            next_actions.push("configure_oidc_or_saml".to_owned());
        }
        if workspaces.is_empty() {
            next_actions.push("create_workspace".to_owned());
        }
        for workspace in &workspaces {
            if !workspace.workspace_active || !workspace.tenant_active {
                next_actions.push(format!("activate_workspace:{}", workspace.workspace_id));
            }
            if workspace.active_proxy_token_count == 0 {
                next_actions.push(format!("issue_proxy_token:{}", workspace.workspace_id));
            }
        }

        Ok(Some(OrganizationOnboardingResponse {
            organization_id: organization.id,
            organization_active: organization.active,
            has_active_oidc,
            has_active_saml,
            active_scim_token_count,
            completed: next_actions.is_empty(),
            workspaces,
            next_actions,
        }))
    }
    .await;

    match result {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "organization_not_found",
            "organization not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load organization onboarding status");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Store public OIDC metadata for a future authorization-code + PKCE flow. The
/// endpoint deliberately has no client-secret field and does not authenticate a
/// user or bind an external subject.
pub async fn set_organization_oidc_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
    Json(request): Json<SetOrganizationOidcConnectionRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_organization_oidc_connection_async(
                    &organization_id,
                    &request.issuer,
                    &request.client_id,
                    &request.redirect_uri,
                    request.active,
                )
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(connection) => Json(connection).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save organization OIDC connection");
            error(
                StatusCode::BAD_REQUEST,
                "organization_oidc_connection_error",
                "OIDC connection could not be saved",
            )
        }
    }
}

pub async fn get_organization_oidc_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .organization_oidc_connection_async(&organization_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(Some(connection)) => Json(connection).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "organization_oidc_connection_not_found",
            "OIDC connection not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load organization OIDC connection");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn delete_organization_oidc_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .delete_organization_oidc_connection_async(&organization_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "organization_oidc_connection_not_found",
            "OIDC connection not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to delete organization OIDC connection");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn set_organization_saml_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
    Json(request): Json<SetOrganizationSamlConnectionRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_organization_saml_connection_async(
                    &organization_id,
                    &request.entity_id,
                    &request.metadata_xml,
                    &request.metadata_signing_cert_pem,
                    request.active,
                )
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(connection) => Json(saml_connection_response(connection)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save organization SAML connection");
            error(
                StatusCode::BAD_REQUEST,
                "organization_saml_connection_error",
                "SAML connection could not be saved",
            )
        }
    }
}

pub async fn get_organization_saml_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .organization_saml_connection_async(&organization_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(Some(connection)) => Json(saml_connection_response(connection)).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "organization_saml_connection_not_found",
            "SAML connection not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load organization SAML connection");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn delete_organization_saml_connection(
    State(state): State<Shared>,
    Path(organization_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .delete_organization_saml_connection_async(&organization_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "organization_saml_connection_not_found",
            "SAML connection not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to delete organization SAML connection");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

fn saml_connection_response(
    connection: crate::tenant_store::OrganizationSamlConnection,
) -> OrganizationSamlConnectionResponse {
    let metadata_sha256 = Sha256::digest(connection.metadata_xml.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    OrganizationSamlConnectionResponse {
        organization_id: connection.organization_id,
        entity_id: connection.entity_id,
        metadata_sha256,
        active: connection.active,
        created_at_unix: connection.created_at_unix,
        updated_at_unix: connection.updated_at_unix,
    }
}

pub async fn create_tenant(
    State(state): State<Shared>,
    Json(request): Json<CreateTenantRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.create_tenant_async(&request.name).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(tenant) => (StatusCode::CREATED, Json(tenant)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create tenant");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_create_error",
                "tenant could not be created",
            )
        }
    }
}

pub async fn list_tenants(State(state): State<Shared>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_tenants_async().await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(tenants) => Json(tenants).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list tenants");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Returns only the identity and role inferred from the verified admin
/// credential. The credential itself is never reflected to the browser.
pub async fn whoami(Extension(identity): Extension<AdminIdentity>) -> Json<AdminIdentity> {
    Json(identity)
}

pub async fn set_tenant_state(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(request): Json<SetTenantStateRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_tenant_active_async(&tenant_id, request.active)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "tenant_not_found",
            "tenant not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to update tenant state");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn delete_tenant(State(state): State<Shared>, Path(tenant_id): Path<String>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.delete_tenant_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "tenant_not_found",
            "tenant not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to delete tenant");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn create_admin(
    State(state): State<Shared>,
    Json(request): Json<CreateAdminRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.create_admin_async(&request.name, request.role).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(admin) => (StatusCode::CREATED, Json(admin)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create control-plane admin");
            error(
                StatusCode::BAD_REQUEST,
                "admin_create_error",
                "control-plane admin could not be created",
            )
        }
    }
}

pub async fn list_admins(State(state): State<Shared>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_admins_async().await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(admins) => Json(admins).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list control-plane admins");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn revoke_admin(State(state): State<Shared>, Path(admin_id): Path<String>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.revoke_admin_async(&admin_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "admin_not_found", "admin not found"),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke control-plane admin");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn issue_token(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(request): Json<IssueTokenRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.issue_token_async(&tenant_id, &request.label).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(token) => (StatusCode::CREATED, Json(token)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to issue tenant token");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_token_issue_error",
                "tenant token could not be issued",
            )
        }
    }
}

pub async fn list_tokens(State(state): State<Shared>, Path(tenant_id): Path<String>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_tokens_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(tokens) => Json(tokens).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list tenant token inventory");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn revoke_token(State(state): State<Shared>, Path(token_id): Path<String>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.revoke_token_async(&token_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "tenant_token_not_found",
            "token not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to revoke tenant token");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn get_limits(State(state): State<Shared>, Path(tenant_id): Path<String>) -> Response {
    let result = match store(&state) {
        Ok(store) => store.limits_for_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(limits) => Json(limits).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load tenant limits");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Replaces both optional tenant policies. Sending `null` (or omitting) a
/// policy clears it, which makes safe rollback straightforward.
pub async fn set_limits(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(limits): Json<crate::tenant_store::TenantLimits>,
) -> Response {
    if limits.spend_limit.is_some() && state.config.spend_limit.model_prices.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "tenant_spend_prices_missing",
            "configure current model_prices before enabling a tenant spend limit",
        );
    }
    let result = match store(&state) {
        Ok(store) => store.set_limits_async(&tenant_id, limits.clone()).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(()) => Json(limits).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save tenant limits");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_limits_error",
                "tenant limits could not be saved",
            )
        }
    }
}

pub async fn get_model_policy(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.model_policy_for_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(policy) => Json(policy).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load tenant model policy");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Replace an exact model allowlist. Send a JSON `null` body to clear it and
/// restore the operator-level model behaviour for the tenant.
pub async fn set_model_policy(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(policy): Json<Option<crate::tenant_store::TenantModelPolicy>>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            async {
                let version = store
                    .create_policy_version_async(
                        &tenant_id,
                        &identity.admin_id,
                        TenantPolicyDocument::new(policy.clone()),
                    )
                    .await?;
                store
                    .approve_policy_version_async(&tenant_id, &version.id, &identity.admin_id)
                    .await?;
                store
                    .deploy_policy_version_async(
                        &tenant_id,
                        &version.id,
                        &identity.admin_id,
                        PolicyDeploymentAction::Activate,
                    )
                    .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(()) => Json(policy).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save tenant model policy");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_model_policy_error",
                "tenant model policy could not be saved",
            )
        }
    }
}

pub async fn create_policy_version(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreatePolicyVersionRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .create_policy_version_async(&tenant_id, &identity.admin_id, request.document)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(version) => (StatusCode::CREATED, Json(version)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create tenant policy version");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_policy_version_error",
                "tenant policy version could not be created",
            )
        }
    }
}

pub async fn list_policy_versions(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_policy_versions_async(&tenant_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(versions) => Json(versions).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list tenant policy versions");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn get_policy_version(
    State(state): State<Shared>,
    Path((tenant_id, version_id)): Path<(String, String)>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.policy_version_async(&tenant_id, &version_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(Some(version)) => Json(version).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "tenant_policy_version_not_found",
            "tenant policy version not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load tenant policy version");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn export_policy_version(
    State(state): State<Shared>,
    Path((tenant_id, version_id)): Path<(String, String)>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.policy_version_async(&tenant_id, &version_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(Some(version)) => {
            let etag = HeaderValue::from_str(&format!("\"sha256:{}\"", version.content_sha256))
                .expect("hex policy hash produces a valid ETag");
            let mut response = Json(version).into_response();
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/vnd.llm-firewall.policy+json"),
            );
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
            response.headers_mut().insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=soup-wall-policy.json"),
            );
            response.headers_mut().insert(ETAG, etag);
            response
        }
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "tenant_policy_version_not_found",
            "tenant policy version not found",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to export tenant policy version");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn simulate_policy_version(
    State(state): State<Shared>,
    Path((tenant_id, version_id)): Path<(String, String)>,
    Json(request): Json<SimulatePolicyVersionRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .simulate_policy_version_async(&tenant_id, &version_id, request.cases)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(simulation) => Json(simulation).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to simulate tenant policy version");
            error(
                StatusCode::BAD_REQUEST,
                "tenant_policy_simulation_error",
                "tenant policy simulation could not be completed",
            )
        }
    }
}

pub async fn approve_policy_version(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant_id, version_id)): Path<(String, String)>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .approve_policy_version_async(&tenant_id, &version_id, &identity.admin_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(version) => Json(version).into_response(),
        Err(error_value) => policy_mutation_error(error_value, "approve"),
    }
}

pub async fn activate_policy_version(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant_id, version_id)): Path<(String, String)>,
) -> Response {
    deploy_policy_version(
        &state,
        &identity,
        &tenant_id,
        &version_id,
        PolicyDeploymentAction::Activate,
    )
    .await
}

pub async fn rollback_policy_version(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant_id, version_id)): Path<(String, String)>,
) -> Response {
    deploy_policy_version(
        &state,
        &identity,
        &tenant_id,
        &version_id,
        PolicyDeploymentAction::Rollback,
    )
    .await
}

async fn deploy_policy_version(
    state: &Shared,
    identity: &AdminIdentity,
    tenant_id: &str,
    version_id: &str,
    action: PolicyDeploymentAction,
) -> Response {
    let result = match store(state) {
        Ok(store) => {
            store
                .deploy_policy_version_async(tenant_id, version_id, &identity.admin_id, action)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(deployment) => Json(deployment).into_response(),
        Err(error_value) => policy_mutation_error(error_value, action.storage_value()),
    }
}

pub async fn list_policy_deployments(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_policy_deployments_async(&tenant_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(deployments) => Json(deployments).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list tenant policy deployments");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

/// Export immutable, cursor-addressable control-plane events for SIEM
/// collectors. The cursor is exclusive and scoped to the tenant in the path.
pub async fn list_security_events(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<SecurityEventQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_security_events_async(&tenant_id, query.after_sequence, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(events) => Json(events).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list security events");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn create_webhook_destination(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateWebhookDestinationRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .create_webhook_destination_async(&tenant_id, &request.url, &request.event_types)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(destination) => (StatusCode::CREATED, Json(destination)).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to create webhook destination");
            error(
                StatusCode::BAD_REQUEST,
                "webhook_destination_error",
                "webhook destination could not be created",
            )
        }
    }
}

pub async fn list_webhook_destinations(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_webhook_destinations_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(destinations) => Json(destinations).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list webhook destinations");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn deactivate_webhook_destination(
    State(state): State<Shared>,
    Path((tenant_id, destination_id)): Path<(String, String)>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .deactivate_webhook_destination_async(&tenant_id, &destination_id)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "webhook_destination_not_found",
            "webhook destination not found or already inactive",
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to deactivate webhook destination");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn list_webhook_deliveries(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_webhook_deliveries_async(&tenant_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(deliveries) => Json(deliveries).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list webhook deliveries");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

fn policy_mutation_error(error_value: anyhow::Error, operation: &str) -> Response {
    tracing::warn!(error = %error_value, operation, "tenant policy lifecycle mutation failed");
    error(
        StatusCode::BAD_REQUEST,
        "tenant_policy_lifecycle_error",
        "tenant policy lifecycle operation could not be completed",
    )
}

pub async fn list_audit(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.list_audit_async(&tenant_id, query.limit).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(events) => Json(events).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list tenant audit history");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn import_usage_reconciliation(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(import): Json<NewUsageReconciliationImport>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .import_usage_reconciliation_async(&tenant_id, &identity.admin_id, &import)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(run) => Json(run).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to import provider usage statement");
            error(
                StatusCode::BAD_REQUEST,
                "usage_reconciliation_import_error",
                "provider usage statement could not be imported",
            )
        }
    }
}

pub async fn list_usage_reconciliation_runs(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_usage_reconciliation_runs_async(&tenant_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(runs) => Json(runs).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list usage reconciliation runs");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn list_usage_reconciliation_observations(
    State(state): State<Shared>,
    Path((tenant_id, run_id)): Path<(String, String)>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_usage_reconciliation_observations_async(&tenant_id, &run_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(observations) => Json(observations).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list usage reconciliation observations");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn get_usage_retention_policy(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.usage_retention_policy_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(policy) => Json(policy).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load usage retention policy");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn set_usage_retention_policy(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(policy): Json<Option<UsageRetentionPolicy>>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_usage_retention_policy_async(&tenant_id, &identity.admin_id, policy.clone())
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(()) => Json(policy).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save usage retention policy");
            error(
                StatusCode::BAD_REQUEST,
                "usage_retention_policy_error",
                "usage retention policy could not be saved",
            )
        }
    }
}

pub async fn run_usage_retention(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(request): Json<RunUsageRetentionRequest>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .run_usage_retention_async(&tenant_id, &identity.admin_id, request.execute)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(run) => Json(run).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to run usage retention");
            error(
                StatusCode::BAD_REQUEST,
                "usage_retention_run_error",
                "usage retention run could not be completed",
            )
        }
    }
}

pub async fn list_usage_retention_runs(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .list_usage_retention_runs_async(&tenant_id, query.limit)
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(runs) => Json(runs).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list usage retention runs");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn get_usage_quota_status(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => store.usage_quota_status_async(&tenant_id).await,
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(status) => Json(status).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load usage quota status");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_store_unavailable",
                "tenant store temporarily unavailable",
            )
        }
    }
}

pub async fn set_usage_quota_policy(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(policy): Json<Option<UsageQuotaPolicy>>,
) -> Response {
    let result = match store(&state) {
        Ok(store) => {
            store
                .set_usage_quota_policy_async(&tenant_id, &identity.admin_id, policy.clone())
                .await
        }
        Err(error_value) => Err(error_value),
    };
    match result {
        Ok(()) => Json(policy).into_response(),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to save usage quota policy");
            error(
                StatusCode::BAD_REQUEST,
                "usage_quota_policy_error",
                "usage quota policy could not be saved",
            )
        }
    }
}

fn store(state: &Shared) -> anyhow::Result<&crate::tenant_store::TenantStore> {
    state
        .tenant_store
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("tenant store is not enabled"))
}

fn bearer_matches(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
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
    use axum::http::Method;

    use super::{bearer_matches, required_admin_role};
    use crate::tenant_store::AdminRole;

    #[test]
    fn accepts_only_the_bearer_form_of_the_exact_admin_token() {
        assert!(bearer_matches("secret", Some("Bearer secret")));
        assert!(!bearer_matches("secret", Some("secret")));
        assert!(!bearer_matches("secret", Some("Bearer incorrect")));
        assert!(!bearer_matches("secret", None));
    }

    #[test]
    fn oidc_connection_changes_are_owner_only_but_readable_by_viewers() {
        let path = "/admin/v1/organizations/org_example/oidc";
        assert_eq!(required_admin_role(&Method::GET, path), AdminRole::Viewer);
        assert_eq!(required_admin_role(&Method::PUT, path), AdminRole::Owner);
        assert_eq!(required_admin_role(&Method::DELETE, path), AdminRole::Owner);
        assert!(!AdminRole::Operator.permits(required_admin_role(&Method::PUT, path)));
    }

    #[test]
    fn onboarding_status_is_read_only_to_viewers() {
        let path = "/admin/v1/organizations/org_example/onboarding";
        assert_eq!(required_admin_role(&Method::GET, path), AdminRole::Viewer);
        assert!(!AdminRole::Viewer.permits(required_admin_role(&Method::POST, path)));
    }

    #[test]
    fn scim_credentials_are_owner_only_even_for_inventory_reads() {
        let inventory_path = "/admin/v1/organizations/org_example/scim-tokens";
        let revoke_path = "/admin/v1/scim-tokens/scim_example/revoke";
        assert_eq!(
            required_admin_role(&Method::GET, inventory_path),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, inventory_path),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, revoke_path),
            AdminRole::Owner
        );
        assert!(!AdminRole::Operator.permits(required_admin_role(&Method::GET, inventory_path)));
    }

    #[test]
    fn usage_retention_mutations_are_owner_only() {
        let policy_path = "/admin/v1/tenants/tenant_example/usage/retention/policy";
        let runs_path = "/admin/v1/tenants/tenant_example/usage/retention/runs";
        let quota_path = "/admin/v1/tenants/tenant_example/usage/quota";
        assert_eq!(
            required_admin_role(&Method::GET, policy_path),
            AdminRole::Viewer
        );
        assert_eq!(
            required_admin_role(&Method::GET, runs_path),
            AdminRole::Viewer
        );
        assert_eq!(
            required_admin_role(&Method::PUT, policy_path),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, runs_path),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::GET, quota_path),
            AdminRole::Viewer
        );
        assert_eq!(
            required_admin_role(&Method::PUT, quota_path),
            AdminRole::Owner
        );
        assert!(!AdminRole::Operator.permits(required_admin_role(&Method::POST, runs_path)));
        assert!(!AdminRole::Operator.permits(required_admin_role(&Method::PUT, quota_path)));
    }

    #[test]
    fn policy_versions_separate_drafting_from_owner_approval() {
        let versions = "/admin/v1/tenants/tenant_example/policy-versions";
        let simulate = "/admin/v1/tenants/tenant_example/policy-versions/policy_example/simulate";
        let approve = "/admin/v1/tenants/tenant_example/policy-versions/policy_example/approve";
        let activate = "/admin/v1/tenants/tenant_example/policy-versions/policy_example/activate";
        let rollback = "/admin/v1/tenants/tenant_example/policy-versions/policy_example/rollback";
        assert_eq!(
            required_admin_role(&Method::POST, versions),
            AdminRole::Operator
        );
        assert_eq!(
            required_admin_role(&Method::POST, simulate),
            AdminRole::Operator
        );
        assert_eq!(
            required_admin_role(&Method::POST, approve),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, activate),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, rollback),
            AdminRole::Owner
        );
    }

    #[test]
    fn webhook_destination_changes_are_owner_only_but_delivery_inventory_is_readable() {
        let destinations = "/admin/v1/tenants/tenant_example/webhook-destinations";
        let deactivate =
            "/admin/v1/tenants/tenant_example/webhook-destinations/webhook_example/deactivate";
        let deliveries = "/admin/v1/tenants/tenant_example/webhook-deliveries";
        assert_eq!(
            required_admin_role(&Method::GET, destinations),
            AdminRole::Viewer
        );
        assert_eq!(
            required_admin_role(&Method::POST, destinations),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::POST, deactivate),
            AdminRole::Owner
        );
        assert_eq!(
            required_admin_role(&Method::GET, deliveries),
            AdminRole::Viewer
        );
        assert!(!AdminRole::Operator.permits(required_admin_role(&Method::POST, destinations)));
    }
}
