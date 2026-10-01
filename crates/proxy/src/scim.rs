// SPDX-License-Identifier: Apache-2.0

//! Minimal, deliberately constrained SCIM 2.0 directory API.
//!
//! A SCIM bearer is scoped to one organization and is not interchangeable
//! with an admin, browser, or proxy credential. Provisioning a user creates a
//! directory record only: no workspace membership, OIDC binding, service
//! token, or model-proxy access is granted implicitly.

use std::collections::HashSet;

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, Extension, Path, Query, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    handlers::Shared,
    tenant_store::{
        ScimGroup, ScimGroupMemberChange, ScimGroupUpdate, ScimIdentity, ScimUser, ScimUserUpdate,
    },
};

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const MAX_PAGE_SIZE: usize = 100;
const MAX_START_INDEX: usize = 1_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimUserCreateRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    pub external_id: String,
    pub user_name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimUserListQuery {
    #[serde(default = "default_start_index")]
    pub start_index: usize,
    #[serde(default = "default_count")]
    pub count: usize,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort_by: Option<String>,
    #[serde(default)]
    pub sort_order: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", alias = "operations")]
    pub operations: Vec<ScimPatchOperation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimPatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimGroupCreateRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    pub external_id: String,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimGroupMemberInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimGroupMemberInput {
    pub value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserResource {
    schemas: [&'static str; 1],
    id: String,
    external_id: String,
    user_name: String,
    display_name: String,
    active: bool,
}

impl From<ScimUser> for ScimUserResource {
    fn from(user: ScimUser) -> Self {
        Self {
            schemas: [SCIM_USER_SCHEMA],
            id: user.id,
            external_id: user.external_id,
            user_name: user.user_name,
            display_name: user.display_name,
            active: user.active,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupMemberResource {
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupResource {
    schemas: [&'static str; 1],
    id: String,
    external_id: String,
    display_name: String,
    members: Vec<ScimGroupMemberResource>,
}

impl From<ScimGroup> for ScimGroupResource {
    fn from(group: ScimGroup) -> Self {
        Self {
            schemas: [SCIM_GROUP_SCHEMA],
            id: group.id,
            external_id: group.external_id,
            display_name: group.display_name,
            members: group
                .member_ids
                .into_iter()
                .map(|value| ScimGroupMemberResource { value })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserListResponse {
    schemas: [&'static str; 1],
    total_results: u64,
    start_index: usize,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<ScimUserResource>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupListResponse {
    schemas: [&'static str; 1],
    total_results: u64,
    start_index: usize,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<ScimGroupResource>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimErrorResponse {
    schemas: [&'static str; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'static str>,
    detail: &'static str,
    status: String,
}

fn default_true() -> bool {
    true
}

fn default_start_index() -> usize {
    1
}

fn default_count() -> usize {
    MAX_PAGE_SIZE
}

/// Require an organization-scoped SCIM bearer. It intentionally never logs a
/// supplied header or token, and attaches only safe organization/token IDs.
pub async fn require_scim_token(
    State(state): State<Shared>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let identity = match store.authenticate_scim_bearer_async(presented).await {
        Ok(identity) => identity,
        Err(error_value) => {
            tracing::error!(error = %error_value, "SCIM credential verification unavailable");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "SCIM control plane is unavailable",
            );
        }
    };
    let Some(identity) = identity else {
        let mut response = scim_error(
            StatusCode::UNAUTHORIZED,
            None,
            "SCIM bearer authentication is required",
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"Soup Wall SCIM\""),
        );
        return response;
    };
    request.extensions_mut().insert(identity);
    next.run(request).await
}

/// Advertise the deliberately constrained SCIM surface. Both resources are
/// provisioned without implicit authority; group-to-workspace grants remain
/// separately owner-approved in the customer control plane.
pub async fn service_provider_config() -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
            "patch": { "supported": true },
            "bulk": { "supported": false },
            "filter": { "supported": false, "maxResults": 0 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Organization SCIM bearer",
                "description": "Expiring organization-scoped bearer credential",
                "primary": true
            }]
        }),
    )
}

pub async fn create_user(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    payload: Result<Json<ScimUserCreateRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "Invalid SCIM JSON",
            )
        }
    };
    if !valid_schemas(&request.schemas, SCIM_USER_SCHEMA) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Unsupported SCIM User schema",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    let display_name = request
        .display_name
        .as_deref()
        .unwrap_or(&request.user_name);
    match store
        .create_scim_user_async(
            &identity,
            &request.external_id,
            &request.user_name,
            display_name,
            request.active,
        )
        .await
    {
        Ok(user) => scim_json(StatusCode::CREATED, ScimUserResource::from(user)),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to provision SCIM user");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM User could not be provisioned",
            )
        }
    }
}

pub async fn list_users(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Query(query): Query<ScimUserListQuery>,
) -> Response {
    if query.filter.is_some() || query.sort_by.is_some() || query.sort_order.is_some() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            "SCIM filtering and sorting are not supported",
        );
    }
    if !valid_page(query.start_index, query.count) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "SCIM pagination is outside the supported range",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store
        .list_scim_users_async(&identity, query.start_index, query.count)
        .await
    {
        Ok(page) => scim_json(
            StatusCode::OK,
            ScimUserListResponse {
                schemas: [SCIM_LIST_RESPONSE_SCHEMA],
                total_results: page.total_results,
                start_index: page.start_index,
                items_per_page: page.items_per_page,
                resources: page
                    .resources
                    .into_iter()
                    .map(ScimUserResource::from)
                    .collect(),
            },
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list SCIM users");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "SCIM control plane is unavailable",
            )
        }
    }
}

pub async fn get_user(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(user_id): Path<String>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store.scim_user_by_id_async(&identity, &user_id).await {
        Ok(Some(user)) => scim_json(StatusCode::OK, ScimUserResource::from(user)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, None, "SCIM User was not found"),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to load SCIM user");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM User identifier is invalid",
            )
        }
    }
}

pub async fn patch_user(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(user_id): Path<String>,
    payload: Result<Json<ScimPatchRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "Invalid SCIM JSON",
            )
        }
    };
    if !valid_schemas(&request.schemas, SCIM_PATCH_OP_SCHEMA) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Unsupported SCIM PatchOp schema",
        );
    }
    let update = match parse_patch(request.operations) {
        Ok(update) => update,
        Err((scim_type, detail)) => {
            return scim_error(StatusCode::BAD_REQUEST, Some(scim_type), detail)
        }
    };
    update_user(&state, &identity, &user_id, update).await
}

pub async fn delete_user(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(user_id): Path<String>,
) -> Response {
    match update_user(
        &state,
        &identity,
        &user_id,
        ScimUserUpdate {
            active: Some(false),
            ..ScimUserUpdate::default()
        },
    )
    .await
    {
        response if response.status() == StatusCode::OK => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        response => response,
    }
}

/// SCIM groups are directory-only records. Neither creating a group nor
/// adding a member grants a workspace role; that remains a separate explicit
/// owner action.
pub async fn create_group(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    payload: Result<Json<ScimGroupCreateRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "Invalid SCIM JSON",
            )
        }
    };
    if !valid_schemas(&request.schemas, SCIM_GROUP_SCHEMA) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Unsupported SCIM Group schema",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    let member_ids = request
        .members
        .into_iter()
        .map(|member| member.value)
        .collect();
    match store
        .create_scim_group_async(
            &identity,
            &request.external_id,
            &request.display_name,
            member_ids,
        )
        .await
    {
        Ok(group) => scim_json(StatusCode::CREATED, ScimGroupResource::from(group)),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to provision SCIM group");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM Group could not be provisioned",
            )
        }
    }
}

pub async fn list_groups(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Query(query): Query<ScimUserListQuery>,
) -> Response {
    if query.filter.is_some() || query.sort_by.is_some() || query.sort_order.is_some() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            "SCIM filtering and sorting are not supported",
        );
    }
    if !valid_page(query.start_index, query.count) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "SCIM pagination is outside the supported range",
        );
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store
        .list_scim_groups_async(&identity, query.start_index, query.count)
        .await
    {
        Ok(page) => scim_json(
            StatusCode::OK,
            ScimGroupListResponse {
                schemas: [SCIM_LIST_RESPONSE_SCHEMA],
                total_results: page.total_results,
                start_index: page.start_index,
                items_per_page: page.items_per_page,
                resources: page
                    .resources
                    .into_iter()
                    .map(ScimGroupResource::from)
                    .collect(),
            },
        ),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to list SCIM groups");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                "SCIM control plane is unavailable",
            )
        }
    }
}

pub async fn get_group(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(group_id): Path<String>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store.scim_group_by_id_async(&identity, &group_id).await {
        Ok(Some(group)) => scim_json(StatusCode::OK, ScimGroupResource::from(group)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, None, "SCIM Group was not found"),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to load SCIM group");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM Group identifier is invalid",
            )
        }
    }
}

pub async fn patch_group(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(group_id): Path<String>,
    payload: Result<Json<ScimPatchRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "Invalid SCIM JSON",
            )
        }
    };
    if !valid_schemas(&request.schemas, SCIM_PATCH_OP_SCHEMA) {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Unsupported SCIM PatchOp schema",
        );
    }
    let update = match parse_group_patch(request.operations) {
        Ok(update) => update,
        Err((scim_type, detail)) => {
            return scim_error(StatusCode::BAD_REQUEST, Some(scim_type), detail)
        }
    };
    update_group(&state, &identity, &group_id, update).await
}

pub async fn delete_group(
    State(state): State<Shared>,
    Extension(identity): Extension<ScimIdentity>,
    Path(group_id): Path<String>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store.delete_scim_group_async(&identity, &group_id).await {
        Ok(true) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(false) => scim_error(StatusCode::NOT_FOUND, None, "SCIM Group was not found"),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to delete SCIM group");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM Group identifier is invalid",
            )
        }
    }
}

async fn update_user(
    state: &Shared,
    identity: &ScimIdentity,
    user_id: &str,
    update: ScimUserUpdate,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store
        .update_scim_user_async(identity, user_id, update)
        .await
    {
        Ok(Some(user)) => scim_json(StatusCode::OK, ScimUserResource::from(user)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, None, "SCIM User was not found"),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to update SCIM user");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM User could not be updated",
            )
        }
    }
}

async fn update_group(
    state: &Shared,
    identity: &ScimIdentity,
    group_id: &str,
    update: ScimGroupUpdate,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "SCIM control plane is unavailable",
        );
    };
    match store
        .update_scim_group_async(identity, group_id, update)
        .await
    {
        Ok(Some(group)) => scim_json(StatusCode::OK, ScimGroupResource::from(group)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, None, "SCIM Group was not found"),
        Err(error_value) => {
            tracing::warn!(error = %error_value, "failed to update SCIM group");
            scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "SCIM Group could not be updated",
            )
        }
    }
}

fn parse_patch(
    operations: Vec<ScimPatchOperation>,
) -> Result<ScimUserUpdate, (&'static str, &'static str)> {
    if operations.is_empty() || operations.len() > 3 {
        return Err((
            "invalidValue",
            "A SCIM patch must contain one to three operations",
        ));
    }
    let mut seen = HashSet::new();
    let mut update = ScimUserUpdate::default();
    for operation in operations {
        if !operation.op.eq_ignore_ascii_case("replace") {
            return Err((
                "invalidSyntax",
                "Only SCIM replace operations are supported",
            ));
        }
        let Some(path) = operation.path else {
            return Err(("invalidPath", "Every SCIM operation needs a supported path"));
        };
        let path = path.to_ascii_lowercase();
        if !seen.insert(path.clone()) {
            return Err((
                "invalidValue",
                "A SCIM attribute can only be changed once per patch",
            ));
        }
        match path.as_str() {
            "active" => {
                update.active = operation.value.as_bool();
                if update.active.is_none() {
                    return Err(("invalidValue", "SCIM active must be a boolean"));
                }
            }
            "username" => {
                update.user_name = operation.value.as_str().map(str::to_owned);
                if update.user_name.is_none() {
                    return Err(("invalidValue", "SCIM userName must be a string"));
                }
            }
            "displayname" => {
                update.display_name = operation.value.as_str().map(str::to_owned);
                if update.display_name.is_none() {
                    return Err(("invalidValue", "SCIM displayName must be a string"));
                }
            }
            _ => return Err(("invalidPath", "That SCIM User attribute is not mutable")),
        }
    }
    Ok(update)
}

fn parse_group_patch(
    operations: Vec<ScimPatchOperation>,
) -> Result<ScimGroupUpdate, (&'static str, &'static str)> {
    if operations.is_empty() || operations.len() > 2 {
        return Err((
            "invalidValue",
            "A SCIM Group patch must contain one or two operations",
        ));
    }
    let mut seen = HashSet::new();
    let mut update = ScimGroupUpdate::default();
    for operation in operations {
        let Some(path) = operation.path else {
            return Err(("invalidPath", "Every SCIM operation needs a supported path"));
        };
        let path = path.to_ascii_lowercase();
        if !seen.insert(path.clone()) {
            return Err((
                "invalidValue",
                "A SCIM Group attribute can only be changed once per patch",
            ));
        }
        match path.as_str() {
            "displayname" => {
                if !operation.op.eq_ignore_ascii_case("replace") {
                    return Err(("invalidSyntax", "SCIM displayName only supports replace"));
                }
                update.display_name = operation.value.as_str().map(str::to_owned);
                if update.display_name.is_none() {
                    return Err(("invalidValue", "SCIM displayName must be a string"));
                }
            }
            "members" => {
                let member_ids = parse_group_member_values(operation.value)?;
                update.member_change = Some(if operation.op.eq_ignore_ascii_case("replace") {
                    ScimGroupMemberChange::Replace(member_ids)
                } else if operation.op.eq_ignore_ascii_case("add") {
                    ScimGroupMemberChange::Add(member_ids)
                } else if operation.op.eq_ignore_ascii_case("remove") {
                    ScimGroupMemberChange::Remove(member_ids)
                } else {
                    return Err((
                        "invalidSyntax",
                        "SCIM members supports add, replace, or remove",
                    ));
                });
            }
            _ => return Err(("invalidPath", "That SCIM Group attribute is not mutable")),
        }
    }
    Ok(update)
}

fn parse_group_member_values(value: Value) -> Result<Vec<String>, (&'static str, &'static str)> {
    let members = serde_json::from_value::<Vec<ScimGroupMemberInput>>(value).map_err(|_| {
        (
            "invalidValue",
            "SCIM members must be an array of objects containing only value",
        )
    })?;
    Ok(members.into_iter().map(|member| member.value).collect())
}

fn valid_schemas(schemas: &[String], expected: &str) -> bool {
    schemas.is_empty() || (schemas.len() == 1 && schemas[0] == expected)
}

fn valid_page(start_index: usize, count: usize) -> bool {
    (1..=MAX_START_INDEX).contains(&start_index) && count <= MAX_PAGE_SIZE
}

fn scim_json(status: StatusCode, value: impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn scim_error(
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: &'static str,
) -> Response {
    scim_json(
        status,
        ScimErrorResponse {
            schemas: [SCIM_ERROR_SCHEMA],
            scim_type,
            detail,
            status: status.as_u16().to_string(),
        },
    )
}
