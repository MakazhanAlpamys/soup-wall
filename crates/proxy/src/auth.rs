// SPDX-License-Identifier: Apache-2.0

//! Client authentication for the firewall boundary.
//!
//! This deliberately uses a firewall-specific header rather than HTTP
//! `Authorization`, which must remain available for an OpenAI/Anthropic
//! credential that is forwarded upstream.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header::RETRY_AFTER, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use subtle::ConstantTimeEq;

use crate::config::RateLimit;
use crate::handlers::Shared;
use crate::rate_limit::{client_id, tenant_client_id, ClientId, Decision};
use crate::tenant_store::TenantAccess;

pub use crate::control_plane::PROXY_AUTH_HEADER;

// Both types moved to `crate::control_plane`: they are plain request-scoped data
// the data plane produces, so it should not have to name this module to describe
// its own request. Re-exported for the existing consumers here.
pub(crate) use crate::control_plane::DeferredTenantAudit;
pub use crate::control_plane::TenantAuditContext;

fn is_authorized(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

/// Reject calls that lack the configured firewall client credential. This
/// middleware sits outside every public API route, before body parsing or an
/// upstream request.
pub async fn require_proxy_token(
    State(state): State<Shared>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let path = request.uri().path().to_owned();
    let presented = request
        .headers()
        .get(PROXY_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let caller_auth_enabled = state.config.proxy_auth.enabled || state.tenant_store.is_some();
    let mut tenant_access = None;
    if caller_auth_enabled {
        let authorized = if let Some(store) = &state.tenant_store {
            match store.authenticate_access_async(presented.as_deref()).await {
                Ok(Some(access)) => {
                    request.extensions_mut().insert(TenantAuditContext {
                        tenant_id: access.identity.tenant_id.clone(),
                        path: path.clone(),
                        started,
                    });
                    request.extensions_mut().insert(access.clone());
                    tenant_access = Some(access);
                    true
                }
                Ok(None) => false,
                Err(error_value) => {
                    tracing::error!(path = %path, error = %error_value, "tenant authentication unavailable");
                    return unavailable_response(
                        "tenant authentication temporarily unavailable",
                        "tenant_store_unavailable",
                    );
                }
            }
        } else {
            state
                .proxy_auth_token
                .as_deref()
                .is_some_and(|expected| is_authorized(expected, presented.as_deref()))
        };
        if !authorized {
            tracing::warn!(path = %path, "rejected unauthenticated proxy request");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "message": "proxy authentication required",
                        "type": "proxy_authentication_error"
                    }
                })),
            )
                .into_response();
        }
    }

    let tenant_rate_limit = tenant_access
        .as_ref()
        .and_then(|access| access.limits.rate_limit.as_ref())
        .map(|limit| crate::config::RateLimit {
            enabled: true,
            requests_per_window: limit.requests_per_window,
            window_seconds: limit.window_seconds,
            max_tracked_clients: state.config.rate_limit.max_tracked_clients,
        });
    let global_decision = if state.config.rate_limit.enabled {
        match check_rate_limit(
            &state,
            client_id(presented.as_deref()),
            &state.config.rate_limit,
            &path,
        )
        .await
        {
            Ok(decision) => Some(decision),
            Err(()) => {
                let response = unavailable_response(
                    "rate limiter temporarily unavailable",
                    "rate_limiter_unavailable",
                );
                return audit_tenant_response(
                    &state,
                    tenant_access.as_ref(),
                    &path,
                    started,
                    response,
                )
                .await;
            }
        }
    } else {
        None
    };
    let decision = match global_decision.unwrap_or(Decision::Allowed) {
        rejected @ Decision::Rejected { .. } => rejected,
        Decision::Allowed => match tenant_rate_limit {
            Some(limit) => {
                let tenant_id = &tenant_access
                    .as_ref()
                    .expect("tenant policy requires tenant access")
                    .identity
                    .tenant_id;
                match check_rate_limit(&state, tenant_client_id(tenant_id), &limit, &path).await {
                    Ok(decision) => decision,
                    Err(()) => {
                        let response = unavailable_response(
                            "rate limiter temporarily unavailable",
                            "rate_limiter_unavailable",
                        );
                        return audit_tenant_response(
                            &state,
                            tenant_access.as_ref(),
                            &path,
                            started,
                            response,
                        )
                        .await;
                    }
                }
            }
            None => Decision::Allowed,
        },
    };
    match decision {
        Decision::Allowed => {
            let response = next.run(request).await;
            audit_tenant_response(&state, tenant_access.as_ref(), &path, started, response).await
        }
        Decision::Rejected { retry_after_secs } => {
            tracing::warn!(path = %path, "rejected rate-limited proxy request");
            let response = rate_limited_response(retry_after_secs);
            audit_tenant_response(&state, tenant_access.as_ref(), &path, started, response).await
        }
    }
}

async fn check_rate_limit(
    state: &Shared,
    client: ClientId,
    config: &RateLimit,
    path: &str,
) -> Result<Decision, ()> {
    if let Some(redis_limits) = &state.redis_limits {
        return match redis_limits
            .check_rate(client, config.requests_per_window, config.window_seconds)
            .await
        {
            Ok(decision) => Ok(decision),
            Err(error_value) => match state.config.redis_limits.fail_mode {
                crate::config::FailMode::FailClosed => {
                    tracing::error!(path = %path, error = %error_value, "Redis rate limiter unavailable");
                    Err(())
                }
                crate::config::FailMode::FailOpen => {
                    tracing::warn!(path = %path, error = %error_value, "Redis rate limiter unavailable; allowing request by configuration");
                    Ok(Decision::Allowed)
                }
            },
        };
    }
    match state.rate_limiter.lock() {
        Ok(mut limiter) => Ok(limiter.check_with(client, config, std::time::Instant::now())),
        Err(_) => {
            tracing::error!(path = %path, "rate limiter mutex unavailable");
            Err(())
        }
    }
}

fn unavailable_response(message: &str, error_type: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": {
                "message": message,
                "type": error_type
            }
        })),
    )
        .into_response()
}

fn rate_limited_response(retry_after_secs: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": {
                "message": "rate limit exceeded",
                "type": "rate_limit_exceeded"
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        RETRY_AFTER,
        HeaderValue::from_str(&retry_after_secs.to_string())
            .expect("retry-after is a valid numeric header"),
    );
    response
}

async fn audit_tenant_response(
    state: &Shared,
    access: Option<&TenantAccess>,
    path: &str,
    started: std::time::Instant,
    response: Response,
) -> Response {
    if response.extensions().get::<DeferredTenantAudit>().is_some() {
        return response;
    }
    let Some(access) = access else {
        return response;
    };
    record_tenant_audit(
        state,
        &TenantAuditContext {
            tenant_id: access.identity.tenant_id.clone(),
            path: path.to_owned(),
            started,
        },
        outcome_for_status(response.status()),
        response.status().as_u16(),
    )
    .await;
    response
}

pub(crate) async fn record_tenant_audit(
    state: &Shared,
    context: &TenantAuditContext,
    outcome: &str,
    status_code: u16,
) {
    let latency_ms = context
        .started
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let Some(store) = &state.tenant_store else {
        return;
    };
    match store.queue_audit(
        &context.tenant_id,
        &context.path,
        outcome,
        status_code,
        latency_ms,
    ) {
        crate::tenant_store::TenantAuditQueueResult::Queued => {}
        crate::tenant_store::TenantAuditQueueResult::Dropped => {
            tracing::error!("tenant audit queue is full; event dropped");
        }
        crate::tenant_store::TenantAuditQueueResult::NotConfigured => {
            if let Err(error_value) = store
                .append_audit_async(
                    &context.tenant_id,
                    &context.path,
                    outcome,
                    status_code,
                    latency_ms,
                )
                .await
            {
                tracing::error!(error = %error_value, "failed to append tenant audit event");
            }
        }
    }
}

fn outcome_for_status(status: StatusCode) -> &'static str {
    if status.is_success() {
        "completed"
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        "rate_limited"
    } else if status.is_client_error() {
        "rejected"
    } else {
        "failed"
    }
}

#[cfg(test)]
mod tests {
    use super::is_authorized;

    #[test]
    fn accepts_only_the_bearer_form_of_the_exact_token() {
        assert!(is_authorized("secret", Some("Bearer secret")));
        assert!(!is_authorized("secret", Some("secret")));
        assert!(!is_authorized("secret", Some("Bearer incorrect")));
        assert!(!is_authorized("secret", None));
    }
}
