// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers: OpenAI-compatible chat completions + native Anthropic messages.

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures_util::StreamExt;
use rand::{rngs::SysRng, TryRng};
use soup_wall_core::Firewall;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::anthropic::AnthropicRequest;
use crate::audit::AuditRecord;
use crate::config::{Config, FailMode, SpendLimit};
use crate::control_plane::{DeferredTenantAudit, TenantAuditContext};
use crate::openai::ChatRequest;
use crate::pipeline::{
    decide_input, decide_input_anthropic, decide_input_responses, decide_output,
};
use crate::rate_limit::{client_id, tenant_client_id};
use crate::responses::{ResponsesRequest, SseDecodeError, SseJsonDecoder};
use crate::spend_limit::{Reservation, ReserveError};
use crate::tenant_store::TenantAccess;

pub struct AppState {
    pub firewall: Firewall,
    pub http: reqwest::Client,
    pub config: Config,
    /// Optional server-side OpenAI API key. It is used only when the caller
    /// did not supply `Authorization`, and is never stored in `firewall.yaml`.
    pub openai_api_key: Option<String>,
    /// Server-side token used only to authenticate callers of this proxy.
    /// It is compared in constant time and never forwarded upstream.
    pub proxy_auth_token: Option<String>,
    /// Optional SQLite-backed tenant/token store. When present, it replaces
    /// the one shared proxy token for model-request authentication.
    pub tenant_store: Option<crate::tenant_store::TenantStore>,
    /// Control-plane credential, separate from tenant credentials and read
    /// only from its configured environment variable.
    pub admin_token: Option<String>,
    /// Optional AES-256-GCM key for short-lived OIDC browser state. Its
    /// absence disables browser login instead of falling back to an insecure
    /// cookie or process-local state map.
    pub oidc_state_cipher: Option<crate::oidc::OidcStateCipher>,
    /// Optional SAML service-provider configuration. SAML remains disabled
    /// unless all secret-backed SP settings are present at startup.
    pub saml: Option<crate::saml_auth::SamlRuntimeConfig>,
    /// Bounded in-memory request limiter keyed by a one-way token fingerprint.
    pub rate_limiter: std::sync::Mutex<crate::rate_limit::RateLimiter>,
    /// Bounded, process-local token-usage ledger for configured spend limits.
    pub spend_ledger: std::sync::Mutex<crate::spend_limit::SpendLedger>,
    /// Optional Redis backend shared by proxy replicas for rate and spend
    /// windows. When absent, the existing bounded local limiters are used.
    pub redis_limits: Option<crate::redis_limits::RedisLimits>,
    /// Agent-layer firewall for tool-block inspection. Behind a Mutex because
    /// `inspect` takes `&mut self`. Only consulted when `agent_inspection.enabled`.
    pub agent: std::sync::Mutex<soup_wall_agent::AgentFirewall>,
    /// Output content moderation gate. `check` is a no-op unless enabled + `ml` + model.
    pub moderation: crate::moderation::ModerationGate,
}

/// Run agent inspection over a response's tool calls against the request's tool
/// results. Returns `Some(reason)` only when the verdict is `Deny` *and* enforcement
/// is on — the caller then refuses the response. Otherwise the verdict is audited
/// (via the tracing warning) and the response passes: shadow-first.
fn agent_refuse_reason(
    state: &AppState,
    request_id: &str,
    results: Vec<String>,
    calls: Vec<crate::agent_scan::ToolCall>,
) -> Option<String> {
    if calls.is_empty() {
        return None;
    }
    let v = {
        let mut fw = state.agent.lock().expect("agent mutex");
        crate::agent_scan::inspect_cycle(&mut fw, request_id, &results, &calls)
    };
    let adapter = v.adapter_response("proxy-local");
    if matches!(v.verdict, soup_wall_agent::Verdict::Allow) {
        return None;
    }
    tracing::warn!(
        cycle = %request_id,
        verdict = ?v.verdict,
        adapter_verdict = ?adapter.verdict,
        reason = ?v.reason,
        "agent verdict on a response tool_use"
    );
    if state.config.agent_inspection.enforce && matches!(v.verdict, soup_wall_agent::Verdict::Deny)
    {
        return Some(
            v.reason
                .unwrap_or_else(|| "agent policy denied a tool call".into()),
        );
    }
    None
}

fn agent_refuse_events(
    state: &AppState,
    request_id: &str,
    events: &[crate::events::SecurityEvent],
) -> Option<String> {
    let verdict = {
        let mut fw = state.agent.lock().expect("agent mutex");
        crate::agent_scan::inspect_normalized_cycle(&mut fw, request_id, events)
    };
    let adapter = verdict.adapter_response("proxy-local");
    if matches!(verdict.verdict, soup_wall_agent::Verdict::Allow) {
        return None;
    }
    tracing::warn!(
        cycle = %request_id,
        verdict = ?verdict.verdict,
        adapter_verdict = ?adapter.verdict,
        reason = ?verdict.reason,
        "agent verdict on normalized provider events"
    );
    if state.config.agent_inspection.enforce
        && matches!(verdict.verdict, soup_wall_agent::Verdict::Deny)
    {
        return Some(
            verdict
                .reason
                .unwrap_or_else(|| "agent policy denied a tool call".into()),
        );
    }
    None
}

fn capability_refuse_events(
    state: &AppState,
    request_id: &str,
    events: &[crate::events::SecurityEvent],
) -> Option<String> {
    let violations = crate::capability::violations(&state.config.capability_policy, events);
    if violations.is_empty() {
        return None;
    }
    let reasons = violations
        .iter()
        .map(|violation| violation.reason.as_str())
        .collect::<Vec<_>>();
    tracing::warn!(cycle = %request_id, ?reasons, "capability policy violation");
    if state.config.capability_policy.enforce {
        Some(format!("capability policy denied: {}", reasons.join("; ")))
    } else {
        None
    }
}

fn capability_refuse_calls(
    state: &AppState,
    request_id: &str,
    calls: &[crate::agent_scan::ToolCall],
) -> Option<String> {
    let violations =
        crate::capability::violations_for_calls(&state.config.capability_policy, calls);
    if violations.is_empty() {
        return None;
    }
    let reasons = violations
        .iter()
        .map(|violation| violation.reason.as_str())
        .collect::<Vec<_>>();
    tracing::warn!(cycle = %request_id, ?reasons, "capability policy violation");
    if state.config.capability_policy.enforce {
        Some(format!("capability policy denied: {}", reasons.join("; ")))
    } else {
        None
    }
}

pub type Shared = Arc<AppState>;

/// Liveness is intentionally dependency-free so an orchestrator can tell a
/// running process from a ready control plane.
pub async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "live" }))
}

/// Readiness verifies the tenant control plane and makes asynchronous-audit
/// loss visible without disclosing database topology or credentials.
pub async fn readyz(State(state): State<Shared>) -> Response {
    let (control_plane_ready, queue, usage) = if let Some(store) = &state.tenant_store {
        (
            store.health_check_async().await.is_ok(),
            store.audit_queue_status(),
            store.usage_ledger_status(),
        )
    } else {
        (
            true,
            crate::control_plane::TenantAuditQueueStatus::disabled(),
            crate::control_plane::UsageLedgerStatus::empty(),
        )
    };
    let redis_ready = if let Some(redis_limits) = &state.redis_limits {
        redis_limits.health_check().await.is_ok()
    } else {
        !state.config.redis_limits.enabled
    };
    let audit_ready = queue.dropped_events == 0 && queue.failed_events == 0;
    let usage_ready = usage.failed_events == 0;
    let status = if control_plane_ready && audit_ready && usage_ready && redis_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "status": if status.is_success() { "ready" } else { "degraded" },
            "control_plane": if control_plane_ready { "ready" } else { "unavailable" },
            "redis": if redis_ready { "ready" } else { "unavailable" },
            "audit": queue,
            "usage_ledger": usage,
        })),
    )
        .into_response()
}

/// Prometheus-compatible operational metrics. The endpoint intentionally
/// exposes only aggregate health/capacity signals: no tenant IDs, prompts,
/// credentials, URLs, or request labels are ever included.
pub async fn metrics(State(state): State<Shared>) -> Response {
    let (control_plane_ready, queue, usage) = if let Some(store) = &state.tenant_store {
        (
            store.health_check_async().await.is_ok(),
            store.audit_queue_status(),
            store.usage_ledger_status(),
        )
    } else {
        (
            true,
            crate::control_plane::TenantAuditQueueStatus::disabled(),
            crate::control_plane::UsageLedgerStatus::empty(),
        )
    };
    let redis_enabled = state.redis_limits.is_some();
    let redis_ready = if let Some(redis_limits) = &state.redis_limits {
        redis_limits.health_check().await.is_ok()
    } else {
        !state.config.redis_limits.enabled
    };
    let body = format!(
        "# HELP llm_firewall_control_plane_ready Whether the tenant control plane is reachable.\n\
# TYPE llm_firewall_control_plane_ready gauge\n\
llm_firewall_control_plane_ready {}\n\
# HELP llm_firewall_audit_queue_enabled Whether asynchronous audit persistence is configured.\n\
# TYPE llm_firewall_audit_queue_enabled gauge\n\
llm_firewall_audit_queue_enabled {}\n\
# HELP llm_firewall_audit_queue_dropped_events Number of audit events dropped before persistence.\n\
# TYPE llm_firewall_audit_queue_dropped_events counter\n\
llm_firewall_audit_queue_dropped_events {}\n\
# HELP llm_firewall_audit_queue_failed_events Number of audit events that failed persistence.\n\
# TYPE llm_firewall_audit_queue_failed_events counter\n\
llm_firewall_audit_queue_failed_events {}\n\
# HELP llm_firewall_usage_ledger_failed_events Number of usage writes that failed.\n\
# TYPE llm_firewall_usage_ledger_failed_events counter\n\
llm_firewall_usage_ledger_failed_events {}\n\
# HELP llm_firewall_redis_limits_enabled Whether shared Redis rate/spend limits are enabled.\n\
# TYPE llm_firewall_redis_limits_enabled gauge\n\
llm_firewall_redis_limits_enabled {}\n\
# HELP llm_firewall_redis_limits_ready Whether shared Redis rate/spend limits are reachable.\n\
# TYPE llm_firewall_redis_limits_ready gauge\n\
llm_firewall_redis_limits_ready {}\n",
        i64::from(control_plane_ready),
        i64::from(queue.enabled),
        queue.dropped_events,
        queue.failed_events,
        usage.failed_events,
        i64::from(redis_enabled),
        i64::from(redis_ready),
    );
    let mut response = body.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

fn next_request_id() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let mut value = [0_u8; 18];
    SysRng
        .try_fill_bytes(&mut value)
        .expect("the OS refused to provide entropy");
    format!("req_{}", URL_SAFE_NO_PAD.encode(value))
}

/// OpenAI-style error envelope.
fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": "llm_firewall_block" } })
}

/// Anthropic-style error envelope.
fn anthropic_error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "type": "error", "error": { "type": "invalid_request_error", "message": msg } })
}

/// Enforce a tenant's exact model allowlist before inspection, spend
/// reservation, or upstream forwarding. A missing policy intentionally keeps
/// the existing operator-level model behaviour.
fn tenant_model_policy_response(
    tenant_access: Option<&TenantAccess>,
    model: &str,
    anthropic: bool,
) -> Option<Response> {
    let policy = tenant_access.and_then(|access| access.model_policy.as_ref())?;
    if policy.permits(model) {
        return None;
    }
    let body = if anthropic {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": "permission_error",
                "message": "model is not allowed for this tenant"
            }
        })
    } else {
        serde_json::json!({
            "error": {
                "message": "model is not allowed for this tenant",
                "type": "tenant_model_not_allowed"
            }
        })
    };
    Some((StatusCode::FORBIDDEN, Json(body)).into_response())
}

enum SpendRequestError {
    StreamingUnsupported,
    ModelUnpriced,
    BudgetExhausted { retry_after_secs: u64 },
    CapacityExhausted { retry_after_secs: u64 },
    Unavailable,
}

async fn reserve_spend(
    state: &AppState,
    headers: &HeaderMap,
    tenant_access: Option<&TenantAccess>,
    model: &str,
    stream: bool,
) -> Result<Option<Reservation>, SpendRequestError> {
    let spend_config =
        if let Some(limit) = tenant_access.and_then(|access| access.limits.spend_limit.as_ref()) {
            SpendLimit {
                enabled: true,
                window_seconds: limit.window_seconds,
                max_usd_micros: limit.max_usd_micros,
                reserve_usd_micros_per_request: limit.reserve_usd_micros_per_request,
                max_tracked_clients: state.config.spend_limit.max_tracked_clients,
                model_prices: state.config.spend_limit.model_prices.clone(),
            }
        } else if state.config.spend_limit.enabled {
            state.config.spend_limit.clone()
        } else {
            return Ok(None);
        };
    if stream {
        return Err(SpendRequestError::StreamingUnsupported);
    }
    let token = headers
        .get(crate::control_plane::PROXY_AUTH_HEADER)
        .and_then(|value| value.to_str().ok());
    let client = tenant_access.map_or_else(
        || client_id(token),
        |access| tenant_client_id(&access.identity.tenant_id),
    );
    let Some(price) = spend_config.model_prices.get(model).copied() else {
        return Err(SpendRequestError::ModelUnpriced);
    };
    if let Some(redis_limits) = &state.redis_limits {
        return match redis_limits
            .reserve_spend(client, price, &spend_config)
            .await
        {
            Ok(reservation) => Ok(Some(reservation)),
            Err(crate::redis_limits::RedisSpendError::BudgetExhausted { retry_after_secs }) => {
                Err(SpendRequestError::BudgetExhausted { retry_after_secs })
            }
            Err(crate::redis_limits::RedisSpendError::Backend(error_value)) => {
                match state.config.redis_limits.fail_mode {
                    FailMode::FailClosed => {
                        tracing::error!(error = %error_value, "Redis spend ledger unavailable");
                        Err(SpendRequestError::Unavailable)
                    }
                    FailMode::FailOpen => {
                        tracing::warn!(error = %error_value, "Redis spend ledger unavailable; forwarding without a spend reservation by configuration");
                        Ok(None)
                    }
                }
            }
        };
    }
    let mut ledger = state
        .spend_ledger
        .lock()
        .map_err(|_| SpendRequestError::Unavailable)?;
    ledger
        .reserve_with(client, model, &spend_config, Instant::now())
        .map(Some)
        .map_err(|error| match error {
            ReserveError::ModelUnpriced => SpendRequestError::ModelUnpriced,
            ReserveError::BudgetExhausted { retry_after_secs } => {
                SpendRequestError::BudgetExhausted { retry_after_secs }
            }
            ReserveError::CapacityExhausted { retry_after_secs } => {
                SpendRequestError::CapacityExhausted { retry_after_secs }
            }
        })
}

async fn release_spend(state: &AppState, reservation: Option<Reservation>) {
    let Some(reservation) = reservation else {
        return;
    };
    if reservation.redis_key().is_some() {
        if let Some(redis_limits) = &state.redis_limits {
            if let Err(error_value) = redis_limits.release_spend(&reservation).await {
                tracing::error!(error = %error_value, "failed to release Redis spend reservation");
            }
        } else {
            tracing::error!("missing Redis limits backend for a distributed spend reservation");
        }
    } else if let Ok(mut ledger) = state.spend_ledger.lock() {
        ledger.release(reservation);
    } else {
        tracing::error!("spend ledger mutex unavailable while releasing a reservation");
    }
}

async fn settle_spend(
    state: &AppState,
    reservation: Option<Reservation>,
    body: &serde_json::Value,
    input_field: &str,
    output_field: &str,
) {
    let Some(reservation) = reservation else {
        return;
    };
    let usage = body.get("usage").and_then(|usage| {
        Some((
            usage.get(input_field)?.as_u64()?,
            usage.get(output_field)?.as_u64()?,
        ))
    });
    if reservation.redis_key().is_some() {
        let Some(redis_limits) = &state.redis_limits else {
            tracing::error!("missing Redis limits backend for a distributed spend reservation");
            return;
        };
        match usage {
            Some((input_tokens, output_tokens)) => {
                match redis_limits
                    .settle_spend(&reservation, input_tokens, output_tokens)
                    .await
                {
                    Ok(charged) => tracing::info!(
                        charged_usd_micros = charged,
                        "settled Redis spend reservation"
                    ),
                    Err(error_value) => tracing::error!(
                        error = %error_value,
                        "failed to settle Redis spend reservation"
                    ),
                }
            }
            None => {
                if let Err(error_value) = redis_limits.exhaust_spend(&reservation).await {
                    tracing::error!(error = %error_value, "failed to exhaust Redis spend reservation after missing usage");
                } else {
                    tracing::error!("provider response omitted usage; client spend budget frozen");
                }
            }
        }
        return;
    }
    match state.spend_ledger.lock() {
        Ok(mut ledger) => match usage {
            Some((input_tokens, output_tokens)) => {
                let charged = ledger.settle(reservation, input_tokens, output_tokens);
                tracing::info!(
                    charged_usd_micros = charged,
                    "settled proxy spend reservation"
                );
            }
            None => {
                ledger.exhaust(reservation);
                tracing::error!("provider response omitted usage; client spend budget frozen");
            }
        },
        Err(_) => tracing::error!("spend ledger mutex unavailable while settling a reservation"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_terminal_usage(
    state: &AppState,
    tenant_access: Option<&TenantAccess>,
    request_id: &str,
    provider: &str,
    path: &str,
    requested_model: &str,
    body: &serde_json::Value,
    input_field: &str,
    output_field: &str,
) {
    let (Some(store), Some(access)) = (&state.tenant_store, tenant_access) else {
        return;
    };
    let event = crate::usage::terminal_usage_event(
        crate::usage::TerminalUsageContext {
            tenant_id: &access.identity.tenant_id,
            request_id,
            provider,
            path,
            requested_model,
            input_field,
            output_field,
            price: state
                .config
                .spend_limit
                .model_prices
                .get(requested_model)
                .copied(),
        },
        body,
    );
    match store.append_usage_event_async(&event).await {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            tenant_id = %access.identity.tenant_id,
            request_id,
            "duplicate terminal usage event ignored"
        ),
        Err(error_value) => tracing::error!(
            tenant_id = %access.identity.tenant_id,
            request_id,
            error = %error_value,
            "failed to append terminal usage event"
        ),
    }
}

#[derive(Clone)]
struct StreamUsageContext {
    tenant_access: Option<TenantAccess>,
    provider: &'static str,
    path: &'static str,
    requested_model: String,
    input_field: &'static str,
    output_field: &'static str,
}

/// What `proxy_stream` needs in order to inspect tool calls that arrive split
/// across SSE frames: the wire format to reassemble, and the request's tool
/// results, which are the taint source the reassembled call is judged against.
struct StreamToolContext {
    protocol: crate::agent_scan::StreamProtocol,
    tool_results: Vec<String>,
}

#[derive(Default)]
struct StreamUsageEvidence {
    provider_response_id: Option<String>,
    provider_model: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    saw_terminal: bool,
}

impl StreamUsageEvidence {
    fn observe(&mut self, event: &serde_json::Value, input_field: &str, output_field: &str) {
        if event.get("type").and_then(serde_json::Value::as_str) == Some("message_stop") {
            self.saw_terminal = true;
        }
        if let Some(id) = event
            .get("id")
            .or_else(|| event.get("message").and_then(|message| message.get("id")))
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 256)
        {
            self.provider_response_id = Some(id.to_owned());
        }
        if let Some(model) = event
            .get("model")
            .or_else(|| {
                event
                    .get("message")
                    .and_then(|message| message.get("model"))
            })
            .and_then(serde_json::Value::as_str)
            .filter(|model| !model.is_empty() && model.len() <= 256)
        {
            self.provider_model = Some(model.to_owned());
        }
        let usage = event.get("usage").or_else(|| {
            event
                .get("message")
                .and_then(|message| message.get("usage"))
        });
        if let Some(usage) = usage {
            if let Some(input_tokens) = usage.get(input_field).and_then(serde_json::Value::as_u64) {
                self.input_tokens = Some(input_tokens);
            }
            if let Some(output_tokens) = usage.get(output_field).and_then(serde_json::Value::as_u64)
            {
                self.output_tokens = Some(output_tokens);
            }
        }
    }

    fn terminal_body(self, input_field: &str, output_field: &str) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        if let Some(id) = self.provider_response_id {
            body.insert("id".into(), serde_json::Value::String(id));
        }
        if let Some(model) = self.provider_model {
            body.insert("model".into(), serde_json::Value::String(model));
        }
        if let (Some(input_tokens), Some(output_tokens)) = (self.input_tokens, self.output_tokens) {
            let mut usage = serde_json::Map::new();
            usage.insert(input_field.to_owned(), input_tokens.into());
            usage.insert(output_field.to_owned(), output_tokens.into());
            body.insert("usage".into(), serde_json::Value::Object(usage));
        }
        serde_json::Value::Object(body)
    }
}

async fn record_stream_usage(
    state: &AppState,
    context: &StreamUsageContext,
    request_id: &str,
    body: &serde_json::Value,
) {
    record_terminal_usage(
        state,
        context.tenant_access.as_ref(),
        request_id,
        context.provider,
        context.path,
        &context.requested_model,
        body,
        context.input_field,
        context.output_field,
    )
    .await;
}

fn spend_error_response(error: SpendRequestError, anthropic: bool) -> Response {
    let (status, message, kind, retry_after) = match error {
        SpendRequestError::StreamingUnsupported => (
            StatusCode::BAD_REQUEST,
            "spend limits currently require stream: false",
            "spend_streaming_not_supported",
            None,
        ),
        SpendRequestError::ModelUnpriced => (
            StatusCode::BAD_REQUEST,
            "model has no configured spend price",
            "spend_model_unpriced",
            None,
        ),
        SpendRequestError::BudgetExhausted { retry_after_secs } => (
            StatusCode::TOO_MANY_REQUESTS,
            "spend limit exceeded",
            "spend_limit_exceeded",
            Some(retry_after_secs),
        ),
        SpendRequestError::CapacityExhausted { retry_after_secs } => (
            StatusCode::TOO_MANY_REQUESTS,
            "spend ledger is at configured client capacity",
            "spend_ledger_capacity_exceeded",
            Some(retry_after_secs),
        ),
        SpendRequestError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "spend ledger temporarily unavailable",
            "spend_ledger_unavailable",
            None,
        ),
    };
    let body = if anthropic {
        serde_json::json!({
            "type": "error",
            "error": { "type": "invalid_request_error", "message": message }
        })
    } else {
        serde_json::json!({ "error": { "message": message, "type": kind } })
    };
    let mut response = (status, Json(body)).into_response();
    if let Some(retry_after) = retry_after {
        response.headers_mut().insert(
            RETRY_AFTER,
            HeaderValue::from_str(&retry_after.to_string())
                .expect("retry-after is a valid numeric header"),
        );
    }
    response
}

/// Propagate the listed caller headers to the upstream request (case-insensitive).
fn forward_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    names: &[&str],
    fallback_bearer: Option<&str>,
) -> reqwest::RequestBuilder {
    for name in names {
        if let Some(v) = headers.get(*name) {
            builder = builder.header(*name, v.clone());
        }
    }
    if !headers.contains_key("authorization") {
        if let Some(key) = fallback_bearer {
            builder = builder.bearer_auth(key);
        }
    }
    builder
}

const OPENAI_HEADERS: &[&str] = &[
    "authorization",
    "openai-organization",
    "openai-project",
    "openai-beta",
];
const ANTHROPIC_HEADERS: &[&str] = &[
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
    "authorization",
];

// ------------------------------------------------------------------ OpenAI path

pub async fn chat_completions(
    State(state): State<Shared>,
    headers: HeaderMap,
    tenant_access: Option<Extension<TenantAccess>>,
    tenant_audit: Option<Extension<TenantAuditContext>>,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    if let Some(response) = tenant_model_policy_response(
        tenant_access.as_ref().map(|Extension(access)| access),
        &req.model,
        false,
    ) {
        return response;
    }

    let decision = decide_input(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        audit_block(
            &request_id,
            decision.score,
            decision.reasons,
            decision.owasp,
            decision.atlas,
            started,
        );
        return (StatusCode::BAD_REQUEST, Json(error_body(&reason))).into_response();
    }

    let spend_reservation = match reserve_spend(
        &state,
        &headers,
        tenant_access.as_ref().map(|Extension(access)| access),
        &decision.request.model,
        decision.request.stream,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => return spend_error_response(error, false),
    };

    let url = format!("{}/v1/chat/completions", state.config.upstream.openai_base);
    if decision.request.stream {
        let builder = forward_headers(
            state.http.post(&url).json(&decision.request),
            &headers,
            OPENAI_HEADERS,
            state.openai_api_key.as_deref(),
        );
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            OPENAI_BLOCK_FRAME,
            tenant_audit.map(|Extension(context)| context),
            StreamUsageContext {
                tenant_access: tenant_access.map(|Extension(access)| access),
                provider: "openai",
                path: "/v1/chat/completions",
                requested_model: decision.request.model.clone(),
                input_field: "prompt_tokens",
                output_field: "completion_tokens",
            },
            Some(StreamToolContext {
                protocol: crate::agent_scan::StreamProtocol::OpenAiChat,
                tool_results: crate::agent_scan::openai_tool_results(&decision.request),
            }),
        )
        .await;
    }

    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        OPENAI_HEADERS,
        state.openai_api_key.as_deref(),
    );
    let (status, body) = match forward_json(&state, builder).await {
        Ok(pair) => pair,
        Err(resp) => {
            release_spend(&state, spend_reservation).await;
            return *resp;
        }
    };
    if status != StatusCode::OK {
        release_spend(&state, spend_reservation).await;
        return (status, Json(body)).into_response();
    }
    settle_spend(
        &state,
        spend_reservation,
        &body,
        "prompt_tokens",
        "completion_tokens",
    )
    .await;
    record_terminal_usage(
        &state,
        tenant_access.as_ref().map(|Extension(access)| access),
        &request_id,
        "openai",
        "/v1/chat/completions",
        &decision.request.model,
        &body,
        "prompt_tokens",
        "completion_tokens",
    )
    .await;

    let events = crate::events::normalize_chat(&decision.request, &body);
    if let Some(reason) = capability_refuse_events(&state, &request_id, &events) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }
    let assistant = crate::events::output_text(&events);
    if let Some(reason) = decide_output(&state.firewall, &assistant) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }

    // Agent layer: inspect the response's tool calls against the request's tool
    // results. Non-streaming only (this is past the stream early-return).
    if state.config.agent_inspection.enabled {
        if let Some(reason) = agent_refuse_events(&state, &request_id, &events) {
            audit_output_block(&request_id, &reason, started);
            return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
        }
    }

    // Output content moderation: restrict a harmful reply regardless of backend.
    // Non-streaming only (v1); `block` refuses, `flag` audits and forwards.
    if !decision.request.stream {
        if let crate::moderation::GateVerdict::Harmful { categories, action } =
            state.moderation.check(&assistant)
        {
            tracing::warn!(?categories, ?action, "output moderation: harmful reply");
            if action == crate::config::ModerationAction::Block {
                let msg = state.moderation.refusal_message().to_string();
                audit_output_block(&request_id, &msg, started);
                return (StatusCode::OK, Json(error_body(&msg))).into_response();
            }
        }
    }

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    (StatusCode::OK, Json(body)).into_response()
}

// ---------------------------------------------------------- OpenAI Responses path

pub async fn responses(
    State(state): State<Shared>,
    headers: HeaderMap,
    tenant_access: Option<Extension<TenantAccess>>,
    tenant_audit: Option<Extension<TenantAuditContext>>,
    Json(req): Json<ResponsesRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    if let Some(response) = tenant_model_policy_response(
        tenant_access.as_ref().map(|Extension(access)| access),
        &req.model,
        false,
    ) {
        return response;
    }

    let decision = decide_input_responses(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        audit_block(
            &request_id,
            decision.score,
            decision.reasons,
            decision.owasp,
            decision.atlas,
            started,
        );
        return (StatusCode::BAD_REQUEST, Json(error_body(&reason))).into_response();
    }

    let spend_reservation = match reserve_spend(
        &state,
        &headers,
        tenant_access.as_ref().map(|Extension(access)| access),
        &decision.request.model,
        decision.request.stream,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => return spend_error_response(error, false),
    };

    let url = format!("{}/v1/responses", state.config.upstream.openai_base);
    if decision.request.stream {
        let tool_results = if state.config.agent_inspection.enabled {
            crate::agent_scan::responses_tool_results(&decision.request)
        } else {
            Vec::new()
        };
        let builder = forward_headers(
            state.http.post(&url).json(&decision.request),
            &headers,
            OPENAI_HEADERS,
            state.openai_api_key.as_deref(),
        );
        return proxy_responses_stream(
            state.clone(),
            builder,
            request_id,
            started,
            tool_results,
            tenant_audit.map(|Extension(context)| context),
            StreamUsageContext {
                tenant_access: tenant_access.map(|Extension(access)| access),
                provider: "openai",
                path: "/v1/responses",
                requested_model: decision.request.model.clone(),
                input_field: "input_tokens",
                output_field: "output_tokens",
            },
        )
        .await;
    }

    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        OPENAI_HEADERS,
        state.openai_api_key.as_deref(),
    );
    let (status, body) = match forward_json(&state, builder).await {
        Ok(pair) => pair,
        Err(resp) => {
            release_spend(&state, spend_reservation).await;
            return *resp;
        }
    };
    if status != StatusCode::OK {
        release_spend(&state, spend_reservation).await;
        return (status, Json(body)).into_response();
    }
    settle_spend(
        &state,
        spend_reservation,
        &body,
        "input_tokens",
        "output_tokens",
    )
    .await;
    record_terminal_usage(
        &state,
        tenant_access.as_ref().map(|Extension(access)| access),
        &request_id,
        "openai",
        "/v1/responses",
        &decision.request.model,
        &body,
        "input_tokens",
        "output_tokens",
    )
    .await;

    let events = crate::events::normalize_responses(&decision.request, &body);
    if let Some(reason) = capability_refuse_events(&state, &request_id, &events) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }
    let assistant = crate::events::output_text(&events);
    if let Some(reason) = decide_output(&state.firewall, &assistant) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }

    if state.config.agent_inspection.enabled {
        if let Some(reason) = agent_refuse_events(&state, &request_id, &events) {
            audit_output_block(&request_id, &reason, started);
            return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
        }
    }

    if let crate::moderation::GateVerdict::Harmful { categories, action } =
        state.moderation.check(&assistant)
    {
        tracing::warn!(?categories, ?action, "output moderation: harmful reply");
        if action == crate::config::ModerationAction::Block {
            let msg = state.moderation.refusal_message().to_string();
            audit_output_block(&request_id, &msg, started);
            return (StatusCode::OK, Json(error_body(&msg))).into_response();
        }
    }

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    (StatusCode::OK, Json(body)).into_response()
}

// --------------------------------------------------------------- Anthropic path

pub async fn messages(
    State(state): State<Shared>,
    headers: HeaderMap,
    tenant_access: Option<Extension<TenantAccess>>,
    tenant_audit: Option<Extension<TenantAuditContext>>,
    Json(req): Json<AnthropicRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    if let Some(response) = tenant_model_policy_response(
        tenant_access.as_ref().map(|Extension(access)| access),
        &req.model,
        true,
    ) {
        return response;
    }

    let decision = decide_input_anthropic(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        audit_block(
            &request_id,
            decision.score,
            decision.reasons,
            decision.owasp,
            decision.atlas,
            started,
        );
        return (StatusCode::BAD_REQUEST, Json(anthropic_error_body(&reason))).into_response();
    }

    let spend_reservation = match reserve_spend(
        &state,
        &headers,
        tenant_access.as_ref().map(|Extension(access)| access),
        &decision.request.model,
        decision.request.stream,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => return spend_error_response(error, true),
    };

    let url = format!("{}/v1/messages", state.config.upstream.anthropic_base);
    if decision.request.stream {
        let builder = forward_headers(
            state.http.post(&url).json(&decision.request),
            &headers,
            ANTHROPIC_HEADERS,
            None,
        );
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            ANTHROPIC_BLOCK_FRAME,
            tenant_audit.map(|Extension(context)| context),
            StreamUsageContext {
                tenant_access: tenant_access.map(|Extension(access)| access),
                provider: "anthropic",
                path: "/v1/messages",
                requested_model: decision.request.model.clone(),
                input_field: "input_tokens",
                output_field: "output_tokens",
            },
            Some(StreamToolContext {
                protocol: crate::agent_scan::StreamProtocol::AnthropicMessages,
                // `anthropic_tool_results` reads the untyped wire shape; the typed
                // request round-trips to it losslessly via `rest`.
                tool_results: serde_json::to_value(&decision.request)
                    .map(|request| crate::agent_scan::anthropic_tool_results(&request))
                    .unwrap_or_default(),
            }),
        )
        .await;
    }

    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        ANTHROPIC_HEADERS,
        None,
    );
    let (status, body) = match forward_json(&state, builder).await {
        Ok(pair) => pair,
        Err(resp) => {
            release_spend(&state, spend_reservation).await;
            return *resp;
        }
    };
    if status != StatusCode::OK {
        release_spend(&state, spend_reservation).await;
        return (status, Json(body)).into_response();
    }
    settle_spend(
        &state,
        spend_reservation,
        &body,
        "input_tokens",
        "output_tokens",
    )
    .await;
    record_terminal_usage(
        &state,
        tenant_access.as_ref().map(|Extension(access)| access),
        &request_id,
        "anthropic",
        "/v1/messages",
        &decision.request.model,
        &body,
        "input_tokens",
        "output_tokens",
    )
    .await;

    let events = crate::events::normalize_anthropic(&decision.request, &body);
    if let Some(reason) = capability_refuse_events(&state, &request_id, &events) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(anthropic_error_body(&reason))).into_response();
    }
    let assistant = crate::events::output_text(&events);
    if let Some(reason) = decide_output(&state.firewall, &assistant) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(anthropic_error_body(&reason))).into_response();
    }

    // Agent layer: inspect the response's tool_use blocks against the request's
    // tool_result blocks. Non-streaming only.
    if state.config.agent_inspection.enabled {
        if let Some(reason) = agent_refuse_events(&state, &request_id, &events) {
            audit_output_block(&request_id, &reason, started);
            return (StatusCode::BAD_GATEWAY, Json(anthropic_error_body(&reason))).into_response();
        }
    }

    // Output content moderation (see the OpenAI path). Non-streaming only.
    if !decision.request.stream {
        if let crate::moderation::GateVerdict::Harmful { categories, action } =
            state.moderation.check(&assistant)
        {
            tracing::warn!(?categories, ?action, "output moderation: harmful reply");
            if action == crate::config::ModerationAction::Block {
                let msg = state.moderation.refusal_message().to_string();
                audit_output_block(&request_id, &msg, started);
                return (StatusCode::OK, Json(anthropic_error_body(&msg))).into_response();
            }
        }
    }

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    (StatusCode::OK, Json(body)).into_response()
}

// ------------------------------------------------------------------- shared bits

enum UpstreamJsonError {
    TooLarge,
    Read(reqwest::Error),
    Decode(serde_json::Error),
}

/// Read at most `max_bytes` from an upstream JSON response. `reqwest::Response::json`
/// has no application-level byte limit, so collect the body manually before parsing.
async fn read_upstream_json(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<serde_json::Value, UpstreamJsonError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(UpstreamJsonError::Read)?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(UpstreamJsonError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(UpstreamJsonError::Decode)
}

/// Send a non-streaming upstream request and parse the JSON body. On transport/body
/// failure returns a ready `Response` (respecting fail mode) via `Err`.
async fn forward_json(
    state: &Shared,
    builder: reqwest::RequestBuilder,
) -> Result<(StatusCode, serde_json::Value), Box<Response>> {
    let resp = match timeout(state.config.upstream_timeout(), builder.send()).await {
        Err(_) => {
            return Err(Box::new(
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(error_body("upstream timeout")),
                )
                    .into_response(),
            ));
        }
        Ok(r) => r,
    };
    let resp = match resp {
        Ok(resp) => resp,
        Err(e) => {
            let msg = match state.config.fail_mode {
                FailMode::FailClosed => format!("upstream error (fail_closed): {e}"),
                FailMode::FailOpen => "upstream error".to_string(),
            };
            return Err(Box::new(
                (StatusCode::BAD_GATEWAY, Json(error_body(&msg))).into_response(),
            ));
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match timeout(
        state.config.upstream_timeout(),
        read_upstream_json(resp, state.config.max_upstream_body_bytes()),
    )
    .await
    {
        Err(_) => Err(Box::new(
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(error_body("upstream timeout")),
            )
                .into_response(),
        )),
        Ok(Ok(v)) => Ok((status, v)),
        Ok(Err(UpstreamJsonError::TooLarge)) => Err(Box::new(
            (
                StatusCode::BAD_GATEWAY,
                Json(error_body("upstream body exceeded configured limit")),
            )
                .into_response(),
        )),
        Ok(Err(UpstreamJsonError::Read(e))) => Err(Box::new(
            (
                StatusCode::BAD_GATEWAY,
                Json(error_body(&format!("bad upstream body: {e}"))),
            )
                .into_response(),
        )),
        Ok(Err(UpstreamJsonError::Decode(e))) => Err(Box::new(
            (
                StatusCode::BAD_GATEWAY,
                Json(error_body(&format!("bad upstream body: {e}"))),
            )
                .into_response(),
        )),
    }
}

const OPENAI_BLOCK_FRAME: &[u8] =
    b"data: {\"error\":{\"message\":\"blocked by Soup Wall output policy\",\"type\":\"llm_firewall_block\"}}\n\ndata: [DONE]\n\n";
const ANTHROPIC_BLOCK_FRAME: &[u8] =
    b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"blocked by Soup Wall output policy\"}}\n\n";

fn responses_block_frame(reason: &str) -> axum::body::Bytes {
    let payload = serde_json::json!({
        "type": "error",
        "sequence_number": 0,
        "code": "llm_firewall_block",
        "message": reason,
        "param": null
    });
    axum::body::Bytes::from(format!("event: error\ndata: {payload}\n\n"))
}

fn append_tail(acc: &mut String, text: &str, window: usize) {
    acc.push_str(text);
    if acc.len() <= window * 4 {
        return;
    }
    let mut cut = acc.len() - window * 4;
    while cut < acc.len() && !acc.is_char_boundary(cut) {
        cut += 1;
    }
    acc.drain(..cut);
}

type StreamItem = Result<Bytes, Infallible>;

/// Build a response body backed by a bounded queue. The producer pauses at
/// `send` when the client is slower than the upstream, so memory use is capped
/// by `capacity` chunks instead of growing with the response duration.
fn bounded_body(capacity: usize) -> (mpsc::Sender<StreamItem>, Body) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let stream = futures_util::stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    });
    (tx, Body::from_stream(stream))
}

async fn finish_tenant_stream(
    state: &Shared,
    tenant_audit: &Option<TenantAuditContext>,
    outcome: &str,
    status_code: u16,
) {
    if let Some(context) = tenant_audit {
        crate::auth::record_tenant_audit(state, context, outcome, status_code).await;
    }
}

fn streaming_response(
    status: StatusCode,
    content_type: String,
    body: Body,
    tenant_audit: Option<TenantAuditContext>,
) -> Response {
    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .expect("stream response builder uses valid status and content type");
    if tenant_audit.is_some() {
        response.extensions_mut().insert(DeferredTenantAudit);
    }
    response
}

/// Forward typed Responses SSE events verbatim while inspecting decoded text
/// deltas and completed function-call Items. JSON is parsed only after a complete
/// SSE frame has arrived, so UTF-8 and event boundaries may cross network chunks.
async fn proxy_responses_stream(
    state: Shared,
    builder: reqwest::RequestBuilder,
    request_id: String,
    started: Instant,
    tool_results: Vec<String>,
    tenant_audit: Option<TenantAuditContext>,
    usage_context: StreamUsageContext,
) -> Response {
    let upstream = match timeout(state.config.upstream_timeout(), builder.send()).await {
        Err(_) | Ok(Err(_)) => {
            return (StatusCode::BAD_GATEWAY, Json(error_body("upstream error"))).into_response();
        }
        Ok(Ok(response)) => response,
    };
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();
    let window = state.config.stream_window.max(16);
    let (tx, body) = bounded_body(state.config.stream_buffer_capacity());
    let task_state = state.clone();
    let task_audit = tenant_audit.clone();
    let mut byte_stream = upstream.bytes_stream();

    tokio::spawn(async move {
        let mut decoder = SseJsonDecoder::default();
        let mut output_tail = String::new();
        let mut inspected_calls = HashSet::new();
        let mut terminal_response = None;
        let mut usage_recorded = false;

        loop {
            let chunk =
                match timeout(task_state.config.stream_idle_timeout(), byte_stream.next()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => {
                        let reason = "upstream stream idle timeout";
                        audit_output_block(&request_id, reason, started);
                        finish_tenant_stream(&task_state, &task_audit, "stream_timeout", 504).await;
                        if tx.send(Ok(responses_block_frame(reason))).await.is_err() {
                            return;
                        }
                        return;
                    }
                };
            let bytes = match chunk {
                Ok(bytes) => bytes,
                Err(_) => {
                    finish_tenant_stream(&task_state, &task_audit, "stream_error", 502).await;
                    return;
                }
            };
            if bytes.len() > task_state.config.max_stream_chunk_bytes() {
                let reason = "upstream stream chunk exceeded configured limit";
                audit_output_block(&request_id, reason, started);
                finish_tenant_stream(&task_state, &task_audit, "blocked", 502).await;
                if tx.send(Ok(responses_block_frame(reason))).await.is_err() {
                    return;
                }
                return;
            }
            let mut block_reason = None;
            let events = match decoder.push(&bytes) {
                Ok(events) => events,
                Err(error) if task_state.config.fail_mode == FailMode::FailClosed => {
                    block_reason = Some(error.reason().to_string());
                    Vec::new()
                }
                Err(error) => {
                    tracing::warn!(
                        reason = error.reason(),
                        "Responses stream inspection failed open"
                    );
                    Vec::new()
                }
            };

            for event in events {
                match event.get("type").and_then(serde_json::Value::as_str) {
                    Some("response.output_text.delta") => {
                        if let Some(delta) = event.get("delta").and_then(serde_json::Value::as_str)
                        {
                            append_tail(&mut output_tail, delta, window);
                            if let Some(reason) = decide_output(&task_state.firewall, &output_tail)
                            {
                                block_reason = Some(reason);
                                break;
                            }
                        }
                    }
                    Some("response.output_item.done") => {
                        let Some(item) = event.get("item") else {
                            continue;
                        };
                        let Some(call) = crate::agent_scan::responses_tool_call(item) else {
                            continue;
                        };
                        if let Some(reason) = capability_refuse_calls(
                            &task_state,
                            &request_id,
                            std::slice::from_ref(&call),
                        ) {
                            block_reason = Some(reason);
                            break;
                        }
                        if !task_state.config.agent_inspection.enabled {
                            continue;
                        }
                        let key = item
                            .get("call_id")
                            .or_else(|| item.get("id"))
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                            .unwrap_or_else(|| item.to_string());
                        if inspected_calls.insert(key) {
                            if let Some(reason) = agent_refuse_reason(
                                &task_state,
                                &request_id,
                                tool_results.clone(),
                                vec![call],
                            ) {
                                block_reason = Some(reason);
                                break;
                            }
                        }
                    }
                    Some("response.completed") => {
                        if let Some(response) = event.get("response") {
                            terminal_response = Some(response.clone());
                            let calls = crate::agent_scan::responses_tool_calls(response);
                            if let Some(reason) =
                                capability_refuse_calls(&task_state, &request_id, &calls)
                            {
                                block_reason = Some(reason);
                                break;
                            }
                            if !task_state.config.agent_inspection.enabled
                                || !inspected_calls.is_empty()
                            {
                                continue;
                            }
                            if let Some(reason) = agent_refuse_reason(
                                &task_state,
                                &request_id,
                                tool_results.clone(),
                                calls,
                            ) {
                                block_reason = Some(reason);
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }

            if !usage_recorded {
                if let Some(response) = &terminal_response {
                    record_stream_usage(&task_state, &usage_context, &request_id, response).await;
                    usage_recorded = true;
                }
            }

            if let Some(reason) = block_reason {
                audit_output_block(&request_id, &reason, started);
                finish_tenant_stream(&task_state, &task_audit, "blocked", 502).await;
                if tx.send(Ok(responses_block_frame(&reason))).await.is_err() {
                    return;
                }
                return;
            }
            if tx.send(Ok(bytes)).await.is_err() {
                finish_tenant_stream(&task_state, &task_audit, "client_disconnected", 499).await;
                return;
            }
        }

        finish_tenant_stream(
            &task_state,
            &task_audit,
            if status.is_success() {
                "completed"
            } else {
                "failed"
            },
            status.as_u16(),
        )
        .await;

        AuditRecord {
            request_id,
            direction: "output".into(),
            decision: "stream_done".into(),
            score: 0,
            reasons: vec![],
            owasp: Vec::new(),
            atlas: Vec::new(),
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
    });

    streaming_response(status, content_type, body, tenant_audit)
}

/// Forward the upstream SSE stream VERBATIM (byte-for-byte), scanning a sliding tail
/// window for output-policy violations. On violation we emit `block_frame` and stop;
/// otherwise upstream framing is preserved exactly.
#[allow(clippy::too_many_arguments)]
async fn proxy_stream(
    state: Shared,
    builder: reqwest::RequestBuilder,
    request_id: String,
    started: Instant,
    block_frame: &'static [u8],
    tenant_audit: Option<TenantAuditContext>,
    usage_context: StreamUsageContext,
    tool_context: Option<StreamToolContext>,
) -> Response {
    let upstream = match timeout(state.config.upstream_timeout(), builder.send()).await {
        Err(_) | Ok(Err(_)) => {
            return (StatusCode::BAD_GATEWAY, Json(error_body("upstream error"))).into_response()
        }
        Ok(Ok(response)) => response,
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let window = state.config.stream_window.max(16);
    let (tx, body) = bounded_body(state.config.stream_buffer_capacity());
    let task_state = state.clone();
    let task_audit = tenant_audit.clone();
    let mut byte_stream = upstream.bytes_stream();

    tokio::spawn(async move {
        let mut acc = String::new();
        let mut usage_decoder = SseJsonDecoder::default();
        let mut usage_evidence = StreamUsageEvidence::default();
        let mut usage_recorded = false;
        let mut tool_assembler = tool_context
            .as_ref()
            .map(|context| crate::agent_scan::StreamingToolCalls::new(context.protocol));
        loop {
            let chunk =
                match timeout(task_state.config.stream_idle_timeout(), byte_stream.next()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => {
                        let reason = "upstream stream idle timeout";
                        AuditRecord {
                            request_id: request_id.clone(),
                            direction: "output".into(),
                            decision: "stream_timeout".into(),
                            score: 0,
                            reasons: vec![reason.into()],
                            owasp: Vec::new(),
                            atlas: Vec::new(),
                            latency_ms: started.elapsed().as_millis(),
                        }
                        .emit();
                        finish_tenant_stream(&task_state, &task_audit, "stream_timeout", 504).await;
                        if tx.send(Ok(Bytes::from_static(block_frame))).await.is_err() {
                            return;
                        }
                        return;
                    }
                };
            let bytes = match chunk {
                Ok(bytes) => bytes,
                Err(_) => {
                    finish_tenant_stream(&task_state, &task_audit, "stream_error", 502).await;
                    return;
                }
            };
            if bytes.len() > task_state.config.max_stream_chunk_bytes() {
                let reason = "upstream stream chunk exceeded configured limit";
                AuditRecord {
                    request_id: request_id.clone(),
                    direction: "output".into(),
                    decision: "stream_chunk_limit".into(),
                    score: 0,
                    reasons: vec![reason.into()],
                    owasp: Vec::new(),
                    atlas: Vec::new(),
                    latency_ms: started.elapsed().as_millis(),
                }
                .emit();
                finish_tenant_stream(&task_state, &task_audit, "blocked", 502).await;
                if tx.send(Ok(Bytes::from_static(block_frame))).await.is_err() {
                    return;
                }
                return;
            }
            // One decode serves both usage evidence and tool-call reassembly.
            let mut tool_block = None;
            let decoded = match usage_decoder.push(&bytes) {
                Ok(events) => events,
                Err(error) => {
                    // Only an oversized frame means a tool call we could not inspect
                    // but the client still receives and parses: that fails closed.
                    // A payload that is not JSON is not a tool call the provider's
                    // own client could execute either, so refusing every stream that
                    // contains one would deny legitimate traffic for no security
                    // gain — warn and carry on.
                    if error == SseDecodeError::TooLarge
                        && tool_assembler.is_some()
                        && task_state.config.fail_mode == FailMode::FailClosed
                    {
                        tool_block = Some(error.reason().to_string());
                    } else {
                        tracing::warn!(
                            reason = error.reason(),
                            "stream event could not be decoded"
                        );
                    }
                    Vec::new()
                }
            };
            for event in &decoded {
                usage_evidence.observe(
                    event,
                    usage_context.input_field,
                    usage_context.output_field,
                );
            }
            // Reassemble tool calls split across frames and judge only completed
            // ones, before the frame that completes them is forwarded.
            if let (Some(assembler), Some(context)) =
                (tool_assembler.as_mut(), tool_context.as_ref())
            {
                for event in &decoded {
                    if tool_block.is_some() {
                        break;
                    }
                    let completed = match assembler.push(event) {
                        Ok(calls) => calls,
                        Err(reason) => {
                            if task_state.config.fail_mode == FailMode::FailClosed {
                                tool_block = Some(reason.to_string());
                                break;
                            }
                            tracing::warn!(reason, "streamed tool call not reassembled");
                            Vec::new()
                        }
                    };
                    if completed.is_empty() {
                        continue;
                    }
                    if let Some(reason) =
                        capability_refuse_calls(&task_state, &request_id, &completed)
                    {
                        tool_block = Some(reason);
                        break;
                    }
                    if task_state.config.agent_inspection.enabled {
                        if let Some(reason) = agent_refuse_reason(
                            &task_state,
                            &request_id,
                            context.tool_results.clone(),
                            completed,
                        ) {
                            tool_block = Some(reason);
                            break;
                        }
                    }
                }
            }
            if let Some(reason) = tool_block {
                AuditRecord {
                    request_id: request_id.clone(),
                    direction: "output".into(),
                    decision: "block".into(),
                    score: 0,
                    reasons: vec![reason],
                    owasp: Vec::new(),
                    atlas: Vec::new(),
                    latency_ms: started.elapsed().as_millis(),
                }
                .emit();
                finish_tenant_stream(&task_state, &task_audit, "blocked", 502).await;
                if tx.send(Ok(Bytes::from_static(block_frame))).await.is_err() {
                    return;
                }
                return;
            }
            if !usage_recorded
                && (usage_decoder.saw_done() || usage_evidence.saw_terminal)
                && status.is_success()
            {
                let terminal_body = std::mem::take(&mut usage_evidence)
                    .terminal_body(usage_context.input_field, usage_context.output_field);
                record_stream_usage(&task_state, &usage_context, &request_id, &terminal_body).await;
                usage_recorded = true;
            }
            append_tail(&mut acc, &String::from_utf8_lossy(&bytes), window);
            if decide_output(&task_state.firewall, &acc).is_some() {
                AuditRecord {
                    request_id: request_id.clone(),
                    direction: "output".into(),
                    decision: "block".into(),
                    score: 0,
                    reasons: vec!["output policy violation".into()],
                    owasp: Vec::new(),
                    atlas: Vec::new(),
                    latency_ms: started.elapsed().as_millis(),
                }
                .emit();
                finish_tenant_stream(&task_state, &task_audit, "blocked", 502).await;
                if tx.send(Ok(Bytes::from_static(block_frame))).await.is_err() {
                    return;
                }
                return;
            }
            // Pass the upstream chunk through VERBATIM (preserves SSE framing).
            if tx.send(Ok(bytes)).await.is_err() {
                finish_tenant_stream(&task_state, &task_audit, "client_disconnected", 499).await;
                return;
            }
        }
        // The stream ended without a terminal marker for a call still being
        // reassembled. Everything has already been forwarded, so this can only be
        // audited, never blocked — but recording it stops a truncated stream from
        // silently skipping inspection altogether.
        if let (Some(assembler), Some(context)) = (tool_assembler.as_mut(), tool_context.as_ref()) {
            let trailing = assembler.flush();
            if !trailing.is_empty() {
                let missed =
                    capability_refuse_calls(&task_state, &request_id, &trailing).or_else(|| {
                        if task_state.config.agent_inspection.enabled {
                            agent_refuse_reason(
                                &task_state,
                                &request_id,
                                context.tool_results.clone(),
                                trailing,
                            )
                        } else {
                            None
                        }
                    });
                if let Some(reason) = missed {
                    tracing::warn!(
                        cycle = %request_id,
                        reason,
                        "streamed tool call completed only at end of stream; it was \
                         already forwarded and could not be blocked"
                    );
                    AuditRecord {
                        request_id: request_id.clone(),
                        direction: "output".into(),
                        decision: "stream_truncated_tool_call".into(),
                        score: 0,
                        reasons: vec![reason],
                        owasp: Vec::new(),
                        atlas: Vec::new(),
                        latency_ms: started.elapsed().as_millis(),
                    }
                    .emit();
                }
            }
        }
        finish_tenant_stream(
            &task_state,
            &task_audit,
            if status.is_success() {
                "completed"
            } else {
                "failed"
            },
            status.as_u16(),
        )
        .await;
        AuditRecord {
            request_id,
            direction: "output".into(),
            decision: "stream_done".into(),
            score: 0,
            reasons: vec![],
            owasp: Vec::new(),
            atlas: Vec::new(),
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
    });

    streaming_response(status, content_type, body, tenant_audit)
}

#[allow(clippy::too_many_arguments)]
fn audit_input(
    request_id: &str,
    decision: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    AuditRecord {
        request_id: request_id.to_string(),
        direction: "input".into(),
        decision: decision.into(),
        score,
        reasons,
        owasp,
        atlas,
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();
}

fn audit_block(
    request_id: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    audit_input(request_id, "block", score, reasons, owasp, atlas, started);
}

fn audit_allow(
    request_id: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    audit_input(request_id, "allow", score, reasons, owasp, atlas, started);
}

fn audit_output_block(request_id: &str, reason: &str, started: Instant) {
    AuditRecord {
        request_id: request_id.to_string(),
        direction: "output".into(),
        decision: "block".into(),
        score: 0,
        reasons: vec![reason.to_string()],
        owasp: Vec::new(),
        atlas: Vec::new(),
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();
}
