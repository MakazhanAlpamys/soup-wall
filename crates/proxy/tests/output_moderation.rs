// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Output moderation wiring: off-by-default passthrough. The verdict logic and the
//! disabled no-op are unit-tested in `moderation.rs`; the live model (block/flag) is
//! exercised by the phase-13 scorecard run under `--features ml`.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use llm_firewall::handlers::AppState;
use llm_firewall::{app, test_config};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn moderation_off_by_default_passes_the_reply_through() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role":"assistant","content":"here is a detailed answer"}}]
        })))
        .mount(&server)
        .await;

    let policy = PolicySet::from_yaml("default: allow").unwrap();
    let fw = Firewall::new(vec![Box::new(InjectionDetector::new())], policy);
    let cfg = test_config(server.uri()); // output_moderation default = off
    let state = Arc::new(AppState {
        firewall: fw,
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: None,
        admin_token: None,
        oidc_state_cipher: None,
        saml: None,
        rate_limiter: std::sync::Mutex::new(llm_firewall::rate_limit::RateLimiter::new(
            Default::default(),
        )),
        spend_ledger: std::sync::Mutex::new(llm_firewall::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(cfg.output_moderation.clone()),
        config: cfg,
    });

    let body = serde_json::json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]});
    let resp = app(state)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("detailed answer"));
}
