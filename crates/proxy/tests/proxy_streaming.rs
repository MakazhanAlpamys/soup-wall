// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use llm_firewall::{app, test_config, AppState};
use soup_wall_core::{Firewall, PolicySet, SecretDetector};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn streams_benign_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("data: hello\n\ndata: world\n\n", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let fw = Firewall::new(
        vec![Box::new(SecretDetector::new())],
        PolicySet::from_yaml("default: allow").unwrap(),
    );
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
        moderation: llm_firewall::moderation::ModerationGate::new(Default::default()),
        config: test_config(server.uri()),
    });

    let body = serde_json::json!({
        "model":"gpt-4o","stream":true,
        "messages":[{"role":"user","content":"say hi"}]
    });
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
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let s = String::from_utf8_lossy(&bytes);
    assert!(
        s.contains("data: hello"),
        "expected verbatim upstream frames, got: {s}"
    );
    assert!(!s.contains("data: data:"), "stream was double-framed: {s}");
}
