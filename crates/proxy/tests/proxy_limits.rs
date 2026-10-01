// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use llm_firewall::{app, test_config, AppState};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn state(base: String) -> Arc<AppState> {
    Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow").unwrap(),
        ),
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
        config: test_config(base),
    })
}

#[tokio::test]
async fn oversized_json_is_rejected_before_the_upstream_is_called() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st).unwrap().config.max_body_bytes = 128;
    let body = serde_json::json!({
        "model":"gpt-5.6",
        "input": "x".repeat(1024)
    });
    let response = app(st)
        .oneshot(
            Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn non_streaming_upstream_timeout_returns_gateway_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                // Keep the proxy deadline comfortably above local/CI scheduling
                // jitter, while still making the upstream response unambiguously late.
                .set_delay(Duration::from_millis(750))
                .set_body_json(serde_json::json!({
                    "choices":[{"message":{"role":"assistant","content":"late"}}]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st).unwrap().config.upstream_timeout_ms = 250;
    let body = serde_json::json!({
        "model":"gpt-5.6",
        "messages":[{"role":"user","content":"hello"}]
    });
    let response = app(st)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn oversized_upstream_json_is_rejected_before_unbounded_buffering() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role":"assistant","content": "x".repeat(1024)}}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st)
        .unwrap()
        .config
        .max_upstream_body_bytes = 64;
    let body = serde_json::json!({
        "model":"gpt-5.6",
        "messages":[{"role":"user","content":"hello"}]
    });
    let response = app(st)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("exceeded configured limit"));
}

#[tokio::test]
async fn oversized_upstream_stream_chunk_is_replaced_with_a_block_frame() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(
                "data: {\"choices\":[{\"delta\":{\"content\":\"this frame is deliberately larger than the cap\"}}]}\n\n",
                "text/event-stream",
            ),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st).unwrap().config.max_stream_chunk_bytes = 8;
    let body = serde_json::json!({
        "model":"gpt-5.6",
        "stream": true,
        "messages":[{"role":"user","content":"hello"}]
    });
    let response = app(st)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("llm_firewall_block"));
}
