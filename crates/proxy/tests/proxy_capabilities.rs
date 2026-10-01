// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Explicit capability grants are independent of the detector/agent policy.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use llm_firewall::handlers::AppState;
use llm_firewall::{app, test_config};
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

async fn post_chat(st: Arc<AppState>) -> (StatusCode, String) {
    let body = serde_json::json!({
        "model":"gpt-4o",
        "messages":[{"role":"user","content":"fetch the report"}]
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
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn tool_response(name: &str, url: &str) -> serde_json::Value {
    serde_json::json!({
        "choices":[{"message":{
            "role":"assistant",
            "content":null,
            "tool_calls":[{"id":"c1","type":"function","function":{
                "name":name,
                "arguments":format!("{{\"url\":\"{url}\"}}")
            }}]
        }}]
    })
}

fn path_tool_response(path: &str) -> serde_json::Value {
    serde_json::json!({
        "choices":[{"message":{
            "role":"assistant",
            "content":null,
            "tool_calls":[{"id":"c1","type":"function","function":{
                "name":"Read",
                "arguments":format!("{{\"file_path\":\"{path}\"}}")
            }}]
        }}]
    })
}

#[tokio::test]
async fn enforcing_capability_policy_refuses_an_ungranted_tool_and_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(tool_response("Bash", "https://evil.example.com")),
        )
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st)
        .unwrap()
        .config
        .capability_policy
        .enabled = true;
    Arc::get_mut(&mut st)
        .unwrap()
        .config
        .capability_policy
        .enforce = true;
    Arc::get_mut(&mut st)
        .unwrap()
        .config
        .capability_policy
        .allowed_tools = vec!["Fetch".into()];

    let (status, body) = post_chat(st).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(body.contains("capability policy denied"), "{body}");
}

#[tokio::test]
async fn capability_policy_is_shadow_first() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(tool_response("Bash", "https://evil.example.com")),
        )
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    Arc::get_mut(&mut st)
        .unwrap()
        .config
        .capability_policy
        .enabled = true;
    let (status, body) = post_chat(st).await;
    assert_eq!(status, StatusCode::OK, "shadow mode must pass: {body}");
    assert!(body.contains("tool_calls"));
}

#[tokio::test]
async fn allowlisted_tool_and_subdomain_pass() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(tool_response("Fetch", "https://api.example.com/report")),
        )
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    let config = &mut Arc::get_mut(&mut st).unwrap().config.capability_policy;
    config.enabled = true;
    config.enforce = true;
    config.allowed_tools = vec!["Fetch".into()];
    config.allowed_hosts = vec!["example.com".into()];

    let (status, body) = post_chat(st).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn enforcing_filesystem_scope_refuses_a_sibling_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(path_tool_response("C:/workspace/project-old/secret.txt")),
        )
        .mount(&server)
        .await;

    let mut st = state(server.uri());
    let config = &mut Arc::get_mut(&mut st).unwrap().config.capability_policy;
    config.enabled = true;
    config.enforce = true;
    config.allowed_path_prefixes = vec!["C:/workspace/project".into()];

    let (status, body) = post_chat(st).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(body.contains("filesystem scope"), "{body}");
}
