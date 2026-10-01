// SPDX-License-Identifier: Apache-2.0

//! Network-level SCIM provider smoke test.
//!
//! The test acts as a small sandbox directory client and drives the real Axum
//! listener over loopback. It complements the in-memory conformance fixture by
//! exercising HTTP headers, content types, routing, bearer authentication, and
//! the full Users lifecycle without contacting a customer directory.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use llm_firewall::handlers::AppState;
use llm_firewall::tenant_store::TenantStore;
use llm_firewall::{app, test_config};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use tokio::net::TcpListener;

fn state() -> anyhow::Result<(Arc<AppState>, String)> {
    let mut config = test_config("http://127.0.0.1:1".into());
    config.tenant_store.enabled = true;
    let store = TenantStore::open(":memory:")?;
    let organization = store.create_organization("network SCIM sandbox")?;
    let expiry = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 + 3600;
    let issued = store.issue_scim_token(&organization.id, "network fixture", expiry)?;
    let state = Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow")?,
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(store),
        admin_token: None,
        oidc_state_cipher: None,
        saml: None,
        rate_limiter: Mutex::new(llm_firewall::rate_limit::RateLimiter::new(
            Default::default(),
        )),
        spend_ledger: Mutex::new(llm_firewall::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(Default::default()),
        config,
    });
    Ok((state, issued.token))
}

#[tokio::test]
async fn scim_users_lifecycle_works_over_a_real_loopback_http_listener() -> anyhow::Result<()> {
    let (state, token) = state()?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let router: Router = app(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client = reqwest::Client::new();
    let base = format!("http://{address}/scim/v2");
    let bearer = format!("Bearer {token}");
    let headers = || {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, bearer.parse().unwrap());
        headers
    };

    let provider_config = client
        .get(format!("{base}/ServiceProviderConfig"))
        .headers(headers())
        .send()
        .await?;
    assert_eq!(provider_config.status(), reqwest::StatusCode::OK);
    assert_eq!(
        provider_config
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("application/scim+json")),
        Some(true)
    );

    let initial = client
        .get(format!("{base}/Users"))
        .headers(headers())
        .send()
        .await?;
    assert_eq!(initial.status(), reqwest::StatusCode::OK);
    assert_eq!(
        initial.json::<serde_json::Value>().await?["totalResults"],
        0
    );

    let created = client
        .post(format!("{base}/Users"))
        .headers(headers())
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "sandbox-user-1",
            "userName": "sandbox-user@example.test",
            "displayName": "Sandbox User",
            "active": true
        }))
        .send()
        .await?;
    assert_eq!(created.status(), reqwest::StatusCode::CREATED);
    let created_body = created.json::<serde_json::Value>().await?;
    let user_id = created_body["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SCIM create response had no id"))?
        .to_owned();

    let patched = client
        .patch(format!("{base}/Users/{user_id}"))
        .headers(headers())
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}]
        }))
        .send()
        .await?;
    assert_eq!(patched.status(), reqwest::StatusCode::OK);
    assert_eq!(patched.json::<serde_json::Value>().await?["active"], false);

    let deleted = client
        .delete(format!("{base}/Users/{user_id}"))
        .headers(headers())
        .send()
        .await?;
    assert_eq!(deleted.status(), reqwest::StatusCode::NO_CONTENT);

    let _ = shutdown_tx.send(());
    server.await??;
    Ok(())
}
