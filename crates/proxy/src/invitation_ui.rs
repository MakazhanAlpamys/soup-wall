// SPDX-License-Identifier: Apache-2.0

//! Same-origin handoff page for a workspace invitation bearer.
//!
//! The raw token arrives only in the URL fragment, is removed from browser
//! history immediately, and is then posted to the OIDC login-start endpoint.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse, Response};

pub async fn accept() -> Response {
    let nonce = crate::oidc::random_urlsafe_value(18);
    let html = include_str!("workspace_invitation.html")
        .replacen("<style>", &format!("<style nonce=\"{nonce}\">"), 1)
        .replacen("<script>", &format!("<script nonce=\"{nonce}\">"), 1);
    let mut response = Html(html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_str(&csp).expect("URL-safe CSP nonce produces a valid header"),
    );
    response
}
