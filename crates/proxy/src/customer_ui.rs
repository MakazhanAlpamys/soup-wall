// SPDX-License-Identifier: Apache-2.0

//! Browser dashboard for an authenticated customer workspace.
//!
//! It contains no server-rendered tenant data. The browser fetches only the
//! current opaque session from its same-origin, cookie-authenticated endpoint.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse, Response};

pub async fn dashboard() -> Response {
    let nonce = crate::oidc::random_urlsafe_value(18);
    let html = include_str!("customer_dashboard.html")
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
        "default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_str(&csp).expect("URL-safe CSP nonce produces a valid header"),
    );
    response
}
