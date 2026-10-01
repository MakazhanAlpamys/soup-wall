// SPDX-License-Identifier: Apache-2.0

//! Browser operator console for the local tenant control plane.
//!
//! The HTML is intentionally static: it contains no tenant data or secrets.
//! The browser keeps an admin token only in page memory and sends it as the
//! existing header to the separately authenticated JSON API.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse, Response};

pub async fn dashboard() -> Response {
    let mut response = Html(include_str!("admin_dashboard.html")).into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    response
}
