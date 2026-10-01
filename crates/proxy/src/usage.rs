// SPDX-License-Identifier: Apache-2.0

//! Durable, provider-neutral usage-event construction.
//!
//! Admission counters answer whether a request may start. These events answer
//! what a terminal provider response actually reported and deliberately never
//! infer an exact token count or cost when that evidence is absent.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use crate::config::ModelPrice;

/// Whether the provider supplied complete terminal token counters. `Missing`
/// is intentionally not an estimate and must never be presented as exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageTokenStatus {
    Actual,
    Missing,
}

/// A priced event has complete token evidence, exact rates and a computed
/// micro-USD amount. Everything else remains explicitly unpriced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsagePricingStatus {
    Priced,
    Unpriced,
}

/// Validated event ready for one idempotent append. It contains no prompt,
/// response content, API key, or raw firewall credential.
///
/// This type lives beside the code that builds it rather than beside the store
/// that persists it: constructing a usage event is data-plane work, and any
/// store — local, remote, or none — is downstream of it. How a store encodes
/// these values is that store's business.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewUsageEvent {
    pub tenant_id: String,
    pub request_id: String,
    pub provider_response_id: Option<String>,
    pub provider: String,
    pub path: String,
    pub requested_model: String,
    pub provider_model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub token_status: UsageTokenStatus,
    pub pricing_status: UsagePricingStatus,
    pub model_price_version: Option<String>,
    pub input_usd_micros_per_million: Option<u64>,
    pub output_usd_micros_per_million: Option<u64>,
    pub cost_usd_micros: Option<u64>,
    pub created_at_unix: i64,
}

#[derive(Clone, Copy)]
pub struct TerminalUsageContext<'a> {
    pub tenant_id: &'a str,
    pub request_id: &'a str,
    pub provider: &'a str,
    pub path: &'a str,
    pub requested_model: &'a str,
    pub input_field: &'a str,
    pub output_field: &'a str,
    pub price: Option<ModelPrice>,
}

/// Convert a terminal non-streaming provider response into one append-only
/// event. Missing or out-of-range usage is explicit and never billed as exact.
pub fn terminal_usage_event(
    context: TerminalUsageContext<'_>,
    body: &serde_json::Value,
) -> NewUsageEvent {
    let provider_model = body
        .get("model")
        .and_then(serde_json::Value::as_str)
        .filter(|model| !model.is_empty() && model.len() <= 256)
        .map(str::to_owned);
    let provider_response_id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .map(str::to_owned);
    let tokens = body.get("usage").and_then(|usage| {
        let input = usage.get(context.input_field)?.as_u64()?;
        let output = usage.get(context.output_field)?.as_u64()?;
        (input <= i64::MAX as u64 && output <= i64::MAX as u64).then_some((input, output))
    });
    let valid_price = context.price.filter(|price| {
        price.input_usd_micros_per_million <= i64::MAX as u64
            && price.output_usd_micros_per_million <= i64::MAX as u64
    });
    let price_version =
        valid_price.map(|price| model_price_version(context.requested_model, price));
    let cost = tokens.and_then(|(input, output)| {
        valid_price.and_then(|price| checked_token_cost(input, output, price))
    });

    NewUsageEvent {
        tenant_id: context.tenant_id.to_owned(),
        request_id: context.request_id.to_owned(),
        provider_response_id,
        provider: context.provider.to_owned(),
        path: context.path.to_owned(),
        requested_model: context.requested_model.to_owned(),
        provider_model,
        input_tokens: tokens.map(|usage| usage.0),
        output_tokens: tokens.map(|usage| usage.1),
        token_status: if tokens.is_some() {
            UsageTokenStatus::Actual
        } else {
            UsageTokenStatus::Missing
        },
        pricing_status: if cost.is_some() {
            UsagePricingStatus::Priced
        } else {
            UsagePricingStatus::Unpriced
        },
        model_price_version: price_version,
        input_usd_micros_per_million: valid_price.map(|price| price.input_usd_micros_per_million),
        output_usd_micros_per_million: valid_price.map(|price| price.output_usd_micros_per_million),
        cost_usd_micros: cost,
        created_at_unix: now_unix(),
    }
}

/// A price version is content-addressed rather than a mutable label. Changing
/// either rate (or the requested model alias it prices) necessarily creates a
/// different version while retaining the exact rates on the event itself.
pub fn model_price_version(model: &str, price: ModelPrice) -> String {
    let mut hash = Sha256::new();
    hash.update(b"llm-firewall/model-price/v1\0");
    hash.update((model.len() as u64).to_be_bytes());
    hash.update(model.as_bytes());
    hash.update(price.input_usd_micros_per_million.to_be_bytes());
    hash.update(price.output_usd_micros_per_million.to_be_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
}

fn checked_token_cost(input_tokens: u64, output_tokens: u64, price: ModelPrice) -> Option<u64> {
    let input = component_cost(input_tokens, price.input_usd_micros_per_million)?;
    let output = component_cost(output_tokens, price.output_usd_micros_per_million)?;
    u64::try_from(input.checked_add(output)?).ok()
}

fn component_cost(tokens: u64, micros_per_million: u64) -> Option<u128> {
    let numerator = u128::from(tokens)
        .checked_mul(u128::from(micros_per_million))?
        .checked_add(999_999)?;
    Some(numerator / 1_000_000)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        model_price_version, terminal_usage_event, TerminalUsageContext, UsagePricingStatus,
        UsageTokenStatus,
    };
    use crate::config::ModelPrice;

    fn context<'a>(price: Option<ModelPrice>) -> TerminalUsageContext<'a> {
        TerminalUsageContext {
            tenant_id: "tenant_acme",
            request_id: "req_one",
            provider: "openai",
            path: "/v1/responses",
            requested_model: "gpt-test",
            input_field: "input_tokens",
            output_field: "output_tokens",
            price,
        }
    }

    #[test]
    fn terminal_usage_is_priced_with_a_content_addressed_version() {
        let price = ModelPrice {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 2_000_000,
        };
        let event = terminal_usage_event(
            context(Some(price)),
            &json!({
                "id": "resp_provider_one",
                "model": "gpt-test-2026-08-01",
                "usage": { "input_tokens": 3, "output_tokens": 4 }
            }),
        );
        assert_eq!(event.token_status, UsageTokenStatus::Actual);
        assert_eq!(event.pricing_status, UsagePricingStatus::Priced);
        assert_eq!(event.input_tokens, Some(3));
        assert_eq!(event.output_tokens, Some(4));
        assert_eq!(event.cost_usd_micros, Some(11));
        assert_eq!(
            event.provider_response_id.as_deref(),
            Some("resp_provider_one")
        );
        assert_eq!(event.provider_model.as_deref(), Some("gpt-test-2026-08-01"));
        assert_eq!(
            event.model_price_version.as_deref(),
            Some(model_price_version("gpt-test", price).as_str())
        );
    }

    #[test]
    fn missing_usage_and_missing_price_are_never_reported_as_exact_cost() {
        let missing_usage = terminal_usage_event(
            context(Some(ModelPrice {
                input_usd_micros_per_million: 1,
                output_usd_micros_per_million: 1,
            })),
            &json!({ "model": "gpt-test" }),
        );
        assert_eq!(missing_usage.token_status, UsageTokenStatus::Missing);
        assert_eq!(missing_usage.pricing_status, UsagePricingStatus::Unpriced);
        assert!(missing_usage.cost_usd_micros.is_none());
        assert!(missing_usage.model_price_version.is_some());

        let unpriced = terminal_usage_event(
            context(None),
            &json!({ "usage": { "input_tokens": 2, "output_tokens": 5 } }),
        );
        assert_eq!(unpriced.token_status, UsageTokenStatus::Actual);
        assert_eq!(unpriced.pricing_status, UsagePricingStatus::Unpriced);
        assert!(unpriced.model_price_version.is_none());
        assert!(unpriced.cost_usd_micros.is_none());
    }
}
