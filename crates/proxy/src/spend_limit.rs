// SPDX-License-Identifier: Apache-2.0

//! Bounded, process-local spend reservations settled from provider token usage.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::{ModelPrice, SpendLimit};
use crate::rate_limit::ClientId;

#[derive(Clone, Debug)]
pub struct Reservation {
    client: ClientId,
    price: ModelPrice,
    reserved_usd_micros: u64,
    max_usd_micros: u64,
    redis_key: Option<String>,
}

impl Reservation {
    pub(crate) fn distributed(
        client: ClientId,
        price: ModelPrice,
        reserved_usd_micros: u64,
        max_usd_micros: u64,
        redis_key: String,
    ) -> Self {
        Self {
            client,
            price,
            reserved_usd_micros,
            max_usd_micros,
            redis_key: Some(redis_key),
        }
    }

    pub(crate) fn redis_key(&self) -> Option<&str> {
        self.redis_key.as_deref()
    }

    pub(crate) fn reserved_usd_micros(&self) -> u64 {
        self.reserved_usd_micros
    }

    pub(crate) fn max_usd_micros(&self) -> u64 {
        self.max_usd_micros
    }

    pub(crate) fn token_cost(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        token_cost(input_tokens, self.price.input_usd_micros_per_million).saturating_add(
            token_cost(output_tokens, self.price.output_usd_micros_per_million),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    ModelUnpriced,
    BudgetExhausted { retry_after_secs: u64 },
    CapacityExhausted { retry_after_secs: u64 },
}

#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    spent_usd_micros: u64,
    reserved_usd_micros: u64,
}

/// A bounded ledger. It never stores raw client tokens, and it has no durable
/// state: deploying more than one replica requires a shared ledger later.
pub struct SpendLedger {
    config: SpendLimit,
    clients: HashMap<ClientId, Window>,
}

impl SpendLedger {
    pub fn new(config: SpendLimit) -> Self {
        Self {
            config,
            clients: HashMap::new(),
        }
    }

    pub fn reserve(
        &mut self,
        client: ClientId,
        model: &str,
        now: Instant,
    ) -> Result<Reservation, ReserveError> {
        let config = self.config.clone();
        self.reserve_with(client, model, &config, now)
    }

    /// Reserve against a per-tenant policy while retaining the global bounded
    /// map. Model prices remain operator-controlled configuration, not data a
    /// tenant can write through the admin API.
    pub fn reserve_with(
        &mut self,
        client: ClientId,
        model: &str,
        config: &SpendLimit,
        now: Instant,
    ) -> Result<Reservation, ReserveError> {
        let Some(price) = config.model_prices.get(model).copied() else {
            return Err(ReserveError::ModelUnpriced);
        };
        let window_duration = Duration::from_secs(config.window_seconds.max(1));
        let max_clients = config.max_tracked_clients.max(1);
        if !self.clients.contains_key(&client) && self.clients.len() >= max_clients {
            self.clients
                .retain(|_, entry| now.duration_since(entry.started) < window_duration);
            if self.clients.len() >= max_clients {
                return Err(ReserveError::CapacityExhausted {
                    retry_after_secs: config.window_seconds.max(1),
                });
            }
        }

        let entry = self.clients.entry(client).or_insert(Window {
            started: now,
            spent_usd_micros: 0,
            reserved_usd_micros: 0,
        });
        if now.duration_since(entry.started) >= window_duration {
            *entry = Window {
                started: now,
                spent_usd_micros: 0,
                reserved_usd_micros: 0,
            };
        }

        let reservation = config.reserve_usd_micros_per_request;
        let committed = entry
            .spent_usd_micros
            .saturating_add(entry.reserved_usd_micros);
        if committed.saturating_add(reservation) > config.max_usd_micros {
            return Err(ReserveError::BudgetExhausted {
                retry_after_secs: seconds_ceil(window_duration - now.duration_since(entry.started)),
            });
        }
        entry.reserved_usd_micros = entry.reserved_usd_micros.saturating_add(reservation);
        Ok(Reservation {
            client,
            price,
            reserved_usd_micros: reservation,
            max_usd_micros: config.max_usd_micros,
            redis_key: None,
        })
    }

    pub fn release(&mut self, reservation: Reservation) {
        if let Some(entry) = self.clients.get_mut(&reservation.client) {
            entry.reserved_usd_micros = entry
                .reserved_usd_micros
                .saturating_sub(reservation.reserved_usd_micros);
        }
    }

    /// Settle a successful response. Returns the charged amount in USD micros.
    pub fn settle(
        &mut self,
        reservation: Reservation,
        input_tokens: u64,
        output_tokens: u64,
    ) -> u64 {
        let cost = reservation.token_cost(input_tokens, output_tokens);
        if let Some(entry) = self.clients.get_mut(&reservation.client) {
            entry.reserved_usd_micros = entry
                .reserved_usd_micros
                .saturating_sub(reservation.reserved_usd_micros);
            entry.spent_usd_micros = entry.spent_usd_micros.saturating_add(cost);
        }
        cost
    }

    /// The provider already processed a response but omitted usage. Freeze the
    /// client for the window rather than allowing unaccounted further spend.
    pub fn exhaust(&mut self, reservation: Reservation) {
        if let Some(entry) = self.clients.get_mut(&reservation.client) {
            entry.reserved_usd_micros = entry
                .reserved_usd_micros
                .saturating_sub(reservation.reserved_usd_micros);
            entry.spent_usd_micros = reservation.max_usd_micros;
        }
    }
}

fn token_cost(tokens: u64, micros_per_million: u64) -> u64 {
    tokens
        .saturating_mul(micros_per_million)
        .saturating_add(999_999)
        / 1_000_000
}

fn seconds_ceil(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
        .max(1)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use super::{ReserveError, SpendLedger};
    use crate::config::{ModelPrice, SpendLimit};
    use crate::rate_limit::client_id;

    fn ledger() -> SpendLedger {
        SpendLedger::new(SpendLimit {
            enabled: true,
            window_seconds: 60,
            max_usd_micros: 10,
            reserve_usd_micros_per_request: 4,
            max_tracked_clients: 2,
            model_prices: BTreeMap::from([(
                "gpt-test".to_string(),
                ModelPrice {
                    input_usd_micros_per_million: 1,
                    output_usd_micros_per_million: 1,
                },
            )]),
        })
    }

    #[test]
    fn reservations_prevent_concurrent_budget_oversubscription() {
        let mut ledger = ledger();
        let now = Instant::now();
        let client = client_id(Some("Bearer token"));
        let first = ledger.reserve(client, "gpt-test", now).unwrap();
        let second = ledger.reserve(client, "gpt-test", now).unwrap();
        assert!(matches!(
            ledger.reserve(client, "gpt-test", now),
            Err(ReserveError::BudgetExhausted { .. })
        ));
        ledger.release(first);
        assert!(ledger.reserve(client, "gpt-test", now).is_ok());
        ledger.release(second);
    }

    #[test]
    fn settlement_uses_ceil_token_cost_and_the_window_resets() {
        let mut ledger = ledger();
        let now = Instant::now();
        let client = client_id(Some("Bearer token"));
        let reservation = ledger.reserve(client, "gpt-test", now).unwrap();
        assert_eq!(ledger.settle(reservation, 1, 1), 2);
        assert!(ledger
            .reserve(client, "gpt-test", now + Duration::from_secs(60))
            .is_ok());
    }

    #[test]
    fn unpriced_models_are_rejected_without_reserving_money() {
        let mut ledger = ledger();
        assert!(matches!(
            ledger.reserve(client_id(Some("Bearer token")), "unknown", Instant::now()),
            Err(ReserveError::ModelUnpriced)
        ));
    }

    #[test]
    fn dynamic_tenant_budget_can_differ_from_the_default_ledger_budget() {
        let mut ledger = ledger();
        let tenant_budget = SpendLimit {
            max_usd_micros: 4,
            reserve_usd_micros_per_request: 4,
            ..ledger.config.clone()
        };
        let tenant = client_id(Some("tenant-a"));
        assert!(ledger
            .reserve_with(tenant, "gpt-test", &tenant_budget, Instant::now())
            .is_ok());
        assert!(matches!(
            ledger.reserve_with(tenant, "gpt-test", &tenant_budget, Instant::now()),
            Err(ReserveError::BudgetExhausted { .. })
        ));
    }
}
