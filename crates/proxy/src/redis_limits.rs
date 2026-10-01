// SPDX-License-Identifier: Apache-2.0

//! Redis-backed shared fixed-window counters for rate and spend protection.
//!
//! Redis stores only domain-separated SHA-256 client fingerprints, never raw
//! firewall bearer tokens, prompts, responses, or upstream credentials.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::aio::ConnectionManager;
use redis::Script;

use crate::config::{ModelPrice, RedisLimitsConfig, SpendLimit};
use crate::rate_limit::{ClientId, Decision};
use crate::spend_limit::Reservation;

const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
if count > tonumber(ARGV[2]) then
  return 0
end
return 1
"#;

const SPEND_RESERVE_SCRIPT: &str = r#"
local spent = tonumber(redis.call('HGET', KEYS[1], 'spent')) or 0
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved')) or 0
local requested = tonumber(ARGV[1])
local maximum = tonumber(ARGV[2])
if spent + reserved + requested > maximum then
  return 0
end
redis.call('HINCRBY', KEYS[1], 'reserved', requested)
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"#;

const SPEND_RELEASE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved')) or 0
local release = tonumber(ARGV[1])
redis.call('HSET', KEYS[1], 'reserved', math.max(0, reserved - release))
return 1
"#;

const SPEND_SETTLE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved')) or 0
local release = tonumber(ARGV[1])
local charge = tonumber(ARGV[2])
redis.call('HSET', KEYS[1], 'reserved', math.max(0, reserved - release))
redis.call('HINCRBY', KEYS[1], 'spent', charge)
return 1
"#;

const SPEND_EXHAUST_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved')) or 0
local release = tonumber(ARGV[1])
local maximum = tonumber(ARGV[2])
redis.call('HSET', KEYS[1], 'reserved', math.max(0, reserved - release))
redis.call('HSET', KEYS[1], 'spent', maximum)
return 1
"#;

#[derive(Debug)]
pub enum RedisLimitError {
    Timeout,
    Backend(redis::RedisError),
}

impl std::fmt::Display for RedisLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Redis command timed out"),
            // Do not include a backend-supplied string in application logs: a
            // managed provider might echo connection information from a URL
            // that contains a password.
            Self::Backend(_) => formatter.write_str("Redis command failed"),
        }
    }
}

impl std::error::Error for RedisLimitError {}

#[derive(Clone)]
pub struct RedisLimits {
    connection: ConnectionManager,
    key_prefix: Arc<str>,
    command_timeout: Duration,
}

impl RedisLimits {
    pub async fn connect(redis_url: &str, config: &RedisLimitsConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|_| anyhow::anyhow!("invalid Redis limits URL"))?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| anyhow::anyhow!("failed to connect Redis limits backend"))?;
        Ok(Self {
            connection,
            key_prefix: Arc::from(config.key_prefix.clone()),
            command_timeout: Duration::from_millis(config.command_timeout_ms.max(1)),
        })
    }

    /// Verify that the shared counter backend is reachable within the same
    /// bounded command budget used for admission checks. The response is
    /// deliberately reduced to success/failure so readiness never exposes a
    /// Redis URL, credential, or provider-specific error text.
    pub async fn health_check(&self) -> Result<(), RedisLimitError> {
        let mut connection = self.connection.clone();
        match tokio::time::timeout(
            self.command_timeout,
            redis::cmd("PING").query_async::<String>(&mut connection),
        )
        .await
        {
            Ok(Ok(response)) if response == "PONG" => Ok(()),
            Ok(Ok(_)) => Err(RedisLimitError::Backend(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "Redis health check returned an unexpected response",
            )))),
            Ok(Err(error_value)) => Err(RedisLimitError::Backend(error_value)),
            Err(_) => Err(RedisLimitError::Timeout),
        }
    }

    /// Atomically consume one request from the same Redis fixed window for all
    /// proxy replicas. A key contains only a one-way client fingerprint.
    pub async fn check_rate(
        &self,
        client: ClientId,
        requests_per_window: u32,
        window_seconds: u64,
    ) -> Result<Decision, RedisLimitError> {
        let window_seconds = window_seconds.max(1);
        let now = unix_seconds();
        let window_start = now / window_seconds * window_seconds;
        let retry_after_secs = window_seconds.saturating_sub(now % window_seconds).max(1);
        let key = format!(
            "{}:rate:{}:{}",
            self.key_prefix,
            client.redis_key_fragment(),
            window_start
        );
        let mut connection = self.connection.clone();
        let script = Script::new(RATE_LIMIT_SCRIPT);
        let mut invocation = script.key(key);
        invocation
            .arg(window_seconds.saturating_add(1))
            .arg(requests_per_window.max(1));
        let allowed: i64 = match tokio::time::timeout(
            self.command_timeout,
            invocation.invoke_async(&mut connection),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error_value)) => return Err(RedisLimitError::Backend(error_value)),
            Err(_) => return Err(RedisLimitError::Timeout),
        };
        Ok(if allowed == 1 {
            Decision::Allowed
        } else {
            Decision::Rejected { retry_after_secs }
        })
    }

    /// Atomically reserve money before contacting the upstream provider. The
    /// returned reservation refers to the same window key for later release,
    /// settlement, or exhaustion.
    pub async fn reserve_spend(
        &self,
        client: ClientId,
        price: ModelPrice,
        config: &SpendLimit,
    ) -> Result<Reservation, RedisSpendError> {
        let window_seconds = config.window_seconds.max(1);
        let now = unix_seconds();
        let window_start = now / window_seconds * window_seconds;
        let retry_after_secs = window_seconds.saturating_sub(now % window_seconds).max(1);
        let key = format!(
            "{}:spend:{}:{}",
            self.key_prefix,
            client.redis_key_fragment(),
            window_start
        );
        let mut connection = self.connection.clone();
        let script = Script::new(SPEND_RESERVE_SCRIPT);
        let mut invocation = script.key(&key);
        invocation
            .arg(config.reserve_usd_micros_per_request)
            .arg(config.max_usd_micros)
            .arg(window_seconds.saturating_add(1));
        let reserved: i64 = match tokio::time::timeout(
            self.command_timeout,
            invocation.invoke_async(&mut connection),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error_value)) => {
                return Err(RedisSpendError::Backend(RedisLimitError::Backend(
                    error_value,
                )))
            }
            Err(_) => return Err(RedisSpendError::Backend(RedisLimitError::Timeout)),
        };
        if reserved == 0 {
            return Err(RedisSpendError::BudgetExhausted { retry_after_secs });
        }
        Ok(Reservation::distributed(
            client,
            price,
            config.reserve_usd_micros_per_request,
            config.max_usd_micros,
            key,
        ))
    }

    pub async fn release_spend(&self, reservation: &Reservation) -> Result<(), RedisLimitError> {
        self.update_reservation(SPEND_RELEASE_SCRIPT, reservation, None)
            .await
    }

    pub async fn settle_spend(
        &self,
        reservation: &Reservation,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<u64, RedisLimitError> {
        let charged = reservation.token_cost(input_tokens, output_tokens);
        self.update_reservation(SPEND_SETTLE_SCRIPT, reservation, Some(charged))
            .await?;
        Ok(charged)
    }

    pub async fn exhaust_spend(&self, reservation: &Reservation) -> Result<(), RedisLimitError> {
        self.update_reservation(
            SPEND_EXHAUST_SCRIPT,
            reservation,
            Some(reservation.max_usd_micros()),
        )
        .await
    }

    async fn update_reservation(
        &self,
        script: &str,
        reservation: &Reservation,
        amount: Option<u64>,
    ) -> Result<(), RedisLimitError> {
        let Some(key) = reservation.redis_key() else {
            return Ok(());
        };
        let mut connection = self.connection.clone();
        let script = Script::new(script);
        let mut invocation = script.key(key);
        invocation.arg(reservation.reserved_usd_micros());
        if let Some(amount) = amount {
            invocation.arg(amount);
        }
        let _: i64 = match tokio::time::timeout(
            self.command_timeout,
            invocation.invoke_async(&mut connection),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error_value)) => return Err(RedisLimitError::Backend(error_value)),
            Err(_) => return Err(RedisLimitError::Timeout),
        };
        Ok(())
    }
}

#[derive(Debug)]
pub enum RedisSpendError {
    BudgetExhausted { retry_after_secs: u64 },
    Backend(RedisLimitError),
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::{ModelPrice, RedisLimitsConfig, SpendLimit};
    use crate::rate_limit::{client_id, Decision};

    use super::RedisLimits;

    #[test]
    fn client_fingerprints_are_safe_and_do_not_contain_bearer_tokens() {
        let fragment = client_id(Some("Bearer secret-value")).redis_key_fragment();
        assert_eq!(fragment.len(), 64);
        assert!(fragment.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!fragment.contains("secret"));
    }

    /// Exercises the real Lua scripts without assuming Redis is installed for
    /// ordinary contributor or CI test runs. Set LLM_FW_TEST_REDIS_URL to a
    /// disposable Redis database, then run this ignored test explicitly.
    #[tokio::test]
    #[ignore = "requires LLM_FW_TEST_REDIS_URL pointing at a disposable Redis instance"]
    async fn redis_shares_rate_and_spend_windows() {
        let redis_url = std::env::var("LLM_FW_TEST_REDIS_URL")
            .expect("set LLM_FW_TEST_REDIS_URL before running this ignored test");
        let unique_prefix = format!(
            "llm-firewall-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let backend = RedisLimits::connect(
            &redis_url,
            &RedisLimitsConfig {
                enabled: true,
                key_prefix: unique_prefix,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let client = client_id(Some("Bearer test-token"));
        assert_eq!(
            backend.check_rate(client, 1, 60).await.unwrap(),
            Decision::Allowed
        );
        assert!(matches!(
            backend.check_rate(client, 1, 60).await.unwrap(),
            Decision::Rejected { .. }
        ));

        let budget = SpendLimit {
            enabled: true,
            window_seconds: 60,
            max_usd_micros: 4,
            reserve_usd_micros_per_request: 2,
            max_tracked_clients: 1,
            model_prices: BTreeMap::from([(
                "gpt-test".into(),
                ModelPrice {
                    input_usd_micros_per_million: 1_000_000,
                    output_usd_micros_per_million: 1_000_000,
                },
            )]),
        };
        let price = *budget.model_prices.get("gpt-test").unwrap();
        let first = backend.reserve_spend(client, price, &budget).await.unwrap();
        backend.release_spend(&first).await.unwrap();
        let second = backend.reserve_spend(client, price, &budget).await.unwrap();
        assert_eq!(backend.settle_spend(&second, 1, 1).await.unwrap(), 2);
        let third = backend.reserve_spend(client, price, &budget).await.unwrap();
        assert!(matches!(
            backend.reserve_spend(client, price, &budget).await,
            Err(super::RedisSpendError::BudgetExhausted { .. })
        ));
        backend.release_spend(&third).await.unwrap();
    }
}
