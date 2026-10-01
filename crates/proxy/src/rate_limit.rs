// SPDX-License-Identifier: Apache-2.0

//! Bounded in-memory fixed-window request limiting for proxy callers.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::config::RateLimit;

/// A one-way identifier used as a map key. The original bearer token is never
/// retained by the limiter or written to logs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClientId([u8; 32]);

impl ClientId {
    /// Encode the already one-way identifier for a Redis key. The original
    /// bearer token is not recoverable from this value.
    pub(crate) fn redis_key_fragment(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

pub fn client_id(presented_token: Option<&str>) -> ClientId {
    let mut digest = Sha256::new();
    digest.update(b"llm-firewall-rate-limit-v1\0");
    match presented_token {
        Some(token) => {
            digest.update(b"token\0");
            digest.update(token.as_bytes());
        }
        None => digest.update(b"anonymous\0"),
    }
    ClientId(digest.finalize().into())
}

/// A tenant-wide limiter key. Every active token issued to the same tenant
/// shares this key, so extra tokens cannot bypass a tenant policy.
pub fn tenant_client_id(tenant_id: &str) -> ClientId {
    let mut digest = Sha256::new();
    digest.update(b"llm-firewall-tenant-rate-limit-v1\0tenant\0");
    digest.update(tenant_id.as_bytes());
    ClientId(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Rejected { retry_after_secs: u64 },
}

#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    requests: u32,
}

/// A process-local rate limiter. The map is capped even if callers mint an
/// unbounded number of distinct tokens. This is deliberately not a durable
/// billing system; restarts reset the windows.
pub struct RateLimiter {
    config: RateLimit,
    clients: HashMap<ClientId, Window>,
}

impl RateLimiter {
    pub fn new(config: RateLimit) -> Self {
        Self {
            config,
            clients: HashMap::new(),
        }
    }

    pub fn check(&mut self, client: ClientId, now: Instant) -> Decision {
        let config = self.config.clone();
        self.check_with(client, &config, now)
    }

    /// Check an operator-supplied per-tenant policy while reusing the same
    /// bounded in-memory map as global limits.
    pub fn check_with(&mut self, client: ClientId, config: &RateLimit, now: Instant) -> Decision {
        if !config.enabled {
            return Decision::Allowed;
        }

        let window = Duration::from_secs(config.window_seconds.max(1));
        let request_limit = config.requests_per_window.max(1);

        if let Some(entry) = self.clients.get_mut(&client) {
            let elapsed = now.duration_since(entry.started);
            if elapsed >= window {
                *entry = Window {
                    started: now,
                    requests: 1,
                };
                return Decision::Allowed;
            }
            if entry.requests >= request_limit {
                return Decision::Rejected {
                    retry_after_secs: seconds_ceil(window - elapsed),
                };
            }
            entry.requests += 1;
            return Decision::Allowed;
        }

        let max_clients = config.max_tracked_clients.max(1);
        if self.clients.len() >= max_clients {
            self.clients
                .retain(|_, entry| now.duration_since(entry.started) < window);
            if self.clients.len() >= max_clients {
                return Decision::Rejected {
                    retry_after_secs: config.window_seconds.max(1),
                };
            }
        }
        self.clients.insert(
            client,
            Window {
                started: now,
                requests: 1,
            },
        );
        Decision::Allowed
    }
}

fn seconds_ceil(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
        .max(1)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{client_id, tenant_client_id, Decision, RateLimiter};
    use crate::config::RateLimit;

    fn enabled_limit(requests_per_window: u32) -> RateLimiter {
        RateLimiter::new(RateLimit {
            enabled: true,
            requests_per_window,
            window_seconds: 60,
            max_tracked_clients: 2,
        })
    }

    #[test]
    fn rejects_after_the_configured_requests_and_resets_at_window_end() {
        let mut limiter = enabled_limit(2);
        let now = Instant::now();
        let client = client_id(Some("Bearer a"));
        assert_eq!(limiter.check(client, now), Decision::Allowed);
        assert_eq!(limiter.check(client, now), Decision::Allowed);
        assert_eq!(
            limiter.check(client, now + Duration::from_secs(1)),
            Decision::Rejected {
                retry_after_secs: 59
            }
        );
        assert_eq!(
            limiter.check(client, now + Duration::from_secs(60)),
            Decision::Allowed
        );
    }

    #[test]
    fn caps_distinct_client_entries() {
        let mut limiter = enabled_limit(10);
        let now = Instant::now();
        assert_eq!(
            limiter.check(client_id(Some("Bearer a")), now),
            Decision::Allowed
        );
        assert_eq!(
            limiter.check(client_id(Some("Bearer b")), now),
            Decision::Allowed
        );
        assert_eq!(
            limiter.check(client_id(Some("Bearer c")), now),
            Decision::Rejected {
                retry_after_secs: 60
            }
        );
    }

    #[test]
    fn fingerprints_keep_raw_tokens_out_of_the_map_key() {
        assert_ne!(client_id(Some("Bearer a")), client_id(Some("Bearer b")));
        assert_ne!(client_id(None), client_id(Some("anonymous")));
        assert_eq!(tenant_client_id("tenant-a"), tenant_client_id("tenant-a"));
        assert_ne!(tenant_client_id("tenant-a"), tenant_client_id("tenant-b"));
    }

    #[test]
    fn a_dynamic_tenant_policy_is_shared_between_its_tokens() {
        let mut limiter = RateLimiter::new(RateLimit::default());
        let policy = RateLimit {
            enabled: true,
            requests_per_window: 1,
            window_seconds: 60,
            max_tracked_clients: 10,
        };
        let now = Instant::now();
        let tenant = tenant_client_id("tenant-a");
        assert_eq!(limiter.check_with(tenant, &policy, now), Decision::Allowed);
        assert!(matches!(
            limiter.check_with(tenant, &policy, now),
            Decision::Rejected { .. }
        ));
    }
}
