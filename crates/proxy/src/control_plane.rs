// SPDX-License-Identifier: Apache-2.0

//! What the data plane needs from a control plane, defined on the data plane's
//! side of the boundary.
//!
//! These types are plain data: request-scoped audit identity and readiness
//! counters. They were previously defined next to the store that consumes them,
//! which meant the data plane had to name control-plane modules in order to
//! report its own readiness or describe its own request. That is backwards —
//! the producer should own the shape of what it produces — and it is one of the
//! edges that stops Core from building without the control plane present.
//!
//! Nothing here knows about tenants as a storage concept, credentials, or any
//! particular backend. A deployment with no control plane at all still builds,
//! constructs these values, and reports readiness truthfully.
//!
//! See [`docs/product/CORE_EXTRACTION_MAP.md`] for the full boundary inventory.

/// Header carrying the caller's proxy credential.
///
/// The wire name belongs to the data plane, which reads it on every request,
/// not to whichever component happens to verify the value.
pub const PROXY_AUTH_HEADER: &str = "x-llm-firewall-token";

/// Request-scoped context used by a streaming producer to record the actual
/// terminal outcome after the HTTP response headers have already been sent.
///
/// Fields are `pub(crate)` rather than public: the control plane constructs and
/// reads them, but nothing outside this crate should depend on their shape
/// while the boundary is still moving.
#[derive(Clone)]
pub struct TenantAuditContext {
    pub(crate) tenant_id: String,
    pub(crate) path: String,
    pub(crate) started: std::time::Instant,
}

/// Marker on a response whose stream producer owns the final tenant audit.
#[derive(Clone)]
pub(crate) struct DeferredTenantAudit;

/// Readiness counters for asynchronous audit delivery. `enabled: false` is the
/// honest answer when no control plane is configured, not a failure.
///
/// `Serialize` is kept from the original definition: `/readyz` renders these
/// directly, and dropping it would silently change that response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TenantAuditQueueStatus {
    pub enabled: bool,
    pub dropped_events: u64,
    pub failed_events: u64,
}

/// Process-local visibility for durable usage events that could not be
/// persisted. The counter is monotonic: a missing billable event must stay
/// visible until an operator reconciles it and restarts the replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct UsageLedgerStatus {
    pub failed_events: u64,
}

impl TenantAuditQueueStatus {
    /// The posture of a deployment running without a control plane: nothing is
    /// queued, so nothing can be dropped or failed.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            dropped_events: 0,
            failed_events: 0,
        }
    }
}

impl UsageLedgerStatus {
    pub fn empty() -> Self {
        Self { failed_events: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Readiness must be reportable with no control plane present at all —
    /// that is the whole point of these living on this side of the boundary.
    #[test]
    fn a_deployment_without_a_control_plane_reports_a_truthful_posture() {
        let queue = TenantAuditQueueStatus::disabled();
        assert!(!queue.enabled);
        assert_eq!(queue.dropped_events, 0);
        assert_eq!(queue.failed_events, 0);
        assert_eq!(UsageLedgerStatus::empty().failed_events, 0);
    }
}
