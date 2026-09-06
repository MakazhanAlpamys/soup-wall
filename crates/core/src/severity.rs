// SPDX-License-Identifier: Apache-2.0

//! Severity levels and their scoring weights.

use serde::{Deserialize, Serialize};

/// Ordered severity of a detector finding. `Ord` derives from declaration order,
/// so `Severity::Critical > Severity::Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Base weight in `[0.0, 1.0]` used by the risk scorer. Critical is deliberately
    /// < 1.0 so a single finding never fully saturates the score.
    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.10,
            Severity::Low => 0.30,
            Severity::Medium => 0.60,
            Severity::High => 0.85,
            Severity::Critical => 0.98,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn weights_are_monotonic_and_bounded() {
        assert!(Severity::Info.weight() < Severity::Low.weight());
        assert!(Severity::High.weight() < Severity::Critical.weight());
        assert!(Severity::Critical.weight() < 1.0);
        assert!(Severity::Info.weight() > 0.0);
    }
}
