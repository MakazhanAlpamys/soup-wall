// SPDX-License-Identifier: Apache-2.0

//! Aggregate findings into a 0–100 risk score using noisy-OR (diminishing returns):
//! `combined = 1 - Π(1 - severity_weight * confidence)`. Bounded, monotonic, and a
//! single Critical always outranks a pile of Lows without any one finding saturating.

use serde::{Deserialize, Serialize};

use crate::Finding;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// 0–100 integer risk score.
    pub score: u8,
    /// Labels of the top contributing findings, highest contribution first.
    pub reasons: Vec<String>,
}

/// Per-finding contribution in `[0.0, 1.0)`. Non-finite confidence (possible only via
/// direct struct construction, bypassing `Finding::new`'s clamp) contributes 0 rather
/// than poisoning the whole product to NaN → a silently-zero score.
fn contribution(f: &Finding) -> f32 {
    let c = f.severity.weight() * f.confidence;
    if !c.is_finite() {
        return 0.0;
    }
    c.clamp(0.0, 1.0)
}

/// Aggregate findings into a `RiskScore`. Empty input -> score 0.
pub fn score_findings(findings: &[Finding]) -> RiskScore {
    let mut product = 1.0f32;
    for f in findings {
        product *= 1.0 - contribution(f);
    }
    let combined = 1.0 - product;
    let score = (combined * 100.0).round().clamp(0.0, 100.0) as u8;

    // Reasons: findings sorted by contribution desc, top 3 labels.
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        contribution(b)
            .partial_cmp(&contribution(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let reasons = ranked.iter().take(3).map(|f| f.label.clone()).collect();

    RiskScore { score, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn f(sev: Severity, conf: f32, label: &str) -> Finding {
        Finding::new("test", sev, conf, label)
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(score_findings(&[]).score, 0);
    }

    #[test]
    fn single_critical_is_98() {
        // weight 0.98 * conf 1.0 -> combined 0.98 -> 98
        assert_eq!(score_findings(&[f(Severity::Critical, 1.0, "x")]).score, 98);
    }

    #[test]
    fn single_high_is_85() {
        assert_eq!(score_findings(&[f(Severity::High, 1.0, "x")]).score, 85);
    }

    #[test]
    fn two_lows_diminish() {
        // 1 - (0.7)^2 = 0.51 -> 51
        assert_eq!(
            score_findings(&[f(Severity::Low, 1.0, "a"), f(Severity::Low, 1.0, "b")]).score,
            51
        );
    }

    #[test]
    fn critical_outranks_many_lows() {
        let lows: Vec<Finding> = (0..10).map(|_| f(Severity::Low, 1.0, "low")).collect();
        let one_crit = vec![f(Severity::Critical, 1.0, "crit")];
        assert!(score_findings(&one_crit).score >= score_findings(&lows).score);
    }

    #[test]
    fn non_finite_confidence_does_not_collapse_score() {
        // A malformed finding (NaN confidence via direct struct construction) must not
        // poison the aggregate to a silently-zero score.
        let good = f(Severity::High, 1.0, "good"); // contributes 0.85 -> 85
        let bad = Finding {
            detector: "test".into(),
            severity: Severity::Critical,
            confidence: f32::NAN,
            span: None,
            label: "bad".into(),
            direction: crate::Direction::Input,
            owasp: None,
            atlas: None,
        };
        assert_eq!(score_findings(&[good, bad]).score, 85);
    }

    #[test]
    fn reasons_are_ranked_top_first() {
        let findings = vec![
            f(Severity::Low, 1.0, "low"),
            f(Severity::Critical, 1.0, "crit"),
            f(Severity::Medium, 1.0, "med"),
        ];
        let rs = score_findings(&findings);
        assert_eq!(rs.reasons.first().map(String::as_str), Some("crit"));
        assert_eq!(rs.reasons.len(), 3);
    }
}
