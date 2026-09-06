// SPDX-License-Identifier: Apache-2.0

//! Flat, first-match YAML policy engine. Policy is data, not code.

use serde::Deserialize;

use crate::{Direction, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Mask,
    Block,
    Flag,
}

/// All present sub-conditions are ANDed. Absent fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Condition {
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub risk_score_gte: Option<u8>,
    #[serde(default)]
    pub direction: Option<Direction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub when: Condition,
    pub action: Action,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_action() -> Action {
    Action::Allow
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicySet {
    #[serde(default)]
    pub policies: Vec<Rule>,
    #[serde(default = "default_action")]
    pub default: Action,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub rule: Option<String>,
    pub message: Option<String>,
}

impl PolicySet {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }

    /// First matching rule wins; otherwise the default action.
    pub fn evaluate(&self, findings: &[Finding], score: u8, direction: Direction) -> Decision {
        for rule in &self.policies {
            if rule.when.matches(findings, score, direction) {
                return Decision {
                    action: rule.action,
                    rule: Some(rule.name.clone()),
                    message: rule.message.clone(),
                };
            }
        }
        Decision {
            action: self.default,
            rule: None,
            message: None,
        }
    }
}

impl Condition {
    /// True when every present sub-condition holds for the given signals.
    pub fn matches(&self, findings: &[Finding], score: u8, direction: Direction) -> bool {
        if let Some(d) = self.direction {
            if d != direction {
                return false;
            }
        }
        if let Some(min) = self.risk_score_gte {
            if score < min {
                return false;
            }
        }
        if self.detector.is_some() || self.min_severity.is_some() {
            let any = findings.iter().any(|f| {
                // Segment-bounded prefix on the `category.subtype` id scheme: "pii"
                // matches "pii" and "pii.email" but NOT "piixyz".
                let det_ok = self.detector.as_ref().is_none_or(|d| {
                    let prefix = d.as_str();
                    f.detector == prefix || f.detector.starts_with(&format!("{prefix}."))
                });
                let sev_ok = self.min_severity.is_none_or(|m| f.severity >= m);
                det_ok && sev_ok
            });
            if !any {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
policies:
  - name: block-critical-injection
    when: { detector: injection, min_severity: high }
    action: block
    message: "Prompt blocked: possible injection"
  - name: mask-pii
    when: { detector: pii }
    action: mask
default: allow
"#;

    #[test]
    fn parses_sample_policy() {
        let p = PolicySet::from_yaml(SAMPLE).expect("parse");
        assert_eq!(p.policies.len(), 2);
        assert_eq!(p.default, Action::Allow);
        assert_eq!(p.policies[0].action, Action::Block);
        assert_eq!(p.policies[0].when.detector.as_deref(), Some("injection"));
        assert_eq!(p.policies[0].when.min_severity, Some(Severity::High));
        assert_eq!(p.policies[1].action, Action::Mask);
    }

    fn f(det: &str, sev: Severity) -> Finding {
        Finding::new(det, sev, 0.9, "x")
    }

    #[test]
    fn detector_prefix_matches_subtype() {
        let c = Condition {
            detector: Some("pii".into()),
            ..Default::default()
        };
        assert!(c.matches(&[f("pii.email", Severity::Medium)], 0, Direction::Input));
        assert!(!c.matches(&[f("secret.jwt", Severity::Medium)], 0, Direction::Input));
    }

    #[test]
    fn min_severity_gate() {
        let c = Condition {
            detector: Some("injection".into()),
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        assert!(c.matches(&[f("injection", Severity::High)], 0, Direction::Input));
        assert!(!c.matches(&[f("injection", Severity::Low)], 0, Direction::Input));
    }

    #[test]
    fn score_and_direction_gates() {
        let c = Condition {
            risk_score_gte: Some(80),
            direction: Some(Direction::Output),
            ..Default::default()
        };
        assert!(c.matches(&[], 90, Direction::Output));
        assert!(!c.matches(&[], 90, Direction::Input));
        assert!(!c.matches(&[], 50, Direction::Output));
    }

    #[test]
    fn severity_only_condition_matches_any_detector() {
        let c = Condition {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        assert!(c.matches(&[f("anything", Severity::Critical)], 0, Direction::Input));
        assert!(!c.matches(&[f("anything", Severity::Low)], 0, Direction::Input));
    }

    #[test]
    fn empty_condition_matches_everything() {
        // No sub-conditions set -> the default-catch rule matches any input.
        let c = Condition::default();
        assert!(c.matches(&[], 0, Direction::Input));
        assert!(c.matches(
            &[f("secret.aws_key", Severity::Critical)],
            99,
            Direction::Output
        ));
    }

    #[test]
    fn prefix_is_segment_bounded() {
        let c = Condition {
            detector: Some("pii".into()),
            ..Default::default()
        };
        assert!(c.matches(&[f("pii", Severity::Low)], 0, Direction::Input));
        assert!(c.matches(&[f("pii.email", Severity::Low)], 0, Direction::Input));
        assert!(!c.matches(&[f("piixyz", Severity::Low)], 0, Direction::Input));
    }

    #[test]
    fn first_match_wins() {
        let p = PolicySet::from_yaml(SAMPLE).unwrap();
        let d = p.evaluate(&[f("injection", Severity::High)], 90, Direction::Input);
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.rule.as_deref(), Some("block-critical-injection"));
    }

    #[test]
    fn falls_through_to_default() {
        let p = PolicySet::from_yaml(SAMPLE).unwrap();
        let d = p.evaluate(&[], 0, Direction::Input);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.rule, None);
    }

    #[test]
    fn pii_masks() {
        let p = PolicySet::from_yaml(SAMPLE).unwrap();
        let d = p.evaluate(&[f("pii.email", Severity::Medium)], 40, Direction::Input);
        assert_eq!(d.action, Action::Mask);
    }

    #[test]
    fn first_match_wins_under_contention() {
        // BOTH rules match a high-risk finding; the earlier rule must win,
        // and its message must propagate.
        let p = PolicySet::from_yaml(
            r#"
policies:
  - name: high-risk-block
    when: { risk_score_gte: 80 }
    action: block
    message: "high risk"
  - name: catch-all-flag
    when: {}
    action: flag
default: allow
"#,
        )
        .unwrap();
        let d = p.evaluate(&[f("injection", Severity::High)], 90, Direction::Input);
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.rule.as_deref(), Some("high-risk-block"));
        assert_eq!(d.message.as_deref(), Some("high risk"));
    }
}
