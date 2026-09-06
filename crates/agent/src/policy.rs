// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Flat, first-match YAML policy over agent signals. Mirrors `core::policy` in shape
//! so operators only learn one format.

use llm_firewall_core::{Finding, Severity};
use serde::Deserialize;

use crate::action::ActionClass;
use crate::egress::is_allowed;
use crate::event::Provenance;
use crate::facet::Facet;
use crate::taint::TaintMark;

/// What to do about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    /// Pause and put the decision to the human.
    Ask,
    Deny,
    /// The rule is not confident. Ask the optional local judge; if none is
    /// available, apply the rule's declared `fallback`. Never appears in a final
    /// decision handed to a collector — it is always resolved first.
    Escalate,
}

/// Which untrusted source classes a rule cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaintSource {
    Network,
    Mcp,
    Subagent,
}

impl TaintSource {
    fn matches(self, p: &Provenance) -> bool {
        matches!(
            (self, p),
            (TaintSource::Network, Provenance::Network { .. })
                | (TaintSource::Mcp, Provenance::McpServer { .. })
                | (TaintSource::Subagent, Provenance::Subagent { .. })
        )
    }
}

/// Everything the engine derived about one event. All fields optional; a rule matches
/// only if every condition it states holds.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub action_class: Option<ActionClass>,
    pub taint: Option<TaintMark>,
    pub findings: Vec<(Facet, Finding)>,
    pub risk_score: u8,
    pub egress_hosts: Vec<String>,
    pub subagent_escalation: bool,
    /// The call touches a credential-shaped path. Never dangerous alone.
    pub touches_sensitive_path: bool,
    /// The MCP server's tool manifest changed vs. its stored pin (rug-pull).
    pub mcp_manifest_changed: bool,
    /// A tool name in this handshake collides with another server's or a builtin.
    pub mcp_tool_shadow: bool,
}

/// All present sub-conditions are ANDed. Absent fields are ignored.
///
/// `deny_unknown_fields`: a typo'd condition key (`detecter` for `detector`) must be a
/// parse error, not a silently-ignored field. Silently ignoring it would leave `when: {}`
/// in effect, which matches every event of the rule's shape — a fat-fingered narrow rule
/// becomes a catch-all, and if its action is `allow` it disables every rule below it. A
/// security policy failing open on a typo, with no diagnostic, is worse than a hard error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCondition {
    #[serde(default)]
    pub taint: Option<Vec<TaintSource>>,
    /// Exact action class.
    #[serde(default)]
    pub action_class: Option<ActionClass>,
    /// Action class at or above this severity.
    #[serde(default)]
    pub min_action_class: Option<ActionClass>,
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub facet: Option<Facet>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub risk_score_gte: Option<u8>,
    #[serde(default)]
    pub egress_not_allowlisted: Option<bool>,
    #[serde(default)]
    pub subagent_escalation: Option<bool>,
    /// True when the call touches a path that commonly holds credentials. Reported
    /// separately from `action_class` because reading such a file is ordinary — use
    /// it only in combination with taint or egress, never alone.
    #[serde(default)]
    pub touches_sensitive_path: Option<bool>,
    #[serde(default)]
    pub mcp_manifest_changed: Option<bool>,
    #[serde(default)]
    pub mcp_tool_shadow: Option<bool>,
}

/// Wire form of a rule, before validation. Only `AgentRule` is used elsewhere.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentRule {
    name: String,
    when: AgentCondition,
    action: Verdict,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fallback: Option<Verdict>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawAgentRule")]
pub struct AgentRule {
    pub name: String,
    pub when: AgentCondition,
    pub action: Verdict,
    pub message: Option<String>,
    /// Verdict to apply when `action` is `Escalate` and no judge is available.
    /// Required for `Escalate`, forbidden otherwise — enforced at parse time.
    pub fallback: Option<Verdict>,
}

impl TryFrom<RawAgentRule> for AgentRule {
    type Error = String;

    fn try_from(r: RawAgentRule) -> Result<Self, Self::Error> {
        match (r.action, r.fallback) {
            (Verdict::Escalate, None) => {
                return Err(format!(
                    "rule {:?}: action 'escalate' requires a 'fallback' of allow or ask. \
                     The judge is optional and off by default, so the fallback is the \
                     normal path and must be stated explicitly.",
                    r.name
                ))
            }
            (Verdict::Escalate, Some(Verdict::Escalate)) => {
                return Err(format!(
                    "rule {:?}: 'fallback' cannot be 'escalate'",
                    r.name
                ))
            }
            (Verdict::Escalate, Some(Verdict::Deny)) => {
                // Permitted but pointless: a rule confident enough to deny should
                // just deny. Rejected to keep intent unambiguous.
                return Err(format!(
                    "rule {:?}: 'fallback' of 'deny' is not allowed — a rule confident \
                     enough to deny should use 'action: deny' directly",
                    r.name
                ));
            }
            (Verdict::Escalate, Some(Verdict::Allow | Verdict::Ask)) => {}
            (_, Some(_)) => {
                return Err(format!(
                    "rule {:?}: 'fallback' is only valid with 'action: escalate'",
                    r.name
                ))
            }
            _ => {}
        }
        Ok(AgentRule {
            name: r.name,
            when: r.when,
            action: r.action,
            message: r.message,
            fallback: r.fallback,
        })
    }
}

fn default_verdict() -> Verdict {
    Verdict::Allow
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicySet {
    #[serde(default)]
    pub agent_policies: Vec<AgentRule>,
    #[serde(default)]
    pub egress_allowlist: Vec<String>,
    #[serde(default = "default_verdict")]
    pub default: Verdict,
}

/// The outcome for one event.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDecision {
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub message: Option<String>,
    /// Set only when `verdict` is `Escalate`.
    pub fallback: Option<Verdict>,
}

impl AgentPolicySet {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        use serde::de::Error as _;
        let p: AgentPolicySet = serde_yaml::from_str(s)?;
        if p.default == Verdict::Escalate {
            // Produce a real serde error rather than a panic or a silent fix.
            return Err(serde_yaml::Error::custom(
                "policy 'default' cannot be 'escalate': there is no rule to take a fallback from",
            ));
        }
        Ok(p)
    }

    /// First matching rule wins; otherwise the default verdict.
    pub fn evaluate(&self, s: &Signals) -> AgentDecision {
        for rule in &self.agent_policies {
            if self.matches(&rule.when, s) {
                return AgentDecision {
                    verdict: rule.action,
                    rule: Some(rule.name.clone()),
                    message: rule.message.clone(),
                    fallback: rule.fallback,
                };
            }
        }
        AgentDecision {
            verdict: self.default,
            rule: None,
            message: None,
            fallback: None,
        }
    }

    fn matches(&self, c: &AgentCondition, s: &Signals) -> bool {
        if let Some(sources) = &c.taint {
            match &s.taint {
                None => return false,
                Some(mark) => {
                    if !sources.iter().any(|t| t.matches(&mark.source)) {
                        return false;
                    }
                }
            }
        }
        if let Some(exact) = c.action_class {
            if s.action_class != Some(exact) {
                return false;
            }
        }
        if let Some(min) = c.min_action_class {
            match s.action_class {
                Some(a) if a >= min => {}
                _ => return false,
            }
        }
        if let Some(min) = c.risk_score_gte {
            if s.risk_score < min {
                return false;
            }
        }
        if c.detector.is_some() || c.min_severity.is_some() || c.facet.is_some() {
            let any = s.findings.iter().any(|(facet, f)| {
                let facet_ok = c.facet.is_none_or(|want| want == *facet);
                // Segment-bounded prefix, matching core's scheme: "secret" matches
                // "secret" and "secret.aws_key" but not "secretsauce".
                let det_ok = c
                    .detector
                    .as_ref()
                    .is_none_or(|d| f.detector == *d || f.detector.starts_with(&format!("{d}.")));
                let sev_ok = c.min_severity.is_none_or(|m| f.severity >= m);
                facet_ok && det_ok && sev_ok
            });
            if !any {
                return false;
            }
        }
        if c.egress_not_allowlisted == Some(true) {
            let any_unlisted = s
                .egress_hosts
                .iter()
                .any(|h| !is_allowed(h, &self.egress_allowlist));
            if !any_unlisted {
                return false;
            }
        }
        if let Some(want) = c.subagent_escalation {
            if s.subagent_escalation != want {
                return false;
            }
        }
        if let Some(want) = c.touches_sensitive_path {
            if s.touches_sensitive_path != want {
                return false;
            }
        }
        if let Some(want) = c.mcp_manifest_changed {
            if s.mcp_manifest_changed != want {
                return false;
            }
        }
        if let Some(want) = c.mcp_tool_shadow {
            if s.mcp_tool_shadow != want {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionClass;
    use crate::event::Provenance;
    use crate::taint::TaintMark;
    use llm_firewall_core::{Finding, Severity};

    const YAML: &str = r#"
agent_policies:
  - name: deny-tainted-destructive
    when: { taint: [network, mcp], action_class: destructive }
    action: deny
    message: "Blocked: destructive action derived from untrusted content"
  - name: ask-tainted-side-effect
    when: { taint: [network, mcp], min_action_class: side_effecting }
    action: ask
  - name: deny-secret-egress
    when: { detector: secret, facet: tool_args, min_action_class: network }
    action: deny
  - name: ask-unknown-host
    when: { egress_not_allowlisted: true }
    action: ask
  - name: deny-subagent-escalation
    when: { subagent_escalation: true }
    action: deny
egress_allowlist: [github.com, crates.io]
default: allow
"#;

    fn signals() -> Signals {
        Signals::default()
    }

    #[test]
    fn parses_the_shipped_shape() {
        let p = AgentPolicySet::from_yaml(YAML).expect("parse");
        assert_eq!(p.agent_policies.len(), 5);
        assert_eq!(p.default, Verdict::Allow);
        assert_eq!(p.egress_allowlist, vec!["github.com", "crates.io"]);
    }

    #[test]
    fn clean_signals_fall_through_to_the_default() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        assert_eq!(p.evaluate(&signals()).verdict, Verdict::Allow);
    }

    #[test]
    fn tainted_destructive_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::Destructive);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "evil.com".into(),
            },
            seq: 2,
        });
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-tainted-destructive"));
    }

    #[test]
    fn tainted_write_is_asked_not_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::SideEffecting);
        s.taint = Some(TaintMark {
            source: Provenance::McpServer {
                name: "rogue".into(),
            },
            seq: 1,
        });
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
    }

    #[test]
    fn tainted_read_only_is_allowed() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::ReadOnly);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "evil.com".into(),
            },
            seq: 1,
        });
        assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
    }

    #[test]
    fn a_secret_in_a_network_call_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::Network);
        s.findings = vec![(
            crate::facet::Facet::ToolArgs,
            Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
        )];
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
    }

    #[test]
    fn an_unlisted_egress_host_is_asked() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.egress_hosts = vec!["evil.com".into()];
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
    }

    #[test]
    fn an_allowlisted_egress_host_is_not_asked() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.egress_hosts = vec!["api.github.com".into()];
        assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
    }

    #[test]
    fn subagent_escalation_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.subagent_escalation = true;
        assert_eq!(p.evaluate(&s).verdict, Verdict::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        // Matches both deny-tainted-destructive and ask-tainted-side-effect.
        s.action_class = Some(ActionClass::Destructive);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "e.com".into(),
            },
            seq: 1,
        });
        assert_eq!(
            p.evaluate(&s).rule.as_deref(),
            Some("deny-tainted-destructive")
        );
    }

    #[test]
    fn the_shipped_default_policy_parses() {
        let yaml = include_str!("../policies/agent-default.yaml");
        let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
        assert!(!p.agent_policies.is_empty());
    }

    #[test]
    fn a_detected_secret_over_the_network_denies_even_with_a_sensitive_path() {
        // Regression pin: deny-secret-egress must win over ask-sensitive-path-egress
        // when a single event matches both. A network send that both touches a
        // credential-shaped path AND carries a detected Critical secret finding is
        // the strongest signal the system can produce; it must never be downgraded
        // to a prompt by a weaker rule that happens to be evaluated first.
        let yaml = include_str!("../policies/agent-default.yaml");
        let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
        let mut s = signals();
        s.action_class = Some(ActionClass::Network);
        s.touches_sensitive_path = true;
        s.findings = vec![(
            crate::facet::Facet::ToolArgs,
            Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
        )];
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
    }

    #[test]
    fn a_typo_d_condition_key_is_a_parse_error_not_a_silent_catch_all() {
        // Before `deny_unknown_fields`: `detecter` (typo for `detector`) parsed
        // successfully, leaving `when: {}` in effect, which matches every event of
        // the rule's action-class shape. A fat-fingered narrow rule silently became
        // a catch-all. This must now be a hard parse error with no valid policy.
        let bad_yaml = r#"
agent_policies:
  - name: typo-rule
    when: { detecter: secret, min_action_class: network }
    action: deny
default: allow
"#;
        let err = AgentPolicySet::from_yaml(bad_yaml)
            .expect_err("a typo'd condition key must fail to parse, not silently match everything");
        let msg = err.to_string();
        assert!(
            msg.contains("detecter") || msg.contains("unknown field"),
            "expected the error to name the bad field, got: {msg}"
        );
    }

    // --- phase 10: the escalate action ---

    const ESCALATE_YAML: &str = r#"
agent_policies:
  - name: escalate-tainted-side-effect
    when: { taint: [network], min_action_class: side_effecting }
    action: escalate
    fallback: allow
    message: "uses fetched content"
default: allow
"#;

    #[test]
    fn an_escalate_rule_parses_and_carries_its_fallback() {
        let p = AgentPolicySet::from_yaml(ESCALATE_YAML).expect("should parse");
        assert_eq!(p.agent_policies[0].action, Verdict::Escalate);
        assert_eq!(p.agent_policies[0].fallback, Some(Verdict::Allow));
    }

    #[test]
    fn a_fallback_of_deny_is_a_parse_error() {
        // Everything in this project fails OPEN: an unreachable daemon proceeds, a
        // malformed payload proceeds, a poisoned mutex proceeds. `fallback: deny`
        // would be the one path where a MISSING optional dependency produces a hard
        // block — the tool getting more restrictive the less of it you have
        // installed. That inverts the failure posture, so reject it at parse time
        // rather than leave it as a footgun. A rule confident enough to deny should
        // say `action: deny`.
        let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\n    fallback: deny\ndefault: allow\n";
        let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
        assert!(
            err.contains("deny"),
            "the error should explain why deny is not a valid fallback, got: {err}"
        );
    }

    #[test]
    fn an_escalate_rule_without_a_fallback_is_a_parse_error() {
        // The judge is OFF by default, so the fallback path is the NORMAL path.
        // A security tool must not have a hidden default for "the thing I depend
        // on is absent".
        let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\ndefault: allow\n";
        let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
        assert!(
            err.contains("fallback"),
            "error should name the missing field, got: {err}"
        );
    }

    #[test]
    fn a_fallback_on_a_non_escalate_rule_is_a_parse_error() {
        // Silently ignoring it would let an operator believe a deny had a fallback.
        let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: deny\n    fallback: allow\ndefault: allow\n";
        let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("fallback"), "got: {err}");
    }

    #[test]
    fn escalate_is_not_a_valid_fallback() {
        // A fallback that escalates again would loop.
        let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\n    fallback: escalate\ndefault: allow\n";
        assert!(AgentPolicySet::from_yaml(yaml).is_err());
    }

    #[test]
    fn escalate_is_not_a_valid_policy_default() {
        // There is no rule to take a fallback from, so this cannot be resolved.
        let yaml = "agent_policies: []\ndefault: escalate\n";
        assert!(AgentPolicySet::from_yaml(yaml).is_err());
    }

    #[test]
    fn evaluate_returns_the_fallback_alongside_an_escalate_verdict() {
        let p = AgentPolicySet::from_yaml(ESCALATE_YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::SideEffecting);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "e.com".into(),
            },
            seq: 1,
        });
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Escalate);
        assert_eq!(d.fallback, Some(Verdict::Allow));
        assert_eq!(d.rule.as_deref(), Some("escalate-tainted-side-effect"));
    }

    #[test]
    fn a_non_escalate_decision_carries_no_fallback() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.subagent_escalation = true;
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.fallback, None);
    }

    #[test]
    fn the_shipped_default_policy_still_parses_with_escalate_support() {
        let yaml = include_str!("../policies/agent-default.yaml");
        AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
    }

    #[test]
    fn a_manifest_drift_rule_matches_only_when_the_signal_is_set() {
        let yaml = "agent_policies:\n  - name: ask-manifest-drift\n    when: { mcp_manifest_changed: true }\n    action: ask\ndefault: allow\n";
        let p = AgentPolicySet::from_yaml(yaml).unwrap();

        let mut s = Signals::default();
        assert_eq!(
            p.evaluate(&s).verdict,
            Verdict::Allow,
            "no drift -> default"
        );

        s.mcp_manifest_changed = true;
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask, "drift -> ask");
    }

    #[test]
    fn a_tool_shadow_rule_matches_only_when_the_signal_is_set() {
        let yaml = "agent_policies:\n  - name: ask-tool-shadow\n    when: { mcp_tool_shadow: true }\n    action: ask\ndefault: allow\n";
        let p = AgentPolicySet::from_yaml(yaml).unwrap();

        let mut s = Signals::default();
        assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
        s.mcp_tool_shadow = true;
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
    }

    #[test]
    fn a_typo_in_an_mcp_condition_is_still_a_parse_error() {
        // deny_unknown_fields must keep protecting the new keys too.
        let yaml = "agent_policies:\n  - name: r\n    when: { mcp_manifest_changd: true }\n    action: ask\ndefault: allow\n";
        assert!(AgentPolicySet::from_yaml(yaml).is_err());
    }
}
