// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Verdict -> Claude Code `permissionDecision`, and shadow mode.

use llm_firewall_agent::Verdict;
use serde::Serialize;

/// A verdict resolved against the enforcement setting.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The literal string handed to Claude Code.
    pub permission_decision: &'static str,
    pub reason: Option<String>,
    /// True when enforcement is off and the verdict was computed but not applied.
    pub shadow: bool,
    /// What the policy actually decided, regardless of shadow mode.
    pub would_have_been: Verdict,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
}

/// Resolve a verdict into a hook decision.
///
/// `Allow` maps to **`defer`**, never `allow`. `allow` approves a call into the
/// normal permission flow; `defer` leaves the operator's existing permission rules
/// exactly as they were. This firewall having no objection is not the same as it
/// vouching for the call.
pub fn decide(
    verdict: Verdict,
    rule: Option<&str>,
    message: Option<&str>,
    enforce: bool,
) -> Decision {
    let reason = match (rule, message) {
        (Some(r), Some(m)) => Some(format!("[{r}] {m}")),
        (Some(r), None) => Some(format!("[{r}]")),
        (None, Some(m)) => Some(m.to_string()),
        (None, None) => None,
    };

    if !enforce {
        return Decision {
            permission_decision: "defer",
            reason: None,
            shadow: true,
            would_have_been: verdict,
        };
    }

    let (pd, reason) = match verdict {
        Verdict::Allow => ("defer", None),
        Verdict::Ask => ("ask", reason),
        Verdict::Deny => ("deny", reason),
        // The handler is responsible for resolving `Escalate` (via the judge, or
        // its rule's `fallback`) before this function ever sees it. If it somehow
        // arrives here anyway, the only safe behaviour is no opinion — never widen
        // it into `deny` or narrow it into `allow` on its behalf.
        Verdict::Escalate => ("defer", None),
    };

    Decision {
        permission_decision: pd,
        reason,
        shadow: false,
        would_have_been: verdict,
    }
}

impl Decision {
    pub fn to_hook_output(&self) -> HookOutput {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: self.permission_decision,
                permission_decision_reason: self.reason.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use llm_firewall_agent::Verdict;

    #[test]
    fn allow_maps_to_defer_never_to_allow() {
        // THE correction this phase exists around. `allow` APPROVES a call into the
        // normal permission flow; `defer` leaves the operator's own rules untouched.
        // Mapping Allow -> allow would auto-approve tool calls the operator would
        // otherwise have been prompted about — installing this firewall would then
        // WEAKEN existing protection.
        let d = decide(Verdict::Allow, None, None, true);
        assert_eq!(d.permission_decision, "defer");
        assert_ne!(d.permission_decision, "allow");
    }

    #[test]
    fn ask_and_deny_map_directly_and_carry_a_reason() {
        let ask = decide(
            Verdict::Ask,
            Some("ask-tainted-side-effect"),
            Some("uses fetched content"),
            true,
        );
        assert_eq!(ask.permission_decision, "ask");
        let r = ask.reason.unwrap();
        assert!(r.contains("ask-tainted-side-effect"), "got {r}");
        assert!(r.contains("uses fetched content"), "got {r}");

        let deny = decide(
            Verdict::Deny,
            Some("deny-secret-egress"),
            Some("secret leaving"),
            true,
        );
        assert_eq!(deny.permission_decision, "deny");
        assert!(deny.reason.unwrap().contains("deny-secret-egress"));
    }

    #[test]
    fn shadow_mode_never_enforces_anything() {
        for v in [Verdict::Allow, Verdict::Ask, Verdict::Deny] {
            let d = decide(v, Some("r"), Some("m"), false);
            assert_eq!(
                d.permission_decision, "defer",
                "shadow mode must not enforce {v:?}"
            );
            assert!(d.shadow);
            assert_eq!(d.would_have_been, v);
        }
    }

    #[test]
    fn enforcing_mode_reports_shadow_false() {
        let d = decide(Verdict::Deny, Some("r"), Some("m"), true);
        assert!(!d.shadow);
        assert_eq!(d.would_have_been, Verdict::Deny);
    }

    #[test]
    fn serializes_to_the_documented_hook_output_shape() {
        let d = decide(Verdict::Deny, Some("deny-x"), Some("because"), true);
        let j = serde_json::to_value(d.to_hook_output()).unwrap();
        assert_eq!(j["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(j["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(j["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("deny-x"));
    }

    #[test]
    fn escalate_must_be_resolved_before_reaching_a_decision() {
        // `decide` should never see Escalate — the handler resolves it first. If it
        // ever does, treat it as the safest thing that cannot be wrong: no opinion.
        let d = decide(Verdict::Escalate, Some("r"), Some("m"), true);
        assert_eq!(d.permission_decision, "defer");
    }

    #[test]
    fn a_deferred_decision_omits_the_reason_field() {
        let d = decide(Verdict::Allow, None, None, true);
        let j = serde_json::to_value(d.to_hook_output()).unwrap();
        assert!(j["hookSpecificOutput"]
            .get("permissionDecisionReason")
            .is_none());
    }
}
