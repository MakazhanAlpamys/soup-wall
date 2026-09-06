// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Summarize a recorded audit log. The question this answers is the one that
//! decides whether enforcement is safe to switch on: how often WOULD it have
//! interrupted you, and on what?
//!
//! This module does **not** re-run events through a policy engine — it summarizes
//! verdicts that were already computed and recorded by the daemon. Genuine
//! re-evaluation against a *modified* policy needs the events themselves, not just
//! their verdicts, and is out of scope here.

use std::collections::{BTreeMap, BTreeSet};

/// Minimum evidence before a promotion recommendation means anything.
///
/// These are deliberate engineering judgement, not a statistical result, and are
/// named constants so a reader can disagree with a specific number rather than
/// with a hidden one. They exist because the failure mode of a shadow soak is not
/// a wrong threshold — it is a confident recommendation drawn from an afternoon
/// of traffic, disproved in production on day one.
pub const MIN_EVENTS_FOR_PROMOTION: usize = 500;
pub const MIN_SESSIONS_FOR_PROMOTION: usize = 20;

/// Whether the recorded evidence supports turning enforcement on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionVerdict {
    /// Too little traffic for any recommendation to be meaningful.
    NotEnoughEvidence,
    /// Enough traffic, and enforcement would have interrupted work. Every
    /// interrupting rule needs a human decision before promotion: this tool
    /// cannot tell a caught attack from a false positive.
    ReviewRequired,
    /// Enough traffic, and nothing would have been interrupted.
    Ready,
}

/// What a recorded run would have done.
#[derive(Debug, Default)]
pub struct Summary {
    pub total: usize,
    pub malformed: usize,
    pub sessions: usize,
    pub allow: usize,
    pub ask: usize,
    pub deny: usize,
    pub by_rule: BTreeMap<String, usize>,
    pub by_tool: BTreeMap<String, usize>,
    pub p50_us: u128,
    pub p99_us: u128,
    /// Bounds of the observed window, from the recorded event timestamps.
    pub first_at_ms: Option<u64>,
    pub last_at_ms: Option<u64>,
}

impl Summary {
    /// Fraction of events that would have interrupted the operator. This is the
    /// number that decides whether enforcement is usable at all — a tool that
    /// interrupts constantly gets switched off before it proves anything.
    pub fn interruption_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.ask + self.deny) as f64 / self.total as f64
    }

    /// Fraction of events that would have been refused outright.
    ///
    /// Reported separately from `interruption_rate` because `deny` changes what
    /// the agent can do, while `ask` only costs a human a decision. Promoting on
    /// a blended number hides which of the two the operator is accepting.
    pub fn denial_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.deny as f64 / self.total as f64
    }

    /// Hours between the first and last recorded event, when timestamps allow it.
    pub fn observed_span_hours(&self) -> Option<f64> {
        let (first, last) = (self.first_at_ms?, self.last_at_ms?);
        Some(last.saturating_sub(first) as f64 / 3_600_000.0)
    }

    /// Whether this log justifies turning enforcement on.
    ///
    /// Conservative in one direction only: it never recommends promotion from
    /// thin evidence, and it never claims an interruption was a false positive.
    /// Telling a caught attack from a false alarm requires knowing what the
    /// operator intended, which is not in the log and must not be guessed by a
    /// tool whose recommendation gates a security control.
    pub fn promotion_verdict(&self) -> PromotionVerdict {
        if self.total < MIN_EVENTS_FOR_PROMOTION || self.sessions < MIN_SESSIONS_FOR_PROMOTION {
            return PromotionVerdict::NotEnoughEvidence;
        }
        if self.ask + self.deny > 0 {
            return PromotionVerdict::ReviewRequired;
        }
        PromotionVerdict::Ready
    }

    /// The promotion section of the report: what the evidence supports, and the
    /// exact next action.
    pub fn render_promotion(&self) -> String {
        let ask_rate = if self.total == 0 {
            0.0
        } else {
            self.ask as f64 / self.total as f64 * 100.0
        };
        let mut out = String::from("\nenforcement promotion\n");
        if let Some(hours) = self.observed_span_hours() {
            out.push_str(&format!("  observed over: {hours:.1} h\n"));
        }
        out.push_str(&format!(
            "  evidence: {} events / {} sessions (need {} / {})\n",
            self.total, self.sessions, MIN_EVENTS_FOR_PROMOTION, MIN_SESSIONS_FOR_PROMOTION
        ));
        out.push_str(&format!(
            "  would have refused: {:.1}%   would have asked: {ask_rate:.1}%\n",
            self.denial_rate() * 100.0
        ));
        out.push_str(match self.promotion_verdict() {
            PromotionVerdict::NotEnoughEvidence => {
                "  VERDICT: not enough evidence. Keep running in shadow mode.\n\
                 \x20   A recommendation from this little traffic would be a guess.\n"
            }
            PromotionVerdict::ReviewRequired => {
                "  VERDICT: review required before enforcing.\n\
                 \x20   Enforcement would have interrupted real work. This tool cannot tell a\n\
                 \x20   caught attack from a false positive - only you know what you intended.\n\
                 \x20   Read the rules above and decide, per rule, whether each interruption was\n\
                 \x20   correct. If any was wrong, narrow that rule before enforcing, not after.\n"
            }
            PromotionVerdict::Ready => {
                "  VERDICT: evidence supports enforcing.\n\
                 \x20   Nothing in this window would have been interrupted. Set `enforce: true`\n\
                 \x20   in ~/.agentfw/config.yaml, restart, then confirm with\n\
                 \x20   `agentfw preflight --require-enforce`.\n"
            }
        });
        out
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "events: {}  sessions: {}  malformed: {}\n\
             allow: {}  ask: {}  deny: {}\n\
             would have interrupted: {:.1}% of events\n\
             latency p50: {} us   p99: {} us\n",
            self.total,
            self.sessions,
            self.malformed,
            self.allow,
            self.ask,
            self.deny,
            self.interruption_rate() * 100.0,
            self.p50_us,
            self.p99_us
        );
        if !self.by_rule.is_empty() {
            s.push_str("\nrules fired:\n");
            let mut rules: Vec<_> = self.by_rule.iter().collect();
            rules.sort_by(|a, b| b.1.cmp(a.1));
            for (rule, n) in rules {
                s.push_str(&format!("  {n:>6}  {rule}\n"));
            }
        }
        s.push_str(&self.render_promotion());
        s
    }
}

/// Summarize an audit log. Malformed lines are counted, never fatal — a log is a
/// forensic record and a single bad line must not discard the rest.
pub fn summarize(log: &str) -> Summary {
    let mut out = Summary::default();
    let mut sessions: BTreeSet<String> = BTreeSet::new();
    let mut latencies: Vec<u128> = Vec::new();

    for line in log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            out.malformed += 1;
            continue;
        };
        out.total += 1;
        if let Some(s) = v["session"].as_str() {
            sessions.insert(s.to_string());
        }
        match v["verdict"].as_str().unwrap_or("") {
            "allow" => out.allow += 1,
            "ask" => out.ask += 1,
            "deny" => out.deny += 1,
            _ => {}
        }
        if let Some(r) = v["rule"].as_str() {
            *out.by_rule.entry(r.to_string()).or_insert(0) += 1;
        }
        if let Some(t) = v["tool"].as_str() {
            *out.by_tool.entry(t.to_string()).or_insert(0) += 1;
        }
        if let Some(l) = v["latency_us"].as_u64() {
            latencies.push(l as u128);
        }
        if let Some(at) = v["at_ms"].as_u64() {
            out.first_at_ms = Some(out.first_at_ms.map_or(at, |first| first.min(at)));
            out.last_at_ms = Some(out.last_at_ms.map_or(at, |last| last.max(at)));
        }
    }

    out.sessions = sessions.len();
    if !latencies.is_empty() {
        latencies.sort_unstable();
        out.p50_us = latencies[latencies.len() / 2];
        out.p99_us = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = r#"{"at_ms":1,"session":"a","seq":1,"event":"pre_tool_use","tool":"Read","verdict":"allow","shadow":true,"risk_score":0,"findings":[],"egress_hosts":[],"latency_us":10,"truncated":false}
{"at_ms":2,"session":"a","seq":2,"event":"pre_tool_use","tool":"Bash","verdict":"ask","shadow":true,"rule":"ask-unknown-host","risk_score":40,"findings":[],"egress_hosts":["evil.com"],"latency_us":20,"truncated":false}
{"at_ms":3,"session":"a","seq":3,"event":"pre_tool_use","tool":"Bash","verdict":"deny","shadow":true,"rule":"deny-secret-egress","risk_score":93,"findings":[],"egress_hosts":[],"latency_us":30,"truncated":false}
{"at_ms":4,"session":"b","seq":1,"event":"pre_tool_use","tool":"Read","verdict":"allow","shadow":true,"risk_score":0,"findings":[],"egress_hosts":[],"latency_us":15,"truncated":false}
"#;

    #[test]
    fn counts_verdicts_and_sessions() {
        let s = summarize(LOG);
        assert_eq!(s.total, 4);
        assert_eq!(s.sessions, 2);
        assert_eq!(s.allow, 2);
        assert_eq!(s.ask, 1);
        assert_eq!(s.deny, 1);
    }

    #[test]
    fn reports_the_interruption_rate() {
        // The number that decides whether enforcement is usable.
        let s = summarize(LOG);
        assert!(
            (s.interruption_rate() - 0.5).abs() < 1e-9,
            "got {}",
            s.interruption_rate()
        );
    }

    #[test]
    fn ranks_rules_by_how_often_they_fired() {
        let s = summarize(LOG);
        assert_eq!(s.by_rule.get("ask-unknown-host"), Some(&1));
        assert_eq!(s.by_rule.get("deny-secret-egress"), Some(&1));
    }

    /// Build a log large enough to clear the evidence bar, so the promotion
    /// tests exercise the verdict rather than the sample-size gate.
    fn wide_log(sessions: usize, per_session: usize, verdict: &str) -> String {
        let mut log = String::new();
        for s in 0..sessions {
            for i in 0..per_session {
                log.push_str(&format!(
                    "{{\"at_ms\":{},\"session\":\"s{s}\",\"seq\":{i},\"tool\":\"Read\",\
                     \"verdict\":\"{verdict}\",\"latency_us\":10}}\n",
                    1_000 + (s * per_session + i) as u64
                ));
            }
        }
        log
    }

    /// The case this exists for: a short soak must never produce a promotion
    /// recommendation, however clean it looks. Four quiet events are not evidence.
    #[test]
    fn a_thin_log_never_recommends_enforcing_however_clean_it_looks() {
        let s = summarize(&wide_log(2, 5, "allow"));
        assert_eq!(s.allow, 10, "all quiet");
        assert_eq!(s.ask + s.deny, 0, "nothing would have been interrupted");
        assert_eq!(
            s.promotion_verdict(),
            PromotionVerdict::NotEnoughEvidence,
            "a clean but tiny sample must not read as ready"
        );
        assert!(s.render_promotion().contains("not enough evidence"));
    }

    #[test]
    fn enough_quiet_traffic_supports_enforcing() {
        let s = summarize(&wide_log(MIN_SESSIONS_FOR_PROMOTION, 30, "allow"));
        assert!(s.total >= MIN_EVENTS_FOR_PROMOTION);
        assert_eq!(s.promotion_verdict(), PromotionVerdict::Ready);
        assert!(s.render_promotion().contains("supports enforcing"));
        assert!(
            s.render_promotion().contains("preflight --require-enforce"),
            "the report must name the command that confirms the change took effect"
        );
    }

    /// A single interruption in an otherwise large, clean window still demands a
    /// human decision: the tool cannot know whether it was a real attack.
    #[test]
    fn one_interruption_in_a_large_window_demands_review_not_promotion() {
        let mut log = wide_log(MIN_SESSIONS_FOR_PROMOTION, 30, "allow");
        log.push_str(
            "{\"at_ms\":99999,\"session\":\"s0\",\"seq\":999,\"tool\":\"Bash\",\
             \"verdict\":\"deny\",\"rule\":\"deny-secret-egress\",\"latency_us\":10}\n",
        );
        let s = summarize(&log);
        assert_eq!(s.deny, 1);
        assert_eq!(s.promotion_verdict(), PromotionVerdict::ReviewRequired);
        let report = s.render_promotion();
        assert!(report.contains("review required"));
        assert!(
            report.contains("cannot tell a"),
            "the report must not claim the interruption was a false positive: {report}"
        );
    }

    /// `deny` and `ask` cost the operator different things and must not be
    /// blended into one number a promotion decision rests on.
    #[test]
    fn denial_rate_is_reported_separately_from_asks() {
        let s = summarize(LOG);
        assert!((s.interruption_rate() - 0.5).abs() < 1e-9);
        assert!(
            (s.denial_rate() - 0.25).abs() < 1e-9,
            "one deny in four events, got {}",
            s.denial_rate()
        );
    }

    #[test]
    fn the_observed_window_comes_from_recorded_timestamps() {
        let s = summarize(LOG);
        assert_eq!(s.first_at_ms, Some(1));
        assert_eq!(s.last_at_ms, Some(4));
        let hours = s.observed_span_hours().expect("timestamps present");
        assert!((0.0..0.001).contains(&hours), "3 ms span, got {hours}");
        assert!(
            summarize("{\"verdict\":\"allow\"}\n")
                .observed_span_hours()
                .is_none(),
            "no timestamps means no claimed window"
        );
    }

    #[test]
    fn tolerates_blank_and_malformed_lines() {
        let s = summarize("not json\n\n{\"broken\":\n");
        assert_eq!(s.total, 0);
        assert_eq!(s.malformed, 2);
    }

    #[test]
    fn reports_latency_percentiles() {
        let s = summarize(LOG);
        assert!(s.p50_us > 0);
        assert!(s.p99_us >= s.p50_us);
    }

    #[test]
    fn an_empty_log_has_a_zero_interruption_rate_and_does_not_divide_by_zero() {
        let s = summarize("");
        assert_eq!(s.total, 0);
        assert_eq!(s.interruption_rate(), 0.0);
    }

    #[test]
    fn an_unrecognized_verdict_string_counts_toward_total_but_no_bucket() {
        // A future/typo'd verdict must not panic and must not be silently attributed
        // to one of the three known buckets — but this DOES mean the buckets no
        // longer sum to `total`, which is the honest reflection of an unknown value
        // rather than a false attribution.
        let log = "{\"session\":\"a\",\"seq\":1,\"verdict\":\"quarantine\",\"latency_us\":1}\n";
        let s = summarize(log);
        assert_eq!(s.total, 1);
        assert_eq!(s.allow + s.ask + s.deny, 0);
    }

    /// Hazard 1: prove key-name agreement with `audit.rs` end to end. A test built
    /// only from hand-written JSON literals (like `LOG` above) would keep passing
    /// even if the real emitter in `audit.rs` used different field names — this
    /// round-trips through the actual `AuditLine` type and its real `Serialize`
    /// impl, so a future rename in `audit.rs` breaks this test rather than making
    /// `replay` silently count zeros forever.
    #[test]
    fn round_trips_through_the_real_audit_line_serializer() {
        use crate::audit::AuditLine;

        let a = AuditLine {
            at_ms: 1,
            session: "s1".into(),
            seq: 2,
            event: "tool_call".into(),
            tool: Some("Bash".into()),
            verdict: "ask".into(),
            shadow: true,
            rule: Some("ask-unknown-host".into()),
            risk_score: 40,
            findings: vec![],
            taint: None,
            judge: None,
            approval: None,
            egress_hosts: vec!["evil.com".into()],
            latency_us: 20,
            truncated: false,
            raw: None,
        };
        let b = AuditLine {
            session: "s2".into(),
            verdict: "deny".into(),
            rule: Some("deny-secret-egress".into()),
            tool: Some("Bash".into()),
            latency_us: 90,
            ..a.clone()
        };

        let mut log = serde_json::to_string(&a).unwrap();
        log.push('\n');
        log.push_str(&serde_json::to_string(&b).unwrap());
        log.push('\n');

        let s = summarize(&log);
        assert_eq!(
            s.total, 2,
            "both lines must parse via the real emitter shape"
        );
        assert_eq!(s.malformed, 0);
        assert_eq!(s.sessions, 2);
        assert_eq!(s.ask, 1);
        assert_eq!(s.deny, 1);
        assert_eq!(s.by_rule.get("ask-unknown-host"), Some(&1));
        assert_eq!(s.by_rule.get("deny-secret-egress"), Some(&1));
        assert_eq!(s.by_tool.get("Bash"), Some(&2));
        // Sorted latencies are [20, 90]; index `len/2 == 1` is 90 for both p50 and
        // p99 at this tiny sample size — see the p99-arithmetic hazard notes.
        assert_eq!(s.p50_us, 90);
        assert_eq!(s.p99_us, 90);
    }
}
