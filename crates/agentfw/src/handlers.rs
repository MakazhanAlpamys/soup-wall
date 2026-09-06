// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! HTTP surface: `POST /hook` for every hook event, `GET /health` for liveness.
//! No detection logic lives here — verdicts come from `soup-wall-agent`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use soup_wall_agent::{AgentFirewall, EventKind, Trust, Verdict};

use crate::audit::{AuditFinding, AuditLine, AuditSink, AuditTaint};
use crate::config::Config;
use crate::decision;
use crate::hook::{HookEvent, HookPayload};
use crate::judge::{Judge, Judgement};
use crate::map;
use crate::spans::SpanCache;

/// Turn a judgement plus the rule's declared fallback into a final verdict.
///
/// `Injection` always lands on `Ask` — the judge may only *tighten*, never soften.
/// Everything else (ordinary documentation, or any judge failure) takes the fallback
/// the rule declared. A missing fallback resolves to `Allow`, never a block: this
/// firewall never invents a denial from an absent optional dependency. Pure, so the
/// policy is testable without a server.
pub fn resolve_escalation(j: Judgement, fallback: Option<Verdict>) -> Verdict {
    match j {
        Judgement::Injection => Verdict::Ask,
        Judgement::Documentation | Judgement::Unavailable(_) => fallback.unwrap_or(Verdict::Allow),
    }
}

/// Stable audit-log string for a verdict. Deliberately explicit rather than
/// `Debug`-derived, for the same reason as `HookEvent::as_str`: the audit log is a
/// forensic record and must not change shape when a variant is renamed.
/// `replay::summarize` matches on these exact strings.
fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
        // Not expected to reach the audit log: the handler resolves `Escalate`
        // into a real verdict before `decision::decide` (and this) ever see it.
        // Named explicitly here rather than a catch-all so a future variant added
        // to `Verdict` fails to compile here too, instead of silently logging
        // under someone else's label.
        Verdict::Escalate => "escalate",
    }
}

/// Per-session monotonic sequence numbers.
#[derive(Default)]
pub struct Sessions {
    counters: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    pub fn next(&self, session: &str) -> u64 {
        let mut m = self.counters.lock().expect("sessions mutex");
        let c = m.entry(session.to_string()).or_insert(0);
        *c += 1;
        *c
    }

    pub fn end(&self, session: &str) {
        self.counters
            .lock()
            .expect("sessions mutex")
            .remove(session);
    }
}

/// All state shared across hook requests.
pub struct AppState {
    pub firewall: Mutex<AgentFirewall>,
    pub sessions: Sessions,
    pub audit: AuditSink,
    pub config: Config,
    pub token: String,
    /// Bounded per-session cache of untrusted content, keyed by the sequence
    /// number the taint tracker recorded it under. The judge tier reads from this
    /// rather than from `TaintMark`, which deliberately carries only an 8-byte
    /// fingerprint. See `spans.rs`.
    pub spans: SpanCache,
    /// The optional local-model escalation tier. Off unless configured; when off,
    /// every `judge()` call returns `Unavailable` and the rule's fallback applies.
    pub judge: Judge,
    /// Persistent per-server MCP manifest pins (the rug-pull defense).
    pub manifests: crate::mcp::store::ManifestStore,
    /// Cross-server tool-name registry (the shadowing defense).
    pub tools: crate::mcp::store::ToolRegistry,
    /// Approvals an operator has issued but no call has matched yet.
    pub grants: crate::grant::GrantStore,
    /// Which approvals have been spent. Single use is enforced here, not by the
    /// pending file, so a failed delete cannot become a second authorization.
    pub grant_ledger: crate::grant::GrantLedger,
    /// Key the daemon signs approvals with. Domain-separated from the hook token
    /// so possession of one never implies the other.
    pub grant_key: Vec<u8>,
}

pub type Shared = Arc<AppState>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Liveness probe. Also reports whether enforcement is on, so `curl`ing it tells
/// an operator at a glance whether a blocked call is expected behavior.
pub async fn health(State(st): State<Shared>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "enforce": st.config.enforce,
    }))
}

/// Every hook event lands here. On ANY internal failure this returns 200 with an
/// empty body, which Claude Code treats as "no opinion" — a security tool that
/// wedges the agent loop gets uninstalled the same day.
pub async fn hook(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&st.token, auth) {
        tracing::warn!("rejected an unauthenticated hook request");
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }

    if body.len() > st.config.max_body_bytes {
        tracing::warn!(
            len = body.len(),
            "hook body over cap; proceeding without inspection"
        );
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    let started = Instant::now();

    let payload: HookPayload = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "unparsable hook payload; proceeding");
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    };

    // An event kind this build does not know about, or a session id too degenerate
    // to key taint by (see `map::to_event`): proceed without blocking. Raw bodies
    // are omitted unless the operator explicitly opted into sensitive forensic capture.
    let seq = st.sessions.next(&payload.session_id);
    let Some(mapped) = map::to_event(&payload, seq, now_ms(), st.config.max_record_bytes) else {
        tracing::warn!(session = %payload.session_id, "unrecognized hook event");
        let _ = st.audit.write(&AuditLine {
            at_ms: now_ms(),
            session: payload.session_id.clone(),
            seq,
            event: "unknown".into(),
            tool: payload.tool_name.clone(),
            verdict: "allow".into(),
            shadow: !st.config.enforce,
            rule: None,
            risk_score: 0,
            findings: vec![],
            taint: None,
            judge: None,
            approval: None,
            egress_hosts: vec![],
            latency_us: started.elapsed().as_micros(),
            truncated: false,
            raw: st.config.capture_unknown_raw.then_some(body),
        });
        return (StatusCode::OK, Json(serde_json::json!({})));
    };
    let event = mapped.event;

    let is_pre = payload.event == HookEvent::PreToolUse;
    if payload.event == HookEvent::SessionEnd {
        st.sessions.end(&payload.session_id);
        st.spans.end_session(&payload.session_id);
    }

    // Retain untrusted content by the same sequence number the taint tracker
    // will fingerprint it under, so a later `Escalate` has something to hand the
    // judge. Mirrors exactly the condition `AgentFirewall::inspect` uses to
    // decide what becomes taint (`crates/agent/src/engine.rs`): a `ToolResult`
    // only when its source is untrusted, a `SubagentReport` unconditionally
    // (subagent output has no `source` field and is always treated as tainted).
    match &event.kind {
        EventKind::ToolResult {
            content, source, ..
        } => {
            if source.trust() == Trust::Untrusted {
                st.spans.put(&payload.session_id, seq, content);
            }
        }
        EventKind::SubagentReport { content, .. } => {
            st.spans.put(&payload.session_id, seq, content);
        }
        _ => {}
    }

    // `AgentFirewall::inspect` takes `&mut self`, so the guard must be held across
    // the call. Scoped in its own block so the `std::sync::Mutex` guard is dropped
    // before the function's first `.await` — nothing here awaits while it is held.
    let outcome = {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        fw.inspect(&event)
    };

    // Resolve `Escalate` into a concrete verdict via the judge before deciding. The
    // `std::sync::Mutex` guard above is already dropped (scoped block), so the judge's
    // `.await` never holds a lock. `judged` records what the model said for the audit
    // log, so a verdict landing on `Ask` (or not) is explainable after the fact.
    let mut verdict = outcome.verdict;
    let mut judged: Option<String> = None;
    if verdict == Verdict::Escalate {
        // The judge sees the tainted CONTENT and its source — never the tool call.
        // Design spec §4b: including the action made it fire on ordinary work.
        let (span, source) = match &outcome.taint {
            Some(t) => (
                st.spans.get(&payload.session_id, t.seq).unwrap_or_default(),
                t.source.label(),
            ),
            None => (String::new(), "unknown".to_string()),
        };
        if span.trim().is_empty() {
            // No retained content means nothing to judge — take the fallback rather
            // than asking the model about an empty string.
            verdict = outcome.fallback.unwrap_or(Verdict::Allow);
            judged = Some("Unavailable(\"no retained span\")".into());
        } else {
            let j = st.judge.judge(&span, &source).await;
            judged = Some(format!("{j:?}"));
            verdict = resolve_escalation(j, outcome.fallback);
        }
    }

    // A human approval, if the operator issued one for exactly this call. Only
    // `Ask` is redeemable: `Deny` is a policy refusal, and letting an approval
    // override it would turn every deny into a prompt an attacker can wait out.
    let mut approval = None;
    if verdict == Verdict::Ask {
        if let Some(tool) = &payload.tool_name {
            let action = crate::grant::ActionRef {
                session: payload.session_id.clone(),
                tool: tool.clone(),
                args_fingerprint: crate::grant::action_fingerprint(tool, &payload.tool_input),
            };
            let redeemed = crate::grant::redeem_pending(
                &st.grant_key,
                &st.grants,
                &st.grant_ledger,
                &action,
                now_ms(),
                |grant, error| {
                    tracing::warn!(
                        nonce = %grant.nonce,
                        reason = error.reason(),
                        "a pending approval matched this action but was refused"
                    );
                },
            );
            if let Some(grant) = redeemed {
                tracing::info!(
                    nonce = %grant.nonce,
                    tool = %tool,
                    "a human approval authorized this call"
                );
                approval = Some(grant.nonce.clone());
                verdict = Verdict::Allow;
            }
        }
    }

    let d = decision::decide(
        verdict,
        outcome.rule.as_deref(),
        outcome.message.as_deref(),
        st.config.enforce,
    );

    let _ = st.audit.write(&AuditLine {
        at_ms: event.at_ms,
        session: payload.session_id.clone(),
        seq,
        event: payload.event.as_str().to_string(),
        tool: payload.tool_name.clone(),
        verdict: verdict_str(d.would_have_been).to_string(),
        shadow: d.shadow,
        rule: outcome.rule.clone(),
        risk_score: outcome.risk_score,
        findings: outcome
            .findings
            .iter()
            .map(|(_, f)| AuditFinding {
                detector: f.detector.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                owasp: f.owasp.clone(),
                atlas: f.atlas.clone(),
            })
            .collect(),
        taint: outcome.taint.as_ref().map(|t| AuditTaint {
            source: t.source.label(),
            origin: t.source.kind().to_string(),
            source_name: t.source.source_name().map(str::to_string),
            trust: format!("{:?}", t.source.trust()).to_lowercase(),
            seq: t.seq,
        }),
        judge: judged,
        approval: approval.clone(),
        egress_hosts: outcome.egress_hosts.clone(),
        latency_us: started.elapsed().as_micros(),
        truncated: mapped.truncated,
        raw: None,
    });

    // Only PreToolUse carries a decision. Everything else mutates state only —
    // this is what "detect and gate, never rewrite" means concretely.
    if is_pre && d.permission_decision != "defer" {
        let out =
            serde_json::to_value(d.to_hook_output()).unwrap_or_else(|_| serde_json::json!({}));
        return (StatusCode::OK, Json(out));
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
pub struct McpHandshakeReq {
    pub server: String,
    #[serde(default)]
    pub tools: Vec<soup_wall_agent::ToolDecl>,
}

/// The MCP handshake endpoint. Computes drift + shadowing from persistent state, runs
/// detection + policy via `inspect_mcp_handshake`, pins the new manifest, audits, and
/// returns the verdict. On any internal failure it returns `allow` (fail open) — a
/// collector that blocks handshakes on its own bug gets uninstalled.
pub async fn mcp(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&st.token, auth) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }
    let req: McpHandshakeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "unparsable /mcp payload; allowing");
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "verdict": "allow" })),
            );
        }
    };

    let hash = crate::mcp::manifest::manifest_hash(&req.tools);
    let pinned = st.manifests.get_pinned(&req.server);
    let manifest_changed = matches!(&pinned, Some(previous) if previous.hash != hash);
    let names: Vec<String> = req.tools.iter().map(|t| t.name.clone()).collect();
    let shadowed = st.tools.shadows(&req.server, &names);
    let shadow = shadowed.is_some();

    let outcome = {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        fw.inspect_mcp_handshake(&req.server, &req.tools, manifest_changed, shadow)
    };

    // Compute the diff BEFORE re-pinning: once the new manifest is stored the
    // previous one is only reachable through history.
    let drift_detail = manifest_changed
        .then_some(pinned.as_ref())
        .flatten()
        .filter(|previous| !previous.tools.is_empty())
        .map(|previous| crate::mcp::manifest::detailed_diff(&previous.tools, &req.tools).render());

    // Pin the new manifest and record its names regardless of verdict: the operator is
    // being told about the change now, so the next handshake compares against it.
    let _ = st
        .manifests
        .put_manifest(&req.server, &hash, &req.tools, now_ms());
    st.tools.record(&req.server, &names);

    let reason = if manifest_changed {
        // A pin written before manifests were retained has no tools to compare
        // against, so it can only report that something changed. Say which case
        // this is rather than implying the diff was computed and came back empty.
        Some(match drift_detail {
            Some(detail) => format!("manifest drift on {}: {detail}", req.server),
            None => format!(
                "manifest drift on {}: the pinned tool manifest changed. The previous                  manifest predates manifest retention, so it cannot be diffed; the next                  change will be shown in full.",
                req.server
            ),
        })
    } else if let Some(name) = shadowed {
        Some(format!("tool name '{name}' collides with an existing tool"))
    } else {
        outcome.message.clone()
    };

    let d = decision::decide(
        outcome.verdict,
        outcome.rule.as_deref(),
        reason.as_deref(),
        st.config.enforce,
    );

    let _ = st.audit.write(&AuditLine {
        at_ms: now_ms(),
        session: req.server.clone(),
        seq: 0,
        event: "mcp_handshake".into(),
        tool: None,
        verdict: verdict_str(d.would_have_been).to_string(),
        shadow: d.shadow,
        rule: outcome.rule.clone(),
        risk_score: outcome.risk_score,
        findings: outcome
            .findings
            .iter()
            .map(|(_, f)| AuditFinding {
                detector: f.detector.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                owasp: f.owasp.clone(),
                atlas: f.atlas.clone(),
            })
            .collect(),
        taint: None,
        judge: None,
        approval: None,
        egress_hosts: vec![],
        latency_us: 0,
        truncated: false,
        raw: None,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "verdict": verdict_str(d.would_have_been),
            "enforce": st.config.enforce,
            "reason": reason,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judge::Judgement;

    #[test]
    fn a_judgement_of_injection_becomes_ask() {
        assert_eq!(
            resolve_escalation(Judgement::Injection, Some(Verdict::Allow)),
            Verdict::Ask
        );
    }

    #[test]
    fn a_judgement_of_documentation_takes_the_fallback() {
        assert_eq!(
            resolve_escalation(Judgement::Documentation, Some(Verdict::Allow)),
            Verdict::Allow
        );
        assert_eq!(
            resolve_escalation(Judgement::Documentation, Some(Verdict::Ask)),
            Verdict::Ask
        );
    }

    #[test]
    fn an_unavailable_judge_takes_the_fallback() {
        assert_eq!(
            resolve_escalation(Judgement::Unavailable("off".into()), Some(Verdict::Allow)),
            Verdict::Allow
        );
    }

    #[test]
    fn a_missing_fallback_resolves_to_allow_rather_than_blocking() {
        // Unreachable — the policy parser requires a fallback on every escalate rule.
        // If it ever happens, never invent a block from a missing field.
        assert_eq!(
            resolve_escalation(Judgement::Unavailable("x".into()), None),
            Verdict::Allow
        );
    }

    #[test]
    fn the_judge_can_only_tighten_never_soften() {
        // Injection must never produce something weaker than the fallback.
        for fb in [Verdict::Allow, Verdict::Ask] {
            let out = resolve_escalation(Judgement::Injection, Some(fb));
            assert!(
                out == Verdict::Ask,
                "Injection must land on Ask regardless of fallback {fb:?}, got {out:?}"
            );
        }
    }

    #[test]
    fn session_sequence_numbers_are_monotonic_and_per_session() {
        let s = Sessions::default();
        assert_eq!(s.next("a"), 1);
        assert_eq!(s.next("a"), 2);
        assert_eq!(
            s.next("b"),
            1,
            "sequences must not be shared across sessions"
        );
        assert_eq!(s.next("a"), 3);
    }

    #[test]
    fn ending_a_session_resets_its_sequence() {
        let s = Sessions::default();
        s.next("a");
        s.next("a");
        s.end("a");
        assert_eq!(s.next("a"), 1);
    }
}
