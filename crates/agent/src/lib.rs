// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `llm-firewall-agent` — agent-loop inspection. No I/O lives here.

pub mod action;
pub mod authority;
pub mod egress;
pub mod engine;
pub mod event;
pub mod facet;
pub mod fingerprint;
pub mod policy;
pub mod taint;

pub use action::{classify, touches_sensitive_path, ActionClass};
pub use authority::{Authority, Escalation};
pub use egress::{hosts, is_allowed};
pub use engine::{AgentFirewall, Outcome, DEFAULT_TAINT_CAP};
pub use event::{AgentEvent, AgentId, EventKind, Provenance, SessionId, ToolDecl, Trust};
pub use facet::{facets, Facet};
pub use fingerprint::{fingerprints, overlap};
pub use policy::{AgentDecision, AgentPolicySet, Signals, TaintSource, Verdict};
pub use taint::{TaintMark, TaintTracker};
