// SPDX-License-Identifier: Apache-2.0

//! Structured audit records emitted per request via `tracing`.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub request_id: String,
    pub direction: String,
    pub decision: String,
    pub score: u8,
    pub reasons: Vec<String>,
    /// OWASP LLM Top 10 (2025) categories implicated by this request's findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    /// MITRE ATLAS technique ids implicated by this request's findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub atlas: Vec<String>,
    pub latency_ms: u128,
}

impl AuditRecord {
    /// Emit as a single JSON log line.
    pub fn emit(&self) {
        match serde_json::to_string(self) {
            Ok(json) => tracing::info!(target: "audit", "{json}"),
            Err(e) => tracing::error!("audit serialize failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_expected_shape() {
        let rec = AuditRecord {
            request_id: "abc".into(),
            direction: "input".into(),
            decision: "block".into(),
            score: 92,
            reasons: vec!["instruction-override phrase".into()],
            owasp: vec!["LLM01:2025 Prompt Injection".into()],
            atlas: vec!["AML.T0051".into()],
            latency_ms: 3,
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["score"], 92);
        assert_eq!(json["reasons"][0], "instruction-override phrase");
        assert_eq!(json["owasp"][0], "LLM01:2025 Prompt Injection");
        assert_eq!(json["atlas"][0], "AML.T0051");
    }
}
