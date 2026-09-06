// SPDX-License-Identifier: Apache-2.0

//! Map detector ids to recognized security frameworks:
//! **OWASP LLM Top 10 (2025)** and **MITRE ATLAS** techniques. Every `Finding` is
//! auto-tagged from its detector id so the audit log and compliance report speak the
//! same language as the standards.
//!
//! References:
//! - OWASP: <https://genai.owasp.org/llm-top-10/>
//! - MITRE ATLAS: <https://atlas.mitre.org/>

/// OWASP LLM Top 10 (2025) category for a detector, if it maps to one.
pub fn owasp(detector: &str) -> Option<&'static str> {
    match root(detector) {
        "injection" => Some("LLM01:2025 Prompt Injection"),
        "secret" | "pii" => Some("LLM02:2025 Sensitive Information Disclosure"),
        "output" => Some("LLM05:2025 Improper Output Handling"),
        // Content moderation is a Trust & Safety control, not an OWASP security category.
        _ => None,
    }
}

/// MITRE ATLAS technique id for a detector, if it maps to one.
pub fn atlas(detector: &str) -> Option<&'static str> {
    match root(detector) {
        "injection" => Some("AML.T0051"),      // LLM Prompt Injection
        "secret" | "pii" => Some("AML.T0057"), // LLM Data Leakage
        _ => None,
    }
}

/// The detector root before any `.` sub-id (`injection.ml` -> `injection`).
fn root(detector: &str) -> &str {
    detector.split('.').next().unwrap_or(detector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_injection_including_subids() {
        assert_eq!(owasp("injection"), Some("LLM01:2025 Prompt Injection"));
        assert_eq!(owasp("injection.ml"), Some("LLM01:2025 Prompt Injection"));
        assert_eq!(atlas("injection.ml"), Some("AML.T0051"));
    }

    #[test]
    fn maps_data_disclosure_and_output() {
        assert_eq!(atlas("secret.aws_key"), Some("AML.T0057"));
        assert_eq!(
            owasp("pii.email"),
            Some("LLM02:2025 Sensitive Information Disclosure")
        );
        assert_eq!(owasp("output"), Some("LLM05:2025 Improper Output Handling"));
        assert_eq!(atlas("output"), None);
    }

    #[test]
    fn unknown_and_moderation_are_untagged() {
        assert_eq!(owasp("moderation"), None);
        assert_eq!(owasp("whatever"), None);
        assert_eq!(atlas("moderation"), None);
    }
}
