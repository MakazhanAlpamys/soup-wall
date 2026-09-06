// SPDX-License-Identifier: Apache-2.0

//! PII detection: structured identifiers via regex; credit cards Luhn-validated.

use std::sync::LazyLock;

use regex::Regex;

use crate::util::luhn_valid;
use crate::{Context, Detector, Finding, Severity};

struct PiiRule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    label: &'static str,
    /// Extra validation beyond the regex (e.g. Luhn for cards).
    validate: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
}

static RULES: LazyLock<Vec<PiiRule>> = LazyLock::new(|| {
    vec![
        PiiRule {
            id: "pii.email",
            re: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            severity: Severity::Medium,
            label: "email address",
            validate: always,
        },
        PiiRule {
            id: "pii.ssn",
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            severity: Severity::High,
            label: "US SSN",
            validate: always,
        },
        PiiRule {
            id: "pii.ipv4",
            re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            severity: Severity::Low,
            label: "IPv4 address",
            validate: always,
        },
        PiiRule {
            id: "pii.credit_card",
            re: Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap(),
            severity: Severity::High,
            label: "credit card number",
            validate: luhn_valid,
        },
    ]
});

#[derive(Default)]
pub struct PiiDetector;

impl PiiDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for PiiDetector {
    fn name(&self) -> &'static str {
        "pii"
    }

    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        let mut out = Vec::new();
        for rule in RULES.iter() {
            for m in rule.re.find_iter(ctx.text) {
                if !(rule.validate)(m.as_str()) {
                    continue;
                }
                out.push(
                    Finding::new(rule.id, rule.severity, 0.9, rule.label)
                        .with_span(m.start()..m.end()),
                );
            }
        }
        for f in &mut out {
            f.direction = ctx.direction;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_email_with_span() {
        let det = PiiDetector::new();
        let f = det.inspect(&Context::input("reach me at alice@acme.com please"));
        let email = f.iter().find(|x| x.detector == "pii.email").unwrap();
        assert_eq!(
            &"reach me at alice@acme.com please"[email.span.clone().unwrap()],
            "alice@acme.com"
        );
    }

    #[test]
    fn valid_card_flagged_invalid_ignored() {
        let det = PiiDetector::new();
        assert!(det
            .inspect(&Context::input("card 4242 4242 4242 4242"))
            .iter()
            .any(|x| x.detector == "pii.credit_card"));
        assert!(!det
            .inspect(&Context::input("card 4242 4242 4242 4241"))
            .iter()
            .any(|x| x.detector == "pii.credit_card"));
    }

    #[test]
    fn finds_ssn() {
        let det = PiiDetector::new();
        assert!(det
            .inspect(&Context::input("ssn 123-45-6789"))
            .iter()
            .any(|x| x.detector == "pii.ssn"));
    }
}
