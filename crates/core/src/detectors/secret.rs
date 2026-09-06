// SPDX-License-Identifier: Apache-2.0

//! Secret detection: high-precision provider patterns + a generic high-entropy gate.

use std::sync::LazyLock;

use regex::Regex;

use crate::util::shannon_entropy;
use crate::{Context, Detector, Finding, Severity};

struct SecretRule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    label: &'static str,
}

static RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    let raw: &[(&str, &str, Severity, &str)] = &[
        (
            "secret.aws_key",
            r"AKIA[0-9A-Z]{16}",
            Severity::Critical,
            "AWS access key id",
        ),
        (
            "secret.github_pat",
            r"ghp_[A-Za-z0-9]{36}",
            Severity::Critical,
            "GitHub personal access token",
        ),
        (
            "secret.slack",
            r"xox[baprs]-[0-9A-Za-z-]{10,48}",
            Severity::High,
            "Slack token",
        ),
        (
            "secret.jwt",
            r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
            Severity::High,
            "JWT",
        ),
        (
            "secret.private_key",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            Severity::Critical,
            "private key material",
        ),
    ];
    raw.iter()
        .map(|(id, p, sev, label)| SecretRule {
            id,
            re: Regex::new(p).expect("static secret regex must compile"),
            severity: *sev,
            label,
        })
        .collect()
});

/// Generic high-entropy token: long alnum/base64-ish run with entropy above threshold.
static GENERIC_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{24,}").expect("generic token regex"));

const ENTROPY_THRESHOLD: f32 = 4.0;

#[derive(Default)]
pub struct SecretDetector;

impl SecretDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for SecretDetector {
    fn name(&self) -> &'static str {
        "secret"
    }

    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        let text = ctx.text;
        let mut out = Vec::new();

        for rule in RULES.iter() {
            for m in rule.re.find_iter(text) {
                out.push(
                    Finding::new(rule.id, rule.severity, 0.95, rule.label)
                        .with_span(m.start()..m.end()),
                );
            }
        }

        // Generic gate: only flag long tokens whose entropy looks key-like, and that
        // weren't already covered by a specific rule span.
        for m in GENERIC_TOKEN.find_iter(text) {
            if shannon_entropy(m.as_str()) < ENTROPY_THRESHOLD {
                continue;
            }
            let overlaps = out.iter().any(|f| {
                f.span
                    .as_ref()
                    .is_some_and(|s| s.start <= m.start() && m.end() <= s.end)
            });
            if overlaps {
                continue;
            }
            out.push(
                Finding::new("secret.generic", Severity::Low, 0.5, "high-entropy token")
                    .with_span(m.start()..m.end()),
            );
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
    fn flags_aws_key() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("key=AKIAIOSFODNN7EXAMPLE end"));
        assert!(f.iter().any(|x| x.detector == "secret.aws_key"));
        assert!(f
            .iter()
            .find(|x| x.detector == "secret.aws_key")
            .unwrap()
            .span
            .is_some());
    }

    #[test]
    fn flags_private_key_header() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(f.iter().any(|x| x.detector == "secret.private_key"));
    }

    #[test]
    fn benign_prose_is_clean() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input(
            "The quick brown fox jumps over the lazy dog.",
        ));
        assert!(f.is_empty());
    }

    #[test]
    fn flags_high_entropy_generic_token() {
        // 30 distinct chars (~4.9 bits/byte) that match no provider rule -> secret.generic.
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("token aA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0 end"));
        assert!(f.iter().any(|x| x.detector == "secret.generic"));
        assert!(
            f.iter()
                .find(|x| x.detector == "secret.generic")
                .unwrap()
                .severity
                == Severity::Low
        );
    }

    #[test]
    fn rule_span_suppresses_overlapping_generic() {
        // A high-entropy GitHub PAT is also a 24+ generic run, but the generic finding
        // must be suppressed because it's contained in the rule span.
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("ghp_aA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2"));
        assert!(f.iter().any(|x| x.detector == "secret.github_pat"));
        assert!(
            f.iter().all(|x| x.detector != "secret.generic"),
            "generic should be deduped against the rule span"
        );
    }
}
