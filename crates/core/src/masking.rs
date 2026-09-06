// SPDX-License-Identifier: Apache-2.0

//! Replace finding spans in text with typed tokens, e.g. "alice@acme.com" -> "‹EMAIL›".
//! Overlapping spans are resolved by keeping the earliest-starting, longest span.

use crate::Finding;

/// Token for a finding: the last dot-segment of its detector id, upper-cased.
/// "pii.email" -> "‹EMAIL›", "secret.aws_key" -> "‹AWS_KEY›".
fn token_for(detector: &str) -> String {
    let suffix = detector.rsplit('.').next().unwrap_or(detector);
    format!("‹{}›", suffix.to_uppercase())
}

/// Return a masked copy of `text`, replacing spans of findings that have one.
pub fn mask(text: &str, findings: &[Finding]) -> String {
    // Collect (span, token), sorted by start asc then length desc.
    let mut spans: Vec<(std::ops::Range<usize>, String)> = findings
        .iter()
        .filter_map(|f| f.span.clone().map(|s| (s, token_for(&f.detector))))
        .collect();
    spans.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (span, token) in spans {
        if span.start < cursor {
            continue; // overlaps an already-masked region
        }
        if span.start > text.len()
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            continue; // defensive: stale or non-char-boundary span (never panic on bad input)
        }
        out.push_str(&text[cursor..span.start]);
        out.push_str(&token);
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    #[test]
    fn masks_single_span() {
        let text = "reach me at alice@acme.com ok";
        let findings =
            vec![Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(12..26)];
        assert_eq!(mask(text, &findings), "reach me at ‹EMAIL› ok");
    }

    #[test]
    fn masks_multiple_in_order() {
        let text = "a AKIAIOSFODNN7EXAMPLE b 123-45-6789 c";
        let findings = vec![
            Finding::new("secret.aws_key", Severity::Critical, 0.95, "aws").with_span(2..22),
            Finding::new("pii.ssn", Severity::High, 0.9, "ssn").with_span(25..36),
        ];
        assert_eq!(mask(text, &findings), "a ‹AWS_KEY› b ‹SSN› c");
    }

    #[test]
    fn findings_without_spans_are_ignored() {
        let text = "nothing to mask";
        let findings = vec![Finding::new("injection", Severity::High, 0.9, "x")];
        assert_eq!(mask(text, &findings), text);
    }

    #[test]
    fn overlapping_spans_keep_longest_earliest() {
        // Nested spans: the earliest-starting longest span wins; the inner one is dropped.
        let text = "SECRETVALUE tail";
        let findings = vec![
            Finding::new("secret.aws_key", Severity::Critical, 0.95, "outer").with_span(0..11),
            Finding::new("secret.generic", Severity::Low, 0.5, "inner").with_span(2..7),
        ];
        assert_eq!(mask(text, &findings), "‹AWS_KEY› tail");
    }

    #[test]
    fn non_char_boundary_span_is_skipped_not_panicked() {
        // A span landing inside a multibyte char must be skipped, never panic.
        let text = "héllo"; // 'é' occupies bytes 1..3
        let findings = vec![Finding::new("pii.x", Severity::Low, 0.5, "x").with_span(2..4)];
        assert_eq!(mask(text, &findings), text); // unchanged, no panic
    }
}
