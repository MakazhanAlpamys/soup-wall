// SPDX-License-Identifier: Apache-2.0

//! Stage B: cheap heuristics that catch novel phrasings signatures miss.
//! Produces at most one aggregate `Finding`; confidence scales with the heuristic score.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Finding, Severity};

static IMPERATIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(ignore|disregard|override|bypass|forget|reveal|pretend|act\s+as)\b")
        .expect("imperative regex")
});

static LONG_B64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("b64 regex"));

/// Count of suspicious delimiter characters commonly used to smuggle instructions.
fn delimiter_hits(text: &str) -> usize {
    text.matches("```").count()
        + text.matches("###").count()
        + text.matches("---").count()
        + text.matches("<|").count()
}

/// Compute a heuristic score in `[0.0, 1.0]`. Pure function so it is trivially testable.
pub(crate) fn score_text(text: &str) -> f32 {
    let mut score = 0.0f32;

    score += 0.30 * IMPERATIVE.find_iter(text).count().min(3) as f32;
    if LONG_B64.is_match(text) {
        score += 0.30;
    }
    score += 0.10 * delimiter_hits(text).min(3) as f32;

    score.min(1.0)
}

/// Emit a single aggregate finding when the heuristic score crosses a floor.
pub(crate) fn scan(text: &str) -> Vec<Finding> {
    let score = score_text(text);
    if score < 0.30 {
        return Vec::new();
    }
    let severity = if score >= 0.75 {
        Severity::High
    } else if score >= 0.5 {
        Severity::Medium
    } else {
        Severity::Low
    };
    vec![Finding::new(
        "injection",
        severity,
        score,
        format!("heuristic injection signals (score {score:.2})"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_scores_low_and_emits_nothing() {
        assert!(score_text("Summarize this article about penguins.") < 0.30);
        assert!(scan("Summarize this article about penguins.").is_empty());
    }

    #[test]
    fn stacked_imperatives_raise_score() {
        let text = "ignore this, disregard that, override everything";
        assert!(score_text(text) >= 0.75);
        let f = scan(text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].detector, "injection");
    }

    #[test]
    fn base64_blob_contributes() {
        let blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=";
        assert!(score_text(blob) >= 0.30);
    }

    #[test]
    fn banding_and_confidence_are_locked() {
        // Intentional design decision (to be tuned against NotInject/benign corpora in the
        // benchmark phase): a single weak imperative reaches the 0.30 floor and emits a LOW
        // finding. Low impact (risk contribution ~0.09) and tempered by later stages.
        let low = scan("please act as a translator");
        assert_eq!(low.len(), 1);
        assert_eq!(low[0].severity, Severity::Low);
        assert!((low[0].confidence - score_text("please act as a translator")).abs() < 1e-6);

        // Medium band: base64 blob (0.30) + one imperative "ignore" (0.30) = 0.60 -> Medium.
        let text = "ignore this aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=";
        let med = scan(text);
        assert_eq!(med.len(), 1);
        assert_eq!(med[0].severity, Severity::Medium);
    }
}
