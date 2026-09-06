// SPDX-License-Identifier: Apache-2.0

//! A single structured detector result. Detectors NEVER return bare bools —
//! scoring, masking, and audit all consume this one shape.

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::{Direction, Severity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable detector id, e.g. "injection", "pii.email", "secret.aws_key".
    pub detector: String,
    pub severity: Severity,
    /// Detector confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Byte range in the inspected text (for masking / highlighting), if known.
    pub span: Option<Range<usize>>,
    /// Human-readable description.
    pub label: String,
    /// Direction of travel this finding was observed on.
    pub direction: Direction,
    /// OWASP LLM Top 10 (2025) category, auto-derived from the detector id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    /// MITRE ATLAS technique id, auto-derived from the detector id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atlas: Option<String>,
}

impl Finding {
    pub fn new(
        detector: impl Into<String>,
        severity: Severity,
        confidence: f32,
        label: impl Into<String>,
    ) -> Self {
        let detector = detector.into();
        let owasp = crate::taxonomy::owasp(&detector).map(String::from);
        let atlas = crate::taxonomy::atlas(&detector).map(String::from);
        Self {
            detector,
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            span: None,
            label: label.into(),
            direction: Direction::Input,
            owasp,
            atlas,
        }
    }

    /// Builder: attach a byte span.
    pub fn with_span(mut self, span: Range<usize>) -> Self {
        self.span = Some(span);
        self
    }

    /// Builder: set the direction of travel this finding was observed on.
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_confidence_and_sets_fields() {
        let f = Finding::new("injection", Severity::High, 1.5, "override phrase");
        assert_eq!(f.detector, "injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, 1.0); // clamped
        assert_eq!(f.span, None);
        assert_eq!(f.label, "override phrase");
        assert_eq!(f.direction, Direction::Input);
    }

    #[test]
    fn with_span_attaches_range() {
        let f = Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(4..17);
        assert_eq!(f.span, Some(4..17));
    }
}
