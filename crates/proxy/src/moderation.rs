// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The output moderation gate: runs the harmful-content classifier on a model reply
//! and returns a verdict. Feature-gated on `ml`; without it, always `Allow` (no-op),
//! so a proxy built without the model never fails — it just does not moderate.

use crate::config::{ModerationAction, OutputModeration};

/// What the gate decided about a reply.
#[derive(Debug, Clone, PartialEq)]
pub enum GateVerdict {
    /// Forward untouched.
    Allow,
    /// Harmful categories at/above threshold. `block` = refuse; `flag` = audit + forward.
    Harmful {
        categories: Vec<String>,
        action: ModerationAction,
    },
}

/// Decide the verdict from the classifier's `(category, score)` output. Pure, so the
/// policy is unit-testable without the model. A category counts if its score is at or
/// above the threshold, it is not a "safe"/"OK" label, and (when `categories` is
/// non-empty) it is in the operator's allowlist.
pub fn verdict_from_scores(scores: &[(String, f32)], cfg: &OutputModeration) -> GateVerdict {
    let hits: Vec<String> = scores
        .iter()
        .filter(|(cat, score)| {
            *score >= cfg.threshold
                && !cat.eq_ignore_ascii_case("safe")
                && !cat.eq_ignore_ascii_case("ok")
                && (cfg.categories.is_empty() || cfg.categories.iter().any(|c| c == cat))
        })
        .map(|(cat, _)| cat.clone())
        .collect();
    if hits.is_empty() {
        GateVerdict::Allow
    } else {
        GateVerdict::Harmful {
            categories: hits,
            action: cfg.action,
        }
    }
}

/// Holds the loaded classifier (ml only) + the config. `check` returns the verdict for
/// a reply. Built once at startup.
pub struct ModerationGate {
    cfg: OutputModeration,
    #[cfg(feature = "ml")]
    classifier: Option<soup_wall_core::ModerationClassifier>,
}

impl ModerationGate {
    /// Build from config. When enabled + `ml` + the model loads, the gate is live;
    /// otherwise it degrades to a no-op with a warning (never a hard failure).
    pub fn new(cfg: OutputModeration) -> Self {
        #[cfg(feature = "ml")]
        {
            if !cfg.enabled {
                return Self {
                    cfg,
                    classifier: None,
                };
            }
            // Binary harmful/safe head, same label assignment the benchmark uses.
            let labels = vec!["harmful".to_string(), "safe".to_string()];
            match soup_wall_core::ModerationClassifier::load_with_labels(&cfg.model_path, labels) {
                Ok(clf) => {
                    tracing::info!(path = %cfg.model_path, "output moderation model loaded");
                    Self {
                        cfg,
                        classifier: Some(clf),
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "output moderation enabled but model unavailable; disabled");
                    Self {
                        cfg,
                        classifier: None,
                    }
                }
            }
        }
        #[cfg(not(feature = "ml"))]
        {
            if cfg.enabled {
                tracing::warn!(
                    "output_moderation.enabled but the proxy was built without the `ml` feature; no-op"
                );
            }
            Self { cfg }
        }
    }

    /// The verdict for a model reply. Always `Allow` when the gate is not live.
    pub fn check(&self, _text: &str) -> GateVerdict {
        if !self.cfg.enabled {
            return GateVerdict::Allow;
        }
        #[cfg(feature = "ml")]
        {
            if let Some(clf) = &self.classifier {
                match clf.predict(_text) {
                    Ok(scores) => return verdict_from_scores(&scores, &self.cfg),
                    Err(e) => {
                        tracing::warn!(error = %e, "moderation predict failed; allowing (fail open)");
                        return GateVerdict::Allow;
                    }
                }
            }
        }
        GateVerdict::Allow
    }

    pub fn refusal_message(&self) -> &str {
        &self.cfg.refusal_message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(action: ModerationAction, threshold: f32, categories: Vec<String>) -> OutputModeration {
        OutputModeration {
            enabled: true,
            action,
            threshold,
            categories,
            ..Default::default()
        }
    }

    #[test]
    fn a_high_scoring_harmful_category_is_flagged() {
        let scores = vec![("harmful".to_string(), 0.95), ("safe".to_string(), 0.05)];
        let v = verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![]));
        assert!(matches!(v, GateVerdict::Harmful { .. }));
    }

    #[test]
    fn a_below_threshold_score_is_allowed() {
        let scores = vec![("harmful".to_string(), 0.5)];
        assert_eq!(
            verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![])),
            GateVerdict::Allow
        );
    }

    #[test]
    fn the_safe_category_never_counts() {
        let scores = vec![("safe".to_string(), 0.99)];
        assert_eq!(
            verdict_from_scores(&scores, &cfg(ModerationAction::Flag, 0.8, vec![])),
            GateVerdict::Allow
        );
    }

    #[test]
    fn the_category_allowlist_narrows_what_counts() {
        let scores = vec![("hate".to_string(), 0.95), ("hacking".to_string(), 0.95)];
        let v = verdict_from_scores(
            &scores,
            &cfg(ModerationAction::Block, 0.8, vec!["hacking".to_string()]),
        );
        match v {
            GateVerdict::Harmful { categories, .. } => {
                assert_eq!(categories, vec!["hacking".to_string()])
            }
            _ => panic!("expected harmful"),
        }
    }

    #[test]
    fn a_disabled_gate_is_a_no_op() {
        let gate = ModerationGate::new(OutputModeration::default());
        assert_eq!(gate.check("anything at all"), GateVerdict::Allow);
    }
}
