// SPDX-License-Identifier: Apache-2.0

//! Content moderation (Trust & Safety) — a DeBERTa-v2/v3 multi-label harmful-content
//! classifier (e.g. `duanyu027/moderation_0703_deberta_v3_small`, OpenAI-style
//! categories: hate / harassment / self-harm / sexual / violence …). Feature-gated (`ml`).
//!
//! This is a distinct capability from prompt-injection detection: it flags harmful
//! *content* in either direction (prompt or reply), not attacks on the model. It is NOT
//! a full safety system and makes no claim to detect illegal material (e.g. CSAM).

#[cfg(feature = "ml")]
use crate::Severity;
use crate::{Context, Detector, Finding};

#[cfg(feature = "ml")]
mod ml {
    use anyhow::{Context as _, Result};
    use candle_core::{Device, IndexOp, Tensor};
    use candle_nn::VarBuilder;
    use candle_transformers::models::debertav2::{Config, DebertaV2SeqClassificationModel};
    use tokenizers::Tokenizer;

    pub struct ModerationClassifier {
        model: DebertaV2SeqClassificationModel,
        tokenizer: Tokenizer,
        device: Device,
        labels: Vec<String>,
    }

    impl ModerationClassifier {
        /// Load from a directory with config.json (incl. `id2label`), tokenizer.json,
        /// model.safetensors — a DeBERTa-v2/v3 sequence classifier.
        pub fn load(dir: &str) -> Result<Self> {
            let cfg_bytes =
                std::fs::read(format!("{dir}/config.json")).context("read config.json")?;
            let raw: serde_json::Value = serde_json::from_slice(&cfg_bytes)?;
            let map = raw
                .get("id2label")
                .and_then(|v| v.as_object())
                .context("config.json missing id2label")?;
            let mut labels = vec![String::new(); map.len()];
            for (k, v) in map {
                let idx: usize = k.parse().context("id2label key not an index")?;
                if idx < labels.len() {
                    labels[idx] = v.as_str().unwrap_or("").to_string();
                }
            }
            Self::load_with_labels(dir, labels)
        }

        /// Load with explicit ordered labels (for checkpoints whose config omits
        /// `id2label`, e.g. some binary harmful/safe classifiers).
        pub fn load_with_labels(dir: &str, labels: Vec<String>) -> Result<Self> {
            use std::collections::HashMap;
            let device = Device::Cpu;
            let cfg_bytes =
                std::fs::read(format!("{dir}/config.json")).context("read config.json")?;
            let config: Config =
                serde_json::from_slice(&cfg_bytes).context("parse deberta config")?;
            let id2label: HashMap<u32, String> = labels
                .iter()
                .enumerate()
                .map(|(i, l)| (i as u32, l.clone()))
                .collect();

            let tokenizer = Tokenizer::from_file(format!("{dir}/tokenizer.json"))
                .map_err(|e| anyhow::anyhow!("load tokenizer: {e}"))?;
            // SAFETY: same invariant as the injection classifier. The mapping is
            // `unsafe` because modifying a mapped file is undefined behaviour; the
            // model is an operator-provisioned, read-only asset mapped once at
            // construction and never written by this process. A concurrent external
            // writer is out of scope and holds the same trust as the binary.
            let vb = unsafe {
                VarBuilder::from_mmaped_safetensors(
                    &[format!("{dir}/model.safetensors")],
                    candle_core::DType::F32,
                    &device,
                )?
            };
            // HF ForSequenceClassification nests the backbone under `deberta.`.
            let model = match DebertaV2SeqClassificationModel::load(
                vb.pp("deberta"),
                &config,
                Some(id2label.clone()),
            ) {
                Ok(m) => m,
                Err(_) => DebertaV2SeqClassificationModel::load(vb, &config, Some(id2label))?,
            };

            Ok(Self {
                model,
                tokenizer,
                device,
                labels,
            })
        }

        /// Per-category probability via **sigmoid** (multi-label: categories are not
        /// mutually exclusive). Returns `(label, prob)` for every category.
        pub fn predict(&self, text: &str) -> Result<Vec<(String, f32)>> {
            let enc = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
            let ids = Tensor::new(enc.get_ids(), &self.device)?.unsqueeze(0)?;
            let logits = self.model.forward(&ids, None, None)?; // [1, num_labels]
            let probs = candle_nn::ops::sigmoid(&logits)?;
            let row = probs.i(0)?.to_vec1::<f32>()?;
            Ok(self
                .labels
                .iter()
                .cloned()
                .zip(row.into_iter().map(|p| p.clamp(0.0, 1.0)))
                .collect())
        }
    }
}

#[cfg(feature = "ml")]
pub use ml::ModerationClassifier;

/// Labels that denote *not harmful* and must never be flagged.
#[cfg(feature = "ml")]
fn is_safe_label(label: &str) -> bool {
    matches!(
        label.to_ascii_lowercase().as_str(),
        "safe" | "ok" | "none" | "neutral" | "not_harmful" | "benign"
    )
}

#[cfg_attr(not(feature = "ml"), derive(Default))]
pub struct ModerationDetector {
    #[cfg(feature = "ml")]
    classifier: Option<ml::ModerationClassifier>,
    /// Category probability at/above which to flag. Default 0.5.
    #[cfg(feature = "ml")]
    threshold: f32,
}

#[cfg(feature = "ml")]
impl Default for ModerationDetector {
    fn default() -> Self {
        Self {
            classifier: None,
            threshold: 0.5,
        }
    }
}

impl ModerationDetector {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "ml")]
    pub fn with_model(mut self, classifier: ml::ModerationClassifier) -> Self {
        self.classifier = Some(classifier);
        self
    }

    #[cfg(feature = "ml")]
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
        self
    }
}

impl Detector for ModerationDetector {
    fn name(&self) -> &'static str {
        "moderation"
    }

    #[cfg_attr(not(feature = "ml"), allow(unused_variables))]
    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        #[cfg(feature = "ml")]
        if let Some(clf) = &self.classifier {
            if let Ok(cats) = clf.predict(ctx.text) {
                // Flag the single most-confident HARMFUL category above threshold.
                // "safe"/"ok"/etc. are benign labels and must never be flagged.
                if let Some((label, p)) = cats
                    .into_iter()
                    .filter(|(l, _)| !is_safe_label(l))
                    .filter(|(_, p)| *p >= self.threshold)
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                {
                    let severity = if p >= 0.85 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    return vec![Finding::new(
                        format!("moderation.{label}"),
                        severity,
                        p,
                        format!("harmful content: {label} (p={p:.2})"),
                    )];
                }
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_moderation_and_default_is_inert_without_model() {
        let d = ModerationDetector::new();
        assert_eq!(d.name(), "moderation");
        assert!(d.inspect(&Context::input("anything")).is_empty());
    }
}
