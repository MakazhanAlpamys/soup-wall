// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `llm-firewall-core` — the pure-Rust detection engine.
//! No I/O lives here; detectors return `Finding`s and the scorer aggregates them.

mod context;
mod detector;
mod finding;
mod firewall;
mod masking;
mod policy;
mod scoring;
mod severity;
mod util;

pub mod detectors;
pub mod normalize;
pub mod taxonomy;

pub use context::{Context, Direction};
pub use detector::Detector;
pub use detectors::injection::InjectionDetector;
#[cfg(feature = "ml")]
pub use detectors::injection::MlClassifier;
#[cfg(feature = "ml")]
pub use detectors::moderation::ModerationClassifier;
pub use detectors::moderation::ModerationDetector;
pub use detectors::output::OutputDetector;
pub use detectors::pii::PiiDetector;
pub use detectors::secret::SecretDetector;
pub use finding::Finding;
pub use firewall::{Firewall, Outcome};
pub use masking::mask;
pub use normalize::{Normalized, Normalizer};
pub use policy::{Action, Condition, Decision, PolicySet, Rule};
pub use scoring::{score_findings, RiskScore};
pub use severity::Severity;
