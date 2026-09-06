// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Stable, dependency-light wire types for the optional control-plane adapter.
//!
//! This crate deliberately contains no network, storage, identity, or proxy code. Core
//! can use the types locally and Enterprise can transport the same JSON without importing
//! private proxy implementation details.

use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// The first negotiated adapter contract version.
pub const CONTRACT_VERSION: &str = "sw-adapter/0.1";

/// Whether a wire message can be interpreted by this crate.
pub fn supports_contract_version(version: &str) -> bool {
    version == CONTRACT_VERSION
}

/// Authorization outcome. Ordering is the enforcement strictness order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    /// Return the stricter of two independent decisions.
    pub const fn strictest(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Ask => 1,
            Self::Deny => 2,
        }
    }
}

/// Privacy-safe summary of taint/provenance state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaintSummary {
    pub tainted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub earliest_sequence: Vec<u64>,
}

/// Privacy-safe destination classification. It contains no URL or credentials.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DestinationSummary {
    pub network: bool,
    pub allowlisted: bool,
    pub private_address: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_classes: Vec<String>,
}

/// Local Core context sent to an optional Enterprise policy adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecisionRequest {
    pub contract_version: String,
    pub request_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub action_class: String,
    pub taint: TaintSummary,
    pub destination: DestinationSummary,
    pub core_policy_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detector_tags: Vec<String>,
    pub risk_score: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub nonce: String,
    pub sequence: u64,
}

impl DecisionRequest {
    /// Validate the identity/replay fields before a request leaves Core.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !supports_contract_version(&self.contract_version) {
            return Err(ValidationError::UnsupportedContract {
                version: self.contract_version.clone(),
            });
        }
        if self.request_id.is_empty() {
            return Err(ValidationError::EmptyField("request_id"));
        }
        if self.agent_id.is_empty() {
            return Err(ValidationError::EmptyField("agent_id"));
        }
        if self.session_id.is_empty() {
            return Err(ValidationError::EmptyField("session_id"));
        }
        if self.nonce.is_empty() {
            return Err(ValidationError::EmptyField("nonce"));
        }
        Ok(())
    }
}

/// Optional signed response from the Enterprise policy adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecisionResponse {
    pub contract_version: String,
    pub verdict: Verdict,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
    /// Unix seconds. Remote allow/ask responses must expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayEnvelope>,
}

impl DecisionResponse {
    /// Validate a response against its request using local time and replay data.
    ///
    /// This checks the envelope only; cryptographic signature verification belongs to
    /// the adapter transport because key storage and rotation are Enterprise concerns.
    pub fn validate_for(
        &self,
        request: &DecisionRequest,
        now_unix_seconds: u64,
    ) -> Result<(), ValidationError> {
        request.validate()?;
        if !supports_contract_version(&self.contract_version)
            || self.contract_version != request.contract_version
        {
            return Err(ValidationError::UnsupportedContract {
                version: self.contract_version.clone(),
            });
        }
        if self.policy_version.is_empty() {
            return Err(ValidationError::EmptyField("policy_version"));
        }
        if self
            .expires_at
            .is_some_and(|expires| expires <= now_unix_seconds)
        {
            return Err(ValidationError::Expired);
        }
        if let Some(replay) = &self.replay {
            if replay.nonce != request.nonce || replay.sequence != request.sequence {
                return Err(ValidationError::ReplayMismatch);
            }
        }
        Ok(())
    }

    /// Validate a response that came from a remote Enterprise adapter.
    pub fn validate_remote_for(
        &self,
        request: &DecisionRequest,
        now_unix_seconds: u64,
    ) -> Result<(), ValidationError> {
        self.validate_for(request, now_unix_seconds)?;
        if matches!(self.verdict, Verdict::Allow | Verdict::Ask) && self.expires_at.is_none() {
            return Err(ValidationError::MissingExpiry);
        }
        if self.signature.is_none() {
            return Err(ValidationError::MissingSignature);
        }
        self.signature
            .as_ref()
            .expect("signature presence checked above")
            .validate()?;
        let replay = self
            .replay
            .as_ref()
            .ok_or(ValidationError::ReplayMismatch)?;
        if replay.nonce != request.nonce || replay.sequence != request.sequence {
            return Err(ValidationError::ReplayMismatch);
        }
        Ok(())
    }

    /// Combine an optional remote answer with the local verdict without weakening it.
    pub const fn combine_with_local(&self, local: Verdict) -> Verdict {
        local.strictest(self.verdict)
    }
}

/// Detached signature metadata; key material is never carried in this envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

impl SignatureEnvelope {
    /// Validate signature metadata before a transport-specific verifier uses it.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.algorithm.is_empty() {
            return Err(ValidationError::EmptyField("signature.algorithm"));
        }
        if self.key_id.is_empty() {
            return Err(ValidationError::EmptyField("signature.key_id"));
        }
        if self.value.is_empty() {
            return Err(ValidationError::EmptyField("signature.value"));
        }
        Ok(())
    }
}

/// Nonce/sequence echo used by adapters to reject stale or duplicated responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayEnvelope {
    pub nonce: String,
    pub sequence: u64,
}

/// Signed policy state distributed by Enterprise or loaded from a local file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyBundle {
    pub contract_version: String,
    pub bundle_id: String,
    pub revision: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub policy_yaml: String,
    pub issuer_key_id: String,
    pub signature: SignatureEnvelope,
}

impl PolicyBundle {
    /// Validate bundle metadata and validity window before activation.
    pub fn validate_at(&self, now_unix_seconds: u64) -> Result<(), ValidationError> {
        if !supports_contract_version(&self.contract_version) {
            return Err(ValidationError::UnsupportedContract {
                version: self.contract_version.clone(),
            });
        }
        if self.bundle_id.is_empty() {
            return Err(ValidationError::EmptyField("bundle_id"));
        }
        if self.policy_yaml.is_empty() {
            return Err(ValidationError::EmptyField("policy_yaml"));
        }
        if self.issuer_key_id.is_empty() {
            return Err(ValidationError::EmptyField("issuer_key_id"));
        }
        self.signature.validate()?;
        if self.valid_from >= self.expires_at
            || now_unix_seconds < self.valid_from
            || now_unix_seconds >= self.expires_at
        {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

/// Privacy-safe event emitted by Core to a local sink or Enterprise telemetry adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub contract_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at: u64,
    pub agent_id: String,
    pub session_id: String,
    pub action_class: String,
    pub verdict: Verdict,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detector_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    pub taint: TaintSummary,
    pub destination: DestinationSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_event_hash: Option<String>,
    pub core_build: String,
}

/// Opaque fleet state supplied to Core; enrollment credentials never belong here.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnrollmentState {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_ceiling: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_id: Option<String>,
    pub enrolled: bool,
}

/// Envelope validation failed before policy state could be trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    UnsupportedContract { version: String },
    EmptyField(&'static str),
    MissingExpiry,
    Expired,
    ReplayMismatch,
    MissingSignature,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedContract { version } => {
                write!(f, "unsupported adapter contract version: {version}")
            }
            Self::EmptyField(field) => write!(f, "adapter field is empty: {field}"),
            Self::MissingExpiry => write!(f, "allow/ask response must expire"),
            Self::Expired => write!(f, "adapter response or bundle is expired"),
            Self::ReplayMismatch => write!(f, "adapter replay nonce or sequence mismatched"),
            Self::MissingSignature => write!(f, "remote adapter response is unsigned"),
        }
    }
}

impl Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_combination_never_weakens_a_local_deny() {
        assert_eq!(Verdict::Deny.strictest(Verdict::Allow), Verdict::Deny);
        assert_eq!(Verdict::Ask.strictest(Verdict::Allow), Verdict::Ask);
        assert_eq!(Verdict::Deny.strictest(Verdict::Ask), Verdict::Deny);
    }

    fn request() -> DecisionRequest {
        DecisionRequest {
            contract_version: CONTRACT_VERSION.into(),
            request_id: "req-1".into(),
            agent_id: "agent-opaque".into(),
            session_id: "session-opaque".into(),
            action_class: "network".into(),
            taint: TaintSummary::default(),
            destination: DestinationSummary::default(),
            core_policy_version: "local-7".into(),
            detector_tags: vec![],
            risk_score: 10,
            severity: None,
            nonce: "n-1".into(),
            sequence: 8,
        }
    }

    #[test]
    fn remote_allow_requires_expiry_signature_and_matching_replay() {
        let request = request();
        let response = DecisionResponse {
            contract_version: CONTRACT_VERSION.into(),
            verdict: Verdict::Allow,
            policy_version: "p-1".into(),
            policy_bundle_id: None,
            reason_codes: vec![],
            remediation_hint: None,
            expires_at: None,
            signature: None,
            replay: None,
        };
        assert_eq!(
            response.validate_remote_for(&request, 100),
            Err(ValidationError::MissingExpiry)
        );

        let response = DecisionResponse {
            expires_at: Some(200),
            signature: Some(SignatureEnvelope {
                algorithm: "ed25519".into(),
                key_id: "k-1".into(),
                value: "sig".into(),
            }),
            replay: Some(ReplayEnvelope {
                nonce: "wrong".into(),
                sequence: 8,
            }),
            ..response
        };
        assert_eq!(
            response.validate_remote_for(&request, 100),
            Err(ValidationError::ReplayMismatch)
        );
    }

    #[test]
    fn local_allow_may_be_unexpired_and_remote_validation_still_requires_expiry() {
        let request = request();
        let response = DecisionResponse {
            contract_version: CONTRACT_VERSION.into(),
            verdict: Verdict::Allow,
            policy_version: "local".into(),
            policy_bundle_id: None,
            reason_codes: vec![],
            remediation_hint: None,
            expires_at: None,
            signature: None,
            replay: None,
        };
        assert!(response.validate_for(&request, 100).is_ok());
        assert_eq!(
            response.validate_remote_for(&request, 100),
            Err(ValidationError::MissingExpiry)
        );
    }

    #[test]
    fn invalid_policy_bundle_is_kept_out_of_the_active_state() {
        let bundle = PolicyBundle {
            contract_version: CONTRACT_VERSION.into(),
            bundle_id: "bundle-1".into(),
            revision: 4,
            valid_from: 100,
            expires_at: 200,
            policy_yaml: "default: allow".into(),
            issuer_key_id: "k-1".into(),
            signature: SignatureEnvelope {
                algorithm: "ed25519".into(),
                key_id: "k-1".into(),
                value: "sig".into(),
            },
        };
        assert!(bundle.validate_at(150).is_ok());
        assert_eq!(bundle.validate_at(200), Err(ValidationError::Expired));
    }

    #[test]
    fn empty_signature_metadata_is_rejected_before_crypto_verification() {
        let bundle = PolicyBundle {
            contract_version: CONTRACT_VERSION.into(),
            bundle_id: "bundle-1".into(),
            revision: 1,
            valid_from: 1,
            expires_at: 10,
            policy_yaml: "default: allow".into(),
            issuer_key_id: "issuer".into(),
            signature: SignatureEnvelope {
                algorithm: String::new(),
                key_id: "key".into(),
                value: "sig".into(),
            },
        };
        assert_eq!(
            bundle.validate_at(5),
            Err(ValidationError::EmptyField("signature.algorithm"))
        );
    }

    #[test]
    fn decision_request_round_trips_without_sensitive_payload_fields() {
        let request = DecisionRequest {
            contract_version: CONTRACT_VERSION.into(),
            request_id: "req-1".into(),
            agent_id: "agent-opaque".into(),
            session_id: "session-opaque".into(),
            action_class: "network".into(),
            taint: TaintSummary {
                tainted: true,
                source_kinds: vec!["web".into()],
                earliest_sequence: vec![4],
            },
            destination: DestinationSummary {
                network: true,
                allowlisted: false,
                private_address: false,
                host_classes: vec!["public".into()],
            },
            core_policy_version: "local-7".into(),
            detector_tags: vec!["secret-egress".into()],
            risk_score: 92,
            severity: Some("high".into()),
            nonce: "n-1".into(),
            sequence: 8,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("prompt"));
        assert!(!json.contains("response"));
        assert!(!json.contains("tool_args"));
        assert_eq!(
            serde_json::from_str::<DecisionRequest>(&json).unwrap(),
            request
        );
    }

    #[test]
    fn unknown_fields_are_ignored_but_unknown_verdicts_fail() {
        let response = r#"{
            "contract_version":"sw-adapter/0.1",
            "verdict":"deny",
            "policy_version":"p-1",
            "future_field":"ignored"
        }"#;
        let parsed: DecisionResponse = serde_json::from_str(response).unwrap();
        assert_eq!(parsed.verdict, Verdict::Deny);
        let invalid = response.replace("deny", "override_everything");
        assert!(serde_json::from_str::<DecisionResponse>(&invalid).is_err());
    }

    #[test]
    fn audit_event_fixture_is_stable_and_privacy_safe() {
        let event = AuditEvent {
            contract_version: CONTRACT_VERSION.into(),
            event_id: "evt-1".into(),
            sequence: 12,
            occurred_at: 1_756_000_000,
            agent_id: "agent-opaque".into(),
            session_id: "session-opaque".into(),
            action_class: "destructive".into(),
            verdict: Verdict::Deny,
            policy_version: "p-1".into(),
            policy_bundle_id: None,
            detector_tags: vec!["tainted-destructive".into()],
            reason_codes: vec!["taint.destructive".into()],
            taint: TaintSummary {
                tainted: true,
                source_kinds: vec!["tool_result".into()],
                earliest_sequence: vec![3],
            },
            destination: DestinationSummary::default(),
            previous_event_hash: Some("sha256:prev".into()),
            core_build: "core-dev".into(),
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["verdict"], "deny");
        assert!(value.get("raw_prompt").is_none());
        assert!(value.get("raw_response").is_none());
    }
}
