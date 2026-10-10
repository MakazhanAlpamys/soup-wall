// SPDX-License-Identifier: Apache-2.0
//! Versioned resource authorization for an authenticated, trusted collector.
//! This checks permissions and correlation; it does not attest an executor sandbox.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::mcp::admission::Invocation;
use crate::mcp::resources::{
    extract, ExecutorContext, Resource, ResourceEvidence, ResourceProfile,
};

pub const CONTRACT: &str = "sw-native/resources/1";

/// Immutable operator configuration, never accepted as a per-call grant.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub profile: ResourceProfile,
    pub workspace: PathBuf,
    pub cwd: PathBuf,
    pub executor_sha256: String,
    pub classifier_sha256: String,
    pub allowed_resources: Vec<Resource>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub server_id: String,
    pub host_call_id: Value,
    pub profile_sha256: String,
    pub executor_sha256: String,
    pub classifier_sha256: String,
    pub snapshot_sha256: String,
    pub definition_sha256: String,
    pub input_sha256: String,
    pub resources: Vec<ResourceEvidence>,
}

impl Admission {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        let id = &self.host_call_id;
        if !super::identifier(&self.server_id)
            || !(id.is_i64()
                || id.is_u64()
                || id.as_str().is_some_and(|s| {
                    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
                }))
            || self.resources.is_empty()
            || self.resources.len() > 256
            || serde_json::to_vec(self)
                .map_err(|_| "native_resource_invalid")?
                .len()
                > super::MAX_CONTENT
            || [
                &self.profile_sha256,
                &self.executor_sha256,
                &self.classifier_sha256,
                &self.snapshot_sha256,
                &self.definition_sha256,
                &self.input_sha256,
            ]
            .iter()
            .any(|digest| !super::is_digest(digest))
        {
            return Err("native_resource_invalid");
        }
        Ok(())
    }

    pub fn resources_sha256(&self) -> String {
        super::canonical_digest(
            &serde_json::to_value(&self.resources).expect("resources serialize"),
        )
    }
}

impl Policy {
    pub fn validate(&self, tool: &super::Tool) -> anyhow::Result<()> {
        anyhow::ensure!(
            super::identifier(&self.profile.server_id)
                && self.profile.tool_name == tool.name
                && self.profile.schema_sha256 == tool.schema_sha256
                && !self.profile.selectors.is_empty()
                && self.profile.selectors.len() <= 32
                && self.workspace.is_absolute()
                && self.cwd.is_absolute()
                && self.workspace.is_dir()
                && self.cwd.is_dir()
                && self
                    .cwd
                    .canonicalize()?
                    .starts_with(self.workspace.canonicalize()?)
                && super::is_digest(&self.executor_sha256)
                && super::is_digest(&self.classifier_sha256)
                && !self.allowed_resources.is_empty()
                && self.allowed_resources.len() <= 256,
            "invalid operator resource policy"
        );
        Ok(())
    }
}

/// Derive resources again from actual arguments and the operator's selectors.
/// A caller's well-formed array and a matching hash are not permissions.
pub fn authorize(
    policy: &Policy,
    tool: &super::Tool,
    registry_sha256: &str,
    args: &Value,
    admission: &Admission,
) -> Result<(), &'static str> {
    admission.validate_shape()?;
    let profile_sha256 = super::canonical_digest(
        &serde_json::to_value(&policy.profile).expect("profile serializes"),
    );
    if admission.server_id != policy.profile.server_id
        || admission.profile_sha256 != profile_sha256
        || admission.executor_sha256 != policy.executor_sha256
        || admission.classifier_sha256 != policy.classifier_sha256
    {
        return Err("native_resource_revision_mismatch");
    }
    let input = Invocation {
        server_id: admission.server_id.clone(),
        host_call_id: admission.host_call_id.clone(),
        registry_sha256: registry_sha256.into(),
        snapshot_sha256: admission.snapshot_sha256.clone(),
        schema_sha256: tool.schema_sha256.clone(),
        tool: tool.name.clone(),
        description: String::new(),
        schema: json!({}),
        definition: Value::Null,
        server_info: Value::Null,
        definition_sha256: admission.definition_sha256.clone(),
        input_sha256: admission.input_sha256.clone(),
        classifier_revision: Some(admission.classifier_sha256.clone()),
        args: args.clone(),
        baseline: tool.action_class,
    };
    // Semantic extraction only. Actual confinement remains the trusted collector's
    // responsibility; this Boolean neither installs nor certifies a sandbox.
    let context = ExecutorContext {
        os: std::env::consts::OS,
        workspace: &policy.workspace,
        cwd: &policy.cwd,
        fixed_destinations: true,
    };
    let derived = extract(&input, &policy.profile, &context);
    if !derived.complete() || derived.resources != admission.resources {
        return Err("native_resource_argument_mismatch");
    }
    if derived
        .resources
        .iter()
        .any(|evidence| !policy.allowed_resources.contains(&evidence.resource))
    {
        return Err("native_resource_not_allowed");
    }
    Ok(())
}
