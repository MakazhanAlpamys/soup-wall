// SPDX-License-Identifier: Apache-2.0
//! Conservative SOU-12 extraction from validated invocation arguments.
//! Operator-reviewed selectors are separate from untrusted tool metadata.
//! Results are evidence, never grants; execution-time confinement is still required.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::admission::Invocation;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Path,
    Url,
    Domain,
    Recipient,
}

/// Reviewed aliases denote the same destination, not additional destinations.
/// Use multiple selectors or an array for multiple independent recipients.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub pointer: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub allow_missing_leaf: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfile {
    pub server_id: String,
    pub tool_name: String,
    pub schema_sha256: String,
    pub selectors: Vec<Selector>,
}

/// Supplied by the selected executor, never taken from arguments or metadata.
/// `fixed_destinations` means the reviewed executor cannot follow redirects or
/// choose an additional destination. It is a prerequisite, not an enforcement switch.
pub struct ExecutorContext<'a> {
    pub os: &'a str,
    pub workspace: &'a Path,
    pub cwd: &'a Path,
    pub fixed_destinations: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Path {
        canonical: String,
    },
    Url {
        canonical: String,
        host: String,
        port: u16,
    },
    Domain {
        host: String,
    },
    Recipient {
        address: String,
        domain: String,
    },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Argument,
    ReviewedDefault,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourceEvidence {
    pub pointer: String,
    pub source: EvidenceSource,
    pub resource: Resource,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExtractionIssue {
    pub pointer: String,
    pub reason: &'static str,
}

/// May contain partial evidence plus issues. Consumers must check completeness.
/// Raw destinations can be sensitive: do not place this object in public audit logs.
#[derive(Debug, Serialize)]
pub struct Extraction {
    pub server_id: String,
    pub tool_name: String,
    pub schema_sha256: String,
    pub args_sha256: String,
    pub profile_sha256: String,
    pub snapshot_sha256: String,
    pub executor_sha256: String,
    pub resources: Vec<ResourceEvidence>,
    pub issues: Vec<ExtractionIssue>,
    pub omitted_optional: Vec<String>,
}

impl Extraction {
    pub fn complete(&self) -> bool {
        self.issues.is_empty() && !self.resources.is_empty()
    }

    /// Projection for the existing host allowlist check, not a complete policy
    /// decision. Full URL/port and recipient restrictions still need the typed
    /// resources. Paths and incomplete extraction cannot use this projection.
    pub fn hosts_for_policy(&self) -> Result<Vec<String>, &'static str> {
        if !self.complete() {
            return Err("resource_extraction_incomplete");
        }
        let mut hosts = BTreeSet::new();
        for evidence in &self.resources {
            let host = match &evidence.resource {
                Resource::Url { host, .. } | Resource::Domain { host } => host,
                Resource::Recipient { domain, .. } => domain,
                Resource::Path { .. } => return Err("resource_path_policy_binding_unsupported"),
            };
            hosts.insert(host.clone());
        }
        Ok(hosts.into_iter().collect())
    }
}

pub fn valid_pointer(value: &str) -> bool {
    if !value.starts_with('/') || value.len() > 256 || value.chars().any(char::is_control) {
        return false;
    }
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

fn bounded_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control)
}

pub(crate) fn selected<'a>(
    args: &'a Value,
    pointer: &str,
) -> Result<Option<&'a Value>, &'static str> {
    let mut current = args;
    for part in pointer[1..].split('/') {
        let key = part.replace("~1", "/").replace("~0", "~");
        let next = match current {
            Value::Object(map) => map.get(&key),
            Value::Array(items) => {
                let index = key
                    .parse::<usize>()
                    .map_err(|_| "resource_pointer_ambiguous")?;
                if index.to_string() != key {
                    return Err("resource_pointer_ambiguous");
                }
                items.get(index)
            }
            _ => return Err("resource_container_type"),
        };
        match next {
            Some(value) => current = value,
            None => return Ok(None),
        }
    }
    Ok(Some(current))
}

/// Shared by legacy native egress extraction and the typed resource profile.
pub fn canonical_url(text: &str) -> Result<(String, String, u16), &'static str> {
    let (scheme, rest) = text.split_once("://").ok_or("resource_url_unsupported")?;
    if !bounded_text(text)
        || text.chars().any(char::is_whitespace)
        || text.contains('\\')
        || !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || rest.starts_with(['/', '?', '#'])
    {
        return Err("resource_url_unsupported");
    }
    let url = reqwest::Url::parse(text).map_err(|_| "resource_url_invalid")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("resource_url_credentials");
    }
    let host = url
        .host_str()
        .ok_or("resource_url_host_missing")?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let host = if host.parse::<std::net::IpAddr>().is_ok() {
        host
    } else {
        canonical_domain(&host)?
    };
    Ok((
        url.to_string(),
        host,
        url.port_or_known_default()
            .ok_or("resource_url_port_missing")?,
    ))
}

fn canonical_domain(text: &str) -> Result<String, &'static str> {
    let domain = text.strip_suffix('.').unwrap_or(text);
    if !bounded_text(domain)
        || domain.len() > 253
        || domain.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        || !domain.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("resource_domain_invalid");
    }
    Ok(domain.to_ascii_lowercase())
}

pub fn canonical_recipient(text: &str) -> Result<(String, String), &'static str> {
    if !bounded_text(text) || text.ends_with('.') {
        return Err("resource_recipient_invalid");
    }
    let (local, domain) = text.rsplit_once('@').ok_or("resource_recipient_invalid")?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&c))
    {
        return Err("resource_recipient_unsupported");
    }
    let domain = canonical_domain(domain)?;
    Ok((format!("{local}@{domain}"), domain))
}

fn no_links(path: &Path, missing_leaf: bool) -> Result<(), &'static str> {
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(value) => value,
            Err(error)
                if index == 0 && missing_leaf && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue
            }
            Err(_) => return Err("resource_path_unavailable"),
        };
        if metadata.file_type().is_symlink() {
            return Err("resource_path_link");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("resource_path_reparse_point");
            }
        }
    }
    Ok(())
}

fn canonical_path(
    text: &str,
    allow_missing: bool,
    executor: &ExecutorContext<'_>,
) -> Result<String, &'static str> {
    if executor.os != std::env::consts::OS {
        return Err("resource_executor_os_unsupported");
    }
    if !bounded_text(text) || text.contains('*') || text.contains('?') {
        return Err("resource_path_unsupported");
    }
    // Reject foreign/ambiguous path syntaxes instead of interpreting them on this host.
    #[cfg(not(windows))]
    if text.contains('\\') || text.contains(':') {
        return Err("resource_path_syntax_unsupported");
    }
    #[cfg(windows)]
    {
        if text.starts_with("\\\\") || text.starts_with("//") {
            return Err("resource_path_syntax_unsupported");
        }
        for (index, part) in text.split(['/', '\\']).enumerate() {
            if index == 0
                && part.len() == 2
                && part.as_bytes()[0].is_ascii_alphabetic()
                && part.ends_with(':')
            {
                continue;
            }
            let device = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            if part.contains(':')
                || (part != "." && (part.ends_with('.') || part.ends_with(' ')))
                || matches!(device.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || [
                    "CONIN$",
                    "CONOUT$",
                    "COM\u{b9}",
                    "COM\u{b2}",
                    "COM\u{b3}",
                    "LPT\u{b9}",
                    "LPT\u{b2}",
                    "LPT\u{b3}",
                ]
                .contains(&device.as_str())
                || (device.len() == 4
                    && (device.starts_with("COM") || device.starts_with("LPT"))
                    && device.as_bytes()[3].is_ascii_digit())
            {
                return Err("resource_path_syntax_unsupported");
            }
        }
    }
    let requested = Path::new(text);
    if requested
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("resource_path_traversal");
    }
    if !executor.workspace.is_absolute() || !executor.cwd.is_absolute() {
        return Err("resource_executor_context_invalid");
    }
    #[cfg(windows)]
    for path in [executor.workspace, executor.cwd] {
        if path.components().any(|c| matches!(c, Component::Prefix(prefix)
            if !matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))) {
            return Err("resource_executor_context_unsupported");
        }
    }
    no_links(executor.workspace, false)?;
    no_links(executor.cwd, false)?;
    let root = executor
        .workspace
        .canonicalize()
        .map_err(|_| "resource_workspace_unavailable")?;
    let cwd = executor
        .cwd
        .canonicalize()
        .map_err(|_| "resource_cwd_unavailable")?;
    if !root.is_dir() || root.parent().is_none() || !cwd.is_dir() || !cwd.starts_with(&root) {
        return Err("resource_executor_context_invalid");
    }
    if requested.has_root() != requested.is_absolute() {
        return Err("resource_path_syntax_unsupported");
    }
    #[cfg(windows)]
    if requested
        .components()
        .any(|c| matches!(c, Component::Prefix(_)))
        && !requested.is_absolute()
    {
        return Err("resource_path_syntax_unsupported");
    }
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        cwd.join(requested)
    };
    no_links(&candidate, allow_missing)?;
    let resolved = if candidate.exists() {
        let metadata = std::fs::metadata(&candidate).map_err(|_| "resource_path_unavailable")?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err("resource_path_special_file");
        }
        candidate
            .canonicalize()
            .map_err(|_| "resource_path_unavailable")?
    } else {
        let parent = candidate
            .parent()
            .ok_or("resource_path_unavailable")?
            .canonicalize()
            .map_err(|_| "resource_path_unavailable")?;
        parent.join(candidate.file_name().ok_or("resource_path_unavailable")?)
    };
    if !resolved.starts_with(&root) {
        return Err("resource_path_outside_workspace");
    }
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or("resource_path_encoding_unsupported")
}

fn resources(
    value: &Value,
    selector: &Selector,
    executor: &ExecutorContext<'_>,
) -> Result<Vec<Resource>, &'static str> {
    let values = match value {
        Value::String(_) => vec![value],
        Value::Array(items) if !items.is_empty() && items.len() <= 256 => items.iter().collect(),
        _ => return Err("resource_value_missing_or_unsupported"),
    };
    if selector.kind != ResourceKind::Path && !executor.fixed_destinations {
        return Err("resource_destination_control_unsupported");
    }
    values
        .into_iter()
        .map(|value| {
            let text = value.as_str().ok_or("resource_value_type")?;
            match selector.kind {
                ResourceKind::Path => canonical_path(text, selector.allow_missing_leaf, executor)
                    .map(|canonical| Resource::Path { canonical }),
                ResourceKind::Url => {
                    canonical_url(text).map(|(canonical, host, port)| Resource::Url {
                        canonical,
                        host,
                        port,
                    })
                }
                ResourceKind::Domain => {
                    canonical_domain(text).map(|host| Resource::Domain { host })
                }
                ResourceKind::Recipient => canonical_recipient(text)
                    .map(|(address, domain)| Resource::Recipient { address, domain }),
            }
        })
        .collect()
}

/// Reads only reviewed pointers from original arguments. Schema defaults,
/// descriptions, predictions and arbitrary nested strings never select resources.
pub fn extract(
    invocation: &Invocation,
    profile: &ResourceProfile,
    executor: &ExecutorContext<'_>,
) -> Extraction {
    let mut output = Extraction {
        server_id: invocation.server_id.clone(),
        tool_name: invocation.tool.clone(),
        schema_sha256: invocation.schema_sha256.clone(),
        snapshot_sha256: invocation.snapshot_sha256.clone(),
        executor_sha256: format!("{:x}", Sha256::digest(serde_json::json!({
            "profile":"sou12-local-v1", "os":executor.os,
            "workspace":executor.workspace.as_os_str().as_encoded_bytes(),
            "cwd":executor.cwd.as_os_str().as_encoded_bytes(), "fixed_destinations":executor.fixed_destinations
        }).to_string().as_bytes())),
        args_sha256: format!(
            "{:x}",
            Sha256::digest(invocation.args.to_string().as_bytes())
        ),
        profile_sha256: format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_value(profile)
                    .expect("profile serializes")
                    .to_string()
                    .as_bytes()
            )
        ),
        resources: vec![],
        issues: vec![],
        omitted_optional: vec![],
    };
    let issue = |pointer: &str, reason| ExtractionIssue {
        pointer: pointer.into(),
        reason,
    };
    if profile.server_id.is_empty()
        || profile.tool_name.is_empty()
        || !crate::native::is_digest(&profile.schema_sha256)
        || profile.server_id != invocation.server_id
        || profile.tool_name != invocation.tool
        || profile.schema_sha256 != invocation.schema_sha256
    {
        output
            .issues
            .push(issue("", "resource_profile_identity_mismatch"));
        return output;
    }
    if !invocation.args.is_object()
        || invocation.args.to_string().len() > crate::native::MAX_CONTENT
        || serde_json::to_vec(profile)
            .expect("profile serializes")
            .len()
            > 65536
        || profile.selectors.is_empty()
        || profile.selectors.len() > 32
    {
        output
            .issues
            .push(issue("", "resource_profile_or_arguments_unsupported"));
        return output;
    }
    let mut seen = BTreeSet::new();
    for selector in &profile.selectors {
        let pointers: Vec<&String> = std::iter::once(&selector.pointer)
            .chain(selector.aliases.iter())
            .collect();
        if pointers.len() > 8
            || pointers
                .iter()
                .any(|p| !valid_pointer(p) || !seen.insert((*p).clone()))
            || (selector.allow_missing_leaf && selector.kind != ResourceKind::Path)
        {
            output
                .issues
                .push(issue(&selector.pointer, "resource_selector_invalid"));
            continue;
        }
        let mut supplied = vec![];
        let mut malformed = false;
        for pointer in &pointers {
            match selected(&invocation.args, pointer) {
                Ok(Some(value)) => {
                    supplied.push((pointer.as_str(), value, EvidenceSource::Argument))
                }
                Ok(None) => {}
                Err(reason) => {
                    output.issues.push(issue(pointer, reason));
                    malformed = true;
                }
            }
        }
        if malformed {
            continue;
        }
        if supplied.is_empty() {
            if let Some(default) = &selector.default {
                supplied.push((&selector.pointer, default, EvidenceSource::ReviewedDefault));
            } else if selector.optional {
                output.omitted_optional.push(selector.pointer.clone());
                continue;
            } else {
                output
                    .issues
                    .push(issue(&selector.pointer, "resource_missing"));
                continue;
            }
        }
        let mut selected = None;
        let mut pending = vec![];
        for (pointer, value, source) in supplied {
            match resources(value, selector, executor) {
                Err(reason) => output.issues.push(issue(pointer, reason)),
                Ok(values) => {
                    if selected
                        .as_ref()
                        .is_some_and(|previous| previous != &values)
                    {
                        output
                            .issues
                            .push(issue(pointer, "resource_conflicting_fields"));
                    }
                    selected = Some(values.clone());
                    pending.extend(values.into_iter().map(|resource| ResourceEvidence {
                        pointer: pointer.into(),
                        source: source.clone(),
                        resource,
                    }));
                }
            }
        }
        output.resources.extend(pending);
    }
    if output.resources.is_empty() && output.issues.is_empty() {
        output.issues.push(issue("", "resource_no_destinations"));
    }
    output
}
