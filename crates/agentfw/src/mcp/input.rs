// SPDX-License-Identifier: Apache-2.0
//! Bounded SOU-11 input profile. Validation never applies defaults, coerces
//! arguments, follows references, launches commands or grants permissions.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context};
use serde::Serialize;
use serde_json::Value;

pub const MAX_DEPTH: usize = 8;
pub const MAX_ITEMS: usize = 256;
pub const MAX_SCHEMA_NODES: usize = 1024;

#[derive(Debug)]
enum Shape {
    Object(BTreeMap<String, InputSchema>, BTreeSet<String>),
    Array(Box<InputSchema>),
    String,
    Integer,
    Number,
    Boolean,
    Null,
}

/// Deliberately smaller than general JSON Schema. Unknown keywords are errors.
/// The original schema remains in the discovery snapshot, not in this validator.
#[derive(Debug)]
pub struct InputSchema(Shape);

impl InputSchema {
    pub fn read(value: &Value) -> anyhow::Result<Self> {
        ensure!(
            value["type"] == "object",
            "MCP input profile requires an object"
        );
        Self::node(value, 0, &mut 0)
    }

    fn node(value: &Value, depth: usize, nodes: &mut usize) -> anyhow::Result<Self> {
        *nodes += 1;
        ensure!(
            depth <= MAX_DEPTH && *nodes <= MAX_SCHEMA_NODES,
            "MCP schema exceeds profile limits"
        );
        let map = value.as_object().context("MCP schema must be an object")?;
        let kind = value["type"].as_str().context("MCP schema type missing")?;
        for key in map.keys() {
            let supported = matches!(key.as_str(), "type" | "title" | "description" | "default")
                || (kind == "object"
                    && matches!(
                        key.as_str(),
                        "properties" | "required" | "additionalProperties"
                    ))
                || (kind == "array" && key == "items");
            ensure!(supported, "unsupported MCP schema keyword");
        }
        for key in ["title", "description"] {
            ensure!(
                map.get(key).is_none_or(Value::is_string),
                "invalid MCP schema annotation"
            );
        }
        let shape = match kind {
            "object" => {
                ensure!(
                    value["additionalProperties"] == false,
                    "MCP objects must explicitly be closed"
                );
                let properties = value["properties"]
                    .as_object()
                    .context("MCP properties missing")?;
                ensure!(properties.len() <= MAX_ITEMS, "too many MCP properties");
                let mut fields = BTreeMap::new();
                for (name, schema) in properties {
                    fields.insert(name.clone(), Self::node(schema, depth + 1, nodes)?);
                }
                let mut required = BTreeSet::new();
                if let Some(value) = map.get("required") {
                    for field in value.as_array().context("invalid MCP required fields")? {
                        let name = field.as_str().context("invalid MCP required field")?;
                        ensure!(
                            fields.contains_key(name) && required.insert(name.to_owned()),
                            "unknown or duplicate MCP required field"
                        );
                    }
                }
                Shape::Object(fields, required)
            }
            "array" => Shape::Array(Box::new(Self::node(
                value.get("items").context("MCP array items missing")?,
                depth + 1,
                nodes,
            )?)),
            "string" => Shape::String,
            "integer" => Shape::Integer,
            "number" => Shape::Number,
            "boolean" => Shape::Boolean,
            "null" => Shape::Null,
            _ => bail!("unsupported MCP schema type"),
        };
        // `default` is preserved as metadata only. It never fills an absent
        // field; resource defaults require separately reviewed semantics.
        Ok(Self(shape))
    }

    pub fn validate(&self, value: &Value) -> anyhow::Result<()> {
        self.check(value, 0, &mut 0)
    }

    fn check(&self, value: &Value, depth: usize, nodes: &mut usize) -> anyhow::Result<()> {
        *nodes += 1;
        ensure!(
            depth <= MAX_DEPTH && *nodes <= 4096,
            "MCP arguments exceed profile limits"
        );
        let valid = match &self.0 {
            Shape::Object(fields, required) => {
                let args = value
                    .as_object()
                    .context("MCP arguments must match object schema")?;
                ensure!(
                    required.iter().all(|key| args.contains_key(key)),
                    "MCP required argument missing"
                );
                ensure!(args.len() <= MAX_ITEMS, "too many MCP arguments");
                for (key, value) in args {
                    fields.get(key).context("unknown MCP argument")?.check(
                        value,
                        depth + 1,
                        nodes,
                    )?;
                }
                true
            }
            Shape::Array(items) => {
                let args = value
                    .as_array()
                    .context("MCP arguments must match array schema")?;
                ensure!(args.len() <= MAX_ITEMS, "too many MCP array elements");
                for value in args {
                    items.check(value, depth + 1, nodes)?;
                }
                true
            }
            Shape::String => value.as_str().is_some_and(|s| s.len() <= 16 * 1024),
            Shape::Integer => value.is_i64() || value.is_u64(),
            Shape::Number => value.as_f64().is_some_and(f64::is_finite),
            Shape::Boolean => value.is_boolean(),
            Shape::Null => value.is_null(),
        };
        ensure!(valid, "MCP argument type or size mismatch");
        Ok(())
    }
}

/// Redacted inventory only. No command, argument, environment value, URL or
/// header is exported; configuration inspection never starts a connection.
#[derive(Debug, Serialize)]
pub struct HostServerSummary {
    pub name: String,
    pub transport: &'static str,
    pub supported: bool,
    pub requires_explicit_selection: bool,
}

/// Supports a selected Claude-style JSON file's `mcpServers` map. Other host
/// formats are explicitly outside this profile. Errors omit source contents.
pub fn inspect_host_config(bytes: &[u8]) -> anyhow::Result<Vec<HostServerSummary>> {
    ensure!(
        bytes.len() <= 1024 * 1024,
        "MCP host configuration exceeds limit"
    );
    let super::admission::Strict(value) = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid MCP host configuration JSON"))?;
    let servers = value
        .get("mcpServers")
        .and_then(Value::as_object)
        .context("unsupported MCP host configuration format")?;
    ensure!(
        servers.len() <= MAX_ITEMS,
        "too many configured MCP servers"
    );
    servers
        .iter()
        .map(|(name, entry)| {
            ensure!(
                !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
                "invalid configured MCP server name"
            );
            let map = entry
                .as_object()
                .context("invalid MCP server configuration")?;
            let local = map.get("type").is_none_or(|kind| kind == "stdio")
                && !map.contains_key("url")
                && map
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                && map.get("args").is_none_or(|args| {
                    args.as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string))
                });
            Ok(HostServerSummary {
                name: name.clone(),
                transport: if local { "stdio" } else { "unsupported" },
                supported: local,
                requires_explicit_selection: true,
            })
        })
        .collect()
}
