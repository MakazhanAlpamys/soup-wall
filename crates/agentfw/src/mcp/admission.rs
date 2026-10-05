// SPDX-License-Identifier: Apache-2.0
//! Explicit, bounded stdio MCP admission. This collector owns server forwarding;
//! `mcp_host` release is not attestation of the host's eventual model context.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use futures_util::StreamExt;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::native::{NativeState, CONTRACT, MAX_CONTENT};

const MAX_REQUESTS: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AdmissionCfg {
    pub daemon_url: String,
    pub manifest_url: String,
    pub manifest_token: String,
    pub server_id: String,
    pub native: NativeState,
    pub command: String,
    pub args: Vec<String>,
}

struct InputSchema(BTreeSet<String>);

impl InputSchema {
    fn read(value: &Value) -> anyhow::Result<Self> {
        keys(
            value,
            &["type", "properties", "required", "additionalProperties"],
        )?;
        ensure!(
            value["type"] == "object" && value["additionalProperties"] == false,
            "unsupported MCP input schema"
        );
        let properties = value["properties"]
            .as_object()
            .context("MCP string properties absent")?;
        let mut names = BTreeSet::new();
        for (name, schema) in properties {
            keys(schema, &["type"])?;
            ensure!(
                schema["type"] == "string",
                "only required string MCP arguments are supported"
            );
            names.insert(name.clone());
        }
        let mut required = BTreeSet::new();
        if let Some(fields) = value.get("required") {
            for field in fields.as_array().context("invalid MCP required fields")? {
                let field = field.as_str().context("invalid MCP required field")?;
                ensure!(
                    required.insert(field.to_string()),
                    "duplicate MCP required field"
                );
            }
        }
        ensure!(
            required == names,
            "MCP argument defaults and optional fields are unsupported"
        );
        Ok(Self(names))
    }

    fn validate(&self, args: &Value) -> anyhow::Result<()> {
        let arguments = args
            .as_object()
            .context("MCP arguments must be an object")?;
        ensure!(
            arguments.len() == self.0.len()
                && arguments
                    .iter()
                    .all(|(name, value)| self.0.contains(name) && value.is_string()),
            "MCP arguments differ from the reviewed string schema"
        );
        Ok(())
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => serde_json::to_value(
            map.iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("JSON values serialize"),
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

// JSON-RPC ids and arguments cannot acquire different meanings in different parsers.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Strict;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("unambiguous JSON")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(value.into())))
            }
            fn visit_string<E>(self, value: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse(raw: &[u8]) -> anyhow::Result<Value> {
    let Strict(value) = serde_json::from_slice(raw).context("unsupported or malformed MCP JSON")?;
    ensure!(
        value.is_object() && value["jsonrpc"] == "2.0",
        "unsupported MCP envelope"
    );
    Ok(value)
}

fn keys(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|map| map.keys().all(|key| allowed.contains(&key.as_str()))),
        "unsupported MCP fields"
    );
    Ok(())
}

fn id(value: &Value) -> anyhow::Result<String> {
    ensure!(
        value
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            || value.as_i64().is_some(),
        "unsupported MCP request id"
    );
    Ok(value.to_string())
}

// The retained partial frame makes select cancellation safe: consumed bytes survive.
async fn line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    raw: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            ensure!(raw.is_empty(), "unterminated MCP frame");
            return Ok(None);
        }
        let end = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        ensure!(
            raw.len() + end <= MAX_CONTENT,
            "MCP frame exceeds admission limit"
        );
        raw.extend_from_slice(&buffer[..end]);
        let complete = buffer[end - 1] == b'\n';
        reader.consume(end);
        if complete {
            return Ok(Some(std::mem::take(raw)));
        }
    }
}

async fn write<W: AsyncWrite + Unpin>(output: &mut W, raw: &[u8]) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        output.write_all(raw).await?;
        output.flush().await
    })
    .await
    .context("MCP stdio write timed out")??;
    Ok(())
}

struct Collector<'a> {
    config: &'a AdmissionCfg,
    client: reqwest::Client,
    session: String,
}

impl<'a> Collector<'a> {
    fn new(config: &'a AdmissionCfg) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            session: format!("mcp:{}", crate::token::generate()),
        })
    }

    async fn post(&self, url: &str, token: &str, body: &Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .context("MCP admission unavailable")?;
        ensure!(
            response.status().is_success(),
            "MCP admission request rejected"
        );
        let mut bytes = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            ensure!(
                bytes.len() + chunk.len() <= 16 * 1024,
                "MCP admission response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let Strict(reply) =
            serde_json::from_slice(&bytes).context("malformed MCP admission receipt")?;
        Ok(reply)
    }

    async fn inspect_manifest(&self, value: &Value) -> anyhow::Result<()> {
        let tools = value["tools"].as_array().context("MCP manifest absent")?.iter().map(|tool| json!({"name":tool["name"],"description":tool.get("description").cloned().unwrap_or_else(|| Value::String(String::new())),"schema":tool["inputSchema"]})).collect::<Vec<_>>();
        let reply = self
            .post(
                &self.config.manifest_url,
                &self.config.manifest_token,
                &json!({"server":self.config.server_id,"tools":tools}),
            )
            .await?;
        keys(&reply, &["verdict", "enforce", "reason"])?;
        ensure!(
            reply.as_object().is_some_and(|map| map.len() == 3)
                && reply["verdict"] == "allow"
                && reply["enforce"] == true
                && (reply["reason"].is_null()
                    || reply["reason"].as_str().is_some_and(|s| s.len() <= 8192)),
            "MCP manifest was not admitted in enforcement mode"
        );
        Ok(())
    }

    async fn event(&self, event: &str, fields: Value) -> anyhow::Result<Value> {
        let mut body = json!({"contract_version":CONTRACT,"registry_sha256":self.config.native.registry_sha256,"session_id":self.session,"event":event});
        body.as_object_mut().expect("object").extend(
            fields
                .as_object()
                .context("invalid admission event")?
                .iter()
                .filter(|(key, _)| key.as_str() != "expected_binding_sha256")
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let reply = self
            .post(&self.config.daemon_url, &self.config.native.token, &body)
            .await?;
        let expected = [
            "contract_version",
            "registry_sha256",
            "session_id",
            "event",
            "verdict",
            "enforced",
            "release",
            "call_id",
            "binding_sha256",
            "content_sha256",
            "reason_codes",
        ];
        keys(&reply, &expected)?;
        ensure!(
            reply
                .as_object()
                .is_some_and(|map| map.len() == expected.len())
                && reply["contract_version"] == CONTRACT
                && reply["registry_sha256"] == self.config.native.registry_sha256
                && reply["session_id"] == self.session
                && reply["event"] == event
                && reply["enforced"] == true,
            "MCP admission receipt identity mismatch"
        );
        let verdict = reply["verdict"]
            .as_str()
            .context("MCP admission verdict absent")?;
        ensure!(
            matches!(verdict, "allow" | "ask" | "deny")
                && reply["release"].as_bool() == Some(verdict == "allow"),
            "inconsistent MCP admission verdict"
        );
        ensure!(
            reply["reason_codes"]
                .as_array()
                .is_some_and(|codes| codes.len() <= 256
                    && codes
                        .iter()
                        .all(|v| v.as_str().is_some_and(|s| s.len() <= 256))),
            "malformed MCP admission reasons"
        );
        if event == "call" {
            if verdict == "allow" {
                ensure!(
                    reply["call_id"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 128)
                        && reply["binding_sha256"]
                            .as_str()
                            .is_some_and(crate::native::is_digest),
                    "MCP admission invocation binding absent"
                );
            } else {
                ensure!(
                    reply["call_id"].is_null() && reply["binding_sha256"].is_null(),
                    "withheld MCP call acquired binding"
                );
            }
            ensure!(
                reply["content_sha256"].is_null(),
                "unexpected MCP call content hash"
            );
        } else if event == "result" {
            ensure!(
                reply["call_id"] == fields["call_id"]
                    && reply["binding_sha256"] == fields["expected_binding_sha256"],
                "MCP result receipt changed invocation"
            );
            ensure!(
                reply["content_sha256"]
                    == sha(fields["content"]
                        .as_str()
                        .context("MCP result content missing")?
                        .as_bytes()),
                "MCP result receipt changed content"
            );
        } else {
            ensure!(
                verdict == "allow"
                    && reply["call_id"].is_null()
                    && reply["binding_sha256"].is_null()
                    && reply["content_sha256"].is_null(),
                "MCP session receipt rejected"
            );
        }
        Ok(reply)
    }
}

enum Pending {
    Handshake(Value),
    Manifest(Value),
    Ping(Value),
    Call {
        id: Value,
        tool: String,
        args: Value,
        call_id: Value,
        binding: Value,
    },
}

impl Pending {
    fn id(&self) -> &Value {
        match self {
            Self::Handshake(id) | Self::Manifest(id) | Self::Ping(id) | Self::Call { id, .. } => id,
        }
    }
}

fn manifest(value: &Value, native: &NativeState) -> anyhow::Result<BTreeMap<String, InputSchema>> {
    keys(value, &["tools"])?;
    let tools = value["tools"]
        .as_array()
        .context("MCP manifest tools absent")?;
    ensure!(
        tools.len() == native.registry.tools.len(),
        "MCP manifest coverage mismatch"
    );
    let mut seen = BTreeSet::new();
    let mut schemas: BTreeMap<String, InputSchema> = BTreeMap::new();
    for tool in tools {
        keys(tool, &["name", "description", "inputSchema"])?;
        let name = tool["name"]
            .as_str()
            .context("MCP manifest tool name absent")?;
        ensure!(seen.insert(name), "duplicate MCP manifest tool");
        ensure!(
            tool.get("description").is_none_or(Value::is_string),
            "unsupported MCP tool description"
        );
        let installed = native
            .registry
            .tools
            .iter()
            .find(|t| t.name == name)
            .context("MCP tool is not installed by operator")?;
        ensure!(
            tool["inputSchema"].is_object()
                && sha(canonical(&tool["inputSchema"]).to_string().as_bytes())
                    == installed.schema_sha256,
            "MCP tool schema differs from operator pin"
        );
        schemas.insert(name.into(), InputSchema::read(&tool["inputSchema"])?);
    }
    Ok(schemas)
}

fn initialization(value: &Value) -> anyhow::Result<()> {
    keys(value, &["protocolVersion", "capabilities", "serverInfo"])?;
    ensure!(
        value["protocolVersion"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control)),
        "unsupported MCP protocol version"
    );
    keys(&value["capabilities"], &["tools"])?;
    if let Some(tools) = value["capabilities"].get("tools") {
        keys(tools, &["listChanged"])?;
        ensure!(
            tools.get("listChanged").is_none_or(|v| v == false),
            "MCP manifest change notifications are unsupported"
        );
    }
    keys(&value["serverInfo"], &["name", "version"])?;
    for field in ["name", "version"] {
        ensure!(
            value["serverInfo"][field]
                .as_str()
                .is_some_and(|s| !s.is_empty()
                    && s.len() <= 128
                    && !s.chars().any(char::is_control)),
            "unsupported MCP server identity"
        );
    }
    Ok(())
}

/// The observed Claude Code pair is host correlation only. It never supplies
/// native arguments, registry semantics, an approval, or result provenance.
fn call_metadata(value: &Value) -> anyhow::Result<()> {
    keys(value, &["claudecode/toolUseId", "progressToken"])?;
    ensure!(
        value.as_object().is_some_and(|map| map.len() == 2)
            && value["claudecode/toolUseId"].as_str().is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            })
            // The selected host uses JavaScript numbers; keep correlation tokens
            // integral and exactly representable across both JSON consumers.
            && value["progressToken"].as_u64().is_some_and(|token| token <= 9_007_199_254_740_991),
        "unsupported MCP call correlation metadata"
    );
    Ok(())
}

fn result_kind(value: &Value) -> anyhow::Result<&'static str> {
    if let Some(error) = value.get("error") {
        ensure!(
            value.get("result").is_none(),
            "ambiguous MCP result and error"
        );
        keys(error, &["code", "message"])?;
        ensure!(
            error["code"].as_i64().is_some() && error["message"].is_string(),
            "unsupported MCP error"
        );
        return Ok("error");
    }
    let result = value.get("result").context("MCP result absent")?;
    keys(result, &["content", "isError"])?;
    ensure!(
        result.get("isError").is_none_or(Value::is_boolean),
        "unsupported MCP isError"
    );
    let blocks = result["content"].as_array().context("MCP content absent")?;
    ensure!(blocks.len() <= 256, "MCP content block limit");
    for block in blocks {
        keys(block, &["type", "text"])?;
        ensure!(
            block["type"] == "text" && block["text"].is_string(),
            "unsupported non-text MCP content"
        );
    }
    Ok(if result["isError"] == true {
        "error"
    } else {
        "value"
    })
}

fn withheld(id: &Value, phase: &str, reasons: &Value) -> Vec<u8> {
    let reason = reasons
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!("Soup Wall withheld MCP {phase} ({reason})");
    let mut raw = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":message}],"isError":true}}).to_string().into_bytes();
    raw.push(b'\n');
    raw
}

async fn relay<R, W, S, T>(
    collector: &Collector<'_>,
    client: &mut R,
    host: &mut W,
    server: &mut S,
    child: &mut T,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncBufRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let mut pending: Option<Pending> = None;
    let mut initialized = false;
    let mut notified = false;
    let mut ready = false;
    let mut schemas: BTreeMap<String, InputSchema> = BTreeMap::new();
    let mut used = BTreeSet::new();
    let mut client_partial = Vec::new();
    let mut server_partial = Vec::new();
    let mut deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        tokio::select! {
            raw = line(client, &mut client_partial) => {
                let Some(raw) = raw? else { ensure!(pending.is_none(), "MCP client closed with an outstanding request"); return Ok(()); };
                let value = parse(&raw)?;
                keys(&value, &["jsonrpc","id","method","params"])?;
                let method = value["method"].as_str().context("unsupported MCP client message")?;
                if method == "notifications/initialized" {
                    ensure!(initialized && !notified && pending.is_none() && value.get("id").is_none(), "unsupported initialized notification");
                    if let Some(params) = value.get("params") { keys(params, &[])?; }
                    notified = true;
                    write(child, &raw).await?;
                    continue;
                }
                ensure!(pending.is_none(), "concurrent MCP requests are not supported");
                let request_id = value.get("id").context("unsupported MCP notification")?;
                ensure!(used.len() < MAX_REQUESTS && used.insert(id(request_id)?), "replayed MCP request or session request limit");
                let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
                ensure!(params.is_object(), "unsupported MCP parameters");
                let next = match method {
                    "initialize" => { ensure!(!initialized, "MCP session already initialized"); Pending::Handshake(request_id.clone()) }
                    "tools/list" => { ensure!(initialized, "MCP manifest before initialization"); keys(&params, &[])?; Pending::Manifest(request_id.clone()) }
                    "ping" => { keys(&params, &[])?; Pending::Ping(request_id.clone()) }
                    "tools/call" => {
                        ensure!(ready, "MCP call before operator-pinned manifest");
                        keys(&params, &["name","arguments","_meta"])?;
                        if let Some(metadata) = params.get("_meta") { call_metadata(metadata)?; }
                        let name = params["name"].as_str().context("MCP call tool absent")?;
                        let installed = collector.config.native.registry.tools.iter().find(|tool| tool.name == name).context("MCP call tool is not installed")?;
                        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                        ensure!(args.is_object(), "MCP call arguments must be an object");
                        schemas.get(name).context("MCP tool schema not installed")?.validate(&args)?;
                        let receipt = collector.event("call", json!({"tool":name,"args":args,"schema_sha256":installed.schema_sha256})).await?;
                        if receipt["release"] != true {
                            write(host, &withheld(request_id, "invocation", &receipt["reason_codes"])).await?;
                            continue;
                        }
                        Pending::Call { id: request_id.clone(), tool:name.into(), args, call_id:receipt["call_id"].clone(), binding:receipt["binding_sha256"].clone() }
                    }
                    _ => bail!("unsupported MCP method"),
                };
                pending = Some(next);
                deadline = tokio::time::Instant::now() + IO_TIMEOUT;
                write(child, &raw).await?;
            }
            raw = line(server, &mut server_partial) => {
                let raw = raw?.context("MCP server closed before client completion")?;
                let value = parse(&raw)?;
                keys(&value, &["jsonrpc","id","result","error"])?;
                let request = pending.take().context("unbound or replayed MCP server response")?;
                ensure!(value.get("id") == Some(request.id()), "MCP response id mismatch");
                match request {
                    Pending::Handshake(_) => {
                        ensure!(value.get("error").is_none() && value["result"].is_object(), "MCP initialization failed");
                        initialization(&value["result"])?;
                        initialized = true;
                    }
                    Pending::Manifest(_) => {
                        ensure!(value.get("error").is_none(), "MCP tools/list failed");
                        schemas = manifest(&value["result"], &collector.config.native)?;
                        collector.inspect_manifest(&value["result"]).await?;
                        ready = true;
                    }
                    Pending::Ping(_) => { ensure!(value.get("error").is_none(), "MCP ping failed"); keys(&value["result"], &[])?; }
                    Pending::Call { id, tool, args, call_id, binding } => {
                        let kind = result_kind(&value)?;
                        let content = std::str::from_utf8(&raw).context("MCP result is not UTF-8")?;
                        let receipt = collector.event("result", json!({"tool":tool,"args":args,"call_id":call_id,"result_kind":kind,"delivery":"mcp_host","content":content,"expected_binding_sha256":binding})).await?;
                        if receipt["release"] != true {
                            write(host, &withheld(&id, "result", &receipt["reason_codes"])).await?;
                            continue;
                        }
                    }
                }
                write(host, &raw).await?;
            }
            _ = tokio::time::sleep_until(deadline), if pending.is_some() => bail!("MCP server response timed out"),
        }
    }
}

pub async fn run(config: AdmissionCfg) -> anyhow::Result<()> {
    let collector = Collector::new(&config)?;
    collector.event("session_start", json!({})).await?;
    // Fail closed before spawning the server if the native daemon cannot admit a session.
    let operation = async {
        let mut process = Command::new(&config.command)
            .args(&config.args)
            .env_remove("AGENTFW_TOKEN")
            .env_remove("AGENTFW_NATIVE_TOKEN")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut child = process
            .stdin
            .take()
            .context("MCP server stdin unavailable")?;
        let mut server = BufReader::new(
            process
                .stdout
                .take()
                .context("MCP server stdout unavailable")?,
        );
        let mut client = BufReader::new(tokio::io::stdin());
        let mut host = tokio::io::stdout();
        let outcome = relay(&collector, &mut client, &mut host, &mut server, &mut child).await;
        let _ = process.kill().await;
        outcome
    }
    .await;
    let ended = collector.event("session_end", json!({})).await;
    operation?;
    ended?;
    Ok(())
}
