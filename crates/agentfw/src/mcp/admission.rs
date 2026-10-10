// SPDX-License-Identifier: Apache-2.0
//! Explicit, bounded stdio MCP admission. This collector owns server forwarding;
//! `mcp_host` release is not attestation of the host's eventual model context.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use futures_util::StreamExt;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::input::InputSchema;
use crate::native::{NativeState, CONTRACT, MAX_CONTENT};
use soup_wall_adapter::runner::evaluate_baseline_policy;
use soup_wall_adapter::{ToolActionCategory, ToolClassification, Verdict as AdapterVerdict};
use soup_wall_agent::ActionClass;

const MAX_REQUESTS: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const CLASSIFICATION_CONTRACT: &str = "sw-classification/candidate-1";
const CLASSIFIER_TIMEOUT: Duration = Duration::from_secs(2);
// Verify and execute one immutable byte snapshot in the child, not a path
// checked by the parent and reopened after another process can replace it.
const PYTHON_CLASSIFIER_BOOTSTRAP: &str = r#"import hashlib, sys
path, expected = sys.argv[1:]
with open(path, "rb") as handle:
    source = handle.read(1024 * 1024 + 1)
if len(source) > 1024 * 1024 or hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit(78)
sys.argv = [path]
exec(compile(source, path, "exec"), {"__name__": "__main__", "__file__": path})
"#;

/// Internal classifier input. Discovery content is evidence; only the registry
/// and successful admission establish the trusted baseline.
#[derive(Clone)]
pub struct Invocation {
    pub server_id: String,
    pub host_call_id: Value,
    pub registry_sha256: String,
    pub snapshot_sha256: String,
    pub schema_sha256: String,
    pub tool: String,
    pub description: String,
    pub schema: Value,
    /// Original untrusted discovery definition, including supported annotations.
    pub definition: Value,
    /// Server-advertised identity; the operator-selected server_id is authoritative.
    pub server_info: Value,
    pub definition_sha256: String,
    /// Identity for semantic prediction reuse, never an execution grant.
    pub input_sha256: String,
    pub classifier_revision: Option<String>,
    pub args: Value,
    pub baseline: ActionClass,
}

impl Invocation {
    /// Semantic input for classifiers. Correlation and operator permissions
    /// stay on the orchestration side; server metadata is untrusted evidence.
    pub fn semantic_input(&self) -> Value {
        json!({"tool_name":self.tool,"raw_arguments":self.args,
            "tool_description":self.description,"tool_schema":self.schema,
            "server_id":self.server_id})
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Classification {
    pub actions: Vec<String>,
    pub unknown: bool,
    pub confidence: f64,
    pub uncertainty: f64,
    pub reason: String,
}

pub trait InvocationClassifier: Send + Sync {
    fn source(&self) -> &'static str;
    fn revision(&self) -> Option<&str> {
        None
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification>;
}

/// Explicit local Python adapter. Classification never grants authorization.
struct RuleBaseline {
    script: std::path::PathBuf,
    python: std::ffi::OsString,
    digest: String,
}

#[derive(Deserialize)]
struct BaselineReply {
    status: String,
    #[serde(flatten)]
    classification: Classification,
}

impl InvocationClassifier for RuleBaseline {
    fn source(&self) -> &'static str {
        "rule-baseline/python"
    }
    fn revision(&self) -> Option<&str> {
        Some(&self.digest)
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        // Do not inherit the daemon's credentials or change original MCP frames.
        let mut bytes = serde_json::to_vec(&invocation.semantic_input())?;
        ensure!(bytes.len() <= 1024 * 1024, "classifier input exceeds limit");
        bytes.push(b'\n');
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let output = runtime.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut command = Command::new(&self.python);
            command
                .arg("-I")
                .arg("-u")
                .arg("-c")
                .arg(PYTHON_CLASSIFIER_BOOTSTRAP)
                .arg(&self.script)
                .arg(&self.digest)
                .env_clear();
            // Windows Python needs its OS runtime directory; no application secrets.
            #[cfg(windows)]
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut input = child.stdin.take().context("classifier stdin missing")?;
            let output = child.stdout.take().context("classifier stdout missing")?;
            let exchange = async {
                let write = async {
                    input.write_all(&bytes).await?;
                    input.shutdown().await?;
                    drop(input);
                    Ok::<_, anyhow::Error>(())
                };
                let read = async {
                    let mut bytes = Vec::new();
                    output.take(16 * 1024 + 1).read_to_end(&mut bytes).await?;
                    ensure!(bytes.len() <= 16 * 1024, "classifier output exceeds limit");
                    Ok::<_, anyhow::Error>(bytes)
                };
                let (_, bytes) = tokio::try_join!(write, read)?;
                ensure!(child.wait().await?.success(), "classifier process failed");
                Ok::<_, anyhow::Error>(bytes)
            };
            // Reclaim the subprocess before the outer two-second admission timeout.
            let result = tokio::time::timeout(Duration::from_millis(1500), exchange).await;
            match result {
                Ok(Ok(bytes)) => Ok(bytes),
                other => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    match other {
                        Ok(Err(error)) => Err(error),
                        _ => Err(anyhow::anyhow!("classifier process timed out")),
                    }
                }
            }
        })?;
        let reply: BaselineReply =
            serde_json::from_slice(&output).context("invalid classifier output")?;
        ensure!(
            matches!(reply.status.as_str(), "ok" | "unknown"),
            "classifier returned technical error"
        );
        ensure!(
            reply.status != "unknown" || reply.classification.unknown,
            "inconsistent unknown status"
        );
        Ok(reply.classification)
    }
}

/// Select a real classifier explicitly; test doubles remain debug-only.
pub fn classifier_from_env() -> anyhow::Result<Option<Arc<dyn InvocationClassifier>>> {
    match std::env::var("AGENTFW_CLASSIFIER") {
        Err(std::env::VarError::NotPresent) => test_classifier_from_env(),
        Ok(value) if value == "rule-baseline" => {
            ensure!(
                std::env::var_os("AGENTFW_TEST_CLASSIFIER").is_none()
                    && std::env::var_os("AGENTFW_TEST_CLASSIFIER_READ").is_none(),
                "conflicting classifiers"
            );
            let script = std::env::var_os("AGENTFW_RULE_BASELINE")
                .context("AGENTFW_RULE_BASELINE must explicitly select a local script")?;
            let script = std::path::PathBuf::from(script).canonicalize()?;
            ensure!(script.is_file(), "classifier script missing");
            let mut source = Vec::new();
            use std::io::Read;
            std::fs::File::open(&script)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut source)?;
            ensure!(
                source.len() <= 1024 * 1024,
                "classifier source exceeds limit"
            );
            let digest = sha(&source);
            let python = std::env::var_os("AGENTFW_CLASSIFIER_PYTHON").unwrap_or_else(|| {
                if cfg!(windows) {
                    "python".into()
                } else {
                    "python3".into()
                }
            });
            Ok(Some(Arc::new(RuleBaseline {
                script,
                python,
                digest,
            })))
        }
        _ => bail!("unsupported classifier setting"),
    }
}

struct ReadTestDouble;

impl InvocationClassifier for ReadTestDouble {
    fn source(&self) -> &'static str {
        "test-double/read-v1"
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        ensure!(
            !invocation.server_id.is_empty()
                && !invocation.registry_sha256.is_empty()
                && !invocation.snapshot_sha256.is_empty()
                && !invocation.schema_sha256.is_empty()
                && id(&invocation.host_call_id).is_ok()
                && invocation.args.is_object()
                && invocation.schema.is_object()
                && invocation.baseline == ActionClass::ReadOnly,
            "test classifier input missing"
        );
        Ok(Classification {
            actions: vec!["read".into()],
            unknown: false,
            confidence: 1.0,
            uncertainty: 0.0,
            reason: "fixed fixture output".into(),
        })
    }
}

/// Identified test double for the seam, never classifier acceptance. It infers
/// `send_data` from URL-valued arguments rather than tool names, otherwise
/// echoes the trusted baseline, and injects faults named in argument values.
struct FixtureTestDouble;

impl InvocationClassifier for FixtureTestDouble {
    fn source(&self) -> &'static str {
        "test-double/fixture-v1"
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        let values: Vec<&str> = invocation
            .args
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, value)| value.as_str())
            .collect();
        let fault = |name: &str| {
            let marker = format!("classifier-fault-{name}");
            values.iter().any(|value| value.contains(&marker))
        };
        if fault("timeout") {
            std::thread::sleep(CLASSIFIER_TIMEOUT * 2);
        }
        assert!(!fault("crash"), "fixture classifier crash");
        let actions = if fault("unknown") {
            vec![]
        } else if fault("mixed") {
            vec!["read".into(), "send_data".into()]
        } else if fault("understate") {
            vec!["read".into()]
        } else if values
            .iter()
            .any(|value| value.starts_with("http://") || value.starts_with("https://"))
        {
            vec!["send_data".into()]
        } else {
            vec![baseline_action(invocation.baseline).into()]
        };
        Ok(Classification {
            actions,
            unknown: fault("unknown"),
            confidence: if fault("invalid") { 2.0 } else { 0.9 },
            uncertainty: 0.1,
            reason: "fixture test double".into(),
        })
    }
}

fn baseline_action(class: ActionClass) -> &'static str {
    match class {
        ActionClass::ReadOnly => "read",
        ActionClass::SideEffecting => "write",
        ActionClass::Network => "send_data",
        ActionClass::PrivilegeChanging => "change_permissions",
        ActionClass::Destructive => "delete",
    }
}

/// Candidate singleton mapping. Mixed actions and `unknown` stay unsupported
/// until Teams 1, 2 and 3 agree their policy semantics; there is no numeric maximum.
fn map_classification(result: &Classification) -> Result<ActionClass, &'static str> {
    let valid = result.confidence.is_finite()
        && (0.0..=1.0).contains(&result.confidence)
        && result.uncertainty.is_finite()
        && (0.0..=1.0).contains(&result.uncertainty)
        && !result.reason.is_empty()
        && result.reason.len() <= 1024
        && result.actions.iter().all(|action| {
            matches!(
                action.as_str(),
                "read" | "write" | "delete" | "send_data" | "change_permissions"
            )
        });
    if !valid {
        return Err("classifier_invalid");
    }
    match (result.unknown, result.actions.as_slice()) {
        (false, [action]) => Ok(match action.as_str() {
            "read" => ActionClass::ReadOnly,
            "write" => ActionClass::SideEffecting,
            "delete" => ActionClass::Destructive,
            "send_data" => ActionClass::Network,
            _ => ActionClass::PrivilegeChanging,
        }),
        _ => Err("unsupported_classification_mapping"),
    }
}

struct AdmittedTool {
    description: String,
    schema: Value,
    schema_sha256: String,
    definition: Value,
    definition_sha256: String,
}
struct Snapshot {
    sha256: String,
    tools: BTreeMap<String, AdmittedTool>,
    server_info: Value,
}

fn prediction_identity(
    server: &str,
    snapshot: &Snapshot,
    tool: &AdmittedTool,
    name: &str,
    args: &Value,
    source: &str,
    revision: Option<&str>,
) -> String {
    // Trusted profiles, policy, native IDs and permissions are not prediction-cache
    // identity. No predictions are cached here: each invocation is recomputed.
    sha(
        canonical(&json!({"profile":"sou11-input-v1","server":server,
        "server_info":snapshot.server_info,"snapshot":snapshot.sha256,
        "tool":name,"schema":tool.schema_sha256,"definition":tool.definition_sha256,
        "arguments":args,"classifier":source,"revision":revision}))
        .to_string()
        .as_bytes(),
    )
}

pub fn classification_to_adapter(
    result: &Classification,
) -> Result<ToolClassification, &'static str> {
    let valid = result.confidence.is_finite()
        && (0.0..=1.0).contains(&result.confidence)
        && result.uncertainty.is_finite()
        && (0.0..=1.0).contains(&result.uncertainty)
        && !result.reason.is_empty()
        && result.reason.len() <= 1024
        && result.actions.iter().all(|action| {
            matches!(
                action.as_str(),
                "read" | "write" | "delete" | "send_data" | "change_permissions"
            )
        });
    if !valid {
        return Err("classifier_invalid");
    }
    let mut categories = Vec::new();
    for action in &result.actions {
        categories.push(match action.as_str() {
            "read" => ToolActionCategory::Read,
            "write" => ToolActionCategory::Write,
            "delete" => ToolActionCategory::Delete,
            "send_data" => ToolActionCategory::SendData,
            "change_permissions" => ToolActionCategory::ChangePermissions,
            _ => ToolActionCategory::Unknown,
        });
    }
    if result.unknown {
        categories.push(ToolActionCategory::Unknown);
    }
    Ok(ToolClassification {
        categories,
        confidence: result.confidence as f32,
        uncertainty: result.uncertainty as f32,
        reason: Some(result.reason.clone()),
    })
}

pub struct AdmissionCfg {
    pub daemon_url: String,
    pub manifest_url: String,
    pub manifest_token: String,
    pub server_id: String,
    pub native: NativeState,
    pub command: String,
    pub args: Vec<String>,
    pub classifier: Option<Arc<dyn InvocationClassifier>>,
    pub resource_profiles: BTreeMap<String, super::resources::ResourceProfile>,
    pub executor_fixed_destinations: bool,
}

pub fn executor_fixed_destinations_from_env() -> bool {
    std::env::var("AGENTFW_EXECUTOR_FIXED_DESTINATIONS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn resource_profiles_from_env(
) -> anyhow::Result<BTreeMap<String, super::resources::ResourceProfile>> {
    match std::env::var_os("AGENTFW_RESOURCE_PROFILES") {
        None => Ok(BTreeMap::new()),
        Some(val) => {
            let path = std::path::PathBuf::from(&val);
            let content = if path.is_file() {
                std::fs::read_to_string(&path)?
            } else {
                val.to_str()
                    .context("invalid AGENTFW_RESOURCE_PROFILES")?
                    .to_owned()
            };
            let profiles: Vec<super::resources::ResourceProfile> =
                serde_json::from_str(&content).context("invalid resource profiles format")?;
            let mut map = BTreeMap::new();
            for profile in profiles {
                map.insert(profile.tool_name.clone(), profile);
            }
            Ok(map)
        }
    }
}

/// Debug fixtures only. The release build refuses both switches.
pub fn test_classifier_from_env() -> anyhow::Result<Option<Arc<dyn InvocationClassifier>>> {
    let read = std::env::var_os("AGENTFW_TEST_CLASSIFIER_READ");
    let fixture = std::env::var_os("AGENTFW_TEST_CLASSIFIER");
    match (read, fixture) {
        (None, None) => Ok(None),
        _ if !cfg!(debug_assertions) => bail!("test classifier is unavailable"),
        (Some(value), None) if value == "1" => Ok(Some(Arc::new(ReadTestDouble))),
        (None, Some(value)) if value == "fixture-v1" => Ok(Some(Arc::new(FixtureTestDouble))),
        _ => bail!("invalid test classifier setting"),
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
pub(crate) struct Strict(pub(crate) Value);

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

    /// Classifies one validated call before the daemon sees it. The outer error is
    /// untrusted session state; the inner label is a call-local failure that must
    /// not execute and does not reach policy. A supported result is evidence only:
    /// the daemon still authorizes against the trusted registry baseline.
    async fn classify(
        &self,
        snapshot: &Snapshot,
        host_call_id: &Value,
        name: &str,
        args: &Value,
        baseline: ActionClass,
    ) -> anyhow::Result<Result<(), &'static str>> {
        let Some(classifier) = self.config.classifier.clone() else {
            return Ok(Ok(()));
        };
        let tool = snapshot
            .tools
            .get(name)
            .context("classifier discovery state missing")?;
        let source = classifier.source();
        let revision = classifier.revision().map(str::to_owned);
        let input_sha256 = prediction_identity(
            &self.config.server_id,
            snapshot,
            tool,
            name,
            args,
            source,
            revision.as_deref(),
        );
        let input = Invocation {
            server_id: self.config.server_id.clone(),
            host_call_id: host_call_id.clone(),
            registry_sha256: self.config.native.registry_sha256.clone(),
            snapshot_sha256: snapshot.sha256.clone(),
            schema_sha256: tool.schema_sha256.clone(),
            tool: name.into(),
            description: tool.description.clone(),
            schema: tool.schema.clone(),
            definition: tool.definition.clone(),
            server_info: snapshot.server_info.clone(),
            definition_sha256: tool.definition_sha256.clone(),
            input_sha256: input_sha256.clone(),
            classifier_revision: revision.clone(),
            args: args.clone(),
            baseline,
        };
        let started = std::time::Instant::now();
        let task = tokio::task::spawn_blocking(move || classifier.classify(&input));
        // ponytail: a timed-out classifier thread is abandoned, not killed; an
        // out-of-process classifier would be needed to reclaim it.
        let (result, mapped) = match tokio::time::timeout(CLASSIFIER_TIMEOUT, task).await {
            Err(_) => (None, Err("classifier_timeout")),
            Ok(Err(_)) => (None, Err("classifier_crash")),
            Ok(Ok(Err(_))) => (None, Err("classifier_error")),
            Ok(Ok(Ok(result))) => {
                let mapped = map_classification(&result);
                (Some(result), mapped)
            }
        };
        let adapter_eval = if let Some(ref res) = result {
            if let Ok(tc) = classification_to_adapter(res) {
                Some(evaluate_baseline_policy(&tc))
            } else {
                None
            }
        } else {
            None
        };
        eprintln!(
            "{}",
            json!({"event":"mcp_classification","contract_version":CLASSIFICATION_CONTRACT,
            "source":source,"classifier_sha256":revision,"host_call_id":host_call_id,"server_id":self.config.server_id,
            "tool":name,"snapshot_sha256":snapshot.sha256,
            "definition_sha256":tool.definition_sha256,"input_sha256":input_sha256,
            "schema_sha256":tool.schema_sha256,"args_sha256":sha(canonical(args).to_string().as_bytes()),
            "registry_sha256":self.config.native.registry_sha256,
            "classification":result.as_ref().map(|result| json!({"actions":result.actions,"unknown":result.unknown,
                "confidence":result.confidence,"uncertainty":result.uncertainty,
                "reason_sha256":sha(result.reason.as_bytes())})),
            "mapped_action_class":mapped.ok(),"trusted_baseline":baseline,
            "baseline_mismatch":mapped.ok().map(|class| class != baseline),
            "adapter_verdict":adapter_eval.as_ref().map(|(v, _)| match v {
                AdapterVerdict::Allow => "allow",
                AdapterVerdict::Ask => "ask",
                AdapterVerdict::Deny => "deny",
            }),
            "policy":if mapped.is_ok() { "reached" } else { "not_reached" },
            "failure":mapped.err(),"latency_us":started.elapsed().as_micros()})
        );
        Ok(mapped.map(|_| ()))
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
        let tools = value["tools"]
            .as_array()
            .context("MCP manifest absent")?
            .iter()
            .map(|tool| {
                // Preserve the original definition in the snapshot; inspect annotation
                // strings as untrusted metadata through the existing manifest boundary.
                let mut description = tool["description"].as_str().unwrap_or("").to_owned();
                if let Some(title) = tool
                    .get("annotations")
                    .and_then(|v| v.get("title"))
                    .and_then(Value::as_str)
                {
                    description.push('\n');
                    description.push_str(title);
                }
                json!({"name":tool["name"],"description":description,"schema":tool["inputSchema"]})
            })
            .collect::<Vec<_>>();
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

fn manifest(
    value: &Value,
    native: &NativeState,
    server_info: &Value,
) -> anyhow::Result<(BTreeMap<String, InputSchema>, Snapshot)> {
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
    let mut admitted = BTreeMap::new();
    for tool in tools {
        keys(tool, &["name", "description", "inputSchema", "annotations"])?;
        let name = tool["name"]
            .as_str()
            .context("MCP manifest tool name absent")?;
        ensure!(seen.insert(name), "duplicate MCP manifest tool");
        ensure!(
            !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
            "invalid MCP tool name"
        );
        if let Some(annotations) = tool.get("annotations") {
            keys(
                annotations,
                &[
                    "title",
                    "readOnlyHint",
                    "destructiveHint",
                    "idempotentHint",
                    "openWorldHint",
                ],
            )?;
            for (key, value) in annotations.as_object().expect("checked object") {
                ensure!(
                    if key == "title" {
                        value.is_string()
                    } else {
                        value.is_boolean()
                    },
                    "invalid MCP tool annotation"
                );
            }
        }
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
        let schema_sha256 = sha(canonical(&tool["inputSchema"]).to_string().as_bytes());
        ensure!(
            tool["inputSchema"].is_object() && schema_sha256 == installed.schema_sha256,
            "MCP tool schema differs from operator pin"
        );
        schemas.insert(name.into(), InputSchema::read(&tool["inputSchema"])?);
        admitted.insert(
            name.into(),
            AdmittedTool {
                description: tool["description"].as_str().unwrap_or("").into(),
                schema: tool["inputSchema"].clone(),
                schema_sha256,
                definition: tool.clone(),
                definition_sha256: sha(canonical(tool).to_string().as_bytes()),
            },
        );
    }
    Ok((
        schemas,
        Snapshot {
            sha256: sha(canonical(value).to_string().as_bytes()),
            tools: admitted,
            server_info: server_info.clone(),
        },
    ))
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
            tools.get("listChanged").is_none_or(Value::is_boolean),
            "invalid MCP manifest change capability"
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

fn correlation_id(value: &Value) -> bool {
    value.as_str().is_some_and(|id| {
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    })
}

fn progress_token(value: &Value) -> bool {
    // Keep tokens integral and exactly representable across JSON consumers.
    value
        .as_u64()
        .is_some_and(|token| token <= 9_007_199_254_740_991)
}

fn discovery_params(value: &Value) -> anyhow::Result<()> {
    keys(value, &["_meta"])?;
    if let Some(metadata) = value.get("_meta") {
        keys(metadata, &["progressToken"])?;
        ensure!(
            progress_token(&metadata["progressToken"]),
            "unsupported MCP discovery correlation metadata"
        );
    }
    Ok(())
}

/// Observed Claude and Codex identifiers are transport correlation only. They
/// never supply native session identity, arguments, authority or provenance.
fn call_metadata(value: &Value) -> anyhow::Result<()> {
    keys(
        value,
        &["claudecode/toolUseId", "threadId", "progressToken"],
    )?;
    let host_id = match (value.get("claudecode/toolUseId"), value.get("threadId")) {
        (Some(id), None) | (None, Some(id)) => id,
        _ => bail!("unsupported MCP call correlation metadata"),
    };
    ensure!(
        value.as_object().is_some_and(|map| map.len() == 2)
            && correlation_id(host_id)
            && progress_token(&value["progressToken"]),
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

/// A JSON-RPC error, not a policy refusal: the call did not execute and policy was not reached.
fn not_classified(id: &Value, failure: &str) -> Vec<u8> {
    let message =
        format!("Soup Wall could not classify the MCP invocation ({failure}); policy not reached");
    let mut raw = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":message}})
        .to_string()
        .into_bytes();
    raw.push(b'\n');
    raw
}

fn unsupported_resource_inventory(id: &Value) -> Vec<u8> {
    let mut raw = json!({"jsonrpc":"2.0","id":id,"error":{
        "code":-32601,"message":"Native MCP admission does not support resource inventory"
    }})
    .to_string()
    .into_bytes();
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
    let mut admitted_snapshot: Option<Snapshot> = None;
    let mut server_info = Value::Null;
    let mut list_changed_supported = false;
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
                    "tools/list" => {
                        ensure!(initialized, "MCP manifest before initialization");
                        discovery_params(&params)?;
                        // A refresh is a new admission, never fallback to old definitions.
                        ready = false;
                        schemas.clear();
                        admitted_snapshot = None;
                        Pending::Manifest(request_id.clone())
                    }
                    "resources/list" | "resources/templates/list" => {
                        ensure!(ready, "MCP resource inventory before operator-pinned manifest");
                        discovery_params(&params)?;
                        // Hosts may probe inventory even though initialization advertises
                        // tools only. No request or resource content reaches the server.
                        write(host, &unsupported_resource_inventory(request_id)).await?;
                        continue;
                    }
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
                        if let Some(profile) = collector.config.resource_profiles.get(name) {
                            let snapshot = admitted_snapshot.as_ref().context("classifier discovery state missing")?;
                            let tool = snapshot.tools.get(name).context("classifier discovery state missing")?;
                            let input = Invocation {
                                server_id: collector.config.server_id.clone(),
                                host_call_id: request_id.clone(),
                                registry_sha256: collector.config.native.registry_sha256.clone(),
                                snapshot_sha256: snapshot.sha256.clone(),
                                schema_sha256: tool.schema_sha256.clone(),
                                tool: name.into(),
                                description: tool.description.clone(),
                                schema: tool.schema.clone(),
                                definition: tool.definition.clone(),
                                server_info: snapshot.server_info.clone(),
                                definition_sha256: tool.definition_sha256.clone(),
                                input_sha256: String::new(),
                                classifier_revision: None,
                                args: args.clone(),
                                baseline: installed.action_class,
                            };
                            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                            let workspace = std::env::var_os("AGENTFW_WORKSPACE")
                                .map(std::path::PathBuf::from)
                                .unwrap_or_else(|| cwd.clone());
                            let executor_ctx = super::resources::ExecutorContext {
                                os: std::env::consts::OS,
                                workspace: &workspace,
                                cwd: &cwd,
                                fixed_destinations: collector.config.executor_fixed_destinations,
                            };
                            let extraction = super::resources::extract(&input, profile, &executor_ctx);
                            if !extraction.complete() {
                                let issue_codes: Vec<Value> = extraction.issues.iter().map(|i| json!(i.reason)).collect();
                                write(host, &withheld(request_id, "invocation", &Value::Array(issue_codes))).await?;
                                continue;
                            }
                            eprintln!(
                                "{}",
                                json!({
                                    "event": "mcp_resource_binding",
                                    "contract_version": CLASSIFICATION_CONTRACT,
                                    "host_call_id": request_id,
                                    "server_id": collector.config.server_id,
                                    "tool": name,
                                    "profile_sha256": extraction.profile_sha256,
                                    "executor_sha256": extraction.executor_sha256,
                                    "args_sha256": extraction.args_sha256,
                                    "resource_count": extraction.resources.len(),
                                    "resources_sha256": sha(serde_json::to_string(&extraction.resources)?.as_bytes()),
                                })
                            );
                        }
                        if collector.config.classifier.is_some() {
                            let snapshot = admitted_snapshot.as_ref().context("classifier discovery state missing")?;
                            if let Err(failure) = collector.classify(snapshot, request_id, name, &args, installed.action_class).await? {
                                write(host, &not_classified(request_id, failure)).await?;
                                continue;
                            }
                        }
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
                if value["method"] == "notifications/tools/list_changed" {
                    keys(&value, &["jsonrpc", "method", "params"])?;
                    ensure!(initialized && list_changed_supported && pending.is_none(), "unsupported MCP definition change timing");
                    if let Some(params) = value.get("params") { keys(params, &[])?; }
                    ready = false;
                    schemas.clear();
                    admitted_snapshot = None;
                    write(host, &raw).await?;
                    continue;
                }
                keys(&value, &["jsonrpc","id","result","error"])?;
                let request = pending.take().context("unbound or replayed MCP server response")?;
                ensure!(value.get("id") == Some(request.id()), "MCP response id mismatch");
                match request {
                    Pending::Handshake(_) => {
                        ensure!(value.get("error").is_none() && value["result"].is_object(), "MCP initialization failed");
                        initialization(&value["result"])?;
                        server_info = value["result"]["serverInfo"].clone();
                        list_changed_supported = value["result"]["capabilities"]["tools"]["listChanged"] == true;
                        initialized = true;
                    }
                    Pending::Manifest(_) => {
                        ensure!(value.get("error").is_none(), "MCP tools/list failed");
                        let (validated_schemas, snapshot) = manifest(&value["result"], &collector.config.native, &server_info)?;
                        collector.inspect_manifest(&value["result"]).await?;
                        schemas = validated_schemas;
                        admitted_snapshot = Some(snapshot);
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
            .env_remove("AGENTFW_TEST_CLASSIFIER_READ")
            .env_remove("AGENTFW_TEST_CLASSIFIER")
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

#[cfg(test)]
mod input_identity_tests {
    use super::*;

    fn discovered(description: &str) -> (NativeState, Value, Value) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/mcp_inputs/nested_schema.json"
        ))
        .unwrap();
        let registry = json!({"contract_version":CONTRACT,"registry_id":"sou11-fixture","tools":[
            {"name":"inventory_lookup","schema_sha256":sha(canonical(&schema).to_string().as_bytes()),
                "action_class":"read_only","result_provenance":"untrusted","egress":[]}]});
        let bytes = registry.to_string().into_bytes();
        let native =
            NativeState::from_bytes(&bytes, &sha(&bytes), "fixture-token-1234567890".into())
                .unwrap();
        let result = json!({"tools":[{"name":"inventory_lookup","description":description,
            "inputSchema":schema,"annotations":{"title":"Synthetic","readOnlyHint":true}}]});
        (native, result, json!({"name":"fixture","version":"1"}))
    }

    #[test]
    fn original_discovery_schema_and_annotations_are_retained() {
        let (native, result, info) = discovered("fixture description");
        let (_, snapshot) = manifest(&result, &native, &info).unwrap();
        let tool = &snapshot.tools["inventory_lookup"];
        assert_eq!(tool.definition, result["tools"][0]);
        assert_eq!(tool.schema, result["tools"][0]["inputSchema"]);
        assert_eq!(snapshot.server_info, info);
        assert_eq!(tool.description, "fixture description");
        let mut invocation = Invocation {
            server_id: "selected-local-server".into(),
            host_call_id: json!("original-id"),
            registry_sha256: "trusted-registry".into(),
            snapshot_sha256: snapshot.sha256.clone(),
            schema_sha256: tool.schema_sha256.clone(),
            tool: "inventory_lookup".into(),
            description: tool.description.clone(),
            schema: tool.schema.clone(),
            definition: tool.definition.clone(),
            server_info: info,
            definition_sha256: tool.definition_sha256.clone(),
            input_sha256: "input".into(),
            classifier_revision: Some("revision".into()),
            args: json!({"query":{"names":[],"limit":1}}),
            baseline: ActionClass::ReadOnly,
        };
        let semantic = invocation.semantic_input();
        assert_eq!(semantic["raw_arguments"], invocation.args);
        assert_eq!(
            semantic,
            json!({"tool_name":"inventory_lookup","raw_arguments":invocation.args,
            "tool_description":tool.description,"tool_schema":tool.schema,"server_id":"selected-local-server"})
        );
        invocation.host_call_id = json!("different-id");
        invocation.registry_sha256 = "different-registry".into();
        invocation.baseline = ActionClass::Destructive;
        assert_eq!(
            semantic,
            invocation.semantic_input(),
            "correlation and permissions are not semantic inputs"
        );
        assert_eq!(
            tool.definition_sha256,
            sha(canonical(&result["tools"][0]).to_string().as_bytes())
        );
    }

    #[test]
    fn prediction_identity_binds_server_arguments_metadata_and_classifier_revision() {
        let (native, result, info) = discovered("first");
        let (_, snapshot) = manifest(&result, &native, &info).unwrap();
        let args = json!({"query":{"names":["alpha"],"limit":1}});
        let identity =
            |server: &str, snap: &Snapshot, args: &Value, source: &str, rev: Option<&str>| {
                prediction_identity(
                    server,
                    snap,
                    &snap.tools["inventory_lookup"],
                    "inventory_lookup",
                    args,
                    source,
                    rev,
                )
            };
        let original = identity(
            "operator-selected",
            &snapshot,
            &args,
            "classifier",
            Some("rev1"),
        );
        assert_eq!(
            original,
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "classifier",
                Some("rev1")
            )
        );
        for changed in [
            identity(
                "different-server",
                &snapshot,
                &args,
                "classifier",
                Some("rev1"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &json!({}),
                "classifier",
                Some("rev1"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "classifier",
                Some("rev2"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "other-classifier",
                Some("rev1"),
            ),
            identity("operator-selected", &snapshot, &args, "classifier", None),
        ] {
            assert_ne!(original, changed);
        }
        let mut updated = result.clone();
        updated["tools"][0]["annotations"]["readOnlyHint"] = json!(false);
        let (_, metadata_changed) = manifest(&updated, &native, &info).unwrap();
        assert_ne!(
            original,
            identity(
                "operator-selected",
                &metadata_changed,
                &args,
                "classifier",
                Some("rev1")
            )
        );
        let (_, server_changed) =
            manifest(&result, &native, &json!({"name":"fixture","version":"2"})).unwrap();
        assert_ne!(
            original,
            identity(
                "operator-selected",
                &server_changed,
                &args,
                "classifier",
                Some("rev1")
            )
        );
    }

    #[test]
    fn changed_schema_tool_list_and_unsupported_annotations_require_readmission() {
        let (native, result, info) = discovered("first");
        let mut changed = result.clone();
        changed["tools"][0]["inputSchema"]["properties"]["new"] = json!({"type":"string"});
        assert!(manifest(&changed, &native, &info).is_err());
        changed = result.clone();
        changed["tools"] = json!([]);
        assert!(manifest(&changed, &native, &info).is_err());
        changed = result;
        changed["tools"][0]["annotations"]["customPermission"] = json!("allow");
        assert!(manifest(&changed, &native, &info).is_err());
    }
}

#[cfg(all(test, unix))]
mod classifier_revision_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[test]
    fn classifier_changed_between_parent_check_and_launch_never_executes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let script = root.join("classifier.py");
        let marker = root.join("unexpected-classifier-execution");
        let wrapper = root.join("python-wrapper");
        let reply = r#"{"status":"ok","actions":["read"],"unknown":false,"confidence":1.0,"uncertainty":0.0,"reason":"synthetic"}"#;
        let original = format!("print({reply:?})\n");
        std::fs::write(&script, &original).unwrap();
        let digest = sha(original.as_bytes());
        let actual_python = std::process::Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .unwrap();
        assert!(actual_python.status.success());
        let python = String::from_utf8(actual_python.stdout).unwrap();
        let python = python.trim();
        let replacement = format!(
            "import pathlib\npathlib.Path({:?}).touch()\nprint({reply:?})\n",
            marker.to_str().unwrap()
        );
        // The interpreter wrapper mutates the file only after the parent has
        // selected the revision and begun launching the classification process.
        let launcher = format!(
            "#!/bin/sh\n{} -c {} {} {}\nexec {} \"$@\"\n",
            quote(python),
            quote("import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])"),
            quote(script.to_str().unwrap()),
            quote(&replacement),
            quote(python)
        );
        std::fs::write(&wrapper, launcher).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let classifier = RuleBaseline {
            script,
            python: wrapper.into_os_string(),
            digest,
        };
        let invocation = Invocation {
            server_id: "synthetic".into(),
            host_call_id: json!(1),
            registry_sha256: "registry".into(),
            snapshot_sha256: "snapshot".into(),
            schema_sha256: "schema".into(),
            tool: "read_file".into(),
            description: "synthetic read".into(),
            schema: json!({"type":"object"}),
            definition: json!({"name":"read_file","inputSchema":{"type":"object"}}),
            server_info: json!({"name":"fixture","version":"1"}),
            definition_sha256: "definition".into(),
            input_sha256: "input".into(),
            classifier_revision: None,
            args: json!({"path":"fixture.txt"}),
            baseline: ActionClass::ReadOnly,
        };
        assert!(classifier.classify(&invocation).is_err());
        assert!(!marker.exists(), "changed classifier source executed");
    }
}
