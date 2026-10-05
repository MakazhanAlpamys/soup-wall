// SPDX-License-Identifier: Apache-2.0
//! Opt-in native admission. Semantics come only from an immutable startup registry.
//! A trusted collector owns execution; this protocol is not runtime attestation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{ActionClass, AgentEvent, EventKind, Outcome, Provenance, Trust, Verdict};

use crate::config::NativeCfg;
use crate::handlers::Shared;

pub const CONTRACT: &str = "sw-native/1";
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_CONTENT: usize = 262_144;
const MAX_SESSIONS: usize = 64;
const MAX_CALLS: usize = 256;
const MAX_SESSION_CALLS: usize = 64;
const TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub contract_version: String,
    pub registry_id: String,
    pub tools: Vec<Tool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub schema_sha256: String,
    pub action_class: ActionClass,
    pub result_provenance: ResultProvenance,
    pub egress: Vec<Egress>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProvenance {
    Untrusted,
    LocalSystem,
    LocalProject,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub pointer: String,
    pub kind: EgressKind,
    pub optional: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressKind {
    UrlHost,
    EmailDomain,
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:/".contains(&c))
}

fn json_pointer(value: &str) -> bool {
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

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => serde_json::to_value(
            map.iter()
                .map(|(k, v)| (k, canonical(v)))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("JSON values serialize"),
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn args_hash(value: &Value) -> String {
    hash(canonical(value).to_string().as_bytes())
}

fn binding(registry: &str, epoch: &str, tool: &str, schema: &str, args: &Value) -> String {
    let mut h = Sha256::new();
    h.update(b"sw-native/call/1\0");
    for field in [registry, epoch, tool, schema, &canonical(args).to_string()] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    format!("{:x}", h.finalize())
}

fn source(registry: &Registry, tool: &Tool) -> Provenance {
    match tool.result_provenance {
        ResultProvenance::Untrusted => Provenance::Native {
            registry: registry.registry_id.clone(),
            tool: tool.name.clone(),
        },
        ResultProvenance::LocalSystem => Provenance::LocalSystem,
        ResultProvenance::LocalProject => Provenance::LocalProject,
    }
}

fn declared_hosts(tool: &Tool, args: &Value) -> Result<Vec<String>, &'static str> {
    let mut hosts = BTreeSet::new();
    for selector in &tool.egress {
        let selected = match args.pointer(&selector.pointer) {
            None | Some(Value::Null) if selector.optional => continue,
            Some(value) => value,
            None => return Err("native_egress_missing"),
        };
        let values: Vec<&Value> = match selected {
            Value::Array(items) if items.len() <= 256 => items.iter().collect(),
            Value::String(_) => vec![selected],
            _ => return Err("native_egress_type"),
        };
        if values.is_empty() && !selector.optional {
            return Err("native_egress_missing");
        }
        for value in values {
            let text = value
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
                .ok_or("native_egress_type")?;
            let host = match selector.kind {
                EgressKind::UrlHost => {
                    let url = reqwest::Url::parse(text).map_err(|_| "native_egress_url")?;
                    if !matches!(url.scheme(), "http" | "https")
                        || !url.username().is_empty()
                        || url.password().is_some()
                    {
                        return Err("native_egress_url");
                    }
                    url.host_str()
                        .ok_or("native_egress_url")?
                        .trim_matches(['[', ']'])
                        .to_ascii_lowercase()
                }
                EgressKind::EmailDomain => {
                    let (local, domain) = text.rsplit_once('@').ok_or("native_egress_email")?;
                    if local.is_empty()
                        || local.contains('@')
                        || text.chars().any(char::is_whitespace)
                        || domain.is_empty()
                        || domain.len() > 253
                        || !domain.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && !label.starts_with('-')
                                && !label.ends_with('-')
                                && label
                                    .bytes()
                                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                        })
                    {
                        return Err("native_egress_email");
                    }
                    domain.to_ascii_lowercase()
                }
            };
            hosts.insert(host);
        }
    }
    Ok(hosts.into_iter().collect())
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Result,
    Context,
}

struct Call {
    tool: String,
    args_sha256: String,
    binding_sha256: String,
    stage: Stage,
    expires: Instant,
    result_kind: Option<String>,
}

struct Session {
    epoch: String,
    seq: u64,
    touched: Instant,
    calls: BTreeMap<String, Call>,
}

#[derive(Default)]
struct Sessions {
    entries: BTreeMap<String, Session>,
}

pub struct NativeState {
    pub registry: Registry,
    pub registry_sha256: String,
    pub token: String,
    sessions: Mutex<Sessions>,
}

impl NativeState {
    pub fn from_bytes(bytes: &[u8], expected: &str, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_BODY && is_digest(expected) && hash(bytes) == expected,
            "native registry bytes do not match the explicit startup digest"
        );
        let registry: Registry = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            registry.contract_version == CONTRACT
                && identifier(&registry.registry_id)
                && !registry.tools.is_empty()
                && registry.tools.len() <= 256,
            "invalid native registry"
        );
        let mut names = BTreeSet::new();
        for tool in &registry.tools {
            anyhow::ensure!(
                identifier(&tool.name)
                    && names.insert(&tool.name)
                    && is_digest(&tool.schema_sha256)
                    && tool.egress.len() <= 32,
                "invalid native tool"
            );
            for selector in &tool.egress {
                anyhow::ensure!(
                    json_pointer(&selector.pointer),
                    "invalid native egress pointer"
                );
            }
        }
        anyhow::ensure!(!token.is_empty(), "native collector token is absent");
        Ok(Self {
            registry,
            registry_sha256: expected.into(),
            token,
            sessions: Mutex::default(),
        })
    }

    pub fn load(config: &NativeCfg, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.registry_path.is_absolute(),
            "native registry needs an absolute operator path"
        );
        for part in config.registry_path.ancestors() {
            let metadata = std::fs::symlink_metadata(part)?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "native registry path is linked"
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.file_attributes() & 0x400 == 0,
                    "native registry path is redirected"
                );
            }
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&config.registry_path)?
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes, &config.registry_sha256, token)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    contract_version: String,
    registry_sha256: String,
    session_id: String,
    event: String,
    tool: Option<String>,
    args: Option<Value>,
    schema_sha256: Option<String>,
    call_id: Option<String>,
    content: Option<String>,
    result_kind: Option<String>,
    delivery: Option<String>,
}

fn parse(body: &str) -> Result<Request, &'static str> {
    if body.len() > MAX_BODY {
        return Err("native_body_over_cap");
    }
    // Deserialize directly as well: an intermediate Value would otherwise
    // discard duplicate protocol fields before the strict field check.
    let request: Request = serde_json::from_str(body).map_err(|_| "native_invalid_fields")?;
    let value: Value = serde_json::from_str(body).map_err(|_| "native_invalid_json")?;
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .ok_or("native_invalid_event")?;
    let mut keys = BTreeSet::from(["contract_version", "registry_sha256", "session_id", "event"]);
    match event {
        "session_start" | "session_end" => {}
        "call" => keys.extend(["tool", "args", "schema_sha256"]),
        "result" => keys.extend([
            "call_id",
            "tool",
            "args",
            "content",
            "result_kind",
            "delivery",
        ]),
        "context" => keys.extend(["call_id", "tool", "args", "content"]),
        _ => return Err("native_invalid_event"),
    }
    let object = value.as_object().ok_or("native_invalid_json")?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys {
        return Err("native_invalid_fields");
    }
    if request.contract_version != CONTRACT || !identifier(&request.session_id) {
        return Err("native_invalid_identity");
    }
    if let Some(args) = &request.args {
        if !args.is_object() || args.to_string().len() > MAX_CONTENT {
            return Err("native_args_over_cap");
        }
    }
    if let Some(content) = &request.content {
        if content.len() > MAX_CONTENT {
            return Err("native_content_over_cap");
        }
    }
    Ok(request)
}

#[derive(Serialize)]
struct Response {
    contract_version: &'static str,
    registry_sha256: String,
    session_id: String,
    event: String,
    verdict: &'static str,
    enforced: bool,
    release: bool,
    call_id: Option<String>,
    binding_sha256: Option<String>,
    content_sha256: Option<String>,
    reason_codes: Vec<String>,
}

fn resolved(outcome: &Outcome) -> Verdict {
    match outcome.verdict {
        Verdict::Escalate => outcome.fallback.unwrap_or(Verdict::Ask),
        verdict => verdict,
    }
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        _ => "ask",
    }
}

/// Inspect the exact provider-visible error, or each original text block separately.
fn context_text(content: &str, tool: &str) -> Result<Vec<String>, &'static str> {
    let value: Value = serde_json::from_str(content).map_err(|_| "native_context_json")?;
    let message = value.as_object().ok_or("native_context_shape")?;
    let tool_call = value["tool_call"]
        .as_object()
        .ok_or("native_context_shape")?;
    if message.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["role", "content", "error", "tool_call", "tool_call_id"])
        || tool_call
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["id", "function", "args", "placeholder_args"])
        || !value["tool_call"]["args"].is_object()
        || !(value["tool_call"]["placeholder_args"].is_null()
            || value["tool_call"]["placeholder_args"].is_object())
        || value["role"] != "tool"
        || value["tool_call"]["function"] != tool
        || !value["tool_call_id"].as_str().is_some_and(identifier)
        || value["tool_call"]["id"] != value["tool_call_id"]
    {
        return Err("native_context_shape");
    }
    let blocks = value["content"].as_array().ok_or("native_context_shape")?;
    if blocks.len() > 256 {
        return Err("native_context_shape");
    }
    let mut text = Vec::new();
    for block in blocks {
        let object = block.as_object().ok_or("native_context_shape")?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["type", "content"])
            || block["type"] != "text"
        {
            return Err("native_context_shape");
        }
        text.push(
            block["content"]
                .as_str()
                .ok_or("native_context_shape")?
                .to_string(),
        );
    }
    if !value["error"].is_null() {
        let error = value["error"].as_str().ok_or("native_context_shape")?;
        if !error.is_empty() {
            return Ok(vec![error.into()]);
        }
    }
    Ok(text)
}

fn failure(code: &'static str, status: StatusCode) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"contract_version": CONTRACT, "release": false, "error_code": code})),
    )
}

pub async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    let Some(native) = &st.native else {
        return failure("native_disabled", StatusCode::SERVICE_UNAVAILABLE);
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
    }
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if body.len() > st.config.max_body_bytes {
        return failure("native_body_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let request = match parse(&body) {
        Ok(request) => request,
        Err(code) => return failure(code, StatusCode::BAD_REQUEST),
    };
    if request.registry_sha256 != native.registry_sha256 {
        return failure("native_registry_mismatch", StatusCode::CONFLICT);
    }
    if request
        .content
        .as_ref()
        .is_some_and(|content| content.len() > st.config.max_record_bytes)
        || request
            .args
            .as_ref()
            .is_some_and(|args| args.to_string().len() > st.config.max_record_bytes)
    {
        return failure("native_record_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    match inspect(&st, native, request) {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).expect("native response serializes")),
        ),
        Err(code) => failure(code, StatusCode::CONFLICT),
    }
}

fn inspect(st: &Shared, native: &NativeState, request: Request) -> Result<Response, &'static str> {
    let started = Instant::now();
    // One lock covers sequencing, inspection, admission and audit. No await,
    // external judge, or network request occurs while this guard is held.
    let mut state = native
        .sessions
        .lock()
        .map_err(|_| "native_state_unavailable")?;
    let now = Instant::now();
    let mut firewall = st
        .firewall
        .lock()
        .map_err(|_| "native_inspection_unavailable")?;
    let expired: Vec<String> = state
        .entries
        .iter()
        .filter(|(_, s)| now.duration_since(s.touched) >= TTL)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(old) = state.entries.remove(&id) {
            firewall.inspect(&event(&old.epoch, old.seq + 1, EventKind::SessionEnd));
            st.spans.end_session(&old.epoch);
        }
    }
    for session in state.entries.values_mut() {
        session.calls.retain(|_, call| call.expires > now);
    }
    let mut response = Response {
        contract_version: CONTRACT,
        registry_sha256: native.registry_sha256.clone(),
        session_id: request.session_id.clone(),
        event: request.event.clone(),
        verdict: "allow",
        enforced: true,
        release: true,
        call_id: None,
        binding_sha256: None,
        content_sha256: request.content.as_ref().map(|c| hash(c.as_bytes())),
        reason_codes: vec![],
    };
    if request.event == "session_start" {
        if state.entries.contains_key(&request.session_id) {
            return Err("native_session_exists");
        }
        if state.entries.len() >= MAX_SESSIONS {
            return Err("native_session_cap");
        }
        let epoch = format!("native:{}", crate::token::generate());
        audit(
            st,
            &request,
            &epoch,
            1,
            &response,
            None,
            started.elapsed().as_micros(),
        )?;
        state.entries.insert(
            request.session_id,
            Session {
                epoch,
                seq: 1,
                touched: now,
                calls: BTreeMap::new(),
            },
        );
        return Ok(response);
    }
    if request.event == "session_end" {
        let session = state
            .entries
            .remove(&request.session_id)
            .ok_or("native_session_unknown")?;
        firewall.inspect(&event(
            &session.epoch,
            session.seq + 1,
            EventKind::SessionEnd,
        ));
        st.spans.end_session(&session.epoch);
        audit(
            st,
            &request,
            &session.epoch,
            session.seq + 1,
            &response,
            None,
            started.elapsed().as_micros(),
        )?;
        return Ok(response);
    }
    let total_calls: usize = state.entries.values().map(|s| s.calls.len()).sum();
    let session = state
        .entries
        .get_mut(&request.session_id)
        .ok_or("native_session_unknown")?;
    session.touched = now;
    session.seq += 1;
    let name = request.tool.as_deref().ok_or("native_tool_missing")?;
    let tool = native
        .registry
        .tools
        .iter()
        .find(|t| t.name == name)
        .ok_or("native_tool_unknown")?;
    let args = request.args.as_ref().ok_or("native_args_missing")?;
    if request.event == "call" {
        if request.schema_sha256.as_deref() != Some(tool.schema_sha256.as_str()) {
            return Err("native_schema_mismatch");
        }
        if total_calls >= MAX_CALLS || session.calls.len() >= MAX_SESSION_CALLS {
            return Err("native_call_cap");
        }
        let hosts = declared_hosts(tool, args)?;
        let ev = event(
            &session.epoch,
            session.seq,
            EventKind::ToolCall {
                tool: name.into(),
                args: args.clone(),
            },
        );
        let outcome = firewall.inspect_native_call(&ev, tool.action_class, &hosts);
        let verdict = resolved(&outcome);
        response.verdict = verdict_label(verdict);
        response.release = verdict == Verdict::Allow;
        response.reason_codes = outcome.rule.iter().cloned().collect();
        let bound = binding(
            &native.registry_sha256,
            &session.epoch,
            name,
            &tool.schema_sha256,
            args,
        );
        if response.release {
            response.binding_sha256 = Some(bound.clone());
            response.call_id = Some(crate::token::generate());
        }
        audit(
            st,
            &request,
            &session.epoch,
            session.seq,
            &response,
            Some(&outcome),
            started.elapsed().as_micros(),
        )?;
        if let Some(id) = &response.call_id {
            session.calls.insert(
                id.clone(),
                Call {
                    tool: name.into(),
                    args_sha256: args_hash(args),
                    binding_sha256: bound,
                    stage: Stage::Result,
                    expires: now + TTL,
                    result_kind: None,
                },
            );
        }
        return Ok(response);
    }
    let id = request.call_id.as_deref().ok_or("native_call_missing")?;
    // Remove before validation. A mismatched/failed completion cannot be retried
    // into a different admission after observing its error.
    let mut call = session
        .calls
        .remove(id)
        .ok_or("native_call_unknown_or_spent")?;
    response.call_id = Some(id.into());
    response.binding_sha256 = Some(call.binding_sha256.clone());
    if call.tool != name || call.args_sha256 != args_hash(args) {
        return Err("native_call_binding_mismatch");
    }
    let content = request.content.as_deref().ok_or("native_content_missing")?;
    let texts = if request.event == "result" {
        if call.stage != Stage::Result {
            return Err("native_stage_mismatch");
        }
        if !matches!(request.result_kind.as_deref(), Some("value" | "error")) {
            return Err("native_result_kind");
        }
        if !matches!(request.delivery.as_deref(), Some("parent" | "model")) {
            return Err("native_delivery");
        }
        vec![content.to_string()]
    } else {
        if call.stage != Stage::Context {
            return Err("native_stage_mismatch");
        }
        let envelope: Value = serde_json::from_str(content).map_err(|_| "native_context_json")?;
        let error = envelope
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if error != (call.result_kind.as_deref() == Some("error")) {
            return Err("native_result_kind_mismatch");
        }
        context_text(content, name)?
    };
    let provenance = source(&native.registry, tool);
    let mut events = Vec::new();
    let mut strongest = Verdict::Allow;
    let mut representative = None;
    let mut observed_findings = BTreeMap::new();
    let mut max_block_risk = 0;
    for text in texts {
        session.seq += 1;
        let ev = event(
            &session.epoch,
            session.seq,
            EventKind::ToolResult {
                tool: name.into(),
                content: text,
                source: provenance.clone(),
            },
        );
        let outcome = firewall.preview_native_result(&ev);
        max_block_risk = max_block_risk.max(outcome.risk_score);
        for (facet, finding) in &outcome.findings {
            let key = (finding.detector.clone(), finding.severity);
            let entry = observed_findings
                .entry(key)
                .or_insert_with(|| (*facet, finding.clone()));
            if finding.confidence > entry.1.confidence {
                *entry = (*facet, finding.clone());
            }
        }
        let verdict = resolved(&outcome);
        if representative.is_none()
            || verdict == Verdict::Deny
            || (verdict == Verdict::Ask && strongest == Verdict::Allow)
        {
            strongest = verdict;
            representative = Some(outcome);
        }
        events.push(ev);
    }
    if let Some(outcome) = &mut representative {
        // Every original block was inspected independently. Audit all observed
        // detector kinds and the largest actual per-block score; do not invent
        // a combined score or policy evaluation over concatenated content.
        outcome.findings = observed_findings.into_values().collect();
        outcome.risk_score = max_block_risk;
    }
    response.verdict = verdict_label(strongest);
    response.release = strongest == Verdict::Allow;
    response.reason_codes = representative
        .as_ref()
        .and_then(|o| o.rule.clone())
        .into_iter()
        .collect();
    audit(
        st,
        &request,
        &session.epoch,
        session.seq,
        &response,
        representative.as_ref(),
        started.elapsed().as_micros(),
    )?;
    if response.release {
        // An outer runtime value is still held inside the collector. It has not
        // entered model context, including while other preplanned tools in the
        // same original executor batch run. Nested values really reach a parent.
        if request.event == "context" || request.delivery.as_deref() == Some("parent") {
            for ev in events {
                firewall.admit_native_result(&ev);
                if let EventKind::ToolResult {
                    content, source, ..
                } = &ev.kind
                {
                    if source.trust() == Trust::Untrusted {
                        st.spans.put(&session.epoch, ev.seq, content);
                    }
                }
            }
        }
        if request.event == "result" && request.delivery.as_deref() == Some("model") {
            call.stage = Stage::Context;
            call.result_kind = request.result_kind;
            session.calls.insert(id.into(), call);
        }
    }
    Ok(response)
}

fn event(session: &str, seq: u64, kind: EventKind) -> AgentEvent {
    AgentEvent {
        session: session.into(),
        agent: "native-runtime".into(),
        parent: None,
        seq,
        at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        kind,
    }
}

fn audit(
    st: &Shared,
    request: &Request,
    epoch: &str,
    seq: u64,
    response: &Response,
    outcome: Option<&Outcome>,
    latency_us: u128,
) -> Result<(), &'static str> {
    let record = json!({"at_ms": event(epoch, seq, EventKind::Unknown).at_ms, "session": epoch,
        "seq": seq, "event": format!("native_{}", request.event), "tool": request.tool,
        "verdict": response.verdict, "shadow": false, "released": response.release,
        "rule": outcome.and_then(|o| o.rule.as_ref()),
        "risk_score": outcome.map_or(0, |o| o.risk_score),
        "findings": outcome.map(|o| o.findings.iter().map(|(_, f)| json!({"detector": f.detector, "severity": format!("{:?}", f.severity).to_lowercase()})).collect::<Vec<_>>()).unwrap_or_default(),
        "egress_hosts": outcome.map(|o| o.egress_hosts.clone()).unwrap_or_default(),
        "taint": outcome.and_then(|o| o.taint.as_ref()).map(|t| json!({"source": t.source.label(),
            "origin": t.source.kind(), "source_name": t.source.source_name(),
            "trust": format!("{:?}", t.source.trust()).to_lowercase(), "seq": t.seq})),
        "latency_us": latency_us, "truncated": false, "registry_sha256": response.registry_sha256,
        "delivery": request.delivery,
        "call_id": response.call_id, "binding_sha256": response.binding_sha256,
        "content_sha256": response.content_sha256, "reason_codes": response.reason_codes});
    st.audit
        .write_native(&record)
        .map_err(|_| "native_audit_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::AuditSink,
        handlers::{AppState, Sessions as HookSessions},
        Config,
    };
    use soup_wall_agent::AgentFirewall;
    use std::sync::Arc;

    fn fixture(dir: &std::path::Path) -> Shared {
        let bytes = json!({"contract_version": CONTRACT, "registry_id": "unit-suite", "tools": [{
            "name": "lookup_note", "schema_sha256": "a".repeat(64), "action_class": "read_only",
            "result_provenance": "untrusted", "egress": []
        }]})
        .to_string()
        .into_bytes();
        Arc::new(AppState {
            native: Some(
                NativeState::from_bytes(&bytes, &hash(&bytes), "native-unit-key".into()).unwrap(),
            ),
            firewall: Mutex::new(AgentFirewall::with_default_policy()),
            sessions: HookSessions::default(),
            audit: AuditSink::open(&dir.join("audit.jsonl")).unwrap(),
            spans: crate::spans::SpanCache::new(64, 4096),
            judge: crate::judge::Judge::new(Default::default()),
            manifests: crate::mcp::store::ManifestStore::new(&dir.join("manifests")),
            tools: crate::mcp::store::ToolRegistry::with_builtins(),
            grants: crate::grant::GrantStore::new(&dir.join("grants")),
            grant_ledger: crate::grant::GrantLedger::open(&dir.join("spent.json")),
            grant_key: crate::grant::derive_key("hook-unit-key"),
            config: Config {
                enforce: true,
                ..Config::default()
            },
            token: "hook-unit-key".into(),
        })
    }

    fn request(native: &NativeState, session: &str, event: &str, fields: Value) -> Request {
        let mut value = json!({"contract_version": CONTRACT, "registry_sha256": native.registry_sha256,
            "session_id": session, "event": event});
        for (key, value_field) in fields.as_object().unwrap() {
            value[key] = value_field.clone();
        }
        parse(&value.to_string()).unwrap()
    }

    fn start(st: &Shared, id: &str) {
        let native = st.native.as_ref().unwrap();
        inspect(st, native, request(native, id, "session_start", json!({}))).unwrap();
    }

    #[test]
    fn audit_write_failure_withholds_result_and_does_not_commit_taint_or_spans() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let native = st.native.as_ref().unwrap();
        start(&st, "s");
        let call = inspect(
            &st,
            native,
            request(
                native,
                "s",
                "call",
                json!({
                    "tool": "lookup_note", "args": {}, "schema_sha256": "a".repeat(64)
                }),
            ),
        )
        .unwrap();
        let epoch = native.sessions.lock().unwrap().entries["s"].epoch.clone();
        st.audit
            .fail_writes_for_test(&dir.path().join("audit.jsonl"));
        let content = "A neutral archived note used to verify that unreleased source content is never admitted.";
        let result = inspect(
            &st,
            native,
            request(
                native,
                "s",
                "result",
                json!({
                    "tool": "lookup_note", "args": {}, "call_id": call.call_id, "result_kind": "value", "delivery": "model", "content": content
                }),
            ),
        );
        assert_eq!(result.err(), Some("native_audit_unavailable"));
        assert_eq!(st.firewall.lock().unwrap().taint_len(&epoch), 0);
        assert!(st.spans.get(&epoch, 4).is_none());
        assert!(native.sessions.lock().unwrap().entries["s"]
            .calls
            .is_empty());
        let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), 2);
        assert!(!audit.contains(content));
    }

    #[test]
    fn expired_native_session_clears_taint_and_invalidates_pending_calls() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let native = st.native.as_ref().unwrap();
        start(&st, "expired");
        let call = inspect(
            &st,
            native,
            request(
                native,
                "expired",
                "call",
                json!({
                    "tool": "lookup_note", "args": {}, "schema_sha256": "a".repeat(64)
                }),
            ),
        )
        .unwrap();
        let epoch = native.sessions.lock().unwrap().entries["expired"]
            .epoch
            .clone();
        st.firewall.lock().unwrap().admit_native_result(&event(&epoch, 3, EventKind::ToolResult {
            tool: "lookup_note".into(), content: "A long neutral note from an untrusted native source retained for this expiry check.".into(),
            source: Provenance::Native { registry: "unit-suite".into(), tool: "lookup_note".into() },
        }));
        assert!(st.firewall.lock().unwrap().taint_len(&epoch) > 0);
        native
            .sessions
            .lock()
            .unwrap()
            .entries
            .get_mut("expired")
            .unwrap()
            .touched = Instant::now() - TTL;
        start(&st, "fresh");
        assert_eq!(st.firewall.lock().unwrap().taint_len(&epoch), 0);
        assert!(!native
            .sessions
            .lock()
            .unwrap()
            .entries
            .contains_key("expired"));
        let result = inspect(
            &st,
            native,
            request(
                native,
                "expired",
                "result",
                json!({
                    "tool": "lookup_note", "args": {}, "call_id": call.call_id, "result_kind": "value", "delivery": "model", "content": "ok"
                }),
            ),
        );
        assert_eq!(result.err(), Some("native_session_unknown"));
    }

    #[test]
    fn pending_call_cap_rejects_new_invocation_without_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let native = st.native.as_ref().unwrap();
        start(&st, "s");
        for _ in 0..MAX_SESSION_CALLS {
            assert!(
                inspect(
                    &st,
                    native,
                    request(
                        native,
                        "s",
                        "call",
                        json!({
                            "tool": "lookup_note", "args": {}, "schema_sha256": "a".repeat(64)
                        })
                    )
                )
                .unwrap()
                .release
            );
        }
        let result = inspect(
            &st,
            native,
            request(
                native,
                "s",
                "call",
                json!({
                    "tool": "lookup_note", "args": {}, "schema_sha256": "a".repeat(64)
                }),
            ),
        );
        assert_eq!(result.err(), Some("native_call_cap"));
        assert_eq!(
            native.sessions.lock().unwrap().entries["s"].calls.len(),
            MAX_SESSION_CALLS
        );
    }

    #[test]
    fn registry_rejects_invalid_pointer_escapes_and_semantic_caller_claims() {
        assert!(json_pointer("/message/~0escaped~1key"));
        for pointer in ["/recipients/~", "/recipients/~2", "recipients"] {
            assert!(!json_pointer(pointer));
        }
        let malformed = json!({"contract_version": CONTRACT, "registry_id": "s", "tools": [{
            "name": "lookup_note", "schema_sha256": "a".repeat(64), "action_class": "read_only",
            "result_provenance": "untrusted", "egress": [{"pointer": "/~2", "kind": "url_host", "optional": true}]
        }]}).to_string();
        assert!(NativeState::from_bytes(
            malformed.as_bytes(),
            &hash(malformed.as_bytes()),
            "key".into()
        )
        .is_err());
        let duplicate = format!(
            r#"{{"contract_version":"{CONTRACT}","registry_sha256":"{}","session_id":"s","session_id":"other","event":"session_start"}}"#,
            "a".repeat(64)
        );
        assert!(parse(&duplicate).is_err());
    }
}
