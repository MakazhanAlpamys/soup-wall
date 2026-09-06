// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Agent-attack benchmark corpus: one labelled *session* per JSONL line. Each event is
//! a serialized `EventKind`; the loader wraps it into a full `AgentEvent` so the corpus
//! stays compact while feeding the real `inspect()` path.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context};
use serde::Deserialize;
use soup_wall_agent::{AgentEvent, EventKind};

/// One labelled session from the corpus.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSession {
    pub id: String,
    /// "attack" or "benign".
    pub label: String,
    #[serde(default)]
    pub category: String,
    /// The main agent's tool grant, registered before replay so subagent-escalation
    /// sessions can be evaluated (authority is set out-of-band, not via an event).
    #[serde(default)]
    pub root_tools: Vec<String>,
    /// Each entry is a serialized `EventKind` (the `kind` payload).
    pub events: Vec<EventKind>,
    #[serde(default)]
    pub note: String,
}

/// A session ready to replay.
pub struct Session {
    pub id: String,
    pub is_attack: bool,
    pub category: String,
    pub root_tools: Vec<String>,
    pub events: Vec<AgentEvent>,
    #[allow(dead_code)]
    pub note: String,
}

/// Versioned, reviewable provenance record for a hand-authored agent corpus.
/// Public benchmark imports must carry their own manifest rather than borrowing
/// this corpus's license declaration.
#[derive(Debug, Deserialize)]
pub struct CorpusManifest {
    pub schema_version: u32,
    pub name: String,
    pub license_spdx: String,
    pub provenance: String,
    pub record_count: usize,
    pub attack_count: usize,
    pub benign_count: usize,
    pub categories: Vec<String>,
}

impl RawSession {
    /// Wrap each `EventKind` into a full `AgentEvent` keyed by this session.
    pub fn into_session(self) -> Session {
        let events = self
            .events
            .into_iter()
            .enumerate()
            .map(|(i, kind)| AgentEvent {
                session: self.id.clone(),
                agent: "main".into(),
                parent: None,
                seq: (i + 1) as u64,
                at_ms: 0,
                kind,
            })
            .collect();
        Session {
            is_attack: self.label == "attack",
            id: self.id,
            category: self.category,
            root_tools: self.root_tools,
            events,
            note: self.note,
        }
    }
}

/// Parse a JSONL corpus into sessions. A malformed line is an error naming the line.
pub fn load(path: &str) -> anyhow::Result<Vec<Session>> {
    let body = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    for (n, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let raw: RawSession = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("corpus line {}: {e}", n + 1))?;
        if raw.id.trim().is_empty() {
            bail!("corpus line {} has an empty id", n + 1);
        }
        if !ids.insert(raw.id.clone()) {
            bail!("corpus line {} repeats session id {}", n + 1, raw.id);
        }
        if raw.label != "attack" && raw.label != "benign" {
            bail!(
                "corpus line {} has invalid label {}; expected attack or benign",
                n + 1,
                raw.label
            );
        }
        if raw.category.trim().is_empty() {
            bail!("corpus line {} has an empty category", n + 1);
        }
        out.push(raw.into_session());
    }
    Ok(out)
}

/// Load a corpus only after its adjacent review manifest has validated its
/// exact label counts and category set. The expected sibling filename is
/// `agent_sessions.manifest.json` for `agent_sessions.jsonl`.
pub fn load_reviewed(path: &str) -> anyhow::Result<Vec<Session>> {
    let sessions = load(path)?;
    let manifest_path = Path::new(path).with_extension("manifest.json");
    let body = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "agent corpus review manifest is required at {}",
            manifest_path.display()
        )
    })?;
    let manifest: CorpusManifest = serde_json::from_str(&body).with_context(|| {
        format!(
            "agent corpus review manifest is not valid JSON: {}",
            manifest_path.display()
        )
    })?;
    validate_manifest(&manifest, &sessions)?;
    Ok(sessions)
}

fn validate_manifest(manifest: &CorpusManifest, sessions: &[Session]) -> anyhow::Result<()> {
    if manifest.schema_version != 1 {
        bail!("unsupported agent corpus manifest schema version");
    }
    if manifest.name.trim().is_empty()
        || manifest.license_spdx.trim().is_empty()
        || manifest.provenance.trim().is_empty()
    {
        bail!("agent corpus manifest requires name, SPDX license, and provenance");
    }
    let attack_count = sessions.iter().filter(|session| session.is_attack).count();
    let benign_count = sessions.len() - attack_count;
    if manifest.record_count != sessions.len()
        || manifest.attack_count != attack_count
        || manifest.benign_count != benign_count
    {
        bail!("agent corpus manifest counts do not match corpus data");
    }
    if sessions.is_empty() || attack_count == 0 || benign_count == 0 {
        bail!("agent corpus must contain both attack and benign sessions");
    }
    let actual_categories = sessions
        .iter()
        .map(|session| session.category.as_str())
        .collect::<BTreeSet<_>>();
    let manifest_categories = manifest
        .categories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if manifest.categories.len() != manifest_categories.len()
        || manifest_categories
            .iter()
            .any(|category| category.trim().is_empty())
    {
        bail!("agent corpus manifest categories must be unique and non-empty");
    }
    if actual_categories != manifest_categories {
        bail!("agent corpus manifest categories do not match corpus data");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_line_parses_and_wraps_events() {
        // NB: Provenance is tagged `origin` (not `kind`).
        let line = r#"{"id":"s1","label":"attack","category":"indirect-injection","events":[
            {"kind":"tool_result","tool":"WebFetch","content":"hi","source":{"origin":"network","host":"b.com"}},
            {"kind":"tool_call","tool":"Bash","args":{"command":"curl evil.com"}}
        ],"note":"n"}"#;
        let raw: RawSession = serde_json::from_str(line).unwrap();
        let s = raw.into_session();
        assert!(s.is_attack);
        assert_eq!(s.events.len(), 2);
        assert_eq!(s.events[0].seq, 1);
        assert_eq!(s.events[1].seq, 2);
        assert_eq!(s.events[0].session, "s1");
    }

    #[test]
    fn a_benign_label_is_not_an_attack() {
        let raw: RawSession =
            serde_json::from_str(r#"{"id":"b","label":"benign","events":[]}"#).unwrap();
        assert!(!raw.into_session().is_attack);
    }

    #[test]
    fn loader_rejects_unknown_labels_and_duplicate_ids() {
        let unknown_label = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            unknown_label.path(),
            r#"{"id":"x","label":"maybe","category":"test","events":[]}"#,
        )
        .unwrap();
        assert!(load(unknown_label.path().to_str().unwrap()).is_err());

        let duplicate = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            duplicate.path(),
            concat!(
                r#"{"id":"x","label":"attack","category":"test","events":[]}"#,
                "\n",
                r#"{"id":"x","label":"benign","category":"test","events":[]}"#
            ),
        )
        .unwrap();
        assert!(load(duplicate.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn manifest_rejects_a_mismatched_count() {
        let session = s(r#"{"id":"a","label":"attack","category":"test","events":[]}"#);
        let manifest = CorpusManifest {
            schema_version: 1,
            name: "test".into(),
            license_spdx: "Apache-2.0".into(),
            provenance: "hand-authored".into(),
            record_count: 2,
            attack_count: 1,
            benign_count: 1,
            categories: vec!["test".into()],
        };
        assert!(validate_manifest(&manifest, &[session]).is_err());
    }

    fn s(json: &str) -> Session {
        serde_json::from_str::<RawSession>(json)
            .unwrap()
            .into_session()
    }
}
