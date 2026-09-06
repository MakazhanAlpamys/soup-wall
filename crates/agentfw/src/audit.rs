// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Append-only JSONL audit sink. Also the phase-10 tuning corpus and the phase-12
//! benign-session benchmark corpus, so completeness matters more than brevity.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

/// One audited event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditLine {
    pub at_ms: u64,
    pub session: String,
    pub seq: u64,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub verdict: String,
    /// True when the verdict was computed but not enforced.
    pub shadow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub risk_score: u8,
    pub findings: Vec<AuditFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<AuditTaint>,
    /// What the local judge concluded, when an `Escalate` verdict was resolved by it.
    /// Absent on every event that did not escalate — the common case. Recorded so the
    /// audit log explains why a verdict landed where it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<String>,
    /// Nonce of the human approval that authorized this call, when one did.
    /// Present only on a call an operator explicitly approved, so the audit
    /// trail distinguishes "policy allowed this" from "a human allowed this".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    pub egress_hosts: Vec<String>,
    pub latency_us: u128,
    pub truncated: bool,
    /// Raw received body for unrecognized events, only when sensitive forensic
    /// capture was explicitly enabled by the operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub detector: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atlas: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditTaint {
    /// Human-readable source label, e.g. `network:evil.com`. Kept for operators
    /// and existing consumers; **not** a parsing target — use the structured
    /// fields below.
    pub source: String,
    /// Origin discriminant: `user`, `project`, `system`, `network`, `mcp`,
    /// `subagent`. Emitted separately so a consumer can group and filter without
    /// re-implementing a split this crate already knows how to do.
    pub origin: String,
    /// The specific host, server, or subagent name. Absent for origins that have
    /// no name of their own, rather than an empty string a reader might mistake
    /// for a source identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Trust class this origin implies: `untrusted`, `semi`, or `trusted`.
    ///
    /// Recorded rather than left to be derived. It is the security-relevant
    /// classification in the whole record, and without it a log reader needs
    /// this crate's source to interpret their own audit trail.
    pub trust: String,
    /// Sequence number of the event that introduced the tainted content.
    pub seq: u64,
}

/// Append-only sink. Serialized behind a mutex so concurrent hooks cannot
/// interleave partial lines.
pub struct AuditSink {
    file: Mutex<File>,
}

impl AuditSink {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = open_private_append(path)?;
        // Belt and suspenders, mirroring `token.rs::load_or_create`: `.mode()` on
        // `OpenOptions` is only honoured when the file is actually CREATED by this
        // call. A pre-existing file at loose permissions (e.g. left over from a
        // build before this fix landed, or created by some other tool) is opened
        // as-is, so tighten it explicitly every time. This file holds prompts, file
        // paths, and tool arguments, so it must never sit at the process umask even
        // for the brief window between create and chmod.
        crate::token::restrict(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Write one line. Failures are returned, never panicked — a broken audit log
    /// must not take down the hook path.
    pub fn write(&self, line: &AuditLine) -> anyhow::Result<()> {
        let mut json = serde_json::to_string(line)?;
        json.push('\n');
        let mut f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("audit mutex poisoned"))?;
        f.write_all(json.as_bytes())?;
        Ok(())
    }
}

/// Open for append, creating the file with owner-only permissions from the outset
/// on unix. Creating loose and chmod'ing after (`OpenOptions::create(true)` then a
/// separate `set_permissions`) leaves a window — however brief — where the file
/// sits at the process umask, and this file holds prompts and file paths. Same
/// reasoning as `token.rs::write_private`.
#[cfg(unix)]
fn open_private_append(path: &Path) -> anyhow::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    Ok(f)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> anyhow::Result<File> {
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit record must be readable without this crate's source. The trust
    /// class is the security-relevant field, so it is emitted rather than left
    /// to be inferred from the origin, and the origin and name are emitted as
    /// their own values rather than recovered by splitting the human label.
    #[test]
    fn a_taint_record_carries_structured_origin_and_trust() {
        let taint = AuditTaint {
            source: "mcp:docs".into(),
            origin: "mcp".into(),
            source_name: Some("docs".into()),
            trust: "untrusted".into(),
            seq: 7,
        };
        let rendered = serde_json::to_value(&taint).expect("taint serializes");
        assert_eq!(rendered["origin"], "mcp");
        assert_eq!(rendered["source_name"], "docs");
        assert_eq!(
            rendered["trust"], "untrusted",
            "a reader must not have to know this crate to classify the source"
        );
        assert_eq!(rendered["seq"], 7);
        assert_eq!(
            rendered["source"], "mcp:docs",
            "the human label stays for existing consumers"
        );
    }

    /// An origin with no name of its own must omit the field rather than emit an
    /// empty string, which a consumer could mistake for a source identity.
    #[test]
    fn an_unnamed_origin_omits_the_name_rather_than_emitting_an_empty_one() {
        let taint = AuditTaint {
            source: "user".into(),
            origin: "user".into(),
            source_name: None,
            trust: "trusted".into(),
            seq: 1,
        };
        let rendered = serde_json::to_value(&taint).expect("taint serializes");
        assert!(
            rendered.get("source_name").is_none(),
            "absent, not empty: {rendered}"
        );
    }

    fn line() -> AuditLine {
        AuditLine {
            at_ms: 1,
            session: "s1".into(),
            seq: 2,
            event: "tool_call".into(),
            tool: Some("Bash".into()),
            verdict: "deny".into(),
            shadow: true,
            rule: Some("deny-x".into()),
            risk_score: 90,
            findings: vec![],
            taint: None,
            judge: None,
            approval: None,
            egress_hosts: vec![],
            latency_us: 120,
            truncated: false,
            raw: None,
        }
    }

    #[test]
    fn writes_one_json_object_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&p).unwrap();
        sink.write(&line()).unwrap();
        sink.write(&line()).unwrap();

        let body = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["session"], "s1");
            assert_eq!(v["shadow"], true);
        }
    }

    #[test]
    fn appends_rather_than_truncating_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        AuditSink::open(&p).unwrap().write(&line()).unwrap();
        AuditSink::open(&p).unwrap().write(&line()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 2);
    }

    #[test]
    fn preserves_raw_bytes_when_explicitly_supplied() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let sink = AuditSink::open(&p).unwrap();
        let mut l = line();
        l.event = "unknown".into();
        l.raw = Some(r#"{"hook_event_name":"FutureThing"}"#.into());
        sink.write(&l).unwrap();

        let v: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&p).unwrap().trim()).unwrap();
        assert!(v["raw"].as_str().unwrap().contains("FutureThing"));
    }

    #[cfg(unix)]
    #[test]
    fn the_audit_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        AuditSink::open(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "audit log holds prompts and paths; got {:o}",
            mode
        );
    }

    // Regression guard for hazard #2: this must fail if the file were created
    // WITHOUT the 0o600 mode and the assertion above only happened to pass because
    // the ambient umask was already tight. Requesting 0o600 explicitly means the
    // umask can only CLEAR bits it already has cleared in the request — it can
    // never ADD permission bits back — so 0o600 cannot be loosened by any umask.
    // This does not mutate the process umask (that would race concurrently-run
    // test binaries); it only documents/checks the reasoning against a request
    // that deliberately asks for the loosest legal mode, 0o666.
    #[cfg(unix)]
    #[test]
    fn requesting_0o600_is_not_an_umask_accident() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let loose = dir.path().join("loose");
        // A bare `create(true)` file (mode request 0o666, the OS default for a new
        // regular file) picks up whatever the umask allows.
        let _ = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o666)
            .open(&loose)
            .unwrap();
        let loose_mode = std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777;

        // Our sink asks for 0o600 explicitly, which the umask cannot loosen.
        let p = dir.path().join("audit.jsonl");
        AuditSink::open(&p).unwrap();
        let strict_mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;

        assert_eq!(
            strict_mode, 0o600,
            "explicit 0o600 request must be honoured exactly"
        );
        // If the ambient umask were tight enough to produce 0o600 from a 0o666
        // request too, this comparison couldn't distinguish "we asked for 0o600"
        // from "umask happened to be tight" — so assert the loose file is NOT
        // already 0o600, proving the two requests diverge in this environment.
        assert_ne!(
            loose_mode, 0o600,
            "test environment's umask is already this tight; this test cannot \
             distinguish an explicit 0o600 request from an umask accident here"
        );
    }
}
