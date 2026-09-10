// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Persistent per-server manifest pins, and the in-memory cross-server tool-name
//! registry that powers shadowing detection.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use soup_wall_agent::ToolDecl;

/// How many superseded manifests are kept per server.
///
/// History exists so drift can be reviewed after the fact, not so the store
/// becomes an archive: a server that rewrites its manifest on every handshake
/// must not grow this file without bound.
pub const MAX_HISTORY: usize = 10;

/// How much of the readable part of a record filename is kept.
///
/// The discriminator makes the name unique on its own, so truncating here costs
/// legibility and nothing else — while an unbounded `--id` would produce a
/// filename past the 255-byte limit most filesystems impose.
const MAX_STEM: usize = 64;

/// Hex characters of the id digest appended to a record name. Thirty-two bits
/// against accidental collision between operator-chosen ids; this is a
/// uniqueness discriminator, not a security boundary.
const STEM_DIGEST_HEX: usize = 8;

/// One recorded manifest: the pin, and the tools it pinned.
///
/// The tools are the point. Storing only the hash makes drift detectable but
/// unreviewable — the operator learns *that* the manifest changed and can then
/// only accept or reject blindly, which is the outcome a rug-pull is counting on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedManifest {
    pub hash: String,
    /// Empty for a pin written before manifests were retained. Such a pin still
    /// detects drift; it just cannot explain it.
    #[serde(default)]
    pub tools: Vec<ToolDecl>,
    #[serde(default)]
    pub recorded_at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ServerRecord {
    current: Option<PinnedManifest>,
    #[serde(default)]
    history: Vec<PinnedManifest>,
}

/// Persistent per-server manifest record, one file per server under `dir`, mode
/// `0600`. Small and rarely written (once per new/changed server), so a
/// file-per-server keeps it trivially correct with no locking across processes.
pub struct ManifestStore {
    dir: PathBuf,
}

impl ManifestStore {
    pub fn new(dir: &Path) -> Self {
        let _ = fs::create_dir_all(dir);
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// The readable half of a record filename: filesystem-safe regardless of the
    /// `--id` value.
    ///
    /// Deliberately lossy — every character outside `[A-Za-z0-9_-]` becomes
    /// `_`, so no separator and no dot survives and traversal is structurally
    /// impossible. That also makes it **not injective**: `foo.bar`, `foo/bar`
    /// and `foo_bar` all clean to `foo_bar`. Never build a path from this
    /// alone; use [`Self::safe_name`], which restores uniqueness.
    fn stem(server: &str) -> String {
        server
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(MAX_STEM)
            .collect()
    }

    /// A filesystem-safe **and injective** record name.
    ///
    /// Uniqueness is not cosmetic here. This is the pin store: two configured
    /// servers sharing one record file means each `put_manifest` overwrites the
    /// other's pinned hash and history, and the next handshake compares against
    /// a manifest belonging to a different server — so genuine drift reads as
    /// "no change". Of everything this component can get wrong, failing *open*
    /// is the one it cannot afford.
    ///
    /// The discriminator is taken over the **original** string, not the cleaned
    /// one, so ids that clean to the same stem still land in different files.
    fn safe_name(server: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(server.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        format!("{}-{}", Self::stem(server), &digest[..STEM_DIGEST_HEX])
    }

    fn path(&self, server: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::safe_name(server)))
    }

    /// Record location from before `safe_name` gained its discriminator. Read,
    /// never written: a record found here migrates to [`Self::path`] on the
    /// next write.
    fn pre_unique_path(&self, server: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::stem(server)))
    }

    /// Pre-retention pin location: a bare hash, no manifest. Written before the
    /// discriminator existed, so it is addressed by the stem.
    fn legacy_path(&self, server: &str) -> PathBuf {
        self.dir.join(format!("{}.pin", Self::stem(server)))
    }

    fn read_record(&self, server: &str) -> ServerRecord {
        if let Ok(text) = fs::read_to_string(self.path(server)) {
            if let Ok(record) = serde_json::from_str::<ServerRecord>(&text) {
                return record;
            }
        }
        // A record written before names carried a discriminator. Read it so an
        // upgrade does not silently re-pin whatever the server now claims.
        //
        // Two ids that used to collide share this one file, so only the first
        // of them to be handled inherits it; the other is treated as a server
        // never seen before. That is the pre-existing corruption surfacing, not
        // new loss — while they shared a file neither record was trustworthy.
        if let Ok(text) = fs::read_to_string(self.pre_unique_path(server)) {
            if let Ok(record) = serde_json::from_str::<ServerRecord>(&text) {
                return record;
            }
        }
        // An installation that pinned before manifests were retained. Read the
        // hash so drift is still detected on the very next handshake rather than
        // silently re-pinning whatever the server now claims.
        if let Ok(hash) = fs::read_to_string(self.legacy_path(server)) {
            let hash = hash.trim().to_string();
            if !hash.is_empty() {
                return ServerRecord {
                    current: Some(PinnedManifest {
                        hash,
                        tools: Vec::new(),
                        recorded_at_ms: 0,
                    }),
                    history: Vec::new(),
                };
            }
        }
        ServerRecord::default()
    }

    /// The pinned hash, or `None` for a server never seen before.
    pub fn get(&self, server: &str) -> Option<String> {
        self.read_record(server).current.map(|pin| pin.hash)
    }

    /// The pinned manifest, including the tools it pinned when they were retained.
    pub fn get_pinned(&self, server: &str) -> Option<PinnedManifest> {
        self.read_record(server).current
    }

    /// Superseded manifests, newest first.
    pub fn history(&self, server: &str) -> Vec<PinnedManifest> {
        self.read_record(server).history
    }

    /// Record a manifest as the current pin, retiring the previous one into
    /// history.
    pub fn put_manifest(
        &self,
        server: &str,
        hash: &str,
        tools: &[ToolDecl],
        recorded_at_ms: u64,
    ) -> std::io::Result<()> {
        let mut record = self.read_record(server);
        if let Some(previous) = record.current.take() {
            // Re-pinning an identical manifest is not a history entry; only real
            // supersessions are worth keeping.
            if previous.hash != hash {
                record.history.insert(0, previous);
                record.history.truncate(MAX_HISTORY);
            }
        }
        record.current = Some(PinnedManifest {
            hash: hash.to_string(),
            tools: tools.to_vec(),
            recorded_at_ms,
        });

        let path = self.path(server);
        let body = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        // Superseded locations are now stale and would mislead anyone reading
        // the directory by hand. Removing the pre-unique file is also what
        // completes the migration: the record now lives under its unique name.
        let _ = fs::remove_file(self.legacy_path(server));
        let _ = fs::remove_file(self.pre_unique_path(server));
        Ok(())
    }
}

const BUILTINS: &[&str] = &[
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Task",
];

/// In-memory map of `tool name -> owning server id`, seeded with the builtins under a
/// reserved owner. A name already owned by a *different* server (or a builtin) is a
/// shadow. Rebuilt at daemon start from the pin directory.
pub struct ToolRegistry {
    owner: Mutex<HashMap<String, String>>,
}

impl ToolRegistry {
    pub fn with_builtins() -> Self {
        let mut m = HashMap::new();
        for b in BUILTINS {
            m.insert((*b).to_string(), "<builtin>".to_string());
        }
        Self {
            owner: Mutex::new(m),
        }
    }

    /// The first name in `names` already owned by someone other than `server`, if any.
    pub fn shadows(&self, server: &str, names: &[String]) -> Option<String> {
        let m = self.owner.lock().ok()?;
        names
            .iter()
            .find(|n| m.get(*n).is_some_and(|o| o != server))
            .cloned()
    }

    /// Claim these names for `server` (idempotent). Unowned names become its; names
    /// owned by others are left as-is (already flagged by `shadows`).
    pub fn record(&self, server: &str, names: &[String]) {
        if let Ok(mut m) = self.owner.lock() {
            for n in names {
                m.entry(n.clone()).or_insert_with(|| server.to_string());
            }
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

/// Rebuild a registry at daemon start. Pins store the manifest hash, not the tool
/// names, so cross-server shadowing is enforced within a daemon run once each server
/// has re-handshaked (clients re-handshake every server at startup). Kept as a named
/// entry point so the startup wiring is explicit.
pub fn seed_registry(_store: &ManifestStore) -> ToolRegistry {
    ToolRegistry::with_builtins()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());
        assert!(store.get("github").is_none(), "no pin at first sight");
        store.put_manifest("github", "hash-abc", &[], 0).unwrap();
        assert_eq!(store.get("github").as_deref(), Some("hash-abc"));

        // A fresh store over the same dir sees the persisted pin.
        let reopened = ManifestStore::new(dir.path());
        assert_eq!(reopened.get("github").as_deref(), Some("hash-abc"));
    }

    fn tool(name: &str, desc: &str) -> ToolDecl {
        ToolDecl {
            name: name.into(),
            description: desc.into(),
            schema: serde_json::Value::Null,
        }
    }

    /// The whole point of retention: after a restart the previous manifest is
    /// still there, so drift can be explained rather than merely detected.
    #[test]
    fn the_pinned_manifest_survives_a_restart_so_drift_can_be_diffed() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());
        let before = vec![tool("search", "Search the docs.")];
        store.put_manifest("docs", "h1", &before, 1_000).unwrap();

        let reopened = ManifestStore::new(dir.path());
        let pinned = reopened.get_pinned("docs").expect("pin survives");
        assert_eq!(pinned.hash, "h1");
        assert_eq!(pinned.tools, before, "the tools themselves are retained");
        assert_eq!(pinned.recorded_at_ms, 1_000);
    }

    #[test]
    fn a_superseded_manifest_moves_into_bounded_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());
        for i in 0..(MAX_HISTORY + 5) {
            let tools = vec![tool("t", &format!("v{i}"))];
            store
                .put_manifest("docs", &format!("h{i}"), &tools, i as u64)
                .unwrap();
        }
        let history = store.history("docs");
        assert_eq!(history.len(), MAX_HISTORY, "history must stay bounded");
        assert_eq!(
            history[0].hash,
            format!("h{}", MAX_HISTORY + 3),
            "newest superseded entry first"
        );
        assert_eq!(
            store.get("docs").as_deref(),
            Some(format!("h{}", MAX_HISTORY + 4).as_str())
        );
    }

    /// Re-pinning the same manifest is not a change and must not consume a
    /// history slot, or a chatty server would evict the real previous version.
    #[test]
    fn re_pinning_an_identical_manifest_adds_no_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());
        let tools = vec![tool("t", "same")];
        for _ in 0..5 {
            store.put_manifest("docs", "h-same", &tools, 0).unwrap();
        }
        assert!(store.history("docs").is_empty());
    }

    /// An installation that pinned before manifests were retained must keep
    /// detecting drift, not silently re-pin whatever the server now claims.
    #[test]
    fn a_legacy_hash_only_pin_still_detects_drift() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("docs.pin"),
            "legacy-hash
",
        )
        .unwrap();

        let store = ManifestStore::new(dir.path());
        assert_eq!(store.get("docs").as_deref(), Some("legacy-hash"));
        let pinned = store.get_pinned("docs").expect("legacy pin is readable");
        assert!(
            pinned.tools.is_empty(),
            "a legacy pin has no manifest to diff against"
        );

        // Writing the new format retires the legacy file rather than leaving a
        // stale one to mislead anyone reading the directory.
        store
            .put_manifest("docs", "h-new", &[tool("t", "d")], 5)
            .unwrap();
        assert!(!dir.path().join("docs.pin").exists());
        assert_eq!(store.get("docs").as_deref(), Some("h-new"));
        assert_eq!(store.history("docs").len(), 1, "the legacy pin is history");
    }

    /// The defect this store cannot tolerate: the filename sanitizer maps every
    /// character outside `[A-Za-z0-9_-]` to `_`, so distinct ids used to clean
    /// onto one record file. One server's pin then overwrote the other's, and
    /// the next handshake compared a manifest against a *different server's*
    /// pin — real drift reading as "no change", which is failing open.
    #[test]
    fn ids_differing_only_in_replaced_characters_do_not_share_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());

        // All four clean to the same stem, `foo_bar`.
        let ids = ["foo.bar", "foo/bar", "foo bar", "foo_bar"];
        for (i, id) in ids.iter().enumerate() {
            store
                .put_manifest(id, &format!("hash-{i}"), &[], i as u64)
                .unwrap();
        }

        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                store.get(id).as_deref(),
                Some(format!("hash-{i}").as_str()),
                "{id} must keep its own pin, not the last writer's"
            );
            assert!(
                store.history(id).is_empty(),
                "{id} was never superseded, so nothing belongs in its history"
            );
        }

        let mut paths: Vec<_> = ids.iter().map(|id| store.path(id)).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), ids.len(), "one record file per id");
    }

    /// A long `--id` must not produce a filename past the limit filesystems
    /// impose, and truncating must not reintroduce the collision it was the
    /// discriminator's job to prevent.
    #[test]
    fn a_long_id_is_bounded_and_still_unique() {
        let a = format!("{}-alpha", "x".repeat(400));
        let b = format!("{}-beta", "x".repeat(400));
        let name_a = ManifestStore::safe_name(&a);
        let name_b = ManifestStore::safe_name(&b);

        assert!(name_a.len() <= MAX_STEM + 1 + STEM_DIGEST_HEX);
        assert_ne!(
            name_a, name_b,
            "ids sharing a truncated stem must still differ by digest"
        );
    }

    /// Upgrade path: a record written before names carried a discriminator is
    /// read, not ignored — otherwise the upgrade would silently re-pin whatever
    /// the server presented next, which is the rug-pull this store exists to
    /// catch.
    #[test]
    fn a_record_written_before_the_discriminator_is_migrated_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());

        // Write one in the old location, by the old rules.
        let old_path = dir.path().join("docs.json");
        let old_record = serde_json::json!({
            "current": { "hash": "pinned-before-upgrade", "tools": [], "recorded_at_ms": 7 },
            "history": []
        });
        std::fs::write(&old_path, serde_json::to_string(&old_record).unwrap()).unwrap();

        assert_eq!(
            store.get("docs").as_deref(),
            Some("pinned-before-upgrade"),
            "the pre-upgrade pin must still be found"
        );

        // Writing migrates it: the record moves under the unique name and the
        // old file is retired rather than left to mislead a reader.
        store.put_manifest("docs", "after-upgrade", &[], 8).unwrap();
        assert!(!old_path.exists(), "the pre-unique file is retired");
        assert!(
            store.path("docs").exists(),
            "the record now lives under its unique name"
        );

        let reopened = ManifestStore::new(dir.path());
        assert_eq!(reopened.get("docs").as_deref(), Some("after-upgrade"));
        assert_eq!(
            reopened.history("docs").first().map(|p| p.hash.as_str()),
            Some("pinned-before-upgrade"),
            "the migrated pin is superseded, not discarded"
        );
    }

    #[test]
    fn the_registry_flags_a_name_owned_by_another_server_or_a_builtin() {
        let reg = ToolRegistry::with_builtins();
        assert!(reg.shadows("srvA", &["safe_name".into()]).is_none());
        reg.record("srvA", &["shared".into(), "safe_name".into()]);

        // Same server re-declaring its own names is not a shadow.
        assert!(reg.shadows("srvA", &["shared".into()]).is_none());
        // A different server claiming a name srvA owns is.
        assert_eq!(
            reg.shadows("srvB", &["shared".into()]),
            Some("shared".to_string())
        );
        // Colliding with a builtin is.
        assert_eq!(
            reg.shadows("srvC", &["Bash".into()]),
            Some("Bash".to_string())
        );
    }
}
