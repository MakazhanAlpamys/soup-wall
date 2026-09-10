// SPDX-License-Identifier: Apache-2.0

//! Single-use, expiring human approvals bound to one exact action.
//!
//! # What this defends against, and what it does not
//!
//! The grant exists so that **the agent cannot approve its own actions**. A
//! sandboxed tool process has no access to the daemon's key material, so it
//! cannot mint a grant however it is manipulated, and it cannot reuse one it
//! observed: a grant names the exact session, tool, and argument fingerprint it
//! was issued for, expires, and is consumed on first use.
//!
//! It is **not** a defense against a local attacker already running as the
//! operator. Such an attacker can read the key and mint whatever they like.
//! Claiming otherwise would be dishonest: the boundary here is the sandbox and
//! the filesystem mode, and the signature is what makes that boundary mean
//! something to the daemon rather than being re-derivable from a bare filename.
//!
//! The approval also binds to arguments, not just to a tool. Approving
//! `rm -rf ./build` must not authorize `rm -rf /`, and a grant that only said
//! "Bash was approved" would do exactly that.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How long a freshly minted approval stays usable.
///
/// Short on purpose: an approval is a human decision about a specific moment,
/// and an hour-old "yes" is no longer evidence that the human still means it.
pub const DEFAULT_TTL_MS: u64 = 5 * 60 * 1000;

/// The exact action a human is approving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRef {
    pub session: String,
    pub tool: String,
    /// Fingerprint of the exact arguments, from [`action_fingerprint`].
    pub args_fingerprint: String,
}

/// Fingerprint the arguments a tool is about to run with.
///
/// Canonicalized so that key order does not change the identity of an action —
/// otherwise a re-serialization between the prompt and the call would look like
/// a different action and silently invalidate a legitimate approval.
pub fn action_fingerprint(tool: &str, args: &serde_json::Value) -> String {
    let mut hash = Sha256::new();
    hash.update(b"agentfw/approval/v1\0");
    hash.update(tool.as_bytes());
    hash.update([0u8]);
    hash.update(canonical(args).to_string().as_bytes());
    format!("{:x}", hash.finalize())
}

fn canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> =
                map.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            serde_json::to_value(sorted).unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical).collect())
        }
        other => other.clone(),
    }
}

/// A minted approval. Carries no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub session: String,
    pub tool: String,
    pub args_fingerprint: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Single-use identifier. Consumption is tracked by the ledger, not here.
    pub nonce: String,
    /// Hex HMAC-SHA256 over every field above.
    pub signature: String,
}

/// Why a grant was not accepted. Each variant is a distinct refusal so an
/// operator can tell "you waited too long" from "this is not the action you
/// approved" — collapsing them into one error would make the feature
/// undebuggable and tempt operators to work around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    BadSignature,
    Expired,
    /// Issued in the future by more than the allowed skew.
    NotYetValid,
    ActionMismatch,
    AlreadyUsed,
}

impl GrantError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::BadSignature => "approval signature does not verify",
            Self::Expired => "approval has expired",
            Self::NotYetValid => "approval is dated in the future",
            Self::ActionMismatch => "approval was issued for a different action",
            Self::AlreadyUsed => "approval was already used",
        }
    }
}

/// Tolerance for a clock that ran slightly ahead when the grant was minted.
/// Small: this exists for clock jitter, not for accepting future-dated approvals.
const FUTURE_SKEW_MS: u64 = 5_000;

fn signing_input(grant: &Grant) -> Vec<u8> {
    // Length-prefixed so no field can impersonate part of another: without it a
    // session ending in a separator could shift the tool boundary and produce a
    // colliding input for a different action.
    let mut out = Vec::new();
    for field in [
        grant.session.as_str(),
        grant.tool.as_str(),
        grant.args_fingerprint.as_str(),
        grant.nonce.as_str(),
    ] {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(&grant.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&grant.expires_at_ms.to_be_bytes());
    out
}

fn sign(key: &[u8], grant: &Grant) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&signing_input(grant));
    format!("{:x}", mac.finalize().into_bytes())
}

/// Derive the approval-signing key from the daemon token.
///
/// Domain-separated so the two never coincide: a component that legitimately
/// holds the hook token must not thereby be able to mint approvals, and a leaked
/// approval must not disclose the token.
pub fn derive_key(token: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"agentfw/approval-key/v1\0");
    hash.update(token.as_bytes());
    hash.finalize().to_vec()
}

/// Mint an approval for one action.
pub fn mint(
    key: &[u8],
    action: &ActionRef,
    issued_at_ms: u64,
    ttl_ms: u64,
    nonce: String,
) -> Grant {
    let mut grant = Grant {
        session: action.session.clone(),
        tool: action.tool.clone(),
        args_fingerprint: action.args_fingerprint.clone(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_ms),
        nonce,
        signature: String::new(),
    };
    grant.signature = sign(key, &grant);
    grant
}

/// Verify a grant against the action actually about to run.
///
/// Order matters: the signature is checked first, so an unsigned or forged
/// grant is rejected before any of its self-reported fields are believed.
pub fn verify(
    key: &[u8],
    grant: &Grant,
    action: &ActionRef,
    now_ms: u64,
) -> Result<(), GrantError> {
    let expected = sign(key, grant);
    if !bool::from(expected.as_bytes().ct_eq(grant.signature.as_bytes())) {
        return Err(GrantError::BadSignature);
    }
    if grant.issued_at_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
        return Err(GrantError::NotYetValid);
    }
    if now_ms >= grant.expires_at_ms {
        return Err(GrantError::Expired);
    }
    if grant.session != action.session
        || grant.tool != action.tool
        || grant.args_fingerprint != action.args_fingerprint
    {
        return Err(GrantError::ActionMismatch);
    }
    Ok(())
}

/// Records which approvals have been spent, so one "yes" authorizes one action.
///
/// Persisted rather than held in memory: a grant outlives a daemon restart, so
/// an in-memory ledger would let a restart inside the TTL replay it. Entries are
/// pruned once past their own expiry, which bounds the file without a policy —
/// a spent nonce stops mattering exactly when the grant it belongs to could no
/// longer be used anyway.
pub struct GrantLedger {
    path: std::path::PathBuf,
    spent: std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
}

impl GrantLedger {
    pub fn open(path: &std::path::Path) -> Self {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let spent = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| {
                serde_json::from_str::<std::collections::BTreeMap<String, u64>>(&text).ok()
            })
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            spent: std::sync::Mutex::new(spent),
        }
    }

    /// Claim a grant. `Ok(())` exactly once per nonce; every later attempt is
    /// [`GrantError::AlreadyUsed`].
    ///
    /// A ledger that cannot be written refuses the claim rather than allowing an
    /// unrecordable approval: an approval nobody can prove was spent is one an
    /// attacker can spend again.
    pub fn claim(&self, grant: &Grant, now_ms: u64) -> Result<(), GrantError> {
        let mut spent = self.spent.lock().map_err(|_| GrantError::AlreadyUsed)?;
        spent.retain(|_, expires_at| *expires_at > now_ms);
        if spent.contains_key(&grant.nonce) {
            return Err(GrantError::AlreadyUsed);
        }
        spent.insert(grant.nonce.clone(), grant.expires_at_ms);
        let body = serde_json::to_string(&*spent).map_err(|_| GrantError::AlreadyUsed)?;
        if std::fs::write(&self.path, body).is_err() {
            spent.remove(&grant.nonce);
            return Err(GrantError::AlreadyUsed);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Directory of approvals an operator has issued but the daemon has not yet
/// matched to a call. One file per grant, owner-only.
///
/// A directory rather than one appended file so an operator can inspect and
/// revoke a pending approval with `ls` and `rm`, which is the only revocation
/// mechanism that still works when the daemon is not running.
pub struct GrantStore {
    dir: std::path::PathBuf,
}

impl GrantStore {
    pub fn new(dir: &std::path::Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Same lossy character map as the manifest store's, and therefore not
    /// injective in general — but here it never has to be. A nonce comes from
    /// [`crate::token::generate`], which emits base64url without padding, and
    /// that alphabet is exactly `[A-Za-z0-9-_]`: the set this map preserves. On
    /// a real nonce the map is the identity, so two grants cannot collide onto
    /// one file. `nonces_are_already_in_the_preserved_alphabet` holds that
    /// invariant in place; if the generator's alphabet ever widens, it fails
    /// here rather than silently clobbering a pending approval.
    ///
    /// Unlike the manifest store this needs no discriminator, and adding one
    /// would break every pending grant file on disk for no gain.
    fn file_name(nonce: &str) -> String {
        let safe: String = nonce
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{safe}.json")
    }

    pub fn write(&self, grant: &Grant) -> std::io::Result<std::path::PathBuf> {
        let path = self.dir.join(Self::file_name(&grant.nonce));
        let body = serde_json::to_string_pretty(grant)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    /// Every readable pending grant. Unparsable files are skipped rather than
    /// fatal: a half-written or hand-edited file must not stop a legitimate
    /// approval sitting beside it from being found.
    pub fn pending(&self) -> Vec<Grant> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .filter_map(|text| serde_json::from_str::<Grant>(&text).ok())
            .collect()
    }

    /// Best-effort removal after a grant is spent. The ledger, not this file, is
    /// what makes single use authoritative — a failed delete must not turn into
    /// a second authorization.
    pub fn discard(&self, grant: &Grant) {
        let _ = std::fs::remove_file(self.dir.join(Self::file_name(&grant.nonce)));
    }
}

/// Find and spend an approval for exactly this action, if the operator issued one.
///
/// Returns the redeemed grant, or `None` when no pending approval matched. A
/// grant that matched but failed to redeem (expired, already used) is reported
/// through `on_refusal` so the refusal is auditable instead of looking like the
/// operator never approved anything.
pub fn redeem_pending(
    key: &[u8],
    store: &GrantStore,
    ledger: &GrantLedger,
    action: &ActionRef,
    now_ms: u64,
    mut on_refusal: impl FnMut(&Grant, GrantError),
) -> Option<Grant> {
    for grant in store.pending() {
        match redeem(key, &grant, action, now_ms, ledger) {
            Ok(()) => {
                store.discard(&grant);
                return Some(grant);
            }
            // Not this action: silent, since every unrelated pending approval
            // lands here and logging them all would drown the real refusals.
            Err(GrantError::ActionMismatch) => {}
            Err(error) => on_refusal(&grant, error),
        }
    }
    None
}

/// Verify a grant and spend it in one step. This is the only entry point callers
/// should use: verifying without claiming would leave a valid grant reusable.
pub fn redeem(
    key: &[u8],
    grant: &Grant,
    action: &ActionRef,
    now_ms: u64,
    ledger: &GrantLedger,
) -> Result<(), GrantError> {
    verify(key, grant, action, now_ms)?;
    ledger.claim(grant, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-material";
    const NOW: u64 = 1_000_000;

    /// `file_name` uses the same lossy map as the manifest store, where it was
    /// a real defect: distinct ids collided onto one file. It is safe here only
    /// because a nonce is base64url, whose alphabet is exactly the set the map
    /// preserves. That is the load-bearing fact, so assert it rather than
    /// trusting the two functions to stay in agreement.
    #[test]
    fn nonces_are_already_in_the_preserved_alphabet() {
        for _ in 0..64 {
            let nonce = crate::token::generate();
            assert!(
                nonce
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "nonce {nonce} left the alphabet file_name preserves"
            );
            assert_eq!(
                GrantStore::file_name(&nonce),
                format!("{nonce}.json"),
                "the sanitizer must be the identity on a real nonce"
            );
        }
    }

    fn action() -> ActionRef {
        ActionRef {
            session: "s1".into(),
            tool: "Bash".into(),
            args_fingerprint: action_fingerprint(
                "Bash",
                &serde_json::json!({"command": "rm -rf ./build"}),
            ),
        }
    }

    fn granted() -> Grant {
        mint(KEY, &action(), NOW, DEFAULT_TTL_MS, "nonce-1".into())
    }

    #[test]
    fn a_fresh_grant_verifies_for_the_action_it_was_issued_for() {
        assert_eq!(verify(KEY, &granted(), &action(), NOW + 1), Ok(()));
    }

    /// The core binding: approving one command must not authorize another. A
    /// grant that only named the tool would turn "yes, delete ./build" into
    /// "yes, run any shell command".
    #[test]
    fn a_grant_does_not_authorize_different_arguments() {
        let destructive = ActionRef {
            args_fingerprint: action_fingerprint(
                "Bash",
                &serde_json::json!({"command": "rm -rf /"}),
            ),
            ..action()
        };
        assert_eq!(
            verify(KEY, &granted(), &destructive, NOW + 1),
            Err(GrantError::ActionMismatch)
        );
    }

    #[test]
    fn a_grant_does_not_cross_sessions_or_tools() {
        let other_session = ActionRef {
            session: "s2".into(),
            ..action()
        };
        assert_eq!(
            verify(KEY, &granted(), &other_session, NOW + 1),
            Err(GrantError::ActionMismatch)
        );
        let other_tool = ActionRef {
            tool: "Write".into(),
            ..action()
        };
        assert_eq!(
            verify(KEY, &granted(), &other_tool, NOW + 1),
            Err(GrantError::ActionMismatch)
        );
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let grant = granted();
        assert_eq!(
            verify(KEY, &grant, &action(), grant.expires_at_ms),
            Err(GrantError::Expired),
            "expiry is exclusive: the moment it expires it is already unusable"
        );
    }

    /// A grant minted under another key must not verify, whatever it claims.
    #[test]
    fn a_grant_from_a_different_key_is_refused() {
        let forged = mint(b"other-key", &action(), NOW, DEFAULT_TTL_MS, "n".into());
        assert_eq!(
            verify(KEY, &forged, &action(), NOW + 1),
            Err(GrantError::BadSignature)
        );
    }

    /// Every field is covered by the signature, so none can be edited after
    /// minting -- in particular the expiry.
    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let base = granted();
        let mutations: Vec<Grant> = vec![
            Grant {
                expires_at_ms: base.expires_at_ms + 86_400_000,
                ..base.clone()
            },
            Grant {
                session: "s2".into(),
                ..base.clone()
            },
            Grant {
                tool: "Write".into(),
                ..base.clone()
            },
            Grant {
                args_fingerprint: "deadbeef".into(),
                ..base.clone()
            },
            Grant {
                nonce: "nonce-2".into(),
                ..base.clone()
            },
            Grant {
                issued_at_ms: base.issued_at_ms - 1,
                ..base.clone()
            },
        ];
        for mutated in mutations {
            assert_eq!(
                verify(KEY, &mutated, &action(), NOW + 1),
                Err(GrantError::BadSignature),
                "field change must invalidate: {mutated:?}"
            );
        }
    }

    /// The signature is checked before any self-reported field is believed, so a
    /// forged grant is rejected as forged rather than as expired -- an operator
    /// chasing "expired" would waste time re-approving instead of investigating.
    #[test]
    fn a_forged_and_expired_grant_reports_the_forgery_first() {
        let mut forged = mint(b"other-key", &action(), 0, 1, "n".into());
        forged.signature = "00".repeat(32);
        assert_eq!(
            verify(KEY, &forged, &action(), NOW),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn a_future_dated_grant_is_refused_beyond_clock_skew() {
        let future = mint(KEY, &action(), NOW + 60_000, DEFAULT_TTL_MS, "n".into());
        assert_eq!(
            verify(KEY, &future, &action(), NOW),
            Err(GrantError::NotYetValid)
        );
        // Small skew is tolerated rather than turning clock jitter into a refusal.
        let jittered = mint(KEY, &action(), NOW + 1_000, DEFAULT_TTL_MS, "n".into());
        assert_eq!(verify(KEY, &jittered, &action(), NOW), Ok(()));
    }

    /// Key order in the arguments is not a different action. A re-serialization
    /// between approval and execution must not silently void a legitimate grant.
    #[test]
    fn argument_key_order_does_not_change_the_fingerprint() {
        let a = action_fingerprint("Bash", &serde_json::json!({"a": 1, "b": {"x": 1, "y": 2}}));
        let b = action_fingerprint("Bash", &serde_json::json!({"b": {"y": 2, "x": 1}, "a": 1}));
        assert_eq!(a, b);
    }

    /// Different tools with identical arguments are different actions.
    #[test]
    fn the_tool_is_part_of_the_fingerprint() {
        let args = serde_json::json!({"path": "x"});
        assert_ne!(
            action_fingerprint("Read", &args),
            action_fingerprint("Write", &args)
        );
    }

    /// One approval authorizes one action. The second attempt is refused even
    /// though the grant is still perfectly valid and unexpired.
    #[test]
    fn a_grant_can_only_be_redeemed_once() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = GrantLedger::open(&dir.path().join("spent.json"));
        let grant = granted();
        assert_eq!(redeem(KEY, &grant, &action(), NOW + 1, &ledger), Ok(()));
        assert_eq!(
            redeem(KEY, &grant, &action(), NOW + 2, &ledger),
            Err(GrantError::AlreadyUsed)
        );
    }

    /// The reason the ledger is on disk: a restart inside the TTL must not
    /// resurrect a spent approval.
    #[test]
    fn a_spent_grant_stays_spent_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spent.json");
        let grant = granted();
        {
            let ledger = GrantLedger::open(&path);
            assert_eq!(redeem(KEY, &grant, &action(), NOW + 1, &ledger), Ok(()));
        }
        let reopened = GrantLedger::open(&path);
        assert_eq!(
            redeem(KEY, &grant, &action(), NOW + 2, &reopened),
            Err(GrantError::AlreadyUsed),
            "an in-memory ledger would have forgotten this"
        );
    }

    /// Spent nonces are pruned once the grants they belong to could no longer be
    /// used, so the file does not grow without bound.
    #[test]
    fn spent_entries_are_pruned_once_they_can_no_longer_matter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spent.json");
        let ledger = GrantLedger::open(&path);
        let old = mint(KEY, &action(), NOW, 1_000, "old".into());
        assert_eq!(redeem(KEY, &old, &action(), NOW + 1, &ledger), Ok(()));

        // Well past the first grant's expiry: claiming anything prunes it.
        let fresh = mint(KEY, &action(), NOW + 10_000, DEFAULT_TTL_MS, "new".into());
        assert_eq!(
            redeem(KEY, &fresh, &action(), NOW + 10_001, &ledger),
            Ok(())
        );
        let stored: std::collections::BTreeMap<String, u64> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(!stored.contains_key("old"), "expired entry must be pruned");
        assert!(stored.contains_key("new"));
    }

    /// An invalid grant must never reach the ledger: recording it would burn a
    /// nonce an attacker chose and could be used to evict a legitimate one.
    #[test]
    fn a_grant_that_fails_verification_is_not_recorded_as_spent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spent.json");
        let ledger = GrantLedger::open(&path);
        let forged = mint(b"other-key", &action(), NOW, DEFAULT_TTL_MS, "n".into());
        assert_eq!(
            redeem(KEY, &forged, &action(), NOW + 1, &ledger),
            Err(GrantError::BadSignature)
        );
        assert!(
            !path.exists() || !std::fs::read_to_string(&path).unwrap().contains("\"n\""),
            "a rejected grant must not consume its nonce"
        );
    }

    /// Length-prefixing keeps one field from impersonating part of another.
    #[test]
    fn field_boundaries_cannot_be_shifted_between_session_and_tool() {
        let left = mint(
            KEY,
            &ActionRef {
                session: "ab".into(),
                tool: "c".into(),
                args_fingerprint: "f".into(),
            },
            NOW,
            DEFAULT_TTL_MS,
            "n".into(),
        );
        let right = mint(
            KEY,
            &ActionRef {
                session: "a".into(),
                tool: "bc".into(),
                args_fingerprint: "f".into(),
            },
            NOW,
            DEFAULT_TTL_MS,
            "n".into(),
        );
        assert_ne!(
            left.signature, right.signature,
            "concatenation without length prefixes would collide here"
        );
    }
}
