// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Shared-secret authentication for the daemon. A loopback TCP port is reachable
//! by any local process, unlike a `0600` Unix socket, so the port needs its own
//! access control.

use std::path::Path;

use rand::RngCore;
use subtle::ConstantTimeEq;

/// 256 bits of randomness, base64url without padding.
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

fn base64url(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// Constant-time check of an `Authorization` header value against the token.
/// Constant-time so a local attacker cannot recover the secret byte-by-byte.
pub fn verify(token: &str, header: &str) -> bool {
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    if presented.is_empty() {
        return false;
    }
    presented.as_bytes().ct_eq(token.as_bytes()).into()
}

/// Read the token at `path`, or create one at `0600` if absent.
pub fn load_or_create(path: &Path) -> anyhow::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let t = generate();
    write_private(path, &t)?;
    // Belt and suspenders: `.mode()` in `write_private` only applies when the file
    // is actually created. An existing-but-empty file (falls through the branch
    // above) is opened and truncated in place, so its original permissions stand
    // unless we tighten them here too.
    restrict(path)?;
    Ok(t)
}

/// Create the file with owner-only permissions from the outset. Writing first and
/// chmod'ing after leaves a window — however brief — where the token is readable at
/// the process umask, and this token grants full access to session data.
#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

/// Owner-only permissions. The token grants full access to session data. Public
/// because `audit.rs` reuses it for the audit log, which holds prompts and paths.
#[cfg(unix)]
pub fn restrict(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn restrict(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_long_and_unique() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
        assert!(
            a.len() >= 43,
            "expected >=256 bits base64url, got {}",
            a.len()
        );
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn matching_tokens_verify() {
        let t = generate();
        assert!(verify(&t, &format!("Bearer {t}")));
    }

    #[test]
    fn wrong_missing_and_malformed_headers_all_fail() {
        let t = generate();
        assert!(!verify(&t, &format!("Bearer {}", generate())));
        assert!(!verify(&t, ""));
        assert!(
            !verify(&t, &t),
            "raw token without the Bearer prefix must fail"
        );
        assert!(!verify(&t, "Basic abc"));
        assert!(!verify(&t, "Bearer "));
    }

    #[test]
    fn a_prefix_of_the_token_does_not_verify() {
        let t = generate();
        let short = &t[..t.len() - 1];
        assert!(!verify(&t, &format!("Bearer {short}")));
    }

    #[test]
    fn load_or_create_round_trips_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("token");
        let a = load_or_create(&p).unwrap();
        let b = load_or_create(&p).unwrap();
        assert_eq!(a, b, "a second call must reuse the existing token");
    }

    #[test]
    fn a_whitespace_only_existing_file_is_regenerated_not_returned_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("token");
        std::fs::write(&p, "   \n\t  \n").unwrap();
        let t = load_or_create(&p).unwrap();
        assert!(
            !t.is_empty(),
            "an empty token would disable authentication entirely"
        );
        assert!(t.len() >= 43);
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("token");
        load_or_create(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "token must be 0600, got {:o}", mode);
    }
}
