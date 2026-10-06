#![forbid(unsafe_code)]

//! # ⚠ HAZMAT — AES-CBC (unauthenticated) ⚠
//!
//! AES-CBC with PKCS#7 / ISO 10126 padding, provided solely for legacy
//! interop (XML Encryption 1.0/1.1, older CMS profiles). See
//! [`crate::hazmat`] for the top-level warning.
//!
//! Use AES-GCM via [`crate::cipher`] for any new protocol. If you
//! genuinely need CBC for interop, you **must** wrap these outputs
//! with an HMAC over `IV || ciphertext` using a separate key and
//! verify that HMAC in constant time before calling [`decrypt`].
//!
//! ## Wire format
//!
//! `encrypt` prepends a 16-byte random IV to the ciphertext:
//! `IV || PKCS#7-padded-ciphertext`. `decrypt` expects the same layout
//! and accepts either PKCS#7 or ISO 10126 padding on the way back (for
//! XML-Enc compatibility).
//!
//! ## Error handling
//!
//! [`decrypt`] deliberately collapses every post-key-check failure
//! (wrong IV-less input length, wrong key for the ciphertext, bad
//! padding, internal RustCrypto error) into a single opaque
//! `Error::Crypto("AES-CBC decrypt failed")`. This narrows the
//! padding oracle but **does not close it** — timing differences
//! between the failure paths are still observable, and an attacker
//! who can repeatedly submit chosen ciphertexts to a real decryption
//! oracle will still recover plaintext. Authenticate your ciphertexts.

use crate::algorithm::AesKeySize;
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crate::software::cipher::{pkcs7_pad, xmlenc_unpad};

/// Encrypt `plaintext` under `key` using AES-CBC with PKCS#7 padding.
///
/// Prepends a freshly-generated 16-byte random IV to the ciphertext.
/// The output is **unauthenticated**; see the module-level warning.
pub fn encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Encrypt(
        crate::algorithm::CipherAlgorithm::AesCbc(size),
    ))?;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    let mut iv = [0u8; 16];
    crate::backend::fill_random(&mut iv)?;

    let mut buf = pkcs7_pad(plaintext, 16);
    let buf_len = buf.len();

    macro_rules! do_encrypt {
        ($aes:ty) => {{
            let enc = cbc::Encryptor::<$aes>::new_from_slices(key, &iv)
                .map_err(|e| Error::Crypto(format!("AES-CBC init: {e}")))?;
            enc.encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
                .map_err(|e| Error::Crypto(format!("AES-CBC encrypt: {e}")))?;
        }};
    }

    match size {
        AesKeySize::Aes128 => do_encrypt!(aes::Aes128),
        AesKeySize::Aes192 => do_encrypt!(aes::Aes192),
        AesKeySize::Aes256 => do_encrypt!(aes::Aes256),
    }

    let mut result = Vec::with_capacity(16 + buf.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);
    Ok(result)
}

/// Decrypt `data` (`IV || ciphertext`) under `key` using AES-CBC.
///
/// Every post-key-check failure collapses to
/// `Error::Crypto("AES-CBC decrypt failed")` to narrow (not close) the
/// padding oracle. See the module-level warning — authenticate the
/// ciphertext before calling this.
pub fn decrypt(size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Decrypt(
        crate::algorithm::CipherAlgorithm::AesCbc(size),
    ))?;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    // From here down, every error path returns the same opaque message.
    let opaque = || Error::Crypto("AES-CBC decrypt failed".into());

    // IV plus at least one ciphertext block; an IV-only input has no
    // padding to check and must not decrypt to an empty plaintext.
    if data.len() < 32 || !data.len().is_multiple_of(16) {
        return Err(opaque());
    }

    let iv = &data[..16];
    let ciphertext = &data[16..];
    let mut buf = ciphertext.to_vec();

    macro_rules! do_decrypt {
        ($aes:ty) => {{
            let dec = cbc::Decryptor::<$aes>::new_from_slices(key, iv).map_err(|_| opaque())?;
            dec.decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| opaque())?;
        }};
    }

    match size {
        AesKeySize::Aes128 => do_decrypt!(aes::Aes128),
        AesKeySize::Aes192 => do_decrypt!(aes::Aes192),
        AesKeySize::Aes256 => do_decrypt!(aes::Aes256),
    }

    xmlenc_unpad(&buf, 16).map_err(|_| opaque())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_sizes() {
        let cases: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let plaintexts: &[&[u8]] = &[
            b"A",
            b"Hello",
            b"Hello, World!",
            b"Exactly16bytes!!",
            b"This is a much longer test message that spans multiple AES blocks.",
        ];

        for &(size, key_len) in cases {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            for &pt in plaintexts {
                let ct = encrypt(size, &key, pt).unwrap();
                let decrypted = decrypt(size, &key, &ct).unwrap();
                assert_eq!(decrypted, pt, "roundtrip {size:?} pt_len={}", pt.len());
            }
        }
    }

    #[test]
    fn decrypt_errors_are_opaque() {
        // Every post-key-check failure must return the same message so
        // that callers cannot distinguish padding errors from ciphertext
        // errors. This narrows the padding oracle; see module docs for
        // why it does not eliminate it.
        //
        // Deterministic failure paths only — an earlier version of this
        // test flipped a bit in a random-IV ciphertext, which invalidated
        // the padding only probabilistically (~94% of the time). A flaky
        // opaque-error test would hide real regressions.
        let key = [0x42u8; 16];
        let expected = "AES-CBC decrypt failed";

        // Length below one full block: trips the structural length check.
        let err = decrypt(AesKeySize::Aes128, &key, &[0u8; 8]).unwrap_err();
        assert!(err.to_string().contains(expected), "got {err}");

        // Empty input: same branch.
        let err = decrypt(AesKeySize::Aes128, &key, &[]).unwrap_err();
        assert!(err.to_string().contains(expected), "got {err}");

        // IV only, no ciphertext block: must not decrypt to Ok(empty).
        let err = decrypt(AesKeySize::Aes128, &key, &[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains(expected), "got {err}");

        // Non-block-aligned input of otherwise-sufficient size: same
        // branch via the `% 16 != 0` check.
        let err = decrypt(AesKeySize::Aes128, &key, &[0u8; 33]).unwrap_err();
        assert!(err.to_string().contains(expected), "got {err}");

        // Deterministic bad-padding path: construct a ciphertext whose
        // decrypted pad byte is guaranteed to be 0x00, which xmlenc_unpad
        // always rejects.
        //
        // Strategy: encrypt a 16-byte plaintext (forces a second block of
        // full 0x10 padding), then XOR the second-to-last ciphertext byte
        // with 0x10. That bit flip propagates through CBC to the last
        // byte of P_2, turning pad=0x10 into pad=0x00 on decrypt.
        let ct = encrypt(AesKeySize::Aes128, &key, b"sixteen-byte-msg").unwrap();
        assert_eq!(ct.len(), 48, "IV(16) + 2 blocks(32) expected");
        let mut bad = ct.clone();
        // ct layout: IV[0..16] || C_1[16..32] || C_2[32..48].
        // P_2 = D(C_2) XOR C_1. Flipping C_1's last bit flips P_2's last bit.
        bad[31] ^= 0x10;
        let err = decrypt(AesKeySize::Aes128, &key, &bad).unwrap_err();
        assert!(err.to_string().contains(expected), "got {err}");
    }

    #[test]
    fn key_size_error_is_distinct() {
        // Key-size errors are structural (attacker can't influence them by
        // submitting ciphertexts), so they're allowed to be distinct and
        // helpful. Pin this so it doesn't regress into the opaque path.
        let err = decrypt(AesKeySize::Aes128, &[0u8; 15], &[0u8; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("16 byte key"), "got {msg}");
    }
}
