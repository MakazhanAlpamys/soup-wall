#![forbid(unsafe_code)]

//! Block cipher operations (AES-GCM, optionally 3DES-CBC).
//!
//! AES-CBC used to live here as well. It now lives in
//! [`crate::hazmat::aes_cbc`] because unauthenticated CBC with a
//! public decrypt API is a padding-oracle hazard. Prefer AES-GCM.

use crate::algorithm::{AesKeySize, CipherAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};

/// Encrypt `plaintext` using the given block cipher algorithm and `key`.
///
/// For AES-GCM a random 12-byte nonce is prepended. For 3DES-CBC
/// (legacy) a random 8-byte IV is prepended with PKCS#7 padding.
///
/// AES-CBC is **not** dispatched here — it lives in
/// [`crate::hazmat::aes_cbc`]. Any call with [`CipherAlgorithm::AesCbc`]
/// returns an `UnsupportedAlgorithm` error pointing at the new path.
pub fn encrypt(algorithm: CipherAlgorithm, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Encrypt(algorithm))?;
    match algorithm {
        CipherAlgorithm::AesCbc(_) => Err(Error::unsupported(
            Operation::Encrypt(algorithm),
            "AES-CBC moved to kryptering::hazmat::aes_cbc (unauthenticated; see module docs)"
                .to_owned(),
        )),
        CipherAlgorithm::AesGcm(size) => aes_gcm_encrypt(size, key, plaintext),
        #[cfg(feature = "legacy")]
        CipherAlgorithm::TripleDesCbc => triple_des_cbc_encrypt(key, plaintext),
    }
}

/// Decrypt `ciphertext` using the given block cipher algorithm and `key`.
///
/// Expects the IV/nonce prepended to the ciphertext (as produced by [`encrypt`]).
///
/// AES-CBC is **not** dispatched here — it lives in
/// [`crate::hazmat::aes_cbc`]. Any call with [`CipherAlgorithm::AesCbc`]
/// returns an `UnsupportedAlgorithm` error pointing at the new path.
pub fn decrypt(algorithm: CipherAlgorithm, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Decrypt(algorithm))?;
    match algorithm {
        CipherAlgorithm::AesCbc(_) => Err(Error::unsupported(
            Operation::Decrypt(algorithm),
            "AES-CBC moved to kryptering::hazmat::aes_cbc (unauthenticated; see module docs)"
                .to_owned(),
        )),
        CipherAlgorithm::AesGcm(size) => aes_gcm_decrypt(size, key, ciphertext),
        #[cfg(feature = "legacy")]
        CipherAlgorithm::TripleDesCbc => triple_des_cbc_decrypt(key, ciphertext),
    }
}

// ── AES-GCM ──────────────────────────────────────────────────────────

fn aes_gcm_encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, KeyInit, Nonce};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }

    let mut nonce_bytes = [0u8; 12];
    crate::backend::fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::from(nonce_bytes);

    let ct = match size {
        AesKeySize::Aes128 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
        AesKeySize::Aes192 => {
            use aes_gcm::aead::consts::U12;
            let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
        AesKeySize::Aes256 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| Error::Crypto(format!("AES-GCM encrypt: {e}")))?
        }
    };

    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ct);
    Ok(result)
}

fn aes_gcm_decrypt(size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, KeyInit, Nonce};

    let expected = size.key_len();
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte key, got {}",
            key.len()
        )));
    }
    if data.len() < 12 + 16 {
        return Err(Error::Crypto("AES-GCM data too short".into()));
    }

    let nonce_bytes: [u8; 12] = data[..12]
        .try_into()
        .map_err(|_| Error::Crypto("AES-GCM invalid nonce".into()))?;
    let nonce = Nonce::from(nonce_bytes);
    let ct_and_tag = &data[12..];

    match size {
        AesKeySize::Aes128 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(&nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
        AesKeySize::Aes192 => {
            use aes_gcm::aead::consts::U12;
            let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(&nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
        AesKeySize::Aes256 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Crypto(format!("AES-GCM init: {e}")))?;
            cipher
                .decrypt(&nonce, ct_and_tag)
                .map_err(|e| Error::Crypto(format!("AES-GCM decrypt: {e}")))
        }
    }
}

// ── 3DES-CBC ─────────────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn triple_des_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    if key.len() != 24 {
        return Err(Error::Crypto(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }

    let mut iv = [0u8; 8];
    crate::backend::fill_random(&mut iv)?;

    let mut buf = pkcs7_pad(plaintext, 8);
    let buf_len = buf.len();

    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(key, &iv)
        .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
    enc.encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, buf_len)
        .map_err(|e| Error::Crypto(format!("3DES encrypt: {e}")))?;

    let mut result = Vec::with_capacity(8 + buf.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);
    Ok(result)
}

#[cfg(feature = "legacy")]
fn triple_des_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    if key.len() != 24 {
        return Err(Error::Crypto(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }
    if data.len() < 16 || !data.len().is_multiple_of(8) {
        return Err(Error::Crypto(
            "3DES data invalid length (need IV + at least one block)".into(),
        ));
    }

    let iv = &data[..8];
    let mut buf = data[8..].to_vec();

    let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("3DES init: {e}")))?;
    dec.decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| Error::Crypto(format!("3DES decrypt: {e}")))?;

    xmlenc_unpad(&buf, 8)
}

// ── PKCS#7 padding ───────────────────────────────────────────────────

/// Apply PKCS#7 padding to `data` for the given `block_size`.
pub(crate) fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    padded
}

/// Remove W3C XML Encryption padding.
///
/// The XML Encryption spec (both 1.0 PKCS#7 style and 1.1 ISO 10126 style)
/// stores the padding length in the last byte. PKCS#7 fills all padding
/// bytes with the length value; ISO 10126 uses random filler bytes with
/// only the last byte indicating the length. We accept both by only
/// checking the last byte.
///
/// The three validity conditions (`pad_len != 0`, `pad_len <= block_size`,
/// `pad_len <= data.len()`) are combined with bitwise AND so the check
/// itself does not short-circuit on the first failing branch. The
/// error-versus-success path is still observable (different Result
/// variants, different allocation sizes), so this narrows — but does
/// not eliminate — the padding-oracle timing side channel. True oracle
/// closure requires authenticating the ciphertext before unpadding; see
/// [`crate::hazmat::aes_cbc`]'s module-level note.
pub(crate) fn xmlenc_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;

    // Branch-free validity check: each condition yields 0 or 1, the full
    // predicate is their bitwise AND. Converting `bool`s to `u8` before
    // AND-ing keeps every byte of the validity check touched, without
    // depending on Rust's short-circuit `&&`.
    let nonzero = u8::from(pad_len != 0);
    let in_block = u8::from(pad_len <= block_size);
    let in_data = u8::from(pad_len <= data.len());
    let valid = nonzero & in_block & in_data;
    if valid == 0 {
        return Err(Error::Crypto("invalid padding".into()));
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AesKeySize;

    #[test]
    fn test_pkcs7_roundtrip() {
        let padded = pkcs7_pad(b"hello", 16);
        assert_eq!(padded.len(), 16);
        let unpadded = xmlenc_unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn test_iso10126_unpad() {
        // ISO 10126 padding: random bytes + last byte = pad length
        let mut data = b"hello world!".to_vec(); // 12 bytes
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x04]); // 4 bytes padding, last = 4
        let unpadded = xmlenc_unpad(&data, 16).unwrap();
        assert_eq!(unpadded, b"hello world!");
    }

    #[test]
    fn aes_cbc_rejected_from_generic_dispatcher() {
        // AES-CBC now lives in kryptering::hazmat::aes_cbc. The generic
        // cipher::{encrypt,decrypt} dispatcher must refuse to handle it so
        // callers see a clear error pointing at the hazmat path rather than
        // silently using an unauthenticated mode.
        let key = [0x42u8; 16];
        let algo = CipherAlgorithm::AesCbc(AesKeySize::Aes128);
        let err = encrypt(algo, &key, b"data").unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { ref algorithm, .. } if algorithm.contains("hazmat::aes_cbc")),
            "got {err:?}"
        );
        let err = decrypt(algo, &key, &[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { ref algorithm, .. } if algorithm.contains("hazmat::aes_cbc")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes256);
        let pt = b"hello world";
        let ct = encrypt(algo, &key, pt).unwrap();
        let decrypted = decrypt(algo, &key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = [0x42u8; 16];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes128);
        let pt = b"test message for GCM auth failure";
        let mut ct = encrypt(algo, &key, pt).unwrap();

        // Corrupt the last byte (part of the GCM authentication tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = decrypt(algo, &key, &ct);
        assert!(
            result.is_err(),
            "decryption should fail for corrupted GCM ciphertext"
        );
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = [0x42u8; 16];
        let key2 = [0x99u8; 16];
        let algo = CipherAlgorithm::AesGcm(AesKeySize::Aes128);
        let pt = b"sensitive data";
        let ct = encrypt(algo, &key1, pt).unwrap();

        let result = decrypt(algo, &key2, &ct);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn test_aes_gcm_roundtrip_all_sizes() {
        let cases: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let pt = b"Hello, World! This is a test message for AES-GCM encryption.";

        for &(size, key_len) in cases {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let algo = CipherAlgorithm::AesGcm(size);
            let ct = encrypt(algo, &key, pt).unwrap();
            let decrypted = decrypt(algo, &key, &ct).unwrap();
            assert_eq!(decrypted, pt, "roundtrip failed for {size:?}");
        }
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn test_3des_roundtrip() {
        let key = [0x42u8; 24];
        let algo = CipherAlgorithm::TripleDesCbc;
        let pt = b"test data";
        let ct = encrypt(algo, &key, pt).unwrap();
        let decrypted = decrypt(algo, &key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn rejects_3des_iv_only_ciphertext() {
        let key = [0x42u8; 24];
        let err = decrypt(CipherAlgorithm::TripleDesCbc, &key, &[0u8; 8]).unwrap_err();
        assert!(err.to_string().contains("at least one block"), "got: {err}");
    }

    #[test]
    fn test_wrong_key_size() {
        // Use AES-GCM here — AES-CBC is now rejected by the generic dispatcher
        // regardless of key size, so it would pass this test for the wrong
        // reason. Key-size validation for CBC is exercised under
        // kryptering::hazmat::aes_cbc::tests.
        let result = encrypt(
            CipherAlgorithm::AesGcm(AesKeySize::Aes128),
            &[0u8; 15],
            b"data",
        );
        assert!(result.is_err());
    }
}
