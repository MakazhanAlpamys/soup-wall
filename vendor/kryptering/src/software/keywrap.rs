//! Software-backed key wrapping (AES-KW, optionally 3DES-KW).

use aes_kw::{AesKw, KeyInit};
use zeroize::Zeroizing;

use crate::algorithm::{AesKeySize, KeyWrapAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};

/// Wrap `key_data` using the specified key wrap algorithm and key-encryption key.
pub fn wrap(algorithm: KeyWrapAlgorithm, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Wrap(algorithm))?;
    match algorithm {
        KeyWrapAlgorithm::AesKw(size) => aes_kw_wrap(size, kek, key_data),
        #[cfg(feature = "legacy")]
        KeyWrapAlgorithm::TripleDesKw => tdes_kw_wrap(kek, key_data),
    }
}

/// Unwrap `wrapped` using the specified key wrap algorithm and key-encryption key.
pub fn unwrap(algorithm: KeyWrapAlgorithm, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Unwrap(algorithm))?;
    match algorithm {
        KeyWrapAlgorithm::AesKw(size) => aes_kw_unwrap(size, kek, wrapped),
        #[cfg(feature = "legacy")]
        KeyWrapAlgorithm::TripleDesKw => tdes_kw_unwrap(kek, wrapped),
    }
}

// ── AES Key Wrap (RFC 3394) ─────────────────────────────────────────

fn aes_kw_wrap(size: AesKeySize, kek_bytes: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
    let expected = size.key_len();
    if kek_bytes.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte KEK, got {}",
            kek_bytes.len()
        )));
    }
    // RFC 3394 §2.2.1: n >= 2 64-bit blocks. Same check and message as the
    // AWS-LC provider.
    if key_data.len() < 16 || !key_data.len().is_multiple_of(8) {
        return Err(Error::Crypto("invalid AES-KW input length".into()));
    }
    let mut out = vec![0u8; key_data.len() + 8];
    macro_rules! do_wrap {
        ($aes:ty) => {{
            let kek = AesKw::<$aes>::new_from_slice(kek_bytes)
                .map_err(|e| Error::Crypto(format!("AES-KW init: {e}")))?;
            kek.wrap_key(key_data, &mut out)
                .map_err(|e| Error::Crypto(format!("AES-KW wrap: {e}")))?;
        }};
    }
    match size {
        AesKeySize::Aes128 => do_wrap!(aes::Aes128),
        AesKeySize::Aes192 => do_wrap!(aes::Aes192),
        AesKeySize::Aes256 => do_wrap!(aes::Aes256),
    }
    Ok(out)
}

fn aes_kw_unwrap(size: AesKeySize, kek_bytes: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    let expected = size.key_len();
    if kek_bytes.len() != expected {
        return Err(Error::Crypto(format!(
            "expected {expected} byte KEK, got {}",
            kek_bytes.len()
        )));
    }
    // Integrity block plus n >= 2 key-data blocks.
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(Error::Crypto("invalid AES-KW input length".into()));
    }
    // Held in `Zeroizing` so a failed integrity check does not leave the
    // partially unwrapped key in a freed allocation.
    let mut out = Zeroizing::new(vec![0u8; wrapped.len() - 8]);
    macro_rules! do_unwrap {
        ($aes:ty) => {{
            let kek = AesKw::<$aes>::new_from_slice(kek_bytes)
                .map_err(|e| Error::Crypto(format!("AES-KW init: {e}")))?;
            kek.unwrap_key(wrapped, &mut out)
                .map_err(|e| Error::Crypto(format!("AES-KW unwrap: {e}")))?;
        }};
    }
    match size {
        AesKeySize::Aes128 => do_unwrap!(aes::Aes128),
        AesKeySize::Aes192 => do_unwrap!(aes::Aes192),
        AesKeySize::Aes256 => do_unwrap!(aes::Aes256),
    }
    Ok(std::mem::take(&mut *out))
}

// ── 3DES Key Wrap (RFC 3217) ────────────────────────────────────────

/// Fixed IV for the second 3DES-CBC encryption pass (RFC 3217 section 3.2).
#[cfg(feature = "legacy")]
const TDES_KW_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

#[cfg(feature = "legacy")]
fn tdes_kw_wrap(kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 24 {
        return Err(Error::Crypto(format!(
            "expected 24 byte 3DES KEK, got {}",
            kek.len()
        )));
    }

    // 1. Compute CMS Key Checksum (SHA-1 hash, first 8 bytes)
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(key_data);
    let hash = hasher.finalize();
    let checksum = &hash[..8];

    // 2. WKCKS = key_data || checksum
    let mut wkcks = Vec::with_capacity(key_data.len() + 8);
    wkcks.extend_from_slice(key_data);
    wkcks.extend_from_slice(checksum);

    // 3. Generate random 8-byte IV
    let mut iv = [0u8; 8];
    crate::backend::fill_random(&mut iv)?;

    // 4. First encryption: 3DES-CBC encrypt WKCKS with random IV
    let temp1 = tdes_cbc_encrypt(kek, &iv, &wkcks)?;

    // 5. TEMP2 = IV || TEMP1
    let mut temp2 = Vec::with_capacity(8 + temp1.len());
    temp2.extend_from_slice(&iv);
    temp2.extend_from_slice(&temp1);

    // 6. Reverse byte order
    temp2.reverse();

    // 7. Second encryption: 3DES-CBC encrypt reversed data with fixed IV
    tdes_cbc_encrypt(kek, &TDES_KW_IV, &temp2)
}

#[cfg(feature = "legacy")]
fn tdes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if kek.len() != 24 {
        return Err(Error::Crypto(format!(
            "expected 24 byte 3DES KEK, got {}",
            kek.len()
        )));
    }
    if wrapped.len() < 16 {
        return Err(Error::Crypto("3DES-KW wrapped data too short".into()));
    }

    // 1. First decryption: 3DES-CBC decrypt with fixed IV
    let mut temp2 = Zeroizing::new(tdes_cbc_decrypt(kek, &TDES_KW_IV, wrapped)?);

    // 2. Reverse byte order
    temp2.reverse();

    // 3. Extract IV (first 8 bytes) and encrypted data
    if temp2.len() < 8 {
        return Err(Error::Crypto("3DES-KW unwrapped data too short".into()));
    }
    let iv: [u8; 8] = temp2[..8]
        .try_into()
        .map_err(|_| Error::Crypto("invalid IV length".into()))?;
    let enc_data = &temp2[8..];

    // 4. Second decryption: 3DES-CBC decrypt with extracted IV
    let wkcks = Zeroizing::new(tdes_cbc_decrypt(kek, &iv, enc_data)?);

    // 5. Split into key data and checksum
    if wkcks.len() < 8 {
        return Err(Error::Crypto(
            "3DES-KW: decrypted data too short for checksum".into(),
        ));
    }
    let key_data = &wkcks[..wkcks.len() - 8];
    let checksum = &wkcks[wkcks.len() - 8..];

    // 6. Verify CMS Key Checksum in constant time. The legacy implementation
    // used `!=` which short-circuits byte-by-byte and leaks the length of
    // the matching prefix to a timing attacker fuzzing wrapped-key tampers.
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(key_data);
    let hash = hasher.finalize();
    if !crate::digest::constant_time_eq(checksum, &hash[..8]) {
        return Err(Error::Crypto(
            "3DES-KW: key checksum verification failed".into(),
        ));
    }

    Ok(key_data.to_vec())
}

/// 3DES-CBC encrypt (no padding -- input must be multiple of 8 bytes).
#[cfg(feature = "legacy")]
fn tdes_cbc_encrypt(key: &[u8], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;

    let encryptor = TdesCbcEnc::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("3DES-CBC init: {e}")))?;
    if !data.len().is_multiple_of(8) {
        return Err(Error::Crypto("3DES-KW: data not block-aligned".into()));
    }
    let mut buf = data.to_vec();
    encryptor
        .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, data.len())
        .map_err(|e| Error::Crypto(format!("3DES-CBC encrypt: {e}")))?;
    Ok(buf)
}

/// 3DES-CBC decrypt (no padding -- input must be multiple of 8 bytes).
#[cfg(feature = "legacy")]
fn tdes_cbc_decrypt(key: &[u8], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
    type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

    let decryptor = TdesCbcDec::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("3DES-CBC init: {e}")))?;
    let mut buf = data.to_vec();
    // NoPadding decrypts in place over the whole buffer; return it rather
    // than copying so no unzeroized plaintext copy is left behind.
    decryptor
        .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| Error::Crypto(format!("3DES-CBC decrypt: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 3394 / NIST SP 800-38F AES Key Wrap test vectors ─────────

    /// Helper: run a single NIST AES-KW test vector (wrap + unwrap).
    fn nist_aes_kw_vector(
        size: AesKeySize,
        plaintext: &[u8],
        kek_bytes: &[u8],
        expected_ct: &[u8],
    ) {
        let algo = KeyWrapAlgorithm::AesKw(size);

        let wrapped = wrap(algo, kek_bytes, plaintext).expect("wrap failed");
        assert_eq!(wrapped, expected_ct, "wrap ciphertext mismatch");

        let unwrapped = unwrap(algo, kek_bytes, expected_ct).expect("unwrap failed");
        assert_eq!(unwrapped, plaintext, "unwrap plaintext mismatch");
    }

    #[test]
    fn test_nist_aes128_kw_128bit_data() {
        // RFC 3394 Section 4.1: 128-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        nist_aes_kw_vector(AesKeySize::Aes128, &pt, &kek, &ct);
    }

    #[test]
    fn test_nist_aes192_kw_128bit_data() {
        // RFC 3394 Section 4.2: 192-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").unwrap();
        nist_aes_kw_vector(AesKeySize::Aes192, &pt, &kek, &ct);
    }

    #[test]
    fn test_nist_aes256_kw_128bit_data() {
        // RFC 3394 Section 4.3: 256-bit KEK, 128-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let ct = hex::decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").unwrap();
        nist_aes_kw_vector(AesKeySize::Aes256, &pt, &kek, &ct);
    }

    #[test]
    fn test_nist_aes192_kw_192bit_data() {
        // RFC 3394 Section 4.4: 192-bit KEK, 192-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF0001020304050607").unwrap();
        let ct = hex::decode("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
            .unwrap();
        nist_aes_kw_vector(AesKeySize::Aes192, &pt, &kek, &ct);
    }

    #[test]
    fn test_nist_aes256_kw_256bit_data() {
        // RFC 3394 Section 4.6: 256-bit KEK, 256-bit data
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
            .unwrap();
        let ct = hex::decode(
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        )
        .unwrap();
        nist_aes_kw_vector(AesKeySize::Aes256, &pt, &kek, &ct);
    }

    #[test]
    fn test_aes_kw_wrong_kek_size() {
        let result = wrap(
            KeyWrapAlgorithm::AesKw(AesKeySize::Aes128),
            &[0u8; 15],
            &[0u8; 16],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_kw_rejects_short_or_unaligned_input() {
        // RFC 3394 requires at least two 64-bit blocks of key data; match
        // the AWS-LC provider's error for every out-of-range length.
        let kek = [0x42u8; 16];
        let algo = KeyWrapAlgorithm::AesKw(AesKeySize::Aes128);
        for len in [0, 8, 15, 17, 23] {
            let err = wrap(algo, &kek, &vec![0u8; len]).unwrap_err();
            assert!(
                err.to_string().contains("invalid AES-KW input length"),
                "wrap {len}: {err}"
            );
        }
        for len in [0, 8, 16, 23, 25] {
            let err = unwrap(algo, &kek, &vec![0u8; len]).unwrap_err();
            assert!(
                err.to_string().contains("invalid AES-KW input length"),
                "unwrap {len}: {err}"
            );
        }
    }

    #[test]
    fn test_aes_kw_integrity_check_failure() {
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let algo = KeyWrapAlgorithm::AesKw(AesKeySize::Aes128);

        let mut wrapped = wrap(algo, &kek, &pt).unwrap();
        // Corrupt the first byte
        wrapped[0] ^= 0xFF;
        let result = unwrap(algo, &kek, &wrapped);
        assert!(
            result.is_err(),
            "unwrap should fail for corrupted ciphertext"
        );
    }

    #[test]
    fn test_aes_kw_roundtrip_all_sizes() {
        let kek_sizes: &[(AesKeySize, usize)] = &[
            (AesKeySize::Aes128, 16),
            (AesKeySize::Aes192, 24),
            (AesKeySize::Aes256, 32),
        ];
        let data_sizes = [16, 24, 32, 40, 48, 64, 128];

        for &(size, kek_len) in kek_sizes {
            let algo = KeyWrapAlgorithm::AesKw(size);
            for &data_size in &data_sizes {
                let kek: Vec<u8> = (0..kek_len).map(|i| (i * 7 + 3) as u8).collect();
                let data: Vec<u8> = (0..data_size).map(|i| (i * 13 + 5) as u8).collect();
                let wrapped = wrap(algo, &kek, &data).unwrap();
                assert_eq!(
                    wrapped.len(),
                    data.len() + 8,
                    "ciphertext should be 8 bytes longer"
                );
                let unwrapped = unwrap(algo, &kek, &wrapped).unwrap();
                assert_eq!(
                    unwrapped, data,
                    "roundtrip failed for kek={kek_len}, data={data_size}"
                );
            }
        }
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn test_tdes_key_wrap_roundtrip() {
        let kek = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18";
        // 24-byte key to wrap (3DES key)
        let key_data = b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8";

        let algo = KeyWrapAlgorithm::TripleDesKw;
        let wrapped = wrap(algo, kek, key_data).expect("wrap");
        let unwrapped = unwrap(algo, kek, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, key_data);
    }
}
