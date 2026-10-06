//! PKCS#12 password KDF and PBE helpers.
//!
//! These helpers keep PKCS#12 processing inside the selected document
//! provider boundary while exposing only byte-oriented protocol parameters.

#[cfg(feature = "legacy")]
use crate::algorithm::CipherAlgorithm;
use crate::algorithm::{AesKeySize, HashAlgorithm};
use crate::error::{Error, Result};
use zeroize::Zeroizing;

pub const ID_KEY: u8 = 1;
pub const ID_IV: u8 = 2;
pub const ID_MAC: u8 = 3;

/// Encode a UTF-8 password as the BMPString (UTF-16BE) octets that
/// RFC 7292 Appendix B.1 feeds to the KDF, including the mandatory
/// trailing U+0000 terminator.
///
/// Earlier versions of this function hashed the caller's raw bytes directly,
/// which produced keys incompatible with standard PKCS#12 implementations
/// (OpenSSL, the `pkcs12` crate) whenever the password contained non-ASCII or
/// differed in encoding. Accepting `&str` and encoding here makes the contract
/// explicit: the password is text, and it is normalized to BMPString exactly
/// once.
fn password_to_bmpstring(password: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity((password.len() + 1) * 2));
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    // RFC 7292 Appendix B.1: the password is terminated by a U+0000.
    out.extend_from_slice(&[0u8, 0u8]);
    out
}

/// RFC 7292 Appendix B password-based derivation.
///
/// `password` is a UTF-8 string; it is encoded as a BMPString (UTF-16BE with
/// a trailing NUL) per RFC 7292 Appendix B.1 before hashing. Passing raw
/// bytes or a pre-encoded BMPString is not supported — callers handling
/// non-UTF-8 passwords must decode to `String` first.
///
/// An iteration count of one is accepted deliberately because this API is
/// for importing existing PKCS#12 containers, including historical files
/// that omit the count and therefore default to one. New password protection
/// should use PBKDF2 with a policy-appropriate work factor instead.
pub fn derive(
    hash: HashAlgorithm,
    id: u8,
    password: &str,
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    crate::backend::require_supported(crate::backend::Operation::Pkcs12Kdf(hash))?;
    if !matches!(id, ID_KEY | ID_IV | ID_MAC) {
        return Err(Error::Crypto(format!(
            "invalid PKCS#12 KDF diversifier {id}"
        )));
    }
    if iterations == 0 || iterations > 100_000_000 || output_len == 0 || output_len > 1 << 20 {
        return Err(Error::Crypto("invalid PKCS#12 KDF parameters".into()));
    }
    let (u, v) = match hash {
        HashAlgorithm::Sha1 => (20, 64),
        HashAlgorithm::Sha256 => (32, 64),
        _ => {
            return Err(Error::unsupported(
                crate::backend::Operation::Pkcs12Kdf(hash),
                "PKCS#12 KDF supports SHA-1 and SHA-256",
            ))
        }
    };

    let d = vec![id; v];
    let salt = extend_to_multiple(salt, v);
    let password = Zeroizing::new(extend_to_multiple(&password_to_bmpstring(password), v));
    let mut input = Zeroizing::new(Vec::with_capacity(salt.len() + password.len()));
    input.extend_from_slice(&salt);
    input.extend_from_slice(&password);

    let blocks = output_len.div_ceil(u);
    let mut output = Vec::with_capacity(blocks * u);
    for block in 0..blocks {
        let mut material = Zeroizing::new(Vec::with_capacity(d.len() + input.len()));
        material.extend_from_slice(&d);
        material.extend_from_slice(&input);
        let mut a = Zeroizing::new(crate::digest::digest(hash, &material)?);
        for _ in 1..iterations {
            *a = crate::digest::digest(hash, &a)?;
        }
        output.extend_from_slice(&a);
        if block + 1 < blocks {
            let b = Zeroizing::new(extend_to_multiple(&a, v));
            for chunk in input.chunks_mut(v) {
                add_one_plus_b(chunk, &b);
            }
        }
    }
    output.truncate(output_len);
    Ok(output)
}

#[cfg(feature = "legacy")]
pub fn decrypt_pbe_sha1_3des(
    ciphertext: &[u8],
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>> {
    let key = Zeroizing::new(derive(
        HashAlgorithm::Sha1,
        ID_KEY,
        password,
        salt,
        iterations,
        24,
    )?);
    let iv = Zeroizing::new(derive(
        HashAlgorithm::Sha1,
        ID_IV,
        password,
        salt,
        iterations,
        8,
    )?);
    let mut framed = Vec::with_capacity(iv.len() + ciphertext.len());
    framed.extend_from_slice(&iv);
    framed.extend_from_slice(ciphertext);
    crate::cipher::decrypt(CipherAlgorithm::TripleDesCbc, &key, &framed)
}

pub fn decrypt_pbes2_aes256cbc(
    hash: HashAlgorithm,
    ciphertext: &[u8],
    password: &str,
    salt: &[u8],
    iterations: u32,
    iv: &[u8],
) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        return Err(Error::Crypto("AES-256-CBC IV must be 16 bytes".into()));
    }
    let key = Zeroizing::new(crate::kdf::pbkdf2_derive(
        password.as_bytes(),
        &crate::kdf::Pbkdf2Params {
            hash,
            salt: salt.to_vec(),
            iteration_count: iterations,
            key_length: 32,
        },
    )?);
    let mut framed = Vec::with_capacity(iv.len() + ciphertext.len());
    framed.extend_from_slice(iv);
    framed.extend_from_slice(ciphertext);
    crate::hazmat::aes_cbc::decrypt(AesKeySize::Aes256, &key, &framed)
}

fn extend_to_multiple(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let length = data.len().div_ceil(block_size) * block_size;
    data.iter().copied().cycle().take(length).collect()
}

fn add_one_plus_b(block: &mut [u8], b: &[u8]) {
    let mut carry = 1u16;
    for index in (0..block.len()).rev() {
        let sum = u16::from(block[index]) + u16::from(b[index]) + carry;
        block[index] = sum as u8;
        carry = sum >> 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7292 Appendix B is not an approved KDF, so FIPS builds refuse it.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn deterministic_sha256_derivation() {
        let first = derive(
            HashAlgorithm::Sha256,
            ID_KEY,
            "password",
            b"saltsalt",
            2,
            48,
        )
        .unwrap();
        let second = derive(
            HashAlgorithm::Sha256,
            ID_KEY,
            "password",
            b"saltsalt",
            2,
            48,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 48);
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_builds_refuse_pkcs12_kdf() {
        crate::backend::initialize_backend().expect("backend initialization");
        let error = derive(
            HashAlgorithm::Sha256,
            ID_KEY,
            "password",
            b"saltsalt",
            2,
            32,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::UnsupportedAlgorithm {
                operation: crate::backend::Operation::Pkcs12Kdf(HashAlgorithm::Sha256),
                ..
            }
        ));
    }

    #[test]
    fn unsupported_hash_reports_pkcs12_operation() {
        crate::backend::initialize_backend().expect("backend initialization");
        let error = derive(
            HashAlgorithm::Sha512,
            ID_KEY,
            "password",
            b"saltsalt",
            2,
            32,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::UnsupportedAlgorithm {
                operation: crate::backend::Operation::Pkcs12Kdf(HashAlgorithm::Sha512),
                ..
            }
        ));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn sha256_derivation_matches_openssl_pkcs12kdf() {
        // Cross-implementation vector generated with OpenSSL 3's PKCS12KDF.
        // The `pass` octets are password's RFC 7292 UTF-16BE BMPString plus
        // its trailing NUL; salt="saltsalt", iter=2, id=1, digest=SHA256.
        let derived = derive(
            HashAlgorithm::Sha256,
            ID_KEY,
            "password",
            b"saltsalt",
            2,
            32,
        )
        .unwrap();
        assert_eq!(
            hex::encode(derived),
            "664c8ff41a0121d0b39b1741f683d26e556453bd6f02068931aa29f4f2f98545"
        );
    }

    /// BMPString regression: the KDF must hash UTF-16BE octets, not the raw
    /// UTF-8 bytes. A pre-BMPString-fix call with `b"password"` produced a
    /// different key than the RFC 7292 encoding; this pins the corrected
    /// behaviour so a future revert is caught.
    #[test]
    fn password_is_bmpstring_encoded() {
        // "password" as BMPString (UTF-16BE) with trailing U+0000:
        //   00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00
        let bmp = password_to_bmpstring("password");
        assert_eq!(
            hex::encode(bmp.as_slice()),
            "00700061007300730077006f007200640000"
        );
        // A non-ASCII password encodes its BMPString code unit, not its
        // UTF-8 bytes (U+00E9 = 0x00E9, UTF-8 0xC3 0xA9).
        let cafe_bmp = password_to_bmpstring("caf\u{00e9}");
        assert_eq!(hex::encode(cafe_bmp.as_slice()), "00630061006600e90000");
    }
}
