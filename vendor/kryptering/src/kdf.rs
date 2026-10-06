//! Key Derivation Functions: ConcatKDF (NIST SP 800-56A), PBKDF2 (RFC 8018), and HKDF (RFC 5869).
//!
//! ## Legacy hashes
//!
//! When the `legacy` feature is enabled, [`concat_kdf`] and [`hkdf_derive`]
//! accept `HashAlgorithm::Md5` and `HashAlgorithm::Ripemd160`. These are
//! provided **solely for interop with pre-2015 protocol specs** (older XML
//! Encryption profiles, CMS with `id-PBKDF2` using HMAC-MD5). KDFs use the
//! underlying hash as an HMAC PRF where collision resistance is not
//! required, so these paths are not as dangerous as they appear — but new
//! protocols should never pick them. No code path enforces this at the
//! primitive layer; selecting a modern hash is the caller's responsibility.

use crate::algorithm::HashAlgorithm;
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};

use digest::Digest;

/// ConcatKDF parameters (NIST SP 800-56A, Section 5.8.1).
///
/// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo
#[derive(Debug, Clone)]
pub struct ConcatKdfParams {
    /// Hash algorithm to use. Defaults to SHA-256.
    pub hash: HashAlgorithm,
    /// AlgorithmID field.
    pub algorithm_id: Option<Vec<u8>>,
    /// PartyUInfo field.
    pub party_u_info: Option<Vec<u8>>,
    /// PartyVInfo field.
    pub party_v_info: Option<Vec<u8>>,
}

impl Default for ConcatKdfParams {
    fn default() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            algorithm_id: None,
            party_u_info: None,
            party_v_info: None,
        }
    }
}

/// Minimum PBKDF2 salt length, in bytes.
///
/// Matches RFC 8018 §4.1's SHOULD-level recommendation (64 bits = 8 bytes).
/// An earlier version enforced 16 bytes per NIST SP 800-132 §5.1, but that
/// conflicts with W3C XML Encryption 1.1 test vectors (xmlenc11-interop-2012)
/// which use 8-byte salts. 8 bytes is still sufficient to defeat
/// pre-computation when the password material is high-entropy (the typical
/// XML-Enc DH-ES / key-transport case); callers deriving keys from
/// user-chosen passwords against rainbow-table adversaries should use a
/// larger salt (and prefer [`Pbkdf2Params::recommended`] for iteration
/// count).
pub const PBKDF2_MIN_SALT_LEN: usize = 8;

/// Minimum PBKDF2 iteration count.
///
/// Rejects only `iteration_count == 0`, which collapses PBKDF2 to a single
/// HMAC of the password — that's a caller configuration bug, not a weak
/// choice. Any positive iteration count at least performs the round
/// function; 1000 (RFC 8018 §4.2 Note) and 600 000 (OWASP 2023 for
/// HMAC-SHA-256) are recommendations, not requirements, and enforcing
/// them at the primitive layer conflicts with legitimate interop cases
/// (W3C XML-Enc test vectors use < 1000 iterations for test-runner speed).
/// Callers who want OWASP-current iteration counts should construct via
/// [`Pbkdf2Params::recommended`].
pub const PBKDF2_MIN_ITERATIONS: u32 = 1;

/// Upper bound on PBKDF2 iteration count.
///
/// RFC 8018 does not mandate an upper bound, but `u32::MAX` would commit
/// hours of synchronous CPU work. 100&nbsp;million is well above any
/// legitimate use case (OWASP 2023 recommends 600 000 for HMAC-SHA-256)
/// while preventing CPU denial of service from attacker-controlled or
/// misconfigured iteration counts.
pub const PBKDF2_MAX_ITERATIONS: u32 = 100_000_000;

/// Upper bound on PBKDF2 output length, in bytes.
///
/// RFC 8018 permits up to `(2^32 - 1) * hLen` bytes, which is orders of
/// magnitude beyond any real use case. Capping at 1 MiB prevents accidental
/// DoS via an absurdly large `key_length` value.
pub const PBKDF2_MAX_KEY_LEN: usize = 1 << 20;

/// Upper bound on ConcatKDF output length, in bytes.
///
/// NIST SP 800-56A permits very large outputs, but real XML Encryption and
/// key-wrap use cases derive symmetric keys or KEKs. A 1 MiB cap prevents
/// attacker-influenced allocation and hashing work from scaling without
/// changing legitimate protocol-sized outputs.
pub const CONCAT_KDF_MAX_KEY_LEN: usize = 1 << 20;

/// PBKDF2 parameters (RFC 8018).
///
/// [`pbkdf2_derive`] rejects parameters below [`PBKDF2_MIN_SALT_LEN`] salt
/// length or [`PBKDF2_MIN_ITERATIONS`] iterations. Earlier versions
/// accepted `iteration_count: 0` and empty salts silently, producing
/// trivially-brute-forceable keys; callers that hit these floors almost
/// always had a configuration bug rather than a legitimate need for weak
/// parameters.
#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    /// Hash algorithm for the HMAC PRF.
    pub hash: HashAlgorithm,
    /// Salt bytes. Must be at least [`PBKDF2_MIN_SALT_LEN`] bytes.
    pub salt: Vec<u8>,
    /// Iteration count. Must be at least [`PBKDF2_MIN_ITERATIONS`].
    pub iteration_count: u32,
    /// Desired key length in bytes. Must be in `1..=PBKDF2_MAX_KEY_LEN`.
    pub key_length: usize,
}

impl Pbkdf2Params {
    /// Build parameters at the OWASP 2023 recommended iteration count for
    /// the chosen hash.
    ///
    /// Current recommendations (OWASP Password Storage Cheat Sheet, 2023):
    ///
    /// | Hash | Iterations |
    /// |------|-----------:|
    /// | SHA-1 | 1 300 000 |
    /// | SHA-256 | 600 000 |
    /// | SHA-384 | 310 000 |
    /// | SHA-512 | 210 000 |
    ///
    /// Any other hash falls back to the SHA-256 recommendation. If you
    /// know your threat model calls for more, construct `Pbkdf2Params`
    /// directly with the higher value.
    pub fn recommended(hash: HashAlgorithm, salt: Vec<u8>, key_length: usize) -> Self {
        let iteration_count = match hash {
            HashAlgorithm::Sha1 => 1_300_000,
            HashAlgorithm::Sha384 => 310_000,
            HashAlgorithm::Sha512 => 210_000,
            // SHA-224, SHA-256, SHA-3 family, legacy: 600k is the SHA-256 baseline.
            _ => 600_000,
        };
        Self {
            hash,
            salt,
            iteration_count,
            key_length,
        }
    }
}

/// HKDF parameters (RFC 5869).
#[derive(Debug, Clone)]
pub struct HkdfParams {
    /// Hash algorithm for the HMAC PRF. Defaults to SHA-256.
    pub hash: HashAlgorithm,
    /// Optional salt bytes. When `None`, HKDF uses a zero-filled salt of hash length.
    pub salt: Option<Vec<u8>>,
    /// Optional info/context bytes for the HKDF-Expand step.
    pub info: Option<Vec<u8>>,
    /// Desired output key length in bits. Converted to bytes internally.
    /// If 0, the caller must supply `key_len` to [`hkdf_derive`].
    pub key_length_bits: u32,
}

impl Default for HkdfParams {
    fn default() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 0,
        }
    }
}

/// Derive a key using ConcatKDF (NIST SP 800-56A, Section 5.8.1).
///
/// The single-step KDF:
///   K(i) = H(counter || Z || OtherInfo)
///   DerivedKeyingMaterial = K(1) || K(2) || ... (truncated to `key_len`)
///
/// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo
pub fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    params: &ConcatKdfParams,
) -> Result<Vec<u8>> {
    require_supported(Operation::ConcatKdf(params.hash))?;
    // Build OtherInfo
    let mut other_info = Vec::new();
    if let Some(ref alg_id) = params.algorithm_id {
        other_info.extend_from_slice(alg_id);
    }
    if let Some(ref party_u) = params.party_u_info {
        other_info.extend_from_slice(party_u);
    }
    if let Some(ref party_v) = params.party_v_info {
        other_info.extend_from_slice(party_v);
    }

    match params.hash {
        HashAlgorithm::Sha1 => concat_kdf_inner::<sha1::Sha1>(shared_secret, &other_info, key_len),
        HashAlgorithm::Sha224 => {
            concat_kdf_inner::<sha2::Sha224>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha256 => {
            concat_kdf_inner::<sha2::Sha256>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha384 => {
            concat_kdf_inner::<sha2::Sha384>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha512 => {
            concat_kdf_inner::<sha2::Sha512>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha3_224 => {
            concat_kdf_inner::<sha3::Sha3_224>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha3_256 => {
            concat_kdf_inner::<sha3::Sha3_256>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha3_384 => {
            concat_kdf_inner::<sha3::Sha3_384>(shared_secret, &other_info, key_len)
        }
        HashAlgorithm::Sha3_512 => {
            concat_kdf_inner::<sha3::Sha3_512>(shared_secret, &other_info, key_len)
        }
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => concat_kdf_inner::<md5::Md5>(shared_secret, &other_info, key_len),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => {
            concat_kdf_inner::<ripemd::Ripemd160>(shared_secret, &other_info, key_len)
        }
    }
}

fn concat_kdf_inner<H: Digest + Clone>(
    shared_secret: &[u8],
    other_info: &[u8],
    key_len: usize,
) -> Result<Vec<u8>> {
    if key_len == 0 {
        return Err(Error::Crypto("ConcatKDF key_len must be > 0".into()));
    }
    if key_len > CONCAT_KDF_MAX_KEY_LEN {
        return Err(Error::Crypto(format!(
            "ConcatKDF key_len {key_len} exceeds cap of {CONCAT_KDF_MAX_KEY_LEN} bytes"
        )));
    }

    let hash_len = <H as Digest>::output_size();
    let reps = key_len.div_ceil(hash_len);
    let mut derived = Vec::with_capacity(reps * hash_len);

    for counter in 1..=(reps as u32) {
        let mut hasher = H::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(other_info);
        derived.extend_from_slice(&hasher.finalize());
    }

    derived.truncate(key_len);
    Ok(derived)
}

/// Derive a key using PBKDF2 (RFC 8018).
///
/// Rejects weak parameters before touching any cryptographic primitive:
///
/// * `salt.len()` must be `>= PBKDF2_MIN_SALT_LEN` (8 bytes — RFC 8018
///   §4.1 SHOULD-level recommendation).
/// * `iteration_count` must be `>= PBKDF2_MIN_ITERATIONS` (1; prefer
///   [`Pbkdf2Params::recommended`] which encodes OWASP 2023 guidance) and
///   `<= PBKDF2_MAX_ITERATIONS`.
/// * `key_length` must be in `1..=PBKDF2_MAX_KEY_LEN` (1 MiB).
///
/// Returns `Error::Crypto` with a descriptive message on violation.
pub fn pbkdf2_derive(password: &[u8], params: &Pbkdf2Params) -> Result<Vec<u8>> {
    require_supported(Operation::Pbkdf2(params.hash))?;
    if params.salt.len() < PBKDF2_MIN_SALT_LEN {
        return Err(Error::Crypto(format!(
            "PBKDF2 salt must be at least {PBKDF2_MIN_SALT_LEN} bytes (RFC 8018 §4.1), got {}",
            params.salt.len()
        )));
    }
    if params.iteration_count < PBKDF2_MIN_ITERATIONS {
        return Err(Error::Crypto(format!(
            "PBKDF2 iteration_count must be at least {PBKDF2_MIN_ITERATIONS}, got {}",
            params.iteration_count
        )));
    }
    if params.iteration_count > PBKDF2_MAX_ITERATIONS {
        return Err(Error::Crypto(format!(
            "PBKDF2 iteration_count {} exceeds cap of {PBKDF2_MAX_ITERATIONS}",
            params.iteration_count
        )));
    }
    if params.key_length == 0 {
        return Err(Error::Crypto("PBKDF2 key_length must be > 0".into()));
    }
    if params.key_length > PBKDF2_MAX_KEY_LEN {
        return Err(Error::Crypto(format!(
            "PBKDF2 key_length {} exceeds cap of {PBKDF2_MAX_KEY_LEN} bytes",
            params.key_length
        )));
    }

    let mut derived = vec![0u8; params.key_length];

    match params.hash {
        HashAlgorithm::Sha1 => {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        HashAlgorithm::Sha224 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha224>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        HashAlgorithm::Sha256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        HashAlgorithm::Sha384 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        HashAlgorithm::Sha512 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                password,
                &params.salt,
                params.iteration_count,
                &mut derived,
            );
        }
        HashAlgorithm::Sha3_224
        | HashAlgorithm::Sha3_256
        | HashAlgorithm::Sha3_384
        | HashAlgorithm::Sha3_512 => {
            return Err(Error::unsupported(
                Operation::Pbkdf2(params.hash),
                format!(
                    "PBKDF2 with {:?}: SHA-3 not supported by PBKDF2",
                    params.hash
                ),
            ));
        }
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 | HashAlgorithm::Ripemd160 => {
            return Err(Error::unsupported(
                Operation::Pbkdf2(params.hash),
                format!("PBKDF2 with {:?}: legacy hash not supported", params.hash),
            ));
        }
    }

    Ok(derived)
}

/// Derive a key using HKDF (RFC 5869: Extract-then-Expand).
///
/// `shared_secret` is the input keying material (IKM).
/// `key_len` is the desired output length in bytes (overridden by
/// `params.key_length_bits / 8` if that is nonzero).
///
/// Returns `Error::Crypto` if neither `params.key_length_bits` nor
/// `key_len` specifies a positive length. An earlier version silently
/// defaulted to 16 bytes (AES-128) when both were zero — a caller who
/// forgot to configure a length would get 128-bit key material without
/// any warning.
pub fn hkdf_derive(shared_secret: &[u8], key_len: usize, params: &HkdfParams) -> Result<Vec<u8>> {
    require_supported(Operation::Hkdf(params.hash))?;
    // Determine output length: params override the caller's key_len.
    let out_len = if params.key_length_bits > 0 {
        if !params.key_length_bits.is_multiple_of(8) {
            return Err(Error::Crypto(format!(
                "HKDF key_length_bits must be byte-aligned, got {}",
                params.key_length_bits
            )));
        }
        (params.key_length_bits as usize) / 8
    } else if key_len > 0 {
        key_len
    } else {
        return Err(Error::Crypto(
            "HKDF output length is required (set params.key_length_bits or pass key_len)".into(),
        ));
    };

    let salt = params.salt.as_deref();
    let info = params.info.as_deref().unwrap_or(&[]);

    macro_rules! hkdf_expand {
        ($hasher:ty) => {{
            let max_len = 255 * <$hasher as Digest>::output_size();
            if out_len == 0 {
                return Err(Error::Crypto("HKDF output length must be > 0".into()));
            }
            if out_len > max_len {
                return Err(Error::Crypto(format!(
                    "HKDF output length {out_len} exceeds RFC 5869 cap of {max_len} bytes for {:?}",
                    params.hash
                )));
            }
            let hk = hkdf::Hkdf::<$hasher>::new(salt, shared_secret);
            let mut okm = vec![0u8; out_len];
            hk.expand(info, &mut okm)
                .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
            Ok(okm)
        }};
    }

    match params.hash {
        HashAlgorithm::Sha1 => hkdf_expand!(sha1::Sha1),
        HashAlgorithm::Sha224 => hkdf_expand!(sha2::Sha224),
        HashAlgorithm::Sha256 => hkdf_expand!(sha2::Sha256),
        HashAlgorithm::Sha384 => hkdf_expand!(sha2::Sha384),
        HashAlgorithm::Sha512 => hkdf_expand!(sha2::Sha512),
        HashAlgorithm::Sha3_224 => hkdf_expand!(sha3::Sha3_224),
        HashAlgorithm::Sha3_256 => hkdf_expand!(sha3::Sha3_256),
        HashAlgorithm::Sha3_384 => hkdf_expand!(sha3::Sha3_384),
        HashAlgorithm::Sha3_512 => hkdf_expand!(sha3::Sha3_512),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => hkdf_expand!(md5::Md5),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => hkdf_expand!(ripemd::Ripemd160),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 5869 HKDF test vectors ────────────────────────────────────

    #[test]
    fn hkdf_sha256_test_case_1() {
        // RFC 5869, Test Case 1
        let ikm = [0x0b; 22];
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_test_case_2() {
        // RFC 5869, Test Case 2
        let ikm = hex_decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );

        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 656, // 82 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 82);
        assert_eq!(
            hex_encode(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn hkdf_sha256_test_case_3() {
        // RFC 5869, Test Case 3: zero-length salt and info
        let ikm = [0x0b; 22];

        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_sha1_test_case_4() {
        // RFC 5869, Test Case 4
        let ikm = [0x0b; 11];
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

        let params = HkdfParams {
            hash: HashAlgorithm::Sha1,
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );
    }

    #[test]
    fn hkdf_sha1_test_case_5() {
        // RFC 5869, Test Case 5
        let ikm = hex_decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );

        let params = HkdfParams {
            hash: HashAlgorithm::Sha1,
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 656, // 82 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 82);
        assert_eq!(
            hex_encode(&okm),
            "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe\
             8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e\
             927336d0441f4c4300e2cff0d0900b52d3b4"
        );
    }

    #[test]
    fn hkdf_sha1_test_case_7() {
        // RFC 5869, Test Case 7: zero-length salt, info, and IKM
        let ikm = [0x0b; 22];

        let params = HkdfParams {
            hash: HashAlgorithm::Sha1,
            salt: None,
            info: None,
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"
        );
    }

    // ── HKDF edge cases ───────────────────────────────────────────────

    #[test]
    fn hkdf_default_hash_is_sha256() {
        let ikm = [0x0b; 22];
        let params_explicit = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 128,
        };
        let params_default = HkdfParams {
            key_length_bits: 128,
            ..Default::default()
        };

        let okm1 = hkdf_derive(&ikm, 0, &params_explicit).unwrap();
        let okm2 = hkdf_derive(&ikm, 0, &params_default).unwrap();
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn hkdf_key_len_fallback() {
        // key_length_bits=0 should use the key_len parameter
        let ikm = [0x0b; 22];
        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 0,
        };

        let okm = hkdf_derive(&ikm, 32, &params).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn hkdf_rejects_non_byte_aligned_key_length_bits() {
        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 9,
        };

        let err = hkdf_derive(&[0x0b; 22], 0, &params).unwrap_err();
        assert!(err.to_string().contains("byte-aligned"), "got: {err}");
    }

    #[test]
    fn hkdf_rejects_output_longer_than_rfc5869_cap() {
        let params = HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: None,
            info: None,
            key_length_bits: 0,
        };

        let err = hkdf_derive(&[0x0b; 22], 255 * 32 + 1, &params).unwrap_err();
        assert!(err.to_string().contains("RFC 5869 cap"), "got: {err}");
    }

    // ── ConcatKDF tests ───────────────────────────────────────────────

    #[test]
    fn concat_kdf_sha256_produces_correct_length() {
        let shared = [0xab; 32];
        let params = ConcatKdfParams {
            hash: HashAlgorithm::Sha256,
            algorithm_id: Some(b"A128CBC-HS256".to_vec()),
            ..Default::default()
        };

        let derived = concat_kdf(&shared, 16, &params).unwrap();
        assert_eq!(derived.len(), 16);
    }

    #[test]
    fn concat_kdf_default_hash_is_sha256() {
        let shared = [0xab; 32];
        let params_default = ConcatKdfParams::default();
        let params_explicit = ConcatKdfParams {
            hash: HashAlgorithm::Sha256,
            ..Default::default()
        };

        let d1 = concat_kdf(&shared, 32, &params_default).unwrap();
        let d2 = concat_kdf(&shared, 32, &params_explicit).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn concat_kdf_multi_round() {
        // Request more bytes than one SHA-256 hash (32 bytes)
        let shared = [0xcd; 32];
        let params = ConcatKdfParams::default();

        let derived = concat_kdf(&shared, 64, &params).unwrap();
        assert_eq!(derived.len(), 64);
    }

    #[test]
    fn concat_kdf_rejects_zero_key_length() {
        let params = ConcatKdfParams::default();
        let err = concat_kdf(&[0xab; 32], 0, &params).unwrap_err();
        assert!(err.to_string().contains("key_len"), "got: {err}");
    }

    #[test]
    fn concat_kdf_rejects_huge_key_length() {
        let params = ConcatKdfParams::default();
        let err = concat_kdf(&[0xab; 32], CONCAT_KDF_MAX_KEY_LEN + 1, &params).unwrap_err();
        assert!(err.to_string().contains("key_len"), "got: {err}");
    }

    // ── PBKDF2 tests ──────────────────────────────────────────────────

    /// 16-byte canned salt used in roundtrip tests. Matches the NIST SP
    /// 800-132 §5.1 floor so it exercises the normal path rather than the
    /// rejection path.
    const PBKDF2_TEST_SALT: &[u8; 16] = b"pbkdf2-salt-16by";

    #[test]
    fn pbkdf2_sha256_basic() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 4096,
            key_length: 32,
        };
        let derived = pbkdf2_derive(b"password", &params).unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn pbkdf2_sha512_basic() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha512,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 1000,
            key_length: 64,
        };
        let derived = pbkdf2_derive(b"secret", &params).unwrap();
        assert_eq!(derived.len(), 64);
    }

    #[test]
    fn pbkdf2_sha3_unsupported() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha3_256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 1000,
            key_length: 32,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnsupportedAlgorithm {
                    operation: Operation::Pbkdf2(HashAlgorithm::Sha3_256),
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pbkdf2_rejects_zero_iterations() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 0,
            key_length: 32,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(err.to_string().contains("iteration_count"), "got: {err}");
    }

    #[test]
    fn pbkdf2_accepts_low_but_positive_iterations() {
        // PBKDF2_MIN_ITERATIONS is 1, not a security-policy floor. Callers
        // who want OWASP-current counts should use Pbkdf2Params::recommended;
        // the raw primitive accepts W3C XML-Enc test vectors (e.g.,
        // IterationCount=512) which predate modern recommendations.
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 512,
            key_length: 32,
        };
        let derived = pbkdf2_derive(b"password", &params).unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn pbkdf2_rejects_empty_salt() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: Vec::new(),
            iteration_count: 4096,
            key_length: 32,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(err.to_string().contains("salt"), "got: {err}");
    }

    #[test]
    fn pbkdf2_rejects_short_salt() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: vec![0xAB; PBKDF2_MIN_SALT_LEN - 1],
            iteration_count: 4096,
            key_length: 32,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(err.to_string().contains("salt"), "got: {err}");
    }

    #[test]
    fn pbkdf2_rejects_zero_key_length() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 4096,
            key_length: 0,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(err.to_string().contains("key_length"), "got: {err}");
    }

    #[test]
    fn pbkdf2_rejects_huge_key_length() {
        let params = Pbkdf2Params {
            hash: HashAlgorithm::Sha256,
            salt: PBKDF2_TEST_SALT.to_vec(),
            iteration_count: 4096,
            key_length: PBKDF2_MAX_KEY_LEN + 1,
        };
        let err = pbkdf2_derive(b"password", &params).unwrap_err();
        assert!(err.to_string().contains("key_length"), "got: {err}");
    }

    #[test]
    fn pbkdf2_recommended_encodes_owasp_values() {
        let salt = PBKDF2_TEST_SALT.to_vec();
        let sha1 = Pbkdf2Params::recommended(HashAlgorithm::Sha1, salt.clone(), 32);
        assert_eq!(sha1.iteration_count, 1_300_000);
        let sha256 = Pbkdf2Params::recommended(HashAlgorithm::Sha256, salt.clone(), 32);
        assert_eq!(sha256.iteration_count, 600_000);
        let sha384 = Pbkdf2Params::recommended(HashAlgorithm::Sha384, salt.clone(), 32);
        assert_eq!(sha384.iteration_count, 310_000);
        let sha512 = Pbkdf2Params::recommended(HashAlgorithm::Sha512, salt, 32);
        assert_eq!(sha512.iteration_count, 210_000);
    }

    // ── helpers ───────────────────────────────────────────────────────

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
