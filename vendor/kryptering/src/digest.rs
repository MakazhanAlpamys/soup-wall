use crate::algorithm::HashAlgorithm;
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use digest::Digest;

/// Streaming digest interface.
pub trait DigestStream: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// Create a streaming digest for the given algorithm.
pub fn new_digest(algorithm: HashAlgorithm) -> Result<Box<dyn DigestStream>> {
    require_supported(Operation::Digest(algorithm))?;
    match algorithm {
        HashAlgorithm::Sha1 => Ok(Box::new(DigestImpl::<sha1::Sha1>::new(algorithm))),
        HashAlgorithm::Sha224 => Ok(Box::new(DigestImpl::<sha2::Sha224>::new(algorithm))),
        HashAlgorithm::Sha256 => Ok(Box::new(DigestImpl::<sha2::Sha256>::new(algorithm))),
        HashAlgorithm::Sha384 => Ok(Box::new(DigestImpl::<sha2::Sha384>::new(algorithm))),
        HashAlgorithm::Sha512 => Ok(Box::new(DigestImpl::<sha2::Sha512>::new(algorithm))),
        HashAlgorithm::Sha3_224 => Ok(Box::new(DigestImpl::<sha3::Sha3_224>::new(algorithm))),
        HashAlgorithm::Sha3_256 => Ok(Box::new(DigestImpl::<sha3::Sha3_256>::new(algorithm))),
        HashAlgorithm::Sha3_384 => Ok(Box::new(DigestImpl::<sha3::Sha3_384>::new(algorithm))),
        HashAlgorithm::Sha3_512 => Ok(Box::new(DigestImpl::<sha3::Sha3_512>::new(algorithm))),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => Ok(Box::new(DigestImpl::<md5::Md5>::new(algorithm))),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => Ok(Box::new(DigestImpl::<ripemd::Ripemd160>::new(algorithm))),
    }
}

/// Compute a digest in one shot.
pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Digest(algorithm))?;
    Ok(match algorithm {
        HashAlgorithm::Sha1 => sha1::Sha1::digest(data).to_vec(),
        HashAlgorithm::Sha224 => sha2::Sha224::digest(data).to_vec(),
        HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        HashAlgorithm::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
        HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        HashAlgorithm::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => md5::Md5::digest(data).to_vec(),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => ripemd::Ripemd160::digest(data).to_vec(),
    })
}

/// Compute HMAC for the given hash algorithm.
pub fn compute_hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Hmac(hash))?;
    use hmac::{Hmac, Mac};
    macro_rules! hmac_compute {
        ($hasher:ty) => {{
            let mut mac = <Hmac<$hasher>>::new_from_slice(key).expect("HMAC key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    Ok(match hash {
        HashAlgorithm::Sha1 => hmac_compute!(sha1::Sha1),
        HashAlgorithm::Sha224 => hmac_compute!(sha2::Sha224),
        HashAlgorithm::Sha256 => hmac_compute!(sha2::Sha256),
        HashAlgorithm::Sha384 => hmac_compute!(sha2::Sha384),
        HashAlgorithm::Sha512 => hmac_compute!(sha2::Sha512),
        HashAlgorithm::Sha3_224 => hmac_compute!(sha3::Sha3_224),
        HashAlgorithm::Sha3_256 => hmac_compute!(sha3::Sha3_256),
        HashAlgorithm::Sha3_384 => hmac_compute!(sha3::Sha3_384),
        HashAlgorithm::Sha3_512 => hmac_compute!(sha3::Sha3_512),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => hmac_compute!(md5::Md5),
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => hmac_compute!(ripemd::Ripemd160),
    })
}

/// Constant-time equality check.
///
/// Returns `true` iff `a` and `b` have the same length and contents. The
/// comparison XOR-accumulates over the full length of the inputs so that a
/// full-length attacker-chosen `b` cannot reveal the first differing byte of
/// `a` via timing.
///
/// Inputs of different lengths are rejected before any byte comparison — this
/// intentionally does **not** support caller-truncated MACs. An earlier
/// version returned `true` when `b.len() < a.len()` and the first `b.len()`
/// bytes of `a` matched, which allowed an attacker to forge HMACs by
/// submitting a 1-byte signature (~1/256 success per attempt).
///
/// For verifier-declared HMAC truncation (e.g., XML Signature's
/// `HMACOutputLength`), use [`hmac_verify_truncated`] instead.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Verify a potentially-truncated HMAC signature against a verifier-declared
/// output length.
///
/// Computes the full HMAC of `data` under `key` with the given `hash`, then
/// compares the first `expected_len_bytes` of the result against `sig` in
/// constant time. Returns `false` (not an error) when:
///
/// * `expected_len_bytes == 0`
/// * `sig.len() != expected_len_bytes`
/// * `expected_len_bytes` exceeds the hash's output size
///
/// # Safety contract
///
/// `expected_len_bytes` is **the verifier's declared truncation length**,
/// **not the attacker's submitted signature length**. The caller MUST
/// enforce their protocol's policy minimum on `expected_len_bytes` before
/// calling this function, and MUST derive `expected_len_bytes` from
/// trusted input (not from `sig.len()` alone). Policy guidance:
///
/// * W3C XML Signature: ≥ 80 bits (CVE-2009-0217).
/// * RFC 4868: ≥ half the hash output size for IPsec.
/// * RFC 2104 §5: ≥ 80 bits for HMAC in general.
///
/// Passing an attacker-controlled value for `expected_len_bytes` reopens
/// the forgery vulnerability that [`constant_time_eq`]'s strict length
/// check was designed to close.
///
/// # Why this is distinct from `constant_time_eq`
///
/// `constant_time_eq` compares two equal-length byte strings. When the
/// strings are HMAC outputs, one must be the full expected MAC and the
/// other the submitted signature — which means the submitted side cannot
/// have been truncated. This function explicitly names the truncation
/// length so that the truncation decision belongs to the verifier (named
/// via the `expected_len_bytes` argument), not to whatever length the
/// attacker chose to submit.
pub fn hmac_verify_truncated(
    hash: HashAlgorithm,
    key: &[u8],
    data: &[u8],
    sig: &[u8],
    expected_len_bytes: usize,
) -> Result<bool> {
    if expected_len_bytes == 0 || sig.len() != expected_len_bytes {
        return Ok(false);
    }
    let full = compute_hmac(hash, key, data)?;
    if expected_len_bytes > full.len() {
        return Ok(false);
    }
    Ok(constant_time_eq(&full[..expected_len_bytes], sig))
}

// ── Internal digest wrapper ─────────────────────────────────────────

struct DigestImpl<H: Digest + Send> {
    inner: H,
    algo: HashAlgorithm,
}

impl<H: Digest + Send> DigestImpl<H> {
    fn new(algo: HashAlgorithm) -> Self {
        Self {
            inner: H::new(),
            algo,
        }
    }
}

impl<H: Digest + Send + 'static> DigestStream for DigestImpl<H> {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>> {
        Ok(Digest::finalize(self.inner).to_vec())
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algo
    }
}

/// Convert raw r||s or canonical DER to DER, checking both scalar ranges.
/// Exact raw width takes precedence; nonstandard raw widths allow zero padding.
pub fn ecdsa_raw_to_der(curve: crate::algorithm::EcCurve, raw: &[u8]) -> Result<Vec<u8>> {
    crate::ecdsa_encoding::to_der(curve, raw)
}

/// Convert canonical DER to fixed-width raw r||s, checking both scalar ranges.
pub fn ecdsa_der_to_raw(curve: crate::algorithm::EcCurve, der: &[u8]) -> Result<Vec<u8>> {
    crate::ecdsa_encoding::from_der(curve, der)
}

pub(crate) fn raw_to_p256_sig(input: &[u8]) -> Result<p256::ecdsa::Signature> {
    let raw = crate::ecdsa_encoding::normalize(crate::algorithm::EcCurve::P256, input)?;
    p256::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| Error::Crypto(format!("invalid P-256 signature: {e}")))
}

pub(crate) fn p256_sig_to_raw(sig: &p256::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

pub(crate) fn raw_to_p384_sig(input: &[u8]) -> Result<p384::ecdsa::Signature> {
    let raw = crate::ecdsa_encoding::normalize(crate::algorithm::EcCurve::P384, input)?;
    p384::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| Error::Crypto(format!("invalid P-384 signature: {e}")))
}

pub(crate) fn p384_sig_to_raw(sig: &p384::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

pub(crate) fn raw_to_p521_sig(input: &[u8]) -> Result<p521::ecdsa::Signature> {
    let raw = crate::ecdsa_encoding::normalize(crate::algorithm::EcCurve::P521, input)?;
    p521::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| Error::Crypto(format!("invalid P-521 signature: {e}")))
}

pub(crate) fn p521_sig_to_raw(sig: &p521::ecdsa::Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let mut out = Vec::with_capacity(132);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Left-pad a prehash with zeros to match the EC field size.
pub(crate) fn pad_prehash(prehash: &[u8], field_size: usize) -> Vec<u8> {
    if prehash.len() >= field_size {
        return prehash.to_vec();
    }
    let mut padded = vec![0u8; field_size];
    padded[field_size - prehash.len()..].copy_from_slice(prehash);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = digest(HashAlgorithm::Sha256, b"hello").unwrap();
        assert_eq!(result.len(), 32);
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn test_sha1() {
        let result = digest(HashAlgorithm::Sha1, b"hello").unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_sha512() {
        let result = digest(HashAlgorithm::Sha512, b"hello").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_streaming_digest() {
        let mut hasher = new_digest(HashAlgorithm::Sha256).unwrap();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let result = hasher.finalize().unwrap();
        let expected = digest(HashAlgorithm::Sha256, b"hello").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        let expected = [0xABu8; 32];
        // Any shorter-than-expected input must be rejected, regardless of
        // whether its bytes happen to match the prefix of `expected`.
        assert!(!constant_time_eq(&expected, &[0xAB]));
        assert!(!constant_time_eq(&expected, &expected[..16]));
        assert!(!constant_time_eq(&expected, &[]));
        // Longer-than-expected is also rejected.
        let mut longer = expected.to_vec();
        longer.push(0);
        assert!(!constant_time_eq(&expected, &longer));
    }

    #[test]
    fn constant_time_eq_equal_length() {
        let a = [0xABu8; 32];
        assert!(constant_time_eq(&a, &a));
        let mut b = a;
        b[31] ^= 1;
        assert!(!constant_time_eq(&a, &b));
    }

    // ── hmac_verify_truncated tests ──────────────────────────────────

    /// Helper: compute the real HMAC for a fixed (hash, key, data) triple
    /// so tests can slice it to various lengths.
    fn full_hmac_for_test() -> (HashAlgorithm, Vec<u8>, Vec<u8>, Vec<u8>) {
        let hash = HashAlgorithm::Sha256;
        let key = b"hmac-verify-truncated-test-key".to_vec();
        let data = b"message to authenticate".to_vec();
        let mac = compute_hmac(hash, &key, &data).unwrap();
        (hash, key, data, mac)
    }

    #[test]
    fn hmac_verify_truncated_full_length() {
        let (hash, key, data, mac) = full_hmac_for_test();
        // Full-length verify: behaves exactly like constant_time_eq.
        assert!(hmac_verify_truncated(hash, &key, &data, &mac, mac.len()).unwrap());
    }

    #[test]
    fn hmac_verify_truncated_accepts_verifier_declared_prefix() {
        let (hash, key, data, mac) = full_hmac_for_test();
        // 10-byte (80-bit) prefix of the real MAC — the XML Signature
        // minimum, and a common verifier-declared truncation length.
        let sig = &mac[..10];
        assert!(hmac_verify_truncated(hash, &key, &data, sig, 10).unwrap());
    }

    #[test]
    fn hmac_verify_truncated_rejects_wrong_prefix() {
        let (hash, key, data, mac) = full_hmac_for_test();
        let mut sig = mac[..10].to_vec();
        sig[0] ^= 0x01;
        assert!(!hmac_verify_truncated(hash, &key, &data, &sig, 10).unwrap());
    }

    #[test]
    fn hmac_verify_truncated_rejects_empty_expected() {
        let (hash, key, data, _mac) = full_hmac_for_test();
        // Verifier declared zero-length MAC → always reject. A naive
        // attacker could otherwise trivially forge via sig = [].
        assert!(!hmac_verify_truncated(hash, &key, &data, &[], 0).unwrap());
    }

    #[test]
    fn hmac_verify_truncated_rejects_length_mismatch() {
        let (hash, key, data, mac) = full_hmac_for_test();
        // sig.len() != expected_len_bytes even though the prefix would
        // match — reject, because the explicit length is the trusted
        // verifier-declared value.
        assert!(!hmac_verify_truncated(hash, &key, &data, &mac[..5], 10).unwrap());
        assert!(!hmac_verify_truncated(hash, &key, &data, &mac[..15], 10).unwrap());
    }

    #[test]
    fn hmac_verify_truncated_rejects_over_hash_size() {
        let (hash, key, data, _mac) = full_hmac_for_test();
        // SHA-256 output is 32 bytes. Ask for 33 bytes of prefix.
        let too_long = vec![0u8; 33];
        assert!(!hmac_verify_truncated(hash, &key, &data, &too_long, 33).unwrap());
    }

    /// This is the scenario that dsig's XML-DSig truncated-HMAC tests
    /// exercise: the signer produced a 5-byte (40-bit) MAC, the verifier
    /// declared the same, and the two must match byte-for-byte.
    #[test]
    fn hmac_verify_truncated_forty_bit_xmldsig_shape() {
        let (hash, key, data, mac) = full_hmac_for_test();
        let submitted = &mac[..5];
        assert!(hmac_verify_truncated(hash, &key, &data, submitted, 5).unwrap());
        // One-byte attacker-truncated forgery attempt: even if the
        // single byte matches the expected MAC's first byte, rejecting
        // because the verifier-declared length (5) doesn't match the
        // submitted length (1) is the safe outcome.
        let one_byte_forgery = &mac[..1];
        assert!(!hmac_verify_truncated(hash, &key, &data, one_byte_forgery, 5).unwrap());
    }

    // ── ECDSA signature-format disambiguation tests ──────────────────

    /// Pin the length-gated DER heuristic: a 64-byte raw P-256 signature
    /// whose first byte happens to be 0x30 must NOT be misinterpreted as
    /// DER. Probability of this shape by chance is ~1/256 per raw sig.
    #[test]
    fn p256_raw_starting_with_0x30_not_mistaken_for_der() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        // Brute a key whose signature over a fixed message starts with 0x30.
        // Bounded by birthday expectation (256 tries avg, 2000 max); we cap
        // the search to keep the test deterministic-bounded.
        let msg = b"format-disambiguation-vector";
        let mut sk;
        let mut raw;
        let mut tries = 0;
        loop {
            sk = SigningKey::random(&mut rand::rngs::OsRng);
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            raw = p256_sig_to_raw(&sig);
            if raw.first() == Some(&0x30) {
                break;
            }
            tries += 1;
            assert!(
                tries < 5000,
                "failed to generate 0x30-prefix raw sig in 5000 tries"
            );
        }
        assert_eq!(raw.len(), 64);

        // The 64-byte raw path should accept it cleanly via the equal-length
        // fast branch (the DER heuristic requires len > 64).
        let parsed = raw_to_p256_sig(&raw).expect("64-byte raw sig must parse");
        assert_eq!(p256_sig_to_raw(&parsed), raw);
    }
}
