//! Digest and HMAC dispatch for the AWS-LC provider.

use crate::algorithm::{EcCurve, HashAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};

/// Opaque streaming digest interface.
pub trait DigestStream: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// AWS-LC-backed streaming digest.
///
/// Wraps `aws_lc_rs::digest::Context` so input is fed to the hash incrementally
/// in constant memory, matching the RustCrypto provider's `DigestImpl`
/// behaviour. An earlier version buffered the entire input in a `Vec<u8>` and
/// hashed it in one shot at finalize time, which made RSS grow linearly with
/// input size on AWS-LC builds while RustCrypto stayed flat.
struct AwsLcDigest {
    algorithm: HashAlgorithm,
    context: aws_lc_rs::digest::Context,
}

impl DigestStream for AwsLcDigest {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>> {
        Ok(self.context.finish().as_ref().to_vec())
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

pub fn new_digest(algorithm: HashAlgorithm) -> Result<Box<dyn DigestStream>> {
    require_supported(Operation::Digest(algorithm))?;
    let aws_algorithm = aws_digest(algorithm).ok_or_else(|| {
        Error::unsupported(Operation::Digest(algorithm), format!("{algorithm:?}"))
    })?;
    Ok(Box::new(AwsLcDigest {
        algorithm,
        context: aws_lc_rs::digest::Context::new(aws_algorithm),
    }))
}

pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Digest(algorithm))?;
    let algorithm = aws_digest(algorithm).ok_or_else(|| {
        Error::unsupported(Operation::Digest(algorithm), format!("{algorithm:?}"))
    })?;
    Ok(aws_lc_rs::digest::digest(algorithm, data).as_ref().to_vec())
}

pub fn compute_hmac(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::Hmac(hash))?;
    let algorithm = aws_hmac(hash)
        .ok_or_else(|| Error::unsupported(Operation::Hmac(hash), format!("{hash:?}")))?;
    let key = aws_lc_rs::hmac::Key::new(algorithm, key);
    Ok(aws_lc_rs::hmac::sign(&key, data).as_ref().to_vec())
}

fn aws_digest(hash: HashAlgorithm) -> Option<&'static aws_lc_rs::digest::Algorithm> {
    Some(match hash {
        HashAlgorithm::Sha1 => &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha224 => &aws_lc_rs::digest::SHA224,
        HashAlgorithm::Sha256 => &aws_lc_rs::digest::SHA256,
        HashAlgorithm::Sha384 => &aws_lc_rs::digest::SHA384,
        HashAlgorithm::Sha512 => &aws_lc_rs::digest::SHA512,
        HashAlgorithm::Sha3_256 => &aws_lc_rs::digest::SHA3_256,
        HashAlgorithm::Sha3_384 => &aws_lc_rs::digest::SHA3_384,
        HashAlgorithm::Sha3_512 => &aws_lc_rs::digest::SHA3_512,
        _ => return None,
    })
}

fn aws_hmac(hash: HashAlgorithm) -> Option<aws_lc_rs::hmac::Algorithm> {
    Some(match hash {
        HashAlgorithm::Sha1 => aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha224 => aws_lc_rs::hmac::HMAC_SHA224,
        HashAlgorithm::Sha256 => aws_lc_rs::hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => aws_lc_rs::hmac::HMAC_SHA384,
        HashAlgorithm::Sha512 => aws_lc_rs::hmac::HMAC_SHA512,
        _ => return None,
    })
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn hmac_verify_truncated(
    hash: HashAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
    expected_len_bytes: usize,
) -> Result<bool> {
    if expected_len_bytes == 0 || signature.len() != expected_len_bytes {
        return Ok(false);
    }
    let full = compute_hmac(hash, key, data)?;
    if expected_len_bytes > full.len() {
        return Ok(false);
    }
    Ok(constant_time_eq(&full[..expected_len_bytes], signature))
}

/// Convert raw r||s or canonical DER to DER, checking both scalar ranges.
/// Exact raw width takes precedence; nonstandard raw widths allow zero padding.
pub fn ecdsa_raw_to_der(curve: EcCurve, raw: &[u8]) -> Result<Vec<u8>> {
    crate::ecdsa_encoding::to_der(curve, raw)
}

/// Convert canonical DER to fixed-width raw r||s, checking both scalar ranges.
pub fn ecdsa_der_to_raw(curve: EcCurve, der: &[u8]) -> Result<Vec<u8>> {
    crate::ecdsa_encoding::from_der(curve, der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        crate::backend::initialize_backend().expect("backend initialization");
        let output = digest(HashAlgorithm::Sha256, b"abc").unwrap();
        assert_eq!(
            hex::encode(output),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ecdsa_der_round_trip() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80;
        raw[63] = 7;
        let der = ecdsa_raw_to_der(EcCurve::P256, &raw).unwrap();
        assert_eq!(ecdsa_der_to_raw(EcCurve::P256, &der).unwrap(), raw);
    }

    #[test]
    fn ecdsa_accepts_short_and_zero_padded_raw_components() {
        let short = vec![1u8; 62];
        assert!(ecdsa_raw_to_der(EcCurve::P256, &short).is_ok());

        let mut padded = vec![0u8; 66];
        padded[1] = 1;
        padded[34] = 2;
        assert!(ecdsa_raw_to_der(EcCurve::P256, &padded).is_ok());
    }

    // DER canonicality (X.690 §8.1.3.3 / §8.3.2): two distinct byte strings
    // must not decode to the same r||s. Each test below is a valid
    // signature semantically but a non-minimal DER encoding; the parser
    // must reject it so consensus callers see one canonical form.

    #[test]
    fn ecdsa_rejects_non_minimal_long_form_length() {
        // SEQUENCE of two 1-byte integers (r=1, s=1). Canonical:
        //   30 06 02 01 01 02 01 01
        // Non-minimal length for the SEQUENCE (0x81 0x06 instead of 0x06):
        //   30 81 06 02 01 01 02 01 01
        let non_minimal = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_rejects_non_minimal_multi_octet_length() {
        // SEQUENCE length 0x80 encoded as 0x82 0x00 0x80 instead of 0x81 0x80.
        // The length octets alone must be rejected before the body is inspected.
        let mut non_minimal = vec![0x30, 0x82, 0x00, 0x80];
        // r: 32 bytes with high bit set (needs leading zero) -> 33 content bytes
        non_minimal.push(0x02);
        non_minimal.push(0x21);
        non_minimal.push(0x00);
        non_minimal.extend([0x80; 32]);
        // s: 32 bytes with high bit set -> 33 content bytes
        non_minimal.push(0x02);
        non_minimal.push(0x21);
        non_minimal.push(0x00);
        non_minimal.extend([0x80; 32]);
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_rejects_unnecessary_leading_zero_in_integer() {
        // r = 0x01 encoded as 0x02 0x02 0x00 0x01 (leading zero, next byte
        // high bit clear) instead of the minimal 0x02 0x01 0x01.
        let non_minimal = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_raw(EcCurve::P256, &non_minimal).is_err());
    }

    #[test]
    fn ecdsa_accepts_required_leading_zero_in_integer() {
        // r = 0x80 (high bit set) must be encoded as 0x02 0x02 0x00 0x80 to
        // stay positive — the leading zero is required, not non-minimal.
        let mut der = vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x80];
        // Pad the raw form to 64 bytes so der_to_raw lands in field width.
        let _ = &mut der;
        let raw =
            ecdsa_der_to_raw(EcCurve::P256, &der).expect("required leading zero is canonical");
        assert_eq!(raw.len(), 64);
    }
}
