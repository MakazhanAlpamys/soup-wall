//! AWS-LC KDFs: module implementations where available, with a portable
//! digest/HMAC composition for the remaining digests.

use crate::algorithm::HashAlgorithm;
use crate::backend::{require_supported, Operation};
use crate::digest;
use crate::error::{Error, Result};

pub const PBKDF2_MIN_SALT_LEN: usize = 8;
pub const PBKDF2_MIN_ITERATIONS: u32 = 1;
pub const PBKDF2_MAX_ITERATIONS: u32 = 100_000_000;
pub const PBKDF2_MAX_KEY_LEN: usize = 1 << 20;
pub const CONCAT_KDF_MAX_KEY_LEN: usize = 1 << 20;
/// FIPS builds require a 128-bit salt (SP 800-132 §5.1).
pub const FIPS_PBKDF2_MIN_SALT_LEN: usize = 16;
/// FIPS builds require the SP 800-132 recommended minimum iteration count.
pub const FIPS_PBKDF2_MIN_ITERATIONS: u32 = 1000;
/// FIPS builds require a password of at least 112 bits.
pub const FIPS_PBKDF2_MIN_PASSWORD_LEN: usize = 14;

#[derive(Debug, Clone)]
pub struct ConcatKdfParams {
    pub hash: HashAlgorithm,
    pub algorithm_id: Option<Vec<u8>>,
    pub party_u_info: Option<Vec<u8>>,
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

#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    pub hash: HashAlgorithm,
    pub salt: Vec<u8>,
    pub iteration_count: u32,
    pub key_length: usize,
}

impl Pbkdf2Params {
    /// Recommended parameters for `hash`, matching the RustCrypto provider
    /// (OWASP Password Storage Cheat Sheet, 2023).
    pub fn recommended(hash: HashAlgorithm, salt: Vec<u8>, key_length: usize) -> Self {
        let iteration_count = match hash {
            HashAlgorithm::Sha1 => 1_300_000,
            HashAlgorithm::Sha384 => 310_000,
            HashAlgorithm::Sha512 => 210_000,
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

#[derive(Debug, Clone)]
pub struct HkdfParams {
    pub hash: HashAlgorithm,
    pub salt: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
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

pub fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    params: &ConcatKdfParams,
) -> Result<Vec<u8>> {
    require_supported(Operation::ConcatKdf(params.hash))?;
    if key_len == 0 || key_len > CONCAT_KDF_MAX_KEY_LEN {
        return Err(Error::Crypto("invalid ConcatKDF output length".into()));
    }
    let mut other_info = Vec::new();
    for value in [
        &params.algorithm_id,
        &params.party_u_info,
        &params.party_v_info,
    ]
    .into_iter()
    .flatten()
    {
        other_info.extend_from_slice(value);
    }
    // ConcatKDF is the SP 800-56C one-step KDF with a digest auxiliary
    // function; use AWS-LC's module implementation where it exists.
    if let Some(algorithm) = sskdf_digest_algorithm(params.hash) {
        let mut output = vec![0u8; key_len];
        aws_lc_rs::kdf::sskdf_digest(algorithm, shared_secret, &other_info, &mut output)
            .map_err(|_| Error::Crypto("AWS-LC ConcatKDF derivation failed".into()))?;
        return Ok(output);
    }
    let hash_len = hash_len(params.hash)?;
    let mut output = Vec::with_capacity(key_len);
    for counter in 1..=key_len.div_ceil(hash_len) {
        let counter = u32::try_from(counter)
            .map_err(|_| Error::Crypto("ConcatKDF counter overflow".into()))?;
        let mut input = Vec::with_capacity(4 + shared_secret.len() + other_info.len());
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_secret);
        input.extend_from_slice(&other_info);
        output.extend_from_slice(&digest::digest(params.hash, &input)?);
    }
    output.truncate(key_len);
    Ok(output)
}

pub fn pbkdf2_derive(password: &[u8], params: &Pbkdf2Params) -> Result<Vec<u8>> {
    require_supported(Operation::Pbkdf2(params.hash))?;
    if params.salt.len() < PBKDF2_MIN_SALT_LEN
        || params.iteration_count < PBKDF2_MIN_ITERATIONS
        || params.iteration_count > PBKDF2_MAX_ITERATIONS
        || params.key_length == 0
        || params.key_length > PBKDF2_MAX_KEY_LEN
    {
        return Err(Error::Crypto("invalid PBKDF2 parameters".into()));
    }
    // SP 800-132 as enforced by AWS-LC's approval indicator: a salt of at
    // least 128 bits, at least 1000 iterations, and a 112-bit password.
    if cfg!(feature = "fips")
        && (params.salt.len() < FIPS_PBKDF2_MIN_SALT_LEN
            || params.iteration_count < FIPS_PBKDF2_MIN_ITERATIONS
            || password.len() < FIPS_PBKDF2_MIN_PASSWORD_LEN)
    {
        return Err(Error::Crypto(
            "PBKDF2 parameters are below the FIPS SP 800-132 minimums".into(),
        ));
    }
    if let Some(algorithm) = pbkdf2_algorithm(params.hash) {
        let iterations = std::num::NonZeroU32::new(params.iteration_count)
            .ok_or_else(|| Error::Crypto("invalid PBKDF2 parameters".into()))?;
        let mut output = vec![0u8; params.key_length];
        aws_lc_rs::pbkdf2::derive(algorithm, iterations, &params.salt, password, &mut output);
        return Ok(output);
    }
    let h_len = hash_len(params.hash)?;
    let blocks = params.key_length.div_ceil(h_len);
    let mut output = Vec::with_capacity(blocks * h_len);
    for block in 1..=blocks {
        let block = u32::try_from(block)
            .map_err(|_| Error::Crypto("PBKDF2 block counter overflow".into()))?;
        let mut first_input = params.salt.clone();
        first_input.extend_from_slice(&block.to_be_bytes());
        let mut u = digest::compute_hmac(params.hash, password, &first_input)?;
        let mut accumulator = u.clone();
        for _ in 1..params.iteration_count {
            u = digest::compute_hmac(params.hash, password, &u)?;
            for (left, right) in accumulator.iter_mut().zip(&u) {
                *left ^= right;
            }
        }
        output.extend_from_slice(&accumulator);
    }
    output.truncate(params.key_length);
    Ok(output)
}

pub fn hkdf_derive(shared_secret: &[u8], key_len: usize, params: &HkdfParams) -> Result<Vec<u8>> {
    require_supported(Operation::Hkdf(params.hash))?;
    let output_len = if params.key_length_bits > 0 {
        if !params.key_length_bits.is_multiple_of(8) {
            return Err(Error::Crypto(
                "HKDF output length is not byte aligned".into(),
            ));
        }
        params.key_length_bits as usize / 8
    } else {
        key_len
    };
    let h_len = hash_len(params.hash)?;
    if output_len == 0 || output_len > 255 * h_len {
        return Err(Error::Crypto("invalid HKDF output length".into()));
    }
    let zero_salt = vec![0u8; h_len];
    let salt = params.salt.as_deref().unwrap_or(&zero_salt);
    let info = params.info.as_deref().unwrap_or_default();
    if let Some(algorithm) = hkdf_algorithm(params.hash) {
        struct OutputLen(usize);
        impl aws_lc_rs::hkdf::KeyType for OutputLen {
            fn len(&self) -> usize {
                self.0
            }
        }
        let info = [info];
        let mut output = vec![0u8; output_len];
        aws_lc_rs::hkdf::Salt::new(algorithm, salt)
            .extract(shared_secret)
            .expand(&info, OutputLen(output_len))
            .and_then(|okm| okm.fill(&mut output))
            .map_err(|_| Error::Crypto("AWS-LC HKDF derivation failed".into()))?;
        return Ok(output);
    }
    let prk = digest::compute_hmac(params.hash, salt, shared_secret)?;
    let mut output = Vec::with_capacity(output_len);
    let mut previous = Vec::new();
    for counter in 1..=output_len.div_ceil(h_len) {
        let mut input = previous;
        input.extend_from_slice(info);
        input.push(counter as u8);
        previous = digest::compute_hmac(params.hash, &prk, &input)?;
        output.extend_from_slice(&previous);
    }
    output.truncate(output_len);
    Ok(output)
}

// The AWS-LC module implements these KDFs only for the digests below. Other
// digests use the portable HMAC/digest composition above, which the backend
// never reports as FIPS approved.

fn pbkdf2_algorithm(hash: HashAlgorithm) -> Option<aws_lc_rs::pbkdf2::Algorithm> {
    use aws_lc_rs::pbkdf2;
    match hash {
        HashAlgorithm::Sha1 => Some(pbkdf2::PBKDF2_HMAC_SHA1),
        HashAlgorithm::Sha256 => Some(pbkdf2::PBKDF2_HMAC_SHA256),
        HashAlgorithm::Sha384 => Some(pbkdf2::PBKDF2_HMAC_SHA384),
        HashAlgorithm::Sha512 => Some(pbkdf2::PBKDF2_HMAC_SHA512),
        _ => None,
    }
}

fn hkdf_algorithm(hash: HashAlgorithm) -> Option<aws_lc_rs::hkdf::Algorithm> {
    use aws_lc_rs::hkdf;
    match hash {
        HashAlgorithm::Sha1 => Some(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY),
        HashAlgorithm::Sha256 => Some(hkdf::HKDF_SHA256),
        HashAlgorithm::Sha384 => Some(hkdf::HKDF_SHA384),
        HashAlgorithm::Sha512 => Some(hkdf::HKDF_SHA512),
        _ => None,
    }
}

fn sskdf_digest_algorithm(
    hash: HashAlgorithm,
) -> Option<&'static aws_lc_rs::kdf::SskdfDigestAlgorithm> {
    use aws_lc_rs::kdf::{get_sskdf_digest_algorithm, SskdfDigestAlgorithmId};
    get_sskdf_digest_algorithm(match hash {
        HashAlgorithm::Sha224 => SskdfDigestAlgorithmId::Sha224,
        HashAlgorithm::Sha256 => SskdfDigestAlgorithmId::Sha256,
        HashAlgorithm::Sha384 => SskdfDigestAlgorithmId::Sha384,
        HashAlgorithm::Sha512 => SskdfDigestAlgorithmId::Sha512,
        _ => return None,
    })
}

fn hash_len(hash: HashAlgorithm) -> Result<usize> {
    Ok(digest::digest(hash, &[])?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case_1() {
        crate::backend::initialize_backend().expect("backend initialization");
        let output = hkdf_derive(
            &[0x0b; 22],
            42,
            &HkdfParams {
                hash: HashAlgorithm::Sha256,
                salt: Some((0u8..13).collect()),
                info: Some((0xf0u8..0xfa).collect()),
                key_length_bits: 0,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
