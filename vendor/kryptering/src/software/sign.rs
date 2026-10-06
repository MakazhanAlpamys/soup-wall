//! Software signing and verification using RustCrypto primitives.
//!
//! `SoftwareSigner` and `SoftwareVerifier` implement the `Signer` and `Verifier`
//! traits from `crate::traits`, holding both the algorithm and key material.

use crate::algorithm::{EcCurve, HashAlgorithm, SignatureAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::digest;
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey as SoftwareKey, SoftwareKey as OpaqueSoftwareKey};
use crate::traits;
use signature::SignatureEncoding;

// ── Hash dispatch macro ─────────────────────────────────────────────

/// Dispatch a macro invocation across all `HashAlgorithm` variants.
/// The callback macro must accept a single type parameter `($hasher:ty)`.
macro_rules! dispatch_hash {
    ($hash:expr, $callback:ident) => {
        match $hash {
            HashAlgorithm::Sha1 => $callback!(sha1::Sha1),
            HashAlgorithm::Sha224 => $callback!(sha2::Sha224),
            HashAlgorithm::Sha256 => $callback!(sha2::Sha256),
            HashAlgorithm::Sha384 => $callback!(sha2::Sha384),
            HashAlgorithm::Sha512 => $callback!(sha2::Sha512),
            HashAlgorithm::Sha3_224 => $callback!(sha3::Sha3_224),
            HashAlgorithm::Sha3_256 => $callback!(sha3::Sha3_256),
            HashAlgorithm::Sha3_384 => $callback!(sha3::Sha3_384),
            HashAlgorithm::Sha3_512 => $callback!(sha3::Sha3_512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => $callback!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => $callback!(ripemd::Ripemd160),
        }
    };
}

// ── SoftwareSigner ──────────────────────────────────────────────────

/// Software-backed signer that holds algorithm and key material.
pub struct SoftwareSigner {
    algorithm: SignatureAlgorithm,
    key: OpaqueSoftwareKey,
    /// Optional FIPS 204 / FIPS 205 context string for ML-DSA / SLH-DSA.
    /// Ignored by every other algorithm. An earlier version hardcoded this
    /// to empty for both sign and verify, which prevented callers from using
    /// a single PQ key across multiple protocols with domain separation.
    #[cfg_attr(not(feature = "post-quantum"), allow(dead_code))]
    pq_context: Vec<u8>,
}

impl SoftwareSigner {
    /// Create a new signer with an empty FIPS 204/205 context (equivalent to
    /// [`new_with_pq_context`](Self::new_with_pq_context) with `&[]`).
    pub fn new<K: Into<OpaqueSoftwareKey>>(algorithm: SignatureAlgorithm, key: K) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    /// Create a new signer with an explicit FIPS 204 (ML-DSA) or FIPS 205
    /// (SLH-DSA) context string. Composite ML-DSA supplies its fixed label
    /// internally and therefore rejects a caller-provided context.
    pub fn new_with_pq_context<K: Into<OpaqueSoftwareKey>>(
        algorithm: SignatureAlgorithm,
        key: K,
        pq_context: &[u8],
    ) -> Result<Self> {
        require_supported(Operation::Sign(algorithm))?;
        let key = key.into();
        validate_signing_key(&algorithm, key.inner())?;
        if !pq_context.is_empty() && !is_pq_algorithm(&algorithm) {
            return Err(Error::Key(
                "signature algorithm does not accept a context string supplied by the caller"
                    .into(),
            ));
        }
        Ok(Self {
            algorithm,
            key,
            pq_context: pq_context.to_vec(),
        })
    }
}

impl traits::Signer for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.inner();
        match &self.algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => rsa_pkcs1v15_sign(key, *hash, data),
            SignatureAlgorithm::RsaPss(hash) => rsa_pss_sign(key, *hash, data),
            SignatureAlgorithm::Ecdsa(curve, hash) => ecdsa_sign(key, *curve, *hash, data),
            SignatureAlgorithm::Ed25519 => ed25519_sign(key, data),
            SignatureAlgorithm::Hmac(hash) => hmac_sign(key, *hash, data),
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => dsa_sign(key, *hash, data),
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::MlDsa(variant) => {
                pq_ml_dsa_sign_dispatch(key, *variant, data, &self.pq_context)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::CompositeMlDsa(variant) => {
                crate::software::composite::sign(key, *variant, data)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::SlhDsa(variant) => {
                pq_slh_dsa_sign_dispatch(key, *variant, data, &self.pq_context)
            }
        }
    }
}

/// Returns true iff `algo` is a post-quantum algorithm that supports a
/// FIPS 204 / 205 context string.
#[allow(dead_code)] // used only when `post-quantum` feature is enabled
fn is_pq_algorithm(algo: &SignatureAlgorithm) -> bool {
    #[cfg(feature = "post-quantum")]
    {
        matches!(
            algo,
            SignatureAlgorithm::MlDsa(_) | SignatureAlgorithm::SlhDsa(_)
        )
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        let _ = algo;
        false
    }
}

// ── SoftwareVerifier ────────────────────────────────────────────────

/// Software-backed verifier that holds algorithm and key material.
pub struct SoftwareVerifier {
    algorithm: SignatureAlgorithm,
    key: OpaqueSoftwareKey,
    rsa_pss_salt_len: Option<usize>,
    /// See [`SoftwareSigner::new_with_pq_context`]. Must match the signer's
    /// context byte-for-byte or verification fails.
    #[cfg_attr(not(feature = "post-quantum"), allow(dead_code))]
    pq_context: Vec<u8>,
}

impl SoftwareVerifier {
    /// Create a new verifier with an empty FIPS 204/205 context.
    pub fn new<K: Into<OpaqueSoftwareKey>>(algorithm: SignatureAlgorithm, key: K) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    /// Create a new verifier with an explicit FIPS 204 (ML-DSA) or FIPS 205
    /// (SLH-DSA) context string. Must match the signer's context exactly;
    /// see [`SoftwareSigner::new_with_pq_context`] for rationale.
    pub fn new_with_pq_context<K: Into<OpaqueSoftwareKey>>(
        algorithm: SignatureAlgorithm,
        key: K,
        pq_context: &[u8],
    ) -> Result<Self> {
        require_supported(Operation::Verify(algorithm))?;
        let key = key.into();
        validate_verifying_key(&algorithm, key.inner())?;
        if !pq_context.is_empty() && !is_pq_algorithm(&algorithm) {
            return Err(Error::Key(
                "signature algorithm does not accept a context string supplied by the caller"
                    .into(),
            ));
        }
        Ok(Self {
            algorithm,
            key,
            rsa_pss_salt_len: None,
            pq_context: pq_context.to_vec(),
        })
    }

    /// Create an RSA-PSS verifier with an explicit salt length.
    ///
    /// This is intended for parameterized certificate/CMS algorithms where
    /// the salt length is carried in the signed `AlgorithmIdentifier`.
    /// A salt length that cannot fit in the key's encoded message
    /// (`emLen - hLen - 2`, RFC 8017 §9.1.2) is rejected here, before the
    /// attacker-controlled value reaches `rsa`'s unchecked length arithmetic.
    pub fn new_rsa_pss_with_salt<K: Into<OpaqueSoftwareKey>>(
        hash: HashAlgorithm,
        salt_len: usize,
        key: K,
    ) -> Result<Self> {
        let mut verifier = Self::new(SignatureAlgorithm::RsaPss(hash), key)?;
        let max_salt_len = rsa_pss_max_salt_len(extract_rsa_public(verifier.key.inner())?, hash)
            .ok_or_else(|| Error::Key("RSA-PSS key is too small for the selected hash".into()))?;
        if salt_len > max_salt_len {
            return Err(Error::Key(format!(
                "RSA-PSS salt length {salt_len} exceeds the {max_salt_len}-byte maximum for this key and hash"
            )));
        }
        verifier.rsa_pss_salt_len = Some(salt_len);
        Ok(verifier)
    }

    /// Verify a signature encoded in the ASN.1 form used by X.509/CMS.
    ///
    /// ECDSA and DSA protocol signatures are DER sequences, while the lower
    /// provider interface uses fixed-width neutral components.
    pub fn verify_der_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        match self.algorithm {
            SignatureAlgorithm::Ecdsa(curve, _) => {
                let raw = digest::ecdsa_der_to_raw(curve, signature)?;
                traits::Verifier::verify(self, data, &raw)
            }
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => {
                use ::digest::Digest;
                use dsa::pkcs8::der::Decode;
                use signature::DigestVerifier;

                let key = self.key.inner();
                let vk = match key {
                    SoftwareKey::Dsa {
                        private: Some(sk), ..
                    } => sk.verifying_key().clone(),
                    SoftwareKey::Dsa { public, .. } => public.clone(),
                    _ => return Err(Error::Key("DSA key required".into())),
                };
                let parsed = dsa::Signature::from_der(signature)
                    .map_err(|e| Error::Crypto(format!("invalid DSA DER signature: {e}")))?;
                let result = match hash {
                    HashAlgorithm::Sha1 => {
                        vk.verify_digest(sha1::Sha1::new_with_prefix(data), &parsed)
                    }
                    HashAlgorithm::Sha256 => {
                        vk.verify_digest(sha2::Sha256::new_with_prefix(data), &parsed)
                    }
                    _ => {
                        return Err(Error::unsupported(
                            Operation::Verify(self.algorithm),
                            format!("DSA with {hash:?}"),
                        ))
                    }
                };
                Ok(result.is_ok())
            }
            _ => traits::Verifier::verify(self, data, signature),
        }
    }
}

impl traits::Verifier for SoftwareVerifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let key = self.key.inner();
        match &self.algorithm {
            SignatureAlgorithm::RsaPkcs1v15(hash) => {
                rsa_pkcs1v15_verify(key, *hash, data, signature)
            }
            SignatureAlgorithm::RsaPss(hash) => {
                rsa_pss_verify(key, *hash, self.rsa_pss_salt_len, data, signature)
            }
            SignatureAlgorithm::Ecdsa(curve, hash) => {
                ecdsa_verify(key, *curve, *hash, data, signature)
            }
            SignatureAlgorithm::Ed25519 => ed25519_verify(key, data, signature),
            SignatureAlgorithm::Hmac(hash) => hmac_verify(key, *hash, data, signature),
            #[cfg(feature = "legacy")]
            SignatureAlgorithm::Dsa(hash) => dsa_verify(key, *hash, data, signature),
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::MlDsa(variant) => {
                pq_ml_dsa_verify_dispatch(key, *variant, data, signature, &self.pq_context)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::CompositeMlDsa(variant) => {
                crate::software::composite::verify(key, *variant, data, signature)
            }
            #[cfg(feature = "post-quantum")]
            SignatureAlgorithm::SlhDsa(variant) => {
                pq_slh_dsa_verify_dispatch(key, *variant, data, signature, &self.pq_context)
            }
        }
    }
}

// ── Key validation ──────────────────────────────────────────────────

/// Validate that a key is suitable for signing with the given algorithm.
fn validate_signing_key(algorithm: &SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    match (algorithm, key) {
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_),
            SoftwareKey::Rsa { private, public },
        ) => {
            if private.is_none() {
                return Err(Error::Key("RSA private key required for signing".into()));
            }
            crate::key::enforce_rsa_min_bits(Operation::Sign(*algorithm), public)
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P256, _), SoftwareKey::EcP256 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-256 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P384, _), SoftwareKey::EcP384 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-384 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ecdsa(EcCurve::P521, _), SoftwareKey::EcP521 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("P-521 private key required for signing".into()));
            }
            Ok(())
        }
        (SignatureAlgorithm::Ed25519, SoftwareKey::Ed25519 { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key(
                    "Ed25519 private key required for signing".into(),
                ));
            }
            Ok(())
        }
        (SignatureAlgorithm::Hmac(_), SoftwareKey::Hmac(key_bytes)) => {
            if key_bytes.is_empty() {
                return Err(Error::Key("HMAC key must not be empty".into()));
            }
            Ok(())
        }
        #[cfg(feature = "legacy")]
        (SignatureAlgorithm::Dsa(_), SoftwareKey::Dsa { private, .. }) => {
            if private.is_none() {
                return Err(Error::Key("DSA private key required for signing".into()));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::MlDsa(variant),
            SoftwareKey::PostQuantum {
                algorithm,
                private_der,
                ..
            },
        ) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::MlDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but signature requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            if private_der.is_none() {
                return Err(Error::Key(format!(
                    "{} private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::CompositeMlDsa(variant),
            SoftwareKey::CompositeMlDsa {
                variant: key_variant,
                private,
                ..
            },
        ) => {
            if key_variant != variant {
                return Err(Error::Key(format!(
                    "composite key is {}, but signature requires {}",
                    key_variant.name(),
                    variant.name()
                )));
            }
            if private.is_none() {
                return Err(Error::Key(format!(
                    "{} aggregate private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::SlhDsa(variant),
            SoftwareKey::PostQuantum {
                algorithm,
                private_der,
                ..
            },
        ) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::SlhDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but signature requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            if private_der.is_none() {
                return Err(Error::Key(format!(
                    "{} private key required for signing",
                    variant.name()
                )));
            }
            Ok(())
        }
        _ => Err(Error::Key(format!(
            "key type does not match algorithm {algorithm:?}"
        ))),
    }
}

/// Validate that a key is suitable for verifying with the given algorithm.
fn validate_verifying_key(algorithm: &SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    match (algorithm, key) {
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_),
            SoftwareKey::Rsa { public, .. },
        ) => crate::key::enforce_rsa_min_bits(Operation::Verify(*algorithm), public),
        (SignatureAlgorithm::Ecdsa(EcCurve::P256, _), SoftwareKey::EcP256 { .. }) => Ok(()),
        (SignatureAlgorithm::Ecdsa(EcCurve::P384, _), SoftwareKey::EcP384 { .. }) => Ok(()),
        (SignatureAlgorithm::Ecdsa(EcCurve::P521, _), SoftwareKey::EcP521 { .. }) => Ok(()),
        (SignatureAlgorithm::Ed25519, SoftwareKey::Ed25519 { .. }) => Ok(()),
        (SignatureAlgorithm::Hmac(_), SoftwareKey::Hmac(key_bytes)) => {
            if key_bytes.is_empty() {
                return Err(Error::Key("HMAC key must not be empty".into()));
            }
            Ok(())
        }
        #[cfg(feature = "legacy")]
        (SignatureAlgorithm::Dsa(_), SoftwareKey::Dsa { .. }) => Ok(()),
        #[cfg(feature = "post-quantum")]
        (SignatureAlgorithm::MlDsa(variant), SoftwareKey::PostQuantum { algorithm, .. }) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::MlDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but verification requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (
            SignatureAlgorithm::CompositeMlDsa(variant),
            SoftwareKey::CompositeMlDsa {
                variant: key_variant,
                ..
            },
        ) => {
            if key_variant != variant {
                return Err(Error::Key(format!(
                    "composite key is {}, but verification requires {}",
                    key_variant.name(),
                    variant.name()
                )));
            }
            Ok(())
        }
        #[cfg(feature = "post-quantum")]
        (SignatureAlgorithm::SlhDsa(variant), SoftwareKey::PostQuantum { algorithm, .. }) => {
            use crate::algorithm::PqAlgorithm;
            let expected = PqAlgorithm::SlhDsa(*variant);
            if *algorithm != expected {
                return Err(Error::Key(format!(
                    "key algorithm mismatch: key is {}, but verification requires {}",
                    algorithm.name(),
                    expected.name(),
                )));
            }
            Ok(())
        }
        _ => Err(Error::Key(format!(
            "key type does not match algorithm {algorithm:?}"
        ))),
    }
}

// ── RSA PKCS#1 v1.5 ────────────────────────────────────────────────

fn rsa_pkcs1v15_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use signature::Signer;
    let SoftwareKey::Rsa {
        private: Some(private_key),
        ..
    } = key
    else {
        return Err(Error::Key("RSA private key required".into()));
    };
    macro_rules! do_sign {
        ($hasher:ty) => {{
            let sk = rsa::pkcs1v15::SigningKey::<$hasher>::new(private_key.clone());
            Ok(sk.sign(data).to_vec())
        }};
    }
    dispatch_hash!(hash, do_sign)
}

fn rsa_pkcs1v15_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::Verifier;
    let public_key = extract_rsa_public(key)?;
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid RSA signature: {e}")))?;
    macro_rules! do_verify {
        ($hasher:ty) => {{
            let vk = rsa::pkcs1v15::VerifyingKey::<$hasher>::new(public_key.clone());
            Ok(vk.verify(data, &sig).is_ok())
        }};
    }
    dispatch_hash!(hash, do_verify)
}

// ── RSA-PSS ─────────────────────────────────────────────────────────

fn rsa_pss_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use signature::RandomizedSigner;
    let SoftwareKey::Rsa {
        private: Some(private_key),
        ..
    } = key
    else {
        return Err(Error::Key("RSA private key required for PSS".into()));
    };
    // `signature 2.2.0` still consumes `rand_core 0.6 CryptoRngCore`, which
    // `getrandom::SysRng` (rand_core 0.10) does not satisfy. `rand::rngs::OsRng`
    // is the rand-0.8-track equivalent: same OS-entropy syscall per draw, zero
    // user-space state, fork-safe. See docs/adr/0001-rng-choice.md.
    let mut rng = rand::rngs::OsRng;
    macro_rules! do_sign {
        ($hasher:ty) => {{
            let sk = rsa::pss::SigningKey::<$hasher>::new(private_key.clone());
            let sig = sk.sign_with_rng(&mut rng, data);
            Ok(sig.to_vec())
        }};
    }
    dispatch_hash!(hash, do_sign)
}

fn rsa_pss_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    salt_len: Option<usize>,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::Verifier;
    let public_key = extract_rsa_public(key)?;
    let sig = rsa::pss::Signature::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid RSA-PSS signature: {e}")))?;
    macro_rules! do_verify {
        ($hasher:ty) => {{
            let vk = match salt_len {
                Some(salt_len) => rsa::pss::VerifyingKey::<$hasher>::new_with_salt_len(
                    public_key.clone(),
                    salt_len,
                ),
                None => rsa::pss::VerifyingKey::<$hasher>::new(public_key.clone()),
            };
            Ok(vk.verify(data, &sig).is_ok())
        }};
    }
    dispatch_hash!(hash, do_verify)
}

/// Largest RSA-PSS salt that fits the key's encoded message:
/// `emLen - hLen - 2` with `emLen = ceil((modBits - 1) / 8)` (RFC 8017 §9.1.1).
/// Returns `None` when even a zero-length salt cannot fit.
fn rsa_pss_max_salt_len(public_key: &rsa::RsaPublicKey, hash: HashAlgorithm) -> Option<usize> {
    use rsa::traits::PublicKeyParts;
    macro_rules! output_len {
        ($hasher:ty) => {
            <$hasher as ::digest::Digest>::output_size()
        };
    }
    let h_len = dispatch_hash!(hash, output_len);
    let em_len = public_key.n().bits().saturating_sub(1).div_ceil(8);
    em_len.checked_sub(h_len + 2)
}

/// Extract the RSA public key from a `SoftwareKey::Rsa`.
fn extract_rsa_public(key: &SoftwareKey) -> Result<&rsa::RsaPublicKey> {
    match key {
        SoftwareKey::Rsa { public, .. } => Ok(public),
        _ => Err(Error::Key("RSA key required".into())),
    }
}

// ── ECDSA ───────────────────────────────────────────────────────────

fn ecdsa_sign(
    key: &SoftwareKey,
    curve: EcCurve,
    hash: HashAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>> {
    use signature::hazmat::PrehashSigner;
    let raw_hash = digest::digest(hash, data)?;
    match (curve, key) {
        (
            EcCurve::P256,
            SoftwareKey::EcP256 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig: p256::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-256 sign: {e}")))?;
            Ok(digest::p256_sig_to_raw(&sig))
        }
        (
            EcCurve::P384,
            SoftwareKey::EcP384 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig: p384::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-384 sign: {e}")))?;
            Ok(digest::p384_sig_to_raw(&sig))
        }
        (
            EcCurve::P521,
            SoftwareKey::EcP521 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig: p521::ecdsa::Signature = sk
                .sign_prehash(&prehash)
                .map_err(|e| Error::Crypto(format!("ECDSA P-521 sign: {e}")))?;
            Ok(digest::p521_sig_to_raw(&sig))
        }
        _ => Err(Error::Key(format!(
            "ECDSA {curve:?} private key required for signing"
        ))),
    }
}

fn ecdsa_verify(
    key: &SoftwareKey,
    curve: EcCurve,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use signature::hazmat::PrehashVerifier;
    let raw_hash = digest::digest(hash, data)?;
    match (curve, key) {
        (
            EcCurve::P256,
            SoftwareKey::EcP256 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig = digest::raw_to_p256_sig(sig_bytes)?;
            Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P256, SoftwareKey::EcP256 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 32);
            let sig = digest::raw_to_p256_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (
            EcCurve::P384,
            SoftwareKey::EcP384 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig = digest::raw_to_p384_sig(sig_bytes)?;
            Ok(sk.verifying_key().verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P384, SoftwareKey::EcP384 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 48);
            let sig = digest::raw_to_p384_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        (
            EcCurve::P521,
            SoftwareKey::EcP521 {
                private: Some(sk), ..
            },
        ) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig = digest::raw_to_p521_sig(sig_bytes)?;
            let vk = p521::ecdsa::VerifyingKey::from(sk);
            Ok(vk.verify_prehash(&prehash, &sig).is_ok())
        }
        (EcCurve::P521, SoftwareKey::EcP521 { public, .. }) => {
            let prehash = digest::pad_prehash(&raw_hash, 66);
            let sig = digest::raw_to_p521_sig(sig_bytes)?;
            Ok(public.verify_prehash(&prehash, &sig).is_ok())
        }
        _ => Err(Error::Key(format!(
            "ECDSA {curve:?} key required for verification"
        ))),
    }
}

// ── Ed25519 ─────────────────────────────────────────────────────────

fn ed25519_sign(key: &SoftwareKey, data: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;
    let SoftwareKey::Ed25519 {
        private: Some(sk), ..
    } = key
    else {
        return Err(Error::Key("Ed25519 private key required".into()));
    };
    let sig = sk.sign(data);
    Ok(sig.to_bytes().to_vec())
}

fn ed25519_verify(key: &SoftwareKey, data: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let vk = match key {
        SoftwareKey::Ed25519 {
            private: Some(sk), ..
        } => sk.verifying_key(),
        SoftwareKey::Ed25519 { public, .. } => *public,
        _ => return Err(Error::Key("Ed25519 key required".into())),
    };
    let sig = ed25519_dalek::Signature::from_slice(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 signature: {e}")))?;
    // `verify_strict` rejects non-canonical `R` encodings, low-order `R`
    // (identity / small-subgroup points), and non-canonical scalar `s`.
    // Standard implementations (ed25519-dalek, OpenSSL, BoringSSL, NaCl)
    // always produce canonical signatures, so this is a no-op for
    // legitimate signers; the strict check closes a malleability surface
    // for consensus / certificate-transparency / signed-receipt callers
    // that treat the signature bytes themselves as unique.
    Ok(vk.verify_strict(data, &sig).is_ok())
}

// ── HMAC ────────────────────────────────────────────────────────────

fn hmac_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    let SoftwareKey::Hmac(key_bytes) = key else {
        return Err(Error::Key("HMAC key required".into()));
    };
    digest::compute_hmac(hash, key_bytes, data)
}

fn hmac_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    let SoftwareKey::Hmac(key_bytes) = key else {
        return Err(Error::Key("HMAC key required".into()));
    };
    let expected = digest::compute_hmac(hash, key_bytes, data)?;
    Ok(digest::constant_time_eq(&expected, sig_bytes))
}

// ── DSA (legacy) ────────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn dsa_sign(key: &SoftwareKey, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use ::digest::Digest;
    use signature::DigestSigner;

    let SoftwareKey::Dsa {
        private: Some(sk), ..
    } = key
    else {
        return Err(Error::Key("DSA private key required".into()));
    };
    let sig: dsa::Signature = match hash {
        HashAlgorithm::Sha1 => sk
            .try_sign_digest(sha1::Sha1::new_with_prefix(data))
            .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
        HashAlgorithm::Sha256 => sk
            .try_sign_digest(sha2::Sha256::new_with_prefix(data))
            .map_err(|e| Error::Crypto(format!("DSA sign: {e}")))?,
        _ => {
            return Err(Error::unsupported(
                crate::backend::Operation::Sign(SignatureAlgorithm::Dsa(hash)),
                format!("DSA with {hash:?}"),
            ));
        }
    };
    Ok(dsa_sig_to_raw(sk.verifying_key(), &sig))
}

#[cfg(feature = "legacy")]
fn dsa_verify(
    key: &SoftwareKey,
    hash: HashAlgorithm,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use ::digest::Digest;
    use signature::DigestVerifier;

    let vk = match key {
        SoftwareKey::Dsa {
            private: Some(sk), ..
        } => sk.verifying_key().clone(),
        SoftwareKey::Dsa { public, .. } => public.clone(),
        _ => return Err(Error::Key("DSA key required".into())),
    };
    let sig = raw_to_dsa_sig(&vk, sig_bytes)?;
    let result = match hash {
        HashAlgorithm::Sha1 => vk.verify_digest(sha1::Sha1::new_with_prefix(data), &sig),
        HashAlgorithm::Sha256 => vk.verify_digest(sha2::Sha256::new_with_prefix(data), &sig),
        _ => {
            return Err(Error::unsupported(
                crate::backend::Operation::Verify(SignatureAlgorithm::Dsa(hash)),
                format!("DSA with {hash:?}"),
            ));
        }
    };
    Ok(result.is_ok())
}

#[cfg(feature = "legacy")]
fn dsa_sig_to_raw(vk: &dsa::VerifyingKey, sig: &dsa::Signature) -> Vec<u8> {
    let q_len = vk.components().q().bits().div_ceil(8);
    let r_bytes = sig.r().to_bytes_be();
    let s_bytes = sig.s().to_bytes_be();
    // Invariant: FIPS 186-4 §4.6 defines a valid DSA signature as
    // (r, s) with 0 < r < q and 0 < s < q. Therefore r_bytes.len() and
    // s_bytes.len() are both `<= q_len`. The `saturating_sub` calls below
    // defend against a buggy signer that violates this, but silent
    // truncation would produce a signature whose serialization does not
    // round-trip. Assert in debug builds so such a signer is caught in
    // tests rather than producing confusingly-malformed output in prod.
    debug_assert!(
        r_bytes.len() <= q_len,
        "DSA signer produced r ({} bytes) > q ({} bytes); violates FIPS 186-4",
        r_bytes.len(),
        q_len,
    );
    debug_assert!(
        s_bytes.len() <= q_len,
        "DSA signer produced s ({} bytes) > q ({} bytes); violates FIPS 186-4",
        s_bytes.len(),
        q_len,
    );
    let mut out = vec![0u8; q_len * 2];
    let r_start = q_len.saturating_sub(r_bytes.len());
    out[r_start..q_len].copy_from_slice(&r_bytes[r_bytes.len().saturating_sub(q_len)..]);
    let s_start = q_len + q_len.saturating_sub(s_bytes.len());
    out[s_start..q_len * 2].copy_from_slice(&s_bytes[s_bytes.len().saturating_sub(q_len)..]);
    out
}

#[cfg(feature = "legacy")]
fn raw_to_dsa_sig(vk: &dsa::VerifyingKey, rs: &[u8]) -> Result<dsa::Signature> {
    let q_len = vk.components().q().bits().div_ceil(8);
    if rs.len() != q_len * 2 {
        return Err(Error::Crypto(format!(
            "DSA signature must be {} bytes (2 * q_len={}), got {}",
            q_len * 2,
            q_len,
            rs.len()
        )));
    }
    let r = dsa::BigUint::from_bytes_be(&rs[..q_len]);
    let s = dsa::BigUint::from_bytes_be(&rs[q_len..]);
    dsa::Signature::from_components(r, s)
        .map_err(|e| Error::Crypto(format!("invalid DSA signature: {e}")))
}

// ── Post-quantum: ML-DSA (FIPS 204) ────────────────────────────────

#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_sign_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::MlDsaVariant,
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use crate::algorithm::MlDsaVariant;
    let SoftwareKey::PostQuantum {
        private_der: Some(private),
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} private key required for signing",
            variant.name()
        )));
    };
    match variant {
        MlDsaVariant::MlDsa44 => pq_ml_dsa_sign::<ml_dsa::MlDsa44>(private, data, context),
        MlDsaVariant::MlDsa65 => pq_ml_dsa_sign::<ml_dsa::MlDsa65>(private, data, context),
        MlDsaVariant::MlDsa87 => pq_ml_dsa_sign::<ml_dsa::MlDsa87>(private, data, context),
    }
}

/// Sign with ML-DSA (FIPS 204).
///
/// `private_der` may be either a full PKCS#8 DER document (RustCrypto format)
/// or just the 32-byte seed (OpenSSL format, extracted by the loader).
#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    // `getrandom::SysRng` is a zero-sized, stateless, fork-safe wrapper over
    // the OS entropy syscall. `sign_randomized` takes `TryCryptoRng`, so an
    // RNG failure is reported by `ml_dsa` and then wrapped by the
    // `.map_err(|e| Error::Crypto(...))` call below as `Error::Crypto`
    // (with the underlying `ml_dsa::Error` in the message) rather than
    // panicking. See docs/adr/0001-rng-choice.md.
    let sk = load_ml_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .sign_randomized(data, context, &mut getrandom::SysRng)
        .map_err(|e| Error::Crypto(format!("ML-DSA sign failed: {e}")))?;
    Ok(sig.encode().to_vec())
}

#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_verify_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::MlDsaVariant,
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool> {
    use crate::algorithm::MlDsaVariant;
    let SoftwareKey::PostQuantum { public_der, .. } = key else {
        return Err(Error::Key(format!(
            "{} key required for verification",
            variant.name()
        )));
    };
    match variant {
        MlDsaVariant::MlDsa44 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa44>(public_der, data, sig_bytes, context)
        }
        MlDsaVariant::MlDsa65 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa65>(public_der, data, sig_bytes, context)
        }
        MlDsaVariant::MlDsa87 => {
            pq_ml_dsa_verify::<ml_dsa::MlDsa87>(public_der, data, sig_bytes, context)
        }
    }
}

/// Verify with ML-DSA (FIPS 204).
#[cfg(feature = "post-quantum")]
fn pq_ml_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    use pkcs8_pq::spki::DecodePublicKey;
    let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse ML-DSA public key: {e}")))?;
    let encoded_sig = ml_dsa::EncodedSignature::<P>::try_from(sig_bytes)
        .map_err(|_| Error::Crypto("invalid ML-DSA signature length".into()))?;
    let sig = ml_dsa::Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::Crypto("failed to decode ML-DSA signature".into()))?;
    Ok(vk.verify_with_context(data, context, &sig))
}

/// Generate a fresh ML-DSA (FIPS 204) key pair.
///
/// Returns an opaque [`crate::SoftwareKey`] carrying:
/// - `algorithm`: `PqAlgorithm::MlDsa(variant)`.
/// - `private_der`: the 32-byte FIPS 204 seed (the durable secret).
///   `ExpandedSigningKey` is derived on demand by the sign path.
/// - `public_der`: the SPKI DER encoding of the verifying key.
///
/// Entropy is drawn directly from the OS via [`getrandom::fill`],
/// matching the signing path's [`getrandom::SysRng`] usage so the crate
/// has a single RNG policy for post-quantum operations. See
/// `docs/adr/0001-rng-choice.md`.
///
/// Zeroization: the stack-resident 32-byte seed buffer is wiped
/// immediately after it is copied into `private_der`. The heap-resident
/// private material is either moved into the returned [`crate::SoftwareKey`]
/// (whose custom [`Drop`] plus `ZeroizeOnDrop` marker wipe the seed on
/// drop) or, on any error return below, wiped explicitly before the
/// error propagates — so the seed does not linger in any allocation on
/// either exit path.
#[cfg(feature = "post-quantum")]
pub fn generate_ml_dsa(variant: crate::algorithm::MlDsaVariant) -> Result<OpaqueSoftwareKey> {
    use crate::algorithm::{MlDsaVariant, PqAlgorithm};
    use pkcs8_pq::spki::EncodePublicKey;
    use zeroize::Zeroize;

    let mut seed_bytes = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed_bytes) {
        seed_bytes.zeroize();
        return Err(Error::Crypto(format!("OS entropy draw failed: {e}")));
    }

    // Copy the seed into a heap-owned Vec now so every subsequent error
    // path wipes a single, well-defined allocation. The stack copy is
    // wiped immediately; from this point on, the only live copy of the
    // seed lives in `private_der` until it is either moved into the
    // `SoftwareKey` or explicitly zeroized on an error path.
    let mut private_der = seed_bytes.to_vec();
    seed_bytes.zeroize();

    fn encode_public<P>(seed: &ml_dsa::Seed) -> Result<Vec<u8>>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
    {
        let sk = ml_dsa::ExpandedSigningKey::<P>::from_seed(seed);
        let vk = sk.verifying_key();
        let der = vk
            .to_public_key_der()
            .map_err(|e| Error::Crypto(format!("ML-DSA SPKI encode: {e}")))?;
        Ok(der.as_bytes().to_vec())
    }

    let build = || -> Result<Vec<u8>> {
        let seed = ml_dsa::Seed::try_from(private_der.as_slice())
            .map_err(|e| Error::Crypto(format!("ML-DSA seed construction failed: {e}")))?;
        match variant {
            MlDsaVariant::MlDsa44 => encode_public::<ml_dsa::MlDsa44>(&seed),
            MlDsaVariant::MlDsa65 => encode_public::<ml_dsa::MlDsa65>(&seed),
            MlDsaVariant::MlDsa87 => encode_public::<ml_dsa::MlDsa87>(&seed),
        }
    };
    let public_der = match build() {
        Ok(der) => der,
        Err(e) => {
            private_der.zeroize();
            return Err(e);
        }
    };

    Ok(SoftwareKey::PostQuantum {
        algorithm: PqAlgorithm::MlDsa(variant),
        private_der: Some(private_der),
        public_der,
    }
    .into())
}

// ── Post-quantum: SLH-DSA (FIPS 205) ───────────────────────────────

#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_sign_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::SlhDsaVariant,
    data: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use crate::algorithm::SlhDsaVariant;
    let SoftwareKey::PostQuantum {
        private_der: Some(private),
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} private key required for signing",
            variant.name()
        )));
    };
    match variant {
        SlhDsaVariant::Sha2_128f => pq_slh_dsa_sign::<slh_dsa::Sha2_128f>(private, data, context),
        SlhDsaVariant::Sha2_128s => pq_slh_dsa_sign::<slh_dsa::Sha2_128s>(private, data, context),
        SlhDsaVariant::Sha2_192f => pq_slh_dsa_sign::<slh_dsa::Sha2_192f>(private, data, context),
        SlhDsaVariant::Sha2_192s => pq_slh_dsa_sign::<slh_dsa::Sha2_192s>(private, data, context),
        SlhDsaVariant::Sha2_256f => pq_slh_dsa_sign::<slh_dsa::Sha2_256f>(private, data, context),
        SlhDsaVariant::Sha2_256s => pq_slh_dsa_sign::<slh_dsa::Sha2_256s>(private, data, context),
    }
}

/// Sign with SLH-DSA (FIPS 205).
///
/// `private_der` may be either a full PKCS#8 DER document (RustCrypto format)
/// or just the raw key bytes (OpenSSL format, extracted by the loader).
#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_sign<P>(private_der: &[u8], data: &[u8], context: &[u8]) -> Result<Vec<u8>>
where
    P: slh_dsa::ParameterSet,
{
    let sk = load_slh_dsa_signing_key::<P>(private_der)?;
    let sig = sk
        .try_sign_with_context(data, context, None)
        .map_err(|e| Error::Crypto(format!("SLH-DSA sign failed: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_verify_dispatch(
    key: &SoftwareKey,
    variant: crate::algorithm::SlhDsaVariant,
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool> {
    use crate::algorithm::SlhDsaVariant;
    let SoftwareKey::PostQuantum { public_der, .. } = key else {
        return Err(Error::Key(format!(
            "{} key required for verification",
            variant.name()
        )));
    };
    match variant {
        SlhDsaVariant::Sha2_128f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_128f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_128s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_128s>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_192f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_192f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_192s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_192s>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_256f => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_256f>(public_der, data, sig_bytes, context)
        }
        SlhDsaVariant::Sha2_256s => {
            pq_slh_dsa_verify::<slh_dsa::Sha2_256s>(public_der, data, sig_bytes, context)
        }
    }
}

/// Verify with SLH-DSA (FIPS 205).
#[cfg(feature = "post-quantum")]
fn pq_slh_dsa_verify<P>(
    public_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    context: &[u8],
) -> Result<bool>
where
    P: slh_dsa::ParameterSet,
{
    use pkcs8_pq::spki::DecodePublicKey;
    let vk = slh_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA public key: {e}")))?;
    let sig = slh_dsa::Signature::<P>::try_from(sig_bytes)
        .map_err(|e| Error::Crypto(format!("invalid SLH-DSA signature: {e}")))?;
    Ok(vk.try_verify_with_context(data, context, &sig).is_ok())
}

// ── PQ key loaders ──────────────────────────────────────────────────

/// Validate ML-DSA / SLH-DSA key encodings during import: the SPKI must
/// parse, and when a private key is present the public key derived from it
/// must equal the imported one.
#[cfg(feature = "post-quantum")]
pub(crate) fn validate_pq_import(
    algorithm: crate::algorithm::PqAlgorithm,
    private_der: Option<&[u8]>,
    public_der: &[u8],
) -> Result<()> {
    use crate::algorithm::{MlDsaVariant, PqAlgorithm, SlhDsaVariant};
    use pkcs8_pq::spki::DecodePublicKey;

    fn ml_dsa<P>(private_der: Option<&[u8]>, public_der: &[u8]) -> Result<bool>
    where
        P: ml_dsa::MlDsaParams,
        P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
    {
        let vk = ml_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
            .map_err(|e| Error::Key(format!("failed to parse ML-DSA public key: {e}")))?;
        let Some(private_der) = private_der else {
            return Ok(true);
        };
        let sk = load_ml_dsa_signing_key::<P>(private_der)?;
        Ok(sk.verifying_key().encode() == vk.encode())
    }

    fn slh_dsa<P: slh_dsa::ParameterSet>(
        private_der: Option<&[u8]>,
        public_der: &[u8],
    ) -> Result<bool> {
        let vk = slh_dsa::VerifyingKey::<P>::from_public_key_der(public_der)
            .map_err(|e| Error::Key(format!("failed to parse SLH-DSA public key: {e}")))?;
        let Some(private_der) = private_der else {
            return Ok(true);
        };
        // An SLH-DSA private key embeds its public key, so recompute the
        // root from the secret seeds (FIPS 205 slh_keygen_internal) rather
        // than trusting the embedded copy.
        let sk = load_slh_dsa_signing_key::<P>(private_der)?;
        let bytes = zeroize::Zeroizing::new(sk.to_bytes());
        let n = bytes.len() / 4; // SK.seed || SK.prf || PK.seed || PK.root
        let derived = slh_dsa::SigningKey::<P>::slh_keygen_internal(
            &bytes[..n],
            &bytes[n..2 * n],
            &bytes[2 * n..3 * n],
        );
        Ok(derived.as_ref() == &vk && sk.as_ref() == &vk)
    }

    let matches = match algorithm {
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44) => {
            ml_dsa::<ml_dsa::MlDsa44>(private_der, public_der)
        }
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa65) => {
            ml_dsa::<ml_dsa::MlDsa65>(private_der, public_der)
        }
        PqAlgorithm::MlDsa(MlDsaVariant::MlDsa87) => {
            ml_dsa::<ml_dsa::MlDsa87>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f) => {
            slh_dsa::<slh_dsa::Sha2_128f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128s) => {
            slh_dsa::<slh_dsa::Sha2_128s>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_192f) => {
            slh_dsa::<slh_dsa::Sha2_192f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_192s) => {
            slh_dsa::<slh_dsa::Sha2_192s>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_256f) => {
            slh_dsa::<slh_dsa::Sha2_256f>(private_der, public_der)
        }
        PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_256s) => {
            slh_dsa::<slh_dsa::Sha2_256s>(private_der, public_der)
        }
        PqAlgorithm::MlKem(_) => {
            return Err(Error::Key(format!(
                "{} is not a signature algorithm",
                algorithm.name()
            )))
        }
    }?;
    if !matches {
        return Err(Error::Key(format!(
            "{} public key does not match the private key",
            algorithm.name()
        )));
    }
    Ok(())
}

/// Load an ML-DSA signing key from either PKCS#8 DER or a 32-byte seed.
#[cfg(feature = "post-quantum")]
fn load_ml_dsa_signing_key<P>(private_der: &[u8]) -> Result<ml_dsa::ExpandedSigningKey<P>>
where
    P: ml_dsa::MlDsaParams,
    P: pkcs8_pq::spki::AssociatedAlgorithmIdentifier<Params = pkcs8_pq::der::AnyRef<'static>>,
{
    // Try full PKCS#8 DER first (RustCrypto format)
    use pkcs8_pq::DecodePrivateKey;
    if let Ok(sk) = ml_dsa::ExpandedSigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    // Fall back to 32-byte seed (from OpenSSL format, extracted by loader)
    if private_der.len() == 32 {
        let seed = ml_dsa::Seed::try_from(private_der)
            .map_err(|_| Error::Key("invalid ML-DSA seed length".into()))?;
        return Ok(ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed));
    }
    Err(Error::Key(format!(
        "failed to parse ML-DSA private key: expected PKCS#8 DER or 32-byte seed, got {} bytes",
        private_der.len()
    )))
}

/// Load an SLH-DSA signing key from either PKCS#8 DER or raw key bytes.
#[cfg(feature = "post-quantum")]
fn load_slh_dsa_signing_key<P>(private_der: &[u8]) -> Result<slh_dsa::SigningKey<P>>
where
    P: slh_dsa::ParameterSet,
{
    use pkcs8_pq::DecodePrivateKey;
    if let Ok(sk) = slh_dsa::SigningKey::<P>::from_pkcs8_der(private_der) {
        return Ok(sk);
    }
    slh_dsa::SigningKey::<P>::try_from(private_der)
        .map_err(|e| Error::Key(format!("failed to parse SLH-DSA private key: {e}")))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Signer, Verifier};

    /// Every exposed SLH-DSA key type must retain the dependency's wiping destructor.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn slh_dsa_signing_keys_zeroize_on_drop() {
        fn requires_wiping_drop<T: zeroize::ZeroizeOnDrop>() {
            assert!(std::mem::needs_drop::<T>());
        }
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_128f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_128s>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_192f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_192s>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_256f>>();
        requires_wiping_drop::<slh_dsa::SigningKey<slh_dsa::Sha2_256s>>();
    }

    /// Wiping typed keys preserves signing through both raw and PKCS#8 import paths.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn slh_dsa_raw_and_pkcs8_signatures_roundtrip() {
        use crate::algorithm::{PqAlgorithm, SlhDsaVariant};
        use pkcs8_pq::{spki::EncodePublicKey, EncodePrivateKey};
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128f>::slh_keygen_internal(
            &[1; 16], &[2; 16], &[3; 16],
        );
        let vk: &slh_dsa::VerifyingKey<_> = sk.as_ref();
        let public = vk.to_public_key_der().unwrap();
        let raw = zeroize::Zeroizing::new(sk.to_bytes());
        let pkcs8 = sk.to_pkcs8_der().unwrap();
        let algorithm = SignatureAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f);
        for private in [raw.as_slice(), pkcs8.as_bytes()] {
            let key = OpaqueSoftwareKey::from_post_quantum_der(
                PqAlgorithm::SlhDsa(SlhDsaVariant::Sha2_128f),
                Some(private),
                public.as_bytes(),
            )
            .unwrap();
            let signer = SoftwareSigner::new(algorithm, key.clone()).unwrap();
            let verifier = SoftwareVerifier::new(algorithm, key).unwrap();
            let signature = signer.sign(b"SLH-DSA zeroizing key control").unwrap();
            assert!(verifier
                .verify(b"SLH-DSA zeroizing key control", &signature)
                .unwrap());
            assert!(!verifier.verify(b"different message", &signature).unwrap());
        }
    }

    #[test]
    fn ed25519_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let sign_key = SoftwareKey::Ed25519 {
            private: Some(sk.clone()),
            public: vk,
        };
        let signer =
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, sign_key).expect("signer creation");
        let data = b"The quick brown fox jumps over the lazy dog";
        let signature = signer.sign(data).expect("signing should succeed");

        // Verify with public-only key
        let verify_key = SoftwareKey::Ed25519 {
            private: None,
            public: vk,
        };
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verify_key)
            .expect("verifier creation");
        assert!(
            verifier.verify(data, &signature).unwrap(),
            "Ed25519 roundtrip should verify"
        );

        // Tampered data should fail
        assert!(
            !verifier.verify(b"tampered data", &signature).unwrap(),
            "Ed25519 verification of tampered data should return false"
        );
    }

    /// Malleability regression: strict verification must reject a signature
    /// whose low-order part has been mangled. The well-known low-order `R`
    /// encoding `\x00...\x00` (identity element) is invalid under
    /// [RFC 8032 §5.1.7] rules that `verify_strict` enforces.
    ///
    /// Pre-fix (plain `verify`), some constructions of low-order-R
    /// signatures could verify against any message, enabling signature
    /// malleability / "bug attacks" on consensus-critical callers.
    #[test]
    fn ed25519_rejects_low_order_r() {
        use ed25519_dalek::Verifier as _;

        // Small-order public key A and small-order R, both the identity
        // point (compressed y = 1), with s = 0. Cofactorless `verify`
        // recomputes R' = [s]B - [k]A = identity for every message and so
        // accepts this signature; `verify_strict` rejects the weak A / R.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&identity).expect("identity decodes");
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&identity);
        let message = b"any message at all";

        // Pin the premise: the permissive check really does accept it.
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(
            vk.verify(message, &sig).is_ok(),
            "plain verify should accept"
        );

        let verify_key = SoftwareKey::Ed25519 {
            private: None,
            public: vk,
        };
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ed25519, verify_key)
            .expect("verifier creation");
        let result = verifier.verify(message, &sig_bytes).unwrap();
        assert!(!result, "low-order R signature must not verify");
    }

    fn rsa_key(bits: usize) -> SoftwareKey {
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).unwrap();
        let public = private.to_public_key();
        SoftwareKey::Rsa {
            private: Some(private),
            public,
        }
    }

    #[cfg(not(feature = "legacy"))]
    #[test]
    fn rsa_keys_below_2048_bits_are_rejected() {
        let algorithm = SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256);
        let err = match SoftwareSigner::new(algorithm, rsa_key(1024)) {
            Ok(_) => panic!("1024-bit RSA signer should be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { operation: Operation::Sign(_), ref algorithm, .. }
                if algorithm.contains("1024-bit RSA key")),
            "got {err:?}"
        );
        let err = match SoftwareVerifier::new(algorithm, rsa_key(1024)) {
            Ok(_) => panic!("1024-bit RSA verifier should be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                Error::UnsupportedAlgorithm {
                    operation: Operation::Verify(_),
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// Distinguish impossible PSS encodings from exact zero-salt capacity.
    #[test]
    fn rsa_pss_capacity_includes_hash_and_trailer() {
        for (bits, expected) in [(512, None), (520, None), (528, Some(0)), (536, Some(1))] {
            let key = rsa_key(bits);
            assert_eq!(
                rsa_pss_max_salt_len(extract_rsa_public(&key).unwrap(), HashAlgorithm::Sha512),
                expected,
            );
        }
    }

    /// Legacy mode still rejects impossible encodings before creating a verifier.
    #[cfg(feature = "legacy")]
    #[test]
    fn rsa_pss_legacy_rejects_hash_larger_than_encoding() {
        let key = OpaqueSoftwareKey::from(rsa_key(512));
        for salt in [0, 1, usize::MAX] {
            let result =
                SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, salt, key.clone());
            assert!(
                matches!(result, Err(Error::Key(ref message)) if message.contains("too small"))
            );
        }
        // SHA-256 does fit this key, including an explicitly empty salt.
        assert!(SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 0, key).is_ok());
        let exact = OpaqueSoftwareKey::from(rsa_key(528));
        assert!(
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, 0, exact.clone())
                .is_ok()
        );
        assert!(SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha512, 1, exact).is_err());
    }

    #[test]
    fn rsa_pss_salt_len_is_bounded() {
        // 2048-bit modulus: emLen = 256, so SHA-256 allows 256 - 32 - 2 = 222.
        let key = OpaqueSoftwareKey::from(rsa_key(2048));
        let signer = SoftwareSigner::new(
            SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256),
            key.clone(),
        )
        .unwrap();
        let signature = signer.sign(b"data").unwrap();

        let verifier =
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 222, key.clone())
                .expect("maximum salt length accepted");
        assert!(!verifier.verify(b"data", &signature).unwrap());
        // The default signer uses a hash-length salt.
        let verifier =
            SoftwareVerifier::new_rsa_pss_with_salt(HashAlgorithm::Sha256, 32, key.clone())
                .unwrap();
        assert!(verifier.verify(b"data", &signature).unwrap());

        for salt_len in [223, usize::MAX] {
            let err = match SoftwareVerifier::new_rsa_pss_with_salt(
                HashAlgorithm::Sha256,
                salt_len,
                key.clone(),
            ) {
                Ok(_) => panic!("salt length {salt_len} should be rejected"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("salt length"), "{err}");
        }
    }

    #[test]
    fn hmac_sha256_roundtrip() {
        let secret = b"super-secret-key-for-hmac-testing";
        let algo = SignatureAlgorithm::Hmac(HashAlgorithm::Sha256);

        let sign_key = SoftwareKey::Hmac(secret.to_vec());
        let signer = SoftwareSigner::new(algo, sign_key).expect("signer creation");
        let data = b"message to authenticate";
        let mac = signer.sign(data).expect("HMAC should succeed");
        assert_eq!(mac.len(), 32, "SHA-256 HMAC output should be 32 bytes");

        let verify_key = SoftwareKey::Hmac(secret.to_vec());
        let verifier = SoftwareVerifier::new(algo, verify_key).expect("verifier creation");
        assert!(
            verifier.verify(data, &mac).unwrap(),
            "HMAC roundtrip should verify"
        );

        // Wrong key should fail
        let wrong_key = SoftwareKey::Hmac(b"wrong-key".to_vec());
        let wrong_verifier = SoftwareVerifier::new(algo, wrong_key).expect("verifier creation");
        assert!(
            !wrong_verifier.verify(data, &mac).unwrap(),
            "HMAC with wrong key should fail"
        );
    }

    #[test]
    fn hmac_rejects_empty_key() {
        let err = match SoftwareSigner::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            SoftwareKey::Hmac(Vec::new()),
        ) {
            Ok(_) => panic!("empty HMAC key should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("must not be empty"), "{err}");

        let err = match SoftwareVerifier::new(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            SoftwareKey::Hmac(Vec::new()),
        ) {
            Ok(_) => panic!("empty HMAC key should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn new_with_pq_context_rejects_non_pq_algorithm() {
        let key = SoftwareKey::Hmac(b"shhh".to_vec());
        let err = match SoftwareSigner::new_with_pq_context(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
            key,
            b"protocol-v1",
        ) {
            Ok(_) => panic!("non-PQ algorithm with context should be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("does not accept a context"),
            "{err}"
        );
    }

    #[test]
    fn key_algorithm_mismatch_rejected() {
        let key = SoftwareKey::Hmac(b"key".to_vec());
        let result = SoftwareSigner::new(SignatureAlgorithm::Ed25519, key);
        assert!(
            result.is_err(),
            "HMAC key with Ed25519 algorithm should fail"
        );

        let key = SoftwareKey::Ed25519 {
            private: None,
            public: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(),
        };
        let result = SoftwareSigner::new(SignatureAlgorithm::Ed25519, key);
        assert!(
            result.is_err(),
            "Ed25519 public-only key should fail for signing"
        );
    }

    /// Randomization regression: ML-DSA signing moved from
    /// `sign_deterministic` to `sign_randomized` (see
    /// `docs/adr/0001-rng-choice.md`). Two signatures over the same
    /// message with the same key must therefore differ, and both must
    /// still verify — this test locks in both properties so that a
    /// future refactor cannot silently revert to the deterministic
    /// path.
    ///
    /// ML-DSA-44 is used because it's the smallest parameter set;
    /// this test runs in well under a second.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn ml_dsa_44_sign_is_randomized_and_verifies() {
        use crate::algorithm::{MlDsaVariant, PqAlgorithm};
        use pkcs8_pq::spki::EncodePublicKey;

        // Fixed seed — this is a test; determinism in key material is
        // fine because the property we're asserting is randomness in
        // the *signature*, not in the key.
        let seed_bytes = [0x42u8; 32];
        let seed = ml_dsa::Seed::try_from(&seed_bytes[..]).expect("32 bytes");
        let expanded_sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
        let public_der = expanded_sk
            .verifying_key()
            .to_public_key_der()
            .expect("public key DER encoding")
            .to_vec();

        let sign_key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44),
            private_der: Some(seed_bytes.to_vec()),
            public_der: public_der.clone(),
        };
        let signer =
            SoftwareSigner::new(SignatureAlgorithm::MlDsa(MlDsaVariant::MlDsa44), sign_key)
                .expect("signer creation");

        let data = b"FIPS 204 randomized signing property test";
        let sig1 = signer.sign(data).expect("first sign");
        let sig2 = signer.sign(data).expect("second sign");

        assert_ne!(
            sig1, sig2,
            "ML-DSA sign_randomized must produce different signatures \
             for the same message — if this fires, someone reverted \
             pq_ml_dsa_sign to sign_deterministic"
        );

        let verify_key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlDsa(MlDsaVariant::MlDsa44),
            private_der: None,
            public_der,
        };
        let verifier =
            SoftwareVerifier::new(SignatureAlgorithm::MlDsa(MlDsaVariant::MlDsa44), verify_key)
                .expect("verifier creation");

        assert!(
            verifier.verify(data, &sig1).expect("verify call"),
            "first signature must verify"
        );
        assert!(
            verifier.verify(data, &sig2).expect("verify call"),
            "second signature must verify"
        );
    }

    /// `generate_ml_dsa` round-trip: the returned key must sign and
    /// verify against itself, at every security level. This also
    /// covers the `public_der` SPKI encoding path (which feeds the
    /// verifier) and the seed-based signer loader (which feeds the
    /// signer).
    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_ml_dsa_round_trips_all_variants() {
        use crate::algorithm::MlDsaVariant;
        for variant in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let key = generate_ml_dsa(variant).expect("generate_ml_dsa");
            let SoftwareKey::PostQuantum {
                private_der,
                public_der,
                ..
            } = key.inner()
            else {
                panic!("generate_ml_dsa returned non-PQ SoftwareKey");
            };
            assert_eq!(
                private_der.as_ref().map(Vec::len),
                Some(32),
                "{} private must be a 32-byte seed",
                variant.name()
            );
            assert!(
                !public_der.is_empty(),
                "{} public_der must be populated",
                variant.name()
            );

            // ML-DSA-87 blows the default 2 MiB debug-build thread
            // stack during ExpandedSigningKey derivation + sign; the
            // other two variants fit. Spawn ML-DSA-87 on an 8 MiB
            // thread to match the jose-rs test harness convention.
            let data = b"generate_ml_dsa round-trip";
            let signer = SoftwareSigner::new(
                SignatureAlgorithm::MlDsa(variant),
                clone_pq_key(key.inner()),
            )
            .expect("signer");
            let verifier = SoftwareVerifier::new(
                SignatureAlgorithm::MlDsa(variant),
                clone_pq_key(key.inner()),
            )
            .expect("verifier");

            let run = move || {
                let sig = signer.sign(data).expect("sign");
                assert!(verifier.verify(data, &sig).expect("verify call"));
            };
            if matches!(variant, MlDsaVariant::MlDsa87) {
                std::thread::Builder::new()
                    .stack_size(8 * 1024 * 1024)
                    .spawn(run)
                    .expect("spawn")
                    .join()
                    .expect("join");
            } else {
                run();
            }
        }
    }

    #[cfg(feature = "post-quantum")]
    fn clone_pq_key(key: &SoftwareKey) -> SoftwareKey {
        let SoftwareKey::PostQuantum {
            algorithm,
            private_der,
            public_der,
        } = key
        else {
            panic!("expected PostQuantum");
        };
        SoftwareKey::PostQuantum {
            algorithm: *algorithm,
            private_der: private_der.clone(),
            public_der: public_der.clone(),
        }
    }

    /// Two successive `generate_ml_dsa` calls must produce different
    /// seeds. Smoke-tests that the RNG isn't returning constant bytes.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn generate_ml_dsa_seeds_are_unique() {
        use crate::algorithm::MlDsaVariant;
        let a = generate_ml_dsa(MlDsaVariant::MlDsa44).unwrap();
        let b = generate_ml_dsa(MlDsaVariant::MlDsa44).unwrap();
        let (
            SoftwareKey::PostQuantum {
                private_der: pa, ..
            },
            SoftwareKey::PostQuantum {
                private_der: pb, ..
            },
        ) = (a.inner(), b.inner())
        else {
            panic!("unexpected variant");
        };
        assert_ne!(pa, pb, "two generate_ml_dsa calls must differ");
    }
}
