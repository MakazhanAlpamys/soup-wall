//! Provider-neutral alternate-provider operation objects.

use crate::algorithm::EcCurve;
use crate::algorithm::{HashAlgorithm, SignatureAlgorithm};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crate::key::SoftwareKey;
use crate::traits;

pub struct SoftwareSigner {
    algorithm: SignatureAlgorithm,
    key: SoftwareKey,
}

impl SoftwareSigner {
    pub fn new(algorithm: SignatureAlgorithm, key: SoftwareKey) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    pub fn new_with_pq_context(
        algorithm: SignatureAlgorithm,
        key: SoftwareKey,
        context: &[u8],
    ) -> Result<Self> {
        if !context.is_empty() {
            return Err(Error::unsupported(Operation::Sign(algorithm), "PQ context"));
        }
        require_supported(Operation::Sign(algorithm))?;
        validate_signing_key(algorithm, &key)?;
        if matches!(
            algorithm,
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_)
        ) {
            enforce_rsa_key_size(Operation::Sign(algorithm), &key)?;
        }
        Ok(Self { algorithm, key })
    }
}

impl traits::Signer for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            SignatureAlgorithm::Hmac(hash) => crate::digest::compute_hmac(
                hash,
                self.key
                    .private_der()
                    .ok_or_else(|| Error::Key("HMAC key material is missing".into()))?,
                data,
            ),
            algorithm => {
                let private = self
                    .key
                    .private_der()
                    .ok_or_else(|| Error::Key("private key material is missing".into()))?;
                aws_lc_sign(algorithm, private, data)
            }
        }
    }
}

fn aws_lc_sign(algorithm: SignatureAlgorithm, private_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair};

    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(hash) | SignatureAlgorithm::RsaPss(hash) => {
            let encoding: &'static dyn signature::RsaEncoding = match algorithm {
                SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256) => {
                    &signature::RSA_PKCS1_SHA256
                }
                SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha384) => {
                    &signature::RSA_PKCS1_SHA384
                }
                SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha512) => {
                    &signature::RSA_PKCS1_SHA512
                }
                SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256) => &signature::RSA_PSS_SHA256,
                SignatureAlgorithm::RsaPss(HashAlgorithm::Sha384) => &signature::RSA_PSS_SHA384,
                SignatureAlgorithm::RsaPss(HashAlgorithm::Sha512) => &signature::RSA_PSS_SHA512,
                _ => {
                    return Err(Error::unsupported(
                        Operation::Sign(algorithm),
                        format!("AWS-LC RSA signing with {hash:?}"),
                    ))
                }
            };
            let key = RsaKeyPair::from_pkcs8(private_der)
                .map_err(|e| Error::Key(format!("AWS-LC RSA private import failed: {e}")))?;
            let mut signature = vec![0u8; key.public_modulus_len()];
            key.sign(encoding, &SystemRandom::new(), data, &mut signature)
                .map_err(|_| Error::Crypto("AWS-LC RSA signing failed".into()))?;
            Ok(signature)
        }
        SignatureAlgorithm::Ecdsa(curve, hash) => {
            let signing_algorithm = match (curve, hash) {
                (EcCurve::P256, HashAlgorithm::Sha256) => {
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING
                }
                (EcCurve::P384, HashAlgorithm::Sha384) => {
                    &signature::ECDSA_P384_SHA384_FIXED_SIGNING
                }
                (EcCurve::P521, HashAlgorithm::Sha224) => {
                    &signature::ECDSA_P521_SHA224_FIXED_SIGNING
                }
                (EcCurve::P521, HashAlgorithm::Sha256) => {
                    &signature::ECDSA_P521_SHA256_FIXED_SIGNING
                }
                (EcCurve::P521, HashAlgorithm::Sha384) => {
                    &signature::ECDSA_P521_SHA384_FIXED_SIGNING
                }
                (EcCurve::P521, HashAlgorithm::Sha512) => {
                    &signature::ECDSA_P521_SHA512_FIXED_SIGNING
                }
                _ => {
                    return Err(Error::unsupported(
                        Operation::Sign(algorithm),
                        format!("AWS-LC ECDSA {curve:?}/{hash:?}"),
                    ))
                }
            };
            let key = EcdsaKeyPair::from_private_key_der(signing_algorithm, private_der)
                .map_err(|e| Error::Key(format!("AWS-LC EC private import failed: {e}")))?;
            key.sign(&SystemRandom::new(), data)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| Error::Crypto("AWS-LC ECDSA signing failed".into()))
        }
        SignatureAlgorithm::Ed25519 => {
            let key = Ed25519KeyPair::from_pkcs8(private_der)
                .map_err(|e| Error::Key(format!("AWS-LC Ed25519 private import failed: {e}")))?;
            Ok(key.sign(data).as_ref().to_vec())
        }
        _ => Err(Error::unsupported(
            Operation::Sign(algorithm),
            format!("{algorithm:?}"),
        )),
    }
}

/// Reject RSA keys below 2048 bits when they are used, with the same error
/// verification reports. The RustCrypto provider accepts shorter keys only
/// with the `legacy` feature; AWS-LC never does.
fn enforce_rsa_key_size(operation: Operation, key: &SoftwareKey) -> Result<()> {
    let bits = key
        .public_der()
        .and_then(crate::key::rsa_spki_modulus_bits)
        .ok_or_else(|| Error::Key("RSA key is not a valid SubjectPublicKeyInfo".into()))?;
    if bits < 2048 {
        return Err(Error::unsupported(
            operation,
            format!("{bits}-bit RSA key (kryptering requires at least 2048 bits)"),
        ));
    }
    Ok(())
}

fn validate_signing_key(algorithm: SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    #[allow(unreachable_patterns)]
    let valid = match algorithm {
        SignatureAlgorithm::Hmac(_) => key.algorithm() == crate::backend::KeyAlgorithm::Hmac,
        SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Rsa && key.has_private_key()
        }
        SignatureAlgorithm::Ecdsa(curve, _) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Ec(curve) && key.has_private_key()
        }
        SignatureAlgorithm::Ed25519 => {
            key.algorithm() == crate::backend::KeyAlgorithm::Ed25519 && key.has_private_key()
        }
        #[cfg(feature = "legacy")]
        SignatureAlgorithm::Dsa(_) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Dsa && key.has_private_key()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Key(format!(
            "key {:?} is not suitable for {:?}",
            key.algorithm(),
            algorithm
        )))
    }
}

/// Validate that a key is suitable for verifying with the given algorithm.
///
/// Unlike [`validate_signing_key`], a public-only key is accepted for
/// asymmetric algorithms — verification does not require the private half.
/// HMAC still requires the secret material to be present.
fn validate_verifying_key(algorithm: SignatureAlgorithm, key: &SoftwareKey) -> Result<()> {
    #[allow(unreachable_patterns)]
    let valid = match algorithm {
        SignatureAlgorithm::Hmac(_) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Hmac && key.has_private_key()
        }
        SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Rsa
        }
        SignatureAlgorithm::Ecdsa(curve, _) => {
            key.algorithm() == crate::backend::KeyAlgorithm::Ec(curve)
        }
        SignatureAlgorithm::Ed25519 => key.algorithm() == crate::backend::KeyAlgorithm::Ed25519,
        #[cfg(feature = "legacy")]
        SignatureAlgorithm::Dsa(_) => key.algorithm() == crate::backend::KeyAlgorithm::Dsa,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Key(format!(
            "key {:?} is not suitable for {:?}",
            key.algorithm(),
            algorithm
        )))
    }
}

pub struct SoftwareVerifier {
    algorithm: SignatureAlgorithm,
    key: SoftwareKey,
    rsa_pss_salt_len: Option<usize>,
}

impl SoftwareVerifier {
    pub fn new(algorithm: SignatureAlgorithm, key: SoftwareKey) -> Result<Self> {
        Self::new_with_pq_context(algorithm, key, &[])
    }

    pub fn new_with_pq_context(
        algorithm: SignatureAlgorithm,
        key: SoftwareKey,
        context: &[u8],
    ) -> Result<Self> {
        if !context.is_empty() {
            return Err(Error::unsupported(
                Operation::Verify(algorithm),
                "PQ context",
            ));
        }
        require_supported(Operation::Verify(algorithm))?;
        validate_verifying_key(algorithm, &key)?;
        Ok(Self {
            algorithm,
            key,
            rsa_pss_salt_len: None,
        })
    }

    /// Create an RSA-PSS verifier with the salt length declared by the protocol.
    pub fn new_rsa_pss_with_salt(
        hash: HashAlgorithm,
        salt_len: usize,
        key: SoftwareKey,
    ) -> Result<Self> {
        let algorithm = SignatureAlgorithm::RsaPss(hash);
        let digest_len = hash_output_len(hash)
            .ok_or_else(|| Error::unsupported(Operation::Verify(algorithm), format!("{hash:?}")))?;
        if salt_len != digest_len {
            return Err(Error::unsupported(
                Operation::Verify(algorithm),
                format!("RSA-PSS salt length {salt_len}"),
            ));
        }
        let mut verifier = Self::new(algorithm, key)?;
        verifier.rsa_pss_salt_len = Some(salt_len);
        Ok(verifier)
    }

    /// Verify a signature encoded in the ASN.1 form used by X.509/CMS.
    pub fn verify_der_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let signature = match self.algorithm {
            SignatureAlgorithm::Ecdsa(curve, _) => {
                crate::digest::ecdsa_der_to_raw(curve, signature)?
            }
            _ => signature.to_vec(),
        };
        traits::Verifier::verify(self, data, &signature)
    }
}

impl traits::Verifier for SoftwareVerifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        if let SignatureAlgorithm::Hmac(hash) = self.algorithm {
            let expected = crate::digest::compute_hmac(
                hash,
                self.key
                    .private_der()
                    .ok_or_else(|| Error::Key("HMAC key material is missing".into()))?,
                data,
            )?;
            if expected.len() != signature.len() {
                return Ok(false);
            }
            return Ok(expected
                .iter()
                .zip(signature)
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0);
        }
        let public = self
            .key
            .public_der()
            .ok_or_else(|| Error::Key("public SPKI is required for verification".into()))?;
        aws_lc_verify(
            self.algorithm,
            self.rsa_pss_salt_len,
            public,
            data,
            signature,
        )
    }
}

fn aws_lc_verify(
    algorithm: SignatureAlgorithm,
    salt_len: Option<usize>,
    spki_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{self, ParsedPublicKey, VerificationAlgorithm};

    if matches!(
        algorithm,
        SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_)
    ) {
        let modulus_bits = crate::key::rsa_spki_modulus_bits(spki_der).ok_or_else(|| {
            Error::Key("AWS-LC RSA key is not a valid RFC 5280 SubjectPublicKeyInfo".into())
        })?;
        // Match the import path's `RSA_PKCS1_2048_8192_SHA256` floor (2048
        // bits) so the two paths reject the same key sizes. AWS-LC's stable
        // SHA-1/SHA-512 verification parameters only come in a 1024+ legacy
        // form, so this manual check is what enforces the 2048-bit policy
        // for those hashes; without it, a 1024-bit key would pass AWS-LC's
        // own floor and report a bad signature as a generic verify failure.
        if modulus_bits < 2048 {
            return Err(Error::unsupported(
                Operation::Verify(algorithm),
                format!("{modulus_bits}-bit RSA key (kryptering requires at least 2048 bits)"),
            ));
        }
    }

    let verification_algorithm: &'static dyn VerificationAlgorithm = match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha1) => {
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
        }
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256) => {
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
        }
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha384) => {
            &signature::RSA_PKCS1_2048_8192_SHA384
        }
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha512) => {
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
        }
        SignatureAlgorithm::RsaPss(hash) => {
            let digest_len = hash_output_len(hash).ok_or_else(|| {
                Error::unsupported(Operation::Verify(algorithm), format!("{algorithm:?}"))
            })?;
            if salt_len.is_some_and(|declared| declared != digest_len) {
                return Err(Error::unsupported(
                    Operation::Verify(algorithm),
                    format!("RSA-PSS salt length {}", salt_len.unwrap()),
                ));
            }
            match hash {
                HashAlgorithm::Sha256 => &signature::RSA_PSS_2048_8192_SHA256,
                HashAlgorithm::Sha384 => &signature::RSA_PSS_2048_8192_SHA384,
                HashAlgorithm::Sha512 => &signature::RSA_PSS_2048_8192_SHA512,
                _ => {
                    return Err(Error::unsupported(
                        Operation::Verify(algorithm),
                        format!("{algorithm:?}"),
                    ))
                }
            }
        }
        SignatureAlgorithm::Ecdsa(curve, hash) => {
            let verification_algorithm: &'static dyn VerificationAlgorithm = match (curve, hash) {
                (EcCurve::P256, HashAlgorithm::Sha256) => &signature::ECDSA_P256_SHA256_ASN1,
                (EcCurve::P256, HashAlgorithm::Sha384) => &signature::ECDSA_P256_SHA384_ASN1,
                (EcCurve::P256, HashAlgorithm::Sha512) => &signature::ECDSA_P256_SHA512_ASN1,
                (EcCurve::P384, HashAlgorithm::Sha256) => &signature::ECDSA_P384_SHA256_ASN1,
                (EcCurve::P384, HashAlgorithm::Sha384) => &signature::ECDSA_P384_SHA384_ASN1,
                (EcCurve::P384, HashAlgorithm::Sha512) => &signature::ECDSA_P384_SHA512_ASN1,
                (EcCurve::P521, HashAlgorithm::Sha224) => &signature::ECDSA_P521_SHA224_ASN1,
                (EcCurve::P521, HashAlgorithm::Sha256) => &signature::ECDSA_P521_SHA256_ASN1,
                (EcCurve::P521, HashAlgorithm::Sha384) => &signature::ECDSA_P521_SHA384_ASN1,
                (EcCurve::P521, HashAlgorithm::Sha512) => &signature::ECDSA_P521_SHA512_ASN1,
                _ => {
                    return Err(Error::unsupported(
                        Operation::Verify(algorithm),
                        format!("{algorithm:?}"),
                    ))
                }
            };
            // Accept the same encodings as the RustCrypto provider: exact
            // fixed-width r||s, zero-padded or stripped r||s, and DER.
            // Everything is re-encoded as minimal DER before verification.
            let der = ecdsa_signature_to_der(curve, signature)?;
            let key = ParsedPublicKey::new(verification_algorithm, spki_der)
                .map_err(|e| Error::Key(format!("AWS-LC SPKI import failed: {e}")))?;
            return Ok(key.verify_sig(data, &der).is_ok());
        }
        SignatureAlgorithm::Ed25519 => &signature::ED25519,
        _ => {
            return Err(Error::unsupported(
                Operation::Verify(algorithm),
                format!("{algorithm:?}"),
            ))
        }
    };
    let key = ParsedPublicKey::new(verification_algorithm, spki_der)
        .map_err(|e| Error::Key(format!("AWS-LC SPKI import failed: {e}")))?;
    Ok(key.verify_sig(data, signature).is_ok())
}

/// Use the same encoding and scalar rules as every other provider.
fn ecdsa_signature_to_der(curve: EcCurve, signature: &[u8]) -> Result<Vec<u8>> {
    crate::digest::ecdsa_raw_to_der(curve, signature)
}

fn hash_output_len(hash: HashAlgorithm) -> Option<usize> {
    Some(match hash {
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha224 => 28,
        HashAlgorithm::Sha256 | HashAlgorithm::Sha3_256 => 32,
        HashAlgorithm::Sha384 | HashAlgorithm::Sha3_384 => 48,
        HashAlgorithm::Sha512 | HashAlgorithm::Sha3_512 => 64,
        HashAlgorithm::Sha3_224 => 28,
        #[cfg(feature = "legacy")]
        HashAlgorithm::Md5 => 16,
        #[cfg(feature = "legacy")]
        HashAlgorithm::Ripemd160 => 20,
    })
}

pub mod cipher {
    use crate::algorithm::{AesKeySize, CipherAlgorithm};
    use crate::backend::{random_bytes, require_supported, Operation};
    use crate::error::{Error, Result};

    pub fn encrypt(algorithm: CipherAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        require_supported(Operation::Encrypt(algorithm))?;
        match algorithm {
            CipherAlgorithm::AesCbc(_) => Err(Error::unsupported(
                Operation::Encrypt(algorithm),
                "AES-CBC moved to kryptering::hazmat::aes_cbc (unauthenticated; see module docs)",
            )),
            CipherAlgorithm::AesGcm(size) => gcm_encrypt(size, key, data),
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => triple_des_encrypt(key, data),
        }
    }

    pub fn decrypt(algorithm: CipherAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        require_supported(Operation::Decrypt(algorithm))?;
        match algorithm {
            CipherAlgorithm::AesCbc(_) => Err(Error::unsupported(
                Operation::Decrypt(algorithm),
                "AES-CBC moved to kryptering::hazmat::aes_cbc (unauthenticated; see module docs)",
            )),
            CipherAlgorithm::AesGcm(size) => gcm_decrypt(size, key, data),
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TripleDesCbc => triple_des_decrypt(key, data),
        }
    }

    #[cfg(feature = "legacy")]
    fn triple_des_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_triple_des_key(key)?;
        let _ = plaintext;
        Err(Error::unsupported(
            Operation::Encrypt(CipherAlgorithm::TripleDesCbc),
            "3DES-CBC AWS-LC provider",
        ))
    }

    #[cfg(feature = "legacy")]
    fn triple_des_decrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        validate_triple_des_key(key)?;
        let _ = input;
        Err(Error::unsupported(
            Operation::Decrypt(CipherAlgorithm::TripleDesCbc),
            "3DES-CBC AWS-LC provider",
        ))
    }

    #[cfg(feature = "legacy")]
    fn validate_triple_des_key(key: &[u8]) -> Result<()> {
        if key.len() != 24 {
            return Err(Error::Crypto(format!(
                "3DES key must be 24 bytes, got {}",
                key.len()
            )));
        }
        Ok(())
    }

    fn validate_key(size: AesKeySize, key: &[u8]) -> Result<()> {
        if key.len() != size.key_len() {
            return Err(Error::Crypto(format!(
                "AES key must be {} bytes, got {}",
                size.key_len(),
                key.len()
            )));
        }
        Ok(())
    }

    fn gcm_encrypt(size: AesKeySize, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_key(size, key)?;
        if !matches!(size, AesKeySize::Aes192) {
            return aws_gcm_encrypt_random_nonce(size, key, plaintext);
        }
        let nonce = random_bytes(12)?;
        let sealed = aws_gcm_encrypt(size, key, &nonce, plaintext)?;
        let mut output = Vec::with_capacity(12 + sealed.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&sealed);
        Ok(output)
    }

    /// Seal with a nonce generated inside the AWS-LC module, which is the
    /// FIPS-approved GCM IV construction. AWS-LC offers this for AES-128 and
    /// AES-256 only; AES-192 keeps the caller-generated nonce path above.
    fn aws_gcm_encrypt_random_nonce(
        size: AesKeySize,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        use aws_lc_rs::aead::{Aad, RandomizedNonceKey};
        let key = RandomizedNonceKey::new(aws_gcm_algorithm(size), key)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM setup failed".into()))?;
        let mut sealed = plaintext.to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::empty(), &mut sealed)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM encryption failed".into()))?;
        let mut output = Vec::with_capacity(12 + sealed.len());
        output.extend_from_slice(nonce.as_ref());
        output.extend_from_slice(&sealed);
        Ok(output)
    }

    fn gcm_decrypt(size: AesKeySize, key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        validate_key(size, key)?;
        if input.len() < 28 {
            return Err(Error::Crypto("AES-GCM input is too short".into()));
        }
        let (nonce, sealed) = input.split_at(12);
        aws_gcm_decrypt(size, key, nonce, sealed)
    }

    fn aws_gcm_algorithm(size: AesKeySize) -> &'static aws_lc_rs::aead::Algorithm {
        match size {
            AesKeySize::Aes128 => &aws_lc_rs::aead::AES_128_GCM,
            AesKeySize::Aes192 => &aws_lc_rs::aead::AES_192_GCM,
            AesKeySize::Aes256 => &aws_lc_rs::aead::AES_256_GCM,
        }
    }

    fn aws_gcm_encrypt(
        size: AesKeySize,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
        let key = LessSafeKey::new(
            UnboundKey::new(aws_gcm_algorithm(size), key)
                .map_err(|_| Error::Crypto("AWS-LC AES-GCM setup failed".into()))?,
        );
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM nonce failed".into()))?;
        let mut output = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut output)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM encryption failed".into()))?;
        Ok(output)
    }

    fn aws_gcm_decrypt(
        size: AesKeySize,
        key: &[u8],
        nonce: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
        let key = LessSafeKey::new(
            UnboundKey::new(aws_gcm_algorithm(size), key)
                .map_err(|_| Error::Crypto("AWS-LC AES-GCM setup failed".into()))?,
        );
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM nonce failed".into()))?;
        let mut output = sealed.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut output)
            .map_err(|_| Error::Crypto("AWS-LC AES-GCM authentication failed".into()))?;
        Ok(plaintext.to_vec())
    }
}

pub mod keywrap {
    use crate::algorithm::{AesKeySize, KeyWrapAlgorithm};
    use crate::backend::{require_supported, Operation};
    use crate::error::{Error, Result};

    pub fn wrap(algorithm: KeyWrapAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        require_supported(Operation::Wrap(algorithm))?;
        match algorithm {
            KeyWrapAlgorithm::AesKw(size) => aes_wrap(true, size, key, data),
            #[cfg(feature = "legacy")]
            KeyWrapAlgorithm::TripleDesKw => triple_des_wrap(key, data),
        }
    }

    pub fn unwrap(algorithm: KeyWrapAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        require_supported(Operation::Unwrap(algorithm))?;
        match algorithm {
            KeyWrapAlgorithm::AesKw(size) => aes_wrap(false, size, key, data),
            #[cfg(feature = "legacy")]
            KeyWrapAlgorithm::TripleDesKw => triple_des_unwrap(key, data),
        }
    }

    #[cfg(feature = "legacy")]
    fn triple_des_wrap(kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
        validate_triple_des_kek(kek)?;
        let _ = key_data;
        Err(Error::unsupported(
            Operation::Wrap(KeyWrapAlgorithm::TripleDesKw),
            "3DES key wrap AWS-LC provider",
        ))
    }

    #[cfg(feature = "legacy")]
    fn triple_des_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
        validate_triple_des_kek(kek)?;
        let _ = wrapped;
        Err(Error::unsupported(
            Operation::Unwrap(KeyWrapAlgorithm::TripleDesKw),
            "3DES key unwrap AWS-LC provider",
        ))
    }

    #[cfg(feature = "legacy")]
    fn validate_triple_des_kek(kek: &[u8]) -> Result<()> {
        if kek.len() != 24 {
            return Err(Error::Crypto(format!(
                "3DES-KW KEK must be 24 bytes, got {}",
                kek.len()
            )));
        }
        Ok(())
    }

    fn aes_wrap(wrap: bool, size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != size.key_len() {
            return Err(Error::Crypto(format!(
                "AES-KW key must be {} bytes, got {}",
                size.key_len(),
                key.len()
            )));
        }
        if (wrap && (data.len() < 16 || !data.len().is_multiple_of(8)))
            || (!wrap && (data.len() < 24 || !data.len().is_multiple_of(8)))
        {
            return Err(Error::Crypto("invalid AES-KW input length".into()));
        }
        aws_aes_wrap(wrap, size, key, data)
    }

    fn aws_aes_wrap(wrap: bool, size: AesKeySize, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::key_wrap::{AesKek, KeyWrap, AES_128, AES_256};
        let cipher = match size {
            AesKeySize::Aes128 => &AES_128,
            AesKeySize::Aes256 => &AES_256,
            AesKeySize::Aes192 => {
                return Err(Error::unsupported(
                    if wrap {
                        Operation::Wrap(KeyWrapAlgorithm::AesKw(size))
                    } else {
                        Operation::Unwrap(KeyWrapAlgorithm::AesKw(size))
                    },
                    "AWS-LC stable AES-KW-192",
                ))
            }
        };
        let kek = AesKek::new(cipher, key)
            .map_err(|_| Error::Crypto("AWS-LC AES-KW setup failed".into()))?;
        let mut output = vec![0u8; if wrap { data.len() + 8 } else { data.len() - 8 }];
        let output = if wrap {
            kek.wrap(data, &mut output)
        } else {
            kek.unwrap(data, &mut output)
        }
        .map_err(|_| Error::Crypto("AWS-LC AES-KW operation failed".into()))?;
        Ok(output.to_vec())
    }
}

pub mod keytransport {
    use crate::algorithm::OaepConfig;
    use crate::algorithm::{HashAlgorithm, KeyTransportAlgorithm};
    use crate::backend::{require_supported, KeyAlgorithm, Operation};
    use crate::error::{Error, Result};
    use crate::key::SoftwareKey;

    pub fn kt_encrypt(
        algorithm: KeyTransportAlgorithm,
        public_key: &SoftwareKey,
        key_data: &[u8],
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        require_supported(Operation::TransportEncrypt(algorithm))?;
        if public_key.algorithm() != KeyAlgorithm::Rsa {
            return Err(Error::Key("RSA public key required".into()));
        }
        super::enforce_rsa_key_size(Operation::TransportEncrypt(algorithm), public_key)?;
        let public_der = public_key
            .public_der()
            .ok_or_else(|| Error::Key("RSA public key is missing".into()))?;

        aws_encrypt(algorithm, public_der, key_data, label)
    }

    pub fn kt_decrypt(
        algorithm: KeyTransportAlgorithm,
        private_key: &SoftwareKey,
        encrypted: &[u8],
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        require_supported(Operation::TransportDecrypt(algorithm))?;
        if private_key.algorithm() != KeyAlgorithm::Rsa {
            return Err(Error::Key("RSA private key required".into()));
        }
        super::enforce_rsa_key_size(Operation::TransportDecrypt(algorithm), private_key)?;
        let private_der = private_key
            .private_der()
            .ok_or_else(|| Error::Key("RSA private key is missing".into()))?;

        aws_decrypt(algorithm, private_der, encrypted, label)
    }

    fn aws_oaep(config: OaepConfig) -> Result<&'static aws_lc_rs::rsa::OaepAlgorithm> {
        use aws_lc_rs::rsa::{
            OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384,
            OAEP_SHA512_MGF1SHA512,
        };

        match (config.digest, config.mgf_digest) {
            (HashAlgorithm::Sha1, HashAlgorithm::Sha1) => Ok(&OAEP_SHA1_MGF1SHA1),
            (HashAlgorithm::Sha256, HashAlgorithm::Sha256) => Ok(&OAEP_SHA256_MGF1SHA256),
            (HashAlgorithm::Sha384, HashAlgorithm::Sha384) => Ok(&OAEP_SHA384_MGF1SHA384),
            (HashAlgorithm::Sha512, HashAlgorithm::Sha512) => Ok(&OAEP_SHA512_MGF1SHA512),
            _ => Err(Error::unsupported(
                Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(config)),
                format!(
                    "AWS-LC RSA-OAEP {:?}/MGF1-{:?}",
                    config.digest, config.mgf_digest
                ),
            )),
        }
    }

    fn aws_encrypt(
        algorithm: KeyTransportAlgorithm,
        public_der: &[u8],
        data: &[u8],
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};

        let key = PublicEncryptingKey::from_der(public_der)
            .map_err(|_| Error::Key("AWS-LC rejected RSA SPKI".into()))?;
        match algorithm {
            #[cfg(feature = "legacy")]
            KeyTransportAlgorithm::RsaPkcs1v15 => {
                use aws_lc_rs::rsa::Pkcs1PublicEncryptingKey;
                if label.is_some() {
                    return Err(Error::Crypto(
                        "RSA PKCS#1 v1.5 does not accept an OAEP label".into(),
                    ));
                }
                let key = Pkcs1PublicEncryptingKey::new(key)
                    .map_err(|_| Error::Key("AWS-LC rejected RSA public key".into()))?;
                let mut output = vec![0; key.ciphertext_size()];
                let written = key
                    .encrypt(data, &mut output)
                    .map_err(|_| Error::Crypto("AWS-LC RSA PKCS#1 encryption failed".into()))?
                    .len();
                output.truncate(written);
                Ok(output)
            }
            KeyTransportAlgorithm::RsaOaep(config) => {
                let oaep = aws_oaep(config)?;
                let key = OaepPublicEncryptingKey::new(key)
                    .map_err(|_| Error::Key("AWS-LC rejected RSA public key".into()))?;
                let mut output = vec![0; key.ciphertext_size()];
                let written = key
                    .encrypt(oaep, data, &mut output, label)
                    .map_err(|_| Error::Crypto("AWS-LC RSA-OAEP encryption failed".into()))?
                    .len();
                output.truncate(written);
                Ok(output)
            }
        }
    }

    fn aws_decrypt(
        algorithm: KeyTransportAlgorithm,
        private_der: &[u8],
        encrypted: &[u8],
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use aws_lc_rs::rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey};

        let key = PrivateDecryptingKey::from_pkcs8(private_der)
            .map_err(|_| Error::Key("AWS-LC rejected RSA PKCS#8".into()))?;
        match algorithm {
            #[cfg(feature = "legacy")]
            KeyTransportAlgorithm::RsaPkcs1v15 => {
                use aws_lc_rs::rsa::Pkcs1PrivateDecryptingKey;
                if label.is_some() {
                    return Err(Error::Crypto(
                        "RSA PKCS#1 v1.5 does not accept an OAEP label".into(),
                    ));
                }
                let key = Pkcs1PrivateDecryptingKey::new(key)
                    .map_err(|_| Error::Key("AWS-LC rejected RSA private key".into()))?;
                let mut output = vec![0; key.min_output_size()];
                let written = key
                    .decrypt(encrypted, &mut output)
                    .map_err(|_| Error::Crypto("AWS-LC RSA PKCS#1 decryption failed".into()))?
                    .len();
                output.truncate(written);
                Ok(output)
            }
            KeyTransportAlgorithm::RsaOaep(config) => {
                let oaep = aws_oaep(config).map_err(|_| {
                    Error::unsupported(
                        Operation::TransportDecrypt(algorithm),
                        format!(
                            "AWS-LC RSA-OAEP {:?}/MGF1-{:?}",
                            config.digest, config.mgf_digest
                        ),
                    )
                })?;
                let key = OaepPrivateDecryptingKey::new(key)
                    .map_err(|_| Error::Key("AWS-LC rejected RSA private key".into()))?;
                let mut output = vec![0; key.min_output_size()];
                let written = key
                    .decrypt(oaep, encrypted, &mut output, label)
                    .map_err(|_| Error::Crypto("AWS-LC RSA-OAEP decryption failed".into()))?
                    .len();
                output.truncate(written);
                Ok(output)
            }
        }
    }
}

pub mod keyagreement {
    use crate::algorithm::EcCurve;
    use crate::backend::{KeyAlgorithm, Operation};
    use crate::error::{Error, Result};
    use crate::key::SoftwareKey;

    pub fn agree(curve: EcCurve, peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
        crate::backend::require_supported(Operation::Agreement(curve))?;
        if private.algorithm() != KeyAlgorithm::Ec(curve) {
            return Err(Error::Key(format!("ECDH {curve:?} private key required")));
        }
        let private_der = private
            .private_der()
            .ok_or_else(|| Error::Key("ECDH private key is missing".into()))?;
        aws_agree(curve, peer_public, private_der)
    }

    pub fn ecdh_x25519(peer_public: &[u8], private: &[u8]) -> Result<Vec<u8>> {
        crate::backend::require_supported(Operation::X25519Agreement)?;
        if peer_public.len() != 32 {
            return Err(Error::Key(format!(
                "invalid X25519 public key length: {} (expected 32)",
                peer_public.len()
            )));
        }
        if private.len() != 32 {
            return Err(Error::Key(format!(
                "invalid X25519 private key length: {} (expected 32)",
                private.len()
            )));
        }
        aws_x25519(peer_public, private)
    }

    pub fn agree_x25519(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
        crate::backend::require_supported(Operation::X25519Agreement)?;
        if private.algorithm() != KeyAlgorithm::X25519 {
            return Err(Error::Key("X25519 private key required".into()));
        }
        if peer_public.len() != 32 {
            return Err(Error::Key("X25519 public key must be 32 bytes".into()));
        }
        let private = private
            .private_der()
            .filter(|value| value.len() == 32)
            .ok_or_else(|| Error::Key("X25519 private key must be 32 bytes".into()))?;
        aws_x25519(peer_public, private)
    }

    /// Finite-field DH remains a deterministic capability gap in the initial
    /// alternate-provider adapters.  Check support before inspecting the key
    /// so callers never fall through to another provider or export a private
    /// exponent.
    pub fn agree_dh(_peer_public: &[u8], _private: &SoftwareKey) -> Result<Vec<u8>> {
        crate::backend::require_supported(Operation::DhAgreement)?;
        unreachable!("a provider advertising finite-field DH must implement agree_dh")
    }

    fn aws_algorithm(curve: EcCurve) -> &'static aws_lc_rs::agreement::Algorithm {
        match curve {
            EcCurve::P256 => &aws_lc_rs::agreement::ECDH_P256,
            EcCurve::P384 => &aws_lc_rs::agreement::ECDH_P384,
            EcCurve::P521 => &aws_lc_rs::agreement::ECDH_P521,
        }
    }

    fn aws_agree(curve: EcCurve, peer: &[u8], private_der: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey};
        let algorithm = aws_algorithm(curve);
        let private = PrivateKey::from_private_key_der(algorithm, private_der)
            .map_err(|e| Error::Key(format!("AWS-LC ECDH private import failed: {e}")))?;
        let peer = UnparsedPublicKey::new(algorithm, peer);
        agree(&private, peer, (), |secret| Ok(secret.to_vec()))
            .map_err(|()| Error::Crypto("AWS-LC ECDH agreement failed".into()))
    }

    fn aws_x25519(peer: &[u8], private: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey, X25519};
        let private = PrivateKey::from_private_key(&X25519, private)
            .map_err(|e| Error::Key(format!("AWS-LC X25519 private import failed: {e}")))?;
        let peer = UnparsedPublicKey::new(&X25519, peer);
        agree(&private, peer, (), |secret| {
            // Keep the contributory-behaviour check explicit at our provider
            // boundary even though AWS-LC currently rejects this output too.
            if secret.iter().copied().fold(0u8, |acc, byte| acc | byte) == 0 {
                return Err(());
            }
            Ok(secret.to_vec())
        })
        .map_err(|()| Error::Crypto("AWS-LC X25519 agreement failed".into()))
    }
}

#[cfg(feature = "post-quantum")]
pub mod kem {
    use zeroize::Zeroizing;

    use crate::algorithm::{KemAlgorithm, MlKemVariant};
    use crate::backend::Operation;
    use crate::error::{Error, Result};
    use crate::key::SoftwareKey;
    use crate::traits;

    pub struct SoftwareEncapsulator {
        algorithm: KemAlgorithm,
        _key: SoftwareKey,
    }

    impl SoftwareEncapsulator {
        pub fn new(variant: MlKemVariant, key: SoftwareKey) -> Result<Self> {
            let algorithm = KemAlgorithm::MlKem(variant);
            crate::backend::require_supported(Operation::KemEncapsulate(algorithm))?;
            Ok(Self {
                algorithm,
                _key: key,
            })
        }
    }

    impl traits::Encapsulator for SoftwareEncapsulator {
        fn algorithm(&self) -> KemAlgorithm {
            self.algorithm
        }
        fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
            Err(Error::unsupported(
                Operation::KemEncapsulate(self.algorithm),
                format!("{:?}", self.algorithm),
            ))
        }
    }

    pub struct SoftwareDecapsulator {
        algorithm: KemAlgorithm,
        _key: SoftwareKey,
    }

    impl SoftwareDecapsulator {
        pub fn new(variant: MlKemVariant, key: SoftwareKey) -> Result<Self> {
            let algorithm = KemAlgorithm::MlKem(variant);
            crate::backend::require_supported(Operation::KemDecapsulate(algorithm))?;
            Ok(Self {
                algorithm,
                _key: key,
            })
        }
    }

    impl traits::Decapsulator for SoftwareDecapsulator {
        fn algorithm(&self) -> KemAlgorithm {
            self.algorithm
        }
        fn decapsulate(&self, _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(Error::unsupported(
                Operation::KemDecapsulate(self.algorithm),
                format!("{:?}", self.algorithm),
            ))
        }
    }

    pub fn generate_ml_kem(variant: MlKemVariant) -> Result<SoftwareKey> {
        let algorithm = KemAlgorithm::MlKem(variant);
        Err(Error::unsupported(
            Operation::KemGenerate(algorithm),
            format!("{algorithm:?}"),
        ))
    }
}

#[cfg(feature = "post-quantum")]
pub mod sign {
    use crate::algorithm::{MlDsaVariant, PqAlgorithm};
    use crate::backend::{KeyAlgorithm, Operation};
    use crate::error::{Error, Result};
    use crate::key::SoftwareKey;

    pub fn generate_ml_dsa(variant: MlDsaVariant) -> Result<SoftwareKey> {
        let key = KeyAlgorithm::PostQuantum(PqAlgorithm::MlDsa(variant));
        Err(Error::unsupported(
            Operation::KeyImport(key),
            format!("{variant:?}"),
        ))
    }
}

#[cfg(not(feature = "post-quantum"))]
pub mod sign {}
