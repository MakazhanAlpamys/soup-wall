//! Composite ML-DSA signatures from
//! draft-ietf-jose-pq-composite-sigs-03.
//!
//! Component keys never become independently addressable `SoftwareKey`
//! values. They are decoded inside an operation and dropped immediately,
//! preserving the draft's requirement that a component key is not reused as
//! a standalone key or in another composite combination.

use crate::algorithm::{CompositeMlDsaVariant, MlDsaVariant};
use crate::backend::{require_supported, KeyAlgorithm, Operation};
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey, SoftwareKey};
use zeroize::Zeroizing;

const COMPOSITE_SIGNATURE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const ML_DSA_SEED_LEN: usize = 32;

/// Generate a fresh aggregate composite key.
///
/// Both component keys are generated for this composite key alone. The
/// returned public and private encodings are the raw concatenations required
/// by draft-ietf-jose-pq-composite-sigs-03, not SPKI or PKCS#8 documents.
pub fn generate_composite_ml_dsa(variant: CompositeMlDsaVariant) -> Result<SoftwareKey> {
    let key_algorithm = KeyAlgorithm::CompositeMlDsa(variant);
    require_supported(Operation::KeyImport(key_algorithm))?;

    let mut ml_dsa_seed = Zeroizing::new(vec![0u8; ML_DSA_SEED_LEN]);
    fill_secret(&mut ml_dsa_seed)?;

    let mut traditional_private = Zeroizing::new(vec![0u8; traditional_private_len(variant)]);
    match variant {
        CompositeMlDsaVariant::MlDsa44Es256 | CompositeMlDsaVariant::MlDsa65Es256 => loop {
            fill_secret(&mut traditional_private)?;
            if p256::ecdsa::SigningKey::from_slice(&traditional_private).is_ok() {
                break;
            }
        },
        CompositeMlDsaVariant::MlDsa87Es384 => loop {
            fill_secret(&mut traditional_private)?;
            if p384::ecdsa::SigningKey::from_slice(&traditional_private).is_ok() {
                break;
            }
        },
        CompositeMlDsaVariant::MlDsa44Ed25519
        | CompositeMlDsaVariant::MlDsa65Ed25519
        | CompositeMlDsaVariant::MlDsa87Ed448 => fill_secret(&mut traditional_private)?,
    }

    let mut private = Zeroizing::new(Vec::with_capacity(variant.private_key_len()));
    private.extend_from_slice(&ml_dsa_seed);
    private.extend_from_slice(&traditional_private);
    let public = derive_public(variant, &private)?;

    Ok(SoftwareKey::from_rustcrypto(
        RustCryptoKey::CompositeMlDsa {
            variant,
            private: Some(std::mem::take(&mut *private)),
            public,
        },
    ))
}

fn fill_secret(output: &mut [u8]) -> Result<()> {
    getrandom::fill(output)
        .map_err(|error| Error::Crypto(format!("OS entropy draw failed: {error}")))
}

/// Validate aggregate raw key material during import.
pub(crate) fn validate_import(
    variant: CompositeMlDsaVariant,
    private: Option<&[u8]>,
    public: &[u8],
) -> Result<()> {
    if public.len() != variant.public_key_len() {
        return Err(Error::Key(format!(
            "{} public key must be {} bytes, got {}",
            variant.name(),
            variant.public_key_len(),
            public.len()
        )));
    }
    validate_public(variant, public)?;

    if let Some(private) = private {
        if private.len() != variant.private_key_len() {
            return Err(Error::Key(format!(
                "{} private key must be {} bytes, got {}",
                variant.name(),
                variant.private_key_len(),
                private.len()
            )));
        }
        let derived = derive_public(variant, private)?;
        if derived != public {
            return Err(Error::Key(format!(
                "{} aggregate public key does not match the private key",
                variant.name()
            )));
        }
    }
    Ok(())
}

fn validate_public(variant: CompositeMlDsaVariant, public: &[u8]) -> Result<()> {
    let ml_len = variant.ml_dsa_public_key_len();
    let (ml_public, traditional_public) = public.split_at(ml_len);
    validate_ml_dsa_public(variant.ml_dsa_variant(), ml_public)?;
    validate_traditional_public(variant, traditional_public)
}

fn validate_ml_dsa_public(variant: MlDsaVariant, public: &[u8]) -> Result<()> {
    fn validate<P: ml_dsa::MlDsaParams>(public: &[u8]) -> Result<()> {
        ml_dsa::EncodedVerifyingKey::<P>::try_from(public)
            .map(|encoded| {
                let _ = ml_dsa::VerifyingKey::<P>::decode(&encoded);
            })
            .map_err(|_| Error::Key("invalid ML-DSA public-key length".into()))
    }

    match variant {
        MlDsaVariant::MlDsa44 => validate::<ml_dsa::MlDsa44>(public),
        MlDsaVariant::MlDsa65 => validate::<ml_dsa::MlDsa65>(public),
        MlDsaVariant::MlDsa87 => validate::<ml_dsa::MlDsa87>(public),
    }
}

fn validate_traditional_public(variant: CompositeMlDsaVariant, public: &[u8]) -> Result<()> {
    match variant {
        CompositeMlDsaVariant::MlDsa44Es256 | CompositeMlDsaVariant::MlDsa65Es256 => {
            let encoded = uncompressed_sec1(public, 64)?;
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
                .map(|_| ())
                .map_err(|error| Error::Key(format!("invalid P-256 public key: {error}")))
        }
        CompositeMlDsaVariant::MlDsa87Es384 => {
            let encoded = uncompressed_sec1(public, 96)?;
            p384::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
                .map(|_| ())
                .map_err(|error| Error::Key(format!("invalid P-384 public key: {error}")))
        }
        CompositeMlDsaVariant::MlDsa44Ed25519 | CompositeMlDsaVariant::MlDsa65Ed25519 => {
            let bytes: &[u8; 32] = public
                .try_into()
                .map_err(|_| Error::Key("Ed25519 public key must be 32 bytes".into()))?;
            ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map(|_| ())
                .map_err(|error| Error::Key(format!("invalid Ed25519 public key: {error}")))
        }
        CompositeMlDsaVariant::MlDsa87Ed448 => {
            let bytes: &[u8; 57] = public
                .try_into()
                .map_err(|_| Error::Key("Ed448 public key must be 57 bytes".into()))?;
            ed448_goldilocks::VerifyingKey::from_bytes(bytes)
                .map(|_| ())
                .map_err(|error| Error::Key(format!("invalid Ed448 public key: {error}")))
        }
    }
}

fn uncompressed_sec1(raw: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if raw.len() != expected_len {
        return Err(Error::Key(format!(
            "raw ECDSA public key must be {expected_len} bytes, got {}",
            raw.len()
        )));
    }
    let mut encoded = Vec::with_capacity(expected_len + 1);
    encoded.push(0x04);
    encoded.extend_from_slice(raw);
    Ok(encoded)
}

fn derive_public(variant: CompositeMlDsaVariant, private: &[u8]) -> Result<Vec<u8>> {
    if private.len() != variant.private_key_len() {
        return Err(Error::Key(format!(
            "{} private key must be {} bytes, got {}",
            variant.name(),
            variant.private_key_len(),
            private.len()
        )));
    }
    let (ml_dsa_seed, traditional_private) = private.split_at(ML_DSA_SEED_LEN);
    let mut public = Vec::with_capacity(variant.public_key_len());
    public.extend_from_slice(&derive_ml_dsa_public(
        variant.ml_dsa_variant(),
        ml_dsa_seed,
    )?);
    public.extend_from_slice(&derive_traditional_public(variant, traditional_private)?);
    Ok(public)
}

fn derive_ml_dsa_public(variant: MlDsaVariant, seed: &[u8]) -> Result<Vec<u8>> {
    fn derive<P: ml_dsa::MlDsaParams>(seed: &[u8]) -> Result<Vec<u8>> {
        let seed = ml_dsa::Seed::try_from(seed)
            .map_err(|_| Error::Key("ML-DSA seed must be 32 bytes".into()))?;
        Ok(ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed)
            .verifying_key()
            .encode()
            .to_vec())
    }

    match variant {
        MlDsaVariant::MlDsa44 => derive::<ml_dsa::MlDsa44>(seed),
        MlDsaVariant::MlDsa65 => derive::<ml_dsa::MlDsa65>(seed),
        MlDsaVariant::MlDsa87 => derive::<ml_dsa::MlDsa87>(seed),
    }
}

fn derive_traditional_public(variant: CompositeMlDsaVariant, private: &[u8]) -> Result<Vec<u8>> {
    match variant {
        CompositeMlDsaVariant::MlDsa44Es256 | CompositeMlDsaVariant::MlDsa65Es256 => {
            let signing_key = p256::ecdsa::SigningKey::from_slice(private)
                .map_err(|error| Error::Key(format!("invalid P-256 private key: {error}")))?;
            Ok(signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()[1..]
                .to_vec())
        }
        CompositeMlDsaVariant::MlDsa87Es384 => {
            let signing_key = p384::ecdsa::SigningKey::from_slice(private)
                .map_err(|error| Error::Key(format!("invalid P-384 private key: {error}")))?;
            Ok(signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()[1..]
                .to_vec())
        }
        CompositeMlDsaVariant::MlDsa44Ed25519 | CompositeMlDsaVariant::MlDsa65Ed25519 => {
            let bytes: &[u8; 32] = private
                .try_into()
                .map_err(|_| Error::Key("Ed25519 private key must be 32 bytes".into()))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(bytes)
                .verifying_key()
                .to_bytes()
                .to_vec())
        }
        CompositeMlDsaVariant::MlDsa87Ed448 => {
            let signing_key = ed448_goldilocks::SigningKey::try_from(private)
                .map_err(|error| Error::Key(format!("invalid Ed448 private key: {error}")))?;
            Ok(signing_key.verifying_key().to_bytes().to_vec())
        }
    }
}

/// Sign using both components and return `ML-DSA signature || traditional
/// signature`.
pub(crate) fn sign(
    key: &RustCryptoKey,
    variant: CompositeMlDsaVariant,
    message: &[u8],
) -> Result<Vec<u8>> {
    let RustCryptoKey::CompositeMlDsa {
        variant: key_variant,
        private: Some(private),
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} aggregate private key required for signing",
            variant.name()
        )));
    };
    if *key_variant != variant {
        return Err(Error::Key(format!(
            "composite key is {}, but signature requires {}",
            key_variant.name(),
            variant.name()
        )));
    }

    let representative = message_representative(variant, message);
    let (ml_dsa_seed, traditional_private) = private.split_at(ML_DSA_SEED_LEN);
    let ml_signature = sign_ml_dsa(
        variant.ml_dsa_variant(),
        ml_dsa_seed,
        &representative,
        variant.label(),
    )?;
    let traditional_signature = sign_traditional(variant, traditional_private, &representative)?;

    let mut signature = Vec::with_capacity(variant.signature_len());
    signature.extend_from_slice(&ml_signature);
    signature.extend_from_slice(&traditional_signature);
    debug_assert_eq!(signature.len(), variant.signature_len());
    Ok(signature)
}

fn sign_ml_dsa(
    variant: MlDsaVariant,
    seed: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    fn sign<P: ml_dsa::MlDsaParams>(
        seed: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>> {
        let seed = ml_dsa::Seed::try_from(seed)
            .map_err(|_| Error::Key("ML-DSA seed must be 32 bytes".into()))?;
        let signing_key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed);
        signing_key
            .sign_randomized(message, context, &mut getrandom::SysRng)
            .map(|signature| signature.encode().to_vec())
            .map_err(|error| Error::Crypto(format!("ML-DSA sign failed: {error}")))
    }

    match variant {
        MlDsaVariant::MlDsa44 => sign::<ml_dsa::MlDsa44>(seed, message, context),
        MlDsaVariant::MlDsa65 => sign::<ml_dsa::MlDsa65>(seed, message, context),
        MlDsaVariant::MlDsa87 => sign::<ml_dsa::MlDsa87>(seed, message, context),
    }
}

fn sign_traditional(
    variant: CompositeMlDsaVariant,
    private: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    use signature::hazmat::PrehashSigner;

    match variant {
        CompositeMlDsaVariant::MlDsa44Es256 | CompositeMlDsaVariant::MlDsa65Es256 => {
            use sha2::Digest;
            let signing_key = p256::ecdsa::SigningKey::from_slice(private)
                .map_err(|error| Error::Key(format!("invalid P-256 private key: {error}")))?;
            let digest = sha2::Sha256::digest(message);
            let signature: p256::ecdsa::Signature = signing_key
                .sign_prehash(&digest)
                .map_err(|error| Error::Crypto(format!("ECDSA P-256 sign failed: {error}")))?;
            Ok(signature.to_bytes().to_vec())
        }
        CompositeMlDsaVariant::MlDsa87Es384 => {
            use sha2::Digest;
            let signing_key = p384::ecdsa::SigningKey::from_slice(private)
                .map_err(|error| Error::Key(format!("invalid P-384 private key: {error}")))?;
            let digest = sha2::Sha384::digest(message);
            let signature: p384::ecdsa::Signature = signing_key
                .sign_prehash(&digest)
                .map_err(|error| Error::Crypto(format!("ECDSA P-384 sign failed: {error}")))?;
            Ok(signature.to_bytes().to_vec())
        }
        CompositeMlDsaVariant::MlDsa44Ed25519 | CompositeMlDsaVariant::MlDsa65Ed25519 => {
            use ed25519_dalek::Signer;
            let bytes: &[u8; 32] = private
                .try_into()
                .map_err(|_| Error::Key("Ed25519 private key must be 32 bytes".into()))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(bytes)
                .sign(message)
                .to_bytes()
                .to_vec())
        }
        CompositeMlDsaVariant::MlDsa87Ed448 => {
            let signing_key = ed448_goldilocks::SigningKey::try_from(private)
                .map_err(|error| Error::Key(format!("invalid Ed448 private key: {error}")))?;
            Ok(signing_key.sign_raw(message).to_bytes().to_vec())
        }
    }
}

/// Verify both component signatures. Malformed signature encodings are
/// reported as an invalid signature rather than an operation error.
pub(crate) fn verify(
    key: &RustCryptoKey,
    variant: CompositeMlDsaVariant,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let RustCryptoKey::CompositeMlDsa {
        variant: key_variant,
        public,
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} aggregate public key required for verification",
            variant.name()
        )));
    };
    if *key_variant != variant {
        return Err(Error::Key(format!(
            "composite key is {}, but verification requires {}",
            key_variant.name(),
            variant.name()
        )));
    }
    if signature.len() != variant.signature_len() {
        return Ok(false);
    }

    let representative = message_representative(variant, message);
    let (ml_public, traditional_public) = public.split_at(variant.ml_dsa_public_key_len());
    let (ml_signature, traditional_signature) = signature.split_at(variant.ml_dsa_signature_len());

    // Evaluate both components even if the first fails. Besides following the
    // draft literally, this avoids exposing which component rejected a
    // well-formed aggregate through an obvious short-circuit.
    let ml_valid = verify_ml_dsa(
        variant.ml_dsa_variant(),
        ml_public,
        &representative,
        variant.label(),
        ml_signature,
    );
    let traditional_valid = verify_traditional(
        variant,
        traditional_public,
        &representative,
        traditional_signature,
    );
    Ok(ml_valid && traditional_valid)
}

fn verify_ml_dsa(
    variant: MlDsaVariant,
    public: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    fn verify<P: ml_dsa::MlDsaParams>(
        public: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        let Ok(public) = ml_dsa::EncodedVerifyingKey::<P>::try_from(public) else {
            return false;
        };
        let verifying_key = ml_dsa::VerifyingKey::<P>::decode(&public);
        let Ok(encoded_signature) = ml_dsa::EncodedSignature::<P>::try_from(signature) else {
            return false;
        };
        let Some(signature) = ml_dsa::Signature::<P>::decode(&encoded_signature) else {
            return false;
        };
        verifying_key.verify_with_context(message, context, &signature)
    }

    match variant {
        MlDsaVariant::MlDsa44 => verify::<ml_dsa::MlDsa44>(public, message, context, signature),
        MlDsaVariant::MlDsa65 => verify::<ml_dsa::MlDsa65>(public, message, context, signature),
        MlDsaVariant::MlDsa87 => verify::<ml_dsa::MlDsa87>(public, message, context, signature),
    }
}

fn verify_traditional(
    variant: CompositeMlDsaVariant,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    use signature::hazmat::PrehashVerifier;

    match variant {
        CompositeMlDsaVariant::MlDsa44Es256 | CompositeMlDsaVariant::MlDsa65Es256 => {
            use sha2::Digest;
            let Ok(encoded) = uncompressed_sec1(public, 64) else {
                return false;
            };
            let Ok(verifying_key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded) else {
                return false;
            };
            let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
                return false;
            };
            verifying_key
                .verify_prehash(&sha2::Sha256::digest(message), &signature)
                .is_ok()
        }
        CompositeMlDsaVariant::MlDsa87Es384 => {
            use sha2::Digest;
            let Ok(encoded) = uncompressed_sec1(public, 96) else {
                return false;
            };
            let Ok(verifying_key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(&encoded) else {
                return false;
            };
            let Ok(signature) = p384::ecdsa::Signature::from_slice(signature) else {
                return false;
            };
            verifying_key
                .verify_prehash(&sha2::Sha384::digest(message), &signature)
                .is_ok()
        }
        CompositeMlDsaVariant::MlDsa44Ed25519 | CompositeMlDsaVariant::MlDsa65Ed25519 => {
            let Ok(public) = <&[u8; 32]>::try_from(public) else {
                return false;
            };
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
                return false;
            };
            let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                return false;
            };
            verifying_key.verify_strict(message, &signature).is_ok()
        }
        CompositeMlDsaVariant::MlDsa87Ed448 => {
            let Ok(public) = <&[u8; 57]>::try_from(public) else {
                return false;
            };
            let Ok(verifying_key) = ed448_goldilocks::VerifyingKey::from_bytes(public) else {
                return false;
            };
            let Ok(signature) = ed448_goldilocks::Signature::from_slice(signature) else {
                return false;
            };
            verifying_key.verify_raw(&signature, message).is_ok()
        }
    }
}

fn traditional_private_len(variant: CompositeMlDsaVariant) -> usize {
    variant.private_key_len() - ML_DSA_SEED_LEN
}

/// Build the byte string signed by both component algorithms.
fn message_representative(variant: CompositeMlDsaVariant, message: &[u8]) -> Vec<u8> {
    use sha2::Digest;

    let prehash = match variant {
        CompositeMlDsaVariant::MlDsa44Es256 => sha2::Sha256::digest(message).to_vec(),
        CompositeMlDsaVariant::MlDsa65Es256
        | CompositeMlDsaVariant::MlDsa87Es384
        | CompositeMlDsaVariant::MlDsa44Ed25519
        | CompositeMlDsaVariant::MlDsa65Ed25519 => sha2::Sha512::digest(message).to_vec(),
        CompositeMlDsaVariant::MlDsa87Ed448 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut hasher = sha3::Shake256::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut output = [0u8; 64];
            reader.read(&mut output);
            output.to_vec()
        }
    };

    let mut representative = Vec::with_capacity(
        COMPOSITE_SIGNATURE_PREFIX.len() + variant.label().len() + 1 + prehash.len(),
    );
    representative.extend_from_slice(COMPOSITE_SIGNATURE_PREFIX);
    representative.extend_from_slice(variant.label());
    representative.push(0);
    representative.extend_from_slice(&prehash);
    representative
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::SignatureAlgorithm;
    use crate::software::sign::{SoftwareSigner, SoftwareVerifier};
    use crate::traits::{Signer, Verifier};

    #[test]
    fn draft_metadata_lengths_are_exact() {
        let expected = [
            (CompositeMlDsaVariant::MlDsa44Es256, 1_376, 64, 2_484),
            (CompositeMlDsaVariant::MlDsa65Es256, 2_016, 64, 3_373),
            (CompositeMlDsaVariant::MlDsa87Es384, 2_688, 80, 4_723),
            (CompositeMlDsaVariant::MlDsa44Ed25519, 1_344, 64, 2_484),
            (CompositeMlDsaVariant::MlDsa65Ed25519, 1_984, 64, 3_373),
            (CompositeMlDsaVariant::MlDsa87Ed448, 2_649, 89, 4_741),
        ];
        for (variant, public, private, signature) in expected {
            assert_eq!(variant.public_key_len(), public, "{}", variant.name());
            assert_eq!(variant.private_key_len(), private, "{}", variant.name());
            assert_eq!(variant.signature_len(), signature, "{}", variant.name());
        }
    }

    #[test]
    fn jose_draft_message_representatives_match_appendix_a() {
        let cases = [
            (
                CompositeMlDsaVariant::MlDsa44Es256,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534134342d45434453412d503235362d534841323536004dc3664a13a79a1e3b82ba12b77a0716b5a3eb10f399eb89d881f5812650f9e7",
            ),
            (
                CompositeMlDsaVariant::MlDsa44Ed25519,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534134342d456432353531392d53484135313200d23794746d85892c086d70a49905c7e9e4012755204e01da3af1d4d17743a448ec42685a47c8913bde2cf7eb4deb3e41aee03802d6bb889ebf61177aff41cbab",
            ),
            (
                CompositeMlDsaVariant::MlDsa65Es256,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534136352d45434453412d503235362d5348413531320083d72345d7781ec2af44f53f717b55da668f876eb1fa59abe0e737341f53ab9763d8220ea65f803b7947fc8e950c2c18acff030bdaf8563431f3d582f6ef4247",
            ),
            (
                CompositeMlDsaVariant::MlDsa65Ed25519,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534136352d456432353531392d534841353132009baf58046749538103f9d14500c2e6a53857983cee47d2a8b6f6170ecee7ba4f854c69a342305faeb17563aa5269250d7be5c3ec63a4e9429e1f5399f014a7f1",
            ),
            (
                CompositeMlDsaVariant::MlDsa87Es384,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534138372d45434453412d503338342d534841353132008a6a432968518367ecc05f10bad14c4156a86024c373bff89757ea849db7b00cb8948c747cc83231e5502b536c7197e3acf52525320e60afd3b88f32fbb6c4e3",
            ),
            (
                CompositeMlDsaVariant::MlDsa87Ed448,
                "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534138372d45643434382d5348414b4532353600c86e106632b46f3f7ada053b838a8cbf21f8773ee7b1f1f2bb80d108008c2378d18bf1a314a40faefed6bbd88bbda4cbae01e4d335b9097c7862e3750b4c7414",
            ),
        ];
        let messages = [
            b"eyJhbGciOiJNTC1EU0EtNDQtRVMyNTYiLCJraWQiOiJoVi1RMW9ZZDNqYmlnWXRTVjNVejRpaWR4VTFlSl8wQTNvdEJYMXY3OTNFIn0.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
            b"eyJhbGciOiJNTC1EU0EtNDQtRWQyNTUxOSIsImtpZCI6IjVFVHp0eWFBUWt2ZmxobWpKNm10ZHdsV0ViM05yNHltY0RwTjhlWFE4aDQifQ.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
            b"eyJhbGciOiJNTC1EU0EtNjUtRVMyNTYiLCJraWQiOiJkTFE4R2ZpZWZST2kxSWFMaloxb09mSTBUVndmeTVvVzBQZzBjVlg1TlJvIn0.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
            b"eyJhbGciOiJNTC1EU0EtNjUtRWQyNTUxOSIsImtpZCI6Ijg3Vm4zSlRtdlRkeHZwZXR2MHJBNUd3Zm9MbkNrTXhCRENKdllnRlZ1aDQifQ.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
            b"eyJhbGciOiJNTC1EU0EtODctRVMzODQiLCJraWQiOiJUTTJnQnVHRW52YmNFZUlEYnJ4Y2JfNF9FTjlDakVYaGZxZUR3Q1RNZktzIn0.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
            b"eyJhbGciOiJNTC1EU0EtODctRWQ0NDgiLCJraWQiOiJxVnNTaHVBVXVFNUVVYnFJNDgxTHNyYXJSX2tLZHJpeDByblZKMjI2S280In0.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu".as_slice(),
        ];

        for ((variant, expected), message) in cases.into_iter().zip(messages) {
            assert_eq!(
                message_representative(variant, message),
                hex::decode(expected).expect("valid draft hex"),
                "{}",
                variant.name()
            );
        }
    }

    #[test]
    fn all_variants_generate_import_sign_and_verify() {
        std::thread::Builder::new()
            .name("composite-roundtrip".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for variant in CompositeMlDsaVariant::ALL {
                    let key = generate_composite_ml_dsa(variant).expect("composite key generation");
                    assert_eq!(
                        key.algorithm(),
                        KeyAlgorithm::CompositeMlDsa(variant),
                        "{}",
                        variant.name()
                    );
                    let public = key
                        .export_composite_public()
                        .expect("aggregate public export");
                    let private = key
                        .export_composite_private()
                        .expect("aggregate private export");
                    assert_eq!(public.len(), variant.public_key_len());
                    assert_eq!(private.len(), variant.private_key_len());

                    let imported_private =
                        SoftwareKey::from_composite_ml_dsa(variant, Some(&private), &public)
                            .expect("aggregate private import");
                    let imported_public =
                        SoftwareKey::from_composite_ml_dsa(variant, None, &public)
                            .expect("aggregate public import");
                    assert!(!imported_public.has_private_key());

                    let algorithm = SignatureAlgorithm::CompositeMlDsa(variant);
                    let signer =
                        SoftwareSigner::new(algorithm, imported_private).expect("composite signer");
                    let verifier = SoftwareVerifier::new(algorithm, imported_public)
                        .expect("composite verifier");
                    let message = b"composite signatures require both components";
                    let signature = signer.sign(message).expect("composite sign");
                    assert_eq!(signature.len(), variant.signature_len());
                    assert!(
                        verifier
                            .verify(message, &signature)
                            .expect("composite verify"),
                        "{}",
                        variant.name()
                    );
                    assert!(
                        !verifier
                            .verify(b"different message", &signature)
                            .expect("wrong-message verify"),
                        "{}",
                        variant.name()
                    );

                    let mut bad_ml_dsa = signature.clone();
                    bad_ml_dsa[0] ^= 0x80;
                    assert!(
                        !verifier
                            .verify(message, &bad_ml_dsa)
                            .expect("mutated ML-DSA verify"),
                        "{} accepted a damaged ML-DSA component",
                        variant.name()
                    );

                    let mut bad_traditional = signature.clone();
                    *bad_traditional.last_mut().expect("non-empty signature") ^= 0x80;
                    assert!(
                        !verifier
                            .verify(message, &bad_traditional)
                            .expect("mutated traditional verify"),
                        "{} accepted a damaged traditional component",
                        variant.name()
                    );

                    assert!(!verifier
                        .verify(message, &signature[..signature.len() - 1])
                        .expect("truncated signature verify"));
                    let mut extended = signature;
                    extended.push(0);
                    assert!(!verifier
                        .verify(message, &extended)
                        .expect("extended signature verify"));
                }
            })
            .expect("spawn large-stack test thread")
            .join()
            .expect("composite roundtrip thread");
    }

    #[test]
    fn import_rejects_mismatched_and_malformed_aggregate_keys() {
        let variant = CompositeMlDsaVariant::MlDsa44Es256;
        let first = generate_composite_ml_dsa(variant).expect("first key");
        let second = generate_composite_ml_dsa(variant).expect("second key");
        let first_private = first.export_composite_private().expect("private");
        let second_public = second.export_composite_public().expect("public");

        let mismatch =
            SoftwareKey::from_composite_ml_dsa(variant, Some(&first_private), &second_public)
                .expect_err("mismatched aggregate key must fail");
        assert!(
            mismatch.to_string().contains("does not match"),
            "{mismatch}"
        );

        let short_public = &second_public[..second_public.len() - 1];
        assert!(SoftwareKey::from_composite_ml_dsa(variant, None, short_public).is_err());

        let mut invalid_point = second_public;
        let traditional_offset = variant.ml_dsa_public_key_len();
        invalid_point[traditional_offset..].fill(0);
        assert!(SoftwareKey::from_composite_ml_dsa(variant, None, &invalid_point).is_err());
    }

    #[test]
    fn composite_rejects_caller_provided_pq_context() {
        let variant = CompositeMlDsaVariant::MlDsa44Ed25519;
        let key = generate_composite_ml_dsa(variant).expect("key generation");
        let error = match SoftwareSigner::new_with_pq_context(
            SignatureAlgorithm::CompositeMlDsa(variant),
            key,
            b"application-context",
        ) {
            Ok(_) => panic!("composite application context must be empty"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not accept a context"),
            "{error}"
        );
    }
}
