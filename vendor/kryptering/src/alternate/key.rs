//! Provider-neutral opaque software keys for AWS-LC.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::backend::{require_supported, KeyAlgorithm, Operation};
use crate::error::{Error, Result};
use crate::parameters::DhParameters;

struct KeyMaterial {
    algorithm: KeyAlgorithm,
    private: Option<Zeroizing<Vec<u8>>>,
    public: Vec<u8>,
    dh_parameters: Option<DhParameters>,
}

/// Shared opaque key handle.
///
/// Cloning shares the same secret-bearing object. Its private buffers are
/// zeroized when the final handle is dropped, not when an individual clone is
/// released.
#[derive(Clone)]
pub struct SoftwareKey(Arc<KeyMaterial>);

impl std::fmt::Debug for SoftwareKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareKey")
            .field("algorithm", &self.0.algorithm)
            .field("has_private_key", &self.0.private.is_some())
            .field("public_len", &self.0.public.len())
            .finish_non_exhaustive()
    }
}

impl SoftwareKey {
    #[allow(dead_code)]
    pub(crate) fn private_der(&self) -> Option<&[u8]> {
        self.0.private.as_ref().map(|value| value.as_slice())
    }

    pub(crate) fn public_der(&self) -> Option<&[u8]> {
        (!self.0.public.is_empty()).then_some(&self.0.public)
    }

    pub fn from_pkcs8_der(algorithm: KeyAlgorithm, der: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        if der.is_empty() {
            return Err(Error::Key("empty PKCS#8 input".into()));
        }
        let public = public_from_private(algorithm, der)?;
        enforce_key_strength(algorithm, &public)?;
        Ok(Self(Arc::new(KeyMaterial {
            algorithm,
            private: Some(Zeroizing::new(der.to_vec())),
            public,
            dh_parameters: None,
        })))
    }

    pub fn from_spki_der(algorithm: KeyAlgorithm, der: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        if der.is_empty() {
            return Err(Error::Key("empty SPKI input".into()));
        }
        enforce_key_strength(algorithm, der)?;
        validate_public(algorithm, der)?;
        Ok(Self(Arc::new(KeyMaterial {
            algorithm,
            private: None,
            public: der.to_vec(),
            dh_parameters: None,
        })))
    }

    pub fn from_symmetric_bytes(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<Self> {
        require_supported(Operation::KeyImport(algorithm))?;
        if bytes.is_empty() {
            return Err(Error::Key("empty symmetric key".into()));
        }
        // Only symmetric families may carry raw bytes; asymmetric families
        // must go through their structured importers, as in RustCrypto.
        match algorithm {
            KeyAlgorithm::Hmac => {}
            KeyAlgorithm::Aes if matches!(bytes.len(), 16 | 24 | 32) => {}
            KeyAlgorithm::Aes => {
                return Err(Error::Key("AES keys must be 16, 24, or 32 bytes".into()))
            }
            #[cfg(feature = "legacy")]
            KeyAlgorithm::TripleDes if bytes.len() == 24 => {}
            #[cfg(feature = "legacy")]
            KeyAlgorithm::TripleDes => return Err(Error::Key("3DES keys must be 24 bytes".into())),
            _ => {
                return Err(Error::unsupported(
                    Operation::KeyImport(algorithm),
                    "raw symmetric bytes for requested key family",
                ))
            }
        }
        Ok(Self(Arc::new(KeyMaterial {
            algorithm,
            private: Some(Zeroizing::new(bytes.to_vec())),
            public: Vec::new(),
            dh_parameters: None,
        })))
    }

    pub fn from_x25519(private: Option<&[u8]>, public: &[u8]) -> Result<Self> {
        let algorithm = KeyAlgorithm::X25519;
        require_supported(Operation::KeyImport(algorithm))?;
        if public.len() != 32 || private.is_some_and(|value| value.len() != 32) {
            return Err(Error::Key("X25519 keys must be 32 bytes".into()));
        }
        Ok(Self(Arc::new(KeyMaterial {
            algorithm,
            private: private.map(|value| Zeroizing::new(value.to_vec())),
            public: public.to_vec(),
            dh_parameters: None,
        })))
    }

    /// Finite-field DH import is unavailable with AWS-LC, which cannot validate
    /// these group parameters and key components through its supported API.
    pub fn from_dh_parameters(
        _modulus: &[u8],
        _generator: &[u8],
        _subgroup_order: Option<&[u8]>,
        _private: Option<&[u8]>,
        _public: &[u8],
    ) -> Result<Self> {
        crate::backend::ensure_backend()?;
        Err(Error::unsupported(
            Operation::KeyImport(KeyAlgorithm::Dh),
            "finite-field DH key validation",
        ))
    }

    #[cfg(feature = "post-quantum")]
    pub fn from_post_quantum_der(
        algorithm: crate::algorithm::PqAlgorithm,
        private_der: Option<&[u8]>,
        public_der: &[u8],
    ) -> Result<Self> {
        let algorithm = KeyAlgorithm::PostQuantum(algorithm);
        require_supported(Operation::KeyImport(algorithm))?;
        if public_der.is_empty() {
            return Err(Error::Key("post-quantum SPKI must not be empty".into()));
        }
        Ok(Self(Arc::new(KeyMaterial {
            algorithm,
            private: private_der.map(|value| Zeroizing::new(value.to_vec())),
            public: public_der.to_vec(),
            dh_parameters: None,
        })))
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.0.algorithm
    }

    pub fn has_private_key(&self) -> bool {
        self.0.private.is_some()
    }

    pub fn spki_der(&self) -> Option<&[u8]> {
        (!self.0.public.is_empty()).then_some(&self.0.public)
    }

    /// Return SPKI DER for public-key algorithms, or a raw X25519/DH public value.
    pub fn public_component(&self) -> Result<Vec<u8>> {
        self.spki_der()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::Key("key has no public component".into()))
    }

    pub fn export_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        require_supported(Operation::KeyExport(self.0.algorithm))?;
        self.0
            .private
            .as_ref()
            .map(|value| Zeroizing::new(value.to_vec()))
            .ok_or_else(|| Error::Key("key has no private material".into()))
    }

    pub fn export_spki_der(&self) -> Result<Vec<u8>> {
        require_supported(Operation::KeyExport(self.0.algorithm))?;
        self.public_component()
    }

    /// Return neutral finite-field DH public parameters when this is a DH key.
    #[must_use]
    pub fn dh_parameters(&self) -> Option<&DhParameters> {
        self.0.dh_parameters.as_ref()
    }
}

/// Enforce size-dependent FIPS import policy after parsing the neutral SPKI.
///
/// EC imports are already restricted by [`KeyAlgorithm`] to P-256, P-384,
/// and P-521. RSA needs an additional modulus-size check because its size is
/// encoded in the key rather than the algorithm enum. Outside FIPS builds the
/// 2048-bit minimum applies when a key is used, as in the RustCrypto provider.
fn enforce_key_strength(algorithm: KeyAlgorithm, public_der: &[u8]) -> Result<()> {
    if !cfg!(feature = "fips") || algorithm != KeyAlgorithm::Rsa {
        return Ok(());
    }
    let bits = rsa_spki_modulus_bits(public_der)
        .ok_or_else(|| Error::Key("RSA key is not a valid SubjectPublicKeyInfo".into()))?;
    if bits < 2048 {
        return Err(Error::unsupported(
            Operation::KeyImport(algorithm),
            format!("{bits}-bit RSA key (kryptering requires at least 2048 bits)"),
        ));
    }
    Ok(())
}

/// Return the RSA modulus size from an RFC 5280 SubjectPublicKeyInfo.
pub(crate) fn rsa_spki_modulus_bits(spki_der: &[u8]) -> Option<usize> {
    fn take_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
        if input.first().copied()? != expected_tag {
            return None;
        }
        let first_len = *input.get(1)?;
        let (header_len, value_len) = if first_len & 0x80 == 0 {
            (2, usize::from(first_len))
        } else {
            let length_octets = usize::from(first_len & 0x7f);
            if length_octets == 0 || length_octets > std::mem::size_of::<usize>() {
                return None;
            }
            let mut value_len = 0usize;
            for byte in input.get(2..2 + length_octets)? {
                value_len = value_len
                    .checked_mul(256)?
                    .checked_add(usize::from(*byte))?;
            }
            (2 + length_octets, value_len)
        };
        let value_end = header_len.checked_add(value_len)?;
        Some((input.get(header_len..value_end)?, input.get(value_end..)?))
    }

    let (spki, trailing) = take_tlv(spki_der, 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (_, after_algorithm) = take_tlv(spki, 0x30)?;
    let (subject_public_key, trailing) = take_tlv(after_algorithm, 0x03)?;
    if !trailing.is_empty() || subject_public_key.first().copied()? != 0 {
        return None;
    }
    let (rsa_public_key, trailing) = take_tlv(&subject_public_key[1..], 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (modulus, _) = take_tlv(rsa_public_key, 0x02)?;
    let modulus = &modulus[modulus.iter().position(|byte| *byte != 0)?..];
    let first = *modulus.first()?;
    Some((modulus.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

fn validate_public(algorithm: KeyAlgorithm, public_der: &[u8]) -> Result<()> {
    use aws_lc_rs::signature::{self, ParsedPublicKey, VerificationAlgorithm};
    let verification: &'static dyn VerificationAlgorithm = match algorithm {
        KeyAlgorithm::Rsa => &signature::RSA_PKCS1_2048_8192_SHA256,
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P256) => &signature::ECDSA_P256_SHA256_FIXED,
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P384) => &signature::ECDSA_P384_SHA384_FIXED,
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P521) => &signature::ECDSA_P521_SHA512_FIXED,
        KeyAlgorithm::Ed25519 => &signature::ED25519,
        _ => {
            return Err(Error::unsupported(
                Operation::KeyImport(algorithm),
                "SPKI for requested key family",
            ))
        }
    };
    ParsedPublicKey::new(verification, public_der)
        .map(|_| ())
        .map_err(|err| Error::Key(format!("AWS-LC SPKI import failed: {err}")))
}

fn public_from_private(algorithm: KeyAlgorithm, private_der: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
    use aws_lc_rs::signature::{self, KeyPair};

    fn encode<K>(key: &K) -> Result<Vec<u8>>
    where
        K: KeyPair,
        K::PublicKey: AsDer<PublicKeyX509Der<'static>>,
    {
        let der: PublicKeyX509Der<'static> = key
            .public_key()
            .as_der()
            .map_err(|_| Error::Key("AWS-LC public-key derivation failed".into()))?;
        Ok(der.as_ref().to_vec())
    }

    match algorithm {
        KeyAlgorithm::Rsa => {
            let key = signature::RsaKeyPair::from_pkcs8(private_der)
                .map_err(|err| Error::Key(format!("AWS-LC RSA PKCS#8 import failed: {err}")))?;
            encode(&key)
        }
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P256) => {
            let key = signature::EcdsaKeyPair::from_private_key_der(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                private_der,
            )
            .map_err(|err| Error::Key(format!("AWS-LC P-256 PKCS#8 import failed: {err}")))?;
            encode(&key)
        }
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P384) => {
            let key = signature::EcdsaKeyPair::from_private_key_der(
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                private_der,
            )
            .map_err(|err| Error::Key(format!("AWS-LC P-384 PKCS#8 import failed: {err}")))?;
            encode(&key)
        }
        KeyAlgorithm::Ec(crate::algorithm::EcCurve::P521) => {
            let key = signature::EcdsaKeyPair::from_private_key_der(
                &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                private_der,
            )
            .map_err(|err| Error::Key(format!("AWS-LC P-521 PKCS#8 import failed: {err}")))?;
            encode(&key)
        }
        KeyAlgorithm::Ed25519 => {
            let key = signature::Ed25519KeyPair::from_pkcs8(private_der)
                .map_err(|err| Error::Key(format!("AWS-LC Ed25519 PKCS#8 import failed: {err}")))?;
            encode(&key)
        }
        _ => Err(Error::unsupported(
            Operation::KeyImport(algorithm),
            "PKCS#8 for requested key family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider without validated DH import must not retain unvalidated keys.
    #[test]
    fn dh_import_is_unsupported() {
        crate::backend::initialize_backend().unwrap();
        assert!(matches!(
            SoftwareKey::from_dh_parameters(&[23], &[4], Some(&[11]), Some(&[5]), &[12]),
            Err(Error::UnsupportedAlgorithm {
                operation: Operation::KeyImport(KeyAlgorithm::Dh),
                ..
            })
        ));
        assert!(!crate::backend::supports(Operation::KeyImport(KeyAlgorithm::Dh)).unwrap());
    }
}
