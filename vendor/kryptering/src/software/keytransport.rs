#![forbid(unsafe_code)]

//! RSA key transport (RSA-OAEP, optionally RSA PKCS#1 v1.5).

use crate::algorithm::{HashAlgorithm, KeyTransportAlgorithm, OaepConfig};
use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey, SoftwareKey};

/// Encrypt `key_data` using the specified RSA key transport algorithm.
///
/// An optional `label` may be provided for OAEP (the OAEPparams / label
/// value). The label is required to be valid UTF-8 — this is a limitation
/// of the underlying `rsa` 0.9 crate, which stores the label as `String`.
/// Non-UTF-8 labels are rejected with `Error::Crypto` rather than being
/// silently corrupted.
pub fn kt_encrypt(
    algorithm: KeyTransportAlgorithm,
    public_key: &SoftwareKey,
    key_data: &[u8],
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    require_supported(Operation::TransportEncrypt(algorithm))?;
    let public_key = match public_key.inner() {
        RustCryptoKey::Rsa { public, .. } => public,
        _ => return Err(Error::Key("RSA public key required".into())),
    };
    crate::key::enforce_rsa_min_bits(Operation::TransportEncrypt(algorithm), public_key)?;
    match algorithm {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => rsa_pkcs1_encrypt(public_key, key_data),
        KeyTransportAlgorithm::RsaOaep(config) => {
            rsa_oaep_encrypt(public_key, key_data, &config, label)
        }
    }
}

/// Decrypt `encrypted` using the specified RSA key transport algorithm.
///
/// An optional `label` may be provided for OAEP (must match the value used
/// during encryption). As with [`kt_encrypt`], the label must be valid
/// UTF-8; non-UTF-8 labels are rejected rather than silently corrupted.
pub fn kt_decrypt(
    algorithm: KeyTransportAlgorithm,
    private_key: &SoftwareKey,
    encrypted: &[u8],
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    require_supported(Operation::TransportDecrypt(algorithm))?;
    let private_key = match private_key.inner() {
        RustCryptoKey::Rsa {
            private: Some(private),
            public,
        } => {
            crate::key::enforce_rsa_min_bits(Operation::TransportDecrypt(algorithm), public)?;
            private
        }
        _ => return Err(Error::Key("RSA private key required".into())),
    };
    match algorithm {
        #[cfg(feature = "legacy")]
        KeyTransportAlgorithm::RsaPkcs1v15 => rsa_pkcs1_decrypt(private_key, encrypted),
        KeyTransportAlgorithm::RsaOaep(config) => {
            rsa_oaep_decrypt(private_key, encrypted, &config, label)
        }
    }
}

// ── RSA PKCS#1 v1.5 ─────────────────────────────────────────────────

#[cfg(feature = "legacy")]
fn rsa_pkcs1_encrypt(public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>> {
    use rsa::Pkcs1v15Encrypt;
    // rsa 0.9 requires rand_core 0.6's infallible CryptoRngCore here. OsRng
    // is the fork-safe, stateless choice documented in ADR 0001.
    let mut rng = rand::rngs::OsRng;
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, key_data)
        .map_err(|e| Error::Crypto(format!("RSA PKCS#1 encrypt: {e}")))
}

#[cfg(feature = "legacy")]
fn rsa_pkcs1_decrypt(private_key: &rsa::RsaPrivateKey, encrypted: &[u8]) -> Result<Vec<u8>> {
    use rsa::Pkcs1v15Encrypt;
    private_key
        .decrypt(Pkcs1v15Encrypt, encrypted)
        .map_err(|e| Error::Crypto(format!("RSA PKCS#1 decrypt: {e}")))
}

// ── RSA-OAEP ────────────────────────────────────────────────────────

/// Convert an OAEP label from bytes to the `Option<String>` form that the
/// underlying `rsa` 0.9 crate requires.
///
/// RFC 8017 defines the OAEP label as an arbitrary octet string. The
/// upstream `rsa::Oaep` API currently stores it as `Option<String>`, so
/// this helper requires valid UTF-8. An earlier version used
/// `String::from_utf8_lossy` here, which silently replaced non-UTF-8
/// bytes with U+FFFD; two distinct binary labels could then collide
/// after lossy conversion, defeating OAEP's domain-separation guarantee.
fn oaep_label(label: Option<&[u8]>) -> Result<Option<String>> {
    match label {
        Some(bytes) => {
            let s = std::str::from_utf8(bytes).map_err(|e| {
                Error::Crypto(format!(
                    "RSA-OAEP label must be valid UTF-8 (rsa 0.9 limitation): {e}"
                ))
            })?;
            Ok(Some(s.to_owned()))
        }
        None => Ok(None),
    }
}

/// Inner encrypt macro: creates an OAEP padding scheme from concrete types.
macro_rules! oaep_encrypt {
    ($public_key:expr, $key_data:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let label = oaep_label($label)?;
        // rsa 0.9 requires rand_core 0.6's infallible CryptoRngCore here.
        // OsRng is fork-safe and holds no process-local PRNG state.
        let mut rng = rand::rngs::OsRng;
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        padding.label = label;
        $public_key
            .encrypt(&mut rng, padding, $key_data)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP encrypt: {e}")))
    }};
}

/// Inner decrypt macro: creates an OAEP padding scheme from concrete types.
macro_rules! oaep_decrypt {
    ($private_key:expr, $encrypted:expr, $digest:ty, $mgf:ty, $label:expr) => {{
        use rsa::Oaep;
        let label = oaep_label($label)?;
        let mut padding = Oaep::new_with_mgf_hash::<$digest, $mgf>();
        padding.label = label;
        $private_key
            .decrypt(padding, $encrypted)
            .map_err(|e| Error::Crypto(format!("RSA-OAEP decrypt: {e}")))
    }};
}

/// Dispatch OAEP encrypt for a given (digest, mgf_digest) pair.
///
/// Unsupported hashes (notably the SHA-3 family) return an error. An earlier
/// version silently fell back to SHA-1 here, which meant a caller selecting
/// `HashAlgorithm::Sha3_256` for either the OAEP digest or the MGF1 hash
/// would get SHA-1 OAEP without any warning.
macro_rules! oaep_dispatch_encrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    HashAlgorithm::Sha1 => oaep_encrypt!($pk, $data, $d, sha1::Sha1, $label),
                    HashAlgorithm::Sha224 => oaep_encrypt!($pk, $data, $d, sha2::Sha224, $label),
                    HashAlgorithm::Sha256 => oaep_encrypt!($pk, $data, $d, sha2::Sha256, $label),
                    HashAlgorithm::Sha384 => oaep_encrypt!($pk, $data, $d, sha2::Sha384, $label),
                    HashAlgorithm::Sha512 => oaep_encrypt!($pk, $data, $d, sha2::Sha512, $label),
                    other => Err(Error::unsupported(
                        Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(OaepConfig {
                            digest: $digest,
                            mgf_digest: $mgf,
                        })),
                        format!("RSA-OAEP MGF1 with {other:?} is not supported"),
                    )),
                }
            };
        }
        match $digest {
            HashAlgorithm::Sha1 => with_mgf!(sha1::Sha1),
            HashAlgorithm::Sha224 => with_mgf!(sha2::Sha224),
            HashAlgorithm::Sha256 => with_mgf!(sha2::Sha256),
            HashAlgorithm::Sha384 => with_mgf!(sha2::Sha384),
            HashAlgorithm::Sha512 => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => with_mgf!(ripemd::Ripemd160),
            other => Err(Error::unsupported(
                Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(OaepConfig {
                    digest: $digest,
                    mgf_digest: $mgf,
                })),
                format!("RSA-OAEP digest {other:?} is not supported"),
            )),
        }
    }};
}

/// Dispatch OAEP decrypt for a given (digest, mgf_digest) pair.
///
/// See [`oaep_dispatch_encrypt`]. The decrypt path errors on the same set of
/// unsupported hashes so that a caller cannot accidentally decrypt SHA-1
/// OAEP ciphertexts while believing they asked for SHA-3.
macro_rules! oaep_dispatch_decrypt {
    ($pk:expr, $data:expr, $digest:expr, $mgf:expr, $label:expr) => {{
        macro_rules! with_mgf {
            ($d:ty) => {
                match $mgf {
                    HashAlgorithm::Sha1 => oaep_decrypt!($pk, $data, $d, sha1::Sha1, $label),
                    HashAlgorithm::Sha224 => oaep_decrypt!($pk, $data, $d, sha2::Sha224, $label),
                    HashAlgorithm::Sha256 => oaep_decrypt!($pk, $data, $d, sha2::Sha256, $label),
                    HashAlgorithm::Sha384 => oaep_decrypt!($pk, $data, $d, sha2::Sha384, $label),
                    HashAlgorithm::Sha512 => oaep_decrypt!($pk, $data, $d, sha2::Sha512, $label),
                    other => Err(Error::unsupported(
                        Operation::TransportDecrypt(KeyTransportAlgorithm::RsaOaep(OaepConfig {
                            digest: $digest,
                            mgf_digest: $mgf,
                        })),
                        format!("RSA-OAEP MGF1 with {other:?} is not supported"),
                    )),
                }
            };
        }
        match $digest {
            HashAlgorithm::Sha1 => with_mgf!(sha1::Sha1),
            HashAlgorithm::Sha224 => with_mgf!(sha2::Sha224),
            HashAlgorithm::Sha256 => with_mgf!(sha2::Sha256),
            HashAlgorithm::Sha384 => with_mgf!(sha2::Sha384),
            HashAlgorithm::Sha512 => with_mgf!(sha2::Sha512),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Md5 => with_mgf!(md5::Md5),
            #[cfg(feature = "legacy")]
            HashAlgorithm::Ripemd160 => with_mgf!(ripemd::Ripemd160),
            other => Err(Error::unsupported(
                Operation::TransportDecrypt(KeyTransportAlgorithm::RsaOaep(OaepConfig {
                    digest: $digest,
                    mgf_digest: $mgf,
                })),
                format!("RSA-OAEP digest {other:?} is not supported"),
            )),
        }
    }};
}

fn rsa_oaep_encrypt(
    public_key: &rsa::RsaPublicKey,
    key_data: &[u8],
    config: &OaepConfig,
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    oaep_dispatch_encrypt!(
        public_key,
        key_data,
        config.digest,
        config.mgf_digest,
        label
    )
}

fn rsa_oaep_decrypt(
    private_key: &rsa::RsaPrivateKey,
    encrypted: &[u8],
    config: &OaepConfig,
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    oaep_dispatch_decrypt!(
        private_key,
        encrypted,
        config.digest,
        config.mgf_digest,
        label
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    fn test_keypair() -> (SoftwareKey, SoftwareKey) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public = SoftwareKey::from_spki_der(
            crate::backend::KeyAlgorithm::Rsa,
            public_key.to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap();
        let private = SoftwareKey::from_pkcs8_der(
            crate::backend::KeyAlgorithm::Rsa,
            private_key.to_pkcs8_der().unwrap().as_bytes(),
        )
        .unwrap();
        (public, private)
    }

    #[test]
    fn test_rsa_oaep_sha1_roundtrip() {
        // SHA-1 OAEP is still supported for XML-Enc 1.0 `rsa-oaep-mgf1p`
        // interop, but callers must now opt in explicitly — the default
        // moved to SHA-256. Construct the config literally so this test
        // actually exercises the SHA-1 path regardless of future default
        // changes.
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        });
        let key_data = b"16-byte-key!!!!"; // 15 bytes

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[cfg(not(feature = "legacy"))]
    #[test]
    fn rejects_rsa_keys_below_2048_bits() {
        // Import accepts these keys; transport must enforce the size floor
        // even for a key built internally.
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let public = private.to_public_key();
        let key = SoftwareKey::from(RustCryptoKey::Rsa {
            private: Some(private),
            public,
        });
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let err = kt_encrypt(algo, &key, &[0x42; 16], None).unwrap_err();
        assert!(err.to_string().contains("1024-bit RSA key"), "{err}");
        let err = kt_decrypt(algo, &key, &[0u8; 128], None).unwrap_err();
        assert!(err.to_string().contains("1024-bit RSA key"), "{err}");
    }

    #[test]
    fn test_oaep_default_is_sha256() {
        // Pins the new default so it cannot silently regress to SHA-1.
        let cfg = OaepConfig::default();
        assert_eq!(cfg.digest, HashAlgorithm::Sha256);
        assert_eq!(cfg.mgf_digest, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_rsa_oaep_sha256_roundtrip() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        let key_data = [0x42u8; 32];

        let encrypted = kt_encrypt(algo, &pub_key, &key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_with_label() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let key_data = b"secret key data!";
        let label = b"my-label";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, Some(label)).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, Some(label)).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_wrong_key_fails() {
        let (pub_key, _priv_key) = test_keypair();
        let (_pub_key2, priv_key2) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
        let key_data = b"secret key data!";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let result = kt_decrypt(algo, &priv_key2, &encrypted, None);
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[test]
    fn test_rsa_oaep_mixed_digests() {
        let (pub_key, priv_key) = test_keypair();
        // SHA-256 digest with SHA-1 MGF (common in XML Encryption 1.0 style)
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha1,
        });
        let key_data = [0xAB; 24];

        let encrypted = kt_encrypt(algo, &pub_key, &key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }

    #[test]
    fn test_rsa_oaep_rejects_non_utf8_label() {
        // An earlier version ran the label through String::from_utf8_lossy,
        // which silently corrupted non-UTF-8 bytes into U+FFFD and let two
        // distinct binary labels collide. This test pins the new rejection
        // behaviour on both encrypt and decrypt paths.
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        // 0xFF is never valid UTF-8.
        let bad_label: &[u8] = &[0xFF, 0xFE, 0xFD];
        let err = kt_encrypt(algo, &pub_key, b"k", Some(bad_label)).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(ref m) if m.contains("UTF-8")),
            "got {err:?}"
        );

        // Produce a valid ciphertext with a valid label, then try to decrypt
        // it while passing a non-UTF-8 label -- the label check must trip
        // before the decryption path even runs.
        let ct = kt_encrypt(algo, &pub_key, b"k", Some(b"good")).unwrap();
        let err = kt_decrypt(algo, &priv_key, &ct, Some(bad_label)).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(ref m) if m.contains("UTF-8")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_rsa_oaep_label_roundtrip_exact_bytes() {
        // Confirm that a UTF-8 label survives encrypt/decrypt byte-for-byte
        // (this would have failed silently when from_utf8_lossy was used
        // with a label that contained e.g. the 4-byte replacement sequence
        // for an invalid codepoint).
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        let label = "utf8-label-\u{1F600}-end".as_bytes();
        let ct = kt_encrypt(algo, &pub_key, b"k", Some(label)).unwrap();
        let pt = kt_decrypt(algo, &priv_key, &ct, Some(label)).unwrap();
        assert_eq!(pt, b"k");

        // A different label must fail to decrypt (sanity: the label is
        // actually participating in the OAEP construction).
        let err = kt_decrypt(algo, &priv_key, &ct, Some(b"other")).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn test_rsa_oaep_rejects_sha3_digest() {
        // SHA-3 is not defined for OAEP in RFC 8017 and an earlier version
        // of the dispatch silently fell back to SHA-1. This test pins the
        // new error behaviour on both encrypt and decrypt paths.
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha3_256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        let err = kt_encrypt(algo, &pub_key, b"k", None).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { .. }),
            "got {err:?}"
        );

        // Produce a ciphertext with a supported digest so we can try to
        // decrypt it back with an unsupported one.
        let good = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        });
        let ct = kt_encrypt(good, &pub_key, b"k", None).unwrap();
        let err = kt_decrypt(algo, &priv_key, &ct, None).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_rsa_oaep_rejects_sha3_mgf() {
        let (pub_key, _priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha3_256,
        });
        let err = kt_encrypt(algo, &pub_key, b"k", None).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm { .. }),
            "got {err:?}"
        );
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn test_rsa_pkcs1v15_roundtrip() {
        let (pub_key, priv_key) = test_keypair();
        let algo = KeyTransportAlgorithm::RsaPkcs1v15;
        let key_data = b"a 24 byte key here!!!!!";

        let encrypted = kt_encrypt(algo, &pub_key, key_data, None).unwrap();
        let decrypted = kt_decrypt(algo, &priv_key, &encrypted, None).unwrap();
        assert_eq!(decrypted, key_data);
    }
}
