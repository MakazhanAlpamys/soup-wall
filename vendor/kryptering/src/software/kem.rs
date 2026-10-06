//! ML-KEM (FIPS 203) key encapsulation, software backend.
//!
//! `SoftwareEncapsulator` and `SoftwareDecapsulator` implement the
//! [`Encapsulator`](crate::traits::Encapsulator) and
//! [`Decapsulator`](crate::traits::Decapsulator) traits from `crate::traits`,
//! holding both the ML-KEM variant and key material.
//!
//! # Key format
//!
//! Keys are exposed through the opaque [`crate::SoftwareKey`] handle. The
//! public (encapsulation) key is stored as SPKI DER, and the private
//! (decapsulation) key is stored as the 64-byte FIPS 203 seed (`d || z`).
//! Loaders also accept a PKCS#8 DER document (the LAMPS seed-only `[0]`
//! CHOICE form) in `private_der` — the same convention as ML-DSA in
//! `crate::software::sign`.
//!
//! # Implicit rejection
//!
//! ML-KEM decapsulation never fails for a well-sized ciphertext: a tampered
//! ciphertext yields a pseudorandom secret derived from the key's rejection
//! value `z` (FIPS 203 §7.3), in constant time. Callers must not expect an
//! error to signal tampering — the mismatch surfaces later when the derived
//! keys disagree.
//!
//! # Randomness and secret hygiene
//!
//! Key generation and encapsulation draw entropy via [`getrandom::fill`]
//! so OS-RNG failure surfaces as [`Error::Crypto`] instead of a panic (see
//! `docs/adr/0001-rng-choice.md`). Returned shared secrets are wrapped in
//! [`Zeroizing`] so they are wiped on drop; borrow (`&secret`) when deriving
//! keys rather than moving the bytes out of the wrapper.

use crate::algorithm::{KemAlgorithm, MlKemVariant, PqAlgorithm};
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey as SoftwareKey, SoftwareKey as OpaqueSoftwareKey};
use crate::traits;
use zeroize::Zeroizing;

// ── ML-KEM parameter-set dispatch macro ─────────────────────────────
//
// ml-kem's `KemParams` trait lives in a private module, so generic helper
// functions cannot name its bound. Dispatch to a callback macro with the
// concrete parameter-set type instead (same pattern as `dispatch_hash!` in
// `crate::software::sign`).
macro_rules! dispatch_ml_kem {
    ($variant:expr, $callback:ident) => {
        match $variant {
            MlKemVariant::MlKem512 => $callback!(ml_kem::MlKem512),
            MlKemVariant::MlKem768 => $callback!(ml_kem::MlKem768),
            MlKemVariant::MlKem1024 => $callback!(ml_kem::MlKem1024),
        }
    };
}

// ── SoftwareEncapsulator ────────────────────────────────────────────

/// Software-backed KEM encapsulator holding an ML-KEM public key.
pub struct SoftwareEncapsulator {
    variant: MlKemVariant,
    key: OpaqueSoftwareKey,
}

impl SoftwareEncapsulator {
    /// Create a new encapsulator for `variant`.
    ///
    /// The key must contain post-quantum key material with a matching
    /// [`PqAlgorithm::MlKem`] algorithm; anything else returns
    /// [`Error::Key`]. A public-only key (no `private_der`) is sufficient.
    pub fn new<K: Into<OpaqueSoftwareKey>>(variant: MlKemVariant, key: K) -> Result<Self> {
        let key = key.into();
        validate_ml_kem_key(variant, key.inner(), false)?;
        Ok(Self { variant, key })
    }
}

impl traits::Encapsulator for SoftwareEncapsulator {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::MlKem(self.variant)
    }

    fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let SoftwareKey::PostQuantum { public_der, .. } = self.key.inner() else {
            // validate_ml_kem_key enforced this in `new`.
            return Err(Error::Key("ML-KEM key required".into()));
        };
        ml_kem_encapsulate(self.variant, public_der)
    }
}

// ── SoftwareDecapsulator ────────────────────────────────────────────

/// Software-backed KEM decapsulator holding an ML-KEM private key.
pub struct SoftwareDecapsulator {
    variant: MlKemVariant,
    key: OpaqueSoftwareKey,
}

impl SoftwareDecapsulator {
    /// Create a new decapsulator for `variant`.
    ///
    /// The key must contain post-quantum key material with a matching
    /// [`PqAlgorithm::MlKem`] algorithm and private key material present;
    /// anything else returns [`Error::Key`].
    pub fn new<K: Into<OpaqueSoftwareKey>>(variant: MlKemVariant, key: K) -> Result<Self> {
        let key = key.into();
        validate_ml_kem_key(variant, key.inner(), true)?;
        Ok(Self { variant, key })
    }
}

impl traits::Decapsulator for SoftwareDecapsulator {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::MlKem(self.variant)
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let SoftwareKey::PostQuantum {
            private_der: Some(private),
            ..
        } = self.key.inner()
        else {
            // validate_ml_kem_key enforced this in `new`.
            return Err(Error::Key("ML-KEM private key required".into()));
        };
        ml_kem_decapsulate(self.variant, private, ciphertext)
    }
}

// ── Key validation ──────────────────────────────────────────────────

/// Validate that `key` is an ML-KEM key of the expected variant, and (when
/// `require_private`) that private key material is present.
fn validate_ml_kem_key(
    variant: MlKemVariant,
    key: &SoftwareKey,
    require_private: bool,
) -> Result<()> {
    let SoftwareKey::PostQuantum {
        algorithm,
        private_der,
        ..
    } = key
    else {
        return Err(Error::Key(format!(
            "{} requires a post-quantum ML-KEM key",
            variant.name()
        )));
    };
    let expected = PqAlgorithm::MlKem(variant);
    if *algorithm != expected {
        return Err(Error::Key(format!(
            "key algorithm {} does not match requested {}",
            algorithm.name(),
            variant.name()
        )));
    }
    if require_private && private_der.is_none() {
        return Err(Error::Key(format!(
            "{} private key required for decapsulation",
            variant.name()
        )));
    }
    Ok(())
}

// ── Encapsulation / decapsulation ───────────────────────────────────

/// Encapsulate to an SPKI-DER encapsulation key, returning
/// `(ciphertext, shared_secret)`.
fn ml_kem_encapsulate(
    variant: MlKemVariant,
    public_der: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use pkcs8_pq::DecodePublicKey;
    use zeroize::Zeroize;

    macro_rules! encapsulate_with {
        ($params:ty) => {{
            let ek = ml_kem::EncapsulationKey::<$params>::from_public_key_der(public_der)
                .map_err(|e| Error::Key(format!("failed to parse ML-KEM public key: {e}")))?;
            // FIPS 203 Algorithm 20: m <-$ B^32, then ML-KEM.Encaps_internal.
            // `encapsulate_deterministic` with fresh OS entropy is exactly the
            // body of `kem::Encapsulate::encapsulate_with_rng`; we call it
            // directly because the kem 0.3 trait only accepts an infallible
            // CryptoRng and OS-RNG failure must surface as Error::Crypto, not
            // a panic (ADR 0001). `m` must be fresh on every call and never
            // reused — it is wiped below as soon as it has been consumed.
            let mut m = ml_kem::B32::default();
            if let Err(e) = getrandom::fill(m.as_mut_slice()) {
                m.as_mut_slice().zeroize();
                return Err(Error::Crypto(format!("OS entropy draw failed: {e}")));
            }
            let (ct, mut ss) = ek.encapsulate_deterministic(&m);
            m.as_mut_slice().zeroize();
            let shared = Zeroizing::new(ss.as_slice().to_vec());
            ss.as_mut_slice().zeroize();
            Ok((ct.as_slice().to_vec(), shared))
        }};
    }
    dispatch_ml_kem!(variant, encapsulate_with)
}

/// Load an ML-KEM decapsulation key from either PKCS#8 DER (the LAMPS
/// seed-only `[0]` CHOICE form) or a raw 64-byte FIPS 203 seed.
///
/// A macro rather than a generic fn because ml-kem's `KemParams` bound is
/// not publicly nameable. Expands to an expression; `return`s an
/// [`Error::Key`] from the enclosing function on parse failure.
macro_rules! load_ml_kem_decapsulation_key {
    ($params:ty, $private_der:expr) => {{
        use pkcs8_pq::DecodePrivateKey;
        let private_der: &[u8] = $private_der;
        if let Ok(dk) = ml_kem::DecapsulationKey::<$params>::from_pkcs8_der(private_der) {
            dk
        } else if private_der.len() == 64 {
            let seed = ml_kem::Seed::try_from(private_der)
                .map_err(|_| Error::Key("invalid ML-KEM seed length".into()))?;
            ml_kem::DecapsulationKey::<$params>::from_seed(seed)
        } else {
            return Err(Error::Key(format!(
                "failed to parse ML-KEM private key: expected PKCS#8 DER or 64-byte seed, got {} bytes",
                private_der.len()
            )));
        }
    }};
}

/// Decapsulate a ciphertext with a private key held as either a 64-byte
/// FIPS 203 seed or PKCS#8 DER, returning the 32-byte shared secret.
fn ml_kem_decapsulate(
    variant: MlKemVariant,
    private_der: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use ml_kem::Decapsulate;
    use zeroize::Zeroize;

    // Length check up front for a precise error; past this point
    // decapsulation cannot fail (implicit rejection, see module docs).
    if ciphertext.len() != variant.ciphertext_len() {
        return Err(Error::Crypto(format!(
            "invalid ML-KEM ciphertext length: expected {} bytes for {}, got {}",
            variant.ciphertext_len(),
            variant.name(),
            ciphertext.len()
        )));
    }

    macro_rules! decapsulate_with {
        ($params:ty) => {{
            let dk = load_ml_kem_decapsulation_key!($params, private_der);
            // Implicit rejection (FIPS 203 §7.3): a well-sized but invalid
            // ciphertext yields a pseudorandom z-derived secret in constant
            // time. Do NOT branch on or surface rejection here.
            // The length was validated above, so this error path should be
            // unreachable; if it ever fires, report it as the internal
            // failure it is rather than a misleading length complaint.
            let mut ss = dk.decapsulate_slice(ciphertext).map_err(|_| {
                Error::Crypto(format!(
                    "unexpected {} decapsulation failure",
                    variant.name()
                ))
            })?;
            let shared = Zeroizing::new(ss.as_slice().to_vec());
            ss.as_mut_slice().zeroize();
            Ok(shared)
        }};
    }
    dispatch_ml_kem!(variant, decapsulate_with)
}

/// Validate ML-KEM key encodings during import: the SPKI must parse, and
/// when a private key is present the encapsulation key derived from it must
/// equal the imported one.
pub(crate) fn validate_import(
    variant: MlKemVariant,
    private_der: Option<&[u8]>,
    public_der: &[u8],
) -> Result<()> {
    use pkcs8_pq::DecodePublicKey;

    macro_rules! validate_with {
        ($params:ty) => {{
            let ek = ml_kem::EncapsulationKey::<$params>::from_public_key_der(public_der)
                .map_err(|e| Error::Key(format!("failed to parse ML-KEM public key: {e}")))?;
            match private_der {
                Some(private_der) => {
                    let dk = load_ml_kem_decapsulation_key!($params, private_der);
                    dk.encapsulation_key() == &ek
                }
                None => true,
            }
        }};
    }
    if !dispatch_ml_kem!(variant, validate_with) {
        return Err(Error::Key(format!(
            "{} public key does not match the private key",
            variant.name()
        )));
    }
    Ok(())
}

// ── Key generation ──────────────────────────────────────────────────

/// Generate a fresh ML-KEM key pair for `variant`.
///
/// Returns an opaque [`crate::SoftwareKey`] whose private export holds the
/// 64-byte FIPS 203 seed (`d || z`) and whose `public_der` holds the
/// encapsulation key as SPKI DER.
///
/// Entropy comes from [`getrandom::fill`]; an OS-RNG failure returns
/// [`Error::Crypto`] rather than panicking (see
/// `docs/adr/0001-rng-choice.md`).
///
/// Zeroization: the stack-resident 64-byte seed buffer is wiped
/// immediately after it is copied into `private_der`. The heap-resident
/// private material is either moved into the returned [`crate::SoftwareKey`]
/// (whose custom [`Drop`] plus `ZeroizeOnDrop` marker wipe the seed on
/// drop) or, on any error return below, wiped explicitly before the
/// error propagates — so the seed does not linger in any allocation on
/// either exit path.
pub fn generate_ml_kem(variant: MlKemVariant) -> Result<OpaqueSoftwareKey> {
    use pkcs8_pq::spki::EncodePublicKey;
    use zeroize::Zeroize;

    let mut seed_bytes = [0u8; 64];
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

    macro_rules! encode_public {
        ($params:ty) => {{
            let seed = ml_kem::Seed::try_from(private_der.as_slice())
                .map_err(|e| Error::Crypto(format!("ML-KEM seed construction failed: {e}")))?;
            // `dk` wipes its internal d/z on drop (ml-kem `zeroize` feature).
            let dk = ml_kem::DecapsulationKey::<$params>::from_seed(seed);
            let der = dk
                .encapsulation_key()
                .to_public_key_der()
                .map_err(|e| Error::Crypto(format!("ML-KEM SPKI encode: {e}")))?;
            Ok(der.as_bytes().to_vec())
        }};
    }
    let build = || -> Result<Vec<u8>> { dispatch_ml_kem!(variant, encode_public) };
    let public_der = match build() {
        Ok(der) => der,
        Err(e) => {
            private_der.zeroize();
            return Err(e);
        }
    };

    Ok(SoftwareKey::PostQuantum {
        algorithm: PqAlgorithm::MlKem(variant),
        private_der: Some(private_der),
        public_der,
    }
    .into())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decapsulator as _, Encapsulator as _};

    /// `SoftwareKey` is intentionally not `Clone` (Drop wipes secrets), so
    /// tests rebuild PQ keys by hand, optionally dropping the private half.
    fn clone_pq_key(key: &SoftwareKey, with_private: bool) -> SoftwareKey {
        let SoftwareKey::PostQuantum {
            algorithm,
            private_der,
            public_der,
        } = key
        else {
            panic!("not a post-quantum key");
        };
        SoftwareKey::PostQuantum {
            algorithm: *algorithm,
            private_der: if with_private {
                private_der.clone()
            } else {
                None
            },
            public_der: public_der.clone(),
        }
    }

    fn roundtrip(variant: MlKemVariant) {
        let key = generate_ml_kem(variant).expect("keygen");
        let public_only = clone_pq_key(key.inner(), false);

        let encapsulator =
            SoftwareEncapsulator::new(variant, public_only).expect("encapsulator creation");
        let (ciphertext, secret_a) = encapsulator.encapsulate().expect("encapsulate");
        assert_eq!(ciphertext.len(), variant.ciphertext_len());
        assert_eq!(secret_a.len(), variant.shared_secret_len());

        let decapsulator = SoftwareDecapsulator::new(variant, key).expect("decapsulator creation");
        let secret_b = decapsulator.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(secret_a, secret_b, "{} secrets must match", variant.name());
    }

    #[test]
    fn ml_kem_512_roundtrip() {
        roundtrip(MlKemVariant::MlKem512);
    }

    #[test]
    fn ml_kem_768_roundtrip() {
        roundtrip(MlKemVariant::MlKem768);
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        roundtrip(MlKemVariant::MlKem1024);
    }

    #[test]
    fn generate_ml_kem_key_shape() {
        use pkcs8_pq::DecodePublicKey;
        for variant in [
            MlKemVariant::MlKem512,
            MlKemVariant::MlKem768,
            MlKemVariant::MlKem1024,
        ] {
            let key = generate_ml_kem(variant).expect("keygen");
            let SoftwareKey::PostQuantum {
                algorithm,
                private_der,
                public_der,
            } = key.inner()
            else {
                panic!("expected PostQuantum key");
            };
            assert_eq!(*algorithm, PqAlgorithm::MlKem(variant));
            assert_eq!(
                private_der.as_ref().map(Vec::len),
                Some(64),
                "{} private key must be the 64-byte FIPS 203 seed",
                variant.name()
            );
            // The SPKI must parse back into an encapsulation key.
            match variant {
                MlKemVariant::MlKem512 => {
                    ml_kem::EncapsulationKey::<ml_kem::MlKem512>::from_public_key_der(public_der)
                        .expect("SPKI parses");
                }
                MlKemVariant::MlKem768 => {
                    ml_kem::EncapsulationKey::<ml_kem::MlKem768>::from_public_key_der(public_der)
                        .expect("SPKI parses");
                }
                MlKemVariant::MlKem1024 => {
                    ml_kem::EncapsulationKey::<ml_kem::MlKem1024>::from_public_key_der(public_der)
                        .expect("SPKI parses");
                }
            }
        }
    }

    /// RNG smoke test: two generations must not produce the same seed.
    #[test]
    fn generate_ml_kem_seeds_are_unique() {
        let a = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let b = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let seed = |k: &OpaqueSoftwareKey| -> Vec<u8> {
            let SoftwareKey::PostQuantum {
                private_der: Some(s),
                ..
            } = k.inner()
            else {
                panic!("expected private key");
            };
            s.clone()
        };
        assert_ne!(seed(&a), seed(&b), "seeds must be unique across keygens");
    }

    /// Regression lock on the fresh-`m` construction: if a refactor ever
    /// fixes or reuses the FIPS 203 message `m`, repeated encapsulations
    /// would collide and this test fails.
    #[test]
    fn encapsulation_is_randomized() {
        let key = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let encapsulator =
            SoftwareEncapsulator::new(MlKemVariant::MlKem768, key).expect("encapsulator creation");
        let (ct1, ss1) = encapsulator.encapsulate().expect("encapsulate");
        let (ct2, ss2) = encapsulator.encapsulate().expect("encapsulate");
        assert_ne!(ct1, ct2, "ciphertexts must differ across encapsulations");
        assert_ne!(ss1, ss2, "secrets must differ across encapsulations");
    }

    /// FIPS 203 §7.3 implicit rejection: a tampered but well-sized
    /// ciphertext decapsulates to `Ok` with a stable pseudorandom secret
    /// derived from `z` — never an error, and never the true secret.
    #[test]
    fn implicit_rejection_yields_stable_pseudorandom_secret() {
        let key = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let encapsulator =
            SoftwareEncapsulator::new(MlKemVariant::MlKem768, clone_pq_key(key.inner(), false))
                .expect("encapsulator creation");
        let (mut ciphertext, true_secret) = encapsulator.encapsulate().expect("encapsulate");
        ciphertext[0] ^= 0x01;

        let decapsulator =
            SoftwareDecapsulator::new(MlKemVariant::MlKem768, key).expect("decapsulator creation");
        let rejected_a = decapsulator
            .decapsulate(&ciphertext)
            .expect("implicit rejection must still return Ok");
        assert_eq!(rejected_a.len(), 32);
        assert_ne!(
            rejected_a, true_secret,
            "tampered ciphertext must not yield the true secret"
        );
        let rejected_b = decapsulator.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(
            rejected_a, rejected_b,
            "implicit-rejection secret must be deterministic (z-derived), not noise"
        );
    }

    #[test]
    fn decapsulate_rejects_wrong_ciphertext_length() {
        let key = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let decapsulator =
            SoftwareDecapsulator::new(MlKemVariant::MlKem768, key).expect("decapsulator creation");
        let err = decapsulator
            .decapsulate(&[0u8; 10])
            .expect_err("short ciphertext must be rejected");
        assert!(
            matches!(&err, Error::Crypto(msg) if msg.contains("ciphertext length")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn constructors_reject_mismatched_keys() {
        use crate::algorithm::{MlDsaVariant, SignatureAlgorithm};
        use crate::software::sign::{generate_ml_dsa, SoftwareSigner};

        // An ML-DSA key is a PostQuantum key, but not an ML-KEM one.
        let ml_dsa_key = generate_ml_dsa(MlDsaVariant::MlDsa44).expect("ML-DSA keygen");
        assert!(matches!(
            SoftwareDecapsulator::new(MlKemVariant::MlKem768, ml_dsa_key),
            Err(Error::Key(_))
        ));

        // Variant mismatch within ML-KEM.
        let kem_key = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        assert!(matches!(
            SoftwareEncapsulator::new(MlKemVariant::MlKem512, clone_pq_key(kem_key.inner(), true)),
            Err(Error::Key(_))
        ));

        // Decapsulation requires private key material; encapsulation does not.
        let public_only = clone_pq_key(kem_key.inner(), false);
        assert!(matches!(
            SoftwareDecapsulator::new(MlKemVariant::MlKem768, public_only),
            Err(Error::Key(_))
        ));
        assert!(SoftwareEncapsulator::new(
            MlKemVariant::MlKem768,
            clone_pq_key(kem_key.inner(), false)
        )
        .is_ok());

        // Guard the PqAlgorithm reuse: an ML-KEM key must not be accepted
        // by the signature constructors.
        assert!(matches!(
            SoftwareSigner::new(SignatureAlgorithm::MlDsa(MlDsaVariant::MlDsa44), kem_key),
            Err(Error::Key(_))
        ));

        // A non-PQ key is rejected outright.
        assert!(matches!(
            SoftwareEncapsulator::new(MlKemVariant::MlKem768, SoftwareKey::Aes(vec![0u8; 32])),
            Err(Error::Key(_))
        ));
    }

    /// The private key may also arrive as PKCS#8 DER (seed-only `[0]` form);
    /// exercise the loader's DER branch end-to-end.
    #[test]
    fn decapsulates_with_pkcs8_der_private_key() {
        use pkcs8_pq::EncodePrivateKey;

        let key = generate_ml_kem(MlKemVariant::MlKem768).expect("keygen");
        let SoftwareKey::PostQuantum {
            private_der: Some(seed_bytes),
            public_der,
            ..
        } = key.inner()
        else {
            panic!("expected private key");
        };
        let seed = ml_kem::Seed::try_from(seed_bytes.as_slice()).expect("64-byte seed");
        let pkcs8_der = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed)
            .to_pkcs8_der()
            .expect("PKCS#8 encode")
            .as_bytes()
            .to_vec();
        let pkcs8_key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlKem(MlKemVariant::MlKem768),
            private_der: Some(pkcs8_der),
            public_der: public_der.clone(),
        };

        let encapsulator =
            SoftwareEncapsulator::new(MlKemVariant::MlKem768, key).expect("encapsulator creation");
        let (ciphertext, secret_a) = encapsulator.encapsulate().expect("encapsulate");
        let decapsulator = SoftwareDecapsulator::new(MlKemVariant::MlKem768, pkcs8_key)
            .expect("decapsulator creation");
        let secret_b = decapsulator.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(secret_a, secret_b);
    }

    // ── NIST ACVP known-answer tests ────────────────────────────────
    //
    // Vectors from usnistgov/ACVP-Server gen-val JSON files
    // (ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203,
    // internalProjection.json), first test case of each group.

    const ACVP_KEYGEN_512_D: &str =
        "47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a";
    const ACVP_KEYGEN_512_Z: &str =
        "1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9";
    const ACVP_KEYGEN_512_EK: &str = "28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9819eb63577891f7bb9cb98413ccc434adc79a16d6ab3076569ce6291c59b5d64612a7fb0c15013200bc8bebb03a570174b5e4363aed86eb02a220d281fb5457f0a549fc5051d49a6b2015259a2c3084f405e1769952260675586a584904059275a265234ef3abf88c171a80898fc783358bbc9803c8789027d917c9ebacbc568cc18de84c85454b94249586c0c6e2b8a16fa789c51212dd1728ee9b8c6c40528bf93826fa82368419623032af27b5694305816811d3ca85805100e9c1a9621e5089e54cb47f5a8fea0b49ef81c6b5187f48924c7947d6b61697a4a8a18452ef803336ad4be503275bcacc03c181405f7b1dc9b47fb169eb37bbe27e29c763a4e52b9a42520388cf09b8edbcdf41ccf6537190e6156c37cc1aac63c0f90ce78d0b9b190c548d71b6f26cc8f585ea14004b5b30aaa100b2adc1263828833b24e46163b41446f98c882092a39941867b80632e2097674a793935227db0b8577e03a69c50a514c7473c892e3fba7c4316bdabc952a70644176687d4191323bad93d85a3ca250868c0747e6c44f6126c874afbec0bdd4503cb2c59a69816e7d4109941467579a1ffe6a4f50fa379051729dab6e2f61432f15be67d667c7cc1054742b2b953078a5cf88d9133087309d88c61da240d99c59137329907b47865321ecd5564e987333b4cb607b0afca86769dc95b2f921357213fcb80c3b152918e9bab2228c0a1b77897ac68ce55088165f87f397da9790873b62c5383c0ccc370f0267cbe195651ccf336182c22ac3924b76c9e779b7a271d166b6d24b84242b7e73cc723f764039f6c851744034c3304db0c091a5764fdc9d593556ff734b82a87ccbc38ca99564d988bbd2d1bf071bb160722d365104fb27610651a8ed817f2742a6b5a1273a61acaf4460b0ab1456a9922351400a1c7d95d856d6e3370622c9c4164bc6b401435624a98b95caeb274f34ce92038d785068cdd8cf44c38d84acb2c466a2756c870ee78c26e738cc451002304eb8c90ab24b6463eb124d779f937a2e3692611d2e34d57b36cc4b2cd3b31ff485c6684d408b972e0d5ca7d2224aae4e";

    const ACVP_KEYGEN_768_D: &str =
        "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0";
    const ACVP_KEYGEN_768_Z: &str =
        "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";
    const ACVP_KEYGEN_768_EK: &str = "28c793778741b80b02b4339f2aa4347255b099f17264e1b8cc0a2c7c2a1a79f7997b907fd0496c6e6c8ad7714f5f339d75f11f625591a869be1175ae47f05fd4313468232ba6957d7807b824f445ac99a0d568ab1ad54dca8249d1482e61275f52248c77f61a4248753188cd1794cd0a465ec0dc4b025985c461b74e76286e4c37e77405695cc9fd0654374b427a20343aec0ff1a187768273bfc4905472a1da387f14559d6ce87313f6a5b6138434539f9a13684055b177e543f8b40f432abd7cc49989a50a9084c660913f45a8593b17499bc4cf936c2bc1851421cb986808a0ef30afe97aab5b8b8eb3f0b3506a95b91563a0e57db7231044987ef141bdab3537c316ad16f17805a81f29329879a94e96157e4b7447f7d59603b21bd896cc47b7cd4e232322eb9c5d2215696bcffca3a04efcc4c5d9cc39ac9a6e8700d38c244b0169e7fa1fe81b4b10365e74e6a1f7f756d11acdc84043f81006d62995376c22535958feb53f78117ee0f61c4c862640d06dc57a2b8be62a41a642af3bc63f6bac98bbbbff70570f37b8f8d9572f2735657a6c98f96caf57a849868720b2640b8bb2732237a1f984c18872d10289ce43c952c9257e06529aeb76afd127b17596fd25c5216c9cabd9b18efc50e87bbb04568bb7d5c4e9288c006483af5912e19108573700bd10cd77224b80659ea75aa74270b33ac4008b738bfee271e78658c8742ff13c96ad0781a03c7576ca26dd58b52980ba58c0505e446afa140cdcea0490db1f9b18815d4314b2459cacc562441c91f4084e5426c88e632cf7482e79907911d06473260835d7b85e7856a829aea0381707b939ce86882cc09c4448c6ae94a9c303107c5667eefb8df7763cc21189a3c590c40aa51f491503a7935ec08f4fc300cbe607ed8c9100c29fbf45584b13c8d780069337aec76c36ceb70373e2ab6e7b934b466f53fb32eaf040055496b8540e23a2a277e534468608d5ec0f8d38cea5bbb806c1bf4f164f6ac826fe733f95461e29dcc11200c0aada1b8332023eab329718ce25cc0a09555903f3578bbc863b1752ca94365da556df54c3b7e05cbb7115fbc1b6c57a172c31b9906560c8fb54f3c563a2256cc073243b8179b4a28d60e086cf51082ee429272996f0aabe03ba0eafd3c8e7d954bd0933e2f60ed0c32cede7b820a28e48f3ca3c40913cccae2337abfc59843f08c9863325d65a4e9e15c1f46172b118b2b5eb0f1d5158a00134f27b085488c3a0621fe4e5678698250fb74ee5152e3e35a66544a05d279ea99131fbc15165060b90f88eeb7b20892a4de4cb1683495bd7da037966b47cc040f1764c5deb06b5499d4267391cebbb47f734d8539e39528436a1858182854bf20b1f93279afb706464c65ccc5ae099b37cc03556c26abf4c3f8b9ba3a936707211a49a59b268f5284f7970c77612719450377417428c4ba47c9ca115cf95304c4759c5d8859b44985c06a6c924689237ba320d610960d61c53e85431789e67a40113f167ff93429c264f6cabc95448c903437d39a6577be0cf0012852aa476351a9046a110a1a625a3d74c910b78bce9cfca735e4f91b8a4c57dbe489e849446098aacf73070aee638fcc8896473d3c159d3afb4b687b40dfbf371a9c2644b605187b71a14bc4c8678fe8247";

    const ACVP_KEYGEN_1024_D: &str =
        "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009";
    const ACVP_KEYGEN_1024_Z: &str =
        "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275";
    const ACVP_KEYGEN_1024_EK: &str = "8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e98aaaa125abc75d3b30322560c197e75dd0e48a348099f7b2144d7b8a8660a4a97bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe1602e7d2715d9cbc00515df432a4f5b32b3bc92ae3f31700166d498123e94576509b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809b2b960a307e25347a32c3eab79288173a878789b296e9e8c1c28c5bb3ac472601c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a8bcb1b6d6ed2a1643736c29095e8a8452a3a36c7bb5ae58cbfdc61529466a90f454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6bccb64af6d56588ae94665961c025c3aa2861974c236bca4bd8ff5509f7ab774593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8290891a76940817dd8c9f52678780548e37a05806600801426dbb950c3b2ba34e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c93f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432156e5cbdf52364a90483a55c39b3fb16fc7465a3f8ac801b70b9fb28b583444ba5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b12150cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8ab34374e7df693e4a1b3e5a8ad0ce820afe1cf401acde650a8101b0946022d52178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c1116dc88a589db9107224a681008c67c589186a6929549beef92253db02b0c8aa9f9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb7849d74541580124e890116a65bc068093b57914e20c937c60a3eb25576f1a976a9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b5793a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a346156b733677932bd36593a7496130cc458dcc5ca987c21960604ec8a8c5396056680cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f85700613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c0cb6a8a44f97a70441c95fa71250116eec20863c0b5a643458788ab001f8869d909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea53896d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa935183bf8bd46abe76ba46e199103a5313c3235f49c915e097bca804de680781d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653d33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f4547195b7788a9150b2649e36aa394121926d568a488b16d3557b2a32af57d11fc3373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e48e34731130aba0b427360a856d96d80b3f028fdd3aba9035c10106ba1c0934bed36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c424395666c54abc2b8fb009847c86317685000c231215c8c15945860f6a85ddb98a8c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf7752569669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e677847";

    const ACVP_ENCAP_768_EK: &str = "b649b9ad5a59aa45640b03ace153499bc1244465735dca6e5ed0c7116070287758e7a31ee53ba171e7c8964b3615075286a4af1ea12479ab0218608692a2606a024d12fcae691c8114828f3547c9d0344af9920d952ba6bce6aae6a47360da1588697f91ab5475c5588ad6328389a34ba50e41514343c534ad7947c5aa4220c73d335bb24f6676cc2549fd40759cd4b54549b04d8932921b183ecb634b579a54742dd6734c7225741ba32ac196aa68faaf3d1425d4a44cc563aaf8816a8258bf745842f1ca7d8eda9a7a6ccd72966abab9061ee21ef3d2b1155133f4b8099b653ba8b5224360cf00295f2b3887d1b12d601b18bd407b80d167aefa0d3f6a906fc2cd08a663b7766815a26c6e2bc83318ac99b5a56d338ec347adbd9a57ec53359ce898fb637b32fc4a6fc216bfa30eec501681751bee46c5c02317c3b3b98f24ac67acc53941cd20035fe2a59890e9ab7cf063fe07a62703643e0580d99c152343c5bdd8cb9f9c1fd0c194ee7281913a7d1f0473722c024df76568a731d309cd5fa87fb3a0c771aa42efd160af89752c1c3eeac74a934b163af92d4ee74c709a31e901045fe6202de9622b552acd807829f46ad9c47087e2856f294b97546103568292a4b7462895f161891af4a66d537e79087f87f63e4e5a7d767a5d6a4a52267c8ce41413ef6c3dc4b1c64ee5ad75d9542099361ef81246a64ad997885fe0631d02919ab6b967b8c441d73b67d52b5fa64ac7789d30e659d776334da3a65a3b4081014455bc858637b23a991fe8ec315c687c36d81553c79f159c2b4b285604c0541ab62749cba6c29472b5dc6ab61b2be2e6a57a1942e729c1e95ba95c8100d4554fcedc0d73ac8023f736a94ac757b7b5108807a5eaba507b6f22e627ef325c0ef3b28123be7882840b7a8efcba7e0d82434c330b37b7c7f546b123d460a0d0c58893a7e4664f49acc9150a5dfbb71fbef44374a987e3192be4a50fc1f1160a0488844864532689e9f29d55366969e014b19869251977c34049437bb41b334c2de7a2eb63cc3ff21b042aa0e6839469e4bfa226cdbf8331cd1640e04b4cf2a89bffc20283dc2d90706604c1021153417b26c650b483856463df2c2c064ab4a9f316c5ba02109b1023370dded31ab1da2eb837bd8ccc52106712eb91a019119bd60951b3662f3f6291ecb76561b253dc4a1cb8e41b3a16b2ec87a252c4b747448823902845527b31c15a3ef18e174b644f548faf30b3da5610edccb73e3a8714bbbdd668c14a9472718b34efc545fff2783f033f13fc1665bc324ca244f1e91851d8ce2df2b388ea24b2cb8eab400f5a8ac1d01442f765688393ce21c4c63113ba49480b247c3fb4d49df82b1f493430bfa78f6d948da4e927bdd9bd2d18a7f230046853bd8be51cd59178d0295509213b7e1b0798584dce835b48312f0257a185d9360e0a702ad8bb0a53c119336889974b8e52b636328556ca1a9eec413f5259c66503c90206a7857925c727815c94fd545f0112c6a7e89c2ef54ae897a4b0792f98f5710ca174288658f5c8596c7807008369831135e1d50d5ac77f6ae9641de0622bca6a8e746700818c4a22a9ad30c9bc660117f3462617baf392280de09f5695b3cdda5e931c5b521bdaa455c3d0f0f7375153a754ed9620da68dd";
    const ACVP_ENCAP_768_M: &str =
        "7d5201502fad05b1463bc2212d6aec1c8503204c491f12d9366ae750144b7831";
    const ACVP_ENCAP_768_C: &str = "04f4a18c69708a17f561778b2ac10d94380abea4a20835939c9015d78dac41a5012ced1bed948aed6c79193f8b2fc6deabd3b092ec33ae2f54778f1c54ce762a69521764e20c05bc2ef96992f463ca95d09dd588af622c297bbd8805113e985388fc9e16fda06b5eed42da629d514f86ed84acff0a09418e720201b794b49d072df15e7b7d6ec6d82379a212c71c7603a1c9bbe57fb1cb9a431de1980ecada0a4fbf5cace9ad0ceedbfdc40761839d9cc1c8590eb6335179075892a8015e04ecadad37fdcd4644ec2284cf4cbb4620fbab6055a163e3733e3a7747044b766ebc356436b33e28fa4e67b083592b05811361445c719f6ae8add4ef8ce145e3933cee75d19e98bb964d58044b6de2b46107f80c3d4690114cc84fb0d3b3d4c3af671ea7b833746b54fce5cc761ca4fd20cd163afa849e5797619c31144a74140abe1c7540d1a3c557a9f23af6e6e3523667ffd13b92444cd3be01b1581ca0cf7a536ce4c073dc17de955ba22e469bc1c0ec213b3b7ceddfc47567a7ecfc2a58a6c2a3c2185563277866f8979bbb86af844349c6021eb9926acfe0188fd0f809e056a8e0a8aaa2a4208562e775ef60c56cadd6e26a9e52d60187bf6ed0565616020e0c2bfd79d961b1069ff261b2abf40c9ee2a2c442877f4edb8d9ad717cb434fed67ef2eacd629da1ce78023548853eeaf7d998923db7ceb0174e67875e787f398435da84c26b478ff6bf785c4714bc6f8e91804e10cc699e1be342c952d57d3c84654d603709f4f6bb596e022e2e6149c81025226b9925045ff365d83991f7d4c8693544ca7ba6da60f8e4f6723c9f14ac48882556336ed88c20163544c55ab4238e510aa910b04f445252d507af02ad24e7467920c81f2d31a71a7241be2726bb9f8b20bf2100633f616a1233801eb37597ddbe2def36ef0727515e7da178da7760a41edf9ffe98fbaa3495a35025f2bd100b3d63e940ba7d997104ac67f653d0a24a2ba2c8a355af1ee048cb116b1a492577cc7cf61226fbbbabd9cbb043839585f2e00ae673ee6becaaf5da7919921c90c74d5b8b173b8a1a650f379b3b5e5f1d04538b936fc2cd0d4f8b9df9f5052ecd9e66602815b4f96586d038d5bd5a3e44bde1ef9ff9cfcb6b9aece3129ef1f026befd299a7a8ad324149b156bc5ab868099df52a2056103432879b495b0655fc1fe8073b502f3f40d403548b1629118ce0edd41558e4215e8e241a45637a3434bf070f17dac885ed656f80783a4c47000464fe78b9db0dbb55895e271d3376bf0c50cec9a403a8729982dc5b9172b5e80a0ef03fa2a24873188f8022a6f9da8ca4f2e24aa7e29987b1060ecfe0b08e039ee1f7fb55a0cd35a73b6c25dc26e469bbc2d034265db5f74e644842bb99199f83947c97bf87532b37a8d40a06f8bc5508efb117d11dfb07325d9482cdce60aa34529546d4c8d8f98e3f5b34b5c757075fee9c3443e0a1109253f5f0a905c571e5343b277e0636a5a46ab36becf5672e93b712b9bc8e3cd3656cad1b29c16e";
    const ACVP_ENCAP_768_K: &str =
        "11b62291b1a9d307c8240d70be0b45436db445793173f6e79fcd2b273d7f3b01";

    /// Build a 64-byte FIPS 203 seed from ACVP `d` and `z` hex strings.
    fn seed_from_hex(d_hex: &str, z_hex: &str) -> Vec<u8> {
        let mut seed = hex::decode(d_hex).expect("valid d hex");
        seed.extend(hex::decode(z_hex).expect("valid z hex"));
        assert_eq!(seed.len(), 64);
        seed
    }

    /// ACVP ML-KEM-keyGen-FIPS203 KAT: seed (`d || z`) must expand to the
    /// expected encapsulation key, checked through the crate's own loader
    /// and SPKI encoding.
    #[test]
    fn acvp_keygen_kat_all_variants() {
        use ml_kem::KeyExport;

        macro_rules! keygen_kat {
            ($params:ty, $d:expr, $z:expr, $ek:expr) => {{
                let seed_bytes = seed_from_hex($d, $z);
                let expected_ek = hex::decode($ek).expect("valid ek hex");
                let seed = ml_kem::Seed::try_from(seed_bytes.as_slice()).expect("seed");
                let dk = ml_kem::DecapsulationKey::<$params>::from_seed(seed);
                assert_eq!(
                    dk.encapsulation_key().to_bytes().as_slice(),
                    expected_ek.as_slice(),
                    "derived encapsulation key must match ACVP vector"
                );
            }};
        }
        keygen_kat!(
            ml_kem::MlKem512,
            ACVP_KEYGEN_512_D,
            ACVP_KEYGEN_512_Z,
            ACVP_KEYGEN_512_EK
        );
        keygen_kat!(
            ml_kem::MlKem768,
            ACVP_KEYGEN_768_D,
            ACVP_KEYGEN_768_Z,
            ACVP_KEYGEN_768_EK
        );
        keygen_kat!(
            ml_kem::MlKem1024,
            ACVP_KEYGEN_1024_D,
            ACVP_KEYGEN_1024_Z,
            ACVP_KEYGEN_1024_EK
        );
    }

    /// ACVP ML-KEM-encapDecap-FIPS203 encapsulation KAT (ML-KEM-768):
    /// `(ek, m)` must produce exactly `(c, k)` via
    /// `encapsulate_deterministic` — the primitive our randomized
    /// `encapsulate` wraps with a fresh OS-entropy `m`.
    #[test]
    fn acvp_encapsulation_kat_ml_kem_768() {
        let ek_bytes = hex::decode(ACVP_ENCAP_768_EK).expect("valid ek hex");
        let m_bytes = hex::decode(ACVP_ENCAP_768_M).expect("valid m hex");
        let expected_c = hex::decode(ACVP_ENCAP_768_C).expect("valid c hex");
        let expected_k = hex::decode(ACVP_ENCAP_768_K).expect("valid k hex");

        let ek_arr = ml_kem::Key::<ml_kem::EncapsulationKey<ml_kem::MlKem768>>::try_from(
            ek_bytes.as_slice(),
        )
        .expect("ek length");
        let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&ek_arr).expect("valid ek");
        let m = ml_kem::B32::try_from(m_bytes.as_slice()).expect("m length");

        let (c, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(c.as_slice(), expected_c.as_slice(), "ciphertext KAT");
        assert_eq!(k.as_slice(), expected_k.as_slice(), "shared secret KAT");
    }

    /// Decapsulation through the public API, anchored to NIST vectors: the
    /// ACVP keyGen-768 seed (whose derived key is KAT-verified above) must
    /// recover the shared secret from a ciphertext produced by the
    /// KAT-verified deterministic encapsulation.
    #[test]
    fn acvp_seed_anchored_decapsulation_ml_kem_768() {
        use pkcs8_pq::spki::EncodePublicKey;

        let seed_bytes = seed_from_hex(ACVP_KEYGEN_768_D, ACVP_KEYGEN_768_Z);
        let seed = ml_kem::Seed::try_from(seed_bytes.as_slice()).expect("seed");
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);

        let m_bytes = hex::decode(ACVP_ENCAP_768_M).expect("valid m hex");
        let m = ml_kem::B32::try_from(m_bytes.as_slice()).expect("m length");
        let (c, k) = dk.encapsulation_key().encapsulate_deterministic(&m);

        let key = SoftwareKey::PostQuantum {
            algorithm: PqAlgorithm::MlKem(MlKemVariant::MlKem768),
            private_der: Some(seed_bytes),
            public_der: dk
                .encapsulation_key()
                .to_public_key_der()
                .expect("SPKI encode")
                .as_bytes()
                .to_vec(),
        };
        let decapsulator =
            SoftwareDecapsulator::new(MlKemVariant::MlKem768, key).expect("decapsulator creation");
        let secret = decapsulator.decapsulate(c.as_slice()).expect("decapsulate");
        assert_eq!(secret.as_slice(), k.as_slice());
    }
}
