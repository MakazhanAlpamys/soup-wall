#![forbid(unsafe_code)]

//! Key agreement: ECDH (P-256, P-384, P-521), X25519, and finite-field
//! Diffie-Hellman (X9.42).
//!
//! Finite-field DH ([`agree_dh`]) delegates to [`crate::hazmat::dh`], which
//! exponentiates with `crypto_bigint`'s constant-time Montgomery `pow` over
//! an exponent padded to the modulus width, and validates the group
//! parameters, private exponent range, and peer subgroup membership. It
//! exists for legacy XML-Enc / CMS interop; prefer ECDH or X25519.
//!
//! Upstream shared-secret types (`p256::ecdh::SharedSecret`,
//! `x25519_dalek::SharedSecret`) wipe themselves on drop; the returned
//! `Vec<u8>` is the caller's copy to protect.

use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crate::key::{RustCryptoKey, SoftwareKey};
use zeroize::Zeroizing;

/// Compute ECDH using an opaque provider key.
pub fn agree(
    curve: crate::algorithm::EcCurve,
    peer_public: &[u8],
    private: &SoftwareKey,
) -> Result<Vec<u8>> {
    match (curve, private.inner()) {
        (
            crate::algorithm::EcCurve::P256,
            RustCryptoKey::EcP256 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p256::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-256 private conversion failed: {e}")))?;
            ecdh_p256(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::P384,
            RustCryptoKey::EcP384 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p384::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-384 private conversion failed: {e}")))?;
            ecdh_p384(peer_public, &key)
        }
        (
            crate::algorithm::EcCurve::P521,
            RustCryptoKey::EcP521 {
                private: Some(key), ..
            },
        ) => {
            let scalar = Zeroizing::new(key.to_bytes());
            let key = p521::SecretKey::from_slice(scalar.as_slice())
                .map_err(|e| Error::Key(format!("P-521 private conversion failed: {e}")))?;
            ecdh_p521(peer_public, &key)
        }
        _ => Err(Error::Key(format!(
            "private {curve:?} key required for ECDH"
        ))),
    }
}

/// Compute X25519 agreement using an opaque provider key.
pub fn agree_x25519(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
    match private.inner() {
        RustCryptoKey::X25519 {
            private: Some(key), ..
        } => ecdh_x25519(peer_public, key),
        _ => Err(Error::Key("X25519 private key required".into())),
    }
}

/// Compute finite-field Diffie-Hellman agreement without exporting the
/// private exponent from the opaque key handle. Group validation is retained
/// from import; peer and private-exponent validation still run on every call.
pub fn agree_dh(peer_public: &[u8], private: &SoftwareKey) -> Result<Vec<u8>> {
    require_supported(Operation::DhAgreement)?;
    match private.inner() {
        RustCryptoKey::Dh {
            private: Some(exponent),
            group,
            ..
        } => group.agree(peer_public, exponent),
        _ => Err(Error::Key("finite-field DH private key required".into())),
    }
}

/// Compute an ECDH shared secret for P-256.
///
/// Takes the originator's (ephemeral) public key as uncompressed SEC1 bytes
/// and the recipient's (static) private key.
pub fn ecdh_p256(originator_public: &[u8], recipient_private: &p256::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P256))?;
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p256::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-256 public key: {e}")))?;

    let public_key: p256::PublicKey =
        Option::from(p256::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-256 public key point".into()))?;

    let shared_secret = p256::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-384.
pub fn ecdh_p384(originator_public: &[u8], recipient_private: &p384::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P384))?;
    use p384::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p384::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-384 public key: {e}")))?;

    let public_key: p384::PublicKey =
        Option::from(p384::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-384 public key point".into()))?;

    let shared_secret = p384::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an ECDH shared secret for P-521.
pub fn ecdh_p521(originator_public: &[u8], recipient_private: &p521::SecretKey) -> Result<Vec<u8>> {
    require_supported(Operation::Agreement(crate::algorithm::EcCurve::P521))?;
    use p521::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p521::EncodedPoint::from_bytes(originator_public)
        .map_err(|e| Error::Key(format!("invalid P-521 public key: {e}")))?;

    let public_key: p521::PublicKey =
        Option::from(p521::PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| Error::Key("invalid P-521 public key point".into()))?;

    let shared_secret = p521::ecdh::diffie_hellman(
        recipient_private.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute an X25519 Diffie-Hellman shared secret (RFC 7748).
///
/// Takes the originator's (ephemeral) public key as raw 32 bytes
/// and the recipient's (static) private key as raw 32 bytes.
/// Returns the 32-byte shared secret.
///
/// Rejects attacker-chosen low-order peer public keys that would force the
/// shared secret to the identity (all-zero) output. RFC 7748 §6.1 notes
/// that implementers MAY check for this "non-contributory" behaviour; in
/// practice any protocol that feeds the shared secret into a KDF and then
/// authenticates with it is subverted if the peer can pin the secret to a
/// known value, so we perform the check unconditionally.
pub fn ecdh_x25519(originator_public: &[u8], recipient_private: &[u8]) -> Result<Vec<u8>> {
    require_supported(Operation::X25519Agreement)?;
    if originator_public.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 public key length: {} (expected 32)",
            originator_public.len()
        )));
    }
    if recipient_private.len() != 32 {
        return Err(Error::Key(format!(
            "invalid X25519 private key length: {} (expected 32)",
            recipient_private.len()
        )));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(originator_public);
    let their_public = x25519_dalek::PublicKey::from(pub_bytes);

    // priv_bytes is a stack copy of the caller's private scalar. StaticSecret
    // takes the array by value (so `my_secret` holds its own copy, wiped by
    // x25519-dalek's ZeroizeOnDrop), but our stack copy must be wiped
    // explicitly or it lingers in this frame until the function returns.
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(recipient_private);
    let my_secret = x25519_dalek::StaticSecret::from(priv_bytes);
    {
        use zeroize::Zeroize;
        priv_bytes.zeroize();
    }

    let shared_secret = my_secret.diffie_hellman(&their_public);
    if !shared_secret.was_contributory() {
        return Err(Error::Key(
            "X25519 peer public key is a low-order point (shared secret is identity)".into(),
        ));
    }
    Ok(shared_secret.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_roundtrip() {
        // Both parties generate key pairs; shared secret must match
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);

        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // Alice computes shared secret with Bob's public key
        let shared_alice = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        // Bob computes shared secret with Alice's public key
        let shared_bob = ecdh_x25519(alice_public.as_bytes(), bob_secret.as_bytes()).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn x25519_rejects_low_order_public_key() {
        // The all-zero public key is the canonical low-order point: it maps
        // to the identity on Curve25519, so the DH output is forced to the
        // all-zero shared secret regardless of the recipient's private key.
        // An earlier version of ecdh_x25519 returned that all-zero secret
        // without complaint, letting a malicious peer pin the KDF input.
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let low_order_pub = [0u8; 32];
        let err = ecdh_x25519(&low_order_pub, secret.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("low-order"),
            "unexpected error: {err}"
        );
    }

    /// Agreement uses validated production-size parameters behind an opaque private key.
    #[test]
    fn finite_field_dh_uses_opaque_private_key() {
        let (p, g, q) = crate::hazmat::dh::tests::parameters();
        let private = SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&[1]), &g).unwrap();
        assert_eq!(agree_dh(&g, &private).unwrap(), g);
    }

    #[test]
    fn x25519_invalid_public_key_length() {
        let secret = [0u8; 32];
        let short_pub = [0u8; 16];
        let err = ecdh_x25519(&short_pub, &secret).unwrap_err();
        assert!(
            err.to_string().contains("invalid X25519 public key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_invalid_private_key_length() {
        let pub_key = [0u8; 32];
        let short_priv = [0u8; 16];
        let err = ecdh_x25519(&pub_key, &short_priv).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid X25519 private key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_deterministic() {
        // Same inputs produce same output
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let shared1 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();
        let shared2 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn p256_roundtrip() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let alice_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let alice_public = alice_secret.public_key();

        let bob_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p256(bob_public.to_encoded_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p256(alice_public.to_encoded_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn p384_roundtrip() {
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let alice_secret = p384::SecretKey::random(&mut rand::rngs::OsRng);
        let alice_public = alice_secret.public_key();

        let bob_secret = p384::SecretKey::random(&mut rand::rngs::OsRng);
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p384(bob_public.to_encoded_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p384(alice_public.to_encoded_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 48);
    }

    #[test]
    fn p521_roundtrip() {
        use p521::elliptic_curve::sec1::ToEncodedPoint;

        let alice_secret = p521::SecretKey::random(&mut rand::rngs::OsRng);
        let alice_public = alice_secret.public_key();

        let bob_secret = p521::SecretKey::random(&mut rand::rngs::OsRng);
        let bob_public = bob_secret.public_key();

        let shared_alice =
            ecdh_p521(bob_public.to_encoded_point(false).as_bytes(), &alice_secret).unwrap();
        let shared_bob =
            ecdh_p521(alice_public.to_encoded_point(false).as_bytes(), &bob_secret).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 66);
    }
}
