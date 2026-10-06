//! Cases that must behave identically under every document provider.
//!
//! Each test runs against whichever provider the build selects, so CI runs
//! this file once per provider feature set. FIPS builds run every case too:
//! approved operations must give the same answers, and operations FIPS does
//! not approve must be refused as unsupported rather than skipped.

use kryptering::kdf::{HkdfParams, Pbkdf2Params};
use kryptering::{
    AesKeySize, EcCurve, HashAlgorithm, KeyAlgorithm, KeyWrapAlgorithm, Operation,
    SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
};
use kryptering::{Signer, Verifier};

fn decode(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).expect("valid test vector")
}

/// Assert that `operation` was refused as unsupported, as FIPS builds do for
/// every operation the module does not approve.
fn assert_refused<T>(result: kryptering::Result<T>, operation: Operation) {
    match result {
        Err(kryptering::Error::UnsupportedAlgorithm {
            operation: actual, ..
        }) if actual == operation => {}
        Err(error) => panic!("{operation:?} failed without being refused: {error}"),
        Ok(_) => panic!("{operation:?} was accepted"),
    }
}

#[test]
fn raw_symmetric_import_rejects_asymmetric_families() {
    kryptering::initialize_backend().expect("provider initialization");
    for algorithm in [
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec(EcCurve::P256),
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Dh,
    ] {
        assert!(
            SoftwareKey::from_symmetric_bytes(algorithm, b"not a raw symmetric key").is_err(),
            "{algorithm:?} accepted raw bytes"
        );
    }
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 32]).is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 20]).is_err());
}

#[test]
fn x25519_agreement_matches_rfc7748_and_checks_key_type() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 7748 §6.1.
    let alice_private = decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();

    if cfg!(feature = "fips") {
        // X25519 is not FIPS approved: every entry point refuses the RFC
        // inputs before inspecting them or the key type.
        assert_refused(
            kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private),
            Operation::X25519Agreement,
        );
        assert_refused(
            SoftwareKey::from_x25519(Some(&alice_private), &alice_public),
            Operation::KeyImport(KeyAlgorithm::X25519),
        );
        assert_refused(
            kryptering::keyagreement::agree_x25519(&bob_public, &aes),
            Operation::X25519Agreement,
        );
    } else {
        assert_eq!(
            kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private).unwrap(),
            shared
        );
        let alice = SoftwareKey::from_x25519(Some(&alice_private), &alice_public).unwrap();
        assert_eq!(
            kryptering::keyagreement::agree_x25519(&bob_public, &alice).unwrap(),
            shared
        );

        assert!(kryptering::keyagreement::agree_x25519(&bob_public, &aes).is_err());
        assert!(kryptering::keyagreement::ecdh_x25519(&bob_public, &alice_private[..31]).is_err());
    }
}

#[test]
fn signers_reject_keys_of_another_family() {
    kryptering::initialize_backend().expect("provider initialization");
    let hmac = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
        SignatureAlgorithm::Ed25519,
    ] {
        assert!(SoftwareSigner::new(algorithm, hmac.clone()).is_err());
        assert!(SoftwareVerifier::new(algorithm, hmac.clone()).is_err());
    }
    if cfg!(feature = "fips") {
        // FIPS refuses Ed25519 itself, before the key family is checked.
        assert_refused(
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, hmac.clone()),
            Operation::Sign(SignatureAlgorithm::Ed25519),
        );
        assert_refused(
            SoftwareVerifier::new(SignatureAlgorithm::Ed25519, hmac),
            Operation::Verify(SignatureAlgorithm::Ed25519),
        );
    }
}

/// Encode a P-256 signature's fixed-width r||s as minimal DER.
fn p256_der(raw: &[u8]) -> Vec<u8> {
    p256::ecdsa::Signature::from_slice(raw)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec()
}

#[test]
fn ecdsa_verify_accepts_the_same_encodings() {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    kryptering::initialize_backend().expect("provider initialization");
    let private = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let key = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);
    let raw = SoftwareSigner::new(algorithm, key)
        .unwrap()
        .sign(b"parity")
        .unwrap();
    assert_eq!(raw.len(), 64);
    let verifier = SoftwareVerifier::new(algorithm, public).unwrap();

    let mut padded = vec![0];
    padded.extend_from_slice(&raw[..32]);
    padded.push(0);
    padded.extend_from_slice(&raw[32..]);

    for (name, encoding) in [
        ("raw", raw.clone()),
        ("DER", p256_der(&raw)),
        ("padded", padded),
    ] {
        assert!(verifier.verify(b"parity", &encoding).unwrap(), "{name}");
        assert!(!verifier.verify(b"tampered", &encoding).unwrap(), "{name}");
    }
    assert!(verifier.verify(b"parity", &[0; 64]).is_err());
    assert!(verifier.verify(b"parity", &raw[..63]).is_err());
}

/// Encode public test scalars without applying validity checks to the fixture.
fn ecdsa_test_der(raw: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    for scalar in raw.chunks_exact(raw.len() / 2) {
        let start = scalar
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(scalar.len() - 1);
        let scalar = &scalar[start..];
        let sign = usize::from(scalar[0] & 0x80 != 0);
        content.extend([2, (scalar.len() + sign) as u8]);
        if sign != 0 {
            content.push(0);
        }
        content.extend(scalar);
    }
    let mut der = vec![0x30];
    if content.len() >= 128 {
        der.push(0x81);
    }
    der.push(content.len() as u8);
    der.extend(content);
    der
}

/// Every provider applies identical encoding precedence and scalar-order bounds.
#[test]
fn ecdsa_encoding_and_scalar_boundaries_match() {
    use p256::elliptic_curve::{bigint::Encoding, Curve};
    use p256::pkcs8::EncodePublicKey;
    kryptering::initialize_backend().unwrap();
    for curve in [EcCurve::P256, EcCurve::P384, EcCurve::P521] {
        let (order, spki) = match curve {
            EcCurve::P256 => (
                p256::NistP256::ORDER.to_be_bytes().to_vec(),
                p256::SecretKey::random(&mut rand::rngs::OsRng)
                    .public_key()
                    .to_public_key_der()
                    .unwrap(),
            ),
            EcCurve::P384 => (
                p384::NistP384::ORDER.to_be_bytes().to_vec(),
                p384::SecretKey::random(&mut rand::rngs::OsRng)
                    .public_key()
                    .to_public_key_der()
                    .unwrap(),
            ),
            EcCurve::P521 => (
                p521::NistP521::ORDER.to_be_bytes()[6..].to_vec(),
                p521::SecretKey::random(&mut rand::rngs::OsRng)
                    .public_key()
                    .to_public_key_der()
                    .unwrap(),
            ),
        };
        let field = order.len();
        let key = SoftwareKey::from_spki_der(KeyAlgorithm::Ec(curve), spki.as_bytes()).unwrap();
        let hash = match curve {
            EcCurve::P256 => HashAlgorithm::Sha256,
            EcCurve::P384 => HashAlgorithm::Sha384,
            EcCurve::P521 => HashAlgorithm::Sha512,
        };
        let verifier = SoftwareVerifier::new(SignatureAlgorithm::Ecdsa(curve, hash), key).unwrap();
        let mut one = vec![0; field];
        one[field - 1] = 1;
        let mut below = order.clone();
        below[field - 1] -= 1;
        let mut above = order.clone();
        above[field - 1] += 1;
        for scalar in [one.clone(), below] {
            let raw = [scalar.as_slice(), one.as_slice()].concat();
            let der = ecdsa_test_der(&raw);
            assert_eq!(
                kryptering::digest::ecdsa_raw_to_der(curve, &der).unwrap(),
                der
            );
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &der).unwrap(),
                raw
            );
            assert!(!verifier.verify(b"boundary", &der).unwrap());
        }
        // Well-formed DER with an over-width scalar must not fall back to raw.
        let mut oversized = vec![0; 2 * (field + 1)];
        oversized[0] = 1;
        *oversized.last_mut().unwrap() = 1;
        let oversized_der = ecdsa_test_der(&oversized);
        assert!(kryptering::digest::ecdsa_raw_to_der(curve, &oversized_der).is_err());
        assert!(verifier.verify(b"boundary", &oversized_der).is_err());
        // r=s=1 produces an eight-byte DER value, well below every raw width.
        let short = [0x30, 6, 2, 1, 1, 2, 1, 1];
        assert_eq!(
            kryptering::digest::ecdsa_raw_to_der(curve, &short).unwrap(),
            short
        );
        for invalid in [vec![0; field], order, above, vec![0xff; field]] {
            for swap in [false, true] {
                let raw = if swap {
                    [one.as_slice(), invalid.as_slice()].concat()
                } else {
                    [invalid.as_slice(), one.as_slice()].concat()
                };
                let der = ecdsa_test_der(&raw);
                let padded = [&[0][..], &raw[..field], &[0], &raw[field..]].concat();
                assert!(kryptering::digest::ecdsa_der_to_raw(curve, &der).is_err());
                for encoding in [&raw, &der, &padded] {
                    assert!(
                        kryptering::digest::ecdsa_raw_to_der(curve, encoding).is_err(),
                        "{curve:?}"
                    );
                    assert!(verifier.verify(b"boundary", encoding).is_err(), "{curve:?}");
                }
            }
        }
        // A DER value can have exactly the raw width: only explicit DER APIs
        // may interpret that ambiguous input as DER.
        let (r_len, s_len) = if curve == EcCurve::P521 {
            (62, 63)
        } else {
            (field - 3, field - 3)
        };
        let mut components = vec![0; field * 2];
        components[field - r_len..field].fill(1);
        components[2 * field - s_len..].fill(1);
        let ambiguous = ecdsa_test_der(&components);
        assert_eq!(ambiguous.len(), field * 2);
        assert_eq!(
            kryptering::digest::ecdsa_der_to_raw(curve, &ambiguous).unwrap(),
            components
        );
        if curve == EcCurve::P521 {
            assert!(kryptering::digest::ecdsa_raw_to_der(curve, &ambiguous).is_err());
        } else {
            let encoded = kryptering::digest::ecdsa_raw_to_der(curve, &ambiguous).unwrap();
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &encoded).unwrap(),
                ambiguous
            );
        }
        let mut raw = [one.as_slice(), one.as_slice()].concat();
        raw[0] = 0x30;
        if curve == EcCurve::P521 {
            // A P-521 scalar cannot have 0x30 in its most significant octet.
            assert!(kryptering::digest::ecdsa_raw_to_der(curve, &raw).is_err());
        } else {
            let der = kryptering::digest::ecdsa_raw_to_der(curve, &raw).unwrap();
            assert_eq!(
                kryptering::digest::ecdsa_der_to_raw(curve, &der).unwrap(),
                raw
            );
        }
    }
}

/// Strict DER conversion rejects malformed lengths and noncanonical integers.
#[test]
fn ecdsa_malformed_der_is_rejected_without_panics() {
    for curve in [EcCurve::P256, EcCurve::P384, EcCurve::P521] {
        let excessive = [
            vec![0x30, 0x80 | std::mem::size_of::<usize>() as u8],
            vec![0xff; std::mem::size_of::<usize>()],
        ]
        .concat();
        for der in [
            excessive,
            vec![0x30, 6, 2, 1, 0, 2, 1, 1],
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
        ] {
            assert!(kryptering::digest::ecdsa_der_to_raw(curve, &der).is_err());
        }
    }
}

#[test]
fn ecdsa_verifies_cross_curve_digest_pairs() {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::pkcs8::EncodePublicKey;

    kryptering::initialize_backend().expect("provider initialization");
    // XML-DSig pairs a P-384 key with whatever digest the URI names.
    let signing = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P384),
        signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let digest = kryptering::digest::digest(HashAlgorithm::Sha256, b"cross").unwrap();
    let signature: p384::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
    let verifier = SoftwareVerifier::new(
        SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha256),
        public,
    )
    .unwrap();
    assert!(verifier.verify(b"cross", &signature.to_bytes()).unwrap());
    assert!(!verifier.verify(b"tampered", &signature.to_bytes()).unwrap());
}

#[test]
fn rsa_keys_below_2048_bits_are_refused_when_used() {
    use kryptering::{KeyTransportAlgorithm, OaepConfig};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    kryptering::initialize_backend().expect("provider initialization");
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
    let spki = private.to_public_key().to_public_key_der().unwrap();
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let public = SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, spki.as_bytes());
    let private = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, pkcs8.as_bytes());
    if cfg!(feature = "fips") {
        // FIPS builds refuse short RSA keys already at import.
        assert!(public.is_err() && private.is_err());
        return;
    }
    let public = public.unwrap();
    let algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256);
    // The one intended difference: RustCrypto with `legacy` uses short RSA
    // keys for historical interoperability; AWS-LC never does.
    let usable = cfg!(all(feature = "rustcrypto", feature = "legacy"));
    match private {
        Ok(private) => assert_eq!(SoftwareSigner::new(algorithm, private).is_ok(), usable),
        // AWS-LC's RSA key-pair parser itself refuses short private keys.
        Err(_) => assert!(!usable && cfg!(feature = "aws-lc")),
    }
    let verified = SoftwareVerifier::new(algorithm, public.clone())
        .and_then(|verifier| verifier.verify(b"message", &[0; 128]));
    assert_eq!(verified.is_ok(), usable, "{verified:?}");
    if !usable {
        assert!(verified
            .unwrap_err()
            .to_string()
            .contains("1024-bit RSA key"));
    }
    let oaep = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
    let transported = kryptering::keytransport::kt_encrypt(oaep, &public, &[0x42; 16], None);
    assert_eq!(transported.is_ok(), usable, "{transported:?}");
}

#[test]
fn aes_cbc_rejects_iv_only_input() {
    kryptering::initialize_backend().expect("provider initialization");
    for size in [AesKeySize::Aes128, AesKeySize::Aes256] {
        let key = vec![3; size.key_len()];
        assert!(kryptering::hazmat::aes_cbc::decrypt(size, &key, &[9; 16]).is_err());
        let sealed = kryptering::hazmat::aes_cbc::encrypt(size, &key, b"").unwrap();
        assert_eq!(sealed.len(), 32);
        assert!(kryptering::hazmat::aes_cbc::decrypt(size, &key, &sealed)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn aes_key_wrap_matches_rfc3394_and_rejects_short_input() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 3394 §4.1 and §4.6.
    let kek128 = decode("000102030405060708090A0B0C0D0E0F");
    let kek256 = decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let data = decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    for (size, kek, input, expected) in [
        (
            AesKeySize::Aes128,
            &kek128,
            &data[..16],
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            AesKeySize::Aes256,
            &kek256,
            &data[..],
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ] {
        let algorithm = KeyWrapAlgorithm::AesKw(size);
        let wrapped = kryptering::keywrap::wrap(algorithm, kek, input).unwrap();
        assert_eq!(wrapped, decode(expected));
        assert_eq!(
            kryptering::keywrap::unwrap(algorithm, kek, &wrapped).unwrap(),
            input
        );
        let mut tampered = wrapped.clone();
        tampered[0] ^= 1;
        assert!(kryptering::keywrap::unwrap(algorithm, kek, &tampered).is_err());

        assert!(kryptering::keywrap::wrap(algorithm, kek, &[]).is_err());
        assert!(kryptering::keywrap::wrap(algorithm, kek, &[1; 8]).is_err());
        assert!(kryptering::keywrap::wrap(algorithm, kek, &[1; 20]).is_err());
        assert!(kryptering::keywrap::unwrap(algorithm, kek, &wrapped[..16]).is_err());
    }
}

#[test]
fn kdfs_match_rfc_vectors() {
    kryptering::initialize_backend().expect("provider initialization");
    // RFC 5869 A.2 (long inputs) and A.3 (no salt, no info).
    let a2 = kryptering::kdf::hkdf_derive(
        &(0u8..=0x4f).collect::<Vec<_>>(),
        82,
        &HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some((0x60u8..=0xaf).collect()),
            info: Some((0xb0u8..=0xff).collect()),
            key_length_bits: 0,
        },
    )
    .unwrap();
    assert_eq!(
        a2,
        decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
    let a3 = kryptering::kdf::hkdf_derive(&[0x0b; 22], 42, &HkdfParams::default()).unwrap();
    assert_eq!(
        a3,
        decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        )
    );
    assert!(kryptering::kdf::hkdf_derive(&[1], 255 * 32 + 1, &HkdfParams::default()).is_err());

    // Cross-checked against Python's hashlib.pbkdf2_hmac. The 8-byte salt and
    // password are below the SP 800-132 minimums FIPS builds enforce.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "2ecc2dfd549e0925a0e4a0b860368e7492b6e65339188d3e1e9e43799b90ff64cf800fb11ff3602b51ed7c8c766643c32be8af72829b3146642d9ddbdf8d7d6d"),
        (HashAlgorithm::Sha512, 40, "fee75217fa12304834340c9e672f9aaa9cc4bb229a9fd37edcdcd6ae57b42ad8ca5ea636c777c33c"),
    ] {
        let output = kryptering::kdf::pbkdf2_derive(
            b"Password",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        );
        if cfg!(feature = "fips") {
            assert!(
                matches!(
                    output,
                    Err(kryptering::Error::Crypto(ref message))
                        if message.contains("SP 800-132")
                ),
                "{hash:?}: {output:?}"
            );
        } else {
            assert_eq!(output.unwrap(), decode(expected), "{hash:?}");
        }
    }

    // The same shapes with SP 800-132 compliant parameters (128-bit salt and
    // password, 1000 iterations), which every provider including FIPS must
    // derive identically. Cross-checked against Python's hashlib.pbkdf2_hmac.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "1e30cde84a0370317564c82ece78efb738195387129590d2fd3d7b48714a40c874de73f494b275b7147b58171cc17101b3cba6a0bd0a3766c839dd7e98f71aed"),
        (HashAlgorithm::Sha512, 40, "20ae6a68e7f944784e186fa29c12c6ae0926c736f4cdb5f025becc9c70a0e12cf39145acd1ad6113"),
    ] {
        let output = kryptering::kdf::pbkdf2_derive(
            b"PasswordPassword",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        )
        .unwrap();
        assert_eq!(output, decode(expected), "{hash:?}");
    }

    let recommended = Pbkdf2Params::recommended(HashAlgorithm::Sha512, b"salt".to_vec(), 32);
    assert_eq!(recommended.hash, HashAlgorithm::Sha512);
    assert_eq!(recommended.iteration_count, 210_000);
}
