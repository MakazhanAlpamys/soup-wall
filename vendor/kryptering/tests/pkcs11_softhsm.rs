#![cfg(all(feature = "pkcs11", not(feature = "fips"), not(target_arch = "wasm32")))]
//! End-to-end PKCS#11 coverage against a private SoftHSM2 token.
//!
//! Skipped unless `KRYPTERING_TEST_SOFTHSM2_MODULE` names the SoftHSM2 module
//! (typically `/usr/lib/softhsm/libsofthsm2.so`). Token setup talks to
//! cryptoki directly; every assertion goes through Kryptering's public
//! PKCS#11 API. SoftHSM2 reads the process-global `SOFTHSM2_CONF` once, at
//! the first `C_Initialize`, so all cases run in order from a single test.

use std::path::{Path, PathBuf};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, RawAuthPin};
use kryptering::pkcs11::{
    Pkcs11Cipher, Pkcs11Decryptor, Pkcs11Encryptor, Pkcs11HmacSigner, Pkcs11KeyAgreement,
    Pkcs11KeyWrapper, Pkcs11Provider, Pkcs11Session, Pkcs11Signer, Pkcs11Verifier,
};
use kryptering::{
    AesKeySize, CipherAlgorithm, EcCurve, HashAlgorithm, KeyAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm, OaepConfig, SignatureAlgorithm, SoftwareKey, SoftwareVerifier,
};
use kryptering::{Decryptor, Encryptor, KeyAgreement, KeyWrapper, Signer, Verifier};

const MODULE_ENV: &str = "KRYPTERING_TEST_SOFTHSM2_MODULE";

const MAIN_TOKEN: &str = "kryptering-main";
const RAW_PIN_TOKEN: &str = "kryptering-raw-pin";
const SO_PIN: &str = "kryptering-so-pin";
const USER_PIN: &str = "kryptering-user-pin";
const ROTATED_USER_PIN: &str = "kryptering-rotated-pin";
/// Not UTF-8: 0xff never occurs in UTF-8 and 0xc3 0x28 is a broken sequence.
const RAW_USER_PIN: &[u8] = b"\xff\xfe raw \xc3\x28 pin";

const KEK_256: &str = "kek-aes-256";
const KEK_128: &str = "kek-aes-128";
const KEK_KNOWN: &str = "kek-aes-256-known";
const KEK_NO_WRAP: &str = "kek-aes-256-no-wrap";
const RSA_KEY: &str = "rsa-2048";
const RSA_LEGACY_KEY: &str = "rsa-1024";
const RSA_TOO_SMALL_KEY: &str = "rsa-512";
const EC_KEY: &str = "ec-p256";
const GCM_KEY: &str = "gcm-aes-256";
const HMAC_KEY: &str = "hmac-sha256";
const RAW_PIN_KEY: &str = "raw-pin-gcm-aes-256";

// Imported rather than generated so token output can be checked against the
// software provider holding the same key.
const GCM_KEY_VALUE: [u8; 32] = [0x2b; 32];
const KEK_KNOWN_VALUE: [u8; 32] = [0x6a; 32];
const HMAC_KEY_VALUE: [u8; 32] = [0x0b; 32];
const KEY_MATERIAL: [u8; 32] = [0x5c; 32];
const MESSAGE: &[u8] = b"kryptering PKCS#11 SoftHSM2 message";

/// DER `namedCurve` OID 1.2.840.10045.3.1.7 (P-256), as in `CKA_EC_PARAMS`.
const P256_EC_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const RSA_PSS: SignatureAlgorithm = SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256);
const ECDSA_P256: SignatureAlgorithm =
    SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);

#[test]
fn softhsm2_token_backs_every_pkcs11_operation() {
    let Some(module) = softhsm2_module() else {
        return;
    };
    let token_dir = private_token_dir();
    std::env::set_var("SOFTHSM2_CONF", token_dir.join("softhsm2.conf"));

    let setup = Pkcs11::new(&module).expect("load the SoftHSM2 module");
    setup
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("C_Initialize");
    let main_slot = init_token(&setup, MAIN_TOKEN);
    populate_main_token(&setup, main_slot);
    let raw_pin_slot = init_token(&setup, RAW_PIN_TOKEN);
    populate_raw_pin_token(&setup, raw_pin_slot, &module);

    provider_selection_pins_the_token(&setup, &module, main_slot);
    let provider = Pkcs11Provider::new_with_token(&module, MAIN_TOKEN, None)
        .expect("select the main token by label");
    wrong_pin_is_rejected(&provider);
    concurrent_sessions_share_the_login(&module, &provider);
    module_links_share_the_login(&module, &token_dir, &provider);

    let session = provider.open_session(USER_PIN).expect("open a session");
    rsa_signatures_interoperate(&session);
    rsa_key_sizes_follow_policy(&session);
    ecdsa_signatures_interoperate(&session);
    hmac_matches_software(&session);
    rsa_oaep_round_trips(&session);
    aes_gcm_matches_software(&session);
    key_wrapper_matches_software(&setup, main_slot, &session);
    ecdh_matches_software_and_destroys_the_secret(&session);
    drop(session);
    pin_change_takes_effect_with_the_next_login(&setup, main_slot, &provider);
    drop(provider);

    raw_non_utf8_pin_logs_in(&setup, &module, raw_pin_slot);

    setup.finalize().expect("C_Finalize");
    std::fs::remove_dir_all(&token_dir).expect("remove the private token directory");
}

fn provider_selection_pins_the_token(setup: &Pkcs11, module: &Path, main_slot: Slot) {
    let error = Pkcs11Provider::new(module)
        .err()
        .expect("two initialized tokens make the default selection ambiguous");
    assert!(
        error
            .to_string()
            .contains("multiple initialized token slots"),
        "got: {error}"
    );

    let by_label = Pkcs11Provider::new_with_token(module, MAIN_TOKEN, None)
        .expect("select the main token by label");
    assert_eq!(by_label.slot_id(), main_slot.id());
    let serial = setup
        .get_token_info(main_slot)
        .expect("C_GetTokenInfo")
        .serial_number()
        .to_owned();
    let by_serial = Pkcs11Provider::new_with_token(module, MAIN_TOKEN, Some(&serial))
        .expect("select the main token by label and serial");
    assert_eq!(by_serial.slot_id(), main_slot.id());
    let by_id = Pkcs11Provider::new_with_slot_id(module, main_slot.id())
        .expect("select the main token by slot id");
    assert_eq!(by_id.slot_id(), main_slot.id());

    for (label, serial) in [
        ("kryptering-missing", None),
        (MAIN_TOKEN, Some("not-the-serial")),
    ] {
        let error = Pkcs11Provider::new_with_token(module, label, serial)
            .err()
            .expect("a selector without a matching token fails closed");
        assert!(
            error.to_string().contains("no initialized token matches"),
            "got: {error}"
        );
    }
}

fn wrong_pin_is_rejected(provider: &Pkcs11Provider) {
    // No session is logged in yet, so C_Login really checks the PIN.
    let error = provider
        .open_session("not-the-user-pin")
        .err()
        .expect("a wrong PIN must not log in");
    assert!(error.to_string().contains("C_Login failed"), "got: {error}");
}

/// Already-logged-in responses cannot authenticate any supplied PIN.
fn joining_is_refused(provider: &Pkcs11Provider) {
    for pin in [
        USER_PIN.as_bytes(),
        ROTATED_USER_PIN.as_bytes(),
        b"wrong",
        RAW_USER_PIN,
    ] {
        let error = provider
            .open_session_bytes(pin)
            .err()
            .expect("joining must fail closed");
        assert!(error.to_string().contains("cannot verify PIN"), "{error}");
    }
}

/// Concurrent operations share one authenticated session; new logins fail closed.
fn concurrent_sessions_share_the_login(module: &Path, provider: &Pkcs11Provider) {
    let session = provider.open_session(USER_PIN).expect("first login");
    joining_is_refused(provider);
    let other = Pkcs11Provider::new_with_token(module, MAIN_TOKEN, None).unwrap();
    let by_slot = Pkcs11Provider::new_with_slot_id(module, provider.slot_id()).unwrap();
    joining_is_refused(&other);
    joining_is_refused(&by_slot);
    let rsa_signer = Pkcs11Signer::new(&session, RSA_KEY, RSA_PSS).unwrap();
    let rsa_verifier = Pkcs11Verifier::new(&session, RSA_KEY, RSA_PSS).unwrap();
    let ec_signer = Pkcs11Signer::new(&session, EC_KEY, ECDSA_P256).unwrap();
    let ec_verifier = Pkcs11Verifier::new(&session, EC_KEY, ECDSA_P256).unwrap();
    std::thread::scope(|scope| {
        for (signer, verifier) in [(&rsa_signer, &rsa_verifier), (&ec_signer, &ec_verifier)] {
            scope.spawn(move || {
                for round in 0..8 {
                    let message = format!("concurrent round {round}");
                    let signature = signer.sign(message.as_bytes()).unwrap();
                    assert!(verifier.verify(message.as_bytes(), &signature).unwrap());
                }
            });
        }
    });
    drop(session);
    joining_is_refused(provider);
    assert!(rsa_verifier
        .verify(MESSAGE, &rsa_signer.sign(MESSAGE).unwrap())
        .unwrap());
    drop((rsa_signer, rsa_verifier, ec_signer, ec_verifier));
    provider
        .open_session(USER_PIN)
        .expect("fresh login after all objects close");
}

/// An alias to the module cannot bypass fail-closed login handling.
fn module_links_share_the_login(module: &Path, token_dir: &Path, provider: &Pkcs11Provider) {
    if !cfg!(unix) {
        return;
    }
    let held = provider.open_session(USER_PIN).unwrap();
    let hard_link = token_dir.join("libsofthsm2-hard-link");
    if let Err(error) = std::fs::hard_link(module, &hard_link) {
        eprintln!("skipping the hard-linked module case: {error}");
        return;
    }
    let linked = Pkcs11Provider::new_with_token(&hard_link, MAIN_TOKEN, None).unwrap();
    joining_is_refused(&linked);
    drop(held);
}

/// Raw and external logout/relogin transitions never authorize a cached PIN.
fn pin_change_takes_effect_with_the_next_login(
    setup: &Pkcs11,
    slot: Slot,
    provider: &Pkcs11Provider,
) {
    for external in [false, true] {
        let held = provider.open_session(USER_PIN).unwrap();
        let outside = setup.open_rw_session(slot).unwrap();
        {
            let raw = held.session().lock().unwrap();
            raw.set_pin(&AuthPin::from(USER_PIN), &AuthPin::from(ROTATED_USER_PIN))
                .unwrap();
            raw.logout().unwrap();
            if external {
                outside
                    .login(UserType::User, Some(&AuthPin::from(ROTATED_USER_PIN)))
                    .unwrap();
            } else {
                raw.login(UserType::User, Some(&AuthPin::from(ROTATED_USER_PIN)))
                    .unwrap();
            }
        }
        joining_is_refused(provider);
        outside.logout().unwrap();
        assert!(provider.open_session(USER_PIN).is_err());
        let fresh = provider
            .open_session(ROTATED_USER_PIN)
            .expect("token checks the rotated PIN");
        joining_is_refused(provider);
        fresh
            .session()
            .lock()
            .unwrap()
            .set_pin(&AuthPin::from(ROTATED_USER_PIN), &AuthPin::from(USER_PIN))
            .unwrap();
        drop((fresh, outside, held));
        provider
            .open_session(USER_PIN)
            .expect("fresh login with restored PIN");
    }
}

fn rsa_signatures_interoperate(session: &Pkcs11Session) {
    let public = rsa_public_key(session);
    for algorithm in [
        RSA_PSS,
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
    ] {
        let signer = Pkcs11Signer::new(session, RSA_KEY, algorithm).expect("RSA signer");
        let verifier = Pkcs11Verifier::new(session, RSA_KEY, algorithm).expect("RSA verifier");
        let signature = signer.sign(MESSAGE).expect("C_Sign");
        assert_eq!(signature.len(), 256, "{algorithm:?}");
        assert!(
            verifier.verify(MESSAGE, &signature).unwrap(),
            "{algorithm:?}"
        );
        assert!(
            !verifier.verify(b"tampered", &signature).unwrap(),
            "{algorithm:?}"
        );
        // CKR_SIGNATURE_LEN_RANGE is a failed verification, not an error.
        assert!(
            !verifier.verify(MESSAGE, &signature[1..]).unwrap(),
            "{algorithm:?}"
        );
        let software = SoftwareVerifier::new(algorithm, public.clone()).unwrap();
        assert!(
            software.verify(MESSAGE, &signature).unwrap(),
            "{algorithm:?}"
        );
    }
}

/// All RSA entry points enforce the floor on actual token objects, including legacy mode.
fn rsa_key_sizes_follow_policy(session: &Pkcs11Session) {
    fn rejected<T>(result: kryptering::Result<T>) {
        let error = result.err().expect("undersized RSA key must be rejected");
        assert!(
            matches!(error, kryptering::Error::UnsupportedAlgorithm { .. }),
            "{error}"
        );
        assert!(
            error.to_string().contains("PKCS#11 requires at least"),
            "{error}"
        );
    }
    for label in [RSA_TOO_SMALL_KEY, RSA_LEGACY_KEY] {
        let allowed = label == RSA_LEGACY_KEY && cfg!(feature = "legacy");
        for algorithm in [
            RSA_PSS,
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        ] {
            let signer = Pkcs11Signer::new(session, label, algorithm).unwrap();
            let verifier = Pkcs11Verifier::new(session, label, algorithm).unwrap();
            if allowed {
                let signature = signer.sign(MESSAGE).unwrap();
                assert!(verifier.verify(MESSAGE, &signature).unwrap());
            } else {
                rejected(signer.sign(MESSAGE));
                rejected(verifier.verify(MESSAGE, &[]));
            }
        }
        let mut transports = vec![KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        })];
        if cfg!(feature = "legacy") {
            #[cfg(feature = "legacy")]
            transports.push(KeyTransportAlgorithm::RsaPkcs1v15);
        }
        for algorithm in transports.drain(..) {
            let encryptor = Pkcs11Encryptor::new(session, label, algorithm).unwrap();
            let decryptor = Pkcs11Decryptor::new(session, label, algorithm).unwrap();
            if allowed {
                let ciphertext = encryptor.encrypt(&KEY_MATERIAL).unwrap();
                assert_eq!(decryptor.decrypt(&ciphertext).unwrap(), KEY_MATERIAL);
            } else {
                rejected(encryptor.encrypt(&KEY_MATERIAL));
                rejected(decryptor.decrypt(&[0; 128]));
            }
        }
    }
    // The HMAC wrapper accepts SignatureAlgorithm too; an RSA algorithm must
    // not bypass the same modulus requirement via this alternate entry point.
    let alias = Pkcs11HmacSigner::new(session, HMAC_KEY, RSA_PSS).unwrap();
    assert!(alias
        .sign(MESSAGE)
        .unwrap_err()
        .to_string()
        .contains("CKA_MODULUS"));
    assert!(alias
        .verify(MESSAGE, &[])
        .unwrap_err()
        .to_string()
        .contains("CKA_MODULUS"));
}

fn ecdsa_signatures_interoperate(session: &Pkcs11Session) {
    use p256::pkcs8::EncodePublicKey;

    let public_der = p256::PublicKey::from_sec1_bytes(&ec_public_point(session))
        .expect("token P-256 point")
        .to_public_key_der()
        .unwrap();
    let public =
        SoftwareKey::from_spki_der(KeyAlgorithm::Ec(EcCurve::P256), public_der.as_bytes()).unwrap();

    let signer = Pkcs11Signer::new(session, EC_KEY, ECDSA_P256).expect("EC signer");
    let verifier = Pkcs11Verifier::new(session, EC_KEY, ECDSA_P256).expect("EC verifier");
    let signature = signer.sign(MESSAGE).expect("C_Sign (ECDSA)");
    // CKM_ECDSA returns the fixed-width r || s encoding.
    assert_eq!(signature.len(), 64);
    assert!(verifier.verify(MESSAGE, &signature).unwrap());
    assert!(!verifier.verify(b"tampered", &signature).unwrap());
    let software = SoftwareVerifier::new(ECDSA_P256, public).unwrap();
    assert!(software.verify(MESSAGE, &signature).unwrap());
}

fn hmac_matches_software(session: &Pkcs11Session) {
    let algorithm = SignatureAlgorithm::Hmac(HashAlgorithm::Sha256);
    let hmac = Pkcs11HmacSigner::new(session, HMAC_KEY, algorithm).expect("HMAC key");
    let tag = hmac.sign(MESSAGE).expect("C_Sign (HMAC)");
    assert_eq!(
        tag,
        kryptering::digest::compute_hmac(HashAlgorithm::Sha256, &HMAC_KEY_VALUE, MESSAGE).unwrap()
    );
    assert!(hmac.verify(MESSAGE, &tag).unwrap());
    assert!(!hmac.verify(b"tampered", &tag).unwrap());
}

fn rsa_oaep_round_trips(session: &Pkcs11Session) {
    // SoftHSM2 2.6 implements CKM_RSA_PKCS_OAEP only with SHA-1, MGF1-SHA-1
    // and an empty label.
    let algorithm = KeyTransportAlgorithm::RsaOaep(OaepConfig {
        digest: HashAlgorithm::Sha1,
        mgf_digest: HashAlgorithm::Sha1,
    });
    let encryptor = Pkcs11Encryptor::new(session, RSA_KEY, algorithm).expect("RSA encryptor");
    let decryptor = Pkcs11Decryptor::new(session, RSA_KEY, algorithm).expect("RSA decryptor");
    let ciphertext = encryptor
        .encrypt(&KEY_MATERIAL)
        .expect("C_Encrypt (RSA-OAEP)");
    assert_eq!(ciphertext.len(), 256);
    assert_eq!(
        decryptor
            .decrypt(&ciphertext)
            .expect("C_Decrypt (RSA-OAEP)"),
        KEY_MATERIAL
    );

    let software = kryptering::keytransport::kt_encrypt(
        algorithm,
        &rsa_public_key(session),
        &KEY_MATERIAL,
        None,
    )
    .unwrap();
    assert_eq!(
        decryptor
            .decrypt(&software)
            .expect("C_Decrypt of a software ciphertext"),
        KEY_MATERIAL
    );

    let mut tampered = ciphertext;
    tampered[128] ^= 1;
    assert!(decryptor.decrypt(&tampered).is_err());
}

fn aes_gcm_matches_software(session: &Pkcs11Session) {
    let algorithm = CipherAlgorithm::AesGcm(AesKeySize::Aes256);
    let cipher = Pkcs11Cipher::new(session, GCM_KEY, algorithm).expect("AES-GCM key");
    let sealed = cipher.encrypt(MESSAGE).expect("C_Encrypt (AES-GCM)");
    assert_eq!(sealed.len(), 12 + MESSAGE.len() + 16);
    assert_eq!(
        kryptering::cipher::decrypt(algorithm, &GCM_KEY_VALUE, &sealed).unwrap(),
        MESSAGE
    );

    let software = kryptering::cipher::encrypt(algorithm, &GCM_KEY_VALUE, MESSAGE).unwrap();
    assert_eq!(
        cipher
            .decrypt(&software)
            .expect("C_Decrypt of a software ciphertext"),
        MESSAGE
    );

    let mut tampered = sealed;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(cipher.decrypt(&tampered).is_err());
    assert!(Pkcs11Cipher::new(
        session,
        GCM_KEY,
        CipherAlgorithm::AesCbc(AesKeySize::Aes256)
    )
    .is_err());
}

fn key_wrapper_matches_software(setup: &Pkcs11, slot: Slot, session: &Pkcs11Session) {
    let kek_256 = Pkcs11KeyWrapper::new(
        session,
        KEK_256,
        KeyWrapAlgorithm::AesKw(AesKeySize::Aes256),
    )
    .expect("AES-256 KEK opened as AES-256");
    let kek_128 = Pkcs11KeyWrapper::new(
        session,
        KEK_128,
        KeyWrapAlgorithm::AesKw(AesKeySize::Aes128),
    )
    .expect("AES-128 KEK opened as AES-128");
    let algorithm = KeyWrapAlgorithm::AesKw(AesKeySize::Aes256);
    let kek_known =
        Pkcs11KeyWrapper::new(session, KEK_KNOWN, algorithm).expect("imported AES-256 KEK");
    for (label, declared) in [(KEK_128, AesKeySize::Aes256), (KEK_256, AesKeySize::Aes128)] {
        let error = Pkcs11KeyWrapper::new(session, label, KeyWrapAlgorithm::AesKw(declared))
            .err()
            .expect("a KEK whose CKA_VALUE_LEN differs from the declared size is rejected");
        assert!(
            error.to_string().contains("KEK length mismatch"),
            "{label}: {error}"
        );
    }

    // SoftHSM2 2.6 offers CKM_AES_KEY_WRAP only to C_WrapKey/C_UnwrapKey
    // (CKF_WRAP | CKF_UNWRAP), so this covers the temporary-object path.
    let info = setup
        .get_mechanism_info(slot, MechanismType::AES_KEY_WRAP)
        .expect("C_GetMechanismInfo (CKM_AES_KEY_WRAP)");
    assert!(info.wrap() && info.unwrap(), "{info:?}");

    let secret_keys = secret_key_count(session);
    for kek in [&kek_256, &kek_128, &kek_known] {
        for key in [&KEY_MATERIAL[..], &KEY_MATERIAL[..16], &KEY_MATERIAL[..24]] {
            let wrapped = kek.wrap(key).expect("C_WrapKey (AES key wrap)");
            assert_eq!(wrapped.len(), key.len() + 8);
            assert_eq!(
                KeyWrapper::unwrap(kek, &wrapped).expect("C_UnwrapKey (AES key unwrap)"),
                key
            );
            for index in [0, wrapped.len() - 1] {
                let mut tampered = wrapped.clone();
                tampered[index] ^= 1;
                assert!(KeyWrapper::unwrap(kek, &tampered).is_err());
            }
        }
        // Lengths outside RFC 3394 are refused as by the software providers
        // (SoftHSM2 would zero-pad a partial block).
        for key in [&KEY_MATERIAL[..8], &KEY_MATERIAL[..20], &[]] {
            let error = kek.wrap(key).expect_err("invalid key length");
            assert!(
                error.to_string().contains("invalid AES-KW input length"),
                "{}: {error}",
                key.len()
            );
        }
        for wrapped in [&[0; 16][..], &[0; 36]] {
            let error = KeyWrapper::unwrap(kek, wrapped).expect_err("invalid wrapped length");
            assert!(
                error.to_string().contains("invalid AES-KW input length"),
                "{}: {error}",
                wrapped.len()
            );
        }
    }

    // AES key wrap is deterministic: with a known KEK value the token's
    // output has to match the software provider byte for byte.
    let software = kryptering::keywrap::wrap(algorithm, &KEK_KNOWN_VALUE, &KEY_MATERIAL).unwrap();
    let token = kek_known.wrap(&KEY_MATERIAL).expect("C_WrapKey");
    assert_eq!(token, software);
    assert_eq!(
        KeyWrapper::unwrap(&kek_known, &software).expect("C_UnwrapKey of a software wrap"),
        KEY_MATERIAL
    );
    assert_eq!(
        kryptering::keywrap::unwrap(algorithm, &KEK_KNOWN_VALUE, &token).unwrap(),
        KEY_MATERIAL
    );

    // C_WrapKey and C_UnwrapKey fail once the temporary object exists (the
    // KEK lacks CKA_WRAP and CKA_UNWRAP); it has to be destroyed all the same.
    let no_wrap =
        Pkcs11KeyWrapper::new(session, KEK_NO_WRAP, algorithm).expect("KEK without CKA_WRAP");
    let error = no_wrap.wrap(&KEY_MATERIAL).expect_err("CKA_WRAP is false");
    assert!(
        error.to_string().contains("C_WrapKey failed"),
        "got: {error}"
    );
    let error = KeyWrapper::unwrap(&no_wrap, &software).expect_err("CKA_UNWRAP is false");
    assert!(
        error.to_string().contains("C_UnwrapKey failed"),
        "got: {error}"
    );

    // The temporary key objects are all destroyed again.
    assert_no_session_secret_key(session, "after key wrapping");
    assert_eq!(secret_key_count(session), secret_keys);
}

/// Reject mismatched P-256 output lengths and clean up full-width agreement secrets.
fn ecdh_matches_software_and_destroys_the_secret(session: &Pkcs11Session) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;

    // Pkcs11KeyAgreement takes the curve from CKA_EC_PARAMS; the token has to
    // expose the named-curve OID the module maps to P-256.
    let private = session.find_private_key(EC_KEY).expect("EC private key");
    assert_eq!(
        byte_attribute(session, private, AttributeType::EcParams),
        P256_EC_PARAMS
    );
    for length in [0, 1, 31, 33, 48, 66] {
        assert!(Pkcs11KeyAgreement::new(session, EC_KEY, length).is_err());
    }
    let agreement = Pkcs11KeyAgreement::new(session, EC_KEY, 32).expect("ECDH key");

    let peer = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let peer_point = peer.public_key().to_encoded_point(false);
    let peer_key = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        peer.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let expected =
        kryptering::keyagreement::agree(EcCurve::P256, &ec_public_point(session), &peer_key)
            .expect("software ECDH");

    assert_no_derived_secret(session, "before agree");
    let shared = agreement
        .agree(peer_point.as_bytes())
        .expect("C_DeriveKey (ECDH)");
    assert_eq!(shared, expected);
    assert_no_derived_secret(session, "after agree");

    // (0, 0) is not a P-256 point: C_DeriveKey fails and nothing may remain.
    let mut not_on_curve = [0; 65];
    not_on_curve[0] = 0x04;
    assert!(agreement.agree(&not_on_curve).is_err());
    assert_no_derived_secret(session, "after a rejected peer point");

    // Control: the search does find a secret derived with the same template
    // when one is left behind, so the checks above are not vacuous.
    let guard = session.session().lock().expect("session lock");
    let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_point.as_bytes());
    let leftover = guard
        .derive_key(
            &Mechanism::Ecdh1Derive(params),
            private,
            &ecdh_derive_template(),
        )
        .expect("C_DeriveKey");
    assert_eq!(
        guard
            .find_objects(&ecdh_derive_template())
            .expect("C_FindObjects"),
        [leftover]
    );
    guard.destroy_object(leftover).expect("C_DestroyObject");
    drop(guard);
    assert_no_derived_secret(session, "after destroying the control secret");
}

fn raw_non_utf8_pin_logs_in(setup: &Pkcs11, module: &Path, slot: Slot) {
    // SoftHSM2 treats PINs as opaque byte strings (only the 4..=255 length is
    // checked), so the raw-PIN token was initialised with non-UTF-8 bytes.
    let provider = Pkcs11Provider::new_with_token(module, RAW_PIN_TOKEN, None)
        .expect("select the raw-PIN token");

    // Kryptering holds no record of a login made past it, so it cannot tell
    // whether the PIN it is given is the one that login used: even the right
    // PIN is refused.
    let outside = setup.open_rw_session(slot).expect("C_OpenSession");
    outside
        .login_with_raw(
            UserType::User,
            &RawAuthPin::new(Box::new(RAW_USER_PIN.to_vec())),
        )
        .expect("C_Login outside Kryptering");
    let error = provider
        .open_session_bytes(RAW_USER_PIN)
        .err()
        .expect("a login Kryptering did not make cannot be verified");
    assert!(
        error.to_string().contains("cannot verify PIN"),
        "got: {error}"
    );
    // Closing the application's only session on the token ends that login.
    drop(outside);

    // Nothing is logged in to this token, so the attempt reaches the PIN
    // check: a lossy UTF-8 rendering is a different PIN.
    let error = provider
        .open_session(&String::from_utf8_lossy(RAW_USER_PIN))
        .err()
        .expect("the lossy UTF-8 rendering must not log in");
    assert!(error.to_string().contains("C_Login failed"), "got: {error}");

    let session = provider
        .open_session_bytes(RAW_USER_PIN)
        .expect("log in with the raw non-UTF-8 PIN");
    // The key is a private object: finding and using it needs a logged-in
    // session.
    let algorithm = CipherAlgorithm::AesGcm(AesKeySize::Aes256);
    let cipher = Pkcs11Cipher::new(&session, RAW_PIN_KEY, algorithm).expect("private key");
    let sealed = cipher.encrypt(MESSAGE).expect("C_Encrypt (AES-GCM)");
    assert_eq!(
        kryptering::cipher::decrypt(algorithm, &GCM_KEY_VALUE, &sealed).unwrap(),
        MESSAGE
    );
}

// ---------------------------------------------------------------------------
// Token setup (cryptoki directly)
// ---------------------------------------------------------------------------

fn softhsm2_module() -> Option<PathBuf> {
    let Some(module) = std::env::var_os(MODULE_ENV).filter(|value| !value.is_empty()) else {
        eprintln!("skipping SoftHSM2 PKCS#11 test: set {MODULE_ENV} to libsofthsm2.so to run it");
        return None;
    };
    let module = PathBuf::from(module);
    assert!(
        module.is_file(),
        "{MODULE_ENV}={} is not a file",
        module.display()
    );
    Some(module)
}

/// Create a private token directory and the `softhsm2.conf` pointing at it.
fn private_token_dir() -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("softhsm2-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("remove a stale token directory");
    }
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).expect("create the token directory");
    std::fs::write(
        dir.join("softhsm2.conf"),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .expect("write softhsm2.conf");
    dir
}

/// Initialise the token in SoftHSM2's spare slot.
///
/// SoftHSM2 always keeps one uninitialised token and adds a fresh one on the
/// next `C_GetSlotList` once it has been initialised.
fn init_token(pkcs11: &Pkcs11, label: &str) -> Slot {
    let slot = pkcs11
        .get_slots_with_token()
        .expect("C_GetSlotList")
        .into_iter()
        .find(|slot| {
            !pkcs11
                .get_token_info(*slot)
                .expect("C_GetTokenInfo")
                .token_initialized()
        })
        .expect("an uninitialised SoftHSM2 token");
    pkcs11
        .init_token(slot, &AuthPin::from(SO_PIN), label)
        .expect("C_InitToken");
    slot
}

fn so_session(pkcs11: &Pkcs11, slot: Slot) -> Session {
    let session = pkcs11.open_rw_session(slot).expect("C_OpenSession");
    session
        .login(UserType::So, Some(&AuthPin::from(SO_PIN)))
        .expect("C_Login (SO)");
    session
}

fn populate_main_token(pkcs11: &Pkcs11, slot: Slot) {
    let session = so_session(pkcs11, slot);
    session
        .init_pin(&AuthPin::from(USER_PIN))
        .expect("C_InitPIN");
    session.logout().expect("C_Logout (SO)");
    session
        .login(UserType::User, Some(&AuthPin::from(USER_PIN)))
        .expect("C_Login (user)");

    for (label, len) in [(KEK_256, 32_usize), (KEK_128, 16)] {
        let mut template = secret_template(label, KeyType::AES);
        template.extend([
            Attribute::ValueLen(len.try_into().unwrap()),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
        ]);
        session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .expect("C_GenerateKey (AES KEK)");
    }

    for (label, bits) in [
        (RSA_KEY, 2048),
        (RSA_LEGACY_KEY, 1024),
        (RSA_TOO_SMALL_KEY, 512),
    ] {
        session
            .generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Label(label.into()),
                    Attribute::ModulusBits(bits.into()),
                    Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                ],
                &private_template(label, [Attribute::Sign(true), Attribute::Decrypt(true)]),
            )
            .expect("C_GenerateKeyPair (RSA size-policy control)");
    }
    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Label(EC_KEY.into()),
                Attribute::EcParams(P256_EC_PARAMS.to_vec()),
                Attribute::Verify(true),
            ],
            &private_template(EC_KEY, [Attribute::Sign(true), Attribute::Derive(true)]),
        )
        .expect("C_GenerateKeyPair (P-256)");

    import_secret(
        &session,
        KEK_KNOWN,
        KeyType::AES,
        &KEK_KNOWN_VALUE,
        [Attribute::Wrap(true), Attribute::Unwrap(true)],
    );
    import_secret(
        &session,
        KEK_NO_WRAP,
        KeyType::AES,
        &KEK_KNOWN_VALUE,
        [Attribute::Wrap(false), Attribute::Unwrap(false)],
    );
    import_secret(
        &session,
        GCM_KEY,
        KeyType::AES,
        &GCM_KEY_VALUE,
        [Attribute::Encrypt(true), Attribute::Decrypt(true)],
    );
    // SoftHSM2 requires at least 32 key bytes for CKM_SHA256_HMAC.
    import_secret(
        &session,
        HMAC_KEY,
        KeyType::GENERIC_SECRET,
        &HMAC_KEY_VALUE,
        [Attribute::Sign(true), Attribute::Verify(true)],
    );
    session.logout().expect("C_Logout (user)");
}

fn populate_raw_pin_token(pkcs11: &Pkcs11, slot: Slot, module: &Path) {
    let session = so_session(pkcs11, slot);
    init_raw_user_pin(module, &session, RAW_USER_PIN);
    session.logout().expect("C_Logout (SO)");
    session
        .login_with_raw(
            UserType::User,
            &RawAuthPin::new(Box::new(RAW_USER_PIN.to_vec())),
        )
        .expect("C_Login with the raw user PIN");
    import_secret(
        &session,
        RAW_PIN_KEY,
        KeyType::AES,
        &GCM_KEY_VALUE,
        [Attribute::Encrypt(true), Attribute::Decrypt(true)],
    );
    session.logout().expect("C_Logout (user)");
}

/// `C_InitPIN` with raw PIN bytes.
///
/// cryptoki's safe `Session::init_pin` only accepts a UTF-8 `AuthPin`, so
/// this goes through the raw bindings. Loading the module again returns the
/// already-initialised library, in which `session`'s handle is valid.
fn init_raw_user_pin(module: &Path, session: &Session, pin: &[u8]) {
    // SAFETY: the library is already loaded and initialised by `session`'s
    // context; loading it again only takes another reference.
    let raw = unsafe { cryptoki_sys::Pkcs11::new(module) }.expect("load the raw bindings");
    let mut pin = pin.to_vec();
    let pin_len = pin.len().try_into().expect("PIN length fits CK_ULONG");
    // SAFETY: the handle belongs to a live SO session of this library, and
    // `pin` outlives the call with `pin_len` as its exact length.
    let rv = unsafe { raw.C_InitPIN(session.handle(), pin.as_mut_ptr(), pin_len) };
    assert_eq!(
        rv,
        cryptoki_sys::CKR_OK,
        "C_InitPIN with a non-UTF-8 PIN returned {rv:#x}"
    );
}

fn secret_template(label: &str, key_type: KeyType) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(key_type),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Label(label.into()),
    ]
}

fn private_template<const N: usize>(label: &str, usage: [Attribute; N]) -> Vec<Attribute> {
    let mut template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.into()),
    ];
    template.extend(usage);
    template
}

/// Import a known secret key value (`CKA_VALUE_LEN` is derived by the token).
fn import_secret<const N: usize>(
    session: &Session,
    label: &str,
    key_type: KeyType,
    value: &[u8],
    usage: [Attribute; N],
) {
    let mut template = secret_template(label, key_type);
    template.push(Attribute::Value(value.to_vec()));
    template.extend(usage);
    session
        .create_object(&template)
        .expect("C_CreateObject (secret key)");
}

// ---------------------------------------------------------------------------
// Token inspection
// ---------------------------------------------------------------------------

/// The template `Pkcs11KeyAgreement::agree` hands to `C_DeriveKey` for a
/// 32-byte shared secret.
fn ecdh_derive_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::ValueLen(32.into()),
        Attribute::Extractable(true),
        Attribute::Sensitive(false),
        Attribute::Token(false),
    ]
}

fn assert_no_derived_secret(session: &Pkcs11Session, stage: &str) {
    let guard = session.session().lock().expect("session lock");
    let derived = guard
        .find_objects(&ecdh_derive_template())
        .expect("C_FindObjects");
    assert!(
        derived.is_empty(),
        "{stage}: {} derived ECDH secret(s) remain",
        derived.len()
    );
    drop(guard);
    assert_no_session_secret_key(session, stage);
}

fn assert_no_session_secret_key(session: &Pkcs11Session, stage: &str) {
    // Setup creates token objects only, so any session secret key is a leak.
    let guard = session.session().lock().expect("session lock");
    let session_secrets = guard
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Token(false),
        ])
        .expect("C_FindObjects");
    assert!(
        session_secrets.is_empty(),
        "{stage}: {} session secret key(s) remain",
        session_secrets.len()
    );
}

/// Secret keys visible to the session, token and session objects alike.
fn secret_key_count(session: &Pkcs11Session) -> usize {
    let guard = session.session().lock().expect("session lock");
    guard
        .find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY)])
        .expect("C_FindObjects")
        .len()
}

fn byte_attribute(session: &Pkcs11Session, object: ObjectHandle, kind: AttributeType) -> Vec<u8> {
    let guard = session.session().lock().expect("session lock");
    guard
        .get_attributes(object, &[kind])
        .expect("C_GetAttributeValue")
        .into_iter()
        .find_map(|attribute| match attribute {
            Attribute::EcParams(bytes)
            | Attribute::EcPoint(bytes)
            | Attribute::Modulus(bytes)
            | Attribute::PublicExponent(bytes) => Some(bytes),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{kind} not returned"))
}

/// The token's P-256 public point as an uncompressed SEC1 encoding.
fn ec_public_point(session: &Pkcs11Session) -> Vec<u8> {
    let public = session.find_public_key(EC_KEY).expect("EC public key");
    let point = byte_attribute(session, public, AttributeType::EcPoint);
    // PKCS#11 v2.40 wraps CKA_EC_POINT in a DER OCTET STRING, as SoftHSM2
    // does; some tokens return the bare point.
    if point.len() == 67 && point.starts_with(&[0x04, 0x41]) {
        point[2..].to_vec()
    } else {
        point
    }
}

/// The token's RSA public key, imported into the software provider.
fn rsa_public_key(session: &Pkcs11Session) -> SoftwareKey {
    use rsa::pkcs8::EncodePublicKey;

    let public = session.find_public_key(RSA_KEY).expect("RSA public key");
    let modulus = byte_attribute(session, public, AttributeType::Modulus);
    let exponent = byte_attribute(session, public, AttributeType::PublicExponent);
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from_bytes_be(&exponent),
    )
    .expect("token RSA public key");
    let der = key.to_public_key_der().unwrap();
    SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, der.as_bytes()).unwrap()
}
