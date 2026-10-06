//! Compile-time cryptographic provider selection and attestation.

use std::sync::OnceLock;

use crate::algorithm::{
    CipherAlgorithm, HashAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, SignatureAlgorithm,
};
use crate::error::{Error, Result};

/// Selected document-cryptography implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendId {
    /// The RustCrypto ecosystem implementation.
    RustCrypto,
    /// AWS-LC through `aws-lc-rs`.
    AwsLc,
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RustCrypto => "rustcrypto",
            Self::AwsLc => "aws-lc",
        })
    }
}

/// Selected TLS cryptography implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsBackendId {
    /// rustls with ring.
    Ring,
    /// rustls with AWS-LC.
    AwsLc,
}

/// Runtime FIPS state for the selected providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsStatus {
    /// FIPS enforcement was not compiled in.
    Disabled,
    /// FIPS was requested but explicit initialization has not run.
    Uninitialized,
    /// Every selected provider attested that FIPS mode is active.
    Active,
}

/// A key family without exposing a provider-specific key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Rsa,
    Ec(crate::algorithm::EcCurve),
    Ed25519,
    X25519,
    Hmac,
    Aes,
    Dh,
    Dsa,
    TripleDes,
    #[cfg(feature = "post-quantum")]
    PostQuantum(crate::algorithm::PqAlgorithm),
    /// Aggregate composite key from draft-ietf-jose-pq-composite-sigs.
    #[cfg(feature = "post-quantum")]
    CompositeMlDsa(crate::algorithm::CompositeMlDsaVariant),
}

/// A provider operation, parameterized by the requested algorithm where useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Random,
    KeyImport(KeyAlgorithm),
    KeyExport(KeyAlgorithm),
    Digest(HashAlgorithm),
    Hmac(HashAlgorithm),
    Sign(SignatureAlgorithm),
    Verify(SignatureAlgorithm),
    Encrypt(CipherAlgorithm),
    Decrypt(CipherAlgorithm),
    Wrap(KeyWrapAlgorithm),
    Unwrap(KeyWrapAlgorithm),
    TransportEncrypt(KeyTransportAlgorithm),
    TransportDecrypt(KeyTransportAlgorithm),
    Agreement(crate::algorithm::EcCurve),
    X25519Agreement,
    DhAgreement,
    ConcatKdf(HashAlgorithm),
    Pbkdf2(HashAlgorithm),
    Hkdf(HashAlgorithm),
    /// RFC 7292 Appendix B password derivation.
    Pkcs12Kdf(HashAlgorithm),
    #[cfg(feature = "post-quantum")]
    KemGenerate(crate::algorithm::KemAlgorithm),
    #[cfg(feature = "post-quantum")]
    KemEncapsulate(crate::algorithm::KemAlgorithm),
    #[cfg(feature = "post-quantum")]
    KemDecapsulate(crate::algorithm::KemAlgorithm),
}

/// One advertised provider capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub operation: Operation,
    pub fips_approved: bool,
}

/// Attested information about the compile-time selected providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    pub document: BackendId,
    pub tls: Option<TlsBackendId>,
    pub fips: FipsStatus,
}

static INITIALIZATION: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn initialization_error(message: String) -> Error {
    #[cfg(feature = "fips")]
    {
        Error::FipsUnavailable {
            backend: selected_backend(),
            message,
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        Error::BackendInitialization {
            backend: selected_backend(),
            message,
        }
    }
}

/// Return the selected document provider.
#[must_use]
pub const fn selected_backend() -> BackendId {
    <compile_time_provider::SelectedProvider as compile_time_provider::Provider>::ID
}

/// Return the selected TLS provider, if TLS support is compiled in.
#[must_use]
pub const fn selected_tls_backend() -> Option<TlsBackendId> {
    #[cfg(feature = "tls-ring")]
    return Some(TlsBackendId::Ring);
    #[cfg(feature = "tls-aws-lc")]
    return Some(TlsBackendId::AwsLc);
    #[cfg(not(any(feature = "tls-ring", feature = "tls-aws-lc")))]
    None
}

fn initialize_selected() -> std::result::Result<(), String> {
    use compile_time_provider::Provider as _;

    compile_time_provider::SelectedProvider::initialize()?;
    #[cfg(all(feature = "tls-aws-lc", not(feature = "aws-lc")))]
    {
        // rustls uses the same aws-lc-rs package and process state.
        aws_lc_rs::init();
        #[cfg(feature = "fips")]
        aws_lc_rs::try_fips_mode().map_err(str::to_owned)?;
    }
    #[cfg(all(feature = "fips", feature = "tls-aws-lc"))]
    {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        if !provider.fips() {
            return Err("the selected AWS-LC rustls provider did not attest FIPS mode".into());
        }
    }
    Ok(())
}

/// Explicitly initialize and attest every selected provider.
///
/// This operation is idempotent.  The first success or failure is retained for
/// the process lifetime so provider state cannot silently change underneath
/// already-created keys or TLS configurations.
pub fn initialize_backend() -> Result<BackendInfo> {
    match INITIALIZATION.get_or_init(initialize_selected) {
        Ok(()) => backend_info(),
        Err(message) => Err(initialization_error(message.clone())),
    }
}

/// Ensure cryptographic use is allowed under the initialization policy.
pub(crate) fn ensure_backend() -> Result<()> {
    if let Some(result) = INITIALIZATION.get() {
        return result.clone().map_err(initialization_error);
    }
    #[cfg(feature = "fips")]
    return Err(Error::BackendNotInitialized {
        backend: selected_backend(),
    });
    #[cfg(not(feature = "fips"))]
    initialize_backend().map(|_| ())
}

/// Enforce FIPS approval for an operation performed by an out-of-process
/// backend (PKCS#11 HSM). Unlike [`require_supported`], this does not check
/// whether the selected software document provider implements the operation
/// — the HSM may support algorithms the software provider does not. It only
/// enforces the FIPS approval policy: in a `fips` build, non-approved
/// operations are rejected before they reach the token.
#[cfg(all(feature = "pkcs11", not(target_arch = "wasm32")))]
pub(crate) fn require_fips_approved(operation: Operation) -> Result<()> {
    ensure_backend()?;
    #[cfg(feature = "fips")]
    {
        if !operation_is_fips_approved(operation) {
            return Err(Error::unsupported(
                operation,
                "operation is not FIPS-approved",
            ));
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        let _ = operation;
    }
    Ok(())
}

/// Inspect selected providers without triggering implicit initialization.
pub fn backend_info() -> Result<BackendInfo> {
    let fips = if cfg!(feature = "fips") {
        if matches!(INITIALIZATION.get(), Some(Ok(()))) {
            FipsStatus::Active
        } else {
            FipsStatus::Uninitialized
        }
    } else {
        FipsStatus::Disabled
    };
    Ok(BackendInfo {
        document: selected_backend(),
        tls: selected_tls_backend(),
        fips,
    })
}

/// Report whether the selected document provider supports an operation.
pub fn supports(operation: Operation) -> Result<bool> {
    ensure_backend()?;
    Ok(provider_supports(operation))
}

/// Return the complete capability registry for the selected document provider.
///
/// Every entry is a fully parameterized operation that is accepted by
/// [`supports`]. In a FIPS build the registry is unavailable before explicit
/// initialization and excludes both unimplemented and non-approved
/// operations. This makes the returned registry suitable for generating
/// provider documentation and for fail-closed algorithm negotiation.
pub fn capabilities() -> Result<Vec<Capability>> {
    ensure_backend()?;
    Ok(known_operations()
        .into_iter()
        .filter(|operation| provider_supports(*operation))
        .map(|operation| Capability {
            operation,
            fips_approved: operation_is_fips_approved(operation),
        })
        .collect())
}

fn known_operations() -> Vec<Operation> {
    let hashes = known_hashes();
    let curves = [
        crate::algorithm::EcCurve::P256,
        crate::algorithm::EcCurve::P384,
        crate::algorithm::EcCurve::P521,
    ];
    let aes_sizes = [
        crate::algorithm::AesKeySize::Aes128,
        crate::algorithm::AesKeySize::Aes192,
        crate::algorithm::AesKeySize::Aes256,
    ];

    let mut operations = vec![Operation::Random];
    let mut keys = vec![
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Hmac,
        KeyAlgorithm::Aes,
        KeyAlgorithm::Dh,
        KeyAlgorithm::Dsa,
        KeyAlgorithm::TripleDes,
    ];
    keys.extend(curves.into_iter().map(KeyAlgorithm::Ec));
    #[cfg(feature = "post-quantum")]
    {
        use crate::algorithm::{
            CompositeMlDsaVariant, MlDsaVariant, MlKemVariant, PqAlgorithm, SlhDsaVariant,
        };
        keys.extend(
            CompositeMlDsaVariant::ALL
                .into_iter()
                .map(KeyAlgorithm::CompositeMlDsa),
        );
        keys.extend(
            [
                MlDsaVariant::MlDsa44,
                MlDsaVariant::MlDsa65,
                MlDsaVariant::MlDsa87,
            ]
            .into_iter()
            .map(|variant| KeyAlgorithm::PostQuantum(PqAlgorithm::MlDsa(variant))),
        );
        keys.extend(
            [
                SlhDsaVariant::Sha2_128f,
                SlhDsaVariant::Sha2_128s,
                SlhDsaVariant::Sha2_192f,
                SlhDsaVariant::Sha2_192s,
                SlhDsaVariant::Sha2_256f,
                SlhDsaVariant::Sha2_256s,
            ]
            .into_iter()
            .map(|variant| KeyAlgorithm::PostQuantum(PqAlgorithm::SlhDsa(variant))),
        );
        keys.extend(
            [
                MlKemVariant::MlKem512,
                MlKemVariant::MlKem768,
                MlKemVariant::MlKem1024,
            ]
            .into_iter()
            .map(|variant| KeyAlgorithm::PostQuantum(PqAlgorithm::MlKem(variant))),
        );
    }
    for key in keys {
        operations.push(Operation::KeyImport(key));
        operations.push(Operation::KeyExport(key));
    }

    for hash in hashes.iter().copied() {
        operations.extend([
            Operation::Digest(hash),
            Operation::Hmac(hash),
            Operation::ConcatKdf(hash),
            Operation::Pbkdf2(hash),
            Operation::Hkdf(hash),
            Operation::Pkcs12Kdf(hash),
        ]);
    }

    let mut signatures = Vec::new();
    for hash in hashes.iter().copied() {
        signatures.extend([
            SignatureAlgorithm::RsaPkcs1v15(hash),
            SignatureAlgorithm::RsaPss(hash),
            SignatureAlgorithm::Hmac(hash),
        ]);
        signatures.extend(
            curves
                .into_iter()
                .map(|curve| SignatureAlgorithm::Ecdsa(curve, hash)),
        );
        #[cfg(feature = "legacy")]
        signatures.push(SignatureAlgorithm::Dsa(hash));
    }
    signatures.push(SignatureAlgorithm::Ed25519);
    #[cfg(feature = "post-quantum")]
    {
        use crate::algorithm::{CompositeMlDsaVariant, MlDsaVariant, SlhDsaVariant};
        signatures.extend(
            CompositeMlDsaVariant::ALL
                .into_iter()
                .map(SignatureAlgorithm::CompositeMlDsa),
        );
        signatures.extend(
            [
                MlDsaVariant::MlDsa44,
                MlDsaVariant::MlDsa65,
                MlDsaVariant::MlDsa87,
            ]
            .into_iter()
            .map(SignatureAlgorithm::MlDsa),
        );
        signatures.extend(
            [
                SlhDsaVariant::Sha2_128f,
                SlhDsaVariant::Sha2_128s,
                SlhDsaVariant::Sha2_192f,
                SlhDsaVariant::Sha2_192s,
                SlhDsaVariant::Sha2_256f,
                SlhDsaVariant::Sha2_256s,
            ]
            .into_iter()
            .map(SignatureAlgorithm::SlhDsa),
        );
    }
    for signature in signatures {
        operations.push(Operation::Sign(signature));
        operations.push(Operation::Verify(signature));
    }

    for size in aes_sizes {
        for cipher in [CipherAlgorithm::AesCbc(size), CipherAlgorithm::AesGcm(size)] {
            operations.push(Operation::Encrypt(cipher));
            operations.push(Operation::Decrypt(cipher));
        }
        let key_wrap = KeyWrapAlgorithm::AesKw(size);
        operations.push(Operation::Wrap(key_wrap));
        operations.push(Operation::Unwrap(key_wrap));
    }
    #[cfg(feature = "legacy")]
    {
        operations.extend([
            Operation::Encrypt(CipherAlgorithm::TripleDesCbc),
            Operation::Decrypt(CipherAlgorithm::TripleDesCbc),
            Operation::Wrap(KeyWrapAlgorithm::TripleDesKw),
            Operation::Unwrap(KeyWrapAlgorithm::TripleDesKw),
            Operation::TransportEncrypt(KeyTransportAlgorithm::RsaPkcs1v15),
            Operation::TransportDecrypt(KeyTransportAlgorithm::RsaPkcs1v15),
        ]);
    }

    for digest in hashes.iter().copied() {
        for mgf_digest in hashes.iter().copied() {
            let transport =
                KeyTransportAlgorithm::RsaOaep(crate::algorithm::OaepConfig { digest, mgf_digest });
            operations.push(Operation::TransportEncrypt(transport));
            operations.push(Operation::TransportDecrypt(transport));
        }
    }

    for curve in curves {
        operations.push(Operation::Agreement(curve));
    }
    operations.extend([Operation::X25519Agreement, Operation::DhAgreement]);

    #[cfg(feature = "post-quantum")]
    for variant in [
        crate::algorithm::MlKemVariant::MlKem512,
        crate::algorithm::MlKemVariant::MlKem768,
        crate::algorithm::MlKemVariant::MlKem1024,
    ] {
        let algorithm = crate::algorithm::KemAlgorithm::MlKem(variant);
        operations.extend([
            Operation::KemGenerate(algorithm),
            Operation::KemEncapsulate(algorithm),
            Operation::KemDecapsulate(algorithm),
        ]);
    }

    operations
}

fn known_hashes() -> Vec<HashAlgorithm> {
    #[allow(unused_mut)] // `legacy` appends MD5/RIPEMD-160.
    let mut hashes = vec![
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
    ];
    #[cfg(feature = "legacy")]
    hashes.extend([HashAlgorithm::Md5, HashAlgorithm::Ripemd160]);
    hashes
}

/// Enforce initialization and reject unsupported operations before key use.
pub(crate) fn require_supported(operation: Operation) -> Result<()> {
    ensure_backend()?;
    if provider_supports(operation) {
        Ok(())
    } else {
        Err(Error::unsupported(operation, format!("{operation:?}")))
    }
}

fn provider_supports(operation: Operation) -> bool {
    use compile_time_provider::Provider as _;

    let implemented = compile_time_provider::SelectedProvider::supports(operation);
    implemented && (!cfg!(feature = "fips") || operation_is_fips_approved(operation))
}

fn operation_is_fips_approved(operation: Operation) -> bool {
    let approved_hash = |hash| {
        matches!(
            hash,
            HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        )
    };
    let approved_signature = |algorithm| match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(hash)
        | SignatureAlgorithm::RsaPss(hash)
        | SignatureAlgorithm::Ecdsa(_, hash)
        | SignatureAlgorithm::Hmac(hash) => approved_hash(hash),
        _ => false,
    };
    match operation {
        Operation::Random => true,
        Operation::KeyImport(KeyAlgorithm::Rsa)
        | Operation::KeyImport(KeyAlgorithm::Ec(_))
        | Operation::KeyImport(KeyAlgorithm::Hmac)
        | Operation::KeyImport(KeyAlgorithm::Aes)
        | Operation::KeyExport(KeyAlgorithm::Rsa)
        | Operation::KeyExport(KeyAlgorithm::Ec(_))
        | Operation::KeyExport(KeyAlgorithm::Hmac)
        | Operation::KeyExport(KeyAlgorithm::Aes) => true,
        // AWS-LC's module has no SHA-224 PBKDF2 or HKDF; those digests use
        // the portable composition in `alternate::kdf` and are not approved.
        Operation::Pbkdf2(HashAlgorithm::Sha224) | Operation::Hkdf(HashAlgorithm::Sha224) => false,
        Operation::Digest(hash)
        | Operation::Hmac(hash)
        | Operation::ConcatKdf(hash)
        | Operation::Pbkdf2(hash)
        | Operation::Hkdf(hash) => approved_hash(hash),
        // RFC 7292 Appendix B is an interoperability KDF, not an approved
        // SP 800-132 password-based derivation method.
        Operation::Pkcs12Kdf(_) => false,
        Operation::Sign(algorithm) | Operation::Verify(algorithm) => approved_signature(algorithm),
        // AES-192-GCM sealing uses a nonce generated outside the module
        // (AWS-LC has no randomized-nonce AES-192 key), so it is not approved.
        Operation::Encrypt(CipherAlgorithm::AesGcm(crate::algorithm::AesKeySize::Aes192)) => false,
        Operation::Encrypt(CipherAlgorithm::AesCbc(_))
        | Operation::Decrypt(CipherAlgorithm::AesCbc(_))
        | Operation::Encrypt(CipherAlgorithm::AesGcm(_))
        | Operation::Decrypt(CipherAlgorithm::AesGcm(_))
        | Operation::Wrap(KeyWrapAlgorithm::AesKw(_))
        | Operation::Unwrap(KeyWrapAlgorithm::AesKw(_))
        | Operation::Agreement(_) => true,
        Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(config))
        | Operation::TransportDecrypt(KeyTransportAlgorithm::RsaOaep(config)) => {
            approved_hash(config.digest) && approved_hash(config.mgf_digest)
        }
        _ => false,
    }
}

#[cfg(feature = "rustcrypto")]
fn rustcrypto_supports(operation: Operation) -> bool {
    let is_legacy_key = matches!(
        operation,
        Operation::KeyImport(KeyAlgorithm::Dsa)
            | Operation::KeyExport(KeyAlgorithm::Dsa)
            | Operation::KeyImport(KeyAlgorithm::TripleDes)
            | Operation::KeyExport(KeyAlgorithm::TripleDes)
    );
    let is_unsupported_pbkdf2 = matches!(
        operation,
        Operation::Pbkdf2(HashAlgorithm::Sha3_224)
            | Operation::Pbkdf2(HashAlgorithm::Sha3_256)
            | Operation::Pbkdf2(HashAlgorithm::Sha3_384)
            | Operation::Pbkdf2(HashAlgorithm::Sha3_512)
    );
    let is_unsupported_pkcs12 = matches!(operation, Operation::Pkcs12Kdf(hash) if !matches!(hash, HashAlgorithm::Sha1 | HashAlgorithm::Sha256));
    (!is_legacy_key || cfg!(feature = "legacy")) && !is_unsupported_pbkdf2 && !is_unsupported_pkcs12
}

#[cfg(feature = "aws-lc")]
fn aws_lc_supports(operation: Operation) -> bool {
    match operation {
        Operation::Random => true,
        Operation::KeyImport(KeyAlgorithm::Rsa)
        | Operation::KeyImport(KeyAlgorithm::Ec(_))
        | Operation::KeyImport(KeyAlgorithm::Ed25519)
        | Operation::KeyImport(KeyAlgorithm::X25519)
        | Operation::KeyImport(KeyAlgorithm::Hmac)
        | Operation::KeyImport(KeyAlgorithm::Aes)
        | Operation::KeyExport(KeyAlgorithm::Rsa)
        | Operation::KeyExport(KeyAlgorithm::Ec(_))
        | Operation::KeyExport(KeyAlgorithm::Ed25519)
        | Operation::KeyExport(KeyAlgorithm::X25519)
        | Operation::KeyExport(KeyAlgorithm::Hmac)
        | Operation::KeyExport(KeyAlgorithm::Aes) => true,
        Operation::Digest(hash) | Operation::ConcatKdf(hash) => matches!(
            hash,
            HashAlgorithm::Sha1
                | HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
                | HashAlgorithm::Sha3_256
                | HashAlgorithm::Sha3_384
                | HashAlgorithm::Sha3_512
        ),
        Operation::Hmac(hash) | Operation::Pbkdf2(hash) | Operation::Hkdf(hash) => matches!(
            hash,
            HashAlgorithm::Sha1
                | HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        Operation::Pkcs12Kdf(hash) => {
            matches!(hash, HashAlgorithm::Sha1 | HashAlgorithm::Sha256)
        }
        Operation::Verify(algorithm) => aws_lc_verifies(algorithm),
        Operation::Sign(SignatureAlgorithm::Hmac(hash)) => matches!(
            hash,
            HashAlgorithm::Sha1
                | HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        Operation::Sign(algorithm) => aws_lc_signs(algorithm),
        Operation::Encrypt(CipherAlgorithm::AesCbc(_))
        | Operation::Decrypt(CipherAlgorithm::AesCbc(_))
        | Operation::Encrypt(CipherAlgorithm::AesGcm(_))
        | Operation::Decrypt(CipherAlgorithm::AesGcm(_)) => true,
        Operation::Wrap(KeyWrapAlgorithm::AesKw(size))
        | Operation::Unwrap(KeyWrapAlgorithm::AesKw(size)) => {
            !matches!(size, crate::algorithm::AesKeySize::Aes192)
        }
        Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(config))
        | Operation::TransportDecrypt(KeyTransportAlgorithm::RsaOaep(config)) => matches!(
            (config.digest, config.mgf_digest),
            (HashAlgorithm::Sha1, HashAlgorithm::Sha1)
                | (HashAlgorithm::Sha256, HashAlgorithm::Sha256)
                | (HashAlgorithm::Sha384, HashAlgorithm::Sha384)
                | (HashAlgorithm::Sha512, HashAlgorithm::Sha512)
        ),
        #[cfg(feature = "legacy")]
        Operation::TransportEncrypt(KeyTransportAlgorithm::RsaPkcs1v15)
        | Operation::TransportDecrypt(KeyTransportAlgorithm::RsaPkcs1v15) => true,
        Operation::Agreement(_) | Operation::X25519Agreement => true,
        _ => false,
    }
}

#[cfg(feature = "aws-lc")]
fn aws_lc_verifies(algorithm: SignatureAlgorithm) -> bool {
    #[allow(unreachable_patterns)]
    match algorithm {
        SignatureAlgorithm::Hmac(hash) => matches!(
            hash,
            HashAlgorithm::Sha1
                | HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::RsaPkcs1v15(hash) => matches!(
            hash,
            HashAlgorithm::Sha1
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::RsaPss(hash) => matches!(
            hash,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
        ),
        // XML-DSig pairs the key's curve with the URI's digest, so verify
        // accepts every SHA-2 digest AWS-LC exposes for each curve.
        SignatureAlgorithm::Ecdsa(
            crate::algorithm::EcCurve::P256 | crate::algorithm::EcCurve::P384,
            hash,
        ) => matches!(
            hash,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::Ecdsa(crate::algorithm::EcCurve::P521, hash) => matches!(
            hash,
            HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::Ed25519 => true,
        _ => false,
    }
}

#[cfg(feature = "aws-lc")]
fn aws_lc_signs(algorithm: SignatureAlgorithm) -> bool {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(hash) | SignatureAlgorithm::RsaPss(hash) => matches!(
            hash,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::Ecdsa(crate::algorithm::EcCurve::P256, hash) => {
            hash == HashAlgorithm::Sha256
        }
        SignatureAlgorithm::Ecdsa(crate::algorithm::EcCurve::P384, hash) => {
            hash == HashAlgorithm::Sha384
        }
        SignatureAlgorithm::Ecdsa(crate::algorithm::EcCurve::P521, hash) => matches!(
            hash,
            HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        ),
        SignatureAlgorithm::Ed25519 => true,
        _ => false,
    }
}

/// Upper bound on a single `random_bytes` allocation, in bytes.
///
/// Every internal caller draws small fixed sizes (8/12/16/32 bytes). A
/// 1&nbsp;MiB cap prevents a downstream consumer passing an attacker-controlled
/// `length` from forcing a multi-gigabyte allocation before any entropy is
/// drawn. Callers needing more should call the provider RNG in chunks.
pub const RANDOM_BYTES_MAX_LEN: usize = 1 << 20;

/// Fill a caller-owned buffer from the selected provider's OS-backed RNG.
///
/// Provider failures are returned to the caller; this function never falls
/// back to a stateful process-local generator.
pub(crate) fn fill_random(output: &mut [u8]) -> Result<()> {
    use compile_time_provider::Provider as _;

    require_supported(Operation::Random)?;
    compile_time_provider::SelectedProvider::fill_random(output)
}

/// Fill a newly allocated buffer with randomness from the selected provider.
pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
    if length > RANDOM_BYTES_MAX_LEN {
        return Err(Error::Crypto(format!(
            "random_bytes length {length} exceeds cap of {RANDOM_BYTES_MAX_LEN}"
        )));
    }
    let mut output = vec![0u8; length];
    fill_random(&mut output)?;
    Ok(output)
}

/// Sealed compile-time provider boundary.
///
/// Every public cryptographic entry point first crosses
/// [`require_supported`], while initialization, capability selection, and RNG
/// dispatch through this trait. Concrete digest/key/signature/cipher state is
/// then compiled exclusively from the matching adapter modules selected in
/// `lib.rs`; no downstream crate can implement or substitute this trait.
mod compile_time_provider {
    use super::{BackendId, Operation};
    use crate::error::Result;

    mod sealed {
        pub trait Sealed {}
    }

    pub(super) trait Provider: sealed::Sealed {
        const ID: BackendId;

        fn initialize() -> std::result::Result<(), String>;
        fn supports(operation: Operation) -> bool;
        fn fill_random(output: &mut [u8]) -> Result<()>;
    }

    #[cfg(feature = "rustcrypto")]
    pub(super) struct RustCrypto;
    #[cfg(feature = "rustcrypto")]
    impl sealed::Sealed for RustCrypto {}
    #[cfg(feature = "rustcrypto")]
    impl Provider for RustCrypto {
        const ID: BackendId = BackendId::RustCrypto;

        fn initialize() -> std::result::Result<(), String> {
            Ok(())
        }

        fn supports(operation: Operation) -> bool {
            super::rustcrypto_supports(operation)
        }

        fn fill_random(output: &mut [u8]) -> Result<()> {
            use rand::RngCore;
            rand::rngs::OsRng.try_fill_bytes(output).map_err(|error| {
                crate::error::Error::Crypto(format!(
                    "RustCrypto OS random generation failed: {error}"
                ))
            })
        }
    }

    #[cfg(feature = "aws-lc")]
    pub(super) struct AwsLc;
    #[cfg(feature = "aws-lc")]
    impl sealed::Sealed for AwsLc {}
    #[cfg(feature = "aws-lc")]
    impl Provider for AwsLc {
        const ID: BackendId = BackendId::AwsLc;

        fn initialize() -> std::result::Result<(), String> {
            aws_lc_rs::init();
            #[cfg(feature = "fips")]
            aws_lc_rs::try_fips_mode().map_err(str::to_owned)?;
            Ok(())
        }

        fn supports(operation: Operation) -> bool {
            super::aws_lc_supports(operation)
        }

        fn fill_random(output: &mut [u8]) -> Result<()> {
            use aws_lc_rs::rand::SecureRandom;
            aws_lc_rs::rand::SystemRandom::new()
                .fill(output)
                .map_err(|_| crate::error::Error::Crypto("AWS-LC random generation failed".into()))
        }
    }

    #[cfg(feature = "rustcrypto")]
    pub(super) type SelectedProvider = RustCrypto;
    #[cfg(all(not(feature = "rustcrypto"), feature = "aws-lc"))]
    pub(super) type SelectedProvider = AwsLc;
}

/// An immutable rustls client configuration carrying provider attestation.
#[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
#[derive(Clone)]
pub struct AttestedTlsConfig {
    config: std::sync::Arc<rustls::ClientConfig>,
    backend: TlsBackendId,
    fips: FipsStatus,
}

#[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
impl AttestedTlsConfig {
    #[must_use]
    pub fn config(&self) -> std::sync::Arc<rustls::ClientConfig> {
        self.config.clone()
    }

    #[must_use]
    pub const fn backend(&self) -> TlsBackendId {
        self.backend
    }

    #[must_use]
    pub const fn fips_status(&self) -> FipsStatus {
        self.fips
    }
}

/// Build a rustls client configuration with the compile-time selected TLS provider.
#[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
pub fn build_tls_client_config(roots: rustls::RootCertStore) -> Result<AttestedTlsConfig> {
    ensure_backend()?;
    let provider = {
        #[cfg(feature = "tls-ring")]
        {
            rustls::crypto::ring::default_provider()
        }
        #[cfg(feature = "tls-aws-lc")]
        {
            rustls::crypto::aws_lc_rs::default_provider()
        }
    };
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::BackendInitialization {
            backend: selected_backend(),
            message: format!("TLS protocol configuration failed: {e}"),
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    #[cfg(feature = "fips")]
    if !config.fips() {
        return Err(Error::FipsUnavailable {
            backend: selected_backend(),
            message: "selected rustls configuration did not attest FIPS mode".into(),
        });
    }
    Ok(AttestedTlsConfig {
        config: std::sync::Arc::new(config),
        backend: selected_tls_backend().expect("TLS feature checked by cfg"),
        fips: if cfg!(feature = "fips") {
            FipsStatus::Active
        } else {
            FipsStatus::Disabled
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_compile_time_backend() {
        let info = initialize_backend().expect("default backend initializes");
        assert_eq!(info.document, selected_backend());
        assert_eq!(info.tls, selected_tls_backend());
    }

    #[test]
    fn initialization_is_idempotent() {
        let first = initialize_backend().expect("first initialization");
        let second = initialize_backend().expect("second initialization");
        assert_eq!(first, second);
    }

    #[test]
    fn capability_registry_is_parameterized_unique_and_authoritative() {
        // FIPS builds require explicit initialization before any query.
        initialize_backend().expect("backend initialization");
        let capabilities = capabilities().expect("capability registry");
        assert!(!capabilities.is_empty());
        for (index, capability) in capabilities.iter().enumerate() {
            assert!(
                supports(capability.operation).expect("capability query"),
                "registry advertised unsupported operation {:?}",
                capability.operation
            );
            assert!(
                !capabilities[..index]
                    .iter()
                    .any(|earlier| earlier.operation == capability.operation),
                "duplicate capability {:?}",
                capability.operation
            );
        }

        assert!(capabilities.iter().any(|capability| {
            capability.operation == Operation::Digest(HashAlgorithm::Sha256)
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.operation
                == Operation::TransportEncrypt(KeyTransportAlgorithm::RsaOaep(
                    crate::algorithm::OaepConfig::default(),
                ))
        }));
    }

    #[test]
    fn fips_policy_rejects_unapproved_signature_algorithms() {
        assert!(!operation_is_fips_approved(Operation::Sign(
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha1)
        )));
        assert!(!operation_is_fips_approved(Operation::Verify(
            SignatureAlgorithm::RsaPss(HashAlgorithm::Sha1)
        )));
        assert!(!operation_is_fips_approved(Operation::Sign(
            SignatureAlgorithm::Ed25519
        )));
        assert!(operation_is_fips_approved(Operation::Sign(
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256)
        )));
        assert!(operation_is_fips_approved(Operation::Verify(
            SignatureAlgorithm::Hmac(HashAlgorithm::Sha256)
        )));
    }

    #[test]
    fn fips_policy_rejects_pkcs12_kdf() {
        assert!(!operation_is_fips_approved(Operation::Pkcs12Kdf(
            HashAlgorithm::Sha256
        )));
    }

    #[test]
    fn fips_policy_rejects_unapproved_key_transport_algorithms() {
        let sha1_oaep = KeyTransportAlgorithm::RsaOaep(crate::algorithm::OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha1,
        });
        assert!(!operation_is_fips_approved(Operation::TransportEncrypt(
            sha1_oaep
        )));
        assert!(!operation_is_fips_approved(Operation::TransportDecrypt(
            sha1_oaep
        )));
        assert!(operation_is_fips_approved(Operation::TransportEncrypt(
            KeyTransportAlgorithm::RsaOaep(crate::algorithm::OaepConfig::default())
        )));
        #[cfg(feature = "legacy")]
        assert!(!operation_is_fips_approved(Operation::TransportDecrypt(
            KeyTransportAlgorithm::RsaPkcs1v15
        )));
    }
}
