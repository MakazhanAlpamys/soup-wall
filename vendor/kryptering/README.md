# kryptering

The compile-time cryptographic provider boundary shared by Kryptering,
`tsp-ltv`, and Bergshamra. Requires Rust 1.88 or later.

## Features

- **Trait-based key abstraction** -- `Signer`, `Verifier`, `Decryptor`, `Encryptor`, `KeyWrapper`, `KeyAgreement` traits that work with both software keys and HSM-backed keys; `Encapsulator`/`Decapsulator` KEM traits (software backend only, for now)
- **Selectable software provider** -- RustCrypto or AWS-LC
- **PKCS#11 backend** -- HSM-backed keys via the `cryptoki` crate (SoftHSM2, Kryoptic, hardware HSMs)
- **Post-quantum** -- ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203), and the six composite ML-DSA signatures from `draft-ietf-jose-pq-composite-sigs-03`, with the RustCrypto provider behind a feature flag

## Supported algorithms

| Category | Algorithms |
|---|---|
| **Signatures** | RSA PKCS#1v1.5, RSA-PSS, ECDSA (P-256/P-384/P-521), Ed25519, HMAC, DSA (legacy), ML-DSA, SLH-DSA, composite ML-DSA |
| **Ciphers** | AES-GCM, AES-CBC (hazmat, unauthenticated — `kryptering::hazmat::aes_cbc`), 3DES-CBC (legacy) |
| **Key wrap** | AES-KW (RFC 3394), 3DES-KW (legacy) |
| **Key transport** | RSA-OAEP, RSA PKCS#1v1.5 (legacy) |
| **Key agreement** | ECDH (P-256/P-384/P-521), X25519, DH (X9.42, hazmat — `kryptering::hazmat::dh`) |
| **KEM** | ML-KEM-512/768/1024 (FIPS 203; RustCrypto provider) |
| **KDFs** | ConcatKDF, PBKDF2, HKDF, PKCS#12 Appendix B (import interoperability; non-FIPS only) |
| **Digests** | SHA-1, SHA-2 (224/256/384/512), SHA-3, MD5 (legacy), RIPEMD-160 (legacy) |

## Provider selection

| Feature | Default | Description |
|---|---|---|
| `rustcrypto` | Yes | RustCrypto document cryptography |
| `aws-lc` | No | AWS-LC document cryptography (Linux x86_64/aarch64) |
| `pkcs11` | Yes | PKCS#11 HSM support via `cryptoki` |
| `legacy` | No | MD5, RIPEMD-160, 3DES, DSA |
| `post-quantum` | No | ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203), composite ML-DSA signatures; RustCrypto only |
| `tls-ring` | No | rustls with ring |
| `tls-aws-lc` | No | rustls with AWS-LC |
| `fips` | No | Select AWS-LC and require explicit, attested FIPS initialization |

Exactly one document provider is required. TLS selection is independent and
at most one TLS provider may be enabled. Provider alternatives must therefore
use `--no-default-features`; `--all-features` is intentionally invalid.

```bash
cargo check                                      # rustcrypto + pkcs11
cargo check --no-default-features --features aws-lc,legacy
cargo check --no-default-features --features fips,tls-aws-lc
```

See [provider capabilities and FIPS behavior](docs/providers.md) for the exact
operation matrix and supported OAEP/signature combinations. The compile-time
provider architecture and future-backend contract are recorded in
[ADR 0002](docs/adr/0002-compile-time-provider-boundary.md).

## Usage

```rust
use kryptering::{HashAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use kryptering::{SoftwareKey, SoftwareSigner, Signer};

// Software signing
let key = SoftwareKey::from_symmetric_bytes(
    KeyAlgorithm::Hmac,
    b"my-secret-key",
)?;
let signer = SoftwareSigner::new(
    SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
    key,
)?;
let signature = signer.sign(b"data to sign")?;
# Ok::<(), kryptering::Error>(())
```

Composite keys are opaque aggregate keys: component keys cannot be turned into
independent `SoftwareKey` handles. With the RustCrypto provider and `post-quantum` enabled:

```rust
use kryptering::{
    generate_composite_ml_dsa, CompositeMlDsaVariant, SignatureAlgorithm,
    Signer, SoftwareSigner, SoftwareVerifier, Verifier,
};

let variant = CompositeMlDsaVariant::MlDsa44Ed25519;
let key = generate_composite_ml_dsa(variant)?;
let signer = SoftwareSigner::new(
    SignatureAlgorithm::CompositeMlDsa(variant),
    key.clone(),
)?;
let verifier = SoftwareVerifier::new(
    SignatureAlgorithm::CompositeMlDsa(variant),
    key,
)?;
let signature = signer.sign(b"data to sign")?;
assert!(verifier.verify(b"data to sign", &signature)?);
# Ok::<(), kryptering::Error>(())
```

In a `fips` build, call `initialize_backend()` once during startup, before any
cryptographic or HTTPS operation, and check the returned `BackendInfo`.
Initialization is mandatory, process-wide, and idempotent. Feature activation
alone is not a statement that an application or deployment is FIPS certified.
FIPS policy rejects the PKCS#12 Appendix B KDF and RSA keys below 2048 bits.
The AWS-LC provider also reports non-digest-length RSA-PSS salts as
`UnsupportedAlgorithm` because its stable API does not expose them.

```rust
// HSM signing (with pkcs11 feature)
use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
use std::path::Path;

let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so")).unwrap();
let session = provider.open_session("1234").unwrap();
let signer = Pkcs11Signer::new(
    &session,
    "my-key-label",
    kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
).unwrap();
let signature = signer.sign(b"data to sign").unwrap();
```

## License

BSD-2-Clause
