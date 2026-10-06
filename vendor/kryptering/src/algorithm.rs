/// Hash algorithm for digest and signature operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    #[cfg(feature = "legacy")]
    Md5,
    #[cfg(feature = "legacy")]
    Ripemd160,
}

/// Elliptic curve identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

/// AES key size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    /// Key size in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

/// Signature algorithm.
///
/// ## Hash / algorithm policy
///
/// Every signature variant carries its hash as a data member. The library
/// does **not** enforce a policy over which hash goes with which outer
/// algorithm — e.g. `Ecdsa(P521, Sha1)` or `Dsa(Sha1)` are accepted at this
/// layer. That's a deliberate choice: XML-DSig 1.0, legacy CMS, SAML
/// assertions in the wild, and many test-vector suites combine curves
/// with SHA-1, and enforcing modern-hash policy at the primitive layer
/// would block interop with those use cases (the same way NIST
/// SP 800-132's PBKDF2 salt/iteration floors blocked XML-Enc 1.1 test
/// vectors before we relaxed them).
///
/// Callers that want to enforce a hash-strength policy should filter
/// `SignatureAlgorithm` values at their API boundary before constructing
/// `SoftwareSigner` / `SoftwareVerifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaPkcs1v15(HashAlgorithm),
    RsaPss(HashAlgorithm),
    Ecdsa(EcCurve, HashAlgorithm),
    Ed25519,
    Hmac(HashAlgorithm),
    #[cfg(feature = "legacy")]
    Dsa(HashAlgorithm),
    #[cfg(feature = "post-quantum")]
    MlDsa(MlDsaVariant),
    /// Composite ML-DSA signatures from
    /// draft-ietf-jose-pq-composite-sigs-03.
    #[cfg(feature = "post-quantum")]
    CompositeMlDsa(CompositeMlDsaVariant),
    #[cfg(feature = "post-quantum")]
    SlhDsa(SlhDsaVariant),
}

/// Block cipher algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    AesCbc(AesKeySize),
    AesGcm(AesKeySize),
    #[cfg(feature = "legacy")]
    TripleDesCbc,
}

impl CipherAlgorithm {
    /// Key size in bytes.
    pub fn key_size(self) -> usize {
        match self {
            Self::AesCbc(s) | Self::AesGcm(s) => s.key_len(),
            #[cfg(feature = "legacy")]
            Self::TripleDesCbc => 24,
        }
    }
}

/// Key wrap algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    AesKw(AesKeySize),
    #[cfg(feature = "legacy")]
    TripleDesKw,
}

impl KeyWrapAlgorithm {
    /// KEK size in bytes.
    pub fn kek_size(self) -> usize {
        match self {
            Self::AesKw(s) => s.key_len(),
            #[cfg(feature = "legacy")]
            Self::TripleDesKw => 24,
        }
    }
}

/// RSA-OAEP configuration.
///
/// The [`Default`] impl returns `SHA-256 / SHA-256`, which is the modern
/// recommendation (NIST SP 800-56B Rev. 2, IETF CFRG). An earlier version
/// defaulted to `SHA-1 / SHA-1` to match RFC 8017's lowest-common-denominator
/// interop; callers who still need SHA-1 for XML Encryption 1.0
/// `rsa-oaep-mgf1p` or other legacy contexts must now opt in explicitly
/// via a literal `OaepConfig { digest: HashAlgorithm::Sha1, .. }` construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OaepConfig {
    pub digest: HashAlgorithm,
    pub mgf_digest: HashAlgorithm,
}

impl Default for OaepConfig {
    fn default() -> Self {
        Self {
            digest: HashAlgorithm::Sha256,
            mgf_digest: HashAlgorithm::Sha256,
        }
    }
}

/// Key transport algorithm (RSA key encryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTransportAlgorithm {
    #[cfg(feature = "legacy")]
    RsaPkcs1v15,
    RsaOaep(OaepConfig),
}

/// Post-quantum ML-DSA (FIPS 204) variant.
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[cfg(feature = "post-quantum")]
impl MlDsaVariant {
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}

/// Composite ML-DSA signature algorithms defined by
/// draft-ietf-jose-pq-composite-sigs-03.
///
/// The enum is intentionally closed over the six registered combinations.
/// Accepting independently selected component algorithms would allow invalid
/// combinations of the ML-DSA parameter set, traditional algorithm, prehash,
/// and domain-separation label.
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompositeMlDsaVariant {
    MlDsa44Es256,
    MlDsa65Es256,
    MlDsa87Es384,
    MlDsa44Ed25519,
    MlDsa65Ed25519,
    MlDsa87Ed448,
}

#[cfg(feature = "post-quantum")]
impl CompositeMlDsaVariant {
    /// Every composite algorithm in draft version `-03`.
    pub const ALL: [Self; 6] = [
        Self::MlDsa44Es256,
        Self::MlDsa65Es256,
        Self::MlDsa87Es384,
        Self::MlDsa44Ed25519,
        Self::MlDsa65Ed25519,
        Self::MlDsa87Ed448,
    ];

    /// JOSE/COSE algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44Es256 => "ML-DSA-44-ES256",
            Self::MlDsa65Es256 => "ML-DSA-65-ES256",
            Self::MlDsa87Es384 => "ML-DSA-87-ES384",
            Self::MlDsa44Ed25519 => "ML-DSA-44-Ed25519",
            Self::MlDsa65Ed25519 => "ML-DSA-65-Ed25519",
            Self::MlDsa87Ed448 => "ML-DSA-87-Ed448",
        }
    }

    /// Domain-separation label encoded as the draft's required ASCII bytes.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Es256 => b"COMPSIG-MLDSA44-ECDSA-P256-SHA256",
            Self::MlDsa65Es256 => b"COMPSIG-MLDSA65-ECDSA-P256-SHA512",
            Self::MlDsa87Es384 => b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",
            Self::MlDsa44Ed25519 => b"COMPSIG-MLDSA44-Ed25519-SHA512",
            Self::MlDsa65Ed25519 => b"COMPSIG-MLDSA65-Ed25519-SHA512",
            Self::MlDsa87Ed448 => b"COMPSIG-MLDSA87-Ed448-SHAKE256",
        }
    }

    /// ML-DSA component parameter set.
    #[must_use]
    pub const fn ml_dsa_variant(self) -> MlDsaVariant {
        match self {
            Self::MlDsa44Es256 | Self::MlDsa44Ed25519 => MlDsaVariant::MlDsa44,
            Self::MlDsa65Es256 | Self::MlDsa65Ed25519 => MlDsaVariant::MlDsa65,
            Self::MlDsa87Es384 | Self::MlDsa87Ed448 => MlDsaVariant::MlDsa87,
        }
    }

    /// Encoded ML-DSA public-key length.
    #[must_use]
    pub const fn ml_dsa_public_key_len(self) -> usize {
        match self.ml_dsa_variant() {
            MlDsaVariant::MlDsa44 => 1_312,
            MlDsaVariant::MlDsa65 => 1_952,
            MlDsaVariant::MlDsa87 => 2_592,
        }
    }

    /// Encoded ML-DSA signature length.
    #[must_use]
    pub const fn ml_dsa_signature_len(self) -> usize {
        match self.ml_dsa_variant() {
            MlDsaVariant::MlDsa44 => 2_420,
            MlDsaVariant::MlDsa65 => 3_309,
            MlDsaVariant::MlDsa87 => 4_627,
        }
    }

    /// Aggregate raw public-key length.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        self.ml_dsa_public_key_len()
            + match self {
                Self::MlDsa44Es256 | Self::MlDsa65Es256 => 64,
                Self::MlDsa87Es384 => 96,
                Self::MlDsa44Ed25519 | Self::MlDsa65Ed25519 => 32,
                Self::MlDsa87Ed448 => 57,
            }
    }

    /// Aggregate raw private-key length.
    ///
    /// The first 32 bytes are always the ML-DSA seed.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        32 + match self {
            Self::MlDsa44Es256 | Self::MlDsa65Es256 => 32,
            Self::MlDsa87Es384 => 48,
            Self::MlDsa44Ed25519 | Self::MlDsa65Ed25519 => 32,
            Self::MlDsa87Ed448 => 57,
        }
    }

    /// Aggregate raw signature length.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        self.ml_dsa_signature_len()
            + match self {
                Self::MlDsa44Es256 | Self::MlDsa65Es256 => 64,
                Self::MlDsa87Es384 => 96,
                Self::MlDsa44Ed25519 | Self::MlDsa65Ed25519 => 64,
                Self::MlDsa87Ed448 => 114,
            }
    }
}

/// Post-quantum SLH-DSA (FIPS 205) variant.
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlhDsaVariant {
    Sha2_128f,
    Sha2_128s,
    Sha2_192f,
    Sha2_192s,
    Sha2_256f,
    Sha2_256s,
}

#[cfg(feature = "post-quantum")]
impl SlhDsaVariant {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Sha2_128s => "SLH-DSA-SHA2-128s",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Sha2_192s => "SLH-DSA-SHA2-192s",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
            Self::Sha2_256s => "SLH-DSA-SHA2-256s",
        }
    }
}

/// Post-quantum ML-KEM (FIPS 203) variant.
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

#[cfg(feature = "post-quantum")]
impl MlKemVariant {
    pub fn name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// FIPS 203 ciphertext length in bytes.
    pub fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// FIPS 203 encapsulation key length in bytes (raw, before SPKI wrapping).
    pub fn encapsulation_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Shared-secret length in bytes — 32 for every ML-KEM variant.
    pub fn shared_secret_len(self) -> usize {
        32
    }
}

/// KEM algorithm identifier used by the [`Encapsulator`](crate::traits::Encapsulator)
/// and [`Decapsulator`](crate::traits::Decapsulator) traits (mirrors the role
/// `SignatureAlgorithm` plays for `Signer`/`Verifier`).
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    MlKem(MlKemVariant),
}

#[cfg(feature = "post-quantum")]
impl KemAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::MlKem(v) => v.name(),
        }
    }
}

/// Combined post-quantum algorithm identifier (used in SoftwareKey).
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqAlgorithm {
    MlDsa(MlDsaVariant),
    SlhDsa(SlhDsaVariant),
    MlKem(MlKemVariant),
}

#[cfg(feature = "post-quantum")]
impl PqAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa(v) => v.name(),
            Self::SlhDsa(v) => v.name(),
            Self::MlKem(v) => v.name(),
        }
    }
}
