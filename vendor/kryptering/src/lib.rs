#[cfg(not(any(feature = "rustcrypto", feature = "aws-lc")))]
compile_error!("select exactly one document provider: rustcrypto or aws-lc");
#[cfg(all(feature = "rustcrypto", feature = "aws-lc"))]
compile_error!(
    "document provider features are mutually exclusive: select exactly one of rustcrypto or aws-lc"
);
#[cfg(all(feature = "tls-ring", feature = "tls-aws-lc"))]
compile_error!(
    "TLS provider features are mutually exclusive: select at most one of tls-ring or tls-aws-lc"
);
#[cfg(all(feature = "fips", feature = "rustcrypto"))]
compile_error!("fips cannot be combined with the RustCrypto document provider");
#[cfg(all(feature = "fips", feature = "tls-ring"))]
compile_error!("fips cannot be combined with the ring TLS provider");
#[cfg(all(
    any(feature = "aws-lc", feature = "tls-aws-lc"),
    not(all(
        any(
            target_os = "linux",
            all(target_os = "macos", not(feature = "fips")),
            all(
                target_os = "windows",
                target_arch = "x86_64",
                target_env = "msvc",
                not(feature = "fips")
            )
        ),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
compile_error!(
    "AWS-LC requires Linux or non-FIPS macOS on x86_64/aarch64, or non-FIPS Windows x86_64 MSVC"
);

pub mod algorithm;
pub mod backend;
#[cfg(feature = "rustcrypto")]
pub mod digest;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/digest.rs"]
pub mod digest;
mod ecdsa_encoding;
pub mod error;
#[cfg(feature = "rustcrypto")]
pub mod hazmat;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/hazmat.rs"]
pub mod hazmat;
#[cfg(feature = "rustcrypto")]
pub mod kdf;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/kdf.rs"]
pub mod kdf;
#[cfg(feature = "rustcrypto")]
pub mod key;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/key.rs"]
pub mod key;
pub mod parameters;
pub mod pkcs12;
#[cfg(feature = "rustcrypto")]
pub mod software;
#[cfg(not(feature = "rustcrypto"))]
#[path = "alternate/software.rs"]
pub mod software;
pub mod traits;

#[cfg(all(feature = "pkcs11", not(target_arch = "wasm32")))]
pub mod pkcs11;

// Re-export core types at crate root for convenience.
pub use algorithm::*;
pub use backend::*;
pub use error::{Error, Result};
pub use key::SoftwareKey;
pub use parameters::DhParameters;
pub use traits::*;

// Re-export software backend types.
pub use software::cipher;
#[cfg(all(feature = "post-quantum", feature = "rustcrypto"))]
pub use software::composite::generate_composite_ml_dsa;
#[cfg(feature = "post-quantum")]
pub use software::kem::{generate_ml_kem, SoftwareDecapsulator, SoftwareEncapsulator};
pub use software::keyagreement;
pub use software::keytransport;
pub use software::keywrap;
#[cfg(feature = "post-quantum")]
pub use software::sign::generate_ml_dsa;
#[cfg(feature = "rustcrypto")]
pub use software::sign::{SoftwareSigner, SoftwareVerifier};
#[cfg(not(feature = "rustcrypto"))]
pub use software::{SoftwareSigner, SoftwareVerifier};
