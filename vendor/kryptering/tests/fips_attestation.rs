#![cfg(all(feature = "fips", feature = "tls-aws-lc"))]

use kryptering::{initialize_backend, supports, FipsStatus, Operation};

#[test]
fn selected_document_and_tls_providers_attest_fips() {
    let info = initialize_backend().expect("selected FIPS providers must initialize");
    assert_eq!(info.fips, FipsStatus::Active);
    assert!(
        supports(Operation::Digest(kryptering::HashAlgorithm::Sha256))
            .expect("approved operation after initialization")
    );
    assert!(
        !supports(Operation::Digest(kryptering::HashAlgorithm::Sha1))
            .expect("unapproved operation query after initialization")
    );

    let tls = kryptering::build_tls_client_config(rustls::RootCertStore::empty())
        .expect("selected FIPS TLS configuration");
    assert_eq!(tls.fips_status(), FipsStatus::Active);
}
