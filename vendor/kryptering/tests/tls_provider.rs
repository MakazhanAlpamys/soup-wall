#![cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]

use kryptering::{FipsStatus, TlsBackendId};

#[test]
fn selected_tls_provider_builds_a_client_configuration() {
    let backend = kryptering::initialize_backend().expect("provider initialization");
    let config = kryptering::build_tls_client_config(rustls::RootCertStore::empty())
        .expect("TLS client configuration");

    #[cfg(feature = "tls-ring")]
    assert_eq!(backend.tls, Some(TlsBackendId::Ring));
    #[cfg(feature = "tls-aws-lc")]
    assert_eq!(backend.tls, Some(TlsBackendId::AwsLc));

    let expected_fips = if cfg!(feature = "fips") {
        FipsStatus::Active
    } else {
        FipsStatus::Disabled
    };
    assert_eq!(config.fips_status(), expected_fips);
}
