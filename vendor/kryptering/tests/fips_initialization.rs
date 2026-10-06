#![cfg(feature = "fips")]

use kryptering::{backend_info, supports, Error, FipsStatus, Operation};

#[test]
fn cryptography_fails_closed_before_explicit_initialization() {
    let info = backend_info().expect("compile-time provider information");
    assert_eq!(info.fips, FipsStatus::Uninitialized);

    let error = supports(Operation::Random).expect_err("FIPS use before initialization must fail");
    assert!(matches!(error, Error::BackendNotInitialized { .. }));
}
