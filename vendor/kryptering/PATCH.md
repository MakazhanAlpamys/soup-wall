# Kryptering platform patch

This directory contains the published `kryptering 0.6.0` package, licensed under
BSD-2-Clause. The upstream source is
[kushaldas/kryptering](https://github.com/kushaldas/kryptering), tag `v0.6.0`,
commit `1cb2c1d64a5ecf78bb0d69abaac22e19d30081c2`.

The original [package archive](https://static.crates.io/crates/kryptering/kryptering-0.6.0.crate)
has SHA-256
`246fc275192d5342930279ed2070daf15204ca2e6158e91daaa3eaff78a5477d`.
The intake verified that digest against the application's original registry
lock entry and compared every retained file with its archive bytes.
`Cargo.toml`, `Cargo.toml.orig`, `LICENSE`, source, tests, README, changelog and
all five upstream documentation files are retained. The manifests remain
byte-identical to the published package.

Omitted package assets are `.cargo/audit.toml`, `.cargo_vcs_info.json`, the three
`.github/workflows/*.yml` files, `.gitignore`, and the upstream development
`Cargo.lock`. Registry-cache markers such as `.cargo-ok` and
`.cargo-checksum.json` are not included. Application dependency resolution uses
the root lockfile. Keep this package excluded from the application workspace;
its upstream development tests have their own RustCrypto dependencies.

## Local delta

The source change is limited to the AWS-LC platform guard and its error
message in `src/lib.rs`. It admits non-FIPS Windows with `target_arch = "x86_64"`
and `target_env = "msvc"`. The existing Linux x86_64/aarch64 and non-FIPS macOS
x86_64/aarch64 support remains. Windows ARM, Windows GNU and Windows FIPS stay
outside this patch. Existing provider exclusivity and initialization checks,
algorithm implementations and capability policy remain unchanged.

AWS-LC provides the cryptographic operations; its
[platform support](https://aws.github.io/aws-lc-rs/platform_support.html) includes
Windows MSVC. This platform extension requires native Windows verification and
application signature, tamper-rejection and disabled-decryption regressions.
This intake note does not claim those checks have passed.

## Updating or removing the patch

For an update, verify the new registry archive checksum and upstream revision,
compare the source delta, preserve upstream licensing, and rerun the supported
platform and dependency-exclusion checks. Do not add a RustCrypto fallback to
the application's SAML configuration. Preserve the application's lack of an
XML decryption key and encrypted-assertion rejection.

Remove the path override and this directory when a reviewed upstream release
supports the required Windows provider and passes the same application checks.
Regenerate the application lockfile and verify that the release graphs and
complete lock still exclude `rsa`, with no advisory exception required.
