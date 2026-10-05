# SAML provider checkpoint — 2026-10-04

This checkpoint advances [issue #19](https://github.com/MakazhanAlpamys/soup-wall/issues/19); it does not close the advisory or certify a customer IdP. It uses `saml-rs 0.5.3`, `bergshamra 0.9.2`, `kryptering 0.6.0`, and `aws-lc-rs 1.18.1` on source derived from `058a6ce`.

## Recorded local checks

| Environment | Provider | SAML tests | Gateway library tests | Public signed metadata probe |
| --- | --- | --- | --- | --- |
| Windows x86_64 MSVC, Rust 1.98.1 | RustCrypto | 8 passed | 148 passed, 2 expected dependency tests ignored | passed |
| Ubuntu WSL x86_64, Rust 1.99.0 | AWS-LC | 8 passed | 148 passed, 2 expected dependency tests ignored | passed |

The SAML checks cover signed SP-initiated SSO, invitation state, signed metadata and response tampering, no advertised encryption certificate, no configured decryption key, and rejection of a signed response containing an encrypted assertion. The Gateway library's ignored tests need disposable PostgreSQL and Redis instances and were not part of this provider checkpoint.

Formatting and diff checks passed. Clippy with warnings denied passed for the Gateway library and tests under both providers. The changed workflow YAML also parsed successfully.

The external probe used Microsoft's public [common federation metadata endpoint](https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml). It exercised retrieval and signature validation under each provider. It used no tenant credentials and performed no external login, assertion exchange, ACS callback, logout, or provisioning. No metadata XML, assertion contents, certificates, or credentials were copied into this evidence.

Reproduce the fixture and metadata checks with:

```powershell
cargo test --locked -p llm-firewall --lib saml_auth::tests
cargo test --locked -p llm-firewall --lib
$env:LLM_FW_EXTERNAL_SAML_METADATA_URL = 'https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml'
cargo test --locked -p llm-firewall --test external_identity real_signed_saml_metadata_is_accepted -- --ignored --nocapture
```

## Dependency and platform boundary

`cargo tree --locked -p llm-firewall --target <target> --edges normal --prefix none` confirmed:

| Release target | Resolved `rsa` dependency |
| --- | --- |
| `x86_64-unknown-linux-gnu` | absent |
| `aarch64-apple-darwin` | absent |
| `x86_64-apple-darwin` | absent |
| `x86_64-pc-windows-msvc` | `rsa 0.9.10` present |

An isolated Windows compile probe using `kryptering =0.6.0` with only the `aws-lc` provider and AWS-LC's prebuilt NASM option failed at kryptering's target guard: `AWS-LC requires Linux or non-FIPS macOS on x86_64/aarch64`. Removing that guard locally would require assuming support that upstream has not reviewed; this change does not vendor or patch its crypto implementation. Other platforms and CPU architectures retain RustCrypto rather than acquiring this new compile failure.

The 2026-10-05 provider API review found no supported downstream feature switch
that removes this Windows boundary. AWS-LC itself [supports Windows](https://aws.github.io/aws-lc-rs/platform_support.html);
the restriction is in the current XML-crypto provider integration. Kryptering's
[provider interface](https://docs.rs/crate/kryptering/0.6.0/source/src/backend.rs)
is sealed, with RustCrypto and AWS-LC implementations. `tls-ring` selects the TLS
provider, and PKCS#11 still needs a software XML provider. The exported
`XmlSecurityBackend` in saml-rs is not injected into its
[standard SSO flow](https://docs.rs/crate/saml-rs/0.5.3/source/src/flow.rs).
An OpenSSL/xmlsec replacement therefore needs upstream API integration and
signature-boundary review. A supported Windows AWS-LC release with upstream CI
is the smallest identified dependency checkpoint; no unsupported guard removal
or local cryptographic fork was introduced.

`cargo audit --json` reported exactly one vulnerability, `RUSTSEC-2023-0071`. Audit with that single existing exception passed, while still reporting the existing informational `paste` maintenance and yanked `chacha20 0.10.1` warnings. The complete release lock continues to include the Windows RSA dependency.

## Remaining acceptance

The four-target CI matrix and archive workflow now run the SAML fixtures. All four native targets passed 8 SAML tests in [hosted CI run 37220861101](https://github.com/MakazhanAlpamys/soup-wall/actions/runs/37220861101), including macOS arm64 and Intel. All 18 PR checks passed before [PR #23](https://github.com/MakazhanAlpamys/soup-wall/pull/23) merged as `65bee72917e34f260da34162094f1a21030f7005`. Dependency checks in the same run confirmed the boundary above. Closing #19 still requires a reviewed Windows provider, real-IdP signed assertion interoperability on every release platform, removal of `rsa` from the complete locked release graph, and audit without the exception. Encrypted assertions remain disabled pending a separate threat review.
