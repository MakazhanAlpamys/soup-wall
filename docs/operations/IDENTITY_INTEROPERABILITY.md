# Identity interoperability checks

Soup Wall Console includes OIDC authorization-code login, signed SAML login,
and a constrained, organization-scoped SCIM Users/Groups implementation. Local
fixtures test the code paths; they do not establish compatibility with a
customer identity provider or authorize a production rollout.

## Local checks

From the repository root, run `pwsh scripts/identity-sandbox-smoke.ps1` for
the local OIDC, signed SAML, SCIM conformance, and loopback HTTP SCIM checks.
The `identity-sandbox` workflow runs this local fixture on pull requests and
pushes. It does not use a customer tenant.

The SAML release-target CI matrix runs the signed local fixture and tampering
checks on Linux x86_64, macOS arm64/x86_64, and Windows x86_64. Linux and macOS
use the AWS-LC provider; Windows uses RustCrypto until kryptering supports
Windows AWS-LC. AWS-LC non-FIPS builds need a C/C++ compiler, already required
by the Gateway's JWT dependency; use the release workflow's runner images.
The workflow verifies that `rsa` is absent from the Linux/macOS resolved graph
and records its expected presence on Windows. To inspect a target locally:

```powershell
cargo tree --locked -p llm-firewall --target x86_64-unknown-linux-gnu -i rsa
cargo tree --locked -p llm-firewall --target aarch64-apple-darwin -i rsa
cargo tree --locked -p llm-firewall --target x86_64-apple-darwin -i rsa
cargo tree --locked -p llm-firewall --target x86_64-pc-windows-msvc -i rsa
```

Empty output for a Unix target means no resolved `rsa` dependency for that
target. The all-target lock still includes Windows' `rsa`, so audit's narrow
exception remains necessary. See [provenance](../PROVENANCE.md) and
[issue #19](https://github.com/MakazhanAlpamys/soup-wall/issues/19).

Configure the IdP to send signed plaintext assertions. Encrypted assertions
remain unsupported on every target: the SP neither advertises an encryption
certificate nor loads a decryption key. Provider changes require preserving
this boundary until a separate threat review approves an extension.

The [2026-10-04 provider checkpoint](evidence/SAML_PROVIDER_2026-10-04.md)
records Windows and Linux fixture results and the limited public metadata probe.

## Optional external discovery probes

`crates/proxy/tests/external_identity.rs` includes ignored tests that exercise
the production OIDC discovery/JWKS client and signed SAML metadata validator
against operator-selected endpoints. Run them only from an operator-controlled
network:

```powershell
$env:LLM_FW_EXTERNAL_OIDC_ISSUER = 'https://accounts.google.com'
cargo test -p llm-firewall --test external_identity real_oidc_discovery_and_jwks_are_accepted -- --ignored --nocapture

$env:LLM_FW_EXTERNAL_SAML_METADATA_URL = 'https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml'
cargo test -p llm-firewall --test external_identity real_signed_saml_metadata_is_accepted -- --ignored --nocapture
```

The former private workspace recorded successful OIDC discovery/JWKS retrieval
against Google's public issuer and signed metadata validation against a
Microsoft federation endpoint on 2026-09-04. The October 2026 public checkpoints
repeat the Microsoft probe on Windows/Linux and record Google discovery plus
two JWKS keys accepted by the production client. The Google path also showed
intermittent five-second connection timeouts on this host; retain those failures
alongside the successful metadata evidence. See the
[execution record](ROADMAP_EXECUTION.md). None of these probes exercises an
interactive OIDC authorization-code exchange, a SAML assertion and ACS callback,
or vendor SCIM behavior.

Before a customer pilot, use a dedicated sandbox IdP with a registered HTTPS
callback and verify login, logout, session rotation, SAML assertion acceptance,
and the supported SCIM Users/Groups operations. Keep credentials and assertion
contents out of logs and test artifacts. See the [self-hosting guide](../SELF_HOSTING.md)
and [production runbook](PRODUCTION_RUNBOOK.md).
