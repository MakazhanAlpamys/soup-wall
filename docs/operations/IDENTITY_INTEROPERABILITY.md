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
[issue #19](https://github.com/SoupTeam/soup-wall/issues/19).

Configure the IdP to send signed plaintext assertions. Encrypted assertions
remain unsupported on every target: the SP neither advertises an encryption
certificate nor loads a decryption key. Provider changes require preserving
this boundary until a separate threat review approves an extension.

The [2026-10-04 provider checkpoint](evidence/SAML_PROVIDER_2026-10-04.md)
records Windows and Linux fixture results and the limited public metadata probe.

The [manual Keycloak SAML driver](KEYCLOAK_SAML_ACCEPTANCE.md) uses an isolated
official vendor runtime, a real password login and the production ACS. Its
[2026-10-05 checkpoint](evidence/KEYCLOAK_SAML_2026-10-05.md) remains incomplete:
the original run recorded 22 expected functional outcomes but failed private
profile cleanup; review found driver isolation and negative-check confounds.
The corrected driver has offline safety tests and awaits a fresh full run
after the operator resolves the cleanup blocker. This does not close managed
staging, other vendor protocols/platforms or issue #19.

## Optional external discovery probes

Record the provider's exact HTTPS issuer, without adding its discovery suffix.
Soup Wall derives discovery URLs using
[OpenID Connect Discovery 1.0 section 4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest):
remove a terminating slash, then append `/.well-known/openid-configuration`
after the issuer path. For example, the issuer
`https://id.example.test/realms/acme` yields
`https://id.example.test/realms/acme/.well-known/openid-configuration`, matching
[Keycloak's realm endpoint](https://www.keycloak.org/securing-apps/oidc-layers).
This is OIDC provider discovery, with a different path rule from RFC 8414 OAuth
authorization-server metadata. The returned issuer must still exactly match
the configured issuer, including a configured terminating slash. HTTPS,
certificate validation, refusal of redirects, and PKCE S256 remain required.

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
two JWKS keys accepted by the production client. During those public checks,
the optional Google test first failed twice at the existing five-second connect timeout.
An isolated probe of the exact production client then accepted discovery and
two JWKS keys in 2.067 seconds; a later connection timed out again. Direct
TCP/curl probes showed variable connection establishment. No reproducible
client, TLS, or proxy defect was demonstrated, and neither the timeout nor TLS
checks were weakened. Retain the failures alongside the successful metadata
evidence as an environment reliability limit. The
[current roadmap](../ROADMAP.md#phases) keeps the external
identity gate open. None of these probes exercises an
interactive OIDC authorization-code exchange, a SAML assertion and ACS callback,
or vendor SCIM behavior.

Before a customer pilot, use a dedicated sandbox IdP with a registered HTTPS
callback and verify login, logout, session rotation, SAML assertion acceptance,
and the supported SCIM Users/Groups operations. Keep credentials and assertion
contents out of logs and test artifacts. See the [self-hosting guide](../SELF_HOSTING.md)
and [production runbook](PRODUCTION_RUNBOOK.md).
