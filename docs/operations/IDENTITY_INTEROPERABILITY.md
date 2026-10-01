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
Microsoft federation endpoint on 2026-09-04. Those historical checks did not
exercise an interactive OIDC authorization-code exchange, a SAML assertion
and ACS callback, or vendor SCIM behavior. They have not been repeated as
part of this public-source import.

Before a customer pilot, use a dedicated sandbox IdP with a registered HTTPS
callback and verify login, logout, session rotation, SAML assertion acceptance,
and the supported SCIM Users/Groups operations. Keep credentials and assertion
contents out of logs and test artifacts. See the [self-hosting guide](../SELF_HOSTING.md)
and [production runbook](PRODUCTION_RUNBOOK.md).
