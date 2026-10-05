# Manual Keycloak SAML acceptance

This manual Windows check starts the official Keycloak distribution and drives
its password login and SAML POST flow against an unchanged Soup Wall Gateway.
It provides a way to collect local vendor evidence without a customer tenant.
The [first checkpoint](evidence/KEYCLOAK_SAML_2026-10-05.md) is incomplete:
22 named functional checks returned their expected results, but disposable
profile cleanup failed. Review also identified isolation and negative-check
defects in that original driver. The corrected driver has offline regression
coverage and has **not** had a fresh full vendor run.

## Scope and isolation

The original Python driver imports two disposable realms, a synthetic user,
and a SAML client into a freshly unpacked Keycloak runtime. The signed realm
sets `saml.signature.algorithm=RSA_SHA256`. Keycloak itself signs the IdP
descriptor and login response/assertion using its freshly generated realm key.
The other realm supplies Keycloak's unsigned default descriptor. No local code
manufactures vendor metadata signatures or a positive SAML response.
The pinned implementation is visible in
[SamlService.java](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/services/src/main/java/org/keycloak/protocol/saml/SamlService.java)
and
[IDPMetadataDescriptor.java](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/services/src/main/java/org/keycloak/protocol/saml/IDPMetadataDescriptor.java).
The realm IdP setting differs from a broker's service-provider metadata setting.

The current driver requires the vendor's own certificate pin for each realm.
The Gateway must reject the unsigned descriptor before login and accept the
signed descriptor with its pin. A new SQLite database pre-provisions two
synthetic local principals with Owner membership. The real vendor subject maps
to one; a negative assertion mutation changes only NameID to the other allowed
subject. This removes unknown-identity authorization as an explanation for
rejection. Existing production SAML unit fixtures remain the executed isolated
signature-negative evidence until a fresh vendor run passes.

Both Keycloak and the Gateway bind to `127.0.0.1`. A local HTTPS edge forwards
to the unchanged Gateway's loopback HTTP listener. Fresh one-day certificates
use an ephemeral CA trusted only by the Python driver's explicit CA file;
certificate verification stays enabled. There is no OS trust installation or
Gateway CA extension. Both outbound driver and internal edge HTTP sessions set
`trust_env=False`, disable automatic redirects, and bound destinations to the
new local services. The edge rejects absolute/authority request targets.

Children receive only the Windows installation root plus generated Windows
runtime/search paths, an owned profile and temporary directory, and fresh
fixture settings. Provider keys, deployment settings, ambient profiles,
proxies and Java overrides are excluded. The vendor receives an explicitly
owned Java `user.home`. Credentials, certificates, database state, raw XML,
assertions and runtime logs remain in the disposable directory. Do not publish
that directory or raw execution artifacts.

The driver verifies login/ACS, secure session cookie attributes, provisioned
membership, replay rejection, the bounded negative mutation, session rotation,
and Gateway logout. It does not exercise OIDC authorization-code/PKCE login,
vendor SCIM, a browser UI, MFA, vendor SAML single logout, managed staging,
customer infrastructure, or Linux/macOS vendor runtimes. Signed plaintext
assertions are required; XML decryption remains unsupported. Windows still uses
RustCrypto, so the `rsa` advisory and
[issue #19](https://github.com/MakazhanAlpamys/soup-wall/issues/19) remain open.
The ignored `target` and runtime scratch path must be real checkout directories;
symlink/junction redirection is rejected before private runtime files are written.

## Pinned external runtimes and licenses

The distributions are external runtime inputs, not vendored repository code.
The driver checks both byte size and SHA-256 before extraction and rejects ZIP
paths escaping the newly allocated scratch directory. Retain the official
archives separately from each disposable profile.

| Runtime | Official input | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Keycloak 26.8.0 | [ZIP](https://github.com/keycloak/keycloak/releases/download/26.8.0/keycloak-26.8.0.zip) | 174169645 | `7ed1de3fda2598369262613bf682aab7e233d80a38c405e91588f7a7454370a1` |
| Temurin 25.0.4.1+1 Windows x64 HotSpot JDK | [ZIP](https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip) | 141167264 | `00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283` |

The download hashes matched official GitHub release-asset SHA-256 digests. The
Keycloak official SHA-1 sidecar also matched
`363e215b4ca65ff41edd2ca8d4f1c293436604ee`; SHA-256 is the extraction gate.
The Temurin official `.zip.sha256.txt` sidecar matched the table's SHA-256.
Keycloak's [26.8.0 release](https://github.com/keycloak/keycloak/releases/tag/26.8.0)
resolves to source commit `4246609cf2024c85016d3fb1254c3d2533367c31` and includes
its [Apache-2.0 license](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/LICENSE.txt).
The [Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4.1%2B1)
includes GPL-2.0 with the Classpath exception and additional bundled notices;
preserve its `legal` directory. Adoptium describes OpenJDK licensing on its
[project page](https://adoptium.net/about/).

Keycloak lists direct Windows installation and OpenJDK 25 among its
[supported configurations](https://www.keycloak.org/server/supported-configurations).
The driver uses development mode for this isolated fixture, not a production
Keycloak deployment. See its official
[ZIP startup guide](https://www.keycloak.org/getting-started/getting-started-zip)
and [TLS configuration](https://www.keycloak.org/server/enabletls).

## Reproduction after the cleanup blocker is resolved

Use Windows x64, Python 3.12+, and a disposable checkout. The tested Python
runtime was 3.12.10 with `requests==2.34.2`, `cryptography==50.0.1` and
`psutil==7.2.2`. Install those in an operator-owned virtual environment if they
are not already available. No Java installer, global `JAVA_HOME`, Docker,
WSL repair or OS certificate trust change is needed.

Build the Gateway and bootstrap example from the same clean source revision:

```powershell
cargo build --locked -p llm-firewall --example keycloak-saml-bootstrap
cargo build --locked -p llm-firewall
```

Store the downloaded archives at the paths below, verify their official
checksums, and invoke the driver only after the existing cleanup blocker is
resolved by the operator:

```powershell
$checkpointRevision = (git rev-parse HEAD).Trim()
python scripts/keycloak-saml-acceptance.py `
  --keycloak-zip target/keycloak-saml/runtime/keycloak-26.8.0.zip `
  --jdk-zip target/keycloak-saml/runtime/temurin25.zip `
  --gateway target/debug/llm-firewall.exe `
  --bootstrap-helper target/debug/examples/keycloak-saml-bootstrap.exe `
  --artifact-label $checkpointRevision `
  --out target/keycloak-saml/acceptance.json
```

Choose a fresh output filename in an existing writable parent directory. The
driver reserves it and publishes an atomic incomplete report before reading
inputs or allocating vendor resources. Existing files and input/source aliases
are rejected. Each named check saves an atomic incomplete snapshot, so a later
publication failure preserves the previous evidence. Successful acceptance is
published only after cleanup succeeds; non-finite JSON numbers are rejected.

`artifact-label` is an operator-supplied label, not independent proof of build
provenance. Preserve clean build commands and exact binary hashes. The driver
records its own source hash, both binary hashes and the local SAML source hash
dynamically; that local source hash alone does not prove the binary was built
from it. Reports contain named checks and hashes, with no raw protocol content.
Review and sanitize a report before copying it out of ignored `target/`.

Teardown terminates only the invocation's live child PID trees, waits for them,
closes owned servers/logs, and deletes only its newly allocated contained
scratch directory. Brief Windows unlink retries apply only to that new owned
directory after child termination. A persistent failure is retained as
`cleanup_passed=false`, with a nonzero exit and an exact operator cleanup path.
There is no option to adopt or delete an existing failed profile. Do not invoke
the driver or another removal method to bypass an approval-denied cleanup.

For the 2026-10-05 incomplete run, a private directory remains under the
original disposable checkout. The public record redacts its machine-specific
path; the local operator has the exact cleanup target:

```text
target/keycloak-saml/<failed-run-directory>
```

Automatic approval review rejected three subsequent native removal attempts
before execution, with the stated reason `blocked by policy`. The Gateway and
Java processes had stopped; the directory remains and contains disposable
private material. The operator must resolve removal of this exact directory
through an authorized environment change before a fresh full checkpoint. The
portable archives outside it must be retained. The failure does not establish
a particular Windows file attribute or open-handle cause: the original driver
retained only `PermissionError`, not its filename or OS error number.

## Offline review checks

The existing CI script test discovery includes this suite. Driver imports are
stdlib-only until a transport/runtime path is entered; only the actual requests
adapter regression skips if requests is unavailable. The `identity-sandbox`
workflow runs all thirteen driver checks with pinned `requests==2.34.2`, including
that transport regression. Cryptography and psutil are not installed for the
offline job. No vendor archive, server, token or paid provider is used:

```powershell
python -m unittest discover -s scripts/tests -p 'test_keycloak_saml_acceptance.py' -v
```

The suite checks fresh output reservation, rejection of existing input/output
aliases, invalid parents before startup, atomic failure preservation, archive
bounds, proxy/netrc isolation and disabled redirects,
edge destination bounds, owned child profiles and credential exclusion, exact
negative NameID byte mutation, persistent cleanup failure, and sanitized
nonzero failure reports. These tests do not substitute for the pending full
vendor run and clean teardown.
