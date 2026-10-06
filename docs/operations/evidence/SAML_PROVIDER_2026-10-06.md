# Windows AWS-LC and genuine Keycloak SAML checkpoint, 2026-10-06

The new Windows local vendor acceptance passed **23 of 23 named checks**,
including termination of its own children and removal of its fresh disposable
runtime. The [sanitized report](SAML_PROVIDER_2026-10-06.json) records the run
from 14:08:22 to 14:09:10 UTC on Windows 11 build 26200 with Python 3.12.10.
It reports `passed=true` and `cleanup_passed=true`, with no failure or
operator-cleanup fields. This is a source-and-binary snapshot checkpoint;
the operator-supplied artifact label does not independently identify a build
commit. No release has been made.

The candidate was built from base commit
`028fa5de38d2cdcc479994468a820eceb4844967` with the provider, driver and shared
SSO-verifier changes on `codex/saml-windows-provider`. The production helper
ordering was finalized before this locked build and the successful run:

```powershell
cargo build --locked -p llm-firewall --bin llm-firewall --example keycloak-saml-bootstrap
```

The hashes below identify the exact working source and binary bytes used;
they do not identify a previously published release or an already existing
candidate commit.

## Executed evidence

| Check | Recorded result | Scope |
| --- | --- | --- |
| Real Keycloak password login and production ACS | 23 passed, cleanup passed | Fresh Windows local services |
| Native production SAML suite | 16 passed, zero failed, zero ignored | Windows x86_64 MSVC; includes six genuine-vendor corpus checks |
| Driver safety suite | 26 passed, zero failed | Windows; no vendor service started by these tests |
| Locked advisory audit | 442 dependencies, zero vulnerabilities, no exception | Complete application lock; informational warnings remain visible |
| Dependency boundary | `rsa` absent | Complete application lock and all four resolved release graphs |
| Native four-platform provider/corpus CI | Not included; pending at local capture | Linux x86_64, macOS arm64/Intel, Windows x86_64 MSVC |

Keycloak 26.8.0 generated the signed IdP descriptor and first positive
plaintext assertion using its fresh realm signing key. The driver did not
manufacture their signatures. The production ACS accepted that assertion,
issued a secure host-only HttpOnly SameSite=Lax session cookie and resolved
the pre-provisioned synthetic Owner membership. Replay was rejected; session
rotation invalidated the old cookie, and Gateway logout invalidated the new
session. The unsigned-descriptor check used that realm's own certificate
pin. The NameID mutation targeted a second pre-provisioned authorized local
principal, separating signature rejection from unknown-subject authorization.
These current checks remove the confounds documented in the older run.

The driver uses a minimal child environment, an owned profile and Java home,
bounded loopback destinations, explicit private-CA verification, disabled
ambient proxy/netrc lookup and an HTTPS edge requiring TLS 1.2 or later.
A native owned batch probe reproduced exit 17 when the launcher environment
omitted `OS`, then passed after the driver set the literal `OS=Windows_NT`.
The probe runs from a different directory and rejects an ambient replacement
of that value. The corrected vendor run subsequently passed readiness and
all later checks; the earlier launcher failure was not a SAML crypto failure.

## Genuine vendor corpus and provenance

The [public synthetic corpus](../../../crates/proxy/tests/fixtures/saml/keycloak-corpus.json)
has schema version 1 and marks `synthetic_fixture=true` and
`acceptance_complete=true`. It preserves the original signed metadata and
first positive base64 response, public IdP certificate, synthetic entities
and NameID, capture time, original outgoing request ID and RelayState, and
source/binary/archive digests. It contains no private key, password, cookie,
database or runtime log. The original request ID and RelayState were captured
from the outgoing SP AuthnRequest before contacting the IdP; response fields
were not used to manufacture the expected correlation.

`--fixture-out` reserves a fresh incomplete output before reading inputs or
allocating vendor resources. It publishes usable corpus data only after all
vendor checks, successful owned cleanup and successful report publication.
Existing files and input/report aliases are rejected. The exported subject
is synthetic and uses `example.test`; IdP and ACS destinations are local
HTTPS services. Review confirmed exact schema fields, matching report and
corpus provenance, matching metadata and public-certificate digests, and an
integer capture time inside the original signed Conditions window. Raw
protocol bytes were not printed during that review.

The corpus runs through production SSO validation with a fixed replay-cache
clock **only in tests**. Tests preserve the signed documents and verify the
positive case, metadata endpoint and NameID tampering, mismatched original
request/RelayState, expiry and replay. Missing or incomplete corpus data is
an explicit test failure. Production uses the real clock and replay cache;
the fixed test clock does not extend the assertion's production validity.
Cross-platform tests establish genuine vendor-document
interoperability, not a live Keycloak password/ACS flow on every platform.

The report and corpus agree on these measured hashes:

| Input | SHA-256 |
| --- | --- |
| Acceptance driver | `3505455f8ea30786e5fa1867bfe3935e193adeb5e7c68756927437eb63c897da` |
| Production SAML source | `b370d25b7462726dd8a118689061b26daf4c9c9e1dd0dbfb43b6964a846418fe` |
| Gateway binary | `a95481733e566c6796ac8308b8b9bea19763688d8a2aabe045aaebbf6bc368eb` |
| Bootstrap binary | `dd8133d59e279c9e6ea336e28692ded2247965f19ac487686411c832c4805355` |
| Official Keycloak 26.8.0 archive | `7ed1de3fda2598369262613bf682aab7e233d80a38c405e91588f7a7454370a1` |
| Official Temurin 25.0.4.1+1 archive | `00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283` |

Review independently matched the current driver, SAML source and both binary
hashes. A source digest alone does not prove which source built a binary;
retain the associated locked build verification. Metadata and public IdP
certificate digests are also recorded in the JSON. Official runtime inputs,
licenses and reproduction instructions are in the
[acceptance guide](../KEYCLOAK_SAML_ACCEPTANCE.md).

## Provider boundary and historical limits

The current SAML feature selection uses the AWS-LC document provider with
no RustCrypto fallback. The
[pinned kryptering 0.6.0 patch](../../../vendor/kryptering/PATCH.md) changes
only the platform guard and its diagnostic to admit non-FIPS Windows
x86_64 MSVC. Cryptographic operations are unchanged. Existing Linux and
non-FIPS macOS support remains; Windows ARM, GNU and FIPS are excluded.
This is a scoped local platform extension, not an upstream Windows support
claim or a new RSA/XML implementation. Encrypted assertions remain disabled:
the SP advertises no encryption certificate, configures no decryption key
and rejects encrypted assertions.

The complete application lock and resolved release graphs exclude `rsa`;
the audit was run without `RUSTSEC-2023-0071` or another vulnerability ignore.
The old exception is not a current clean-audit result. These dependency
checks and the Windows live run are recorded separately from hosted native
four-platform CI, which was pending at this local checkpoint and is not
included in this record. Exact-head run links and per-platform results belong
in the candidate PR after those jobs pass. This checkpoint does not close
[issue #19](https://github.com/SoupTeam/soup-wall/issues/19) or
certify a release, customer IdP, managed staging, browser/MFA flow, OIDC
code/PKCE login, vendor SCIM or vendor SAML single logout.

The [2026-10-05 record](KEYCLOAK_SAML_2026-10-05.md) and its
[original JSON](KEYCLOAK_SAML_2026-10-05.json) remain unchanged and incomplete.
That run had failed private-profile cleanup; subsequent removal attempts
were rejected before execution with the reason `blocked by policy`.
Its retained profile was not read, adopted, moved or deleted for this new
checkpoint. The new independent run used a newly allocated contained profile
under the current public checkout and cleaned only its own live children and
directory. It does not resolve or reinterpret the historical cleanup failure.
The [2026-10-04 provider record](SAML_PROVIDER_2026-10-04.md) likewise remains
historical evidence rather than a description of the current provider graph.
