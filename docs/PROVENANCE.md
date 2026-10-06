# Source provenance and intake rules

Soup Wall contains the Agent, Gateway, Console, and supporting crates in one Apache-2.0 workspace. The project is derived from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall) by Arthur Lin and contributors. Upstream copyright and patent terms remain in force. Keep SPDX identifiers, [LICENSE](../LICENSE), [NOTICE](../NOTICE), and required third-party notices. A per-file copyright line should be added only when its ownership can be established.

## External source intake

Record the origin, exact version or revision, license, and required notices before introducing external code or assets:

1. **Permissive reuse:** MIT, Apache-2.0, BSD, ISC, and similar licenses may be integrated after review.
2. **Reviewed copyleft:** GPL, LGPL, MPL, AGPL, and similar terms require an explicit legal and architectural review for the exact linked binary, container, frontend bundle, or hosted use.
3. **Specification only:** proprietary, non-commercial, research-only, source-available, unknown, or incompatible sources must not be copied. An independent implementation may use public specifications, documented behavior, and independently written tests. Keep the behavioral specification free of source fragments and distinctive implementation details.

Model weights, benchmark datasets, container base images, and frontend assets need their own license and provenance review. Their terms are not changed by the Rust workspace license. Optional ML model weights are fetched separately and are not silently bundled into the source distribution. The reviewed agent-session corpus is synthetic and hand-authored; it is regression material, not customer data or a held-out benchmark.

## Dependency and advisory review

The locked workspace includes the Gateway's identity and storage dependencies. The SAML adapter uses [`saml-rs 0.5.3`](https://github.com/salasebas/saml-rs/releases/tag/v0.5.3) (MIT), `bergshamra 0.9.2` (BSD-2-Clause), and [`kryptering 0.6.0`](https://github.com/kushaldas/kryptering/releases/tag/v0.6.0) (BSD-2-Clause). Kryptering is a pinned local package with a narrowly scoped platform patch. [Its intake record](../vendor/kryptering/PATCH.md) records the original registry archive checksum, upstream revision, retained license and source, omitted development assets, exact delta and update procedure. The upstream source differs only in its platform guard and error message; cryptographic operations are unchanged. Other dependencies remain registry packages.

All release targets select the AWS-LC document provider, using the workspace's existing `aws-lc-rs 1.18.1` dependency (Apache-2.0 OR ISC). The patch adds only non-FIPS Windows x86_64 MSVC to kryptering's existing Linux and non-FIPS macOS x86_64/aarch64 support. [AWS-LC itself supports Windows MSVC](https://aws.github.io/aws-lc-rs/platform_support.html). Windows ARM, Windows GNU and Windows FIPS are not admitted by this patch. Unsupported targets fail at the provider guard; there is no RustCrypto fallback. The complete application `Cargo.lock` and release graphs exclude `rsa`. Keep the vendored package excluded from the application workspace so upstream development dependencies do not enter that lock.

[`RUSTSEC-2023-0071`](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) concerns observable timing during RSA key-transport **decryption**. Soup Wall's SAML path does not configure an XML decryption key or advertise encrypted assertions; encrypted assertions fail closed, and regression tests protect that behavior. Provider selection does not enable encrypted assertions. The local, CI and release advisory checks run `cargo audit` without vulnerability exceptions. Informational maintenance and yanked-package warnings remain visible. Encrypted-assertion support still requires a separate threat review and new interoperability evidence.

[Issue #19](https://github.com/SoupTeam/soup-wall/issues/19) requires reviewed provider evidence, native signature and real-IdP document interoperability on every release target, absence of the vulnerable dependency from the complete locked release graph, and audit without an exception. The `saml-release-targets` CI job checks provider attestation, the resolved dependency boundary, signed SSO, signature and metadata tampering, and encrypted-assertion rejection on all four release targets. A locally manufactured IdP response is not vendor interoperability evidence; genuine vendor documents and live password/ACS acceptance must be identified separately.

The [2026-10-06 provider checkpoint](operations/evidence/SAML_PROVIDER_2026-10-06.md) records Windows-native SAML checks, live Keycloak password/ACS acceptance with successful cleanup, and the complete lock audit without an exception. Captured vendor-signed documents provide regression inputs for the four native release-target jobs. Review the candidate pull request's exact-head CI results before accepting the provider change; live vendor acceptance covers Windows. Issue closure requires every acceptance criterion above to pass.

Run a fresh locked dependency, license, and advisory review for each release. The `Cargo.lock` and generated CycloneDX SBOM describe the actual versions; this document is not a substitute for examining the current graph. A previous public Core-only audit with no exceptions does not describe the full workspace after the Gateway import.

The SAML interoperability fixture under `crates/proxy/tests/fixtures/saml/` uses a self-signed test key pair. It is not a customer credential and must not be used in a deployment. Secret scans of working files and Git history, including generated artifacts and workflow logs, are release checks before publishing material from a previously private source tree.

## Release evidence

Review and retain the locked dependency graph, an SBOM, third-party license and notice inventory, model and dataset records, the upstream attribution, and security-scan findings for the **complete** workspace. Document any unresolved advisory or deployment limitation in the release notes.
