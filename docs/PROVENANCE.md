# Source provenance and intake rules

Soup Wall contains the Agent, Gateway, Console, and supporting crates in one Apache-2.0 workspace. The project is derived from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall) by Arthur Lin and contributors. Upstream copyright and patent terms remain in force. Keep SPDX identifiers, [LICENSE](../LICENSE), [NOTICE](../NOTICE), and required third-party notices. A per-file copyright line should be added only when its ownership can be established.

## External source intake

Record the origin, exact version or revision, license, and required notices before introducing external code or assets:

1. **Permissive reuse:** MIT, Apache-2.0, BSD, ISC, and similar licenses may be integrated after review.
2. **Reviewed copyleft:** GPL, LGPL, MPL, AGPL, and similar terms require an explicit legal and architectural review for the exact linked binary, container, frontend bundle, or hosted use.
3. **Specification only:** proprietary, non-commercial, research-only, source-available, unknown, or incompatible sources must not be copied. An independent implementation may use public specifications, documented behavior, and independently written tests. Keep the behavioral specification free of source fragments and distinctive implementation details.

Model weights, benchmark datasets, container base images, and frontend assets need their own license and provenance review. Their terms are not changed by the Rust workspace license. Optional ML model weights are fetched separately and are not silently bundled into the source distribution. The reviewed agent-session corpus is synthetic and hand-authored; it is regression material, not customer data or a held-out benchmark.

## Dependency and advisory review

The locked workspace includes the Gateway's identity and storage dependencies. The SAML adapter uses `saml-rs 0.5.0`, which pulls in `rsa 0.9.10`. `RUSTSEC-2023-0071` concerns observable timing during RSA key-transport **decryption**. Soup Wall's SAML path does not configure an XML decryption key or advertise encrypted assertions; encrypted assertions fail closed, and a regression test protects that behavior. The supply-chain workflow narrowly ignores this advisory with `cargo audit --ignore RUSTSEC-2023-0071`. Any other advisory remains a failure. Do not extend this exception to encrypted-assertion support without a reviewed, timing-safe replacement and a new threat review.

Run a fresh locked dependency, license, and advisory review for each release. The `Cargo.lock` and generated CycloneDX SBOM describe the actual versions; this document is not a substitute for examining the current graph. A previous public Core-only audit with no exceptions does not describe the full workspace after the Gateway import.

The SAML interoperability fixture under `crates/proxy/tests/fixtures/saml/` uses a self-signed test key pair. It is not a customer credential and must not be used in a deployment. Secret scans of working files and Git history, including generated artifacts and workflow logs, are release checks before publishing material from a previously private source tree.

## Release evidence

Review and retain the locked dependency graph, an SBOM, third-party license and notice inventory, model and dataset records, the upstream attribution, and security-scan findings for the **complete** workspace. Document any unresolved advisory or deployment limitation in the release notes.
