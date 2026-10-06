# ADR 0002 — Compile-time provider boundary and AWS-LC integration

**Status:** Accepted
**Date:** 2026-07-20
**Deciders:** Kushal Das (crate author)
**Related:** PR #12, `docs/providers.md`, ADR 0001

---

## Context

Kryptering exposes one provider-neutral document-cryptography API to
Bergshamra, `tsp-ltv`, and direct consumers. Version 0.5 adds AWS-LC alongside
the original RustCrypto implementation and uses AWS-LC's validated module for
FIPS builds.

The providers do not have identical dependency graphs, key representations, or
algorithm surfaces. They must nevertheless share these security properties:

- a caller cannot silently fall back to another provider;
- unsupported parameter combinations fail before key material is used;
- initialization, capability checks, and randomness cross one control-plane
  boundary;
- secret-bearing concrete provider types do not leak into the public API; and
- a FIPS build cannot accidentally execute a RustCrypto implementation.

AWS-LC also introduces a native toolchain and a narrower stable Rust API. The
initial adapter supports Linux on x86_64 and aarch64. Algorithms absent from
stable `aws-lc-rs`, including DSA, finite-field DH, 3DES, and the current
post-quantum implementations, must remain unavailable rather than falling back
to RustCrypto.

## Decision

### Select document providers at compile time

Exactly one of the `rustcrypto` and `aws-lc` Cargo features must be enabled.
The `fips` feature selects `aws-lc`, enables the AWS-LC FIPS module, and is
incompatible with `rustcrypto`.

TLS provider selection remains a separate compile-time domain because document
cryptography and network TLS have different consumers. At most one of
`tls-ring` and `tls-aws-lc` may be enabled; FIPS builds may not select
`tls-ring`.

Provider implementations are conditionally compiled behind the same public
module paths. A binary therefore contains one document provider and cannot
downgrade at runtime or acquire a second implementation through a fallback.
CI checks the feature exclusions and audits the AWS-LC dependency tree for
RustCrypto primitive implementations.

### Keep the control-plane trait private and sealed

`backend::compile_time_provider::Provider` is the internal control-plane
contract. It deliberately contains only:

- the provider identity;
- initialization and attestation;
- parameterized capability decisions; and
- fallible random-byte generation.

The trait is private and sealed. It is not a public plugin API and is not the
data-plane interface for every cryptographic operation. Digest, key,
signature, cipher, KDF, and agreement implementations remain ordinary modules
selected by `cfg`, while public traits such as `Signer`, `Verifier`, and
`KeyAgreement` describe operation objects used by callers.

This split keeps the provider policy small enough to audit. Making the trait
public today would suggest that a downstream crate could add a backend, while
it could not also supply the conditionally selected modules, key
representation, capability registry entries, feature guards, or CI coverage
needed to uphold the provider contract.

### Integrate future providers in-tree against the same contract

The sealed trait is an extension point for Kryptering maintainers. A future
provider must add all of the following as one coordinated change:

1. A mutually exclusive Cargo feature and compile-time target guards.
2. A `BackendId` variant and sealed `Provider` implementation.
3. Provider modules implementing the existing public operation and key APIs.
4. Parameterized `supports(Operation)` entries that match actual behavior.
5. Neutral PKCS#8, SPKI, raw-key, or parameter import boundaries; public API
   types must not expose the provider SDK.
6. Fallible, OS-backed randomness with no process-local state or silent
   fallback, following ADR 0001.
7. Explicit FIPS policy and attestation behavior if the provider makes a FIPS
   claim. Provider capability and FIPS approval remain separate decisions.
8. Provider-baseline known-answer, round-trip, and negative tests, plus CI that
   proves other primitive implementations are absent from its dependency tree.
9. Documentation of unsupported algorithms and parameter combinations.

An operation missing from the new provider returns `UnsupportedAlgorithm`.
Calling into RustCrypto to fill a capability gap is not permitted.

## Why AWS-LC

AWS-LC provides maintained C implementations, a stable Rust wrapper, rustls
integration, and an available FIPS module. It allows Kryptering to offer an
attested FIPS execution mode without changing the provider-neutral API used by
document-processing crates.

The choice is not a claim that every AWS-LC algorithm is approved or that a
consuming application is certified. Kryptering still applies its own
operation-level FIPS allowlist, requires explicit process-wide initialization,
checks document and TLS provider attestation, and rejects the PKCS#12 Appendix
B KDF and other non-approved operations.

Stable `aws-lc-rs` limitations are part of the advertised capability surface.
For example, non-digest-length RSA-PSS salts and algorithm combinations without
stable parameter objects fail deterministically. They are not emulated with a
second provider.

## Consequences

### Positive

- Provider selection and dependency provenance are visible in the build.
- FIPS builds cannot silently execute RustCrypto document primitives.
- Capability failures are deterministic and occur before key use.
- The public API remains neutral across provider-specific key types.
- Adding another maintained backend has a documented, testable checklist.
- The small sealed control plane is easier to review than a public plugin ABI.

### Negative

- `--all-features` is intentionally invalid; CI and downstream automation must
  test explicit feature combinations.
- Adding a provider requires coordinated changes across modules, capabilities,
  tests, documentation, and CI rather than only implementing one trait.
- AWS-LC builds require its supported native toolchain and target platforms.
- Provider capability sets can differ where stable upstream APIs differ.

### Neutral

- PKCS#11 remains orthogonal. Token-held operations use the token, while policy
  checks and any software preprocessing use the selected document provider.
- TLS selection remains independent except where FIPS policy constrains it.

## Alternatives considered

### Public downstream-implementable `Provider` trait

Rejected for 0.5. The trait alone cannot replace the module implementations or
prove dependency exclusivity, and provider-defined associated types would leak
key and algorithm representations into the public API. A future public plugin
design would need a separate object-safe data-plane API, lifecycle model,
capability negotiation, key isolation contract, and compatibility policy.

### Runtime provider selection with trait objects

Rejected. Shipping multiple primitive implementations increases binary and
supply-chain surface, complicates opaque key ownership, and makes accidental
fallback or FIPS boundary crossing possible at runtime.

### Use AWS-LC only

Rejected. RustCrypto remains the portable default and provides the broad
document-interoperability and post-quantum surface required by existing
consumers. AWS-LC is selected when its implementation or FIPS properties are
required.

### Fall back to RustCrypto for missing AWS-LC operations

Rejected. It would make provider identity misleading, invalidate dependency
and FIPS assurances, and turn upstream API gaps into silent policy downgrades.

