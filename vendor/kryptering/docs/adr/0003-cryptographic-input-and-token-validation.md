# ADR 0003 - Cryptographic input validation and token security boundaries

**Status:** Accepted
**Date:** 2026-09-26
**Related:** [ADR 0001](0001-rng-choice.md),
[ADR 0002](0002-compile-time-provider-boundary.md),
[provider guidance](../providers.md), [0.6.0 changelog](../../CHANGELOG.md)

## Context

The 0.6.0 branch incorporates provider and PKCS#11 security fixes and follow-up
review changes. Algorithm support alone did not establish that supplied keys,
group parameters, signature encodings, or token results met Kryptering's
security requirements. Equivalent operations also reached different checks
depending on the selected provider or token mechanism.

The library serves both new applications and consumers of historical signed
and encrypted documents, including Bergshamra and tsp-ltv. Compatibility must
therefore be explicit: the `legacy` feature can select documented weaker size
limits, while validation of mathematical relationships, encodings, token
authentication, and secret lifetimes remains mandatory.

This ADR records the security boundaries implemented in this branch. Provider
selection and the prohibition on software-provider fallback remain governed
by ADR 0002. The known XMLSec compatibility failure described below remains
unresolved; acceptance of this decision does not mean that the full
interoperability gate passes.

## Decision

### Validate finite-field DH before retaining an opaque key

`ValidatedDhGroup::new` is the shared group-validation boundary for
`SoftwareKey::from_dh_parameters` and raw `hazmat::dh::compute` calls.

| Requirement | Normal RustCrypto build | RustCrypto with `legacy` |
|---|---|---|
| Minimum significant bits in modulus `p` | 2048 | 1024 |
| Minimum significant bits in subgroup order `q` | 224 | 160 |
| Maximum encoded modulus length, including leading zeros | 1025 bytes | 1025 bytes |
| Prime `p` and `q`, valid group and key relationships | Required | Required |

Leading zero padding does not contribute to either size. The original
modulus encoding width is still retained for the shared-secret output, so
valid padded inputs preserve their wire-format behavior.

The complete modulus encoding is capped before scanning the subgroup order
or allocating any bigint. Without this bound, a valid modulus preceded by
arbitrarily many zeros could satisfy the significant-bit minimum while
inflating every primality check, retained Montgomery parameter, subsequent
agreement, and output allocation. The 1025-byte cap accommodates an 8192-bit
modulus plus a sign byte; it limits encoding length, not significant bits.
Leading padding is allowed only within this total budget, including with
`legacy`. Keeping the bounded encoded width preserves both output padding
and private exponents padded to that width, without scanning secret leading
zeros. Encodings longer than the cap now fail even when their significant
values describe a valid group.

Both parameters must pass 64 independent, randomly based Miller-Rabin rounds.
The subgroup order is mandatory, must satisfy `1 < q < p`, and must divide
`p - 1`. Imported generators and public values must be nonidentity subgroup
elements. When a private exponent is supplied, it must lie in `[1, q-1]`
and produce the supplied public value from the generator.

Imported keys retain an immutable validated group, shared across cloned key
handles. Each agreement still checks the peer and private exponent; caching
group validation does not cache peer validity. Raw hazmat calls validate the
supplied group on every call. This avoids repeating expensive primality
checks for retained keys without exposing an unchecked import route.

AWS-LC refuses DH import and agreement because its supported API cannot
perform these validations. It does not retain unvalidated DH keys or invoke
RustCrypto as a fallback.

### Enforce RSA strength and PSS encoding bounds at use

RSA minimums are provider-specific where historical compatibility or upstream
capabilities require it:

| RSA path | Without `legacy` | With non-FIPS `legacy` | FIPS |
|---|---|---|---|
| RustCrypto software | 2048 bits | Size floor disabled; encoding bounds retained | Unavailable |
| AWS-LC software | 2048 bits | 2048 bits | 2048 bits |
| PKCS#11 token | 2048 bits | 1024 bits | 2048 bits |

The RustCrypto software legacy exception is an existing compatibility policy;
it does not imply that PKCS#11 accepts arbitrary small keys. In particular,
enabling `legacy` must not lower the FIPS RSA minimum.

PKCS#11 signing, verification, encryption, and decryption read the actual
selected object's `CKA_MODULUS` while holding the same session mutex used for
the operation. The check measures significant bits rather than trusting a
label, padded byte length, or `CKA_MODULUS_BITS`. Missing, unreadable, empty,
or zero moduli are errors, including for private-key objects. The common
check also covers RSA algorithms supplied through the HMAC wrapper's shared
`SignatureAlgorithm` argument.

Software RSA checks apply when keys are used; FIPS AWS-LC additionally checks
strength at import, and AWS-LC may reject short private keys during parsing.
RustCrypto's configurable RSA-PSS verification validates encoding capacity
and salt length before verification. Checked arithmetic rejects a key/hash
combination that cannot encode PSS even with an empty salt, including in
legacy mode. AWS-LC continues to reject non-digest-length PSS salts when its
stable API cannot represent them.

### Share ECDSA encoding and scalar validation across software providers

Both software providers use `src/ecdsa_encoding.rs` for conversion and
normalization. DER length decoding is bounded by the machine integer width;
sequence and INTEGER endpoints use checked addition and bounds-checked access.
Explicit DER conversion requires canonical lengths and INTEGER encodings and
rejects trailing data. Both signature scalars must satisfy `1 <= scalar < n`
for the selected P-256, P-384, or P-521 subgroup order.

The API also accepts raw `r || s`. Exact raw width takes precedence over DER
detection. At other widths, successful structural DER parsing commits to DER:
invalid scalars cannot then fall back to raw interpretation. Inputs that do
not parse structurally as canonical DER can still enter raw normalization,
where width and scalar checks apply. This preserves the existing raw-input
contract while making both software providers agree on ambiguous inputs.

PKCS#11 signature verification still delegates signature-format handling to
the token; it is not covered by this shared software parser.

### Authenticate token sessions and validate token-dependent operations

`CKR_USER_ALREADY_LOGGED_IN` always fails session creation. That response does
not authenticate the supplied PIN, even if Kryptering previously established
the login. Raw session access and independent contexts can change token state
without invalidating a local credential cache.

Callers can share one authenticated `Pkcs11Session` across operation objects.
A fresh login requires closing existing sessions and operation objects; the
library does not log out other sessions to force authentication. Raw-byte PIN
input is supported, and the library-owned PIN copy is zeroized on drop.
Token selectors and object lookups reject ambiguous matches.

AES-KW validates inputs before invoking the token: wrapping requires at least
16 bytes in eight-byte blocks; unwrapping requires at least 24 bytes in
eight-byte blocks. Successful wrap output must be exactly eight bytes longer
than the input, and unwrap output exactly eight bytes shorter. These result
checks follow both the key-management calls (`C_WrapKey`/`C_UnwrapKey`) and
the cipher fallbacks (`C_Encrypt`/`C_Decrypt`). Rejected output buffers are
zeroized, including unwrapped plaintext.

Temporary derived, wrapped, and unwrapped key objects are session objects.
Once created, destruction is attempted before returning success or an error.
A destruction failure takes precedence over an earlier read or operation
error because an extractable secret may remain on the token. The error tells
the caller to close the session to purge it. Host copies held during error
handling are wiped when the library owns them.

ECDH policy derives the named curve from `CKA_EC_PARAMS`. Recognized P-256,
P-384, and P-521 keys require requested full-width outputs of 32, 48, and
66 bytes, respectively; unknown curves are refused in FIPS mode. AES KEK
lengths are checked against `CKA_VALUE_LEN` when the token exposes it. Unlike
the RSA modulus policy, an absent KEK length attribute retains the existing
compatibility behavior.

These checks enforce library contracts at the token boundary. They do not
sandbox a native PKCS#11 module or establish that the token is FIPS validated.

### Wipe stored and temporary signing secrets

Post-quantum imports validate key encodings and the public/private
relationship before retaining an opaque key. SLH-DSA validation recomputes the
public root from the secret seeds rather than trusting the public half
embedded in a private-key encoding.

The locked ML-DSA and SLH-DSA dependencies enable their `zeroize` features.
For SLH-DSA this is necessary for `SigningKey`'s wiping destructor: wiping
only the retained private DER leaves loaded and recomputed typed keys without
that destructor. The feature covers keys created during signing and import
validation, through both raw-key and PKCS#8 loading paths. Temporary serialized
SLH-DSA private material is held in `Zeroizing`, and retained private encodings
are wiped when their owning key material is dropped.

Regression checks require `ZeroizeOnDrop` and a destructor for all six exposed
SLH-DSA parameter sets. This is a memory-lifetime guarantee for the covered
objects, not a claim that all compiler, operating-system, dependency-internal,
or caller-owned copies of secrets are erased.

### Keep provider capability, FIPS policy, and parsing checks distinct

AWS-LC uses its module-backed KDFs and internally generated AES-GCM nonces
where exposed by the supported API. FIPS PBKDF2 parameter minimums and
algorithm restrictions are checked explicitly; unsupported combinations
return errors rather than falling back to another implementation. Raw
symmetric imports and agreement entry points validate the key family.

The branch also rejects IV-only AES-CBC input and invalid software AES-KW
lengths. These structural checks are independent of algorithm availability
and remain in effect for historical documents. Dependency minimums for
rustls and cryptoki are recorded in the 0.6.0 changelog; dependency upgrades
complement the application-level checks rather than replacing them.

## Consequences and compatibility

Malformed or undersized inputs now fail at their owning validation boundary.
Some previously accepted DH imports, token sessions, RSA token objects, and
signature encodings are intentionally rejected. Token vendors must expose
the RSA public modulus on the selected object. Reading it on every operation
adds a token round trip, while retained DH validation avoids repeated
primality work for the same key.

`legacy` preserves valid 1024/160-bit DH groups and non-FIPS 1024-bit token
RSA operations. It does not disable subgroup validation, encoding bounds,
authentication checks, output-length checks, cleanup, or zeroization.
AWS-LC capability restrictions also remain in force.

The XMLSec fixture
`xmlenc11-interop-2012/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF`
has an even, composite subgroup order. Its existing-document decryption phase
was already rejected by this branch's primality fix before the size minimums
were added. The associated encryption and round-trip phases use valid
RFC 5114 group 3 parameters and continue to pass.

The 2026-09-26 validation run recorded:

| Check | Result |
|---|---|
| Kryptering default, full RustCrypto, AWS-LC, and FIPS configurations | Passed |
| SoftHSM RSA policy and token-operation integration tests | Passed |
| Formatting, Clippy, rustdoc, and Rust 1.88 build check | Passed |
| Bergshamra Rust tests with its default legacy configuration | 189 passed; existing ignored tests unchanged |
| tsp-ltv default tests | 255 passed |
| XMLSec signatures | 447 passed, 0 failed, 3 skipped |
| XMLSec encryption | 700 passed, 1 failed, 0 skipped |

Bergshamra's `tests/run-provider-interop.sh` still requires 701 successful
encryption cases. Its gate therefore remains failing; this ADR does not
change that expectation, skip the fixture, or claim 100% compatibility.
Resolving the fixture or its expected behavior is separate from weakening
the prime-subgroup requirement.

## Alternatives considered

- **Delegate all validation to providers and tokens.** Rejected: supported
  algorithms do not establish library key-strength, encoding, or output-size
  requirements, and token implementations differ.
- **Check token RSA sizes only when constructing an operation object.**
  Rejected: reading the actual object at use avoids relying on cached key
  metadata and covers every RSA dispatch path.
- **Repeat DH primality checks on every retained-key agreement.** Rejected:
  immutable imported groups can safely share validation; per-peer and
  private-exponent checks still run each time.
- **Disable validation wholesale in `legacy`.** Rejected: compatibility
  exceptions need explicit bounds. Accepting composite subgroup orders to
  satisfy one fixture would remove an existing security invariant.
- **Wipe only stored private encodings.** Rejected: typed signing keys and
  serialized temporary material are separate owned copies with independent
  lifetimes.
- **Maintain separate ECDSA parsers for each software provider.** Rejected:
  shared parsing makes length, canonicality, and scalar rules consistent and
  lets provider-parity tests protect the same boundary.

## Implementation and regression coverage

- [DH validation and tests](../../src/hazmat/dh.rs) and
  [opaque key imports](../../src/key.rs).
- [PKCS#11 policy, cleanup, and output checks](../../src/pkcs11/mod.rs) and
  [SoftHSM integration tests](../../tests/pkcs11_softhsm.rs).
- [Shared ECDSA parser](../../src/ecdsa_encoding.rs) and
  [provider-parity tests](../../tests/provider_parity.rs).
- [RSA-PSS bounds and post-quantum key handling](../../src/software/sign.rs)
  and [dependency features](../../Cargo.toml).

Regression coverage includes independently undersized and padded DH
parameters, valid modern and legacy groups, unavailable and padded RSA
modulus attributes, malformed AES-KW result lengths, temporary-object error
handling, and SLH-DSA raw/PKCS#8 import and signing controls. New tests include
Rustdoc comments explaining the invariant they protect. Feature combinations
are tested separately because `--all-features` is intentionally unsupported.
