# Cryptographic providers

Kryptering 0.5 selects document cryptography and network TLS independently at
compile time. It never falls back from one provider to another.

See [ADR 0002](adr/0002-compile-time-provider-boundary.md) for the AWS-LC
selection rationale, the sealed provider-trait design, and the requirements
for adding future backends.

See [ADR 0003](adr/0003-cryptographic-input-and-token-validation.md) for the
0.6.0 validation decisions, legacy limits, token lifecycle rules, and the
remaining XMLSec compatibility limitation.

## Selection contract

| Domain | Features | Rule |
|---|---|---|
| Document crypto | `rustcrypto`, `aws-lc` | exactly one |
| Network TLS | `tls-ring`, `tls-aws-lc` | at most one |
| Compliance | `fips` | incompatible with `rustcrypto` and `tls-ring` |
| HSM | `pkcs11` | orthogonal to the software provider |

AWS-LC is initially gated to Linux x86_64/aarch64.
`--all-features` is an expected compile failure.

## Non-FIPS capability registry

This table describes provider operations implemented and exercised by the
backend test matrix. A parameter combination outside the row returns
`UnsupportedAlgorithm` before key material is parsed or used.

| Operation | RustCrypto | AWS-LC |
|---|---|---|
| RNG | yes | yes |
| SHA-2 / HMAC-SHA-2 | yes | yes |
| RSA PKCS#1/PSS signatures | broad legacy + modern set | SHA-256/384/512 signing |
| ECDSA | broad curve/hash set | stable AWS-LC curve/hash mappings |
| Ed25519 | yes | yes |
| AES-CBC/GCM | 128/192/256 | 128/192/256 |
| AES-KW | 128/192/256 | 128/256 |
| RSA-OAEP | SHA-1/224/256/384/512 with independent MGF1; MD5/RIPEMD160 with `legacy` | SHA-1/256/384/512 when OAEP and MGF hashes match |
| ECDH | P-256/P-384/P-521 | P-256/P-384/P-521 |
| X25519 | yes | yes |
| finite-field X9.42 DH | validated group and key components | import and agreement unsupported |
| HKDF/PBKDF2/ConcatKDF | yes | SHA-1/SHA-2 family where the AWS API supports it |
| DSA signatures | with `legacy` | unsupported |
| 3DES-CBC / 3DES key wrap | with `legacy` | unsupported |
| ML-DSA / SLH-DSA | feature-dependent | unsupported by stable AWS-LC APIs |
| Composite ML-DSA (`draft-ietf-jose-pq-composite-sigs-03`) | all six variants with `post-quantum` | unsupported |

The authoritative queries are `supports(Operation)` for a single fully
parameterized operation and `capabilities()` for the complete tested registry.
The latter is generated from the same parameter registry used by capability
tests, rather than from a separately maintained list.

## Initialization and FIPS

Non-FIPS builds initialize ergonomically on first use. In a `fips` build,
`initialize_backend()` must succeed first; cryptographic operations and TLS
configuration otherwise return `BackendNotInitialized`.

The `fips` feature selects AWS-LC for document cryptography. AWS-LC
initialization calls `try_fips_mode()`; when TLS is enabled, `tls-aws-lc` is
the only permitted TLS provider and must independently report active FIPS mode.

Stable AWS-LC APIs require RSA public keys of at least 2048 bits. They also do
not expose non-default RSA-PSS salt lengths. Those salt declarations are
reported as `UnsupportedAlgorithm` when the verifier is constructed, before
signature verification uses the key.

FIPS capability reporting excludes unavailable or unapproved operations.
Building with the `fips` feature does not certify the consuming binary or its
deployment. AWS-LC FIPS builds additionally need the native toolchain required
by aws-lc-rs.

## Key migration

Provider-specific public key enums are replaced by the cloneable,
`Arc`-backed `SoftwareKey`. Import PKCS#8 private keys, SPKI public keys, raw
symmetric bytes, X25519 components, neutral finite-field DH parameters,
post-quantum DER, or aggregate raw composite ML-DSA keys through explicit
constructors. Use `algorithm()`, `has_private_key()`, and `public_component()`
for metadata; private export is explicit and returns a zeroizing buffer.
`Debug` never prints secret material.

Digest one-shot and streaming construction are fallible in 0.5 because
initialization or provider capability checks can fail.

Finite-field DH imports require a subgroup order. RustCrypto validates prime
`p` and `q`, their relationship, generator and public subgroup membership,
private-exponent range, and the public/private relationship before retaining
a key. Cloned handles share that validation; every agreement still validates
the peer. AWS-LC refuses DH import because its supported API cannot perform
these checks. Raw hazmat DH calls validate their supplied group every time.
The minimum significant sizes are 2048 bits for `p` and 224 bits for `q`.
For historical documents, `legacy` permits 1024/160-bit groups. Leading zero
padding never contributes to these limits. Both modes still require prime
parameters and valid subgroup membership; `legacy` does not permit composite
subgroup orders.

Both modes limit the complete modulus encoding to 1025 bytes, including all
leading zero padding. Raw calls and imports enforce this before bigint
allocation, bounding arithmetic precision, retained Montgomery parameters,
and shared-secret output size. This accommodates an 8192-bit modulus with a
sign byte. Accepted encodings still determine the shared-secret output width.

SLH-DSA signing keys have zeroizing destructors, including temporary keys
created while validating imports and signing. Stored private encodings and
temporary serialized secret material are also wiped on drop.

ECDSA conversion and verification in both software providers share encoding
rules. PKCS#11 verification delegates signature format handling to the token.
Exact-width input is raw `r||s`; otherwise canonical DER is recognized before
raw normalization. Both scalars must be nonzero and less than the curve order.
Explicit DER conversion always requires canonical DER. Once structurally
valid DER is recognized, invalid scalars are errors, without a raw fallback.

## PKCS#11 login ownership

Opening a session succeeds only when the token actually authenticates the
supplied PIN. `CKR_USER_ALREADY_LOGGED_IN` is always refused, even for a PIN
previously accepted by kryptering: raw sessions and external contexts can
change authentication state without notification. Reuse one `Pkcs11Session`
when constructing multiple signers, verifiers, or other operation objects;
they share its synchronized session and may be used concurrently. Close all
session handles and operation objects before requesting a fresh login.

RSA signing, verification and key transport read the selected token object's
`CKA_MODULUS` on every use while holding the session lock. Its significant
size must be at least 2048 bits, or 1024 bits in non-FIPS `legacy` builds.
Missing, unreadable, empty or zero moduli are errors. This applies to private
and public objects alike; tokens must expose the public modulus even when
the private exponent remains non-extractable.

AES-KW checks token output lengths as well as caller input lengths. Wrapping
must add exactly eight bytes, and unwrapping must remove exactly eight bytes,
for both key-management calls and cipher fallbacks. Unexpected unwrapped
bytes are wiped before returning an error; temporary token objects are still
destroyed before the result is returned.
