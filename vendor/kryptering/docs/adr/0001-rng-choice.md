# ADR 0001 — Choice of CSPRNG for signing paths

**Status:** Accepted
**Date:** 2026-04-23
**Deciders:** Kushal Das (crate author)
**Related:** `DRR02.md` findings L-01 / L-02

---

## Context

`kryptering` contains two randomized signing paths:

1. ML-DSA (`src/software/sign.rs::pq_ml_dsa_sign`) — calls
   `ml_dsa::ExpandedSigningKey::sign_randomized(rng: &mut impl TryCryptoRng)`
   from `ml-dsa 0.1.0-rc.8`, which is built on **`rand_core 0.10`**.

2. RSA-PSS (`src/software/sign.rs::rsa_pss_sign`) — calls
   `rsa::pss::SigningKey::sign_with_rng(rng: &mut impl CryptoRngCore)` from
   `signature 2.2.0` (transitively via `rsa 0.9`), which is built on
   **`rand_core 0.6`**.

Additional randomness is required in test-only key generation paths (Ed25519,
ML-DSA generation), but those have no production impact.

Three CSPRNGs are readily available in the dependency graph:

| RNG | Crate | rand_core version | Nature |
|---|---|---|---|
| `getrandom::SysRng` | `getrandom 0.4` (w/ `sys_rng`) | 0.10 (fallible `TryCryptoRng`) | zero-sized syscall wrapper |
| `rand::rngs::OsRng` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | zero-sized syscall wrapper |
| `rand::thread_rng()` | `rand 0.8` | 0.6 (infallible `CryptoRngCore`) | ChaCha12 reseeded from OsRng, thread-local state |

`SysRng` and `OsRng` are **semantically identical** — both issue one OS entropy
syscall (`getrandom(2)` on Linux, `getentropy(2)` on *BSD, `BCryptGenRandom` on
Windows, `SecRandomCopyBytes` on macOS) per randomness draw, hold zero user-space
state, and are fork-safe by construction. They differ only in which `rand_core`
major version's traits they implement.

`thread_rng()` is a userspace ChaCha12 stream reseeded periodically from
`OsRng`. It is faster (no per-call syscall) at the cost of holding a keyed RNG
state in process memory.

---

## Decision

**Prefer `getrandom::SysRng` for all new code. Where an upstream API
requires `rand_core 0.6` traits that `SysRng` does not satisfy, use
`rand::rngs::OsRng` as the equivalent-semantics substitute. Never use
`rand::thread_rng()` for cryptographic signing paths.**

Concretely in this crate:

| Call site | RNG | Reason |
|---|---|---|
| `pq_ml_dsa_sign` | `&mut getrandom::SysRng` | `sign_randomized` takes `TryCryptoRng` (rand_core 0.10) — direct fit |
| composite ML-DSA signing | `&mut getrandom::SysRng` | the ML-DSA component uses the same randomized FIPS 204 operation |
| `rsa_pss_sign` | `let mut rng = rand::rngs::OsRng; &mut rng` | `sign_with_rng` requires `CryptoRngCore` (rand_core 0.6); `SysRng` does not implement that trait |
| `generate_ml_dsa` / `generate_ml_kem` / composite key generation | `getrandom::fill` | plain fallible secret generation; no trait bound to satisfy |
| `ml_kem_encapsulate` (`src/software/kem.rs`) | `getrandom::fill` + `encapsulate_deterministic` | see "ML-KEM encapsulation" below — kem 0.3's `Encapsulate` bound is an infallible `CryptoRng` |
| tests (key generation) | `rand::rngs::OsRng` | test-only; uniformity with RSA-PSS path |

Tests-only call sites are explicitly out of scope of this ADR but follow the
same preference for readability.

---

## Rationale

Kryptering is a cryptographic library: it runs inside other people's processes,
in unknown threading / forking / sandboxing regimes, and is touched at modest
call rates (one signature per API call, not per TLS record). The ranking of
what we care about, highest to lowest:

1. **Correctness under fork.** `thread_rng()` holds keyed ChaCha state in TLS.
   Post-`fork(2)`, both parent and child share that state until the next
   reseed; this is a historically recurring footgun
   ([OpenSSL CVE-2010-4252](https://nvd.nist.gov/vuln/detail/CVE-2010-4252),
   [Wireguard-Go wg-fork bug](https://www.zx2c4.com/projects/wireguard-go/)).
   `SysRng` / `OsRng` hold no state, so forking cannot produce correlated
   output.

2. **Failure visibility.** `SysRng` implements the fallible
   `TryCryptoRng`; OS RNG exhaustion (e.g. seccomp filter blocking
   `getrandom(2)`, chroot without `/dev/urandom`) propagates as a `Result`
   and is converted to `Error::Crypto` by the existing error path. The
   previously-used `UnwrapErr(SysRng)` collapsed the same failure into a
   panic (see DRR02 finding L-01), which is surprising to callers running
   under `catch_unwind`, async runtimes, or structured logging. Direct
   `SysRng` is clean.

   `rand_core 0.6`'s `CryptoRngCore` is infallible — `OsRng` panics on OS
   RNG failure. This is accepted on the RSA-PSS path because we cannot
   bridge traits without adapters, and fail-closed-by-panic is still the
   correct answer in the cryptographic-signing context (better than signing
   with predictable output).

3. **Memory hygiene.** `SysRng` and `OsRng` are unit structs — they carry no
   secret material that could leak via core dump, swap, `ptrace(2)`, or
   `/proc/<pid>/mem`. `thread_rng()` holds a live ChaCha key whose exposure
   is bounded only by reseed frequency; that keyed state is not wrapped in
   `Zeroize`.

4. **Dependency minimality.** `SysRng` comes from **`getrandom 0.4`**. This
   PR adds `getrandom 0.4` as a new direct dependency, gated behind the
   `post-quantum` feature so it's only compiled when ML-DSA signing is
   actually in use. `rand 0.8` is already present in the graph for
   `OsRng`, but it pulls **`getrandom 0.2`** transitively, so enabling
   `post-quantum` puts a second `getrandom` major into the build (plus
   the WASI transitive set that `getrandom 0.4` carries). That cost is
   accepted for PQ builds because `getrandom 0.4` is the only path to a
   `rand_core 0.10 TryCryptoRng`, and non-PQ builds pay nothing.

5. **Performance.** The per-sign syscall cost (~μs) is negligible next to
   the ML-DSA / RSA-PSS arithmetic (~ms). The speed advantage of
   `thread_rng()` is irrelevant on signing paths — it only matters in hot
   loops drawing thousands of random values per second (e.g. TLS record
   masking, randomized blinding in tight loops), none of which exist in
   this crate.

---

## ML-KEM encapsulation

ML-KEM encapsulation (added with `ml-kem 0.3.2`) needs 32 bytes of fresh
entropy per call — the FIPS 203 message `m`. The natural entry point,
`kem 0.3`'s `Encapsulate::encapsulate_with_rng`, only accepts an
**infallible** `rand_core 0.10 CryptoRng`; the only ways to feed it OS
randomness are `rand_core::UnwrapErr(SysRng)` or the `kem/getrandom`
convenience method, and both panic on OS-RNG failure — exactly the
failure mode this ADR prohibits (DRR02 finding L-01).

`encapsulate_with_rng` is, verbatim,
`let m = B32::generate_from_rng(rng); self.encapsulate_deterministic(&m)`,
and `encapsulate_deterministic` is a stable public method (its `hazmat`
cargo feature is empty and only controls doc visibility). So
`ml_kem_encapsulate` in `src/software/kem.rs` draws `m` with the fallible
`getrandom::fill` — surfacing failure as `Error::Crypto` — and calls
`encapsulate_deterministic(&m)` itself. This is byte-for-byte FIPS 203
Algorithm 20. The invariant, enforced by a comment at the call site and a
randomization regression test: **`m` must be fresh OS entropy on every
call, never fixed or reused, and wiped after use.** If a future `ml-kem`
release restricts `encapsulate_deterministic`, revisit this section
before falling back to `UnwrapErr` — that would reintroduce the panic.

---

## Why the split across two RNG types is acceptable

A reader will note that, after this ADR, two different concrete RNG types
appear in the signing module: `getrandom::SysRng` (ML-DSA) and
`rand::rngs::OsRng` (RSA-PSS). This is a pragmatic response to the current
state of the RustCrypto trait ecosystem:

- `signature 2.2.0` (used by `rsa 0.9`, `dsa 0.6`, `ed25519-dalek 2.x`, etc.)
  defines `RandomizedSigner::sign_with_rng<R: CryptoRngCore>` where
  `CryptoRngCore` comes from `rand_core 0.6`.
- `ml-dsa 0.1.0-rc.8` was published against the newer
  `rand_core 0.10 TryCryptoRng`.
- There is no automatic trait bridge between the two `rand_core` major
  versions.

We considered writing a small shim implementing `rand_core 0.6`'s `RngCore`
on top of `getrandom` directly; we rejected that option because (a) it
duplicates code that already exists in `rand::rngs::OsRng`, (b) it requires
us to maintain a trait adapter, and (c) `OsRng`'s behaviour is
bit-for-bit equivalent to what the shim would implement.

When `signature` and downstream crates migrate to `rand_core 0.10` (tracked
upstream — see [RustCrypto/traits#1596](https://github.com/RustCrypto/traits/issues/1596)),
this ADR should be revisited and the RSA-PSS path should be moved to
`SysRng` for uniformity.

---

## Consequences

**Positive**
- OS RNG failures in ML-DSA surface as `Error::Crypto("ML-DSA sign failed: ...")`
  — no panic — allowing callers to handle RNG exhaustion programmatically.
- Both signing paths now share the "syscall-per-draw, no user-space state"
  property; fork-safety is no longer hash-rate-dependent on reseeding.
- No new application-owned RNG machinery or runtime RNG semantics are
  introduced beyond the dependency upgrades already present in this PR
  (`getrandom 0.4` via the `post-quantum` feature, `ml-dsa 0.1.0-rc.8`).
  Non-PQ builds see zero Cargo.lock delta from the RNG choice itself.
- `thread_rng()`'s internal ChaCha state is gone from the signing module,
  reducing the surface area that would need `Zeroize` coverage to be airtight.

**Negative**
- Per-sign latency on RSA-PSS grows by one `getrandom(2)` syscall relative
  to the old `thread_rng()` path. For a signing API, this is submicrosecond
  vs. millisecond arithmetic — practically unmeasurable.
- Two concrete RNG types live in the same module until upstream trait
  alignment catches up. Comments at both call sites point back to this ADR.

**Neutral**
- Tests continue to use `rand::rngs::OsRng` directly; test semantics
  unchanged.

---

## Alternatives considered

### A. Keep `rand::thread_rng()` everywhere
Rejected: user-space RNG state introduces a fork-safety class of bug we
do not need to carry, and the speed advantage does not apply to signing.

### B. Write a `rand_core 0.6` adapter over `getrandom` directly
Rejected: code duplication of `OsRng`; no functional benefit.

### C. Use `rand_chacha::ChaCha20Rng::from_entropy()` per call
Rejected: creates ChaCha state whose zeroization story is upstream, not
under our control; no advantage over `OsRng` for a single 32-byte draw.

### D. Accept `impl RngCore` in a public API so callers choose
Rejected: pushes the RNG-choice footgun to every caller. The crate is
opinionated about cryptographic primitives elsewhere (e.g., rejecting
SHA-1 MGF1 in OAEP); RNG choice fits the same pattern.

---

## References

- FIPS 204 §3.4 ML-DSA signing (hedged vs deterministic rationale)
- `getrandom 0.4` documentation, `SysRng`
- `rand_core 0.10` `TryCryptoRng`, `UnwrapErr`
- `rand_core 0.6` `CryptoRngCore`
- DRR02 findings L-01, L-02
- RustCrypto migration tracking: <https://github.com/RustCrypto/traits/issues/1596>
