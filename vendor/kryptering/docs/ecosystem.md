# Dependency ecosystem status

**Last reviewed:** 2026-07-23
**Tool:** `cargo outdated --depth 1` against the top-level `Cargo.toml`
**Scope:** kryptering's direct RustCrypto / randomness deps only
(transitive deps are not evaluated here; `cargo audit` handles those)

This document records which direct-dep major bumps are currently
*ecosystem-blocked* — i.e. the upstream crate has shipped a new major,
but other direct deps we still need haven't caught up to the new
trait version, so taking the bump unilaterally produces trait-bound
errors at compile time. It exists so that future `cargo outdated`
runs don't re-litigate the same investigation: the blockers and the
upstream gating versions are listed up front.

## Status at a glance

| Crate | Current | Latest | Ecosystem blocker |
|---|---|---|---|
| `digest` | 0.10.7 | 0.11.2 | RustCrypto `digest 0.11` wave |
| `sha1` | 0.10.6 | 0.11.0 | `digest 0.11` wave |
| `sha2` | 0.10.9 | 0.11.0 | `digest 0.11` wave |
| `sha3` | 0.10.9 | 0.12.0 | `digest 0.11` wave |
| `hmac` | 0.12.1 | 0.13.0 | `digest 0.11` wave |
| `hkdf` | 0.12.4 | 0.13.0 | `digest 0.11` wave |
| `pbkdf2` | 0.12.2 | 0.13.0 | `digest 0.11` wave |
| `md-5` | 0.10.6 | 0.11.0 | `digest 0.11` wave |
| `ripemd` | 0.1.3 | 0.2.0 | `digest 0.11` wave |
| `rand` | 0.8.6 | 0.10.1 | `rand_core 0.10` wave |

The `cipher 0.5` wave (`aes`, `aes-kw`, `cbc`, `des`, `aes-gcm`) was
**taken on 2026-07-01** — see "Recently unblocked — cipher 0.5 wave"
below. The two remaining waves cannot be taken in isolation; the
explanation walks through each.

> **Note (2026-06-01):** `signature 3.0.0` and `digest 0.11.3` have now
> shipped as finals and are already present in the lockfile *transitively*
> (pulled by the post-quantum crates — see the "Recently unblocked" section
> below). They do **not** unblock Waves 1/3 for kryptering's direct
> `rsa`/`ecdsa`/`dsa` deps: those crates still have no new major on
> crates.io (`rsa 0.9.10`, `ecdsa 0.16.9`, `dsa 0.6.3` remain latest), so
> they continue to pin `signature 2.2` / `digest 0.10` / `rand_core 0.6`.
> The documented straddle (old line for RSA/ECDSA, new line for the PQ
> crates) is therefore still in force.

---

## Recently unblocked — post-quantum pre-release wave (2026-06-01)

The post-quantum crates were previously pinned to exact pre-releases
because their APIs were still churning. Finals (or newer RCs) have now
shipped and were taken together in this update:

| Crate | Was | Now | Pin style |
|---|---|---|---|
| `ml-dsa` | `=0.1.0-rc.8` | `0.1.0` | caret (final) |
| `pkcs8-pq` (`pkcs8`) | `=0.11.0-rc.11` | `0.11.0` | caret (final) |
| `slh-dsa` | `0.2.0-rc.4` | `0.2.0-rc.5` | pre-release caret (still RC) |

`ml-dsa 0.1.0`, `pkcs8 0.11.0` final, and `slh-dsa 0.2.0-rc.5` resolve
together cleanly — they agree on the same `pkcs8 0.11`, `signature 3`,
and `digest 0.11` lines. New transitive deps pulled: `shake 0.1.0`,
`sponge-cursor 0.1.0` (both clean under `cargo audit`).

**Source fallout:** `ml-dsa 0.1.0` removed the `KeyGen` trait (in rc.8 it
was a blanket `impl<P> KeyGen for P` used only as a bound). Key generation
now lives on `SigningKey::<P>::generate()` via the new `Generate` trait.
kryptering never called `key_gen` — it generates keys via
`ExpandedSigningKey::<P>::from_seed` — so the fix was simply dropping the
now-nonexistent `+ ml_dsa::KeyGen` bound from the four
`P: ml_dsa::MlDsaParams + ml_dsa::KeyGen` sites in `src/software/sign.rs`.
No behavioural change; 96 lib tests still pass.

`slh-dsa` remains a release candidate (`0.2.0-rc.5`); it has no final yet.
Keep the pre-release caret pin until `slh-dsa 0.2.0` final ships.

---

## Recently unblocked — cipher 0.5 wave (2026-07-01)

The two blockers Wave 2 was waiting on both shipped finals since the
last review, so the whole wave was taken together in one migration:

| Blocker | Was | Now |
|---|---|---|
| `aes-gcm` | 0.10 (internal `aes 0.8`) | **0.11.0** (internal `aes 0.9`) |
| `pkcs5` (transitive, PBES2) | 0.7 (`des 0.8`) | **0.8.1** (`des 0.9`) |

Direct-dep bumps taken:

```
aes      0.8 -> 0.9
aes-gcm  0.10 -> 0.11
aes-kw   0.2 -> 0.3
cbc      0.1 -> 0.2
des      0.8 -> 0.9   (legacy feature)
```

`cipher` moved 0.4 -> 0.5 in the lockfile as a result. No half-wave:
every direct block-cipher dep moved at once.

**Source fallout** (all in kryptering's own code — verified against the
registry sources for each new major):

- **cbc 0.2 (`cipher 0.5`)**: the block-mode traits were renamed
  `BlockEncryptMut`/`BlockDecryptMut` -> `BlockModeEncrypt`/`BlockModeDecrypt`,
  and the padded helpers lost their `_mut` suffix
  (`encrypt_padded_mut`/`decrypt_padded_mut` -> `encrypt_padded`/`decrypt_padded`).
  `KeyIvInit::new_from_slices` and the `block_padding::NoPadding` path are
  unchanged. Touched `src/hazmat/aes_cbc.rs`, `src/software/cipher.rs`
  (3DES-CBC), `src/software/keywrap.rs` (3DES-CBC). The 3DES sites also
  moved from `new(key.into(), iv.into())` to `new_from_slices(key, iv)?`
  because `&Array: From<&[u8]>` was removed from hybrid-array.
- **aes-kw 0.3**: `Kek<C>` was replaced by `AesKw<C>`; construction is now
  via `KeyInit::new_from_slice` (returns `Result`, no longer panics on bad
  length); `wrap`/`unwrap` were renamed `wrap_key`/`unwrap_key`. Touched
  `src/software/keywrap.rs`. The RFC 3394 / NIST SP 800-38F known-answer
  vectors still pass byte-for-byte, confirming the wrap output is identical.
- **aes-gcm 0.11**: no trait/method changes, but `Nonce::from_slice` is now
  deprecated in favour of `TryFrom` (hybrid-array). Replaced with
  `Nonce::from([u8; 12])` on the encrypt path and a checked `try_into` +
  `Nonce::from` on the decrypt path. Touched `src/software/cipher.rs`.

96 -> 107 lib tests passed under the then-current complete RustCrypto feature
set; clippy with all targets was clean and `cargo audit --deny warnings`
exited 0. Provider builds now use the explicit matrix documented in
`docs/providers.md`.

---

## Wave 1 — `digest 0.11`

`digest` is the trait crate. Every hash and every MAC / KDF built on
a hash implements traits from `digest`. A major version of `digest`
changes those trait definitions, so hash crates and consumers must
move in lockstep.

### Direct deps that pin `digest 0.10`

Verified by reading each crate's registry `Cargo.toml`:

| Consumer | Exact pin |
|---|---|
| `rsa 0.9.10` | `digest = 0.10.5` |
| `ecdsa 0.16.9` | `digest = 0.10.7` |
| `signature 2.2.0` | `digest = 0.10.6` |
| `hmac 0.12.1` | `digest = 0.10.3` |
| `pbkdf2 0.12.2` | `digest = 0.10.7` |

If we bump `sha2` to `0.11`, the `Sha256` struct implements
`digest::Digest` from `digest 0.11` but **not** from `digest 0.10` —
so `rsa::pss::SigningKey::<Sha256>::new(...)` stops compiling, along
with `Hmac::<Sha256>::new_from_slice(...)` and every `HashType`
dispatch macro site in `src/software/sign.rs` and `src/digest.rs`.

### Empirical probe

Attempted on 2026-04-23 by editing `Cargo.toml`:

```toml
sha2 = { version = "0.11", features = ["oid"] }   # was "0.10"
```

`cargo build` produced 40+ errors of the form:

```
error[E0277]: the trait bound `sha2::Sha256: digest::FixedOutput` is not satisfied
error[E0277]: the trait bound `sha2::Sha256: digest::HashMarker` is not satisfied
error[E0599]: the function or associated item `new` exists for struct
              `DigestImpl<sha2::Sha256>`, but its trait bounds were not satisfied
 --> src/digest.rs:36:48
```

...all rooted in the `digest 0.10 ↔ digest 0.11` type split. The
Cargo.toml change was reverted; no source edits were made.

### Unblock-condition

One coordinated bump wave when all of the following ship:

- `rsa 0.10` (also fixes the Marvin Attack, RUSTSEC-2023-0071)
- `ecdsa 0.17` / `dsa 0.7`
- `signature 3`
- `hmac 0.13`, `hkdf 0.13`, `pbkdf2 0.13` (already released but
  blocked by the above consumers)
- `ed25519-dalek 3` (or whatever release rebases onto `signature 3`)

At that point the right sequence is:
1. Bump `rsa`, `ecdsa`, `dsa`, `signature`, `ed25519-dalek` first.
2. Then bump `digest`, all `sha*`, `hmac`, `hkdf`, `pbkdf2`,
   `md-5`, `ripemd` together.
3. Rebuild each valid provider feature set and run `cargo clippy
   --all-targets -- -D warnings` for each one.

`slh-dsa 0.2.0-rc.4` already ships against `digest 0.11.0-rc.11`, so
it does *not* block the wave.

---

## Wave 2 — `cipher 0.5` / block-cipher majors — ✅ DONE (2026-07-01)

This wave is complete. `aes-gcm 0.11` and `pkcs5 0.8` shipped finals,
which were the two blockers (the former moved its internal `aes` to
0.9, the latter its `des` to 0.9), so `aes`, `aes-kw`, `cbc`, and `des`
were all bumped together on 2026-07-01. See "Recently unblocked —
cipher 0.5 wave" above for the blocker table and source fallout.

## Composite-signature Ed448 dependency (2026-07-23)

`draft-ietf-jose-pq-composite-sigs-03` requires Ed448 for its
ML-DSA-87-Ed448 combination. Kryptering pins
`ed448-goldilocks =0.14.0-pre.15`, because that is still a pre-release and
draft-vector behavior must not change through an implicit update. Only its
`alloc` and `signing` features are enabled.

The crate uses `signature 3` and `rand_core 0.10`, which are already present
through the PQ dependency family. Composite code calls Ed448's inherent
raw-key/sign/verify APIs, so the existing RSA/ECDSA `signature 2` line does
not cross the trait-version boundary. Revisit the exact pin, upstream audit
status, and API calls when a final `ed448-goldilocks 0.14` is released.

---

## Wave 3 — `rand_core 0.10`

`rand 0.10.1` ships against `rand_core 0.10`. Every signing path that
takes `&mut impl RngCore` or `&mut impl CryptoRngCore` from
`rand_core 0.6` breaks at the trait-bound site.

### Direct deps that pin `rand_core 0.6`

| Consumer | Why it matters |
|---|---|
| `signature 2.2.0` | defines `RandomizedSigner::sign_with_rng<R: CryptoRngCore>` where `CryptoRngCore` comes from `rand_core 0.6`. Used by `rsa::pss::SigningKey::sign_with_rng`, the Ed25519 / ECDSA signer impls, and the ML-DSA `sign_deterministic` path (old; now replaced by `sign_randomized`). |
| `rsa 0.9`, `dsa 0.6` | same. |
| `ed25519-dalek 2.1`, `x25519-dalek 2.0` | key generation takes `rand_core 0.6 CryptoRng` |

Kryptering already straddles both versions deliberately (see
`docs/adr/0001-rng-choice.md`): ML-DSA uses `getrandom::SysRng` which
is `rand_core 0.10 TryCryptoRng`, while RSA-PSS uses
`rand::rngs::OsRng` which is `rand_core 0.6 CryptoRngCore`. Both
call the same OS entropy syscall; the split is purely a trait-version
accommodation.

### Unblock-condition

- `signature 3` rebased onto `rand_core 0.10` (fallible
  `TryCryptoRng`)
- `rsa 0.10`, `dsa 0.7`, `ed25519-dalek 3`, `x25519-dalek 3` on the
  same trait line

At that point `rand::rngs::OsRng` can be replaced with
`getrandom::SysRng` workspace-wide and `docs/adr/0001-rng-choice.md`
retired.

---

## What was actually pulled on 2026-07-01

Direct-dep major bumps (the `cipher 0.5` wave — see "Recently unblocked
— cipher 0.5 wave" above for the source migration):

```
aes      0.8 -> 0.9
aes-gcm  0.10 -> 0.11
aes-kw   0.2 -> 0.3
cbc      0.1 -> 0.2
des      0.8 -> 0.9   (legacy)
# cipher 0.4 -> 0.5 followed transitively
```

`cargo update` compat-range patches (no Cargo.toml changes required),
notably clearing a **yanked** advisory:

```
crypto-bigint  0.7.3 -> 0.7.5   (0.7.3 was YANKED — cargo audit warning, now gone)
zeroize        1.8.2 -> 1.9.0
ml-dsa         0.1.0 -> 0.1.1
getrandom      0.4.2 -> 0.4.3
block-buffer   0.12.0 -> 0.12.1
hybrid-array   0.4.12 -> 0.4.13
log            0.4.30 -> 0.4.33
quote          1.0.45 -> 1.0.46
smallvec       1.15.1 -> 1.15.2
syn            2.0.117 -> 2.0.118
zerocopy(+derive) 0.8.50 -> 0.8.52
zeroize_derive 1.4.3 -> 1.5.0
```

Pin held back deliberately:

```
generic-array  0.14.9 -> 0.14.7 (pinned)
```

`generic-array 0.14.9` added a `#[deprecated(note = "please upgrade to
generic-array 1.x")]` attribute to `from_slice`, which fires 12 times in
`src/digest.rs` (via `p256::FieldBytes::from_slice`) and breaks
`clippy -- -D warnings`. `from_slice` cannot be dropped without moving to
`generic-array 1.x`, which is gated behind the `digest 0.11` wave (Wave 1,
still blocked on `rsa 0.10`). Pinning to `0.14.7` — the last 0.14 release
without the deprecation attribute — keeps clippy clean without touching the
digest-0.10-era code. Drop this pin when Wave 1 is taken.

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set built cleanly
- the complete RustCrypto library suite passed 107 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0 (127 deps scanned, no yanked crates)

## What was actually pulled on 2026-06-01

Direct-dep major bumps (post-quantum pre-release wave — see "Recently
unblocked" above):

```
ml-dsa    0.1.0-rc.8   -> 0.1.0    (KeyGen bound dropped in src/software/sign.rs)
pkcs8-pq  0.11.0-rc.11 -> 0.11.0
slh-dsa   0.2.0-rc.4   -> 0.2.0-rc.5
```

`cargo update` compat-range patches (no Cargo.toml changes required):

```
autocfg        1.5.0   -> 1.5.1
cmov           0.5.3   -> 0.5.4
cpubits        0.1.0   -> 0.1.1
crypto-common  0.2.1   -> 0.2.2
digest         0.11.2  -> 0.11.3   (transitive, PQ line)
hashbrown      0.17.0  -> 0.17.1
hybrid-array   0.4.10  -> 0.4.12
libc           0.2.185 -> 0.2.186
log            0.4.29  -> 0.4.30
memchr         2.8.0   -> 2.8.1
module-lattice 0.2.1   -> 0.2.3
serde_json     1.0.149 -> 1.0.150
serdect        0.4.2   -> 0.4.3
signature      3.0.0-rc.10 -> 3.0.0  (transitive, PQ line)
typenum        1.20.0  -> 1.20.1
zerocopy       0.8.48  -> 0.8.50
```

New transitive deps added: `shake 0.1.0`, `sponge-cursor 0.1.0`.

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set and its individual combinations built
- the complete RustCrypto library suite passed 96 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0 (155 deps scanned)

## What was actually pulled on 2026-04-23

`cargo update` picked up these compat-range patches (no Cargo.toml
changes required):

```
cmov      0.5.2  -> 0.5.3
ctutils   0.4.0  -> 0.4.2
libc      0.2.184 -> 0.2.185
rand      0.8.5  -> 0.8.6
rand_core 0.10.0 -> 0.10.1
semver    1.0.27 -> 1.0.28
sha3      0.10.8 -> 0.10.9
spki      0.8.0-rc.4 -> 0.8.0
typenum   1.19.0 -> 1.20.0
```

After the update (before selectable providers were introduced):
- the complete RustCrypto feature set built cleanly
- the complete RustCrypto library suite passed 93 tests
- clippy with all targets was clean
- `cargo audit --deny warnings` exits 0

## How to re-evaluate

```bash
cargo outdated --depth 1
```

For each crate still shown as a major behind, check:
1. What does `cargo outdated` report for `rsa`, `signature`, `ecdsa`,
   `aes-gcm`, `pkcs5`? If those are still at their current majors,
   the wave hasn't moved.
2. For a targeted probe, temporarily edit one crate (e.g.
   `sha2 = "0.11"`) in `Cargo.toml`, run `cargo build`, revert if
   the error cascade matches the ones above, and update this doc
   with the new pin versions you saw.

When an upstream release finally unblocks a wave, bump every crate in
that wave in a single commit, rebuild, and delete the corresponding
section of this document.
