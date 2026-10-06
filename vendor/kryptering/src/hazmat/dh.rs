#![forbid(unsafe_code)]

//! # ⚠ HAZMAT — Finite-field Diffie-Hellman (X9.42) ⚠
//!
//! Modular-exponentiation Diffie-Hellman, provided solely for legacy
//! interop (XML Encryption 1.0/1.1 DH-ES per W3C, RFC 2631 CMS). See
//! [`crate::hazmat`] for the top-level warning.
//!
//! For any new protocol, use ECDH ([`crate::keyagreement::ecdh_p256`] etc.
//! or [`crate::keyagreement::ecdh_x25519`]). Finite-field DH is slower,
//! larger, and has a rougher side-channel profile.
//!
//! ## Wire format
//!
//! All byte slices are **big-endian**. [`compute`] returns the shared
//! secret zero-padded on the left to `p.len()` bytes — this is required
//! by the DH-ES / ConcatKDF pipeline so that the derived KEK is
//! reproducible against test vectors.
//!
//! ## Constant-time caveats
//!
//! The modular exponentiation is performed via
//! [`crypto_bigint::modular::BoxedMontyForm::pow`], which uses a
//! Montgomery ladder with windowed lookups. This is **constant-time in
//! the bit pattern** of the exponent, but the **bit-length** of the
//! exponent is observable: the number of ladder iterations is
//! proportional to `exponent.bits_precision()`.
//!
//! We mitigate the bit-length leak by padding the private exponent to
//! `p.bits_precision()` before calling `pow`. Every DH operation against
//! the same modulus therefore runs for the same number of iterations
//! regardless of the caller's private-key magnitude.
//!
//! Heap allocation and windowed-table cache timing are **not** mitigated.
//! A remote network attacker without sub-microsecond timing precision
//! will not recover key material; a co-located attacker (shared SMT
//! core, shared L1 cache, hypervisor-level observation) may still extract
//! bits. If that threat model applies, do DH on a hardware HSM.
//!
//! ## Parameter and subgroup validation
//!
//! The modulus `p` must have at least 2048 significant bits and the subgroup
//! order `q` at least 224. The `legacy` feature lowers these minimums to
//! 1024 and 160 bits for historical documents. Leading zero padding does not
//! contribute to either size; primality and subgroup checks still apply.
//! In both modes, the complete encoding of `p`, including all leading zeros,
//! must be at most 1025 bytes. This bounds arithmetic and output allocation
//! while accommodating an 8192-bit modulus with a leading sign byte.
//!
//! [`compute`] first checks the group parameters: `1 < q < p` and
//! `q` divides `p - 1`. Both `p` and `q` must pass 64 independent,
//! randomly based Miller–Rabin rounds (false acceptance probability at most
//! 2^-128 per composite candidate). Entropy failures return an error.
//! The private exponent must lie in `[1, q-1]`
//! (compared in constant time). It then performs two checks on the
//! peer's public key `y`:
//!
//! 1. `1 < y < p` — rejects the identity / trivial points.
//! 2. `y^q mod p == 1` — confirms `y` is in the subgroup of order `q`.
//!    Prevents small-subgroup attacks where an attacker supplies a `y`
//!    in a short-order subgroup to leak bits of the private key.
//!
//! Leading zero bytes on the public inputs (`y`, `q`) are ignored, so a
//! DER-style `y` with a single `0x00` sign byte is accepted.
//!
//! `q` is therefore required (the API takes `Option<&[u8]>` for
//! signature stability with the previous keyagreement::dh_compute, but
//! `None` is rejected). Imported [`crate::SoftwareKey`] handles validate
//! supplied group parameters once at import and reuse that immutable result.
//! Each agreement still checks the peer public key and private exponent.

use crate::backend::{require_supported, Operation};
use crate::error::{Error, Result};
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Choice, CtEq, CtGt, CtLt, NonZero, Odd, RandomMod};
use crypto_primes::hazmat::MillerRabin;
use zeroize::Zeroize;

const MIN_P_BITS: u32 = if cfg!(feature = "legacy") { 1024 } else { 2048 };
const MIN_Q_BITS: u32 = if cfg!(feature = "legacy") { 160 } else { 224 };
// Cap the entire encoding before allocating bigints. Padding contributes to
// both arithmetic precision and shared-secret length, even for small values.
const MAX_P_ENCODED_LEN: usize = 1025;

/// Compute `shared = other_public ^ my_private mod p`.
///
/// All values are big-endian byte slices. The output is zero-padded
/// on the left to `p.len()` bytes. `q` (the subgroup order) is
/// required for subgroup validation; passing `None` returns an error.
/// Both `p` and `q` are checked for primality as described in the module docs.
/// Their minimum sizes are 2048 and 224 significant bits, respectively.
/// With `legacy`, the minimums are 1024 and 160 bits.
/// In either mode, `p` is limited to 1025 bytes including leading zero padding.
pub fn compute(
    other_public: &[u8],
    my_private: &[u8],
    p: &[u8],
    q: Option<&[u8]>,
) -> Result<Vec<u8>> {
    require_supported(Operation::DhAgreement)?;
    ValidatedDhGroup::new(p, q)?.agree(other_public, my_private)
}

/// Immutable proof of group validation, constructed only through `new`.
/// Stored with imported keys so peer agreement never repeats primality checks.
pub(crate) struct ValidatedDhGroup {
    p: BoxedUint,
    q: BoxedUint,
    params: BoxedMontyParams,
    encoded_len: usize,
}

impl ValidatedDhGroup {
    pub(crate) fn new(p: &[u8], q: Option<&[u8]>) -> Result<Self> {
        // ---- Parse public parameters (all non-secret) ----

        // ---- Structural checks (fail fast, no crypto yet) ----

        if p.is_empty() {
            return Err(Error::Key("DH modulus p is empty".into()));
        }
        if p.len() > MAX_P_ENCODED_LEN {
            return Err(Error::Key(format!(
                "DH modulus encoding exceeds {MAX_P_ENCODED_LEN} bytes including leading padding"
            )));
        }
        let q_bytes = strip_leading_zeros(q.ok_or_else(|| {
            Error::Key("DH subgroup order q is required for subgroup validation".into())
        })?);

        // Pick a common bit precision for every BoxedUint in this call. We
        // round up to the modulus byte length in bits; crypto-bigint will
        // further round up internally to a whole-limb boundary, so all our
        // operands land in the same limb count.
        let bits = u32::try_from(p.len())
            .ok()
            .and_then(|len| len.checked_mul(8))
            .ok_or_else(|| Error::Key("DH modulus encoding is too large".into()))?;

        let p_uint = BoxedUint::from_be_slice(p, bits)
            .map_err(|e| Error::Key(format!("DH modulus parse: {e:?}")))?;
        let q_uint = BoxedUint::from_be_slice(q_bytes, bits)
            .map_err(|e| Error::Key(format!("DH subgroup order q parse: {e:?}")))?;
        // Check actual magnitudes before expensive primality tests. Padding
        // changes the output width, but must never satisfy a strength floor.
        for (value, name, minimum) in [(&p_uint, "p", MIN_P_BITS), (&q_uint, "q", MIN_Q_BITS)] {
            let actual = value.bits_vartime();
            if actual < minimum {
                return Err(Error::Key(format!(
                    "DH parameter {name} has {actual} bits; requires at least {minimum} bits"
                )));
            }
        }
        let one = BoxedUint::one_with_precision(bits);

        // Reject even modulus up-front — Montgomery form requires it odd,
        // and all real DH primes are odd. This path also catches `p == 0`
        // and `p == 2` as edge cases.
        let p_odd = Option::<Odd<BoxedUint>>::from(Odd::new(p_uint.clone()))
            .ok_or_else(|| Error::Key("DH modulus p must be odd".into()))?;

        // ---- Group parameter checks: 1 < q < p and q | (p - 1) ----
        // All public, so variable-time arithmetic is fine here.
        if !bool::from(q_uint.ct_gt(&one) & q_uint.ct_lt(&p_uint)) {
            return Err(Error::Key(
                "DH subgroup order q out of range (must satisfy 1 < q < p)".into(),
            ));
        }
        let q_nonzero = Option::<NonZero<BoxedUint>>::from(NonZero::new(q_uint.clone()))
            .ok_or_else(|| Error::Key("DH subgroup order q out of range".into()))?;
        if !bool::from(p_uint.wrapping_sub(&one).rem_vartime(&q_nonzero).is_zero()) {
            return Err(Error::Key(
                "DH subgroup order q does not divide p - 1".into(),
            ));
        }

        require_probable_prime(&p_uint, "p")?;
        require_probable_prime(&q_uint, "q")?;
        let params = BoxedMontyParams::new(p_odd);

        Ok(Self {
            p: p_uint,
            q: q_uint,
            params,
            encoded_len: p.len(),
        })
    }

    /// Validate all imported components before retaining a key handle.
    pub(crate) fn validate_key(
        &self,
        generator: &[u8],
        public: &[u8],
        private: Option<&[u8]>,
    ) -> Result<()> {
        self.validate_element(generator, "generator")?;
        self.validate_element(public, "public key")?;
        if let Some(private) = private {
            let expected = zeroize::Zeroizing::new(self.agree(generator, private)?);
            let public = left_pad_to(strip_leading_zeros(public), self.encoded_len);
            if !crate::digest::constant_time_eq(&expected, &public) {
                return Err(Error::Key(
                    "DH public key does not match generator and private exponent".into(),
                ));
            }
        }
        Ok(())
    }

    /// Return a nonidentity element of the validated prime-order subgroup.
    fn validate_element(&self, input: &[u8], name: &str) -> Result<BoxedMontyForm> {
        let bits = self.p.bits_precision();
        let one = BoxedUint::one_with_precision(bits);
        let value = BoxedUint::from_be_slice(strip_leading_zeros(input), bits)
            .map_err(|e| Error::Key(format!("DH {name} parse: {e:?}")))?;
        if !bool::from(value.ct_gt(&one) & value.ct_lt(&self.p)) {
            return Err(Error::Key(format!(
                "DH {name} out of range (must be in 2..p-1)"
            )));
        }
        let value = BoxedMontyForm::new(value, &self.params);
        if !bool::from(value.pow(&self.q).retrieve().ct_eq(&one)) {
            return Err(Error::Key(format!(
                "DH {name} fails subgroup check (y^q mod p != 1)"
            )));
        }
        Ok(value)
    }

    pub(crate) fn agree(&self, other_public: &[u8], my_private: &[u8]) -> Result<Vec<u8>> {
        require_supported(Operation::DhAgreement)?;
        if my_private.len() > self.encoded_len {
            return Err(Error::Key(
                "DH private exponent longer than modulus byte length".into(),
            ));
        }
        let bits = self.p.bits_precision();
        let zero = BoxedUint::zero_with_precision(bits);
        let other_public = strip_leading_zeros(other_public);
        let y_mont = self.validate_element(other_public, "peer public key")?;

        // ---- Shared secret: y^x mod p ----
        // Pad x to `bits` precision so pow() iterates for a fixed count
        // regardless of the caller's leading-zero trimming. `my_private`
        // bytes shorter than p.len() are zero-extended by from_be_slice.
        let mut priv_uint = BoxedUint::from_be_slice(my_private, bits)
            .map_err(|e| Error::Key(format!("DH private exponent parse: {e:?}")))?;

        // x in [1, q-1]: both comparisons run in constant time and only the
        // combined validity bit is branched on.
        let x_in_range: Choice = priv_uint.ct_gt(&zero) & priv_uint.ct_lt(&self.q);
        if !bool::from(x_in_range) {
            priv_uint.zeroize();
            return Err(Error::Key(
                "DH private exponent out of range (must be in 1..q-1)".into(),
            ));
        }

        let mut shared_mont = y_mont.pow(&priv_uint);

        // Wipe the heap copy of the private exponent before returning.
        priv_uint.zeroize();

        let mut shared_uint = shared_mont.retrieve();
        shared_mont.zeroize();

        // ---- Output: big-endian, left-padded to p.len() ----
        let mut raw = shared_uint.to_be_bytes();
        shared_uint.zeroize();
        let out = left_pad_to(&raw, self.encoded_len);
        raw.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
thread_local! {
    static PRIME_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Validate a public group parameter with independent, OS-random bases.
/// Variable-time operations are safe here because the candidate is public.
fn require_probable_prime(candidate: &BoxedUint, name: &str) -> Result<()> {
    #[cfg(test)]
    PRIME_CHECKS.with(|count| count.set(count.get() + 1));
    let bits = candidate.bits_precision();
    let two = BoxedUint::from_be_slice(&[2], bits).expect("parameter precision fits 2");
    let three = BoxedUint::from_be_slice(&[3], bits).expect("parameter precision fits 3");
    if candidate == &two || candidate == &three {
        return Ok(());
    }
    let composite = || Error::Key(format!("DH group parameter {name} must be prime"));
    if candidate < &three {
        return Err(composite());
    }
    let odd = Option::<Odd<BoxedUint>>::from(Odd::new(candidate.clone())).ok_or_else(composite)?;
    let test = MillerRabin::new(odd);
    // Sample uniformly in [2, candidate - 2]. Fresh random bases are needed
    // for the 4^-64 bound to hold even for adversarially chosen candidates.
    let range = Option::<NonZero<BoxedUint>>::from(NonZero::new(candidate.wrapping_sub(&three)))
        .expect("odd candidate is at least 5");
    for _ in 0..64 {
        let base = BoxedUint::try_random_mod_vartime(&mut getrandom::SysRng, &range)
            .map_err(|e| Error::Key(format!("DH primality randomness failed: {e}")))?
            .wrapping_add(&two);
        if test.test(&base).is_composite() {
            return Err(composite());
        }
    }
    Ok(())
}

/// Drop leading zero bytes from a public big-endian integer encoding,
/// keeping one byte so zero still parses (and is then range-rejected).
fn strip_leading_zeros(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(input.len().saturating_sub(1));
    &input[start..]
}

/// Left-pad `input` with leading zero bytes until its length equals
/// `target_len`. Returns `input` unchanged if it is already long
/// enough; truncates leading zeros if longer (only possible when the
/// Montgomery form's limb rounding produced extra high bytes, all of
/// which must be zero because `shared < p`).
fn left_pad_to(input: &[u8], target_len: usize) -> Vec<u8> {
    if input.len() == target_len {
        return input.to_vec();
    }
    if input.len() < target_len {
        let mut out = vec![0u8; target_len - input.len()];
        out.extend_from_slice(input);
        return out;
    }
    // input longer than p.len(): trim leading bytes. These are
    // expected to be zero because shared < p.
    input[input.len() - target_len..].to_vec()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // RFC 5114 section 2.2 (id-dhpublicnumber group "2048-bit MODP
    // Group with 224-bit Prime Order Subgroup") — the group used by
    // bergshamra's test fixtures. Inlined in hex for test isolation.
    const RFC5114_GROUP2_P: &str = "\
AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141D\
F95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212\
9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C\
8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330\
278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E1\
98C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763\
C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE\
0C10E64F";
    const RFC5114_GROUP2_G: &str = "\
AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E\
10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7\
C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54\
DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EF\
BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4\
770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269\
EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3\
191F2BFA";
    const RFC5114_GROUP2_Q: &str = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

    /// Decode fixed public test parameters.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Public RFC parameters shared by tests of the opaque key API.
    pub(crate) fn parameters() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            hex(RFC5114_GROUP2_P),
            hex(RFC5114_GROUP2_G),
            hex(RFC5114_GROUP2_Q),
        )
    }

    /// Reuse a validated production-size group for tests of individual key checks.
    fn group() -> &'static ValidatedDhGroup {
        static GROUP: std::sync::OnceLock<ValidatedDhGroup> = std::sync::OnceLock::new();
        GROUP.get_or_init(|| {
            let (p, _, q) = parameters();
            ValidatedDhGroup::new(&p, Some(&q)).unwrap()
        })
    }

    /// Padded keys preserve output width and reuse validation across cloned handles.
    #[test]
    fn imported_groups_validate_once_and_keep_peer_checks() {
        use crate::{keyagreement::agree_dh, SoftwareKey};
        let (mut p, g, mut q) = parameters();
        p.insert(0, 0);
        q.insert(0, 0);
        let expected = left_pad_to(&g, p.len());
        let private = left_pad_to(&[1], p.len());
        let before = PRIME_CHECKS.with(|count| count.get());
        let key = SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&private), &g).unwrap();
        let parameters = key.dh_parameters().unwrap();
        assert_eq!(parameters.modulus(), p);
        assert_eq!(parameters.subgroup_order(), Some(q.as_slice()));
        assert_eq!(PRIME_CHECKS.with(|count| count.get()), before + 2);
        for handle in [&key, &key.clone()] {
            assert_eq!(agree_dh(&g, handle).unwrap(), expected);
            for peer in [&[0][..], &[1], &p] {
                assert!(agree_dh(peer, handle).is_err());
            }
        }
        assert_eq!(PRIME_CHECKS.with(|count| count.get()), before + 2);
        assert_eq!(compute(&g, &private, &p, Some(&q)).unwrap(), expected);
        assert_eq!(PRIME_CHECKS.with(|count| count.get()), before + 4);
    }

    /// Oversized encodings fail before primality checks through every group entry point.
    #[test]
    fn rejects_oversized_modulus_encodings_before_primality() {
        let (p, g, q) = parameters();
        let padded = left_pad_to(&p, MAX_P_ENCODED_LEN + 1);
        let before = PRIME_CHECKS.with(|count| count.get());
        for modulus in [
            padded,
            vec![0; MAX_P_ENCODED_LEN + 1],
            vec![0xff; MAX_P_ENCODED_LEN + 1],
        ] {
            for result in [
                compute(&g, &[1], &modulus, Some(&q)).map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(&modulus, &g, Some(&q), Some(&[1]), &g)
                    .map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(&modulus, &g, Some(&q), None, &g)
                    .map(|_| ()),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("modulus encoding exceeds 1025 bytes"),
                    "{error}"
                );
                assert_eq!(PRIME_CHECKS.with(|count| count.get()), before);
            }
        }
    }

    /// The encoding cap is inclusive, but padding at the cap cannot satisfy size floors.
    #[test]
    fn modulus_encoding_limit_preserves_significant_size_checks() {
        let before = PRIME_CHECKS.with(|count| count.get());
        for value in [0, 23] {
            let p = left_pad_to(&[value], MAX_P_ENCODED_LEN);
            for result in [
                compute(&[4], &[1], &p, Some(&[11])).map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(&p, &[4], Some(&[11]), Some(&[1]), &[4])
                    .map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(&p, &[4], Some(&[11]), None, &[4])
                    .map(|_| ()),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("DH parameter p has"), "{error}");
                assert!(error.contains("requires at least"), "{error}");
                assert_eq!(PRIME_CHECKS.with(|count| count.get()), before);
            }
        }
    }

    /// Both public entry points reject valid but undersized groups even with padding.
    #[test]
    fn small_prime_groups_are_rejected() {
        for padding in [0, 256] {
            let mut p = vec![0; padding];
            p.push(23);
            let mut q = vec![0; padding];
            q.push(11);
            for result in [
                compute(&[4], &[1], &p, Some(&q)).map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(&p, &[4], Some(&q), Some(&[1]), &[4])
                    .map(|_| ()),
            ] {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("requires at least"));
            }
        }
    }

    /// Each parameter has its own significant-bit floor, unaffected by padding.
    #[test]
    fn rejects_parameters_one_bit_below_each_minimum() {
        let (p, g, q) = parameters();
        for (name, minimum) in [("p", MIN_P_BITS), ("q", MIN_Q_BITS)] {
            let mut short = vec![0xff; (minimum / 8) as usize];
            short[0] = 0x7f;
            short.insert(0, 0);
            let (p, q) = if name == "p" {
                (&short, &q)
            } else {
                (&p, &short)
            };
            for result in [
                compute(&g, &[1], p, Some(q)).map(|_| ()),
                crate::SoftwareKey::from_dh_parameters(p, &g, Some(q), None, &g).map(|_| ()),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(&format!("parameter {name}")), "{error}");
                assert!(
                    error.contains(&format!("requires at least {minimum} bits")),
                    "{error}"
                );
            }
        }
    }

    /// RFC 5114 group 1 remains available only through the explicit legacy feature.
    #[test]
    fn legacy_group_requires_legacy_feature() {
        let p = hex(concat!(
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616",
            "073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACC",
            "BDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151A",
            "F5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
        ));
        let g = hex(concat!(
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D3126",
            "6FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7F",
            "BD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662",
            "A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
        ));
        let q = hex("F518AA8781A8DF278ABA4E7D64B7CB9D49462353");
        let raw = compute(&g, &[1], &p, Some(&q));
        let imported = crate::SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&[1]), &g);
        if cfg!(feature = "legacy") {
            assert_eq!(raw.unwrap(), g);
            assert_eq!(
                crate::keyagreement::agree_dh(&g, &imported.unwrap()).unwrap(),
                g
            );
        } else {
            assert!(raw
                .unwrap_err()
                .to_string()
                .contains("requires at least 2048 bits"));
            assert!(imported
                .unwrap_err()
                .to_string()
                .contains("requires at least 2048 bits"));
        }
    }

    /// Import checks every component after real group validation succeeds.
    #[test]
    fn imported_groups_validate_every_key_component() {
        use crate::SoftwareKey;
        let (p, g, q) = parameters();
        let mut minus_one = p.clone();
        *minus_one.last_mut().unwrap() -= 1;
        for padded in [false, true] {
            let encode = |v: &[u8]| {
                let mut out = if padded { vec![0] } else { vec![] };
                out.extend_from_slice(v);
                out
            };
            for invalid in [&[0][..], &[1], &minus_one, &p] {
                assert!(group().validate_key(&encode(invalid), &g, None).is_err());
                assert!(group().validate_key(&g, &encode(invalid), None).is_err());
            }
            assert!(group().validate_key(&g, &encode(&g), Some(&[2])).is_err());
            assert!(group()
                .validate_key(&encode(&g), &encode(&g), Some(&[1]))
                .is_ok());
            assert!(group().validate_key(&encode(&g), &encode(&g), None).is_ok());
        }
        // Public import must retain the same checks, not just group validation.
        assert!(SoftwareKey::from_dh_parameters(&p, &[1], Some(&q), None, &g).is_err());
        assert!(SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&[2]), &g).is_err());
        assert!(SoftwareKey::from_dh_parameters(&p, &g, Some(&q), Some(&[0]), &g).is_err());
        assert!(SoftwareKey::from_dh_parameters(&p, &g, Some(&q), None, &g).is_ok());
    }

    /// Primality checks reject composite candidates independently of the size floor.
    #[test]
    fn rejects_composite_group_parameters() {
        for (value, name) in [(15u8, "q"), (91, "p")] {
            for bytes in [vec![value], vec![0, value]] {
                let candidate = BoxedUint::from_be_slice(&bytes, 64).unwrap();
                let error = require_probable_prime(&candidate, name).unwrap_err();
                assert!(error
                    .to_string()
                    .contains(&format!("parameter {name} must be prime")));
            }
        }
        // Doubling the real q preserves q | p-1 and meets both size floors,
        // but must still fail prime-order validation, including in legacy.
        let (p, g, q) = parameters();
        let mut doubled = vec![0];
        doubled.extend_from_slice(&q);
        let mut carry = 0;
        for byte in doubled.iter_mut().rev() {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
        let error = compute(&g, &[1], &p, Some(&doubled)).unwrap_err();
        assert!(
            error.to_string().contains("parameter q must be prime"),
            "{error}"
        );
    }

    /// The production-size fixture still performs a full two-party agreement.
    #[test]
    fn rfc5114_group2_roundtrip() {
        let (p, g, q) = parameters();
        let y_a = compute(&g, &[0x11], &p, Some(&q)).unwrap();
        let y_b = compute(&g, &[0x23], &p, Some(&q)).unwrap();
        let shared_a = compute(&y_b, &[0x11], &p, Some(&q)).unwrap();
        let shared_b = compute(&y_a, &[0x23], &p, Some(&q)).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), p.len());
    }

    /// Zero, identity and out-of-range peers remain rejected in validated groups.
    #[test]
    fn rejects_out_of_range_peers() {
        let (p, _, _) = parameters();
        for peer in [&[0][..], &[1], &p] {
            let error = group().agree(peer, &[1]).unwrap_err();
            assert!(error.to_string().contains("out of range"), "{error}");
        }
    }

    /// An order-two peer does not belong to the validated odd-prime subgroup.
    #[test]
    fn rejects_bad_subgroup_point() {
        let (mut peer, _, _) = parameters();
        *peer.last_mut().unwrap() -= 1;
        let error = group().agree(&peer, &[1]).unwrap_err();
        assert!(error.to_string().contains("subgroup check"), "{error}");
    }

    /// Group relationships are checked even when both integer sizes suffice.
    #[test]
    fn rejects_invalid_group_parameters() {
        let (p, g, mut q) = parameters();
        let error = compute(&g, &[1], &p, Some(&p)).unwrap_err();
        assert!(error.to_string().contains("q out of range"), "{error}");
        *q.last_mut().unwrap() -= 2;
        let error = compute(&g, &[1], &p, Some(&q)).unwrap_err();
        assert!(error.to_string().contains("does not divide"), "{error}");
    }

    /// The subgroup order remains mandatory; zero cannot satisfy its size floor.
    #[test]
    fn rejects_missing_and_zero_q() {
        let (p, g, _) = parameters();
        let error = compute(&g, &[1], &p, None).unwrap_err();
        assert!(
            error.to_string().contains("subgroup order q is required"),
            "{error}"
        );
        let error = compute(&g, &[1], &p, Some(&[0])).unwrap_err();
        assert!(
            error.to_string().contains("parameter q has 0 bits"),
            "{error}"
        );
    }

    /// Neither zero nor q is a valid private exponent, regardless of padding.
    #[test]
    fn rejects_private_exponent_out_of_range() {
        let (_, g, q) = parameters();
        for private in [&[0][..], &q] {
            let error = group().agree(&g, private).unwrap_err();
            assert!(
                error.to_string().contains("private exponent out of range"),
                "{error}"
            );
        }
    }

    /// DER-style leading zeros preserve peer values and output encoding width.
    #[test]
    fn accepts_peer_public_with_leading_zero_byte() {
        let (_, g, _) = parameters();
        let mut padded = vec![0];
        padded.extend_from_slice(&g);
        assert_eq!(group().agree(&padded, &[1]).unwrap(), g);
    }

    /// Even moduli fail before Montgomery arithmetic when their size is sufficient.
    #[test]
    fn rejects_even_modulus() {
        let (mut p, g, q) = parameters();
        *p.last_mut().unwrap() -= 1;
        let error = compute(&g, &[1], &p, Some(&q)).unwrap_err();
        assert!(error.to_string().contains("must be odd"), "{error}");
    }

    /// Empty and unit moduli are rejected before any agreement takes place.
    #[test]
    fn rejects_empty_and_unit_modulus() {
        for p in [&[][..], &[1]] {
            assert!(compute(&[2], &[1], p, Some(&[2])).is_err());
        }
    }

    /// Private encodings cannot exceed the retained modulus width.
    #[test]
    fn rejects_private_longer_than_modulus() {
        let (p, g, _) = parameters();
        let error = group().agree(&g, &vec![0; p.len() + 1]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("private exponent longer than modulus"),
            "{error}"
        );
    }

    /// Shared-secret encodings retain leading zeros to the full modulus width.
    #[test]
    fn output_is_left_padded_to_p_length() {
        let (p, g, _) = parameters();
        let secret = group().agree(&g, &[1]).unwrap();
        assert_eq!(secret, g);
        assert_eq!(secret.len(), p.len());
        assert_eq!(left_pad_to(&[4], p.len()).last(), Some(&4));
        assert!(left_pad_to(&[4], p.len())[..p.len() - 1]
            .iter()
            .all(|b| *b == 0));
    }
}
