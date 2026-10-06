//! # ⚠ HAZMAT ⚠
//!
//! This module holds cryptographic primitives that are known to be
//! dangerous when used without a surrounding construction. Everything
//! in here is **unauthenticated** — a ciphertext produced here gives
//! you confidentiality (and not always that) but **no integrity and
//! no authentication**. You cannot safely expose any of these APIs
//! to an attacker-controlled decryption oracle.
//!
//! These primitives exist solely to interoperate with legacy formats
//! (XML Encryption 1.0/1.1, some CMS/PKCS#7 profiles) that predate
//! AEADs. If you are designing a new protocol, use
//! [`crate::cipher`] with an AES-GCM algorithm instead.
//!
//! Common misuse patterns to avoid:
//!
//! * Handing a ciphertext directly to [`aes_cbc::decrypt`] and
//!   returning a distinguishable error to a remote caller — this is
//!   Bleichenbacher/Vaudenay padding-oracle material. Even though
//!   this module collapses its error messages into a single opaque
//!   `"AES-CBC decrypt failed"`, the mere fact that decryption *may*
//!   fail is still an oracle if you return that information to the
//!   attacker.
//! * Using these primitives without first verifying a MAC (or a
//!   signature) over the ciphertext. Always authenticate first,
//!   decrypt second.
//! * Reusing the same key across this module and [`crate::cipher`]
//!   without domain separation.

pub mod aes_cbc;
pub mod dh;
