// SPDX-License-Identifier: Apache-2.0

//! Small pure helpers shared by detectors.

use std::collections::HashMap;

/// Shannon entropy (bits per byte) of a string. Empty -> 0.0.
pub(crate) fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u8, usize> = HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.values() {
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

/// Luhn checksum validity over the digits found in `s`. Requires 13–19 digits.
pub(crate) fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut x = d;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_random_is_high() {
        // 16 distinct hex-ish chars -> ~4 bits/byte
        assert!(shannon_entropy("0123456789abcdef") > 3.5);
    }

    #[test]
    fn luhn_accepts_valid_card() {
        assert!(luhn_valid("4242 4242 4242 4242"));
    }

    #[test]
    fn luhn_rejects_invalid_and_short() {
        assert!(!luhn_valid("4242 4242 4242 4241"));
        assert!(!luhn_valid("1234"));
    }
}
