//! Provider-independent ECDSA encoding and scalar validation.
use crate::algorithm::EcCurve;
use crate::error::{Error, Result};

/// Exact-width inputs are raw; other lengths may contain canonical DER.
/// Structural DER success commits to DER even if its scalars are invalid.
pub(crate) fn normalize(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let field = curve_field_len(curve);
    if input.len() != field * 2 && input.first() == Some(&0x30) {
        if let Ok((r, s)) = parse_der(input) {
            let raw = der_components_to_raw(field, r, s)?;
            validate_scalars(curve, &raw)?;
            return Ok(raw);
        }
    }
    if input.len() < 2 || !input.len().is_multiple_of(2) {
        return Err(Error::Crypto("invalid ECDSA raw signature length".into()));
    }
    let half = input.len() / 2;
    let mut raw = vec![0; field * 2];
    copy_raw_component(&input[..half], &mut raw[..field], "ECDSA")?;
    copy_raw_component(&input[half..], &mut raw[field..], "ECDSA")?;
    validate_scalars(curve, &raw)?;
    Ok(raw)
}

pub(crate) fn to_der(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let raw = normalize(curve, input)?;
    let field = curve_field_len(curve);
    let mut content = der_integer(&raw[..field]);
    content.extend(der_integer(&raw[field..]));
    let mut output = vec![0x30];
    output.extend(der_length(content.len()));
    output.extend(content);
    Ok(output)
}

pub(crate) fn from_der(curve: EcCurve, input: &[u8]) -> Result<Vec<u8>> {
    let (r, s) = parse_der(input)?;
    let raw = der_components_to_raw(curve_field_len(curve), r, s)?;
    validate_scalars(curve, &raw)?;
    Ok(raw)
}

/// Signature scalars are public: bytewise range comparisons need not be constant-time.
fn validate_scalars(curve: EcCurve, raw: &[u8]) -> Result<()> {
    let order = curve_order(curve);
    for scalar in raw.chunks_exact(order.len()) {
        if scalar.iter().all(|byte| *byte == 0) || scalar >= order {
            return Err(Error::Crypto(
                "invalid ECDSA signature scalar (must satisfy 1 <= scalar < curve order)".into(),
            ));
        }
    }
    Ok(())
}

/// SEC 2 / NIST prime-curve subgroup orders, encoded at the curve's raw width.
fn curve_order(curve: EcCurve) -> &'static [u8] {
    match curve {
        EcCurve::P256 => &[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ],
        EcCurve::P384 => &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
            0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
            0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
        ],
        EcCurve::P521 => &[
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b,
            0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
            0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
        ],
    }
}

fn parse_der(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut cursor = 0;
    expect_tag(der, &mut cursor, 0x30)?;
    let sequence_len = read_length(der, &mut cursor)?;
    if cursor.checked_add(sequence_len) != Some(der.len()) {
        return Err(Error::Crypto("invalid ECDSA DER sequence length".into()));
    }
    let r = read_integer(der, &mut cursor)?;
    let s = read_integer(der, &mut cursor)?;
    if cursor != der.len() {
        return Err(Error::Crypto("trailing ECDSA DER data".into()));
    }
    Ok((r, s))
}

fn der_components_to_raw(field: usize, r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    let mut raw = vec![0u8; field * 2];
    copy_integer(r, &mut raw[..field])?;
    copy_integer(s, &mut raw[field..])?;
    Ok(raw)
}

fn curve_field_len(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        EcCurve::P521 => 66,
    }
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&value[value.len() - 1..], |index| &value[index..]);
    let leading_zero = value[0] & 0x80 != 0;
    let mut output = vec![0x02];
    output.extend_from_slice(&der_length(value.len() + usize::from(leading_zero)));
    if leading_zero {
        output.push(0);
    }
    output.extend_from_slice(value);
    output
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return vec![length as u8];
    }
    let bytes = length.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut output = vec![0x80 | (bytes.len() - start) as u8];
    output.extend_from_slice(&bytes[start..]);
    output
}

fn expect_tag(input: &[u8], cursor: &mut usize, expected: u8) -> Result<()> {
    if input.get(*cursor) != Some(&expected) {
        return Err(Error::Crypto("invalid ECDSA DER tag".into()));
    }
    *cursor += 1;
    Ok(())
}

fn read_length(input: &[u8], cursor: &mut usize) -> Result<usize> {
    let first = *input
        .get(*cursor)
        .ok_or_else(|| Error::Crypto("truncated ECDSA DER length".into()))?;
    *cursor += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || *cursor + count > input.len() {
        return Err(Error::Crypto("invalid ECDSA DER length".into()));
    }
    let mut length = 0usize;
    for byte in &input[*cursor..*cursor + count] {
        length = (length << 8) | *byte as usize;
    }
    // DER (X.690 §8.1.3.3) requires the minimum number of length octets:
    //   * a one-octet long form may only encode values >= 128 (otherwise
    //     the short form must be used);
    //   * a multi-octet long form must not have a leading zero octet
    //     (otherwise fewer octets suffice).
    // Rejecting non-minimal encodings closes a signature-malleability
    // surface where two distinct DER byte strings decode to the same r||s.
    if count == 1 && length < 128 {
        return Err(Error::Crypto("non-minimal ECDSA DER length".into()));
    }
    if count > 1 && input[*cursor] == 0 {
        return Err(Error::Crypto("non-minimal ECDSA DER length".into()));
    }
    *cursor += count;
    Ok(length)
}

fn read_integer<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    expect_tag(input, cursor, 0x02)?;
    let length = read_length(input, cursor)?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::Crypto("invalid ECDSA DER integer length".into()))?;
    let value = input
        .get(*cursor..end)
        .ok_or_else(|| Error::Crypto("truncated ECDSA DER integer".into()))?;
    *cursor = end;
    if value.is_empty() || value[0] & 0x80 != 0 {
        return Err(Error::Crypto(
            "invalid negative or empty ECDSA integer".into(),
        ));
    }
    // DER (X.690 §8.3.2) requires the minimum number of content octets. A
    // leading 0x00 is only permitted when the next octet has its high bit
    // set (to keep the integer positive); any other leading zero is
    // non-minimal and yields a second, distinct DER encoding of the same
    // value — a signature-malleability surface for consensus callers.
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(Error::Crypto("non-minimal ECDSA DER integer".into()));
    }
    Ok(value)
}

fn copy_integer(value: &[u8], output: &mut [u8]) -> Result<()> {
    let value = if value.len() > 1 && value[0] == 0 {
        &value[1..]
    } else {
        value
    };
    if value.len() > output.len() {
        return Err(Error::Crypto(
            "ECDSA DER integer exceeds curve width".into(),
        ));
    }
    let offset = output.len() - value.len();
    output[offset..].copy_from_slice(value);
    Ok(())
}

fn copy_raw_component(value: &[u8], output: &mut [u8], name: &str) -> Result<()> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&value[value.len().saturating_sub(1)..], |index| {
            &value[index..]
        });
    if value.len() > output.len() {
        return Err(Error::Crypto(format!(
            "{name} signature component exceeds field width"
        )));
    }
    let offset = output.len() - value.len();
    output[offset..].copy_from_slice(value);
    Ok(())
}
