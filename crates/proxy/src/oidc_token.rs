// SPDX-License-Identifier: Apache-2.0

//! Cryptographic validation for OIDC ID tokens.
//!
//! The caller supplies JWKS fetched from the issuer's already validated
//! discovery document. This module never follows `jku`, `x5u`, or other URLs
//! embedded in an attacker-controlled JWT header.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::tenant_store::OrganizationOidcConnection;

const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWT_HEADER_BYTES: usize = 1024;
const CLOCK_SKEW_SECONDS: u64 = 60;
const SUPPORTED_ID_TOKEN_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The only identity data released after a complete OIDC ID-token
/// verification. An email address or display name is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdToken {
    pub issuer: String,
    pub subject: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: i64,
    iat: i64,
    nonce: String,
    #[serde(default)]
    azp: Option<String>,
}

/// Verify a signed ID token using the selected issuer's JWKS. This fails
/// closed on any ambiguous key, weak/symmetric algorithm, unsupported JOSE
/// header, issuer/audience/nonce mismatch, or invalid time claim.
pub fn verify_id_token(
    id_token: &str,
    jwks: &JwkSet,
    connection: &OrganizationOidcConnection,
    expected_nonce: &str,
) -> anyhow::Result<VerifiedIdToken> {
    if id_token.is_empty() || id_token.len() > MAX_ID_TOKEN_BYTES || expected_nonce.is_empty() {
        bail!("invalid OIDC ID token");
    }
    reject_unsafe_jose_header(id_token)?;
    let header = decode_header(id_token).map_err(|_| anyhow::anyhow!("invalid OIDC ID token"))?;
    if !SUPPORTED_ID_TOKEN_ALGORITHMS.contains(&header.alg) {
        bail!("OIDC ID token uses an unsupported signature algorithm");
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC ID token is missing a key identifier"))?;
    let key = select_verification_key(jwks, kid, header.alg)?;
    let decoding_key =
        DecodingKey::from_jwk(key).map_err(|_| anyhow::anyhow!("invalid OIDC verification key"))?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.validate_nbf = true;
    validation.set_issuer(&[&connection.issuer]);
    validation.set_audience(&[&connection.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| anyhow::anyhow!("OIDC ID token verification failed"))?
        .claims;

    validate_claims(&claims, connection, expected_nonce)?;
    Ok(VerifiedIdToken {
        issuer: claims.iss,
        subject: claims.sub,
    })
}

fn reject_unsafe_jose_header(token: &str) -> anyhow::Result<()> {
    let mut parts = token.split('.');
    let Some(encoded_header) = parts.next() else {
        bail!("invalid OIDC ID token");
    };
    if parts.next().is_none() || parts.next().is_none() || parts.next().is_some() {
        bail!("invalid OIDC ID token");
    }
    let header = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| anyhow::anyhow!("invalid OIDC ID token"))?;
    if header.len() > MAX_JWT_HEADER_BYTES {
        bail!("OIDC ID token header exceeds the size limit");
    }
    let header: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&header).map_err(|_| anyhow::anyhow!("invalid OIDC ID token"))?;
    for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
        if header.contains_key(forbidden) {
            bail!("OIDC ID token has an unsupported JOSE header");
        }
    }
    if header.get("b64").is_some_and(|value| value == false) {
        bail!("OIDC ID token has an unsupported JOSE header");
    }
    Ok(())
}

fn select_verification_key<'a>(
    jwks: &'a JwkSet,
    kid: &str,
    algorithm: Algorithm,
) -> anyhow::Result<&'a Jwk> {
    let matches = jwks
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid))
        .collect::<Vec<_>>();
    let [key] = matches.as_slice() else {
        bail!("OIDC verification key is missing or ambiguous");
    };
    match key.common.public_key_use {
        Some(PublicKeyUse::Signature) | None => {}
        _ => bail!("OIDC verification key is not intended for signatures"),
    }
    if key
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        bail!("OIDC verification key cannot verify signatures");
    }
    if key
        .common
        .key_algorithm
        .is_some_and(|key_algorithm| !jwk_algorithm_matches(key_algorithm, algorithm))
    {
        bail!("OIDC verification key algorithm does not match the token");
    }
    Ok(key)
}

fn jwk_algorithm_matches(key_algorithm: KeyAlgorithm, token_algorithm: Algorithm) -> bool {
    matches!(
        (key_algorithm, token_algorithm),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

fn validate_claims(
    claims: &IdTokenClaims,
    connection: &OrganizationOidcConnection,
    expected_nonce: &str,
) -> anyhow::Result<()> {
    if claims.iss != connection.issuer
        || claims.sub.is_empty()
        || claims.sub.len() > 1024
        || claims.sub.chars().any(char::is_control)
        || claims
            .nonce
            .as_bytes()
            .ct_eq(expected_nonce.as_bytes())
            .unwrap_u8()
            != 1
    {
        bail!("OIDC ID token claims are invalid");
    }
    if has_multiple_audiences(&claims.aud) && claims.azp.is_none() {
        bail!("OIDC ID token with multiple audiences is missing azp");
    }
    if claims
        .azp
        .as_deref()
        .is_some_and(|authorized_party| authorized_party != connection.client_id)
    {
        bail!("OIDC ID token azp does not match the client ID");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let now = i64::try_from(now).context("system clock is out of range")?;
    if claims.exp <= 0 || claims.iat <= 0 || claims.iat > now + CLOCK_SKEW_SECONDS as i64 {
        bail!("OIDC ID token time claims are invalid");
    }
    Ok(())
}

fn has_multiple_audiences(audience: &serde_json::Value) -> bool {
    matches!(audience, serde_json::Value::Array(values) if values.len() > 1)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use serde_json::{json, Value};

    use super::verify_id_token;
    use crate::tenant_store::OrganizationOidcConnection;

    #[derive(Clone, Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        aud: Value,
        exp: i64,
        iat: i64,
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        azp: Option<String>,
    }

    struct Signer {
        encoding_key: EncodingKey,
        jwks: jsonwebtoken::jwk::JwkSet,
    }

    fn connection() -> OrganizationOidcConnection {
        OrganizationOidcConnection {
            organization_id: "org_acme".into(),
            issuer: "https://id.example.test/acme".into(),
            client_id: "firewall-console".into(),
            redirect_uri: "https://console.example.test/auth/oidc/callback".into(),
            active: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn signer() -> Signer {
        // Fixed, test-only RSA material eliminates the need for a runtime key
        // generator in the test dependency graph. It is not a deployment key.
        const PRIVATE_DER_BASE64: &str = "MIIEogIBAAKCAQEAm5e-AU5v7IbFs9KBBoL5LdAACvdEJsIbxxyy2S7Ja8HwkwY0Drlg9Rw6Y1fWpEsebUheEC2FrXALHdaOZL1EYsd3TulmABwsdqrPUzhtqom4GS2bs6a1ovgDNqeg3S3i5vkybMHibwlm-0bQlW7MyPypf1Z3wTnOGnePbpa09AOygEfU1RASCr3EdwcJ0kxpvYWCZbXYDDX7sZq6RCl0XyHEG5NGbAB0fZbbodeUjwZIctL4sjjGBrGiI_J0V_txD5D5DlKYEPpw6sdb7MhloPJPS3-IurUaVv6L8LY6DJ9AoZ_6jHKZrk3EgW7hcM4lxM2xBJdUmJ9KakidorrTDwIDAQABAoIBAFI97ffgzvZV8pBvVzXq6u0VQcCKHKLj_SzM9Zgoy9zCgXglUkTqJd7Jke9K0bC76BRZqSah-UPIsoeODmwfQtN3nY-_fOPYAISlGrthW05GR2I_okpedynyMDimeDgQ9huiYs3r2dVZQe7V6pDiJSqjqrAdM2WWOWPyCIWq8XD85C6jhmrmMRRLnoy0G9QYBvqkrOCv_0ZGFKG8mxn-JCEQuLJLAAANFM2Z0sRe7VkqtAgx21YNTBrZwutQvaWT_kL9D8v9KM3jntms9--SNmLpkF2BLKIiVtUzuv5_BmrUI0cPq8ASkvlaI64Csv3enSjSE1tI-_6z22ZfHuuovBECgYEAzxqDR7QDpZRX_pbTXMt4nQs_hh80J1pk7RaWf_w2OyW3lQ7DlKCeelec6xxtDBHA0aanlANWWiphObXzyf3eDWmI-LTdXqBRNXJfpaavcjvrU4gHVLX7bqB7nW-uhVEPD56_Y20_EXBbchLAupoB-A3czKKG4hGx9soiEATcPVkCgYEAwFPg6BkR852-niMMN14a9zEax3aSmVjpSE8FwjPXAd0VihxPgP9R1LSC_k1fOni0MhXTy2-CgRV2bn8RgqwaY9sJt6rloQ5eqS5ug4Wok9FWNeS6dE1zigC0KbgX720CiZhA5jouG4bmkk-nZaw56Ae_9gcmHO_4iWMEFWslfqcCgYBg1cG6XhYybokyVe1f_xdXPrImESL-n4p_PMeD8jadM0aCYJPcQ7m19I8_c1wdf5OLs4O5dlIC-LvbExN5R8Vyufy8ZTz4iLdP6TmFp8ly_UdMGFdtKWX11P3XoCeW2E7Ve-F7KNKLYeCwFsqctXPkOv8Zg4jT3Xg7r0l7-fnMiQKBgDPlbkaynRlzc0AQjPdTuUsCQQuZfy1JxIjyacdhXZ7vHSTLRti0DEys-LvN_Og2McliAmheioRyWiauuvbbobNYI2MgBh5TVk-oa8Gpizd3wR-BvJ4tWAPg9LxdJHhCnfCq2LhG8rIS0JyiSbUxp95oWO_2Nd6REitgQHXXF6L5AoGAXidGrP2-Yoe13jK-k4dYnWbmn4voljEPxxrQE_ByueLhK2tmad2_Xjo96dV5ALiXDjEpBgL5vtwDUV-je-YdTFwpvUKjs8g-PUgINFMia4S3pFirj_1sktdqjat_66mbbiVVpFld2Gnzew7edTd8aFpl8ct8bYW_HXOGGUreYGI";
        const MODULUS_BASE64: &str = "m5e-AU5v7IbFs9KBBoL5LdAACvdEJsIbxxyy2S7Ja8HwkwY0Drlg9Rw6Y1fWpEsebUheEC2FrXALHdaOZL1EYsd3TulmABwsdqrPUzhtqom4GS2bs6a1ovgDNqeg3S3i5vkybMHibwlm-0bQlW7MyPypf1Z3wTnOGnePbpa09AOygEfU1RASCr3EdwcJ0kxpvYWCZbXYDDX7sZq6RCl0XyHEG5NGbAB0fZbbodeUjwZIctL4sjjGBrGiI_J0V_txD5D5DlKYEPpw6sdb7MhloPJPS3-IurUaVv6L8LY6DJ9AoZ_6jHKZrk3EgW7hcM4lxM2xBJdUmJ9KakidorrTDw";
        let private_der = URL_SAFE_NO_PAD.decode(PRIVATE_DER_BASE64).unwrap();
        let jwks = serde_json::from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "key-1",
                "alg": "RS256",
                "use": "sig",
                "n": MODULUS_BASE64,
                "e": "AQAB",
            }]
        }))
        .unwrap();
        Signer {
            encoding_key: EncodingKey::from_rsa_der(&private_der),
            jwks,
        }
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn claims(audience: Value) -> TestClaims {
        let now = now_unix();
        TestClaims {
            iss: "https://id.example.test/acme".into(),
            sub: "idp-opaque-subject".into(),
            aud: audience,
            exp: now + 300,
            iat: now,
            nonce: "expected-nonce".into(),
            azp: None,
        }
    }

    fn signed_token(signer: &Signer, claims: &TestClaims) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("key-1".into());
        encode(&header, claims, &signer.encoding_key).unwrap()
    }

    pub(crate) fn signed_local_id_token(
        issuer: &str,
        subject: &str,
        audience: &str,
        nonce: &str,
    ) -> (String, Value) {
        let signer = signer();
        let now = now_unix();
        let claims = TestClaims {
            iss: issuer.into(),
            sub: subject.into(),
            aud: json!(audience),
            exp: now + 300,
            iat: now,
            nonce: nonce.into(),
            azp: None,
        };
        let token = signed_token(&signer, &claims);
        let jwks = serde_json::to_value(signer.jwks).unwrap();
        (token, jwks)
    }

    #[test]
    fn verifies_a_signed_asymmetric_id_token_and_releases_only_subject_identity() {
        let connection = connection();
        let signer = signer();
        let token = signed_token(&signer, &claims(json!("firewall-console")));
        assert_eq!(
            verify_id_token(&token, &signer.jwks, &connection, "expected-nonce").unwrap(),
            super::VerifiedIdToken {
                issuer: connection.issuer,
                subject: "idp-opaque-subject".into(),
            }
        );
    }

    #[test]
    fn rejects_nonce_audience_and_authorized_party_mismatches() {
        let connection = connection();
        let signer = signer();
        let wrong_audience = signed_token(&signer, &claims(json!("another-client")));
        assert!(
            verify_id_token(&wrong_audience, &signer.jwks, &connection, "expected-nonce").is_err()
        );

        let token = signed_token(&signer, &claims(json!("firewall-console")));
        assert!(verify_id_token(&token, &signer.jwks, &connection, "other-nonce").is_err());

        let multiple_audiences = claims(json!(["firewall-console", "other-client"]));
        let multiple_audience_token = signed_token(&signer, &multiple_audiences);
        assert!(verify_id_token(
            &multiple_audience_token,
            &signer.jwks,
            &connection,
            "expected-nonce"
        )
        .is_err());

        let mut wrong_azp = claims(json!(["firewall-console", "other-client"]));
        wrong_azp.azp = Some("other-client".into());
        let wrong_azp_token = signed_token(&signer, &wrong_azp);
        assert!(verify_id_token(
            &wrong_azp_token,
            &signer.jwks,
            &connection,
            "expected-nonce"
        )
        .is_err());
    }

    #[test]
    fn rejects_symmetric_algorithms_and_header_supplied_key_locations() {
        let connection = connection();
        let claims = claims(json!("firewall-console"));
        let symmetric_token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"not an OIDC public key"),
        )
        .unwrap();
        let empty_jwks = serde_json::from_value(json!({"keys": []})).unwrap();
        assert!(
            verify_id_token(&symmetric_token, &empty_jwks, &connection, "expected-nonce").is_err()
        );

        let unsafe_header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"key-1","crit":["unhandled"]}"#);
        let unsafe_token = format!("{unsafe_header}.payload.signature");
        assert!(
            verify_id_token(&unsafe_token, &empty_jwks, &connection, "expected-nonce").is_err()
        );
    }

    #[test]
    fn rejects_an_ambiguous_jwks_key_identifier() {
        let connection = connection();
        let signer = signer();
        let token = signed_token(&signer, &claims(json!("firewall-console")));
        let mut ambiguous_jwks = signer.jwks.clone();
        ambiguous_jwks.keys.push(ambiguous_jwks.keys[0].clone());
        assert!(verify_id_token(&token, &ambiguous_jwks, &connection, "expected-nonce").is_err());
    }
}
