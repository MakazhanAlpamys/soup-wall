// SPDX-License-Identifier: Apache-2.0

//! Opt-in interoperability probes against real provider metadata.
//!
//! These tests are ignored by default because they require network access and
//! provider-specific configuration. Run them from an operator-controlled
//! environment with `cargo test -p llm-firewall --test external_identity
//! -- --ignored --nocapture`; no client secret or bearer is accepted by these
//! metadata-only probes.

use std::env;

use base64::{engine::general_purpose::STANDARD, Engine};
use llm_firewall::oidc::OidcHttpClient;
use llm_firewall::saml_auth::validate_idp_metadata;
use llm_firewall::tenant_store::{OrganizationOidcConnection, OrganizationSamlConnection};

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("set {name} for the external identity probe"))
}

#[tokio::test]
#[ignore = "requires an operator-selected real OIDC issuer"]
async fn real_oidc_discovery_and_jwks_are_accepted() -> anyhow::Result<()> {
    let issuer = required("LLM_FW_EXTERNAL_OIDC_ISSUER");
    let connection = OrganizationOidcConnection {
        organization_id: "external-probe".into(),
        issuer: issuer.clone(),
        client_id: env::var("LLM_FW_EXTERNAL_OIDC_CLIENT_ID")
            .unwrap_or_else(|_| "metadata-probe-public-client".into()),
        redirect_uri: env::var("LLM_FW_EXTERNAL_OIDC_REDIRECT_URI")
            .unwrap_or_else(|_| "https://firewall.example.test/auth/oidc/callback".into()),
        active: true,
        created_at_unix: 0,
        updated_at_unix: 0,
    };
    let client = OidcHttpClient::new()?;
    let endpoints = client.fetch_validated_discovery(&connection).await?;
    let jwks = client.fetch_jwks(&endpoints).await?;
    assert!(!jwks.keys.is_empty(), "external OIDC JWKS had no keys");
    println!("OIDC metadata and JWKS accepted for {issuer}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires an operator-selected real SAML metadata URL"]
async fn real_signed_saml_metadata_is_accepted() -> anyhow::Result<()> {
    let metadata_url = required("LLM_FW_EXTERNAL_SAML_METADATA_URL");
    let response = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(&metadata_url)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "SAML metadata request failed"
    );
    let xml = response.text().await?;
    let entity_id = xml
        .split_once("entityID=\"")
        .and_then(|(_, tail)| tail.split_once('\"'))
        .map(|(value, _)| value.to_owned())
        .ok_or_else(|| anyhow::anyhow!("SAML metadata has no entityID"))?;
    let certificate = xml
        .split_once("<ds:X509Certificate>")
        .or_else(|| xml.split_once("<X509Certificate>"))
        .and_then(|(_, tail)| tail.split_once('<'))
        .map(|(value, _)| {
            value
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        })
        .ok_or_else(|| anyhow::anyhow!("SAML metadata has no signing certificate"))?;
    let der = STANDARD.decode(certificate)?;
    let encoded = STANDARD.encode(der);
    let encoded = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
    let connection = OrganizationSamlConnection {
        organization_id: "external-probe".into(),
        entity_id: entity_id.clone(),
        metadata_xml: xml,
        metadata_signing_cert_pem: pem,
        active: true,
        created_at_unix: 0,
        updated_at_unix: 0,
    };
    validate_idp_metadata(&connection)?;
    println!("signed SAML metadata accepted for {entity_id}");
    Ok(())
}
