// SPDX-License-Identifier: Apache-2.0

//! OIDC protocol primitives shared by the browser-login handlers.
//!
//! A caller must first obtain a connection selected by the organization, then
//! use these primitives to fetch and validate its discovery document before
//! starting an authorization-code + PKCE flow. The caller must never select an
//! issuer, redirect URI, or endpoint from browser input.

use std::time::Duration;

use aes_gcm::{
    aead::{Aead, Generate, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::JwkSet;
use rand::{rngs::SysRng, TryRng};
use reqwest::{redirect::Policy, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tenant_store::OrganizationOidcConnection;

pub const CALLBACK_PATH: &str = "/auth/oidc/callback";
const AUTHORIZATION_STATE_AAD: &[u8] = b"llm-firewall/oidc-authorization-state/v1";
const SAML_AUTHORIZATION_STATE_AAD: &[u8] = b"llm-firewall/saml-authorization-state/v1";
const SAML_RELAY_STATE_AAD: &[u8] = b"llm-firewall/saml-relay-state/v1";
const BROWSER_CSRF_KEY_DERIVATION: &[u8] = b"llm-firewall/browser-csrf-key/v1";
const BROWSER_CSRF_AAD: &[u8] = b"llm-firewall/browser-csrf-token/v1";
const AES_GCM_NONCE_BYTES: usize = 12;
const MAX_SEALED_AUTHORIZATION_STATE_BYTES: usize = 4 * 1024;
/// A discovery document should be tiny. This limit prevents a misconfigured
/// provider or hostile network peer from consuming unbounded proxy memory.
pub const MAX_DISCOVERY_DOCUMENT_BYTES: usize = 64 * 1024;
/// JWK sets normally contain a handful of keys. This permits provider key
/// rotation without permitting an unbounded remote response.
pub const MAX_JWKS_DOCUMENT_BYTES: usize = 256 * 1024;
/// The ID token is the only token-response field this proxy consumes. Keep the
/// complete response bounded before JSON parsing so provider extensions cannot
/// allocate unbounded memory.
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_AUTHORIZATION_CODE_BYTES: usize = 8 * 1024;
const OIDC_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OIDC_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// An authorization-code verifier and its mandatory `S256` challenge. Do not
/// serialize, log, or persist `code_verifier` in plaintext.
#[derive(Clone)]
pub struct PkcePair {
    code_verifier: String,
    code_challenge: String,
}

impl PkcePair {
    pub fn generate() -> Self {
        let code_verifier = random_urlsafe_value(32);
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        Self {
            code_verifier,
            code_challenge,
        }
    }

    /// Return the one-time verifier only to the immediate token-exchange
    /// request. Callers must not serialize or log it.
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// Generate a high-entropy URL-safe opaque value for state, nonce, or session
/// identifiers. The byte count must be chosen by the protocol caller.
pub(crate) fn random_urlsafe_value(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    SysRng
        .try_fill_bytes(&mut value)
        .expect("the OS refused to provide entropy");
    URL_SAFE_NO_PAD.encode(value)
}

/// Encrypts the browser-facing OIDC state with a 256-bit key supplied by the
/// deployment's secret manager. Database storage keeps only a hash of the
/// resulting ciphertext, never the state or PKCE verifier itself.
pub struct OidcStateCipher {
    cipher: Aes256Gcm,
    csrf_key: [u8; 32],
}

/// Values that must survive the redirect to the identity provider. It is
/// intentionally not serializable or debuggable; only [`OidcStateCipher`]
/// serializes it inside authenticated encryption.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationState {
    organization_id: String,
    workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invitation_id: Option<String>,
    code_verifier: String,
    nonce: String,
    expires_at_unix: i64,
}

/// Authenticated SAML browser correlation. The pending request fields are
/// sealed together with the selected organization/workspace so the ACS never
/// trusts browser-controlled routing or an IdP-provided relay state.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlAuthorizationState {
    organization_id: String,
    workspace_id: String,
    expires_at_unix: i64,
}

impl OidcStateCipher {
    /// Construct the cipher from exactly 32 random bytes encoded as unpadded
    /// base64url. The source must be an environment-backed secret, never YAML
    /// or a database setting.
    pub fn from_base64url_key(encoded_key: &str) -> anyhow::Result<Self> {
        let key = URL_SAFE_NO_PAD
            .decode(encoded_key)
            .context("OIDC state encryption key is not valid base64url")?;
        if key.len() != 32 {
            bail!("OIDC state encryption key must decode to exactly 32 bytes");
        }
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("invalid OIDC state encryption key"))?;
        let mut derivation = Sha256::new();
        derivation.update(BROWSER_CSRF_KEY_DERIVATION);
        derivation.update(&key);
        let csrf_key = derivation.finalize().into();
        Ok(Self { cipher, csrf_key })
    }

    /// Seal one authorization state. A fresh AES-GCM nonce makes every state
    /// unique even if its input values match another attempt.
    pub fn seal_authorization_state(
        &self,
        organization_id: &str,
        workspace_id: &str,
        pkce: &PkcePair,
        nonce: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<String> {
        self.seal_authorization_state_with_invitation(
            organization_id,
            workspace_id,
            None,
            pkce,
            nonce,
            expires_at_unix,
        )
    }

    /// Seal an OIDC state for invitation enrollment. Only the opaque
    /// invitation ID is carried; the raw bearer never leaves the acceptance
    /// page for the identity provider and is not retained in browser state.
    pub fn seal_authorization_state_with_invitation(
        &self,
        organization_id: &str,
        workspace_id: &str,
        invitation_id: Option<&str>,
        pkce: &PkcePair,
        nonce: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<String> {
        let state = AuthorizationState {
            organization_id: validate_state_component(organization_id, "OIDC organization", 256)?,
            workspace_id: validate_state_component(workspace_id, "OIDC workspace", 256)?,
            invitation_id: invitation_id
                .map(|value| validate_state_component(value, "workspace invitation", 256))
                .transpose()?,
            code_verifier: pkce.code_verifier().to_owned(),
            nonce: validate_state_component(nonce, "OIDC nonce", 256)?,
            expires_at_unix,
        };
        let plaintext =
            serde_json::to_vec(&state).context("failed to encode OIDC authorization state")?;
        let nonce = Nonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: AUTHORIZATION_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt OIDC authorization state"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// Authenticate and decrypt a browser-returned state. Any malformed,
    /// modified, or key-mismatched value returns an opaque error.
    pub fn open_authorization_state(&self, sealed: &str) -> anyhow::Result<AuthorizationState> {
        if sealed.is_empty() || sealed.len() > MAX_SEALED_AUTHORIZATION_STATE_BYTES {
            bail!("invalid OIDC authorization state");
        }
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| anyhow::anyhow!("invalid OIDC authorization state"))?;
        if sealed.len() <= AES_GCM_NONCE_BYTES {
            bail!("invalid OIDC authorization state");
        }
        let (nonce, ciphertext) = sealed.split_at(AES_GCM_NONCE_BYTES);
        let nonce = Nonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("invalid OIDC authorization state"))?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: AUTHORIZATION_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid OIDC authorization state"))?;
        serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("invalid OIDC authorization state"))
    }

    pub fn seal_saml_authorization_state(
        &self,
        organization_id: &str,
        workspace_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<String> {
        let state = SamlAuthorizationState {
            organization_id: validate_state_component(organization_id, "SAML organization", 256)?,
            workspace_id: validate_state_component(workspace_id, "SAML workspace", 256)?,
            expires_at_unix,
        };
        let plaintext =
            serde_json::to_vec(&state).context("failed to encode SAML authorization state")?;
        let nonce = Nonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: SAML_AUTHORIZATION_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt SAML authorization state"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    pub fn open_saml_authorization_state(
        &self,
        sealed: &str,
    ) -> anyhow::Result<SamlAuthorizationState> {
        if sealed.is_empty() || sealed.len() > MAX_SEALED_AUTHORIZATION_STATE_BYTES {
            bail!("invalid SAML authorization state");
        }
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| anyhow::anyhow!("invalid SAML authorization state"))?;
        if sealed.len() <= AES_GCM_NONCE_BYTES {
            bail!("invalid SAML authorization state");
        }
        let (nonce, ciphertext) = sealed.split_at(AES_GCM_NONCE_BYTES);
        let nonce = Nonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("invalid SAML authorization state"))?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: SAML_AUTHORIZATION_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid SAML authorization state"))?;
        serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("invalid SAML authorization state"))
    }

    /// Seal a compact, authenticated SAML RelayState. SAML HTTP bindings cap
    /// RelayState at 80 bytes, so the durable pending-state row carries the
    /// organization/workspace binding while this value provides an opaque,
    /// key-bound browser correlation that fits the protocol limit.
    pub fn seal_saml_relay_state(&self) -> anyhow::Result<String> {
        let mut marker = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut marker)
            .expect("the OS refused to provide entropy");
        let nonce = Nonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &marker,
                    aad: SAML_RELAY_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt SAML RelayState"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// Verify a compact RelayState without exposing its random marker. The
    /// pending database row remains the source of organization/workspace
    /// routing and one-time consumption.
    pub fn open_saml_relay_state(&self, sealed: &str) -> anyhow::Result<()> {
        if sealed.is_empty() || sealed.len() > 80 {
            bail!("invalid SAML RelayState");
        }
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| anyhow::anyhow!("invalid SAML RelayState"))?;
        if sealed.len() != AES_GCM_NONCE_BYTES + 16 + 16 {
            bail!("invalid SAML RelayState");
        }
        let (nonce, ciphertext) = sealed.split_at(AES_GCM_NONCE_BYTES);
        let nonce =
            Nonce::try_from(nonce).map_err(|_| anyhow::anyhow!("invalid SAML RelayState"))?;
        let marker = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: SAML_RELAY_STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid SAML RelayState"))?;
        if marker.len() != 16 {
            bail!("invalid SAML RelayState");
        }
        Ok(())
    }

    /// Derive a same-origin CSRF proof from the opaque session bearer. The
    /// browser can request this proof only after presenting its HttpOnly
    /// session cookie; the bearer itself never enters JavaScript.
    pub fn browser_csrf_token(&self, session_token: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.csrf_key)
            .expect("a SHA-256 key has a valid HMAC length");
        mac.update(BROWSER_CSRF_AAD);
        mac.update(session_token.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verify a browser-supplied CSRF proof in constant time. The expected
    /// proof uses a domain-separated key, rather than reusing the AES-GCM key
    /// directly for a second cryptographic purpose.
    pub fn verifies_browser_csrf_token(&self, session_token: &str, presented: &str) -> bool {
        if presented.is_empty() || presented.len() > 128 {
            return false;
        }
        let Ok(presented) = URL_SAFE_NO_PAD.decode(presented) else {
            return false;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.csrf_key)
            .expect("a SHA-256 key has a valid HMAC length");
        mac.update(BROWSER_CSRF_AAD);
        mac.update(session_token.as_bytes());
        mac.verify_slice(&presented).is_ok()
    }
}

impl AuthorizationState {
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// The exact organization workspace selected before the browser redirect.
    /// The callback must authorize the verified identity against this value; it
    /// must never infer a workspace from an IdP claim or browser input.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub fn invitation_id(&self) -> Option<&str> {
        self.invitation_id.as_deref()
    }

    /// Return the verifier only for the direct server-to-server token exchange.
    /// It must not be logged or placed in a browser cookie.
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

impl SamlAuthorizationState {
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

/// OpenID Provider Metadata fields used by this product. Unknown provider
/// metadata is deliberately ignored so conforming providers can publish their
/// own optional extensions.
#[derive(Clone, Debug, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

/// Validated endpoints from an exact, organization-selected OIDC issuer.
#[derive(Clone, Debug)]
pub struct ValidatedEndpoints {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
}

/// The narrowly scoped portion of an authorization-code token response used
/// by this proxy. Access and refresh tokens are deliberately neither exposed
/// nor retained by the browser-session path.
#[derive(Deserialize)]
pub struct OidcTokenResponse {
    id_token: String,
}

impl OidcTokenResponse {
    pub fn id_token(&self) -> &str {
        &self.id_token
    }
}

/// Purpose-built HTTP client for OIDC provider metadata. It has no ambient
/// proxy defaults: redirects are refused, HTTPS is mandatory, and both time
/// and response size are bounded before metadata is parsed.
#[derive(Clone)]
pub struct OidcHttpClient {
    client: reqwest::Client,
    #[cfg(test)]
    validated_endpoints_override: Option<ValidatedEndpoints>,
}

impl OidcHttpClient {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(OIDC_HTTP_CONNECT_TIMEOUT)
            .timeout(OIDC_HTTP_REQUEST_TIMEOUT)
            .user_agent("soup-wall-oidc/1")
            .build()
            .context("failed to build OIDC HTTP client")?;
        Ok(Self {
            client,
            #[cfg(test)]
            validated_endpoints_override: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_local_test_provider(endpoints: ValidatedEndpoints) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(OIDC_HTTP_CONNECT_TIMEOUT)
            .timeout(OIDC_HTTP_REQUEST_TIMEOUT)
            .user_agent("llm-firewall-oidc-test/1")
            .build()
            .context("failed to build local OIDC test client")?;
        Ok(Self {
            client,
            validated_endpoints_override: Some(endpoints),
        })
    }

    /// Fetch and validate metadata only from the exact issuer recorded for
    /// this organization. The metadata endpoints remain data until
    /// [`DiscoveryDocument::validate_for_connection`] has accepted them.
    pub async fn fetch_validated_discovery(
        &self,
        connection: &OrganizationOidcConnection,
    ) -> anyhow::Result<ValidatedEndpoints> {
        #[cfg(test)]
        if let Some(endpoints) = &self.validated_endpoints_override {
            return Ok(endpoints.clone());
        }

        let url = discovery_url(&connection.issuer)?;
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("OIDC discovery request failed")?;
        ensure_success_response_size(
            &response,
            MAX_DISCOVERY_DOCUMENT_BYTES,
            "OIDC discovery response",
        )?;

        let body = read_bounded_response(
            response,
            MAX_DISCOVERY_DOCUMENT_BYTES,
            "OIDC discovery response",
        )
        .await?;
        parse_and_validate_discovery(&body, connection)
    }

    /// Fetch the current key set only from the JWKS endpoint validated from
    /// the selected issuer's discovery document. Redirects remain disabled on
    /// this dedicated client.
    pub async fn fetch_jwks(&self, endpoints: &ValidatedEndpoints) -> anyhow::Result<JwkSet> {
        let response = self
            .client
            .get(endpoints.jwks_uri.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("OIDC JWKS request failed")?;
        ensure_success_response_size(&response, MAX_JWKS_DOCUMENT_BYTES, "OIDC JWKS response")?;
        let body =
            read_bounded_response(response, MAX_JWKS_DOCUMENT_BYTES, "OIDC JWKS response").await?;
        parse_jwks(&body)
    }

    /// Exchange one authorization code at an already validated token endpoint
    /// using PKCE. This public-client flow never sends a browser-provided
    /// secret, never follows redirects, and returns only the ID token needed
    /// for the subsequent cryptographic verification step.
    pub async fn exchange_authorization_code(
        &self,
        endpoints: &ValidatedEndpoints,
        connection: &OrganizationOidcConnection,
        code: &str,
        code_verifier: &str,
    ) -> anyhow::Result<OidcTokenResponse> {
        validate_token_exchange_component(
            code,
            "OIDC authorization code",
            MAX_AUTHORIZATION_CODE_BYTES,
        )?;
        validate_token_exchange_component(code_verifier, "OIDC PKCE verifier", 256)?;
        let response = self
            .client
            .post(endpoints.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", connection.redirect_uri.as_str()),
                ("client_id", connection.client_id.as_str()),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .context("OIDC token request failed")?;
        ensure_success_response_size(&response, MAX_TOKEN_RESPONSE_BYTES, "OIDC token response")?;
        let body = read_bounded_response(response, MAX_TOKEN_RESPONSE_BYTES, "OIDC token response")
            .await?;
        parse_token_response(&body)
    }
}

/// Construct the OpenID Connect Discovery URL according to OIDC Discovery
/// section 4.1: remove a terminating slash and append
/// `/.well-known/openid-configuration` after the issuer path. This differs from
/// the OAuth authorization-server metadata path construction in RFC 8414.
pub fn discovery_url(issuer: &str) -> anyhow::Result<Url> {
    let mut url = parse_https_uri(issuer, "OIDC issuer", false)?;
    let discovery_path = format!(
        "{}/.well-known/openid-configuration",
        url.path().trim_end_matches('/')
    );
    url.set_path(&discovery_path);
    Ok(url)
}

impl DiscoveryDocument {
    /// Fail closed unless discovery metadata belongs to the stored exact issuer
    /// and explicitly supports authorization-code plus PKCE S256. Endpoint
    /// URLs are parsed before any later HTTP fetch; redirects must remain
    /// disabled in the future OIDC HTTP client.
    pub fn validate_for_connection(
        &self,
        connection: &OrganizationOidcConnection,
    ) -> anyhow::Result<ValidatedEndpoints> {
        if !connection.active {
            bail!("OIDC connection is inactive");
        }
        if self.issuer != connection.issuer {
            bail!("OIDC discovery issuer does not exactly match the organization connection");
        }
        if !self
            .response_types_supported
            .iter()
            .any(|response_type| response_type == "code")
        {
            bail!("OIDC provider does not advertise authorization-code response support");
        }
        if !self.grant_types_supported.is_empty()
            && !self
                .grant_types_supported
                .iter()
                .any(|grant_type| grant_type == "authorization_code")
        {
            bail!("OIDC provider does not advertise authorization-code grant support");
        }
        if !self
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256")
        {
            bail!("OIDC provider does not advertise PKCE S256 support");
        }

        Ok(ValidatedEndpoints {
            authorization_endpoint: parse_https_uri(
                &self.authorization_endpoint,
                "OIDC authorization endpoint",
                true,
            )?,
            token_endpoint: parse_https_uri(&self.token_endpoint, "OIDC token endpoint", true)?,
            jwks_uri: parse_https_uri(&self.jwks_uri, "OIDC JWKS URI", true)?,
        })
    }
}

fn parse_and_validate_discovery(
    body: &[u8],
    connection: &OrganizationOidcConnection,
) -> anyhow::Result<ValidatedEndpoints> {
    let document: DiscoveryDocument =
        serde_json::from_slice(body).context("OIDC discovery document is not valid JSON")?;
    document.validate_for_connection(connection)
}

fn parse_jwks(body: &[u8]) -> anyhow::Result<JwkSet> {
    let jwks: JwkSet =
        serde_json::from_slice(body).context("OIDC JWKS response is not valid JSON")?;
    if jwks.keys.is_empty() {
        bail!("OIDC JWKS response contains no keys");
    }
    Ok(jwks)
}

fn parse_token_response(body: &[u8]) -> anyhow::Result<OidcTokenResponse> {
    let response: OidcTokenResponse =
        serde_json::from_slice(body).context("OIDC token response is not valid JSON")?;
    if response.id_token.is_empty() {
        bail!("OIDC token response has no ID token");
    }
    Ok(response)
}

fn ensure_success_response_size(
    response: &reqwest::Response,
    max_bytes: usize,
    description: &str,
) -> anyhow::Result<()> {
    if !response.status().is_success() {
        bail!("{description} returned a non-success status");
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("{description} exceeds the size limit");
    }
    Ok(())
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_bytes: usize,
    description: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("failed to read {description}"))?;
        append_bounded_chunk(&mut body, &chunk, max_bytes, description)?;
    }
    Ok(body)
}

fn append_bounded_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
    description: &str,
) -> anyhow::Result<()> {
    if chunk.len() > max_bytes.saturating_sub(body.len()) {
        bail!("{description} exceeds the size limit");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn parse_https_uri(value: &str, field: &str, query_allowed: bool) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| format!("{field} must be an absolute URI"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (!query_allowed && url.query().is_some())
        || url.fragment().is_some()
    {
        bail!("{field} must be an HTTPS URI without credentials or a fragment");
    }
    Ok(url)
}

fn validate_state_component(value: &str, field: &str, max_bytes: usize) -> anyhow::Result<String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        bail!("{field} is invalid");
    }
    Ok(value.to_owned())
}

fn validate_token_exchange_component(
    value: &str,
    field: &str,
    max_bytes: usize,
) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        bail!("{field} is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        append_bounded_chunk, discovery_url, parse_and_validate_discovery, parse_jwks,
        parse_token_response, random_urlsafe_value, validate_token_exchange_component,
        DiscoveryDocument, OidcHttpClient, OidcStateCipher, PkcePair, ValidatedEndpoints,
        MAX_DISCOVERY_DOCUMENT_BYTES, MAX_SEALED_AUTHORIZATION_STATE_BYTES,
    };
    use crate::tenant_store::OrganizationOidcConnection;

    fn connection() -> OrganizationOidcConnection {
        OrganizationOidcConnection {
            organization_id: "org_test".into(),
            issuer: "https://id.example.test/realms/acme".into(),
            client_id: "firewall-console".into(),
            redirect_uri: "https://console.example.test/auth/oidc/callback".into(),
            active: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn discovery() -> DiscoveryDocument {
        DiscoveryDocument {
            issuer: "https://id.example.test/realms/acme".into(),
            authorization_endpoint: "https://id.example.test/authorize".into(),
            token_endpoint: "https://id.example.test/token".into(),
            jwks_uri: "https://id.example.test/keys".into(),
            response_types_supported: vec!["code".into()],
            grant_types_supported: vec!["authorization_code".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    #[test]
    fn discovery_url_appends_well_known_to_the_oidc_issuer_path() {
        // OIDC Discovery 1.0 section 4.1, including Keycloak's realm endpoint.
        for (issuer, expected) in [
            (
                "https://id.example.test",
                "https://id.example.test/.well-known/openid-configuration",
            ),
            (
                "https://id.example.test/",
                "https://id.example.test/.well-known/openid-configuration",
            ),
            (
                "https://id.example.test/realms/acme",
                "https://id.example.test/realms/acme/.well-known/openid-configuration",
            ),
            (
                "https://id.example.test/auth/realms/acme/",
                "https://id.example.test/auth/realms/acme/.well-known/openid-configuration",
            ),
        ] {
            assert_eq!(discovery_url(issuer).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn discovery_url_preserves_ports_and_encoded_path_components() {
        for (issuer, expected) in [
            (
                "https://id.example.test:8443/realms/acme%2Fdivision%20one/",
                "https://id.example.test:8443/realms/acme%2Fdivision%20one/.well-known/openid-configuration",
            ),
            (
                "https://[::1]:8443/realms/acme",
                "https://[::1]:8443/realms/acme/.well-known/openid-configuration",
            ),
        ] {
            assert_eq!(discovery_url(issuer).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn discovery_url_rejects_unsafe_issuer_uris() {
        for issuer in [
            "http://id.example.test/realms/acme",
            "https://user:pass@id.example.test/realms/acme",
            "https://id.example.test/realms/acme?other=issuer",
            "https://id.example.test/realms/acme#fragment",
        ] {
            assert!(discovery_url(issuer).is_err());
        }
    }

    #[test]
    fn discovery_path_trimming_does_not_relax_exact_issuer_validation() {
        let mut connection = connection();
        connection.issuer.push('/');
        let mut document = discovery();
        assert!(document.validate_for_connection(&connection).is_err());
        document.issuer.push('/');
        assert!(document.validate_for_connection(&connection).is_ok());
        assert_eq!(
            discovery_url(&connection.issuer).unwrap().as_str(),
            "https://id.example.test/realms/acme/.well-known/openid-configuration"
        );
    }

    #[test]
    fn pkce_uses_a_high_entropy_s256_verifier() {
        let pair = PkcePair::generate();
        assert_eq!(pair.code_verifier().len(), 43);
        assert_eq!(pair.code_challenge().len(), 43);
        assert_ne!(pair.code_verifier(), pair.code_challenge());
        assert!(pair
            .code_verifier()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    }

    #[test]
    fn discovery_must_match_the_connection_and_advertise_s256() {
        let connection = connection();
        assert!(discovery().validate_for_connection(&connection).is_ok());

        let mut wrong_issuer = discovery();
        wrong_issuer.issuer = "https://id.example.test/other".into();
        assert!(wrong_issuer.validate_for_connection(&connection).is_err());

        let mut no_s256 = discovery();
        no_s256.code_challenge_methods_supported = vec!["plain".into()];
        assert!(no_s256.validate_for_connection(&connection).is_err());

        let mut unsafe_endpoint = discovery();
        unsafe_endpoint.jwks_uri = "https://user:pass@id.example.test/keys".into();
        assert!(unsafe_endpoint
            .validate_for_connection(&connection)
            .is_err());
    }

    #[test]
    fn discovery_json_is_parsed_only_after_bounded_complete_read() {
        let connection = connection();
        let body = br#"{
            "issuer":"https://id.example.test/realms/acme",
            "authorization_endpoint":"https://id.example.test/authorize",
            "token_endpoint":"https://id.example.test/token",
            "jwks_uri":"https://id.example.test/keys",
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code"],
            "code_challenge_methods_supported":["S256"]
        }"#;
        assert!(parse_and_validate_discovery(body, &connection).is_ok());
        assert!(parse_and_validate_discovery(b"not JSON", &connection).is_err());

        let mut collected = Vec::new();
        append_bounded_chunk(&mut collected, &[1, 2], 3, "test response").unwrap();
        append_bounded_chunk(&mut collected, &[3], 3, "test response").unwrap();
        assert_eq!(collected, vec![1, 2, 3]);
        assert!(append_bounded_chunk(&mut collected, &[4], 3, "test response").is_err());
        assert!(append_bounded_chunk(
            &mut Vec::new(),
            &vec![0; MAX_DISCOVERY_DOCUMENT_BYTES + 1],
            MAX_DISCOVERY_DOCUMENT_BYTES,
            "test response",
        )
        .is_err());
    }

    #[tokio::test]
    async fn local_idp_exchanges_pkce_code_and_serves_jwks_without_external_network() {
        let provider = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kty": "RSA", "kid": "local-key", "alg": "RS256", "use": "sig",
                    "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyoP7gJ-vT7I7Y8", "e": "AQAB"
                }]
            })))
            .expect(1)
            .mount(&provider)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=local-code"))
            .and(body_string_contains("client_id=firewall-console"))
            .and(body_string_contains("code_verifier=local-verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": "header.claims.signature"
            })))
            .expect(1)
            .mount(&provider)
            .await;

        let endpoints = ValidatedEndpoints {
            authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
                .unwrap(),
            token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
            jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
        };
        let client = OidcHttpClient::for_local_test_provider(endpoints.clone()).unwrap();
        let jwks = client.fetch_jwks(&endpoints).await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("local-key"));
        let token = client
            .exchange_authorization_code(&endpoints, &connection(), "local-code", "local-verifier")
            .await
            .unwrap();
        assert_eq!(token.id_token(), "header.claims.signature");
    }

    #[test]
    fn token_and_jwks_responses_must_have_the_data_needed_for_verification() {
        assert_eq!(
            parse_token_response(br#"{"id_token":"header.claims.signature"}"#)
                .unwrap()
                .id_token(),
            "header.claims.signature"
        );
        assert!(parse_token_response(br#"{}"#).is_err());
        assert!(parse_token_response(br#"{"id_token":""}"#).is_err());
        assert!(parse_token_response(b"not JSON").is_err());

        assert!(parse_jwks(br#"{"keys":[]}"#).is_err());
        assert!(
            parse_jwks(br#"{"keys":[{"kty":"RSA","kid":"key-1","n":"abc","e":"AQAB"}]}"#).is_ok()
        );
    }

    #[test]
    fn token_exchange_values_are_bounded_and_control_free() {
        assert!(validate_token_exchange_component("code-value", "code", 16).is_ok());
        assert!(validate_token_exchange_component("", "code", 16).is_err());
        assert!(validate_token_exchange_component("too-long-value", "code", 3).is_err());
        assert!(validate_token_exchange_component("line\nbreak", "code", 16).is_err());
    }

    #[test]
    fn authorization_state_is_authenticated_encrypted_and_key_bound() {
        let encoded_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let cipher = OidcStateCipher::from_base64url_key(&encoded_key).unwrap();
        let pkce = PkcePair::generate();
        let nonce = random_urlsafe_value(32);
        let sealed = cipher
            .seal_authorization_state("org_acme", "workspace_prod", &pkce, &nonce, 1_700_000_000)
            .unwrap();
        assert!(!sealed.contains(pkce.code_verifier()));
        assert!(!sealed.contains(&nonce));

        let opened = cipher.open_authorization_state(&sealed).unwrap();
        assert_eq!(opened.organization_id(), "org_acme");
        assert_eq!(opened.workspace_id(), "workspace_prod");
        assert_eq!(opened.invitation_id(), None);
        assert_eq!(opened.code_verifier(), pkce.code_verifier());
        assert_eq!(opened.nonce(), nonce);
        assert_eq!(opened.expires_at_unix(), 1_700_000_000);

        let invitation_sealed = cipher
            .seal_authorization_state_with_invitation(
                "org_acme",
                "workspace_prod",
                Some("invitation_one"),
                &pkce,
                &nonce,
                1_700_000_000,
            )
            .unwrap();
        assert!(!invitation_sealed.contains("invitation_one"));
        assert_eq!(
            cipher
                .open_authorization_state(&invitation_sealed)
                .unwrap()
                .invitation_id(),
            Some("invitation_one")
        );

        let sealed_for_other_key = sealed.clone();
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(cipher.open_authorization_state(&tampered).is_err());
        assert!(cipher
            .open_authorization_state(&"A".repeat(MAX_SEALED_AUTHORIZATION_STATE_BYTES + 1))
            .is_err());

        let other_key = URL_SAFE_NO_PAD.encode([8_u8; 32]);
        let other_cipher = OidcStateCipher::from_base64url_key(&other_key).unwrap();
        assert!(other_cipher
            .open_authorization_state(&sealed_for_other_key)
            .is_err());
        assert!(OidcStateCipher::from_base64url_key("not-a-key").is_err());
    }

    #[test]
    fn saml_state_is_authenticated_and_key_bound() {
        let cipher =
            OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();
        let sealed = cipher
            .seal_saml_authorization_state("org_acme", "workspace_prod", 1_700_000_000)
            .unwrap();
        let opened = cipher.open_saml_authorization_state(&sealed).unwrap();
        assert_eq!(opened.organization_id(), "org_acme");
        assert_eq!(opened.workspace_id(), "workspace_prod");
        assert_eq!(opened.expires_at_unix(), 1_700_000_000);
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(cipher
            .open_saml_authorization_state(&String::from_utf8(tampered).unwrap())
            .is_err());

        let relay = cipher.seal_saml_relay_state().unwrap();
        assert!(relay.len() <= 80);
        cipher.open_saml_relay_state(&relay).unwrap();
        let mut tampered_relay = relay.into_bytes();
        let last = tampered_relay.len() - 1;
        tampered_relay[last] = if tampered_relay[last] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(cipher
            .open_saml_relay_state(&String::from_utf8(tampered_relay).unwrap())
            .is_err());
    }

    #[test]
    fn browser_csrf_token_is_bound_to_the_opaque_session() {
        let cipher =
            OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([5_u8; 32])).unwrap();
        let token = cipher.browser_csrf_token("session-a");
        assert!(cipher.verifies_browser_csrf_token("session-a", &token));
        assert!(!cipher.verifies_browser_csrf_token("session-b", &token));
        assert!(!cipher.verifies_browser_csrf_token("session-a", "not-a-valid-token"));
    }
}
