// SPDX-License-Identifier: Apache-2.0

//! Fail-closed SAML 2.0 service-provider flow.
//!
//! The owner stores a signed IdP metadata document and its pinned signing
//! certificate. Every login reparses and verifies that metadata, creates a
//! short-lived opaque RelayState, and persists the pending request only by a
//! one-way hash. No SAML claim can grant a workspace role: the verified
//! `(issuer, NameID)` pair must already have an active local membership.

use std::collections::BTreeMap;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpDescriptor,
    MetadataTrustPolicy, PendingAuthnRequest, PendingSnapshot, PrivateKeyPem, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, Saml, SamlError, SamlValidationContext, SpConfig,
    SpValidationPolicy, SsoResponse, SsoResponseBinding, StartSso, XmlEncryptionPolicy, XmlPolicy,
};
use serde::Deserialize;

use crate::handlers::Shared;
use crate::oidc::OidcStateCipher;
use crate::tenant_store::{
    BrowserSessionFederation, OrganizationSamlConnection, SamlAuthorizationPending, TenantStore,
};

pub const SAML_ACS_PATH: &str = "/auth/saml/acs";
const SAML_STATE_TTL_SECONDS: i64 = 10 * 60;
const MAX_FORM_FIELDS: usize = 64;
const MAX_FORM_FIELD_BYTES: usize = 2 * 1024 * 1024;

/// Secret-bearing local SP configuration. Values are loaded from the process
/// environment only and deliberately do not implement `Serialize`.
#[derive(Clone)]
pub struct SamlRuntimeConfig {
    pub(crate) sp_entity_id: String,
    pub(crate) acs_url: String,
    pub(crate) sp_private_key_pem: String,
    pub(crate) sp_certificate_pem: String,
}

impl SamlRuntimeConfig {
    /// Load all SAML SP settings, or disable SAML when all are absent. Partial
    /// configuration is an operator error and never falls back to unsigned or
    /// locally generated credentials.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let names = [
            "LLM_FW_SAML_SP_ENTITY_ID",
            "LLM_FW_SAML_ACS_URL",
            "LLM_FW_SAML_SP_PRIVATE_KEY_PEM",
            "LLM_FW_SAML_SP_CERTIFICATE_PEM",
        ];
        let values = names.map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()));
        Self::from_optional_values(values)
    }

    fn from_optional_values(values: [Option<String>; 4]) -> anyhow::Result<Option<Self>> {
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            anyhow::bail!(
                "SAML SP configuration requires all four LLM_FW_SAML_* environment variables"
            );
        }
        let entity_id = values[0].as_ref().expect("checked above").trim().to_owned();
        let acs_url = values[1].as_ref().expect("checked above").trim().to_owned();
        let sp_private_key_pem = values[2].as_ref().expect("checked above").to_owned();
        let sp_certificate_pem = values[3].as_ref().expect("checked above").to_owned();
        EntityId::try_new(entity_id.clone())
            .map_err(|_| anyhow::anyhow!("SAML SP entity ID is invalid"))?;
        let url = reqwest::Url::parse(&acs_url)
            .map_err(|_| anyhow::anyhow!("SAML ACS URL is invalid"))?;
        if url.scheme() != "https"
            || url.query().is_some()
            || url.fragment().is_some()
            || url.username() != ""
        {
            anyhow::bail!(
                "SAML ACS URL must be an HTTPS URL without credentials, query, or fragment"
            );
        }
        if url.path() != SAML_ACS_PATH {
            anyhow::bail!("SAML ACS URL must use the fixed /auth/saml/acs path");
        }
        if sp_private_key_pem.len() > 32 * 1024 || sp_certificate_pem.len() > 32 * 1024 {
            anyhow::bail!("SAML SP key and certificate are too large");
        }
        if !sp_private_key_pem.contains("-----BEGIN")
            || !sp_certificate_pem.contains("-----BEGIN CERTIFICATE-----")
        {
            anyhow::bail!("SAML SP credentials must be PEM encoded");
        }
        Ok(Some(Self {
            sp_entity_id: entity_id,
            acs_url,
            sp_private_key_pem,
            sp_certificate_pem,
        }))
    }

    fn sp(&self) -> anyhow::Result<Saml<saml_rs::Sp>> {
        Ok(Saml::sp(self.sp_config()?)?)
    }

    fn sp_config(&self) -> anyhow::Result<SpConfig> {
        // Do not configure a decryption key or encrypted assertions. This
        // deliberately rejects encrypted inbound assertions on every provider.
        // Provider selection does not approve encrypted-assertion support;
        // that requires a separate threat review and interoperability evidence.
        let xml = XmlPolicy {
            encryption: XmlEncryptionPolicy::default(),
            ..XmlPolicy::default()
        };
        Ok(
            SpConfig::builder(EntityId::try_new(self.sp_entity_id.clone())?)
                .acs_endpoint(AcsEndpoint::post(self.acs_url.clone())?)
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(self.sp_private_key_pem.clone())),
                    signing_certificate: Some(CertificatePem::new(self.sp_certificate_pem.clone())),
                    ..Credentials::default()
                })
                .validation(SpValidationPolicy::strict())
                .xml(xml)
                .build()?,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartSamlLoginQuery {
    pub organization_id: String,
    pub workspace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationStartForm {
    pub token: String,
}

/// Start an SP-initiated SAML login for an explicitly selected workspace.
pub async fn start_login(
    State(state): State<Shared>,
    Query(query): Query<StartSamlLoginQuery>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    match store
        .active_workspace_in_organization_async(&query.organization_id, &query.workspace_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to verify SAML workspace");
            return unavailable();
        }
    }
    let connection = match store
        .organization_saml_connection_async(&query.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML connection");
            return unavailable();
        }
    };
    match start_login_inner(
        store,
        cipher,
        runtime,
        connection,
        &query.workspace_id,
        None,
    )
    .await
    {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "SAML login start failed");
            login_failed()
        }
    }
}

/// Begin SAML enrollment from a raw invitation bearer posted by the same-origin
/// acceptance page. The token selects the organization and workspace; no
/// browser-supplied routing values are trusted.
pub async fn start_invitation_login(
    State(state): State<Shared>,
    Form(form): Form<InvitationStartForm>,
) -> Response {
    if form.token.len() > 256 || !form.token.starts_with("llmfw_invite_") {
        return login_failed();
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    let invitation = match store
        .workspace_invitation_for_federation_token_async(
            &form.token,
            BrowserSessionFederation::Saml,
        )
        .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to resolve SAML workspace invitation");
            return unavailable();
        }
    };
    let connection = match store
        .organization_saml_connection_async(&invitation.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML invitation connection");
            return unavailable();
        }
    };
    match start_login_inner(
        store,
        cipher,
        runtime,
        connection,
        &invitation.workspace_id,
        Some(&invitation.id),
    )
    .await
    {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "SAML invitation login start failed");
            login_failed()
        }
    }
}

async fn start_login_inner(
    store: &TenantStore,
    cipher: &OidcStateCipher,
    runtime: &SamlRuntimeConfig,
    connection: OrganizationSamlConnection,
    workspace_id: &str,
    invitation_id: Option<&str>,
) -> anyhow::Result<String> {
    let sp = runtime.sp()?;
    let idp = idp_descriptor(&connection)?;
    let expires_at_unix = now_unix()?
        .checked_add(SAML_STATE_TTL_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("SAML state expiry overflow"))?;
    // The sealed value is RelayState. Pending AuthnRequest details are stored
    // durably after the library creates the request ID, avoiding a circular
    // dependency between the request ID and the browser correlation value.
    let state_value = cipher.seal_saml_relay_state()?;
    let relay = RelayStateParam::try_from_option(Some(state_value.clone()))?;
    let started = sp.start_sso(
        &idp,
        StartSso::redirect()
            .response_binding(SsoResponseBinding::Post)
            .relay_state(relay),
    )?;
    let snapshot = started.pending.snapshot();
    let pending = SamlAuthorizationPending {
        organization_id: connection.organization_id.clone(),
        workspace_id: workspace_id.to_owned(),
        invitation_id: invitation_id.map(str::to_owned),
        request_id: snapshot.id,
        idp_entity_id: snapshot.peer_entity_id,
        expected_binding: snapshot.expected_binding,
        request_binding: snapshot
            .request_binding
            .unwrap_or_else(|| "redirect".to_owned()),
        acs_url: snapshot.acs_url,
        acs_binding: snapshot.acs_binding,
    };
    store
        .reserve_saml_authorization_state_async(&state_value, &pending, expires_at_unix)
        .await?;
    Ok(started.outbound.redirect_url()?.to_owned())
}

#[derive(Deserialize)]
pub struct SamlAcsForm(pub Vec<(String, String)>);

/// Consume and validate a SAML HTTP-POST response. Duplicate RelayState or
/// SAMLResponse fields are rejected to avoid parser differentials.
pub async fn acs(
    State(state): State<Shared>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    if fields.len() > MAX_FORM_FIELDS
        || fields
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_FORM_FIELD_BYTES
    {
        return login_failed();
    }
    let relay_states = fields.iter().filter(|(key, _)| key == "RelayState").count();
    let responses = fields
        .iter()
        .filter(|(key, _)| key == "SAMLResponse")
        .count();
    if relay_states != 1 || responses != 1 {
        return login_failed();
    }
    let state_value = fields
        .iter()
        .find_map(|(key, value)| (key == "RelayState").then_some(value.clone()))
        .unwrap_or_default();
    if cipher.open_saml_relay_state(&state_value).is_err() {
        return login_failed();
    }
    let pending = match store
        .consume_saml_authorization_state_async(&state_value)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to consume SAML state");
            return unavailable();
        }
    };
    let Some(pending) = pending else {
        return login_failed();
    };
    let organization_id = pending.organization_id.clone();
    let workspace_id = pending.workspace_id.clone();
    let invitation_id = pending.invitation_id.clone();
    let connection = match store
        .organization_saml_connection_async(&pending.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML connection");
            return unavailable();
        }
    };
    let result = finish_sso(runtime, connection, pending, &state_value, fields);
    let session = match result {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(error = %error, "SAML response validation failed");
            return login_failed();
        }
    };
    let issuer = session.issuer().as_str();
    let subject = session.name_id().value();
    let access_result = match invitation_id.as_deref() {
        Some(invitation_id) => {
            store
                .accept_workspace_invitation_async(
                    invitation_id,
                    &organization_id,
                    &workspace_id,
                    issuer,
                    subject,
                    BrowserSessionFederation::Saml,
                )
                .await
        }
        None => {
            store
                .verified_saml_identity_workspace_access_async(
                    &organization_id,
                    &workspace_id,
                    issuer,
                    subject,
                )
                .await
        }
    };
    let access = match access_result {
        Ok(Some(access)) => access,
        Ok(None) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to authorize SAML identity");
            return unavailable();
        }
    };
    let expires_at = match now_unix().and_then(|now| {
        now.checked_add(8 * 60 * 60)
            .ok_or_else(|| anyhow::anyhow!("session expiry overflow"))
    }) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to create SAML session expiry");
            return unavailable();
        }
    };
    let session = match store
        .issue_oidc_browser_session_async(&access, BrowserSessionFederation::Saml, expires_at)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to issue SAML browser session");
            return unavailable();
        }
    };
    let cookie = match crate::oidc_auth::session_cookie(&session.token, 8 * 60 * 60) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to create SAML session cookie");
            return unavailable();
        }
    };
    let mut response = Redirect::to("/customer").into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn finish_sso(
    runtime: &SamlRuntimeConfig,
    connection: OrganizationSamlConnection,
    pending: SamlAuthorizationPending,
    state_value: &str,
    fields: Vec<(String, String)>,
) -> anyhow::Result<saml_rs::SsoSession> {
    let prepared = PreparedSso::new(runtime, connection, pending, state_value, fields)?;
    let mut replay = replay_cache()
        .lock()
        .expect("SAML replay cache mutex poisoned");
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut *replay))
            .with_replay_retention(Duration::from_secs(SAML_STATE_TTL_SECONDS as u64));
    prepared.finish(validation)
}

struct PreparedSso {
    sp: Saml<saml_rs::Sp>,
    idp: IdpDescriptor,
    pending: PendingAuthnRequest,
    fields: Vec<FormField>,
}

impl PreparedSso {
    fn new(
        runtime: &SamlRuntimeConfig,
        connection: OrganizationSamlConnection,
        pending: SamlAuthorizationPending,
        state_value: &str,
        fields: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let sp = runtime.sp()?;
        let idp = idp_descriptor(&connection)?;
        let relay = RelayStateParam::try_from_option(Some(state_value.to_owned()))?;
        let snapshot = PendingSnapshot::<saml_rs::AuthnRequest>::authn_request(
            pending.request_id,
            relay,
            pending.idp_entity_id,
            pending.expected_binding,
            pending.acs_url,
            pending.acs_binding,
        );
        let pending = PendingAuthnRequest::from_snapshot(snapshot)?;
        let fields = fields
            .into_iter()
            .map(|(name, value)| FormField::new(name, value))
            .collect();
        Ok(Self {
            sp,
            idp,
            pending,
            fields,
        })
    }

    fn finish(self, validation: SamlValidationContext<'_>) -> anyhow::Result<saml_rs::SsoSession> {
        Ok(self.sp.finish_sso(
            &self.idp,
            &self.pending,
            BrowserInput::<SsoResponse>::post(self.fields),
            validation,
        )?)
    }
}

fn idp_descriptor(connection: &OrganizationSamlConnection) -> anyhow::Result<IdpDescriptor> {
    let entity_id = EntityId::try_new(connection.entity_id.clone())?;
    let certificate = CertificatePem::new(connection.metadata_signing_cert_pem.clone());
    Ok(IdpDescriptor::from_metadata_xml_for(
        entity_id,
        &connection.metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: std::slice::from_ref(&certificate),
        },
    )?)
}

/// Validate an externally supplied signed IdP metadata document using the same
/// parser and pinned certificate path as the login flow. This is intentionally
/// a metadata-only helper for operator conformance probes; it does not create
/// a session or trust any role claim.
pub fn validate_idp_metadata(connection: &OrganizationSamlConnection) -> anyhow::Result<()> {
    let _ = idp_descriptor(connection)?;
    Ok(())
}

#[derive(Default)]
struct BoundedReplayCache {
    entries: BTreeMap<String, SystemTime>,
}

impl ReplayCache for BoundedReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let now = SystemTime::now();
        self.entries.retain(|_, expiry| *expiry > now);
        let cache_key = format!("{}:{}", key.kind(), key.value());
        if self.entries.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        if self.entries.len() >= 4_096 {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, expiry)| *expiry)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(cache_key, expires_at);
        Ok(())
    }
}

fn replay_cache() -> &'static Mutex<BoundedReplayCache> {
    static CACHE: OnceLock<Mutex<BoundedReplayCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedReplayCache::default()))
}

fn now_unix() -> anyhow::Result<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(i64::try_from(seconds)?)
}

fn unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"error": {"message": "SAML browser login is not enabled"}})),
    )
        .into_response()
}

fn login_failed() -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({"error": {"message": "SAML login could not be completed"}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use axum::extract::{Form, State};
    use axum::http::{header, StatusCode};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use reqwest::Url;
    use saml_rs::constants::signature_algorithm::RSA_SHA256;
    use saml_rs::crypto::construct_saml_signature;
    use saml_rs::crypto::keys::load_private_key;
    use saml_rs::entity::{SignatureAction, SignatureConfig};
    use saml_rs::{
        BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig, IdpValidationPolicy,
        MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy, RespondSso, Saml,
        SamlValidationContext, SpDescriptor, SsoEndpoint, Subject,
    };
    use soup_wall_core::{Firewall, InjectionDetector, PolicySet};

    use crate::handlers::AppState;
    use crate::tenant_store::{TenantStore, WorkspaceRole};
    use crate::test_config;

    const FIXTURE_KEY: &str = include_str!("../tests/fixtures/saml/local-idp-key.pem");
    const FIXTURE_CERT: &str = include_str!("../tests/fixtures/saml/local-idp-cert.pem");
    const SP_ENTITY_ID: &str = "https://sp.example.test/metadata";
    const SP_ACS_URL: &str = "https://sp.example.test/auth/saml/acs";
    const IDP_ENTITY_ID: &str = "https://idp.example.test/metadata";
    const IDP_SSO_URL: &str = "https://idp.example.test/sso";

    fn fixture_runtime() -> SamlRuntimeConfig {
        SamlRuntimeConfig {
            sp_entity_id: SP_ENTITY_ID.to_owned(),
            acs_url: SP_ACS_URL.to_owned(),
            sp_private_key_pem: FIXTURE_KEY.to_owned(),
            sp_certificate_pem: FIXTURE_CERT.to_owned(),
        }
    }

    fn fixture_idp() -> anyhow::Result<Saml<saml_rs::Idp>> {
        let config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_URL)?)
            .credentials(Credentials {
                signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
                signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                ..Credentials::default()
            })
            .validation(IdpValidationPolicy::strict())
            .build()?;
        Ok(Saml::idp(config)?)
    }

    fn signed_idp_metadata(idp: &Saml<saml_rs::Idp>) -> anyhow::Result<String> {
        let key = load_private_key(FIXTURE_KEY, None)?;
        let signature = SignatureConfig {
            prefix: "ds".into(),
            reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
            action: SignatureAction::Prepend,
        };
        let unsigned = idp.metadata_xml().replacen(
            "<EntityDescriptor ",
            "<EntityDescriptor ID=\"_fixture_metadata\" ",
            1,
        );
        Ok(construct_saml_signature(
            &unsigned,
            true,
            &key,
            FIXTURE_CERT,
            RSA_SHA256,
            &[],
            Some(&signature),
        )?)
    }

    fn validation() -> SamlValidationContext<'static> {
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
    }

    struct FixedReplayCache {
        now: SystemTime,
        entries: BTreeMap<String, SystemTime>,
    }

    impl FixedReplayCache {
        fn new(now: SystemTime) -> Self {
            Self {
                now,
                entries: BTreeMap::new(),
            }
        }

        fn validation(&mut self) -> SamlValidationContext<'_> {
            SamlValidationContext::new(self.now, ReplayPolicy::RequireCache(self))
                .with_replay_retention(Duration::from_secs(SAML_STATE_TTL_SECONDS as u64))
        }
    }

    impl ReplayCache for FixedReplayCache {
        fn check_and_store(
            &mut self,
            key: ReplayKey,
            expires_at: SystemTime,
        ) -> Result<(), SamlError> {
            self.entries.retain(|_, expiry| *expiry > self.now);
            let key = format!("{}:{}", key.kind(), key.value());
            if self.entries.contains_key(&key) {
                return Err(SamlError::ReplayDetected { key });
            }
            self.entries.insert(key, expires_at);
            Ok(())
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeycloakVendor {
        name: String,
        version: String,
        archive_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeycloakProvenance {
        driver_sha256: String,
        saml_source_sha256: String,
        gateway_sha256: String,
        bootstrap_helper_sha256: String,
        keycloak_archive_sha256: String,
        jdk_archive_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeycloakCorpus {
        schema_version: u32,
        acceptance_complete: bool,
        synthetic_fixture: bool,
        vendor: KeycloakVendor,
        captured_at_unix: u64,
        sp_entity_id: String,
        acs_url: String,
        idp_entity_id: String,
        idp_signing_cert_pem: String,
        request_id: String,
        relay_state: String,
        expected_name_id: String,
        metadata_xml: String,
        saml_response: String,
        provenance: KeycloakProvenance,
    }

    impl KeycloakCorpus {
        fn load() -> anyhow::Result<Self> {
            // Runtime loading keeps ordinary Gateway builds independent of
            // fixture generation. Missing or incomplete corpus is a test failure.
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/saml/keycloak-corpus.json");
            let bytes = std::fs::read(path).map_err(|error| {
                anyhow::anyhow!("required fresh Keycloak corpus unavailable: {error}")
            })?;
            let corpus: Self = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                corpus.schema_version == 1,
                "unsupported Keycloak corpus schema"
            );
            anyhow::ensure!(
                corpus.acceptance_complete && corpus.synthetic_fixture,
                "Keycloak corpus requires complete synthetic vendor acceptance"
            );
            anyhow::ensure!(
                corpus.vendor.name == "Keycloak" && corpus.vendor.version == "26.8.0",
                "Keycloak corpus vendor provenance is unsupported"
            );
            anyhow::ensure!(
                corpus.vendor.archive_sha256
                    == "7ed1de3fda2598369262613bf682aab7e233d80a38c405e91588f7a7454370a1",
                "Keycloak corpus does not identify the pinned official archive"
            );
            anyhow::ensure!(
                corpus.vendor.archive_sha256 == corpus.provenance.keycloak_archive_sha256,
                "Keycloak corpus archive provenance differs"
            );
            for digest in [
                &corpus.provenance.driver_sha256,
                &corpus.provenance.saml_source_sha256,
                &corpus.provenance.gateway_sha256,
                &corpus.provenance.bootstrap_helper_sha256,
                &corpus.provenance.keycloak_archive_sha256,
                &corpus.provenance.jdk_archive_sha256,
            ] {
                anyhow::ensure!(
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "Keycloak corpus lacks a SHA-256 provenance digest"
                );
            }
            anyhow::ensure!(
                !corpus.request_id.is_empty()
                    && !corpus.relay_state.is_empty()
                    && !corpus.expected_name_id.is_empty(),
                "Keycloak corpus correlation is absent"
            );
            Ok(corpus)
        }

        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.captured_at_unix)
        }

        fn runtime(&self) -> SamlRuntimeConfig {
            // Published local test credentials satisfy the strict SP builder;
            // plaintext response verification needs no captured private key.
            SamlRuntimeConfig {
                sp_entity_id: self.sp_entity_id.clone(),
                acs_url: self.acs_url.clone(),
                sp_private_key_pem: FIXTURE_KEY.into(),
                sp_certificate_pem: FIXTURE_CERT.into(),
            }
        }

        fn connection(&self) -> OrganizationSamlConnection {
            OrganizationSamlConnection {
                organization_id: "keycloak-corpus".into(),
                entity_id: self.idp_entity_id.clone(),
                metadata_xml: self.metadata_xml.clone(),
                metadata_signing_cert_pem: self.idp_signing_cert_pem.clone(),
                active: true,
                created_at_unix: 0,
                updated_at_unix: 0,
            }
        }

        fn pending(&self) -> SamlAuthorizationPending {
            // These expectations were captured from the original outgoing SP
            // request, independently of the vendor response under validation.
            SamlAuthorizationPending {
                organization_id: "keycloak-corpus".into(),
                workspace_id: "corpus-workspace".into(),
                invitation_id: None,
                request_id: self.request_id.clone(),
                idp_entity_id: self.idp_entity_id.clone(),
                expected_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
                request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
                acs_url: self.acs_url.clone(),
                acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
            }
        }

        fn fields(&self) -> Vec<(String, String)> {
            vec![
                ("SAMLResponse".into(), self.saml_response.clone()),
                ("RelayState".into(), self.relay_state.clone()),
            ]
        }

        fn verify(&self, replay: &mut FixedReplayCache) -> anyhow::Result<saml_rs::SsoSession> {
            PreparedSso::new(
                &self.runtime(),
                self.connection(),
                self.pending(),
                &self.relay_state,
                self.fields(),
            )?
            .finish(replay.validation())
        }

        fn assert_valid(&self) -> anyhow::Result<()> {
            let session = self.verify(&mut FixedReplayCache::new(self.now()))?;
            assert_eq!(session.issuer().as_str(), self.idp_entity_id);
            assert_eq!(session.name_id().value(), self.expected_name_id);
            assert!(!session.verified_xml_signatures().is_empty());
            Ok(())
        }
    }

    #[test]
    fn keycloak_corpus_accepts_original_vendor_signed_documents() -> anyhow::Result<()> {
        KeycloakCorpus::load()?.assert_valid()
    }

    #[test]
    fn keycloak_corpus_rejects_tampered_metadata_endpoint() -> anyhow::Result<()> {
        let corpus = KeycloakCorpus::load()?;
        corpus.assert_valid()?;
        let mut connection = corpus.connection();
        let service = connection
            .metadata_xml
            .find("SingleSignOnService")
            .ok_or_else(|| anyhow::anyhow!("vendor corpus lacks an SSO endpoint"))?;
        let start = service
            + connection.metadata_xml[service..]
                .find("Location=\"")
                .ok_or_else(|| anyhow::anyhow!("vendor corpus lacks a quoted SSO location"))?
            + "Location=\"".len();
        let end = start
            + connection.metadata_xml[start..]
                .find('"')
                .ok_or_else(|| anyhow::anyhow!("vendor corpus has an unterminated SSO location"))?;
        connection
            .metadata_xml
            .replace_range(start..end, "https://attacker.example.test/sso");
        assert!(idp_descriptor(&connection).is_err());
        Ok(())
    }

    #[test]
    fn keycloak_corpus_rejects_tampered_name_id() -> anyhow::Result<()> {
        let corpus = KeycloakCorpus::load()?;
        corpus.assert_valid()?;
        let mut xml = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(&corpus.saml_response)?,
        )?;
        let positions: Vec<usize> = xml
            .match_indices(&corpus.expected_name_id)
            .filter_map(|(offset, _)| {
                let (_, prefix) = xml[..offset].rsplit_once('<')?;
                let tag = prefix.split_whitespace().next()?.trim_end_matches('>');
                (prefix.ends_with('>') && tag.rsplit(':').next() == Some("NameID"))
                    .then_some(offset)
            })
            .collect();
        assert_eq!(
            positions.len(),
            1,
            "vendor corpus must have exactly one expected NameID"
        );
        let start = positions[0];
        xml.replace_range(
            start..start + corpus.expected_name_id.len(),
            "tampered-synthetic@example.test",
        );
        let mut fields = corpus.fields();
        fields[0].1 = base64::engine::general_purpose::STANDARD.encode(xml);
        let mut replay = FixedReplayCache::new(corpus.now());
        assert!(PreparedSso::new(
            &corpus.runtime(),
            corpus.connection(),
            corpus.pending(),
            &corpus.relay_state,
            fields,
        )?
        .finish(replay.validation())
        .is_err());
        Ok(())
    }

    #[test]
    fn keycloak_corpus_rejects_wrong_original_request_correlation() -> anyhow::Result<()> {
        let corpus = KeycloakCorpus::load()?;
        corpus.assert_valid()?;
        for mutation in ["request_id", "relay_state", "acs_url"] {
            let mut pending = corpus.pending();
            let mut fields = corpus.fields();
            match mutation {
                "request_id" => pending.request_id = "_different_original_request".into(),
                "relay_state" => fields[1].1 = "different-original-relay".into(),
                "acs_url" => {
                    pending.acs_url = "https://different.example.test/auth/saml/acs".into()
                }
                _ => unreachable!(),
            }
            let mut replay = FixedReplayCache::new(corpus.now());
            assert!(
                PreparedSso::new(
                    &corpus.runtime(),
                    corpus.connection(),
                    pending,
                    &corpus.relay_state,
                    fields,
                )?
                .finish(replay.validation())
                .is_err(),
                "accepted incorrect {mutation}"
            );
        }
        Ok(())
    }

    #[test]
    fn keycloak_corpus_rejects_expired_vendor_assertion() -> anyhow::Result<()> {
        let corpus = KeycloakCorpus::load()?;
        corpus.assert_valid()?;
        let mut replay = FixedReplayCache::new(corpus.now() + Duration::from_secs(24 * 60 * 60));
        assert!(corpus.verify(&mut replay).is_err());
        Ok(())
    }

    #[test]
    fn keycloak_corpus_rejects_replayed_vendor_assertion() -> anyhow::Result<()> {
        let corpus = KeycloakCorpus::load()?;
        let mut replay = FixedReplayCache::new(corpus.now());
        let session = corpus.verify(&mut replay)?;
        assert_eq!(session.name_id().value(), corpus.expected_name_id);
        let error = corpus
            .verify(&mut replay)
            .err()
            .ok_or_else(|| anyhow::anyhow!("replayed vendor assertion was accepted"))?;
        assert!(
            matches!(
                error.downcast_ref::<SamlError>(),
                Some(SamlError::ReplayDetected { .. })
            ),
            "expected replay rejection, got {error}"
        );
        Ok(())
    }

    #[test]
    fn historical_signed_response_is_accepted_at_its_validation_time() -> anyhow::Result<()> {
        let runtime = fixture_runtime();
        let connection = OrganizationSamlConnection {
            organization_id: "context-fixture".into(),
            entity_id: IDP_ENTITY_ID.into(),
            metadata_xml: signed_idp_metadata(&fixture_idp()?)?,
            metadata_signing_cert_pem: FIXTURE_CERT.into(),
            active: true,
            created_at_unix: 0,
            updated_at_unix: 0,
        };
        let pending = SamlAuthorizationPending {
            organization_id: "context-fixture".into(),
            workspace_id: "context-workspace".into(),
            invitation_id: None,
            request_id: "_context_request".into(),
            idp_entity_id: IDP_ENTITY_ID.into(),
            expected_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
            request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
            acs_url: SP_ACS_URL.into(),
            acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
        };
        let unsigned = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_context_response" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="{SP_ACS_URL}" InResponseTo="_context_request"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_context_assertion" Version="2.0" IssueInstant="2020-01-01T00:00:00Z"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><saml:Subject><saml:NameID>alice@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_context_request" Recipient="{SP_ACS_URL}" NotOnOrAfter="2020-01-01T00:05:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2020-01-01T00:05:00Z"><saml:AudienceRestriction><saml:Audience>{SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2020-01-01T00:00:00Z" SessionIndex="_context_session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>"#
        );
        let key = load_private_key(FIXTURE_KEY, None)?;
        let signed =
            construct_saml_signature(&unsigned, false, &key, FIXTURE_CERT, RSA_SHA256, &[], None)?;
        let fields = vec![
            (
                "SAMLResponse".into(),
                base64::engine::general_purpose::STANDARD.encode(signed),
            ),
            ("RelayState".into(), "context-relay".into()),
        ];
        // Establish that the real signed response is valid at this independent
        // instant before exercising the application's shared verifier.
        let captured_at = UNIX_EPOCH + Duration::from_secs(1_577_836_801);
        let snapshot = PendingSnapshot::<saml_rs::AuthnRequest>::authn_request(
            pending.request_id.clone(),
            RelayStateParam::try_from_option(Some("context-relay"))?,
            pending.idp_entity_id.clone(),
            pending.expected_binding.clone(),
            pending.acs_url.clone(),
            pending.acs_binding.clone(),
        );
        let verified = runtime
            .sp()?
            .finish_sso(
                &idp_descriptor(&connection)?,
                &PendingAuthnRequest::from_snapshot(snapshot)?,
                BrowserInput::<SsoResponse>::post(
                    fields
                        .iter()
                        .map(|(name, value)| FormField::new(name, value))
                        .collect(),
                ),
                SamlValidationContext::new(captured_at, ReplayPolicy::DisabledForCompatibility),
            )
            .map_err(|error| {
                anyhow::anyhow!("fixed-time signed fixture control failed: {error}")
            })?;
        assert_eq!(verified.name_id().value(), "alice@example.test");
        assert!(finish_sso(
            &runtime,
            connection.clone(),
            pending.clone(),
            "context-relay",
            fields.clone()
        )
        .is_err());
        let mut replay = FixedReplayCache::new(captured_at);
        let session = PreparedSso::new(&runtime, connection, pending, "context-relay", fields)?
            .finish(replay.validation())?;
        assert_eq!(session.name_id().value(), "alice@example.test");
        Ok(())
    }

    #[test]
    fn saml_initializes_the_timing_safe_document_provider() -> anyhow::Result<()> {
        let provider = saml_rs::initialize_crypto_provider()?;
        assert_eq!(provider.provider(), saml_rs::CryptoProvider::AwsLc);
        assert_eq!(provider.fips_status(), saml_rs::CryptoFipsStatus::Disabled);
        Ok(())
    }

    #[test]
    fn runtime_requires_complete_fixed_https_configuration() {
        assert!(
            SamlRuntimeConfig::from_optional_values([None, None, None, None])
                .unwrap()
                .is_none()
        );
        assert!(SamlRuntimeConfig::from_optional_values([
            Some("https://sp.example.test/metadata".to_owned()),
            None,
            None,
            None,
        ])
        .is_err());

        let valid = [
            Some("https://sp.example.test/metadata".to_owned()),
            Some("https://sp.example.test/auth/saml/acs".to_owned()),
            Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
            Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
        ];
        assert!(SamlRuntimeConfig::from_optional_values(valid)
            .unwrap()
            .is_some());

        assert!(SamlRuntimeConfig::from_optional_values([
            Some("https://sp.example.test/metadata".to_owned()),
            Some("http://sp.example.test/auth/saml/acs".to_owned()),
            Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
            Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
        ])
        .is_err());
    }

    #[test]
    fn runtime_never_configures_xml_decryption() {
        let runtime = SamlRuntimeConfig::from_optional_values([
            Some("https://sp.example.test/metadata".to_owned()),
            Some("https://sp.example.test/auth/saml/acs".to_owned()),
            Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
            Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
        ])
        .unwrap()
        .unwrap();
        let config = runtime.sp_config().unwrap();
        assert!(config.credentials.decryption_key.is_none());
        assert!(config.credentials.encryption_certificate.is_none());
        assert_eq!(
            config.xml.encryption.assertions,
            saml_rs::AssertionEncryptionPolicy::PlaintextAssertions
        );
    }

    #[test]
    fn runtime_metadata_does_not_advertise_assertion_encryption() -> anyhow::Result<()> {
        let sp = fixture_runtime().sp()?;
        assert!(sp.metadata_xml().contains("use=\"signing\""));
        assert!(!sp.metadata_xml().contains("use=\"encryption\""));
        Ok(())
    }

    #[test]
    fn pinned_metadata_rejects_a_tampered_sso_endpoint() -> anyhow::Result<()> {
        let metadata_xml = signed_idp_metadata(&fixture_idp()?)?;
        let mut connection = OrganizationSamlConnection {
            organization_id: "org_signature_fixture".to_owned(),
            entity_id: IDP_ENTITY_ID.to_owned(),
            metadata_xml,
            metadata_signing_cert_pem: FIXTURE_CERT.to_owned(),
            active: true,
            created_at_unix: now_unix()?,
            updated_at_unix: now_unix()?,
        };
        // Establish that this exact signed metadata is trusted before changing
        // an authenticated field while leaving the signature intact.
        idp_descriptor(&connection)?;
        connection.metadata_xml = connection
            .metadata_xml
            .replace(IDP_SSO_URL, "https://attacker.example.test/sso");
        assert!(connection
            .metadata_xml
            .contains("https://attacker.example.test/sso"));
        assert!(idp_descriptor(&connection).is_err());
        Ok(())
    }

    #[test]
    fn signed_response_rejects_a_tampered_name_id() -> anyhow::Result<()> {
        let sp = fixture_runtime().sp()?;
        let idp = fixture_idp()?;
        let sp_descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
        let redirect = Url::parse(started.outbound.redirect_url()?)?;
        let received = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<saml_rs::AuthnRequest>::redirect(redirect.query().expect("SSO query")),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            Subject::new(NameId::new("alice@example.test", None), Vec::new()),
            RespondSso::post(),
        )?;
        let form = response.post_form()?;
        let fields = || {
            form.fields()
                .iter()
                .map(|field| FormField::new(field.name(), field.value()))
                .collect()
        };
        // A valid response and the modified response use identical request
        // correlation, binding, timestamps, issuer and audience.
        let valid = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(fields()),
            validation(),
        )?;
        assert_eq!(valid.name_id().value(), "alice@example.test");
        let mut tampered = Vec::new();
        for field in form.fields() {
            if field.name() == "SAMLResponse" {
                let xml = String::from_utf8(
                    base64::engine::general_purpose::STANDARD.decode(field.value())?,
                )?;
                assert!(xml.contains("alice@example.test"));
                let changed = xml.replace("alice@example.test", "mallory@example.test");
                tampered.push(FormField::new(
                    field.name(),
                    base64::engine::general_purpose::STANDARD.encode(changed),
                ));
            } else {
                tampered.push(FormField::new(field.name(), field.value()));
            }
        }
        assert!(sp
            .finish_sso(
                &idp_descriptor,
                &started.pending,
                BrowserInput::<SsoResponse>::post(tampered),
                validation(),
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn signed_response_with_encrypted_assertion_is_rejected_without_a_decryption_key(
    ) -> anyhow::Result<()> {
        let runtime = fixture_runtime();
        let sp = runtime.sp()?;

        // Advertise an encryption certificate to the test IdP so it can send
        // a valid encrypted response. The actual runtime SP still has no
        // decryption key and must reject that response.
        let advertised_sp = Saml::sp(
            SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
                .acs_endpoint(AcsEndpoint::post(SP_ACS_URL)?)
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
                    signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                    encryption_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                    ..Credentials::default()
                })
                .validation(SpValidationPolicy::strict())
                .build()?,
        )?;
        let sp_descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            advertised_sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let idp = Saml::idp(
            IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
                .sso_endpoint(SsoEndpoint::post(IDP_SSO_URL)?)
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
                    signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                    ..Credentials::default()
                })
                .validation(IdpValidationPolicy::strict())
                .xml(XmlPolicy {
                    encryption: XmlEncryptionPolicy::encrypt_assertions(),
                    ..XmlPolicy::default()
                })
                .build()?,
        )?;
        let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let request_fields = started
            .outbound
            .post_form()?
            .fields()
            .iter()
            .map(|field| FormField::new(field.name(), field.value()))
            .collect();
        let received = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<saml_rs::AuthnRequest>::post(request_fields),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            Subject::new(NameId::new("alice@example.test", None), Vec::new()),
            RespondSso::post(),
        )?;
        let response_fields: Vec<_> = response
            .post_form()?
            .fields()
            .iter()
            .map(|field| FormField::new(field.name(), field.value()))
            .collect();
        let encoded = response_fields
            .iter()
            .find(|field| field.name() == "SAMLResponse")
            .ok_or_else(|| anyhow::anyhow!("test IdP omitted SAMLResponse"))?;
        let xml =
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded.value())?)?;
        assert!(xml.contains("EncryptedAssertion"));
        assert!(xml.contains("<ds:Signature"));

        let error = sp
            .finish_sso(
                &idp_descriptor,
                &started.pending,
                BrowserInput::<SsoResponse>::post(response_fields),
                validation(),
            )
            .err()
            .ok_or_else(|| anyhow::anyhow!("encrypted assertion was accepted"))?;
        assert!(
            matches!(error, SamlError::AssertionSignatureRequired),
            "expected a signed plaintext assertion, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn local_signed_customer_idp_completes_sp_initiated_flow() -> anyhow::Result<()> {
        let runtime = fixture_runtime();
        let idp = fixture_idp()?;
        let metadata_xml = signed_idp_metadata(&idp)?;
        let idp_connection = OrganizationSamlConnection {
            organization_id: "org_fixture".to_owned(),
            entity_id: IDP_ENTITY_ID.to_owned(),
            metadata_xml: metadata_xml.clone(),
            metadata_signing_cert_pem: FIXTURE_CERT.to_owned(),
            active: true,
            created_at_unix: now_unix()?,
            updated_at_unix: now_unix()?,
        };
        let sp = runtime.sp()?;
        let sp_descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;

        let store = TenantStore::open(":memory:")?;
        let organization = store.create_organization("Local SAML fixture")?;
        let tenant = store.create_tenant_in_organization(&organization.id, "Fixture tenant")?;
        let workspace = store.workspace_for_tenant(&tenant.id)?.expect("workspace");
        let principal = store.create_workspace_principal("Fixture Alice")?;
        store.set_workspace_membership(
            &workspace.id,
            &principal.id,
            crate::tenant_store::WorkspaceRole::Analyst,
        )?;
        store.link_workspace_external_identity(
            &principal.id,
            IDP_ENTITY_ID,
            "alice@example.test",
        )?;
        let connection = store.set_organization_saml_connection(
            &organization.id,
            IDP_ENTITY_ID,
            &metadata_xml,
            FIXTURE_CERT,
            true,
        )?;
        let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([7_u8; 32]))?;

        let redirect_url =
            start_login_inner(&store, &cipher, &runtime, connection, &workspace.id, None).await?;
        let redirect = Url::parse(&redirect_url)?;
        let query = redirect
            .query()
            .ok_or_else(|| anyhow::anyhow!("fixture redirect has no query"))?;
        let relay_state = redirect
            .query_pairs()
            .find(|(key, _)| key == "RelayState")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| anyhow::anyhow!("fixture redirect has no RelayState"))?;
        let request = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<saml_rs::AuthnRequest>::redirect(query),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &request,
            Subject::new(NameId::new("alice@example.test", None), Vec::new()),
            RespondSso::post(),
        )?;
        let form = response.post_form()?;
        let response_fields = form
            .fields()
            .iter()
            .map(|field| (field.name().to_owned(), field.value().to_owned()))
            .collect::<Vec<(String, String)>>();
        assert_eq!(
            response_fields
                .iter()
                .find(|(key, _)| key == "RelayState")
                .map(|(_, value)| value),
            Some(&relay_state)
        );
        let pending = store
            .consume_saml_authorization_state(&relay_state)?
            .ok_or_else(|| anyhow::anyhow!("fixture RelayState was not pending"))?;
        let session = finish_sso(
            &runtime,
            idp_connection,
            pending,
            &relay_state,
            response_fields,
        )?;
        assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
        assert_eq!(session.name_id().value(), "alice@example.test");

        let access = store
            .verified_saml_identity_workspace_access(
                &organization.id,
                &workspace.id,
                IDP_ENTITY_ID,
                "alice@example.test",
            )?
            .expect("local fixture identity is a member");
        assert_eq!(access.principal_id, principal.id);
        assert_eq!(access.role, crate::tenant_store::WorkspaceRole::Analyst);
        let browser_session = store.issue_oidc_browser_session(
            &access,
            BrowserSessionFederation::Saml,
            now_unix()? + 3_600,
        )?;
        assert!(!browser_session.token.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn saml_invitation_start_redirects_and_persists_only_invitation_id() -> anyhow::Result<()>
    {
        let runtime = fixture_runtime();
        let idp = fixture_idp()?;
        let metadata_xml = signed_idp_metadata(&idp)?;
        let store = TenantStore::open(":memory:")?;
        let organization = store.create_organization("SAML invitation route")?;
        let issuer = IDP_ENTITY_ID;
        store.set_organization_saml_connection(
            &organization.id,
            issuer,
            &metadata_xml,
            FIXTURE_CERT,
            true,
        )?;
        let tenant = store.create_tenant_in_organization(&organization.id, "SAML route tenant")?;
        let workspace = store.workspace_for_tenant(&tenant.id)?.expect("workspace");
        let owner = store.create_workspace_principal("SAML route owner")?;
        store.set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)?;
        let invitation = store.create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "SAML route recipient",
            WorkspaceRole::Analyst,
            now_unix()? + 3_600,
        )?;
        let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([8_u8; 32]))?;
        let state = Arc::new(AppState {
            firewall: Firewall::new(
                vec![Box::new(InjectionDetector::new())],
                PolicySet::from_yaml("default: allow")?,
            ),
            http: reqwest::Client::new(),
            openai_api_key: None,
            proxy_auth_token: None,
            tenant_store: Some(store),
            admin_token: None,
            oidc_state_cipher: Some(cipher),
            saml: Some(runtime),
            rate_limiter: std::sync::Mutex::new(crate::rate_limit::RateLimiter::new(
                Default::default(),
            )),
            spend_ledger: std::sync::Mutex::new(crate::spend_limit::SpendLedger::new(
                Default::default(),
            )),
            redis_limits: None,
            agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
            moderation: crate::moderation::ModerationGate::new(Default::default()),
            config: test_config("http://127.0.0.1:1".into()),
        });

        let response = start_invitation_login(
            State(state.clone()),
            Form(InvitationStartForm {
                token: invitation.token,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("SAML invitation response has no redirect"))?;
        let redirect = Url::parse(location)?;
        let relay_state = redirect
            .query_pairs()
            .find(|(key, _)| key == "RelayState")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| anyhow::anyhow!("SAML invitation redirect has no RelayState"))?;
        let pending = state
            .tenant_store
            .as_ref()
            .expect("test store")
            .consume_saml_authorization_state(&relay_state)?
            .ok_or_else(|| anyhow::anyhow!("SAML invitation state was not persisted"))?;
        assert_eq!(pending.invitation_id, Some(invitation.invitation.id));
        Ok(())
    }
}
