// SPDX-License-Identifier: Apache-2.0

//! A deliberately local, synthetic restore fixture. No Gateway worker, IdP,
//! provider, webhook dispatcher or database migration runs in this helper.
//! The driver compares complete private PostgreSQL rows before exercise.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::tenant_store::{
    PolicyDeploymentAction, TenantLimits, TenantModelPolicy, TenantPolicyDocument, TenantRateLimit,
    TenantSpendLimit, TenantStore, WebhookDeliveryStatus, WorkspaceRole,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::{json, Value};
use tokio_postgres::{Client, NoTls};

const DATABASE_ENV: &str = "LLM_FW_RESTORE_FIXTURE_DATABASE_URL";
const RESTORED_ENV: &str = "LLM_FW_RESTORE_FIXTURE_RESTORED_DATABASE_FINGERPRINT";
const DESTINATION: &str = "https://hooks.example.test/restore-fixture";
const MAX_PRIVATE_FILE: u64 = 64 * 1024;

// Never derive Debug: the manifest contains one-time credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    run_id: String,
    source_fingerprint: String,
    webhook_signing_key: String,
    tenant_id: String,
    control_tenant_id: String,
    workspace_id: String,
    owner_principal_id: String,
    active_account_id: String,
    active_account_token: String,
    revoked_account_id: String,
    revoked_account_token: String,
    destination_id: String,
    policy_version_id: String,
    control_policy_version_id: String,
    event_id: String,
    control_event_id: String,
    delivery_id: String,
    limits: TenantLimits,
    model_policy: TenantModelPolicy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema_version: u16,
    run_id: String,
    source_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Seed,
    Probe,
    ExerciseRestored,
}

impl FromStr for Phase {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "seed" => Ok(Self::Seed),
            "probe" => Ok(Self::Probe),
            "exercise-restored" => Ok(Self::ExerciseRestored),
            _ => bail!("unsupported fixture mode"),
        }
    }
}

// Public output has no manifest, database metadata, credential or arbitrary JSON
// fields. Its fixed values describe the checks required by each validated phase.
#[derive(Serialize)]
struct PublicAggregate {
    schema_version: u16,
    mode: Phase,
    status: &'static str,
    tenants: u8,
    service_accounts: u8,
    webhook_destinations: u8,
    pending_deliveries: u8,
    security_events: u8,
    retained_token_authenticated: bool,
    revoked_token_rejected: bool,
    tenant_isolation_verified: bool,
    destination_active: bool,
    model_requests_sent: u8,
    webhook_requests_sent: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    restored_only_mutation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_token_revoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_delivery_enqueued: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deactivated_destination_suppressed_delivery: Option<bool>,
}

impl PublicAggregate {
    const fn for_phase(mode: Phase) -> Self {
        let exercise = matches!(mode, Phase::ExerciseRestored);
        let exercise_passed = if exercise { Some(true) } else { None };
        Self {
            schema_version: 1,
            mode,
            status: "passed",
            tenants: 2,
            service_accounts: 2,
            webhook_destinations: 1,
            pending_deliveries: if exercise { 2 } else { 1 },
            security_events: if exercise { 4 } else { 2 },
            retained_token_authenticated: !exercise,
            revoked_token_rejected: true,
            tenant_isolation_verified: true,
            destination_active: !exercise,
            model_requests_sent: 0,
            webhook_requests_sent: 0,
            restored_only_mutation: exercise_passed,
            retained_token_revoked: exercise_passed,
            new_delivery_enqueued: exercise_passed,
            deactivated_destination_suppressed_delivery: exercise_passed,
        }
    }
}

fn refuse() -> ! {
    // Do not print database errors or manifest values, even for direct invocation.
    eprintln!("populated restore fixture refused; private artifacts are retained");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [mode, directory] = arguments.as_slice() else {
        refuse();
    };
    let phase = Phase::from_str(mode).unwrap_or_else(|_| refuse());
    if run(phase, Path::new(directory)).await.is_err() {
        refuse();
    }
    // Only the phase enum crosses the output boundary after all private checks.
    let aggregate =
        serde_json::to_string(&PublicAggregate::for_phase(phase)).unwrap_or_else(|_| refuse());
    println!("{aggregate}");
}

async fn run(phase: Phase, directory: &Path) -> Result<()> {
    let directory = private_run_directory(directory)?;
    let url = std::env::var(DATABASE_ENV).context("explicit fixture database is absent")?;
    validate_local_url(&url)?;
    let fingerprint = database_fingerprint(&url).await?;
    let store_url = if phase == Phase::Probe {
        readonly_url(&url)?
    } else {
        url.clone()
    };
    // This API checks schema currency; it never migrates the database.
    let store = TenantStore::open_postgres_with_ca_and_tls(
        &store_url,
        1000,
        Duration::from_secs(5),
        2,
        Duration::from_secs(5),
        None,
        false,
    )
    .await?;
    if phase == Phase::Seed {
        ensure!(
            !directory.join("manifest.json").exists(),
            "manifest already exists"
        );
        let run_id = random_text(16);
        write_private_new(
            &directory.join("seed-start.json"),
            &Marker {
                schema_version: 1,
                run_id: run_id.clone(),
                source_fingerprint: fingerprint.clone(),
            },
        )?;
        // The marker is durable before the first fixture write. Interrupted
        // attempts are never retried into a partially populated database.
        require_empty_postgres(&url).await?;
        let key = random_text(32);
        let store = store.with_webhook_signing_key_base64url(&key)?;
        let manifest = seed_fixture(&store, &run_id, &fingerprint, &key).await?;
        probe_fixture(&store, &manifest).await?;
        write_private_new(&directory.join("manifest.json"), &manifest)?;
        return Ok(());
    }
    let manifest: Manifest = read_private(&directory.join("manifest.json"))?;
    let marker: Marker = read_private(&directory.join("seed-start.json"))?;
    ensure!(
        manifest.schema_version == 1
            && marker.schema_version == 1
            && marker.run_id == manifest.run_id
            && marker.source_fingerprint == manifest.source_fingerprint,
        "fixture run binding differs"
    );
    ensure!(
        manifest.limits == fixture_limits() && manifest.model_policy == fixture_model_policy(),
        "fixture policy differs"
    );
    if phase == Phase::Probe {
        return probe_fixture(&store, &manifest).await;
    }
    let expected = std::env::var(RESTORED_ENV).context("restored target binding is absent")?;
    ensure_restored_target(&manifest.source_fingerprint, &fingerprint, &expected)?;
    // Validate the complete baseline before marking any behavioral mutation.
    probe_fixture(&store, &manifest).await?;
    write_private_new(
        &directory.join("exercise-start.json"),
        &Marker {
            schema_version: 1,
            run_id: manifest.run_id.clone(),
            source_fingerprint: fingerprint.clone(),
        },
    )?;
    exercise_fixture(&store, &manifest, &fingerprint, &expected).await
}

fn validate_local_url(value: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(value).context("invalid fixture database URL")?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql"),
        "fixture requires PostgreSQL"
    );
    let host = parsed.host_str().context("fixture host is absent")?;
    let address: IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .context("fixture requires a numeric loopback host")?;
    ensure!(address.is_loopback(), "fixture host is not loopback");
    ensure!(
        !parsed.username().is_empty() && parsed.path().len() > 1 && parsed.fragment().is_none(),
        "fixture database identity is absent"
    );
    let query: Vec<_> = parsed.query_pairs().collect();
    ensure!(
        query.len() == 1 && query[0].0 == "sslmode" && query[0].1 == "disable",
        "local fixture requires only sslmode=disable"
    );
    Ok(())
}

fn readonly_url(value: &str) -> Result<String> {
    validate_local_url(value)?;
    let mut parsed = reqwest::Url::parse(value)?;
    // PostgreSQL URI options use percent decoding, not form decoding: a '+'
    // remains literal instead of becoming a space between '-c' and the setting.
    parsed.set_query(Some(
        "sslmode=disable&options=-c%20default_transaction_read_only%3Don",
    ));
    Ok(parsed.into())
}

async fn database_client(url: &str) -> Result<Client> {
    let mut config = tokio_postgres::Config::from_str(url)?;
    config.connect_timeout(Duration::from_secs(5));
    config.options("-c default_transaction_read_only=on -c statement_timeout=5000");
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn database_fingerprint(url: &str) -> Result<String> {
    let row = database_client(url)
        .await?
        .query_one(
            "SELECT current_database() || '|' || COALESCE(host(inet_server_addr()), 'local') || '|' || COALESCE(inet_server_port()::text, 'local')",
            &[],
        )
        .await?;
    Ok(row.get(0))
}

async fn require_empty_postgres(url: &str) -> Result<()> {
    let client = database_client(url).await?;
    let tables = client
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
            &[],
        )
        .await?;
    for row in tables {
        let table: String = row.get(0);
        if table == "llm_firewall_schema_migrations" || table == "organizations" {
            continue;
        }
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let count: i64 = client
            .query_one(&format!("SELECT COUNT(*) FROM public.{quoted}"), &[])
            .await?
            .get(0);
        ensure!(count == 0, "fixture source is already populated");
    }
    // Migrations create the bootstrap organization. Extra organizations are
    // operator state even when they have no tenants and must not be seeded.
    let extra: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM organizations WHERE id <> 'org_bootstrap'",
            &[],
        )
        .await?
        .get(0);
    ensure!(extra == 0, "fixture source contains operator organizations");
    Ok(())
}

fn ensure_restored_target(source: &str, actual: &str, expected: &str) -> Result<()> {
    ensure!(
        !source.is_empty() && !expected.is_empty() && actual == expected && actual != source,
        "behavioral exercise is not bound to the separate restored database"
    );
    Ok(())
}

fn fixture_limits() -> TenantLimits {
    TenantLimits {
        rate_limit: Some(TenantRateLimit {
            requests_per_window: 7,
            window_seconds: 60,
        }),
        spend_limit: Some(TenantSpendLimit {
            window_seconds: 86_400,
            max_usd_micros: 1_000_000,
            reserve_usd_micros_per_request: 50_000,
        }),
    }
}

fn fixture_model_policy() -> TenantModelPolicy {
    TenantModelPolicy {
        allowed_models: vec!["restore-fixture-allowed".into()],
    }
}

async fn activate(store: &TenantStore, tenant: &str, policy: TenantModelPolicy) -> Result<String> {
    let version = store
        .create_policy_version_async(
            tenant,
            "restore-fixture-operator",
            TenantPolicyDocument::new(Some(policy)),
        )
        .await?;
    store
        .approve_policy_version_async(tenant, &version.id, "restore-fixture-owner")
        .await?;
    store
        .deploy_policy_version_async(
            tenant,
            &version.id,
            "restore-fixture-owner",
            PolicyDeploymentAction::Activate,
        )
        .await?;
    Ok(version.id)
}

async fn seed_fixture(
    store: &TenantStore,
    run: &str,
    fingerprint: &str,
    key: &str,
) -> Result<Manifest> {
    ensure!(
        store.list_tenants_async().await?.is_empty(),
        "fixture source already has tenants"
    );
    let tenant = store
        .create_tenant_async(&format!("Restore fixture {run}"))
        .await?;
    let control = store
        .create_tenant_async("Restore isolation control")
        .await?;
    let workspace = store
        .workspace_for_tenant_async(&tenant.id)
        .await?
        .context("fixture workspace is absent")?;
    let owner = store
        .create_workspace_principal_async("Restore fixture owner")
        .await?;
    store
        .set_workspace_membership_async(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .await?;
    store
        .set_workspace_limits_async(&workspace.id, &owner.id, fixture_limits())
        .await?;
    let expires = now_unix()? + 86_400;
    let active = store
        .create_workspace_service_account_async(
            &workspace.id,
            &owner.id,
            "retained-machine",
            expires,
        )
        .await?;
    let revoked = store
        .create_workspace_service_account_async(
            &workspace.id,
            &owner.id,
            "revoked-machine",
            expires,
        )
        .await?;
    ensure!(
        store
            .revoke_workspace_service_account_async(&workspace.id, &revoked.account.id, &owner.id)
            .await?,
        "fixture revocation failed"
    );
    let destination = store
        .create_workspace_webhook_destination_async(
            &workspace.id,
            &owner.id,
            DESTINATION,
            &["policy.deployed".into()],
        )
        .await?;
    let policy_version_id = activate(store, &tenant.id, fixture_model_policy()).await?;
    let control_policy_version_id = activate(
        store,
        &control.id,
        TenantModelPolicy {
            allowed_models: vec!["restore-control-allowed".into()],
        },
    )
    .await?;
    let events = store.list_security_events_async(&tenant.id, 0, 10).await?;
    let control_events = store.list_security_events_async(&control.id, 0, 10).await?;
    let deliveries = store.list_webhook_deliveries_async(&tenant.id, 10).await?;
    ensure!(
        events.len() == 1 && control_events.len() == 1 && deliveries.len() == 1,
        "fixture event counts differ"
    );
    Ok(Manifest {
        schema_version: 1,
        run_id: run.into(),
        source_fingerprint: fingerprint.into(),
        webhook_signing_key: key.into(),
        tenant_id: tenant.id,
        control_tenant_id: control.id,
        workspace_id: workspace.id,
        owner_principal_id: owner.id,
        active_account_id: active.account.id,
        active_account_token: active.token,
        revoked_account_id: revoked.account.id,
        revoked_account_token: revoked.token,
        destination_id: destination.destination.id,
        policy_version_id,
        control_policy_version_id,
        event_id: events[0].id.clone(),
        control_event_id: control_events[0].id.clone(),
        delivery_id: deliveries[0].id.clone(),
        limits: fixture_limits(),
        model_policy: fixture_model_policy(),
    })
}

async fn probe_fixture(store: &TenantStore, m: &Manifest) -> Result<()> {
    let tenants = store.list_tenants_async().await?;
    ensure!(
        tenants.len() == 2
            && tenants
                .iter()
                .all(|t| t.active && (t.id == m.tenant_id || t.id == m.control_tenant_id)),
        "fixture tenants differ"
    );
    let workspace = store
        .workspace_for_tenant_async(&m.tenant_id)
        .await?
        .context("fixture workspace absent")?;
    ensure!(
        workspace.id == m.workspace_id && workspace.active,
        "fixture workspace differs"
    );
    let members = store.list_workspace_members_async(&m.workspace_id).await?;
    ensure!(
        members.len() == 1
            && members[0].principal_id == m.owner_principal_id
            && members[0].active
            && members[0].role == WorkspaceRole::Owner,
        "fixture membership differs"
    );
    let accounts = store
        .list_workspace_service_accounts_async(&m.workspace_id, &m.owner_principal_id)
        .await?;
    let active = accounts
        .iter()
        .find(|a| a.id == m.active_account_id)
        .context("retained account absent")?;
    let revoked = accounts
        .iter()
        .find(|a| a.id == m.revoked_account_id)
        .context("revoked account absent")?;
    ensure!(
        accounts.len() == 2
            && active.active
            && active.revoked_at_unix.is_none()
            && active.expires_at_unix > now_unix()?
            && !revoked.active
            && revoked.revoked_at_unix.is_some(),
        "fixture account state differs"
    );
    let access = store
        .authenticate_access_async(Some(&format!("Bearer {}", m.active_account_token)))
        .await?
        .context("retained token failed")?;
    ensure!(
        access.identity.tenant_id == m.tenant_id
            && access.limits == m.limits
            && access.model_policy.as_ref() == Some(&m.model_policy),
        "retained token policy differs"
    );
    ensure!(
        store
            .authenticate_access_async(Some(&format!("Bearer {}", m.revoked_account_token)))
            .await?
            .is_none(),
        "revoked token authenticates"
    );
    ensure!(
        store
            .authenticate_access_async(Some("Bearer invalid-fixture-token"))
            .await?
            .is_none(),
        "invalid token authenticates"
    );
    let destinations = store.list_webhook_destinations_async(&m.tenant_id).await?;
    ensure!(
        destinations.len() == 1
            && destinations[0].id == m.destination_id
            && destinations[0].active
            && destinations[0].url == DESTINATION
            && destinations[0].event_types == ["policy.deployed"],
        "fixture destination differs"
    );
    let deliveries = store
        .list_webhook_deliveries_async(&m.tenant_id, 10)
        .await?;
    ensure!(
        deliveries.len() == 1
            && deliveries[0].id == m.delivery_id
            && deliveries[0].event_id == m.event_id
            && deliveries[0].destination_id == m.destination_id
            && deliveries[0].status == WebhookDeliveryStatus::Pending
            && deliveries[0].attempt_count == 0
            && deliveries[0].locked_until_unix.is_none()
            && deliveries[0].delivered_at_unix.is_none()
            && deliveries[0].last_http_status.is_none()
            && deliveries[0].last_error.is_none(),
        "fixture delivery differs"
    );
    let events = store
        .list_security_events_async(&m.tenant_id, 0, 10)
        .await?;
    let control_events = store
        .list_security_events_async(&m.control_tenant_id, 0, 10)
        .await?;
    ensure!(
        events.len() == 1
            && events[0].id == m.event_id
            && events[0].sequence == 1
            && events[0].event_type == "policy.deployed"
            && events[0].payload["version_id"] == m.policy_version_id
            && control_events.len() == 1
            && control_events[0].id == m.control_event_id
            && control_events[0].sequence == 1
            && control_events[0].payload["version_id"] == m.control_policy_version_id,
        "fixture security events differ"
    );
    for (tenant, version) in [
        (&m.tenant_id, &m.policy_version_id),
        (&m.control_tenant_id, &m.control_policy_version_id),
    ] {
        let versions = store.list_policy_versions_async(tenant, 10).await?;
        ensure!(
            versions.len() == 1
                && versions[0].id == *version
                && versions[0].active
                && versions[0].approved_by.as_deref() == Some("restore-fixture-owner"),
            "fixture approved policy differs"
        );
    }
    verify_control_isolation(store, m).await?;
    Ok(())
}

async fn verify_control_isolation(store: &TenantStore, m: &Manifest) -> Result<()> {
    ensure!(
        store
            .list_webhook_destinations_async(&m.control_tenant_id)
            .await?
            .is_empty()
            && store
                .list_webhook_deliveries_async(&m.control_tenant_id, 10)
                .await?
                .is_empty(),
        "control tenant inherited a webhook"
    );
    let control_workspace = store
        .workspace_for_tenant_async(&m.control_tenant_id)
        .await?
        .context("control workspace absent")?;
    ensure!(
        store
            .list_workspace_service_accounts_async(&control_workspace.id, &m.owner_principal_id)
            .await?
            .is_empty(),
        "control workspace exposed service accounts"
    );
    Ok(())
}

async fn exercise_fixture(
    store: &TenantStore,
    m: &Manifest,
    actual: &str,
    expected: &str,
) -> Result<()> {
    ensure_restored_target(&m.source_fingerprint, actual, expected)?;
    probe_fixture(store, m).await?;
    ensure!(
        store
            .revoke_workspace_service_account_async(
                &m.workspace_id,
                &m.active_account_id,
                &m.owner_principal_id
            )
            .await?,
        "restored revocation failed"
    );
    ensure!(
        store
            .authenticate_access_async(Some(&format!("Bearer {}", m.active_account_token)))
            .await?
            .is_none(),
        "restored revoked credential still authenticates"
    );
    activate(store, &m.tenant_id, m.model_policy.clone()).await?;
    let events = store
        .list_security_events_async(&m.tenant_id, 0, 10)
        .await?;
    let deliveries = store
        .list_webhook_deliveries_async(&m.tenant_id, 10)
        .await?;
    ensure!(
        events.len() == 2
            && events[0].id == m.event_id
            && events[1].sequence == 2
            && deliveries.len() == 2
            && deliveries
                .iter()
                .any(|d| d.event_id == events[1].id && d.destination_id == m.destination_id),
        "restored deployment failed to enqueue a new event"
    );
    ensure!(
        store
            .deactivate_workspace_webhook_destination_async(
                &m.workspace_id,
                &m.owner_principal_id,
                &m.destination_id
            )
            .await?,
        "restored destination deactivation failed"
    );
    activate(store, &m.tenant_id, m.model_policy.clone()).await?;
    let events = store
        .list_security_events_async(&m.tenant_id, 0, 10)
        .await?;
    let deliveries = store
        .list_webhook_deliveries_async(&m.tenant_id, 10)
        .await?;
    ensure!(
        events.len() == 3
            && events[2].sequence == 3
            && deliveries.len() == 2
            && deliveries
                .iter()
                .all(|d| d.status == WebhookDeliveryStatus::Pending
                    && d.attempt_count == 0
                    && d.delivered_at_unix.is_none()),
        "inactive destination enqueued or dispatched a delivery"
    );
    let destinations = store.list_webhook_destinations_async(&m.tenant_id).await?;
    ensure!(
        destinations.len() == 1 && !destinations[0].active,
        "restored destination remains active"
    );
    let accounts = store
        .list_workspace_service_accounts_async(&m.workspace_id, &m.owner_principal_id)
        .await?;
    ensure!(
        accounts.len() == 2
            && accounts
                .iter()
                .all(|a| !a.active && a.revoked_at_unix.is_some()),
        "restored account revocation metadata differs"
    );
    verify_control_isolation(store, m).await?;
    Ok(())
}

fn now_unix() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn random_text(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn private_run_directory(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "private run directory must be absolute");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("workspace root absent")?
        .canonicalize()?;
    let target = root.join("target");
    let resolved = path.canonicalize()?;
    ensure!(
        resolved.starts_with(&target) && resolved != target,
        "private run directory is outside ignored target"
    );
    for ancestor in path.ancestors().take_while(|p| *p != root) {
        ensure!(
            !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
            "private run path is linked"
        );
    }
    private_permissions(&resolved, true)?;
    Ok(resolved)
}

#[cfg(unix)]
fn private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && (if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            }),
        "private artifact has wrong type"
    );
    ensure!(
        metadata.permissions().mode() & 0o777 == if directory { 0o700 } else { 0o600 },
        "private artifact permissions differ"
    );
    Ok(())
}

#[cfg(not(unix))]
fn private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    bail!("private restore artifacts require Unix owner-only permissions");
}

fn write_private_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("private artifact parent absent")?;
    private_permissions(parent, true)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    private_permissions(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            file.metadata()?.uid() == fs::metadata(parent)?.uid(),
            "private artifact owner differs"
        );
    }
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn read_private<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    private_permissions(path, false)?;
    ensure!(
        fs::metadata(path)?.len() <= MAX_PRIVATE_FILE,
        "private artifact is oversized"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            fs::metadata(path)?.uid()
                == fs::metadata(path.parent().context("private artifact parent absent")?)?.uid(),
            "private artifact owner differs"
        );
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed_store(path: &str) -> TenantStore {
        TenantStore::open(path)
            .unwrap()
            .with_webhook_signing_key_base64url(&URL_SAFE_NO_PAD.encode([7_u8; 32]))
            .unwrap()
    }

    async fn seed(store: &TenantStore) -> Manifest {
        seed_fixture(
            store,
            "offline-run",
            "source|127.0.0.1|5432",
            &URL_SAFE_NO_PAD.encode([7_u8; 32]),
        )
        .await
        .unwrap()
    }

    async fn inventory(store: &TenantStore, m: &Manifest) -> Value {
        json!({"tenants": store.list_tenants_async().await.unwrap(),
            "accounts": store.list_workspace_service_accounts_async(&m.workspace_id, &m.owner_principal_id).await.unwrap(),
            "destinations": store.list_webhook_destinations_async(&m.tenant_id).await.unwrap(),
            "deliveries": store.list_webhook_deliveries_async(&m.tenant_id, 10).await.unwrap(),
            "events": store.list_security_events_async(&m.tenant_id, 0, 10).await.unwrap(),
            "policies": store.list_policy_versions_async(&m.tenant_id, 10).await.unwrap(),
            "audit": store.list_workspace_admin_audit_async(&m.workspace_id, 20).await.unwrap()})
    }

    #[tokio::test]
    async fn seed_uses_genuine_accounts_policies_events_and_pending_delivery_without_dispatch() {
        let store = keyed_store(":memory:");
        let m = seed(&store).await;
        probe_fixture(&store, &m).await.unwrap();
        let audit = store
            .list_workspace_admin_audit_async(&m.workspace_id, 20)
            .await
            .unwrap();
        assert!(audit.iter().any(|a| a.action == "service_account.create"));
        assert!(audit.iter().any(|a| a.action == "service_account.revoke"));
        assert!(audit
            .iter()
            .any(|a| a.action == "webhook_destination.create"));
    }

    #[tokio::test]
    async fn probing_retained_and_revoked_credentials_is_read_only() {
        let store = keyed_store(":memory:");
        let m = seed(&store).await;
        let before = inventory(&store, &m).await;
        for _ in 0..2 {
            probe_fixture(&store, &m).await.unwrap();
        }
        assert_eq!(inventory(&store, &m).await, before);
    }

    #[tokio::test]
    async fn a_populated_source_cannot_be_reseeded() {
        let store = keyed_store(":memory:");
        let m = seed(&store).await;
        let before = inventory(&store, &m).await;
        assert!(seed_fixture(
            &store,
            "retry",
            &m.source_fingerprint,
            &m.webhook_signing_key
        )
        .await
        .is_err());
        assert_eq!(inventory(&store, &m).await, before);
    }

    #[tokio::test]
    async fn restored_sqlite_copy_preserves_credentials_and_exercise_leaves_source_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.sqlite");
        let restored = directory.path().join("restored.sqlite");
        let store = keyed_store(source.to_str().unwrap());
        let m = seed(&store).await;
        let before = inventory(&store, &m).await;
        drop(store);
        fs::copy(&source, &restored).unwrap();
        let source_store = TenantStore::open(source.to_str().unwrap()).unwrap();
        let restored_store = TenantStore::open(restored.to_str().unwrap()).unwrap();
        probe_fixture(&restored_store, &m).await.unwrap();
        assert_eq!(inventory(&restored_store, &m).await, before);
        exercise_fixture(
            &restored_store,
            &m,
            "restored|127.0.0.1|5432",
            "restored|127.0.0.1|5432",
        )
        .await
        .unwrap();
        assert_eq!(inventory(&source_store, &m).await, before);
        probe_fixture(&source_store, &m).await.unwrap();
    }

    #[tokio::test]
    async fn source_or_mismatched_target_refuses_exercise_before_any_mutation() {
        let store = keyed_store(":memory:");
        let m = seed(&store).await;
        let before = inventory(&store, &m).await;
        for (actual, expected) in [
            (m.source_fingerprint.as_str(), m.source_fingerprint.as_str()),
            ("restored|127.0.0.1|5432", "different|127.0.0.1|5432"),
            ("restored|127.0.0.1|5432", ""),
        ] {
            assert!(exercise_fixture(&store, &m, actual, expected)
                .await
                .is_err());
        }
        assert_eq!(inventory(&store, &m).await, before);
    }

    #[tokio::test]
    async fn public_aggregate_never_contains_credentials_or_fixture_identity() {
        let store = keyed_store(":memory:");
        let m = seed(&store).await;
        probe_fixture(&store, &m).await.unwrap();
        for phase in [Phase::Seed, Phase::Probe, Phase::ExerciseRestored] {
            let public = serde_json::to_string(&PublicAggregate::for_phase(phase)).unwrap();
            for private in [
                &m.run_id,
                &m.source_fingerprint,
                &m.active_account_token,
                &m.revoked_account_token,
                &m.webhook_signing_key,
                &m.tenant_id,
                &m.control_tenant_id,
                &m.workspace_id,
                &m.owner_principal_id,
                &m.active_account_id,
                &m.revoked_account_id,
                &m.destination_id,
                &m.policy_version_id,
                &m.control_policy_version_id,
                &m.event_id,
                &m.control_event_id,
                &m.delivery_id,
            ] {
                assert!(!public.contains(private));
            }
            assert!(!public.contains(DESTINATION));
        }
    }

    #[test]
    fn public_output_contract_is_exact_for_each_validated_phase() {
        for (mode, expected) in [
            (
                "seed",
                json!({"schema_version": 1, "mode": "seed", "status": "passed",
                "tenants": 2, "service_accounts": 2, "webhook_destinations": 1,
                "pending_deliveries": 1, "security_events": 2,
                "retained_token_authenticated": true, "revoked_token_rejected": true,
                "tenant_isolation_verified": true, "destination_active": true,
                "model_requests_sent": 0, "webhook_requests_sent": 0}),
            ),
            (
                "probe",
                json!({"schema_version": 1, "mode": "probe", "status": "passed",
                "tenants": 2, "service_accounts": 2, "webhook_destinations": 1,
                "pending_deliveries": 1, "security_events": 2,
                "retained_token_authenticated": true, "revoked_token_rejected": true,
                "tenant_isolation_verified": true, "destination_active": true,
                "model_requests_sent": 0, "webhook_requests_sent": 0}),
            ),
            (
                "exercise-restored",
                json!({"schema_version": 1,
                "mode": "exercise-restored", "status": "passed", "tenants": 2,
                "service_accounts": 2, "webhook_destinations": 1,
                "pending_deliveries": 2, "security_events": 4,
                "retained_token_authenticated": false, "revoked_token_rejected": true,
                "tenant_isolation_verified": true, "destination_active": false,
                "model_requests_sent": 0, "webhook_requests_sent": 0,
                "restored_only_mutation": true, "retained_token_revoked": true,
                "new_delivery_enqueued": true,
                "deactivated_destination_suppressed_delivery": true}),
            ),
        ] {
            let phase = Phase::from_str(mode).unwrap();
            let public = serde_json::to_value(PublicAggregate::for_phase(phase)).unwrap();
            assert_eq!(public, expected);
        }
    }

    #[test]
    fn invalid_phase_is_refused_without_echoing_input() {
        for invalid in [
            "",
            "unsupported-private-value",
            "probe\nprivate-value",
            "SEED",
        ] {
            let error = Phase::from_str(invalid).unwrap_err();
            assert_eq!(error.to_string(), "unsupported fixture mode");
            if !invalid.is_empty() {
                assert!(!error.to_string().contains(invalid));
            }
        }
    }

    #[test]
    fn only_explicit_numeric_loopback_postgres_urls_are_accepted() {
        for url in [
            "postgresql://fixture:private@127.0.0.1/source?sslmode=disable",
            "postgresql://fixture:private@[::1]/source?sslmode=disable",
        ] {
            validate_local_url(url).unwrap();
        }
        for url in ["postgresql://fixture:private@localhost/source?sslmode=disable", "postgresql://fixture:private@203.0.113.1/source?sslmode=disable", "postgresql://fixture:private@127.0.0.1/source?sslmode=require", "postgresql://fixture:private@127.0.0.1/source?sslmode=disable&options=-c%20search_path=other", "http://127.0.0.1/source?sslmode=disable"] {
            assert!(validate_local_url(url).is_err());
        }
    }

    #[test]
    fn read_only_probe_options_decode_without_changing_the_endpoint() {
        for url in [
            "postgresql://fixture:private@127.0.0.1:5432/source?sslmode=disable",
            "postgresql://fixture%2Boperator:p%2Bass%20word%40%3A%2F%23@[::1]:5433/source%2Bdb?sslmode=disable",
            "postgresql://fixture+operator:p+ass%20word@127.0.0.1:6543/source+db?sslmode=disable",
        ] {
            let original = tokio_postgres::Config::from_str(url).unwrap();
            let probe = tokio_postgres::Config::from_str(&readonly_url(url).unwrap()).unwrap();
            assert_eq!(
                probe.get_options(),
                Some("-c default_transaction_read_only=on")
            );
            assert_eq!(probe.get_hosts(), original.get_hosts());
            assert_eq!(probe.get_ports(), original.get_ports());
            assert_eq!(probe.get_user(), original.get_user());
            assert_eq!(probe.get_password(), original.get_password());
            assert_eq!(probe.get_dbname(), original.get_dbname());
            assert_eq!(probe.get_ssl_mode(), original.get_ssl_mode());
        }
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_private_marker_refuses_replay_and_linked_or_public_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("seed-start.json");
        let marker = Marker {
            schema_version: 1,
            run_id: "run".into(),
            source_fingerprint: "source".into(),
        };
        write_private_new(&path, &marker).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(write_private_new(&path, &marker).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let link = directory.path().join("linked.json");
        symlink(&path, &link).unwrap();
        assert!(read_private::<Marker>(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private::<Marker>(&path).is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn secret_artifacts_fail_closed_without_unix_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret.json");
        assert!(write_private_new(&path, &json!({"token": "fixture-secret"})).is_err());
        assert!(!path.exists());
    }
}
