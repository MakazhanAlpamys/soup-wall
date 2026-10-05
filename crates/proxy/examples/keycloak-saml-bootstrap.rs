// SPDX-License-Identifier: Apache-2.0

//! Pre-provision two synthetic SAML identities in a new, disposable SQLite store.
//! This example never reads an assertion or grants access from an IdP role claim.

use std::path::Path;

use anyhow::{bail, Context};
use llm_firewall::tenant_store::{TenantStore, WorkspaceRole};

fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [database, issuer, subject, alias] = arguments.as_slice() else {
        bail!(
            "usage: keycloak-saml-bootstrap NEW_DATABASE ISSUER SYNTHETIC_SUBJECT SYNTHETIC_ALIAS"
        );
    };
    if subject == alias {
        bail!("the negative signature check needs a distinct pre-provisioned alias");
    }
    if Path::new(database).exists() {
        bail!("refusing to change an existing database");
    }
    let store = TenantStore::open(database)?;
    let organization = store.create_organization("Disposable Keycloak acceptance")?;
    let tenant = store.create_tenant_in_organization(&organization.id, "Disposable workspace")?;
    let workspace = store
        .workspace_for_tenant(&tenant.id)?
        .context("new tenant has no workspace")?;
    let principal = store.create_workspace_principal("Synthetic Keycloak user")?;
    store.link_workspace_external_identity(&principal.id, issuer, subject)?;
    store.set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Owner)?;
    // One issuer has one subject per principal. Use another authorized principal
    // so the negative mutation cannot be rejected merely as an unknown identity.
    let alias_principal = store.create_workspace_principal("Synthetic negative-check user")?;
    store.link_workspace_external_identity(&alias_principal.id, issuer, alias)?;
    store.set_workspace_membership(&workspace.id, &alias_principal.id, WorkspaceRole::Owner)?;
    for name_id in [subject, alias] {
        let access = store
            .verified_identity_workspace_access(&organization.id, &workspace.id, issuer, name_id)?
            .context("pre-provisioned synthetic identity has no workspace access")?;
        if access.role != WorkspaceRole::Owner {
            bail!("pre-provisioned synthetic identity lacks the owner role");
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "organization_id": organization.id,
            "workspace_id": workspace.id,
        })
    );
    Ok(())
}
