# Upgrade to the full Soup Wall source

The public Soup Wall workspace now contains the Agent, Gateway, and self-hosted Console. This guide is for operators moving from an earlier Soup Wall Agent release or an installation built from the former private Gateway repository. Test the move in a disposable environment before changing a live deployment.

## Interfaces that remain compatible

- The Gateway Cargo package and source-built executable remain `llm-firewall`. Release archives also include the same executable under the `soup-wall-gateway` name; the container uses that name as its entrypoint.
- Existing `firewall.yaml` keys, `LLM_FW_*` environment variables, HTTP headers, token prefixes, stored database identifiers, and cryptographic labels retain their names. Do not rewrite them merely to match the new brand.
- The Agent still uses `agentfw`, its existing config and local token. Its default is shadow mode; check the effective mode after every upgrade.

## Before switching the Gateway

1. Record the current image digest or binary checksum, configuration, policy file, and `Cargo.lock` or release tag. Keep a copy of the running version for rollback.
2. Back up the PostgreSQL or SQLite tenant store and verify a restore in an isolated environment. Preserve the admin, OIDC state, webhook signing, provider, and Redis credentials in your secret manager. Do not put them in a migration bundle or Git.
3. Build the new source with `cargo build --release --locked -p llm-firewall`, or pull a tagged Soup Wall image by digest when the full-source release is published. Verify its attached checksums and SBOM.
4. Copy your existing configuration to the test environment. Run `llm-firewall preflight` (or `soup-wall-gateway preflight` from a release archive). This validates local settings without opening the listener or contacting external services.
5. For PostgreSQL, run `migrate` once with a migration role before starting replicas with their least-privileged runtime role. Do not run concurrent migrations from every replica. For SQLite, use one Gateway instance and back up the database before replacing it.
6. Start one candidate instance and check `/healthz`, `/readyz`, provider forwarding, tenant authentication, admin access, identity sign-in, audit persistence, and the metrics or alerts your deployment relies on. Keep `/metrics` and `/admin` behind the intended network boundary.

The supplied Compose image now starts `soup-wall-gateway` directly. With `deploy/docker-compose.production.yaml`, pass subcommands as `docker compose ... run --rm firewall preflight` and `docker compose ... run --rm firewall migrate`; do not repeat a binary name after the service name. See the [production runbook](operations/PRODUCTION_RUNBOOK.md) for the exact sequence and failure drills.

## Unreleased SAML provider change

The current source uses AWS-LC for SAML on every release target, including non-FIPS Windows x86_64 MSVC. The complete application lock excludes `rsa`, and advisory checks run without a vulnerability exception. This change is unreleased; [the provider checkpoint](operations/evidence/SAML_PROVIDER_2026-10-06.md) records Windows checks and live Keycloak acceptance. The candidate pull request must also pass native verification on all four release platforms.

Source builds must retain `vendor/kryptering`, its license, the root path override and its exclusion from the application workspace. Follow [the patch maintenance rules](../vendor/kryptering/PATCH.md) when updating dependencies or replacing the patch with an upstream release. Windows ARM, Windows GNU and Windows FIPS remain unsupported by this patch; unsupported targets fail at the provider guard. AWS-LC non-FIPS builds require a C/C++ compiler. Windows x64 builds use NASM or the configured `prebuilt-nasm` feature.

Keep existing SP signing credentials, pinned IdP metadata certificates, entity IDs and HTTPS ACS configuration. Test the candidate against your sandbox IdP before switching a deployment: AWS-LC requires RSA keys of at least 2048 bits and RSA-PSS salts equal to the digest length. Signed plaintext assertions remain required. The SP still advertises no encryption certificate, loads no XML decryption key and rejects encrypted assertions. No database migration is introduced by this provider change.

## Agent check

Replace the `agentfw` executable while preserving `~/.agentfw/config.yaml` and its token. Run `agentfw preflight` before a session. If you require blocking, verify `agentfw preflight --require-enforce` and review the replay evidence. The Claude Code hook still fails open when the daemon is unavailable; a successful binary upgrade alone does not make that hook fail closed.

## Rollback

Stop new Gateway replicas before restoring the previous binary or image. If a database migration changed the schema, validate that the old version can read it in a drill; otherwise restore the pre-upgrade snapshot into an isolated target and cut over only after consistency checks. Keep the same token and cryptographic settings when returning to a prior version unless rotating them as part of a separate incident response. Record the release digest, schema version, policy hash, readiness results, and any missing audit or usage evidence.

This guide does not certify production interoperability with a particular IdP or provider. The [self-hosting guide](SELF_HOSTING.md) describes feature boundaries, and [SECURITY.md](../SECURITY.md) describes enforcement and file-permission limits.
