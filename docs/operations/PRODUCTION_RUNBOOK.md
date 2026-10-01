# Soup Wall production runbook

This runbook is a release gate companion to `deploy/production.firewall.yaml` and
`deploy/docker-compose.production.yaml`. It deliberately contains commands and
placeholders, never real credentials. A production owner must adapt the commands
to the managed PostgreSQL/Redis provider and record the chosen retention region.

## Before first deployment

1. Use a dedicated PostgreSQL database role for migrations and a separate runtime
   role with only the application tables/sequence privileges. For managed or
   cross-host PostgreSQL, require TLS in `LLM_FW_POSTGRES_URL`
   (`sslmode=require`, the TLS mode supported by the Rust PostgreSQL driver).
   The default trust store contains Mozilla public roots. If the provider uses
   a private CA, mount a read-only PEM bundle and set
   `LLM_FW_POSTGRES_CA_CERT_FILE` to its path; the bundle is added to (not
   substituted for) the public roots and must contain at least one
   `CERTIFICATE` block.
   The bundled Compose service name `postgres` is an explicit single-host development exception and
   is never exposed as a host port.
2. Generate independent high-entropy values for `LLM_FW_ADMIN_TOKEN`,
   `LLM_FW_OIDC_STATE_KEY`, and `LLM_FW_WEBHOOK_SIGNING_KEY`. The production
   tenant-store template deliberately disables the shared proxy-token mode;
   customer requests authenticate with their issued tenant token while the
   upstream provider credential remains caller-supplied. Store all runtime
   secrets in the provider secret manager, not in Git, images, logs, or shell
   history.
3. Run migrations as a one-shot release job, then start the proxy with the
   runtime role. Do not let every replica run migrations concurrently:

   ```text
   docker compose -f deploy/docker-compose.production.yaml run --rm --no-deps firewall preflight
   docker compose -f deploy/docker-compose.production.yaml run --rm firewall migrate
   docker compose -f deploy/docker-compose.production.yaml up -d firewall
   ```

   `preflight` parses the mounted policy and checks required secrets, auth,
   fail-closed settings, and TLS on backend URLs without connecting to
   PostgreSQL or Redis. Run it again for every image/config change; it does not
   replace the migration or restore drills below.

4. Terminate TLS at the edge and forward only to the loopback-bound firewall
   port. Expose `/healthz` and `/readyz` to the orchestrator; expose `/metrics`
   only to the internal monitoring network. `deploy/Caddyfile.example` is a
   starting point for a Caddy v2 edge; replace its hostname and validate the
   final edge config in a disposable environment. Pin the image by digest
   before a customer pilot. The Docker image is built with `Cargo.lock` and has
   a curl-based liveness healthcheck; readiness remains the authoritative
   dependency gate. Keep `.dockerignore` in the build context so local `.env`,
   runtime data, and model artifacts never reach the Docker daemon.

## Health and monitoring

- `/healthz` is dependency-free liveness.
- `/readyz` is not liveness: it checks PostgreSQL/SQLite reachability and reports
  audit or usage-write loss. Remove a replica from service on HTTP 503.
- `/metrics` is intentionally low-cardinality and contains no tenant IDs,
  prompts, responses, URLs, or credentials. Alert on
  `llm_firewall_control_plane_ready == 0`, any increase in audit/usage failures,
  `llm_firewall_redis_limits_ready == 0`, and Redis being disabled when distributed
  limits are required. `/readyz` returns `503` while an enabled Redis backend is
  unreachable, so the orchestrator can remove the replica before it admits traffic.
- Alert on webhook deliveries entering `dead`; replay only after the endpoint,
  signature key, and event deduplication behavior are reviewed.

The repository ships the matching Prometheus rule group in
`deploy/prometheus-alerts.yaml`. Validate it with the exact `promtool` version
used by the monitoring stack before rollout:

```text
promtool check rules deploy/prometheus-alerts.yaml
```

Route `critical` alerts to the staffed incident channel and `warning` alerts
to the operational backlog. The file contains no tenant labels or customer
data; keep the `/metrics` listener on the internal monitoring network.

## PostgreSQL backup and restore drill

Run at least monthly and before schema or billing changes. Use an encrypted
provider snapshot or an encrypted `pg_dump` stored under the approved retention
policy:

```text
pg_dump --format=custom --no-owner --no-privileges "$LLM_FW_POSTGRES_URL" \
  | age -r <backup-recipient> > soup-wall-$(date -u +%Y%m%d).dump.age
```

For a drill, restore into an isolated database, run the application migration
check, and verify counts/content hashes without exposing customer data:

```text
age -d -i <backup-identity> soup-wall-YYYYMMDD.dump.age \
  | pg_restore --clean --if-exists --no-owner --dbname "$DRILL_POSTGRES_URL"
soup-wall-gateway migrate   # must be a no-op against the restored schema
```

Record restore duration, the newest `tenant_security_events` sequence per test
tenant, policy content hashes, usage reconciliation IDs, and any missing rows.
Destroy the drill database and decrypted dump after verification.

On Windows, `scripts/postgres-restore-drill.ps1` automates the same flow. It
refuses to overwrite an existing backup, refuses identical source/drill URLs or
source/drill URLs that PostgreSQL resolves to the same server/database,
encrypts the dump with `age`, verifies the minimum schema version (currently
25, including SAML invitation state), and prints only aggregate evidence counts. Supply the drill URL explicitly;
the script never targets the source database for `pg_restore`.

## Dependency failure drills

Before running fault drills, run the read-only staging acceptance gate from the
monitoring/operator host:

```powershell
pwsh scripts/staging-acceptance.ps1 -BaseUrl https://soup-wall-staging.internal.example -RequireRedis
```

Use an internal monitoring endpoint: the supplied public Caddy edge returns
404 for `/metrics`. The gate performs only `GET /healthz`, `GET /readyz`, and
`GET /metrics`. It checks the control-plane and evidence-persistence gauges,
requires shared Redis limits when requested, rejects sensitive values in the metrics response, and
prints aggregate JSON evidence. It sends no credentials, model requests, or
state-changing calls. Use `-AllowHttpForLocal` only with a loopback URL.

Run the drill against a disposable staging deployment first and isolate one
dependency at a time. `scripts/dependency-failure-drill.ps1` is read-only: it
checks liveness, readiness, and aggregate metrics but never stops PostgreSQL,
Redis, a container, or a managed service. The deployment owner must trigger
and recover the fault through the approved staging control plane.

```powershell
.\scripts\dependency-failure-drill.ps1 -BaseUrl https://soup-wall-staging.internal.example -Phase Baseline
# Make only PostgreSQL unavailable, then:
.\scripts\dependency-failure-drill.ps1 -BaseUrl https://soup-wall-staging.internal.example -Phase PostgresDown
# Restore PostgreSQL, make only Redis unavailable, then:
.\scripts\dependency-failure-drill.ps1 -BaseUrl https://soup-wall-staging.internal.example -Phase RedisDown
# Restore both dependencies, then:
.\scripts\dependency-failure-drill.ps1 -BaseUrl https://soup-wall-staging.internal.example -Phase Recovered
```

Each successful phase emits one compact JSON evidence record without URLs,
credentials, tenant IDs, or customer content. Preserve it with the incident or
release evidence. During both dependency faults `/healthz` must remain live and
`/readyz` must return `503`; after recovery readiness must return `200`.

### Redis failure and recovery

Redis stores shared rate/spend windows, not policy or invoice truth. With
`fail_mode: fail_closed`, a Redis outage should reject limited requests until
connectivity is restored; do not silently switch to process-local counters for a
multi-replica deployment. Check the Redis health/auth/TLS path, then restart or
fail over the managed service. Counters may reset after an intentional Redis
restore; record that window in the incident and reconcile usage from immutable
PostgreSQL events.

## Incident response

1. Declare an incident and capture UTC start time, affected replicas, release
   digest, and the last healthy readiness/metrics snapshot.
2. If credentials may be exposed, revoke and rotate the proxy/admin/OIDC/webhook
   secrets immediately. Never paste the values into the incident channel.
3. Preserve logs and immutable security/usage event evidence. Redact prompts,
   responses, bearer tokens, provider keys, and personal data before sharing.
4. Contain by suspending the affected tenant/organization or routing traffic to a
   known-good replica. Keep the firewall fail-closed for unavailable control
   planes unless the incident commander documents a bounded exception.
5. Restore from a verified snapshot only after the target and schema version are
   confirmed. Re-run readiness, policy hash, audit sequence, and usage
   reconciliation checks.
6. Close with a timeline, customer impact, data-integrity assessment, root cause,
   and a regression test or runbook change. Security incidents follow
   `SECURITY.md` and the applicable notification deadlines.

## Release checklist

- Local `cargo fmt`, all tests, Clippy, audit, and SBOM pass.
- GitHub Actions required checks are green; billing-blocked runs are not treated
  as release evidence.
- PostgreSQL backup and restore drill is current; Redis and webhook alerts are
  wired; metrics are reachable only from the monitoring network.
- Threat-model, data-retention, residency, support boundary, and rollback notes
  are approved before enabling a hosted customer.
