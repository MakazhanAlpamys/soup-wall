# Staging and restore drills

Run these scripts from an operator-controlled host on the internal staging
network. The repository provides procedures, not evidence of a passing staging
deployment. No public staging URL or customer database is supplied.

Use a disposable or explicitly approved staging deployment and a separate
drill database. Keep database URLs and the `age` identity in your existing
secret manager. Capture the aggregate JSON output in a private release record.
The public GitHub Actions workflows do not connect to staging infrastructure.

## Health and dependency phases

Choose an internal HTTPS base URL that serves `/healthz`, `/readyz`, and
`/metrics` without credentials in the URL. The supplied public
[`Caddyfile.example`](../../deploy/Caddyfile.example) intentionally returns 404
for `/metrics`; use an internal monitoring endpoint instead. Do not expose
metrics at the customer-facing edge.

From the operator host, run the baseline gate and record its output:

```powershell
$baseUrl = 'https://soup-wall-staging.internal.example'
pwsh ./scripts/staging-acceptance.ps1 -BaseUrl $baseUrl -RequireRedis
pwsh ./scripts/dependency-failure-drill.ps1 -BaseUrl $baseUrl -Phase Baseline
```

Induce one dependency failure through your staging control plane and run
`-Phase PostgresDown` or `-Phase RedisDown`. Restore the dependency before
testing the next one. After both are healthy, run `-Phase Recovered` and repeat
the acceptance gate. The scripts only probe endpoints; they never stop or
restart services. They require HTTPS, except for loopback tests using
`-AllowHttpForLocal`.

Keep the baseline and recovered acceptance JSON alongside every dependency
phase JSON in the private release record. Each record includes
`observed_at_utc`; use these timestamps to preserve the sequence and duration
of the drill. The acceptance record also includes `schema_version` so later
changes to its evidence format can be distinguished.

## Encrypted PostgreSQL restore

Install PowerShell, `pg_dump`, `pg_restore`, `psql`, and `age` on an
operator-controlled host. Provide source and drill database URLs from the
secret manager, an `age` recipient, and the path to an owner-readable `age`
identity file. Confirm that the drill database can be replaced and that the
encrypted backup path does not already exist. For example, after securely
loading these values into the operator session:

```powershell
pwsh ./scripts/postgres-restore-drill.ps1 `
  -SourceDatabaseUrl $env:LLM_FW_SOURCE_DATABASE_URL `
  -DrillDatabaseUrl $env:LLM_FW_DRILL_DATABASE_URL `
  -BackupRecipient $env:LLM_FW_BACKUP_RECIPIENT `
  -BackupIdentity $env:LLM_FW_BACKUP_IDENTITY_FILE `
  -BackupPath './soup-wall-staging-backup.age' `
  -MinimumSchemaVersion 25
```

Review the minimum schema version when migrations change. The script
fingerprints both PostgreSQL endpoints and refuses a restore into the source
database. It creates an encrypted backup, decrypts into a private temporary
directory, restores into the drill database, and verifies schema and evidence
tables. It removes temporary plaintext files after the run. Retain or destroy
the encrypted backup under your policy; destroy the drill database separately.

Do not treat local fixture tests as a completed managed staging drill. See the
[production runbook](PRODUCTION_RUNBOOK.md) for readiness transitions and
backup practices.
