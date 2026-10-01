# Staging and restore drills

The public repository includes two **manual-only** GitHub Actions workflows:
[`staging-drills.yml`](../../.github/workflows/staging-drills.yml) and
[`postgres-restore-drill.yml`](../../.github/workflows/postgres-restore-drill.yml).
They are procedures, not evidence of a passing staging deployment. No public
staging URL or customer database is supplied by this repository.

Configure a GitHub `staging` environment with required reviewers before
running either workflow. Keep database URLs, the age recipient, and the age
identity in that environment's secrets. Limit who may dispatch workflows and
who may approve the environment. Use only a disposable or explicitly approved
staging deployment and a separately isolated drill database. The restore
workflow requires these `staging` environment secrets:

| Secret | Purpose |
| --- | --- |
| `LLM_FW_SOURCE_DATABASE_URL` | Source staging PostgreSQL database |
| `LLM_FW_DRILL_DATABASE_URL` | Separate restore target; its contents are replaced |
| `LLM_FW_BACKUP_RECIPIENT` | age public recipient for the temporary encrypted backup |
| `LLM_FW_BACKUP_IDENTITY` | age private identity for the temporary restore |

## Health and dependency phases

Dispatch **staging-drills** with an HTTPS base URL containing no credentials,
query, or fragment. Run `Baseline`, induce one dependency failure yourself,
run its `PostgresDown` or `RedisDown` phase, restore the dependency, and run
`Recovered`. The workflow reads `/healthz`, `/readyz`, and `/metrics` using
[`staging-acceptance.ps1`](../../scripts/staging-acceptance.ps1) and
[`dependency-failure-drill.ps1`](../../scripts/dependency-failure-drill.ps1).
It does not stop or restart services. The generated JSON artifacts contain
aggregate status and a staging host name; use an appropriate retention and
access policy for Actions artifacts. The scripts require HTTPS; loopback HTTP
is supported only when you run the scripts locally with `-AllowHttpForLocal`.

## Encrypted restore

Dispatch **postgres-restore-drill** only after checking the source and drill
database identities and the configured staging secrets. Its script fingerprints
both PostgreSQL endpoints and refuses the same database. It creates an
encrypted `pg_dump`, decrypts it into a temporary runner file, restores into
the drill database, and verifies the schema and evidence tables. The archive
and identity file are removed from the runner after the workflow; the drill
database must be destroyed separately. The minimum schema version input
defaults to 25 and should be reviewed when migrations change.

The same scripts can be run locally with PowerShell and the required services.
Record the observed phase results and restore evidence in a private release
record. Do not treat local fixture tests or a workflow definition as a
completed managed staging drill. See the [production runbook](PRODUCTION_RUNBOOK.md)
for the expected readiness transitions and backup practices.
