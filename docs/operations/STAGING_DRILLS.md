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

## Populated local restore fixture

The previous local restore contained two tenants and two security events, with
empty webhook and service-account tables. The opt-in
[`postgres-populated-restore-acceptance.py`](../../scripts/postgres-populated-restore-acceptance.py)
driver verifies nonempty synthetic records on an explicitly disposable,
numeric-loopback PostgreSQL instance. It allocates fresh source and drill
databases and a fresh fixture role; it never seeds an existing database or starts
an installed service. The admin credential must belong to that disposable
instance and permit creation of the isolated databases and role.

The client URL must use numeric loopback. Docker can expose that route while
PostgreSQL reports a different server-side address or port. Before database
mutations, the driver checks the selected admin database and pins its observed
numeric server address/port. Every source/drill identity must match its reserved
database name and that same frozen server identity. Changed or inconsistent
identities are refused; loopback URL restrictions remain in force.

The runner overrides subprocess `TMPDIR`, `TMP` and `TEMP` with a fresh
owner-only directory inside its private run. The original PowerShell drill
creates its own temporary subdirectory there and restricts permissions before
writing plaintext. Ambient temporary-directory settings cannot redirect these
fixture files elsewhere.

Build the original migration command and the fixture helper:

```sh
cargo test --locked -p llm-firewall --example postgres-restore-fixture
cargo build --locked -p llm-firewall --bin llm-firewall --example postgres-restore-fixture
python3 -m unittest discover -s scripts/tests -p 'test_postgres_populated_restore_acceptance.py' -v
```

The example tests use SQLite and synthetic credentials. They do not establish
a passing PostgreSQL encrypted restore. The driver's default invocation is dry
and starts no processes. For the real fixture, use Linux or WSL with a filesystem
that enforces Unix owner-only permissions, and ensure `psql`, `pg_dump`,
`pg_restore`, `age`, `age-keygen`, and `pwsh` are available. Secret artifact
creation fails closed on Windows; this procedure does not claim Windows DACL
hardening for the generic restore script.

After loading `LLM_FW_RESTORE_FIXTURE_ADMIN_URL` privately with an explicit
numeric-loopback URL using `sslmode=disable`, run:

```sh
python3 scripts/postgres-populated-restore-acceptance.py --run \
  --helper "$PWD/target/debug/examples/postgres-restore-fixture" \
  --gateway "$PWD/target/debug/llm-firewall" \
  --psql "$(command -v psql)" \
  --pg-dump "$(command -v pg_dump)" \
  --pg-restore "$(command -v pg_restore)" \
  --age "$(command -v age)" \
  --age-keygen "$(command -v age-keygen)" \
  --pwsh "$(command -v pwsh)" \
  > target/populated-restore-evidence.json
```

The Rust helper uses the existing `TenantStore` APIs to create two tenants,
an owner membership, retained and revoked service accounts, limits and approved
policies, one webhook destination, two security events and one pending delivery.
The destination uses reserved `.test` DNS and is never contacted. The driver
invokes only the Gateway's `migrate` command from a private working directory;
the Gateway listener and automatic webhook dispatcher never start.

The run directory under ignored `target` has mode `0700`; credentials, generated
age identity, manifests and full-row snapshots have mode `0600`. An exclusive
seed marker precedes fixture writes. Partial or completed seed/exercise runs are
refused instead of reseeded. A new attempt requires fresh allocated databases
and a new run directory. `probe` uses read-only database transactions and never
migrates, deploys or revokes anything.

Before behavioral changes, the driver compares complete private source/restored
table rows and sequence state, including credential hashes, expiry/revocation,
policy bodies, event payloads and webhook delivery fields. Counts must be
nonempty and match the fixture. Only the fingerprint-bound restored database
is then exercised: retained-token authentication works with restored limits and
policy, revocation disables it, a new deployment enqueues a second pending
delivery, and destination deactivation prevents another enqueue. Source rows
and sequences are rechecked afterwards, including when exercise fails.

Only aggregate evidence is printed or uploaded by CI. Raw tokens, signing key,
database URLs, backup identity and snapshots remain private. The driver retains
its fresh databases, role and private artifacts for operator review; disposal
is a separate explicit operator action. The existing encrypted restore script
still removes its own bounded temporary plaintext files.

Record an actual passing run before updating acceptance status. This local
checkpoint covers database preservation and queue/authentication behavior.
Successful webhook delivery needs an owned public HTTPS receiver and retained
signing key; real IdP login, managed TLS, provider traffic and staffed alert
routing remain separate acceptance gates.
