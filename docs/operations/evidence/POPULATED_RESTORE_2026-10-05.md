# Populated encrypted restore checkpoint

The isolated Linux run passed on clean source
`75a0e76834bf99cfb14ba537480106c3e69db348` at
`2026-10-05T11:20:16.780909+00:00`. It used an exported source tree on an owner-only
ext4 directory, Rust 1.98.1, PostgreSQL 18.6, age 1.2.1 and PowerShell 7.6.6.
Only reusable runtime binaries/caches were reused. A fresh owned loopback cluster,
role, source database and drill database were allocated; historical databases
were never used as targets. The owned cluster stopped successfully afterwards.

The original Gateway `migrate` command created the schema without starting a
Gateway listener or delivery worker. Original TenantStore APIs created two
tenants, an owner membership, limits/approved policies, two service accounts
(retained and already revoked), one active webhook destination, two security
events and one genuine pending delivery. No direct fixture INSERT bypassed
these product APIs. The destination is reserved `.test` DNS and was not contacted.

The original encrypted PowerShell drill dumped, age-encrypted, decrypted and
restored the source into the separately fingerprinted drill database. Complete
private public-schema rows and sequence state matched before behavioral changes,
including credential hashes, revocation/expiry, policy bodies and delivery fields.
Read-only probes authenticated the retained token with the restored tenant,
limits and model policy, rejected the revoked token and checked tenant isolation.
The restored-only exercise revoked the retained token and verified immediate
rejection, deployed another approved policy to enqueue a second delivery, and
deactivated the destination to suppress the next enqueue. Source rows/sequences
were unchanged after the exercise. No actual delivery or provider request ran.

All 21 Python orchestration tests passed on Linux/Python 3.14, including both Unix
permission/symlink cases. All nine Rust helper tests passed. The expanded existing
PostgreSQL integration test also passed on a separate fresh database: successful
issuance returns the stored metadata and authenticating token; outsider issuance
and revocation create no records/audit effects; authorized/repeated revocation
preserves the expected audit behavior. These runs are local acceptance evidence.

Actual execution found a production issuance defect: an INSERT CTE returned only
the ID, then its outer SELECT scanned the base table using the statement's earlier
snapshot. The account and audit persisted while the API returned an error and
withheld its one-time token. `a938cc8` returns metadata directly from the INSERT's
RETURNING relation, preserving authorization and atomic audit. This matches
[PostgreSQL's documented data-modifying WITH semantics](https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING).
Independent source review checked column order, role/active predicates and audit
execution. The new actual PostgreSQL regression fails on the earlier behavior.

Earlier incomplete attempts remain in the aggregate record and ignored private
artifacts. They exposed literal-address/CIDR comparison, read-only URI encoding
and platform-mock errors, all corrected before the passing run. An ignored
diagnostic helper stored the earlier error privately; the final passing helper
contains no diagnostic modification. Failed fixture runs were never resumed or
reseeded; every new acceptance attempt used fresh data. Diagnostic inspection
was read-only. The earlier run whose tests later failed had already passed the
restore exercise, as its retained aggregate explicitly records.

The [aggregate evidence](POPULATED_RESTORE_2026-10-05.json) binds source archive and
executable hashes. Both executables stayed unchanged through the run. Private
credentials, master signing key, age identity, full rows, database names and tool
transcripts are not published. Private fixture data remains for operator review;
the original restore script removes its own temporary plaintext files.

Reproduce using [STAGING_DRILLS](../STAGING_DRILLS.md#populated-local-restore-fixture)
on an explicitly disposable loopback PostgreSQL instance. This closes the local
populated database/queue/authentication checkpoint. Managed TLS, actual webhook
delivery, real IdP interoperability and recovery of customer data remain separate
gates, as do live model effectiveness and staffed routing.
